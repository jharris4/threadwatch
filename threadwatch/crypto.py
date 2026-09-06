"""Optional Thread decryption: MAC-layer AES-CCM, 6LoWPAN-lite, MLE parsing.

Only imported when a network key is configured. Requires the `cryptography`
package (Debian/RPi: apt install python3-cryptography).

Thread key derivation (as implemented by OpenThread and Wireshark):
    HMAC-SHA256(network_key, key_sequence_be32 || "Thread") -> 32 bytes
    bytes[0:16]  = MLE key
    bytes[16:32] = MAC key
The 802.15.4 aux header carries key_index = (key_sequence & 0x7f) + 1 (so
indices 1-128 repeat every 128 rotations; OpenThread mac_types.cpp), so the
sequence is recovered by trying candidates that match the observed index:
the first few generations until a frame has decrypted, then the generations
around the sequence that frame used. MLE messages carry the sequence
outright in their key source, and every decryption (MAC or MLE) teaches it
to the MAC search, so a network rotating its key stays readable however
high the sequence climbs.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import struct
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

MLE_UDP_PORT = 19788

MLE_COMMANDS = {
    0: "Link Request", 1: "Link Accept", 2: "Link Accept And Request",
    3: "Link Reject", 4: "Advertisement", 5: "Update", 6: "Update Request",
    7: "Data Request", 8: "Data Response", 9: "Parent Request",
    10: "Parent Response", 11: "Child ID Request", 12: "Child ID Response",
    13: "Child Update Request", 14: "Child Update Response", 15: "Announce",
    16: "Discovery Request", 17: "Discovery Response",
}

_HOSTNAME_RE = re.compile(rb"([\x01-\x3f][\x20-\x7e]{1,63}){2,}")


def derive_keys(network_key: bytes, sequence: int) -> tuple[bytes, bytes]:
    """Return (mle_key, mac_key) for a key sequence counter."""
    digest = hmac.new(network_key, struct.pack(">L", sequence) + b"Thread",
                      hashlib.sha256).digest()
    return digest[:16], digest[16:32]


@dataclass
class MleInfo:
    command: int
    command_name: str
    partition_id: int | None = None
    leader_router_id: int | None = None
    source_addr16: int | None = None
    # False for a security-suite-255 message: it carried no MIC, so it
    # came from anything on the channel and proves nothing. Only the
    # command is reported for it; its TLVs are never read.
    secured: bool = True
    # The MLE frame counter of a secured message: the pipeline keeps the
    # highest accepted per sender, so a replayed message is not a sighting.
    counter: int | None = None
    # The key sequence that counter belongs to. Counters restart at zero
    # when the network rotates its key, so one is only comparable with
    # another under the same generation.
    key_sequence: int | None = None


@dataclass
class Decryptor:
    network_key: bytes
    # short (rloc16 hex, 4 chars) -> extended (16 chars) learned/seeded mapping
    short_to_ext: dict = field(default_factory=dict)
    # The highest key sequence a frame has decrypted under, None until one
    # has. The MAC key search is centred on it (see _keys_for_index).
    key_sequence: int | None = None
    _keys_by_index: dict = field(default_factory=dict)  # key_index -> (sequence basis, [(seq, mle, mac)])
    stats: dict = field(default_factory=lambda: {
        "mac_decrypted": 0, "mac_failed": 0, "mac_no_ext_addr": 0, "mac_unsupported": 0,
        "mle_decrypted": 0, "mle_failed": 0, "mle_unsecured": 0, "plaintext": 0,
        "short_resolved": 0, "short_unresolved": 0, "short_candidates_tried": 0, "parse_failed": 0,
    })

    # Before any frame has decrypted, a key index is tried as the first
    # generations that map to it; after one has, as the generations within
    # this many rotations of the sequence it used (the next rotation, and a
    # straggler still on the previous key, are each one away).
    INITIAL_GENERATIONS = 8
    NEARBY_GENERATIONS = 2

    def note_key_sequence(self, sequence: int) -> None:
        """A frame decrypted under this sequence: search near it from now
        on. Only ever moves up, so a straggler on the old key after a
        rotation does not pull the search back."""
        if self.key_sequence is None or sequence > self.key_sequence:
            self.key_sequence = sequence

    def _keys_for_index(self, key_index: int):
        if not 1 <= key_index <= 128:
            return []
        cached = self._keys_by_index.get(key_index)
        if cached is None or cached[0] != self.key_sequence:
            if self.key_sequence is None:
                seqs = [key_index - 1 + 128 * k for k in range(self.INITIAL_GENERATIONS)]
            else:
                span = 128 * self.NEARBY_GENERATIONS
                seqs = sorted((s for s in range(max(0, self.key_sequence - span), self.key_sequence + span + 1)
                               if (s & 0x7f) + 1 == key_index),
                              key=lambda s: abs(s - self.key_sequence))
            cached = (self.key_sequence, [(s, *derive_keys(self.network_key, s)) for s in seqs])
            self._keys_by_index[key_index] = cached
        return cached[1]

    # ------------------------------------------------------------------ MAC

    def decrypt_frame(self, psdu: bytes, src_ext_hex: str | None,
                      src_short_hex: str | None) -> bytes | None:
        """Return the decrypted MAC payload of a secured data frame, or the
        plaintext payload for unsecured frames, or None when undecryptable.
        The returned bytes start at the MAC payload (after aux header)."""
        return self.decrypt_frame_counter(psdu, src_ext_hex, src_short_hex)[0]

    def decrypt_frame_counter(self, psdu: bytes, src_ext_hex: str | None,
                              src_short_hex: str | None) -> tuple[bytes | None, int | None, int | None]:
        """decrypt_frame, plus the MAC frame counter of a secured frame that
        passed its MIC and the key sequence it was authenticated under: the
        proof that the sender holds the key and used this extended address
        as its nonce, and which generation of that key it used. A counter
        only means anything within its own generation - the network rotates
        its key and every device restarts its counters at zero - so the two
        travel together. Both None for an unsecured frame (anyone's bytes)
        and for one that failed."""
        sec = self._secured_parts(psdu)
        if sec is None:
            # Secured, but not the Thread way (a security level other than
            # ENC-MIC-32, a key id mode other than 1), or cut before the
            # end of its aux header: never tried, so neither decrypted nor
            # failed. Counted apart, so status shows what the recorder saw
            # and could not read, and a stale-credentials check judging
            # failures against successes is not fed these.
            self.stats["mac_unsupported"] += 1
            return None, None, None
        if sec is False:
            self.stats["plaintext"] += 1
            return psdu[self._mac_header_len(psdu):], None, None
        ext_hex = src_ext_hex or (self.short_to_ext.get(src_short_hex or "") if src_short_hex else None)
        if not ext_hex:
            self.stats["mac_no_ext_addr"] += 1
            return None, None, None
        plain, sequence = self._decrypt_with_ext(sec, ext_hex)
        self.stats["mac_decrypted" if plain is not None else "mac_failed"] += 1
        return plain, (sec[1] if plain is not None else None), sequence

    def verify_short(self, psdu: bytes, ext_hex: str) -> bool:
        """Does this secured frame really come from ext_hex (MIC check)?"""
        sec = self._secured_parts(psdu)
        return bool(sec) and self._decrypt_with_ext(sec, ext_hex)[0] is not None

    def resolve_short(self, psdu: bytes, short_hex: str, candidates) -> str | None:
        """Learn which extended address a short-source secured frame came from.

        The MAC nonce is the sender's extended address, so trying each
        candidate against the 32-bit MIC identifies the sender with no
        MLE traffic at all. This is how sleepy end devices get an identity:
        they poll and talk from their short address for days and only ever
        use the extended one while attaching.
        """
        sec = self._secured_parts(psdu)
        if not sec:
            return None
        for ext_hex in candidates:
            self.stats["short_candidates_tried"] += 1
            if self._decrypt_with_ext(sec, ext_hex)[0] is not None:
                self.short_to_ext[short_hex] = ext_hex
                self.stats["short_resolved"] += 1
                return ext_hex
        self.stats["short_unresolved"] += 1
        return None

    def _secured_parts(self, psdu: bytes):
        """None: not decryptable. False: unsecured. Else a tuple for
        _decrypt_with_ext: (key_index, counter, sec_level, open_part, secret)."""
        if len(psdu) < 3:
            return None
        fcf = struct.unpack("<H", psdu[0:2])[0]
        hdr_len = self._mac_header_len(psdu)
        if hdr_len is None:
            return None
        if not (fcf & 0x0008):
            return False
        if hdr_len + 5 > len(psdu):
            return None
        sec_ctl = psdu[hdr_len]
        sec_level = sec_ctl & 0x07
        key_mode = (sec_ctl >> 3) & 0x03
        counter = struct.unpack("<L", psdu[hdr_len + 1:hdr_len + 5])[0]
        aux_len = 5 + (1 if key_mode == 1 else 5 if key_mode == 2 else 9 if key_mode == 3 else 0)
        if key_mode != 1 or sec_level != 5:   # Thread uses ENC-MIC-32, key index mode
            return None
        open_len = hdr_len + aux_len
        # 802.15.4-2006 7.5.8.2.3: for MAC command frames the command
        # identifier is authenticated but not encrypted, so it belongs to
        # the a-data and a data request's encrypted payload is empty (just
        # the MIC follows). Polls are the bulk of what a sleepy end device
        # sends, so getting this right is what identifies those devices.
        if (fcf & 0x7) == 3:
            open_len += 1
        secret = psdu[open_len:]
        if len(secret) < 4:
            return None
        return psdu[hdr_len + 5], counter, sec_level, psdu[:open_len], secret

    def resolvable(self, psdu: bytes) -> bool:
        """True when the frame is secured the Thread way and worth a nonce search."""
        return bool(self._secured_parts(psdu))

    def _decrypt_with_ext(self, sec, ext_hex: str) -> tuple[bytes | None, int | None]:
        """The decrypted payload and the key sequence whose MAC key read it,
        or (None, None). The sequence is what makes the frame counter mean
        something: counters restart at zero in each generation."""
        key_index, counter, sec_level, open_part, secret = sec
        # A candidate that is not an extended address (a stray form in a
        # state file the loaders did not catch) is nobody, not a crash in
        # the capture loop.
        try:
            addr = bytes.fromhex(ext_hex)
        except (ValueError, TypeError):
            return None, None
        if len(addr) != 8:
            return None, None
        nonce = addr + struct.pack(">L", counter) + bytes([sec_level])
        # The vendored sniffer strips the FCS (DLT 230, IEEE802_15_4_NOFCS),
        # so a frame this recorder captured decrypts untrimmed: that pass
        # goes first. An imported capture may still carry the 2-byte FCS
        # at the tail, so the trimmed pass follows, for those files only;
        # tried the other way round, every ring frame paid a full key
        # search in a pass that could never succeed.
        for trim in (0, 2):
            body = secret[:len(secret) - trim]
            if len(body) < 4:
                continue
            for seq, _mle, mac_key in self._keys_for_index(key_index):
                try:
                    plain = AESCCM(mac_key, tag_length=4).decrypt(nonce, body, open_part)
                except InvalidTag:
                    continue
                self.note_key_sequence(seq)
                return plain, seq
        return None, None

    @staticmethod
    def _mac_header_len(p: bytes) -> int | None:
        fcf = struct.unpack("<H", p[0:2])[0]
        pan_comp = bool(fcf & 0x0040)
        dst_mode = (fcf >> 10) & 0x3
        src_mode = (fcf >> 14) & 0x3
        off = 3
        if dst_mode in (2, 3):
            off += 2 + (2 if dst_mode == 2 else 8)
        if src_mode in (2, 3):
            if not (pan_comp and dst_mode in (2, 3)):
                off += 2
            off += 2 if src_mode == 2 else 8
        return off if off <= len(p) else None

    # ------------------------------------------------------- 6LoWPAN (lite)

    @staticmethod
    def _iid_from_ext(ext_hex: str) -> bytes:
        b = bytearray(bytes.fromhex(ext_hex))
        b[0] ^= 0x02  # universal/local bit flip
        return bytes(b)

    @staticmethod
    def udp_ports(payload: bytes, mac_src_ext: str | None = None,
                  mac_dst_ext: str | None = None,
                  mac_dst_short: str | None = None):
        """Best-effort 6LoWPAN IPHC+NHC parse.

        Returns (sport, dport, udp_payload, src_ip16, dst_ip16) where the IPs
        are 16-byte addresses when reconstructable (stateless link-local and
        common multicast forms — sufficient for MLE), else None. Handles the
        common Thread on-air forms; returns None for non-first fragments and
        unhandled layouts.
        """
        p = payload
        if p and (p[0] >> 6) == 0b10:   # mesh header
            hops_deep = (p[0] & 0x0F) == 0x0F
            p = p[1 + (1 if hops_deep else 0) + 2 + 2:]
        if p and (p[0] >> 3) == 0b11000:   # FRAG1
            p = p[4:]
        elif p and (p[0] >> 3) == 0b11100:  # FRAGN
            return None
        if len(p) < 2 or (p[0] >> 5) != 0b011:
            return None
        iphc = struct.unpack(">H", p[0:2])[0]
        off = 2
        if iphc & 0x0080:  # CID
            off += 1
        tf = (iphc >> 11) & 0x3
        off += (4, 3, 1, 0)[tf]
        nh_compressed = bool(iphc & 0x0400)
        if not nh_compressed:
            off += 1
        if (iphc >> 8) & 0x3 == 0:
            off += 1
        LL = bytes.fromhex("fe80000000000000")

        sam = (iphc >> 4) & 0x3
        sac = bool(iphc & 0x0040)
        src_ip = None
        if not sac:
            if sam == 0:
                src_ip = p[off:off + 16]; off += 16
            elif sam == 1:
                src_ip = LL + p[off:off + 8]; off += 8
            elif sam == 2:
                src_ip = LL + b"\x00\x00\x00\xff\xfe\x00" + p[off:off + 2]; off += 2
            else:
                if mac_src_ext:
                    src_ip = LL + Decryptor._iid_from_ext(mac_src_ext)
        else:
            off += (0, 8, 2, 0)[sam]  # context-based: skip, no reconstruction

        m = bool(iphc & 0x0008)
        dam = iphc & 0x3
        dac = bool(iphc & 0x0004)
        dst_ip = None
        if m and not dac:
            if dam == 0:
                dst_ip = p[off:off + 16]; off += 16
            elif dam == 1:
                dst_ip = bytes([0xFF, p[off]]) + b"\x00" * 9 + p[off + 1:off + 6]; off += 6
            elif dam == 2:
                dst_ip = bytes([0xFF, p[off]]) + b"\x00" * 11 + p[off + 1:off + 4]; off += 4
            else:
                dst_ip = bytes([0xFF, 0x02]) + b"\x00" * 13 + p[off:off + 1]; off += 1
        elif m and dac:
            off += 6
        elif not m and not dac:
            if dam == 0:
                dst_ip = p[off:off + 16]; off += 16
            elif dam == 1:
                dst_ip = LL + p[off:off + 8]; off += 8
            elif dam == 2:
                dst_ip = LL + b"\x00\x00\x00\xff\xfe\x00" + p[off:off + 2]; off += 2
            else:
                if mac_dst_ext:
                    dst_ip = LL + Decryptor._iid_from_ext(mac_dst_ext)
                elif mac_dst_short:
                    dst_ip = LL + b"\x00\x00\x00\xff\xfe\x00" + bytes.fromhex(mac_dst_short)
        else:
            off += (0, 8, 2, 0)[dam]

        if off >= len(p):
            return None
        if not nh_compressed:
            return None
        nhc = p[off]
        if (nhc >> 3) != 0b11110:
            return None
        pbits = nhc & 0x3
        off += 1
        if pbits == 3:
            sport = 0xF0B0 | (p[off] >> 4); dport = 0xF0B0 | (p[off] & 0xF); off += 1
        elif pbits == 1:
            sport = struct.unpack(">H", p[off:off + 2])[0]; dport = 0xF000 | p[off + 2]; off += 3
        elif pbits == 2:
            sport = 0xF000 | p[off]; dport = struct.unpack(">H", p[off + 1:off + 3])[0]; off += 3
        else:
            sport, dport = struct.unpack(">HH", p[off:off + 4]); off += 4
        if not (nhc & 0x04):
            off += 2
        return sport, dport, p[off:], src_ip, dst_ip

    # ------------------------------------------------------------------ MLE

    def parse_mle(self, udp_payload: bytes, src_ext_hex: str | None,
                  src_ip: bytes | None = None,
                  dst_ip: bytes | None = None) -> MleInfo | None:
        """Decrypt and parse an MLE message (UDP port 19788).

        MLE's AES-CCM auth data is srcIPv6 || dstIPv6 || security header
        (from the security-control byte through the key identifier), so the
        reconstructed link-local addresses from the 6LoWPAN layer are required
        for secured messages.
        """
        if not udp_payload:
            return None
        suite = udp_payload[0]
        if suite == 255:
            # No security (Discovery Request/Response). Inside a MAC-unsecured
            # frame, so anything on the channel can send one: it is reported
            # by command only, counted apart from the authenticated ones, and
            # teaches nothing (no partition, no leader, no short address).
            if len(udp_payload) < 2:
                return None
            self.stats["mle_unsecured"] += 1
            cmd = udp_payload[1]
            return MleInfo(command=cmd, command_name=MLE_COMMANDS.get(cmd, f"cmd{cmd}"), secured=False)
        elif suite == 0:
            if len(udp_payload) < 11 or not src_ext_hex or not src_ip or not dst_ip:
                return None
            sec_ctl = udp_payload[1]
            sec_level = sec_ctl & 0x07
            key_mode = (sec_ctl >> 3) & 0x03
            counter = struct.unpack("<L", udp_payload[2:6])[0]
            aux = 1 + 4 + (1 if key_mode == 1 else 5 if key_mode == 2 else 9 if key_mode == 3 else 0)
            if key_mode == 0 or len(udp_payload) < 1 + aux + 4:
                # Mode 0 carries no key identifier (the key is implicit,
                # and Thread never sends it on air), so there is no index
                # to search under; and a message shorter than its security
                # header plus the MIC is not one. Neither says anything
                # about the credentials, so neither counts as a failure.
                return None
            nonce = bytes.fromhex(src_ext_hex) + struct.pack(">L", counter) + bytes([sec_level])
            aad = src_ip + dst_ip + udp_payload[1:1 + aux]
            secret = udp_payload[1 + aux:]
            body, used_sequence = None, None
            if key_mode == 2:
                # Thread MLE: the 4-byte key source IS the key sequence.
                sequence = struct.unpack(">L", udp_payload[6:10])[0]
                mle_key, _mac = derive_keys(self.network_key, sequence)
                candidates = [(sequence, mle_key, _mac)]
            else:
                # Modes 1 and 3: the key index is the last byte of the key
                # identifier, after the 8-byte key source in mode 3.
                candidates = self._keys_for_index(udp_payload[aux])
            for seq, mle_key, _mac in candidates:
                try:
                    body = AESCCM(mle_key, tag_length=4).decrypt(nonce, secret, aad)
                except InvalidTag:
                    continue
                # Authenticated under this sequence: the MAC search follows
                # it, and the caller judges the counter within it.
                self.note_key_sequence(seq)
                used_sequence = seq
                break
            if body is None:
                self.stats["mle_failed"] += 1
                return None
        else:
            return None
        if not body:
            return None
        self.stats["mle_decrypted"] += 1
        info = MleInfo(command=body[0], command_name=MLE_COMMANDS.get(body[0], f"cmd{body[0]}"), counter=counter,
                       key_sequence=used_sequence)
        off = 1
        while off + 2 <= len(body):
            t, l = body[off], body[off + 1]
            if l == 255 or off + 2 + l > len(body):
                break
            val = body[off + 2:off + 2 + l]
            if t == 11 and l >= 8:  # Leader Data
                info.partition_id = struct.unpack(">L", val[0:4])[0]
                info.leader_router_id = val[7]
            elif t == 0 and l >= 2:  # Source Address (sender's RLOC16)
                info.source_addr16 = struct.unpack(">H", val[0:2])[0]
            off += 2 + l
        # Learn the short->extended mapping from the sender itself, which
        # unlocks MAC decryption of its short-source data frames.
        if info.source_addr16 is not None and src_ext_hex:
            self.short_to_ext[f"{info.source_addr16:04x}"] = src_ext_hex
        return info

    # ------------------------------------------------------------ SRP names

    @staticmethod
    def harvest_names(udp_payload: bytes) -> list[str]:
        """Pull DNS-style labels (SRP/DNS-SD registrations) out of a decrypted
        UDP payload — a heuristic that surfaces device host/instance names."""
        names = []
        for m in _HOSTNAME_RE.finditer(udp_payload):
            chunk = m.group(0)
            parts, i = [], 0
            while i < len(chunk):
                n = chunk[i]
                label = chunk[i + 1:i + 1 + n]
                if not label or not all(0x20 <= c < 0x7F for c in label):
                    break
                parts.append(label.decode("ascii", "replace"))
                i += 1 + n
            if len(parts) >= 2 and any(len(x) > 2 for x in parts):
                names.append(".".join(parts))
        return names
