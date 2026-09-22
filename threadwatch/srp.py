"""SRP on the air: the 6LoWPAN fragments a registration arrives in, put
back together, and the DNS UPDATE inside read for what it says about the
device that sent it.

A Matter device publishes its host and one ``_matter._tcp`` service per
fabric by SRP (RFC 9665): a DNS UPDATE to the SRP server's anycast
locator. The update is a few hundred bytes, so on air it is three to six
802.15.4 frames: a FRAG1 carrying the compressed IPv6/UDP header and the
first records, then FRAGN frames carrying the rest (RFC 4944). Read one
frame at a time, the recorder saw the header and the host name; the
service instance names, ``<compressed fabric id>-<node id>``, sit further
in. Those names are the device's Matter identity. They survive a reboot,
a firmware update and the new extended address a device may take with
one, which is exactly when the address alone stops naming the device: on
2026-09-22 a climate sensor came back from a firmware update under a new
address, registered the same three service names, and was refused
(YXDOMAIN, the names still belonged to the old address's key); the
warning named an address nobody recognised.
"""
from __future__ import annotations

import re
import struct

# IPv6 (40) + UDP (8): what the FRAGN offsets count that the compressed
# FRAG1 header does not carry as bytes.
UNCOMPRESSED_HEADERS = 48
MAX_DATAGRAM = 1280
OPT_UPDATE_LEASE = 2


def fragment(plain: bytes) -> tuple[str, int, int, int, bytes] | None:
    """(kind, datagram size, tag, offset in bytes, body) for a FRAG1
    ("first") or FRAGN ("next") 6LoWPAN payload, past any mesh header;
    None for a frame that is not a fragment. The body of a FRAG1 is the
    compressed header and the first bytes of the datagram, of a FRAGN the
    next bytes of the uncompressed datagram at ``offset``."""
    p = plain
    if p and (p[0] >> 6) == 0b10:                       # mesh header: originator and final, short
        p = p[1 + (1 if (p[0] & 0x0F) == 0x0F else 0) + 4:]
    if len(p) < 4:
        return None
    size = ((p[0] & 0x07) << 8) | p[1]
    tag = (p[2] << 8) | p[3]
    if (p[0] >> 3) == 0b11000:
        return "first", size, tag, 0, p[4:]
    if (p[0] >> 3) == 0b11100 and len(p) >= 5:
        return "next", size, tag, p[4] * 8, p[5:]
    return None


# A ``_matter._tcp`` instance name as it sits in a DNS message the first
# time it is written out: a 33-byte label, <16 hex>-<16 hex>, then the
# service labels. Later mentions are compression pointers and are not
# matched; one full mention per name is enough.
_INSTANCE_RE = re.compile(rb"\x21([0-9A-Fa-f]{16}-[0-9A-Fa-f]{16})\x07_matter\x04_tcp")


def matter_instances_in(body: bytes, zone: str) -> list[str]:
    """The ``_matter._tcp`` instance names written out in full in a piece
    of a DNS message (one fragment of a registration): what a partial
    registration still says about the device, when the sniffer missed a
    fragment or two. Same form as parse_update's ``instances``."""
    return sorted({f"{m.group(1).decode().lower()}._matter._tcp.{zone}" for m in _INSTANCE_RE.finditer(body)})


class Reassembler:
    """Datagrams under reassembly, keyed by sender and tag. ``add`` takes
    each fragment as it is heard, with the FRAG1's parsed header (what
    Decryptor.udp_ports made of it), and returns that header with the
    whole UDP payload once every byte is in; None until then. A FRAGN
    heard before its FRAG1 has no header to belong to and is dropped,
    as is a datagram left incomplete for HOLD_S: a sniffer misses
    frames, and a table of partial datagrams must not grow with them."""

    HOLD_S = 10.0
    MAX = 64

    def __init__(self) -> None:
        self.pending: dict[tuple[str, int], dict] = {}
        # After add() of a FRAGN that did not complete its datagram: the
        # pending registration it belongs to ({id, zone, dip, pieces}),
        # when the FRAG1 was an SRP request; else None. ``pieces`` are
        # the bytes heard so far, each unbroken run of adjacent fragments
        # joined, so a name split over two fragments is read whole and
        # nothing is read across a hole.
        self.last_update: dict | None = None

    @staticmethod
    def _runs(parts: dict[int, bytes]) -> list[bytes]:
        runs: list[bytes] = []
        pos = None
        for start in sorted(parts):
            if runs and start == pos:
                runs[-1] += parts[start]
            else:
                runs.append(parts[start])
            pos = start + len(parts[start])
        return runs

    def add(self, sender: str, frag: tuple, first: tuple | None, ts: float):
        kind, size, tag, offset, body = frag
        self.last_update = None
        if len(self.pending) >= self.MAX:
            cutoff = ts - self.HOLD_S
            self.pending = {k: v for k, v in self.pending.items() if v["ts"] >= cutoff}
            if len(self.pending) >= self.MAX:
                self.pending.pop(next(iter(self.pending)))
        key = (sender, tag)
        rec = self.pending.get(key)
        if kind == "first":
            if first is None:
                return None
            sport, dport, payload, sip, dip = first
            total = size - UNCOMPRESSED_HEADERS
            if total <= 0 or size > MAX_DATAGRAM:
                return None
            rec = self.pending[key] = {"ts": ts, "size": size, "total": total, "parts": {0: bytes(payload)},
                                       "header": (sport, dport, sip, dip), "update": None}
            if dport == 53 and len(payload) >= 12:
                # An SRP registration: its id and zone sit in the first
                # fragment, so a later fragment can be read for the names
                # it carries even if the whole never arrives (pending).
                flags = struct.unpack(">H", payload[2:4])[0]
                if (flags >> 11) & 0xF == 5 and not flags & 0x8000:
                    try:
                        zone, _ = _name(bytes(payload), 12)
                    except ValueError:
                        zone = None
                    if zone:
                        rec["update"] = {"id": struct.unpack(">H", payload[:2])[0], "zone": zone.lower(),
                                         "dip": dip}
        else:
            if rec is None or rec["size"] != size or ts - rec["ts"] > self.HOLD_S:
                self.pending.pop(key, None)
                return None
            start = offset - UNCOMPRESSED_HEADERS
            if start < 0:
                return None
            rec["parts"][start] = bytes(body)
            rec["ts"] = ts
        if kind == "next" and rec["update"] is not None:
            self.last_update = dict(rec["update"], pieces=self._runs(rec["parts"]))
        pos = 0
        for start in sorted(rec["parts"]):
            if start != pos:
                return None                             # a hole: not yet, or never
            pos += len(rec["parts"][start])
        if pos < rec["total"]:
            return None
        del self.pending[key]
        sport, dport, sip, dip = rec["header"]
        payload = b"".join(rec["parts"][s] for s in sorted(rec["parts"]))[:rec["total"]]
        return sport, dport, payload, sip, dip


# ------------------------------------------------------------- DNS UPDATE

def _name(msg: bytes, off: int) -> tuple[str, int]:
    """A DNS name at ``off``, compression followed; returns it and the
    offset past it (past the pointer, when the name ended in one)."""
    labels: list[str] = []
    end = None
    hops = 0
    while True:
        if off >= len(msg):
            raise ValueError("name runs past the message")
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise ValueError("truncated pointer")
            target = ((n & 0x3F) << 8) | msg[off + 1]
            if end is None:
                end = off + 2
            hops += 1
            if hops > 64 or target >= off:
                raise ValueError("pointer loop")
            off = target
            continue
        if n & 0xC0:
            raise ValueError("bad label length")
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels), (end if end is not None else off)


def _rr(msg: bytes, off: int) -> tuple[str, int, int, int, int]:
    """(owner, type, rdata offset, rdata length, offset past the record)."""
    owner, off = _name(msg, off)
    if off + 10 > len(msg):
        raise ValueError("truncated record")
    rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
    off += 10
    if off + rdlen > len(msg):
        raise ValueError("truncated rdata")
    return owner, rtype, off, rdlen, off + rdlen


def parse_update(payload: bytes) -> dict | None:
    """What an SRP registration (a DNS UPDATE request) says: ``host`` (the
    registered host name, first label only: the rest is the zone),
    ``instances`` (the owner names of its ``_matter._tcp`` SRV records,
    lower-cased, in full), ``lease`` and ``key_lease`` (seconds, from the
    Update Lease option; None when absent). None for anything that is not
    a well-formed UPDATE request. Records the recorder has no use for
    (KEY, TXT, PTR, SIG) are stepped over, not understood."""
    if len(payload) < 12:
        return None
    dns_id, flags, zones, prereqs, updates, extras = struct.unpack(">6H", payload[:12])
    if (flags >> 11) & 0xF != 5 or flags & 0x8000:
        return None
    try:
        off = 12
        zone = None
        for _ in range(zones):
            name, off = _name(payload, off)
            off += 4
            zone = zone if zone is not None else name.lower()
        for _ in range(prereqs):
            _owner, _t, _r, _n, off = _rr(payload, off)
        host = None
        instances: set[str] = set()
        for _ in range(updates):
            owner, rtype, rd, rdlen, off = _rr(payload, off)
            lower = owner.lower()
            if rtype == 33 and "._matter._tcp." in lower:              # SRV: an operational service
                instances.add(lower)
                target, _ = _name(payload, rd + 6)
                host = host or target.split(".")[0] or None
            elif rtype in (28, 25) and host is None:                    # AAAA, KEY: the host itself
                if zone is None or lower.endswith("." + zone):
                    host = owner.split(".")[0] or None
        lease = key_lease = None
        for _ in range(extras):
            owner, rtype, rd, rdlen, off = _rr(payload, off)
            if rtype != 41:                                             # OPT
                continue
            o = rd
            while o + 4 <= rd + rdlen:
                code, n = struct.unpack(">HH", payload[o:o + 4])
                data = payload[o + 4:o + 4 + n]
                o += 4 + n
                if code == OPT_UPDATE_LEASE and len(data) >= 4:
                    lease = struct.unpack(">I", data[:4])[0]
                    if len(data) >= 8:
                        key_lease = struct.unpack(">I", data[4:8])[0]
    except (ValueError, struct.error):
        return None
    return {"id": dns_id, "zone": zone, "host": host, "instances": sorted(instances),
            "lease": lease, "key_lease": key_lease}
