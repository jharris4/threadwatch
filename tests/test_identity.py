"""Short-address identity resolution via the MAC nonce (needs `cryptography`)."""

import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.config import Config  # noqa: E402
from threadwatch.events import NullEventLog  # noqa: E402
from threadwatch.pcap import parse_frame  # noqa: E402
from threadwatch.pipeline import Pipeline  # noqa: E402

# cryptography is required, not optional: load_decryptor raises without it,
# doctor.check_credentials is a hard FAIL, and setup-host.sh aborts on the
# same import. These used to be guarded by "skip if AESCCM is None", which
# could never fire - three other test modules import the package at module
# scope, so a run without it is three collection errors before any guard
# is read - and the guards suggested a configuration nobody tests.
from cryptography.hazmat.primitives.ciphers.aead import AESCCM  # noqa: E402
from threadwatch.crypto import Decryptor, derive_keys  # noqa: E402

KEY = bytes(range(16))
SED = "029a47566a00b543"
OTHER = "d20bfcd1a12f625d"
PAN = 0x4e21


def secured_frame(src_ext: str, src_short: str, counter: int, ftype: int = 1,
                  payload: bytes = b"\x7f\x33\xf0\x11\x22", sequence: int = 0,
                  pan: int = PAN, key: bytes = KEY) -> bytes:
    """An 802.15.4 frame with short source addressing, secured as Thread does
    (ENC-MIC-32, key index mode) under a key sequence, plus a trailing FCS.
    ftype 3 builds a data request: the command id (0x04) is authenticated
    but not encrypted, and the encrypted payload is empty. Another PAN and
    network key make a neighbour's frame."""
    fcf = ftype | 0x0008 | 0x0040 | (2 << 10) | (1 << 12) | (2 << 14)
    header = struct.pack("<HBH", fcf, counter & 0xFF, pan) + bytes.fromhex("00cc")[::-1] \
        + bytes.fromhex(src_short)[::-1]
    aux = bytes([0x0D]) + struct.pack("<L", counter) + bytes([(sequence & 0x7f) + 1])   # level 5, key mode 1
    open_part = header + aux + (b"\x04" if ftype == 3 else b"")
    if ftype == 3:
        payload = b""
    _mle, mac_key = derive_keys(key, sequence)
    nonce = bytes.fromhex(src_ext) + struct.pack(">L", counter) + bytes([5])
    body = AESCCM(mac_key, tag_length=4).encrypt(nonce, payload, open_part)
    return open_part + body + b"\x00\x00"


def mle_message(src_ext: str, sequence: int, counter: int, src_ip: bytes, dst_ip: bytes,
                body: bytes) -> bytes:
    """A secured MLE message (UDP payload) as Thread sends it: security suite
    0, key id mode 2, whose key source is the key sequence itself."""
    aux = bytes([5 | (2 << 3)]) + struct.pack("<L", counter) + struct.pack(">L", sequence) \
        + bytes([(sequence & 0x7f) + 1])
    mle_key, _mac = derive_keys(KEY, sequence)
    nonce = bytes.fromhex(src_ext) + struct.pack(">L", counter) + bytes([5])
    return bytes([0]) + aux + AESCCM(mle_key, tag_length=4).encrypt(nonce, body, src_ip + dst_ip + aux)


class KeySequenceTest(unittest.TestCase):
    """The key sequence climbs with every rotation; the search must follow."""

    def _decrypts(self, d, sequence, counter=1):
        return d.decrypt_frame(secured_frame(SED, "c829", counter, sequence=sequence), SED, None) is not None

    def test_a_high_sequence_decrypts_once_the_sequence_is_known(self):
        d = Decryptor(network_key=KEY)
        for seq in (0, 84, 1015):                        # the first eight generations: found cold
            self.assertTrue(self._decrypts(Decryptor(network_key=KEY), seq), seq)
        self.assertFalse(self._decrypts(d, 1031))        # the ninth generation of key index 8: not searched cold
        self.assertFalse(self._decrypts(d, 5000))
        d.note_key_sequence(4999)                        # ...until something says where the network is
        self.assertTrue(self._decrypts(d, 5000))
        self.assertTrue(self._decrypts(d, 4998))         # a straggler on an older key still reads
        self.assertFalse(self._decrypts(d, 5000 + 128 * 3))   # too far to be this network's next key
        self.assertEqual(d.key_sequence, 5000)

    def test_rotations_are_followed_past_the_initial_search(self):
        d = Decryptor(network_key=KEY)
        self.assertTrue(self._decrypts(d, 1015))         # generation 7 of key index 120: found cold
        self.assertEqual(d.key_sequence, 1015)
        for seq in range(1016, 1016 + 400):              # then one rotation at a time, well past 1023
            self.assertTrue(self._decrypts(d, seq), seq)
        self.assertEqual(d.key_sequence, 1415)
        self.assertEqual(d.stats["mac_failed"], 0)

    def test_key_index_wraps_at_128_as_openthread_derives_it(self):
        # OpenThread: key index = (sequence & 0x7f) + 1, so sequence 127 is
        # index 128 and 128 is index 1 again. Read mod 127, every sequence
        # from 127 on maps to the wrong index and nothing decrypts again.
        for seq in (126, 127, 128, 200, 255, 256):
            self.assertTrue(self._decrypts(Decryptor(network_key=KEY), seq), seq)
        d = Decryptor(network_key=KEY)
        d.note_key_sequence(126)
        for seq in (127, 128, 129):
            self.assertTrue(self._decrypts(d, seq), seq)
        self.assertEqual(d.key_sequence, 129)
        self.assertEqual(d.stats["mac_failed"], 0)

    def test_mle_key_source_teaches_the_mac_search(self):
        d = Decryptor(network_key=KEY)
        src_ip = bytes.fromhex("fe80000000000000") + bytes([0x02 ^ int(SED[:2], 16)]) + bytes.fromhex(SED[2:])
        dst_ip = bytes.fromhex("ff020000000000000000000000000001")
        body = b"\x04" + b"\x00\x02" + bytes.fromhex("c829")     # Advertisement, Source Address c829
        info = d.parse_mle(mle_message(SED, 5000, 9, src_ip, dst_ip, body), SED, src_ip, dst_ip)
        self.assertEqual((info.command_name, info.source_addr16), ("Advertisement", 0xc829))
        self.assertEqual(d.key_sequence, 5000)
        self.assertEqual(d.short_to_ext["c829"], SED)
        # The sleepy device's short-source data frame under the same key now reads.
        self.assertIsNotNone(d.decrypt_frame(secured_frame(SED, "c829", 10, sequence=5000), None, "c829"))
        self.assertEqual(d.stats["mac_decrypted"], 1)
        self.assertEqual(d._keys_for_index(0), [])         # an index Thread never uses: nothing to try


class UnsupportedSecurityTest(unittest.TestCase):
    def test_frames_secured_some_other_way_are_counted_not_dropped_silently(self):
        # The aux header of secured_frame's output starts at byte 9
        # (0x0D: level 5, key id mode 1). Key id mode 2, a level other
        # than 5, and an aux header cut short are all refused before any
        # key is tried, and each shows in the counters.
        d = Decryptor(network_key=KEY)
        frame = bytearray(secured_frame(SED, "c829", 1))
        mode2 = bytes(frame[:9]) + bytes([5 | (2 << 3)]) + bytes(frame[10:])
        level4 = bytes(frame[:9]) + bytes([4 | (1 << 3)]) + bytes(frame[10:])
        cut = bytes(frame[:11])
        for psdu in (mode2, level4, cut):
            self.assertIsNone(d.decrypt_frame(psdu, SED, None))
        self.assertEqual(d.stats["mac_unsupported"], 3)
        self.assertEqual((d.stats["mac_decrypted"], d.stats["mac_failed"], d.stats["plaintext"]), (0, 0, 0))
        self.assertIsNotNone(d.decrypt_frame(bytes(frame), SED, None))    # the real one still reads
        self.assertEqual(d.stats["mac_decrypted"], 1)


class ResolveShortTest(unittest.TestCase):
    def test_resolver_identifies_sender_and_caches(self):
        d = Decryptor(network_key=KEY)
        psdu = secured_frame(SED, "c829", 7)
        self.assertIsNone(d.decrypt_frame(psdu, None, "c829"))
        self.assertEqual(d.resolve_short(psdu, "c829", [OTHER, SED]), SED)
        self.assertEqual(d.short_to_ext["c829"], SED)
        self.assertIsNotNone(d.decrypt_frame(secured_frame(SED, "c829", 8), None, "c829"))
        self.assertEqual(d.decrypt_frame(secured_frame(SED, "c829", 9, ftype=3), None, "c829"), b"")
        self.assertEqual(len(secured_frame(SED, "c829", 9, ftype=3)), 22)   # 20 on air + FCS
        self.assertIsNone(d.resolve_short(secured_frame("1111111111111111", "c82b", 1), "c82b", [OTHER, SED]))
        self.assertEqual(d.stats["short_resolved"], 1)
        self.assertEqual(d.stats["short_unresolved"], 1)

    def test_pipeline_attributes_short_source_frames_to_the_device(self):
        with tempfile.TemporaryDirectory() as tmp:
            dd = Path(tmp)
            (dd / "devices.json").write_text(json.dumps([
                {"name": "Front Door", "extendedAddress": SED.upper(), "threadRole": "sleepy-end-device"},
                {"name": "Living Room Motion", "extendedAddress": OTHER, "threadRole": "sleepy-end-device"},
            ]))
            cfg = Config(data_dir=dd / "data", devices_path=dd / "devices.json")
            pipe = Pipeline(cfg, NullEventLog(), Decryptor(network_key=KEY))
            t0 = 1_700_000_000.0
            for i in range(5):   # polls (MAC command frames) from the short address only
                pipe.ingest(parse_frame(t0 + i, secured_frame(SED, "c829", 100 + i, ftype=3), 195))
            self.assertIn(SED, pipe.seen.table)
            self.assertEqual(pipe.seen.table[SED]["types"], {"3": 5})
            self.assertEqual(pipe.devices[SED].polls, 5)
            self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_first_seen"], [SED])
            pipe.periodic(t0 + 91 * 60)
            quiet = [(r["addr"], r["name"]) for r in pipe.events.records if r["event"] == "device_quiet"]
            self.assertEqual(quiet, [(SED, "Front Door")])
            pipe.ingest(parse_frame(t0 + 92 * 60, secured_frame(SED, "c829", 200, ftype=3), 195))
            self.assertEqual(pipe.events.records[-1]["event"], "device_returned")
            # The short address is remembered with the row, and seeds the next run.
            self.assertEqual(pipe.seen.table[SED]["rloc16"], "c829")
            self.assertEqual(pipe.seen.table[SED]["rloc16_ts"], t0 + 92 * 60)
            pipe.seen.save()
            pipe2 = Pipeline(cfg, NullEventLog(), Decryptor(network_key=KEY))
            self.assertEqual(pipe2.decryptor.short_to_ext, {"c829": SED})
            pipe2.ingest(parse_frame(t0 + 93 * 60, secured_frame(SED, "c829", 201, ftype=3), 195))
            self.assertEqual(pipe2.decryptor.stats["short_resolved"], 0)   # no search needed
            self.assertEqual(pipe2.devices[SED].polls, 1)

    def test_reassigned_short_address_moves_to_its_new_holder(self):
        with tempfile.TemporaryDirectory() as tmp:
            dd = Path(tmp)
            (dd / "devices.json").write_text(json.dumps([
                {"name": "A", "extendedAddress": SED}, {"name": "B", "extendedAddress": OTHER},
            ]))
            cfg = Config(data_dir=dd / "data", devices_path=dd / "devices.json")
            pipe = Pipeline(cfg, NullEventLog(), Decryptor(network_key=KEY))
            t0 = 1_700_000_000.0
            for i in range(3):
                pipe.ingest(parse_frame(t0 + i, secured_frame(SED, "c829", i, ftype=3), 195))
            # A dies; its parent restarts and hands c829 to B.
            for i in range(3):
                pipe.ingest(parse_frame(t0 + 40 + i, secured_frame(OTHER, "c829", 500 + i, ftype=3), 195))
            self.assertEqual(pipe.decryptor.short_to_ext["c829"], OTHER)
            self.assertEqual((pipe.devices[SED].polls, pipe.devices[OTHER].polls), (3, 3))
            self.assertEqual((pipe.seen.table[SED]["rloc16"], pipe.seen.table[OTHER]["rloc16"]), ("c829", "c829"))
            self.assertLess(pipe.seen.table[SED]["rloc16_ts"], pipe.seen.table[OTHER]["rloc16_ts"])
            self.assertEqual(pipe.seen.table[SED]["last_seen"], t0 + 2)

    def test_a_neighbours_frame_sharing_a_short_address_is_not_our_device(self):
        # Short addresses are unique per PAN. With the local mapping for
        # c829 verified and inside its re-check cooldown, a frame from
        # another PAN (another network key) using c829 used to be handed
        # the cached identity: the local row took the foreign PAN, its
        # quiet checks stopped, and the neighbour's frames counted as its.
        with tempfile.TemporaryDirectory() as tmp:
            dd = Path(tmp)
            (dd / "devices.json").write_text(json.dumps([{"name": "Front Door", "extendedAddress": SED}]))
            cfg = Config(data_dir=dd / "data", devices_path=dd / "devices.json")
            cfg.pan_id = PAN
            pipe = Pipeline(cfg, NullEventLog(), Decryptor(network_key=KEY))
            t0 = 1_700_000_000.0
            self.assertEqual(pipe.ingest(parse_frame(t0, secured_frame(SED, "c829", 1, ftype=3), 195)), SED)
            self.assertEqual(pipe.ingest(parse_frame(t0 + 1, secured_frame(SED, "c829", 2, ftype=3), 195)), SED)
            self.assertLess(t0 + 2, pipe._verify_after["c829"])           # the cooldown fast path is open
            foreign = bytes(range(16, 32))
            for i in range(20):
                who = pipe.ingest(parse_frame(t0 + 2 + i, secured_frame(OTHER, "c829", 900 + i, ftype=3,
                                                                        pan=0x58bc, key=foreign), 195))
                self.assertIsNone(who)
            row = pipe.seen.table[SED]
            self.assertEqual((row["pan"], row["frames"], row["last_seen"]), (PAN, 2, t0 + 1))
            self.assertEqual(pipe.devices[SED].polls, 2)
            self.assertEqual(pipe.decryptor.short_to_ext, {"c829": SED})   # the local mapping survives
            self.assertLessEqual(pipe.decryptor.stats["mac_failed"], 1)    # one MIC check per 30 s, not per frame
            pipe.periodic(t0 + 2000)
            self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"], [SED])
            # The device itself moving to another PAN still passes the MIC
            # check and is followed there.
            self.assertEqual(pipe.ingest(parse_frame(t0 + 2100, secured_frame(SED, "c829", 3, ftype=3, pan=0x58bc),
                                                     195)), SED)
            self.assertEqual(pipe.seen.table[SED]["pan"], 0x58bc)

    def test_truncated_unsecured_plaintext_does_not_crash_ingest(self):
        with tempfile.TemporaryDirectory() as tmp:
            dd = Path(tmp)
            cfg = Config(data_dir=dd / "data")
            dec = Decryptor(network_key=KEY)
            pipe = Pipeline(cfg, NullEventLog(), dec)
            fcf = 1 | 0x0040 | (2 << 10) | (1 << 12) | (3 << 14)      # unsecured data, ext source
            for payload in (b"\x7f\x33\xf0", b"\x7f\x33\xf3", b"\x7f\x33\xf1\x12"):
                psdu = struct.pack("<HBH", fcf, 1, PAN) + bytes.fromhex("00cc")[::-1] \
                    + bytes.fromhex(SED)[::-1] + payload   # no FCS, as the sniffer delivers them
                pipe.ingest(parse_frame(1.0, psdu, 230))
            self.assertEqual(dec.stats["parse_failed"], 3)

    def test_extra_candidates_resolve_a_device_missing_from_the_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(data_dir=Path(tmp) / "data")          # no devices.json at all
            pipe = Pipeline(cfg, NullEventLog(), Decryptor(network_key=KEY), ephemeral=True)
            pipe.extra_candidates = [SED]
            f = parse_frame(1.0, secured_frame(SED, "c829", 3, ftype=3), 195)
            self.assertEqual(pipe.identity(f), SED)

    def test_the_nonce_search_is_bounded_in_candidates_and_in_trials(self):
        # The candidate set was the whole last-seen table, which anything
        # in range can grow (a forged extended address per frame), and the
        # only rate limit was per short address, of which there are 65,536:
        # a flood of unmappable short sources cost O(table) AES-CCM per
        # frame on the capture thread until the ring dropped frames.
        with tempfile.TemporaryDirectory() as tmp:
            dd = Path(tmp)
            (dd / "devices.json").write_text(json.dumps([{"name": "x", "extendedAddress": OTHER}]))
            cfg = Config(data_dir=dd / "data", devices_path=dd / "devices.json")
            dec = Decryptor(network_key=KEY)
            pipe = Pipeline(cfg, NullEventLog(), dec)
            t0 = 1_700_000_000.0
            for n in range(1000):                                      # a thousand addresses heard once
                addr = f"{0x3000000000000000 + n:016x}"
                pipe.ingest(parse_frame(t0 + n * 0.001, secured_ext_frame(addr, 1, b"\x7f\x33"), 195))
            for i in range(5):                                         # and the real device, five times
                pipe.ingest(parse_frame(t0 + 2 + i, secured_ext_frame(SED, 1 + i, b"\x7f\x33"), 195))
            self.assertEqual(len(pipe.seen.table), 1001)
            # One unmappable short source: the inventory and the most-heard
            # rows are tried, the device is found, and the thousand
            # once-heard addresses were never in the running.
            self.assertEqual(pipe.ingest(parse_frame(t0 + 10, secured_frame(SED, "c829", 1), 195)), SED)
            self.assertLessEqual(dec.stats["short_candidates_tried"], Pipeline.RESOLVE_CANDIDATES_MAX + 1)
            candidates = pipe._resolve_candidates(t0 + 10)
            self.assertEqual(candidates[:2], [OTHER, SED])
            self.assertLessEqual(len(candidates), Pipeline.RESOLVE_CANDIDATES_MAX + 1)
            # A flood of forged short sources under a foreign key: the
            # searches draw on one budget, so the trials stop growing with
            # the flood, and every short address is not a fresh search.
            foreign = bytes(range(16, 32))
            before = dec.stats["short_candidates_tried"]
            for n in range(5000):
                psdu = secured_frame(OTHER, f"{0x1000 + n:04x}", n, key=foreign)
                pipe.ingest(parse_frame(t0 + 20 + n * 0.002, psdu, 195))   # 10 s of frames
            spent = dec.stats["short_candidates_tried"] - before
            self.assertLessEqual(spent, Pipeline.RESOLVE_TRIALS_BURST + 10 * Pipeline.RESOLVE_TRIALS_PER_S + 300)
            self.assertLess(dec.stats["short_unresolved"], 5000)
            # A short address that found nobody backs off further each
            # time: 30 s after the first search, then 60, 120 ... to 30 min.
            self.assertEqual(pipe._resolve_after["1000"], t0 + 20 + 30)
            waits = []
            for t in (t0 + 60, t0 + 130, t0 + 300, t0 + 700, t0 + 2000, t0 + 4000):
                pipe._resolve_tokens = Pipeline.RESOLVE_TRIALS_BURST
                pipe.ingest(parse_frame(t, secured_frame(OTHER, "1000", 9000, key=foreign), 195))
                waits.append(pipe._resolve_after["1000"] - t)
            self.assertEqual(waits, [60, 120, 240, 480, 960, 1800])
            # Success clears the backoff; a neighbour's PAN is not searched at all.
            self.assertNotIn("c829", pipe._resolve_fails)
            before = dec.stats["short_candidates_tried"]
            pipe._resolve_tokens = Pipeline.RESOLVE_TRIALS_BURST
            pipe.ingest(parse_frame(t0 + 5000, secured_frame(OTHER, "abcd", 1, pan=0x58bc, key=foreign), 195))
            self.assertEqual(dec.stats["short_candidates_tried"], before)

    def test_a_malformed_address_in_last_seen_does_not_crash_the_capture_loop(self):
        # The inventory's addresses are checked before they reach the
        # nonce search; the table's keys were not, and bytes.fromhex on a
        # "0x" prefix raised in ingest, outside every except, on the next
        # secured short-source frame: a crash loop, since the key was on
        # disk. Colons and case are forgiven, the rest is dropped and said.
        import contextlib, io
        with tempfile.TemporaryDirectory() as tmp:
            dd = Path(tmp)
            cfg = Config(data_dir=dd / "data")
            cfg.state_dir.mkdir(parents=True, exist_ok=True)
            t0 = 1_700_000_000.0
            row = lambda: {"first_seen": t0, "last_seen": t0, "frames": 3, "types": {}}
            (cfg.state_dir / "last-seen.json").write_text(json.dumps({
                "0x" + OTHER: row(), "02:9a:47:56:6a:00:b5:43": row(), "d20bfcd1-a12f-625d": row(),
                "not an address": row(), OTHER.upper(): row(), "": row()}))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                dec = Decryptor(network_key=KEY)
                pipe = Pipeline(cfg, NullEventLog(), dec)
            self.assertEqual(sorted(pipe.seen.table), sorted([SED, OTHER]))
            for bad in ("'0x" + OTHER + "'", "'d20bfcd1-a12f-625d'", "'not an address'", "''"):
                self.assertIn(f"last-seen.json: dropping row {bad}: not 16 hex digits", out.getvalue())
            # The kept rows are candidates; a secured poll from the colon-form
            # device resolves, and nothing raised on the way.
            self.assertEqual(pipe.ingest(parse_frame(t0 + 10, secured_frame(SED, "c829", 1, ftype=3), 195)), SED)
            # And the decryptor itself shrugs at a bad candidate, should one reach it.
            self.assertIsNone(dec.resolve_short(secured_frame(SED, "c82a", 2), "c82a", ["0x" + SED, "abc", SED[:14]]))
            self.assertEqual(dec.resolve_short(secured_frame(SED, "c82a", 3), "c82a", ["zz", SED]), SED)

    def test_unresolvable_short_is_retried_only_after_backoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            dd = Path(tmp)
            (dd / "devices.json").write_text(json.dumps([{"name": "x", "extendedAddress": OTHER}]))
            cfg = Config(data_dir=dd / "data", devices_path=dd / "devices.json")
            dec = Decryptor(network_key=KEY)
            pipe = Pipeline(cfg, NullEventLog(), dec)
            t0 = 1_700_000_000.0
            for i in range(10):
                pipe.ingest(parse_frame(t0 + i, secured_frame(SED, "c829", i), 195))
            self.assertEqual(dec.stats["short_unresolved"], 1)
            pipe.ingest(parse_frame(t0 + 31, secured_frame(SED, "c829", 99), 195))
            self.assertEqual(dec.stats["short_unresolved"], 2)
            self.assertEqual(pipe.seen.table, {})


if __name__ == "__main__":
    unittest.main()


def secured_ext_frame(src_ext: str, counter: int, payload: bytes, sequence: int = 0,
                      dst_short: str = "0000") -> bytes:
    """The same Thread security, from an extended source address: how a device
    talks while it is attaching, and the only form whose IPv6 source the
    6LoWPAN layer can reconstruct for MLE."""
    fcf = 1 | 0x0008 | 0x0040 | (2 << 10) | (1 << 12) | (3 << 14)
    header = struct.pack("<HBH", fcf, counter & 0xFF, PAN) + bytes.fromhex(dst_short)[::-1] \
        + bytes.fromhex(src_ext)[::-1]
    aux = bytes([0x0D]) + struct.pack("<L", counter) + bytes([(sequence & 0x7f) + 1])
    open_part = header + aux
    _mle, mac_key = derive_keys(KEY, sequence)
    nonce = bytes.fromhex(src_ext) + struct.pack(">L", counter) + bytes([5])
    return open_part + AESCCM(mac_key, tag_length=4).encrypt(nonce, payload, open_part) + b"\x00\x00"


def lowpan_udp(sport: int, dport: int, payload: bytes) -> bytes:
    """A 6LoWPAN IPHC + UDP-NHC packet in the form Thread puts on air: traffic
    class and flow label elided, hop limit 64, source address elided (derived
    from the MAC extended source) and destination the 8-bit multicast form."""
    iphc = (0b011 << 13) | (3 << 11) | (1 << 10) | (2 << 8) | (3 << 4) | (1 << 3) | 3
    return (struct.pack(">H", iphc) + b"\x01"        # ff02::1
            + b"\xf0" + struct.pack(">HH", sport, dport) + b"\x00\x00" + payload)


LINK_LOCAL = bytes.fromhex("fe80000000000000")
ALL_NODES = bytes.fromhex("ff020000000000000000000000000001")


class SixLowpanTest(unittest.TestCase):
    """`udp_ports` is the only way into the MLE layer: no rejoin events, no
    partition detection and no leader without it."""

    def test_elided_addresses_are_reconstructed_from_the_mac_header(self):
        r = Decryptor.udp_ports(lowpan_udp(19788, 19788, b"\xff\x09"), mac_src_ext=SED)
        sport, dport, payload, src_ip, dst_ip = r
        self.assertEqual((sport, dport, payload), (19788, 19788, b"\xff\x09"))
        self.assertEqual(src_ip, LINK_LOCAL + Decryptor._iid_from_ext(SED))
        self.assertEqual(dst_ip, ALL_NODES)

    def test_the_iid_flips_the_universal_local_bit(self):
        self.assertEqual(Decryptor._iid_from_ext(SED).hex(), "009a47566a00b543")
        self.assertEqual(Decryptor._iid_from_ext("009a47566a00b543").hex(), SED)

    def test_a_short_destination_becomes_its_link_local_address(self):
        iphc = (0b011 << 13) | (3 << 11) | (1 << 10) | (2 << 8) | (3 << 4) | 3   # unicast, dst elided
        pkt = struct.pack(">H", iphc) + b"\xf0" + struct.pack(">HH", 19788, 19788) + b"\x00\x00" + b"\xff\x09"
        r = Decryptor.udp_ports(pkt, mac_src_ext=SED, mac_dst_short="c829")
        self.assertEqual(r[4], LINK_LOCAL + bytes.fromhex("000000fffe00c829"))

    def test_later_fragments_and_non_iphc_payloads_are_declined(self):
        self.assertIsNone(Decryptor.udp_ports(b"\xe0\x00\x00\x00" + lowpan_udp(19788, 19788, b"\xff")))
        self.assertIsNone(Decryptor.udp_ports(b"\x00\x01\x02\x03"))
        self.assertIsNone(Decryptor.udp_ports(b""))


class HarvestNamesTest(unittest.TestCase):
    def test_dns_labels_are_pulled_out_of_a_registration(self):
        payload = b"\x00\x06\x00\x00" + b"\x0dthreadwatch-1\x05local\x00"
        self.assertEqual(Decryptor.harvest_names(payload), ["threadwatch-1.local"])

    def test_a_single_label_or_binary_noise_yields_nothing(self):
        self.assertEqual(Decryptor.harvest_names(b"\x05local\x00"), [])
        self.assertEqual(Decryptor.harvest_names(bytes(range(0, 32)) * 4), [])


class MleThroughThePipelineTest(unittest.TestCase):
    """Frame -> MAC decryption -> 6LoWPAN -> MLE, as the live pipeline runs
    it: the path that answers "did it try to rejoin?"."""

    def _pipe(self, d):
        cfg = Config(data_dir=Path(d) / "data")
        return Pipeline(cfg, NullEventLog(), Decryptor(network_key=KEY), ephemeral=True)

    @staticmethod
    def _mle_frame(ts, body, counter, sequence=0):
        src_ip = LINK_LOCAL + Decryptor._iid_from_ext(SED)
        msg = mle_message(SED, sequence, counter, src_ip, ALL_NODES, body)
        return parse_frame(ts, secured_ext_frame(SED, counter, lowpan_udp(19788, 19788, msg), sequence), 195)

    @staticmethod
    def _leader_data(partition_id, router_id):
        return bytes([11, 8]) + struct.pack(">L", partition_id) + b"\x00\x00\x00" + bytes([router_id])

    def test_mle_without_a_key_identifier_or_cut_short_is_refused_not_a_crash(self):
        # Key id mode 0 names no key: there is no index byte to read, and
        # the byte at that offset is the frame counter's high byte. Mode 3
        # puts the index 14 bytes in; a message cut before it must not
        # raise. Neither is Thread traffic, so neither counts as a failure.
        d = Decryptor(network_key=KEY)
        src_ip = LINK_LOCAL + Decryptor._iid_from_ext(SED)
        mode0 = bytes([0, 5 | (0 << 3)]) + struct.pack("<L", 0x01FFFFFF) + b"\x00" * 8
        self.assertIsNone(d.parse_mle(mode0, SED, src_ip, ALL_NODES))
        mode3 = bytes([0, 5 | (3 << 3)]) + struct.pack("<L", 7) + b"\x00" * 6
        self.assertIsNone(d.parse_mle(mode3, SED, src_ip, ALL_NODES))
        self.assertEqual(d.stats["mle_failed"], 0)

    def test_rejoin_partition_and_leader_are_learned_from_mle(self):
        with tempfile.TemporaryDirectory() as d:
            pipe = self._pipe(d)
            t = 1_700_000_000.0
            # An advertisement: partition, leader router id and the sender's RLOC16.
            pipe.ingest(self._mle_frame(t, b"\x04" + self._leader_data(0x3a2b1c0d, 60)
                                        + bytes([0, 2]) + bytes.fromhex("c829"), 1))
            self.assertEqual(pipe.partition_status()["id"], 0x3a2b1c0d)
            self.assertEqual(pipe.partition_status()["leader_router"], 60)
            self.assertEqual(pipe.decryptor.short_to_ext["c829"], SED)
            self.assertEqual(pipe.decryptor.stats["mle_decrypted"], 1)
            # Then it loses its parent and asks for a new one.
            pipe.ingest(self._mle_frame(t + 60, b"\x09", 2))
            ev = [r for r in pipe.events.records if r["event"] == "mle_rejoin_attempt"]
            self.assertEqual([(e["command"], e["addr"]) for e in ev], [("Parent Request", SED)])
            self.assertIn("trying to get back", ev[0]["note"])
            # ...and comes back in a different partition.
            pipe.ingest(self._mle_frame(t + 120, b"\x04" + self._leader_data(0x51119999, 11), 3))
            chg = [r for r in pipe.events.records if r["event"] == "partition_or_leader_change"]
            self.assertEqual(len(chg), 1)
            self.assertEqual((chg[0]["previous"]["partition"], chg[0]["current"]["partition"]),
                             (0x3a2b1c0d, 0x51119999))
            self.assertEqual(pipe.partition_status()["leader_router"], 11)

    def test_a_service_registration_teaches_the_device_a_name(self):
        with tempfile.TemporaryDirectory() as d:
            pipe = self._pipe(d)
            srp = lowpan_udp(49152, 53, b"\x00\x06\x00\x00\x0dthreadwatch-1\x05local\x00")
            pipe.ingest(parse_frame(1_700_000_000.0, secured_ext_frame(SED, 4, srp), 195))
            self.assertEqual(pipe.observed_names, {SED: {"threadwatch-1.local": 1}})


class ThreadKeyScheduleTest(unittest.TestCase):
    """`derive_keys` against a frame decrypted by something that is not us.

    Every other crypto test here is a round trip through `derive_keys`, so
    it would hold just as well with the two halves of the hash swapped - and
    a recorder that swapped them decrypts nothing on a real mesh.

    Provenance of the vector below: the frame was built under the public
    OpenThread default network key 00112233445566778899aabbccddeeff (never
    the network's own key) and handed to Wireshark 4.6.5, configured with
    only that network key as a "Thread hash" entry in the 802.15.4 key table
    and thr_seq_ctr 00000000, so Wireshark derived the MAC key with its own
    implementation of the Thread key schedule. It reported exactly the
    plaintext asserted here. The same frame with the halves swapped it
    rejected: "No encryption key set - can't decrypt". Both implementations
    that publish the split agree - Wireshark's packet-thread.c copies "upper
    hashed bytes to the MAC key" and the lower to the MLE key, and
    OpenThread's key_manager.hpp lays HashKeys out as {Mle::Key; Mac::Key}.
    """

    NETWORK_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
    SRC_EXT = "0a1b2c3d4e5f6071"
    # 802.15.4 data frame, ENC-MIC-32, key id mode 1, key index 1, sequence 0
    FRAME = bytes.fromhex("49d807cefa000071605f4e3d2c1b0a0d07000000"
                          "01978d2892f9e12ac96a5e136fbda65d9b")
    # what Wireshark printed as "Decrypted IEEE 802.15.4 payload (12 bytes)"
    PLAINTEXT = bytes.fromhex("7e3b01f04d4c4d4c0000ff0f")

    def test_the_frame_wireshark_decrypted_decrypts_here_too(self):
        d = Decryptor(network_key=self.NETWORK_KEY)
        self.assertEqual(d.decrypt_frame(self.FRAME, self.SRC_EXT, None), self.PLAINTEXT)
        self.assertEqual(d.key_sequence, 0)

    def test_the_mle_half_is_not_the_mac_half(self):
        mle_key, mac_key = derive_keys(self.NETWORK_KEY, 0)
        self.assertNotEqual(mle_key, mac_key)
        # The frame above is authenticated under the MAC key. Reading the
        # halves the other way round fails the MIC, exactly as Wireshark did.
        swapped = Decryptor(network_key=self.NETWORK_KEY)
        swapped._keys_by_index[1] = (None, [(0, mac_key, mle_key)])
        self.assertIsNone(swapped.decrypt_frame(self.FRAME, self.SRC_EXT, None))


def unsecured_mle_frame(src_ext: str, body: bytes, counter: int = 1) -> bytes:
    """A MAC-unsecured data frame carrying a security-suite-255 MLE message
    (as Discovery does) to ff02::1, port 19788, from an extended source."""
    fcf = 1 | 0x0040 | (2 << 10) | (1 << 12) | (3 << 14)
    header = struct.pack("<HBH", fcf, counter & 0xFF, PAN) + b"\xff\xff" + bytes.fromhex(src_ext)[::-1]
    iphc = struct.pack(">H", 0x7F3B) + b"\x01"                         # TF/HLIM elided, src from MAC, dst ff02::1
    udp = b"\xf0" + struct.pack(">HH", 19788, 19788) + b"\x00\x00"      # NHC UDP, ports in full, checksum
    return header + iphc + udp + b"\xff" + body + b"\x00\x00"


class UnsecuredMleTest(unittest.TestCase):
    """A suite-255 MLE message carries no MIC, so it is anyone's bytes: it
    must not count as decrypted, teach an address, or move the mesh state."""

    BODY = (b"\x04" + b"\x00\x02" + bytes.fromhex("c829")                     # Advertisement, Source Address
            + b"\x0b\x08" + struct.pack(">L", 999999) + b"\x40\x01\x01" + bytes([60]))   # Leader Data

    def test_parse_reports_the_command_and_nothing_else(self):
        d = Decryptor(network_key=KEY)
        info = d.parse_mle(b"\xff" + self.BODY, OTHER, None, None)
        self.assertEqual((info.command_name, info.secured), ("Advertisement", False))
        self.assertIsNone(info.partition_id)
        self.assertIsNone(info.source_addr16)
        self.assertEqual(d.short_to_ext, {})
        self.assertEqual((d.stats["mle_decrypted"], d.stats["mle_unsecured"]), (0, 1))
        self.assertIsNone(d.parse_mle(b"\xff", OTHER, None, None))

    def test_pipeline_ignores_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            dd = Path(tmp)
            (dd / "devices.json").write_text(json.dumps([
                {"name": "Front Door", "extendedAddress": SED.upper(), "threadRole": "sleepy-end-device"}]))
            cfg = Config(data_dir=dd / "data", devices_path=dd / "devices.json")
            dec = Decryptor(network_key=KEY)
            pipe = Pipeline(cfg, NullEventLog(), dec)
            pipe.partition = (111111, 10)
            t0 = 1_700_000_000.0
            pipe.ingest(parse_frame(t0, unsecured_mle_frame(OTHER, self.BODY), 230))
            rejoin = b"\x09" + b"\x00\x02" + bytes.fromhex("c829")             # Parent Request
            pipe.ingest(parse_frame(t0 + 1, unsecured_mle_frame(OTHER, rejoin, 2), 230))
            self.assertEqual(pipe.partition, (111111, 10))
            self.assertEqual(dec.short_to_ext, {})
            self.assertEqual(dec.stats["mle_decrypted"], 0)
            self.assertEqual(dec.stats["mle_unsecured"], 2)
            events = [r["event"] for r in pipe.events.records]
            self.assertNotIn("partition_or_leader_change", events)
            self.assertNotIn("mle_rejoin_attempt", events)
            self.assertNotIn(OTHER, pipe.seen.table)          # nor a sighting: anyone can send one


class SightingAuthenticityTest(unittest.TestCase):
    """An extended source address is 64 bits the sender asserts. Liveness
    came from it verbatim, so a forged unsecured frame, or a recording of
    the device played back after it died, kept it "heard" and device_quiet
    never fired. A frame is a sighting only when its MIC vouches for the
    sender and its counter is above the last accepted."""

    def _pipe(self, tmp):
        dd = Path(tmp)
        (dd / "devices.json").write_text(json.dumps([{"name": "Bedroom Sensor", "extendedAddress": SED}]))
        cfg = Config(data_dir=dd / "data", devices_path=dd / "devices.json", quiet_s=1800)
        return Pipeline(cfg, NullEventLog(), Decryptor(network_key=KEY)), cfg

    @staticmethod
    def _quiet(pipe):
        return [r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"]

    def test_forged_and_replayed_frames_do_not_keep_a_dead_device_heard(self):
        import contextlib, io
        with tempfile.TemporaryDirectory() as tmp:
            pipe, _cfg = self._pipe(tmp)
            t0 = 1_700_000_000.0
            real = [secured_ext_frame(SED, c, b"\x7f\x33") for c in range(1, 4)]
            for i, psdu in enumerate(real):
                self.assertEqual(pipe.ingest(parse_frame(t0 + i, psdu, 195)), SED)
            self.assertEqual(pipe.seen.table[SED]["last_seen"], t0 + 2)
            self.assertEqual((pipe.seen.table[SED]["counter"], pipe.seen.table[SED]["frames"]), (3, 3))
            # The device dies. Someone else puts its address on the air,
            # unsecured, every minute for four hours; and plays back its
            # own three frames. Neither is a sighting.
            fcf = 1 | 0x0040 | (2 << 10) | (1 << 12) | (3 << 14)
            forged = struct.pack("<HBH", fcf, 9, PAN) + bytes.fromhex("0000")[::-1] + bytes.fromhex(SED)[::-1] + b"\x7f\x33"
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                for m in range(240):
                    t = t0 + 60 + m * 60
                    pipe.ingest(parse_frame(t, forged, 230))
                    pipe.ingest(parse_frame(t + 1, real[m % 3], 195))
                    pipe.periodic(t + 2)
            self.assertEqual(pipe.seen.table[SED]["last_seen"], t0 + 2)
            self.assertEqual(pipe.seen.table[SED]["frames"], 3)
            self.assertEqual(self._quiet(pipe), [SED])
            self.assertEqual(pipe.replayed, 240)
            said = [l for l in out.getvalue().splitlines() if "not counted as a sighting" in l]
            self.assertEqual(len(said), 4)                        # once an hour, not per frame
            self.assertIn("Bedroom Sensor: a secured frame with counter 1 at or below the last accepted (3)", said[0])
            # Back for real, with a counter past the last accepted: heard again.
            pipe.ingest(parse_frame(t0 + 20000, secured_ext_frame(SED, 4, b"\x7f\x33"), 195))
            self.assertEqual(pipe.seen.table[SED]["last_seen"], t0 + 20000)
            self.assertIn("device_returned", [r["event"] for r in pipe.events.records])

    def test_a_mac_retry_counts_and_the_counter_survives_a_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            pipe, cfg = self._pipe(tmp)
            t0 = 1_700_000_000.0
            psdu = secured_ext_frame(SED, 7, b"\x7f\x33")
            pipe.ingest(parse_frame(t0, psdu, 195))
            pipe.ingest(parse_frame(t0 + 0.02, psdu, 195))         # retried before its ACK: the same frame
            pipe.ingest(parse_frame(t0 + 0.05, psdu, 195))
            self.assertEqual((pipe.seen.table[SED]["frames"], pipe.devices[SED].tx, pipe.replayed), (3, 3, 0))
            pipe.ingest(parse_frame(t0 + 10, psdu, 195))           # ten seconds on: a replay
            self.assertEqual((pipe.seen.table[SED]["frames"], pipe.replayed), (3, 1))
            pipe.seen.save()
            again = Pipeline(cfg, NullEventLog(), Decryptor(network_key=KEY))
            again.ingest(parse_frame(t0 + 100, secured_ext_frame(SED, 5, b"\x7f\x33"), 195))   # below 7
            self.assertEqual((again.seen.table[SED]["frames"], again.replayed), (3, 1))
            again.ingest(parse_frame(t0 + 101, secured_ext_frame(SED, 8, b"\x7f\x33"), 195))
            self.assertEqual((again.seen.table[SED]["frames"], again.seen.table[SED]["counter"]), (4, 8))

    def test_a_secured_mle_message_vouches_for_an_unsecured_frame(self):
        # Routers advertise in MAC-unsecured frames secured at the MLE
        # layer: those are sightings, on the MLE MIC and MLE counter.
        with tempfile.TemporaryDirectory() as tmp:
            pipe, _cfg = self._pipe(tmp)
            t0 = 1_700_000_000.0
            body = b"\x04" + b"\x00\x02" + bytes.fromhex("c829")           # Advertisement, Source Address
            src_ip = LINK_LOCAL + Decryptor._iid_from_ext(OTHER)
            fcf = 1 | 0x0040 | (2 << 10) | (1 << 12) | (3 << 14)             # MAC-unsecured, ext source

            def advert(counter):
                msg = mle_message(OTHER, 0, counter, src_ip, ALL_NODES, body)
                return (struct.pack("<HBH", fcf, counter & 0xFF, PAN) + b"\xff\xff" + bytes.fromhex(OTHER)[::-1]
                        + lowpan_udp(19788, 19788, msg))
            for counter in (1, 2):
                pipe.ingest(parse_frame(t0 + counter, advert(counter), 230))
            self.assertEqual((pipe.seen.table[OTHER]["frames"], pipe.seen.table[OTHER]["mle_counter"]), (2, 2))
            pipe.ingest(parse_frame(t0 + 60, advert(2), 230))                # the same message, a minute later
            self.assertEqual((pipe.seen.table[OTHER]["frames"], pipe.replayed), (2, 1))
            pipe.ingest(parse_frame(t0 + 61, unsecured_mle_frame(OTHER, body, 3), 230))   # suite 255: anyone's
            self.assertEqual(pipe.seen.table[OTHER]["frames"], 2)


def iphc_packet(*, sac=False, sam=3, src=b"", m=True, dac=False, dam=3, dst=b"",
                tf=3, hlim=2, cid=False, pbits=0, sport=19788, dport=19788,
                checksum_elided=False, payload=b"\xff\x09", mesh=None, frag1=False) -> bytes:
    """A 6LoWPAN packet built from RFC 6282 field by field, independently of
    the parser: the IPHC word, its inline header fields, the inline address
    bytes given (`src`, `dst`), then a UDP NHC header at the given port
    compression, and the payload. `mesh` is a hop count for an RFC 4944 mesh
    header with 16-bit originator and final addresses in front; `frag1`
    puts a first-fragment header in front too."""
    iphc = (0b011 << 13) | (tf << 11) | (1 << 10) | (hlim << 8) | (int(cid) << 7) \
        | (int(sac) << 6) | (sam << 4) | (int(m) << 3) | (int(dac) << 2) | dam
    pkt = struct.pack(">H", iphc)
    if cid:
        pkt += b"\x11"                                     # context ids: src 1, dst 1
    pkt += (b"\xa5\x5a\x5a\xa5", b"\x5a\x5a\xa5", b"\xa5", b"")[tf]
    if hlim == 0:
        pkt += b"\x40"                                     # hop limit inline
    pkt += src + dst
    nhc = 0b11110000 | (int(checksum_elided) << 2) | pbits
    pkt += bytes([nhc])
    if pbits == 3:
        pkt += bytes([((sport & 0xF) << 4) | (dport & 0xF)])
    elif pbits == 1:
        pkt += struct.pack(">H", sport) + bytes([dport & 0xFF])
    elif pbits == 2:
        pkt += bytes([sport & 0xFF]) + struct.pack(">H", dport)
    else:
        pkt += struct.pack(">HH", sport, dport)
    if not checksum_elided:
        pkt += b"\xc5\x3a"
    pkt += payload
    if frag1:
        pkt = struct.pack(">HH", (0b11000 << 11) | 200, 0x1234) + pkt
    if mesh is not None:
        head = bytes([0b10000000 | min(mesh, 0xF)]) + (bytes([mesh]) if mesh >= 0xF else b"")
        pkt = head + bytes.fromhex("c829") + bytes.fromhex("00cc") + pkt
    return pkt


# Every (SAC, SAM) form: the inline bytes the sender puts on air, and the
# source address the parser must hand back for them, given mac_src_ext=SED.
# Context-based forms carry no reconstruction (None).
SRC_FORMS = {
    "full":         (False, 0, bytes.fromhex("fd00db8000000000" "0123456789abcdef"),
                     bytes.fromhex("fd00db8000000000" "0123456789abcdef")),
    "iid":          (False, 1, bytes.fromhex("0212345678abcdef"),
                     LINK_LOCAL + bytes.fromhex("0212345678abcdef")),
    "short":        (False, 2, bytes.fromhex("9c01"), LINK_LOCAL + bytes.fromhex("000000fffe009c01")),
    "elided":       (False, 3, b"", LINK_LOCAL + bytes.fromhex("009a47566a00b543")),
    "ctx-unspec":   (True, 0, b"", None),
    "ctx-iid":      (True, 1, bytes.fromhex("0312345678abcdef"), None),
    "ctx-short":    (True, 2, bytes.fromhex("9c02"), None),
    "ctx-elided":   (True, 3, b"", None),
}

# Every (M, DAC, DAM) form the same way, given mac_dst_ext=OTHER and
# mac_dst_short="c829" (the extended one wins when both are known).
DST_FORMS = {
    "mcast-full":   (True, False, 0, bytes.fromhex("ff05000000000000" "00000000000000fd"),
                     bytes.fromhex("ff05000000000000" "00000000000000fd")),
    "mcast-48":     (True, False, 1, bytes.fromhex("05" "1122334455"),
                     bytes.fromhex("ff05000000000000" "0000001122334455")),
    "mcast-32":     (True, False, 2, bytes.fromhex("03" "aabbcc"),
                     bytes.fromhex("ff03000000000000" "0000000000aabbcc")),
    "mcast-8":      (True, False, 3, b"\x02", bytes.fromhex("ff02000000000000" "0000000000000002")),
    "mcast-ctx":    (True, True, 0, bytes.fromhex("334455667788"), None),
    "ucast-full":   (False, False, 0, bytes.fromhex("fd00db8000000000" "fedcba9876543210"),
                     bytes.fromhex("fd00db8000000000" "fedcba9876543210")),
    "ucast-iid":    (False, False, 1, bytes.fromhex("02fedcba98765432"),
                     LINK_LOCAL + bytes.fromhex("02fedcba98765432")),
    "ucast-short":  (False, False, 2, bytes.fromhex("6e03"), LINK_LOCAL + bytes.fromhex("000000fffe006e03")),
    "ucast-elided": (False, False, 3, b"", LINK_LOCAL + bytes.fromhex("d00bfcd1a12f625d")),
    "ucast-ctx-iid":    (False, True, 1, bytes.fromhex("03fedcba98765432"), None),
    "ucast-ctx-short":  (False, True, 2, bytes.fromhex("6e04"), None),
    "ucast-ctx-elided": (False, True, 3, b"", None),
}

PAYLOAD = bytes(range(0x60, 0x80))    # 32 distinct bytes: a mis-sliced payload cannot match


class IphcAddressMatrixTest(unittest.TestCase):
    """`udp_ports` accumulates its offset through every address branch, so
    one wrong field width yields the wrong ports and a mis-sliced payload
    rather than an error; MLE then fails to decrypt and the recorder
    reports no rejoins, no partitions and no leader. Each form is encoded
    here from the RFC, not from the parser, and the whole tuple is checked."""

    def _check(self, pkt, src_ip, dst_ip, **kw):
        r = Decryptor.udp_ports(pkt, **kw)
        self.assertIsNotNone(r)
        sport, dport, payload, got_src, got_dst = r
        self.assertEqual((sport, dport), (19788, 19788))
        self.assertEqual(payload, PAYLOAD)
        self.assertEqual(got_src, src_ip)
        self.assertEqual(got_dst, dst_ip)

    def test_every_source_form_with_every_destination_form(self):
        for sname, (sac, sam, src, src_ip) in SRC_FORMS.items():
            for dname, (m, dac, dam, dst, dst_ip) in DST_FORMS.items():
                with self.subTest(src=sname, dst=dname):
                    pkt = iphc_packet(sac=sac, sam=sam, src=src, m=m, dac=dac, dam=dam, dst=dst,
                                      payload=PAYLOAD)
                    self._check(pkt, src_ip, dst_ip, mac_src_ext=SED, mac_dst_ext=OTHER,
                                mac_dst_short="c829")

    def test_elided_addresses_without_a_mac_address_to_derive_from_are_none(self):
        pkt = iphc_packet(sam=3, m=False, dam=3, payload=PAYLOAD)
        self._check(pkt, None, None)
        # A short MAC destination serves when no extended one is known.
        self._check(pkt, None, LINK_LOCAL + bytes.fromhex("000000fffe00c829"), mac_dst_short="c829")

    def test_mesh_and_fragment_headers_in_front_are_stepped_over(self):
        sac, sam, src, src_ip = SRC_FORMS["iid"]
        m, dac, dam, dst, dst_ip = DST_FORMS["ucast-short"]
        for label, kw in (("mesh", dict(mesh=3)), ("mesh-deep-hops", dict(mesh=0x14)),
                          ("frag1", dict(frag1=True)), ("mesh+frag1", dict(mesh=3, frag1=True))):
            with self.subTest(form=label):
                pkt = iphc_packet(sac=sac, sam=sam, src=src, m=m, dac=dac, dam=dam, dst=dst,
                                  payload=PAYLOAD, **kw)
                self._check(pkt, src_ip, dst_ip)

    def test_inline_traffic_class_hop_limit_and_context_id_are_stepped_over(self):
        sac, sam, src, src_ip = SRC_FORMS["short"]
        m, dac, dam, dst, dst_ip = DST_FORMS["mcast-32"]
        for tf in range(4):
            for hlim in (0, 1, 2, 3):
                for cid in (False, True):
                    with self.subTest(tf=tf, hlim=hlim, cid=cid):
                        pkt = iphc_packet(sac=sac, sam=sam, src=src, m=m, dac=dac, dam=dam, dst=dst,
                                          tf=tf, hlim=hlim, cid=cid, payload=PAYLOAD)
                        self._check(pkt, src_ip, dst_ip)

    def test_every_port_compression_with_and_without_the_checksum(self):
        sac, sam, src, src_ip = SRC_FORMS["elided"]
        m, dac, dam, dst, dst_ip = DST_FORMS["mcast-8"]
        # Ports each compression can carry: 0xF0Bx for nibbles, 0xF0xx for a byte.
        ports = {0: (19788, 19788), 1: (19788, 0xF0A1), 2: (0xF0A2, 19788), 3: (0xF0B1, 0xF0B2)}
        for pbits, (sport, dport) in ports.items():
            for elided in (False, True):
                with self.subTest(pbits=pbits, checksum_elided=elided):
                    pkt = iphc_packet(sac=sac, sam=sam, src=src, m=m, dac=dac, dam=dam, dst=dst,
                                      pbits=pbits, sport=sport, dport=dport, checksum_elided=elided,
                                      payload=PAYLOAD)
                    r = Decryptor.udp_ports(pkt, mac_src_ext=SED)
                    self.assertEqual(r, (sport, dport, PAYLOAD, src_ip, dst_ip))
