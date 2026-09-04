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

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESCCM
    from threadwatch.crypto import Decryptor, derive_keys
except ImportError:  # pragma: no cover
    AESCCM = None

KEY = bytes(range(16))
SED = "029a47566a00b543"
OTHER = "d20bfcd1a12f625d"
PAN = 0x4e21


def secured_frame(src_ext: str, src_short: str, counter: int, ftype: int = 1,
                  payload: bytes = b"\x7f\x33\xf0\x11\x22", sequence: int = 0) -> bytes:
    """An 802.15.4 frame with short source addressing, secured as Thread does
    (ENC-MIC-32, key index mode) under a key sequence, plus a trailing FCS.
    ftype 3 builds a data request: the command id (0x04) is authenticated
    but not encrypted, and the encrypted payload is empty."""
    fcf = ftype | 0x0008 | 0x0040 | (2 << 10) | (1 << 12) | (2 << 14)
    header = struct.pack("<HBH", fcf, counter & 0xFF, PAN) + bytes.fromhex("00cc")[::-1] \
        + bytes.fromhex(src_short)[::-1]
    aux = bytes([0x0D]) + struct.pack("<L", counter) + bytes([sequence % 127 + 1])   # level 5, key mode 1
    open_part = header + aux + (b"\x04" if ftype == 3 else b"")
    if ftype == 3:
        payload = b""
    _mle, mac_key = derive_keys(KEY, sequence)
    nonce = bytes.fromhex(src_ext) + struct.pack(">L", counter) + bytes([5])
    body = AESCCM(mac_key, tag_length=4).encrypt(nonce, payload, open_part)
    return open_part + body + b"\x00\x00"


def mle_message(src_ext: str, sequence: int, counter: int, src_ip: bytes, dst_ip: bytes,
                body: bytes) -> bytes:
    """A secured MLE message (UDP payload) as Thread sends it: security suite
    0, key id mode 2, whose key source is the key sequence itself."""
    aux = bytes([5 | (2 << 3)]) + struct.pack("<L", counter) + struct.pack(">L", sequence) \
        + bytes([sequence % 127 + 1])
    mle_key, _mac = derive_keys(KEY, sequence)
    nonce = bytes.fromhex(src_ext) + struct.pack(">L", counter) + bytes([5])
    return bytes([0]) + aux + AESCCM(mle_key, tag_length=4).encrypt(nonce, body, src_ip + dst_ip + aux)


@unittest.skipIf(AESCCM is None, "cryptography not installed")
class KeySequenceTest(unittest.TestCase):
    """The key sequence climbs with every rotation; the search must follow."""

    def _decrypts(self, d, sequence, counter=1):
        return d.decrypt_frame(secured_frame(SED, "c829", counter, sequence=sequence), SED, None) is not None

    def test_a_high_sequence_decrypts_once_the_sequence_is_known(self):
        d = Decryptor(network_key=KEY)
        for seq in (0, 84, 1015):                        # the first eight generations: found cold
            self.assertTrue(self._decrypts(Decryptor(network_key=KEY), seq), seq)
        self.assertFalse(self._decrypts(d, 1023))        # the ninth generation of key index 8: not searched cold
        self.assertFalse(self._decrypts(d, 5000))
        d.note_key_sequence(4999)                        # ...until something says where the network is
        self.assertTrue(self._decrypts(d, 5000))
        self.assertTrue(self._decrypts(d, 4998))         # a straggler on an older key still reads
        self.assertFalse(self._decrypts(d, 5000 + 127 * 3))   # too far to be this network's next key
        self.assertEqual(d.key_sequence, 5000)

    def test_rotations_are_followed_past_the_initial_search(self):
        d = Decryptor(network_key=KEY)
        self.assertTrue(self._decrypts(d, 1015))         # generation 7 of key index 127: found cold
        self.assertEqual(d.key_sequence, 1015)
        for seq in range(1016, 1016 + 400):              # then one rotation at a time, well past 1023
            self.assertTrue(self._decrypts(d, seq), seq)
        self.assertEqual(d.key_sequence, 1415)
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


@unittest.skipIf(AESCCM is None, "cryptography not installed")
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

    def test_truncated_unsecured_plaintext_does_not_crash_ingest(self):
        with tempfile.TemporaryDirectory() as tmp:
            dd = Path(tmp)
            cfg = Config(data_dir=dd / "data")
            dec = Decryptor(network_key=KEY)
            pipe = Pipeline(cfg, NullEventLog(), dec)
            fcf = 1 | 0x0040 | (2 << 10) | (1 << 12) | (3 << 14)      # unsecured data, ext source
            for payload in (b"\x7f\x33\xf0", b"\x7f\x33\xf3", b"\x7f\x33\xf1\x12"):
                psdu = struct.pack("<HBH", fcf, 1, PAN) + bytes.fromhex("00cc")[::-1] \
                    + bytes.fromhex(SED)[::-1] + payload   # no FCS: the sniffer may strip it
                pipe.ingest(parse_frame(1.0, psdu, 195))
            self.assertEqual(dec.stats["parse_failed"], 3)

    def test_extra_candidates_resolve_a_device_missing_from_the_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(data_dir=Path(tmp) / "data")          # no devices.json at all
            pipe = Pipeline(cfg, NullEventLog(), Decryptor(network_key=KEY), ephemeral=True)
            pipe.extra_candidates = [SED]
            f = parse_frame(1.0, secured_frame(SED, "c829", 3, ftype=3), 195)
            self.assertEqual(pipe.identity(f), SED)

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
