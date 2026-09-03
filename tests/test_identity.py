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
                  payload: bytes = b"\x7f\x33\xf0\x11\x22") -> bytes:
    """An 802.15.4 frame with short source addressing, secured as Thread does
    (ENC-MIC-32, key index mode) under key sequence 0, plus a trailing FCS.
    ftype 3 builds a data request: the command id (0x04) is authenticated
    but not encrypted, and the encrypted payload is empty."""
    fcf = ftype | 0x0008 | 0x0040 | (2 << 10) | (1 << 12) | (2 << 14)
    header = struct.pack("<HBH", fcf, counter & 0xFF, PAN) + bytes.fromhex("00cc")[::-1] \
        + bytes.fromhex(src_short)[::-1]
    aux = bytes([0x0D]) + struct.pack("<L", counter) + bytes([1])   # level 5, key mode 1, index 1
    open_part = header + aux + (b"\x04" if ftype == 3 else b"")
    if ftype == 3:
        payload = b""
    _mle, mac_key = derive_keys(KEY, 0)
    nonce = bytes.fromhex(src_ext) + struct.pack(">L", counter) + bytes([5])
    body = AESCCM(mac_key, tag_length=4).encrypt(nonce, payload, open_part)
    return open_part + body + b"\x00\x00"


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
            self.assertEqual(pipe.seen.table[SED]["last_seen"], t0 + 2)

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
