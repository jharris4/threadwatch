"""Malformed wire data must not invent metadata or request unbounded reads."""

import io
import json
import math
import struct
import tempfile
import unittest
from pathlib import Path

from threadwatch.config import Config
from threadwatch.crypto import Decryptor
from threadwatch.events import NullEventLog
from threadwatch.mdns import TYPE_PTR, TYPE_TXT, encode_name, parse_message, read_name
from threadwatch.pcap import (DLT_NOFCS, DLT_TAP, PCAP_MAGIC_LE_US,
                              PcapStreamReader, complete_length, parse_frame)
from threadwatch.pipeline import Pipeline
from tests.no_lan import setUpModule, tearDownModule  # noqa: E402, F401  (no mDNS from the suite)


class TapBoundaryTest(unittest.TestCase):
    def test_tlv_value_cannot_borrow_mac_payload_bytes(self):
        raw = struct.pack('<HHHH', 0, 8, 1, 4) + struct.pack('<f', -60)
        self.assertIsNone(parse_frame(1, raw, DLT_TAP).rssi)

    def test_incomplete_tap_header_is_not_parsed_as_mac(self):
        for raw in (b'\x01\x00\x07', struct.pack('<HHHHf', 0, 100, 1, 4, -60)):
            with self.subTest(raw=raw):
                f = parse_frame(1, raw, DLT_TAP)
                self.assertIsNone(f.ftype)
                self.assertIsNone(f.rssi)

    def test_nonfinite_rssi_does_not_poison_later_signal_measurements(self):
        # Secured data from an extended source (a sighting); payload need not decode.
        from tests.frames import secured_psdu
        addr = bytes(range(8))[::-1].hex()
        with tempfile.TemporaryDirectory() as d:
            for bad in (float('nan'), float('inf'), float('-inf')):
                with self.subTest(bad=bad):
                    pipe = Pipeline(Config(data_dir=Path(d)), NullEventLog(),
                                    Decryptor(bytes(16)), ephemeral=True)
                    for i, rssi in enumerate((bad, -60.0)):
                        raw = struct.pack('<HHHHf', 0, 12, 1, 4, rssi) + secured_psdu(addr, i + 1, seq=i)
                        pipe.ingest(parse_frame(1700000000 + i, raw, DLT_TAP))
                    self.assertEqual(pipe.seen.table[addr]['rssi'], -60.0)
                    self.assertTrue(math.isfinite(pipe.devices[addr].rssi_ewma))
                    json.dumps(pipe.seen.table, allow_nan=False)


class DnsBoundaryTest(unittest.TestCase):
    def message(self, kind, declared, payload):
        return (struct.pack('>HHHHHH', 0, 0x8400, 0, 1, 0, 0)
                + encode_name('router.local')
                + struct.pack('>HHIH', kind, 1, 120, declared) + payload)

    def test_truncated_rdata_is_rejected_even_if_prefix_is_parseable(self):
        payload = b'\x0bxa=' + bytes(range(8))
        with self.assertRaises(ValueError):
            parse_message(self.message(TYPE_TXT, len(payload) + 1, payload))

    def test_truncated_txt_item_cannot_supply_an_address(self):
        payload = b'\xffxa=' + bytes(range(8))
        with self.assertRaises(ValueError):
            parse_message(self.message(TYPE_TXT, len(payload), payload))

    def test_ptr_name_cannot_extend_past_its_rdata(self):
        # Trailing bytes outside the record currently finish its name.
        payload = encode_name('other.local')
        with self.assertRaises(ValueError):
            parse_message(self.message(TYPE_PTR, 1, payload))

    def test_reserved_label_encoding_is_not_an_ordinary_label(self):
        with self.assertRaises(ValueError):
            read_name(b'\x40' + b'a' * 64 + b'\x00', 0)

    def test_valid_compression_can_point_outside_rdata(self):
        msg = self.message(TYPE_PTR, 2, b'\xc0\x0c')
        self.assertEqual(parse_message(msg), [('router.local', TYPE_PTR, 'router.local')])


class PcapAllocationTest(unittest.TestCase):
    def test_hostile_lengths_never_reach_a_large_read(self):
        class BoundedStream(io.BytesIO):
            def read(self, n=-1):
                if n > 65535:
                    raise AssertionError(f'unbounded read requested: {n}')
                return super().read(n)

        for snaplen in (0, 0xffffffff):
            with self.subTest(snaplen=snaplen):
                header = struct.pack('<LHHIILL', PCAP_MAGIC_LE_US, 2, 4, 0, 0, snaplen, DLT_NOFCS)
                data = header + struct.pack('<LLLL', 1, 0, 0xffffffff, 0xffffffff)
                self.assertEqual(list(PcapStreamReader(BoundedStream(data))), [])
                with tempfile.TemporaryDirectory() as d:
                    p = Path(d) / 'bad.pcap'
                    p.write_bytes(data)
                    # The recovery scanner must apply the same bound.
                    from unittest.mock import patch
                    with patch('builtins.open', return_value=BoundedStream(data)):
                        self.assertEqual(complete_length(p), 24)
