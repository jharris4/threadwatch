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
