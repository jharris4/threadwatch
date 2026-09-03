"""The ring survives a capture killed mid-write."""

import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.capture import RingWriter  # noqa: E402
from threadwatch.pcap import DLT_NOFCS, Frame, PcapStreamReader, PcapWriter, complete_length  # noqa: E402


def frame(ts):
    return Frame(ts=ts, raw=b"\x41\x88\x01\xcd\xab\x01\x00\x02\x00", psdu=b"",
                 rssi=None, channel=None, lqi=None)


class TruncatedRingTest(unittest.TestCase):
    def test_reader_stops_cleanly_at_a_partial_tail_record(self):
        buf = io.BytesIO()
        w = PcapWriter(buf, DLT_NOFCS)
        w.write(frame(1.0)); w.write(frame(2.0))
        cut = buf.getvalue()[:-3]
        self.assertEqual(len(list(PcapStreamReader(io.BytesIO(cut)))), 1)
        self.assertEqual(complete_length_of(cut), 24 + 16 + 9)   # header + one whole record

    def test_resumed_hour_file_drops_the_fragment_before_appending(self):
        with tempfile.TemporaryDirectory() as d:
            ring = RingWriter(Path(d), keep_files=5, dlt=DLT_NOFCS)
            ring.write(frame(1_700_000_000.0)); ring.write(frame(1_700_000_001.0))
            ring.close()
            path = ring.current_path
            with open(path, "r+b") as fh:
                fh.truncate(path.stat().st_size - 3)   # killed mid-record
            ring2 = RingWriter(Path(d), keep_files=5, dlt=DLT_NOFCS)
            ring2.write(frame(1_700_000_002.0))
            ring2.close()
            with open(path, "rb") as fh:
                seen = [round(f.ts) for f in PcapStreamReader(fh)]
            self.assertEqual(seen, [1_700_000_000, 1_700_000_002])
            self.assertEqual(complete_length(path), path.stat().st_size)


def complete_length_of(data: bytes) -> int:
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(data); tmp.flush()
        return complete_length(tmp.name)


if __name__ == "__main__":
    unittest.main()
