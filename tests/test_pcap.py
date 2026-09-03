"""The ring survives a capture killed mid-write."""

import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.capture import RingWriter  # noqa: E402
import unittest as _ut  # noqa: E402


class RingSizeCapTest(_ut.TestCase):
    def test_oldest_go_until_under_the_byte_cap_but_never_the_current_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ring = RingWriter(Path(d), keep_files=10, dlt=0, keep_bytes=2500)
            for h in ("00", "01", "02", "03"):
                (Path(d) / f"threadwatch-20260903-{h}.pcap").write_bytes(b"x" * 1000)
            ring._prune()
            self.assertEqual(sorted(p.name[-7:-5] for p in Path(d).glob("*.pcap")), ["02", "03"])
            (Path(d) / "threadwatch-20260903-03.pcap").write_bytes(b"x" * 9000)   # one huge current file
            ring._prune()
            self.assertEqual(sorted(p.name[-7:-5] for p in Path(d).glob("*.pcap")), ["03"])
            ring = RingWriter(Path(d), keep_files=10, dlt=0)                        # no cap: files only
            (Path(d) / "threadwatch-20260903-04.pcap").write_bytes(b"x" * 9000)
            ring._prune()
            self.assertEqual(len(list(Path(d).glob("*.pcap"))), 2)
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

    def test_microseconds_never_round_to_a_full_second(self):
        buf = io.BytesIO()
        PcapWriter(buf, DLT_NOFCS).write(frame(1700000000.9999996))
        f = next(iter(PcapStreamReader(io.BytesIO(buf.getvalue()))))
        self.assertEqual(f.ts, 1700000001.0)
        self.assertLess(int.from_bytes(buf.getvalue()[28:32], "little"), 1_000_000)

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
