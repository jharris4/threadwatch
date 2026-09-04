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

    def test_current_file_survives_a_clock_step_back(self):
        import tempfile
        import time
        from threadwatch.pcap import Frame
        with tempfile.TemporaryDirectory() as d:
            for h in ("12", "13", "14", "15"):
                (Path(d) / f"threadwatch-20260904-{h}.pcap").write_bytes(b"x" * 1000)
            ring = RingWriter(Path(d), keep_files=4, dlt=0)
            ts = time.mktime(time.strptime("2026-09-04 09:30:00", "%Y-%m-%d %H:%M:%S"))
            ring.write(Frame(ts=ts, raw=b"\x00" * 20, psdu=b"", rssi=None, channel=None, lqi=None))
            self.assertTrue(ring.current_path.exists())
            self.assertEqual(len(list(Path(d).glob("*.pcap"))), 4)

    def test_keep_files_zero_does_not_delete_the_file_being_written(self):
        import tempfile
        import time
        from threadwatch.pcap import Frame
        with tempfile.TemporaryDirectory() as d:
            ring = RingWriter(Path(d), keep_files=0, dlt=0)
            ts = time.mktime(time.strptime("2026-09-04 10:00:00", "%Y-%m-%d %H:%M:%S"))
            ring.write(Frame(ts=ts, raw=b"\x00" * 20, psdu=b"", rssi=None, channel=None, lqi=None))
            self.assertTrue(ring.current_path.exists())

    def test_byte_cap_counts_only_what_the_file_cap_keeps(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ring = RingWriter(Path(d), keep_files=2, dlt=0, keep_bytes=2500)
            for h in ("00", "01", "02", "03"):
                (Path(d) / f"threadwatch-20260903-{h}.pcap").write_bytes(b"x" * 1000)
            ring._prune()
            # The two newest total 2000 bytes, under the cap: both stay.
            self.assertEqual(sorted(p.name[-7:-5] for p in Path(d).glob("*.pcap")), ["02", "03"])
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


class TapHeaderTest(_ut.TestCase):
    """DLT 283 is what the dongle actually produces; a corrupt ring file
    must not take the parser with it."""

    def _tap(self, body: bytes):
        from threadwatch.pcap import DLT_TAP, parse_frame
        return parse_frame(0.0, body, DLT_TAP)

    def test_tlv_cut_short_does_not_raise(self):
        for body in ("0000080001000400", "0000080003000200", "000008000a000100"):
            f = self._tap(bytes.fromhex(body))
            self.assertIsNone(f.rssi)
            self.assertIsNone(f.channel)
            self.assertIsNone(f.lqi)

    def test_tap_len_below_header_yields_no_psdu(self):
        self.assertEqual(self._tap(bytes.fromhex("00000200") + b"\xff" * 8).psdu, b"")

    def test_well_formed_tap_header_still_parses(self):
        import struct
        body = (struct.pack("<HH", 0, 20)                       # version/reserved, tap_len
                + struct.pack("<HH", 1, 4) + struct.pack("<f", -61.0)      # RSSI
                + struct.pack("<HH", 3, 2) + struct.pack("<H", 25) + b"\x00\x00"   # channel
                + b"\xab" * 6)                                  # PSDU
        f = self._tap(body)
        self.assertEqual(round(f.rssi), -61)
        self.assertEqual(f.channel, 25)
        self.assertEqual(f.psdu, b"\xab" * 6)


if __name__ == "__main__":
    unittest.main()


class RingHourNamingTest(_ut.TestCase):
    """One file per local hour. The name is a contract: `why.select_recent`
    parses it to pick a window, and per-file retention drops one hour at a
    time rather than a whole day."""

    def test_two_hours_of_one_day_become_two_files_why_can_window(self):
        import time
        from threadwatch.why import RING_NAME, select_recent
        with tempfile.TemporaryDirectory() as d:
            ring = RingWriter(Path(d), keep_files=10, dlt=DLT_NOFCS)
            for stamp in ("2026-09-04 08:30:00", "2026-09-04 09:10:00"):
                ring.write(frame(time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M:%S"))))
            ring.close()
            names = sorted(p.name for p in Path(d).glob("*.pcap"))
            self.assertEqual(names, ["threadwatch-20260904-08.pcap", "threadwatch-20260904-09.pcap"])
            for name in names:
                time.strptime(name, RING_NAME)       # the name `why` has to parse
            now = time.mktime(time.strptime("2026-09-04 09:40:00", "%Y-%m-%d %H:%M:%S"))
            recent = select_recent(sorted(Path(d).glob("*.pcap")), 0.5, now)
            self.assertEqual([p.name for p in recent], ["threadwatch-20260904-09.pcap"])
