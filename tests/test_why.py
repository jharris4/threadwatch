"""`threadwatch why`: which ring files a time window selects."""

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.why import select_recent  # noqa: E402

NOW = time.mktime(time.strptime("2026-09-03 10:20", "%Y-%m-%d %H:%M"))


def ring(*hours):
    return [Path(f"/ring/threadwatch-{h}.pcap") for h in hours]


class SelectRecentTest(unittest.TestCase):
    FILES = ring("20260902-22", "20260902-23", "20260903-00", "20260903-08", "20260903-09", "20260903-10")

    def test_none_keeps_everything(self):
        self.assertEqual(select_recent(self.FILES, None, NOW), self.FILES)

    def test_window_keeps_files_whose_hour_ends_inside_it(self):
        # 2 h back from 10:20 is 08:20: the 08h file still covers 08:20-09:00.
        self.assertEqual(select_recent(self.FILES, 2, NOW), ring("20260903-08", "20260903-09", "20260903-10"))
        # 1.25 h back is 09:05: the 08h file ended at 09:00, so it goes.
        self.assertEqual(select_recent(self.FILES, 1.25, NOW), ring("20260903-09", "20260903-10"))

    def test_window_crosses_midnight(self):
        self.assertEqual(select_recent(self.FILES, 11, NOW),
                         ring("20260902-23", "20260903-00", "20260903-08", "20260903-09", "20260903-10"))

    def test_unparsable_name_is_kept(self):
        odd = Path("/ring/threadwatch-frozen.pcap")
        self.assertEqual(select_recent([odd, *self.FILES], 1, NOW), [odd, *ring("20260903-09", "20260903-10")])

    def test_empty_when_nothing_is_recent(self):
        self.assertEqual(select_recent(ring("20260901-10"), 1, NOW), [])


if __name__ == "__main__":
    unittest.main()


class EventHistoryTest(unittest.TestCase):
    def test_merges_every_address_of_a_device_newest_first(self):
        import tempfile
        from threadwatch.events import EventLog
        from threadwatch.why import event_history
        a1, a2, other = "b62c32bf669272db", "e6c279e8f0c70298", "26976e7f7d20964a"
        with tempfile.TemporaryDirectory() as d:
            log = EventLog(Path(d) / "events")
            log.emit("device_quiet", "warning", NOW - 7200, addr=a1, name="TV", silent_for_s=1800)
            log.emit("device_returned", "notice", NOW - 5400, addr=a1, name="TV")
            log.emit("device_quiet", "warning", NOW - 3000, addr=other, name="AQ", silent_for_s=1800)
            log.emit("mle_rejoin_attempt", "notice", NOW - 600, addr=a2, name="TV", command="Parent Request")
            eps = event_history(log.dir, [a1, a2.upper(), a1], NOW)
        self.assertEqual([e["kind"] for e in eps], ["rejoin", "quiet"])
        self.assertEqual(eps[1]["title"], "TV quiet for 60m")

    def test_empty_without_an_event_log(self):
        from threadwatch.why import event_history
        self.assertEqual(event_history(Path("/nonexistent/events"), ["b62c32bf669272db"], NOW), [])


class HourTableTest(unittest.TestCase):
    """The per-hour table is in time order, not label order."""

    DEV = "26976e7f7d20964a"

    def _table(self, stamps):
        import contextlib
        import io
        import struct
        import tempfile
        from threadwatch.config import Config
        from threadwatch.pcap import DLT_NOFCS, Frame, PcapWriter
        from threadwatch.why import run_why
        fcf = 1 | 0x0040 | (2 << 10) | (1 << 12) | (3 << 14)        # data, pan compressed, short dst, ext src

        def psdu(seq):
            return struct.pack("<HBH", fcf, seq, 0x4e21) + b"\x00\x00" + bytes.fromhex(self.DEV)[::-1] + b"\x7f\x33"

        with tempfile.TemporaryDirectory() as d:
            cred = Path(d) / "credentials.toml"
            cred.write_text('[credentials]\nnetwork_key = "00112233445566778899aabbccddeeff"\n')
            cfg = Config(data_dir=Path(d) / "data", credentials_path=cred)
            pcap = Path(d) / "window.pcap"
            with open(pcap, "wb") as fh:
                w = PcapWriter(fh, DLT_NOFCS)
                for i, stamp in enumerate(stamps):
                    ts = time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M"))
                    w.write(Frame(ts=ts, raw=psdu(i), psdu=psdu(i), rssi=None, channel=None, lqi=None))
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                run_why(cfg, self.DEV, pcap)
        self.assertIn("credentials: loaded", err.getvalue())
        lines = out.getvalue().splitlines()
        start = next(i for i, l in enumerate(lines) if l.startswith("hour"))
        rows = []
        for line in lines[start + 1:]:                        # the table ends at the first blank line
            if not line:
                break
            rows.append(line.split())
        return rows

    def test_rows_stay_in_time_order_across_a_year_boundary(self):
        rows = self._table(["2025-12-31 23:10", "2025-12-31 23:40", "2026-01-01 00:20"])
        self.assertEqual([(r[0], r[1], r[2]) for r in rows],
                         [("2025-12-31", "23h", "2"), ("2026-01-01", "00h", "1")])

    def test_a_single_year_keeps_the_short_label(self):
        rows = self._table(["2026-09-03 08:10", "2026-09-03 09:40"])
        self.assertEqual([(r[0], r[1], r[2]) for r in rows], [("09-03", "08h", "1"), ("09-03", "09h", "1")])


class RunWhyTest(unittest.TestCase):
    """`why` tells one device's story. Everything it counts - frames, polls,
    transmissions, ACKs - has to be that device's; the whole mesh's traffic
    attributed to one device answers the question confidently and wrongly."""

    DEV = "26976e7f7d20964a"
    OTHER = "b62c32bf669272db"

    @staticmethod
    def _at(stamp, plus=0.0):
        return time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M")) + plus

    def _psdu(self, addr, seq, ftype=1, dst="0000"):
        import struct
        fcf = ftype | 0x0040 | (2 << 10) | (1 << 12) | (3 << 14)   # pan compressed, short dst, ext src
        return (struct.pack("<HBH", fcf, seq, 0x4e21) + bytes.fromhex(dst)[::-1]
                + bytes.fromhex(addr)[::-1] + b"\x7f\x33")

    @staticmethod
    def _ack(seq):
        import struct
        return struct.pack("<HB", 2, seq)

    def _run(self, frames, target=None):
        """Write the frames to a pcap, run `why` over it, return its output."""
        import contextlib
        import io
        import tempfile
        from threadwatch.config import Config
        from threadwatch.pcap import DLT_NOFCS, Frame, PcapWriter
        from threadwatch.why import run_why
        with tempfile.TemporaryDirectory() as d:
            cred = Path(d) / "credentials.toml"
            cred.write_text('[credentials]\nnetwork_key = "00112233445566778899aabbccddeeff"\n')
            cfg = Config(data_dir=Path(d) / "data", credentials_path=cred)
            pcap = Path(d) / "window.pcap"
            with open(pcap, "wb") as fh:
                w = PcapWriter(fh, DLT_NOFCS)
                for ts, psdu in sorted(frames, key=lambda p: p[0]):
                    w.write(Frame(ts=ts, raw=psdu, psdu=psdu, rssi=None, channel=None, lqi=None))
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                run_why(cfg, target or self.DEV, pcap)
        return out.getvalue()

    def _rows(self, text):
        lines = text.splitlines()
        start = next(i for i, l in enumerate(lines) if l.startswith("hour"))
        rows = []
        for line in lines[start + 1:]:                        # the table ends at the first blank line
            if not line:
                break
            rows.append(line.split())
        return rows

    def test_the_table_counts_only_this_devices_frames_and_acks(self):
        frames = []
        for i in range(4):                                    # ours: four unicast data frames
            frames.append((self._at(f"2026-09-03 08:{10 + i:02d}"), self._psdu(self.DEV, 10 + i)))
        frames.append((self._at("2026-09-03 08:10", 0.002), self._ack(10)))     # ACK for the first
        frames.append((self._at("2026-09-03 08:20"), self._psdu(self.DEV, 20, ftype=3)))   # a poll
        for i in range(10):                                   # the rest of the mesh, same hour
            frames.append((self._at(f"2026-09-03 08:{30 + i:02d}"), self._psdu(self.OTHER, 40 + i)))
        frames.append((self._at("2026-09-03 08:31", 0.002), self._ack(41)))     # and an ACK of theirs
        frames.append((self._at("2026-09-03 09:50"), self._psdu(self.DEV, 60)))  # after a long silence
        text = self._run(frames)
        rows = self._rows(text)
        # date, hour, frames, polls, tx, acked
        self.assertEqual(rows[0][:6], ["09-03", "08h", "5", "1", "5", "1"])
        self.assertEqual(rows[1][:6], ["09-03", "09h", "1", "0", "1", "0"])
        self.assertIn(f"=== {self.DEV} ({self.DEV}) ===", text)
        self.assertIn("silences (>30 min):", text)
        self.assertIn("(90 min)", text)                       # ours only: 08:20 -> 09:50
        self.assertIn("no rejoin-related MLE seen from this device", text)
        self.assertIn("event log: nothing recorded for this device.", text)

    def test_a_device_with_nothing_in_the_window_says_so(self):
        quiet = "72d035122fdf06f6"
        text = self._run([(self._at("2026-09-03 08:10"), self._psdu(self.OTHER, 7))], target=quiet)
        self.assertIn("No frames from this device in the analyzed window.", text)
        self.assertIn("check `threadwatch report` for unknowns", text)
