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

    def _psdu(self, addr, seq, ftype=1, dst="0000", cmd=4):
        """A data frame, or (ftype 3) an unsecured MAC command: a data
        request (4, a poll) unless another command id is given."""
        import struct
        fcf = ftype | 0x0040 | (2 << 10) | (1 << 12) | (3 << 14)   # pan compressed, short dst, ext src
        payload = bytes([cmd, 0x33]) if ftype == 3 else b"\x7f\x33"
        return (struct.pack("<HBH", fcf, seq, 0x4e21) + bytes.fromhex(dst)[::-1]
                + bytes.fromhex(addr)[::-1] + payload)

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
                self.rc = run_why(cfg, target or self.DEV, pcap)
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
        # A beacon request (MAC command 7, a join scan) is a MAC command
        # but not a poll: it used to be counted as one.
        frames.append((self._at("2026-09-03 08:15"), self._psdu(self.DEV, 21, ftype=3, dst="ffff", cmd=7)))
        for i in range(10):                                   # the rest of the mesh, same hour
            frames.append((self._at(f"2026-09-03 08:{30 + i:02d}"), self._psdu(self.OTHER, 40 + i)))
        frames.append((self._at("2026-09-03 08:31", 0.002), self._ack(41)))     # and an ACK of theirs
        frames.append((self._at("2026-09-03 09:50"), self._psdu(self.DEV, 60)))  # after a long silence
        text = self._run(frames)
        rows = self._rows(text)
        # date, hour, frames, polls, tx, acked
        self.assertEqual(rows[0][:6], ["09-03", "08h", "6", "1", "5", "1"])
        self.assertEqual(rows[1][:6], ["09-03", "09h", "1", "0", "1", "0"])
        self.assertIn(f"=== {self.DEV} ({self.DEV}) ===", text)
        self.assertIn("silences (>30 min):", text)
        self.assertIn("(90 min)", text)                       # ours only: 08:20 -> 09:50
        self.assertIn("no rejoin-related MLE seen from this device", text)
        self.assertIn("event log: nothing recorded for this device.", text)

    def test_a_pcap_that_cannot_be_read_is_an_error_not_a_diagnosis(self):
        # "No frames from this device" over zero examined packets, with
        # exit 0, is the wrong answer in the middle of an outage.
        import contextlib
        import io
        import tempfile
        from threadwatch.config import Config
        from threadwatch.why import run_why
        with tempfile.TemporaryDirectory() as d:
            cred = Path(d) / "credentials.toml"
            cred.write_text('[credentials]\nnetwork_key = "00112233445566778899aabbccddeeff"\n')
            cfg = Config(data_dir=Path(d) / "data", credentials_path=cred)
            junk = Path(d) / "notes.txt"
            junk.write_text("not a capture")
            for path in (Path(d) / "missing.pcap", junk):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    with self.assertRaises(SystemExit) as cm:
                        run_why(cfg, self.DEV, path)
                self.assertIn(str(path), str(cm.exception))
                self.assertIn("could not read", str(cm.exception))
                self.assertNotIn("No frames from this device", out.getvalue())
                self.assertNotIn("Interpretation", out.getvalue())
                self.assertIn(f"(skipping {path}", err.getvalue())    # the detail goes to stderr

    def test_a_readable_pcap_returns_zero(self):
        self._run([(self._at("2026-09-03 08:10"), self._psdu(self.DEV, 7))])
        self.assertEqual(self.rc, 0)
        self._run([(self._at("2026-09-03 08:10"), self._psdu(self.OTHER, 7))])   # a real "no frames" verdict
        self.assertEqual(self.rc, 0)


        quiet = "72d035122fdf06f6"
        text = self._run([(self._at("2026-09-03 08:10"), self._psdu(self.OTHER, 7))], target=quiet)
        self.assertIn("No frames from this device in the analyzed window.", text)
        self.assertIn("check `threadwatch report` for unknowns", text)


class RunWhyRingTest(unittest.TestCase):
    """`why` without --pcap reads the ring: the files of the last --hours
    (or all of them), says which, and carries on past one it cannot read
    while saying that too. This is the form an operator runs during an
    outage; the tests above only ever handed it one file."""

    DEV = RunWhyTest.DEV
    OTHER = RunWhyTest.OTHER

    def setUp(self):
        import tempfile
        from threadwatch.config import Config
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        cred = d / "credentials.toml"
        cred.write_text('[credentials]\nnetwork_key = "00112233445566778899aabbccddeeff"\n')
        self.cfg = Config(data_dir=d / "data", credentials_path=cred)
        self.now = time.time()

    def tearDown(self):
        self.tmp.cleanup()

    def _hour(self, hours_ago):
        return time.strftime("%Y%m%d-%H", time.localtime(self.now - hours_ago * 3600))

    def _ring_file(self, hours_ago, frames):
        """A ring file named for the hour, holding (ts, psdu) frames."""
        from threadwatch.pcap import DLT_NOFCS, Frame, PcapWriter
        self.cfg.ring_dir.mkdir(parents=True, exist_ok=True)
        path = self.cfg.ring_dir / f"threadwatch-{self._hour(hours_ago)}.pcap"
        with open(path, "wb") as fh:
            w = PcapWriter(fh, DLT_NOFCS)
            for ts, psdu in frames:
                w.write(Frame(ts=ts, raw=psdu, psdu=psdu, rssi=None, channel=None, lqi=None))
        return path

    def _frames(self, hours_ago, n, seq0=0):
        t0 = self.now - hours_ago * 3600
        return [(t0 + i, RunWhyTest._psdu(self, self.DEV, seq0 + i)) for i in range(n)]

    def _run(self, hours=None):
        import contextlib
        import io
        from threadwatch.why import run_why
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = run_why(self.cfg, self.DEV, None, hours=hours)
        return rc, out.getvalue(), err.getvalue()

    @staticmethod
    def _frames_in_table(text):
        return sum(int(row[2]) for row in RunWhyTest._rows(None, text))

    def test_no_ring_is_said_plainly(self):
        with self.assertRaises(SystemExit) as cm:
            self._run()
        self.assertEqual(str(cm.exception), "no ring files; is the capture daemon running?")
        self.cfg.ring_dir.mkdir(parents=True)                         # a ring directory with nothing in it
        with self.assertRaises(SystemExit) as cm:
            self._run(hours=2)
        self.assertEqual(str(cm.exception), "no ring files; is the capture daemon running?")

    def test_a_window_the_ring_does_not_reach_names_what_the_ring_spans(self):
        self._ring_file(6, self._frames(6, 2))
        self._ring_file(5, self._frames(5, 2))
        with self.assertRaises(SystemExit) as cm:
            self._run(hours=2)
        self.assertEqual(str(cm.exception),
                         f"no ring files in the last 2 h (the ring spans {self._hour(6)} to {self._hour(5)})")

    def test_hours_selects_the_files_and_none_selects_them_all(self):
        self._ring_file(5, self._frames(5, 3))
        self._ring_file(1, self._frames(1, 4, seq0=10))
        self._ring_file(0, self._frames(0, 5, seq0=20))
        rc, out, _err = self._run(hours=2)
        self.assertEqual(rc, 0)
        self.assertIn(f"analyzed last 2 h: 2 ring file(s), {self._hour(1)} to {self._hour(0)}", out)
        self.assertEqual(self._frames_in_table(out), 9)
        rc, out, _err = self._run()
        self.assertEqual(rc, 0)
        self.assertIn(f"analyzed 3 ring file(s), {self._hour(5)} to {self._hour(0)}", out)
        self.assertEqual(self._frames_in_table(out), 12)
        self.assertIn("silences (>30 min):", out)                     # the 5 h file to the 1 h file

    def test_a_ring_file_that_cannot_be_read_is_reported_and_the_rest_still_counts(self):
        bad = self._ring_file(1, [])
        bad.write_bytes(b"\x00" * 40)                                 # a power cut left NULs: no usable header
        self._ring_file(0, self._frames(0, 5))
        rc, out, err = self._run(hours=2)
        self.assertEqual(rc, 1)
        self.assertIn(f"(skipping {bad}: ", err)
        self.assertIn("WARNING: 1 of 2 ring file(s) could not be read (see stderr); what follows covers the rest only", out)
        self.assertIn(f"=== {self.DEV} ({self.DEV}) ===", out)
        self.assertEqual(self._frames_in_table(out), 5)
        self.assertNotIn("No frames from this device", out)
        bad.unlink()
        self._ring_file(1, []).write_bytes(b"\x00" * 40)
        self.cfg.ring_dir.joinpath(f"threadwatch-{self._hour(0)}.pcap").write_bytes(b"junk")
        with self.assertRaises(SystemExit) as cm:                     # none readable: no report at all
            self._run(hours=2)
        self.assertIn("none of the 2 ring files could be read", str(cm.exception))


sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_identity import AESCCM, KEY, OTHER, PAN, SED, mle_message, secured_frame  # noqa: E402


@unittest.skipIf(AESCCM is None, "cryptography not installed")
class WhyNetworkContextTest(unittest.TestCase):
    """BUG-04: `why` used to identify frames without ingesting them, so an
    MLE advertisement from another device (the one thing that carries a
    key sequence past the decryptor's initial search) was skipped as not
    ours, and the target's polls under that sequence resolved to nobody."""

    def _run(self, frames, target):
        import contextlib
        import io
        import tempfile
        from threadwatch.config import Config
        from threadwatch.pcap import Frame, PcapWriter
        from threadwatch.why import run_why
        with tempfile.TemporaryDirectory() as d:
            cred = Path(d) / "credentials.toml"
            cred.write_text(f'[credentials]\nnetwork_key = "{KEY.hex()}"\n')
            cfg = Config(data_dir=Path(d) / "data", credentials_path=cred)
            pcap = Path(d) / "window.pcap"
            with open(pcap, "wb") as fh:
                w = PcapWriter(fh, 195)                         # frames carry an FCS, as the sniffer's do
                for ts, raw in frames:
                    w.write(Frame(ts=ts, raw=raw, psdu=raw, rssi=None, channel=None, lqi=None))
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                run_why(cfg, target, pcap)
        return out.getvalue()

    @staticmethod
    def _advertisement(src_ext, sequence, counter):
        """A MAC-unsecured data frame to the broadcast PAN carrying an
        MLE-secured Advertisement, as every router sends on the air."""
        import struct
        fcf = 1 | 0x0040 | (2 << 10) | (1 << 12) | (3 << 14)
        header = struct.pack("<HBH", fcf, counter & 0xFF, PAN) + b"\xff\xff" + bytes.fromhex(src_ext)[::-1]
        iphc = struct.pack(">H", 0x7F3B) + b"\x01"
        udp = b"\xf0" + struct.pack(">HH", 19788, 19788) + b"\x00\x00"
        src_ip = bytes.fromhex("fe80000000000000") + bytes([0x02 ^ int(src_ext[:2], 16)]) + bytes.fromhex(src_ext[2:])
        dst_ip = bytes.fromhex("ff020000000000000000000000000001")
        body = b"\x04" + b"\x00\x02" + bytes.fromhex("0400")   # Advertisement, Source Address 0x0400
        # With an FCS, as the DLT 195 file it goes into says every frame
        # has: the reader strips it, or the MLE MIC (over the whole
        # payload) would fail on every unsecured frame in such a capture.
        return header + iphc + udp + mle_message(src_ext, sequence, counter, src_ip, dst_ip, body) + b"\x00\x00"

    def test_another_devices_mle_supplies_the_sequence_the_targets_polls_need(self):
        t0 = time.mktime(time.strptime("2026-09-03 08:10", "%Y-%m-%d %H:%M"))
        frames = [(t0, self._advertisement(OTHER, 5000, 9)),
                  (t0 + 5, secured_frame(SED, "c829", 10, ftype=3, sequence=5000))]
        text = self._run(frames, SED)
        self.assertNotIn("No frames from this device", text)
        self.assertIn(f"=== {SED} ({SED}) ===", text)
        row = next(l.split() for l in text.splitlines() if l.startswith("09-03 08h"))
        self.assertEqual(row[2:4], ["1", "1"])                   # one frame, and it is a poll
        # The advertisement itself stays the other device's frame.
        self.assertNotIn("Advertisement", text)
