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

    def test_the_day_count_is_local_days_not_utc_ones(self):
        # Every other day computation here goes through events.day_of,
        # which is local. Bucketing by // 86400 is the UTC calendar day, so
        # two evening episodes on one local day west of Greenwich reported
        # as two days.
        import contextlib
        import io
        import os
        import tempfile
        from threadwatch.events import EventLog, day_of
        from threadwatch.why import print_history
        addr = "b62c32bf669272db"
        old_tz = os.environ.get("TZ")
        os.environ["TZ"] = "America/New_York"
        time.tzset()
        try:
            # 19:00 and 21:00 local on the same day, either side of UTC midnight.
            evening = 1_757_026_800.0                 # 2025-09-04 19:00 EDT, 23:00 UTC
            later = evening + 2 * 3600
            self.assertEqual(day_of(evening), day_of(later))
            self.assertNotEqual(int(evening // 86400), int(later // 86400))
            with tempfile.TemporaryDirectory() as d:
                log = EventLog(Path(d) / "events")
                for at in (evening, later):
                    log.emit("device_quiet", "warning", at, addr=addr, name="TV", silent_for_s=1800)
                    log.emit("device_returned", "notice", at + 900, addr=addr, name="TV")
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    print_history(log.dir, [addr], later + 3600)
            self.assertIn("2 episode(s) across 1 day(s)", out.getvalue())
        finally:
            if old_tz is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = old_tz
            time.tzset()

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

    def _run(self, frames, target=None, quiet_s=None):
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
            if quiet_s is not None:
                cfg.quiet_s = quiet_s
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
        self.assertIn("silences (>30m, the configured [quiet] silence_s):", text)
        self.assertIn("(90 min)", text)                       # ours only: 08:20 -> 09:50
        self.assertIn("no rejoin-related MLE seen from this device", text)
        self.assertIn("event log: nothing recorded for this device.", text)

    def test_the_silence_threshold_is_the_configured_one(self):
        # why hardcoded 30 minutes while the recorder pages after
        # [quiet] silence_s, so "why did this device go offline" reported
        # no silences for the very gap that had just paged. The legacy
        # config path can also produce quiet_s = 5400 from an old
        # router_s / end_device_s pair, putting a stock upgrade out of
        # step in the other direction.
        frames = [(self._at("2026-09-03 08:00"), self._psdu(self.DEV, 1)),
                  (self._at("2026-09-03 08:12"), self._psdu(self.DEV, 2))]
        self.assertNotIn("silences", self._run(frames))                       # 12 min, default 30
        text = self._run(frames, quiet_s=600)
        self.assertIn("silences (>10m, the configured [quiet] silence_s):", text)
        self.assertIn("(12 min)", text)

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

    def test_an_incident_is_read_with_its_own_names_and_history(self):
        # An incident frozen months ago, read on a box whose inventory has
        # moved on: the names, the event log and the recorder's coverage
        # are the incident's own. The silence between its two files was
        # one the recorder slept through for an hour, and the story says so.
        import contextlib
        import io
        import json
        from threadwatch.why import run_why
        inc = self.cfg.incidents_dir / "20260903T100000_storm"
        inc.mkdir(parents=True)
        for hours_ago, seq0 in ((3, 0), (1, 100)):
            self._ring_file(hours_ago, self._frames(hours_ago, 5, seq0))
        for p in self.cfg.ring_dir.iterdir():
            p.rename(inc / p.name)
        self.cfg.ring_dir.rmdir()
        (inc / "devices.json").write_text(json.dumps([{"name": "Frozen AQ", "extendedAddress": self.DEV}]))
        from threadwatch.events import EventLog
        log = EventLog(inc / "events")
        log.emit("recorder_started", "notice", self.now - 1.5 * 3600, cause="unknown", gap_s=3600,
                 last_frame_ts=self.now - 2.5 * 3600, stopped_ts=None, exit_code=None, note="n")
        log.emit("device_quiet", "warning", self.now - 2 * 3600, addr=self.DEV, name="Frozen AQ",
                 silent_for_s=1800, last_seen=self.now - 2.5 * 3600, reception="good")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = run_why(self.cfg, "Frozen AQ", None, hours=None, incident_dir=inc)
        text = out.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn(f"analyzed incident {inc.name}: 2 ring file(s)", text)
        self.assertIn(f"=== Frozen AQ ({self.DEV}) ===", text)
        self.assertIn("(recorder not listening for 60m of it)", text)
        self.assertIn("Frozen AQ quiet for", text)                     # the incident's log, not the live one
        self.assertFalse((self.cfg.data_dir / "state").exists())       # nothing written to the live state
        # --hours counts back from the incident's newest file, not from now.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                run_why(self.cfg, self.DEV, None, hours=0.5, incident_dir=inc / "nothing-here")
        self.assertIn("no pcap files in incident", str(cm.exception))

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
        self.assertIn("silences (>30m, the configured [quiet] silence_s):", out)                     # the 5 h file to the 1 h file

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
from test_identity import KEY, OTHER, PAN, SED, mle_message, secured_frame  # noqa: E402


class WhyMleAnalysisTest(unittest.TestCase):
    """The rejoin evidence the command exists to show. why.py's whole MLE
    half - parse_mle, the per-hour histogram, and the collection of
    Parent Request / Child ID Request / Announce into the attach-attempts
    section - had no test: it could have returned an empty histogram for
    every input and nothing would have noticed."""

    T0 = time.mktime(time.strptime("2026-09-03 08:10", "%Y-%m-%d %H:%M"))

    def _mle_frame(self, src_ext, command, sequence, counter, extra=b""):
        """A MAC-unsecured data frame carrying an MLE-secured command, as a
        device attaching sends on the air."""
        import struct
        fcf = 1 | 0x0040 | (2 << 10) | (1 << 12) | (3 << 14)
        header = struct.pack("<HBH", fcf, counter & 0xFF, PAN) + b"\xff\xff" + bytes.fromhex(src_ext)[::-1]
        iphc = struct.pack(">H", 0x7F3B) + b"\x01"
        udp = b"\xf0" + struct.pack(">HH", 19788, 19788) + b"\x00\x00"
        src_ip = bytes.fromhex("fe80000000000000") + bytes([0x02 ^ int(src_ext[:2], 16)]) + bytes.fromhex(src_ext[2:])
        dst_ip = bytes.fromhex("ff020000000000000000000000000001")
        body = bytes([command]) + extra
        return header + iphc + udp + mle_message(src_ext, sequence, counter, src_ip, dst_ip, body) + b"\x00\x00"

    def _run(self, frames, target=SED):
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
                w = PcapWriter(fh, 195)
                for ts, raw in frames:
                    w.write(Frame(ts=ts, raw=raw, psdu=raw, rssi=None, channel=None, lqi=None))
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = run_why(cfg, target, pcap)
        return code, out.getvalue()

    def test_the_histogram_and_the_attach_section_name_what_the_device_sent(self):
        # Parent Request, then Child ID Request: a device re-attaching. The
        # Advertisement in between is MLE too, and belongs in the histogram
        # but not in the attach-attempts list.
        frames = [(self.T0, self._mle_frame(SED, 9, 5000, 1)),          # Parent Request
                  (self.T0 + 2, self._mle_frame(SED, 4, 5000, 2, b"\x00\x02\x04\x00")),   # Advertisement
                  (self.T0 + 4, self._mle_frame(SED, 11, 5000, 3)),     # Child ID Request
                  (self.T0 + 6, self._mle_frame(SED, 15, 5000, 4))]     # Announce
        code, text = self._run(frames)
        self.assertEqual(code, 0)
        row = next(l for l in text.splitlines() if l.startswith("09-03 08h"))
        for expected in ("Parent Requestx1", "Advertisementx1", "Child ID Requestx1", "Announcex1"):
            self.assertIn(expected, row)
        section = text.split("rejoin-related MLE (attach attempts):")[1]
        self.assertEqual([l.split()[-1] for l in section.splitlines()[1:4]],
                         ["Request", "Request", "Announce"])          # Parent, Child ID, Announce
        self.assertIn("08:10:00  Parent Request", section)
        self.assertIn("08:10:04  Child ID Request", section)
        self.assertNotIn("Advertisement", section)

    def test_the_pipelines_own_rssi_ack_and_poll_figures_are_printed(self):
        # DeviceStats.as_dict had one caller in the repository, a test, so
        # rssi_min, rssi_max, tx, acked, polls and a 32-entry interval
        # deque per device were maintained on the per-frame path and never
        # observed anywhere, while the README says why shows them. The
        # hour table counts an ACK on a sequence match alone; these are
        # the pipeline's stricter figures, which is what the recorder
        # judges a link by.
        import struct
        frames = [(self.T0, secured_frame(SED, "00aa", counter=1)),
                  (self.T0 + 0.002, struct.pack("<HB", 2, 1) + b"\x00\x00")]   # ACK for the first
        frames += [(self.T0 + 1 + i, secured_frame(SED, "00aa", counter=2 + i)) for i in range(3)]
        for i in range(3):                                              # polls, two minutes apart
            frames.append((self.T0 + 10 + 120 * i, secured_frame(SED, "00aa", counter=10 + i, ftype=3)))
        code, text = self._run(frames)
        self.assertEqual(code, 0)
        self.assertIn("acked: 14% of 7 unicast", text)
        self.assertIn("polls: 3 every 2m (median)", text)
        self.assertIn("rssi:  -", text)                                 # the test frames carry none

    def test_a_device_that_never_tried_to_attach_is_said_so_in_as_many_words(self):
        # The documented reasoning: no rejoin after a silence points at the
        # device rather than at RF, so the absence has to be printed.
        code, text = self._run([(self.T0, self._mle_frame(SED, 4, 5000, 1, b"\x00\x02\x04\x00"))])
        self.assertEqual(code, 0)
        self.assertIn("no rejoin-related MLE seen from this device in the window.", text)
        self.assertNotIn("attach attempts", text)

    def test_a_payload_that_cannot_be_decoded_is_counted_not_fatal(self):
        import struct
        fcf = 1 | 0x0040 | (2 << 10) | (1 << 12) | (3 << 14)
        header = struct.pack("<HBH", fcf, 1, PAN) + b"\xff\xff" + bytes.fromhex(SED)[::-1]
        # An IPHC header that says a UDP header follows and then stops.
        broken = header + struct.pack(">H", 0x7F3B) + b"\x01" + b"\xf0" + b"\x00\x00"
        code, text = self._run([(self.T0, broken),
                                (self.T0 + 2, self._mle_frame(SED, 9, 5000, 2))])
        self.assertEqual(code, 0)
        self.assertIn("frames with undecodable payloads skipped", text)
        self.assertIn("Parent Request", text)                  # the good frame still read

    def test_a_name_that_resolves_to_nothing_exits_with_the_resolver_s_message(self):
        with self.assertRaises(SystemExit) as cm:
            self._run([], target="nothing like it")
        self.assertIn("neither a 16-hex-char address nor a known device name", str(cm.exception))


class WhyIncidentWindowTest(unittest.TestCase):
    """--hours inside a frozen incident counts back from where the freeze
    stopped, not from now, so it can select nothing."""

    def _run(self, hours, files=("20260903-08", "20260903-09")):
        import contextlib
        import io
        import tempfile
        from threadwatch.config import Config
        from threadwatch.pcap import PcapWriter
        from threadwatch.why import run_why
        with tempfile.TemporaryDirectory() as d:
            cred = Path(d) / "credentials.toml"
            cred.write_text(f'[credentials]\nnetwork_key = "{KEY.hex()}"\n')
            cfg = Config(data_dir=Path(d) / "data", credentials_path=cred)
            inc = cfg.incidents_dir / "20260903T100000_storm"
            inc.mkdir(parents=True)
            for name in files:
                with open(inc / f"threadwatch-{name}.pcap", "wb") as fh:
                    PcapWriter(fh, 195)
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = run_why(cfg, SED, hours=hours, incident_dir=inc)
            return code, out.getvalue()

    def test_the_window_counts_back_from_the_freeze_not_from_now(self):
        # These files are days old by the time anyone reads the bundle, so
        # counting back from now would select nothing from any incident.
        code, text = self._run(hours=48)
        self.assertEqual(code, 0)
        self.assertIn("analyzed incident 20260903T100000_storm: last 48 h: 2 ring file(s)", text)
        code, text = self._run(hours=0.25)
        self.assertEqual(code, 0)
        self.assertIn("last 0.25 h: 1 ring file(s), 20260903-09 to 20260903-09", text)
        # An empty bundle is the one case with nothing to read at all. (The
        # "no files in the last N h" arm below it cannot be reached: the
        # window ends where the newest file ends, so that file is always in
        # it, and a name that does not parse as an hour is always kept.)
        with self.assertRaises(SystemExit) as cm:
            self._run(hours=1, files=())
        self.assertIn("no pcap files in incident", str(cm.exception))


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
