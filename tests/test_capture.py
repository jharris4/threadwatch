"""status.json as the capture daemon writes it, and what a later run reads back."""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.capture import (EXIT_FILE, EXIT_SNIFFER_DIED, EXIT_STALLED, PERIODIC_S, STALL_TIMEOUT_S, TICK_S,  # noqa: E402
                                 Housekeeping, _write_status, capture_healthy, capture_stalled,
                                 last_frame_on_record, periodic_due, record_exit, status_tick, watchdog_verdict)
from threadwatch.config import Config  # noqa: E402
from threadwatch.crypto import Decryptor  # noqa: E402
from threadwatch.events import NullEventLog  # noqa: E402
from threadwatch.pipeline import Pipeline  # noqa: E402


class StatusFileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config(data_dir=Path(self.tmp.name) / "data")
        self.pipe = Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)), ephemeral=True)
        self.ring = SimpleNamespace(current_path=self.cfg.ring_dir / "threadwatch-20260904-10.pcap")

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, **kw):
        _write_status(self.cfg, "/dev/x", 12, time.time() - 100, self.pipe, self.ring, self.pipe.decryptor, **kw)
        return json.loads((self.cfg.state_dir / "status.json").read_text())

    def test_last_frame_stamp_is_written_and_read_back(self):
        self.assertIsNone(last_frame_on_record(self.cfg.state_dir))      # no file yet
        st = self._write(last_frame_age=170.0)                            # a run that heard nothing
        self.assertEqual((st["last_frame_age_s"], st["last_frame_ts"], st["frames_total"]), (170.0, None, 12))
        self.assertIsNone(last_frame_on_record(self.cfg.state_dir))
        heard = time.time() - 7200
        st = self._write(last_frame_age=170.0, last_frame_ts=heard)      # carried from an earlier run
        self.assertEqual(st["last_frame_ts"], heard)
        self.assertEqual(last_frame_on_record(self.cfg.state_dir), heard)
        self.assertEqual(st["current_file"], str(self.ring.current_path))
        (self.cfg.state_dir / "status.json").write_text("{not json")
        self.assertIsNone(last_frame_on_record(self.cfg.state_dir))


class ExitNoteTest(unittest.TestCase):
    """The note a run leaves about how it ended, for the next start's
    recorder_started record and the review's coverage."""

    def test_every_exit_path_leaves_its_reason_and_the_last_frame(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d)
            heard = time.time() - 200
            for code, reason in ((0, "stopped"), (1, "crashed"), (EXIT_STALLED, "stalled"),
                                 (3, "stream_ended"), (EXIT_SNIFFER_DIED, "sniffer_died"), (7, "exit_7")):
                self.assertEqual(record_exit(state, code, heard, now=heard + 190), reason)
                note = json.loads((state / EXIT_FILE).read_text())
                self.assertEqual((note["code"], note["reason"], note["last_frame_ts"], note["ts"]),
                                 (code, reason, heard, heard + 190))
            self.assertEqual(sorted(p.name for p in state.iterdir()), [EXIT_FILE])   # written whole, renamed in
            self.assertEqual(record_exit(state, 0, None), "stopped")                # a run that heard nothing
            self.assertIsNone(json.loads((state / EXIT_FILE).read_text())["last_frame_ts"])

    def test_a_note_that_cannot_be_written_is_not_fatal(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(record_exit(Path(d) / "missing" / "state", EXIT_STALLED, None))


class StatusConsumersTest(unittest.TestCase):
    """One status.json, written by the daemon and read by everything that
    reads it: the web header and status page, doctor, and `threadwatch
    status`. Each consumer used to be tested against a fixture of its own,
    so the writer and the readers could drift apart unnoticed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        (self.d / "config.toml").write_text(f'[capture]\ndata_dir = "{self.d / "data"}"\n')
        self.cfg = Config(data_dir=self.d / "data")
        self.pipe = Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)), ephemeral=True)
        self.ring = SimpleNamespace(current_path=self.cfg.ring_dir / "threadwatch-20260904-10.pcap")

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_written_file_is_the_file_every_consumer_reads(self):
        import contextlib
        import io
        from threadwatch.cli import main
        from threadwatch.doctor import OK, WARN, check_daemon
        from threadwatch.web import Site
        self.pipe.decryptor.stats["mac_decrypted"] = 41
        now = time.time()
        # A run that is alive but has heard nothing for a while: the state
        # where each consumer has something of its own to say.
        _write_status(self.cfg, "/dev/tty.usbmodem1", 4210, now - 3600, self.pipe,
                      self.ring, self.pipe.decryptor, last_frame_age=170.0, last_frame_ts=now - 170)
        st = json.loads((self.cfg.state_dir / "status.json").read_text())
        self.assertEqual(sorted(st), ["channel", "crypto", "current_file", "detector", "devices_tracked",
                                      "frames_total", "last_frame_age_s", "last_frame_ts", "partition",
                                      "port", "updated", "uptime_s"])
        self.assertEqual(sorted(st["crypto"]), sorted([*self.pipe.decryptor.stats, "key_sequence"]))

        site = Site(self.cfg)
        self.assertEqual(site.status(), st)
        header = site.header()
        self.assertIn("no frames for", header)          # last_frame_age_s, not "capturing"
        self.assertIn("<b>4,210</b> frames", header)
        self.assertIn(f'ch {self.cfg.channel}', header)
        self.assertIn("41 decrypted", header)
        page = site.status_page()
        self.assertIn("threadwatch-20260904-10.pcap", page)
        self.assertIn("/dev/tty.usbmodem1", page)
        self.assertIn("mac_decrypted 41", page)         # every crypto key is printed by name

        self.assertEqual(check_daemon(self.cfg, now)[0][:2], (WARN, "capture"))
        self.assertIn("no frames for 170 s", check_daemon(self.cfg, now)[0][2])
        # ...and it reads as healthy once a frame has just arrived.
        _write_status(self.cfg, "/dev/tty.usbmodem1", 4211, now - 3600, self.pipe,
                      self.ring, self.pipe.decryptor, last_frame_age=1.0, last_frame_ts=now - 1)
        self.assertEqual(check_daemon(self.cfg, now)[0][:2], (OK, "capture"))
        self.assertIn("capturing", Site(self.cfg).header())

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["--config", str(self.d / "config.toml"), "status"])
        printed = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(printed["daemon_alive"])
        self.assertEqual({k: v for k, v in printed.items()
                          if k not in ("status_age_s", "daemon_alive")},
                         json.loads((self.cfg.state_dir / "status.json").read_text()))


if __name__ == "__main__":
    unittest.main()


class StallWatchdogTest(unittest.TestCase):
    """The watchdog is the only thing that notices a dead dongle, a host
    sleep/wake or a sniffer child that stopped delivering: the main thread
    is blocked in the FIFO read and looks alive forever. Its timeout is the
    size of the hole a stall leaves in the flight record."""

    def test_three_minutes_without_a_frame_is_a_stall(self):
        self.assertEqual(STALL_TIMEOUT_S, 180.0)
        self.assertFalse(capture_stalled(179.0))
        self.assertFalse(capture_stalled(180.0))
        self.assertTrue(capture_stalled(181.0))
        self.assertTrue(capture_stalled(181.0, STALL_TIMEOUT_S))
        self.assertFalse(capture_stalled(181.0, 1800.0))    # the timeout is the whole decision


class HeartbeatHealthTest(unittest.TestCase):
    """What the liveness heartbeat tells the monitor. Unknown until this run
    has heard a frame (a restart loop that never hears one must not keep a
    monitor reassured), then healthy only while the last frame is fresher
    than the stall timeout: widened, the recorder beats "healthy" through
    an outage, the one thing the heartbeat exists to prevent."""

    def test_health_is_unknown_before_a_frame_and_gone_at_the_stall_timeout(self):
        self.assertIsNone(capture_healthy(None, 5000.0))
        self.assertTrue(capture_healthy(1000.0, 1179.0))
        self.assertFalse(capture_healthy(1000.0, 1180.0))
        self.assertFalse(capture_healthy(1000.0, 1181.0))
        self.assertTrue(capture_healthy(1000.0, 1181.0, 1800.0))   # the timeout is the whole decision


class WatchdogVerdictTest(unittest.TestCase):
    """The watchdog's two ways out. A sniffer thread dead before any data
    is the serial port busy or gone (a second capture started by hand, a
    dongle unplugged between enumeration and open): exit at once, or the
    main thread waits on a FIFO nothing will ever write, behind a "no
    frames" message three minutes later that blames the wrong thing."""

    def test_a_dead_sniffer_exits_at_once_and_a_stall_at_the_timeout(self):
        self.assertEqual((EXIT_STALLED, EXIT_SNIFFER_DIED), (2, 4))
        self.assertEqual(watchdog_verdict(30.0, ring_open=False, sniffer_alive=False), EXIT_SNIFFER_DIED)
        self.assertIsNone(watchdog_verdict(30.0, ring_open=False, sniffer_alive=True))    # still opening the port
        self.assertIsNone(watchdog_verdict(30.0, ring_open=True, sniffer_alive=False))    # the FIFO closes: main loop's exit
        self.assertIsNone(watchdog_verdict(30.0, ring_open=True, sniffer_alive=True))
        self.assertEqual(watchdog_verdict(181.0, ring_open=True, sniffer_alive=True), EXIT_STALLED)
        self.assertEqual(watchdog_verdict(181.0, ring_open=False, sniffer_alive=True), EXIT_STALLED)   # alive, never delivered
        self.assertEqual(watchdog_verdict(181.0, ring_open=False, sniffer_alive=False), EXIT_SNIFFER_DIED)


class PeriodicTickTest(unittest.TestCase):
    """Pipeline.periodic is where silences are judged and state is saved,
    and the main loop runs it once per 30 s of frame time. Slower, and
    every device_quiet lands late and a crash loses more of the table;
    the loop only ever ran it inline, so nothing pinned the interval."""

    B = 1_700_000_010.0          # a multiple of 30: the start of a period

    def test_periodic_is_due_once_per_thirty_seconds_and_never_on_the_first_tick(self):
        self.assertEqual((TICK_S, PERIODIC_S), (10.0, 30))
        B = self.B
        self.assertFalse(periodic_due(0.0, B))                # the loop's first tick
        self.assertFalse(periodic_due(B, B + 10))             # still the period that began at B
        self.assertFalse(periodic_due(B + 10, B + 20))
        self.assertTrue(periodic_due(B + 20, B + 30))         # the next period begins
        self.assertFalse(periodic_due(B + 30, B + 40))
        self.assertTrue(periodic_due(B + 50, B + 60))
        self.assertTrue(periodic_due(B + 20, B + 300))        # a gap: due at once, not once per missed period

    def test_the_loop_runs_it_ten_times_in_five_minutes_of_frames(self):
        ran, clock = [], Housekeeping()
        for i in range(301):                                  # a frame a second, as the main loop sees them
            if clock.due(self.B + i, 5000.0 + i):
                ran.append(i)
        self.assertEqual(ran, [30, 60, 90, 120, 150, 180, 210, 240, 270, 300])

    def test_housekeeping_goes_on_after_a_clock_step_either_way(self):
        # BUG-05: with the ticks spaced on the frame clock, a step back of
        # an hour (NTP correcting a Pi that booted on a saved time, or a
        # manual set) held every periodic call until the wall clock had
        # caught up with the last tick. The monotonic clock spaces them.
        for step in (-3600.0, 3600.0):
            with self.subTest(step=step):
                ran, clock = [], Housekeeping()
                for i in range(120):
                    clock.due(self.B + i, 5000.0 + i)
                for i in range(120, 421):                     # the clock steps between two frames
                    if clock.due(self.B + i + step, 5000.0 + i):
                        ran.append(i)
                # The tick that sees the step is a new period (a call at
                # once, not a wait), then one per PERIODIC_S as before.
                self.assertEqual(ran, list(range(120, 421, PERIODIC_S)))


class StatusTickTest(unittest.TestCase):
    """The watchdog's status.json refresh. last_frame_ts is the stamp of
    the last frame any run heard: this run's, else the one the previous
    run's file recorded, else None. Stamping the current time instead
    would make a stalled recorder look fresh to doctor, the web header
    and the next run's blindness accounting, all of which read it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config(data_dir=Path(self.tmp.name) / "data")
        self.pipe = Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)), ephemeral=True)
        self.ring = SimpleNamespace(current_path=self.cfg.ring_dir / "threadwatch-20260904-10.pcap")
        self.logs = []

    def tearDown(self):
        self.tmp.cleanup()

    def _tick(self, beat, prior_frame, started_mono):
        age = status_tick(self.cfg, "/dev/x", beat, time.time() - 3600, started_mono,
                          self.pipe, self.pipe.decryptor, prior_frame, self.logs.append)
        path = self.cfg.state_dir / "status.json"
        return age, (json.loads(path.read_text()) if path.exists() else None)

    def test_last_frame_ts_is_a_frame_the_recorder_heard_never_the_time_now(self):
        mono = time.monotonic()
        prior = time.time() - 7200                                    # the previous run's last frame
        # Before the ring is open nothing is written, but the stall clock runs from start-up.
        age, st = self._tick({"last_frame": None, "last_frame_mono": None, "total": 0, "ring": None}, prior, mono - 170)
        self.assertAlmostEqual(age, 170.0, delta=2.0)
        self.assertIsNone(st)
        # Open, nothing heard this run: the earlier run's stamp is carried, and the age says so.
        age, st = self._tick({"last_frame": None, "last_frame_mono": None, "total": 0, "ring": self.ring}, prior, mono - 170)
        self.assertAlmostEqual(age, 170.0, delta=2.0)
        self.assertEqual((st["last_frame_ts"], st["last_frame_age_s"], st["frames_total"]), (prior, round(age, 1), 0))
        self.assertLess(st["last_frame_ts"], time.time() - 7000)
        # A frame heard this run, fifty seconds ago, is the stamp whatever an earlier run recorded.
        heard = time.time() - 50
        age, st = self._tick({"last_frame": heard, "last_frame_mono": mono - 50, "total": 12, "ring": self.ring},
                             prior, mono - 170)
        self.assertAlmostEqual(age, 50.0, delta=2.0)
        self.assertEqual((st["last_frame_ts"], st["frames_total"]), (heard, 12))
        # No run has ever heard one: None, not now.
        _age, st = self._tick({"last_frame": None, "last_frame_mono": None, "total": 0, "ring": self.ring}, None, mono - 170)
        self.assertIsNone(st["last_frame_ts"])
        self.assertEqual(self.logs, [])

    def test_a_status_file_that_cannot_be_written_is_logged_and_the_stall_clock_still_runs(self):
        (self.cfg.state_dir / "status.tmp").mkdir(parents=True)          # the temp file's name is taken
        mono = time.monotonic()
        age, st = self._tick({"last_frame": None, "last_frame_mono": mono - 200, "total": 3, "ring": self.ring},
                             None, mono - 300)
        self.assertAlmostEqual(age, 200.0, delta=2.0)
        self.assertIsNone(st)
        self.assertEqual(len(self.logs), 1)
        self.assertTrue(self.logs[0].startswith("status.json not written: "), self.logs)
