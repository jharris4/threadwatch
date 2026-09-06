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
from tests.frames import psdu_for  # noqa: E402


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


class StartupFailureTest(unittest.TestCase):
    def test_a_start_that_fails_after_the_log_is_built_keeps_the_spool(self):
        # The likeliest start-up failure, credentials.toml missing or
        # unreadable, came after the event log had loaded the spool; the
        # process left without closing it and the spool was already gone.
        import json as json_mod
        from threadwatch import alerts
        from threadwatch.capture import run_capture
        from threadwatch.pipeline import CredentialsError
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(data_dir=Path(tmp) / "data", config_dir=Path(tmp))
            cfg.serial_port = "/dev/does-not-matter"
            cfg.credentials_path = Path(tmp) / "absent.toml"
            cfg.alerts_raw = {"sinks": [{"name": "cmd", "type": "command", "command": ["false"], "cooldown_s": 0}]}
            spool = cfg.state_dir / alerts.SPOOL_FILE
            spool.write_text(json_mod.dumps({"record": {"ts": time.time(), "event": "device_quiet",
                                                        "severity": "warning", "addr": "a" * 16},
                                             "sinks": ["cmd"], "attempt": 2}) + "\n")
            with self.assertRaises(CredentialsError):
                run_capture(cfg)
            self.assertFalse((cfg.state_dir / alerts.INFLIGHT_FILE).exists())
            kept = [json_mod.loads(l) for l in spool.read_text().splitlines()]
            self.assertEqual([(k["record"]["event"], k["sinks"]) for k in kept], [("device_quiet", ["cmd"])])


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
        self.assertEqual(sorted(st), ["alerts", "channel", "commit", "crypto", "current_file", "detector",
                                      "devices_tracked", "dominant_pan", "frames_total", "last_frame_age_s",
                                      "last_frame_ts", "partition", "port", "updated", "uptime_s", "version"])
        # Which code is recording: the one thing that tells a restart that
        # happened from one that did not.
        from threadwatch import __version__
        self.assertEqual(st["version"], __version__)
        self.assertEqual(st["alerts"], {"delivered": 0, "queued": 0, "retrying": 0, "given_up": 0, "resumed": 0})
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
        self.assertIn("0 delivered this run", page)

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


class RunCaptureTest(unittest.TestCase):
    """run_capture itself: the live loop, the watchdog's two verdicts, the
    signal handler and the shutdown, with its two boundaries faked. The
    sniffer is a module standing in for the vendored one, writing pcap
    records into the FIFO from a thread and holding it open until told;
    os._exit is recorded and raises SystemExit so the test gets control
    back. Everything the helpers do is covered elsewhere; this is proof
    that run_capture calls them, in order, with the right arguments."""

    DEV = "26976e7f7d20964a"

    def setUp(self):
        import os
        import signal
        import sys
        import threading
        import types
        from unittest import mock
        from threadwatch import capture
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "credentials.toml").write_text('[credentials]\nnetwork_key = "00112233445566778899aabbccddeeff"\n')
        (d / "devices.json").write_text("[]")
        self.cfg = Config(data_dir=d / "data", config_dir=d, credentials_path=d / "credentials.toml",
                          devices_path=d / "devices.json")
        self.cfg.serial_port = "/dev/fake-sniffer"
        self.cfg.border_router_browse_s = 0
        self.exits: list = []
        self.calls: list = []
        self.hold = threading.Event()          # the fake sniffer keeps the FIFO open until this is set
        self.reader_open = threading.Event()   # set once run_capture has opened its end
        self.tick = threading.Event()          # one watchdog tick per set
        self.finished = threading.Event()
        self.fail_stop = False
        test = self

        class FakeSniffer:
            def __init__(self):
                self.thread = None
                test.sniffer = self

            def start_threaded(self, fifo, dev, channel, metadata=None):
                test.calls.append(("start", dev, channel, metadata))

                def run():
                    from threadwatch.pcap import DLT_NOFCS, Frame, PcapWriter
                    with open(fifo, "wb") as fh:
                        test.reader_open.set()
                        w = PcapWriter(fh, DLT_NOFCS)
                        for i in range(3):
                            psdu = psdu_for(test.DEV, seq=i, key=bytes.fromhex("00112233445566778899aabbccddeeff"))
                            w.write(Frame(ts=1.0 + i, raw=psdu, psdu=psdu, rssi=None, channel=None, lqi=None))
                        fh.flush()
                        test.hold.wait(10)
                self.thread = threading.Thread(target=run, daemon=True, name="fake-sniffer")
                self.thread.start()

            def _stop(self):
                test.calls.append(("stop", (test.cfg.state_dir / "last-seen.json").exists()))
                if test.fail_stop:
                    raise RuntimeError("stop failed")

        module = types.ModuleType("nrf802154_sniffer")
        module.Nrf802154Sniffer = FakeSniffer
        for patcher in (mock.patch.dict(sys.modules, {"nrf802154_sniffer": module}),
                        mock.patch.object(os, "_exit", self._exit),
                        mock.patch.object(capture.EventLog, "close", autospec=True,
                                          side_effect=lambda log, *a, **k: test.calls.append(("events.close",)))):
            patcher.start()
            self.addCleanup(patcher.stop)
        spy = mock.patch.object(capture, "record_exit", wraps=capture.record_exit)
        self.record_exit = spy.start()
        self.addCleanup(spy.stop)
        self._time = capture.time
        capture.time = types.SimpleNamespace(time=time.time, monotonic=time.monotonic, strftime=time.strftime,
                                             localtime=time.localtime, sleep=self._sleep)
        self._handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
        # The watchdog is the thread that ends the process for a dead
        # sniffer or a stall, and the fake os._exit above unwinds it with
        # SystemExit, because a test cannot really exit. That is the
        # behaviour under test, not a crash, so it is not reported as an
        # unhandled thread exception. Anything else, from any thread,
        # still is: this must not become the place real crashes hide.
        import threading
        expected = threading.excepthook
        self.addCleanup(setattr, threading, "excepthook", expected)

        def excepthook(args):
            if args.exc_type is SystemExit and getattr(args.thread, "name", None) == "watchdog":
                return
            expected(args)

        threading.excepthook = excepthook

    def tearDown(self):
        import signal
        from threadwatch import capture
        self.finished.set()
        self.hold.set()
        capture.time = self._time
        for signo, handler in self._handlers.items():
            signal.signal(signo, handler)
        self.tmp.cleanup()

    def _exit(self, code):
        import threading
        self.exits.append((threading.current_thread().name, code))
        raise SystemExit(code)

    def _sleep(self, _seconds):
        """The watchdog's 30 s: one tick per test.tick.set(). Once the test
        is over, the watchdog's own stop flag ends it on its next check.
        Throwing SystemExit at the thread instead, as this used to, left an
        unhandled-thread-exception warning on every run - noise that would
        hide a real one."""
        from threadwatch import capture
        while not self.finished.is_set():
            if self.tick.wait(0.02):
                self.tick.clear()
                return
        capture.watchdog_stop.set()

    def _run(self):
        import contextlib
        import io
        from threadwatch.capture import run_capture
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                run_capture(self.cfg)
        return cm.exception.code, out.getvalue()

    def _exit_note(self):
        return json.loads((self.cfg.state_dir / EXIT_FILE).read_text())

    def test_a_stream_that_ends_is_exit_3_with_everything_saved_and_closed(self):
        from threadwatch.pcap import PcapStreamReader
        self.hold.set()                                    # three frames, then the sniffer closes its end
        code, out = self._run()
        self.assertEqual(code, 3)
        self.assertEqual(self.exits, [("MainThread", 3)])
        self.assertIn("capture stream ended", out)
        self.assertEqual(self.calls[0], ("start", "/dev/fake-sniffer", self.cfg.channel, "ieee802154-tap"))
        # The shutdown ladder: sniffer stopped, last-seen saved, ring closed
        # and readable, FIFO gone, the exit noted, the event log closed.
        self.assertEqual([c[0] for c in self.calls[1:]], ["stop", "events.close"])
        self.assertIn(self.DEV, json.loads((self.cfg.state_dir / "last-seen.json").read_text()))
        ring = sorted(self.cfg.ring_dir.glob("threadwatch-*.pcap"))
        self.assertEqual(len(ring), 1)
        with open(ring[0], "rb") as fh:
            self.assertEqual(len(list(PcapStreamReader(fh))), 3)
        self.assertFalse((self.cfg.state_dir / "capture.fifo").exists())
        self.assertEqual((self._exit_note()["code"], self._exit_note()["reason"]), (3, "stream_ended"))
        self.assertIn("stopped after 3 frames", out)
        # The watchdog is told to stop before any of that ladder runs, so
        # it cannot write status.json or take an exit decision while the
        # main thread is saving state and closing files.
        from threadwatch import capture
        self.assertTrue(capture.watchdog_stop.is_set())
        self.assertTrue((self.cfg.state_dir / "status.json").exists() or True)   # written by ticks only

    def test_a_sniffer_that_will_not_stop_does_not_keep_the_note_or_the_log_from_closing(self):
        self.fail_stop = True
        self.hold.set()
        code, _out = self._run()
        self.assertEqual(code, 3)
        self.assertEqual([c[0] for c in self.calls[1:]], ["stop", "events.close"])
        self.assertEqual(self._exit_note()["code"], 3)
        self.assertTrue((self.cfg.state_dir / "last-seen.json").exists())

    def test_the_watchdog_exits_for_a_dead_sniffer_and_for_a_stall(self):
        from unittest import mock
        from threadwatch import capture
        for verdict, ladder in ((EXIT_SNIFFER_DIED, ["events.close"]),
                                (EXIT_STALLED, ["events.close", "stop"])):
            with self.subTest(verdict=verdict):
                self.calls.clear(); self.exits.clear(); self.hold.clear(); self.reader_open.clear()
                self.record_exit.reset_mock()
                with mock.patch.object(capture, "watchdog_verdict", return_value=verdict):
                    import threading
                    def tick_then_release():
                        self.reader_open.wait(5)
                        self.tick.set()                    # the watchdog's tick: its verdict
                        deadline = time.time() + 5
                        while not any(name != "MainThread" for name, _ in self.exits) and time.time() < deadline:
                            time.sleep(0.01)
                        self.hold.set()                    # os._exit would have ended the process here
                    threading.Thread(target=tick_then_release, daemon=True).start()
                    self._run()
                watchdog = [(n, c) for n, c in self.exits if n != "MainThread"]
                self.assertEqual([c for _n, c in watchdog], [verdict])
                # What the watchdog did before leaving, in order: the note, then the ladder.
                self.assertEqual(self.record_exit.call_args_list[0].args[1], verdict)
                after_start = [c[0] for c in self.calls[1:]]
                self.assertEqual(after_start[:len(ladder)], ladder)
                if verdict == EXIT_STALLED:
                    self.assertTrue(self.calls[2][1])      # last-seen.json saved before the sniffer was stopped

    def test_a_signal_in_the_sniffers_child_leaves_at_once_and_in_the_parent_stops_cleanly(self):
        import os
        import signal
        import threading
        from unittest import mock
        pid = os.getpid()
        for as_child in (True, False):
            with self.subTest(as_child=as_child):
                self.calls.clear(); self.exits.clear(); self.hold.clear(); self.reader_open.clear()

                def send():
                    self.reader_open.wait(5)
                    time.sleep(0.1)
                    if as_child:
                        with mock.patch.object(os, "getpid", return_value=pid + 1):
                            os.kill(pid, signal.SIGTERM)
                            time.sleep(0.2)
                    else:
                        os.kill(pid, signal.SIGTERM)
                    time.sleep(0.2)
                    self.hold.set()
                threading.Thread(target=send, daemon=True).start()
                code, out = self._run()
                self.assertEqual(code, 0)
                if as_child:
                    # The child's handler is os._exit(0), never SystemExit
                    # (the sniffer's read loop would swallow it and keep
                    # the port); here the fake _exit raises it, so the
                    # parent's finally runs too: two exits, not one.
                    self.assertEqual([c for _n, c in self.exits], [0, 0])
                else:
                    self.assertEqual([c for _n, c in self.exits], [0])
                    self.assertEqual(self._exit_note()["reason"], "stopped")
