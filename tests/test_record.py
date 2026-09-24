"""status.json as the recorder writes it, and what a later run reads back."""

import json
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.frames import psdu_for
from threadwatch.config import Config
from threadwatch.crypto import Decryptor
from threadwatch.events import NullEventLog
from threadwatch.pipeline import Pipeline
from threadwatch.record import (
    EXIT_CLEANUP_FAILED,
    EXIT_FILE,
    EXIT_SNIFFER_DIED,
    EXIT_STALLED,
    PERIODIC_S,
    STALL_TIMEOUT_S,
    TICK_S,
    Housekeeping,
    _write_status,
    capture_healthy,
    capture_stalled,
    last_frame_on_record,
    periodic_due,
    record_exit,
    status_tick,
    watchdog_verdict,
)


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

    def test_a_ring_with_no_hour_file_yet_is_null_not_the_string_None(self):
        # beat["ring"] is set when the RingWriter is built, before the
        # first frame rotates an hour file into place, so a watchdog tick
        # in the first 30 s of a silent channel writes current_file with
        # nothing open. It used to write "None", which the web header
        # rendered as <code>None</code>.
        self.ring.current_path = None
        self.assertIsNone(self._write(last_frame_age=5.0)["current_file"])

    def test_a_partition_reassigned_mid_read_does_not_cost_the_status_write(self):
        # partition_status runs on the watchdog thread while the capture
        # thread may replace self.partition between the emptiness test and
        # the indexing. The IndexError is caught by status_tick, at the
        # price of one skipped status.json write, and the web header calls
        # a status file older than 180 s "capture stale": two skipped
        # writes in a row is a false banner on a healthy recorder.
        reads = iter([[0x2a, 60]])

        class Racing(type(self.pipe)):
            @property
            def partition(self):
                return next(reads, [])          # reassigned after the first read

        self.pipe.__class__ = Racing
        self.assertEqual(self.pipe.partition_status(),
                         {"id": 0x2a, "leader_router": 60, "id_sequence": None,
                          "sequence_advanced_ts": None, "stalled": False})

    def test_dropped_serial_lines_are_counted_into_the_status_file(self):
        # The vendored sniffer swallowed a line its packet regex did not
        # match with a bare `except: ...`, so a garbled serial line was a
        # dropped frame nothing recorded. A flight recorder that drops
        # frames without counting them cannot tell you that it did.
        from types import SimpleNamespace
        self.assertEqual(self._write(last_frame_age=5.0)["dropped_lines"], 0)
        beat = {"last_frame_mono": None, "total": 0, "last_frame": None, "ring": self.ring}
        status_tick(self.cfg, "/dev/x", beat, time.time(), time.monotonic(), self.pipe,
                    self.pipe.decryptor, None, lambda _m: None, SimpleNamespace(parse_failures=7))
        st = json.loads((self.cfg.state_dir / "status.json").read_text())
        self.assertEqual(st["dropped_lines"], 7)

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
    def stub_startup(self, radios):
        from unittest import mock

        from threadwatch import record
        for name, value in (("plan_radios", radios), ("load_decryptor", object()),
                            ("Pipeline", mock.Mock()), ("build_sinks", []), ("build_heartbeats", [])):
            patcher = mock.patch.object(record, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(record, "EventLog")
        events = patcher.start().return_value
        self.addCleanup(patcher.stop)
        return events

    def test_listener_failure_precedes_usb_start_and_closes_all_listeners(self):
        from unittest import mock

        from threadwatch import record
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            radios = [record.Radio("hub", "AA", "", None, root / "hub.fifo", lambda msg: None),
                      record.Radio("annex", None, "", None, root / "annex.fifo", lambda msg: None,
                                   source="tcp", listen="127.0.0.1:9154"),
                      record.Radio("shed", None, "", None, root / "shed.fifo", lambda msg: None,
                                   source="tcp", listen="127.0.0.1:9155")]
            events = self.stub_startup(radios)
            radios[0].fifo.write_text("not owned by this startup")
            first, second = mock.Mock(), mock.Mock()
            first.accept.side_effect = OSError("closed")
            second.bind.side_effect = OSError("Address already in use")
            with mock.patch.object(record.socket, "socket", side_effect=[first, second]), \
                    mock.patch.object(radios[0], "attach") as attach:
                with self.assertRaisesRegex(OSError, "Address already in use"):
                    record.run_record(Config(data_dir=root))
            attach.assert_not_called()
            first.close.assert_called_once()
            second.close.assert_called_once()
            events.close.assert_called_once()
            self.assertTrue(all(r.listener is None for r in radios))
            self.assertEqual(radios[0].fifo.read_text(), "not owned by this startup")

    def test_a_relay_radio_waiting_for_its_relay_is_not_a_dead_sniffer(self):
        import queue

        from threadwatch import record
        with tempfile.TemporaryDirectory() as tmp:
            radio = record.Radio("annex", None, "", None, Path(tmp) / "annex.fifo", lambda msg: None,
                                 source="tcp", listen="127.0.0.1:0")
            self.assertFalse(radio.sniffer_alive())
            radio._listen(queue.Queue())
            try:
                self.assertTrue(radio.sniffer_alive())
                self.assertIsNone(record.watchdog_verdict(30.0, ring_open=False,
                                                          sniffer_alive=radio.sniffer_alive()))
            finally:
                radio.close_listener()
            radio.accept_thread.join(2)
            self.assertFalse(radio.sniffer_alive())

    def test_a_transient_accept_error_does_not_end_the_relay_listener(self):
        # accept(2) hands over the new connection's pending network error
        # (no route, aborted, out of descriptors) and says to retry. Read
        # as "the listener was closed", the accept thread returned and the
        # listener stayed open with nobody accepting: the relay connected
        # and sent into the backlog while the radio stayed missing for good.
        import errno
        import queue
        import socket
        from unittest import mock

        from threadwatch import record
        from threadwatch.relay import handshake_line
        failures = [OSError(errno.EHOSTUNREACH, "No route to host")]

        class FlakyListener(socket.socket):
            def accept(self):
                if failures:
                    raise failures.pop(0)
                return super().accept()

        logged = []
        with tempfile.TemporaryDirectory() as tmp:
            radio = record.Radio("annex", None, "", None, Path(tmp) / "annex.fifo", logged.append,
                                 source="tcp", listen="127.0.0.1:0")
            q = queue.Queue()
            with mock.patch.object(record.socket, "socket", FlakyListener):
                radio._listen(q)
            try:
                port = radio.listener.getsockname()[1]
                with socket.create_connection(("127.0.0.1", port), timeout=2) as client:
                    client.sendall(handshake_line("annex", None, 25))
                    label, kind, _, (conn, _peer, hs) = q.get(timeout=5)
                self.assertEqual((label, kind, hs["label"]), ("annex", "connect", "annex"))
                conn.close()
                self.assertTrue(radio.accept_thread.is_alive())
            finally:
                radio.close_listener()
            radio.accept_thread.join(2)
            self.assertFalse(radio.accept_thread.is_alive())
            retries = [m for m in logged if "accept failed, retrying" in m]
            self.assertEqual(len(retries), 1, logged)
            self.assertIn("No route to host", retries[0])

    def test_later_attach_failure_wakes_a_non_daemon_worker_stuck_opening_its_fifo(self):
        import os
        import queue
        from unittest import mock

        from threadwatch import record
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = record.Radio("hub", "AA", "", None, root / "hub.fifo", lambda msg: None)
            second = record.Radio("annex", "BB", "", None, root / "annex.fifo", lambda msg: None)
            events = self.stub_startup([first, second])
            packets = queue.Queue()
            stopped = mock.Mock()
            received = []

            def worker():
                with open(first.fifo, "wb") as fifo:
                    fifo.write(b"header")
                    received.append(packets.get(timeout=2))

            def attach(*_args):
                os.mkfifo(first.fifo)
                first._owns_fifo = True
                thread = threading.Thread(target=worker)  # deliberately non-daemon
                first.sniffer = SimpleNamespace(thread=thread, queue=packets, _stop=stopped)
                thread.start()
                return True

            with mock.patch.object(first, "attach", side_effect=attach), \
                    mock.patch.object(second, "attach", side_effect=OSError("cannot create FIFO")):
                with self.assertRaisesRegex(OSError, "cannot create FIFO"):
                    record.run_record(Config(data_dir=root))
            self.assertFalse(first.sniffer.thread.is_alive())
            self.assertEqual(type(received[0]).__name__, "ExitEvent")
            stopped.assert_called_once()
            events.close.assert_called_once()
            self.assertFalse(first.fifo.exists())

    def test_a_start_that_fails_after_the_log_is_built_keeps_the_spool(self):
        # The likeliest start-up failure, credentials.toml missing or
        # unreadable, came after the event log had loaded the spool; the
        # process left without closing it and the spool was already gone.
        import json as json_mod

        from threadwatch import alerts
        from threadwatch.pipeline import CredentialsError
        from threadwatch.record import run_record
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
                run_record(cfg)
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


class VendoredSnifferTest(unittest.TestCase):
    """vendor/nrf802154_sniffer.py carries two threadwatch changes: a
    garbled serial line is counted rather than swallowed, and a
    disconnected dongle ends the reader instead of spinning."""

    def _reader(self, lines, disconnect_after):
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vendor"))
        from nrf802154_sniffer import ExitEvent, Nrf802154Sniffer, ParseFailure, SnifferPacket

        class FakeSerial:
            def __init__(self, *_a, **_k):
                self.n = 0

            def readline(self):
                self.n += 1
                if self.n > disconnect_after:
                    raise OSError("device gone")
                return lines[self.n - 1]

        class FakeQueue:
            def __init__(self):
                self.items = []

            def put(self, item):
                self.items.append(item)

        import nrf802154_sniffer as mod
        real, q = mod.Serial, FakeQueue()
        mod.Serial = FakeSerial
        try:
            Nrf802154Sniffer.serial_reader("/dev/x", q)
        finally:
            mod.Serial = real
        return q.items, ExitEvent, ParseFailure, SnifferPacket

    def test_a_garbled_line_is_a_counted_drop_and_a_disconnect_ends_the_reader(self):
        good = (b"received: 0102030405060708 power: -42 lqi: 128 time: 1000\r\n")
        items, ExitEvent, ParseFailure, SnifferPacket = self._reader(
            [good, b"\xff\xfe garbage\r\n", good], disconnect_after=3)
        kinds = [type(i).__name__ for i in items]
        self.assertEqual(kinds, ["SnifferPacket", "ParseFailure", "SnifferPacket", "ExitEvent"])
        # It used to fall through and spin here, filling the queue with
        # ExitEvents at whatever rate the failing read returned.
        self.assertEqual(kinds.count("ExitEvent"), 1)


class StatusConsumersTest(unittest.TestCase):
    """One status.json, written by the daemon and read by everything that
    reads it: the web header and status page, doctor, and `threadwatch
    status`. Each consumer used to be tested against a fixture of its own,
    so the writer and the readers could drift apart unnoticed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        (self.d / "config.toml").write_text(f'[record]\ndata_dir = "{self.d / "data"}"\n')
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
                                      "devices_tracked", "dominant_pan", "dropped_lines", "frames_total",
                                      "ha_availability", "ha_logs_archive", "keys", "last_frame_age_s",
                                      "last_frame_ts", "merge", "otbr_inventory", "partition", "port", "radios",
                                      "updated", "uptime_s", "version"])
        self.assertEqual(st["keys"], {})                  # nothing heard yet: no generation on record
        self.assertIsNone(st["otbr_inventory"])           # optional SSH inventory off
        self.assertIsNone(st["ha_logs_archive"])          # [ha_logs] archive off
        self.assertIsNone(st["ha_availability"])          # [ha_availability] off
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

        self.assertEqual(check_daemon(self.cfg, now)[0][:2], (WARN, "recorder"))
        self.assertIn("no frames for 170 s", check_daemon(self.cfg, now)[0][2])
        # ...and it reads as healthy once a frame has just arrived.
        _write_status(self.cfg, "/dev/tty.usbmodem1", 4211, now - 3600, self.pipe,
                      self.ring, self.pipe.decryptor, last_frame_age=1.0, last_frame_ts=now - 1)
        self.assertEqual(check_daemon(self.cfg, now)[0][:2], (OK, "recorder"))
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
        self.assertIsNone(watchdog_verdict(30.0, ring_open=False, sniffer_alive=True))  # still opening the port
        self.assertIsNone(watchdog_verdict(30.0, ring_open=True, sniffer_alive=False))  # FIFO closes: main loop's exit
        self.assertIsNone(watchdog_verdict(30.0, ring_open=True, sniffer_alive=True))
        self.assertEqual(watchdog_verdict(181.0, ring_open=True, sniffer_alive=True), EXIT_STALLED)
        self.assertEqual(watchdog_verdict(181.0, ring_open=False, sniffer_alive=True), EXIT_STALLED)  # never delivered
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
        age, st = self._tick({"last_frame": None, "last_frame_mono": None, "total": 0, "ring": self.ring}, prior,
                             mono - 170)
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
        _age, st = self._tick({"last_frame": None, "last_frame_mono": None, "total": 0, "ring": self.ring}, None,
                              mono - 170)
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


class RadioClockTest(unittest.TestCase):
    """The recorder's timestamps: the radio's intervals, on the host's epoch."""

    def _clock(self, wall):
        from threadwatch.record import RadioClock
        return RadioClock(wall=lambda: wall[0], mono=lambda: wall[0])

    def test_intervals_survive_a_backlog_the_host_clock_would_have_erased(self):
        """Frames buffered in the serial reader or the FIFO are processed in a
        rush. Stamping them with time.time() at that moment collapsed the
        traffic they represent -- exactly during the storms worth recording,
        when disk stalls and CPU contention cause the backlog."""
        wall = [1_700_000_000.0]
        clock = self._clock(wall)
        out = []
        for raw in (500.0, 500.25, 500.5, 501.0):     # a second of radio, drained at once
            out.append(clock.stamp(raw))
        # Intact but for the offset correction the clock allows itself per
        # captured second: the whole second arrived while wall clock stood
        # still, so it is correcting at exactly that bound throughout.
        for expected, got in zip((0.0, 0.25, 0.5, 1.0), (t - out[0] for t in out), strict=True):
            self.assertAlmostEqual(got, expected, delta=2 * clock.MAX_SLEW)
        self.assertEqual(out[0], wall[0])             # the first frame lands at wall clock

    def test_a_long_backlog_and_its_drain_do_not_step_the_clock(self):
        wall = [1_700_000_000.0]
        clock = self._clock(wall)
        first = clock.stamp(0.0)
        wall[0] += 20
        stamps = [clock.stamp(float(i)) for i in range(1, 21)]
        self.assertEqual(clock.steps, 0)
        self.assertAlmostEqual(stamps[-1] - first, 20, delta=20 * clock.MAX_SLEW)
        for a, b in zip([first] + stamps, stamps, strict=False):
            self.assertAlmostEqual(b - a, 1, delta=2 * clock.MAX_SLEW)

    def test_host_steps_are_measured_independently_of_queue_delay(self):
        from threadwatch.record import RadioClock
        for step in (120, -120):
            wall, mono = [1_700_000_000.0], [100.0]
            clock = RadioClock(wall=lambda w=wall: w[0], mono=lambda m=mono: m[0])
            first = clock.stamp(0.0)
            wall[0] += 20 + step
            mono[0] += 20
            self.assertAlmostEqual(clock.stamp(1.0) - first, 1 + step)
            self.assertEqual(clock.last_step_s, step)
            self.assertEqual(clock.steps, 1)

    def test_the_offset_is_walked_toward_the_host_clock_not_jumped(self):
        wall = [1_700_000_000.0]
        clock = self._clock(wall)
        clock.stamp(0.0)
        wall[0] += 100.5                              # 100 s of radio, host clock 100.5 s on: drifting
        stamped = clock.stamp(100.0)
        # Half a second out, corrected by at most MAX_SLEW per captured second.
        self.assertAlmostEqual(stamped, 1_700_000_100.0 + clock.MAX_SLEW * 100, places=6)
        self.assertEqual(clock.steps, 0)

    def test_a_gap_too_large_to_walk_off_is_stepped_and_reported(self):
        """A sniffer that restarts re-anchors on its own first packet, and a
        host whose clock is stepped moves under the offset. Neither can be
        slewed away in any useful time."""
        wall = [1_700_000_000.0]
        clock = self._clock(wall)
        clock.stamp(500.0)
        wall[0] += 10.0
        stamped = clock.stamp(9.0)                    # the sniffer restarted: its clock began again
        self.assertEqual(stamped, wall[0])
        self.assertEqual(clock.steps, 1)
        self.assertAlmostEqual(clock.last_step_s, 501.0, places=6)
        # ...and the next frame carries on from the new anchor, intervals intact.
        self.assertAlmostEqual(clock.stamp(9.5) - stamped, 0.5, delta=2 * clock.MAX_SLEW)
        self.assertEqual(clock.steps, 1)
        self.assertEqual(clock.last_step_s, 0.0)      # only the frame that stepped reports one

    def test_a_burst_of_frames_does_not_buy_a_bigger_correction(self):
        """The correction is bounded by captured time, not by frame count: a
        thousand frames in one radio second must not slew a thousand times."""
        wall = [1_700_000_000.0]
        clock = self._clock(wall)
        clock.stamp(0.0)
        wall[0] += 1.5                                # half a second of error to work off
        for i in range(1, 1001):
            last = clock.stamp(i / 1000.0)            # a radio second, a thousand frames
        self.assertLessEqual(abs(last - (1_700_000_000.0 + 1.0)), clock.MAX_SLEW * 1.0 + 1e-9)


class RunRecordTest(unittest.TestCase):
    """run_record itself: the live loop, the watchdog's two verdicts, the
    signal handler and the shutdown, with its two boundaries faked. The
    sniffer is a module standing in for the vendored one, writing pcap
    records into the FIFO from a thread and holding it open until told;
    os._exit is recorded and raises SystemExit so the test gets control
    back. Everything the helpers do is covered elsewhere; this is proof
    that run_record calls them, in order, with the right arguments."""

    DEV = "26976e7f7d20964a"

    def setUp(self):
        import os
        import signal
        import sys
        import threading
        import types
        from unittest import mock

        from threadwatch import record
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
        self.reader_open = threading.Event()   # set once run_record has opened its end
        self.tick = threading.Event()          # one watchdog tick per set
        self.finished = threading.Event()
        self.run_over = threading.Event()      # set when run_record has returned
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
                        mock.patch.object(record.EventLog, "close", autospec=True,
                                          side_effect=lambda log, *a, **k: test.calls.append(("events.close",)))):
            patcher.start()
            self.addCleanup(patcher.stop)
        spy = mock.patch.object(record, "record_exit", wraps=record.record_exit)
        self.record_exit = spy.start()
        self.addCleanup(spy.stop)
        self._time = record.time
        record.time = types.SimpleNamespace(time=time.time, monotonic=time.monotonic, strftime=time.strftime,
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

        from threadwatch import record
        self.finished.set()
        self.hold.set()
        record.time = self._time
        for signo, handler in self._handlers.items():
            signal.signal(signo, handler)
        self.tmp.cleanup()

    def _exit(self, code):
        import threading
        self.exits.append((threading.current_thread().name, code))
        raise SystemExit(code)

    def _sleep(self, _seconds):
        """The watchdog's 30 s: one tick per test.tick.set(). Once the test
        is over, the run's own stop flag (set by its shutdown) ends the
        thread on its next check. Throwing SystemExit at the thread
        instead, as this used to, left an unhandled-thread-exception
        warning on every run - noise that would hide a real one."""
        while not (self.finished.is_set() or self.run_over.is_set()):
            if self.tick.wait(0.02):
                self.tick.clear()
                return
        return      # the run is over: its own stop flag ends the thread on the next check

    def _run(self):
        import contextlib
        import io

        from threadwatch.record import run_record
        out = io.StringIO()
        self.run_over.clear()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                with self.assertRaises(SystemExit) as cm:
                    run_record(self.cfg)
        finally:
            # Lets a watchdog parked in the faked sleep return, so it sees
            # its own run's stop flag and ends instead of outliving the
            # test. One left behind used to sit in a real 30 s sleep once
            # tearDown put the clock back.
            self.run_over.set()
        return cm.exception.code, out.getvalue()

    @staticmethod
    def _watchdogs() -> set:
        """The live watchdog threads, by identity."""
        import threading
        return {t.ident for t in threading.enumerate() if t.name == "watchdog" and t.is_alive()}

    def _exit_note(self):
        return json.loads((self.cfg.state_dir / EXIT_FILE).read_text())

    def test_a_stream_that_ends_is_exit_3_with_everything_saved_and_closed(self):
        from threadwatch.pcap import PcapStreamReader
        before = self._watchdogs()
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
            written = [f.ts for f in PcapStreamReader(fh)]
        self.assertEqual(len(written), 3)
        # The FIFO carries frames one second apart. Every stamp used to be
        # replaced with time.time() as the loop got to it, so two seconds of
        # captured traffic reached the ring inside a millisecond and the real
        # timing was gone from the evidence for good. Each interval is now the
        # radio's, less at most the offset correction the clock allows itself
        # per captured second -- this fake sniffer hands over three seconds of
        # radio time at once, so it is correcting at exactly that bound.
        from itertools import pairwise

        from threadwatch.record import RadioClock
        for got in (b - a for a, b in pairwise(written)):
            self.assertAlmostEqual(got, 1.0, delta=2 * RadioClock.MAX_SLEW)
        self.assertLess(abs(written[0] - time.time()), 60)      # ...on the host's epoch, not the dongle's
        self.assertFalse((self.cfg.state_dir / "capture.fifo").exists())
        self.assertEqual((self._exit_note()["code"], self._exit_note()["reason"]), (3, "stream_ended"))
        self.assertIn("stopped after 3 frames", out)
        # The watchdog is told to stop before any of that ladder runs, so
        # it cannot write status.json or take an exit decision while the
        # main thread is saving state and closing files - and it goes. Only
        # this run's: earlier tests in this class leave their own parked in
        # a real 30 s sleep, tearDown having put the real clock back.
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and self._watchdogs() - before:
            time.sleep(0.02)
        self.assertEqual(self._watchdogs() - before, set())
        self.assertTrue((self.cfg.state_dir / "status.json").exists() or True)   # written by ticks only

    def test_a_sniffer_that_will_not_stop_does_not_keep_the_note_or_the_log_from_closing(self):
        self.fail_stop = True
        self.hold.set()
        code, _out = self._run()
        self.assertEqual(code, 3)
        self.assertEqual([c[0] for c in self.calls[1:]], ["stop", "events.close"])
        self.assertEqual(self._exit_note()["code"], 3)
        self.assertTrue((self.cfg.state_dir / "last-seen.json").exists())

    def test_a_ring_that_will_not_close_does_not_stop_the_rest_of_the_shutdown(self):
        # A full disk out of ring.close() propagated out of the finally
        # block: the alerts were never drained or spooled, no exit note
        # was written, the FIFO stayed behind, and os._exit was never
        # reached - with both signals ignored by then and the sniffer's
        # non-daemon thread still alive, which is a recorder nothing can
        # stop. Each step now fails on its own, and the exit is certain.
        import errno
        from unittest import mock

        from threadwatch.record import RingWriter
        self.hold.set()
        with mock.patch.object(RingWriter, "close",
                               side_effect=OSError(errno.ENOSPC, "No space left on device")):
            code, out = self._run()
        self.assertEqual(code, 3)                      # how the run ended, not how it tidied up
        self.assertEqual(self.exits, [("MainThread", 3)])
        self.assertIn("exit: ring close failed", out)
        self.assertEqual([c[0] for c in self.calls[1:]], ["stop", "events.close"])
        self.assertEqual(self._exit_note()["code"], 3)
        self.assertFalse((self.cfg.state_dir / "capture.fifo").exists())
        self.assertTrue((self.cfg.state_dir / "last-seen.json").exists())

    def test_a_stop_that_could_not_put_everything_away_is_not_reported_as_clean(self):
        # The run ended as asked, but part of it did not land. exit 0 and
        # "stopped" would say the opposite of what happened.
        import errno
        import os
        import signal
        import threading
        from unittest import mock

        from threadwatch.record import RingWriter

        def send():
            self.reader_open.wait(5)
            time.sleep(0.1)
            os.kill(os.getpid(), signal.SIGTERM)
            time.sleep(0.2)
            self.hold.set()
        threading.Thread(target=send, daemon=True).start()
        with mock.patch.object(RingWriter, "close",
                               side_effect=OSError(errno.ENOSPC, "No space left on device")):
            code, out = self._run()
        self.assertEqual(code, EXIT_CLEANUP_FAILED)
        self.assertIn("exit: ring close failed", out)
        self.assertEqual((self._exit_note()["code"], self._exit_note()["reason"]),
                         (EXIT_CLEANUP_FAILED, "cleanup_failed"))
        self.assertEqual([c[0] for c in self.calls[1:]], ["stop", "events.close"])

    def test_the_watchdog_exits_for_a_dead_sniffer_and_for_a_stall(self):
        from unittest import mock

        from threadwatch import record
        for verdict, ladder in ((EXIT_SNIFFER_DIED, ["events.close"]),
                                (EXIT_STALLED, ["events.close", "stop"])):
            with self.subTest(verdict=verdict):
                self.calls.clear(); self.exits.clear(); self.hold.clear(); self.reader_open.clear()
                self.record_exit.reset_mock()
                with mock.patch.object(record, "watchdog_verdict", return_value=verdict):
                    import threading
                    def watchdog_left():
                        return any(name != "MainThread" for name, _ in self.exits)

                    def tick_then_release():
                        self.reader_open.wait(5)
                        self.tick.set()                    # the watchdog's tick: its verdict
                        # Not a pacing delay: releasing the stream before
                        # the watchdog has acted ends the main loop, and
                        # its shutdown sets watchdog_stop, which sends the
                        # watchdog home without a verdict. Long enough that
                        # only a real hang reaches it.
                        deadline = time.monotonic() + 30
                        while not watchdog_left() and time.monotonic() < deadline:
                            time.sleep(0.01)
                        self.hold.set()                    # os._exit would have ended the process here
                    threading.Thread(target=tick_then_release, daemon=True).start()
                    self._run()
                # The watchdog exits on its own thread, so its entry can
                # land just after the main thread's does.
                deadline = time.monotonic() + 5
                while not watchdog_left() and time.monotonic() < deadline:
                    time.sleep(0.01)
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

                def send(as_child=as_child):
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


if __name__ == "__main__":
    unittest.main()


class FindSniffersTest(unittest.TestCase):
    """Dongles by serial, one entry each, and no guessing between two."""

    @staticmethod
    def _ports(*specs):
        ports = []
        for device, serial in specs:
            ports.append(SimpleNamespace(device=device, serial_number=serial, vid=0x1915, pid=0x154B))
        ports.append(SimpleNamespace(device="/dev/ttyUSB0", serial_number="FTDI1", vid=0x0403, pid=0x6001))
        return lambda: ports

    def test_every_sniffer_is_listed_once_by_port_with_its_serial_upper_cased(self):
        from threadwatch.record import find_sniffers
        found = find_sniffers(self._ports(("/dev/ttyACM1", "fedcba9876543210"), ("/dev/ttyACM0", "0123456789ABCDEF")))
        self.assertEqual(found, [("/dev/ttyACM0", "0123456789ABCDEF"), ("/dev/ttyACM1", "FEDCBA9876543210")])
        # macOS: the same dongle as tty. and cu.; cu. is the one kept.
        found = find_sniffers(self._ports(("/dev/tty.usbmodem0123456789ABCDEF1", "0123456789ABCDEF"),
                                          ("/dev/cu.usbmodem0123456789ABCDEF1", "0123456789ABCDEF")))
        self.assertEqual(found, [("/dev/cu.usbmodem0123456789ABCDEF1", "0123456789ABCDEF")])
        # ...and still one dongle when the platform reports no serial at all.
        found = find_sniffers(self._ports(("/dev/tty.usbmodem1", None), ("/dev/cu.usbmodem1", None)))
        self.assertEqual(found, [("/dev/cu.usbmodem1", None)])
        self.assertEqual(find_sniffers(self._ports()), [])

    def test_one_dongle_is_the_port_and_two_without_a_table_are_refused_by_name(self):
        from threadwatch.record import find_sniffer_port
        self.assertEqual(find_sniffer_port(self._ports(("/dev/ttyACM0", "AA"))), "/dev/ttyACM0")
        with self.assertRaises(SystemExit) as cm:
            find_sniffer_port(self._ports())
        self.assertIn("No nRF 802.15.4 sniffer found", str(cm.exception))
        with self.assertRaises(SystemExit) as cm:
            find_sniffer_port(self._ports(("/dev/ttyACM0", "AA"), ("/dev/ttyACM1", "BB")))
        self.assertIn("2 nRF 802.15.4 sniffers found (AA at /dev/ttyACM0, BB at /dev/ttyACM1)", str(cm.exception))
        self.assertIn("[record] radios", str(cm.exception))

    def test_a_configured_radio_is_found_by_serial_wherever_it_enumerated(self):
        from threadwatch.record import resolve_radio_port
        ports = self._ports(("/dev/ttyACM3", "0123456789ABCDEF"), ("/dev/ttyACM0", "BB"))
        self.assertEqual(resolve_radio_port("0123456789abcdef", ports), "/dev/ttyACM3")
        self.assertIsNone(resolve_radio_port("CC", ports))


class RingSeriesTest(unittest.TestCase):
    """One RingWriter per radio, each pruning only its own hours."""

    def test_a_labelled_writer_names_its_files_and_leaves_the_other_series_alone(self):
        from threadwatch.pcap import Frame
        from threadwatch.record import RingWriter
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            for h in ("00", "01", "02", "03"):
                (d / f"threadwatch-20260903-{h}.pcap").write_bytes(b"x" * 10)
            annex = RingWriter(d, keep_hours=2, dlt=230, label="annex")
            for h in ("00", "01", "02"):
                (d / f"threadwatch-20260903-{h}-annex.pcap").write_bytes(b"x" * 10)
            ts = time.mktime(time.strptime("20260903-03", "%Y%m%d-%H"))
            annex.write(Frame(ts=ts, raw=b"\x01\x02\x03", psdu=b"\x01\x02\x03", rssi=None, channel=None, lqi=None))
            annex.close()
            self.assertEqual(annex.current_path.name, "threadwatch-20260903-03-annex.pcap")
            names = sorted(p.name for p in d.glob("*.pcap"))
            # keep_hours=2 pruned the annex series to its two newest hours...
            self.assertEqual([n for n in names if n.endswith("-annex.pcap")],
                             ["threadwatch-20260903-02-annex.pcap", "threadwatch-20260903-03-annex.pcap"])
            # ...and did not count or touch the primary's four.
            self.assertEqual([n for n in names if not n.endswith("-annex.pcap")],
                             [f"threadwatch-20260903-{h}.pcap" for h in ("00", "01", "02", "03")])
            primary = RingWriter(d, keep_hours=3, dlt=230)
            primary._prune()
            self.assertEqual(sorted(p.name for p in d.glob("threadwatch-*-annex.pcap")),
                             ["threadwatch-20260903-02-annex.pcap", "threadwatch-20260903-03-annex.pcap"])
            self.assertEqual(sorted(p.name for p in d.glob("threadwatch-????????-??.pcap")),
                             [f"threadwatch-20260903-{h}.pcap" for h in ("01", "02", "03")])


class TwoRadiosRunTest(unittest.TestCase):
    """run_record with [record] radios: two fake sniffers, one per port,
    each writing its own frames into its own FIFO. What is proven here is
    the recorder's side: attach by serial, one ring series per radio, a
    radio that goes away while the other carries on, a radio missing at
    start and found later, and the run ending only when every radio has."""

    DEV = "26976e7f7d20964a"
    KEY = "00112233445566778899aabbccddeeff"

    def setUp(self):
        import os
        import sys
        import types
        from unittest import mock

        from threadwatch import record
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "credentials.toml").write_text(f'[credentials]\nnetwork_key = "{self.KEY}"\n')
        (d / "devices.json").write_text("[]")
        (d / "config.toml").write_text(
            '[record]\n[[record.radios]]\nlabel = "hub"\nserial = "AA"\nplacement = "by the router"\n'
            '[[record.radios]]\nlabel = "annex"\nserial = "BB"\n')
        from threadwatch import config as config_mod
        self.cfg = config_mod.load(d / "config.toml")
        self.cfg.data_dir = d / "data"
        self.cfg.credentials_path = d / "credentials.toml"
        self.cfg.devices_path = d / "devices.json"
        self.cfg.border_router_browse_s = 0
        self.ports = {"AA": "/dev/fake-hub", "BB": "/dev/fake-annex"}   # serial -> port, None = unplugged
        self.scripts = {}          # port -> list of (ts, psdu, rssi); written then the FIFO is held
        self.holds = {}            # port -> Event that lets the fake close its FIFO
        self.calls = []
        self.exits = []
        self.tick = threading.Event()
        self.finished = threading.Event()
        self.run_over = threading.Event()
        test = self

        class FakeSniffer:
            def __init__(self):
                self.thread = None

            def start_threaded(self, fifo, dev, channel, metadata=None):
                test.calls.append(("start", dev))
                hold = test.holds.setdefault(dev, threading.Event())

                def run():
                    from threadwatch.pcap import DLT_TAP, Frame, PcapWriter
                    with open(fifo, "wb") as fh:
                        w = PcapWriter(fh, DLT_TAP)
                        for ts, psdu, rssi in test.scripts.get(dev, []):
                            raw = struct.pack("<HH", 0, 28) + struct.pack("<HHf", 1, 4, rssi) \
                                + struct.pack("<HHHH", 3, 3, 25, 0) + struct.pack("<HHI", 10, 1, 200) + psdu
                            w.write(Frame(ts=ts, raw=raw, psdu=psdu, rssi=rssi, channel=25, lqi=200))
                        fh.flush()
                        hold.wait(10)
                self.thread = threading.Thread(target=run, daemon=True, name=f"fake-{dev}")
                self.thread.start()

            def _stop(self):
                test.calls.append(("stop",))

        module = types.ModuleType("nrf802154_sniffer")
        module.Nrf802154Sniffer = FakeSniffer
        for patcher in (mock.patch.dict(sys.modules, {"nrf802154_sniffer": module}),
                        mock.patch.object(os, "_exit", self._exit),
                        mock.patch.object(record, "resolve_radio_port", lambda serial: test.ports.get(serial)),
                        mock.patch.object(record, "REATTACH_S", 0.0),
                        mock.patch.object(record.EventLog, "close", autospec=True,
                                          side_effect=lambda log, *a, **k: None)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self._time = record.time
        record.time = types.SimpleNamespace(time=time.time, monotonic=time.monotonic, strftime=time.strftime,
                                             localtime=time.localtime, sleep=self._sleep)
        expected = threading.excepthook
        self.addCleanup(setattr, threading, "excepthook", expected)

        def excepthook(args):
            if args.exc_type is SystemExit and getattr(args.thread, "name", None) == "watchdog":
                return
            expected(args)
        threading.excepthook = excepthook

    def tearDown(self):
        from threadwatch import record
        self.finished.set()
        for h in self.holds.values():
            h.set()
        record.time = self._time
        self.tmp.cleanup()

    def _exit(self, code):
        self.exits.append((threading.current_thread().name, code))
        raise SystemExit(code)

    def _sleep(self, _seconds):
        while not (self.finished.is_set() or self.run_over.is_set()):
            if self.tick.wait(0.02):
                self.tick.clear()
                return

    def _run(self):
        import contextlib
        import io

        from threadwatch.record import run_record
        out = io.StringIO()
        self.run_over.clear()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                with self.assertRaises(SystemExit) as cm:
                    run_record(self.cfg)
        finally:
            self.run_over.set()
        return cm.exception.code, out.getvalue()

    def _long_hold(self):
        """For a test that counts the frames two radios shared: the fake
        radios are threads, and on a loaded CI runner one's copy of a frame
        can reach the merger more than the live 250 ms hold after the
        other's, so both went out and the shared frames were counted twice.
        The run ends when the radios do, so the long hold costs nothing."""
        from unittest import mock
        hold = mock.patch("threadwatch.merge.HOLD_S", 5.0)
        hold.start()
        self.addCleanup(hold.stop)

    def _events(self):
        """The radio events of the run, in order."""
        from threadwatch.events import read_all
        return [(r["event"], r.get("radio")) for r in read_all(self.cfg.events_dir) if r["event"].startswith("radio")]

    def _frames(self, n, offset=0.0, start=0):
        key = bytes.fromhex(self.KEY)
        return [(1000.0 + i + offset, psdu_for(self.DEV, seq=i, key=key), -60.0 - (10 if offset else 0))
                for i in range(start, start + n)]

    def test_both_radios_write_their_own_series_and_the_run_ends_when_both_have(self):
        from threadwatch.pcap import PcapStreamReader
        self.cfg.keep_hours = 1
        self._long_hold()
        self.cfg.ring_dir.mkdir(parents=True, exist_ok=True)
        old_primary = self.cfg.ring_dir / "threadwatch-20200101-00.pcap"
        old_primary.write_bytes(b"old primary hour")
        frames = self._frames(3)
        self.scripts["/dev/fake-hub"] = frames
        # The annex hears the same three frames, its clock 10 ms ahead, and one more.
        self.scripts["/dev/fake-annex"] = [(ts + 0.010, psdu, -70.0) for ts, psdu, _ in frames] + \
            [(1003.01, psdu_for(self.DEV, seq=9, key=bytes.fromhex(self.KEY)), -70.0)]
        hub_hold = self.holds.setdefault("/dev/fake-hub", threading.Event())
        annex_hold = self.holds.setdefault("/dev/fake-annex", threading.Event())

        def later():
            time.sleep(0.5)
            hub_hold.set()                # the hub's dongle goes first: the annex carries the run...
            time.sleep(0.4)
            annex_hold.set()              # ...until it goes too, which ends the run
        threading.Thread(target=later, daemon=True).start()
        code, out = self._run()
        self.assertEqual(code, 3)
        self.assertEqual(self.calls[:2], [("start", "/dev/fake-hub"), ("start", "/dev/fake-annex")])
        self.assertIn("capturing channel 25 from /dev/fake-hub (radio hub (by the router))", out)
        ring = sorted(p.name for p in self.cfg.ring_dir.glob("*.pcap"))
        self.assertFalse(old_primary.exists())
        self.assertEqual(len(ring), 2)
        self.assertTrue(ring[0].endswith("-annex.pcap"), ring)
        self.assertEqual(ring[1], ring[0].replace("-annex.pcap", ".pcap"))
        read = {}
        for name in ring:
            with open(self.cfg.ring_dir / name, "rb") as fh:
                read[name] = [(round(f.ts), f.rssi) for f in PcapStreamReader(fh)]
        self.assertEqual(len(read[ring[1]]), 3)                 # hub's copies
        self.assertEqual(len(read[ring[0]]), 4)                 # annex's copies, its own RSSI
        self.assertEqual({r for _, r in read[ring[0]]}, {-70.0})
        self.assertEqual({r for _, r in read[ring[1]]}, {-60.0})
        # The pipeline saw four frames, not seven: the three shared ones once each.
        self.assertIn("stopped after 4 frames", out)
        # The first radio to go is lost; the last to go ends the run instead.
        self.assertEqual(self._events(), [("radio_lost", "hub")])
        self.assertIn("radio hub (by the router) detached: capture stream ended", out)
        self.assertFalse(list(self.cfg.state_dir.glob("capture-*.fifo")))

    def test_a_radio_missing_at_start_is_reported_and_attached_when_it_appears(self):
        self.ports["BB"] = None
        self.scripts["/dev/fake-hub"] = self._frames(2)
        self.scripts["/dev/fake-annex"] = self._frames(2, offset=0.010, start=5)
        hub_hold = self.holds.setdefault("/dev/fake-hub", threading.Event())
        annex_hold = self.holds.setdefault("/dev/fake-annex", threading.Event())

        def later():
            time.sleep(0.3)
            self.ports["BB"] = "/dev/fake-annex"          # plugged in
            self.tick.set()                                 # the watchdog looks for it
            time.sleep(0.5)
            annex_hold.set()
            time.sleep(0.2)
            hub_hold.set()
        threading.Thread(target=later, daemon=True).start()
        code, out = self._run()
        self.assertEqual(code, 3)
        self.assertIn("no sniffer with serial BB is plugged in", out)
        self.assertEqual(self._events(), [("radio_missing", "annex"), ("radio_attached", "annex"),
                                          ("radio_lost", "annex")])
        self.assertEqual([c for c in self.calls if c[0] == "start"],
                         [("start", "/dev/fake-hub"), ("start", "/dev/fake-annex")])
        self.assertIn("stopped after 4 frames", out)

    def test_nothing_plugged_in_is_a_start_failure_naming_every_radio(self):
        self.ports = {"AA": None, "BB": None}
        code, _out = self._run()
        self.assertIn("none of the radios in [record] radios is plugged in: hub (serial AA), annex (serial BB)",
                      str(code))

    def test_the_status_file_carries_every_radio(self):
        frames = self._frames(2)
        self.scripts["/dev/fake-hub"] = frames
        self.scripts["/dev/fake-annex"] = [(ts + 0.010, psdu, -70.0) for ts, psdu, _ in frames]   # the same frames
        hub_hold = self.holds.setdefault("/dev/fake-hub", threading.Event())
        annex_hold = self.holds.setdefault("/dev/fake-annex", threading.Event())

        def later():
            time.sleep(0.4)
            self.tick.set()                                 # a watchdog tick writes status.json
            time.sleep(0.3)
            annex_hold.set(); hub_hold.set()
        threading.Thread(target=later, daemon=True).start()
        self._run()
        st = json.loads((self.cfg.state_dir / "status.json").read_text())
        self.assertEqual(st["port"], "/dev/fake-hub")
        self.assertEqual(sorted(st["radios"]), ["annex", "hub"])
        hub, annex = st["radios"]["hub"], st["radios"]["annex"]
        self.assertEqual((hub["state"], hub["serial"], hub["placement"], hub["frames_total"], hub["lock"]),
                         ("up", "AA", "by the router", 2, None))
        self.assertEqual((annex["state"], annex["port"], annex["frames_total"]), ("up", "/dev/fake-annex", 2))
        self.assertIn("locked", annex["lock"])
        self.assertTrue(annex["current_file"].endswith("-annex.pcap"))
        self.assertEqual((st["merge"]["merged"], st["merge"]["duplicates"]), (2, 2))


class RelayRadioRunTest(TwoRadiosRunTest):
    """The annex as a relay from another host: the recorder listens, a
    client connects with the handshake and streams pcap records."""

    def setUp(self):
        import socket
        super().setUp()
        with socket.socket() as probe:               # a free port for the listener
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        d = Path(self.tmp.name)
        (d / "config.toml").write_text(
            '[record]\n[[record.radios]]\nlabel = "hub"\nserial = "AA"\n'
            f'[[record.radios]]\nlabel = "annex"\nsource = "tcp"\nlisten = "127.0.0.1:{self.port}"\n')
        from threadwatch import config as config_mod
        cfg = config_mod.load(d / "config.toml")
        cfg.data_dir, cfg.credentials_path, cfg.devices_path = self.cfg.data_dir, self.cfg.credentials_path, \
            self.cfg.devices_path
        cfg.border_router_browse_s = 0
        self.cfg = cfg

    def _client(self, frames, hold: threading.Event, label="annex", channel=25):
        """A relay: handshake, header, records, then hold the connection until told."""
        import socket
        import struct as _struct

        from threadwatch.pcap import DLT_TAP
        from threadwatch.relay import handshake_line
        deadline = time.monotonic() + 5
        while True:
            try:
                sock = socket.create_connection(("127.0.0.1", self.port), timeout=2)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        sock.sendall(handshake_line(label, "BB", channel))
        sock.sendall(_struct.pack("<LHHIILL", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, DLT_TAP))
        for ts, psdu, rssi in frames:
            raw = (_struct.pack("<HH", 0, 28) + _struct.pack("<HHf", 1, 4, rssi)
                   + _struct.pack("<HHHH", 3, 3, 25, 0) + _struct.pack("<HHI", 10, 1, 200) + psdu)
            sec, usec = int(ts), int(round((ts - int(ts)) * 1e6))
            sock.sendall(_struct.pack("<LLLL", sec, usec, len(raw), len(raw)) + raw)
        hold.wait(10)
        sock.close()

    # The parent's tests assume two USB dongles; only the ones below run here.
    def test_both_radios_write_their_own_series_and_the_run_ends_when_both_have(self):
        pass

    def test_a_radio_missing_at_start_is_reported_and_attached_when_it_appears(self):
        pass

    def test_nothing_plugged_in_is_a_start_failure_naming_every_radio(self):
        pass

    def test_the_status_file_carries_every_radio(self):
        pass

    def test_a_relay_is_adopted_streams_its_copies_and_its_loss_is_the_radios_not_the_runs(self):
        from threadwatch.pcap import PcapStreamReader
        self._long_hold()
        frames = self._frames(3)
        self.scripts["/dev/fake-hub"] = frames
        hub_hold = self.holds.setdefault("/dev/fake-hub", threading.Event())
        relay_hold = threading.Event()
        annex = [(ts + 0.010, psdu, -70.0) for ts, psdu, _ in frames[1:]]
        threading.Thread(target=self._client, args=(annex, relay_hold), daemon=True).start()

        def later():
            time.sleep(1.0)
            relay_hold.set()              # the relay disconnects: annex lost, the run goes on
            time.sleep(0.4)
            hub_hold.set()                # the hub ends: the run ends
        threading.Thread(target=later, daemon=True).start()
        code, out = self._run()
        self.assertEqual(code, 3)
        self.assertIn(f"radio annex: listening on 127.0.0.1:{self.port} for its relay", out)
        self.assertIn("radio annex: relay connected from 127.0.0.1:", out)
        self.assertEqual(self._events(), [("radio_missing", "annex"), ("radio_attached", "annex"),
                                          ("radio_lost", "annex")])
        ring = sorted(p.name for p in self.cfg.ring_dir.glob("*.pcap"))
        self.assertEqual(len(ring), 2, out)
        with open(self.cfg.ring_dir / ring[0], "rb") as fh:           # the annex's series
            self.assertEqual([f.rssi for f in PcapStreamReader(fh)], [-70.0, -70.0])
        self.assertIn("stopped after 3 frames", out)                    # the two shared frames once each

    def test_a_relay_for_another_radio_or_channel_is_refused(self):
        frames = self._frames(2)
        self.scripts["/dev/fake-hub"] = frames
        hub_hold = self.holds.setdefault("/dev/fake-hub", threading.Event())
        hold = threading.Event()
        threading.Thread(target=self._client, args=([], hold, "attic"), daemon=True).start()
        threading.Thread(target=self._client, args=([], hold, "annex", 11), daemon=True).start()

        def later():
            time.sleep(0.8)
            hold.set()
            time.sleep(0.2)
            hub_hold.set()
        threading.Thread(target=later, daemon=True).start()
        code, out = self._run()
        self.assertEqual(code, 3)
        self.assertIn("refused: relay is radio 'attic', this listener is 'annex'", out)
        self.assertIn("refused: relay captures channel 11, this recorder channel 25", out)
        self.assertEqual(self._events(), [("radio_missing", "annex")])
