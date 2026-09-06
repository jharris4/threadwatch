"""Continuous capture daemon: dongle -> ring buffer pcaps + live pipeline."""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
import traceback
from pathlib import Path

from .alerts import HeartbeatRunner, build_heartbeats, build_sinks
from . import __version__
from .config import Config, repo_commit
from .events import EventLog, NullEventLog
from .pcap import PcapFormatError, PcapStreamReader, PcapWriter, Frame, scan_file
from .pipeline import Pipeline, load_decryptor


def find_sniffer_port() -> str:
    """Locate the nRF 802.15.4 sniffer dongle by USB VID/PID."""
    from serial.tools import list_ports
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vendor"))
    from nrf802154_sniffer import Nrf802154Sniffer
    candidates = []
    for port in list_ports.comports():
        if port.vid == Nrf802154Sniffer.NORDICSEMI_VID and port.pid == Nrf802154Sniffer.SNIFFER_802154_PID:
            candidates.append(port.device)
    if not candidates:
        raise SystemExit(
            "No nRF 802.15.4 sniffer found. Is the dongle plugged in and flashed "
            "with the sniffer firmware? (see SETUP.md; flash with bin/flash-dongle.sh)"
        )
    for c in candidates:
        if "/cu." in c:
            return c
    return candidates[0]


class RingWriter:
    """Hourly pcap files in a ring directory, oldest pruned beyond
    keep_files, and beyond keep_bytes of total size when that is set (a
    small SD card is a harder limit than a week).

    The byte cap is kept while the hour's file grows, not only at the
    rotation: every PRUNE_STEP bytes written the oldest closed files go
    until the ring, the open file included, is back under it. Pruned
    only at rotation, the ring sat over the cap for the rest of the
    hour, by as much as the hour brought. What remains is the open file
    itself, which is never pruned: one hour heavier than the whole cap
    exceeds it on its own (review.storage allows an hour for that)."""

    PRUNE_STEP = 4 * 1024 * 1024

    def __init__(self, ring_dir: Path, keep_files: int, dlt: int, keep_bytes: int | None = None):
        if keep_bytes is not None and keep_bytes <= 0:
            # _prune would otherwise delete every file but the current one
            # at every rotation and call it a size cap.
            raise ValueError(f"keep_bytes must be positive or None, not {keep_bytes}")
        self.ring_dir = ring_dir
        self.keep_files = keep_files
        self.keep_bytes = keep_bytes
        # A small cap is checked in proportion (a 64 KiB step under a few
        # MiB), a large one every few MiB: a stat of every ring file each.
        self._prune_step = max(65536, min(self.PRUNE_STEP, keep_bytes // 32)) if keep_bytes else None
        self._pruned_at = 0
        self.dlt = dlt
        self.current_hour = None
        self.fh = None
        self.writer = None
        self.current_path = None
        ring_dir.mkdir(parents=True, exist_ok=True)

    def write(self, frame: Frame) -> None:
        hour = time.strftime("%Y%m%d-%H", time.localtime(frame.ts))
        if hour != self.current_hour:
            self._rotate(hour)
        self.writer.write(frame)
        # Hand each record to the OS as it is written. A freeze (manual ones
        # run in another process) copies the active file through its own
        # handle and sees only what has left this buffer: without this, the
        # packets right before an incident's trigger, or the whole file
        # early in the hour, were missing from the snapshot. This is a
        # write(2) per frame, not a sync: the kernel still writes the card
        # back on its own schedule.
        self.fh.flush()
        if self._prune_step is not None and self.fh.tell() - self._pruned_at >= self._prune_step:
            self._pruned_at = self.fh.tell()
            self._prune()

    def _rotate(self, hour: str) -> None:
        if self.fh:
            self.fh.close()
        self.current_hour = hour
        self.current_path = self.ring_dir / f"threadwatch-{hour}.pcap"
        # Resuming an hour file after a restart: a previous run killed
        # mid-write leaves a partial record at the tail, and appending after
        # it would make every later frame unreadable. Drop the fragment.
        # A bad record in the middle of the file (a flipped byte on a
        # wearing card) is another matter: the readers step over it, and
        # cutting the file there would delete every record after it.
        # Resuming appends bare records under the existing global header,
        # so that header has to be the one this writer would have written.
        # A file whose header says another link type (an older firmware's
        # DLT, a foreign pcap dropped in under the hour's name) would take
        # our records and hand every later reader the wrong parse: a TAP
        # TLV header read as the MAC PSDU, and the RSSI and channel a
        # detector works from read out of frame bytes. A big-endian file
        # is the same problem in the record headers. Neither is written
        # into; the hour starts over, and says so.
        scan = scan_file(self.current_path) if self.current_path.exists() else None
        good = scan.good if scan else 0
        mismatch = good and (scan.dlt != self.dlt or scan.endian != "<")
        if mismatch:
            order = "big-endian" if scan.endian == ">" else "little-endian"
            print(f"[threadwatch] {self.current_path.name}: a {order} pcap of link type "
                  f"{scan.dlt}, not the {self.dlt} being recorded; starting the hour's file "
                  "over rather than appending frames it would misread", flush=True)
            good = 0
        if good:
            size = self.current_path.stat().st_size
            if scan.skipped_bytes:
                print(f"[threadwatch] {self.current_path.name}: {scan.skipped_bytes} bytes in "
                      f"{scan.gaps} place(s) are not readable records; left in place, "
                      "readers skip them", flush=True)
            if size > good:
                print(f"[threadwatch] {self.current_path.name}: dropping {size - good} "
                      "trailing bytes of a record cut short by the last run", flush=True)
                with open(self.current_path, "r+b") as fh:
                    fh.truncate(good)
            self.fh = open(self.current_path, "ab")   # noqa: SIM115  (the ring writer owns this until rotation)
            self.writer = PcapWriter.__new__(PcapWriter)
            self.writer.stream = self.fh
            self.writer.dlt = self.dlt
        else:
            if self.current_path.exists() and self.current_path.stat().st_size:
                # Not a pcap this recorder can read (no usable global
                # header): nothing in it is a frame to anyone, but it is
                # not replaced in silence.
                if not mismatch:
                    print(f"[threadwatch] {self.current_path.name}: {self.current_path.stat().st_size} bytes "
                          "with no usable pcap header; starting the hour's file over", flush=True)
            self.fh = open(self.current_path, "wb")   # noqa: SIM115  (the ring writer owns this until rotation)
            self.writer = PcapWriter(self.fh, self.dlt)
        self.fh.flush()                     # the header, so an early freeze copies a readable pcap
        self._prune()
        self._pruned_at = self.fh.tell()

    def _prune(self) -> None:
        # The file being written is never a candidate: it does not always sort
        # last, since a clock step back names it before the ring's oldest.
        files = sorted(self.ring_dir.glob("threadwatch-*.pcap"))
        current = self.current_path if self.current_path in files else None
        candidates = [f for f in files if f != current]
        drop = min(max(0, len(files) - self.keep_files), len(candidates))
        if self.keep_bytes is not None:
            sizes = [f.stat().st_size if f.exists() else 0 for f in candidates]
            held = current.stat().st_size if current and current.exists() else 0
            total = sum(sizes[drop:]) + held       # only what the count cap is keeping
            floor = len(candidates) if current else len(candidates) - 1
            while total > self.keep_bytes and drop < floor:
                total -= sizes[drop]
                drop += 1
        for old in candidates[:drop]:
            old.unlink(missing_ok=True)

    def close(self) -> None:
        if self.fh:
            self.fh.close()


# How long the capture may go without a frame before the watchdog gives up
# on it: long enough to sit out a quiet channel, short enough that a dead
# dongle or a host sleep/wake costs minutes of the flight record, not more.
STALL_TIMEOUT_S = 180.0


def capture_stalled(age: float, timeout: float = STALL_TIMEOUT_S) -> bool:
    """The watchdog's decision: `age` seconds since the last frame (or since
    start-up, before any) is a stall once it passes the timeout."""
    return age > timeout


# The watchdog's exit codes, so the journal says which way the capture went.
EXIT_STALLED = 2            # no frames for STALL_TIMEOUT_S
EXIT_SNIFFER_DIED = 4       # the sniffer thread died before delivering any data
# How a run ended, by its exit code, as the note it leaves for the next
# start says it (record_exit). Every other code is "exit_<code>".
EXIT_REASONS = {0: "stopped", 1: "crashed", EXIT_STALLED: "stalled", 3: "stream_ended",
                EXIT_SNIFFER_DIED: "sniffer_died"}
EXIT_FILE = "last-exit.json"


def record_exit(state_dir: Path, code: int, last_frame_ts: float | None = None,
                now: float | None = None) -> str | None:
    """Leave a note of how this run ended for the next start to read:
    the Pipeline announces the restart with the cause and the gap, and
    the review's coverage tells the recorder's own outage from a
    device's silence by it. Written whole and renamed into place. A run
    that never got to write one (a power cut, a SIGKILL) leaves nothing,
    which the next start reads as an end it knows nothing about, and the
    start that reads the note removes it, so it can only ever describe
    the run just before. Returns the reason written, None when the file
    could not be (a full disk must not keep the process from leaving)."""
    reason = EXIT_REASONS.get(code, f"exit_{code}")
    record = {"ts": now if now is not None else time.time(), "code": code, "reason": reason,
              "last_frame_ts": last_frame_ts}
    try:
        tmp = state_dir / "last-exit.tmp"
        tmp.write_text(json.dumps(record))
        tmp.replace(state_dir / EXIT_FILE)
    except OSError:
        return None
    return reason


def watchdog_verdict(age: float, ring_open: bool, sniffer_alive: bool) -> int | None:
    """What the watchdog does on this tick: an exit code, or None to keep
    waiting. A sniffer thread that died before the ring opened never got
    the serial port (held by a stale process, or gone after enumeration):
    left alone, the main thread sits in the FIFO open for the whole stall
    timeout behind a misleading message. With the ring open, a dead
    sniffer closes the FIFO and the main loop leaves on its own."""
    if not ring_open and not sniffer_alive:
        return EXIT_SNIFFER_DIED
    if capture_stalled(age):
        return EXIT_STALLED
    return None


# The main loop looks at the frame clock every TICK_S and runs
# Pipeline.periodic (quiet checks, link checks, the state saves, the daily
# summary) once per PERIODIC_S of it: every quiet decision and every save
# waits on this, so it is as slow as it can be and no slower.
TICK_S = 10.0
PERIODIC_S = 30


def periodic_due(last_tick: float, now: float) -> bool:
    """Whether a tick at `now` is the first inside a new PERIODIC_S period
    since the tick before it. Nothing is due on the loop's first tick
    (`last_tick` 0.0)."""
    return bool(last_tick) and int(last_tick) // PERIODIC_S != int(now) // PERIODIC_S


class Housekeeping:
    """The main loop's tick clock. Ticks are spaced by the monotonic clock,
    which a step of the host clock in either direction cannot stretch: on
    the frame clock alone, a step back of an hour held every quiet check,
    link check and state save until the wall clock had caught up with the
    last tick. Which PERIODIC_S period a tick falls in is still judged on
    the frame clock (periodic_due), the clock the pipeline is handed."""

    def __init__(self) -> None:
        self.last_tick = 0.0             # frame clock at the last tick
        self.last_mono: float | None = None

    def due(self, now: float, mono: float) -> bool:
        """Called per frame with its wall-clock stamp and the monotonic
        clock: True when Pipeline.periodic(now) should run."""
        if self.last_mono is not None and mono - self.last_mono < TICK_S:
            return False
        run = periodic_due(self.last_tick, now)
        self.last_tick, self.last_mono = now, mono
        return run


def capture_healthy(last_frame_mono: float | None, now: float,
                    timeout: float = STALL_TIMEOUT_S) -> bool | None:
    """The heartbeat's answer: unknown (None) until this run has heard a
    frame, then healthy while the last one is fresher than the stall
    timeout, so the beat stops before the watchdog exits."""
    if last_frame_mono is None:
        return None
    return now - last_frame_mono < timeout


def run_capture(cfg: Config) -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vendor"))
    from nrf802154_sniffer import Nrf802154Sniffer
    # Set on the way out, so the watchdog stops ticking rather than writing
    # status.json or taking an exit decision while the main thread is saving
    # state and closing files. One per run, not module state: a watchdog
    # outliving its own run must not be able to stop a later one's.
    watchdog_stop = threading.Event()

    def _log(msg: str) -> None:
        print(f"[threadwatch] {msg}", flush=True)

    # Everything that can fail on configuration is built before the sniffer
    # starts. The vendored sniffer runs a non-daemon thread that blocks until
    # this process opens the FIFO, so an exception raised after
    # start_threaded() would leave the interpreter waiting on that thread
    # forever: a live process that systemd never restarts, holding the port.
    port = cfg.serial_port or find_sniffer_port()
    sinks = build_sinks(cfg.alerts_raw, _log)
    events = EventLog(cfg.events_dir, sinks)
    for s in sinks:
        _log(f"alert sink {s.describe()} (min {['info', 'notice', 'warning', 'critical'][s.min_severity]})")
    if not sinks:
        _log("no alert sinks configured (events go to the event log only; see docs/ALERTING.md)")
    # The log's dispatcher has taken the last run's undelivered alerts
    # from the spool by now; a failure anywhere below (credentials.toml
    # unreadable, the FIFO's directory gone, the port busy) leaves before
    # the finally that closes it, so it is closed here, and the records go
    # back to the spool rather than out with the heap.
    try:
        decryptor = load_decryptor(cfg)      # raises CredentialsError: no key, no recorder
        _log("credentials: loaded")
        pipe = Pipeline(cfg, events, decryptor)
        heartbeats = build_heartbeats(cfg.heartbeats_raw, _log)
        for b in heartbeats:
            _log(f"heartbeat {b.describe()}")

        fifo_path = cfg.state_dir / "capture.fifo"
        fifo_path.unlink(missing_ok=True)
        os.mkfifo(fifo_path)

        sniffer = Nrf802154Sniffer()
        sniffer.start_threaded(str(fifo_path), port, cfg.channel, metadata="ieee802154-tap")
        _log(f"capturing channel {cfg.channel} from {port}")
    except BaseException:
        events.close()
        raise

    # Raising from the handler interrupts the blocking FIFO read, so
    # `systemctl stop` works even when the channel is silent. The finally
    # block below closes files. The watchdog's os._exit path flushes the
    # ring but can still leave a partial record: readers stop cleanly there
    # and RingWriter trims it before appending.
    main_pid = os.getpid()

    def _sig(_signo, _frame):
        # The sniffer forks a serial-reader child that inherits this handler
        # and wraps its read loop in a bare except: a SystemExit raised there
        # is swallowed and the child keeps the port, so systemd waits 90 s
        # and SIGKILLs. In a child, just leave.
        if os.getpid() != main_pid:
            os._exit(0)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    total = 0
    started = time.time()
    started_mono = time.monotonic()
    housekeeping = Housekeeping()
    ring = None
    # Shared with the watchdog thread; benign races (status snapshot only).
    # last_frame is the wall clock (None until the first frame), for the
    # record; the stall clock and the heartbeat's health run on the
    # monotonic stamp beside it, which NTP stepping the host clock forward
    # after boot cannot turn into a three-hour "stall".
    beat = {"last_frame": None, "last_frame_mono": None, "total": 0, "ring": None}
    # When any run last heard a frame, carried through runs that hear
    # nothing: the next start credits the gap since then as its own
    # blindness, not the devices' silence (Pipeline._last_frame_heard).
    prior_frame = last_frame_on_record(cfg.state_dir)

    def _watchdog():
        # The main loop blocks reading the FIFO, so a stalled stream (host
        # sleep/wake, dongle unplug, sniffer process death) looks alive
        # forever without this. Exit non-zero so a supervisor restarts us.
        # Also keeps status.json fresh when the channel is merely quiet.
        while True:
            time.sleep(30)
            if watchdog_stop.is_set():
                return          # shutting down: the main thread owns the state now
            age = status_tick(cfg, port, beat, started, started_mono, pipe, decryptor, prior_frame, _log,
                              sniffer)
            verdict = watchdog_verdict(age, ring_open=beat["ring"] is not None,
                                       sniffer_alive=sniffer.thread.is_alive())
            if verdict == EXIT_SNIFFER_DIED:
                _log("sniffer thread died before delivering any data (serial port busy or gone? "
                     "see the traceback above); exiting for supervisor restart")
                record_exit(cfg.state_dir, EXIT_SNIFFER_DIED, beat["last_frame"] or prior_frame)
                events.close()      # the start-up quiet announcements, if any
                os._exit(EXIT_SNIFFER_DIED)
            if verdict == EXIT_STALLED:
                _log(f"no frames for {age:.0f}s - capture stalled (host slept? "
                     "dongle gone?); exiting for supervisor restart")
                # The main thread is blocked in the FIFO read, so nothing is
                # being written: keep the last frames and what they taught us,
                # deliver the alerts still queued or held for a digest, and
                # take the sniffer's child (which holds the port) with us.
                # Each step is allowed to fail without taking the rest
                # with it, but never in silence: the whole point of the
                # ladder is that what it saved is what the next run reads.
                for what, step in (("ring flush", lambda: beat["ring"].fh.flush()),
                                   ("last-seen save", pipe.seen.save),
                                   ("exit note", lambda: record_exit(cfg.state_dir, EXIT_STALLED,
                                                                     beat["last_frame"] or prior_frame)),
                                   ("alert delivery", events.close),
                                   ("sniffer stop", sniffer._stop)):
                    try:
                        step()
                    except Exception as exc:
                        _log(f"stalled exit: {what} failed: {exc}")
                os._exit(EXIT_STALLED)

    threading.Thread(target=_watchdog, daemon=True, name="watchdog").start()

    # Liveness heartbeats: "healthy" means frames are still flowing, and
    # unknown (nothing sent) until this run has heard its first frame, so a
    # restart loop that never hears one cannot keep a monitor reassured.
    # Once the stall timeout passes the watchdog exits anyway.
    HeartbeatRunner(heartbeats,
                    healthy=lambda: capture_healthy(beat["last_frame_mono"], time.monotonic()),
                    log=_log)

    # Exit status: 0 for a requested stop, otherwise non-zero so the journal
    # and the supervisor see a failure, and the traceback is printed here
    # because the os._exit in finally would otherwise swallow it.
    exit_code = 0
    try:
        with open(fifo_path, "rb") as fifo:
            reader = PcapStreamReader(fifo)
            ring = RingWriter(cfg.ring_dir, cfg.keep_files, reader.dlt, cfg.keep_bytes)
            beat["ring"] = ring
            for frame in reader:
                frame.ts = time.time()   # host wall clock, NTP-aligned
                ring.write(frame)
                pipe.ingest(frame)
                total += 1
                beat["last_frame"] = frame.ts
                beat["last_frame_mono"] = time.monotonic()
                beat["total"] = total
                if housekeeping.due(frame.ts, beat["last_frame_mono"]):
                    pipe.periodic(frame.ts)
        # The sniffer closed its end of the FIFO: dongle unplugged or the
        # sniffer process died. Not a clean stop.
        _log("capture stream ended (dongle unplugged? sniffer died?); exiting for supervisor restart")
        exit_code = 3
    except SystemExit as exc:
        exit_code = exc.code if isinstance(exc.code, int) else 0
    except BaseException:
        traceback.print_exc()
        _log("capture crashed; exiting for supervisor restart")
        exit_code = 1
    finally:
        # A second Ctrl-C here (or a SIGTERM racing a Ctrl-C) would raise
        # SystemExit out of this block, skip the os._exit below, and leave
        # the interpreter hanging on the sniffer's non-daemon thread until
        # a kill -9. Everything below is quick: hold the signals until it
        # is done. (The sniffer's children keep their own handler.)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            sniffer._stop()
        except Exception:
            pass
        watchdog_stop.set()
        try:
            pipe.seen.save()
        except Exception as exc:
            _log(f"last-seen.json not saved: {exc}")
        if ring:
            ring.close()
        fifo_path.unlink(missing_ok=True)
        record_exit(cfg.state_dir, exit_code, beat["last_frame"] or prior_frame)
        # os._exit skips thread joins: the alert thread's queue and the
        # digests its cooldowns hold would go with it.
        events.close()
        _log(f"stopped after {total} frames")
        # The vendored sniffer starts a non-daemon thread and worker
        # processes that outlive _stop(); everything of ours is closed and
        # saved by now, so end the process outright rather than hang.
        os._exit(exit_code)


def status_tick(cfg, port, beat: dict, started: float, started_mono: float, pipe: Pipeline,
                decryptor, prior_frame: float | None, log, sniffer=None) -> float:
    """One watchdog tick: refresh status.json once the ring is open, and
    return the stall clock's reading (seconds since this run's last frame,
    or since it started). The file's last_frame_ts is when a frame was
    last heard by any run: this run's, else the stamp the previous run's
    status.json carried (prior_frame), else None. Never the time now: a
    stalled recorder reports a stale frame, which is the fact a reader of
    the file needs."""
    age = time.monotonic() - (beat["last_frame_mono"] or started_mono)
    if beat["ring"] is not None:
        try:
            _write_status(cfg, port, beat["total"], started, pipe, beat["ring"], decryptor,
                          last_frame_age=age, last_frame_ts=beat["last_frame"] or prior_frame,
                          dropped_lines=getattr(sniffer, "parse_failures", 0))
        except Exception as exc:   # a full disk must not take the stall check with it
            log(f"status.json not written: {exc}")
    return age


def last_frame_on_record(state_dir: Path) -> float | None:
    """When the recorder last heard a frame, as the status.json of a
    previous run recorded it; None when no run has heard one."""
    try:
        st = json.loads((state_dir / "status.json").read_text())
        if not isinstance(st, dict):
            return None             # valid JSON of another shape: a list has no .get
        return float(st["last_frame_ts"]) if st.get("last_frame_ts") is not None else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _write_status(cfg, port, total, started, pipe: Pipeline, ring, decryptor,
                  last_frame_age: float = 0.0, last_frame_ts: float | None = None,
                  dropped_lines: int = 0) -> None:
    # last_frame_age_s is this run's view (the watchdog's stall clock);
    # last_frame_ts is the wall-clock time of the last frame any run heard,
    # which does not move while nothing is heard.
    status = {
        "updated": time.time(),
        # Which code is recording: a restart that did not happen, or a
        # deploy that did not land, is invisible in everything else here.
        "version": __version__,
        "commit": repo_commit(),
        "last_frame_age_s": round(last_frame_age, 1),
        "last_frame_ts": last_frame_ts,
        "port": port,
        "channel": cfg.channel,
        "frames_total": total,
        # Serial lines the sniffer could not parse: frames the dongle sent
        # and nothing recorded. Steadily climbing means a cable or a
        # baud-rate problem, not a quiet mesh.
        "dropped_lines": dropped_lines,
        "uptime_s": round(time.time() - started, 1),
        # None until the first frame opens an hour file: a tick in the
        # first 30 s of a silent channel used to write the string "None".
        "current_file": str(ring.current_path) if ring.current_path else None,
        "devices_tracked": len(pipe.devices),
        # The PAN the recorder judges by (configured, or adopted with the
        # pipeline's floor and hysteresis): the report and the pages read
        # it here, so "quiet" and "foreign" mean the same thing everywhere.
        "dominant_pan": pipe.dominant_pan(),
        "partition": pipe.partition_status(),
        "detector": pipe.detector.snapshot(),
        "alerts": pipe.events.dispatcher.stats(),
    }
    status["crypto"] = {**decryptor.stats, "key_sequence": decryptor.key_sequence}
    tmp = cfg.state_dir / "status.tmp"
    tmp.write_text(json.dumps(status, indent=1))
    tmp.replace(cfg.state_dir / "status.json")


def replay_files(paths: list[Path]) -> list[Path]:
    """The pcaps a replay reads, in order: a file as given, a directory
    (an incident, or the ring) as every pcap in it by name, which for
    ring files is by hour. Nothing to read is an error, not an empty run."""
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            found = sorted(p.glob("*.pcap"))
            if not found:
                raise SystemExit(f"threadwatch replay: no pcap files in {p}")
            out.extend(found)
        else:
            out.append(p)
    if not out:
        raise SystemExit("threadwatch replay: nothing to read")
    return out


def run_replay(cfg: Config, pcap_path: Path | list[Path]) -> None:
    """Run the full pipeline over existing pcaps, one file or several in
    order (a directory is every pcap in it), as one run: a silence or a
    storm that spans two hourly files is judged once, across the
    boundary, as the recorder judged it. Prints events + summary."""
    files = replay_files(pcap_path if isinstance(pcap_path, list) else [pcap_path])
    events = NullEventLog()
    decryptor = load_decryptor(cfg)
    print("[threadwatch] credentials: loaded", file=sys.stderr, flush=True)   # stdout is the JSON
    pipe = Pipeline(cfg, events, decryptor, ephemeral=True)
    pipe.detector.cfg.alert_cooldown_s = 0
    total = 0
    first = last = None
    # The housekeeping the live loop runs on the frame clock (quiet checks,
    # link assessment) runs here on the packets' own clock at the same
    # cadence: a silence that ends before EOF, or a drop that holds and
    # then recovers, is only found by looking between the frames, not
    # once at the end.
    last_tick = 0.0
    for path in files:
        try:
            with open(path, "rb") as fh:
                reader = PcapStreamReader(fh)
                for frame in reader:
                    if first is None:
                        first = frame.ts
                    last = frame.ts
                    pipe.ingest(frame)
                    total += 1
                    now = frame.ts
                    if now < last_tick:
                        last_tick = now       # stamps stepped back: keep ticking from here
                    if now - last_tick >= TICK_S:
                        if periodic_due(last_tick, now):
                            pipe.periodic(now)
                        last_tick = now
                if reader.skipped_bytes:
                    print(f"[threadwatch] {path}: skipped {reader.skipped_bytes} bytes in {reader.gaps} "
                          "place(s) that are not readable records", file=sys.stderr, flush=True)
        except (OSError, PcapFormatError) as exc:
            # A path that does not exist, cannot be read, or is not a pcap:
            # one line and exit 1 (as `why` does), not a traceback and not a
            # zero-frame JSON that reads as a quiet capture.
            raise SystemExit(f"threadwatch replay: could not read {path}: {exc}") from None
    if last:
        pipe.periodic(last)
    out = {
        "file": str(files[0]) if len(files) == 1 else None,
        "files": [str(f) for f in files],
        "frames": total,
        "duration_s": round(last - first, 1) if first else 0,
        "partition": pipe.partition_status(),
        "detector": pipe.detector.snapshot(),
        "events": events.records,
    }
    out["crypto"] = {**decryptor.stats, "key_sequence": decryptor.key_sequence}
    print(json.dumps(out, indent=1))
