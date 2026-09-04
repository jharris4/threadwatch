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
from typing import Optional

from .alerts import HeartbeatRunner, build_heartbeats, build_sinks
from .config import Config
from .events import EventLog, NullEventLog
from .pcap import PcapStreamReader, PcapWriter, Frame, complete_length
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
    small SD card is a harder limit than a week)."""

    def __init__(self, ring_dir: Path, keep_files: int, dlt: int, keep_bytes: Optional[int] = None):
        self.ring_dir = ring_dir
        self.keep_files = keep_files
        self.keep_bytes = keep_bytes
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

    def _rotate(self, hour: str) -> None:
        if self.fh:
            self.fh.close()
        self.current_hour = hour
        self.current_path = self.ring_dir / f"threadwatch-{hour}.pcap"
        # Resuming an hour file after a restart: a previous run killed
        # mid-write leaves a partial record at the tail, and appending after
        # it would make every later frame unreadable. Drop the fragment.
        good = complete_length(self.current_path) if self.current_path.exists() else 0
        if good:
            size = self.current_path.stat().st_size
            if size > good:
                print(f"[threadwatch] {self.current_path.name}: dropping {size - good} "
                      "trailing bytes of a record cut short by the last run", flush=True)
                with open(self.current_path, "r+b") as fh:
                    fh.truncate(good)
            self.fh = open(self.current_path, "ab")
            self.writer = PcapWriter.__new__(PcapWriter)
            self.writer.stream = self.fh
            self.writer.dlt = self.dlt
        else:
            self.fh = open(self.current_path, "wb")
            self.writer = PcapWriter(self.fh, self.dlt)
        self._prune()

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


def run_capture(cfg: Config) -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vendor"))
    from nrf802154_sniffer import Nrf802154Sniffer

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
    last_tick = 0.0
    ring = None
    # Shared with the watchdog thread; benign races (status snapshot only).
    beat = {"last_frame": None, "total": 0, "ring": None}   # last_frame: None until the first frame
    # When any run last heard a frame, carried through runs that hear
    # nothing: the next start credits the gap since then as its own
    # blindness, not the devices' silence (Pipeline._last_frame_heard).
    prior_frame = last_frame_on_record(cfg.state_dir)

    def _watchdog():
        # The main loop blocks reading the FIFO, so a stalled stream (host
        # sleep/wake, dongle unplug, sniffer process death) looks alive
        # forever without this. Exit non-zero so a supervisor restarts us.
        # Also keeps status.json fresh when the channel is merely quiet.
        stall_timeout = 180.0
        while True:
            time.sleep(30)
            now = time.time()
            age = now - (beat["last_frame"] or started)
            if beat["ring"] is not None:
                try:
                    _write_status(cfg, port, beat["total"], started, pipe,
                                  beat["ring"], decryptor, last_frame_age=age,
                                  last_frame_ts=beat["last_frame"] or prior_frame)
                except Exception as exc:   # a full disk must not take the stall check with it
                    _log(f"status.json not written: {exc}")
            if beat["ring"] is None and not sniffer.thread.is_alive():
                # The serial open failed (port held by a stale process, gone
                # after enumeration): the main thread would sit in the FIFO
                # open for the whole stall timeout with a misleading message.
                _log("sniffer thread died before delivering any data (serial port busy or gone? "
                     "see the traceback above); exiting for supervisor restart")
                events.close()      # the start-up quiet announcements, if any
                os._exit(4)
            if age > stall_timeout:
                _log(f"no frames for {age:.0f}s - capture stalled (host slept? "
                     "dongle gone?); exiting for supervisor restart")
                # The main thread is blocked in the FIFO read, so nothing is
                # being written: keep the last frames and what they taught us,
                # deliver the alerts still queued or held for a digest, and
                # take the sniffer's child (which holds the port) with us.
                for step in (lambda: beat["ring"].fh.flush(), pipe.seen.save, events.close, sniffer._stop):
                    try:
                        step()
                    except Exception:
                        pass
                os._exit(2)

    threading.Thread(target=_watchdog, daemon=True).start()

    # Liveness heartbeats: "healthy" means frames are still flowing, and
    # unknown (nothing sent) until this run has heard its first frame, so a
    # restart loop that never hears one cannot keep a monitor reassured.
    # Once the stall timeout passes the watchdog exits anyway.
    HeartbeatRunner(heartbeats,
                    healthy=lambda: None if beat["last_frame"] is None
                    else time.time() - beat["last_frame"] < 180.0,
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
                beat["total"] = total
                now = frame.ts
                if now - last_tick >= 10:
                    if last_tick and int(last_tick) // 30 != int(now) // 30:
                        pipe.periodic(now)
                    last_tick = now
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
        try:
            sniffer._stop()
        except Exception:
            pass
        try:
            pipe.seen.save()
        except Exception as exc:
            _log(f"last-seen.json not saved: {exc}")
        if ring:
            ring.close()
        fifo_path.unlink(missing_ok=True)
        # os._exit skips thread joins: the alert thread's queue and the
        # digests its cooldowns hold would go with it.
        events.close()
        _log(f"stopped after {total} frames")
        # The vendored sniffer starts a non-daemon thread and worker
        # processes that outlive _stop(); everything of ours is closed and
        # saved by now, so end the process outright rather than hang.
        os._exit(exit_code)


def last_frame_on_record(state_dir: Path) -> Optional[float]:
    """When the recorder last heard a frame, as the status.json of a
    previous run recorded it; None when no run has heard one."""
    try:
        st = json.loads((state_dir / "status.json").read_text())
        return float(st["last_frame_ts"]) if st.get("last_frame_ts") is not None else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _write_status(cfg, port, total, started, pipe: Pipeline, ring, decryptor,
                  last_frame_age: float = 0.0, last_frame_ts: Optional[float] = None) -> None:
    # last_frame_age_s is this run's view (the watchdog's stall clock);
    # last_frame_ts is the wall-clock time of the last frame any run heard,
    # which does not move while nothing is heard.
    status = {
        "updated": time.time(),
        "last_frame_age_s": round(last_frame_age, 1),
        "last_frame_ts": last_frame_ts,
        "port": port,
        "channel": cfg.channel,
        "frames_total": total,
        "uptime_s": round(time.time() - started, 1),
        "current_file": str(ring.current_path),
        "devices_tracked": len(pipe.devices),
        "partition": pipe.partition_status(),
        "detector": pipe.detector.snapshot(),
    }
    status["crypto"] = {**decryptor.stats, "key_sequence": decryptor.key_sequence}
    tmp = cfg.state_dir / "status.tmp"
    tmp.write_text(json.dumps(status, indent=1))
    tmp.replace(cfg.state_dir / "status.json")


def run_replay(cfg: Config, pcap_path: Path) -> None:
    """Run the full pipeline over an existing pcap; print events + summary."""
    events = NullEventLog()
    decryptor = load_decryptor(cfg)
    pipe = Pipeline(cfg, events, decryptor, ephemeral=True)
    pipe.detector.cfg.alert_cooldown_s = 0
    total = 0
    first = last = None
    with open(pcap_path, "rb") as fh:
        for frame in PcapStreamReader(fh):
            if first is None:
                first = frame.ts
            last = frame.ts
            pipe.ingest(frame)
            total += 1
    if last:
        pipe.periodic(last)
    out = {
        "file": str(pcap_path),
        "frames": total,
        "duration_s": round(last - first, 1) if first else 0,
        "partition": pipe.partition_status(),
        "detector": pipe.detector.snapshot(),
        "events": events.records,
    }
    out["crypto"] = {**decryptor.stats, "key_sequence": decryptor.key_sequence}
    print(json.dumps(out, indent=1))
