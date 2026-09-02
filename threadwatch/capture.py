"""Continuous capture daemon: dongle -> ring buffer pcaps + live pipeline."""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

from .config import Config
from .events import EventLog, NullEventLog
from .pcap import PcapStreamReader, PcapWriter, Frame
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
    """Hourly pcap files in a ring directory, oldest pruned beyond keep_files."""

    def __init__(self, ring_dir: Path, keep_files: int, dlt: int):
        self.ring_dir = ring_dir
        self.keep_files = keep_files
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
        fresh = not self.current_path.exists()
        self.fh = open(self.current_path, "wb" if fresh else "ab")
        if fresh:
            self.writer = PcapWriter(self.fh, self.dlt)
        else:
            self.writer = PcapWriter.__new__(PcapWriter)
            self.writer.stream = self.fh
            self.writer.dlt = self.dlt
        self._prune()

    def _prune(self) -> None:
        files = sorted(self.ring_dir.glob("threadwatch-*.pcap"))
        for old in files[: max(0, len(files) - self.keep_files)]:
            old.unlink(missing_ok=True)

    def close(self) -> None:
        if self.fh:
            self.fh.close()


def run_capture(cfg: Config) -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vendor"))
    from nrf802154_sniffer import Nrf802154Sniffer

    port = cfg.serial_port or find_sniffer_port()
    fifo_path = cfg.state_dir / "capture.fifo"
    fifo_path.unlink(missing_ok=True)
    os.mkfifo(fifo_path)

    sniffer = Nrf802154Sniffer()
    sniffer.start_threaded(str(fifo_path), port, cfg.channel, metadata="ieee802154-tap")
    print(f"[threadwatch] capturing channel {cfg.channel} from {port}", flush=True)

    events = EventLog(cfg.state_dir / "events.jsonl",
                      webhook_url=cfg.detector.webhook_url,
                      webhook_min_severity=cfg.webhook_min_severity)
    decryptor = load_decryptor(cfg)
    print(f"[threadwatch] credentials: {'loaded (deep inspection on)' if decryptor else 'none (header-level only)'}",
          flush=True)
    pipe = Pipeline(cfg, events, decryptor)

    # Raising from the handler interrupts the blocking FIFO read, so
    # `systemctl stop` works even when the channel is silent. The finally
    # block below closes files; a truncated final pcap record is tolerated
    # by readers.
    def _sig(_signo, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    stop = {"flag": False}

    total = 0
    started = time.time()
    last_tick = 0.0
    ring = None
    # Shared with the watchdog thread; benign races (status snapshot only).
    beat = {"last_frame": time.time(), "total": 0, "ring": None}

    def _watchdog():
        # The main loop blocks reading the FIFO, so a stalled stream (host
        # sleep/wake, dongle unplug, sniffer process death) looks alive
        # forever without this. Exit non-zero so a supervisor restarts us.
        # Also keeps status.json fresh when the channel is merely quiet.
        stall_timeout = 180.0
        while True:
            time.sleep(30)
            now = time.time()
            age = now - beat["last_frame"]
            if beat["ring"] is not None:
                _write_status(cfg, port, beat["total"], started, pipe,
                              beat["ring"], decryptor, last_frame_age=age)
            if age > stall_timeout:
                print(f"[threadwatch] no frames for {age:.0f}s - capture "
                      "stalled (host slept? dongle gone?); exiting for "
                      "supervisor restart", flush=True)
                os._exit(2)

    threading.Thread(target=_watchdog, daemon=True).start()

    try:
        with open(fifo_path, "rb") as fifo:
            reader = PcapStreamReader(fifo)
            ring = RingWriter(cfg.ring_dir, cfg.keep_files, reader.dlt)
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
                if stop["flag"]:
                    break
    finally:
        try:
            sniffer._stop()
        except Exception:
            pass
        pipe.seen.save()
        if ring:
            ring.close()
        fifo_path.unlink(missing_ok=True)
        print(f"[threadwatch] stopped after {total} frames", flush=True)
        # The vendored sniffer starts a non-daemon thread and worker
        # processes that outlive _stop(); everything of ours is closed and
        # saved by now, so end the process outright rather than hang.
        os._exit(0)


def _write_status(cfg, port, total, started, pipe: Pipeline, ring, decryptor,
                  last_frame_age: float = 0.0) -> None:
    status = {
        "updated": time.time(),
        "last_frame_age_s": round(last_frame_age, 1),
        "port": port,
        "channel": cfg.channel,
        "frames_total": total,
        "uptime_s": round(time.time() - started, 1),
        "current_file": str(ring.current_path),
        "devices_tracked": len(pipe.devices),
        "deep_inspection": decryptor is not None,
        "partition": {"id": pipe.partition[0], "leader_router": pipe.partition[1]}
        if pipe.partition else None,
        "detector": pipe.detector.snapshot(),
    }
    if decryptor:
        status["crypto"] = dict(decryptor.stats)
    tmp = cfg.state_dir / "status.tmp"
    tmp.write_text(json.dumps(status, indent=1))
    tmp.replace(cfg.state_dir / "status.json")


def run_replay(cfg: Config, pcap_path: Path) -> None:
    """Run the full pipeline over an existing pcap; print events + summary."""
    events = NullEventLog()
    decryptor = load_decryptor(cfg)
    pipe = Pipeline(cfg, events, decryptor)
    pipe.seen.table = {}   # replay judges the file on its own, not live state
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
        "deep_inspection": decryptor is not None,
        "partition": {"id": pipe.partition[0], "leader_router": pipe.partition[1]}
        if pipe.partition else None,
        "detector": pipe.detector.snapshot(),
        "events": events.records,
    }
    if decryptor:
        out["crypto"] = dict(decryptor.stats)
    print(json.dumps(out, indent=1))
