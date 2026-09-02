"""Continuous capture daemon: dongle -> ring buffer pcaps + live detection."""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

from .config import Config
from .detect import Detector
from .names import DeviceNames, LastSeen
from .pcap import PcapStreamReader, PcapWriter, Frame


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
    # Prefer the cu.* form on macOS (non-blocking on open).
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
        self.fh = open(self.current_path, "ab" if not fresh else "wb")
        if fresh:
            self.writer = PcapWriter(self.fh, self.dlt)
        else:
            # Appending after restart: records only, header already present.
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

    stop = {"flag": False}

    def _sig(_signo, _frame):
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    names = DeviceNames(cfg.devices_path)
    seen = LastSeen(cfg.state_dir / "last-seen.json")
    detector = Detector(cfg.detector)
    total = 0
    started = time.time()
    last_status = 0.0

    try:
        with open(fifo_path, "rb") as fifo:
            reader = PcapStreamReader(fifo)
            ring = RingWriter(cfg.ring_dir, cfg.keep_files, reader.dlt)
            for frame in reader:
                # The sniffer timestamps relative to its own clock; stamp with host time.
                frame.ts = time.time()
                ring.write(frame)
                seen.touch(frame.src, frame.ts, frame.ftype)
                detector.add_frame(frame.ts)
                total += 1
                now = time.time()
                if now - last_status >= 10:
                    last_status = now
                    seen.maybe_save()
                    _write_status(cfg, port, total, started, detector, ring)
                if stop["flag"]:
                    break
    finally:
        try:
            sniffer._stop()
        except Exception:
            pass
        seen.save()
        try:
            ring.close()
        except UnboundLocalError:
            pass
        fifo_path.unlink(missing_ok=True)
        print(f"[threadwatch] stopped after {total} frames", flush=True)


def _write_status(cfg, port, total, started, detector, ring) -> None:
    import json
    status = {
        "updated": time.time(),
        "port": port,
        "channel": cfg.channel,
        "frames_total": total,
        "uptime_s": round(time.time() - started, 1),
        "current_file": str(ring.current_path),
        "detector": detector.snapshot(),
    }
    tmp = cfg.state_dir / "status.tmp"
    tmp.write_text(json.dumps(status, indent=1))
    tmp.replace(cfg.state_dir / "status.json")


def run_replay(cfg: Config, pcap_path: Path) -> None:
    """Run the detector + last-seen pipeline over an existing pcap file.

    Validation and offline analysis: frame timestamps from the file are used
    as-is, so historical storms are detected at their recorded times.
    """
    names = DeviceNames(cfg.devices_path)
    seen = LastSeen(cfg.state_dir / "replay-last-seen.json")
    detector = Detector(cfg.detector)
    detector.cfg.alert_cooldown_s = 0  # show every alert in replay
    total = 0
    first = last = None
    with open(pcap_path, "rb") as fh:
        reader = PcapStreamReader(fh)
        for frame in reader:
            if first is None:
                first = frame.ts
            last = frame.ts
            seen.touch(frame.src, frame.ts, frame.ftype)
            detector.add_frame(frame.ts)
            total += 1
    import json
    print(json.dumps({
        "file": str(pcap_path),
        "frames": total,
        "duration_s": round((last - first), 1) if first else 0,
        "detector": detector.snapshot(),
        "quiet_report": seen.report(names, quiet_after_s=600, now=last),
    }, indent=1))
