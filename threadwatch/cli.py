"""threadwatch command-line interface."""

from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path

from . import config as config_mod


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="threadwatch",
        description="Continuous 802.15.4/Thread capture and storm detection "
                    "using an nRF52840 dongle.",
    )
    parser.add_argument("--config", type=Path, help="path to config.toml")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("capture", help="run the capture daemon (foreground)")
    sub.add_parser("status", help="show the running daemon's status")

    p_replay = sub.add_parser("replay", help="run detection over an existing pcap file")
    p_replay.add_argument("pcap", type=Path)

    p_freeze = sub.add_parser("freeze", help="preserve the current ring buffer as an incident")
    p_freeze.add_argument("label", nargs="?", default="incident")

    p_report = sub.add_parser("report", help="device last-seen / quiet / unknown-address report")
    p_report.add_argument("--quiet-minutes", type=float, default=90.0,
                          help="minutes of silence before a device is listed as quiet")

    p_why = sub.add_parser("why", help="reconstruct one device's story from the ring buffer")
    p_why.add_argument("device", help="device name (from devices.json) or 16-hex extended address")
    p_why.add_argument("--pcap", type=Path, help="analyze this file instead of the ring")

    p_events = sub.add_parser("events", help="show recent events")
    p_events.add_argument("-n", type=int, default=30)

    p_test = sub.add_parser("alert-test",
                            help="send a synthetic event through every alert sink and "
                                 "push every heartbeat once (cooldowns ignored)")
    p_test.add_argument("--severity", default="warning",
                        choices=("info", "notice", "warning", "critical"))
    p_test.add_argument("--event", default="alert_test")
    p_test.add_argument("--no-heartbeats", action="store_true")

    args = parser.parse_args(argv)
    cfg = config_mod.load(args.config)

    if args.cmd == "capture":
        from .capture import run_capture
        run_capture(cfg)
        return 0

    if args.cmd == "replay":
        from .capture import run_replay
        run_replay(cfg, args.pcap)
        return 0

    if args.cmd == "status":
        path = cfg.state_dir / "status.json"
        if not path.exists():
            print("no status file; is the capture daemon running?")
            return 1
        status = json.loads(path.read_text())
        age = time.time() - status.get("updated", 0)
        status["status_age_s"] = round(age, 1)
        status["daemon_alive"] = age < 30
        print(json.dumps(status, indent=1))
        return 0

    if args.cmd == "freeze":
        ts = time.strftime("%Y%m%dT%H%M%S")
        dest = cfg.incidents_dir / f"{ts}_{args.label}"
        dest.mkdir(parents=True, exist_ok=False)
        count = 0
        for f in sorted(cfg.ring_dir.glob("threadwatch-*.pcap")):
            shutil.copy2(f, dest / f.name)
            count += 1
        for extra in ("status.json", "last-seen.json", "events.jsonl", "observed-names.json"):
            src = cfg.state_dir / extra
            if src.exists():
                shutil.copy2(src, dest / extra)
        print(f"froze {count} ring files -> {dest}")
        return 0

    if args.cmd == "why":
        from .why import run_why
        run_why(cfg, args.device, args.pcap)
        return 0

    if args.cmd == "events":
        path = cfg.state_dir / "events.jsonl"
        if not path.exists():
            print("no events yet")
            return 0
        lines = path.read_text().splitlines()[-args.n:]
        for line in lines:
            e = json.loads(line)
            stamp = time.strftime("%m-%d %H:%M:%S", time.localtime(e.pop("ts")))
            sev = e.pop("severity")
            name = e.pop("event")
            print(f"{stamp} [{sev:8s}] {name}  {json.dumps(e)}")
        return 0

    if args.cmd == "alert-test":
        from .alerts import Dispatcher, HeartbeatRunner, build_heartbeats, build_sinks
        import socket
        log = lambda m: print(f"  ! {m}")
        sinks = build_sinks(cfg.alerts_raw, log)
        beats = [] if args.no_heartbeats else build_heartbeats(cfg.heartbeats_raw, log)
        record = {"ts": time.time(), "event": args.event, "severity": args.severity,
                  "name": "Test device", "addr": "0000000000000000",
                  "note": f"threadwatch alert-test from {socket.gethostname()}"}
        failures = 0
        print(f"sinks ({len(sinks)}):")
        for sink, err in Dispatcher(sinks, log).deliver_now(record):
            print(f"  {'ok  ' if err is None else 'FAIL'} {sink.describe()}" + (f" -> {err}" if err else ""))
            failures += err is not None
        skipped = [s for s in sinks if s.min_severity > ["info", "notice", "warning", "critical"].index(args.severity)]
        for s in skipped:
            print(f"  skip {s.name} (min severity above {args.severity})")
        if beats:
            print(f"heartbeats ({len(beats)}):")
            for beat, err in HeartbeatRunner(beats, healthy=lambda: True, log=log, start=False).push_all(healthy=True):
                print(f"  {'ok  ' if err is None else 'FAIL'} {beat.describe()}" + (f" -> {err}" if err else ""))
                failures += err is not None
        return 1 if failures else 0

    if args.cmd == "report":
        from .names import DeviceNames, LastSeen
        names = DeviceNames(cfg.devices_path)
        seen = LastSeen(cfg.state_dir / "last-seen.json")
        report = seen.report(names, quiet_after_s=args.quiet_minutes * 60,
                             min_rssi_dbm=cfg.quiet_min_rssi_dbm)
        print(json.dumps(report, indent=1))
        if report["unknown"]:
            import sys
            print(f"{len(report['unknown'])} unknown address(es) seen. Add them to "
                  f"config/devices.json to name them (see docs in threadwatch/names.py).",
                  file=sys.stderr)
        return 0

    return 1
