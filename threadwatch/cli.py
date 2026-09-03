"""threadwatch command-line interface."""

from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path

from . import config as config_mod


def _positive_int(text: str) -> int:
    n = int(text)
    if n < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return n


def _inventory_path(cfg) -> Path:
    """Where devices.json lives, whether or not it exists yet."""
    return cfg.devices_path or cfg.config_dir / "devices.json"


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
    p_report.add_argument("--suggest", action="store_true",
                          help="print a ready-to-paste devices.json entry per unknown address "
                               "instead of the report (names prefilled from harvested SRP hostnames)")

    p_adopt = sub.add_parser("adopt", help="name an address: add it to devices.json")
    p_adopt.add_argument("addr", help="16-hex extended address (from 'report')")
    p_adopt.add_argument("name", help="device name; an existing name gains the address (rotation)")
    p_adopt.add_argument("--role", help="router, reed, border-router, border-router-leader "
                                        "(always-on: short quiet window) or sleepy-end-device")

    p_why = sub.add_parser("why", help="reconstruct one device's story from the ring buffer")
    p_why.add_argument("device", help="device name (from devices.json) or 16-hex extended address")
    p_why.add_argument("--pcap", type=Path, help="analyze this file instead of the ring")
    p_why.add_argument("--hours", type=float,
                       help="only the ring files covering the last N hours (default: the whole ring)")

    p_events = sub.add_parser("events", help="show recent events, or one day's")
    p_events.add_argument("-n", type=_positive_int, default=30, help="how many of the latest records")
    p_events.add_argument("--day", help="YYYY-MM-DD: every record from that local day")
    p_events.add_argument("--episodes", action="store_true",
                          help="group into episodes the way the web review page does")

    p_web = sub.add_parser("web", help="serve the review pages (day-by-day events, devices)")
    p_web.add_argument("--bind", help="address to listen on (default: [web] bind, else 0.0.0.0)")
    p_web.add_argument("--port", type=int, help="port (default: [web] port, else 8080)")

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
        status["daemon_alive"] = age < 90    # written every 30 s by the watchdog
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
        for extra in ("status.json", "last-seen.json", "observed-names.json"):
            src = cfg.state_dir / extra
            if src.exists():
                shutil.copy2(src, dest / extra)
        if cfg.events_dir.exists():
            shutil.copytree(cfg.events_dir, dest / "events", dirs_exist_ok=True)
        print(f"froze {count} ring files -> {dest}")
        return 0

    if args.cmd == "why":
        from .why import run_why
        if args.pcap and args.hours is not None:
            parser.error("--hours selects ring files; it does not apply with --pcap")
        if args.hours is not None and args.hours <= 0:
            parser.error("--hours must be positive")
        run_why(cfg, args.device, args.pcap, hours=args.hours)
        return 0

    if args.cmd == "events":
        from .events import list_days, migrate_legacy, read_day
        migrate_legacy(cfg.events_dir)
        days = list_days(cfg.events_dir)
        if not days:
            print("no events yet")
            return 0
        if args.day:
            from .web import valid_day
            if not valid_day(args.day):
                parser.error(f"--day wants YYYY-MM-DD, not {args.day!r}")
            records = read_day(cfg.events_dir, args.day)
            if not records:
                print(f"no events on {args.day}")
                return 0
        else:
            records = []
            for day in reversed(days):
                records = read_day(cfg.events_dir, day) + records
                if len(records) >= args.n:
                    break
            records = records[-args.n:]
        if args.episodes:
            from .review import fmt_episode, group_episodes
            for ep in group_episodes(records):
                print(fmt_episode(ep))
            return 0
        for e in records:
            e = dict(e)
            stamp = time.strftime("%m-%d %H:%M:%S", time.localtime(e.pop("ts")))
            sev = e.pop("severity")
            name = e.pop("event")
            print(f"{stamp} [{sev:8s}] {name}  {json.dumps(e)}")
        return 0

    if args.cmd == "web":
        from .web import serve
        serve(cfg, bind=args.bind or cfg.web_bind, port=args.port or cfg.web_port)
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
        import sys
        from .names import DeviceNames, LastSeen, load_observed_names, rotation_hints, suggest_entries
        names = DeviceNames(cfg.devices_path)
        seen = LastSeen(cfg.state_dir / "last-seen.json")
        report = seen.report(names, quiet_after_s=args.quiet_minutes * 60,
                             min_rssi_dbm=cfg.quiet_min_rssi_dbm)
        if args.suggest:
            hints = rotation_hints(report["unknown"], seen.table, names)
            entries = suggest_entries(report["unknown"], load_observed_names(cfg.state_dir), hints)
            print(json.dumps(entries, indent=2, ensure_ascii=False))
            for addr, h in hints.items():
                print(f"{addr}: looks like {h['name']!r} rotated its address "
                      f"({h['delta_s']:+d} s from its previous one going silent). If so: "
                      f"threadwatch adopt {addr} '{h['name']}'", file=sys.stderr)
            if entries:
                print(f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} to fill in and "
                      f"paste into {_inventory_path(cfg).name}, or name one directly with: "
                      f"threadwatch adopt <addr> '<name>'", file=sys.stderr)
            return 0
        print(json.dumps(report, indent=1))
        if report["unknown"]:
            print(f"{len(report['unknown'])} unknown address(es) seen. Name them with "
                  f"'threadwatch adopt <addr> <name>', or 'threadwatch report --suggest' "
                  f"for ready-to-paste entries (format: threadwatch/names.py).",
                  file=sys.stderr)
        return 0

    if args.cmd == "adopt":
        from .names import adopt
        path = _inventory_path(cfg)
        try:
            print(f"{adopt(path, args.addr, args.name, args.role)} -> {path}")
        except ValueError as exc:
            parser.exit(1, f"threadwatch adopt: {exc}\n")
        print("(the capture daemon reads the inventory at start: restart it to use the name)")
        return 0

    return 1
