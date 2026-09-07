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


def _find_snapshot(cfg, want: str, parser, command: str) -> Path:
    """The snapshot directory a user named: by its directory name, its
    label as typed when it was saved, or that label's filename-safe form;
    a path to the directory itself also works. One match, or an error."""
    from .review import snapshots
    from .snapshot import safe_label
    as_path = Path(want)
    if as_path.is_dir():
        return as_path
    want = want.strip().rstrip("/")
    items = snapshots(cfg.snapshots_dir)
    hits = ([i for i in items if i["name"] == want]
            or [i for i in items if i["label"] == want]
            or [i for i in items if i["label"] == safe_label(want)])
    if not hits:
        parser.exit(1, f"threadwatch {command}: no snapshot named {want!r}\n")
    if len(hits) > 1:
        parser.exit(1, f"threadwatch {command}: {want!r} names {len(hits)} snapshots; "
                       f"use the full name: {', '.join(i['name'] for i in hits)}\n")
    return cfg.snapshots_dir / hits[0]["name"]


def _print_episodes(episodes: list, floor: int, ranks: dict, what: str) -> int:
    """The episode lines, or a word about there being none."""
    from .review import fmt_episode
    shown = [ep for ep in episodes if ranks.get(ep["severity"], 0) >= floor]
    if not shown:
        print(f"no episodes {what}".rstrip())
        return 0
    for ep in shown:
        print(fmt_episode(ep))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="threadwatch",
        description="Continuous 802.15.4/Thread capture and storm detection "
                    "using an nRF52840 dongle.",
    )
    parser.add_argument("--config", type=Path, help="path to config.toml")
    # Which code this is, for telling a host running what you just pushed
    # from one running a six-month-old checkout. Nothing else did.
    from . import __version__
    from .config import repo_commit
    commit = repo_commit()
    parser.add_argument("--version", action="version",
                        version=f"threadwatch {__version__}" + (f" ({commit})" if commit else ""))
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("record", help="run the recorder (foreground)")
    sub.add_parser("status", help="show the running daemon's status")

    p_replay = sub.add_parser("replay", help="run detection over existing pcap files, as one run")
    p_replay.add_argument("pcap", type=Path, nargs="*",
                          help="pcap files in order, or a directory (a snapshot, the ring) of them")
    p_replay.add_argument("--snapshot", metavar="NAME",
                          help="a saved snapshot (name or label): its pcaps, judged with its own inventory "
                               "and state; any pcaps given are read instead of its own")

    p_snapshot = sub.add_parser("snapshot", help="save the current ring buffer as a snapshot")
    p_snapshot.add_argument("label", nargs="?", default="snapshot")

    p_devices = sub.add_parser("devices", help="device last-seen / quiet / unknown-address report")
    p_devices.add_argument("--quiet-minutes", type=float, default=None,
                          help="list every device silent this many minutes (wall clock) as quiet, instead of "
                               "the devices the recorder has announced quiet (the same set the review pages "
                               "show: [quiet] silence_s of silence it was up to hear)")
    p_devices.add_argument("--suggest", action="store_true",
                          help="print a ready-to-paste devices.json entry per unknown address "
                               "instead of the report (names prefilled from harvested SRP hostnames)")

    p_name = sub.add_parser("name", help="name an address: add it to devices.json")
    p_name.add_argument("addr", help="16-hex extended address (from 'devices')")
    p_name.add_argument("name", help="device name; an existing name gains the address (rotation)")

    p_imp = sub.add_parser("import", help="fill devices.json and credentials.toml from Home Assistant (Matter "
                                          "devices, the network key) and mDNS (border routers)")
    p_imp.add_argument("--write", action="store_true", help="apply; without it, only report what would change")
    p_imp.add_argument("--no-ha", action="store_true", help="skip Home Assistant (no token needed then)")
    p_imp.add_argument("--no-mdns", action="store_true", help="skip the mDNS border-router browse")
    p_imp.add_argument("--url", help="Home Assistant URL (default: HA_URL from config/ha.env, else "
                                     "http://homeassistant.local:8123)")
    p_imp.add_argument("--env-file", type=Path, help="file holding HA_TOKEN and HA_URL (default: config/ha.env)")
    p_imp.add_argument("--dataset-id", help="which Thread dataset, when HA holds several and none is preferred")
    p_imp.add_argument("--no-devices", action="store_true", help="skip devices.json")
    p_imp.add_argument("--no-credentials", action="store_true", help="skip credentials.toml")
    p_imp.add_argument("--mdns-seconds", type=float, default=4.0, help="how long to wait for mDNS answers")

    p_br = sub.add_parser("border-routers", help="ask the LAN (mDNS) which Thread border routers it can see, "
                                                 "with their current extended addresses")
    p_br.add_argument("--seconds", type=float, default=4.0, help="how long to wait for answers")

    p_device = sub.add_parser("device", help="reconstruct one device's story from the ring buffer")
    p_device.add_argument("device", help="device name (from devices.json) or 16-hex extended address")
    p_device.add_argument("--pcap", type=Path, help="analyze this file instead of the ring")
    p_device.add_argument("--snapshot", metavar="NAME",
                       help="analyze a saved snapshot (name or label) instead of the ring, with the "
                            "inventory and event log saved with it")
    p_device.add_argument("--hours", type=float,
                       help="only the ring files covering the last N hours (default: the whole ring)")

    p_events = sub.add_parser("events", help="show recent events, or one day's")
    p_events.add_argument("-n", type=_positive_int, default=30, help="how many of the latest records")
    p_events.add_argument("--day", help="YYYY-MM-DD: every record from that local day")
    p_events.add_argument("--episodes", action="store_true",
                          help="group into episodes the way the web review page does")
    p_events.add_argument("--device", help="only records about this device (name, part of one, or address); "
                                           "every address of a rotating device counts")
    p_events.add_argument("--severity", choices=("info", "notice", "warning", "critical"),
                          help="only records at this severity or above")

    p_serve = sub.add_parser("serve", help="serve the review pages (day-by-day events, devices)")
    p_serve.add_argument("--bind", help="address to listen on (default: [web] bind, else 127.0.0.1; "
                                      "\"0.0.0.0\" serves the LAN, where nothing authenticates)")
    p_serve.add_argument("--port", type=int, help="port (default: [web] port, else 8080)")

    p_snapshots = sub.add_parser("snapshots", help="list saved snapshots, or delete one")
    p_snapshots.add_argument("--delete", metavar="NAME", help="remove this snapshot (its directory name, or a "
                                                          "label that names exactly one)")

    sub.add_parser("doctor", help="check this box is fit to record: dongle, config, key file, disk, "
                                  "clock, services, ring, sinks (read-only)")

    p_test = sub.add_parser("alert-test",
                            help="send a synthetic event through every alert sink and "
                                 "push every heartbeat once (cooldowns ignored)")
    p_test.add_argument("--severity", default="warning",
                        choices=("info", "notice", "warning", "critical"))
    p_test.add_argument("--event", default="alert_test")
    p_test.add_argument("--no-heartbeats", action="store_true")

    args = parser.parse_args(argv)
    try:
        cfg = config_mod.load(args.config)
    except (ValueError, OSError) as exc:
        # ValueError covers malformed TOML and rejected values; OSError a
        # --config path that does not exist or cannot be read (a typo, or
        # a volume that failed to mount): one line, not five frames.
        parser.exit(2, f"threadwatch: {exc}\n")
    from .pipeline import CredentialsError

    if args.cmd == "record":
        from .record import run_record
        try:
            run_record(cfg)
        except CredentialsError as exc:
            parser.exit(2, f"threadwatch record: {exc}\n")
        return 0

    if args.cmd == "replay":
        from .record import run_replay
        paths = list(args.pcap)
        if args.snapshot:
            inc = _find_snapshot(cfg, args.snapshot, parser, "replay")
            cfg = cfg.for_snapshot(inc)
            paths = paths or [inc]
        if not paths:
            parser.error("give pcap files, a directory of them, or --snapshot NAME")
        try:
            run_replay(cfg, paths)
        except CredentialsError as exc:
            parser.exit(2, f"threadwatch replay: {exc}\n")
        return 0

    if args.cmd == "status":
        path = cfg.state_dir / "status.json"
        if not path.exists():
            print("no status file; is the recorder running?")
            return 1
        from .review import status_state
        try:
            status = json.loads(path.read_text())
        except ValueError:
            print("status file is unreadable (mid-write? damaged?)")
            return 1
        # The one reading of a status file's age (written every 30 s by
        # the watchdog), shared with the status page and doctor.
        state, age = status_state(status, time.time())
        if state == "none":
            print("status file holds no recorder state; is the recorder running?")
            return 1
        status["status_age_s"] = round(age, 1)
        # Only a status file the recorder is still writing says it is alive.
        # "dead" is a stale file; "none" is an empty or damaged one, which is
        # no evidence of a recorder at all.
        status["daemon_alive"] = state in ("live", "quiet")
        print(json.dumps(status, indent=1))
        return 0

    if args.cmd == "snapshot":
        from .snapshot import save_snapshot
        dest, count = save_snapshot(cfg, args.label)
        print(f"saved {count} ring files -> {dest}")
        return 0

    if args.cmd == "device":
        from .device import run_device
        if args.pcap and args.hours is not None:
            parser.error("--hours selects ring files; it does not apply with --pcap")
        if args.pcap and args.snapshot:
            parser.error("--pcap and --snapshot each say what to read; give one")
        if args.hours is not None and args.hours <= 0:
            parser.error("--hours must be positive")
        snap = _find_snapshot(cfg, args.snapshot, parser, "device") if args.snapshot else None
        try:
            return run_device(cfg, args.device, args.pcap, hours=args.hours, snapshot_dir=snap)
        except CredentialsError as exc:
            parser.exit(2, f"threadwatch device: {exc}\n")

    if args.cmd == "events":
        from .events import list_days, migrate_legacy, read_day
        from .review import SEVERITY_RANK
        migrate_legacy(cfg.events_dir)
        days = list_days(cfg.events_dir)
        if not days:
            print("no events yet")
            return 0
        addrs = None
        if args.device:
            try:
                from .names import load_names
                addrs = set(load_names(cfg).resolve(args.device)[0])
            except ValueError as exc:
                parser.error(str(exc))
        floor = SEVERITY_RANK.get(args.severity or "info", 0)

        def wanted(rec):
            # With --episodes the floor is applied to the episodes, after
            # grouping (as the day page does): the notice that closes a
            # warning (device_returned, poll_answered) is what tells a
            # recovered episode from an open one, and filtering it out
            # first turned every recovery into "still quiet".
            if not args.episodes and SEVERITY_RANK.get(rec.get("severity", "info"), 0) < floor:
                return False
            if addrs is not None:
                who = (rec.get("addr") or rec.get("src") or "").lower()
                return who in addrs
            return True

        what = " ".join(filter(None, [f"about {args.device!r}" if args.device else "",
                                      f"at {args.severity} or above" if args.severity else ""]))
        def mine(ep):
            return addrs is None or (ep.get("addr") or "").lower() in addrs

        if args.day:
            from .web import valid_day
            if not valid_day(args.day):
                parser.error(f"--day wants YYYY-MM-DD, not {args.day!r}")
            # First, whether the recorder was there to hear the day: a
            # silence inside one of these lines is not the device's.
            from .review import coverage
            for seg in coverage(cfg.events_dir, args.day):
                a, b = (time.strftime("%H:%M", time.localtime(t)) for t in (seg["start"], seg["end"]))
                how = "not listening" if seg["state"] == "blind" else "may not have heard"
                print(f"{a}-{b} recorder {how}: {seg['note']}")
            if args.episodes:
                # The same call the web day page makes, which groups over
                # the days around this one. Grouping this day's file alone
                # rebuilt an episode that opened earlier from its closing
                # record: a different kind, a shorter duration and a
                # notice where the page showed a warning, so a 15-hour
                # outage was missing from --severity warning entirely.
                from .review import day_episodes
                episodes = [ep for ep in day_episodes(cfg.events_dir, args.day) if mine(ep)]
                return _print_episodes(episodes, floor, SEVERITY_RANK, f"{what} on {args.day}")
            records = [r for r in read_day(cfg.events_dir, args.day) if wanted(r)]
            if not records:
                print(f"no events {what + ' ' if what else ''}on {args.day}")
                return 0
        else:
            if args.episodes:
                # Episodes are not records. Reading only as far back as -n
                # raw records could load a recovery whose opening record is
                # on the day before, which rebuilds the episode from its
                # close: a different kind, a shorter duration, and a notice
                # where the warning was, so a real overnight outage was
                # missing from --severity warning altogether. Days are read
                # newest first until n episodes pass the severity and
                # device filters, and then a further EPISODE_WINDOW_DAYS,
                # which is the window the day page groups over.
                from .review import EPISODE_WINDOW_DAYS, group_episodes
                episodes, records, enough_at = [], [], None
                for i, day in enumerate(reversed(days)):
                    records = [r for r in read_day(cfg.events_dir, day) if wanted(r)] + records
                    episodes = [ep for ep in group_episodes(records)
                                if mine(ep) and SEVERITY_RANK.get(ep["severity"], 0) >= floor]
                    if enough_at is None and len(episodes) >= args.n:
                        enough_at = i
                    if enough_at is not None and i - enough_at >= EPISODE_WINDOW_DAYS:
                        break
                return _print_episodes(episodes[-args.n:], floor, SEVERITY_RANK, what)
            records = []
            for day in reversed(days):
                records = [r for r in read_day(cfg.events_dir, day) if wanted(r)] + records
                if len(records) >= args.n:
                    break
            records = records[-args.n:]
            if not records:
                print(f"no events {what}")
                return 0
        for e in records:
            e = dict(e)
            stamp = time.strftime("%m-%d %H:%M:%S", time.localtime(e.pop("ts")))
            sev = e.pop("severity")
            name = e.pop("event")
            print(f"{stamp} [{sev:8s}] {name}  {json.dumps(e)}")
        return 0

    if args.cmd == "serve":
        from .web import serve
        serve(cfg, bind=args.bind or cfg.web_bind, port=args.port or cfg.web_port)
        return 0

    if args.cmd == "snapshots":
        import sys

        from .review import fmt_bytes, snapshots
        items = snapshots(cfg.snapshots_dir)
        if args.delete:
            target = _find_snapshot(cfg, args.delete, parser, "snapshots")
            if target.parent.resolve() != cfg.snapshots_dir.resolve():
                parser.exit(1, f"threadwatch snapshots: {target} is not under {cfg.snapshots_dir}\n")
            size = next((i["bytes"] for i in items if i["name"] == target.name), 0)
            shutil.rmtree(target)
            print(f"deleted {target} ({fmt_bytes(size)})")
            return 0
        if not items:
            print("no snapshots (threadwatch snapshot <label> makes one)")
            return 0
        for i in items:
            span = f"{i['span'][0]} to {i['span'][1]}" if i["span"] else "no ring files"
            print(f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(i['saved']))}  {i['name']:36s} "
                  f"{fmt_bytes(i['bytes']):>9s}  {i['pcaps']:3d} pcaps  {span}"
                  + ("  +events" if i["events"] else ""))
        total = sum(i["bytes"] for i in items)
        print(f"{len(items)} snapshot(s), {fmt_bytes(total)} in {cfg.snapshots_dir}", file=sys.stderr)
        return 0

    if args.cmd == "doctor":
        from .doctor import print_report, run_doctor
        return print_report(run_doctor(cfg))

    if args.cmd == "alert-test":
        import socket

        from .alerts import Dispatcher, HeartbeatRunner, build_heartbeats, build_sinks
        log = lambda m: print(f"  ! {m}")
        # A recipient that is enabled but could not be built (a ${VARIABLE}
        # it names is unset) delivers nothing: that is what this command
        # exists to catch, so it is a FAIL line and a non-zero exit, not a
        # note above an "ok". A recipient switched off with enabled = false
        # is not listed, as before.
        unbuilt_sinks: list = []
        unbuilt_beats: list = []
        sinks = build_sinks(cfg.alerts_raw, log, unbuilt_sinks)
        beats = [] if args.no_heartbeats else build_heartbeats(cfg.heartbeats_raw, log, unbuilt_beats)
        record = {"ts": time.time(), "event": args.event, "severity": args.severity,
                  "name": "Test device", "addr": "0000000000000000",
                  "note": f"threadwatch alert-test from {socket.gethostname()}"}
        failures = len(unbuilt_sinks) + len(unbuilt_beats)
        print(f"sinks ({len(sinks) + len(unbuilt_sinks)}):")
        for sink, err in Dispatcher(sinks, log).deliver_now(record):
            print(f"  {'ok  ' if err is None else 'FAIL'} {sink.describe()}" + (f" -> {err}" if err else ""))
            failures += err is not None
        for name, reason in unbuilt_sinks:
            print(f"  FAIL {name}: not built -> {reason}")
        for s in sinks:
            if s.min_severity > ["info", "notice", "warning", "critical"].index(args.severity):
                print(f"  skip {s.name} (min severity above {args.severity})")
            elif not s.takes_event(args.event):
                print(f"  skip {s.name} (does not take {args.event})")
        if beats or unbuilt_beats:
            print(f"heartbeats ({len(beats) + len(unbuilt_beats)}):")
            for beat, err in HeartbeatRunner(beats, healthy=lambda: True, log=log, start=False).push_all(healthy=True):
                print(f"  {'ok  ' if err is None else 'FAIL'} {beat.describe()}" + (f" -> {err}" if err else ""))
                failures += err is not None
            for name, reason in unbuilt_beats:
                print(f"  FAIL {name}: not built -> {reason}")
        return 1 if failures else 0

    if args.cmd == "devices":
        import sys

        from .names import LastSeen, load_names, load_observed_names, rotation_hints, suggest_entries
        from .review import dominant_pan
        names = load_names(cfg)
        seen = LastSeen(cfg.state_dir / "last-seen.json")
        report = seen.report(names, quiet_after_s=None if args.quiet_minutes is None else args.quiet_minutes * 60,
                             min_rssi_dbm=cfg.quiet_min_rssi_dbm,
                             dominant=dominant_pan(seen, cfg.pan_id, cfg.state_dir))
        if args.suggest:
            hints = rotation_hints(report["unknown"], seen.table, names)
            entries = suggest_entries(report["unknown"], load_observed_names(cfg.state_dir), hints)
            print(json.dumps(entries, indent=2, ensure_ascii=False))
            for addr, h in hints.items():
                print(f"{addr}: looks like {h['name']!r} rotated its address "
                      f"({h['delta_s']:+d} s from its previous one going silent). If so: "
                      f"threadwatch name {addr} '{h['name']}'", file=sys.stderr)
            if entries:
                print(f"{len(entries)} entr{'y' if len(entries) == 1 else 'ies'} to fill in and "
                      f"paste into {_inventory_path(cfg).name}, or name one directly with: "
                      f"threadwatch name <addr> '<name>'", file=sys.stderr)
            return 0
        print(json.dumps(report, indent=1))
        if report["unknown"]:
            print(f"{len(report['unknown'])} unknown address(es) seen. Name them with "
                  f"'threadwatch name <addr> <name>', or 'threadwatch devices --suggest' "
                  f"for ready-to-paste entries (the format: README.md, devices.json).",
                  file=sys.stderr)
        return 0

    if args.cmd == "border-routers":
        from .mdns import browse
        from .names import load_names
        names = load_names(cfg)
        found = browse(timeout=args.seconds, log=lambda m: print(f"  ! {m}"))
        if not found:
            print("no Thread border routers answered over mDNS: is this host on their subnet, or is mDNS "
                  "reflected between VLANs?")
            return 1
        for r in found:
            who = names.name(r["ext"]) if r.get("ext") else None
            print(f"{r['instance']}  {r.get('vendor') or '?'} {r.get('model') or ''}\n"
                  f"  hostname {r.get('hostname')}  address {r.get('ext') or '?'}"
                  f"  -> {who or 'not in devices.json'}\n"
                  f"  network {r.get('network_name')}  ext PAN {r.get('ext_pan_id')}  "
                  f"ip {', '.join(r.get('addresses') or [])}")
        return 0

    if args.cmd == "import":
        from .ha import HAError
        from .importer import run_import
        try:
            return run_import(cfg, _inventory_path(cfg), write=args.write, url=args.url, env_file=args.env_file,
                              dataset_id=args.dataset_id, use_ha=not args.no_ha, use_mdns=not args.no_mdns,
                              mdns_seconds=args.mdns_seconds, devices=not args.no_devices,
                              credentials=not args.no_credentials)
        except (HAError, ValueError) as exc:     # ValueError: a malformed devices.json, named
            parser.exit(1, f"threadwatch import: {exc}\n")

    if args.cmd == "name":
        from .names import adopt
        path = _inventory_path(cfg)
        try:
            print(f"{adopt(path, args.addr, args.name)} -> {path}")
        except ValueError as exc:
            parser.exit(1, f"threadwatch name: {exc}\n")
        print("(the recorder reads the inventory at start: restart it to use the name)")
        return 0

    return 1
