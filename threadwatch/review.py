"""Turn the raw event log into something a person can review.

The log is the right unit for machines and the wrong unit for people: a
device that went quiet and came back is two lines an hour apart, and a
bad link between two devices is a warning every fifteen minutes. This
module groups records into *episodes* (one row per thing that happened),
builds the per-day index the review pages navigate with, and summarises
devices from the last-seen table. Pure functions over dicts; the web pages
and the CLI both render from here.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from .events import day_bounds, day_of, iter_days, list_days, read_day
from .names import DeviceNames, LastSeen, reception

SEVERITY_RANK = {"info": 0, "notice": 1, "warning": 2, "critical": 3}


def _label(rec: dict) -> str:
    return rec.get("name") or rec.get("addr") or rec.get("src") or ""


def _addr(rec: dict) -> Optional[str]:
    return rec.get("addr") or rec.get("src")


def fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 120:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours}h{minutes:02d}m"
    days, hours = divmod(hours, 24)
    return f"{days}d{hours}h"


def group_episodes(records: list[dict], now: Optional[float] = None) -> list[dict]:
    """Collapse records into episodes.

    Each episode: {kind, start, end, severity, count, title, detail, addr,
    name, events: [records]}. ``end`` is None while a quiet spell is still
    open. Sorted by start.
    """
    now = now or time.time()
    records = sorted(records, key=lambda r: r["ts"])
    episodes: list[dict] = []
    open_quiet: dict[str, dict] = {}
    retrans: dict[tuple, dict] = {}
    foreign: dict[tuple, dict] = {}
    rejoin: dict[str, dict] = {}
    first_seen: Optional[dict] = None
    join_scan: Optional[dict] = None

    def new(kind, rec, title, detail="", **extra):
        ep = {"kind": kind, "start": rec["ts"], "end": rec["ts"], "severity": rec["severity"],
              "count": 1, "title": title, "detail": detail, "addr": _addr(rec),
              "name": rec.get("name"), "events": [rec]}
        ep.update(extra)
        episodes.append(ep)
        return ep

    def bump(ep, rec):
        ep["count"] += 1
        ep["end"] = rec["ts"]
        ep["events"].append(rec)
        if SEVERITY_RANK.get(rec["severity"], 0) > SEVERITY_RANK.get(ep["severity"], 0):
            ep["severity"] = rec["severity"]

    for rec in records:
        ev = rec.get("event", "")
        if ev == "device_quiet":
            addr = _addr(rec) or ""
            marginal = rec.get("reception") == "marginal"
            # The record is written when the silence crosses the threshold;
            # the silence itself began silent_for_s earlier.
            ep = new("quiet", rec, f"{_label(rec)} went quiet",
                     "sniffer hears it at the edge of range; probably fading, not failure"
                     if marginal else "no frames heard", end=None,
                     silent_since=rec["ts"] - float(rec.get("silent_for_s") or 0))
            open_quiet[addr] = ep
        elif ev == "device_returned":
            addr = _addr(rec) or ""
            ep = open_quiet.pop(addr, None)
            if ep is not None:
                ep["end"] = rec["ts"]
                ep["events"].append(rec)
                ep["title"] = f"{_label(rec)} quiet for {fmt_duration(rec['ts'] - ep['silent_since'])}"
            else:
                new("returned", rec, f"{_label(rec)} returned",
                    "was quiet before this day's log starts")
        elif ev == "retransmission_elevation":
            key = (rec.get("top_sender") or "", rec.get("top_target") or "")
            ep = retrans.get(key)
            if ep is None:
                who = f"{key[0]} -> {key[1]}" if key[0] else "mesh-wide"
                ep = retrans[key] = new("retransmissions", rec, f"retransmissions: {who}",
                                        rec.get("note", ""), max_rate=rec.get("rate", 0))
            else:
                bump(ep, rec)
                ep["max_rate"] = max(ep["max_rate"], rec.get("rate", 0))
        elif ev == "possible_foreign_pan":
            key = (rec.get("pan"), rec.get("src"))
            ep = foreign.get(key)
            if ep is None:
                foreign[key] = new("foreign_pan", rec, f"foreign PAN {rec.get('pan')} from {rec.get('src')}",
                                   f"ours is {rec.get('dominant_pan')}")
            else:
                bump(ep, rec)
        elif ev == "mle_rejoin_attempt":
            key = _label(rec)
            ep = rejoin.get(key)
            if ep is None:
                rejoin[key] = new("rejoin", rec, f"{key} rejoin attempt", rec.get("command", ""))
            else:
                bump(ep, rec)
                cmds = {e.get("command") for e in ep["events"]}
                ep["detail"] = ", ".join(sorted(c for c in cmds if c))
        elif ev == "device_first_seen":
            if first_seen is None or rec["ts"] - first_seen["end"] > 600:
                first_seen = new("first_seen", rec, "1 device first seen", _label(rec))
            else:
                bump(first_seen, rec)
                first_seen["title"] = f"{first_seen['count']} devices first seen"
                first_seen["detail"] = ", ".join(_label(e) for e in first_seen["events"][:8]) + \
                    (" ..." if first_seen["count"] > 8 else "")
        elif ev == "join_scan_activity":
            if join_scan is None or rec["ts"] - join_scan["end"] > 1800:
                join_scan = new("join_scan", rec, "join-scan beacons", f"{rec.get('count_60s')} in 60 s")
            else:
                bump(join_scan, rec)
                join_scan["detail"] = f"{join_scan['count']} bursts"
        elif ev == "partition_or_leader_change":
            prev, cur = rec.get("previous", {}), rec.get("current", {})
            new("partition", rec, "partition or leader change",
                f"partition {prev.get('partition')} leader r{prev.get('leader_router')} -> "
                f"partition {cur.get('partition')} leader r{cur.get('leader_router')}")
        elif ev == "phase_locked_storm":
            new("storm", rec, "phase-locked storm",
                f"period {rec.get('period_s')}s, onsets {rec.get('onsets')}, "
                f"baseline {rec.get('baseline_frames_per_window')} frames/window")
        elif ev == "alert_test":
            new("test", rec, "alert test", rec.get("note", ""))
        else:
            new(ev or "event", rec, ev, rec.get("note", ""))

    for ep in episodes:
        if ep["kind"] == "quiet" and ep["end"] is None:
            ep["title"] = f"{ep['name'] or ep['addr']} quiet for {fmt_duration(now - ep['silent_since'])} (still quiet)"
    return sorted(episodes, key=lambda e: e["start"])


def day_episodes(events_dir: Path, day: str, now: Optional[float] = None) -> list[dict]:
    """Episodes that touch a day. The neighbouring days are read too so a
    quiet spell that started yesterday and ended today shows on both days
    with its real duration, and one still open today is not shown as open
    on yesterday's page once it has closed."""
    from .events import next_day, prev_day
    start, end = day_bounds(day)
    records = (read_day(events_dir, prev_day(day)) + read_day(events_dir, day)
               + read_day(events_dir, next_day(day)))
    out = []
    for ep in group_episodes(records, now):
        ep_end = ep["end"] if ep["end"] is not None else (now or time.time())
        if ep_end >= start and ep["start"] < end:
            out.append(ep)
    return out


def day_index(events_dir: Path) -> list[dict]:
    """One row per day with an event file: counts by severity, newest first."""
    rows = []
    for day, recs in iter_days(events_dir):
        counts = {"info": 0, "notice": 0, "warning": 0, "critical": 0}
        for r in recs:
            counts[r.get("severity", "info")] = counts.get(r.get("severity", "info"), 0) + 1
        rows.append({"day": day, "total": len(recs), **counts})
    rows.reverse()
    return rows


def device_rows(seen: LastSeen, names: DeviceNames, min_rssi_dbm: float,
                now: Optional[float] = None) -> list[dict]:
    now = now or time.time()
    rows = []
    for addr, row in seen.table.items():
        rssi = row.get("rssi")
        rows.append({
            "addr": addr,
            "name": names.name(addr),
            "role": names.role(addr),
            "frames": row.get("frames", 0),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "silent_for_s": round(now - row.get("last_seen", now)),
            "rssi_dbm": rssi,
            "reception": reception(rssi, min_rssi_dbm),
            "pan": row.get("pan"),
            "polls": row.get("types", {}).get("3", 0),
        })
    rows.sort(key=lambda r: ((r["name"] is None), (r["name"] or r["addr"]).lower()))
    return rows


def device_history(events_dir: Path, addr: str, now: Optional[float] = None) -> list[dict]:
    """Every episode involving one device, across all days, newest first."""
    addr = addr.lower()
    records = []
    for _day, recs in iter_days(events_dir):
        for r in recs:
            a = (_addr(r) or "").lower()
            if a == addr:
                records.append(r)
    return list(reversed(group_episodes(records, now)))


def capture_for_day(ring_dir: Path, incidents_dir: Path, day: str) -> dict:
    """Whether packets for a day still exist: ring files (one week) and any
    frozen incidents dated that day."""
    stamp = day.replace("-", "")
    ring = sorted(p.name for p in ring_dir.glob(f"threadwatch-{stamp}-*.pcap")) if ring_dir.exists() else []
    incidents = sorted(p.name for p in incidents_dir.iterdir()
                       if p.is_dir() and p.name.startswith(stamp)) if incidents_dir.exists() else []
    return {"ring_files": ring, "incidents": incidents}


def today() -> str:
    return day_of(time.time())


def days_available(events_dir: Path) -> list[str]:
    return list_days(events_dir)
