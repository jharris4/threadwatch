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

from .events import day_bounds, day_of, iter_days, list_days, read_all, read_day
from .names import DeviceNames, LastSeen, reception, rloc16_role

SEVERITY_RANK = {"info": 0, "notice": 1, "warning": 2, "critical": 3}

# A recurring thing (the same bad link, the same neighbour's PAN, the same
# device rejoining) is one row while its records keep coming, and a new row
# after this much silence; without a limit a device that rejoins once a day
# would be a single row for the whole history.
GAP_S = {"retransmissions": 3600.0, "rejoin": 3600.0, "foreign_pan": 86400.0}


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
    open_link: dict[str, dict] = {}
    open_starved: dict[str, dict] = {}
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
            ep = open_quiet.get(addr)
            if ep is not None:
                # Announced again before it returned (the recorder died
                # between announcing and saving): same silence, one row.
                ep["count"] += 1
                ep["events"].append(rec)
                if SEVERITY_RANK.get(rec["severity"], 0) > SEVERITY_RANK.get(ep["severity"], 0):
                    ep["severity"] = rec["severity"]
                continue
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
        elif ev == "poll_starvation":
            addr = _addr(rec) or ""
            ep = open_starved.get(addr)
            if ep is not None:
                bump(ep, rec)
                continue
            open_starved[addr] = new("starved", rec, f"{_label(rec)} polls unanswered",
                                     f"{rec.get('unanswered_polls')} polls, {rec.get('acked_polls')} answered before",
                                     end=None, starved_since=rec.get("since", rec["ts"]))
        elif ev == "poll_answered":
            addr = _addr(rec) or ""
            ep = open_starved.pop(addr, None)
            if ep is not None:
                ep["end"] = rec["ts"]
                ep["events"].append(rec)
                ep["title"] += f" for {fmt_duration(rec['ts'] - ep['starved_since'])}"
            else:
                new("starved", rec, f"{_label(rec)} polls answered again", rec.get("note", ""))
        elif ev == "rssi_degradation":
            addr = _addr(rec) or ""
            ep = open_link.get(addr)
            if ep is not None:
                bump(ep, rec)
                continue
            drop = rec.get("drop_db")
            open_link[addr] = new("link", rec, f"{_label(rec)} signal down {drop:g} dB",
                                  f"{rec.get('rssi_dbm')} dBm, usually {rec.get('reference_dbm')} dBm",
                                  end=None, low_since=rec.get("since", rec["ts"]))
        elif ev == "rssi_recovered":
            addr = _addr(rec) or ""
            ep = open_link.pop(addr, None)
            if ep is not None:
                ep["end"] = rec["ts"]
                ep["events"].append(rec)
                ep["title"] += f" for {fmt_duration(rec['ts'] - ep['low_since'])}"
            else:
                new("link", rec, f"{_label(rec)} signal recovered",
                    f"{rec.get('rssi_dbm')} dBm, usually {rec.get('reference_dbm')} dBm")
        elif ev == "retransmission_elevation":
            key = (rec.get("top_sender") or "", rec.get("top_target") or "")
            ep = retrans.get(key)
            if ep is None or rec["ts"] - ep["end"] > GAP_S["retransmissions"]:
                who = f"{key[0]} -> {key[1]}" if key[0] else "mesh-wide"
                ep = retrans[key] = new("retransmissions", rec, f"retransmissions: {who}",
                                        rec.get("note", ""), max_rate=rec.get("rate", 0))
            else:
                bump(ep, rec)
                ep["max_rate"] = max(ep["max_rate"], rec.get("rate", 0))
        elif ev == "possible_foreign_pan":
            key = (rec.get("pan"), rec.get("src"))
            ep = foreign.get(key)
            if ep is None or rec["ts"] - ep["end"] > GAP_S["foreign_pan"]:
                foreign[key] = new("foreign_pan", rec, f"foreign PAN {rec.get('pan')} from {rec.get('src')}",
                                   f"ours is {rec.get('dominant_pan')}")
            else:
                bump(ep, rec)
        elif ev == "mle_rejoin_attempt":
            key = _label(rec)
            ep = rejoin.get(key)
            if ep is None or rec["ts"] - ep["end"] > GAP_S["rejoin"]:
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
        elif ev in ("incident_frozen", "incident_freeze_failed"):
            new("frozen", rec, "incident frozen" if ev == "incident_frozen" else "incident freeze failed",
                rec.get("note", ""))
        elif ev == "daily_summary":
            new("summary", rec, "daily summary", rec.get("note", ""))
        elif ev == "alert_test":
            new("test", rec, "alert test", rec.get("note", ""))
        else:
            new(ev or "event", rec, ev, rec.get("note", ""))

    for ep in episodes:
        if ep["kind"] == "quiet" and ep["end"] is None:
            ep["title"] = f"{ep['name'] or ep['addr']} quiet for {fmt_duration(now - ep['silent_since'])} (still quiet)"
        elif ep["kind"] == "link" and ep["end"] is None:
            ep["title"] += f" for {fmt_duration(now - ep['low_since'])} (still down)"
        elif ep["kind"] == "starved" and ep["end"] is None:
            ep["title"] += f" for {fmt_duration(now - ep['starved_since'])} (still unanswered)"
    return sorted(episodes, key=lambda e: e["start"])


def fmt_episode(ep: dict, stamp_fmt: str = "%m-%d %H:%M") -> str:
    """One terminal line per episode, the way the CLI prints them."""
    stamp = time.strftime(stamp_fmt, time.localtime(ep["start"]))
    span = "" if ep["count"] == 1 else \
        f" x{ep['count']} over {fmt_duration((ep['end'] or ep['start']) - ep['start'])}"
    return f"{stamp} [{ep['severity']:8s}] {ep['title']}{span}  {ep['detail']}"


def day_episodes(events_dir: Path, day: str, now: Optional[float] = None) -> list[dict]:
    """Episodes that touch a day. Grouping runs over the whole history, so a
    silence that began days ago and is still open appears on every day it
    covers with its real duration, and closes everywhere once the device
    returns. The day files are small and cached (events.read_day)."""
    start, end = day_bounds(day)
    out = []
    for ep in group_episodes(read_all(events_dir), now):
        ep_end = ep["end"] if ep["end"] is not None else (now or time.time())
        if ep_end >= start and ep["start"] < end:
            ep["carried_over"] = ep["start"] < start   # began on an earlier day
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
                now: Optional[float] = None, leader_router: Optional[int] = None) -> list[dict]:
    """One dict per tracked address. The live role comes from the RLOC16 the
    recorder last saw the device use: router or child, which router it is
    or hangs off, and whether it holds the partition's leader id."""
    now = now or time.time()
    # Who holds each router address, newest confirmation winning.
    holder: dict[int, str] = {}
    for addr, row in sorted(seen.table.items(), key=lambda kv: kv[1].get("rloc16_ts") or 0):
        r = rloc16_role(row.get("rloc16"))
        if r and r["role"] == "router":
            holder[r["router_id"]] = addr
    rows = []
    for addr, row in seen.table.items():
        rssi = row.get("rssi")
        live = rloc16_role(row.get("rloc16")) or {}
        parent_addr = holder.get(live["router_id"]) if live.get("role") == "child" else None
        br = names.border_routers.get(addr)
        rows.append({
            "border_router": br["hostname"] if br else None,
            "border_router_label": (f'{br.get("instance") or br["hostname"]} ({br.get("vendor") or "?"} '
                                    f'{br.get("model") or ""})'.strip() if br else None),
            "rotated_to": row.get("rotated_to"),
            "rloc16": row.get("rloc16"),
            "rloc16_ts": row.get("rloc16_ts"),
            "role": live.get("role"),
            "router_id": live.get("router_id"),
            "leader": bool(live) and live["role"] == "router" and leader_router is not None
                      and live["router_id"] == leader_router,
            "parent_addr": parent_addr,
            "parent": (names.name(parent_addr) or parent_addr) if parent_addr else None,
            "addr": addr,
            "name": names.name(addr),
            "frames": row.get("frames", 0),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "silent_for_s": round(now - row.get("last_seen", now)),
            "rssi_dbm": rssi,
            "reception": reception(rssi, min_rssi_dbm),
            "pan": row.get("pan"),
            "polls": row.get("types", {}).get("3", 0),
            "quiet": bool(row.get("quiet_reported")),
            "degraded": bool(row.get("rssi_degraded")),
        })
    rows.sort(key=lambda r: ((r["name"] is None), (r["name"] or r["addr"]).lower()))
    return rows


DEVICE_FILTERS = {
    "unknown": ("not in devices.json", lambda r, dom: r["name"] is None),
    "quiet": ("quiet now", lambda r, dom: r["quiet"] and not r["rotated_to"]),
    "marginal": ("heard marginally", lambda r, dom: r["reception"] == "marginal"),
    "down": ("signal down", lambda r, dom: r["degraded"]),
    "foreign": ("on another PAN", lambda r, dom: r["pan"] is not None and dom is not None and r["pan"] != dom),
    "routers": ("routers", lambda r, dom: r["role"] == "router"),
    "children": ("children", lambda r, dom: r["role"] == "child"),
}
DEVICE_SORTS = {
    "name": ("name", lambda r: ((r["name"] is None), (r["name"] or r["addr"]).lower())),
    "last": ("longest unheard", lambda r: -r["silent_for_s"]),
    "rssi": ("weakest", lambda r: (r["rssi_dbm"] is None, r["rssi_dbm"] or 0)),
    "frames": ("busiest", lambda r: -r["frames"]),
}


def select_devices(rows: list[dict], dominant: Optional[int], only: str = "", sort: str = "name") -> list[dict]:
    """The devices page's subset and order. An unknown filter or sort name
    is ignored rather than an error: the page still renders."""
    f = DEVICE_FILTERS.get(only)
    if f:
        rows = [r for r in rows if f[1](r, dominant)]
    s = DEVICE_SORTS.get(sort) or DEVICE_SORTS["name"]
    return sorted(rows, key=s[1])


def dominant_pan(seen: LastSeen, configured: Optional[int] = None) -> Optional[int]:
    """This network's PAN: [network] pan_id when set, else the one the
    tracked addresses send most frames on."""
    if configured is not None:
        return configured
    weight: dict = {}
    for row in seen.table.values():
        if row.get("pan") is not None:
            weight[row["pan"]] = weight.get(row["pan"], 0) + row.get("frames", 0)
    return max(weight, key=weight.get) if weight else None


def now_card(seen: LastSeen, names: DeviceNames, events_dir: Path, min_rssi_dbm: float,
             day: str, now: Optional[float] = None, pan_id: Optional[int] = None) -> dict:
    """What matters at this moment, for the top of today's page: devices
    quiet right now (as the recorder announced them), devices whose signal
    is down, unknown addresses still to name, and the day's daily_summary
    record if one has gone out. Devices on a foreign PAN are left out."""
    now = now or time.time()
    dominant = dominant_pan(seen, pan_id)
    quiet, degraded, unknown = [], [], []
    for addr, row in seen.table.items():
        pan = row.get("pan")
        if dominant is not None and pan is not None and pan != dominant:
            continue
        item = {"addr": addr, "name": names.name(addr), "last_seen": row.get("last_seen"),
                "silent_for_s": round(now - row.get("last_seen", now)),
                "rssi_dbm": row.get("rssi"), "reception": reception(row.get("rssi"), min_rssi_dbm)}
        if row.get("quiet_reported"):
            quiet.append(item)
        if row.get("rssi_degraded"):
            degraded.append({**item, "reference_dbm": row.get("rssi_ref")})
        if item["name"] is None:
            unknown.append(item)
    quiet.sort(key=lambda i: -i["silent_for_s"])
    unknown.sort(key=lambda i: i["silent_for_s"])
    summary = None
    for rec in read_day(events_dir, day):
        if rec.get("event") == "daily_summary":
            summary = rec
    return {"quiet": quiet, "degraded": degraded, "unknown": unknown, "summary": summary}


def live_address(addrs: list[str], table: dict[str, dict]) -> str:
    """Which of a device's addresses to describe it by: the one heard most
    recently. A rotating device reached by name lists its addresses in
    inventory order (oldest first), and reached by an old address puts
    that one first; either way the header must not describe a retired
    address while the cards below show the live one."""
    return max(addrs, key=lambda a: ((table.get(a) or {}).get("last_seen") or 0, -addrs.index(a)))


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


def devices_history(events_dir: Path, addrs: list[str], now: Optional[float] = None) -> list[dict]:
    """device_history over every address of one device (a rotating device
    is several addresses with one story), newest first."""
    episodes = []
    for addr in dict.fromkeys(a.lower() for a in addrs):
        episodes.extend(device_history(events_dir, addr, now))
    return sorted(episodes, key=lambda e: e["start"], reverse=True)


def _dir_size(path: Path) -> int:
    try:
        return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())
    except OSError:
        return 0


def _span(pcaps: list[str]) -> Optional[tuple[str, str]]:
    """First and last hour covered by ring-named pcaps, as YYYYMMDD-HH."""
    hours = sorted(n[12:23] for n in pcaps if n.startswith("threadwatch-") and n.endswith(".pcap") and len(n) == 28)
    return (hours[0], hours[-1]) if hours else None


DEFAULT_BYTES_PER_HOUR = 30 * 1024 * 1024   # a busy mesh; used until the ring has measured itself


def storage(cfg) -> dict:
    """What the recorder keeps on disk and how much room is left there.
    ring_bound_bytes is the most the ring can grow to (keep_files hours at
    the measured rate, and no more than keep_gb when set); ring_needs_bytes
    is how much of that it has not used yet. Both consumers (doctor, the
    status page) judge free space against these, so they agree."""
    import shutil
    ring = sorted(p.name for p in cfg.ring_dir.glob("threadwatch-*.pcap")) if cfg.ring_dir.exists() else []
    out = {"ring_files": len(ring), "ring_span": _span(ring), "ring_bytes": _dir_size(cfg.ring_dir),
           "keep_files": cfg.keep_files,
           "incidents_bytes": _dir_size(cfg.incidents_dir) if cfg.incidents_dir.exists() else 0,
           "events_bytes": _dir_size(cfg.events_dir) if cfg.events_dir.exists() else 0}
    try:
        usage = shutil.disk_usage(cfg.data_dir if cfg.data_dir.exists() else cfg.data_dir.parent)
        out.update({"disk_total": usage.total, "disk_free": usage.free})
    except OSError:
        out.update({"disk_total": None, "disk_free": None})
    if ring and len(ring) > 1:
        out["bytes_per_hour"] = out["ring_bytes"] // len(ring)
    bound = cfg.keep_files * (out.get("bytes_per_hour") or DEFAULT_BYTES_PER_HOUR)
    if cfg.keep_bytes:
        bound = min(bound, cfg.keep_bytes)
    out["keep_bytes"] = cfg.keep_bytes
    out["ring_bound_bytes"] = bound
    out["ring_needs_bytes"] = max(0, bound - out["ring_bytes"])
    return out


def incidents(incidents_dir: Path) -> list[dict]:
    """Frozen incidents (threadwatch freeze), newest first: label, when
    frozen, the hours their pcaps cover, size, whether events came along."""
    if not incidents_dir.exists():
        return []
    out = []
    for d in incidents_dir.iterdir():
        if not d.is_dir() or d.name.endswith(".partial"):      # freeze.PARTIAL_SUFFIX: a copy still running, or cut short
            continue
        stamp, _, label = d.name.partition("_")
        try:
            frozen = time.mktime(time.strptime(stamp, "%Y%m%dT%H%M%S"))
        except ValueError:
            frozen = d.stat().st_mtime
        pcaps = sorted(p.name for p in d.glob("*.pcap"))
        out.append({"name": d.name, "label": label or d.name, "frozen": frozen,
                    "pcaps": len(pcaps), "span": _span(pcaps), "bytes": _dir_size(d),
                    "events": (d / "events").is_dir(), "day": day_of(frozen)})
    out.sort(key=lambda i: -i["frozen"])
    return out


def fmt_bytes(n: Optional[int]) -> str:
    if n is None:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def capture_for_day(ring_dir: Path, incidents_dir: Path, day: str) -> dict:
    """Whether packets for a day still exist: ring files (one week) and any
    frozen incidents whose pcaps cover it. An incident belongs to the days
    its packets span, not the moment it was frozen: the storm logged on
    one day is usually frozen after midnight, and the day page for the
    storm is where the packets are wanted. One with no pcaps is filed
    under its freeze day."""
    stamp = day.replace("-", "")
    ring = sorted(p.name for p in ring_dir.glob(f"threadwatch-{stamp}-*.pcap")) if ring_dir.exists() else []
    kept = []
    for inc in incidents(incidents_dir):
        span = inc["span"]
        if (span[0][:8] <= stamp <= span[1][:8]) if span else inc["day"] == day:
            kept.append(inc["name"])
    return {"ring_files": ring, "incidents": sorted(kept)}


def today() -> str:
    return day_of(time.time())


def days_available(events_dir: Path) -> list[str]:
    return list_days(events_dir)
