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

import json
import threading
import time
from pathlib import Path
from typing import Optional

from .events import day_bounds, day_of, iter_days, list_days, next_day, prev_day, read_day
from .freeze import STAGING_DIR
from .names import DeviceNames, LastSeen, reception, rloc16_role

SEVERITY_RANK = {"info": 0, "notice": 1, "warning": 2, "critical": 3}

# A recurring thing (the same bad link, the same neighbour's PAN, the same
# device rejoining) is one row while its records keep coming, and a new row
# after this much silence; without a limit a device that rejoins once a day
# would be a single row for the whole history.
GAP_S = {"retransmissions": 3600.0, "rejoin": 3600.0, "foreign_pan": 86400.0, "recorder": 1800.0}


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
    recorder: Optional[dict] = None

    def new(kind, rec, title, detail="", **extra):
        ep = {"kind": kind, "start": rec["ts"], "end": rec["ts"], "severity": rec["severity"],
              "count": 1, "title": title, "detail": detail, "addr": _addr(rec),
              "name": rec.get("name"), "events": [rec]}
        ep.update(extra)
        episodes.append(ep)
        return ep

    def bump(ep, rec):
        """Another record of an episode. Its end moves to the record for
        the kinds whose end is their last occurrence; an episode that is
        open (end None: a starvation or link drop not yet recovered) stays
        open, since a repeat, or the page confirming it, is not the
        recovery that closes it."""
        ep["count"] += 1
        if ep["end"] is not None:
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
            # the silence itself began at the device's last frame, which
            # the record carries (older records: silent_for_s before it).
            since = rec.get("last_seen")
            if not isinstance(since, (int, float)):
                since = rec["ts"] - float(rec.get("silent_for_s") or 0)
            ep = new("quiet", rec, f"{_label(rec)} went quiet",
                     "sniffer hears it at the edge of range; probably fading, not failure"
                     if marginal else "no frames heard", end=None, silent_since=float(since))
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
            if rec.get("confirmed") and (ep is None or rec["ts"] - ep["end"] > GAP_S["retransmissions"]):
                # The page for an elevation logged minutes ago: the busiest
                # pair may have changed since, but it is the same elevation,
                # so it joins the newest open row rather than starting one.
                recent = [e for e in retrans.values() if rec["ts"] - e["end"] <= GAP_S["retransmissions"]]
                if recent:
                    ep = max(recent, key=lambda e: e["end"])
                    key = next(k for k, v in retrans.items() if v is ep)
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
        elif ev == "recorder_started":
            # Starts minutes apart are the watchdog's restart loop (a host
            # asleep, a dongle gone): one row, counting them.
            if recorder is None or rec["ts"] - recorder["end"] > GAP_S["recorder"]:
                gap = rec.get("gap_s")
                title = ("recorder started (first run)" if rec.get("cause") == "first_start" else
                         "recorder started" if not isinstance(gap, (int, float)) else
                         f"recorder restarted ({fmt_duration(gap)} without frames)")
                recorder = new("recorder", rec, title, rec.get("note", ""))
            else:
                bump(recorder, rec)
                recorder["title"] = f"recorder restarted {recorder['count']} times"
                recorder["detail"] = rec.get("note", "")      # the latest: the longest gap
        elif ev == "clock_step":
            step = rec.get("step_s") or 0
            new("clock", rec, f"host clock jumped {'forward' if step > 0 else 'back'} {fmt_duration(abs(step))}",
                rec.get("note", ""))
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


# How far either side of a day the day page reads, in days. An episode
# that began before the window (a device quiet for over a month) still
# shows, from its first record inside the window; one that closes after
# it reads as still open. Reading the whole history instead made every
# day page cost the whole log, which nothing bounded.
EPISODE_WINDOW_DAYS = 31


def day_episodes(events_dir: Path, day: str, now: Optional[float] = None) -> list[dict]:
    """Episodes that touch a day. Grouping runs over the days around it
    (EPISODE_WINDOW_DAYS either side), so a silence that began days ago
    and is still open appears on every day it covers with its real
    duration, and closes everywhere once the device returns. The day
    files are small and cached (events.read_day)."""
    start, end = day_bounds(day)
    first = day_of(start - EPISODE_WINDOW_DAYS * 86400)
    last = day_of(end + EPISODE_WINDOW_DAYS * 86400)
    records = [r for _day, recs in iter_days(events_dir, first, last) for r in recs]
    out = []
    for ep in group_episodes(records, now):
        ep_end = ep["end"] if ep["end"] is not None else (now or time.time())
        if ep_end >= start and ep["start"] < end:
            ep["carried_over"] = ep["start"] < start   # began on an earlier day
            out.append(ep)
    return out


# ------------------------------------------------------------ coverage
#
# Whether the recorder was listening: the answer to "was the device silent,
# or was nothing there to hear it?" that a day page must give beside each
# silence. Built from the log alone: every start says when its run began,
# when the last frame before it was heard, and (from the note the run
# before left) when that run ended; a forward clock step says how much
# wall-clock time was never lived through; the configured PAN going silent
# says frames were heard but none of ours.

# A run that stopped this soon after its last frame was listening to a
# quiet channel for the seconds a stop takes: not worth a segment.
COVERAGE_MIN_S = 60.0
# How far past a day the log is read for a start whose gap reaches back
# into it; an outage longer than this shows on its first days only.
COVERAGE_LOOKAHEAD_DAYS = EPISODE_WINDOW_DAYS
# A status file this old is a daemon that is not running (it writes every
# 30 s while alive); the header and the status page use the same figure.
STATUS_DEAD_S = 180.0
STATUS_QUIET_S = 120.0

_BLIND_NOTES = {
    "stopped": "the recorder was stopped",
    "stalled": "the recorder was not running: it left after 3 min without frames and was restarted",
    "crashed": "the recorder crashed and was restarted",
    "sniffer_died": "the recorder lost its sniffer and was restarted",
    "stream_ended": "the recorder lost its capture stream (dongle unplugged?) and was restarted",
    "unknown": "the recorder was not running, and left no note of how it ended (power cut, or killed)",
    "clock_step": "the host clock jumped forward over this: no time to hear anything in",
    "down": "the recorder is not running now",
}
_UNCERTAIN_NOTES = {
    "no_frames": "the recorder was running but heard nothing: a quiet channel, or a dongle that had stopped hearing",
    "pan_silent": "frames were heard, but none on the configured PAN",
}


def coverage_records(events_dir: Path, day: str) -> list[dict]:
    """The records coverage for ``day`` is built from: the day's own and
    the day before (a clock step or a silent PAN window can start there),
    then later days until a start is found whose last frame is after the
    day, since no start after that one can reach back into it. A recorder
    that ran a month without a restart is a month of small cached files."""
    start, end = day_bounds(day)
    first = prev_day(day)
    last = day
    for _ in range(COVERAGE_LOOKAHEAD_DAYS):
        last = next_day(last)
    out = []
    for d, recs in iter_days(events_dir, first, last):
        wanted = [r for r in recs if r.get("event") in ("recorder_started", "clock_step", "configured_pan_silent")]
        out.extend(wanted)
        if d > day and any(r.get("event") == "recorder_started" and
                           (not isinstance(r.get("last_frame_ts"), (int, float)) or r["last_frame_ts"] >= end)
                           for r in wanted):
            break
    return out


def coverage_since(events_dir: Path) -> Optional[float]:
    """When the first start on record is: before it the log cannot say
    whether the recorder was listening (the starts were not logged), and
    a day page from then says so rather than showing a clean day."""
    for _day, recs in iter_days(events_dir):
        for r in recs:
            if r.get("event") == "recorder_started" and isinstance(r.get("ts"), (int, float)):
                return float(r["ts"])
    return None


def _merge(spans: list[tuple]) -> list[dict]:
    """Overlapping or touching spans of one state become one segment,
    keeping the cause and note of the longest piece and counting the
    pieces (a restart loop is one segment of many starts). ``credited``
    is true if any piece was: see coverage."""
    out: list[dict] = []
    for a, b, cause, note, credited in sorted(spans):
        if b <= a:
            continue
        if out and a <= out[-1]["end"]:
            cur = out[-1]
            if b - a > cur["longest"]:
                cur.update(cause=cause, note=note, longest=b - a)
            cur["end"] = max(cur["end"], b)
            cur["count"] += 1
            cur["credited"] = cur["credited"] or credited
            continue
        out.append({"start": a, "end": b, "cause": cause, "note": note, "count": 1,
                    "longest": b - a, "credited": credited})
    return out


def _subtract(segments: list[dict], holes: list[dict]) -> list[dict]:
    """The parts of ``segments`` no hole covers, in order."""
    out = []
    for seg in segments:
        pieces = [(seg["start"], seg["end"])]
        for h in holes:
            pieces = [p for a, b in pieces
                      for p in ((a, min(b, h["start"])), (max(a, h["end"]), b)) if p[1] > p[0]]
        out.extend({**seg, "start": a, "end": b} for a, b in pieces)
    return out


def coverage(events_dir: Path, day: str, now: Optional[float] = None,
             status: Optional[dict] = None) -> list[dict]:
    """The parts of ``day`` the recorder was not listening (state "blind":
    not running, or a forward clock step) or may not have been
    ("uncertain": running but hearing nothing, or hearing other PANs
    only), clipped to the day and to now; whatever is left is coverage.
    ``status`` (the daemon's status.json) adds the live tail on today's
    page: a recorder that is down or hearing nothing right now has logged
    nothing about it yet. Each segment: start, end, state, cause, note,
    count (starts or steps merged into it). Sorted by start."""
    now = now or time.time()
    start, end = day_bounds(day)
    blind: list[tuple] = []
    uncertain: list[tuple] = []
    for r in coverage_records(events_dir, day):
        ev, ts = r.get("event"), r.get("ts")
        if not isinstance(ts, (int, float)):
            continue
        if ev == "recorder_started":
            last, stopped = r.get("last_frame_ts"), r.get("stopped_ts")
            if not isinstance(last, (int, float)):
                continue                      # the first start ever: nothing before it to cover
            cause = r.get("cause") if r.get("cause") in _BLIND_NOTES else "unknown"
            if isinstance(stopped, (int, float)) and last <= stopped <= ts:
                # The last run was up and hearing nothing from its last
                # frame until it stopped, then nothing was running until
                # this start. The two read differently on the page, but
                # the pipeline credited the whole span to itself, so the
                # whole span is credited here too.
                if stopped - last >= COVERAGE_MIN_S:
                    uncertain.append((last, stopped, "no_frames", _UNCERTAIN_NOTES["no_frames"], True))
                blind.append((stopped, ts, cause, _BLIND_NOTES[cause], True))
            else:
                blind.append((last, ts, cause, _BLIND_NOTES[cause], True))
        elif ev == "clock_step":
            step = r.get("step_s") or 0
            if step > 0:
                blind.append((ts - step, ts, "clock_step", _BLIND_NOTES["clock_step"], True))
        elif ev == "configured_pan_silent":
            # Frames were heard, just not ours: nothing the pipeline
            # subtracts from any device's silence.
            window = r.get("window_s") or 1800
            uncertain.append((ts - window, ts, "pan_silent", _UNCERTAIN_NOTES["pan_silent"], False))
    if status and day == day_of(now):
        updated = status.get("updated")
        if isinstance(updated, (int, float)):
            # The live tail: nothing is on record about it yet, so
            # nothing has been credited to any device's silence either.
            if now - updated > STATUS_DEAD_S:
                blind.append((updated, now, "down", _BLIND_NOTES["down"], False))
            elif (status.get("last_frame_age_s") or 0) > STATUS_QUIET_S:
                uncertain.append((now - status["last_frame_age_s"], now, "no_frames",
                                  _UNCERTAIN_NOTES["no_frames"], False))
    blind_segs = _merge(blind)
    segs = [{**seg, "state": "blind"} for seg in blind_segs]
    segs += [{**seg, "state": "uncertain"} for seg in _subtract(_merge(uncertain), blind_segs)]
    out = []
    for seg in segs:
        a, b = max(seg["start"], start), min(seg["end"], end, now)
        if b > a:
            out.append({"start": a, "end": b, "state": seg["state"], "cause": seg["cause"],
                        "note": seg["note"], "count": seg["count"], "credited": seg["credited"]})
    return sorted(out, key=lambda x: (x["start"], x["state"]))


def episode_blind_s(ep: dict, segments: list[dict], now: Optional[float] = None) -> float:
    """How much of an episode's span the recorder was not listening for:
    the figure beside a silence that says how much of it nobody was there
    to hear. A quiet spell spans from the device's last frame; anything
    else from its first record.

    The credited segments, not the blind ones. They are the same except
    at a restart, where the pipeline credits the whole span from the last
    frame any run heard - including the tail during which the last run
    was up and hearing nothing, drawn as uncertain here. Counting the
    blind ones alone made the day page and the event disagree about the
    same outage by exactly that tail (90 min against 80)."""
    a = ep.get("silent_since") if isinstance(ep.get("silent_since"), (int, float)) else ep["start"]
    b = ep["end"] if ep["end"] is not None else (now or time.time())
    return sum(max(0.0, min(b, s["end"]) - max(a, s["start"])) for s in segments if s["credited"])


# Counts per day file, keyed by (mtime, size) as events.read_day is. The
# index is every day on disk - a year by default - which is far more files
# than the parsed-record cache can hold, and a sequential scan evicts
# exactly what the next scan wants, so that cache never warmed. A row is
# four integers, so all of retention fits here several times over and only
# today's file is ever re-counted.
DAY_COUNTS_MAX = 2048
_day_counts: dict[Path, tuple[tuple, dict]] = {}
_day_counts_lock = threading.Lock()


def day_index(events_dir: Path) -> list[dict]:
    """One row per day with an event file: counts by severity, newest first."""
    rows = []
    for day in list_days(events_dir):
        path = events_dir / f"{day}.jsonl"
        try:
            st = path.stat()
        except OSError:
            continue
        stamp = (st.st_mtime_ns, st.st_size)
        with _day_counts_lock:
            hit = _day_counts.get(path)
        if hit is not None and hit[0] == stamp:
            rows.append(dict(hit[1]))
            continue
        counts = {"info": 0, "notice": 0, "warning": 0, "critical": 0}
        recs = read_day(events_dir, day)
        for r in recs:
            counts[r.get("severity", "info")] = counts.get(r.get("severity", "info"), 0) + 1
        row = {"day": day, "total": len(recs), **counts}
        with _day_counts_lock:
            if len(_day_counts) >= DAY_COUNTS_MAX:
                _day_counts.pop(next(iter(_day_counts)), None)
            _day_counts[path] = (stamp, row)
        rows.append(dict(row))
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
            # A row from before polls were counted by name carries every
            # MAC command under type 3, beacon requests and all.
            "polls": row.get("polls", row.get("types", {}).get("3", 0)),
            "quiet": bool(row.get("quiet_reported")),
            "degraded": bool(row.get("rssi_degraded")) and not row.get("rotated_to"),
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


def dominant_pan(seen: LastSeen, configured: Optional[int] = None,
                 state_dir: Optional[Path] = None) -> Optional[int]:
    """This network's PAN, as the recorder judges it: [network] pan_id
    when set, else the PAN the recorder adopted (status.json, written
    every 30 s), else the one the tracked addresses send most frames on.

    The recorder adopts a PAN only once it has DOMINANT_MIN_FRAMES and
    replaces it only with one holding twice as many, so two networks
    trading the lead do not swap whose silences count on every tick.
    Recomputed here from the table alone, the answer disagreed whenever
    a second PAN overtook the first without doubling it, and the pages
    denied a quiet the recorder had paged for (or showed as ours half a
    mesh it was not judging). The recorder's own answer is read first;
    the count stands in only with no status to read, with the same
    floor and no memory of which PAN came first."""
    if configured is not None:
        return configured
    if state_dir is not None:
        try:
            status = json.loads((state_dir / "status.json").read_text())
        except (OSError, ValueError):
            status = None
        if isinstance(status, dict) and "dominant_pan" in status:
            adopted = status["dominant_pan"]
            if adopted is None or (isinstance(adopted, int) and not isinstance(adopted, bool)):
                return adopted
    from .pipeline import Pipeline
    weight: dict = {}
    for row in seen.table.values():
        if row.get("pan") is not None:
            weight[row["pan"]] = weight.get(row["pan"], 0) + (row.get("frames") or 0)
    if not weight:
        return None
    leader = max(weight, key=weight.get)
    return leader if weight[leader] >= Pipeline.DOMINANT_MIN_FRAMES else None


def now_card(seen: LastSeen, names: DeviceNames, events_dir: Path, min_rssi_dbm: float,
             day: str, now: Optional[float] = None, pan_id: Optional[int] = None,
             state_dir: Optional[Path] = None) -> dict:
    """What matters at this moment, for the top of today's page: devices
    quiet right now (as the recorder announced them), devices whose signal
    is down, unknown addresses still to name, and the day's daily_summary
    record if one has gone out. Devices on a foreign PAN are left out."""
    now = now or time.time()
    dominant = dominant_pan(seen, pan_id, state_dir)
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
        if row.get("rssi_degraded") and not row.get("rotated_to"):
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


# How far back a device page reads. Retention is a year by default, and
# walking all of it on every request made the pages slower every month
# with no plateau: a day file is small, but 365 of them per request, on
# the Pi this runs on, is not. Days before this are still on disk and
# still on the day pages; the device page says where it stopped.
DEVICE_HISTORY_DAYS = 90


def devices_history(events_dir: Path, addrs: list[str], now: Optional[float] = None,
                    days: int = DEVICE_HISTORY_DAYS) -> list[dict]:
    """Every episode involving one device over the last ``days``, newest
    first. A rotating device is several addresses with one story, so they
    are read in one pass over the day files rather than one pass each,
    and grouped per address (an episode belongs to the address it names).
    Records from EPISODE_WINDOW_DAYS before the window are read too, so an
    episode that began earlier and is still open keeps its real start."""
    now = now or time.time()
    wanted = list(dict.fromkeys(a.lower() for a in addrs))
    cutoff = now - days * 86400
    first = day_of(cutoff - EPISODE_WINDOW_DAYS * 86400)
    per: dict[str, list[dict]] = {a: [] for a in wanted}
    for _day, recs in iter_days(events_dir, first):
        for r in recs:
            bucket = per.get((_addr(r) or "").lower())
            if bucket is not None:
                bucket.append(r)
    episodes = []
    for addr in wanted:
        episodes.extend(ep for ep in group_episodes(per[addr], now)
                        if (ep["end"] if ep["end"] is not None else now) >= cutoff)
    return sorted(episodes, key=lambda e: e["start"], reverse=True)


def device_history(events_dir: Path, addr: str, now: Optional[float] = None,
                   days: int = DEVICE_HISTORY_DAYS) -> list[dict]:
    """devices_history for a single address."""
    return devices_history(events_dir, [addr], now, days)


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
    per_hour = out.get("bytes_per_hour") or DEFAULT_BYTES_PER_HOUR
    bound = cfg.keep_files * per_hour
    if cfg.keep_bytes:
        # The writer prunes closed files to the cap as the hour grows, but
        # never the file being written: the ring can stand one hour over.
        bound = min(bound, cfg.keep_bytes + per_hour)
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
        if not d.is_dir() or d.name == STAGING_DIR:      # a copy still running, or cut short, is not an incident
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
