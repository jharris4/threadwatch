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
import math
import threading
import time
from pathlib import Path

from .events import day_bounds, day_of, iter_days, list_days, next_day, prev_day, read_day
from .keyfacts import summary as key_summary
from .names import (
    DeviceNames,
    LastSeen,
    VisitorNames,
    newest_generation,
    parent_address,
    reception,
    rloc16_role,
    router_holders,
)
from .snapshot import STAGING_DIR

SEVERITY_RANK = {"info": 0, "notice": 1, "warning": 2, "critical": 3}

# A recurring thing (the same bad link, the same neighbour's PAN, the same
# device rejoining) is one row while its records keep coming, and a new row
# after this much silence; without a limit a device that rejoins once a day
# would be a single row for the whole history.
GAP_S = {"retransmissions": 3600.0, "rejoin": 3600.0, "foreign_pan": 86400.0, "recorder": 1800.0}


def _label(rec: dict) -> str:
    return rec.get("name") or rec.get("addr") or rec.get("src") or ""


def _addr(rec: dict) -> str | None:
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


def group_episodes(records: list[dict], now: float | None = None) -> list[dict]:
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
    open_leader: dict[str, dict] = {}
    open_srp: dict[str, dict] = {}
    open_starved: dict[str, dict] = {}
    open_unserved: dict[str, dict] = {}
    open_keylag: dict[str, dict] = {}
    open_ha: dict[str, dict] = {}
    open_visit: dict[str, dict] = {}
    first_seen: dict | None = None
    join_scan: dict | None = None
    recorder: dict | None = None

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
        elif ev == "visitor_returned":
            # Back for another visit: the row opens now and closes when the
            # visit is filed, half an hour after it leaves.
            addr = _addr(rec) or ""
            open_visit[addr] = new("visit", rec, f"{_label(rec)} visiting{_nth(rec)}", rec.get("note", ""),
                                   end=None)
        elif ev == "visitor_left":
            # Filed when its silence crossed the window; the row spans the
            # visit itself. A quiet announced for the address by a run from
            # before visits were filed was this same leaving: it folds in,
            # so no still-quiet row stands beside the visit. Anything else
            # left open for the address (its parent stopped answering its
            # polls as it went) ends when the visit does, since the visitor
            # is not coming back to close it.
            addr = _addr(rec) or ""
            first, last = rec.get("first_seen"), rec.get("last_seen")
            start = float(first) if isinstance(first, (int, float)) else rec["ts"]
            end = float(last) if isinstance(last, (int, float)) else rec["ts"]
            heard = rec.get("heard_for_s") if isinstance(rec.get("heard_for_s"), (int, float)) else end - start
            title = f"{_label(rec)} visited for {fmt_duration(heard)}{_nth(rec)}"
            ep = open_visit.pop(addr, None)
            if ep is not None:
                ep.update(start=min(ep["start"], start), end=end, title=title, detail=rec.get("note", ""))
                ep["events"].append(rec)
            else:
                ep = new("visit", rec, title, rec.get("note", ""), start=start, end=end)
            quiet = open_quiet.pop(addr, None)
            if quiet is not None:
                episodes.remove(quiet)
                ep["events"] = quiet["events"] + ep["events"]
            for table, since_key in ((open_starved, "starved_since"), (open_unserved, "unserved_since"),
                                     (open_link, "low_since"),
                                     (open_keylag, "lag_since")):
                left = table.pop(addr, None)
                if left is not None:
                    left["end"] = end
                    left["events"].append(rec)
                    left["title"] += f" for {fmt_duration(end - left[since_key])}, then it left"
        elif ev == "poll_starvation":
            addr = _addr(rec) or ""
            ep = open_starved.get(addr)
            if ep is not None:
                bump(ep, rec)
                continue
            open_starved[addr] = new("starved", rec, f"{_label(rec)} polls unanswered",
                                     f"{rec.get('unanswered_polls')} polls, {rec.get('acked_polls')} answered before",
                                     end=None, starved_since=rec.get("since", rec["ts"]))
        elif ev == "poll_unserved":
            addr = _addr(rec) or ""
            ep = open_unserved.get(addr)
            if ep is not None:
                bump(ep, rec)
                continue
            open_unserved[addr] = new("unserved", rec, f"{_label(rec)} polls acknowledged, nothing delivered",
                                      f"{rec.get('unserved_polls')} polls, {rec.get('served_polls')} served before",
                                      end=None, unserved_since=rec.get("since", rec["ts"]))
        elif ev == "poll_served":
            addr = _addr(rec) or ""
            ep = open_unserved.pop(addr, None)
            if ep is not None:
                ep["end"] = rec["ts"]
                ep["events"].append(rec)
                ep["title"] += f" for {fmt_duration(rec['ts'] - ep['unserved_since'])}"
            else:
                new("unserved", rec, f"{_label(rec)} polls served again", rec.get("note", ""))
        elif ev == "poll_answered":
            addr = _addr(rec) or ""
            ep = open_starved.pop(addr, None)
            if ep is not None:
                ep["end"] = rec["ts"]
                ep["events"].append(rec)
                ep["title"] += f" for {fmt_duration(rec['ts'] - ep['starved_since'])}"
            else:
                new("starved", rec, f"{_label(rec)} polls answered again", rec.get("note", ""))
        elif ev == "key_lag":
            addr = _addr(rec) or ""
            ep = open_keylag.get(addr)
            if ep is not None:
                bump(ep, rec)
                continue
            against = rec.get("parent") or ("the mesh" if rec.get("role") == "router" else "its parent")
            reference = rec.get("mesh_generation") if rec.get("role") == "router" else rec.get("parent_generation")
            open_keylag[addr] = new("key_lag", rec,
                                    f"{_label(rec)} {rec.get('lag')} key generations behind {against}",
                                    f"on generation {rec.get('generation')}, {against} on {reference}: cut off "
                                    "while its polls are still acknowledged",
                                    end=None, lag_since=rec.get("since", rec["ts"]))
        elif ev == "key_lag_cleared":
            addr = _addr(rec) or ""
            ep = open_keylag.pop(addr, None)
            if ep is not None:
                ep["end"] = rec["ts"]
                ep["events"].append(rec)
                ep["title"] += f" for {fmt_duration(rec['ts'] - ep['lag_since'])}"
                ep["detail"] = rec.get("note", "")
            else:
                new("key_lag", rec, f"{_label(rec)} key lag cleared", rec.get("note", ""))
        elif ev == "ha_unavailable":
            key = rec.get("ha_device_id") or _addr(rec) or ""
            ep = open_ha.get(key)
            if ep is not None:
                bump(ep, rec)
                continue
            cause = rec.get("cause") or "?"
            open_ha[key] = new("ha_unavailable", rec, f"{_label(rec)} unavailable in Home Assistant",
                               f"cause: {cause}" + (f" ({rec.get('burst_id')})" if rec.get("burst_id") else ""),
                               end=None, down_since=rec.get("since", rec["ts"]))
        elif ev == "ha_available":
            key = rec.get("ha_device_id") or _addr(rec) or ""
            ep = open_ha.pop(key, None)
            if ep is not None:
                ep["end"] = rec["ts"]
                ep["events"].append(rec)
                ep["title"] += f" for {fmt_duration(rec['ts'] - ep['down_since'])}"
            else:
                new("ha_unavailable", rec, f"{_label(rec)} available in Home Assistant again", rec.get("note", ""))
        elif ev == "ha_unavailable_burst":
            devs = rec.get("devices") or []
            new("ha_burst", rec, f"{rec.get('count') or len(devs)} devices unavailable in Home Assistant together",
                ", ".join(f"{d.get('name') or d.get('addr')} ({d.get('cause')})" for d in devs[:8])
                + (" ..." if len(devs) > 8 else ""))
        elif ev in ("ha_unreachable", "ha_reachable"):
            new("ha_link", rec, "Home Assistant unreachable" if ev == "ha_unreachable"
                else "Home Assistant reachable again", rec.get("note", ""))
        elif ev == "key_sequence_advanced":
            seq, prev = rec.get("sequence"), rec.get("previous")
            title = (f"key sequence {prev} -> {seq}" if prev is not None
                     else f"first key generation heard: {seq}")
            suspects = [s for s in (rec.get("suspects") or []) if isinstance(s, dict)]
            ahead = suspects[0] if suspects and suspects[0].get("evidence") == "ahead of its parent" else None
            new("key_rotation", rec, title, f"first from {_label(rec)} ({rec.get('frame')})"
                + (f", {fmt_duration(rec['since_previous_s'])} after the previous"
                   if isinstance(rec.get("since_previous_s"), (int, float)) else "")
                + (" (early)" if "early" in (rec.get("note") or "") else "")
                + (f"; ahead of last known parent sequence: {ahead.get('parent')} on {ahead.get('parent_generation')}"
                   if ahead else ""))
        elif ev == "key_lag_census":
            behind = rec.get("behind_parent_2plus") or []
            one = rec.get("behind_parent_1") or []
            routers = rec.get("routers_behind") or []
            suspects = [s for s in (rec.get("suspects") or []) if isinstance(s, dict)]
            new("key_census", rec, f"key generation census: generation {rec.get('sequence')}",
                (", ".join(p for p in (f"{len(one)} one behind" if one else "",
                                       "cut off: " + ", ".join(i.get("name") or i.get("addr") for i in behind)
                                       if behind else "",
                                       "routers behind: " + ", ".join(i.get("name") or i.get("addr") for i in routers)
                                       if routers else "") if p) or "everyone on the current generation")
                + ("; origin candidates: " + ", ".join(
                    (s.get("name") or s.get("addr") or "?")
                    + (" (ahead of last known parent sequence)" if s.get("evidence") == "ahead of its parent" else "")
                    for s in suspects) if suspects else ""))
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
        elif ev == "srp_refused":
            addr = _addr(rec) or ""
            open_srp[addr] = new("srp", rec, f"{_label(rec)} SRP registration refused",
                                 f"{rec.get('refusals')} refusals ({rec.get('rcode_name')}) over "
                                 f"{fmt_duration(rec.get('refused_for_s') or 0)}", end=None)
        elif ev == "srp_accepted":
            addr = _addr(rec) or ""
            ep = open_srp.pop(addr, None)
            if ep is not None:
                ep["end"] = rec["ts"]
                ep["events"].append(rec)
                ep["title"] += f" for {fmt_duration(rec.get('refused_for_s') or 0)}"
            else:
                new("srp", rec, f"{_label(rec)} SRP registration accepted", rec.get("note", ""))
        elif ev == "rejoin_wave":
            ep = new("rejoin", rec, f"rejoin wave: {rec.get('devices')} devices",
                     (f"after {rec['trigger']}: " if rec.get("trigger") else "")
                     + ", ".join(rec.get("names") or [])[:200])
            ep["end"] = rec.get("until", rec["ts"])
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
        elif ev == "partition_storm":
            prev, cur = rec.get("previous", {}), rec.get("current", {})
            ep = new("partition", rec, f"partition storm: {rec.get('partitions')} partitions",
                     f"leader {prev.get('leader')} -> {cur.get('leader')} in "
                     f"{fmt_duration(rec.get('duration_s') or 0)}, {rec.get('changes')} flips")
            ep["end"] = rec.get("until", rec["ts"])
        elif ev == "leader_stalled":
            addr = _addr(rec) or f"r{rec.get('leader_router')}"
            open_leader[addr] = new("partition", rec, f"leader stalled: {rec.get('leader')}",
                                    f"sequence {rec.get('id_sequence')} stuck for "
                                    f"{fmt_duration(rec.get('stalled_for_s') or 0)}", end=None)
        elif ev == "leader_resumed":
            addr = _addr(rec) or f"r{rec.get('leader_router')}"
            ep = open_leader.pop(addr, None)
            if ep is not None:
                ep["end"] = rec["ts"]
                ep["events"].append(rec)
                ep["title"] += f" for {fmt_duration(rec.get('stalled_for_s') or 0)}"
            else:
                new("partition", rec, f"leader resumed: {rec.get('leader')}", rec.get("note", ""))
        elif ev == "phase_locked_storm":
            new("storm", rec, "phase-locked storm",
                f"period {rec.get('period_s')}s, onsets {rec.get('onsets')}, "
                f"baseline {rec.get('baseline_frames_per_window')} frames/window")
        elif ev in ("snapshot_saved", "snapshot_failed"):
            new("snapshot", rec, "snapshot saved" if ev == "snapshot_saved" else "snapshot failed",
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
        elif ev in ("radio_missing", "radio_attached", "radio_lost", "radio_returned"):
            what = {"radio_missing": "not plugged in", "radio_attached": "found", "radio_lost": "lost",
                    "radio_returned": "back"}[ev]
            where = f" ({rec['placement']})" if rec.get("placement") else ""
            new("radio", rec, f"radio {rec.get('radio') or '?'}{where} {what}", rec.get("note", ""))
        else:
            new(ev or "event", rec, ev, rec.get("note", ""))

    for ep in episodes:
        if ep["kind"] == "quiet" and ep["end"] is None:
            ep["title"] = f"{ep['name'] or ep['addr']} quiet for {fmt_duration(now - ep['silent_since'])} (still quiet)"
        elif ep["kind"] == "link" and ep["end"] is None:
            ep["title"] += f" for {fmt_duration(now - ep['low_since'])} (still down)"
        elif ep["kind"] == "starved" and ep["end"] is None:
            ep["title"] += f" for {fmt_duration(now - ep['starved_since'])} (still unanswered)"
        elif ep["kind"] == "unserved" and ep["end"] is None:
            ep["title"] += f" for {fmt_duration(now - ep['unserved_since'])} (still undelivered)"
        elif ep["kind"] == "key_lag" and ep["end"] is None:
            ep["title"] += f" for {fmt_duration(now - ep['lag_since'])} (still behind)"
        elif ep["kind"] == "ha_unavailable" and ep["end"] is None:
            ep["title"] += f" for {fmt_duration(now - ep['down_since'])} (still unavailable)"
        elif ep["kind"] == "visit" and ep["end"] is None:
            ep["title"] += " (not yet over)"
    return sorted(episodes, key=lambda e: e["start"])


def _nth(rec: dict) -> str:
    n = rec.get("visit")
    return f" (visit {n})" if isinstance(n, int) and not isinstance(n, bool) and n > 1 else ""


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


def episode_onset(ep: dict) -> float:
    """When the interval an episode reports actually began, which is not when
    it was announced. A silence starts at the device's last frame, a
    starvation at the first unanswered poll, a signal drop at the first low
    reading -- each of them before the threshold that logged the event. The
    alert time stays in ``start``."""
    for key in ("silent_since", "starved_since", "unserved_since", "low_since"):
        since = ep.get(key)
        if isinstance(since, (int, float)) and not isinstance(since, bool):
            return float(since)
    return ep["start"]


def day_episodes(events_dir: Path, day: str, now: float | None = None) -> list[dict]:
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
        # By the interval's onset, not by the alert that announced it. A
        # device last heard at 23:50 whose device_quiet was logged at 00:20
        # belonged to neither day by the alert time: it was missing from the
        # evening it began in, while the next day's episode counted those ten
        # minutes in its duration.
        onset = episode_onset(ep)
        if ep_end >= start and onset < end:
            ep["carried_over"] = onset < start         # began on an earlier day
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
# A status file this old is a daemon that is not running: the watchdog
# writes it every 30 s while alive, so three writes have been missed.
# This is the only figure any of them may use. Read at 90 s in the status
# page's capture row, `threadwatch status` and doctor, and at 180 s in the
# page header and here, one status file was a daemon that was both
# "capturing" and "not running" - on the same page, during the outage the
# page exists to report.
STATUS_DEAD_S = 90.0
# A daemon that is alive but has heard nothing for this long: a quiet
# channel, the wrong channel, or a dongle that has stopped hearing.
STATUS_QUIET_S = 120.0


def status_state(status: dict | None, now: float) -> tuple[str, float]:
    """How to read a status file, and how old it is: "none" (no file, or
    one with nothing in it), "dead" (nothing has written it for
    STATUS_DEAD_S), "quiet" (alive, hearing nothing) or "live"."""
    if not isinstance(status, dict) or not status:
        return "none", 0.0
    updated = status.get("updated")
    # No usable "updated" is not evidence that anything is running: read it
    # as old, not as fresh. json.loads accepts NaN, and every comparison
    # against NaN is false, so an unchecked one would fall through to "live".
    if isinstance(updated, bool) or not isinstance(updated, (int, float)) or not math.isfinite(updated):
        updated = 0
    age = now - updated
    if age > STATUS_DEAD_S:
        return "dead", age
    if (status.get("last_frame_age_s") or 0) > STATUS_QUIET_S:
        return "quiet", age
    return "live", age

_BLIND_NOTES = {
    "stopped": "the recorder was stopped",
    "stalled": "the recorder was not running: it left after 3 min without frames and was restarted",
    "crashed": "the recorder crashed and was restarted",
    "cleanup_failed": "the recorder stopped as asked but could not put all of it away (a full disk?)",
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


def coverage_since(events_dir: Path) -> float | None:
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


def coverage(events_dir: Path, day: str, now: float | None = None,
             status: dict | None = None) -> list[dict]:
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


def episode_blind_s(ep: dict, segments: list[dict], now: float | None = None) -> float:
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
                now: float | None = None, leader_router: int | None = None,
                mesh_generation: int | None = None, ha: dict | None = None,
                visitors: VisitorNames | None = None, key_fresh_s: float = 1800) -> list[dict]:
    """One dict per tracked address. The live role comes from the RLOC16 the
    recorder last saw the device use: router or child, which router it is
    or hangs off, and whether it holds the partition's leader id. The key
    generation is the newest its frames were accepted under; ``lag`` is
    how far behind its parent's (a child) or ``mesh_generation`` (a
    router, from status.json's crypto.key_sequence) that is, whatever the
    age of either reading: the recorder judges only fresh ones, and
    ``key_lagging`` says whether it has an episode open. ``ha`` is
    haavail.availability_by_addr's view: for every device Home Assistant
    knows, whether it is available there and since when it is not
    (``ha_state`` available / unavailable, or None for a device HA does
    not know or with the feature off)."""
    now = now or time.time()
    ha = ha or {}
    holders = router_holders(seen.table)
    generations = {addr: newest_generation(row) for addr, row in seen.table.items()}
    rows = []
    for addr, row in seen.table.items():
        rssi = row.get("rssi")
        live = rloc16_role(row.get("rloc16")) or {}
        parent_addr = parent_address(row, holders)
        br = names.border_routers.get(addr)
        generation, generation_ts = generations[addr]
        parent_generation = generations[parent_addr][0] if parent_addr else None
        reference = mesh_generation if live.get("role") == "router" else parent_generation
        ha_info = ha.get(addr)
        rows.append({
            "ha_state": (None if ha_info is None else "unavailable" if ha_info.get("since") is not None
                         else "available"),
            "ha_since": ha_info.get("since") if ha_info else None,
            "ha_burst_id": ha_info.get("burst_id") if ha_info else None,
            "generation": generation,
            "generation_ts": generation_ts,
            "key_sequences": key_summary(row, now, key_fresh_s),
            "parent_generation": parent_generation,
            "mesh_generation": mesh_generation,
            "lag": reference - generation if generation is not None and reference is not None else None,
            "key_lagging": row.get("keylag_since") is not None,
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
            "visitor": visitors.name(addr) if visitors else None,    # a labelled phone, here right now
            "frames": row.get("frames", 0),
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "silent_for_s": round(now - row.get("last_seen", now)),
            "rssi_dbm": rssi,
            "reception": reception(rssi, min_rssi_dbm),
            # With named radios: frames per radio, and each radio's own
            # RSSI average; None for a single unnamed dongle's rows.
            "heard_by": row.get("heard_by"),
            "rssi_by_radio": row.get("rssi_by_radio"),
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
    "unknown": ("not in devices.json", lambda r, dom: r["name"] is None and not r.get("visitor")),
    "visitors": ("visitors", lambda r, dom: bool(r.get("visitor"))),
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


def select_devices(rows: list[dict], dominant: int | None, only: str = "", sort: str = "name") -> list[dict]:
    """The devices page's subset and order. An unknown filter or sort name
    is ignored rather than an error: the page still renders."""
    f = DEVICE_FILTERS.get(only)
    if f:
        rows = [r for r in rows if f[1](r, dominant)]
    s = DEVICE_SORTS.get(sort) or DEVICE_SORTS["name"]
    return sorted(rows, key=s[1])


def dominant_pan(seen: LastSeen, configured: int | None = None,
                 state_dir: Path | None = None) -> int | None:
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
             day: str, now: float | None = None, pan_id: int | None = None,
             state_dir: Path | None = None, visitors: VisitorNames | None = None) -> dict:
    """What matters at this moment, for the top of today's page: devices
    quiet right now (as the recorder announced them), devices whose signal
    is down, unknown addresses still to name, labelled visitors here right
    now (a phone whose visit is not yet filed), and the day's daily_summary
    record if one has gone out. Devices on a foreign PAN are left out."""
    now = now or time.time()
    dominant = dominant_pan(seen, pan_id, state_dir)
    quiet, degraded, unknown, visiting = [], [], [], []
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
            label = visitors.name(addr) if visitors else None
            if label:
                visiting.append({**item, "name": label})
            else:
                unknown.append(item)
    quiet.sort(key=lambda i: -i["silent_for_s"])
    unknown.sort(key=lambda i: i["silent_for_s"])
    visiting.sort(key=lambda i: i["silent_for_s"])
    summary = None
    for rec in read_day(events_dir, day):
        if rec.get("event") == "daily_summary":
            summary = rec
    return {"quiet": quiet, "degraded": degraded, "unknown": unknown, "visiting": visiting, "summary": summary}


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


def devices_history(events_dir: Path, addrs: list[str], now: float | None = None,
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


def device_history(events_dir: Path, addr: str, now: float | None = None,
                   days: int = DEVICE_HISTORY_DAYS) -> list[dict]:
    """devices_history for a single address."""
    return devices_history(events_dir, [addr], now, days)


def _dir_size(path: Path) -> int:
    try:
        return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())
    except OSError:
        return 0


def _span(pcaps: list[str]) -> tuple[str, str] | None:
    """First and last hour covered by ring-named pcaps, as YYYYMMDD-HH."""
    from .ring import parse_ring_name
    hours = sorted({parsed[0] for n in pcaps if (parsed := parse_ring_name(n))})
    return (hours[0], hours[-1]) if hours else None


DEFAULT_BYTES_PER_HOUR = 30 * 1024 * 1024   # a busy mesh; used until the ring has measured itself


# What an hour of HA add-on log costs gzipped, per add-on, for the room a
# snapshot with logs needs: the OTBR at log level info runs about 47k
# lines/h, 7 MB raw, under 1 MB gzipped; the Matter Server far less. A
# round figure that errs high.
HA_LOG_GZ_BYTES_PER_HOUR = 1024 * 1024


def storage(cfg) -> dict:
    """What the recorder keeps on disk and how much room is left there.
    ring_bound_bytes is the most the ring can grow to (keep_hours hours at
    the measured rate, and no more than keep_gb when set); ring_needs_bytes
    is how much of that it has not used yet. Both consumers (doctor, the
    status page) judge free space against these, so they agree.
    snapshot_extra_bytes is what a snapshot adds beyond the ring copy: the
    HA add-on logs when [ha_logs] is on, [ha_logs] max_hours of each
    add-on at HA_LOG_GZ_BYTES_PER_HOUR."""
    import shutil

    from .ring import ring_hours
    # Counted in hours: with several radios an hour is a file per radio,
    # and the rate per hour is what the ring grows by, all series together.
    ring = [p.name for _hour, files in ring_hours(cfg.ring_dir) for p in files.values()]
    hours = len(ring_hours(cfg.ring_dir))
    out = {"ring_files": hours, "ring_span": _span(ring), "ring_bytes": _dir_size(cfg.ring_dir),
           "keep_hours": cfg.keep_hours,
           "snapshots_bytes": _dir_size(cfg.snapshots_dir) if cfg.snapshots_dir.exists() else 0,
           "events_bytes": _dir_size(cfg.events_dir) if cfg.events_dir.exists() else 0}
    try:
        usage = shutil.disk_usage(cfg.data_dir if cfg.data_dir.exists() else cfg.data_dir.parent)
        out.update({"disk_total": usage.total, "disk_free": usage.free})
    except OSError:
        out.update({"disk_total": None, "disk_free": None})
    if hours > 1:
        out["bytes_per_hour"] = out["ring_bytes"] // hours
    per_hour = out.get("bytes_per_hour") or DEFAULT_BYTES_PER_HOUR
    bound = cfg.keep_hours * per_hour
    if cfg.keep_bytes:
        # The writer prunes closed files to the cap as the hour grows, but
        # never the file being written: the ring can stand one hour over.
        bound = min(bound, cfg.keep_bytes + per_hour)
    out["keep_bytes"] = cfg.keep_bytes
    out["ring_bound_bytes"] = bound
    out["ring_needs_bytes"] = max(0, bound - out["ring_bytes"])
    out["snapshot_extra_bytes"] = (int(len(cfg.ha_logs_addons) * cfg.ha_logs_max_hours * HA_LOG_GZ_BYTES_PER_HOUR)
                                   if getattr(cfg, "ha_logs_enabled", False) else 0)
    return out


def snapshots(snapshots_dir: Path) -> list[dict]:
    """Saved snapshots (threadwatch snapshot), newest first: label, when
    saved, the hours their pcaps cover, size, whether events came along."""
    if not snapshots_dir.exists():
        return []
    out = []
    for d in snapshots_dir.iterdir():
        if not d.is_dir() or d.name == STAGING_DIR:      # a copy still running, or cut short, is not a snapshot
            continue
        stamp, _, label = d.name.partition("_")
        try:
            saved = time.mktime(time.strptime(stamp, "%Y%m%dT%H%M%S"))
        except ValueError:
            saved = d.stat().st_mtime
        pcaps = sorted(p.name for p in d.glob("*.pcap"))
        out.append({"name": d.name, "label": label or d.name, "saved": saved,
                    "pcaps": len(pcaps), "span": _span(pcaps), "bytes": _dir_size(d),
                    "events": (d / "events").is_dir(), "day": day_of(saved),
                    **_ha_logs_of(d)})
    out.sort(key=lambda i: -i["saved"])
    return out


def _ha_logs_of(snapshot_dir: Path) -> dict:
    """The HA add-on logs a snapshot carries (ha-logs.json, docs/ANALYSIS.md):
    ha_logs is the status (complete, partial, failed, skipped, fetching) or
    None when the snapshot never asked for them, and ha_log_files lists
    each add-on's file with its line count and whether it is whole."""
    try:
        status = json.loads((snapshot_dir / "ha-logs.json").read_text())
    except (OSError, ValueError):
        return {"ha_logs": None, "ha_log_files": []}
    if not isinstance(status, dict) or not isinstance(status.get("addons"), dict):
        return {"ha_logs": None, "ha_log_files": []}
    files = [{"addon": slug, "file": r.get("file"), "lines": r.get("lines"), "complete": bool(r.get("complete"))}
             for slug, r in status["addons"].items() if isinstance(r, dict) and r.get("file")]
    return {"ha_logs": status.get("status") if isinstance(status.get("status"), str) else None,
            "ha_log_files": files}


def fmt_bytes(n: int | None) -> str:
    if n is None:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def recording_for_day(ring_dir: Path, snapshots_dir: Path, day: str) -> dict:
    """Whether packets for a day still exist: ring files (one week) and any
    saved snapshots whose pcaps cover it. A snapshot belongs to the days
    its packets span, not the moment it was saved: the storm logged on
    one day is usually saved after midnight, and the day page for the
    storm is where the packets are wanted. One with no pcaps is filed
    under the day it was saved."""
    stamp = day.replace("-", "")
    ring = sorted(p.name for p in ring_dir.glob(f"threadwatch-{stamp}-*.pcap")) if ring_dir.exists() else []
    kept = []
    for inc in snapshots(snapshots_dir):
        span = inc["span"]
        if (span[0][:8] <= stamp <= span[1][:8]) if span else inc["day"] == day:
            kept.append(inc["name"])
    return {"ring_files": ring, "snapshots": sorted(kept)}


def today() -> str:
    return day_of(time.time())


def days_available(events_dir: Path) -> list[str]:
    return list_days(events_dir)
