"""Read-only review pages: what happened on a day, what a device has done.

Standard library only, server-rendered HTML, no JavaScript required. Runs
as its own process (``threadwatch web``) reading the state directory, so it
can never affect capture. No authentication: LAN or your own proxy.
"""

from __future__ import annotations

import html
import json
import signal
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, quote, unquote, urlparse

from .events import DAY_RE, day_bounds, day_of, next_day, prev_day
from .names import AmbiguousName, DeviceNames, LastSeen, load_names
from .review import (DEVICE_FILTERS, DEVICE_SORTS, capture_for_day, coverage, coverage_since, day_episodes, day_index,
                     episode_blind_s,
                     days_available, device_rows, devices_history, dominant_pan,
                     fmt_bytes, fmt_duration, incidents, live_address, now_card, select_devices, storage, today)
from .review import SEVERITY_RANK

REFRESH_S = 60   # today's page reloads itself this often

CSS = """
:root{--bg:#fff;--fg:#1c1c1e;--muted:#6b6b70;--line:#e3e3e6;--card:#f6f6f8;
 --info:#8a8a90;--notice:#2f7bd6;--warning:#d08700;--critical:#d03a2f;--ok:#2e9e5b;--link:#1f5fbf}
@media (prefers-color-scheme:dark){:root{--bg:#141416;--fg:#ececf0;--muted:#9a9aa2;--line:#2c2c31;
 --card:#1d1d21;--info:#77777e;--notice:#5b9cf0;--warning:#e6a23c;--critical:#ef5b50;--ok:#4cc27a;--link:#7fb0f5}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
 font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
header{display:flex;flex-wrap:wrap;gap:.6em 1.4em;align-items:baseline;padding:.8em 1.2em;
 border-bottom:1px solid var(--line)}header .brand{font-weight:650;font-size:1.05em}
header .status{color:var(--muted);font-size:.92em}header .status b{color:var(--fg);font-weight:600}
main{max-width:1100px;margin:0 auto;padding:1em 1.2em 3em}
h1{font-size:1.35em;margin:.4em 0 .5em}h2{font-size:1.05em;margin:1.4em 0 .5em;color:var(--muted);
 text-transform:uppercase;letter-spacing:.04em}
.daynav{display:flex;gap:1em;align-items:center;flex-wrap:wrap;margin:.2em 0 .8em}
.strip{display:flex;gap:.3em;flex-wrap:wrap;margin:.4em 0 1em}
.strip a{display:block;min-width:3.3em;padding:.25em .4em;border:1px solid var(--line);border-radius:6px;
 text-align:center;font-size:.8em;color:var(--fg);background:var(--card)}
.strip a.cur{border-color:var(--link);box-shadow:inset 0 0 0 1px var(--link)}
.strip a small{display:block;color:var(--muted)}
.strip a .w{color:var(--warning)}.strip a .c{color:var(--critical)}
.cov{position:relative;height:14px;border:1px solid var(--line);border-radius:4px;background:var(--card);
 overflow:hidden;margin:.3em 0 .15em}
.cov div{position:absolute;top:0;bottom:0}.cov .on{background:var(--ok);opacity:.45}
.cov .blind{background:var(--critical)}.cov .uncertain{background:var(--warning)}
.covh{display:flex;justify-content:space-between;font-size:.72em;color:var(--muted);margin:0 0 .3em}
.covl{font-size:.88em;margin:0 0 .8em}.covl li{margin:.1em 0}.covl ul{margin:.2em 0 0 1.2em;padding:0}
table{border-collapse:collapse;width:100%;font-size:.94em}
table.facts th{width:11em;text-transform:none;letter-spacing:0;font-size:.94em}
th,td{text-align:left;padding:.45em .6em;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:.85em;text-transform:uppercase;letter-spacing:.03em}
td.t{white-space:nowrap;color:var(--muted);font-variant-numeric:tabular-nums}
td.t small{display:block;font-size:.75em;line-height:1.1;opacity:.85}
td.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.sev{display:inline-block;min-width:5.2em;padding:.05em .5em;border-radius:999px;font-size:.78em;
 font-weight:600;text-align:center;color:#fff;background:var(--info)}
.sev.notice{background:var(--notice)}.sev.warning{background:var(--warning)}.sev.critical{background:var(--critical)}
.muted{color:var(--muted)}.ok{color:var(--ok)}.bad{color:var(--critical)}.warn{color:var(--warning)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.7em .9em;margin:.6em 0}
.card .k{color:var(--muted);font-size:.85em;text-transform:uppercase;letter-spacing:.03em;margin-right:.4em}
.card .sep{color:var(--line);margin:0 .5em}
.filters{display:flex;gap:.4em 1.2em;flex-wrap:wrap;margin:.3em 0 .8em;font-size:.9em}
.filters span.k{color:var(--muted)}.filters a.cur{font-weight:650;color:var(--fg);text-decoration:underline}
details{margin:1em 0}summary{cursor:pointer;color:var(--muted)}
pre{font-size:.8em;overflow-x:auto;background:var(--card);padding:.6em;border-radius:6px}
.empty{color:var(--muted);padding:1em 0}
@media(max-width:640px){td.detail{display:block;padding-top:0;border-top:none;color:var(--muted)}
 th.detail{display:none}}
"""


# Plain-language meaning of each episode kind: the help page, and the
# tooltip on every row.
LEGEND = [
    ("quiet", "Device quiet / returned",
     "The recorder heard nothing from the device for longer than the quiet window (30 min by "
     "default, [quiet] silence_s in config.toml), then later heard it again. One row, with the real duration "
     "measured from the device's last frame. 'Still quiet' means it has not come back. A warning "
     "when the sniffer hears the device well; only a notice when its signal is marginal, because "
     "a device at the edge of the sniffer's range fades in and out without anything being wrong."),
    ("link", "Signal down / recovered",
     "The device is still talking, but the sniffer hears it well below its usual level: more "
     "than 8 dB under its daily reference for 30 minutes (set in [link] in config.toml). A "
     "device that moved, a door or appliance now in the way, a failing antenna, or interference "
     "near it. Notice, logged only. A silence without a rejoin attempt often follows; a drop "
     "that lasts a day becomes the new normal."),
    ("starved", "Polls unanswered / answered again",
     "A sleepy end device keeps polling its parent and nothing acknowledges it, after its polls "
     "used to be answered (credentials needed: polls carry a short address). Its parent died or "
     "the link to it broke, and the device has not noticed: it looks alive, never goes quiet, and "
     "delivers nothing until it gives up and rejoins. Logged at notice when it starts, warning "
     "if the polls are still unanswered ten minutes later ([polls] confirm_s). If the device just moved to a "
     "parent the sniffer cannot hear, the acknowledgements are missing at the sniffer, not on air: "
     "a rejoin row just before this one says so."),
    ("retransmissions", "Retransmissions elevated",
     "In one minute, more than 20% of data frames were repeats (same sender and sequence number "
     "within 2 s), and more than double the recent baseline. A repeat means the sender got no "
     "acknowledgement. One sender hammering one target is a bad link between those two (notice, "
     "logged only); retries spread across many devices is channel-wide contention or "
     "interference, which is the early sign of a storm: logged at notice for the first minute, "
     "warning if the rate stays up for five ([retransmissions] confirm_s), since one minute is a "
     "microwave."),
    ("storm", "Phase-locked storm",
     "Traffic floods recurring with a stable period: the signature of the mesh-wide broadcast "
     "storm that took the network down before. Critical. This is what the ring buffer is for: "
     "run 'threadwatch freeze' to keep the packets."),
    ("partition", "Partition or leader change",
     "The Thread mesh split, merged, or elected a new leader (credentials needed to see this). "
     "Routine after a border router reboots; a problem if it keeps happening."),
    ("rejoin", "Rejoin attempt",
     "A device sent MLE Parent Request, Child ID Request or Announce: it lost its parent or its "
     "network and is trying to get back (credentials needed). Expected after a device or router "
     "restarts; a device doing this repeatedly has a bad link to every parent it can hear."),
    ("first_seen", "Device first seen",
     "An address the recorder has never tracked before. Happens once per device, ever. Bursts "
     "of these mark the recorder's first start or a new way of identifying devices; a single "
     "one later is a genuinely new or newly named device, or a device at the edge of range "
     "heard for the first time."),
    ("returned", "Returned (without a matching quiet)",
     "A device came back but its quiet record predates the log."),
    ("foreign_pan", "Foreign PAN",
     "Frames on this channel carrying a PAN id that is not this network's, seen repeatedly. "
     "Another Thread mesh, or a Zigbee network on the same channel. Harmless, but it competes "
     "for airtime. Devices on a foreign PAN are never reported quiet."),
    ("join_scan", "Join-scan beacons",
     "Beacon requests or beacons in a burst: something is scanning to join a network. Normal "
     "while commissioning a device; otherwise a neighbour's device or a factory-reset one."),
    ("frozen", "Incident frozen",
     "The recorder copied the ring buffer into an incident directory by itself, because a critical "
     "event fired and [capture] freeze_on_critical is on. One per six hours at most. A failure "
     "(disk full, usually) is logged as a warning instead."),
    ("recorder", "Recorder started / restarted",
     "The recorder itself started: how long it had not been listening (since the last frame any run "
     "heard) and how the run before ended. A stop that was asked for is information; a crash, a "
     "stall (three minutes without frames, after which the recorder leaves and the supervisor "
     "restarts it) or an end it left no note of (a power cut, a kill) is a notice. Starts minutes "
     "apart are one row: the restart loop of a host asleep or a dongle gone. The coverage bar at "
     "the top of the day is drawn from these."),
    ("clock", "Host clock jumped",
     "The host clock was stepped, usually by NTP after a boot on a Pi without a real-time clock. "
     "Forward: the time jumped over was never lived through and counts as the recorder's own "
     "blindness. Back: every stamp taken before the jump was moved back with it."),
    ("summary", "Daily summary",
     "Once a day (at [summary] hour in config.toml, 08:00 by default): frames captured in the "
     "last 24 hours, devices heard out of those tracked, who is quiet, unknown addresses still "
     "to name, devices heard marginally or with their signal down, and the day's event counts. "
     "A quiet way to know the recorder is still watching and nothing is slowly going wrong."),
    ("test", "Alert test", "A synthetic event from 'threadwatch alert-test'."),
]
LEGEND_BY_KIND = {k: one for k, _t, one in LEGEND}


def valid_day(day: str) -> bool:
    if not DAY_RE.match(day):
        return False
    try:
        time.strptime(day, "%Y-%m-%d")
        return True
    except ValueError:
        return False


def esc(x) -> str:
    return html.escape("" if x is None else str(x))


def hm(ts: Optional[float]) -> str:
    return time.strftime("%H:%M", time.localtime(ts)) if ts else ""


def when(ts: Optional[float], day: str, stacked: bool = False) -> str:
    """HH:MM, plus the day when it is not the page's own day, so a row
    carried over from an earlier day says so. ``stacked`` puts the day on
    its own line under the time (for the narrow time column); otherwise it
    is inline, for use inside a sentence."""
    if not ts:
        return ""
    d = day_of(ts)
    if d == day:
        return hm(ts)
    label = "yesterday" if d == prev_day(day) else "tomorrow" if d == next_day(day) else d[5:]
    if stacked:
        return f'{hm(ts)}<small>{label}</small>'
    return f'{hm(ts)} <span class="muted">{label}</span>'


def ago(ts: Optional[float], now: Optional[float] = None) -> str:
    if not ts:
        return "never"
    return fmt_duration((now or time.time()) - ts) + " ago"


class Site:
    """Everything the handler needs; re-reads state files on each request
    (they are small and the daemon rewrites them atomically)."""

    def __init__(self, cfg):
        self.cfg = cfg

    # ----------------------------------------------------------- data

    def status(self) -> dict:
        path = self.cfg.state_dir / "status.json"
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            return {}

    def names(self) -> DeviceNames:
        return load_names(self.cfg)

    def leader_router(self) -> Optional[int]:
        part = self.status().get("partition") or {}
        return part.get("leader_router")

    @staticmethod
    def role_html(r: dict, now: float) -> str:
        """'leader · router 60', 'router 33', 'child of Mudroom Air Quality',
        each with its RLOC16 and how long ago the recorder last saw it in
        use; the mapping lives in the recorder's memory and its state file,
        so it can lag a re-attach."""
        if not r.get("role"):
            return '<span class="muted">?</span>'
        if r["role"] == "router":
            text = ("<b>leader</b> &middot; " if r.get("leader") else "") + f'router {r["router_id"]}'
        elif r.get("parent_addr"):
            text = f'child of <a href="/device/{esc(r["parent_addr"])}">{esc(r["parent"])}</a>'
        else:
            text = f'child of router {r["router_id"]}'
        return f'{text} <span class="muted">{esc(r["rloc16"])}, {ago(r.get("rloc16_ts"), now)}</span>'

    def seen(self) -> LastSeen:
        return LastSeen(self.cfg.state_dir / "last-seen.json")

    # ---------------------------------------------------------- pages

    def header(self) -> str:
        st = self.status()
        now = time.time()
        age = now - st.get("updated", 0) if st else None
        if not st:
            live = '<span class="bad">no status yet</span>'
        elif age > 180:
            live = f'<span class="bad">capture stale</span> (status {fmt_duration(age)} old)'
        elif st.get("last_frame_age_s", 0) > 120:
            live = f'<span class="warn">no frames for {fmt_duration(st["last_frame_age_s"])}</span>'
        else:
            live = '<span class="ok">capturing</span>'
        det = st.get("detector", {})
        storm = ' <span class="bad">STORM ACTIVE</span>' if det.get("storm_active") else ""
        crypto = f'{(st.get("crypto") or {}).get("mac_decrypted", 0):,} decrypted'
        return (f'<header><a class="brand" href="/">threadwatch</a>'
                f'<nav><a href="/">today</a> &nbsp; <a href="/devices">devices</a> &nbsp; '
                f'<a href="/incidents">incidents</a> &nbsp; <a href="/status">status</a> &nbsp; '
                f'<a href="/help">what these mean</a></nav>'
                f'<span class="status">{live}{storm} &middot; ch {esc(st.get("channel"))} &middot; '
                f'<b>{st.get("frames_total", 0):,}</b> frames &middot; {st.get("devices_tracked", 0)} devices '
                f'&middot; {crypto} &middot; up {fmt_duration(st.get("uptime_s", 0))}</span></header>')

    def page(self, title: str, body: str, refresh: bool = False) -> str:
        meta = f'<meta http-equiv="refresh" content="{REFRESH_S}">' if refresh else ""
        return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
                f'<meta name="viewport" content="width=device-width,initial-scale=1">{meta}'
                f'<title>{esc(title)} - threadwatch</title><style>{CSS}</style></head>'
                f'<body>{self.header()}<main>{body}</main></body></html>')

    def strip(self, current: str) -> str:
        rows = day_index(self.cfg.events_dir)[:21]
        parts = []
        for r in reversed(rows):
            cls = ' class="cur"' if r["day"] == current else ""
            counts = []
            if r["critical"]:
                counts.append(f'<span class="c">{r["critical"]}!</span>')
            if r["warning"]:
                counts.append(f'<span class="w">{r["warning"]}</span>')
            counts.append(str(r["total"]))
            parts.append(f'<a href="/day/{r["day"]}"{cls}>{r["day"][5:]}<small>{" / ".join(counts)}</small></a>')
        return f'<div class="strip">{"".join(parts)}</div>' if parts else ""

    def now_html(self, day: str, now: float) -> str:
        """The headline card: live facts on today's page, the day's summary
        on any day that has one."""
        card = now_card(self.seen(), self.names(), self.cfg.events_dir,
                        self.cfg.quiet_min_rssi_dbm, day, now, pan_id=self.cfg.pan_id)
        out = ""
        if day == today():
            parts = []
            if card["quiet"]:
                who = ", ".join(f'<a href="/device/{esc(i["addr"])}">{esc(i["name"] or i["addr"])}</a> '
                                f'<span class="muted">({fmt_duration(i["silent_for_s"])}'
                                f'{", marginal" if i["reception"] == "marginal" else ""})</span>'
                                for i in card["quiet"])
                parts.append(f'<span class="k">quiet now</span><span class="bad">{len(card["quiet"])}</span>: {who}')
            if card["degraded"]:
                who = ", ".join(f'<a href="/device/{esc(i["addr"])}">{esc(i["name"] or i["addr"])}</a> '
                                f'<span class="muted">({esc(i["rssi_dbm"])} dBm, usually {esc(i["reference_dbm"])})</span>'
                                for i in card["degraded"])
                parts.append(f'<span class="k">signal down</span>{who}')
            if card["unknown"]:
                n = len(card["unknown"])
                parts.append(f'<span class="k">unnamed</span><a href="/devices?only=unknown">'
                             f'{n} address{"es" if n != 1 else ""}</a> <span class="muted">to add to devices.json</span>')
            if not parts:
                parts.append('<span class="k">right now</span><span class="ok">nothing quiet, nothing fading, '
                             'every address named</span>')
            out += f'<div class="card">{"<span class=sep>&middot;</span>".join(parts)}</div>'
        if card["summary"]:
            s = card["summary"]
            out += (f'<div class="card"><span class="k">daily summary</span>'
                    f'<span class="muted">{hm(s["ts"])}</span> {esc(s.get("note", ""))}</div>')
        return out

    def coverage_html(self, day: str, segs: list[dict], now: float) -> str:
        """The day as a bar: listening in green, not listening in red,
        running but hearing nothing in amber, and the rest of today
        blank; under it, one line per gap."""
        start, end = day_bounds(day)
        until = min(end, now)
        if until <= start:
            return ""
        since = coverage_since(self.cfg.events_dir)
        if since is None or since >= until:
            return ('<p class="muted">coverage: not recorded' +
                    (f' before {esc(day_of(since))}' if since is not None else " yet") + '</p>')

        def pct(ts):
            return max(0.0, min(100.0, (ts - start) / (end - start) * 100))

        bar = [f'<div class="on" style="left:0;width:{pct(until):.2f}%"></div>']
        lines = []
        for s in segs:
            a, b = pct(s["start"]), pct(s["end"])
            tip = esc(f'{hm(s["start"])}-{hm(s["end"])}: {s["note"]}')
            bar.append(f'<div class="{esc(s["state"])}" style="left:{a:.2f}%;width:{max(b - a, 0.15):.2f}%" '
                       f'title="{tip}"></div>')
            what = "not listening" if s["state"] == "blind" else "may not have heard"
            more = f', {s["count"]} starts' if s["cause"] not in ("clock_step", "down") and s["count"] > 1 else ""
            lines.append(f'<li><b>{hm(s["start"])}-{hm(s["end"])}</b> {what} '
                         f'<span class="muted">({fmt_duration(s["end"] - s["start"])}{more}): {esc(s["note"])}</span></li>')
        out = (f'<div class="cov">{"".join(bar)}</div>'
               f'<div class="covh"><span>00</span><span>06</span><span>12</span><span>18</span><span>24</span></div>')
        if lines:
            out += f'<div class="covl"><span class="k muted">coverage</span><ul>{"".join(lines)}</ul></div>'
        else:
            out += '<p class="covl muted">coverage: listening throughout</p>'
        return out

    def day_page(self, day: str, min_severity: str = "") -> str:
        now = time.time()
        floor = SEVERITY_RANK.get(min_severity)
        eps = day_episodes(self.cfg.events_dir, day, now)
        segs = coverage(self.cfg.events_dir, day, now, self.status())
        total = len(eps)
        if floor:
            eps = [e for e in eps if SEVERITY_RANK.get(e["severity"], 0) >= floor]
        q = f"?min={min_severity}" if floor else ""
        cap = capture_for_day(self.cfg.ring_dir, self.cfg.incidents_dir, day)
        avail = days_available(self.cfg.events_dir)
        first = avail[0] if avail else day
        is_today = day == today()
        nav = (f'<div class="daynav"><a href="/day/{prev_day(day)}{q}">&larr; {prev_day(day)}</a>'
               f'<b>{esc(day)}</b>' + (f'<a href="/day/{next_day(day)}{q}">{next_day(day)} &rarr;</a>'
                                        if not is_today else '<span class="muted">today</span>') + '</div>')
        sev = '<div class="filters"><span class="k">show</span>' + "".join(
            f'<a href="/day/{day}{"?min=" + s if s else ""}"{" class=cur" if (s or "") == (min_severity if floor else "") else ""}>'
            f'{label}</a>' for s, label in (("", "everything"), ("notice", "notice and up"), ("warning", "warning and up")))
        sev += (f' <span class="muted">{len(eps)} of {total}</span>' if floor else "") + '</div>'
        if cap["ring_files"]:
            pk = f'<span class="ok">{len(cap["ring_files"])} hourly capture files still in the ring</span>'
        else:
            pk = '<span class="muted">packets for this day are gone from the ring</span>'
        if cap["incidents"]:
            pk += ' &middot; frozen incidents: ' + ", ".join(
                f'<a href="/incidents#{esc(i)}">{esc(i)}</a>' for i in cap["incidents"])
        rows = []
        for ep in eps:
            span = ""
            if ep["kind"] == "quiet":
                if ep["end"]:
                    span = f' <span class="muted">back {when(ep["end"], day)}</span>'
                elif ep["count"] > 1:   # announced again before it returned
                    span = f' <span class="muted">x{ep["count"]}</span>'
            elif ep["count"] > 1:
                span = f' <span class="muted">x{ep["count"]}, {when(ep["start"], day)}-{when(ep["end"], day)}</span>'
            who = ""
            if ep.get("addr") and len(ep["addr"]) == 16:   # older rejoin rows carry a short src
                who = f' <a class="muted" href="/device/{esc(ep["addr"])}">&#9656;</a>'
            blind = episode_blind_s(ep, segs, now) if ep["kind"] != "recorder" else 0
            if blind >= 60:
                span += (f' <span class="warn" title="the recorder was not listening for this much of it">'
                         f'&#9888; recorder off {fmt_duration(blind)} of this</span>')
            tip = LEGEND_BY_KIND.get(ep["kind"], "")
            if ep.get("carried_over"):
                tip = "Carried over: this began on an earlier day and was still going on this one. " + tip
            tip = esc(tip)
            rows.append(f'<tr title="{tip}"><td class="t">{when(ep["start"], day, stacked=True)}</td>'
                        f'<td><span class="sev {esc(ep["severity"])}">{esc(ep["severity"])}</span></td>'
                        f'<td>{esc(ep["title"])}{span}{who}</td>'
                        f'<td class="detail muted">{esc(ep["detail"])}</td></tr>')
        table = (f'<table><tr><th>time</th><th></th><th>what</th><th class="detail">detail</th></tr>'
                 f'{"".join(rows)}</table>' if rows else
                 f'<p class="empty">nothing at {esc(min_severity)} or above this day</p>' if floor and total else
                 '<p class="empty">nothing logged this day</p>' if day >= first else
                 '<p class="empty">before the recorder\'s first day</p>')
        raw = (f'<details><summary>raw records</summary>'
               f'<p><a href="/api/day/{esc(day)}">JSON</a></p></details>')
        live = f'<span class="muted">reloads every {REFRESH_S} s</span>' if is_today else ""
        return self.page(day, f'<h1>{esc(day)}</h1>{nav}{self.strip(day)}{self.now_html(day, now)}'
                              f'{self.coverage_html(day, segs, now)}'
                              f'<p class="muted">{pk} {live}</p>{sev}<h2>episodes</h2>{table}{raw}',
                         refresh=is_today)

    def devices_page(self, only: str = "", sort: str = "name") -> str:
        now = time.time()
        names = self.names()
        seen = self.seen()
        every = device_rows(seen, names, self.cfg.quiet_min_rssi_dbm, now, leader_router=self.leader_router())
        dominant = dominant_pan(seen, self.cfg.pan_id)
        rows = select_devices(every, dominant, only, sort)
        only = only if only in DEVICE_FILTERS else ""
        sort = sort if sort in DEVICE_SORTS else "name"

        def link(param, value, label, cur):
            q = {"only": only, "sort": sort}
            q[param] = value
            href = "/devices" + ("?" + "&".join(f"{k}={v}" for k, v in q.items() if v and not (k == "sort" and v == "name")) if any(
                v and not (k == "sort" and v == "name") for k, v in q.items()) else "")
            return f'<a href="{href}"{" class=cur" if cur else ""}>{label}</a>'

        filters = ('<div class="filters"><span class="k">show</span>' + link("only", "", "all", not only)
                   + "".join(link("only", k, f"{v[0]}", only == k) for k, v in DEVICE_FILTERS.items())
                   + '</div><div class="filters"><span class="k">order</span>'
                   + "".join(link("sort", k, v[0], sort == k) for k, v in DEVICE_SORTS.items()) + '</div>')
        trs = []
        for r in rows:
            if r["pan"] is None:
                pan_html = '<span class="muted">?</span>'
            elif r["pan"] == dominant:
                pan_html = '<span class="muted">ours</span>'
            else:
                pan_html = f'<span class="warn">foreign 0x{r["pan"]:04x}</span>'
            rec = r["reception"]
            rec_html = {"good": '<span class="ok">good</span>', "marginal": '<span class="warn">marginal</span>'}.get(rec, '<span class="muted">?</span>')
            silent = r["silent_for_s"]
            seen_html = f'<span class="{"bad" if silent > 1800 else ""}">{ago(r["last_seen"], now)}</span>'
            nm = esc(r["name"]) if r["name"] else f'<span class="warn">unknown</span>'
            if r.get("border_router_label"):
                nm += f' <span class="muted">border router {esc(r["border_router_label"])}</span>'
            if r.get("rotated_to"):
                seen_html = (f'<span class="muted">retired: now <a href="/device/{esc(r["rotated_to"])}">'
                             f'{esc(r["rotated_to"])}</a></span>')
            trs.append(f'<tr><td><a href="/device/{esc(r["addr"])}">{nm}</a></td>'
                       f'<td>{self.role_html(r, now)}</td>'
                       f'<td>{seen_html}</td>'
                       f'<td class="n">{esc(r["rssi_dbm"])}</td><td>{rec_html}</td>'
                       f'<td class="n">{r["frames"]:,}</td><td>{pan_html}</td>'
                       f'<td class="muted"><code>{esc(r["addr"])}</code></td></tr>')
        unknown = sum(1 for r in every if r["name"] is None)
        note = (f'<p class="muted">{len(every)} addresses tracked'
                + (f', <span class="warn">{unknown} not in devices.json</span>' if unknown else "")
                + (f'; showing {len(rows)} ({DEVICE_FILTERS[only][0]})' if only else "") + '.</p>')
        table = (f'<table><tr><th>device</th><th>role (live)</th><th>last heard</th><th>rssi</th>'
                 f'<th>reception</th><th>frames</th><th>pan</th><th>address</th></tr>{"".join(trs)}</table>'
                 if trs else f'<p class="empty">no devices {DEVICE_FILTERS[only][0] if only else "tracked"}</p>')
        return self.page("devices", f'<h1>devices</h1>{note}{filters}{table}')

    def device_page(self, target: str) -> str:
        """One device: every address it has used, what the recorder knows
        about each, and its history across all of them. ``target`` is an
        address or (part of) an inventory name."""
        now = time.time()
        names = self.names()
        try:
            addrs, name = names.resolve(target)
        except AmbiguousName as exc:
            # quote() so a '#', '?' or '%' in a name stays part of the
            # path; esc() alone would send "Lamp #1" to /device/Lamp.
            items = "".join(f'<li><a href="/device/{quote(c, safe="")}">{esc(c)}</a></li>' for c in exc.candidates)
            return self.page("which device?", f'<h1>which device?</h1><p class="muted">{esc(target)} '
                                              f'matches several names.</p><ul>{items}</ul>')
        except ValueError as exc:
            return self.page("no such device", f'<h1>no such device</h1><p class="muted">{esc(str(exc))}</p>'
                                               f'<p><a href="/devices">all devices</a></p>')
        seen = self.seen()
        from .names import reception
        primary = live_address(addrs, seen.table)
        entry = names.by_addr.get(primary, {})
        head = []
        if entry.get("model"):
            head.append(esc(entry["model"]))
        if len(addrs) > 1:
            head.append(f'{len(addrs)} addresses (rotates)')
        live = next((r for r in device_rows(seen, names, self.cfg.quiet_min_rssi_dbm, now,
                                            leader_router=self.leader_router())
                     if r["addr"] == primary), None)
        if live and live["role"]:
            head.append(self.role_html(live, now))
        if live and live.get("border_router_label"):
            head.append(f'border router {esc(live["border_router_label"])}, hostname <code>{esc(live["border_router"])}</code>'
                        ' (its address is learned from mDNS after every reboot)')
        cards = []
        for addr in sorted(addrs, key=lambda a: -(seen.table.get(a) or {}).get("last_seen", 0)):
            row = seen.table.get(addr)
            facts = []
            if row:
                rec = reception(row.get("rssi"), self.cfg.quiet_min_rssi_dbm)
                heard = ago(row.get("last_seen"), now)
                facts.append(f'<span class="bad">quiet</span>, last heard {heard}' if row.get("quiet_reported")
                             else f'last heard {heard}')
                level = f'rssi {esc(row.get("rssi"))} dBm ({rec})'
                if row.get("rssi_ref") is not None:
                    level += f', usually {esc(row.get("rssi_ref"))}'
                    if row.get("rssi_degraded"):
                        level += ' <span class="warn">signal down</span>'
                facts.append(level)
                facts.append(f'{row.get("frames", 0):,} frames since '
                             f'{time.strftime("%Y-%m-%d", time.localtime(row.get("first_seen", now)))}')
            cards.append(f'<div class="card"><code>{esc(addr)}</code><br>'
                         f'{" &middot; ".join(facts) if facts else "<span class=muted>never heard</span>"}</div>')
        card = (f'<p class="muted">{" &middot; ".join(head)}</p>' if head else "") + "".join(cards)
        eps = devices_history(self.cfg.events_dir, addrs, now)
        trs = []
        for ep in eps:
            day = time.strftime("%Y-%m-%d", time.localtime(ep["start"]))
            span = f' <span class="muted">x{ep["count"]}</span>' if ep["count"] > 1 else ""
            trs.append(f'<tr><td class="t"><a href="/day/{day}">{day}</a> {hm(ep["start"])}</td>'
                       f'<td><span class="sev {esc(ep["severity"])}">{esc(ep["severity"])}</span></td>'
                       f'<td>{esc(ep["title"])}{span}</td><td class="detail muted">{esc(ep["detail"])}</td></tr>')
        table = (f'<table><tr><th>when</th><th></th><th>what</th><th class="detail">detail</th></tr>{"".join(trs)}</table>'
                 if trs else '<p class="empty">no events for this device</p>')
        title = name if name != addrs[0] else "unknown device"
        return self.page(title, f'<h1>{esc(title)}</h1>{card}<h2>history</h2>{table}'
                                f'<p><a class="muted" href="/api/device/{esc(primary)}">JSON</a></p>')

    def status_page(self) -> str:
        st = self.status()
        now = time.time()
        sto = storage(self.cfg)
        dl = []

        def row(k, v):
            dl.append(f'<tr><th>{esc(k)}</th><td>{v}</td></tr>')

        if not st:
            row("capture", '<span class="bad">no status file: the capture daemon has not run here</span>')
        else:
            age = now - st.get("updated", 0)
            alive = age < 90
            row("capture", (f'<span class="ok">running</span>' if alive else
                            f'<span class="bad">not running</span>') + f' <span class="muted">(status written '
                                                                        f'{fmt_duration(age)} ago; every 30 s while alive)</span>')
            fa = st.get("last_frame_age_s", 0)
            row("last frame", (f'<span class="{"warn" if fa > 120 else "ok"}">{fmt_duration(fa)} ago</span>'
                               if alive else f'<span class="muted">{fmt_duration(age + fa)} ago</span>'))
            row("channel / port", f'{esc(st.get("channel"))} &middot; <code>{esc(st.get("port"))}</code>')
            row("this run", f'{st.get("frames_total", 0):,} frames in {fmt_duration(st.get("uptime_s", 0))}, '
                            f'{st.get("devices_tracked", 0)} devices with stats')
            row("current file", f'<code>{esc(Path(st.get("current_file", "")).name)}</code>')
            part = st.get("partition")
            if part:
                # "router 60" means nothing on its own: name the device that
                # holds that router id when the MLE layer has matched it.
                rid = esc(part.get("leader_router"))
                rloc = f' <span class="muted">(router id {rid}, RLOC16 {esc(part.get("leader_rloc16") or "?")})</span>'
                if part.get("leader_addr"):
                    who = (f'<a href="/device/{esc(part["leader_addr"])}">'
                           f'{esc(part.get("leader_name") or part["leader_addr"])}</a>{rloc}')
                else:
                    who = (f'router id {rid}{rloc} <span class="muted">not matched to a device yet: '
                           'the leader has not sent an MLE frame this run</span>')
                row("partition", f'{esc(part.get("id"))} &middot; leader {who}')
            al = st.get("alerts")
            if al:
                parts = [f'{al.get("delivered", 0)} delivered this run']
                if al.get("retrying"):
                    parts.append(f'<span class="warn">{al["retrying"]} retrying</span>')
                if al.get("given_up"):
                    parts.append(f'<span class="bad">{al["given_up"]} given up</span>')
                if al.get("resumed"):
                    parts.append(f'{al["resumed"]} resumed from the last run')
                row("alerts", ", ".join(parts))
            det = st.get("detector") or {}
            if det:
                storm = '<span class="bad">STORM ACTIVE</span>' if det.get("storm_active") else '<span class="ok">quiet</span>'
                extra = ", ".join(f"{esc(k)} {esc(v)}" for k, v in det.items()
                                  if k != "storm_active" and not isinstance(v, (list, dict)))
                row("storm detector", f'{storm} <span class="muted">{extra}</span>')
            cr = st.get("crypto")
            if cr:
                row("crypto", '<span class="muted">' + ", ".join(f"{esc(k)} {esc(v)}" for k, v in cr.items()) + '</span>')
        span = f' <span class="muted">({sto["ring_span"][0]} to {sto["ring_span"][1]})</span>' if sto["ring_span"] else ""
        rate = f', about {fmt_bytes(sto["bytes_per_hour"])}/hour' if sto.get("bytes_per_hour") else ""
        cap = f', capped at {fmt_bytes(sto["keep_bytes"])}' if sto.get("keep_bytes") else ""
        row("ring", f'{sto["ring_files"]} of {sto["keep_files"]} hourly files, {fmt_bytes(sto["ring_bytes"])}{rate}{cap}{span}')
        row("incidents", f'{fmt_bytes(sto["incidents_bytes"])} &middot; <a href="/incidents">list</a>')
        row("event log", fmt_bytes(sto["events_bytes"]))
        if sto.get("disk_total"):
            free = sto["disk_free"]
            need = sto["ring_needs_bytes"]
            cls = "bad" if free < max(need, 512 * 1024 * 1024) else "ok"
            row("disk", f'<span class="{cls}">{fmt_bytes(free)} free</span> of {fmt_bytes(sto["disk_total"])}'
                        + (f' <span class="muted">(a full ring needs about {fmt_bytes(need)} more)</span>' if need else ""))
        row("state dir", f'<code>{esc(self.cfg.state_dir)}</code>')
        return self.page("status", f'<h1>status</h1><table class="facts">{"".join(dl)}</table>'
                                   f'<p><a class="muted" href="/api/status">JSON</a></p>')

    def incidents_page(self) -> str:
        items = incidents(self.cfg.incidents_dir)
        trs = []
        for i in items:
            span = f'{i["span"][0]} to {i["span"][1]}' if i["span"] else '<span class="muted">no ring files</span>'
            trs.append(f'<tr id="{esc(i["name"])}"><td class="t"><a href="/day/{i["day"]}">{i["day"]}</a> {hm(i["frozen"])}</td>'
                       f'<td><b>{esc(i["label"])}</b></td><td>{i["pcaps"]} pcaps, {span}</td>'
                       f'<td class="n">{fmt_bytes(i["bytes"])}</td>'
                       f'<td class="muted">{"events included" if i["events"] else ""}</td></tr>')
        table = (f'<table><tr><th>frozen</th><th>label</th><th>packets</th><th>size</th><th></th></tr>{"".join(trs)}</table>'
                 if trs else '<p class="empty">no frozen incidents</p>')
        intro = (f'<p class="muted">Snapshots of the ring buffer taken with <code>threadwatch freeze &lt;label&gt;</code>, '
                 f'kept forever under <code>{esc(self.cfg.incidents_dir)}</code>. Open them in Wireshark or with '
                 f'<code>threadwatch why --pcap</code> / <code>replay</code>.</p>')
        return self.page("incidents", f'<h1>incidents</h1>{intro}{table}')

    def help_page(self) -> str:
        sev = ('<div class="card"><b>Severities.</b> '
               '<span class="sev info">info</span> bookkeeping &middot; '
               '<span class="sev notice">notice</span> worth a glance here, never paged &middot; '
               '<span class="sev warning">warning</span> paged to the phone &middot; '
               '<span class="sev critical">critical</span> paged, and the ring buffer is worth freezing.</div>')
        items = "".join(f'<h2>{esc(title)}</h2><p>{esc(text)}</p>' for _k, title, text in LEGEND)
        conv = ('<h2>How the pages read</h2><p>Each row is an <i>episode</i>, not a log line: repeated '
                'records about the same thing are one row with a count and a time span. An episode that '
                'crosses midnight appears on both days; on the later day its time is marked '
                '<i>yesterday</i>, and a silence not yet over keeps carrying forward until the '
                'device returns. The strip of days shows how many events '
                'each day had, with warnings in amber and criticals in red. Packets are kept for a '
                'week in the ring buffer and forever in frozen incidents; the top of a day page says '
                'which still exist. The devices page shows how well the sniffer hears each device: '
                '<i>marginal</i> means its silences are more likely fading than failure.</p>')
        return self.page("what these mean", f'<h1>What these events mean</h1>{sev}{conv}{items}')

    # ------------------------------------------------------------ json

    def api(self, path: str, query: dict):
        if path == "/api/status":
            return {**self.status(), "storage": storage(self.cfg)}
        if path == "/api/incidents":
            return {"incidents": incidents(self.cfg.incidents_dir)}
        if path.startswith("/api/day/"):
            day = path[len("/api/day/"):]
            if not valid_day(day):
                return None
            eps = day_episodes(self.cfg.events_dir, day)
            for ep in eps:
                ep.pop("events", None)
            from .events import read_day
            return {"day": day, "episodes": eps, "records": read_day(self.cfg.events_dir, day),
                    "capture": capture_for_day(self.cfg.ring_dir, self.cfg.incidents_dir, day),
                    "coverage": coverage(self.cfg.events_dir, day, status=self.status())}
        if path == "/api/devices":
            seen = self.seen()
            rows = device_rows(seen, self.names(), self.cfg.quiet_min_rssi_dbm, leader_router=self.leader_router())
            return {"devices": select_devices(rows, dominant_pan(seen, self.cfg.pan_id), query.get("only", ""),
                                              query.get("sort", "name"))}
        if path.startswith("/api/device/"):
            names = self.names()
            try:
                addrs, name = names.resolve(unquote(path[len("/api/device/"):]).strip())
            except ValueError as exc:
                return {"error": str(exc)}
            eps = devices_history(self.cfg.events_dir, addrs)
            for ep in eps:
                ep.pop("events", None)
            seen = self.seen()
            table = seen.table
            # addr and last_seen describe the live address (the shape
            # sensors were written against); the per-address rows of a
            # device whose address rotates are beside it.
            primary = live_address(addrs, table)
            live = next((r for r in device_rows(seen, names, self.cfg.quiet_min_rssi_dbm,
                                                leader_router=self.leader_router())
                         if r["addr"] == primary), {})
            return {"addr": primary, "addresses": addrs, "name": name if name != addrs[0] else None,
                    "live": {k: live.get(k) for k in ("role", "rloc16", "rloc16_ts", "router_id",
                                                      "leader", "parent", "parent_addr", "border_router",
                                                      "rotated_to")},
                    "last_seen": table.get(primary),
                    "addresses_seen": {a: table.get(a) for a in addrs}, "episodes": eps}
        if path == "/api/days":
            return {"days": day_index(self.cfg.events_dir)}
        return None

    # --------------------------------------------------------- routing

    def respond(self, path: str, query_string: str = "") -> tuple[int, str, bytes]:
        """(status, content-type, body) for a request path."""
        if len(path) > 1:
            path = path.rstrip("/")   # /devices/ and /day/2026-09-02/ are the same pages
        query = {k: v[-1] for k, v in parse_qs(query_string).items()}
        if path.startswith("/api/"):
            data = self.api(path, query)
            if data is None:
                return 404, "application/json", b'{"error": "not found"}'
            status = 404 if "error" in data else 200
            return status, "application/json", json.dumps(data, indent=1).encode()
        if path in ("/", "/day"):
            return 200, "text/html; charset=utf-8", self.day_page(today(), query.get("min", "")).encode()
        if path.startswith("/day/"):
            day = path[len("/day/"):]
            if not valid_day(day):
                return 404, "text/plain", b"bad day"
            return 200, "text/html; charset=utf-8", self.day_page(day, query.get("min", "")).encode()
        if path == "/devices":
            return 200, "text/html; charset=utf-8", self.devices_page(
                query.get("only", ""), query.get("sort", "name")).encode()
        if path == "/help":
            return 200, "text/html; charset=utf-8", self.help_page().encode()
        if path == "/status":
            return 200, "text/html; charset=utf-8", self.status_page().encode()
        if path == "/incidents":
            return 200, "text/html; charset=utf-8", self.incidents_page().encode()
        if path.startswith("/device/"):
            target = unquote(path[len("/device/"):]).strip()
            if not target or len(target) > 100:
                return 404, "text/plain", b"bad device"
            body = self.device_page(target)
            return (404 if "<h1>no such device</h1>" in body else 200), "text/html; charset=utf-8", body.encode()
        return 404, "text/plain", b"not found"


def make_server(cfg, bind: str, port: int) -> ThreadingHTTPServer:
    site = Site(cfg)

    class Handler(BaseHTTPRequestHandler):
        server_version = "threadwatch"

        def do_GET(self):
            try:
                url = urlparse(self.path)
                status, ctype, body = site.respond(url.path, url.query)
            except Exception as exc:  # a page bug is a 500, never a dead server
                status, ctype, body = 500, "text/plain", f"error: {type(exc).__name__}: {exc}".encode()
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            pass

    ThreadingHTTPServer.allow_reuse_address = True
    return ThreadingHTTPServer((bind, port), Handler)


def serve(cfg, bind: str = "0.0.0.0", port: int = 8080) -> None:
    httpd = make_server(cfg, bind, port)
    state = cfg.state_dir
    print(f"[threadwatch] web: http://{bind}:{httpd.server_port}/ (state {state})"
          + ("" if state.is_dir() else ": does not exist yet, so the pages are empty until "
                                       "threadwatch capture has started"), flush=True)
    # In the container this process is PID 1, which the kernel does not
    # deliver a default-action signal to: without a handler, stop is ignored.
    # shutdown() must not run on the thread inside serve_forever, or it
    # blocks waiting for a loop that cannot proceed.
    signal.signal(signal.SIGTERM,
                  lambda *_: threading.Thread(target=httpd.shutdown, daemon=True).start())
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
