"""Read-only review pages: what happened on a day, what a device has done.

Standard library only, server-rendered HTML, no JavaScript required. Runs
as its own process (``threadwatch web``) reading the state directory, so it
can never affect capture. No authentication: LAN or your own proxy.
"""

from __future__ import annotations

import html
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from .events import DAY_RE, day_of, next_day, prev_day
from .names import DeviceNames, LastSeen
from .review import (capture_for_day, day_episodes, day_index, days_available,
                     device_history, device_rows, fmt_duration, today)

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
table{border-collapse:collapse;width:100%;font-size:.94em}
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
     "The recorder heard nothing from the device for longer than its window (30 min by default, "
     "set per role in config.toml), then later heard it again. One row, with the real duration "
     "measured from the device's last frame. 'Still quiet' means it has not come back. A warning "
     "when the sniffer hears the device well; only a notice when its signal is marginal, because "
     "a device at the edge of the sniffer's range fades in and out without anything being wrong."),
    ("retransmissions", "Retransmissions elevated",
     "In one minute, more than 20% of data frames were repeats (same sender and sequence number "
     "within 2 s), and more than double the recent baseline. A repeat means the sender got no "
     "acknowledgement. One sender hammering one target is a bad link between those two (notice, "
     "logged only); retries spread across many devices is channel-wide contention or "
     "interference (warning), which is the early sign of a storm."),
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
        return DeviceNames(self.cfg.devices_path)

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
        crypto = "deep inspection on" if st.get("deep_inspection") else "header-level only"
        return (f'<header><a class="brand" href="/">threadwatch</a>'
                f'<nav><a href="/">today</a> &nbsp; <a href="/devices">devices</a> &nbsp; '
                f'<a href="/help">what these mean</a></nav>'
                f'<span class="status">{live}{storm} &middot; ch {esc(st.get("channel"))} &middot; '
                f'<b>{st.get("frames_total", 0):,}</b> frames &middot; {st.get("devices_tracked", 0)} devices '
                f'&middot; {crypto} &middot; up {fmt_duration(st.get("uptime_s", 0))}</span></header>')

    def page(self, title: str, body: str) -> str:
        return (f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
                f'<meta name="viewport" content="width=device-width,initial-scale=1">'
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

    def day_page(self, day: str) -> str:
        now = time.time()
        eps = day_episodes(self.cfg.events_dir, day, now)
        cap = capture_for_day(self.cfg.ring_dir, self.cfg.incidents_dir, day)
        avail = days_available(self.cfg.events_dir)
        first = avail[0] if avail else day
        nav = (f'<div class="daynav"><a href="/day/{prev_day(day)}">&larr; {prev_day(day)}</a>'
               f'<b>{esc(day)}</b>' + (f'<a href="/day/{next_day(day)}">{next_day(day)} &rarr;</a>'
                                        if day < today() else '<span class="muted">today</span>') + '</div>')
        if cap["ring_files"]:
            pk = f'<span class="ok">{len(cap["ring_files"])} hourly capture files still in the ring</span>'
        else:
            pk = '<span class="muted">packets for this day are gone from the ring</span>'
        if cap["incidents"]:
            pk += " &middot; frozen incidents: " + ", ".join(esc(i) for i in cap["incidents"])
        rows = []
        for ep in eps:
            span = ""
            if ep["count"] > 1:
                span = f' <span class="muted">x{ep["count"]}, {when(ep["start"], day)}-{when(ep["end"], day)}</span>'
            elif ep["kind"] == "quiet" and ep["end"]:
                span = f' <span class="muted">back {when(ep["end"], day)}</span>'
            who = ""
            if ep.get("addr") and len(ep["addr"]) == 16:   # older rejoin rows carry a short src
                who = f' <a class="muted" href="/device/{esc(ep["addr"])}">&#9656;</a>'
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
                 '<p class="empty">nothing logged this day</p>' if day >= first else
                 '<p class="empty">before the recorder\'s first day</p>')
        raw = (f'<details><summary>raw records</summary>'
               f'<p><a href="/api/day/{esc(day)}">JSON</a></p></details>')
        return self.page(day, f'<h1>{esc(day)}</h1>{nav}{self.strip(day)}'
                              f'<p class="muted">{pk}</p><h2>episodes</h2>{table}{raw}')

    def devices_page(self) -> str:
        now = time.time()
        names = self.names()
        rows = device_rows(self.seen(), names, self.cfg.quiet_min_rssi_dbm, now)
        st = self.status()
        dominant = None
        trs = []
        for r in rows:
            rec = r["reception"]
            rec_html = {"good": '<span class="ok">good</span>', "marginal": '<span class="warn">marginal</span>'}.get(rec, '<span class="muted">?</span>')
            silent = r["silent_for_s"]
            seen_html = f'<span class="{"bad" if silent > 1800 else ""}">{ago(r["last_seen"], now)}</span>'
            nm = esc(r["name"]) if r["name"] else f'<span class="warn">unknown</span>'
            trs.append(f'<tr><td><a href="/device/{esc(r["addr"])}">{nm}</a></td>'
                       f'<td class="muted">{esc(r["role"] or "")}</td>'
                       f'<td>{seen_html}</td>'
                       f'<td class="n">{esc(r["rssi_dbm"])}</td><td>{rec_html}</td>'
                       f'<td class="n">{r["frames"]:,}</td>'
                       f'<td class="muted"><code>{esc(r["addr"])}</code></td></tr>')
        unknown = sum(1 for r in rows if r["name"] is None)
        note = (f'<p class="muted">{len(rows)} addresses tracked'
                + (f', <span class="warn">{unknown} not in devices.json</span>' if unknown else "") + '.</p>')
        table = (f'<table><tr><th>device</th><th>role</th><th>last heard</th><th>rssi</th>'
                 f'<th>reception</th><th>frames</th><th>address</th></tr>{"".join(trs)}</table>')
        return self.page("devices", f'<h1>devices</h1>{note}{table}')

    def device_page(self, addr: str) -> str:
        now = time.time()
        addr = addr.lower()
        names = self.names()
        seen = self.seen()
        row = seen.table.get(addr)
        name = names.name(addr) or "unknown device"
        entry = names.by_addr.get(addr, {})
        facts = []
        if entry.get("model"):
            facts.append(esc(entry["model"]))
        if names.role(addr):
            facts.append(esc(names.role(addr)))
        if row:
            from .names import reception
            rec = reception(row.get("rssi"), self.cfg.quiet_min_rssi_dbm)
            facts.append(f'last heard {ago(row.get("last_seen"), now)}')
            facts.append(f'rssi {esc(row.get("rssi"))} dBm ({rec})')
            facts.append(f'{row.get("frames", 0):,} frames since {time.strftime("%Y-%m-%d", time.localtime(row.get("first_seen", now)))}')
        card = f'<div class="card"><code>{esc(addr)}</code><br>{" &middot; ".join(facts) if facts else "<span class=muted>never heard</span>"}</div>'
        eps = device_history(self.cfg.events_dir, addr, now)
        trs = []
        for ep in eps:
            day = time.strftime("%Y-%m-%d", time.localtime(ep["start"]))
            span = f' <span class="muted">x{ep["count"]}</span>' if ep["count"] > 1 else ""
            trs.append(f'<tr><td class="t"><a href="/day/{day}">{day}</a> {hm(ep["start"])}</td>'
                       f'<td><span class="sev {esc(ep["severity"])}">{esc(ep["severity"])}</span></td>'
                       f'<td>{esc(ep["title"])}{span}</td><td class="detail muted">{esc(ep["detail"])}</td></tr>')
        table = (f'<table><tr><th>when</th><th></th><th>what</th><th class="detail">detail</th></tr>{"".join(trs)}</table>'
                 if trs else '<p class="empty">no events for this device</p>')
        return self.page(name, f'<h1>{esc(name)}</h1>{card}<h2>history</h2>{table}'
                               f'<p><a class="muted" href="/api/device/{esc(addr)}">JSON</a></p>')

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

    def api(self, path: str):
        if path == "/api/status":
            return self.status()
        if path.startswith("/api/day/"):
            day = path[len("/api/day/"):]
            if not valid_day(day):
                return None
            eps = day_episodes(self.cfg.events_dir, day)
            for ep in eps:
                ep.pop("events", None)
            from .events import read_day
            return {"day": day, "episodes": eps, "records": read_day(self.cfg.events_dir, day),
                    "capture": capture_for_day(self.cfg.ring_dir, self.cfg.incidents_dir, day)}
        if path == "/api/devices":
            return {"devices": device_rows(self.seen(), self.names(), self.cfg.quiet_min_rssi_dbm)}
        if path.startswith("/api/device/"):
            addr = path[len("/api/device/"):].lower()
            eps = device_history(self.cfg.events_dir, addr)
            for ep in eps:
                ep.pop("events", None)
            return {"addr": addr, "name": self.names().name(addr), "role": self.names().role(addr),
                    "last_seen": self.seen().table.get(addr), "episodes": eps}
        if path == "/api/days":
            return {"days": day_index(self.cfg.events_dir)}
        return None

    # --------------------------------------------------------- routing

    def respond(self, path: str) -> tuple[int, str, bytes]:
        """(status, content-type, body) for a request path."""
        if path.startswith("/api/"):
            data = self.api(path)
            if data is None:
                return 404, "application/json", b'{"error": "not found"}'
            return 200, "application/json", json.dumps(data, indent=1).encode()
        if path in ("/", "/day", "/day/"):
            return 200, "text/html; charset=utf-8", self.day_page(today()).encode()
        if path.startswith("/day/"):
            day = path[len("/day/"):]
            if not valid_day(day):
                return 404, "text/plain", b"bad day"
            return 200, "text/html; charset=utf-8", self.day_page(day).encode()
        if path == "/devices":
            return 200, "text/html; charset=utf-8", self.devices_page().encode()
        if path == "/help":
            return 200, "text/html; charset=utf-8", self.help_page().encode()
        if path.startswith("/device/"):
            addr = path[len("/device/"):]
            if not (len(addr) == 16 and all(c in "0123456789abcdefABCDEF" for c in addr)):
                return 404, "text/plain", b"bad address"
            return 200, "text/html; charset=utf-8", self.device_page(addr).encode()
        return 404, "text/plain", b"not found"


def make_server(cfg, bind: str, port: int) -> ThreadingHTTPServer:
    site = Site(cfg)

    class Handler(BaseHTTPRequestHandler):
        server_version = "threadwatch"

        def do_GET(self):
            try:
                status, ctype, body = site.respond(urlparse(self.path).path)
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
    print(f"[threadwatch] web: http://{bind}:{httpd.server_port}/ (state {cfg.state_dir})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
