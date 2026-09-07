"""Alert sinks and liveness heartbeats.

threadwatch deliberately knows nothing about any particular notification or
monitoring service. Two generic sink types cover nearly everything:

* ``http``    - POST (or any method) to a URL with optional headers and an
                optional body template. Without a template the raw event
                record is sent as JSON, which is what Home Assistant's
                webhook trigger and most generic receivers expect. With a
                template the body can take whatever shape the receiver
                wants (ntfy, Gotify, Discord, Slack, Pushover, ...).
* ``command`` - run a local program with the event record on stdin. The
                escape hatch for anything HTTP cannot reach.

``ntfy`` is offered as a convenience preset that expands into an ``http``
sink; it adds no code path of its own.

Heartbeats are the same idea in reverse: while capture is healthy, hit a URL
every ``interval_s`` so an external monitor (Gatus, Healthchecks.io, Uptime
Kuma, Cronitor, ...) can page when the recorder itself goes silent.

Secrets never belong in config.toml. Any string value in a sink or heartbeat
definition may reference an environment variable as ``${NAME}``; the systemd
unit loads ``config/alerts.env`` for that purpose. A sink whose variables are
unset is disabled with a warning rather than crashing the recorder.

A sink's cooldown is per event name: the first device_quiet pages at once,
and further device_quiet records inside ``cooldown_s`` are held back. When
the window ends, everything held back goes out as one *digest* record (same
event name, ``digest = true``, ``count``, the names in ``note``), so a second
failure never vanishes from the phone and a mesh-wide outage costs two
messages rather than one per device.

A sink may also take only some event names (``events``, an allowlist) or all
but some (``ignore_events``). The filter is applied before the severity floor
opens a cooldown window, so a filtered-out name never appears in a digest
either. This is how one phone hears about a dead device and a storm while a
chat channel or the review pages get every warning.

Templates use Python ``str.format`` field syntax over the event record plus a
few derived fields (see ``TEMPLATE_FIELDS``). Missing fields render as empty
strings. When the sink's Content-Type is JSON, substituted values are
JSON-escaped so a device name containing a quote cannot break the document.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import string
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any, Callable

SEVERITIES = ("info", "notice", "warning", "critical")

# Every event name the recorder emits (the table in docs/ALERTING.md; a test
# keeps the two in step). Sink filters are checked against it so that a typo
# is a journal line rather than a page that keeps coming.
KNOWN_EVENTS = frozenset((
    "device_first_seen", "device_returned", "join_scan_activity", "possible_foreign_pan",
    "dominant_pan_changed", "configured_pan_silent", "mle_rejoin_attempt", "device_quiet",
    "poll_starvation", "poll_answered", "rssi_degradation", "rssi_recovered",
    "retransmission_elevation", "partition_or_leader_change", "credentials_stale", "clock_step",
    "border_router_address_changed", "border_router_unlisted", "phase_locked_storm",
    "snapshot_saved", "snapshot_failed", "snapshot_skipped", "snapshots_pruned",
    "daily_summary", "alert_test", "recorder_started",
    "address_flood",
))

TEMPLATE_FIELDS = {
    "id": "a stable id for the record: the same on every retry, for receivers that dedupe",
    "event": "event name, e.g. device_quiet",
    "severity": "info | notice | warning | critical",
    "severity_index": "0..3 in the order above",
    "severity_value": "severity mapped through the sink's severity_values table",
    "ts": "unix timestamp (float)",
    "time": "local time, YYYY-MM-DD HH:MM:SS",
    "name": "device name when the event concerns one device, else empty",
    "addr": "device extended address when present, else empty",
    "who": "name when known, else addr, else empty",
    "note": "detector's free-text hint when present, else empty",
    "summary": "one-line human summary: event, device, note",
    "record_json": "the whole event record as a JSON document",
    "hostname": "capture host name",
    "count": "digest records only: how many suppressed events it stands for",
}

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(Exception):
    pass


# ----------------------------------------------------------------- helpers

def expand_env(value: Any, missing: set[str], found: set[str] | None = None) -> Any:
    """Expand ${VAR} references in strings (recursively through dict/list).

    Names of unset variables are collected into ``missing`` and left in place,
    so the caller can decide to disable the sink with a clear message. The
    values that were substituted are collected into ``found`` when it is
    given: those are the secrets alerts.env holds, and knowing them is
    what lets a failure be logged without them (_redact_text).
    """
    if isinstance(value, str):
        def _sub(m):
            v = os.environ.get(m.group(1))
            if v is None:
                missing.add(m.group(1))
                return m.group(0)
            if found is not None:
                found.add(v)
            return v
        return _ENV_REF.sub(_sub, value)
    if isinstance(value, dict):
        return {k: expand_env(v, missing, found) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v, missing, found) for v in value]
    return value


class _Fields(dict):
    """format_map source: unknown fields render as ''. Optional JSON escaping."""

    def __init__(self, data: dict, json_escape: bool):
        super().__init__(data)
        self.json_escape = json_escape

    def __missing__(self, key):
        return ""

    def __getitem__(self, key):
        v = super().__getitem__(key)
        if v is None:
            v = ""
        elif isinstance(v, (dict, list)):
            v = json.dumps(v)
        else:
            v = str(v)
        if self.json_escape:
            v = json.dumps(v)[1:-1]
        return v


def template_fields(record: dict, severity_values: dict | None = None) -> dict:
    sev = record.get("severity", "info")
    idx = SEVERITIES.index(sev) if sev in SEVERITIES else 0
    name = record.get("name") or ""
    addr = record.get("addr") or record.get("src") or ""
    who = name or addr
    parts = [record.get("event", "")]
    if who:
        parts.append(who)
    if record.get("note"):
        parts.append(record["note"])
    out = dict(record)
    out.update({
        "id": record.get("id") or record_id(record),      # a record from before ids: the same one it would have
        "severity_index": idx,
        "severity_value": _severity_value(sev, idx, severity_values or {}),
        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(record.get("ts", time.time()))),
        "name": name,
        "addr": addr,
        "who": who,
        "note": record.get("note") or "",
        "summary": " - ".join(str(p) for p in parts),
        "record_json": json.dumps(record),
        "hostname": os.uname().nodename if hasattr(os, "uname") else "",
    })
    return out


def _severity_value(sev: str, idx: int, table: dict):
    """The sink's value for a severity. One missing from a partial table takes
    the value of the nearest lower severity listed, else the lowest listed:
    templates splice this unquoted, so falling back to the name would make
    invalid JSON (the Gotify recipe with a lowered floor)."""
    if sev in table:
        return table[sev]
    if not table:
        return sev
    lower = [s for s in SEVERITIES[:idx] if s in table]
    return table[lower[-1]] if lower else table[min(table, key=_severity_index)]


def render(template: str, record: dict, json_escape: bool,
           severity_values: dict | None = None) -> str:
    fields = _Fields(template_fields(record, severity_values), json_escape)
    return string.Formatter().vformat(template, (), fields)


def _severity_index(name: str, default: int = 2) -> int:
    return SEVERITIES.index(name) if name in SEVERITIES else default


def _min_severity(raw, sink: str) -> int:
    """A sink's floor, by name. An unrecognised name used to fall back to
    warning without a word, so a typo ("notce", "Notice", "warn") raised
    the floor and every notice the operator asked for was dropped, with
    alert-test still saying ok. A typo in an event filter is logged for
    the same reason; a floor that is wrong is worse, so it is refused."""
    name = str(raw)
    if name not in SEVERITIES:
        raise ConfigError(f"alert sink '{sink}': min_severity must be one of {', '.join(SEVERITIES)}, "
                          f"not {raw!r}")
    return SEVERITIES.index(name)


# ------------------------------------------------------------------- sinks

def record_id(record: dict) -> str:
    """A stable id for a record: the same event at the same stamp about the
    same address has the same id however many times it is sent, so a
    receiver that keeps what it has seen (a webhook with a store, an
    automation keyed on it) can drop a retry of a page that did arrive.
    Twelve hex digits of a SHA-1 over stamp, event and address."""
    key = (f"{float(record.get('ts') or 0):.3f}|{record.get('event', '')}|"
           f"{record.get('addr') or record.get('src') or ''}")
    return hashlib.sha1(key.encode()).hexdigest()[:12]


def digest_record(event: str, records: list[dict], cooldown_s: float, now: float) -> dict:
    """One record standing in for the events a cooldown held back."""
    labels: list[str] = []
    for r in records:
        who = r.get("name") or r.get("addr") or r.get("src")
        if who and who not in labels:
            labels.append(who)
    severity = max((r.get("severity", "info") for r in records), key=_severity_index)
    shown = ", ".join(labels[:6]) + (f", +{len(labels) - 6} more" if len(labels) > 6 else "")
    window = f"{cooldown_s / 60:.0f} min" if cooldown_s >= 60 else f"{cooldown_s:.0f} s"
    n = len(records)
    out = {"ts": now, "event": event, "severity": severity, "digest": True, "count": n,
           "name": f"{n} more", "addr": None,
           "note": f"{n} more {event} in the {window} after the last page" + (f": {shown}" if shown else ""),
           "first_ts": records[0].get("ts"), "last_ts": records[-1].get("ts")}
    out["id"] = record_id(out)
    return out


@dataclass
class Sink:
    name: str
    min_severity: int = 2          # warning
    cooldown_s: float = 300.0      # per event name, per sink
    timeout_s: float = 10.0
    # Which event names this sink takes: an allowlist (None = every name), then
    # a denylist. Checked before the cooldown, so a name a sink does not want
    # never opens a window and never appears in a digest.
    events: frozenset | None = None
    ignore_events: frozenset = frozenset()
    # The values ${VAR} expansion put into this sink's definition, so that
    # what a failing send prints can be logged without them. Never in the
    # repr: a sink turns up in exception text and in test output.
    secrets: tuple = field(default=(), repr=False)
    _last: dict = field(default_factory=dict)      # event -> start of its current window
    _pending: dict = field(default_factory=dict)   # event -> records held back this window
    # event -> start of the window its pending records were held in. A
    # page that arrives at the window's end before the dispatcher has
    # collected the digest opens the next window (_last moves on); the
    # batch's deadline stays with the window it was held in, or each such
    # page pushed the same batch back another cooldown.
    _since: dict = field(default_factory=dict)
    # Held while a send is in flight: a sink that has not answered is not
    # sent to again until it has (see _bounded).
    _inflight: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def takes_event(self, event: str) -> bool:
        """The event filter alone: is this name one the sink is for?"""
        if self.events is not None and event not in self.events:
            return False
        return event not in self.ignore_events

    def wants(self, record: dict, now: float, ignore_cooldown: bool = False) -> bool:
        if _severity_index(record.get("severity", "info"), 0) < self.min_severity:
            return False
        ev = record.get("event", "")
        if not self.takes_event(ev):
            return False
        if ignore_cooldown:
            return True
        # The window is judged on elapsed time within it: a wall clock
        # stepped back (NTP correcting a Pi that booted on its saved time)
        # puts now before the window's start, and that used to read as
        # "inside the cooldown" for the length of the step, with the
        # cooldown disabled as much as not. A window that starts in the
        # future is over.
        elapsed = now - self._last.get(ev, 0.0)
        if 0.0 <= elapsed < self.cooldown_s:
            self._pending.setdefault(ev, []).append(record)
            self._since.setdefault(ev, self._last.get(ev, 0.0))
            return False
        self._last[ev] = now
        return True

    def _held_since(self, ev: str) -> float:
        return self._since.get(ev, self._last.get(ev, 0.0))

    def next_digest_at(self, now: float | None = None) -> float | None:
        """When the earliest window with held-back records ends, or None.
        A window that began after ``now`` (the clock stepped back) ends now."""
        if not self._pending:
            return None
        now = time.time() if now is None else now
        return min(now if self._held_since(ev) > now else self._held_since(ev) + self.cooldown_s
                   for ev in self._pending)

    def due_digests(self, now: float, all_pending: bool = False) -> list[dict]:
        """Digests for windows that have ended; each opens the next window.
        ``all_pending`` closes every window now (the process is leaving)."""
        out = []
        for ev in list(self._pending):
            elapsed = now - self._held_since(ev)
            if all_pending or elapsed < 0.0 or elapsed >= self.cooldown_s:
                records = self._pending.pop(ev)
                self._since.pop(ev, None)
                self._last[ev] = now
                out.append(digest_record(ev, records, self.cooldown_s, now))
        return out

    def send(self, record: dict) -> None:   # raises on failure
        raise NotImplementedError

    def describe(self) -> str:
        return f"{self.name}"


@dataclass
class HttpSink(Sink):
    url: str = ""
    method: str = "POST"
    headers: dict = field(default_factory=dict)
    body: str | None = None                     # template; None = raw record
    severity_values: dict = field(default_factory=dict)

    def __post_init__(self):
        # Normalise header names once so Content-Type lookups are reliable.
        self.headers = {str(k): str(v) for k, v in self.headers.items()}
        if not any(k.lower() == "content-type" for k in self.headers):
            self.headers["Content-Type"] = "application/json"

    @property
    def content_type(self) -> str:
        for k, v in self.headers.items():
            if k.lower() == "content-type":
                return v
        return "application/json"

    def payload(self, record: dict) -> bytes:
        if self.body is None:
            return json.dumps(record).encode()
        is_json = "json" in self.content_type.lower()
        return render(self.body, record, is_json, self.severity_values).encode()

    def send(self, record: dict) -> None:
        headers = dict(self.headers)
        # The same key on every retry of one record, so a receiver that
        # dedupes on it does not show the alert twice when a slow answer
        # made us send again.
        if record.get("id") and not any(k.lower() == "idempotency-key" for k in headers):
            headers["Idempotency-Key"] = str(record["id"])
        req = urllib.request.Request(self.url, data=self.payload(record),
                                     headers=headers, method=self.method)
        with _urlopen(req, timeout=self.timeout_s) as resp:
            resp.read()

    def describe(self) -> str:
        return f"{self.name}: {self.method} {_redact_url(self.url)}"


@dataclass
class CommandSink(Sink):
    command: list = field(default_factory=list)

    def send(self, record: dict) -> None:
        env = dict(os.environ)
        env["THREADWATCH_EVENT"] = record.get("event", "")
        env["THREADWATCH_SEVERITY"] = record.get("severity", "")
        env["THREADWATCH_SUMMARY"] = template_fields(record)["summary"]
        subprocess.run(self.command, input=json.dumps(record).encode(),
                       env=env, timeout=self.timeout_s, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def describe(self) -> str:
        # The program only: the arguments have had ${VAR} expanded by then,
        # and a token passed on the command line is the usual way to
        # authenticate curl. The journal is not the place for it.
        rest = len(self.command) - 1
        return f"{self.name}: {shlex.quote(self.command[0]) if self.command else '<command>'}" \
            + (f" (+{rest} args)" if rest > 0 else "")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse 3xx answers. urlopen follows them by default and re-sends the
    request's headers, Authorization included, to wherever Location points,
    another host or not: whoever answers a sink or heartbeat URL (its
    operator, a MITM on a plain-http one, a DNS race for its name) could
    collect the bearer token with one 302. None of the supported targets
    answers a webhook with a redirect, so a 3xx is reported as the HTTP
    error it is and the token stays with the configured host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(_NoRedirect())


def _urlopen(req: urllib.request.Request, timeout: float):
    return _opener.open(req, timeout=timeout)


def _redact_url(url: str) -> str:
    """Scheme and host only for log output: Discord, Healthchecks, Uptime
    Kuma, Cronitor and Home Assistant all carry the secret in the path,
    and Gotify, a basic-auth proxy or Uptime Kuma may carry it as
    user:password before the host."""
    parts = urllib.parse.urlsplit(url)
    if not parts.netloc:
        return "<url>"
    host = parts.netloc.rsplit("@", 1)[-1]
    dropped = parts.path not in ("", "/") or parts.query or host != parts.netloc
    return f"{parts.scheme}://{host}{'/...' if dropped else ''}"


# ----------------------------------------------------------------- presets

def _ntfy_preset(raw: dict) -> dict:
    """Expand ``type = "ntfy"`` into an http sink using ntfy's JSON publish API."""
    server = raw.get("url", "").rstrip("/")
    topic = raw.get("topic", "")
    if not server or not topic:
        raise ConfigError("ntfy sink needs url and topic")
    headers = dict(raw.get("headers", {}))
    if raw.get("token"):
        headers["Authorization"] = f"Bearer {raw['token']}"
    body = {
        "topic": topic,
        "title": raw.get("title", "{event}: {who}"),
        "message": raw.get("message", "{note}"),
        "priority": "__PRIORITY__",
        "tags": raw.get("tags", ["{event}"]),
    }
    # The document's own braces must be doubled for str.format; the user's
    # {field} placeholders inside the values stay single. ntfy wants priority
    # as an integer, so that template is spliced in unquoted.
    text = json.dumps(body)
    text = "{{" + text[1:-1] + "}}"
    text = text.replace('"__PRIORITY__"', "{severity_value}")
    out = {k: v for k, v in raw.items()
           if k in ("name", "min_severity", "cooldown_s", "timeout_s", "events", "ignore_events")}
    # A partial priority table falls back to the defaults for the rest;
    # the template splices the value unquoted, so an unmapped severity
    # would otherwise produce invalid JSON and a rejected publish.
    priority = {"info": 2, "notice": 3, "warning": 4, "critical": 5}
    priority.update(raw.get("priority", {}))
    out.update({
        "type": "http",
        "url": server,           # JSON publish goes to the server root
        "method": "POST",
        "headers": headers,
        "body": text,
        "severity_values": priority,
    })
    return out


PRESETS = {"ntfy": _ntfy_preset}


def _event_filter(raw: dict, key: str, name: str, log: Callable[[str], None]) -> frozenset | None:
    """``events`` / ``ignore_events``: a list of event names, or absent.

    A name the recorder never emits is almost certainly a typo, and a typo in
    a filter fails silently (the page you meant to stop keeps coming, or the
    one you meant to keep never does), so unknown names get a journal line.
    """
    if key not in raw:
        return None
    value = raw[key]
    if isinstance(value, str) or not isinstance(value, list) \
            or not all(isinstance(v, str) and v for v in value):
        raise ConfigError(f"alert sink '{name}': {key} must be a list of event names, "
                          f"like [\"device_quiet\", \"phase_locked_storm\"]")
    unknown = sorted(set(value) - KNOWN_EVENTS)
    if unknown:
        log(f"alert sink '{name}': {key} names event(s) the recorder does not emit: "
            f"{', '.join(unknown)} (see docs/ALERTING.md for the list)")
    return frozenset(value)


def build_sink(raw: dict, index: int, log: Callable[[str], None],
               unbuilt: list | None = None) -> Sink | None:
    """Turn one [[alerts.sinks]] table into a Sink, or None if disabled.
    A sink that is enabled but cannot be built (a ${VARIABLE} it names is
    not set) is logged and, when ``unbuilt`` is given, appended to it as
    (name, reason): alert-test counts those as failures, since an
    installation check that says "ok" with no recipient built is no check."""
    raw = dict(raw)
    kind = raw.get("type", "http")
    name = raw.get("name") or f"{kind}-{index}"
    raw["name"] = name
    if not raw.get("enabled", True):
        return None
    missing: set[str] = set()
    found: set[str] = set()
    raw = expand_env(raw, missing, found)
    if missing:
        reason = f"environment variable(s) not set: {', '.join(sorted(missing))} (see config/alerts.env)"
        log(f"alert sink '{name}' disabled: {reason}")
        if unbuilt is not None:
            unbuilt.append((name, reason))
        return None
    if kind in PRESETS:
        raw = PRESETS[kind](raw)
        kind = raw["type"]
    if "events" in raw and "ignore_events" in raw:
        raise ConfigError(f"alert sink '{name}': give events or ignore_events, not both")
    common = dict(
        name=name,
        min_severity=_min_severity(raw.get("min_severity", "warning"), name),
        cooldown_s=float(raw.get("cooldown_s", 300.0)),
        timeout_s=float(raw.get("timeout_s", 10.0)),
        events=_event_filter(raw, "events", name, log),
        ignore_events=_event_filter(raw, "ignore_events", name, log) or frozenset(),
        secrets=tuple(sorted(found, key=len, reverse=True)),
    )
    if kind == "http":
        if not raw.get("url"):
            raise ConfigError(f"alert sink '{name}': url is required")
        return HttpSink(url=str(raw["url"]), method=str(raw.get("method", "POST")).upper(),
                        headers=dict(raw.get("headers", {})), body=raw.get("body"),
                        severity_values={str(k): v for k, v in raw.get("severity_values", {}).items()},
                        **common)
    if kind == "command":
        cmd = raw.get("command")
        if isinstance(cmd, str):
            cmd = shlex.split(cmd)
        if not cmd:
            raise ConfigError(f"alert sink '{name}': command is required")
        return CommandSink(command=[str(c) for c in cmd], **common)
    raise ConfigError(f"alert sink '{name}': unknown type '{kind}'")


def _check_unique_names(kind: str, items) -> None:
    seen: set[str] = set()
    for it in items:
        if it.name in seen:
            raise ConfigError(f"two {kind}s are named '{it.name}'; give each its own name")
        seen.add(it.name)


def build_sinks(alerts_raw: dict, log: Callable[[str], None], unbuilt: list | None = None) -> list[Sink]:
    sinks: list[Sink] = []
    # Legacy single-webhook form, kept working as a shorthand.
    if alerts_raw.get("webhook_url"):
        missing: set[str] = set()
        url = expand_env(str(alerts_raw["webhook_url"]), missing)
        if missing:
            reason = f"environment variable(s) not set: {', '.join(sorted(missing))} (see config/alerts.env)"
            log(f"alert sink 'webhook' disabled: {reason}")
            if unbuilt is not None:
                unbuilt.append(("webhook", reason))
        else:
            sinks.append(HttpSink(name="webhook", url=url,
                                  min_severity=_min_severity(alerts_raw.get("min_severity", "warning"), "webhook")))
    for i, raw in enumerate(alerts_raw.get("sinks", []) or []):
        s = build_sink(raw, i, log, unbuilt)
        if s is not None:
            sinks.append(s)
    _check_unique_names("alert sink", sinks)
    return sinks


# -------------------------------------------------------------- dispatcher

# A send that failed is tried again after each of these delays, then every
# RETRY_CAP_S, until the record is STALE_S old. A router rebooting or ntfy
# restarting is minutes; a house network down with the mesh is hours; both
# end with the page delivered late rather than not at all. A record older
# than STALE_S when its turn comes is dropped and said so: a quiet alert
# from yesterday's outage is no longer news, and a daily summary least of
# all. What is still undelivered when the process leaves goes to the spool
# file in data/state, and the next start sends it.
RETRY_DELAYS_S = (30.0, 120.0, 480.0)
RETRY_CAP_S = 600.0
STALE_S = 6 * 3600.0
# A send that timed out had its request on the wire before any answer was
# due, so the receiver may already have it: the full schedule above would
# put forty copies of one alert on a phone over six hours, which is how
# people learn to mute a topic. One more try, then it is let go.
TIMEOUT_RETRIES = 1
SPOOL_FILE = "alert-spool.jsonl"
# The spool is renamed to this at load and removed only once every record
# in it has been delivered, given up or spooled again: a run that dies
# before then (a start-up failure right after the log is built, an OOM
# kill, a power cut) leaves the file for the next start, which loads it
# again. Used to be unlinked at load, with the records on the heap.
INFLIGHT_FILE = SPOOL_FILE + ".inflight"


class Dispatcher:
    """Delivers records to sinks from a background thread.

    Delivery never blocks the capture path and never raises: a dead
    endpoint costs a journal line, not frames, and the record is tried
    again with backoff (RETRY_DELAYS_S) until it is STALE_S old. The
    thread is a daemon and the capture process leaves through os._exit,
    so nothing waits for it by itself: ``close`` is how what it still
    holds (queued records, and the digests the cooldowns are holding
    back) reaches the phone before the process ends, and what a sink
    still refuses then is written to the spool for the next start. A
    mesh-wide outage is exactly what the digest is for, and it is also
    what puts the recorder into the watchdog restart loop that would
    otherwise discard it.
    """

    def __init__(self, sinks: list[Sink], log: Callable[[str], None], spool: Path | None = None,
                 retry_delays: tuple = RETRY_DELAYS_S, retry_cap_s: float = RETRY_CAP_S,
                 stale_s: float = STALE_S):
        self.sinks = sinks
        self.log = log
        self.spool = spool
        self.retry_delays, self.retry_cap_s, self.stale_s = retry_delays, retry_cap_s, stale_s
        # No retry is ever scheduled further ahead than this: an item due
        # later than that was scheduled before the clock stepped back, and
        # is due now rather than when the clock climbs back over the step.
        self._max_delay = max(retry_cap_s, *retry_delays) if retry_delays else retry_cap_s
        self._queue: list[dict] = []          # {record, sinks, attempt, due}
        self._undelivered: list[dict] = []    # for the spool: {record, sinks: [names], attempt}
        # The sends this pass has begun and not settled, one per sink, as
        # spoolable work: a digest is removed from its sink's held records
        # when it is built, so if it is only a local variable while the
        # send runs, a close that reaches its deadline mid-send takes it
        # with the process.
        self._inflight: list[dict] = []
        self._cv = threading.Condition()
        self._closing = False
        self._thread: threading.Thread | None = None
        self.delivered = 0
        self.given_up = 0
        self.resumed = 0
        self._inflight_spool: Path | None = None   # the loaded spool, kept until the queue drains
        if sinks:
            self._load_spool()
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="alert-dispatch")
            self._thread.start()

    def close(self, timeout: float = 15.0) -> None:
        """Deliver everything queued, send every held-back digest now, and
        stop the thread; returns after ``timeout`` at the latest (a sink
        that hangs must not keep the process from exiting). What a sink
        refused, and what the thread never got to, is spooled."""
        if self._thread is None:
            return
        with self._cv:
            self._closing = True
            self._cv.notify()
        self._thread.join(timeout)
        if self._thread.is_alive():
            # Parked in a send: whatever is still queued, and the record
            # in flight, would leave with the process.
            with self._cv:
                items = list(self._inflight) + self._queue
                self._undelivered.extend(self._spool_item(it) for it in items)
                self._queue.clear()
                self._inflight = []
            self._write_spool()
        self._drop_inflight_spool()

    def offer(self, record: dict) -> None:
        if not self.sinks:
            return
        now = time.time()
        with self._cv:
            targets = [s for s in self.sinks if s.wants(record, now)]
            if targets:
                self._queue.append({"record": record, "sinks": targets, "attempt": 0, "due": now})
            self._cv.notify()   # a held-back record changes the next digest time

    def deliver_now(self, record: dict, ignore_cooldown: bool = True) -> list[tuple[Sink, str | None]]:
        """Synchronous delivery for tests and `threadwatch alert-test`.

        Returns (sink, error-or-None) per eligible sink.
        """
        out = []
        for s in self.sinks:
            if not s.wants(record, time.time(), ignore_cooldown=ignore_cooldown):
                continue
            try:
                _bounded(s, partial(s.send, record), s.timeout_s, "send")
                out.append((s, None))
            except Exception as exc:
                out.append((s, _describe_error(exc, s.secrets)))
        return out

    def stats(self) -> dict:
        """For status.json: what this run has delivered, holds, and gave up."""
        with self._cv:
            queued = len(self._queue) + len(self._inflight)
            retrying = (sum(1 for it in self._queue if it["attempt"])
                        + sum(1 for it in self._inflight if it["attempt"]))
        return {"delivered": self.delivered, "queued": queued, "retrying": retrying,
                "given_up": self.given_up, "resumed": self.resumed}

    # ------------------------------------------------------------ thread

    def _due(self, item: dict, now: float) -> bool:
        return item["due"] <= now or item["due"] - now > self._max_delay

    def _next_due(self, now: float) -> float | None:
        times = [now if self._due(it, now) else it["due"] for it in self._queue]
        times += [t for t in (s.next_digest_at(now) for s in self.sinks) if t is not None]
        return min(times) if times else None

    def _run(self) -> None:
        while True:
            with self._cv:
                while not self._closing:
                    now = time.time()
                    if any(self._due(it, now) for it in self._queue):
                        break
                    if any(t is not None and t <= now for t in (s.next_digest_at(now) for s in self.sinks)):
                        break       # a cooldown window ended: send its digest
                    nxt = self._next_due(now)
                    self._cv.wait(timeout=None if nxt is None else max(0.05, nxt - now))
                now = time.time()
                item = None
                for i, it in enumerate(self._queue):
                    if self._closing or self._due(it, now):
                        item = self._queue.pop(i)
                        break
                last = self._closing and not self._queue
                digests = [(s, rec) for s in self.sinks for rec in s.due_digests(now, all_pending=last)]
                # One entry per delivery still owed, held where close() can
                # find it. The digests are already out of their sinks'
                # held records by now: this is the only place they exist.
                sends = [{"record": item["record"], "sinks": [s], "attempt": item["attempt"]}
                         for s in item["sinks"]] if item else []
                sends += [{"record": rec, "sinks": [s], "attempt": 0} for s, rec in digests]
                self._inflight = list(sends)
            for it in sends:
                s = it["sinks"][0]
                try:
                    _bounded(s, partial(s.send, it["record"]), s.timeout_s, "send")
                    self.delivered += 1
                except Exception as exc:
                    self._failed(s, it["record"], it, exc)
                finally:
                    # Settled either way: delivered, spooled by _failed, or
                    # queued again for a retry. It is no longer in flight.
                    with self._cv:
                        if it in self._inflight:
                            self._inflight.remove(it)
            with self._cv:
                self._inflight = []
                drained = not self._queue and self._inflight_spool is not None
            if last:
                self._write_spool()
                self._drop_inflight_spool()
                return
            if drained:
                self._drop_inflight_spool()

    def _failed(self, sink: Sink, record: dict, item: dict | None, exc: Exception) -> None:
        """A send that raised: try again later, spool it when the process
        is leaving, or give it up when the record is too old to be news."""
        err = _describe_error(exc, sink.secrets)
        attempt = (item["attempt"] if item else 0) + 1
        now = time.time()
        age = now - float(record.get("ts") or now)
        with self._cv:
            if _maybe_delivered(exc) and attempt > TIMEOUT_RETRIES:
                self.given_up += 1
                self.log(f"alert sink '{sink.name}' failed: {err}; not retried again (attempt {attempt}) "
                         "because the request was already sent and a retry would be a second notification")
                return
            if self._closing:
                self._undelivered.append({"record": record, "sinks": [sink.name], "attempt": attempt})
                self.log(f"alert sink '{sink.name}' failed: {err}; kept for the next start")
                return
            if age > self.stale_s:
                self.given_up += 1
                self.log(f"alert sink '{sink.name}' failed: {err}; given up, the record is "
                         f"{age / 3600:.1f} h old (attempt {attempt})")
                return
            delay = self.retry_delays[attempt - 1] if attempt <= len(self.retry_delays) else self.retry_cap_s
            self._queue.append({"record": record, "sinks": [sink], "attempt": attempt, "due": now + delay})
            self._cv.notify()
            self.log(f"alert sink '{sink.name}' failed: {err}; retrying in {delay:g} s (attempt {attempt})")

    # ------------------------------------------------------------- spool

    @staticmethod
    def _spool_item(item: dict) -> dict:
        return {"record": item["record"], "sinks": [s.name for s in item["sinks"]], "attempt": item["attempt"]}

    def _write_spool(self) -> None:
        if self.spool is None:
            return
        with self._cv:
            items = list(self._undelivered)
        if not items:
            return
        try:
            tmp = self.spool.with_suffix(".tmp")
            tmp.write_text("".join(json.dumps(it) + "\n" for it in items))
            tmp.replace(self.spool)
        except OSError as exc:
            self.log(f"alert spool not written: {exc}")
            self._inflight_spool = None     # keep the loaded file: it is the only copy left
            return
        self.log(f"alert spool: {len(items)} undelivered record(s) kept in {self.spool.name} for the next start")

    def _drop_inflight_spool(self) -> None:
        """The loaded spool has served: every record in it was delivered,
        given up, or written to a new spool."""
        path, self._inflight_spool = self._inflight_spool, None
        if path is not None:
            try:
                path.unlink()
            except OSError:
                pass

    def _load_spool(self) -> None:
        """What the last run could not deliver, offered again to the sinks
        it was for (by name: a sink since removed takes nothing), less
        what has gone stale meanwhile. The file is renamed, not removed,
        and stays until the queue drains (see INFLIGHT_FILE); what fails
        again this run is spooled again at this run's end. A leftover
        in-flight file from a run that died mid-delivery is loaded too."""
        if self.spool is None:
            return
        inflight = self.spool.with_name(INFLIGHT_FILE)
        lines: list[str] = []
        for path in (inflight, self.spool):
            if not path.exists():
                continue
            try:
                lines.extend(path.read_text().splitlines())
            except OSError as exc:
                self.log(f"alert spool not read: {exc}")
                return
        if not lines:
            return
        try:
            if self.spool.exists():
                if inflight.exists():
                    tmp = self.spool.with_suffix(".tmp")
                    tmp.write_text("".join(line + "\n" for line in lines))
                    tmp.replace(inflight)
                    self.spool.unlink()
                else:
                    self.spool.replace(inflight)
        except OSError as exc:
            self.log(f"alert spool not read: {exc}")
            return
        self._inflight_spool = inflight
        by_name = {s.name: s for s in self.sinks}
        now = time.time()
        stale = skipped = 0
        for line in lines:
            try:
                it = json.loads(line)
                record, names, attempt = it["record"], it["sinks"], int(it.get("attempt", 0))
            except (ValueError, KeyError, TypeError):
                skipped += 1
                continue
            targets = [by_name[n] for n in names if n in by_name]
            if not targets or not isinstance(record, dict):
                skipped += 1
                continue
            if now - float(record.get("ts") or now) > self.stale_s:
                stale += 1
                continue
            self._queue.append({"record": record, "sinks": targets, "attempt": attempt, "due": now})
            self.resumed += 1
        if not self._queue:
            self._drop_inflight_spool()     # nothing to send: stale or unreadable throughout
        if self.resumed or stale or skipped:
            self.log(f"alert spool: {self.resumed} record(s) the last run could not deliver, sending now"
                     + (f"; {stale} too old, dropped" if stale else "")
                     + (f"; {skipped} unreadable or for a sink no longer configured, dropped" if skipped else ""))


class SendInFlight(TimeoutError):
    """A previous send to this target has not been answered yet, so this
    record was never put on the wire. Unlike a deadline that expired with
    the request already out, retrying it cannot duplicate anything."""


def _bounded(target, call: Callable[[], Any], timeout_s: float, what: str) -> Any:
    """Run ``call`` (a send to ``target``) under a wall-clock deadline.

    urlopen's timeout bounds each socket operation, not the request: a
    remote that accepts the connection and then answers a byte at a time
    (an overloaded server behind a proxy, a captive portal) never trips
    it, and the thread parks there with every other sink and every queued
    record behind it, silently. So the call runs in a thread of its own;
    past the deadline it is left to finish or not and TimeoutError is
    raised. While it is still in flight another send to the same target
    is refused at once, rather than stacking one parked thread behind
    another.
    """
    lock = target._inflight
    if not lock.acquire(blocking=False):
        raise SendInFlight(f"the previous {what} has still not been answered")
    done = threading.Event()
    box: dict = {}

    def run():
        try:
            box["result"] = call()
        except BaseException as exc:
            box["exc"] = exc
        finally:
            lock.release()
            done.set()

    try:
        threading.Thread(target=run, daemon=True, name=f"{what}-{target.name}").start()
    except BaseException:
        # run() never executed, so nothing will ever release the lock. Under
        # thread or memory pressure start() raises RuntimeError, and without
        # this the sink is poisoned for the life of the process: every later
        # send fails the acquire above, _failed reads that as transient, and
        # the retries give up six hours later having delivered nothing.
        lock.release()
        raise
    if not done.wait(timeout_s):
        raise TimeoutError(f"no answer within {timeout_s:g} s")
    if "exc" in box:
        raise box["exc"]
    return box.get("result")


def _maybe_delivered(exc: BaseException) -> bool:
    """Did the receiver possibly get this record already? A deadline that
    expired means the request was on the wire long before any answer was
    due back: the notification may well have landed, and a retry is a
    second copy on somebody's phone rather than a redelivery. A refused
    connection, a name that does not resolve, an HTTP error status and a
    command that exited non-zero are all answers, and safe to retry."""
    if isinstance(exc, SendInFlight):
        return False                       # never put on the wire
    if isinstance(exc, subprocess.TimeoutExpired):
        return True
    if isinstance(exc, urllib.error.HTTPError):
        return False
    if isinstance(exc, urllib.error.URLError):
        exc = exc.reason if isinstance(exc.reason, BaseException) else exc
    return isinstance(exc, TimeoutError)


# A URL anywhere in free text, for _redact_text.
_URL_IN_TEXT = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s'\"<>|]+")
# An authentication credential written the way a program prints one: a
# header or a parameter whose name says what it carries, and the rest of
# that line with it (an Authorization value is "Bearer <token>", two
# words), or a bare scheme and its token. curl -v echoes the headers it
# sent; a script written for a sink prints whatever it likes.
_SECRET_KV = re.compile(r"(?i)\b([a-z0-9_.-]*(?:authorization|api[-_]?key|token|secret|"
                        r"password|passwd|auth)[a-z0-9_.-]*)(\s*[:=]\s*)[^\r\n]+")
_SECRET_SCHEME = re.compile(r"(?i)\b(bearer|basic|digest)\s+[^\s\r\n]+")
# Under this many characters, a value expanded from the environment is
# not scrubbed out of free text: a two-character one is a substring of
# ordinary words and would blank the diagnostic instead of the secret.
_SCRUB_MIN = 6


def _redact_text(text: str, secrets: tuple = ()) -> str:
    """Free text with what must not reach the journal taken out of it.

    Every URL is reduced to scheme and host, as describe() does for a
    configured one: a command sink's stderr is written by a program the
    operator chose - curl echoing the address it could not reach is the
    ordinary case - and for ntfy, Discord, Healthchecks, Uptime Kuma and
    Home Assistant the secret is the path. Credentials that are not URLs
    go too: the header shapes above, and the exact values ${VAR}
    expansion put into this sink's own definition (``secrets``), which is
    the only way to catch a token a program prints in a shape nobody can
    write a pattern for. The journal is the one output nobody thinks of
    as one, and it is pasted into issues."""
    text = _URL_IN_TEXT.sub(lambda m: _redact_url(m.group(0)), text)
    text = _SECRET_KV.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", text)
    text = _SECRET_SCHEME.sub(lambda m: f"{m.group(1)} <redacted>", text)
    for secret in secrets:
        if len(secret) >= _SCRUB_MIN:
            text = text.replace(secret, "<redacted>")
    return text


def _describe_error(exc: Exception, secrets: tuple = ()) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        err = _redact_text((exc.stderr or b"").decode(errors="replace").strip(), secrets)
        return f"exit {exc.returncode}" + (f": {err}" if err else "")
    if isinstance(exc, subprocess.TimeoutExpired):
        # Never str(exc): it quotes the whole argument list, and by then
        # ${VAR} expansion has put the real token into the arguments -
        # "curl -H Authorization: Bearer ..." is how a command sink
        # authenticates. What went wrong is the timeout, not the command.
        return f"timed out after {float(exc.timeout):g} s"
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    return _redact_text(f"{type(exc).__name__}: {exc}", secrets)


# -------------------------------------------------------------- heartbeats

@dataclass
class Heartbeat:
    name: str
    url: str
    interval_s: float = 60.0
    method: str = "POST"
    headers: dict = field(default_factory=dict)
    body: str | None = None
    failure_url: str | None = None     # hit instead of url when unhealthy
    timeout_s: float = 10.0
    _inflight: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def push(self, healthy: bool) -> bool:
        """Beat, or report the stall. Returns False when nothing was sent:
        an unhealthy capture with no failure_url stays silent, so the
        monitor's own timeout fires instead of a reassuring beat."""
        if healthy:
            url = self.url
        elif self.failure_url:
            url = self.failure_url
        else:
            return False
        data = self.body.encode() if self.body is not None else None
        headers = dict(self.headers)
        if data is not None and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "text/plain"
        req = urllib.request.Request(url, data=data, headers=headers, method=self.method)
        with _urlopen(req, timeout=self.timeout_s) as resp:
            resp.read()
        return True

    def describe(self) -> str:
        return f"{self.name}: {self.method} {_redact_url(self.url)} every {self.interval_s:.0f}s"


def build_heartbeats(raw_list: list, log: Callable[[str], None],
                     unbuilt: list | None = None) -> list[Heartbeat]:
    """The [[heartbeats]] tables as Heartbeats. ``unbuilt`` collects, as
    build_sink does, the enabled ones a missing ${VARIABLE} kept out."""
    out: list[Heartbeat] = []
    for i, raw in enumerate(raw_list or []):
        raw = dict(raw)
        name = raw.get("name") or f"heartbeat-{i}"
        if not raw.get("enabled", True):
            continue
        missing: set[str] = set()
        raw = expand_env(raw, missing)
        if missing:
            reason = f"environment variable(s) not set: {', '.join(sorted(missing))} (see config/alerts.env)"
            log(f"heartbeat '{name}' disabled: {reason}")
            if unbuilt is not None:
                unbuilt.append((name, reason))
            continue
        if not raw.get("url"):
            raise ConfigError(f"heartbeat '{name}': url is required")
        interval = float(raw.get("interval_s", 60.0))
        if interval < 10:
            raise ConfigError(f"heartbeat '{name}': interval_s must be at least 10")
        out.append(Heartbeat(name=name, url=str(raw["url"]), interval_s=interval,
                             method=str(raw.get("method", "POST")).upper(),
                             headers={str(k): str(v) for k, v in raw.get("headers", {}).items()},
                             body=raw.get("body"), failure_url=raw.get("failure_url"),
                             timeout_s=float(raw.get("timeout_s", 10.0))))
    # The runner schedules and reports by name; two beats sharing one
    # would collapse into a single timer and the second would never fire.
    _check_unique_names("heartbeat", out)
    return out


class HeartbeatRunner:
    """One daemon thread pushing every configured heartbeat on its own interval.

    ``healthy`` is polled at each push; it should be cheap and reflect whether
    frames are actually flowing, so a stalled capture stops (or flips) the
    heartbeat instead of lying to the monitor. None means "not known yet"
    (no frame heard this run): nothing is sent and the check repeats soon.
    """

    def __init__(self, beats: list[Heartbeat], healthy: Callable[[], bool],
                 log: Callable[[str], None], start: bool = True):
        self.beats = beats
        self.healthy = healthy
        self.log = log
        self._failing: set[str] = set()
        if beats and start:
            threading.Thread(target=self._run, daemon=True, name="heartbeat").start()

    def push_all(self, healthy: bool | None = None) -> list[tuple[Heartbeat, str | None]]:
        state = self.healthy() if healthy is None else healthy
        out = []
        if state is None:
            return out
        for b in self.beats:
            try:
                _bounded(b, partial(b.push, state), b.timeout_s, "heartbeat")
                out.append((b, None))
            except Exception as exc:
                out.append((b, _describe_error(exc)))
        return out

    def _run(self) -> None:
        # Deadlines are monotonic, never wall-clock. A Pi has no RTC and NTP
        # steps it minutes after boot: absolute time.time() deadlines left
        # every beat the length of a backward step in the future, and the
        # monitor paged that the recorder was down while it was recording
        # normally. Nothing here needs to know the date.
        due = {b.name: 0.0 for b in self.beats}
        while True:
            now = time.monotonic()
            state = self.healthy()
            for b in self.beats:
                if now < due[b.name]:
                    continue
                if state is None:      # nothing known yet: keep checking, send nothing
                    continue
                due[b.name] = now + b.interval_s
                try:
                    _bounded(b, partial(b.push, state), b.timeout_s, "heartbeat")
                    if b.name in self._failing:
                        self._failing.discard(b.name)
                        self.log(f"heartbeat '{b.name}' recovered")
                except Exception as exc:
                    if b.name not in self._failing:    # log the edge, not every miss
                        self._failing.add(b.name)
                        self.log(f"heartbeat '{b.name}' failed: {_describe_error(exc)}")
            time.sleep(min(5.0, max(0.5, min(due.values()) - time.monotonic())))
