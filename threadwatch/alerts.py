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

Templates use Python ``str.format`` field syntax over the event record plus a
few derived fields (see ``TEMPLATE_FIELDS``). Missing fields render as empty
strings. When the sink's Content-Type is JSON, substituted values are
JSON-escaped so a device name containing a quote cannot break the document.
"""

from __future__ import annotations

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
from typing import Any, Callable, Optional

SEVERITIES = ("info", "notice", "warning", "critical")

TEMPLATE_FIELDS = {
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

def expand_env(value: Any, missing: set[str]) -> Any:
    """Expand ${VAR} references in strings (recursively through dict/list).

    Names of unset variables are collected into ``missing`` and left in place,
    so the caller can decide to disable the sink with a clear message.
    """
    if isinstance(value, str):
        def _sub(m):
            v = os.environ.get(m.group(1))
            if v is None:
                missing.add(m.group(1))
                return m.group(0)
            return v
        return _ENV_REF.sub(_sub, value)
    if isinstance(value, dict):
        return {k: expand_env(v, missing) for k, v in value.items()}
    if isinstance(value, list):
        return [expand_env(v, missing) for v in value]
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


def template_fields(record: dict, severity_values: Optional[dict] = None) -> dict:
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
           severity_values: Optional[dict] = None) -> str:
    fields = _Fields(template_fields(record, severity_values), json_escape)
    return string.Formatter().vformat(template, (), fields)


def _severity_index(name: str, default: int = 2) -> int:
    return SEVERITIES.index(name) if name in SEVERITIES else default


# ------------------------------------------------------------------- sinks

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
    return {"ts": now, "event": event, "severity": severity, "digest": True, "count": n,
            "name": f"{n} more", "addr": None,
            "note": f"{n} more {event} in the {window} after the last page" + (f": {shown}" if shown else ""),
            "first_ts": records[0].get("ts"), "last_ts": records[-1].get("ts")}


@dataclass
class Sink:
    name: str
    min_severity: int = 2          # warning
    cooldown_s: float = 300.0      # per event name, per sink
    timeout_s: float = 10.0
    _last: dict = field(default_factory=dict)      # event -> start of its current window
    _pending: dict = field(default_factory=dict)   # event -> records held back this window
    # Held while a send is in flight: a sink that has not answered is not
    # sent to again until it has (see _bounded).
    _inflight: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def wants(self, record: dict, now: float, ignore_cooldown: bool = False) -> bool:
        if _severity_index(record.get("severity", "info"), 0) < self.min_severity:
            return False
        if ignore_cooldown:
            return True
        ev = record.get("event", "")
        if now - self._last.get(ev, 0.0) < self.cooldown_s:
            self._pending.setdefault(ev, []).append(record)
            return False
        self._last[ev] = now
        return True

    def next_digest_at(self) -> Optional[float]:
        """When the earliest window with held-back records ends, or None."""
        if not self._pending:
            return None
        return min(self._last.get(ev, 0.0) + self.cooldown_s for ev in self._pending)

    def due_digests(self, now: float, all_pending: bool = False) -> list[dict]:
        """Digests for windows that have ended; each opens the next window.
        ``all_pending`` closes every window now (the process is leaving)."""
        out = []
        for ev in list(self._pending):
            if all_pending or now - self._last.get(ev, 0.0) >= self.cooldown_s:
                records = self._pending.pop(ev)
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
    body: Optional[str] = None                     # template; None = raw record
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
        req = urllib.request.Request(self.url, data=self.payload(record),
                                     headers=self.headers, method=self.method)
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
           if k in ("name", "min_severity", "cooldown_s", "timeout_s")}
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


def build_sink(raw: dict, index: int, log: Callable[[str], None]) -> Optional[Sink]:
    """Turn one [[alerts.sinks]] table into a Sink, or None if disabled."""
    raw = dict(raw)
    kind = raw.get("type", "http")
    name = raw.get("name") or f"{kind}-{index}"
    raw["name"] = name
    if not raw.get("enabled", True):
        return None
    missing: set[str] = set()
    raw = expand_env(raw, missing)
    if missing:
        log(f"alert sink '{name}' disabled: environment variable(s) not set: "
            f"{', '.join(sorted(missing))} (see config/alerts.env)")
        return None
    if kind in PRESETS:
        raw = PRESETS[kind](raw)
        kind = raw["type"]
    common = dict(
        name=name,
        min_severity=_severity_index(str(raw.get("min_severity", "warning"))),
        cooldown_s=float(raw.get("cooldown_s", 300.0)),
        timeout_s=float(raw.get("timeout_s", 10.0)),
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


def build_sinks(alerts_raw: dict, log: Callable[[str], None]) -> list[Sink]:
    sinks: list[Sink] = []
    # Legacy single-webhook form, kept working as a shorthand.
    if alerts_raw.get("webhook_url"):
        missing: set[str] = set()
        url = expand_env(str(alerts_raw["webhook_url"]), missing)
        if missing:
            log(f"alert sink 'webhook' disabled: environment variable(s) not set: "
                f"{', '.join(sorted(missing))} (see config/alerts.env)")
        else:
            sinks.append(HttpSink(name="webhook", url=url,
                                  min_severity=_severity_index(str(alerts_raw.get("min_severity", "warning")))))
    for i, raw in enumerate(alerts_raw.get("sinks", []) or []):
        s = build_sink(raw, i, log)
        if s is not None:
            sinks.append(s)
    _check_unique_names("alert sink", sinks)
    return sinks


# -------------------------------------------------------------- dispatcher

class Dispatcher:
    """Delivers records to sinks from a background thread.

    Delivery never blocks the capture path and never raises: a dead endpoint
    costs one log line, not frames. The thread is a daemon and the capture
    process leaves through os._exit, so nothing waits for it by itself:
    ``close`` is how what it still holds (queued records, and the digests
    the cooldowns are holding back) reaches the phone before the process
    ends. A mesh-wide outage is exactly what the digest is for, and it is
    also what puts the recorder into the watchdog restart loop that would
    otherwise discard it.
    """

    def __init__(self, sinks: list[Sink], log: Callable[[str], None]):
        self.sinks = sinks
        self.log = log
        self._queue: list[dict] = []
        self._cv = threading.Condition()
        self._closing = False
        self._thread: Optional[threading.Thread] = None
        if sinks:
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="alert-dispatch")
            self._thread.start()

    def close(self, timeout: float = 15.0) -> None:
        """Deliver everything queued, send every held-back digest now, and
        stop the thread; returns after ``timeout`` at the latest (a sink
        that hangs must not keep the process from exiting)."""
        if self._thread is None:
            return
        with self._cv:
            self._closing = True
            self._cv.notify()
        self._thread.join(timeout)

    def offer(self, record: dict) -> None:
        if not self.sinks:
            return
        now = time.time()
        with self._cv:
            targets = [s for s in self.sinks if s.wants(record, now)]
            if targets:
                self._queue.append({"record": record, "sinks": targets})
            self._cv.notify()   # a held-back record changes the next digest time

    def deliver_now(self, record: dict, ignore_cooldown: bool = True) -> list[tuple[Sink, Optional[str]]]:
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
                out.append((s, _describe_error(exc)))
        return out

    def _run(self) -> None:
        while True:
            with self._cv:
                while not self._queue and not self._closing:
                    due = [t for t in (s.next_digest_at() for s in self.sinks) if t is not None]
                    timeout = max(0.05, min(due) - time.time()) if due else None
                    if not self._cv.wait(timeout=timeout):
                        break   # a cooldown window ended: send its digest
                item = self._queue.pop(0) if self._queue else None
                last = self._closing and not self._queue
                now = time.time()
                digests = [(s, rec) for s in self.sinks for rec in s.due_digests(now, all_pending=last)]
            sends = [(s, item["record"]) for s in item["sinks"]] if item else []
            for s, record in sends + digests:
                try:
                    _bounded(s, partial(s.send, record), s.timeout_s, "send")
                except Exception as exc:
                    self.log(f"alert sink '{s.name}' failed: {_describe_error(exc)}")
            if last:
                return


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
        raise TimeoutError(f"the previous {what} has still not been answered")
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

    threading.Thread(target=run, daemon=True, name=f"{what}-{target.name}").start()
    if not done.wait(timeout_s):
        raise TimeoutError(f"no answer within {timeout_s:g} s")
    if "exc" in box:
        raise box["exc"]
    return box.get("result")


def _describe_error(exc: Exception) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        err = (exc.stderr or b"").decode(errors="replace").strip()
        return f"exit {exc.returncode}" + (f": {err}" if err else "")
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    return f"{type(exc).__name__}: {exc}"


# -------------------------------------------------------------- heartbeats

@dataclass
class Heartbeat:
    name: str
    url: str
    interval_s: float = 60.0
    method: str = "POST"
    headers: dict = field(default_factory=dict)
    body: Optional[str] = None
    failure_url: Optional[str] = None     # hit instead of url when unhealthy
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


def build_heartbeats(raw_list: list, log: Callable[[str], None]) -> list[Heartbeat]:
    out: list[Heartbeat] = []
    for i, raw in enumerate(raw_list or []):
        raw = dict(raw)
        name = raw.get("name") or f"heartbeat-{i}"
        if not raw.get("enabled", True):
            continue
        missing: set[str] = set()
        raw = expand_env(raw, missing)
        if missing:
            log(f"heartbeat '{name}' disabled: environment variable(s) not set: "
                f"{', '.join(sorted(missing))} (see config/alerts.env)")
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

    def push_all(self, healthy: Optional[bool] = None) -> list[tuple[Heartbeat, Optional[str]]]:
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
        due = {b.name: 0.0 for b in self.beats}
        while True:
            now = time.time()
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
            time.sleep(min(5.0, max(0.5, min(due.values()) - time.time())))
