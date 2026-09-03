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
import urllib.request
from dataclasses import dataclass, field
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
        "severity_value": (severity_values or {}).get(sev, sev),
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


def render(template: str, record: dict, json_escape: bool,
           severity_values: Optional[dict] = None) -> str:
    fields = _Fields(template_fields(record, severity_values), json_escape)
    return string.Formatter().vformat(template, (), fields)


def _severity_index(name: str, default: int = 2) -> int:
    return SEVERITIES.index(name) if name in SEVERITIES else default


# ------------------------------------------------------------------- sinks

@dataclass
class Sink:
    name: str
    min_severity: int = 2          # warning
    cooldown_s: float = 300.0      # per event name, per sink
    timeout_s: float = 10.0
    _last: dict = field(default_factory=dict)

    def wants(self, record: dict, now: float, ignore_cooldown: bool = False) -> bool:
        if _severity_index(record.get("severity", "info"), 0) < self.min_severity:
            return False
        if ignore_cooldown:
            return True
        ev = record.get("event", "")
        if now - self._last.get(ev, 0.0) < self.cooldown_s:
            return False
        self._last[ev] = now
        return True

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
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
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
        return f"{self.name}: {' '.join(shlex.quote(c) for c in self.command)}"


def _redact_url(url: str) -> str:
    """Hide query strings (some services carry tokens there) in log output."""
    return url.split("?", 1)[0] + ("?..." if "?" in url else "")


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
    out.update({
        "type": "http",
        "url": server,           # JSON publish goes to the server root
        "method": "POST",
        "headers": headers,
        "body": text,
        "severity_values": raw.get("priority",
                                   {"info": 2, "notice": 3, "warning": 4, "critical": 5}),
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


def build_sinks(alerts_raw: dict, log: Callable[[str], None]) -> list[Sink]:
    sinks: list[Sink] = []
    # Legacy single-webhook form, kept working as a shorthand.
    if alerts_raw.get("webhook_url"):
        sinks.append(HttpSink(name="webhook", url=str(alerts_raw["webhook_url"]),
                              min_severity=_severity_index(str(alerts_raw.get("min_severity", "warning")))))
    for i, raw in enumerate(alerts_raw.get("sinks", []) or []):
        s = build_sink(raw, i, log)
        if s is not None:
            sinks.append(s)
    return sinks


# -------------------------------------------------------------- dispatcher

class Dispatcher:
    """Delivers records to sinks from a background thread.

    Delivery never blocks the capture path and never raises: a dead endpoint
    costs one log line, not frames.
    """

    def __init__(self, sinks: list[Sink], log: Callable[[str], None]):
        self.sinks = sinks
        self.log = log
        self._queue: list[dict] = []
        self._cv = threading.Condition()
        self._thread: Optional[threading.Thread] = None
        if sinks:
            self._thread = threading.Thread(target=self._run, daemon=True,
                                            name="alert-dispatch")
            self._thread.start()

    def offer(self, record: dict) -> None:
        if not self.sinks:
            return
        now = time.time()
        targets = [s for s in self.sinks if s.wants(record, now)]
        if not targets:
            return
        with self._cv:
            self._queue.append({"record": record, "sinks": targets})
            self._cv.notify()

    def deliver_now(self, record: dict, ignore_cooldown: bool = True) -> list[tuple[Sink, Optional[str]]]:
        """Synchronous delivery for tests and `threadwatch alert-test`.

        Returns (sink, error-or-None) per eligible sink.
        """
        out = []
        for s in self.sinks:
            if not s.wants(record, time.time(), ignore_cooldown=ignore_cooldown):
                continue
            try:
                s.send(record)
                out.append((s, None))
            except Exception as exc:
                out.append((s, _describe_error(exc)))
        return out

    def _run(self) -> None:
        while True:
            with self._cv:
                while not self._queue:
                    self._cv.wait()
                item = self._queue.pop(0)
            for s in item["sinks"]:
                try:
                    s.send(item["record"])
                except Exception as exc:
                    self.log(f"alert sink '{s.name}' failed: {_describe_error(exc)}")


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

    def push(self, healthy: bool) -> None:
        url = self.url if healthy or not self.failure_url else self.failure_url
        data = self.body.encode() if self.body is not None else None
        headers = dict(self.headers)
        if data is not None and not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "text/plain"
        req = urllib.request.Request(url, data=data, headers=headers, method=self.method)
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            resp.read()

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
    return out


class HeartbeatRunner:
    """One daemon thread pushing every configured heartbeat on its own interval.

    ``healthy`` is polled at each push; it should be cheap and reflect whether
    frames are actually flowing, so a stalled capture stops (or flips) the
    heartbeat instead of lying to the monitor.
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
        for b in self.beats:
            try:
                b.push(state)
                out.append((b, None))
            except Exception as exc:
                out.append((b, _describe_error(exc)))
        return out

    def _run(self) -> None:
        due = {b.name: 0.0 for b in self.beats}
        while True:
            now = time.time()
            for b in self.beats:
                if now < due[b.name]:
                    continue
                due[b.name] = now + b.interval_s
                try:
                    b.push(self.healthy())
                    if b.name in self._failing:
                        self._failing.discard(b.name)
                        self.log(f"heartbeat '{b.name}' recovered")
                except Exception as exc:
                    if b.name not in self._failing:    # log the edge, not every miss
                        self._failing.add(b.name)
                        self.log(f"heartbeat '{b.name}' failed: {_describe_error(exc)}")
            time.sleep(min(5.0, max(0.5, min(due.values()) - time.time())))
