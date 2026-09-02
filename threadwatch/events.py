"""Append-only event log with severity-filtered webhook dispatch.

Every detector and tracker emits events here; the log is the flight
recorder's annotation track. Severities: info < notice < warning < critical.
"""

from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path
from typing import Optional

SEVERITIES = ("info", "notice", "warning", "critical")


class EventLog:
    def __init__(self, path: Path, webhook_url: str = "",
                 webhook_min_severity: str = "warning",
                 webhook_cooldown_s: float = 300.0):
        self.path = path
        self.webhook_url = webhook_url
        self.webhook_min = SEVERITIES.index(webhook_min_severity) \
            if webhook_min_severity in SEVERITIES else 2
        self.cooldown = webhook_cooldown_s
        self._last_webhook: dict[str, float] = {}
        path.parent.mkdir(parents=True, exist_ok=True)

    def emit(self, event: str, severity: str = "info", ts: Optional[float] = None,
             **fields) -> dict:
        record = {"ts": ts if ts is not None else time.time(),
                  "event": event, "severity": severity, **fields}
        with open(self.path, "a") as fh:
            fh.write(json.dumps(record) + "\n")
        if severity in ("warning", "critical"):
            print(f"[threadwatch] {severity.upper()}: {event} {fields}", flush=True)
        if (self.webhook_url
                and SEVERITIES.index(severity) >= self.webhook_min
                and time.time() - self._last_webhook.get(event, 0) >= self.cooldown):
            self._last_webhook[event] = time.time()
            self._post(record)
        return record

    def _post(self, record: dict) -> None:
        try:
            req = urllib.request.Request(
                self.webhook_url, data=json.dumps(record).encode(),
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as exc:   # alerting must never kill capture
            print(f"[threadwatch] webhook failed: {exc}", flush=True)


class NullEventLog(EventLog):
    """Collects events in memory (replay/analysis) instead of file+webhook."""

    def __init__(self):
        self.records: list[dict] = []

    def emit(self, event: str, severity: str = "info", ts: Optional[float] = None,
             **fields) -> dict:
        record = {"ts": ts if ts is not None else time.time(),
                  "event": event, "severity": severity, **fields}
        self.records.append(record)
        return record
