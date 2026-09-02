"""Append-only event log with severity-filtered alert dispatch.

Every detector and tracker emits events here; the log is the flight
recorder's annotation track. Severities: info < notice < warning < critical.

Alert delivery is delegated to ``alerts.Dispatcher`` (background thread, one
or more sinks, per-sink severity floor and cooldown). The log itself never
blocks on the network and never raises because of it.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from .alerts import SEVERITIES, Dispatcher, Sink  # noqa: F401  (re-exported)


def _log(msg: str) -> None:
    print(f"[threadwatch] {msg}", flush=True)


class EventLog:
    def __init__(self, path: Path, sinks: Optional[list[Sink]] = None):
        self.path = path
        self.dispatcher = Dispatcher(sinks or [], _log)
        path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def sinks(self) -> list[Sink]:
        return self.dispatcher.sinks

    def emit(self, event: str, severity: str = "info", ts: Optional[float] = None,
             **fields) -> dict:
        record = {"ts": ts if ts is not None else time.time(),
                  "event": event, "severity": severity, **fields}
        with open(self.path, "a") as fh:
            fh.write(json.dumps(record) + "\n")
        if severity in ("warning", "critical"):
            print(f"[threadwatch] {severity.upper()}: {event} {fields}", flush=True)
        self.dispatcher.offer(record)
        return record


class NullEventLog(EventLog):
    """Collects events in memory (replay/analysis) instead of file+sinks."""

    def __init__(self):
        self.records: list[dict] = []
        self.dispatcher = Dispatcher([], _log)

    def emit(self, event: str, severity: str = "info", ts: Optional[float] = None,
             **fields) -> dict:
        record = {"ts": ts if ts is not None else time.time(),
                  "event": event, "severity": severity, **fields}
        self.records.append(record)
        return record
