"""Append-only event log with severity-filtered alert dispatch.

Every detector and tracker emits events here; the log is the flight
recorder's annotation track. Severities: info < notice < warning < critical.

Records live in one JSON-lines file per local day, ``events/YYYY-MM-DD.jsonl``
under the state directory, so a day of history is one small file and the
review page can walk back in time by filename. (A single ``events.jsonl``
from before 2026-09-03 is split into day files on first start.)

Alert delivery is delegated to ``alerts.Dispatcher`` (background thread, one
or more sinks, per-sink severity floor and cooldown). The log itself never
blocks on the network and never raises because of it.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Iterator, Optional

from .alerts import SEVERITIES, Dispatcher, Sink  # noqa: F401  (re-exported)

DAY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _log(msg: str) -> None:
    print(f"[threadwatch] {msg}", flush=True)


def day_of(ts: float) -> str:
    """Local calendar day a timestamp belongs to."""
    return time.strftime("%Y-%m-%d", time.localtime(ts))


def day_bounds(day: str) -> tuple[float, float]:
    """Unix start and end of a local calendar day (DST-correct)."""
    start = time.mktime(time.strptime(day, "%Y-%m-%d"))
    nxt = time.mktime(time.strptime(next_day(day), "%Y-%m-%d"))
    return start, nxt


def next_day(day: str) -> str:
    t = time.mktime(time.strptime(day, "%Y-%m-%d")) + 36 * 3600
    return time.strftime("%Y-%m-%d", time.localtime(t))


def prev_day(day: str) -> str:
    t = time.mktime(time.strptime(day, "%Y-%m-%d")) - 12 * 3600
    return time.strftime("%Y-%m-%d", time.localtime(t))


class EventLog:
    def __init__(self, events_dir: Path, sinks: Optional[list[Sink]] = None):
        self.dir = events_dir
        self.dispatcher = Dispatcher(sinks or [], _log)
        events_dir.mkdir(parents=True, exist_ok=True)
        migrate_legacy(events_dir)

    @property
    def sinks(self) -> list[Sink]:
        return self.dispatcher.sinks

    def path_for(self, ts: float) -> Path:
        return self.dir / f"{day_of(ts)}.jsonl"

    def emit(self, event: str, severity: str = "info", ts: Optional[float] = None,
             **fields) -> dict:
        record = {"ts": ts if ts is not None else time.time(),
                  "event": event, "severity": severity, **fields}
        with open(self.path_for(record["ts"]), "a") as fh:
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


# ------------------------------------------------------------------ reading

def migrate_legacy(events_dir: Path) -> int:
    """Split a pre-day-rolling ``events.jsonl`` (sibling of the events
    directory) into day files. Returns the number of records moved."""
    legacy = events_dir.parent / "events.jsonl"
    if not legacy.exists():
        return 0
    events_dir.mkdir(parents=True, exist_ok=True)
    moved = 0
    handles: dict[str, object] = {}
    try:
        for line in legacy.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ts = json.loads(line)["ts"]
            except (ValueError, KeyError, TypeError):
                continue
            path = events_dir / f"{day_of(ts)}.jsonl"
            fh = handles.get(path.name)
            if fh is None:
                fh = handles[path.name] = open(path, "a")
            fh.write(line + "\n")
            moved += 1
    finally:
        for fh in handles.values():
            fh.close()
    legacy.rename(legacy.with_suffix(".jsonl.migrated"))
    _log(f"event log: split {moved} legacy records into {len(handles)} day file(s)")
    return moved


def list_days(events_dir: Path) -> list[str]:
    """Days that have an event file, oldest first."""
    if not events_dir.exists():
        return []
    return sorted(p.stem for p in events_dir.glob("*.jsonl") if DAY_RE.match(p.stem))


def read_day(events_dir: Path, day: str) -> list[dict]:
    path = events_dir / f"{day}.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def iter_days(events_dir: Path, first: Optional[str] = None,
              last: Optional[str] = None) -> Iterator[tuple[str, list[dict]]]:
    for day in list_days(events_dir):
        if first and day < first:
            continue
        if last and day > last:
            continue
        yield day, read_day(events_dir, day)


def read_all(events_dir: Path) -> list[dict]:
    out: list[dict] = []
    for _day, recs in iter_days(events_dir):
        out.extend(recs)
    return out
