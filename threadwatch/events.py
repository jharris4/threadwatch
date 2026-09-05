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
import os
import re
import threading
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


def _close_partial_line(path: Path) -> None:
    """A record cut short by a kill or a power cut would otherwise swallow
    the next line appended after it, losing both."""
    if path.exists() and path.stat().st_size:
        with open(path, "rb+") as fh:
            fh.seek(-1, os.SEEK_END)
            if fh.read(1) != b"\n":
                fh.write(b"\n")


class EventLog:
    def __init__(self, events_dir: Path, sinks: Optional[list[Sink]] = None):
        self.dir = events_dir
        self.dispatcher = Dispatcher(sinks or [], _log)
        events_dir.mkdir(parents=True, exist_ok=True)
        migrate_legacy(events_dir)

    @property
    def sinks(self) -> list[Sink]:
        return self.dispatcher.sinks

    def close(self, timeout: float = 15.0) -> None:
        """Deliver what the sinks still hold (see Dispatcher.close); the
        capture daemon calls this on every way out."""
        self.dispatcher.close(timeout)

    def path_for(self, ts: float) -> Path:
        return self.dir / f"{day_of(ts)}.jsonl"

    def on_record(self, event: str, ts: float, addr: str) -> bool:
        """Is there a record of this event, at this stamp, for this address,
        in the log on disk? The recovery pass asks before trusting a flag
        the last run persisted about an event it may never have appended."""
        return any(r.get("event") == event and r.get("addr") == addr and r.get("ts") == ts
                   for r in read_day(self.dir, day_of(ts)))

    def emit(self, event: str, severity: str = "info", ts: Optional[float] = None,
             **fields) -> dict:
        record = {"ts": ts if ts is not None else time.time(),
                  "event": event, "severity": severity, **fields}
        path = self.path_for(record["ts"])
        _close_partial_line(path)
        with open(path, "a") as fh:
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

    def on_record(self, event: str, ts: float, addr: str) -> bool:
        return True       # nothing durable to reconcile against


# ------------------------------------------------------------------ reading

def migrate_legacy(events_dir: Path) -> int:
    """Split a pre-day-rolling ``events.jsonl`` (sibling of the events
    directory) into day files. Returns the number of records moved."""
    legacy = events_dir.parent / "events.jsonl"
    working = legacy.with_suffix(".jsonl.migrating")
    # Renamed before the split, so a run killed part-way leaves the
    # .migrating file for the next start; lines already copied are
    # recognised and skipped, so nothing is duplicated.
    if legacy.exists():
        legacy.rename(working)
    if not working.exists():
        return 0
    events_dir.mkdir(parents=True, exist_ok=True)
    moved = 0
    handles: dict[str, object] = {}
    present: dict[str, set] = {}
    try:
        for line in working.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                day = day_of(float(json.loads(line)["ts"]))
            except (ValueError, KeyError, TypeError, OverflowError):
                continue
            path = events_dir / f"{day}.jsonl"
            if day not in present:
                present[day] = set(path.read_text().splitlines()) if path.exists() else set()
                _close_partial_line(path)
                handles[day] = open(path, "a")
            if line in present[day]:
                continue
            handles[day].write(line + "\n")
            present[day].add(line)
            moved += 1
    finally:
        for fh in handles.values():
            fh.close()
    working.rename(legacy.with_suffix(".jsonl.migrated"))
    _log(f"event log: split {moved} legacy records into {len(handles)} day file(s)")
    return moved


def list_days(events_dir: Path) -> list[str]:
    """Days that have an event file, oldest first."""
    if not events_dir.exists():
        return []
    return sorted(p.stem for p in events_dir.glob("*.jsonl") if DAY_RE.match(p.stem))


_read_cache: dict[Path, tuple[tuple, list]] = {}   # path -> ((mtime, size), records)
_read_lock = threading.Lock()      # the cache is shared by every web request thread
# Day files the web process keeps parsed: the pages read a window of days
# around the one shown (review.EPISODE_WINDOW_DAYS either side), and a
# reader walking back through history must not keep every day it passed.
READ_CACHE_MAX = 128


def read_day(events_dir: Path, day: str) -> list[dict]:
    """Records of one day. Parsed files are cached by (mtime, size): the
    review pages read a window of days per request, and only today's file
    ever changes. The cache holds READ_CACHE_MAX files, oldest read first out."""
    path = events_dir / f"{day}.jsonl"
    try:
        st = path.stat()
    except OSError:
        return []
    stamp = (st.st_mtime_ns, st.st_size)
    with _read_lock:
        hit = _read_cache.get(path)
    if hit is not None and hit[0] == stamp:
        return list(hit[1])
    out = []
    for line in path.read_text().splitlines():      # the file is read outside the lock
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    # Insert and evict under the lock: the web server serves each request
    # on its own thread, and picking the oldest entry while another thread
    # inserts or deletes raised mid-iteration.
    with _read_lock:
        _read_cache.pop(path, None)
        _read_cache[path] = (stamp, out)
        while len(_read_cache) > READ_CACHE_MAX:
            del _read_cache[next(iter(_read_cache))]
    return list(out)


def prune_days(events_dir: Path, keep_days: int, now: Optional[float] = None) -> list[str]:
    """Delete day files older than ``keep_days`` local days (0: none), and
    return the days deleted. Nothing else bounds the event log: the ring
    has keep_files and keep_gb, and without this every incident freeze
    copies the whole history and a day page's window is the only thing
    keeping its cost flat."""
    if keep_days <= 0:
        return []
    cutoff = day_of((now if now is not None else time.time()) - keep_days * 86400)
    gone = []
    for day in list_days(events_dir):
        if day >= cutoff:
            break
        try:
            (events_dir / f"{day}.jsonl").unlink()
        except OSError:
            continue
        _read_cache.pop(events_dir / f"{day}.jsonl", None)
        gone.append(day)
    if gone:
        _log(f"event log: dropped {len(gone)} day file(s) older than {keep_days} days ({gone[0]} .. {gone[-1]})")
    return gone


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
