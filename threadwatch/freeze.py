"""Preserve the ring buffer as an incident before it rolls over.

Used by `threadwatch freeze <label>` and, with [capture]
freeze_on_critical, by the pipeline itself the moment a critical event
fires. Copies every ring file plus the state files and the event log into
data/incidents/<stamp>_<label>. The file being written is copied as it
is; a partial last record at its tail is harmless (readers stop cleanly).
A ring file pruned while the copy runs is skipped, not fatal.
"""

from __future__ import annotations

import re
import shutil
import time
from pathlib import Path

STATE_FILES = ("status.json", "last-seen.json", "observed-names.json")
_LABEL = re.compile(r"[^A-Za-z0-9._-]+")


def freeze_ring(cfg, label: str = "incident", now: float | None = None) -> tuple[Path, int]:
    """Snapshot the ring. Returns (incident dir, ring files copied). The
    label is reduced to filename-safe characters."""
    label = _LABEL.sub("-", label.strip()).strip("-") or "incident"
    stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime(now or time.time()))
    dest = cfg.incidents_dir / f"{stamp}_{label}"
    dest.mkdir(parents=True, exist_ok=False)
    count = 0
    for f in sorted(cfg.ring_dir.glob("threadwatch-*.pcap")) if cfg.ring_dir.exists() else []:
        try:
            shutil.copy2(f, dest / f.name)
        except FileNotFoundError:
            # The ring rotated under us and pruned its oldest file between
            # the glob and the copy. That file was leaving anyway; the rest
            # of the snapshot is still worth having.
            continue
        count += 1
    for extra in STATE_FILES:
        src = cfg.state_dir / extra
        if src.exists():
            shutil.copy2(src, dest / extra)
    if cfg.events_dir.exists():
        shutil.copytree(cfg.events_dir, dest / "events", dirs_exist_ok=True)
    return dest, count
