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

# border-routers.json is the hostname -> address history of every hub that
# rotates its address: without it an incident cannot name the border
# router on the very day it rebooted, the device most worth reading.
STATE_FILES = ("status.json", "last-seen.json", "observed-names.json", "frames-by-hour.json",
               "border-routers.json")
_LABEL = re.compile(r"[^A-Za-z0-9._-]+")
# A copy in progress is built under this directory, beside the finished
# incidents, and renamed into place only once whole. The capture daemon
# leaves through os._exit on every path, which unwinds nothing: a freeze it
# interrupts must not be findable as an incident (review.incidents lists
# only the incidents directory itself), and a leftover is discarded at the
# next start (discard_partials). Staging lives in its own directory rather
# than under a name suffix so that no label a user can type (safe_label
# keeps periods, so "test.partial" is one) can make a whole incident look
# like a half copy.
STAGING_DIR = ".staging"


def safe_label(label: str) -> str:
    """The filename-safe form a label takes in an incident's directory name
    ("storm at noon" -> "storm-at-noon"). `incidents --delete` applies the
    same rule, so the label a user typed at freeze time finds it again."""
    return _LABEL.sub("-", label.strip()).strip("-") or "incident"


def freeze_ring(cfg, label: str = "incident", now: float | None = None) -> tuple[Path, int]:
    """Snapshot the ring. Returns (incident dir, ring files copied). The
    label is reduced to filename-safe characters (safe_label)."""
    label = safe_label(label)
    stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime(now or time.time()))
    final = cfg.incidents_dir / f"{stamp}_{label}"
    dest = cfg.incidents_dir / STAGING_DIR / final.name
    # Never over an incident that exists (the same label twice in one
    # second), and never into a half copy another freeze is building or
    # a dead run left behind: an incident is whole or it is nothing.
    if final.exists():
        raise FileExistsError(f"incident {final.name} already exists; nothing was copied over it")
    dest.mkdir(parents=True, exist_ok=False)
    count = 0
    try:
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
    except BaseException:
        # A copy cut short by a full disk, an I/O error or Ctrl-C would
        # otherwise stay behind looking like a whole incident, with nothing
        # to say it is not. Remove it (on a full disk that also gives the
        # ring its space back) and let the caller report and retry.
        shutil.rmtree(dest, ignore_errors=True)
        raise
    dest.rename(final)
    return final, count


def discard_partials(incidents_dir: Path) -> list[str]:
    """Remove the half copies a previous run left behind (a freeze cut short
    by a restart or the stall watchdog) and return their labels. Nothing in
    one can be trusted to be whole, and the ring it was copied from is
    still there for the retry."""
    staging = incidents_dir / STAGING_DIR
    if not staging.is_dir():
        return []
    labels = []
    for d in sorted(staging.iterdir()):
        if d.is_dir():
            shutil.rmtree(d, ignore_errors=True)
            labels.append(d.name.partition("_")[2] or d.name)
    return labels
