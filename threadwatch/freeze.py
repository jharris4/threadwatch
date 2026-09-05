"""Preserve the ring buffer as an incident before it rolls over.

Used by `threadwatch freeze <label>` and, with [capture]
freeze_on_critical, by the pipeline itself the moment a critical event
fires. Copies every ring file plus the state files and the event log into
data/incidents/<stamp>_<label>. The file being written is copied as it
is; a partial last record at its tail is harmless (readers stop cleanly).
A ring file pruned while the copy runs is skipped, not fatal.
"""

from __future__ import annotations

import fcntl
import os
import re
import shutil
import time
from pathlib import Path
from typing import Optional

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
# Beside each staging directory, a file the freeze building it holds an
# advisory lock on for as long as it runs. A manual freeze is another
# process and may overlap a recorder restart; the start-up cleanup takes
# the lock before removing a directory, so a copy still being built is
# left alone, and a dead run's lock is free whatever its PID (the kernel
# drops it with the process).
LOCK_SUFFIX = ".lock"


def safe_label(label: str) -> str:
    """The filename-safe form a label takes in an incident's directory name
    ("storm at noon" -> "storm-at-noon"). `incidents --delete` applies the
    same rule, so the label a user typed at freeze time finds it again."""
    return _LABEL.sub("-", label.strip()).strip("-") or "incident"


def _take_lock(path: Path, wait: bool) -> Optional[int]:
    """Hold an exclusive lock on the file at ``path``, creating it. Returns
    the descriptor to close when done, or None when another live process
    holds it and ``wait`` is off. The file is opened again when it was
    unlinked between opening and locking (a cleanup that got there
    first removes the lock file it held), so the lock held is on the
    file the next comer opens."""
    for _ in range(50):
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        except OSError:
            os.close(fd)
            return None
        try:
            if os.fstat(fd).st_ino == os.stat(path).st_ino:
                return fd
        except FileNotFoundError:
            pass
        os.close(fd)
    raise OSError(f"could not take the lock {path.name}")


def freeze_ring(cfg, label: str = "incident", now: float | None = None) -> tuple[Path, int]:
    """Snapshot the ring. Returns (incident dir, ring files copied). The
    label is reduced to filename-safe characters (safe_label)."""
    label = safe_label(label)
    stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime(now or time.time()))
    final = cfg.incidents_dir / f"{stamp}_{label}"
    staging = cfg.incidents_dir / STAGING_DIR
    dest = staging / final.name
    # Never over an incident that exists (the same label twice in one
    # second), and never into a half copy another freeze is building or
    # a dead run left behind: an incident is whole or it is nothing.
    if final.exists():
        raise FileExistsError(f"incident {final.name} already exists; nothing was copied over it")
    staging.mkdir(parents=True, exist_ok=True)
    lock = dest.with_name(dest.name + LOCK_SUFFIX)
    fd = _take_lock(lock, wait=True)      # a same-named freeze finishing: wait, then find its incident
    try:
        if final.exists():
            raise FileExistsError(f"incident {final.name} already exists; nothing was copied over it")
        dest.mkdir(exist_ok=False)
        count = 0
        try:
            for f in sorted(cfg.ring_dir.glob("threadwatch-*.pcap")) if cfg.ring_dir.exists() else []:
                try:
                    shutil.copy2(f, dest / f.name)
                except FileNotFoundError:
                    if not dest.is_dir():
                        # The destination is what went missing, not the
                        # source: nothing copied so far is there any more,
                        # and copying on would report a snapshot that is
                        # not one.
                        raise
                    # The ring rotated under us and pruned its oldest file
                    # between the glob and the copy. That file was leaving
                    # anyway; the rest of the snapshot is still worth having.
                    continue
                count += 1
            for extra in STATE_FILES:
                src = cfg.state_dir / extra
                if src.exists():
                    shutil.copy2(src, dest / extra)
            if cfg.events_dir.exists():
                shutil.copytree(cfg.events_dir, dest / "events", dirs_exist_ok=True)
            kept = len(list(dest.glob("threadwatch-*.pcap")))
            if kept != count:
                raise OSError(f"{count} ring files were copied but the snapshot holds {kept}")
        except BaseException:
            # A copy cut short by a full disk, an I/O error or Ctrl-C would
            # otherwise stay behind looking like a whole incident, with nothing
            # to say it is not. Remove it (on a full disk that also gives the
            # ring its space back) and let the caller report and retry.
            shutil.rmtree(dest, ignore_errors=True)
            raise
        dest.rename(final)
    finally:
        lock.unlink(missing_ok=True)
        os.close(fd)
    return final, count


def discard_partials(incidents_dir: Path) -> list[str]:
    """Remove the half copies a previous run left behind (a freeze cut short
    by a restart or the stall watchdog) and return their labels. Nothing in
    one can be trusted to be whole, and the ring it was copied from is
    still there for the retry. A copy a live freeze is still building (its
    lock is held) is not a leftover and is left alone."""
    staging = incidents_dir / STAGING_DIR
    if not staging.is_dir():
        return []
    labels = []
    # What is a half copy and what is a lock is told by kind, never by
    # name: safe_label keeps periods, so a user can freeze "debug.lock" and
    # leave a staging directory whose name ends in the lock suffix. Read by
    # suffix, that directory was skipped here and then opened as a lock
    # file below, and the IsADirectoryError stopped every start after it.
    for d in sorted(staging.iterdir()):
        if not d.is_dir():
            continue
        lock = d.with_name(d.name + LOCK_SUFFIX)
        fd = _take_lock(lock, wait=False)
        if fd is None:
            continue            # a freeze still running in another process
        try:
            shutil.rmtree(d, ignore_errors=True)
            labels.append(d.name.partition("_")[2] or d.name)
            lock.unlink(missing_ok=True)
        finally:
            os.close(fd)
    for stray in staging.glob("*" + LOCK_SUFFIX):
        # A lock left by a run that died before making its directory.
        if not stray.is_file():
            continue
        fd = _take_lock(stray, wait=False)
        if fd is not None:
            stray.unlink(missing_ok=True)
            os.close(fd)
    return labels
