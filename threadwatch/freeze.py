"""Preserve the ring buffer as an incident before it rolls over.

Used by `threadwatch freeze <label>` and, with [capture]
freeze_on_critical, by the pipeline itself the moment a critical event
fires. Copies every ring file plus the state files, the event log, the
inventory and the configuration (secrets blanked) into
data/incidents/<stamp>_<label>, with a manifest naming them all, so the
incident can be read on its own, months later or on another machine,
with the names and settings that were current when it was frozen. The
file being written is copied as it is; a partial last record at its tail
is harmless (readers stop cleanly). A ring file pruned while the copy
runs is skipped, not fatal.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import shutil
import time
from pathlib import Path
from typing import Optional

from . import __version__
from .config import repo_commit

# border-routers.json is the hostname -> address history of every hub that
# rotates its address: without it an incident cannot name the border
# router on the very day it rebooted, the device most worth reading.
STATE_FILES = ("status.json", "last-seen.json", "observed-names.json", "frames-by-hour.json",
               "border-routers.json", "blind-spans.json", "retransmissions.json")
# The configuration goes along with its secrets blanked: a value whose key
# contains one of these words, anywhere in the file, is replaced by
# "<redacted>" (a value that runs on over lines - an array, a table, a
# """ string - is swallowed whole), as is every key inside a table whose
# own name contains one, such as [alerts.sinks.headers]. Matching is on
# containment, not on the whole key: webhook_url, Authorization and
# X-Api-Key are the shapes an operator actually writes, and over-redacting
# a bundle costs nothing while under-redacting one ships a bearer token.
# Secrets are meant to live in alerts.env as ${VAR} references, but a
# token pasted into a URL or a header must not travel with the packets.
# credentials.toml, alerts.env and ha.env are never copied.
REDACT_WORDS = ("url", "header", "command", "token", "topic", "password",
                "secret", "auth", "username", "key")
_KEY_LINE = re.compile(r"""^(\s*)([A-Za-z0-9_-]+|"[^"]*"|'[^']*')(\s*=)""")
_TABLE_LINE = re.compile(r"^\s*\[\[?\s*(.+?)\s*\]\]?\s*(?:#.*)?$")
MANIFEST = "manifest.json"
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


def _is_secret(key: str) -> bool:
    """Is a key (or the last segment of a table's name) one whose value must
    not leave the host?"""
    k = key.strip().strip("\"'").lower()
    return any(word in k for word in REDACT_WORDS)


def redact_config(text: str) -> str:
    """The configuration with every secret value blanked. Line-based rather
    than a tomllib round-trip, so the file keeps its comments and its shape
    and stays valid TOML: a reader of the incident sees which sinks and
    settings were in force without seeing where they pointed."""
    out = []
    depth, open_ml, skipping = 0, None, False
    secret_table = False
    for line in text.splitlines():
        if depth or open_ml is not None:
            # Inside a value that runs on over lines: follow it to its end,
            # dropping it if it belongs to a key that is being blanked.
            depth, open_ml = _run_state(line, depth, open_ml)
            if not skipping:
                out.append(line)
            continue
        table = _TABLE_LINE.match(line)
        if table:
            # [alerts.sinks.headers] and the like: the secret is not the
            # table's value but every key inside it (Authorization,
            # X-Api-Key), none of which reads as sensitive on its own.
            secret_table = _is_secret(table.group(1).rsplit(".", 1)[-1])
            out.append(line)
            continue
        m = _KEY_LINE.match(line)
        if not m:
            out.append(line)
            continue
        skipping = secret_table or _is_secret(m.group(2))
        rest = line[m.end():] if skipping else line
        out.append(f'{m.group(1)}{m.group(2)} = "<redacted>"' if skipping else line)
        depth, open_ml = _run_state(rest, 0, None)
        depth = max(0, depth)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


def _run_state(text: str, depth: int, open_ml: Optional[str]) -> tuple[int, Optional[str]]:
    """Walk one line from the given state and report what it leaves open:
    net brackets, and the ''' or \"\"\" of a string still running. Counting
    brackets alone missed a multi-line basic string, whose body was then
    copied out verbatim and left the config.toml in the bundle invalid."""
    i, quote = 0, None
    while i < len(text):
        ch = text[i]
        if open_ml is not None:
            if text.startswith(open_ml, i):
                i, open_ml = i + 3, None
            else:
                i += 1
            continue
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if text.startswith('"""', i) or text.startswith("'''", i):
            open_ml = text[i:i + 3]
            i += 3
            continue
        if ch in "\"'":
            quote = ch
        elif ch == "#":
            break
        elif ch in "[{":
            depth += 1
        elif ch in "]}":
            depth -= 1
        i += 1
    return depth, open_ml


# A reader of the bundle months later should know which code judged it.
_commit = repo_commit


def write_manifest(cfg, dest: Path, label: str, now: float, trigger: Optional[str]) -> dict:
    """manifest.json: what the bundle holds and the recorder that made it.
    Written last, so a bundle without one was cut short."""
    files = {str(p.relative_to(dest)): p.stat().st_size for p in sorted(dest.rglob("*")) if p.is_file()}
    pcaps = sorted(n for n in files if n.endswith(".pcap"))
    hours = sorted(n[12:23] for n in pcaps if n.startswith("threadwatch-") and len(n) == 28)
    manifest = {
        "format": 1,
        "threadwatch": __version__,
        "commit": _commit(),
        "frozen_at": now,
        "frozen_at_local": time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(now)),
        "label": label,
        "trigger": trigger or "manual",
        "channel": cfg.channel,
        "pan_id": None if cfg.pan_id is None else f"0x{cfg.pan_id:04x}",
        "capture_files": "one pcap per local hour, named threadwatch-YYYYMMDD-HH.pcap; "
                         "the newest was still being written",
        "ring_files": len(pcaps),
        "span": [hours[0], hours[-1]] if hours else None,
        "inventory": "devices.json" if "devices.json" in files else None,
        "config": "config.toml" if "config.toml" in files else None,
        "events_days": sum(1 for n in files if n.startswith("events/") and n.endswith(".jsonl")),
        "files": files,
        "read_with": "threadwatch replay --incident <name>; threadwatch why <device> --incident <name>",
    }
    (dest / MANIFEST).write_text(json.dumps(manifest, indent=1))
    return manifest


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


def freeze_ring(cfg, label: str = "incident", now: float | None = None,
                trigger: Optional[str] = None) -> tuple[Path, int]:
    """Snapshot the ring. Returns (incident dir, ring files copied). The
    label is reduced to filename-safe characters (safe_label); ``trigger``
    names the event that asked for the freeze, for the manifest."""
    label = safe_label(label)
    now = now or time.time()
    stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime(now))
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
            # The names and settings in force now: an incident read after
            # a device rotated its address, or the quiet window changed,
            # must be judged by what was current when it was frozen.
            if cfg.devices_path and cfg.devices_path.exists():
                shutil.copy2(cfg.devices_path, dest / "devices.json")
            if cfg.config_path and cfg.config_path.exists():
                (dest / "config.toml").write_text(redact_config(cfg.config_path.read_text()))
            kept = len(list(dest.glob("threadwatch-*.pcap")))
            if kept != count:
                raise OSError(f"{count} ring files were copied but the snapshot holds {kept}")
            write_manifest(cfg, dest, label, now, trigger)
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


def prune_auto_incidents(incidents_dir: Path, keep: int) -> list[str]:
    """Remove all but the newest ``keep`` automatic incidents and return
    their names, oldest first. Only the snapshots freeze_on_critical made
    (label ``auto-*``) are pruned: an incident somebody froze by hand and
    named is kept, however old, because nothing else remembers to.
    ``keep`` of 0 prunes every automatic one; a negative keep is no cap."""
    if keep < 0 or not incidents_dir.is_dir():
        return []
    autos = sorted(d for d in incidents_dir.iterdir()
                   if d.is_dir() and d.name != STAGING_DIR and d.name.partition("_")[2].startswith("auto-"))
    removed = []
    for d in autos[:max(0, len(autos) - keep)]:
        shutil.rmtree(d, ignore_errors=True)
        removed.append(d.name)
    return removed


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
