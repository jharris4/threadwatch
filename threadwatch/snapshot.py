"""Save the ring buffer as a snapshot before it rolls over.

Used by `threadwatch snapshot <label>` and, with [record]
snapshot_on_critical, by the pipeline itself the moment a critical event
fires. Copies every ring file plus the state files, the event log, the
inventory and the configuration (secrets blanked) into
data/snapshots/<stamp>_<label>, with a manifest naming them all, so the
snapshot can be read on its own, months later or on another machine,
with the names and settings that were current when it was saved. The
file being written is copied as it is; a partial last record at its tail
is harmless (readers stop cleanly). A ring file pruned while the copy
runs is skipped, not fatal.
"""

from __future__ import annotations

import datetime
import fcntl
import json
import os
import re
import shutil
import time
import tomllib
from pathlib import Path

from . import __version__
from .config import repo_commit

# border-routers.json is the hostname -> address history of every hub that
# rotates its address: without it a snapshot cannot name the border
# router on the very day it rebooted, the device most worth reading.
STATE_FILES = ("status.json", "last-seen.json", "observed-names.json", "frames-by-hour.json",
               "border-routers.json", "blind-spans.json", "retransmissions.json",
               "storm.json")
# The configuration goes along with its secrets blanked: it is parsed as
# TOML and written back out, and a value whose key contains one of these
# words - at any depth, written as a plain key, a dotted one, an inline
# table or an array of them - is replaced by "<redacted>", as is every
# value inside a table whose own key contains one, such as
# [alerts.sinks.headers]. Matching is on containment, not on the whole
# key: webhook_url, Authorization and X-Api-Key are the shapes an operator
# actually writes, and over-redacting a bundle costs nothing while
# under-redacting one ships a bearer token.
# Secrets are meant to live in alerts.env as ${VAR} references, but a
# token pasted into a URL or a header must not travel with the packets.
# credentials.toml, alerts.env and ha.env are never copied.
REDACT_WORDS = ("url", "header", "command", "token", "topic", "password",
                "secret", "auth", "username", "key")
REDACTED = "<redacted>"
MANIFEST = "manifest.json"
_LABEL = re.compile(r"[^A-Za-z0-9._-]+")
# A copy in progress is built under this directory, beside the finished
# snapshots, and renamed into place only once whole. The recorder leaves
# through os._exit on every path, which unwinds nothing: a copy it
# interrupts must not be findable as a snapshot (review.snapshots lists
# only the snapshots directory itself), and a leftover is discarded at the
# next start (discard_partials). Staging lives in its own directory rather
# than under a name suffix so that no label a user can type (safe_label
# keeps periods, so "test.partial" is one) can make a whole snapshot look
# like a half copy.
STAGING_DIR = ".staging"
# Beside each staging directory, a file the copy building it holds an
# advisory lock on for as long as it runs. A snapshot taken by hand is another
# process and may overlap a recorder restart; the start-up cleanup takes
# the lock before removing a directory, so a copy still being built is
# left alone, and a dead run's lock is free whatever its PID (the kernel
# drops it with the process).
LOCK_SUFFIX = ".lock"


def safe_label(label: str) -> str:
    """The filename-safe form a label takes in a snapshot's directory name
    ("storm at noon" -> "storm-at-noon"). `snapshots --delete` applies the
    same rule, so the label a user typed at the time finds it again."""
    return _LABEL.sub("-", label.strip()).strip("-") or "snapshot"


def _is_secret(key: str) -> bool:
    """Is a key (or the last segment of a table's name) one whose value must
    not leave the host?"""
    k = key.strip().strip("\"'").lower()
    return any(word in k for word in REDACT_WORDS)


def redact_config(text: str) -> str:
    """The configuration with every secret value blanked, as valid TOML.

    Parsed with tomllib and written back out, rather than edited line by
    line: an editor has to recognize every form a key can be written in,
    and the ones it did not - a dotted key, an inline table, an array of
    inline tables - carried a webhook URL and a bearer token into the
    bundle intact. Redacting the parsed data instead reaches every value
    at every depth whatever shape it was written in, and what is emitted
    parses by construction. The cost is the operator's comments and
    layout, which do not survive the round trip: a reader of the snapshot
    still sees which sinks and settings were in force, without seeing
    where they pointed."""
    if not text.strip():
        return text
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        # A configuration the recorder itself could not have loaded. Say so
        # and blank it whole: copying the text through unparsed is the one
        # case where nothing has looked at what is in it.
        return f"# the configuration in force did not parse as TOML ({exc}); redacted whole\n"
    return _HEADER + _dump_table(_redact(data, False), ()).lstrip("\n") + "\n"


# What replaces the operator's own comments at the top of the copy.
_HEADER = ('# The configuration in force when this snapshot was saved, with every\n'
           '# secret value replaced by "<redacted>". Written back out from the\n'
           '# parsed file, so the comments and the layout of the original are not\n'
           '# here; the settings that judged these packets are.\n\n')


def _redact(value, secret: bool):
    """The value with every secret leaf blanked. ``secret`` is set once a
    key on the way down was a sensitive one, and everything below that key
    goes with it: the tokens are as often a table's values (Authorization,
    X-Api-Key) as the table's own."""
    if isinstance(value, dict):
        return {k: _redact(v, secret or _is_secret(k)) for k, v in value.items()}
    if secret:
        return REDACTED
    if isinstance(value, list):
        return [_redact(v, False) for v in value]
    return value


def _dump_table(table: dict, path: tuple[str, ...], header: str | None = None) -> str:
    """One table and everything below it as TOML text. Its own values come
    first and its sub-tables after, which is the order TOML requires: a key
    written below a [header] belongs to that table, not to this one."""
    lines = [header] if header else []
    lines += [f"{_key(k)} = {_value(v)}" for k, v in table.items()
              if not _is_table(v) and not _is_table_array(v)]
    for k, v in table.items():
        name = _key_path(path + (k,))
        if _is_table(v):
            lines += ["", _dump_table(v, path + (k,), f"[{name}]")]
        elif _is_table_array(v):
            for item in v:
                lines += ["", _dump_table(item, path + (k,), f"[[{name}]]")]
    return "\n".join(lines)


def _is_table(value) -> bool:
    return isinstance(value, dict)


def _is_table_array(value) -> bool:
    """A list [[alerts.sinks]] can be written as. An empty list, or one
    holding anything but tables, is an ordinary value and stays inline."""
    return isinstance(value, list) and bool(value) and all(isinstance(v, dict) for v in value)


def _key(key: str) -> str:
    return key if _BARE_KEY.fullmatch(key) else _string(key)


def _key_path(path: tuple[str, ...]) -> str:
    return ".".join(_key(part) for part in path)


def _value(value) -> str:
    """One TOML value. bool is checked before int, which it is a subclass
    of, or a sink's enabled = true would come back out as 1."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value:
            return "nan"
        if value in (float("inf"), float("-inf")):
            return "inf" if value > 0 else "-inf"
        return repr(value)
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat()
    if isinstance(value, list):
        return "[" + ", ".join(_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ", ".join(f"{_key(k)} = {_value(v)}" for k, v in value.items()) + "}"
    return _string(str(value))


def _string(text: str) -> str:
    """A TOML basic string. Newlines and the rest of the control characters
    are escaped rather than left in: a multi-line value written as \"\"\"...\"\"\"
    comes back as one escaped line, which parses to the same string."""
    out = []
    for ch in text:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ch < " " or ch == "\x7f":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


_BARE_KEY = re.compile(r"[A-Za-z0-9_-]+")
_ESCAPES = {"\\": "\\\\", '"': '\\"', "\b": "\\b", "\t": "\\t",
            "\n": "\\n", "\f": "\\f", "\r": "\\r"}


# A reader of the bundle months later should know which code judged it.
_commit = repo_commit


def write_manifest(cfg, dest: Path, label: str, now: float, trigger: str | None) -> dict:
    """manifest.json: what the bundle holds and the recorder that made it.
    Written last, so a bundle without one was cut short."""
    files = {str(p.relative_to(dest)): p.stat().st_size for p in sorted(dest.rglob("*")) if p.is_file()}
    pcaps = sorted(n for n in files if n.endswith(".pcap"))
    hours = sorted(n[12:23] for n in pcaps if n.startswith("threadwatch-") and len(n) == 28)
    manifest = {
        "format": 1,
        "threadwatch": __version__,
        "commit": _commit(),
        "saved_at": now,
        "saved_at_local": time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(now)),
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
        "read_with": "threadwatch replay --snapshot <name>; threadwatch device <device> --snapshot <name>",
    }
    (dest / MANIFEST).write_text(json.dumps(manifest, indent=1))
    return manifest


def _take_lock(path: Path, wait: bool) -> int | None:
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


def save_snapshot(cfg, label: str = "snapshot", now: float | None = None,
                trigger: str | None = None) -> tuple[Path, int]:
    """Save the ring. Returns (snapshot dir, ring files copied). The
    label is reduced to filename-safe characters (safe_label); ``trigger``
    names the event that asked for it, for the manifest."""
    label = safe_label(label)
    now = now or time.time()
    stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime(now))
    final = cfg.snapshots_dir / f"{stamp}_{label}"
    staging = cfg.snapshots_dir / STAGING_DIR
    dest = staging / final.name
    # Never over a snapshot that exists (the same label twice in one
    # second), and never into a half copy another run is building or
    # a dead run left behind: a snapshot is whole or it is nothing.
    if final.exists():
        raise FileExistsError(f"snapshot {final.name} already exists; nothing was copied over it")
    staging.mkdir(parents=True, exist_ok=True)
    lock = dest.with_name(dest.name + LOCK_SUFFIX)
    fd = _take_lock(lock, wait=True)      # a same-named copy finishing: wait, then find its snapshot
    try:
        if final.exists():
            raise FileExistsError(f"snapshot {final.name} already exists; nothing was copied over it")
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
            # The names and settings in force now: a snapshot read after
            # a device rotated its address, or the quiet window changed,
            # must be judged by what was current when it was saved.
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
            # otherwise stay behind looking like a whole snapshot, with nothing
            # to say it is not. Remove it (on a full disk that also gives the
            # ring its space back) and let the caller report and retry.
            shutil.rmtree(dest, ignore_errors=True)
            raise
        dest.rename(final)
    finally:
        lock.unlink(missing_ok=True)
        os.close(fd)
    return final, count


def prune_auto_snapshots(snapshots_dir: Path, keep: int) -> list[str]:
    """Remove all but the newest ``keep`` automatic snapshots and return
    their names, oldest first. Only those snapshot_on_critical made
    (label ``auto-*``) are pruned: a snapshot somebody saved by hand and
    named is kept, however old, because nothing else remembers to.
    ``keep`` of 0 prunes every automatic one; a negative keep is no cap."""
    if keep < 0 or not snapshots_dir.is_dir():
        return []
    autos = sorted(d for d in snapshots_dir.iterdir()
                   if d.is_dir() and d.name != STAGING_DIR and d.name.partition("_")[2].startswith("auto-"))
    removed = []
    for d in autos[:max(0, len(autos) - keep)]:
        shutil.rmtree(d, ignore_errors=True)
        removed.append(d.name)
    return removed


def discard_partials(snapshots_dir: Path) -> list[str]:
    """Remove the half copies a previous run left behind (a copy cut short
    by a restart or the stall watchdog) and return their labels. Nothing in
    one can be trusted to be whole, and the ring it was copied from is
    still there for the retry. A copy still being built (its
    lock is held) is not a leftover and is left alone."""
    staging = snapshots_dir / STAGING_DIR
    if not staging.is_dir():
        return []
    labels = []
    # What is a half copy and what is a lock is told by kind, never by
    # name: safe_label keeps periods, so a user can save "debug.lock" and
    # leave a staging directory whose name ends in the lock suffix. Read by
    # suffix, that directory was skipped here and then opened as a lock
    # file below, and the IsADirectoryError stopped every start after it.
    for d in sorted(staging.iterdir()):
        if not d.is_dir():
            continue
        lock = d.with_name(d.name + LOCK_SUFFIX)
        fd = _take_lock(lock, wait=False)
        if fd is None:
            continue            # a copy still running in another process
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
