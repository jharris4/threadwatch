"""The Home Assistant add-on logs, copied into snapshots.

The border router (the OTBR add-on) and the Matter Server keep their own
view of the mesh in Home Assistant's journal, and that view is what closes
an incident: a ChannelAccessFailure beside a flood window, a Matter node
going unreachable beside a key-lag page. The journal is short, about 11.5
hours with the OTBR at log level info, so the logs have to be copied
while they exist. Every snapshot, taken by hand or on a critical event,
fetches each configured add-on's log for the snapshot's window into
ha-logs/<slug>.log.gz beside the packets, after the ring copy is final: a
slow or failed fetch never delays, invalidates or removes it. ha-logs.json
in the snapshot says what arrived, and the manifest lists the files.

The endpoint is GET {HA_URL}/api/hassio/addons/<slug>/logs?verbose, which
HA core forwards to the Supervisor (so the token must belong to an admin
user), with Range: realtime=<since>:<until> in epoch seconds. ?verbose
puts a wall-clock UTC stamp in front of every line, so a line can be set
beside a ring frame without converting the OTBR's own uptime stamp.

Secrets never travel in a bundle: known secrets (the network key in every
spelling, the HA token, alerts.env values) are scrubbed from each line
before it is written, and every message this module produces goes
through the URL and text redaction in httpclient.
"""

from __future__ import annotations

import calendar
import gzip
import http.client
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

from .httpclient import SCRUB_MIN, redact_text, redact_url, urlopen
from .snapshot import MANIFEST, STAGING_DIR, _take_lock, rewrite_manifest, saved_at

LOG_DIR = "ha-logs"                  # inside a snapshot: ha-logs/<slug>.log.gz
STATUS_FILE = "ha-logs.json"
LOCK_FILE = "ha-logs.lock"           # held while a fetch into the snapshot runs (recover_interrupted asks)
PART_SUFFIX = ".part"
# A failed or partial fetch is tried again this long after the snapshot
# was saved: HA may have been down, or the recorder's own retry may not
# have had the window yet. Each retry asks for the same window; the
# journal returns whatever it still holds.
RETRY_AFTER_S = (15 * 60, 60 * 60, 4 * 60 * 60)
# The journal prefix ?verbose puts before each line, UTC:
#   2026-09-13 22:09:43.197 homeassistant app_core_openthread_border_router[697]: 4d.06:59:10.452 [I] ...
JOURNAL_PREFIX = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}) (\S+) ([^\[]+)\[(\d+)\]: ")
DEFAULT_READ_TIMEOUT_S = 30.0
DEFAULT_DEADLINE_S = 900.0
PROGRESS_EVERY_S = 5.0


def journal_stamp(line: str) -> float | None:
    """The epoch time of a journal line's prefix, or None for a line
    without one (a continuation line, written as it is)."""
    m = JOURNAL_PREFIX.match(line)
    if not m:
        return None
    stamp = m.group(1)
    try:
        return calendar.timegm(time.strptime(stamp[:19], "%Y-%m-%d %H:%M:%S")) + int(stamp[20:23]) / 1000.0
    except ValueError:
        return None


def secret_forms(network_key: bytes | None = None, token: str | None = None, extra=()) -> tuple[str, ...]:
    """Every spelling a known secret could take in a log line: the network
    key as hex in either case, with or without colon, dash or space
    separators, in either byte order; the token; and whatever else the
    caller knows (alerts.env values). Short values are left out, as
    redact_text leaves them out: a substring of ordinary words would blank
    the log instead of the secret."""
    forms: set[str] = set()
    if network_key:
        for key in (network_key, network_key[::-1]):
            pairs = [f"{b:02x}" for b in key]
            for sep in ("", ":", "-", " "):
                forms.add(sep.join(pairs))
    if token:
        forms.add(token)
    forms.update(s for s in extra if isinstance(s, str))
    return tuple(sorted((f for f in forms if len(f) >= SCRUB_MIN), key=len, reverse=True))


def known_secrets(cfg, network_key: bytes | None = None, token: str | None = None) -> tuple[str, ...]:
    """The secrets this host holds, for scrubbing: the network key (from
    the decryptor when the caller has one, else the credentials file), the
    HA token, and every value in alerts.env and ha.env."""
    from .ha import load_env
    if network_key is None:
        try:
            from .pipeline import load_decryptor
            network_key = load_decryptor(cfg).network_key
        except Exception:
            network_key = None
    extra = []
    for name in ("alerts.env", "ha.env"):
        extra.extend(load_env(cfg.config_dir / name).values())
    return secret_forms(network_key, token, extra)


def _scrubber(secrets) -> Callable[[str], str]:
    if not secrets:
        return lambda line: line
    pattern = re.compile("|".join(re.escape(s) for s in secrets), re.IGNORECASE)
    return lambda line: pattern.sub("<redacted>", line)


def _describe(exc: BaseException, secrets) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code} {exc.reason}"
    if isinstance(exc, urllib.error.URLError):
        return redact_text(f"{exc.reason}", secrets)
    return redact_text(f"{type(exc).__name__}: {exc}", secrets)


def fetch_addon_log(url: str, token: str, slug: str, since: float, until: float, dest: Path, *,
                    read_timeout_s: float = DEFAULT_READ_TIMEOUT_S, deadline_s: float = DEFAULT_DEADLINE_S,
                    secrets=(), progress: Callable | None = None,
                    progress_every_s: float = PROGRESS_EVERY_S) -> dict:
    """Copy one add-on's journal lines for [since, until] into ``dest``
    (gzip), streaming through ``dest`` + ".part" and renaming only once
    the transfer is over. ``read_timeout_s`` bounds one silent read and
    ``deadline_s`` the whole transfer: past either, what arrived is kept
    and the result says ``complete`` false. Ctrl-C does the same and sets
    ``interrupted``. ``progress(slug, lines, bytes, elapsed_s)`` is called
    about every ``progress_every_s`` while lines arrive.

    The result: slug, file (the name written, or None), requested
    [since, until], received [first_ts, last_ts] (journal stamps, UTC),
    lines, bytes_gz, complete, error, http_status, elapsed_s and
    gap_before_s (how far the journal had already rolled past ``since``
    when it is positive). Never raises for anything the endpoint does;
    the token appears in no field."""
    result = {"slug": slug, "file": None, "requested": [since, until], "received": [None, None],
              "lines": 0, "bytes_gz": 0, "complete": False, "error": None, "http_status": None,
              "elapsed_s": 0.0, "gap_before_s": None, "interrupted": False}
    req = urllib.request.Request(f"{url.rstrip('/')}/api/hassio/addons/{slug}/logs?verbose",
                                 headers={"Authorization": f"Bearer {token}", "Accept": "text/plain",
                                          "Range": f"realtime={int(since)}:{int(until)}"})
    scrub = _scrubber(secrets)
    part = dest.with_suffix(PART_SUFFIX)
    started = time.monotonic()
    where = f"{slug} at {redact_url(url)}"
    try:
        resp = urlopen(req, timeout=read_timeout_s)
    except urllib.error.HTTPError as exc:
        result["http_status"] = exc.code
        hint = (": the token is not an admin user's, or is wrong" if exc.code in (401, 403)
                else ": no such add-on" if exc.code == 404
                else ": a redirect, which is never followed with the token" if 300 <= exc.code < 400 else "")
        result["error"] = f"{where}: {_describe(exc, secrets)}{hint}"
        result["elapsed_s"] = round(time.monotonic() - started, 3)
        return result
    except (OSError, http.client.HTTPException, ValueError) as exc:
        result["error"] = f"{where}: {_describe(exc, secrets)}"
        result["elapsed_s"] = round(time.monotonic() - started, 3)
        return result
    result["http_status"] = resp.status
    first = last = None
    lines = raw_bytes = 0
    reported = started
    dest.parent.mkdir(parents=True, exist_ok=True)
    error = None
    try:
        with resp, gzip.open(part, "wb") as gz:
            while True:
                try:
                    raw = resp.readline()
                except (OSError, http.client.HTTPException) as exc:
                    error = f"{where}: {_describe(exc, secrets)} after {lines} lines; what arrived is kept"
                    break
                if not raw:
                    result["complete"] = True
                    break
                line = raw.decode("utf-8", "replace")
                raw_bytes += len(raw)
                stamp = journal_stamp(line)
                if stamp is not None:
                    if first is None:
                        first = stamp
                    last = stamp
                gz.write(scrub(line).encode("utf-8"))
                lines += 1
                now = time.monotonic()
                if now - started > deadline_s:
                    error = (f"{where}: the {deadline_s:g} s deadline passed after {lines} lines; what arrived "
                             "is kept")
                    break
                if progress is not None and now - reported >= progress_every_s:
                    reported = now
                    progress(slug, lines, raw_bytes, now - started)
    except KeyboardInterrupt:
        result["interrupted"] = True
        error = f"{where}: interrupted after {lines} lines; what arrived is kept"
    result["elapsed_s"] = round(time.monotonic() - started, 3)
    result["lines"] = lines
    result["received"] = [first, last]
    result["error"] = error
    if first is not None:
        result["gap_before_s"] = round(max(0.0, first - since))
    if lines or result["complete"]:
        part.replace(dest)
        result["file"] = dest.name
        result["bytes_gz"] = dest.stat().st_size
    else:
        part.unlink(missing_ok=True)
    if progress is not None and lines:
        progress(slug, lines, raw_bytes, time.monotonic() - started)
    return result


# ------------------------------------------------------- in a snapshot

def credentials(cfg) -> tuple[str, str] | None:
    """(url, token) from config/ha.env, or None when there is no token."""
    from .ha import HAError, connection_settings
    try:
        return connection_settings(cfg.config_dir / "ha.env")
    except HAError:
        return None


def window(snapshot_dir: Path, now: float, max_hours: float, saved: float | None = None) -> tuple[float, float]:
    """The journal window a snapshot asks for: from the start of its oldest
    ring file's hour (a local hour, as ring files are named), never further
    back than ``max_hours`` before now, up to when it was saved (an until
    in the future was never tested against the realtime range)."""
    saved = saved if saved is not None else now
    until = min(saved, now)
    floor = now - max_hours * 3600.0
    since = floor
    for pcap in sorted(snapshot_dir.glob("threadwatch-*.pcap")):
        try:
            since = max(floor, time.mktime(time.strptime(pcap.name[12:23], "%Y%m%d-%H")))
        except ValueError:
            since = floor
        break
    if since >= until:
        since = until - 3600.0
    return since, until


def read_status(snapshot_dir: Path) -> dict | None:
    try:
        status = json.loads((snapshot_dir / STATUS_FILE).read_text())
    except (OSError, ValueError):
        return None
    return status if isinstance(status, dict) and isinstance(status.get("addons"), dict) else None


def _write_status(snapshot_dir: Path, status: dict) -> None:
    status["updated"] = time.time()
    path = snapshot_dir / STATUS_FILE
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(status, indent=1))
    os.replace(tmp, path)


def summary(status: dict) -> dict:
    """The manifest's ha_logs key: ha-logs.json without the noise."""
    keep = ("file", "lines", "complete", "received", "gap_before_s", "error", "http_status", "source")
    return {"status": status.get("status"), "reason": status.get("reason"), "requested": status.get("requested"),
            "attempts": status.get("attempts"),
            "addons": {slug: {k: r.get(k) for k in keep if k in r} for slug, r in status["addons"].items()}}


def _settle(status: dict, interrupted: bool = False) -> dict:
    """status from the add-on results: complete when every add-on's log
    is whole, partial when any file exists, failed when none does."""
    results = list(status["addons"].values())
    if results and all(r.get("complete") for r in results) and not interrupted:
        status["status"], status["reason"] = "complete", None
    elif any(r.get("file") for r in results):
        status["status"] = "partial"
        status["reason"] = "interrupted" if interrupted else "; ".join(
            r["error"] for r in results if r.get("error")) or None
    else:
        status["status"] = "failed"
        status["reason"] = "; ".join(r["error"] for r in results if r.get("error")) or "nothing arrived"
    return status


def attach_logs(cfg, snapshot_dir: Path, *, now: float | None = None, settings: tuple | None = None,
                secrets=None, progress: Callable | None = None) -> dict | None:
    """Add the add-on logs to a snapshot that is already final, and say
    so in ha-logs.json and the manifest. Returns the status written, or
    None when [ha_logs] is off (nothing is written then, and the manifest
    gets no ha_logs key). Called again on a snapshot that has a
    ha-logs.json, it is the retry: the same window is asked for, only the
    add-ons whose log is not yet whole are fetched, and ``attempts``
    counts the rounds.

    The order is the point: the ring copy is never delayed, invalidated
    or removed by anything here. A lock beside the status file says a
    fetch is live, so a recorder starting meanwhile leaves it alone."""
    if not cfg.ha_logs_enabled:
        return None
    now = now if now is not None else time.time()
    saved = saved_at(snapshot_dir)
    status = read_status(snapshot_dir) or {"status": "fetching", "reason": None, "saved_at": saved,
                                           "requested": None, "attempts": 0, "addons": {}}
    status["attempts"] = int(status.get("attempts") or 0) + 1
    settings = settings if settings is not None else credentials(cfg)
    if settings is None:
        status["status"], status["reason"] = "skipped", "no token: put an admin user's HA_TOKEN in config/ha.env"
        _write_status(snapshot_dir, status)
        rewrite_manifest(snapshot_dir, ha_logs=summary(status))
        return status
    url, token = settings
    if secrets is None:
        secrets = known_secrets(cfg, token=token)
    if not (isinstance(status.get("requested"), list) and len(status["requested"]) == 2):
        status["requested"] = list(window(snapshot_dir, now, cfg.ha_logs_max_hours, saved))
    since, until = status["requested"]
    for slug in cfg.ha_logs_addons:
        status["addons"].setdefault(slug, {"slug": slug, "file": None, "complete": False, "error": None})
    lock = snapshot_dir / LOCK_FILE
    fd = _take_lock(lock, wait=True)
    try:
        status["status"], status["reason"] = "fetching", None
        _write_status(snapshot_dir, status)
        interrupted = False
        for slug in cfg.ha_logs_addons:
            if status["addons"][slug].get("complete"):
                continue
            dest = snapshot_dir / LOG_DIR / f"{slug}.log.gz"
            result = fetch_addon_log(url, token, slug, since, until, dest, read_timeout_s=cfg.ha_logs_read_timeout_s,
                                     deadline_s=cfg.ha_logs_deadline_s, secrets=secrets, progress=progress)
            if result["file"]:
                result["file"] = f"{LOG_DIR}/{result['file']}"
            result.pop("requested", None)
            result["source"] = "live"
            status["addons"][slug] = result
            if result.pop("interrupted", False):
                interrupted = True
                break
        _settle(status, interrupted)
        _write_status(snapshot_dir, status)
        rewrite_manifest(snapshot_dir, ha_logs=summary(status))
    finally:
        lock.unlink(missing_ok=True)
        os.close(fd)
    return status


def recover_interrupted(snapshots_dir: Path) -> list[str]:
    """At start: a snapshot whose ha-logs.json still says "fetching" with
    no fetch holding its lock was cut short by a stop. Any .part file is
    renamed into place (what arrived is evidence), the status becomes
    partial or failed, and the manifest is rewritten. Returns the
    snapshot names touched; the retry pass takes them from there."""
    if not snapshots_dir.is_dir():
        return []
    touched = []
    for d in sorted(snapshots_dir.iterdir()):
        if not d.is_dir() or d.name == STAGING_DIR:
            continue
        status = read_status(d)
        if status is None or status.get("status") != "fetching":
            continue
        fd = _take_lock(d / LOCK_FILE, wait=False)
        if fd is None:
            continue                       # a fetch by hand, still running
        try:
            for part in sorted((d / LOG_DIR).glob("*" + PART_SUFFIX)) if (d / LOG_DIR).is_dir() else []:
                final = part.with_suffix(".gz")
                part.replace(final)
                slug = final.name[:-len(".log.gz")]
                entry = status["addons"].setdefault(slug, {"slug": slug})
                entry.update(file=f"{LOG_DIR}/{final.name}", complete=False, bytes_gz=final.stat().st_size,
                             error="the recorder stopped during the fetch; what arrived is kept", source="live")
            for entry in status["addons"].values():
                if not entry.get("complete") and not entry.get("error"):
                    entry["error"] = "the recorder stopped before this add-on's log was fetched"
            _settle(status)
            _write_status(d, status)
            rewrite_manifest(d, ha_logs=summary(status))
            touched.append(d.name)
            (d / LOCK_FILE).unlink(missing_ok=True)
        finally:
            os.close(fd)
    return touched


def retries_due(cfg, now: float) -> list[Path]:
    """The snapshots whose logs are failed or partial and due another try:
    fewer than len(RETRY_AFTER_S) retries so far, the next one's time
    reached, and the snapshot still inside [ha_logs] max_hours (past
    that the journal has nothing left to give)."""
    if not cfg.snapshots_dir.is_dir():
        return []
    due = []
    for d in sorted(cfg.snapshots_dir.iterdir()):
        if not d.is_dir() or d.name == STAGING_DIR or not (d / MANIFEST).exists():
            continue
        status = read_status(d)
        if status is None or status.get("status") not in ("failed", "partial"):
            continue
        attempts = int(status.get("attempts") or 1)
        retries = attempts - 1
        if retries >= len(RETRY_AFTER_S):
            continue
        saved = status.get("saved_at") if isinstance(status.get("saved_at"), (int, float)) else saved_at(d)
        if saved is None or now - saved > cfg.ha_logs_max_hours * 3600.0:
            continue
        if now >= saved + RETRY_AFTER_S[retries]:
            due.append(d)
    return due


def retry_pending(cfg, now: float | None = None, secrets=None) -> list[tuple[Path, dict, bool]]:
    """One pass of the retry schedule: every snapshot due is fetched again
    (attach_logs on its own ha-logs.json). Returns (snapshot, status,
    final) per snapshot tried, ``final`` meaning no retry remains."""
    now = now if now is not None else time.time()
    out = []
    for d in retries_due(cfg, now):
        status = attach_logs(cfg, d, now=now, secrets=secrets)
        if status is None:
            continue
        final = status.get("status") == "complete" or int(status.get("attempts") or 1) - 1 >= len(RETRY_AFTER_S)
        out.append((d, status, final))
    return out
