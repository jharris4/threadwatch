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
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

from .httpclient import SCRUB_MIN, redact_text, redact_url, urlopen

LOG_DIR = "ha-logs"                  # inside a snapshot: ha-logs/<slug>.log.gz
STATUS_FILE = "ha-logs.json"
PART_SUFFIX = ".part"
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
