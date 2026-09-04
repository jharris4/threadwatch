"""`threadwatch doctor`: is this box fit to record?

One line per check, each ok / warn / FAIL, for the things that have
silently broken a recorder before: a dongle that is not there, a key file
the world can read, a full SD card, a clock nobody synced, a service that
is not running, a ring that stopped growing, sinks that will not build.
Read-only; it changes nothing.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable

OK, WARN, FAIL = "ok", "warn", "FAIL"
Check = tuple[str, str, str]   # (level, subject, text)


def check_config(cfg) -> list[Check]:
    out = [(OK, "config", f"channel {cfg.channel}, data in {cfg.data_dir}")]
    if not 11 <= cfg.channel <= 26:
        out[0] = (FAIL, "config", f"channel {cfg.channel} is not an 802.15.4 channel (11-26)")
    return out


def check_inventory(cfg) -> list[Check]:
    path = cfg.devices_path
    if path is None or not path.exists():
        return [(WARN, "inventory", "no devices.json: every address will be reported as unknown "
                                    "(threadwatch report --suggest drafts entries)")]
    try:
        entries = json.loads(path.read_text())
    except ValueError as exc:
        return [(FAIL, "inventory", f"{path.name} is not valid JSON: {exc}")]
    if not isinstance(entries, list):
        return [(FAIL, "inventory", f"{path.name} must be a JSON list")]
    from .names import _EXT_ADDR, _norm
    bad, addrs, unnamed = [], 0, 0
    for e in entries:
        got = list(e.get("extendedAddresses") or []) + ([e["extendedAddress"]] if e.get("extendedAddress") else [])
        if not (e.get("name") or "").strip():
            unnamed += 1
        for a in got:
            addrs += 1
            if not _EXT_ADDR.match(_norm(str(a))):
                bad.append(str(a))
    text = f"{len(entries)} devices, {addrs} addresses"
    if bad:
        return [(WARN, "inventory", f"{text}; ignored (not 16 hex digits): {', '.join(bad[:5])}")]
    if unnamed:
        return [(WARN, "inventory", f"{text}; {unnamed} with a blank name (still unknown)")]
    return [(OK, "inventory", text)]


def check_credentials(cfg) -> list[Check]:
    path = cfg.credentials_path
    if path is None or not path.exists():
        return [(OK, "credentials", "none: header-level analysis only (docs/CREDENTIALS.md to add the key)")]
    out = []
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        out.append((WARN, "credentials", f"{path.name} is mode {mode:04o}: readable by others; chmod 600 it"))
    try:
        import tomllib
        key = tomllib.loads(path.read_text()).get("credentials", {}).get("network_key", "")
        if len(key) != 32 or any(c not in "0123456789abcdefABCDEF" for c in key):
            out.append((FAIL, "credentials", f"{path.name}: network_key must be 32 hex digits; deep inspection is off"))
        else:
            out.append((OK, "credentials", f"{path.name} loads; deep inspection on"))
    except Exception as exc:
        out.append((FAIL, "credentials", f"{path.name} unusable ({exc}); deep inspection is off"))
    return out


def check_dongle(cfg, find: Callable[[], str] | None = None) -> list[Check]:
    if cfg.serial_port:
        if Path(cfg.serial_port).exists():
            return [(OK, "dongle", f"configured port {cfg.serial_port} exists")]
        return [(FAIL, "dongle", f"configured port {cfg.serial_port} does not exist")]
    try:
        import serial  # noqa: F401
    except ImportError:
        return [(FAIL, "dongle", "pyserial is not installed (pip install -r requirements.txt)")]
    try:
        port = (find or _find_port)()
    except SystemExit as exc:
        return [(FAIL, "dongle", str(exc).splitlines()[0])]
    except Exception as exc:
        return [(FAIL, "dongle", f"could not enumerate serial ports: {exc}")]
    return [(OK, "dongle", f"nRF 802.15.4 sniffer at {port}")]


def _find_port() -> str:
    from .capture import find_sniffer_port
    return find_sniffer_port()


def check_daemon(cfg, now: float | None = None) -> list[Check]:
    now = now or time.time()
    path = cfg.state_dir / "status.json"
    if not path.exists():
        return [(WARN, "capture", "no status.json: the capture daemon has never run here")]
    try:
        st = json.loads(path.read_text())
    except ValueError:
        return [(WARN, "capture", "status.json is unreadable (mid-write?)")]
    age = now - st.get("updated", 0)
    if age > 90:
        return [(FAIL, "capture", f"daemon not running: status last written {age / 60:.0f} min ago")]
    fa = st.get("last_frame_age_s", 0)
    if fa > 120:
        return [(WARN, "capture", f"daemon alive but no frames for {fa:.0f} s (quiet channel? wrong channel?)")]
    return [(OK, "capture", f"running, last frame {fa:.0f} s ago, {st.get('frames_total', 0):,} frames this run")]


def check_ring(cfg, now: float | None = None) -> list[Check]:
    now = now or time.time()
    files = sorted(cfg.ring_dir.glob("threadwatch-*.pcap")) if cfg.ring_dir.exists() else []
    if not files:
        return [(WARN, "ring", "no ring files yet")]
    newest = files[-1]
    age = now - newest.stat().st_mtime
    text = f"{len(files)} of {cfg.keep_files} hourly files, newest {newest.name} written {age / 60:.0f} min ago"
    if age > 2 * 3600:
        return [(FAIL, "ring", text + ": the ring stopped growing")]
    return [(OK, "ring", text)]


def check_disk(cfg) -> list[Check]:
    from .review import fmt_bytes, storage
    sto = storage(cfg)
    if not sto.get("disk_total"):
        return [(WARN, "disk", f"could not measure free space under {cfg.data_dir}")]
    free = sto["disk_free"]
    need = sto["ring_needs_bytes"]
    per_hour = sto.get("bytes_per_hour")
    rate = (f" at {fmt_bytes(per_hour)}/hour" if per_hour
            else " (assuming 30 MB/hour until the ring has measured itself)")
    cap = f", capped at {fmt_bytes(sto['keep_bytes'])}" if sto.get("keep_bytes") else ""
    text = (f"{fmt_bytes(free)} free; a full ring ({fmt_bytes(sto['ring_bound_bytes'])}{cap}) "
            f"needs about {fmt_bytes(need)} more{rate}")
    if free < need:
        return [(FAIL, "disk", text + ": it will not fit; lower keep_files, set keep_gb, or move data_dir")]
    if free < need + 1024 ** 3:
        return [(WARN, "disk", text + ": under 1 GB to spare")]
    return [(OK, "disk", text)]


def check_writable(cfg) -> list[Check]:
    out = []
    for label, d in (("state", cfg.state_dir), ("ring", cfg.ring_dir), ("incidents", cfg.incidents_dir)):
        probe = d / ".doctor-probe"
        try:
            d.mkdir(parents=True, exist_ok=True)
            probe.write_text("x")
            probe.unlink()
        except OSError as exc:
            out.append((FAIL, "writable", f"{label} dir {d}: {exc}"))
    return out or [(OK, "writable", "state, ring and incidents directories")]


def _run(cmd: list[str]) -> str | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def check_clock() -> list[Check]:
    if shutil.which("timedatectl"):
        got = _run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
        if got == "yes":
            return [(OK, "clock", "NTP synchronized")]
        if got == "no":
            return [(WARN, "clock", "NTP not synchronized: pcap timestamps will not line up with other logs")]
        return [(WARN, "clock", "timedatectl gave no answer")]
    if sys.platform == "darwin":
        return [(OK, "clock", "macOS keeps time itself (not checked)")]
    return [(WARN, "clock", "no timedatectl: NTP state not checked")]


def check_services() -> list[Check]:
    if not shutil.which("systemctl"):
        return [(OK, "services", "no systemd here (not checked)")]
    out = []
    for unit in ("threadwatch", "threadwatch-web"):
        state = _run(["systemctl", "is-active", unit]) or "unknown"
        enabled = _run(["systemctl", "is-enabled", unit]) or "unknown"
        if state == "active":
            out.append((OK, "services", f"{unit}.service active, {enabled}"))
        elif enabled in ("unknown", "not-found"):
            out.append((WARN, "services", f"{unit}.service not installed (bin/setup-host.sh)"))
        else:
            out.append((FAIL, "services", f"{unit}.service {state} ({enabled})"))
    return out


_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*$")


def load_env(path: Path) -> list[Check]:
    """Put config/alerts.env into this process's environment the way the
    systemd unit does (EnvironmentFile), so sinks build the same here.
    Variables already set win."""
    if not path.exists():
        return []
    out = []
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        out.append((WARN, "alerts.env", f"mode {mode:04o}: readable by others; chmod 400 it"))
    loaded = 0
    for lineno, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith(("#", ";")) or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip("'\"")
        if k.startswith("export ") or not _ENV_NAME.match(k):
            # systemd's EnvironmentFile takes everything before "=" as the
            # name and drops a line whose name is not a valid variable name
            # ("export TOKEN" has a space in it), so the daemon would never
            # see this value. Say so instead of quietly making it work here.
            hint = "drop the 'export' prefix" if k.startswith("export ") else "not a valid variable name"
            out.append((WARN, "alerts.env", f"line {lineno}: {k!r}: the systemd unit ignores this line "
                                            f"({hint}); write NAME=value"))
            continue
        if k not in os.environ:
            os.environ[k] = v
            loaded += 1
    out.append((OK, "alerts.env", f"{loaded} secret(s) loaded for this check"))
    return out


def check_alerts(cfg) -> list[Check]:
    from .alerts import build_heartbeats, build_sinks
    problems = []
    sinks = build_sinks(cfg.alerts_raw, problems.append)
    beats = build_heartbeats(cfg.heartbeats_raw, problems.append)
    out = load_env(cfg.config_dir / "alerts.env")
    if out:   # secrets may have arrived just now: build again with them
        problems.clear()
        sinks = build_sinks(cfg.alerts_raw, problems.append)
        beats = build_heartbeats(cfg.heartbeats_raw, problems.append)
    for p in problems:
        out.append((FAIL, "alerts", p))
    if not sinks:
        out.append((WARN, "alerts", "no sinks: warnings and criticals stay in the log (docs/ALERTING.md)"))
    else:
        out.append((OK, "alerts", f"{len(sinks)} sink(s): " + ", ".join(s.name for s in sinks)
                    + "; 'threadwatch alert-test' sends through them"))
    out.append((OK if beats else WARN, "heartbeats",
                f"{len(beats)} monitor(s)" if beats else "none: nothing pages when the recorder itself dies"))
    return out


def check_web(cfg) -> list[Check]:
    import urllib.request
    url = f"http://127.0.0.1:{cfg.web_port}/api/status"
    try:
        with urllib.request.urlopen(url, timeout=2) as r:
            json.loads(r.read())
        return [(OK, "web", f"review pages answer on port {cfg.web_port}")]
    except Exception as exc:
        return [(WARN, "web", f"nothing answers on port {cfg.web_port} ({type(exc).__name__}); "
                              "'threadwatch web' or threadwatch-web.service")]


def run_doctor(cfg, find_port: Callable[[], str] | None = None, now: float | None = None) -> list[Check]:
    checks = []
    for step in (lambda: check_config(cfg), lambda: check_inventory(cfg), lambda: check_credentials(cfg),
                 lambda: check_dongle(cfg, find_port), lambda: check_daemon(cfg, now), lambda: check_ring(cfg, now),
                 lambda: check_disk(cfg), lambda: check_writable(cfg), check_clock, check_services,
                 lambda: check_alerts(cfg), lambda: check_web(cfg)):
        try:
            checks.extend(step())
        except Exception as exc:   # one broken check must not hide the rest
            checks.append((WARN, "doctor", f"check crashed: {type(exc).__name__}: {exc}"))
    return checks


def print_report(checks: list[Check]) -> int:
    for level, subject, text in checks:
        print(f"{level:4s} {subject:12s} {text}")
    fails = sum(1 for c in checks if c[0] == FAIL)
    warns = sum(1 for c in checks if c[0] == WARN)
    print(f"{'all good' if not fails and not warns else f'{fails} failing, {warns} warning(s)'}")
    return 1 if fails else 0
