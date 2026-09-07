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
    if cfg.config_path is None:
        out.append((WARN, "config", f"no config.toml was read: built-in defaults are in use, "
                                    f"including channel {cfg.channel} "
                                    f"(cp config/config.example.toml config/config.toml)"))
    else:
        out.append((OK, "config", f"read {cfg.config_path}"))
    return out


def check_inventory(cfg) -> list[Check]:
    path = cfg.devices_path
    if path is None or not path.exists():
        return [(WARN, "inventory", "no devices.json: every address will be reported as unknown "
                                    "(threadwatch devices --suggest drafts entries)")]
    try:
        entries = json.loads(path.read_text())
    except ValueError as exc:
        return [(FAIL, "inventory", f"{path.name} is not valid JSON: {exc}")]
    if not isinstance(entries, list):
        return [(FAIL, "inventory", f"{path.name} must be a JSON list")]
    from .names import _EXT_ADDR, _norm, address_field_error, entry_addresses
    bad, addrs, unnamed, wrong_shape = [], 0, 0, []
    bad_fields = []
    for i, e in enumerate(entries, 1):
        # A null an editor left, or a bare string: the recorder skips it
        # and keeps recording, and naming it is this check's whole job.
        # Calling .get() on one made doctor report its own AttributeError.
        if not isinstance(e, dict):
            wrong_shape.append(f"entry {i} is {'null' if e is None else 'a ' + type(e).__name__}")
            continue
        if not (e.get("name") or "").strip():
            unnamed += 1
        # An address field of the wrong type - a number where the list of
        # addresses belongs. The recorder ignores that entry's addresses;
        # naming which entry it is, is this check's job. It used to raise
        # TypeError out of entry_addresses instead, here and in the
        # recorder, so the one command that reports on the file could not.
        shape = address_field_error(e)
        if shape:
            bad_fields.append(f"entry {i} ({e.get('name') or 'unnamed'}): {shape}")
        for a in entry_addresses(e):
            addrs += 1
            if not _EXT_ADDR.match(_norm(a)):
                bad.append(a)
    text = f"{len(entries) - len(wrong_shape)} devices, {addrs} addresses"
    if wrong_shape:
        return [(WARN, "inventory", f"{text}; skipped, not device objects: {', '.join(wrong_shape[:5])}"
                                    " (adopt and import refuse to rewrite the file until it is fixed)")]
    if bad_fields:
        return [(WARN, "inventory", f"{text}; addresses ignored, the field is not a list of addresses: "
                                    f"{', '.join(bad_fields[:5])}")]
    if bad:
        return [(WARN, "inventory", f"{text}; ignored (not 16 hex digits): {', '.join(bad[:5])}")]
    if unnamed:
        return [(WARN, "inventory", f"{text}; {unnamed} with a blank name (still unknown)")]
    return [(OK, "inventory", text)]


def check_border_routers(cfg) -> list[Check]:
    """Can this host see the Thread border routers over mDNS? Without that
    an Apple hub's new address after a reboot stays unnamed."""
    if cfg.border_router_browse_s <= 0:
        return [(OK, "border routers", "mDNS browse disabled ([border_routers] browse_s = 0)")]
    from .mdns import browse
    try:
        found = browse()
    except OSError as exc:
        return [(WARN, "border routers", f"mDNS browse failed ({exc})")]
    with_addr = [r for r in found if r.get("ext")]
    if not with_addr:
        return [(WARN, "border routers", "none found over mDNS: is this host on the routers' subnet, or is mDNS "
                                         "reflected between VLANs? Apple hubs' address changes will go unnamed")]
    names = ", ".join(f"{r['instance']} ({r['ext']})" for r in with_addr)
    return [(OK, "border routers", f"{len(with_addr)} found over mDNS: {names}")]


def check_credentials(cfg) -> list[Check]:
    from .pipeline import credentials_path
    try:
        import cryptography  # noqa: F401
    except ModuleNotFoundError:
        return [(FAIL, "credentials", "the 'cryptography' package is missing from this interpreter: "
                                      "the recorder cannot decrypt and will not start")]
    path = credentials_path(cfg)
    if not path.exists():
        return [(FAIL, "credentials", f"{path.name} missing: the recorder does not start without the Thread "
                                      "network key (docs/CREDENTIALS.md)")]
    out = []
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        out.append((WARN, "credentials", f"{path.name} is mode {mode:04o}: readable by others; chmod 600 it"))
    try:
        import tomllib
        key = tomllib.loads(path.read_text()).get("credentials", {}).get("network_key", "")
        if len(key) != 32 or any(c not in "0123456789abcdefABCDEF" for c in key):
            out.append((FAIL, "credentials",
                        f"{path.name}: network_key must be 32 hex digits; the recorder will not start"))
        else:
            out.append((OK, "credentials", f"{path.name} loads"))
    except Exception as exc:
        out.append((FAIL, "credentials", f"{path.name} unusable ({exc}); the recorder will not start"))
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
    from .record import find_sniffer_port
    return find_sniffer_port()


def check_daemon(cfg, now: float | None = None) -> list[Check]:
    now = now or time.time()
    path = cfg.state_dir / "status.json"
    if not path.exists():
        return [(WARN, "recorder", "no status.json: the recorder has never run here")]
    try:
        st = json.loads(path.read_text())
    except ValueError:
        return [(WARN, "recorder", "status.json is unreadable (mid-write?)")]
    age = now - st.get("updated", 0)
    if age > 90:
        return [(FAIL, "recorder", f"not running: status last written {age / 60:.0f} min ago")]
    fa = st.get("last_frame_age_s", 0)
    if fa > 120:
        return [(WARN, "recorder", f"alive but no frames for {fa:.0f} s (quiet channel? wrong channel?)")]
    return [(OK, "recorder", f"running, last frame {fa:.0f} s ago, {st.get('frames_total', 0):,} frames this run")]


def check_ring(cfg, now: float | None = None) -> list[Check]:
    now = now or time.time()
    files = sorted(cfg.ring_dir.glob("threadwatch-*.pcap")) if cfg.ring_dir.exists() else []
    if not files:
        return [(WARN, "ring", "no ring files yet")]
    newest = files[-1]
    age = now - newest.stat().st_mtime
    text = f"{len(files)} of {cfg.keep_hours} hourly files, newest {newest.name} written {age / 60:.0f} min ago"
    if age > 2 * 3600:
        return [(FAIL, "ring", text + ": the ring stopped growing")]
    return [(OK, "ring", text)]


def check_last_seen(cfg) -> list[Check]:
    """The last-seen table is the only record of when each device was heard
    and which silences were announced. It is written atomically, so a file
    that will not parse here is really damaged, not caught mid-write, and
    the recorder is running blind to every device's history."""
    path = cfg.state_dir / "last-seen.json"
    kept = sorted(cfg.state_dir.glob("last-seen.json.corrupt*")) if cfg.state_dir.exists() else []
    if not path.exists():
        return [(OK, "last-seen", "not written yet (nothing heard here so far)")]
    try:
        table = json.loads(path.read_text())
        if not isinstance(table, dict):
            raise ValueError(f"expected an object, got {type(table).__name__}")
    except (ValueError, OSError) as exc:
        return [(FAIL, "last-seen", f"last-seen.json is unreadable ({exc}): the recorder is starting from "
                                    "an empty table, so no device has a history and none can go quiet")]
    out = [(OK, "last-seen", f"{len(table)} address(es) with a history")]
    if kept:
        out.append((WARN, "last-seen", f"an earlier table was kept aside as {kept[-1].name}: "
                                       "that history is lost unless you put it back"))
    return out


def check_blind_spans(cfg) -> list[Check]:
    """blind-spans.json is when the recorder was not listening. Every
    silence is measured against it, so losing it charges each device for
    the recorder's own outages: a mesh quiet since before one pages
    device_quiet for every device at once."""
    path = cfg.state_dir / "blind-spans.json"
    if not path.exists():
        return [(OK, "blind-spans", "not written yet (no outage on record)")]
    try:
        spans = json.loads(path.read_text())
        if not isinstance(spans, list):
            raise ValueError(f"expected a list, got {type(spans).__name__}")
        for since, length in spans:
            float(since), float(length)
    except (ValueError, TypeError, OSError) as exc:
        return [(FAIL, "blind-spans", f"blind-spans.json is unreadable ({exc}): the recorder does not know "
                                      "when it was last off, so a silence that spans one of its own outages "
                                      "is charged to the device in full")]
    return [(OK, "blind-spans", f"{len(spans)} outage(s) on record")]


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
    saved = sto.get("snapshots_bytes") or 0
    if saved:
        text += f"; snapshots hold {fmt_bytes(saved)}"
    if free < need:
        return [(FAIL, "disk", text + ": it will not fit; lower keep_hours, set keep_gb, or move data_dir")]
    if free < need + 1024 ** 3:
        return [(WARN, "disk", text + ": under 1 GB to spare")]
    out = [(OK, "disk", text)]
    # A snapshot is a whole second copy of the ring, and only keep_snapshots
    # bounds how many are kept, so the room the ring still needs has to
    # survive one more of them.
    if cfg.snapshot_on_critical and free - sto["ring_bytes"] < need:
        out.append((WARN, "snapshots",
                    f"snapshot_on_critical is on and one more snapshot ({fmt_bytes(sto['ring_bytes'])}) would "
                    f"leave less than the {fmt_bytes(need)} the ring still needs: the recorder will refuse it "
                    "until you delete snapshots (threadwatch snapshots --delete) or lower keep_hours"))
    return out


def check_writable(cfg) -> list[Check]:
    out = []
    for label, d in (("state", cfg.state_dir), ("ring", cfg.ring_dir), ("snapshots", cfg.snapshots_dir)):
        probe = d / ".doctor-probe"
        try:
            d.mkdir(parents=True, exist_ok=True)
            probe.write_text("x")
            probe.unlink()
        except OSError as exc:
            out.append((FAIL, "writable", f"{label} dir {d}: {exc}"))
    return out or [(OK, "writable", "state, ring and snapshots directories")]


def _run(cmd: list[str]) -> str | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _in_container() -> bool:
    """Docker, Podman or an LXC container. Doctor cannot check the clock or
    reach the web container from inside one, and saying so beats a warning
    the reader can do nothing about (docs/DOCKER.md)."""
    if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
        return True
    if (_run(["systemd-detect-virt", "--container"]) or "none") != "none":
        return True
    try:
        return any(w in Path("/proc/1/cgroup").read_text() for w in ("docker", "containerd", "lxc"))
    except OSError:
        return False


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
    if _in_container():
        return [(OK, "clock", "in a container: the host keeps the time (not checked)")]
    return [(WARN, "clock", "no timedatectl: NTP state not checked")]


def check_version() -> list[Check]:
    """Which code is running here, and since when. Every other check says
    whether the box is fit to record, and answers the same whether the
    host holds the code you just pushed or a six-month-old checkout: this
    is the one that discriminates, so "doctor is green" at 3am after a fix
    can mean the fix is running."""
    from . import __version__
    from .config import repo_commit
    commit = repo_commit()
    what = f"threadwatch {__version__}" + (f" ({commit})" if commit
                                          else " (no .git and no REVISION here: an old rsync deploy?)")
    started = _run(["systemctl", "show", "-p", "ExecMainStartTimestamp", "--value", "threadwatch"]) \
        if shutil.which("systemctl") else None
    if started:
        what += f"; threadwatch.service started {started}"
    return [(OK, "version", what)]


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
        out.append((WARN, "alerts.env", f"mode {mode:04o}: readable by others; chmod 600 it"))
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


def check_ha_env(cfg) -> list[Check]:
    """config/ha.env holds the Home Assistant long-lived access token
    (docs/CREDENTIALS.md), so it gets the same mode check credentials.toml
    and alerts.env get. Not loaded into the environment: only `import`
    reads it, and it does that for itself.

    setup-host.sh and push-to-host.sh both chmod it on the capture host,
    so it is the workstation copy, and any host where setup-host.sh never
    ran, that this catches."""
    path = cfg.config_dir / "ha.env"
    if not path.exists():
        return []
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        return [(WARN, "ha.env", f"mode {mode:04o}: readable by others, and it holds the Home Assistant "
                                 "long-lived access token; chmod 600 it")]
    return [(OK, "ha.env", f"mode {mode:04o}")]


def check_alerts(cfg) -> list[Check]:
    from .alerts import SPOOL_FILE, ConfigError, build_heartbeats, build_sinks

    def build(problems: list[str]) -> tuple[list, list]:
        # A sink or heartbeat the daemon would refuse (unknown type, no
        # url, two with one name) raises here as it does at capture
        # start. That is the failing configuration this check exists to
        # catch, so it is a FAIL line, not a "check crashed" warning and
        # a green exit.
        sinks: list = []
        beats: list = []
        try:
            sinks = build_sinks(cfg.alerts_raw, problems.append)
        except ConfigError as exc:
            problems.append(f"{exc}: the recorder refuses to start on this [alerts] table")
        try:
            beats = build_heartbeats(cfg.heartbeats_raw, problems.append)
        except ConfigError as exc:
            problems.append(f"{exc}: the recorder refuses to start on this [[heartbeats]] table")
        return sinks, beats

    problems: list[str] = []
    sinks, beats = build(problems)
    out = load_env(cfg.config_dir / "alerts.env")
    if out:   # secrets may have arrived just now: build again with them
        problems.clear()
        sinks, beats = build(problems)
    for p in problems:
        out.append((FAIL, "alerts", p))
    if not sinks:
        out.append((WARN, "alerts", "no sinks: warnings and criticals stay in the log (docs/ALERTING.md)"))
    else:
        out.append((OK, "alerts", f"{len(sinks)} sink(s): " + ", ".join(s.name for s in sinks)
                    + "; 'threadwatch alert-test' sends through them"))
    spool = cfg.state_dir / SPOOL_FILE
    if spool.exists():
        try:
            held = sum(1 for line in spool.read_text().splitlines() if line.strip())
        except OSError:
            held = 0
        if held:
            out.append((WARN, "alerts", f"{held} record(s) the last run could not deliver are spooled in "
                                        f"{spool.name}; the recorder sends them at its next start"))
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
        if _in_container():
            # 127.0.0.1 is this container; the review pages serve from their
            # own, which doctor has no way to reach or to tell apart from one
            # that is down.
            return [(OK, "web", "review pages run in their own container (not checked from in here)")]
        return [(WARN, "web", f"nothing answers on port {cfg.web_port} ({type(exc).__name__}); "
                              "'threadwatch serve' or threadwatch-web.service")]


def run_doctor(cfg, find_port: Callable[[], str] | None = None, now: float | None = None) -> list[Check]:
    checks = []
    for step in (lambda: check_config(cfg), lambda: check_inventory(cfg), lambda: check_credentials(cfg),
                 lambda: check_border_routers(cfg),
                 lambda: check_dongle(cfg, find_port), lambda: check_daemon(cfg, now), lambda: check_ring(cfg, now),
                 lambda: check_last_seen(cfg), lambda: check_blind_spans(cfg), lambda: check_disk(cfg),
                 lambda: check_writable(cfg), check_clock,
                 check_services,
                 lambda: check_alerts(cfg), lambda: check_ha_env(cfg), lambda: check_web(cfg),
                 check_version):
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
