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
    from .names import _EXT_ADDR, _norm, address_field_error, entry_addresses, tolerance_field_error
    bad, addrs, unnamed, wrong_shape = [], 0, 0, []
    bad_fields, bad_tolerance, held, muted = [], [], 0, 0
    owners: dict[str, int] = {}
    shared: list[str] = []
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
        # The person's hold_s and mute (docs/ALERTING.md): the recorder
        # ignores a bad one and applies the defaults, so name it here.
        tolerance = tolerance_field_error(e)
        if tolerance:
            bad_tolerance.append(f"entry {i} ({e.get('name') or 'unnamed'}): {tolerance}")
        else:
            held += e.get("hold_s") is not None
            muted += e.get("mute") is True
        for a in entry_addresses(e):
            addrs += 1
            n = _norm(a)
            if not _EXT_ADDR.match(n):
                bad.append(a)
            elif owners.setdefault(n, i) != i:
                first = entries[owners[n] - 1]
                shared.append(f"{n} in entry {owners[n]} ({first.get('name') or 'unnamed'}) "
                              f"and entry {i} ({e.get('name') or 'unnamed'})")
    text = f"{len(entries) - len(wrong_shape)} devices, {addrs} addresses"
    if held or muted:
        text += f", {held} with a hold of their own, {muted} muted"
    if shared:
        return [(FAIL, "inventory", f"{text}; an address may belong to one entry, the recorder uses the "
                                    f"first: {', '.join(shared[:5])}")]
    if wrong_shape:
        return [(WARN, "inventory", f"{text}; skipped, not device objects: {', '.join(wrong_shape[:5])}"
                                    " (adopt and import refuse to rewrite the file until it is fixed)")]
    if bad_fields:
        return [(WARN, "inventory", f"{text}; addresses ignored, the field is not a list of addresses: "
                                    f"{', '.join(bad_fields[:5])}")]
    if bad:
        return [(WARN, "inventory", f"{text}; ignored (not 16 hex digits): {', '.join(bad[:5])}")]
    if bad_tolerance:
        return [(WARN, "inventory", f"{text}; default hold and not muted, the field cannot be read: "
                                    f"{', '.join(bad_tolerance[:5])}")]
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


def check_dongle(cfg, find: Callable[[], str] | None = None,
                 find_all: Callable[[], list[tuple[str, str | None]]] | None = None) -> list[Check]:
    """The dongle, or with [record] radios every dongle by serial: one line
    per configured radio (found, at which port, or missing), and a warning
    for any sniffer plugged in that the table does not name, with its
    serial ready to paste in."""
    if cfg.serial_port:
        if Path(cfg.serial_port).exists():
            return [(OK, "dongle", f"configured port {cfg.serial_port} exists")]
        return [(FAIL, "dongle", f"configured port {cfg.serial_port} does not exist")]
    try:
        import serial  # noqa: F401
    except ImportError:
        return [(FAIL, "dongle", "pyserial is not installed (pip install -r requirements.txt)")]
    if not cfg.radios:
        try:
            port = (find or _find_port)()
        except SystemExit as exc:
            return [(FAIL, "dongle", str(exc).splitlines()[0])]
        except Exception as exc:
            return [(FAIL, "dongle", f"could not enumerate serial ports: {exc}")]
        return [(OK, "dongle", f"nRF 802.15.4 sniffer at {port}")]
    try:
        found = (find_all or _find_all)()
    except Exception as exc:
        return [(FAIL, "dongle", f"could not enumerate serial ports: {exc}")]
    out: list[Check] = []
    by_serial = {usb_serial: port for port, usb_serial in found if usb_serial}
    for radio in cfg.radios:
        where = f" ({radio.placement})" if radio.placement else ""
        if radio.source == "tcp":
            out.append((OK, "dongle", f"radio {radio.label}: a relay from another host, listening on {radio.listen}"
                                      f"{where}; 'threadwatch status' says whether it is connected"))
            continue
        port = by_serial.get(radio.serial)
        if port:
            out.append((OK, "dongle", f"radio {radio.label}: sniffer {radio.serial} at {port}{where}"))
        else:
            out.append((FAIL, "dongle", f"radio {radio.label}: no sniffer with serial {radio.serial} is plugged "
                                        f"in{where}; the recorder runs without it and keeps looking"))
    configured = {r.serial for r in cfg.radios if r.serial}
    for port, usb_serial in found:
        if usb_serial is None:
            out.append((WARN, "dongle", f"a sniffer at {port} reports no USB serial: it cannot be named in "
                                        "[record] radios (reflash it, SETUP.md)"))
        elif usb_serial not in configured:
            out.append((WARN, "dongle", f"a sniffer with serial {usb_serial} at {port} is not in [record] radios: "
                                        "add a [[record.radios]] table for it, or unplug it"))
    return out


def _find_port() -> str:
    from .record import find_sniffer_port
    return find_sniffer_port()


def _find_all() -> list[tuple[str, str | None]]:
    from .record import find_sniffers
    return find_sniffers()


def check_daemon(cfg, now: float | None = None) -> list[Check]:
    now = now or time.time()
    path = cfg.state_dir / "status.json"
    if not path.exists():
        return [(WARN, "recorder", "no status.json: the recorder has never run here")]
    try:
        st = json.loads(path.read_text())
    except ValueError:
        return [(WARN, "recorder", "status.json is unreadable (mid-write?)")]
    from .review import status_state
    state, age = status_state(st, now)
    if state == "none":
        return [(WARN, "recorder", "status.json holds no recorder state (empty, or restored damaged)")]
    if state == "dead":
        return [(FAIL, "recorder", f"not running: status last written {age / 60:.0f} min ago")]
    fa = st.get("last_frame_age_s", 0)
    if state == "quiet":
        return [(WARN, "recorder", f"alive but no frames for {fa:.0f} s (quiet channel? wrong channel?)")]
    return [(OK, "recorder", f"running, last frame {fa:.0f} s ago, {st.get('frames_total', 0):,} frames this run")]


def check_ring(cfg, now: float | None = None) -> list[Check]:
    """The ring by hours, not files: with several radios an hour is one
    file per radio, and a radio that wrote fewer hours than the others was
    down for the difference."""
    from .ring import ring_hours
    now = now or time.time()
    hours = ring_hours(cfg.ring_dir)
    if not hours:
        return [(WARN, "ring", "no ring files yet")]
    _hour, newest_files = hours[-1]
    newest = max(newest_files.values(), key=lambda p: p.stat().st_mtime)
    age = now - newest.stat().st_mtime
    text = f"{len(hours)} of {cfg.keep_hours} hourly files, newest {newest.name} written {age / 60:.0f} min ago"
    labels = {label for _, files in hours for label in files}
    if len(labels) > 1:
        counts = {label: sum(1 for _, files in hours if label in files) for label in labels}
        short = [f"radio {label} has {n} of them" for label, n in sorted(counts.items(), key=lambda kv: kv[0] or "")
                 if n < len(hours)]
        text = f"{len(hours)} of {cfg.keep_hours} hours ({len(labels)} radios), newest {newest.name} written " \
               f"{age / 60:.0f} min ago" + (f"; {', '.join(short)}" if short else "")
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
    from .names import last_seen_row_problem
    bad = {a: "not an object" if not isinstance(r, dict) else last_seen_row_problem(r) for a, r in table.items()}
    bad = {a: why for a, why in bad.items() if why is not None}
    out = [(OK, "last-seen", f"{len(table) - len(bad)} address(es) with a history")]
    if bad:
        a, why = next(iter(bad.items()))
        out.append((WARN, "last-seen", f"{len(bad)} row(s) the recorder drops when it starts ({a}: {why}"
                                       + (f", and {len(bad) - 1} more" if len(bad) > 1 else "") + ")"))
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
    extra = sto.get("snapshot_extra_bytes") or 0
    if extra:
        text += f"; a snapshot adds up to {fmt_bytes(extra)} of HA add-on logs"
    if free < need:
        return [(FAIL, "disk", text + ": it will not fit; lower keep_hours, set keep_gb, or move data_dir")]
    if free < need + 1024 ** 3:
        return [(WARN, "disk", text + ": under 1 GB to spare")]
    out = [(OK, "disk", text)]
    # A snapshot is a whole second copy of the ring, and only keep_snapshots
    # bounds how many are kept, so the room the ring still needs has to
    # survive one more of them.
    copy = sto["ring_bytes"] + extra
    if cfg.snapshot_on_critical and free - copy < need:
        out.append((WARN, "snapshots",
                    f"snapshot_on_critical is on and one more snapshot ({fmt_bytes(copy)}"
                    + (" with the HA logs" if extra else "") + ") would "
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


HA_LOGS_PROBE_TIMEOUT_S = 10.0
HA_LOGS_STALE_S = 10 * 60


def check_ha_logs(cfg, now: float | None = None) -> list[Check]:
    """With [ha_logs] enabled: can this host read each add-on's log? One
    read-only request per add-on for its newest line (Range:
    entries=:-1:1), which says whether the token is an admin's, the slug
    exists, HA answers, and the add-on is running (a newest line over ten
    minutes old is an add-on that has stopped)."""
    if not getattr(cfg, "ha_logs_enabled", False):
        return []
    import urllib.error
    import urllib.request

    from .halogs import credentials, journal_stamp
    from .httpclient import redact_text, redact_url, urlopen
    settings = credentials(cfg)
    if settings is None:
        return [(WARN, "ha-logs", "[ha_logs] enabled but config/ha.env has no HA_TOKEN: snapshots will carry no "
                                  "add-on logs (docs/HOME-ASSISTANT.md: the token must be an admin user's)")]
    url, token = settings
    now = now if now is not None else time.time()
    out: list[Check] = []
    for slug in cfg.ha_logs_addons:
        req = urllib.request.Request(f"{url}/api/hassio/addons/{slug}/logs?verbose",
                                     headers={"Authorization": f"Bearer {token}", "Accept": "text/plain",
                                              "Range": "entries=:-1:1"})
        try:
            with urlopen(req, timeout=HA_LOGS_PROBE_TIMEOUT_S) as resp:
                body = resp.read(65536).decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            why = ("the token is not an admin user's, or is wrong" if exc.code in (401, 403)
                   else "no such add-on" if exc.code == 404 else "unexpected answer")
            out.append((WARN, "ha-logs", f"{slug}: HTTP {exc.code} from {redact_url(url)}: {why}"))
            continue
        except (OSError, ValueError) as exc:
            out.append((WARN, "ha-logs", f"{slug}: {redact_url(url)} not reachable: "
                                         f"{redact_text(str(getattr(exc, 'reason', exc)), (token,))}"))
            continue
        stamps = [t for t in (journal_stamp(line) for line in body.splitlines()) if t is not None]
        if not stamps:
            out.append((WARN, "ha-logs", f"{slug}: the log has no timestamped line: the add-on may be stopped, "
                                         "or the endpoint did not answer in the journal's verbose format"))
            continue
        newest = max(stamps)
        age = now - newest
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(newest))
        if age > HA_LOGS_STALE_S:
            out.append((WARN, "ha-logs", f"{slug}: newest line {when} ({age / 60:.0f} min ago): the add-on looks "
                                         "stopped"))
        else:
            out.append((OK, "ha-logs", f"{slug}: newest line {when} ({age:.0f} s ago)"))
    if getattr(cfg, "ha_logs_archive", False):
        for slug in cfg.ha_logs_addons:
            out.extend(_check_archive(cfg, slug, now))
    return out


ARCHIVE_STALE_S = 2 * 3600


def _check_archive(cfg, slug: str, now: float) -> list[Check]:
    """With the archive on: is its newest hour for this add-on recent? An
    archive more than two hours behind has missed a boundary pass, which
    the recorder's own stalled event also says."""
    from .halogs import archive_status, hour_start
    status = archive_status(cfg).get(slug) or {}
    last = status.get("last_archived")
    if not last:
        return [(WARN, "ha-logs", f"{slug}: the hourly archive has nothing yet (it fills two minutes after each "
                                  "hour while the recorder runs)")]
    age = now - (hour_start(last) + 3600.0)
    text = f"{slug}: archive up to {last} UTC ({age / 60:.0f} min behind)"
    if status.get("pending"):
        text += f", {len(status['pending'])} hour(s) pending"
    if status.get("lost"):
        text += f", {len(status['lost'])} lost"
    if age > ARCHIVE_STALE_S:
        return [(WARN, "ha-logs", text + ": the archive has not kept up; is the recorder running, and does HA answer?")]
    return [(OK, "ha-logs", text)]


def check_ha_availability(cfg, now: float | None = None) -> list[Check]:
    """With [ha_availability] enabled: HA answers /api/states, the
    websocket registry lookup works, which HA Thread devices match the
    inventory (WARN naming the unmatched, watched under their HA names),
    and devices with no usable entity (WARN). A device's own hold and
    mute are inventory fields, checked by check_inventory."""
    if not getattr(cfg, "ha_availability_enabled", False):
        return []
    from .ha import HAError
    from .haavail import credentials_or_none, poll_states, refresh_map
    from .httpclient import redact_text, redact_url
    from .names import read_inventory
    out: list[Check] = []
    creds = credentials_or_none(cfg)
    if creds is None:
        out.append((WARN, "ha-avail", "[ha_availability] enabled but config/ha.env has no HA_TOKEN: nothing is polled"))
        return out
    url, token = creds
    try:
        states = poll_states(url, token)
        out.append((OK, "ha-avail", f"GET /api/states: {len(states)} entities from {redact_url(url)}"))
    except Exception as exc:
        out.append((WARN, "ha-avail", f"GET /api/states at {redact_url(url)} failed: "
                                      f"{redact_text(str(getattr(exc, 'reason', exc)), (token,))}"))
    try:
        entries = read_inventory(cfg.devices_path) if cfg.devices_path else []
    except ValueError:
        entries = []
    try:
        mapping = refresh_map(url, token, entries)
    except HAError as exc:
        out.append((WARN, "ha-avail", f"device registry over the websocket: {redact_text(str(exc), (token,))}"))
        return out
    matched = [m for m in mapping.values() if m.get("matched")]
    unmatched = sorted((m.get("ha_name") or "?") for m in mapping.values() if not m.get("matched"))
    out.append((OK, "ha-avail", f"{len(mapping)} Thread devices in Home Assistant, {len(matched)} matched to the "
                                "inventory by address"))
    if unmatched:
        out.append((WARN, "ha-avail", f"{len(unmatched)} not in devices.json, watched under their HA names: "
                                      + ", ".join(unmatched) + " (threadwatch import --write adds them)"))
    empty = sorted((m.get("name") or m.get("ha_name") or "?") for m in mapping.values() if not m.get("entities"))
    if empty:
        out.append((WARN, "ha-avail", f"{len(empty)} device(s) with no usable entity, so never judged: "
                                      + ", ".join(empty)))
    return out


OTBR_STALE_POLLS = 2


def check_otbr(cfg, now: float | None = None, probe: Callable[[list[str]], dict] | None = None) -> list[Check]:
    """With [otbr] enabled: can this host run ot-ctl on the border router,
    and is the recorder's inventory fresh? The poller writes nothing to
    the journal on failure and backs off up to an hour, so a revoked key,
    a renamed container or a sudo that stopped answering would otherwise
    show only as a stale sample, and the key journal would silently fall
    back to guard `unknown` and unnamed TREL peers. One read-only
    `ot-ctl state` over the configured key, then the newest sample's
    age and per-command results."""
    if not getattr(cfg, "otbr_enabled", False):
        return []
    from . import otbr
    now = now if now is not None else time.time()
    where = f"{cfg.otbr_ssh_target}:{cfg.otbr_ssh_port}"
    out: list[Check] = []
    identity = cfg.otbr_ssh_identity_file
    if identity and not Path(identity).expanduser().exists():
        out.append((WARN, "otbr", f"ssh_identity_file {identity} does not exist on this host: the inventory "
                                  f"cannot reach {where} (docs/OPERATIONS.md: the recorder's own key)"))
    else:
        result = (probe or otbr.run_command)(otbr.command_argv(cfg, "state"))
        if result["status"] == "ok":
            lines = [ln.strip() for ln in result["output"].splitlines() if ln.strip() and ln.strip() != "Done"]
            out.append((OK, "otbr", f"ot-ctl state: {lines[0] if lines else '(no role line)'} "
                                    f"via {where} in {cfg.otbr_container}"))
        else:
            reason = next((ln.strip() for ln in result.get("output", "").splitlines() if ln.strip()),
                          result.get("error") or "")
            why = {"unreachable": "SSH did not connect: host, port, key or the add-on's authorized_keys",
                   "timeout": f"no answer within {otbr.TIMEOUT_S} s",
                   "unsupported": "ot-ctl did not accept the command",
                   "error": "the command ran but failed: sudo, docker or the container name",
                   "incomplete": "output ended without Done"}.get(result["status"], result["status"])
            out.append((WARN, "otbr", f"ot-ctl state via {where}: {result['status']} ({why})"
                                      + (f": {reason[:160]}" if reason else "")))
    history = otbr.load_inventory(cfg.state_dir / otbr.STATE)
    samples = history.get("samples") or []
    poll_s = float(getattr(cfg, "otbr_poll_s", 600))
    if not samples:
        out.append((WARN, "otbr", f"{otbr.STATE}: no sample yet (the recorder polls at startup and every "
                                  f"{poll_s / 60:.0f} min while it runs)"))
        return out
    newest = samples[-1]
    age = now - newest["completed_at"]
    when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(newest["completed_at"]))
    statuses = {k: (r.get("status") if isinstance(r, dict) else None) for k, r in newest["commands"].items()}
    bad = {k: v for k, v in statuses.items() if v != "ok"}
    ok_count = len(statuses) - len(bad)
    text = f"newest sample {when} ({age / 60:.0f} min ago), {ok_count} of {len(otbr.COMMANDS)} commands ok, " \
           f"{len(samples)} sample(s) on record"
    if newest.get("status") != "ok" or bad:
        failing = ", ".join(f"{k} {v}" for k, v in bad.items()) or newest.get("status", "?")
        wait = history.get("next_poll_at", 0) - now
        retry = f"next poll in {wait / 60:.0f} min" if wait > 0 else "next poll is due"
        backoff = " (backing off)" if history.get("failures") else ""
        out.append((WARN, "otbr", f"{text}: {failing}; {retry}{backoff}"))
    elif age > OTBR_STALE_POLLS * poll_s:
        out.append((WARN, "otbr", f"{text}: older than {OTBR_STALE_POLLS} polls, so the key journal will not use "
                                  "it; is the recorder running?"))
    else:
        out.append((OK, "otbr", text))
    return out


def check_alerts(cfg) -> list[Check]:
    from .alerts import SPOOL_FILE, ConfigError, build_heartbeats, build_sinks

    def build(problems: list[str], notes: list[str]) -> tuple[list, list]:
        # A sink or heartbeat the daemon would refuse (unknown type, no
        # url, two with one name) raises here as it does at capture
        # start. That is the failing configuration this check exists to
        # catch, so it is a FAIL line, not a "check crashed" warning and
        # a green exit. One kept out by a missing secret is a FAIL too.
        # Anything else the builders log (an event filter naming an event
        # the recorder does not emit) is a start-up note the recorder runs
        # with, so here it is a warning: doctor exits 1 only when the box
        # is not fit to record.
        sinks: list = []
        beats: list = []
        logged: list[str] = []
        unbuilt: list[tuple[str, str]] = []
        try:
            sinks = build_sinks(cfg.alerts_raw, logged.append, unbuilt)
        except ConfigError as exc:
            problems.append(f"{exc}: the recorder refuses to start on this [alerts] table")
        try:
            beats = build_heartbeats(cfg.heartbeats_raw, logged.append, unbuilt)
        except ConfigError as exc:
            problems.append(f"{exc}: the recorder refuses to start on this [[heartbeats]] table")
        disabled = tuple(f"disabled: {reason}" for _, reason in unbuilt)
        for line in logged:
            (problems if line.endswith(disabled) else notes).append(line)
        return sinks, beats

    problems: list[str] = []
    notes: list[str] = []
    sinks, beats = build(problems, notes)
    out = load_env(cfg.config_dir / "alerts.env")
    if out:   # secrets may have arrived just now: build again with them
        problems.clear()
        notes.clear()
        sinks, beats = build(problems, notes)
    for p in problems:
        out.append((FAIL, "alerts", p))
    for n in notes:
        out.append((WARN, "alerts", n))
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
                 lambda: check_alerts(cfg), lambda: check_ha_env(cfg), lambda: check_ha_logs(cfg, now),
                 lambda: check_ha_availability(cfg, now), lambda: check_otbr(cfg, now),
                 lambda: check_web(cfg), check_version):
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
