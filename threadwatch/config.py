"""Configuration loading (TOML, stdlib tomllib — Python 3.11+)."""

from __future__ import annotations

import math
import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .detect import ONSETS_MAX, DetectorConfig

REPO_ROOT = Path(__file__).resolve().parent.parent


# What a deploy that ships no .git leaves behind to say which revision it
# copied (bin/push-to-host.sh writes it). Without it an rsynced host can
# say nothing at all about which code it holds, which is the one question
# a deploy needs answered.
REVISION_FILE = "REVISION"

# [border_routers] rotation: how much evidence retires the address a border
# router rotated away from. Retirement exempts a row from every quiet check,
# so this is the setting that decides whether an unauthenticated mDNS record
# alone can stop a device being reported silent.
ROTATION_POLICIES = frozenset(("corroborated", "trusted"))


def _git(*args: str) -> str | None:
    import subprocess
    try:
        done = subprocess.run(["git", "-C", str(REPO_ROOT), *args],
                              capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def repo_commit() -> str | None:
    """The revision of the code at REPO_ROOT as it stands on disk now.

    What a deploy recorded in REVISION when there is one, else the
    checkout's HEAD, marked "+" when the working tree holds edits that are
    not in it (push-to-host.sh rsyncs the working tree, edits and all).
    What tells a host running the code you pushed from one running a
    six-month-old copy. A process that has been running has to ask
    running_commit() instead: this answer moves under it.

    REVISION wins over .git: the file is only ever written by a deploy
    (push-to-host.sh, a Docker build), never in a checkout, and a host
    that was cloned once and rsynced ever since keeps its original .git,
    which the deploys neither update nor remove. Read by git that names a
    commit from months ago; on a host without git it names nothing, and
    the answer was "no .git and no REVISION" beside a REVISION file."""
    try:
        recorded = (REPO_ROOT / REVISION_FILE).read_text().strip().splitlines()[0][:64]
    except (OSError, IndexError):
        recorded = ""
    if recorded:
        return recorded
    if not (REPO_ROOT / ".git").exists():
        return None
    head = (_git("rev-parse", "--short", "HEAD") or "").strip()
    if not head:
        return None
    dirty = _git("status", "--porcelain", "--untracked-files=no")
    return head + ("+" if dirty and dirty.strip() else "")


_running: list = []


def running_commit() -> str | None:
    """The revision the calling process is running, resolved once and kept.

    A process runs the code it imported, and repo_commit() answers for the
    checkout as it is now: `git pull` under a running recorder moves HEAD,
    and a status line that re-read it then claimed the newly deployed
    commit while the daemon still executed the old one - the opposite of
    what the line is for, since it is how a restart that did not happen is
    caught. Ask it at start (a long-lived process should, before anything
    can change under it); a short-lived command may as well ask
    repo_commit() and answer for the checkout."""
    if not _running:
        _running.append(repo_commit())
    return _running[0]


@dataclass
class RadioConfig:
    """One entry of [record] radios: a dongle named by its USB serial.
    label goes into file names, events and the pages; placement is free
    text for the pages ("upstairs landing"). The first entry is the
    primary: its ring files keep the unlabelled names."""
    label: str
    serial: str
    placement: str = ""


@dataclass
class Config:
    channel: int = 25
    # [network] pan_id: this network's PAN id. When set, it decides whose
    # silences count and which PANs are foreign; when unset the recorder
    # guesses from which PAN it hears most, which a busier neighbour on the
    # same channel can win (see Pipeline.dominant_pan).
    pan_id: int | None = None
    serial_port: str | None = None          # auto-detect when unset
    radios: list[RadioConfig] = field(default_factory=list)   # [record] radios; empty = one dongle, found by id
    data_dir: Path = REPO_ROOT / "data"
    keep_hours: int = 168                      # ring: one hourly file each, a week of them
    keep_bytes: int | None = None           # ring: total size cap ([record] keep_gb), None = files only
    snapshot_on_critical: bool = False         # save the ring when a critical event fires
    keep_snapshots: int = 4                    # how many auto-* snapshots to keep; -1 = no cap, 0 = take none
    devices_path: Path | None = None
    visitors_path: Path | None = None        # config/visitors.json: labels for visiting addresses (phones)
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    config_dir: Path = REPO_ROOT / "config"
    config_path: Path | None = None         # the file load() read, None when defaults stood
    credentials_path: Path | None = None
    # A saved snapshot to read state and events from instead of
    # data/state (replay and device --snapshot): its copies of the state
    # files and the event log sit at its top level, and nothing is ever
    # written there. See for_snapshot.
    snapshot_dir: Path | None = None
    loaded_config: str | None = None       # redacted source captured by load()
    capture_provenance: dict | None = None # recorder startup evidence
    # Silence (seconds) before a device_quiet event. 30 min: the 2026-09-02
    # soak (9.8 h, 22 sleepy end devices) showed 19 of them never silent for
    # 3 min and the rest under 30 min once marginal-reception devices are
    # excluded, so from the sniffer's chair sleepy devices are no quieter
    # than routers and one window serves both.
    quiet_s: float = 30 * 60
    # Below this average RSSI the sniffer is at the edge of its range and a
    # silence is logged at notice severity (kept, not paged): the 2026-09-02
    # soak showed every device heard at -84 dBm or worse dropping out for
    # 20-70 min at a time while everything at -80 dBm or better never went
    # 2 min without a frame.
    quiet_min_rssi_dbm: float = -82.0
    # [link] slow degradation: the average RSSI sitting this far below the
    # device's daily reference for this long is logged (notice). 0 disables.
    link_drop_db: float = 8.0
    link_hold_s: float = 30 * 60
    # [polls] a poll_starvation that opens within this long of the previous
    # episode's close is logged at notice, not paged: the 2026-09-04 night
    # (37 episodes from one sensor at -81 dBm, every one closed by a plain
    # ACK, no rejoin) showed a flapping device is a parent whose ACKs the
    # sniffer only sometimes hears, not a device losing its parent. 0 pages
    # every episode.
    poll_rearm_s: float = 60 * 60
    # [polls] a starvation that would page is logged at notice first and
    # paged only if the polls are still unanswered this long later. Every
    # starvation in the 2026-09-02..05 log that recovered by itself did so
    # inside eight minutes; a device that has really lost its parent stays
    # unanswered far longer. 0 pages at the threshold, as before.
    poll_confirm_s: float = 10 * 60
    # [keys] the key-generation detectors (docs/ALERTING.md, key_lag). A
    # device still transmitting two or more key generations below its live
    # parent (or, for a router, the mesh) is cut off: OpenThread accepts
    # frames only within one generation of its own, while the radio still
    # acknowledges its polls, so nothing else notices. The episode is
    # opened silently and paged only once it has held this long with fresh
    # frames past the mark (0 pages at once).
    key_confirm_s: float = 15 * 60
    # A generation reading (the device's last authenticated frame) older
    # than this is not judged: neither behind nor caught up.
    key_fresh_s: float = 30 * 60
    # How long after a rotation to log key_lag_census, the per-generation
    # roll call that shows who followed.
    key_census_delay_s: float = 60 * 60
    # An episode reopening this soon after closing is logged at notice,
    # not paged, as for [polls] rearm_s.
    key_rearm_s: float = 60 * 60
    # The mesh's rotation time in hours, when known: a rotation arriving
    # under 90% of it after the previous one is called "early" in the
    # key_sequence_advanced note. None says nothing about timing.
    key_rotation_hours: float | None = None
    # [ha_logs] copy the Home Assistant OTBR and Matter Server add-on logs
    # into every snapshot (docs/ANALYSIS.md, "Snapshots"). Off by default: it
    # needs config/ha.env with a token from an admin user, since the add-on
    # log endpoint goes through the Supervisor.
    ha_logs_enabled: bool = False
    ha_logs_addons: list = field(default_factory=lambda: ["core_openthread_border_router", "core_matter_server"])
    # Never request further back than this: HA's journal retained about
    # 11.5 h with the OTBR at log level info, and a request past it costs
    # nothing but returns nothing.
    ha_logs_max_hours: float = 12.0
    ha_logs_read_timeout_s: float = 30.0      # one silent read
    ha_logs_deadline_s: float = 15 * 60       # the whole transfer, per add-on; what arrived is kept past it
    ha_logs_retry: bool = True                # the recorder retries failed or partial fetches
    ha_logs_archive: bool = False             # phase 2: the hourly archive under data/ha-logs/
    # [ha_availability] alert when Home Assistant marks a Thread device
    # unavailable, with the radio evidence that says why (docs/ALERTING.md,
    # ha_unavailable). Off by default: it needs config/ha.env, and the
    # devices are linked to the inventory at runtime, never in devices.json.
    ha_availability_enabled: bool = False
    # Per-device hold and mute, keyed by HA device id, relative to the
    # config directory like [devices] inventory (config/ha-availability.json).
    ha_availability_settings: str = "ha-availability.json"
    ha_availability_poll_s: float = 60.0          # one GET /api/states this often
    ha_availability_hold_s: float = 10 * 60       # unavailable this long before a warning
    ha_availability_burst_devices: int = 3        # this many non-muted devices ...
    ha_availability_burst_window_s: float = 10 * 60   # ... within this window is one critical burst
    ha_availability_burst_hold_s: float = 120.0   # the newest must have stayed unavailable this long
    ha_availability_rearm_s: float = 60 * 60      # a reopening this soon after closing is a notice
    ha_availability_registry_refresh_s: float = 60 * 60   # how often the HA device map is rebuilt
    # [retransmissions] a minute of elevated retries is logged at notice and
    # paged only if the rate has stayed up this long. One minute of
    # elevation is a microwave; a storm building keeps the rate up. 0 pages
    # at the first minute, as before.
    retrans_confirm_s: float = 5 * 60
    # [border_routers] how often the recorder asks the LAN (mDNS, the
    # _meshcop._udp service every border router advertises) which extended
    # address each border router has now. Apple hubs change theirs on every
    # reboot; this is how the new one gets the old name. 0 disables.
    border_router_browse_s: float = 10 * 60
    # [border_routers] what it takes to believe a rotation. "corroborated"
    # (the default) retires the old address only once the radio agrees the
    # two addresses are one device -- the same router id, or a clean
    # handover at the same signal level. mDNS is unauthenticated, and a
    # retired row is exempt from every quiet check, so an advertisement
    # nobody can check must not be able to silence a device for ever.
    # "trusted" retires on the advertisement alone, as before.
    border_router_rotation: str = "corroborated"
    # [summary] one daily_summary event per local day, at this hour (-1 off).
    summary_hour: int = 8
    summary_severity: str = "notice"
    # [events] day files older than this are deleted by the recorder, at
    # start and once a day. 0 keeps them for ever. The pages read a month
    # either side of a day (review.EPISODE_WINDOW_DAYS), so history past
    # that costs disk and the snapshot copy only.
    events_keep_days: int = 365
    # Loopback, not 0.0.0.0: the pages have no authentication of any kind
    # and publish every device name and EUI-64, each device's role, parent
    # and last-seen time, and the whole event history - a per-room,
    # per-hour trace of the home. Reaching them from another machine is an
    # explicit [web] bind, so nobody gets it by not reading the comment.
    web_bind: str = "127.0.0.1"                # [web] review pages (threadwatch serve)
    web_port: int = 8080
    alerts_raw: dict = field(default_factory=dict)      # [alerts] table, verbatim
    heartbeats_raw: list = field(default_factory=list)  # [[heartbeats]] tables, verbatim

    @property
    def ring_dir(self) -> Path:
        return self.data_dir / "ring"

    def for_snapshot(self, snapshot_dir: Path) -> "Config":
        """This configuration turned on a saved snapshot: state, events
        and (when the copy kept one) the inventory come from the
        snapshot's copies, so names and history are the ones current when
        it was saved, not today's. Everything else is the live
        configuration's - the credentials above all, but the detector
        thresholds, the quiet window, the channel and the configured PAN
        too. The snapshot's own config.toml is a record of what judged
        those packets, and is deliberately not loaded: its sinks are
        redacted, and reading a bundle must not turn a stranger's file
        into settings this host runs on."""
        import dataclasses
        inventory = snapshot_dir / "devices.json"
        return dataclasses.replace(self, snapshot_dir=snapshot_dir,
                                   devices_path=inventory if inventory.exists() else self.devices_path)

    @property
    def state_dir(self) -> Path:
        if self.snapshot_dir is not None:
            return self.snapshot_dir
        d = self.data_dir / "state"
        # Created on first use for whoever writes there (the recorder). A
        # reader on a read-only mount (the web container, data:ro) cannot
        # create it and must not die trying: a missing state directory
        # means capture has not run yet, which every reader copes with as
        # empty state, and whoever writes fails at its own write with the
        # real path in the message.
        try:
            d.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
        return d

    @property
    def snapshots_dir(self) -> Path:
        return self.data_dir / "snapshots"

    @property
    def events_dir(self) -> Path:
        return self.state_dir / "events"


# Every section load() understands, and the keys it reads from each.
# A name that is not here is a typo, or a setting from a different version:
# either way tomllib parses it happily and load() never looks at it, so the
# value silently does nothing. On a recorder that means retention, a
# snapshot or an alert quietly not happening, discovered when the packets
# are already gone. Unknown names are rejected at load instead.
# [alerts] and [heartbeats] map to None: alerts.py owns their shape and
# reports on it when it builds the sinks, where a single unbuildable sink
# can be logged rather than stop the recorder from starting.
SECTIONS: dict[str, frozenset[str] | None] = {
    "network": frozenset(("channel", "pan_id")),
    "record": frozenset(("serial_port", "data_dir", "keep_hours", "keep_gb",
                         "snapshot_on_critical", "keep_snapshots", "radios")),
    "devices": frozenset(("inventory",)),
    "visitors": frozenset(("file",)),
    "quiet": frozenset(("silence_s", "min_rssi_dbm")),
    "link": frozenset(("drop_db", "hold_s")),
    "polls": frozenset(("rearm_s", "confirm_s")),
    "keys": frozenset(("confirm_s", "fresh_s", "census_delay_s", "rearm_s", "rotation_hours")),
    "ha_logs": frozenset(("enabled", "addons", "max_hours", "read_timeout_s", "deadline_s", "retry", "archive")),
    "ha_availability": frozenset(("enabled", "settings", "poll_s", "hold_s", "burst_devices", "burst_window_s",
                                  "burst_hold_s", "rearm_s", "registry_refresh_s")),
    "retransmissions": frozenset(("confirm_s",)),
    "border_routers": frozenset(("browse_s", "rotation")),
    "summary": frozenset(("hour", "severity")),
    "detect": frozenset(("flood_multiplier", "flood_min_frames", "period_min_s",
                         "period_max_s", "period_onsets", "alert_cooldown_s")),
    "events": frozenset(("keep_days",)),
    "web": frozenset(("bind", "port")),
    "credentials": frozenset(("file",)),
    "alerts": None,
    "heartbeats": None,
}


# An add-on slug as the Supervisor names them: core_openthread_border_router.
_ADDON_SLUG = re.compile(r"^[a-z0-9_]+$")


def _finite(section: str, key: str, value):
    """A number a range check can actually reject, or a ValueError.

    TOML has ``nan`` and ``inf``. Every comparison against nan is false, so
    ``if x < 0: raise`` reads as satisfied and the setting is accepted; a
    positive infinity passes "0 or more" and then sets a confirmation time no
    packet timestamp reaches, so the delay never ends. Neither is a duration,
    a threshold or a limit. Values of other types are handed back untouched:
    the coercions around each call site (a quoted channel, a "0x4e21" PAN id)
    are unchanged.
    """
    # Float-valued settings also accept numeric strings. Validate the
    # converted value so quoted "nan", "inf" and overflowing exponents
    # cannot reintroduce non-finite durations after this check.
    number = value
    if isinstance(value, str):
        try:
            number = float(value)
        except ValueError:
            pass                       # preserve each setting's own coercion/error
    if isinstance(number, float) and not math.isfinite(number):
        raise ValueError(f"[{section}] {key} must be a finite number, not {value!r}")
    return value


_RADIO_KEYS = frozenset(("label", "serial", "placement"))
_SERIAL_RE = re.compile(r"^[0-9A-Za-z]{1,64}$")


def _radios(raw) -> list[RadioConfig]:
    """[record] radios as written: an array of tables, each a dongle by USB
    serial. Labels become file names and event fields, so they are held
    to a short lower-case alphabet; serials are compared case-blind and
    kept upper-case, as udev and /dev/serial/by-id print them. Nothing
    here is optional once the table exists: a radio without a serial
    would be "whichever dongle is left", which is the ambiguity the table
    is there to remove."""
    if raw is None:
        return []
    from .ring import LABEL_RE
    if not isinstance(raw, list) or not all(isinstance(r, dict) for r in raw):
        raise ValueError("[record] radios must be an array of tables ([[record.radios]] with label and serial); "
                         "see config/config.example.toml")
    out: list[RadioConfig] = []
    for i, entry in enumerate(raw, 1):
        for key in sorted(entry):
            if key not in _RADIO_KEYS:
                raise ValueError(f"unknown key {key!r} in [[record.radios]] entry {i} "
                                 f"(a radio takes: {', '.join(sorted(_RADIO_KEYS))})")
        label, serial, placement = entry.get("label"), entry.get("serial"), entry.get("placement", "")
        if not isinstance(label, str) or not LABEL_RE.match(label):
            raise ValueError(f"[[record.radios]] entry {i}: label must be 1-16 of a-z, 0-9 and _ (it names ring "
                             f"files and events), not {label!r}")
        if not isinstance(serial, str) or not _SERIAL_RE.match(serial):
            raise ValueError(f"[[record.radios]] entry {i} ({label}): serial must be the dongle's USB serial as "
                             f"'threadwatch doctor' or /dev/serial/by-id prints it, not {serial!r}")
        if not isinstance(placement, str):
            raise ValueError(f"[[record.radios]] entry {i} ({label}): placement must be text, not {placement!r}")
        if any(r.label == label for r in out):
            raise ValueError(f"[[record.radios]]: two radios labelled {label!r}")
        if any(r.serial == serial.upper() for r in out):
            raise ValueError(f"[[record.radios]]: serial {serial} is listed twice (for {label} and for "
                             f"{next(r.label for r in out if r.serial == serial.upper())})")
        out.append(RadioConfig(label=label, serial=serial.upper(), placement=placement))
    return out


def check_sections(raw: dict, path: Path) -> None:
    """Reject sections and keys load() would otherwise ignore in silence."""
    where = f" in {path}"
    for section in sorted(raw):
        if section not in SECTIONS:
            raise ValueError(f"unknown section [{section}]{where} "
                             f"(see config/config.example.toml for the sections there are)")
        keys = SECTIONS[section]
        if keys is None:
            continue
        table = raw[section]
        if not isinstance(table, dict):
            raise ValueError(f"[{section}]{where} must be a section of settings, not {table!r}")
        for key in sorted(table):
            if key not in keys:
                raise ValueError(f"unknown key {key!r} in [{section}]{where} "
                                 f"([{section}] takes: {', '.join(sorted(keys))})")


def load(path: Path | None) -> Config:
    explicit_path = path is not None
    cfg = Config()
    if path is None:
        default = REPO_ROOT / "config" / "config.toml"
        path = default if default.exists() else None
    if path:
        cfg.config_dir = Path(path).resolve().parent
        cfg.config_path = Path(path).resolve()
        source = Path(path).read_text()
        raw = tomllib.loads(source)
        from .snapshot import redact_config
        cfg.loaded_config = redact_config(source)
        check_sections(raw, Path(path))
        net = raw.get("network", {})
        cfg.channel = int(_finite("network", "channel", net.get("channel", cfg.channel)))
        if not 11 <= cfg.channel <= 26:
            raise ValueError(f"[network] channel must be 11-26, not {cfg.channel}")
        if net.get("pan_id") is not None:
            raw_pan = net["pan_id"]
            try:
                cfg.pan_id = (int(raw_pan, 0) if isinstance(raw_pan, str)
                              else int(_finite("network", "pan_id", raw_pan)))
            except ValueError:
                raise ValueError(f"[network] pan_id must be a PAN id such as \"0x4e21\", not {raw_pan!r}") from None
            if not 0 <= cfg.pan_id <= 0xfffe:
                raise ValueError(f"[network] pan_id must be 0x0000-0xfffe, not 0x{cfg.pan_id:x}")
        rec = raw.get("record", {})
        cfg.serial_port = rec.get("serial_port") or None
        cfg.radios = _radios(rec.get("radios"))
        if cfg.radios and cfg.serial_port:
            raise ValueError("[record] serial_port and radios exclude each other: radios names every dongle "
                             "by serial, so there is no one port to pin")
        if rec.get("data_dir"):
            cfg.data_dir = Path(os.path.expandvars(str(rec["data_dir"]))).expanduser()
        cfg.keep_hours = int(_finite("record", "keep_hours", rec.get("keep_hours", cfg.keep_hours)))
        if cfg.keep_hours < 1:
            raise ValueError(f"[record] keep_hours must be at least 1, not {cfg.keep_hours}")
        if rec.get("keep_gb") is not None:
            # A negative cap would prune every file but the one being
            # written at each rotation (RingWriter._prune loops while the
            # total exceeds it), and zero would be no cap at all: neither
            # is a size to keep.
            gb = _finite("record", "keep_gb", rec["keep_gb"])
            try:
                keep_gb = float(gb)
            except (TypeError, ValueError):
                raise ValueError(f"[record] keep_gb must be a number of gigabytes, not {rec['keep_gb']!r}") from None
            if not keep_gb > 0:
                raise ValueError(f"[record] keep_gb must be more than 0 (unset it for no size cap), not {keep_gb:g}")
            cfg.keep_bytes = int(keep_gb * 1024 ** 3)
        cfg.snapshot_on_critical = bool(rec.get("snapshot_on_critical", cfg.snapshot_on_critical))
        if rec.get("keep_snapshots") is not None:
            # Each automatic snapshot is a whole ring, and nothing else
            # deletes one: without a cap a mesh that storms repeatedly
            # fills the card and the recorder stops recording.
            keep = rec["keep_snapshots"]
            if isinstance(keep, bool) or not isinstance(keep, int):
                raise ValueError(f"[record] keep_snapshots must be a whole number of snapshots, not {keep!r}")
            if keep < -1:
                raise ValueError(f"[record] keep_snapshots must be -1 (no cap) or more, not {keep}")
            cfg.keep_snapshots = keep
        if raw.get("devices", {}).get("inventory"):
            cfg.devices_path = (Path(path).parent / raw["devices"]["inventory"]).resolve()
        if raw.get("visitors", {}).get("file"):
            cfg.visitors_path = (Path(path).parent / raw["visitors"]["file"]).resolve()
        det = raw.get("detect", {})
        # Every value is a number by the time the detector sees it: a
        # quoted "400" compares fine against nothing at load time and
        # raises TypeError at the first window close, or, for the period
        # and cooldown keys, at the first storm, weeks later.
        def _number(key: str, unit: str) -> float:
            value = det[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"[detect] {key} must be a number of {unit}, not {value!r}")
            return float(_finite("detect", key, value))
        if "flood_multiplier" in det:
            cfg.detector.flood_multiplier = _number("flood_multiplier", "times the baseline")
            if not cfg.detector.flood_multiplier > 0:
                raise ValueError(f"[detect] flood_multiplier must be more than 0, "
                                 f"not {cfg.detector.flood_multiplier:g}")
        if "flood_min_frames" in det:
            frames = _number("flood_min_frames", "frames")
            if frames != int(frames):
                raise ValueError(f"[detect] flood_min_frames must be a whole number of frames, "
                                 f"not {det['flood_min_frames']!r}")
            cfg.detector.flood_min_frames = int(frames)
            if cfg.detector.flood_min_frames < 1:
                raise ValueError(f"[detect] flood_min_frames must be at least 1, "
                                 f"not {cfg.detector.flood_min_frames}")
        if "period_min_s" in det:
            cfg.detector.period_min_s = _number("period_min_s", "seconds")
            if not cfg.detector.period_min_s > 0:
                raise ValueError(f"[detect] period_min_s must be more than 0, "
                                 f"not {cfg.detector.period_min_s:g}")
        if "period_max_s" in det:
            cfg.detector.period_max_s = _number("period_max_s", "seconds")
        if not cfg.detector.period_min_s < cfg.detector.period_max_s:
            raise ValueError(f"[detect] period_max_s must be more than period_min_s "
                             f"({cfg.detector.period_min_s:g}), not {cfg.detector.period_max_s:g}")
        if "alert_cooldown_s" in det:
            cfg.detector.alert_cooldown_s = _number("alert_cooldown_s", "seconds")
            if cfg.detector.alert_cooldown_s < 0:
                raise ValueError(f"[detect] alert_cooldown_s must be 0 (no cooldown) or more, "
                                 f"not {cfg.detector.alert_cooldown_s:g}")
        if "period_onsets" in det:
            cfg.detector.period_onsets = det["period_onsets"]
        # Kept as the int the detector slices with: a TOML 3.0 passed the
        # check below and crashed _check_periodicity at the first storm.
        onsets = cfg.detector.period_onsets
        if isinstance(onsets, bool) or not isinstance(onsets, (int, float)) or onsets != int(onsets):
            raise ValueError(f"[detect] period_onsets must be a whole number of onsets, not {onsets!r}")
        cfg.detector.period_onsets = int(onsets)
        if cfg.detector.period_onsets < 2:
            raise ValueError(f"[detect] period_onsets must be at least 2 (a period needs two "
                             f"onsets to measure), not {cfg.detector.period_onsets}")
        # The detector keeps the onsets it is asked for, but not without
        # limit: a threshold in the thousands is a typo, and one the mesh
        # could not reach in a day is the storm detector switched off in a
        # setting that reads like a sensitivity.
        if cfg.detector.period_onsets > ONSETS_MAX:
            raise ValueError(f"[detect] period_onsets must be at most {ONSETS_MAX}, not "
                             f"{cfg.detector.period_onsets}")
        quiet = raw.get("quiet", {})
        cfg.quiet_s = float(_finite("quiet", "silence_s", quiet.get("silence_s", cfg.quiet_s)))
        # There is no "disable" value here, though [summary] hour = -1 and
        # [border_routers] browse_s = 0 both mean that in the same file. At
        # zero or less the quiet test is true for every device on every
        # tick: a 40-device mesh pages 40 times, each one persisted as
        # announced so a restart does not undo it, and then says nothing
        # about a real silence again.
        if not cfg.quiet_s > 0:
            raise ValueError(f"[quiet] silence_s must be more than 0 seconds, not {cfg.quiet_s:g}")
        cfg.quiet_min_rssi_dbm = float(_finite("quiet", "min_rssi_dbm",
                                              quiet.get("min_rssi_dbm", cfg.quiet_min_rssi_dbm)))
        link = raw.get("link", {})
        cfg.link_drop_db = float(_finite("link", "drop_db", link.get("drop_db", cfg.link_drop_db)))
        cfg.link_hold_s = float(_finite("link", "hold_s", link.get("hold_s", cfg.link_hold_s)))
        polls = raw.get("polls", {})
        cfg.poll_rearm_s = float(_finite("polls", "rearm_s", polls.get("rearm_s", cfg.poll_rearm_s)))
        cfg.poll_confirm_s = float(_finite("polls", "confirm_s", polls.get("confirm_s", cfg.poll_confirm_s)))
        if cfg.poll_confirm_s < 0:
            raise ValueError(f"[polls] confirm_s must be 0 (page at once) or more, not {cfg.poll_confirm_s:g}")
        keys = raw.get("keys", {})
        for name, attr, floor in (("confirm_s", "key_confirm_s", "0 (page at once)"),
                                  ("census_delay_s", "key_census_delay_s", "0 (log at the rotation)"),
                                  ("rearm_s", "key_rearm_s", "0 (page every episode)")):
            value = float(_finite("keys", name, keys.get(name, getattr(cfg, attr))))
            if value < 0:
                raise ValueError(f"[keys] {name} must be {floor} or more, not {value:g}")
            setattr(cfg, attr, value)
        cfg.key_fresh_s = float(_finite("keys", "fresh_s", keys.get("fresh_s", cfg.key_fresh_s)))
        if not cfg.key_fresh_s > 0:
            raise ValueError(f"[keys] fresh_s must be more than 0 seconds, not {cfg.key_fresh_s:g}")
        if keys.get("rotation_hours") is not None:
            cfg.key_rotation_hours = float(_finite("keys", "rotation_hours", keys["rotation_hours"]))
            if not cfg.key_rotation_hours > 0:
                raise ValueError(f"[keys] rotation_hours must be more than 0, not {cfg.key_rotation_hours:g}")
        ha_logs = raw.get("ha_logs", {})
        for name, attr in (("enabled", "ha_logs_enabled"), ("retry", "ha_logs_retry"), ("archive", "ha_logs_archive")):
            value = ha_logs.get(name, getattr(cfg, attr))
            if not isinstance(value, bool):
                raise ValueError(f"[ha_logs] {name} must be true or false, not {value!r}")
            setattr(cfg, attr, value)
        addons = ha_logs.get("addons", cfg.ha_logs_addons)
        if not isinstance(addons, list) or not all(isinstance(a, str) and _ADDON_SLUG.match(a) for a in addons):
            raise ValueError(f"[ha_logs] addons must be a list of add-on slugs (lower-case letters, digits and "
                             f"underscores, e.g. \"core_openthread_border_router\"), not {addons!r}")
        cfg.ha_logs_addons = list(addons)
        for name, attr in (("max_hours", "ha_logs_max_hours"), ("read_timeout_s", "ha_logs_read_timeout_s"),
                           ("deadline_s", "ha_logs_deadline_s")):
            value = float(_finite("ha_logs", name, ha_logs.get(name, getattr(cfg, attr))))
            if not value > 0:
                raise ValueError(f"[ha_logs] {name} must be more than 0, not {value:g}")
            setattr(cfg, attr, value)
        avail = raw.get("ha_availability", {})
        enabled = avail.get("enabled", cfg.ha_availability_enabled)
        if not isinstance(enabled, bool):
            raise ValueError(f"[ha_availability] enabled must be true or false, not {enabled!r}")
        cfg.ha_availability_enabled = enabled
        settings = avail.get("settings", cfg.ha_availability_settings)
        if not isinstance(settings, str) or not settings.strip():
            raise ValueError(f"[ha_availability] settings must be a file name, not {settings!r}")
        cfg.ha_availability_settings = settings
        for name, attr, positive in (("poll_s", "ha_availability_poll_s", True),
                                     ("hold_s", "ha_availability_hold_s", False),
                                     ("burst_window_s", "ha_availability_burst_window_s", True),
                                     ("burst_hold_s", "ha_availability_burst_hold_s", False),
                                     ("rearm_s", "ha_availability_rearm_s", False),
                                     ("registry_refresh_s", "ha_availability_registry_refresh_s", True)):
            value = float(_finite("ha_availability", name, avail.get(name, getattr(cfg, attr))))
            if positive and not value > 0:
                raise ValueError(f"[ha_availability] {name} must be more than 0, not {value:g}")
            if not positive and value < 0:
                raise ValueError(f"[ha_availability] {name} must be 0 or more, not {value:g}")
            setattr(cfg, attr, value)
        devices = avail.get("burst_devices", cfg.ha_availability_burst_devices)
        if isinstance(devices, bool) or not isinstance(devices, int) or devices < 2:
            raise ValueError(f"[ha_availability] burst_devices must be a whole number of 2 or more, not {devices!r}")
        cfg.ha_availability_burst_devices = devices
        retrans = raw.get("retransmissions", {})
        cfg.retrans_confirm_s = float(_finite("retransmissions", "confirm_s",
                                             retrans.get("confirm_s", cfg.retrans_confirm_s)))
        if cfg.retrans_confirm_s < 0:
            raise ValueError("[retransmissions] confirm_s must be 0 (page at the first minute) or more, "
                             f"not {cfg.retrans_confirm_s:g}")
        brs = raw.get("border_routers", {})
        cfg.border_router_browse_s = float(_finite("border_routers", "browse_s",
                                                  brs.get("browse_s", cfg.border_router_browse_s)))
        cfg.border_router_rotation = str(brs.get("rotation", cfg.border_router_rotation))
        if cfg.border_router_rotation not in ROTATION_POLICIES:
            raise ValueError(f"[border_routers] rotation must be one of "
                             f"{', '.join(sorted(ROTATION_POLICIES))}, not {cfg.border_router_rotation!r}")
        summary = raw.get("summary", {})
        cfg.summary_hour = int(_finite("summary", "hour", summary.get("hour", cfg.summary_hour)))
        if not -1 <= cfg.summary_hour <= 23:
            raise ValueError(f"[summary] hour must be 0-23, or -1 to disable, not {cfg.summary_hour}")
        cfg.summary_severity = str(summary.get("severity", cfg.summary_severity))
        if cfg.summary_severity not in ("info", "notice", "warning", "critical"):
            raise ValueError(f"[summary] severity must be info, notice, warning or critical, "
                             f"not {cfg.summary_severity!r}")
        events = raw.get("events", {})
        cfg.events_keep_days = int(_finite("events", "keep_days", events.get("keep_days", cfg.events_keep_days)))
        if cfg.events_keep_days < 0:
            raise ValueError(f"[events] keep_days must be 0 (keep for ever) or more, not {cfg.events_keep_days}")
        web = raw.get("web", {})
        cfg.web_bind = str(web.get("bind", cfg.web_bind))
        cfg.web_port = int(_finite("web", "port", web.get("port", cfg.web_port)))
        # Sinks and heartbeats are built lazily (alerts.build_sinks /
        # build_heartbeats) so ${ENV} expansion and validation happen where
        # a disabled sink can be logged rather than crash config loading.
        cfg.alerts_raw = dict(raw.get("alerts", {}))
        cfg.heartbeats_raw = list(raw.get("heartbeats", []) or [])
        if raw.get("credentials", {}).get("file"):
            cfg.credentials_path = (Path(path).parent / raw["credentials"]["file"]).resolve()
    if cfg.devices_path is None:
        if explicit_path:
            # This is both the read location and the destination for name/import,
            # including when the second recorder's inventory does not exist yet.
            cfg.devices_path = cfg.config_dir / "devices.json"
        else:
            for candidate in (cfg.config_dir / "devices.json", REPO_ROOT / "config" / "devices.json"):
                if candidate.exists():
                    cfg.devices_path = candidate
                    break
    if cfg.visitors_path is None:
        # Beside the config file, like devices.json; read and written
        # (name-visitor) there whether or not it exists yet.
        cfg.visitors_path = cfg.config_dir / "visitors.json"
    if cfg.credentials_path is None:
        default_creds = cfg.config_dir / "credentials.toml"
        if default_creds.exists():
            cfg.credentials_path = default_creds
    return cfg
