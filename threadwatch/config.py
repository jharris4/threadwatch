"""Configuration loading (TOML, stdlib tomllib — Python 3.11+)."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .detect import DetectorConfig

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Config:
    channel: int = 25
    # [network] pan_id: this network's PAN id. When set, it decides whose
    # silences count and which PANs are foreign; when unset the recorder
    # guesses from which PAN it hears most, which a busier neighbour on the
    # same channel can win (see Pipeline.dominant_pan).
    pan_id: Optional[int] = None
    serial_port: Optional[str] = None          # auto-detect when unset
    data_dir: Path = REPO_ROOT / "data"
    keep_files: int = 168                      # ring: hourly files, one week
    keep_bytes: Optional[int] = None           # ring: total size cap ([capture] keep_gb), None = files only
    freeze_on_critical: bool = False           # snapshot the ring when a critical event fires
    devices_path: Optional[Path] = None
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    config_dir: Path = REPO_ROOT / "config"
    config_path: Optional[Path] = None         # the file load() read, None when defaults stood
    credentials_path: Optional[Path] = None
    # A frozen incident to read state and events from instead of
    # data/state (replay and why --incident): its copies of the state
    # files and the event log sit at its top level, and nothing is ever
    # written there. See for_incident.
    frozen_dir: Optional[Path] = None
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
    # [summary] one daily_summary event per local day, at this hour (-1 off).
    summary_hour: int = 8
    summary_severity: str = "notice"
    # [events] day files older than this are deleted by the recorder, at
    # start and once a day. 0 keeps them for ever. The pages read a month
    # either side of a day (review.EPISODE_WINDOW_DAYS), so history past
    # that costs disk and the freeze copy only.
    events_keep_days: int = 365
    web_bind: str = "0.0.0.0"                  # [web] review pages (threadwatch web)
    web_port: int = 8080
    alerts_raw: dict = field(default_factory=dict)      # [alerts] table, verbatim
    heartbeats_raw: list = field(default_factory=list)  # [[heartbeats]] tables, verbatim

    @property
    def ring_dir(self) -> Path:
        return self.data_dir / "ring"

    def for_incident(self, incident_dir: Path) -> "Config":
        """This configuration turned on a frozen incident: state, events
        and (when the freeze kept one) the inventory come from the
        incident's copies, so names and history are the ones current when
        it was frozen, not today's. Everything else, the credentials
        above all, is the live configuration's."""
        import dataclasses
        inventory = incident_dir / "devices.json"
        return dataclasses.replace(self, frozen_dir=incident_dir,
                                   devices_path=inventory if inventory.exists() else self.devices_path)

    @property
    def state_dir(self) -> Path:
        if self.frozen_dir is not None:
            return self.frozen_dir
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
    def incidents_dir(self) -> Path:
        return self.data_dir / "incidents"

    @property
    def events_dir(self) -> Path:
        return self.state_dir / "events"


def load(path: Optional[Path]) -> Config:
    cfg = Config()
    if path is None:
        default = REPO_ROOT / "config" / "config.toml"
        path = default if default.exists() else None
    if path:
        cfg.config_dir = Path(path).resolve().parent
        cfg.config_path = Path(path).resolve()
        raw = tomllib.loads(Path(path).read_text())
        net = raw.get("network", {})
        cfg.channel = int(net.get("channel", cfg.channel))
        if not 11 <= cfg.channel <= 26:
            raise ValueError(f"[network] channel must be 11-26, not {cfg.channel}")
        if net.get("pan_id") is not None:
            raw_pan = net["pan_id"]
            try:
                cfg.pan_id = int(raw_pan, 0) if isinstance(raw_pan, str) else int(raw_pan)
            except ValueError:
                raise ValueError(f"[network] pan_id must be a PAN id such as \"0x4e21\", not {raw_pan!r}") from None
            if not 0 <= cfg.pan_id <= 0xfffe:
                raise ValueError(f"[network] pan_id must be 0x0000-0xfffe, not 0x{cfg.pan_id:x}")
        cap = raw.get("capture", {})
        cfg.serial_port = cap.get("serial_port") or None
        if cap.get("data_dir"):
            cfg.data_dir = Path(os.path.expandvars(str(cap["data_dir"]))).expanduser()
        cfg.keep_files = int(cap.get("keep_files", cfg.keep_files))
        if cfg.keep_files < 1:
            raise ValueError(f"[capture] keep_files must be at least 1, not {cfg.keep_files}")
        if cap.get("keep_gb") is not None:
            # A negative cap would prune every file but the one being
            # written at each rotation (RingWriter._prune loops while the
            # total exceeds it), and zero would be no cap at all: neither
            # is a size to keep.
            try:
                keep_gb = float(cap["keep_gb"])
            except (TypeError, ValueError):
                raise ValueError(f"[capture] keep_gb must be a number of gigabytes, not {cap['keep_gb']!r}") from None
            if not keep_gb > 0:
                raise ValueError(f"[capture] keep_gb must be more than 0 (unset it for no size cap), not {keep_gb:g}")
            cfg.keep_bytes = int(keep_gb * 1024 ** 3)
        cfg.freeze_on_critical = bool(cap.get("freeze_on_critical", cfg.freeze_on_critical))
        if raw.get("devices", {}).get("inventory"):
            cfg.devices_path = (Path(path).parent / raw["devices"]["inventory"]).resolve()
        det = raw.get("detect", {})
        # Every value is a number by the time the detector sees it: a
        # quoted "400" compares fine against nothing at load time and
        # raises TypeError at the first window close, or, for the period
        # and cooldown keys, at the first storm, weeks later.
        def _number(key: str, unit: str) -> float:
            value = det[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"[detect] {key} must be a number of {unit}, not {value!r}")
            return float(value)
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
        quiet = raw.get("quiet", {})
        # end_device_s / router_s were the pre-2026-09-04 split by inventory
        # role; the longer of them stands in for silence_s in an old file.
        legacy = [float(quiet[k]) for k in ("end_device_s", "router_s") if k in quiet]
        cfg.quiet_s = float(quiet.get("silence_s", max(legacy) if legacy else cfg.quiet_s))
        cfg.quiet_min_rssi_dbm = float(quiet.get("min_rssi_dbm", cfg.quiet_min_rssi_dbm))
        link = raw.get("link", {})
        cfg.link_drop_db = float(link.get("drop_db", cfg.link_drop_db))
        cfg.link_hold_s = float(link.get("hold_s", cfg.link_hold_s))
        polls = raw.get("polls", {})
        cfg.poll_rearm_s = float(polls.get("rearm_s", cfg.poll_rearm_s))
        cfg.poll_confirm_s = float(polls.get("confirm_s", cfg.poll_confirm_s))
        if cfg.poll_confirm_s < 0:
            raise ValueError(f"[polls] confirm_s must be 0 (page at once) or more, not {cfg.poll_confirm_s:g}")
        retrans = raw.get("retransmissions", {})
        cfg.retrans_confirm_s = float(retrans.get("confirm_s", cfg.retrans_confirm_s))
        if cfg.retrans_confirm_s < 0:
            raise ValueError("[retransmissions] confirm_s must be 0 (page at the first minute) or more, "
                             f"not {cfg.retrans_confirm_s:g}")
        brs = raw.get("border_routers", {})
        cfg.border_router_browse_s = float(brs.get("browse_s", cfg.border_router_browse_s))
        summary = raw.get("summary", {})
        cfg.summary_hour = int(summary.get("hour", cfg.summary_hour))
        if not -1 <= cfg.summary_hour <= 23:
            raise ValueError(f"[summary] hour must be 0-23, or -1 to disable, not {cfg.summary_hour}")
        cfg.summary_severity = str(summary.get("severity", cfg.summary_severity))
        if cfg.summary_severity not in ("info", "notice", "warning", "critical"):
            raise ValueError(f"[summary] severity must be info, notice, warning or critical, "
                             f"not {cfg.summary_severity!r}")
        events = raw.get("events", {})
        cfg.events_keep_days = int(events.get("keep_days", cfg.events_keep_days))
        if cfg.events_keep_days < 0:
            raise ValueError(f"[events] keep_days must be 0 (keep for ever) or more, not {cfg.events_keep_days}")
        web = raw.get("web", {})
        cfg.web_bind = str(web.get("bind", cfg.web_bind))
        cfg.web_port = int(web.get("port", cfg.web_port))
        # Sinks and heartbeats are built lazily (alerts.build_sinks /
        # build_heartbeats) so ${ENV} expansion and validation happen where
        # a disabled sink can be logged rather than crash config loading.
        cfg.alerts_raw = dict(raw.get("alerts", {}))
        cfg.heartbeats_raw = list(raw.get("heartbeats", []) or [])
        if raw.get("credentials", {}).get("file"):
            cfg.credentials_path = (Path(path).parent / raw["credentials"]["file"]).resolve()
    if cfg.devices_path is None:
        # Beside the config file first: that is where `threadwatch adopt`
        # writes when [devices] inventory is unset, so a --config elsewhere
        # reads back the names it adopted. The repo default is the fallback.
        for candidate in (cfg.config_dir / "devices.json", REPO_ROOT / "config" / "devices.json"):
            if candidate.exists():
                cfg.devices_path = candidate
                break
    if cfg.credentials_path is None:
        default_creds = cfg.config_dir / "credentials.toml"
        if default_creds.exists():
            cfg.credentials_path = default_creds
    return cfg
