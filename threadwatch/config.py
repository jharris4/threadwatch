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
    # [border_routers] how often the recorder asks the LAN (mDNS, the
    # _meshcop._udp service every border router advertises) which extended
    # address each border router has now. Apple hubs change theirs on every
    # reboot; this is how the new one gets the old name. 0 disables.
    border_router_browse_s: float = 10 * 60
    # [summary] one daily_summary event per local day, at this hour (-1 off).
    summary_hour: int = 8
    summary_severity: str = "notice"
    web_bind: str = "0.0.0.0"                  # [web] review pages (threadwatch web)
    web_port: int = 8080
    alerts_raw: dict = field(default_factory=dict)      # [alerts] table, verbatim
    heartbeats_raw: list = field(default_factory=list)  # [[heartbeats]] tables, verbatim

    @property
    def ring_dir(self) -> Path:
        return self.data_dir / "ring"

    @property
    def state_dir(self) -> Path:
        d = self.data_dir / "state"
        d.mkdir(parents=True, exist_ok=True)
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
        if cap.get("keep_gb"):
            cfg.keep_bytes = int(float(cap["keep_gb"]) * 1024 ** 3)
        cfg.freeze_on_critical = bool(cap.get("freeze_on_critical", cfg.freeze_on_critical))
        if raw.get("devices", {}).get("inventory"):
            cfg.devices_path = (Path(path).parent / raw["devices"]["inventory"]).resolve()
        det = raw.get("detect", {})
        for key in ("flood_multiplier", "flood_min_frames", "period_min_s",
                    "period_max_s", "period_onsets", "alert_cooldown_s"):
            if key in det:
                setattr(cfg.detector, key, det[key])
        if int(cfg.detector.period_onsets) < 2:
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
