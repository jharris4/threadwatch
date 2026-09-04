"""Configuration loading (TOML, stdlib tomllib — Python 3.11+)."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .detect import DetectorConfig

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Config:
    channel: int = 25
    serial_port: Optional[str] = None          # auto-detect when unset
    data_dir: Path = REPO_ROOT / "data"
    keep_files: int = 168                      # ring: hourly files, one week
    keep_bytes: Optional[int] = None           # ring: total size cap ([capture] keep_gb), None = files only
    freeze_on_critical: bool = False           # snapshot the ring when a critical event fires
    devices_path: Optional[Path] = None
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    config_dir: Path = REPO_ROOT / "config"
    credentials_path: Optional[Path] = None
    # Silence (seconds) before a device_quiet event, by inventory role. Both
    # default to 30 min: the 2026-09-02 soak (9.8 h, 22 sleepy end devices)
    # showed 19 of them never silent for 3 min and the rest under 30 min once
    # marginal-reception devices are excluded, so end devices are not quiet
    # from the sniffer's point of view. The split is kept for meshes where a
    # class of device genuinely sleeps for long stretches.
    quiet_end_device_s: float = 30 * 60
    quiet_router_s: float = 30 * 60
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
        raw = tomllib.loads(Path(path).read_text())
        net = raw.get("network", {})
        cfg.channel = net.get("channel", cfg.channel)
        cap = raw.get("capture", {})
        cfg.serial_port = cap.get("serial_port") or None
        if cap.get("data_dir"):
            cfg.data_dir = Path(cap["data_dir"]).expanduser()
        cfg.keep_files = cap.get("keep_files", cfg.keep_files)
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
        quiet = raw.get("quiet", {})
        cfg.quiet_end_device_s = float(quiet.get("end_device_s", cfg.quiet_end_device_s))
        cfg.quiet_router_s = float(quiet.get("router_s", cfg.quiet_router_s))
        cfg.quiet_min_rssi_dbm = float(quiet.get("min_rssi_dbm", cfg.quiet_min_rssi_dbm))
        link = raw.get("link", {})
        cfg.link_drop_db = float(link.get("drop_db", cfg.link_drop_db))
        cfg.link_hold_s = float(link.get("hold_s", cfg.link_hold_s))
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
