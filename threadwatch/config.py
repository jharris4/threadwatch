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
    devices_path: Optional[Path] = None
    detector: DetectorConfig = field(default_factory=DetectorConfig)
    config_dir: Path = REPO_ROOT / "config"
    credentials_path: Optional[Path] = None
    # Silence (seconds) before a device_quiet event. Routers keep advertising
    # every few seconds, so a short window is meaningful for them; end devices
    # legitimately sleep for long stretches (battery air-quality sensors were
    # seen going 70+ min between frames at night). A device counts as a
    # router only when its devices.json entry says so (role = "router" or
    # "border-router"): polling cannot be attributed from cleartext, because
    # data requests carry the short address.
    quiet_end_device_s: float = 90 * 60
    quiet_router_s: float = 30 * 60
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
        # Sinks and heartbeats are built lazily (alerts.build_sinks /
        # build_heartbeats) so ${ENV} expansion and validation happen where
        # a disabled sink can be logged rather than crash config loading.
        cfg.alerts_raw = dict(raw.get("alerts", {}))
        cfg.heartbeats_raw = list(raw.get("heartbeats", []) or [])
        if raw.get("credentials", {}).get("file"):
            cfg.credentials_path = (Path(path).parent / raw["credentials"]["file"]).resolve()
    default_devices = REPO_ROOT / "config" / "devices.json"
    if cfg.devices_path is None and default_devices.exists():
        cfg.devices_path = default_devices
    if cfg.credentials_path is None:
        default_creds = cfg.config_dir / "credentials.toml"
        if default_creds.exists():
            cfg.credentials_path = default_creds
    return cfg
