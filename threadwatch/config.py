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
    webhook_min_severity: str = "warning"

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
        cfg.detector.webhook_url = raw.get("alerts", {}).get("webhook_url", "")
        cfg.webhook_min_severity = raw.get("alerts", {}).get("min_severity", "warning")
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
