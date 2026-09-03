"""Device naming and last-seen tracking.

Maps 802.15.4 extended addresses to human names using a devices.json
inventory, and keeps a per-address last-seen table so quiet/vanished
devices can be reported without any controller (Home Assistant, HomeKit)
integration.

Inventory format (config/devices.json) — a JSON list; each entry may use
either a single `extendedAddress` or a list `extendedAddresses` (devices
such as Apple TVs rotate their extended address, so keep every address
ever observed):

    [
      {"name": "Office Air Quality", "extendedAddress": "66417FE110ED6950"},
      {"name": "Living Room Apple TV",
       "extendedAddresses": ["B62C32BF669272DB", "E6C279E8F0C70298"],
       "role": "border-router"}
    ]

`role` (or `threadRole`, as exported from Home Assistant's Thread panel)
is optional: router, reed, border-router and border-router-leader are
always-on devices that advertise every few seconds, so a short silence is
meaningful; anything else (sleepy-end-device, or untagged) gets the long
quiet window.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional


ROUTER_ROLES = {"router", "reed", "border-router", "border-router-leader"}


def _norm(addr: str) -> str:
    return addr.replace(":", "").strip().lower()


class DeviceNames:
    def __init__(self, inventory_path: Optional[Path]):
        self.by_addr: dict[str, dict] = {}
        self.inventory_path = inventory_path
        if inventory_path and inventory_path.exists():
            for entry in json.loads(inventory_path.read_text()):
                addrs = entry.get("extendedAddresses") or []
                if entry.get("extendedAddress"):
                    addrs = addrs + [entry["extendedAddress"]]
                for a in addrs:
                    self.by_addr[_norm(a)] = entry

    def name(self, addr: str) -> Optional[str]:
        entry = self.by_addr.get(_norm(addr))
        return entry.get("name") if entry else None

    def role(self, addr: str) -> Optional[str]:
        entry = self.by_addr.get(_norm(addr))
        if not entry:
            return None
        return entry.get("role") or entry.get("threadRole")

    def is_router(self, addr: str) -> bool:
        return (self.role(addr) or "").lower() in ROUTER_ROLES


class LastSeen:
    """Tracks when each source address (extended, 16-hex-char) last transmitted."""

    def __init__(self, state_path: Path):
        self.state_path = state_path
        self.table: dict[str, dict] = {}
        if state_path.exists():
            try:
                self.table = json.loads(state_path.read_text())
            except (json.JSONDecodeError, OSError):
                self.table = {}
        self._dirty = False
        self._last_save = 0.0

    def touch(self, addr: Optional[str], ts: float, ftype: Optional[int],
              pan: Optional[int] = None, rssi: Optional[float] = None) -> None:
        if not addr or len(addr) != 16:  # extended addresses only
            return
        row = self.table.setdefault(addr, {"first_seen": ts, "frames": 0, "types": {}})
        row["last_seen"] = ts
        row["frames"] += 1
        if ftype is not None:
            key = str(ftype)
            row["types"][key] = row["types"].get(key, 0) + 1
        if pan is not None:
            row["pan"] = pan   # last source PAN; lets quiet checks skip foreign meshes
        if rssi is not None:
            # Slow EWMA of received signal strength at the sniffer. Devices
            # near the receiver's floor (-85 dBm and below) drop out for tens
            # of minutes at a time; that is reception, not device silence.
            prev = row.get("rssi")
            row["rssi"] = round(rssi if prev is None else 0.95 * prev + 0.05 * rssi, 1)
        self._dirty = True

    def maybe_save(self, interval: float = 30.0) -> None:
        now = time.time()
        if self._dirty and now - self._last_save >= interval:
            self.save()

    def save(self) -> None:
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.table))
        tmp.replace(self.state_path)
        self._dirty = False
        self._last_save = time.time()

    def report(self, names: DeviceNames, quiet_after_s: float, now: Optional[float] = None,
               min_rssi_dbm: float = -82.0) -> dict:
        now = now or time.time()
        quiet, active, unknown = [], [], []
        for addr, row in sorted(self.table.items(), key=lambda kv: kv[1]["last_seen"]):
            silent_for = now - row["last_seen"]
            name = names.name(addr)
            rssi = row.get("rssi")
            item = {
                "addr": addr,
                "name": name,
                "role": names.role(addr),
                "frames": row["frames"],
                "last_seen": row["last_seen"],
                "silent_for_s": round(silent_for, 1),
                "rssi_dbm": rssi,
                "reception": reception(rssi, min_rssi_dbm),
            }
            if name is None:
                unknown.append(item)
            if silent_for > quiet_after_s:
                quiet.append(item)
            else:
                active.append(item)
        return {"quiet": quiet, "active_count": len(active), "unknown": unknown}


def reception(rssi: Optional[float], min_rssi_dbm: float) -> str:
    """How much a silence from this address means, given how well we hear it."""
    if rssi is None:
        return "unknown"
    return "good" if rssi >= min_rssi_dbm else "marginal"
