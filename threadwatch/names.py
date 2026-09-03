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

Two helpers keep the file from being hand-written: `threadwatch report
--suggest` prints a ready-to-paste entry per unknown address, prefilled
with any SRP hostname the credentialed pipeline harvested for it, and
`threadwatch adopt <addr> <name>` appends one (or adds a rotated address
to a device already listed under that name).
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Optional


ROUTER_ROLES = {"router", "reed", "border-router", "border-router-leader"}
_EXT_ADDR = re.compile(r"^[0-9a-f]{16}$")


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
                    n = _norm(str(a))
                    # Every inventory address is fed to the decryptor's nonce
                    # search as raw hex; a stray 0x prefix or dash would
                    # raise there, in the capture loop, on every frame.
                    if not _EXT_ADDR.match(n):
                        print(f"[threadwatch] {inventory_path.name}: ignoring address {a!r} of "
                              f"{entry.get('name')!r}: not 16 hex digits", flush=True)
                        continue
                    self.by_addr[n] = entry

    def name(self, addr: str) -> Optional[str]:
        entry = self.by_addr.get(_norm(addr))
        return (entry.get("name") or None) if entry else None

    def role(self, addr: str) -> Optional[str]:
        entry = self.by_addr.get(_norm(addr))
        if not entry:
            return None
        return entry.get("role") or entry.get("threadRole")

    def is_router(self, addr: str) -> bool:
        return (self.role(addr) or "").lower() in ROUTER_ROLES


class LastSeen:
    """Tracks when each source address (extended, 16-hex-char) last transmitted."""

    def __init__(self, state_path: Optional[Path]):
        """``state_path`` None: an in-memory table that is never saved
        (replay must not touch the live recorder's state)."""
        self.state_path = state_path
        self.table: dict[str, dict] = {}
        if state_path is not None and state_path.exists():
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
        if self.state_path is None:
            self._dirty = False
            return
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
                "first_seen": row.get("first_seen"),
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


# ------------------------------------------------ growing the inventory

def load_observed_names(state_dir: Path) -> dict[str, dict[str, int]]:
    """SRP/DNS-SD hostnames the credentialed pipeline harvested, by extended
    address (observed-names.json: {addr: {name: sightings}}). Empty without
    credentials or before anything registered a service."""
    path = state_dir / "observed-names.json"
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def suggest_entries(unknown: list[dict], observed: dict[str, dict[str, int]]) -> list[dict]:
    """A devices.json entry per unknown address from a LastSeen report, ready
    to paste. The name is the most-sighted harvested hostname, or blank
    (a blank name keeps the address in the unknown list until filled in);
    the note carries what the recorder knows so the entry can be matched
    to a real device (power-cycle test, OTBR's device list, ...)."""
    out = []
    for item in unknown:
        addr = item["addr"]
        seen = observed.get(addr) or observed.get(addr.upper()) or {}
        hostnames = [n for n, _ in sorted(seen.items(), key=lambda kv: (-kv[1], kv[0]))]
        facts = [f"{item.get('frames', 0):,} frames"]
        if item.get("first_seen"):
            facts[-1] += " since " + time.strftime("%Y-%m-%d %H:%M", time.localtime(item["first_seen"]))
        if item.get("last_seen"):
            facts.append("last " + time.strftime("%Y-%m-%d %H:%M", time.localtime(item["last_seen"])))
        rssi = item.get("rssi_dbm")
        facts.append(f"{item.get('reception', 'unknown')} reception"
                     + (f" ({rssi} dBm)" if rssi is not None else ""))
        if hostnames:
            facts.append("advertised as " + ", ".join(hostnames[:3]))
        out.append({"name": hostnames[0] if hostnames else "",
                    "extendedAddress": addr.upper(),
                    "note": "; ".join(facts)})
    return out


def adopt(inventory_path: Path, addr: str, name: str, role: Optional[str] = None) -> str:
    """Add ``addr`` to the inventory under ``name`` and rewrite the file.

    A device already listed under that name gains the address in its
    `extendedAddresses` list (that is how rotating devices are recorded);
    otherwise a new entry is appended. Returns a one-line description of
    what changed. Raises ValueError for a malformed address, an empty
    name, or an address already listed under a different name (moving it
    is a decision for the person editing the file, not a side effect).
    """
    n = _norm(addr)
    if not _EXT_ADDR.match(n):
        raise ValueError(f"{addr!r} is not a 16-hex-digit extended address")
    name = name.strip()
    if not name:
        raise ValueError("a device name is required")
    entries = []
    if inventory_path.exists():
        entries = json.loads(inventory_path.read_text() or "[]")
        if not isinstance(entries, list):
            raise ValueError(f"{inventory_path.name} is not a JSON list")
    for entry in entries:
        addrs = [_norm(str(a)) for a in (entry.get("extendedAddresses") or [])]
        if entry.get("extendedAddress"):
            addrs.append(_norm(str(entry["extendedAddress"])))
        if n in addrs:
            if (entry.get("name") or "").strip().lower() == name.lower():
                return f"{n} is already listed as {entry.get('name')!r}"
            raise ValueError(f"{n} is already listed as {entry.get('name') or '(unnamed)'!r}; "
                             f"edit {inventory_path.name} to move it")
    existing = next((e for e in entries
                     if (e.get("name") or "").strip().lower() == name.lower()), None)
    stored = n.upper()
    if existing is not None:
        addrs = list(existing.get("extendedAddresses") or [])
        if existing.get("extendedAddress"):
            addrs.insert(0, existing.pop("extendedAddress"))
        addrs.append(stored)
        existing["extendedAddresses"] = addrs
        if role and not (existing.get("role") or existing.get("threadRole")):
            existing["role"] = role
        what = f"added {n} to {existing.get('name')!r} ({len(addrs)} addresses)"
    else:
        entry = {"name": name, "extendedAddress": stored}
        if role:
            entry["role"] = role
        entries.append(entry)
        what = f"added {name!r} = {n}" + (f" ({role})" if role else "")
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = inventory_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2, ensure_ascii=False) + "\n")
    tmp.replace(inventory_path)
    return what
