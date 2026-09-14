"""Home Assistant availability: the outage a person actually notices,
joined with the recorder's radio evidence for why.

Home Assistant marks a Matter device unavailable when it stops answering,
and on 2026-09-13 five devices went that way while their radios looked
healthy to every detector here (key-generation lag). The recorder polls
HA's states once a minute (a plain GET /api/states), keeps one episode
per device that is unavailable, and when an episode has lasted its hold
it emits ha_unavailable with the cause hacause.classify reads off the
last-seen rows. Several devices dropping together are one critical
ha_unavailable_burst, with the automatic snapshot that critical brings.

What links HA's devices to the inventory is built at runtime and cached
in data/state/ha-map.json: HA device id -> extended address (from the
Matter node diagnostics, matched to devices.json by address), HA name,
and the entities whose state says whether the device is available.
devices.json itself stays identity only and never learns an HA id.

Per-device settings (a longer hold for a known flapper, or mute) live in
config/ha-availability.json, keyed by HA device id, which survives
renames on either side. The person owns hold_s and mute; the tools keep
name and extendedAddress fresh, for readability and the link to the
inventory, and never add or remove an entry.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .names import _norm, inventory_lock

SETTINGS_KEYS = ("name", "extendedAddress", "hold_s", "mute")
_DURATION = re.compile(r"^\s*(?:(\d+)\s*h)?\s*(?:(\d+)\s*m)?\s*(?:(\d+)\s*s?)?\s*$", re.I)


class SettingsError(ValueError):
    """config/ha-availability.json is not usable: the feature stops, the
    recorder does not, and doctor says FAIL."""


def parse_duration(text: str) -> float:
    """'2h', '30m', '1h30m', '7200' or '90s' -> seconds. A bare number is
    seconds."""
    m = _DURATION.match(text or "")
    if not m or not any(m.groups()):
        raise ValueError(f"{text!r} is not a duration (try 2h, 30m, 1h30m or 7200)")
    h, mi, s = (int(g) if g else 0 for g in m.groups())
    return float(h * 3600 + mi * 60 + s)


def settings_path(cfg) -> Path:
    return cfg.config_dir / cfg.ha_availability_settings


def load_settings(path: Path) -> dict[str, dict]:
    """The per-device settings, keyed by HA device id. A missing file is no
    settings. Invalid JSON, or a value of the wrong shape (a hold that is
    not a number, a mute that is not a boolean, an entry that is not an
    object), raises SettingsError naming the entry: a file the person is
    editing must not half-apply."""
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text() or "{}")
    except ValueError as exc:
        raise SettingsError(f"{path.name} is not valid JSON ({exc})") from None
    if not isinstance(data, dict):
        raise SettingsError(f"{path.name} must be a JSON object keyed by Home Assistant device id, "
                            f"not a {type(data).__name__}")
    out: dict[str, dict] = {}
    for device_id, entry in data.items():
        where = f"{path.name}: entry {device_id!r}"
        if not isinstance(device_id, str) or not device_id.strip():
            raise SettingsError(f"{path.name}: every key must be a Home Assistant device id")
        if not isinstance(entry, dict):
            raise SettingsError(f"{where} must be an object, not {type(entry).__name__}")
        unknown = sorted(k for k in entry if k not in SETTINGS_KEYS)
        if unknown:
            raise SettingsError(f"{where} has unknown field(s) {', '.join(unknown)}; the fields are "
                                f"{', '.join(SETTINGS_KEYS)} (hold_s and mute are yours; name and "
                                "extendedAddress are kept by the tools)")
        hold = entry.get("hold_s")
        if hold is not None and (isinstance(hold, bool) or not isinstance(hold, (int, float)) or hold < 0
                                 or hold != hold or hold in (float("inf"), float("-inf"))):
            raise SettingsError(f"{where}: hold_s must be a number of seconds, 0 or more, not {hold!r}")
        mute = entry.get("mute")
        if mute is not None and not isinstance(mute, bool):
            raise SettingsError(f"{where}: mute must be true or false, not {mute!r}")
        for key in ("name", "extendedAddress"):
            if entry.get(key) is not None and not isinstance(entry[key], str):
                raise SettingsError(f"{where}: {key} must be a string, not {entry[key]!r}")
        out[device_id] = dict(entry)
    return out


def write_settings(path: Path, settings: dict[str, dict]) -> None:
    """Rewrite the file whole, atomically. Callers hold inventory_lock(path)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(settings, indent=2) + "\n")
    os.replace(tmp, path)


def _inventory_name(addr: str | None, entries: list[dict]) -> str | None:
    """The devices.json name for an address, if any (any of an entry's
    addresses)."""
    if not addr:
        return None
    want = _norm(addr)
    for entry in entries:
        addrs = list(entry.get("extendedAddresses") or [])
        if entry.get("extendedAddress"):
            addrs.append(entry["extendedAddress"])
        if any(isinstance(a, str) and _norm(a) == want for a in addrs):
            return (entry.get("name") or "").strip() or None
    return None


def link_fields(device: dict, entries: list[dict]) -> dict:
    """The name and extendedAddress the tools keep for an HA device: the
    inventory's name for its address, else the HA name."""
    return {"name": _inventory_name(device.get("addr"), entries) or device.get("name"),
            "extendedAddress": (device.get("addr") or "").upper() or None}


def refresh_settings(path: Path, devices: list[dict], entries: list[dict], write: bool) -> list[str]:
    """What `import --write` does to the settings file: refresh name and
    extendedAddress for every entry whose HA device id is still known,
    report the ids HA no longer has (never removed: they are the person's
    to delete), and touch neither hold_s nor mute nor add anything.
    Returns one line per change, or per stale id."""
    if not path.exists():
        return []
    with inventory_lock(path):
        settings = load_settings(path)
        by_id = {d.get("ha_device_id"): d for d in devices if d.get("ha_device_id")}
        lines: list[str] = []
        changed = False
        for device_id, entry in settings.items():
            dev = by_id.get(device_id)
            if dev is None:
                lines.append(f"{path.name}: {entry.get('name') or device_id} ({device_id[:8]}...) is no longer a "
                             "device Home Assistant knows; its settings stay until you remove the entry")
                continue
            fresh = link_fields(dev, entries)
            for key, value in fresh.items():
                if entry.get(key) != value:
                    lines.append(f"{path.name}: {entry.get('name') or device_id}: {key} "
                                 f"{entry.get(key)!r} -> {value!r}")
                    entry[key] = value
                    changed = True
        if changed and write:
            write_settings(path, settings)
            lines.append(f"wrote {path}")
    return lines


def resolve_device(target: str, devices: list[dict], entries: list[dict]) -> dict:
    """The HA device a person means by an inventory name, an extended
    address or an HA device id. Raises ValueError naming the candidates
    when the text matches several, or nothing."""
    t = target.strip()
    hits = [d for d in devices if d.get("ha_device_id") == t]
    if not hits:
        n = _norm(t)
        hits = [d for d in devices if d.get("addr") and _norm(d["addr"]) == n]
    if not hits:
        # An inventory name: every address of that entry, then the HA
        # device at any of them; else the HA name itself.
        for entry in entries:
            if (entry.get("name") or "").strip().lower() == t.lower():
                addrs = {_norm(a) for a in [*(entry.get("extendedAddresses") or []),
                                           *([entry["extendedAddress"]] if entry.get("extendedAddress") else [])]
                         if isinstance(a, str)}
                hits = [d for d in devices if d.get("addr") and _norm(d["addr"]) in addrs]
                break
    if not hits:
        hits = [d for d in devices if (d.get("name") or "").strip().lower() == t.lower()]
    if not hits:
        hits = [d for d in devices if t.lower() in (d.get("name") or "").lower()
                or t.lower() in (_inventory_name(d.get("addr"), entries) or "").lower()]
    if len(hits) == 1:
        return hits[0]
    if hits:
        raise ValueError(f"{target!r} matches several Home Assistant devices: "
                         + ", ".join(f"{_inventory_name(d.get('addr'), entries) or d.get('name')} "
                                     f"({d.get('ha_device_id')})" for d in hits))
    raise ValueError(f"{target!r} is not a Home Assistant Thread device's name, address or device id "
                     "(threadwatch ha-availability list shows them)")


def set_device(path: Path, devices: list[dict], entries: list[dict], target: str, *,
               hold_s: float | None = None, mute: bool | None = None, clear: bool = False) -> str:
    """`threadwatch ha-availability set`: write or update the entry for a
    device under the file's lock, with fresh name and extendedAddress.
    --clear removes the entry. Returns what changed."""
    dev = resolve_device(target, devices, entries)
    device_id = dev["ha_device_id"]
    label = _inventory_name(dev.get("addr"), entries) or dev.get("name")
    with inventory_lock(path):
        settings = load_settings(path)
        if clear:
            if settings.pop(device_id, None) is None:
                return f"{label} ({device_id}) had no settings"
            write_settings(path, settings)
            return f"{label} ({device_id}): settings removed"
        entry = settings.setdefault(device_id, {})
        before = dict(entry)
        entry.update(link_fields(dev, entries))
        if hold_s is not None:
            entry["hold_s"] = hold_s
        if mute is not None:
            if mute:
                entry["mute"] = True
            else:
                entry.pop("mute", None)
        write_settings(path, settings)
    what = []
    if hold_s is not None:
        what.append(f"hold {hold_s:g} s" + (f" (was {before['hold_s']:g} s)" if "hold_s" in before else ""))
    if mute is not None:
        what.append("muted" if mute else "unmuted")
    return f"{label} ({device_id}): " + (", ".join(what) or "name and address refreshed")


def list_settings(path: Path, devices: list[dict], entries: list[dict]) -> list[dict]:
    """`threadwatch ha-availability list`: every entry with its current HA
    name, inventory name, address and settings, marking ids HA no longer
    has (stale) and entries whose kept name or address no longer match."""
    settings = load_settings(path)
    by_id = {d.get("ha_device_id"): d for d in devices if d.get("ha_device_id")}
    out = []
    for device_id, entry in settings.items():
        dev = by_id.get(device_id)
        fresh = link_fields(dev, entries) if dev else None
        out.append({"ha_device_id": device_id, "name": entry.get("name"),
                    "extendedAddress": entry.get("extendedAddress"),
                    "hold_s": entry.get("hold_s"), "mute": bool(entry.get("mute")),
                    "ha_name": dev.get("name") if dev else None,
                    "inventory_name": _inventory_name(dev.get("addr"), entries) if dev else None,
                    "stale": dev is None,
                    "outdated": bool(dev) and (fresh["name"] != entry.get("name")
                                               or fresh["extendedAddress"] != entry.get("extendedAddress"))})
    return out


def fmt_hold(seconds: float | None) -> str:
    if seconds is None:
        return "default"
    seconds = int(seconds)
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"

