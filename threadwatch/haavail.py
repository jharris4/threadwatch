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
import time
from datetime import datetime
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



# ------------------------------------------------------------ the HA map

MAP_FILE = "ha-map.json"
STATES_TIMEOUT_S = 10.0


def usable_entities(entities: list[dict]) -> list[str]:
    """The entity ids whose state says whether a device is available: not
    disabled, and not the config or diagnostic ones when the device has
    others (a diagnostic entity can stay 'unavailable' on its own)."""
    live = [e for e in entities if isinstance(e, dict) and e.get("entity_id") and not e.get("disabled_by")]
    primary = [e for e in live if e.get("entity_category") not in ("config", "diagnostic")]
    return sorted(e["entity_id"] for e in (primary or live))


def build_map(ha, entries: list[dict], log=lambda m: None) -> dict[str, dict]:
    """The runtime link from HA's devices to the inventory: HA device id ->
    extended address (from the Matter node diagnostics), node id, the HA
    name, the inventory's name for that address when it has one, and the
    entities to watch. Built over the websocket (the one client `import`
    uses); the once-a-minute poll is REST and needs only this."""
    from .ha import thread_devices
    devices = thread_devices(ha, log)
    registry = ha.call("config/entity_registry/list") or []
    by_device: dict[str, list[dict]] = {}
    for ent in registry:
        if isinstance(ent, dict) and ent.get("device_id"):
            by_device.setdefault(ent["device_id"], []).append(ent)
    out = {}
    for dev in devices:
        device_id = dev.get("ha_device_id")
        if not device_id:
            continue
        inventory = _inventory_name(dev.get("addr"), entries)
        out[device_id] = {"addr": (dev.get("addr") or "").upper() or None, "node_id": dev.get("node_id"),
                          "ha_name": dev.get("name"), "name": inventory or dev.get("name"),
                          "matched": inventory is not None,
                          "entities": usable_entities(by_device.get(device_id, []))}
    return out


def load_map(state_dir: Path) -> dict[str, dict]:
    try:
        data = json.loads((state_dir / MAP_FILE).read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, dict) and isinstance(v.get("entities"), list)}


def save_map(state_dir: Path, mapping: dict[str, dict]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    tmp = (state_dir / MAP_FILE).with_suffix(".tmp")
    tmp.write_text(json.dumps(mapping, indent=1))
    os.replace(tmp, state_dir / MAP_FILE)


def _iso(value) -> float | None:
    """An ISO 8601 stamp as HA writes them ('2026-09-13T21:03:12.123456+00:00') to epoch seconds."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def poll_states(url: str, token: str, timeout_s: float = STATES_TIMEOUT_S) -> list[dict]:
    """GET /api/states: every entity's state. Raises OSError-family or
    urllib errors for the caller to report (redacted)."""
    import urllib.request

    from .httpclient import urlopen
    req = urllib.request.Request(f"{url.rstrip('/')}/api/states",
                                 headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urlopen(req, timeout=timeout_s) as resp:
        data = json.loads(resp.read().decode("utf-8", "replace"))
    if not isinstance(data, list):
        raise ValueError("/api/states did not return a list")
    return data


def reduce_states(states: list[dict], mapping: dict[str, dict]) -> dict[str, tuple[bool, float | None]]:
    """The 1.3 MB of states reduced, on the worker thread, to what the
    capture thread judges: per HA device (all_unavailable, since), where
    a device is unavailable only when every watched entity is
    'unavailable' ('unknown' does not count) and ``since`` is the newest
    last_changed among them. A device with no watched entity, or whose
    entities are not in the states at all, is left out: nothing is known."""
    by_entity = {s.get("entity_id"): s for s in states if isinstance(s, dict)}
    out: dict[str, tuple[bool, float | None]] = {}
    for device_id, info in mapping.items():
        present = [by_entity[e] for e in (info.get("entities") or []) if e in by_entity]
        if not present:
            continue
        down = all(s.get("state") == "unavailable" for s in present)
        since = None
        if down:
            stamps = [t for t in (_iso(s.get("last_changed")) for s in present) if t is not None]
            since = max(stamps) if stamps else None
        out[device_id] = (down, since)
    return out


def fetch_availability(url: str, token: str, mapping: dict[str, dict], now: float | None = None) -> dict:
    """One poll, for the worker thread: {ok, devices, polled_ts} or
    {ok: False, error} with the error redacted of the URL and the token."""
    from .httpclient import redact_text
    now = now if now is not None else time.time()
    try:
        states = poll_states(url, token)
    except Exception as exc:                 # a refused connection, a 5xx while HA restarts, bad JSON
        reason = getattr(exc, "reason", None)
        text = f"HTTP {exc.code}" if hasattr(exc, "code") else f"{type(exc).__name__}: {reason or exc}"
        return {"ok": False, "error": redact_text(text, (token,)), "polled_ts": now}
    return {"ok": True, "devices": reduce_states(states, mapping), "polled_ts": now}
