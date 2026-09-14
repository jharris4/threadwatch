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


# ------------------------------------------------------------- episodes

STATE_FILE = "ha-availability.json"
UNREACHABLE_AFTER_S = 5 * 60.0
# Rule 6: this share of mapped devices unavailable at once, most of them
# heard by the recorder inside HEARD_RECENTLY_S, points at HA or the
# Matter Server rather than the mesh.
HA_SIDE_SHARE = 0.8
HEARD_RECENTLY_S = 5 * 60.0


def load_state(path: Path | None) -> dict:
    empty = {"episodes": {}, "closed": {}, "burst": None, "ha_last_ok_ts": None, "last_poll_ts": None,
             "unreachable": False, "fail_since": None}
    if path is None:
        return empty
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return empty
    if not isinstance(data, dict):
        return empty
    state = dict(empty)
    state["episodes"] = {k: v for k, v in (data.get("episodes") or {}).items()
                         if isinstance(v, dict) and isinstance(v.get("since"), (int, float))}
    state["closed"] = {k: v for k, v in (data.get("closed") or {}).items() if isinstance(v, dict)}
    state["burst"] = data.get("burst") if isinstance(data.get("burst"), dict) else None
    for key in ("ha_last_ok_ts", "last_poll_ts", "fail_since"):
        value = data.get(key)
        state[key] = float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None
    state["unreachable"] = bool(data.get("unreachable"))
    return state


class Tracker:
    """The episode rules (docs/ALERTING.md, ha_unavailable), fed one poll
    result at a time on the capture thread. ``emit`` is the pipeline's
    _emit (a critical burst reserves the automatic snapshot); ``rows`` is
    the live last-seen table, read for the radio evidence and never
    written; ``settings`` the per-device hold and mute."""

    def __init__(self, cfg, state_path: Path | None, settings: dict, *, emit, rows: dict, names,
                 mapping: dict | None = None):
        self.cfg, self.state_path, self.settings = cfg, state_path, settings
        self.emit, self.rows, self.names = emit, rows, names
        self.mapping: dict = mapping or {}
        self.state = load_state(state_path)
        # Every start is a baseline: an episode carried over that was not
        # paged is one the last run never got to, and is said at notice.
        for ep in self.state["episodes"].values():
            if not ep.get("paged"):
                ep["at_start"] = True
        self.baseline_pending = True

    # ------------------------------------------------------------ helpers

    def _save(self) -> None:
        if self.state_path is None:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(self.state, indent=1))
        os.replace(tmp, self.state_path)

    def _setting(self, device_id: str, key: str):
        return (self.settings.get(device_id) or {}).get(key)

    def _muted(self, device_id: str) -> bool:
        return bool(self._setting(device_id, "mute"))

    def _hold(self, device_id: str) -> float:
        hold = self._setting(device_id, "hold_s")
        return float(hold) if isinstance(hold, (int, float)) and not isinstance(hold, bool) \
            else self.cfg.ha_availability_hold_s

    def _info(self, device_id: str) -> dict:
        return self.mapping.get(device_id) or {}

    def _label(self, device_id: str) -> str:
        info = self._info(device_id)
        return info.get("name") or info.get("ha_name") or device_id

    def _radio(self, device_id: str, since: float, now: float) -> tuple[dict, tuple[str, str]]:
        """The evidence fields and the cause for one device."""
        from .hacause import classify
        from .names import parent_address, reception, rloc16_role, router_holders
        addr = (self._info(device_id).get("addr") or "").lower() or None
        row = self.rows.get(addr) if addr else None
        parent_row = None
        parent = None
        live = rloc16_role(row.get("rloc16")) if row else None
        if row:
            parent = parent_address(row, router_holders(self.rows))
            parent_row = self.rows.get(parent) if parent else None
        from .names import newest_generation
        generation = newest_generation(row)[0] if row else None
        parent_generation = newest_generation(parent_row)[0] if parent_row else None
        cause = classify(row, parent_row, since, now, fresh_s=self.cfg.key_fresh_s,
                         min_rssi_dbm=self.cfg.quiet_min_rssi_dbm)
        last = row.get("last_seen") if row else None
        fields = {"addr": addr, "last_seen": last,
                  "silent_for_s": round(now - last) if isinstance(last, (int, float)) else None,
                  "rssi_dbm": row.get("rssi") if row else None,
                  "reception": reception(row.get("rssi"), self.cfg.quiet_min_rssi_dbm) if row else "unknown",
                  "starved": bool(row.get("starved")) if row else False,
                  "role": live.get("role") if live else None,
                  "parent": (self.names.name(parent) or parent) if parent else None,
                  "generation": generation, "parent_generation": parent_generation,
                  "rejoin_ts": row.get("rejoin_ts") if row else None}
        return fields, cause

    # -------------------------------------------------------------- apply

    def apply(self, result: dict, now: float) -> None:
        st = self.state
        st["last_poll_ts"] = now
        if not result.get("ok"):
            # Rule 5: failures, a refused connection or a 5xx while HA
            # restarts, open and close nothing.
            st["fail_since"] = st["fail_since"] or now
            if not st["unreachable"] and now - st["fail_since"] >= UNREACHABLE_AFTER_S:
                st["unreachable"] = True
                self.emit("ha_unreachable", "notice", now, failing_for_s=round(now - st["fail_since"]),
                          error=result.get("error"),
                          note=(f"Home Assistant has not answered the availability poll for "
                                f"{round((now - st['fail_since']) / 60)} min ({result.get('error')}); no device "
                                "episode opens or closes meanwhile, and the next successful poll is a baseline"))
            self._save()
            return
        baseline = self.baseline_pending
        if st["unreachable"]:
            st["unreachable"] = False
            self.emit("ha_reachable", "info", now, unreachable_for_s=round(now - (st["fail_since"] or now)),
                      note="Home Assistant answers the availability poll again; this poll is a baseline")
            baseline = True
        st["fail_since"] = None
        st["ha_last_ok_ts"] = now
        self.baseline_pending = False
        if isinstance(result.get("map"), dict):
            self.mapping = result["map"]
        devices = result.get("devices") or {}
        self.mapped = len(devices)
        episodes = st["episodes"]
        for device_id, (down, since) in devices.items():
            ep = episodes.get(device_id)
            if down and ep is None:
                # Rule 1: open, at HA's own last_changed. No event.
                episodes[device_id] = {"since": float(since) if since is not None else now, "opened_ts": now,
                                       "paged": False, "severity": None, "burst_id": None,
                                       "at_start": baseline, "episode": 1}
            elif not down and ep is not None:
                self._close(device_id, ep, now)
        self._bursts(devices, now)
        for device_id, ep in list(episodes.items()):
            if device_id not in devices or ep.get("paged"):
                continue
            if now - ep["since"] >= self._hold(device_id):
                self._page(device_id, ep, now)
        self._save()

    def _page(self, device_id: str, ep: dict, now: float) -> None:
        """Rule 2: the hold has passed. One ha_unavailable per episode."""
        muted = self._muted(device_id)
        closed = self.state["closed"].get(device_id) or {}
        gap = ep["opened_ts"] - closed["closed_ts"] if isinstance(closed.get("closed_ts"), (int, float)) else None
        flapping = gap is not None and self.cfg.ha_availability_rearm_s > 0 and gap < self.cfg.ha_availability_rearm_s
        episode = (int(closed.get("episodes") or 0) + 1) if flapping else 1
        at_start = bool(ep.get("at_start"))
        severity = "notice" if (muted or ep.get("burst_id") or flapping or at_start) else "warning"
        ep.update(paged=True, severity=severity, episode=episode)
        info = self._info(device_id)
        radio, (cause, sentence) = self._radio(device_id, ep["since"], now)
        name = self._label(device_id)
        down_min = round((now - ep["since"]) / 60)
        note = f"{name} has been unavailable in Home Assistant for {down_min} min. {sentence}"
        if ep.get("burst_id"):
            note += f" Part of {ep['burst_id']}, which paged: logged, not paged again."
        elif muted:
            note += " Muted in ha-availability.json: logged, not paged."
        elif flapping:
            note += (f" Episode {episode} since the last page, {gap / 60:.0f} min after the previous one closed: "
                     f"logged, not paged, until it has stayed available for "
                     f"{self.cfg.ha_availability_rearm_s / 60:.0f} min.")
        elif at_start:
            note += " It was already unavailable when the recorder started: logged, not paged."
        fields = dict(name=name, ha_device_id=device_id, entities=info.get("entities") or [], since=ep["since"],
                      unavailable_for_s=round(now - ep["since"]), hold_s=self._hold(device_id), muted=muted,
                      burst_id=ep.get("burst_id"), episode=episode, cause=cause, **radio, note=note)
        if at_start:
            fields["already_unavailable_at_start"] = True
        self.emit("ha_unavailable", severity, now, **fields)

    def _close(self, device_id: str, ep: dict, now: float) -> None:
        """Rule 4: available again. ha_available only if the episode was
        said; the close is remembered either way for the flap guard."""
        if ep.get("paged"):
            radio, _cause = self._radio(device_id, ep["since"], now)
            rejoin = radio.get("rejoin_ts")
            rejoined = isinstance(rejoin, (int, float)) and ep["since"] <= rejoin <= now
            self.emit("ha_available", "info", now, addr=radio["addr"], name=self._label(device_id),
                      ha_device_id=device_id, since=ep["since"], down_for_s=round(now - ep["since"]),
                      rejoined=rejoined, generation=radio.get("generation"),
                      note=(f"{self._label(device_id)} is available in Home Assistant again after "
                            f"{round((now - ep['since']) / 60)} min"
                            + (f"; it rejoined the mesh at {time.strftime('%H:%M:%S', time.localtime(rejoin))}"
                               if rejoined else "")))
        self.state["closed"][device_id] = {"closed_ts": now, "episodes": int(ep.get("episode") or 1)}
        del self.state["episodes"][device_id]

    def _bursts(self, devices: dict, now: float) -> None:
        """Rule 3: several non-muted devices dropping together are one
        critical burst; rule 6 says when it looks like HA's side."""
        st = self.state
        episodes = st["episodes"]
        window = self.cfg.ha_availability_burst_window_s
        burst = st.get("burst")
        if burst:
            still = [m for m in burst.get("members", []) if m in episodes]
            if len(still) < self.cfg.ha_availability_burst_devices or now - burst["latest_since"] > window:
                st["burst"] = None
            else:
                for device_id, ep in episodes.items():
                    if device_id in burst["members"] or self._muted(device_id) or ep.get("burst_id"):
                        continue
                    if burst["first_since"] <= ep["since"] and ep["since"] - burst["latest_since"] <= window:
                        burst["members"].append(device_id)
                        burst["latest_since"] = max(burst["latest_since"], ep["since"])
                        ep["burst_id"] = burst["id"]
                return
        candidates = [(d, ep) for d, ep in episodes.items()
                      if not self._muted(d) and ep.get("burst_id") is None and ep["since"] >= now - window]
        if len(candidates) < self.cfg.ha_availability_burst_devices:
            return
        newest = max(ep["since"] for _d, ep in candidates)
        if now - newest < self.cfg.ha_availability_burst_hold_s:
            return
        burst_id = f"burst-{time.strftime('%Y%m%dT%H%M%S', time.localtime(now))}"
        members = []
        causes: dict[str, int] = {}
        heard = 0
        for device_id, ep in sorted(candidates, key=lambda c: c[1]["since"]):
            ep["burst_id"] = burst_id
            radio, (cause, _sentence) = self._radio(device_id, ep["since"], now)
            causes[cause] = causes.get(cause, 0) + 1
            if isinstance(radio.get("last_seen"), (int, float)) and now - radio["last_seen"] <= HEARD_RECENTLY_S:
                heard += 1
            members.append({"name": self._label(device_id), "addr": radio["addr"], "ha_device_id": device_id,
                            "since": ep["since"], "cause": cause})
        st["burst"] = {"id": burst_id, "members": [m["ha_device_id"] for m in members],
                       "first_since": members[0]["since"], "latest_since": newest, "ts": now}
        down_now = sum(1 for d, (down, _s) in devices.items() if down and not self._muted(d))
        ha_side = (self.mapped and down_now >= HA_SIDE_SHARE * self.mapped and heard * 2 > len(members))
        summary = ", ".join(f"{n} {c}" for c, n in sorted(causes.items(), key=lambda kv: -kv[1]))
        note = (f"{len(members)} devices went unavailable in Home Assistant within {round(window / 60)} min "
                f"({', '.join(m['name'] for m in members)}): a network problem, not one device. Causes: {summary}.")
        if ha_side:
            note += (f" {down_now} of {self.mapped} mapped devices are down at once while the recorder heard most "
                     "of them in the last 5 min: this looks like the HA or Matter Server side, not the mesh.")
        else:
            note += " Each device's own ha_unavailable record carries its evidence."
        self.emit("ha_unavailable_burst", "critical", now, burst_id=burst_id, devices=members, count=len(members),
                  window_s=window, first_since=members[0]["since"], ha_side=bool(ha_side), note=note)

    # ------------------------------------------------------------- status

    def status(self) -> dict:
        st = self.state
        return {"reachable": not st["unreachable"], "last_poll_ts": st["last_poll_ts"],
                "last_ok_ts": st["ha_last_ok_ts"], "devices_mapped": len(self.mapping),
                "burst": (st.get("burst") or {}).get("id"),
                "open": [{"ha_device_id": d, "name": self._label(d), "addr": self._info(d).get("addr"),
                          "since": ep["since"], "paged": bool(ep.get("paged")), "severity": ep.get("severity"),
                          "burst_id": ep.get("burst_id")}
                         for d, ep in sorted(st["episodes"].items(), key=lambda kv: kv[1]["since"])]}


def availability_by_addr(state_dir: Path) -> dict[str, dict]:
    """For the pages: extended address -> {name, since, paged, burst_id}
    for every open episode the recorder has on file, from the state and
    the cached map. Empty without the feature."""
    state = load_state(state_dir / STATE_FILE)
    mapping = load_map(state_dir)
    out = {}
    for device_id, ep in state["episodes"].items():
        info = mapping.get(device_id) or {}
        addr = (info.get("addr") or "").lower()
        if addr:
            out[addr] = {"name": info.get("name") or info.get("ha_name"), "since": ep.get("since"),
                         "paged": bool(ep.get("paged")), "burst_id": ep.get("burst_id")}
    return out


# ------------------------------------------------------------ the worker

def refresh_map(url: str, token: str, entries: list[dict], log=lambda m: None) -> dict[str, dict]:
    """Rebuild the HA map over the websocket. Raises HAError."""
    from .ha import HomeAssistant
    with HomeAssistant(url, token) as ha:
        return build_map(ha, entries, log)


def poll_once(cfg, mapping: dict[str, dict], entries: list[dict], *, map_age_s: float | None,
              now: float | None = None, log=lambda m: None) -> dict:
    """One worker pass: refresh the map when it is missing or older than
    [ha_availability] registry_refresh_s (the only websocket use), then
    the REST poll. Returns fetch_availability's result, with ``map`` set
    when it was rebuilt and cached. A refresh that fails keeps the cached
    map; with no map at all there is nothing to poll for."""
    from .ha import HAError
    now = now if now is not None else time.time()
    settings = None
    try:
        from .ha import connection_settings
        settings = connection_settings(cfg.config_dir / "ha.env")
    except HAError as exc:
        return {"ok": False, "error": str(exc).split(":")[0], "polled_ts": now}
    url, token = settings
    refreshed = None
    if not mapping or map_age_s is None or map_age_s >= cfg.ha_availability_registry_refresh_s:
        try:
            refreshed = refresh_map(url, token, entries, log)
            save_map(cfg.state_dir, refreshed)
            mapping = refreshed
        except HAError as exc:
            if not mapping:
                from .httpclient import redact_text
                return {"ok": False, "error": redact_text(f"device registry: {exc}", (token,)), "polled_ts": now}
            log(f"HA device map not refreshed ({exc}); polling with the cached map")
    result = fetch_availability(url, token, mapping, now)
    if refreshed is not None:
        result["map"] = refreshed
    return result
