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
devices.json never learns an HA id.

A longer hold for a known flapper, or mute, is the device's `hold_s` or
`mute` in devices.json (threadwatch hold / mute), read through the
inventory by address: the same tolerance device_quiet honours, since a
sensor that drops out in the afternoon sun does so on the air and in HA
alike.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime
from pathlib import Path

from .names import _norm


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


def _number(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


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
    # Parsed JSON of the wrong shape would raise in the Tracker's
    # constructor or its next poll, both on the capture thread, every
    # start: what does not fit is dropped here instead.
    episodes, closed = data.get("episodes"), data.get("closed")
    state["episodes"] = {k: v for k, v in (episodes if isinstance(episodes, dict) else {}).items()
                         if isinstance(v, dict) and _number(v.get("since"))}
    state["closed"] = {k: v for k, v in (closed if isinstance(closed, dict) else {}).items() if isinstance(v, dict)}
    burst = data.get("burst")
    if (isinstance(burst, dict) and isinstance(burst.get("members"), list)
            and "id" in burst and _number(burst.get("first_since")) and _number(burst.get("latest_since"))):
        state["burst"] = burst
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
    written; ``names`` the inventory, for the device's own hold and mute."""

    def __init__(self, cfg, state_path: Path | None, *, emit, rows: dict, names,
                 mapping: dict | None = None, lost_leader=None):
        self.cfg, self.state_path = cfg, state_path
        self.emit, self.rows, self.names = emit, rows, names
        # addr -> the pipeline's record of the leader a partition change
        # replaced, when it is that device (Pipeline.lost_leader_for).
        self.lost_leader = lost_leader or (lambda addr: None)
        self.mapping: dict = mapping or {}
        # Rotations the last map refresh reported (a device whose extended
        # address changed in HA's node diagnostics): the pipeline drains
        # these after apply and retires the old rows, which live on its
        # thread and are never written here.
        self.rotations: list[dict] = []
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

    def _addr(self, device_id: str) -> str | None:
        return (self._info(device_id).get("addr") or "").lower() or None

    def _muted(self, device_id: str) -> bool:
        addr = self._addr(device_id)
        return bool(addr) and self.names.muted(addr)

    def _hold(self, device_id: str) -> float:
        addr = self._addr(device_id)
        hold = self.names.hold_s(addr) if addr else None
        return self.cfg.ha_availability_hold_s if hold is None else hold

    def _info(self, device_id: str) -> dict:
        return self.mapping.get(device_id) or {}

    def _label(self, device_id: str) -> str:
        info = self._info(device_id)
        return info.get("name") or info.get("ha_name") or device_id

    def _radio(self, device_id: str, since: float, now: float) -> tuple[dict, tuple[str, str]]:
        """The evidence fields and the cause for one device."""
        from .hacause import classify
        from .names import parent_address, reception, rloc16_role, router_holders
        addr = self._addr(device_id)
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
                         min_rssi_dbm=self.cfg.quiet_min_rssi_dbm,
                         lost_leader=self.lost_leader(addr) if addr else None)
        last = row.get("last_seen") if row else None
        fields = {"addr": addr, "last_seen": last,
                  "silent_for_s": round(now - last) if isinstance(last, (int, float)) else None,
                  "rssi_dbm": row.get("rssi") if row else None,
                  "reception": reception(row.get("rssi"), self.cfg.quiet_min_rssi_dbm) if row else "unknown",
                  "starved": bool(row.get("starved")) if row else False,
                  "unserved": bool(row.get("unserved")) if row else False,
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
            self._note_rotations(result["map"], now)
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
            note += " Muted in devices.json: logged, not paged."
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
        said, and only then is the close remembered for the flap guard:
        a blip inside the hold (every device, at each Home Assistant or
        Matter Server restart) paged nothing, so there is nothing to
        guard, and remembering it demoted the next real outage."""
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

    def _note_rotations(self, new_map: dict, now: float) -> None:
        """A device whose extended address differs between the map the
        tracker held and the one just built took a new address: the
        Matter Server read the new one from the device itself. Queued for
        the pipeline (Pipeline._device_rotated), which names the new
        address, retires the old row and says so once."""
        for device_id, info in new_map.items():
            before = ((self.mapping.get(device_id) or {}).get("addr") or "").lower()
            after = (info.get("addr") or "").lower()
            if before and after and before != after:
                self.rotations.append({"previous": before, "addr": after, "ha_device_id": device_id})

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
    for every device the cached map knows, ``since`` None when it is
    available, from the state file and the map. Empty without the
    feature (no map on disk)."""
    state = load_state(state_dir / STATE_FILE)
    mapping = load_map(state_dir)
    out = {}
    for device_id, info in mapping.items():
        addr = (info.get("addr") or "").lower()
        if not addr:
            continue
        ep = state["episodes"].get(device_id) or {}
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


def credentials_or_none(cfg) -> tuple[str, str] | None:
    """(url, token) from config/ha.env, or None without a token."""
    from .ha import HAError, connection_settings
    try:
        return connection_settings(cfg.config_dir / "ha.env")
    except HAError:
        return None
