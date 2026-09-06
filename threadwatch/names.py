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
       "model": "Apple TV 4K", "note": "rotates its address"}
    ]

The inventory is identity only: a name, the addresses it has used, and
optionally a `model` and a free-text `note`. What a device is doing on
the mesh (router or child, leader, parent) changes without anyone
editing a file, so the recorder learns it from traffic and never reads
it from here. Other fields are ignored, so a file produced by another
tool loads as long as it has names and addresses.

Apple hubs (Apple TV, HomePod) change their Thread extended address on
every reboot, so their entries would go stale within weeks. The recorder
finds every border router on the LAN over mDNS (threadwatch/mdns.py),
where the hostname is stable and the current extended address is
advertised, and keeps hostname -> address in the state file
border-routers.json. An entry is tied to a hostname either explicitly,
with `"borderRouter": "appletv-living-room.local"` (`threadwatch import`
writes it), or implicitly, the first time a discovered address matches
one the entry lists; from then on a new address for that hostname is
named from the entry without anyone editing this file. The addresses
the entry lists still name the device on their own, so nothing depends
on mDNS being reachable.

Two helpers keep the file from being hand-written: `threadwatch report
--suggest` prints a ready-to-paste entry per unknown address, prefilled
with any SRP hostname the credentialed pipeline harvested for it, and
`threadwatch adopt <addr> <name>` appends one (or adds a rotated address
to a device already listed under that name).
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import time
from pathlib import Path
from typing import Iterator, Optional


_EXT_ADDR = re.compile(r"^[0-9a-f]{16}$")


def _norm(addr: str) -> str:
    return addr.replace(":", "").strip().lower()


def entry_addresses(entry: dict) -> list[str]:
    """Every address an inventory entry lists, as written: the
    `extendedAddresses` list and then a single `extendedAddress`."""
    addrs = [str(a) for a in (entry.get("extendedAddresses") or [])]
    if entry.get("extendedAddress"):
        addrs.append(str(entry["extendedAddress"]))
    return addrs


class AmbiguousName(ValueError):
    """A name fragment that matches several inventory names; `candidates`
    holds them, sorted, for whoever asks the user to pick."""

    def __init__(self, target: str, candidates: list[str]):
        self.target, self.candidates = target, sorted(candidates)
        super().__init__(f"ambiguous name {target!r}: {self.candidates}")


class DeviceNames:
    def __init__(self, inventory_path: Optional[Path], learned_path: Optional[Path] = None):
        """``learned_path``: the recorder's border-routers.json, whose
        hostname -> address bindings name a rebooted Apple hub's new
        address after the inventory (which lists only old ones)."""
        self.by_addr: dict[str, dict] = {}
        self.inventory_path = inventory_path
        self.entries: list[dict] = []
        self.border_routers: dict[str, dict] = {}    # addr -> {hostname, instance, vendor, model, name, retired}
        if inventory_path and inventory_path.exists():
            # The file is hand-edited (README): a trailing comma or a
            # truncated save is the likeliest damage, and it must not stop
            # the recorder or 500 every review page any more than a stray
            # entry does. Said loudly, since every device is unknown until
            # it is fixed; threadwatch doctor reports it as a failure.
            try:
                raw = json.loads(inventory_path.read_text())
            except ValueError as exc:
                print(f"[threadwatch] {inventory_path.name} is not valid JSON ({exc}): ignoring the file, "
                      "so every device is unknown until it is fixed (threadwatch doctor checks it)", flush=True)
                raw = []
            if not isinstance(raw, list):
                print(f"[threadwatch] {inventory_path.name}: expected a list of devices, got "
                      f"{type(raw).__name__}; ignoring the file", flush=True)
                raw = []
            # A hand-edit can leave a bare string or a stray null behind. One bad
            # entry must not stop the recorder or 500 every review page.
            self.entries = [e for e in raw if isinstance(e, dict)]
            for entry in self.entries:
                for a in entry_addresses(entry):
                    n = _norm(str(a))
                    # Every inventory address is fed to the decryptor's nonce
                    # search as raw hex; a stray 0x prefix or dash would
                    # raise there, in the capture loop, on every frame.
                    if not _EXT_ADDR.match(n):
                        print(f"[threadwatch] {inventory_path.name}: ignoring address {a!r} of "
                              f"{entry.get('name')!r}: not 16 hex digits", flush=True)
                        continue
                    self.by_addr[n] = entry
        for host, rec in load_border_routers(learned_path).items():
            addr = _norm(str(rec.get("addr") or ""))
            if not _EXT_ADDR.match(addr):
                continue
            entry = self.entry_for_border_router(host) or (self.entry_named(rec["name"]) if rec.get("name") else None)
            # The current address, then every address the hub retired
            # (the recorder writes each rotation to `previous`): a retired
            # address keeps the name, so the device page and `why` still
            # tell the device's story across its reboots, in every process
            # and not only the one that saw the rotation happen.
            retired = [_norm(str(p.get("addr") or "")) for p in (rec.get("previous") or []) if isinstance(p, dict)]
            for a, is_current in [(addr, True)] + [(a, False) for a in reversed(retired)]:
                if not _EXT_ADDR.match(a) or a in self.border_routers:
                    continue
                self.border_routers[a] = {"hostname": host, "instance": rec.get("instance"),
                                          "vendor": rec.get("vendor"), "model": rec.get("model"),
                                          "name": rec.get("name"), "retired": not is_current}
                if entry is not None and a not in self.by_addr:
                    self.by_addr[a] = entry

    def entry_named(self, name: str) -> Optional[dict]:
        want = name.strip().lower()
        return next((e for e in self.entries if (e.get("name") or "").strip().lower() == want), None)

    def entry_for_border_router(self, hostname: str) -> Optional[dict]:
        """The entry that names this border router explicitly."""
        want = hostname.rstrip(".").lower()
        return next((e for e in self.entries
                     if str(e.get("borderRouter") or "").rstrip(".").lower() == want), None)

    def learn(self, addr: str, entry: dict) -> None:
        """Name an address from an inventory entry it does not list (a
        border router's new address after a reboot)."""
        self.by_addr[_norm(addr)] = entry

    def name(self, addr: str) -> Optional[str]:
        entry = self.by_addr.get(_norm(addr))
        return (str(entry["name"]) if entry and entry.get("name") else None)

    def addresses_of(self, addr: str) -> list[str]:
        """Every inventory address that belongs to the same device as
        ``addr``: the entry's own list, plus any other entry under the same
        name (a rotating device is sometimes listed once per address). The
        address itself comes first; an address not in the inventory is a
        device of one."""
        addr = _norm(addr)
        name = self.name(addr)
        out = [addr]
        if name:
            for a, entry in self.by_addr.items():
                if (entry.get("name") or "").lower() == name.lower() and a not in out:
                    out.append(a)
        return out

    def resolve(self, target: str) -> tuple[list[str], str]:
        """A 16-hex address, or a case-insensitive substring of one
        inventory name, to (every address of that device, display name).
        Raises AmbiguousName (a ValueError carrying the candidates) when the
        text matches several names, and ValueError when it matches nothing."""
        t = _norm(target)
        if _EXT_ADDR.match(t):
            return self.addresses_of(t), self.name(t) or t
        matches: dict[str, list[str]] = {}
        for a, entry in self.by_addr.items():
            name = str(entry.get("name") or "")
            if name and target.strip().lower() in name.lower():
                matches.setdefault(name, []).append(a)
        exact = [n for n in matches if n.lower() == target.strip().lower()]
        if exact:
            matches = {exact[0]: matches[exact[0]]}
        if len(matches) == 1:
            name, addrs = next(iter(matches.items()))
            return addrs, name
        if matches:
            raise AmbiguousName(target, list(matches))
        raise ValueError(f"{target!r} is neither a 16-hex-char address nor a known device name")


_warned_unreadable: set = set()     # state files already complained about, once per process


class LastSeen:
    """Tracks when each source address (extended, 16-hex-char) last transmitted."""

    def __init__(self, state_path: Optional[Path]):
        """``state_path`` None: an in-memory table that is never saved
        (replay must not touch the live recorder's state).

        A file that does not parse is a week of first_seen, frames and
        announced silences, and the only record of which devices died
        while the recorder was down. Starting from an empty table is the
        only way to keep recording, but it must not look like a first
        run: the recorder says so, and the first save moves the broken
        file aside as <name>.corrupt instead of writing over it."""
        self.state_path = state_path
        self.table: dict[str, dict] = {}
        self.unreadable: Optional[Exception] = None
        if state_path is not None and state_path.exists():
            try:
                table = json.loads(state_path.read_text())
                if not isinstance(table, dict):
                    raise ValueError(f"expected an object, got {type(table).__name__}")
                # A row that is not an object has no .get, and every row is
                # read that way at start-up: one would have stopped the
                # recorder from starting. Such rows are dropped and said.
                rows = {a: r for a, r in table.items() if isinstance(r, dict)}
                if len(rows) < len(table):
                    print(f"[threadwatch] {state_path.name}: dropping {len(table) - len(rows)} row(s) that are "
                          "not objects", flush=True)
                self.table = rows
            except (ValueError, OSError) as exc:
                self.unreadable = exc
                if state_path not in _warned_unreadable:
                    _warned_unreadable.add(state_path)
                    print(f"[threadwatch] {state_path.name} is unreadable ({exc}): starting from an empty "
                          f"table, so nothing is known about the devices until they are heard again; the "
                          f"recorder keeps the file as {state_path.name}.corrupt when it next saves", flush=True)
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
        if self.unreadable is not None:
            self._keep_aside()
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.table))
        tmp.replace(self.state_path)
        self._dirty = False
        self._last_save = time.time()

    def _keep_aside(self) -> None:
        """Move the file that would not parse out of the way of the first
        save, never over an earlier one kept the same way."""
        self.unreadable = None
        if not self.state_path.exists():
            return
        kept = self.state_path.with_name(self.state_path.name + ".corrupt")
        if kept.exists():
            kept = kept.with_name(f"{kept.name}-{int(time.time())}")
        try:
            self.state_path.replace(kept)
        except OSError as exc:
            print(f"[threadwatch] could not keep {self.state_path.name} aside as {kept.name}: {exc}", flush=True)
            return
        print(f"[threadwatch] unreadable {self.state_path.name} kept as {kept.name}", flush=True)

    def report(self, names: DeviceNames, quiet_after_s: Optional[float] = None,
               now: Optional[float] = None, min_rssi_dbm: float = -82.0,
               dominant: Optional[int] = None) -> dict:
        """Quiet, active and unknown devices. "Quiet" is one thing
        everywhere: what the recorder announced (the row's persisted
        quiet_reported flag, set after [quiet] silence_s of silence it
        was up to hear), which is also what the review pages show.
        ``quiet_after_s`` instead lists every device silent that long on
        the wall clock, for a table no recorder is judging. Either way
        a retired address (an Apple hub's before its reboot) and a device
        on another PAN (``dominant``) are never quiet, as in the
        pipeline; they still count as unknown if unnamed."""
        now = now or time.time()
        quiet, active, unknown = [], [], []
        for addr, row in sorted(self.table.items(), key=lambda kv: kv[1]["last_seen"]):
            silent_for = now - row["last_seen"]
            name = names.name(addr)
            rssi = row.get("rssi")
            item = {
                "addr": addr,
                "name": name,
                "frames": row["frames"],
                "first_seen": row.get("first_seen"),
                "last_seen": row["last_seen"],
                "silent_for_s": round(silent_for, 1),
                "rssi_dbm": rssi,
                "reception": reception(rssi, min_rssi_dbm),
            }
            if name is None:
                unknown.append(item)
            judged = not row.get("rotated_to") and (
                dominant is None or row.get("pan") is None or row.get("pan") == dominant)
            if quiet_after_s is None:
                is_quiet = judged and bool(row.get("quiet_reported"))
            else:
                is_quiet = judged and silent_for > quiet_after_s
            if is_quiet:
                quiet.append(item)
            elif judged:
                active.append(item)
        return {"quiet": quiet, "active_count": len(active), "unknown": unknown}


def load_border_routers(path: Optional[Path]) -> dict[str, dict]:
    """border-routers.json: {hostname: {addr, name, instance, vendor, model,
    since, seen, previous: [{addr, until}]}}, written by the recorder."""
    if path is None:
        return {}
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    # A row that is not an object (a hand-edit, a half-restored backup)
    # has no .get, and every reader of a row asks it: the recorder could
    # not start on one. Rows are dropped, never the file.
    return {host: rec for host, rec in data.items() if isinstance(rec, dict)}


def load_names(cfg) -> DeviceNames:
    """The inventory plus what the recorder has learned about border
    routers: the one way every command and page should build names."""
    return DeviceNames(cfg.devices_path, cfg.state_dir / "border-routers.json")


def rloc16_role(rloc16: Optional[str]) -> Optional[dict]:
    """What a Thread short address says about its holder. The top six bits
    are a router id; a zero low ten bits is the router itself, anything
    else is one of its children. 0xF000 is router 60; 0xC004 is child 4
    of router 48."""
    if not rloc16:
        return None
    try:
        v = int(rloc16, 16)
    except ValueError:
        return None
    rid, cid = v >> 10, v & 0x3FF
    return {"rloc16": rloc16, "router_id": rid, "child_id": cid or None,
            "role": "router" if cid == 0 else "child"}


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
    if not isinstance(data, dict):
        return {}
    # A row that is not an object (a hand-edit, a half-restored backup)
    # has no .get, and every reader of a row asks it: the recorder could
    # not start on one. Rows are dropped, never the file.
    return {host: rec for host, rec in data.items() if isinstance(rec, dict)}


ROTATION_WINDOW_S = 15 * 60


def rotation_hints(unknown: list[dict], table: dict[str, dict], names: DeviceNames,
                   window_s: float = ROTATION_WINDOW_S) -> dict[str, dict]:
    """Which unknown addresses look like a known device's new address.

    A rotating device (Apple TV, HomePod) stops using one extended address
    and starts another within minutes. So: for every named device, the
    moment its last known address was last heard; an unknown address that
    first appeared within ``window_s`` of that moment, after which none of
    the device's known addresses were heard again while the unknown one
    kept talking, is probably the same device. Returns {unknown addr:
    {"name", "previous", "delta_s", "rotates"}} with the closest candidate,
    ``rotates`` meaning the inventory already lists several addresses."""
    devices: dict[str, list[str]] = {}
    for a, entry in names.by_addr.items():
        if entry.get("name"):
            devices.setdefault(entry["name"], []).append(a)
    hints = {}
    for item in unknown:
        born = item.get("first_seen")
        if born is None:
            continue
        best = None
        for name, addrs in devices.items():
            rows = [(table[a]["last_seen"], a) for a in addrs if a in table]
            if not rows:
                continue
            last, prev = max(rows)
            delta = born - last
            outlived = item.get("last_seen", born) > last + window_s   # the new address carried on alone
            if abs(delta) <= window_s and outlived and (best is None or abs(delta) < abs(best["delta_s"])):
                best = {"name": name, "previous": prev, "delta_s": round(delta), "rotates": len(addrs) > 1}
        if best:
            hints[item["addr"]] = best
    return hints


# A harvested hostname is a suggestion only once it has been seen this
# often: the scraper (crypto.Decryptor.harvest_names) is a regex that
# also matches random ciphertext now and then, and a real SRP name recurs
# as its lease is renewed.
MIN_SIGHTINGS = 2


def suggest_entries(unknown: list[dict], observed: dict[str, dict[str, int]],
                    hints: Optional[dict[str, dict]] = None) -> list[dict]:
    """A devices.json entry per unknown address from a LastSeen report, ready
    to paste. The name is the most-sighted harvested hostname seen at least
    MIN_SIGHTINGS times, or blank
    (a blank name keeps the address in the unknown list until filled in);
    the note carries what the recorder knows so the entry can be matched
    to a real device (power-cycle test, OTBR's device list, ...), and a
    rotation hint (rotation_hints) when a named device fell silent as this
    address appeared."""
    out = []
    for item in unknown:
        addr = item["addr"]
        seen = observed.get(addr) or observed.get(addr.upper()) or {}
        hostnames = [n for n, count in sorted(seen.items(), key=lambda kv: (-kv[1], kv[0]))
                     if count >= MIN_SIGHTINGS]
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
        hint = (hints or {}).get(addr)
        if hint:
            d = hint["delta_s"]
            when = "as" if abs(d) < 60 else f"{abs(d) // 60} min {'after' if d > 0 else 'before'}"
            facts.append(f"possibly a new address of {hint['name']}"
                         f"{' (which rotates)' if hint['rotates'] else ''}: its previous address "
                         f"{hint['previous']} fell silent {when} this one appeared")
        out.append({"name": hostnames[0] if hostnames else "",
                    "extendedAddress": addr.upper(),
                    "note": "; ".join(facts)})
    return out


def read_inventory(inventory_path: Path) -> list[dict]:
    """The inventory as the commands that rewrite it (adopt, import) read
    it: every entry a device object. A missing file is an empty inventory.

    The recorder (DeviceNames) skips a stray null or bare string and keeps
    recording; a command about to rewrite the file must neither crash on
    one nor silently drop it, so this raises ValueError naming the file
    and the entry, and the person editing decides."""
    if not inventory_path.exists():
        return []
    try:
        entries = json.loads(inventory_path.read_text() or "[]")
    except ValueError as exc:
        raise ValueError(f"{inventory_path.name} is not valid JSON ({exc})") from None
    if not isinstance(entries, list):
        raise ValueError(f"{inventory_path.name} is not a JSON list")
    for i, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            what = "null" if entry is None else f"a {type(entry).__name__}"
            raise ValueError(f"{inventory_path.name}: entry {i} is {what}, not a device object "
                             f"({{\"name\": ..., \"extendedAddress\": ...}}); fix the file first")
    return entries


@contextlib.contextmanager
def inventory_lock(inventory_path: Path) -> Iterator[None]:
    """Hold the inventory's lock across a read-modify-write of the file.
    `adopt` and `import` both take it, so two edits at once queue instead
    of the later one replacing the file with a copy that never saw the
    earlier one's change (the atomic replace protects readers from a half
    written file, not writers from each other). The lock is a file beside
    the inventory, held with flock, so it works across processes and is
    released with the process that took it."""
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    lock = inventory_path.with_name(inventory_path.name + ".lock")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def adopt(inventory_path: Path, addr: str, name: str) -> str:
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
    with inventory_lock(inventory_path):
        return _adopt(inventory_path, n, name)


def _adopt(inventory_path: Path, n: str, name: str) -> str:
    entries = read_inventory(inventory_path)
    for entry in entries:
        if n in [_norm(a) for a in entry_addresses(entry)]:
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
        what = f"added {n} to {existing.get('name')!r} ({len(addrs)} addresses)"
    else:
        entry = {"name": name, "extendedAddress": stored}
        entries.append(entry)
        what = f"added {name!r} = {n}"
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = inventory_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2, ensure_ascii=False) + "\n")
    tmp.replace(inventory_path)
    return what
