"""`threadwatch import`: fill devices.json and credentials.toml from what
the network already knows.

Two sources, each optional:

  Home Assistant  (threadwatch/ha.py) the device registry names every
                  Matter-over-Thread device and its diagnostics give the
                  extended address; the preferred Thread dataset holds the
                  network key. HA is where those devices were named, so HA
                  wins on their names.
  mDNS            (threadwatch/mdns.py) every Thread border router on the
                  LAN advertises a stable hostname and its current
                  extended address. Apple hubs change the address on every
                  reboot, so an entry gets both: the hostname, which the
                  recorder uses to follow the address live, and the
                  addresses it has had, which name the device if mDNS is
                  ever out of reach. The mDNS instance name is only used
                  when the entry is created; after that the name in the
                  file is yours.

Everything hand-written in devices.json is carried through: notes, extra
addresses, devices no source knows (HomeKit-only locks). Entries are
never deleted. The plan is printed; ``--write`` applies it.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Callable

from .names import _norm, entry_addresses, inventory_lock, read_inventory


def _addresses(entry: dict) -> list[str]:
    """Every address an entry lists, in the one form addresses are matched
    in here: the loader's normalisation (colons out), upper-cased. The
    inventory accepts 00:11:22:... and the sources send 001122...; matched
    as written, an entry in the colon form was never found by its
    address and a second entry was made for the same device."""
    return [_norm(str(a)).upper() for a in entry_addresses(entry)]


def _add_address(entry: dict, addr: str) -> int:
    """Append an address to an entry, moving to the list form. Returns
    how many addresses the entry now has. The addresses already there
    are kept as written."""
    addrs = entry_addresses(entry)
    entry.pop("extendedAddress", None)
    entry["extendedAddresses"] = addrs + [addr]
    return len(addrs) + 1


def _told_apart(devs: list[dict], entries: list[dict]) -> dict[str, str]:
    """Names for devices Home Assistant calls the same thing: the shared
    name and the tail of each address, as many characters of it as it
    takes for the names to differ from one another and from every entry
    that holds none of these addresses. Four characters told two devices
    apart until two shared them, when the second was filed under the
    first's name as its rotated address. Address -> name."""
    base = devs[0]["name"]
    addrs = {dev["addr"].upper() for dev in devs}
    taken = {(e.get("name") or "").strip().lower() for e in entries if not addrs & set(_addresses(e))}
    names = {}
    for n in range(4, 17, 2):
        names = {dev["addr"].upper(): f"{base} ({dev['addr'][-n:].upper()})" for dev in devs}
        if len(set(names.values())) == len(names) and not any(v.lower() in taken for v in names.values()):
            break
    return names


def plan_inventory(entries: list[dict], found: list[dict]) -> tuple[list[dict], list[str]]:
    """Merge Home Assistant's Matter-over-Thread devices into the
    inventory. HA is the authority on their names. Returns the new list
    and one line per change.

    HA does not keep names unique. Devices sharing one are told apart here
    by the tail of their address ("Contact Sensor (6950)"): the name is
    the inventory's identity, and two addresses live at the same moment
    are two devices, never one that rotates. The address-by-name fallback
    below (an Apple TV known under an old address) therefore only ever
    matches a name that is unique in HA."""
    entries = copy.deepcopy(entries)
    changes: list[str] = []
    holders: dict[str, list[dict]] = {}
    for dev in found:
        holders.setdefault(dev["name"].strip().lower(), []).append(dev)
    shared = [devs for devs in holders.values() if len(devs) > 1]
    for devs in shared:
        changes.append(f"{devs[0]['name']!r} names {len(devs)} devices in Home Assistant: told apart here "
                       "by address; rename them there to give each its own name")
    apart = {addr: name for devs in shared for addr, name in _told_apart(devs, entries).items()}
    found = [{**dev, "name": apart[dev["addr"].upper()]} if dev["addr"].upper() in apart else dev
             for dev in found]
    by_addr = {a: e for e in entries for a in _addresses(e)}
    by_name = {(e.get("name") or "").strip().lower(): e for e in entries if e.get("name")}
    for dev in found:
        addr = dev["addr"].upper()
        entry = by_addr.get(addr)
        if entry is not None:
            if (entry.get("name") or "").strip() != dev["name"]:
                changes.append(f"rename {entry.get('name')!r} -> {dev['name']!r} ({addr})")
                by_name.pop((entry.get("name") or "").strip().lower(), None)
                entry["name"] = dev["name"]
                by_name[dev["name"].lower()] = entry
            if dev.get("model") and not entry.get("model"):
                entry["model"] = dev["model"]
                changes.append(f"{dev['name']}: model {dev['model']!r}")
            continue
        # A device told apart by its address is one of several live at
        # once, never a rotating device known under an old address: it is
        # matched by address or added, whatever entry carries its name.
        entry = by_name.get(dev["name"].lower()) if addr not in apart else None
        if entry is not None:
            n = _add_address(entry, addr)
            by_addr[addr] = entry
            changes.append(f"{dev['name']}: new address {addr} (now {n} addresses)")
            if dev.get("model") and not entry.get("model"):
                entry["model"] = dev["model"]
                changes.append(f"{dev['name']}: model {dev['model']!r}")
            continue
        new = {"name": dev["name"], "extendedAddress": addr}
        if dev.get("model"):
            new["model"] = dev["model"]
        entries.append(new)
        by_addr[addr] = new
        by_name[dev["name"].lower()] = new
        changes.append(f"add {dev['name']!r} = {addr}")
    return entries, changes


def plan_border_routers(entries: list[dict], routers: list[dict]) -> tuple[list[dict], list[str]]:
    """Merge the border routers mDNS found. An entry is matched by its
    borderRouter hostname, then by an address it lists, then by the mDNS
    instance name; a match gains the hostname and the current address,
    a miss becomes a new entry named after the instance.

    The hostname is a router's identity; the display name is not. The
    name fallback binds an entry written by hand before its hub was ever
    heard, so it only matches an entry with no hostname yet: an entry
    bound to another hostname is another hub, and a second one under
    the same instance name (a replacement, the old one offline; a name
    copied into the inventory) is added beside it, told apart by the
    tail of its address, rather than rebinding the first hub's entry
    and taking its address history."""
    entries = copy.deepcopy(entries)
    changes: list[str] = []
    for r in routers:
        host, ext = (r.get("hostname") or "").rstrip(".").lower(), (r.get("ext") or "").upper()
        if not host or len(ext) != 16:
            continue
        label = r.get("instance") or host
        model = " ".join(x for x in (r.get("vendor"), r.get("model")) if x) or None
        entry = next((e for e in entries if str(e.get("borderRouter") or "").rstrip(".").lower() == host), None)
        if entry is None:
            entry = next((e for e in entries if ext in _addresses(e)), None)
        if entry is None:
            entry = next((e for e in entries if (e.get("name") or "").strip().lower() == label.strip().lower()
                          and not e.get("borderRouter")), None)
        if entry is None:
            taken = {(e.get("name") or "").strip().lower() for e in entries}
            name, why = label, ""
            if name.strip().lower() in taken:
                for n in range(4, 17, 2):
                    name = f"{label} ({ext[-n:]})"
                    if name.lower() not in taken:
                        break
                why = f"; {label!r} already names another border router"
            new = {"name": name, "borderRouter": host, "extendedAddress": ext}
            if model:
                new["model"] = model
            entries.append(new)
            changes.append(f"add {name!r} = {ext} (border router {host}{why})")
            continue
        name = entry.get("name") or label
        if str(entry.get("borderRouter") or "").rstrip(".").lower() != host:
            entry["borderRouter"] = host
            changes.append(f"{name}: border router {host}")
        if ext not in _addresses(entry):
            n = _add_address(entry, ext)
            changes.append(f"{name}: new address {ext} (now {n} addresses)")
        if model and not entry.get("model"):
            entry["model"] = model
            changes.append(f"{name}: model {model!r}")
    return entries, changes


def run_import(cfg, inventory_path: Path, *, write: bool = False, url: str | None = None,
               env_file: Path | None = None, dataset_id: str | None = None,
               use_ha: bool = True, use_mdns: bool = True, mdns_seconds: float = 4.0,
               devices: bool = True, credentials: bool = True,
               out: Callable[[str], None] = print) -> int:
    """The whole command. Raises ha.HAError for anything Home Assistant
    related that stops the import; mDNS finding nothing is reported, not
    fatal, because the recorder host may simply be on another VLAN. The
    inventory is read and written under its lock (names.inventory_lock),
    held for the whole run, so an `adopt` meanwhile waits its turn rather
    than losing its edit to the write here."""
    kw = dict(write=write, url=url, env_file=env_file, dataset_id=dataset_id, use_ha=use_ha,
              use_mdns=use_mdns, mdns_seconds=mdns_seconds, devices=devices, credentials=credentials, out=out)
    if not devices:
        return _import(cfg, inventory_path, **kw)
    with inventory_lock(inventory_path):
        return _import(cfg, inventory_path, **kw)


def _import(cfg, inventory_path: Path, *, write: bool, url: str | None, env_file: Path | None,
            dataset_id: str | None, use_ha: bool, use_mdns: bool, mdns_seconds: float,
            devices: bool, credentials: bool, out: Callable[[str], None]) -> int:
    from .ha import HomeAssistant, connection_settings, current_key, thread_dataset, thread_devices, write_private
    from .pipeline import credentials_path

    # ValueError, naming the entry, for a malformed file: only when the
    # inventory is being imported into. Fetching the network key (the
    # --no-devices recovery path) neither reads nor writes it, and must not
    # wait on an unrelated repair.
    existing = read_inventory(inventory_path) if devices else []
    planned, changes = existing, []
    wrote = False

    if use_mdns and devices:
        from .mdns import browse
        routers = browse(timeout=mdns_seconds, log=lambda m: out(f"  ! {m}"))
        routers = [r for r in routers if r.get("ext")]
        if routers:
            out(f"mDNS: {len(routers)} border router(s): "
                + ", ".join(r.get("instance") or r.get("hostname") for r in routers))
            planned, more = plan_border_routers(planned, routers)
            changes += more
        else:
            out("mDNS: no border routers answered: is this host on their subnet, or is mDNS reflected between "
                "VLANs? Border-router entries are left as they are")

    if use_ha:
        ha_url, token = connection_settings(env_file or (cfg.config_dir / "ha.env"), url)
        out(f"Home Assistant: {ha_url}")
        with HomeAssistant(ha_url, token) as ha:
            if devices:
                found = thread_devices(ha, log=lambda m: out(f"  {'' if m.startswith('asking') else '! '}{m}"))
                out(f"Home Assistant: {len(found)} Matter-over-Thread devices")
                planned, more = plan_inventory(planned, found)
                changes += more
            if credentials:
                ds = thread_dataset(ha, dataset_id)
                cred = credentials_path(cfg)
                out(f"thread: {ds.get('network_name')}, channel {ds.get('channel')}, "
                    f"PAN 0x{ds.get('pan_id', 0):04x}, extended PAN {ds.get('ext_pan_id')}")
                if ds.get("channel") and ds["channel"] != cfg.channel:
                    out(f"  ! config.toml says channel {cfg.channel}; the dataset says {ds['channel']}: "
                        "the recorder listens on the wrong channel until you fix [network] channel")
                if ds.get("pan_id") is not None:
                    if cfg.pan_id is None:
                        out(f"  [network] pan_id is unset; the dataset says 0x{ds['pan_id']:04x}: set it and the "
                            "recorder stops guessing which PAN is yours")
                    elif ds["pan_id"] != cfg.pan_id:
                        out(f"  ! config.toml says pan_id 0x{cfg.pan_id:04x}; the dataset says 0x{ds['pan_id']:04x}: "
                            "every device counts as foreign and none is judged until you fix [network] pan_id")
                if current_key(cred) == ds["network_key"]:
                    out(f"  network key: {cred.name} already holds it")
                elif write:
                    write_private(cred, "[credentials]\n# Written by threadwatch import from Home Assistant's "
                                        f"Thread dataset {ds.get('network_name')!r}. Mode 0600; never commit.\n"
                                        f'network_key = "{ds["network_key"]}"\n')
                    out(f"  network key: wrote {cred} (mode 0600)")
                    wrote = True
                else:
                    out(f"  network key: {'differs from' if cred.exists() else 'not in'} "
                        f"{cred.name}; --write stores it")

    if devices:
        out(f"{inventory_path.name}: {len(existing)} entries" + (":" if changes else ", nothing to change"))
        for line in changes:
            out(f"  {line}")
        # Not every line above is an edit: a name two HA devices share is
        # reported on every run, because the fix for it is in HA. Write only
        # when the entries themselves differ, so a run that has nothing to
        # say but that reminder leaves the file, and its mtime, alone.
        if planned != existing:
            if write:
                inventory_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = inventory_path.with_suffix(".tmp")
                tmp.write_text(json.dumps(planned, indent=2) + "\n")
                tmp.replace(inventory_path)
                out(f"  wrote {inventory_path} ({len(planned)} entries)")
                wrote = True
        elif changes:
            out("  (nothing to write: no entry changes)")

    if not write:
        out("(nothing written: add --write to apply)")
    elif wrote:
        out("(the capture daemon reads both files at start: restart it to use them)")
    return 0
