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
from typing import Callable, Optional

from .names import entry_addresses


def _addresses(entry: dict) -> list[str]:
    return [a.upper() for a in entry_addresses(entry)]


def _add_address(entry: dict, addr: str) -> int:
    """Append an address to an entry, moving to the list form. Returns
    how many addresses the entry now has."""
    addrs = _addresses(entry)
    entry.pop("extendedAddress", None)
    entry["extendedAddresses"] = addrs + [addr]
    return len(addrs) + 1


def plan_inventory(entries: list[dict], found: list[dict]) -> tuple[list[dict], list[str]]:
    """Merge Home Assistant's Matter-over-Thread devices into the
    inventory. HA is the authority on their names. Returns the new list
    and one line per change."""
    entries = copy.deepcopy(entries)
    changes: list[str] = []
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
        entry = by_name.get(dev["name"].lower())
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
    a miss becomes a new entry named after the instance."""
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
            entry = next((e for e in entries if (e.get("name") or "").strip().lower() == label.strip().lower()), None)
        if entry is None:
            new = {"name": label, "borderRouter": host, "extendedAddress": ext}
            if model:
                new["model"] = model
            entries.append(new)
            changes.append(f"add {label!r} = {ext} (border router {host})")
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


def run_import(cfg, inventory_path: Path, *, write: bool = False, url: Optional[str] = None,
               env_file: Optional[Path] = None, dataset_id: Optional[str] = None,
               use_ha: bool = True, use_mdns: bool = True, mdns_seconds: float = 3.0,
               devices: bool = True, credentials: bool = True,
               out: Callable[[str], None] = print) -> int:
    """The whole command. Raises ha.HAError for anything Home Assistant
    related that stops the import; mDNS finding nothing is reported, not
    fatal, because the recorder host may simply be on another VLAN."""
    from .ha import HomeAssistant, connection_settings, current_key, thread_dataset, thread_devices, write_private
    from .pipeline import credentials_path

    existing = json.loads(inventory_path.read_text() or "[]") if inventory_path.exists() else []
    planned, changes = existing, []
    wrote = False

    if use_mdns and devices:
        from .mdns import browse
        routers = browse(timeout=mdns_seconds, log=lambda m: out(f"  ! {m}"))
        routers = [r for r in routers if r.get("ext")]
        if routers:
            out(f"mDNS: {len(routers)} border router(s): " + ", ".join(r.get("instance") or r.get("hostname") for r in routers))
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
                if current_key(cred) == ds["network_key"]:
                    out(f"  network key: {cred.name} already holds it")
                elif write:
                    write_private(cred, "[credentials]\n# Written by threadwatch import from Home Assistant's "
                                        f"Thread dataset {ds.get('network_name')!r}. Mode 0600; never commit.\n"
                                        f'network_key = "{ds["network_key"]}"\n')
                    out(f"  network key: wrote {cred} (mode 0600)")
                    wrote = True
                else:
                    out(f"  network key: {'differs from' if cred.exists() else 'not in'} {cred.name}; --write stores it")

    if devices:
        out(f"{inventory_path.name}: {len(existing)} entries" + (":" if changes else ", nothing to change"))
        for line in changes:
            out(f"  {line}")
        if changes and write:
            inventory_path.parent.mkdir(parents=True, exist_ok=True)
            inventory_path.write_text(json.dumps(planned, indent=2) + "\n")
            out(f"  wrote {inventory_path} ({len(planned)} entries)")
            wrote = True

    if not write:
        out("(nothing written: add --write to apply)")
    elif wrote:
        out("(the capture daemon reads both files at start: restart it to use them)")
    return 0
