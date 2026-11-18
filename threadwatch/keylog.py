"""Each device's boots and key switches out of the key journal, in the
form the key guard model takes (keyguard.Boot, keyguard.Switch), and the
forecast's Device list built from them. No file, network or clock access:
the caller hands over the journal's records, the inventory entries, the
stack table, the HA map and who is whose child.

A device is an inventory entry, not an address: extended addresses rotate,
so records are joined on the entry's address list. Three kinds of record
have no listed address and join another way:
- the OTBR's inventory samples and uptime resets, filed under otbr:<source>,
  go to the inventory name the caller gives for the OTBR;
- a reboot entered by name (`threadwatch rebooted`, the seed) carries the
  name in its evidence;
- a device named by mDNS and not by a listed address (an Apple TV) is
  named in its transition records' context, and every record of that
  address then joins it.
"""

from __future__ import annotations

from .keyfacts import _int, _time, switch_seen
from .keyforecast import Device
from .keyguard import Boot, Switch
from .names import _norm, entry_addresses
from .stacks import device_stack

KINDS = ("transition", "reboot", "inventory")


def by_device(records, entries, otbr: str | None = None) -> dict[str, list[dict]]:
    """The journal's switch and boot records per inventory name. ``otbr``
    is the inventory name of the border router the [otbr] inventory reads.
    A record no rule above places is left out."""
    names = {e["name"] for e in entries if isinstance(e.get("name"), str)}
    by_addr = {_norm(a): e["name"] for e in entries if e.get("name") in names for a in entry_addresses(e)}
    mine = [r for r in records if r.get("kind") in KINDS and isinstance(r.get("addr"), str)]
    for r in mine:                       # an address only a record names, wherever in the journal that record is
        named = (r["context"] if r["kind"] == "transition" else r["evidence"]).get("name")
        if r["kind"] != "inventory" and named in names and not r["addr"].startswith("otbr:"):
            by_addr.setdefault(_norm(r["addr"]), named)
    out: dict[str, list[dict]] = {}
    for r in mine:
        name = otbr if r["addr"].startswith("otbr:") else by_addr.get(_norm(r["addr"]))
        if name is not None:
            out.setdefault(name, []).append(r)
    return out


def switch_log(records) -> list[Switch]:
    """One device's key switches, oldest first, from its transition
    records (MAC and MLE, every address) and the OTBR's key counter
    changes, merged: the first record on each higher key is the switch, and
    a layer or address catching up later is not one. A switch is seen
    ("since") or first seen after a gap ("by") by keyfacts.switch_seen, the
    device page's rule: the gap runs from the last time any record has the
    device on the old key."""
    rows = []
    for r in records:
        if r["kind"] == "transition":
            rows.append((r["ts"], r.get("new_sequence"), r.get("old_sequence"), r.get("last_old_observation_ts")))
        elif r["kind"] == "inventory":
            e = r["evidence"]
            rows.append((r["ts"], e.get("new_sequence"), e.get("old_sequence"), (e.get("before") or {}).get("ts")))
    # by time, then key: two records can share a stamp, and their other fields may be None
    rows = sorted((row for row in rows if _time(row[0]) and _int(row[1])), key=lambda row: row[:2])
    out: list[Switch] = []
    key = None
    for ts, new, _old, _last in rows:
        if key is None:
            out.append(Switch(ts, None, new))
        elif new > key:
            # on the old key: when a record arrived at it, and the last frame on it that a record leaving it names
            heard = [t for t, n, _o, _l in rows if n == key and t <= ts]
            heard += [last for _t, _n, o, last in rows if o == key and _time(last) and last <= ts]
            last = max(heard, default=None)
            out.append(Switch(ts, key, new, None if switch_seen(last, ts) else last))
        else:
            continue
        key = new
    return out


def boot_log(records) -> list[Boot]:
    """One device's boot stamps, each with the range its source gives: a
    first read's `earliest`, a range's `until`. The OTBR's uptime reset is
    stamped with the sample that noticed it, so the boot lies between the
    sample before and that one; with that range the log's exact stamp is
    the better dated when keyguard.one_per_boot merges the two."""
    out = []
    for r in records:
        if r["kind"] != "reboot" or not _time(r.get("ts")):
            continue
        e = r["evidence"]
        earliest, until = e.get("earliest"), e.get("until")
        if r["addr"].startswith("otbr:") and e.get("source") == "uptime_reset":
            earliest = (e.get("before") or {}).get("ts")
        out.append(Boot(r["ts"], earliest if _time(earliest) else None, until if _time(until) else None))
    return sorted(out, key=lambda b: b.ts)


def newest(rows, inventory) -> dict[str, dict]:
    """Each inventory name's row from the recorder's device rows
    (review.device_rows): the address heard last."""
    out = {}
    for r in sorted(rows, key=lambda r: r["last_seen"] or 0):
        if r["name"] in inventory:
            out[r["name"]] = r
    return out


def links(rows: dict[str, dict]) -> dict[str, tuple[str | None, bool]]:
    """devices()' ``links`` from newest(): a child's parent, and whether it
    is sleepy (a child that polls). A name with no role on record is left
    out, so devices() takes it for a router."""
    return {n: (r["parent"] if r["role"] == "child" else None, r["role"] == "child" and bool(r["polls"]))
            for n, r in rows.items() if r["role"]}


def devices(records, entries, key_stacks: dict, ha_map: dict, links: dict[str, tuple[str | None, bool]],
            otbr: str | None = None, until: float | None = None) -> list[Device]:
    """Every inventory device as the forecast takes it. ``links`` gives
    each name its parent (None for a router) and whether it is sleepy (a
    child that polls its parent); a name it leaves out is taken for a
    router. ``until`` leaves out records after that time, to forecast from
    a past state."""
    per = by_device([r for r in records if until is None or _time(r.get("ts")) and r["ts"] <= until], entries, otbr)
    out = []
    for name in sorted({e["name"] for e in entries if isinstance(e.get("name"), str)}):
        parent, sleepy = links.get(name, (None, False))
        mine = per.get(name, [])
        out.append(Device(name, device_stack(key_stacks, name, ha_map), tuple(boot_log(mine)),
                          tuple(switch_log(mine)), parent, sleepy))
    return out
