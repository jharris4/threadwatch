"""Device reboots, read from the Matter Server's log in the hourly archive.

A Matter device reports why it last started (General Diagnostics
BootReason) each time a controller subscribes after a restart, and the
Matter Server logs it:

    ... Received event generalDiagnostics.bootReason on server-1-7c21.@1:1f bootReason: 1

where 2e is the node id in hex. The radio cannot see this: a sleepy child
that browns out comes back under the same parent without a rejoin the
sniffer catches, and Home Assistant keeps it available through a reboot
that takes under a minute. From 2026-09-22 to 09-26 a door button went
from one power-on reboot a day to 25, its battery level reading about 40%
the whole time, and on 09-27 it stopped coming back; nothing here said
anything until then.

Every reboot is a device_rebooted notice, dated when the Matter Server
logged it. A device rebooting far more than it usually does is one
reboots_climbing warning: at least CLIMB_MIN reboots in the last 24 h and
at least CLIMB_RATIO times its own daily average over the days before.
The comparison is with the device's own history, so a sensor that reboots
two or three times every sunny afternoon sets its own baseline and never
pages, while a device that never rebooted pages at its fifth in a day.
A climb pages once and stays open while CLIMB_MIN reboots remain in the
window, however far its own baseline catches up.
Only unplanned reboots count (power-on, brown-out, watchdog, unspecified):
a firmware update's reboot or a commanded reset is logged at info, and so
is a reboot that CROWD_NODES or more devices share within CROWD_S of each
other (a power cut, or a Matter Server restart replaying startup events).
A device pages only once BASELINE_MIN_H hours of the archive cover it
before the last 24 h: the archive keeps [record] keep_hours, a week, so
the baseline is the up-to-six days before today.

Node ids are named through the [ha_availability] map (ha-map.json), and
the inventory names and mutes by the address the map gives; a node the
map does not have is "Matter node 0x1f" and cannot be muted.
"""

from __future__ import annotations

import gzip
import json
import os
import re
from pathlib import Path

SLUG = "core_matter_server"
STATE_FILE = "reboots.json"

WINDOW_S = 86400.0          # "the last 24 h" the climb is judged over
LOOKBACK_S = 7 * 86400.0    # the archive's reach: the baseline is what precedes the window in it
BASELINE_MIN_H = 72         # archived hours a device needs before the window to be judged at all
CLIMB_MIN = 5               # reboots in the window that can page
CLIMB_RATIO = 3.0           # ... when they are this many times the device's daily average
DUPLICATE_S = 60.0          # the same startup logged twice (resubscribe replays it) is one reboot
CROWD_NODES = 3             # this many devices rebooting ...
CROWD_S = 300.0             # ... within this long of each other is not any one device's trouble

# Matter General Diagnostics BootReasonEnum.
REASONS = {0: "unspecified", 1: "power-on reboot", 2: "brown-out reset", 3: "software watchdog reset",
           4: "hardware watchdog reset", 5: "software update completed", 6: "software reset"}
UNPLANNED = frozenset({0, 1, 2, 3, 4})

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_BOOT = re.compile(r"generalDiagnostics\.bootReason on \S*?@\d+:([0-9a-f]+) bootReason: (\d+)")
_NODE = re.compile(r"@\d+:([0-9a-f]+)\b")


def parse_line(line: str) -> tuple[int, int] | None:
    """(node id, boot reason) for a Matter Server bootReason line, else None."""
    m = _BOOT.search(_ANSI.sub("", line))
    return (int(m.group(1), 16), int(m.group(2))) if m else None


def scan(archive_root: Path) -> dict:
    """Every bootReason line in the archived Matter Server hours: boots as
    [ts, node, reason] (journal stamps, UTC epoch), the first time each
    node is mentioned at all, and the hours on disk. The files are a few
    kilobytes an hour, so the worker reads the whole week each pass."""
    from .halogs import journal_stamp
    boots: list[list] = []
    first: dict[int, float] = {}
    hours = []
    d = archive_root / SLUG
    for path in sorted(d.glob("????????-??.log.gz")) if d.is_dir() else []:
        try:
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except (OSError, EOFError):
            continue
        hours.append(path.name[:11])
        for line in lines:
            ts = journal_stamp(line)
            if ts is None:
                continue
            if "@" in line:
                for node in _NODE.findall(_ANSI.sub("", line)):
                    first.setdefault(int(node, 16), ts)
            boot = parse_line(line)
            if boot is not None:
                boots.append([ts, boot[0], boot[1]])
    return {"boots": boots, "first_seen": {str(k): v for k, v in first.items()}, "hours": hours}


def distinct(boots) -> list[dict]:
    """The boots once each (a second record of a node's startup within
    DUPLICATE_S of the first is the same startup), oldest first, with
    `crowd` set on those CROWD_NODES or more nodes share within CROWD_S."""
    out: list[dict] = []
    last: dict[int, float] = {}
    for ts, node, reason in sorted(boots):
        if node in last and ts - last[node] <= DUPLICATE_S:
            continue
        last[node] = ts
        out.append({"ts": ts, "node": node, "reason": reason, "crowd": False})
    for b in out:
        near = {o["node"] for o in out if abs(o["ts"] - b["ts"]) <= CROWD_S}
        b["crowd"] = len(near) >= CROWD_NODES
    return out


def counts(b: dict) -> bool:
    return b["reason"] in UNPLANNED and not b["crowd"]


def boot_id(b: dict) -> str:
    return f"{b['node']}:{b['ts']:.3f}"


def judge(boots: list[dict], node: int, first_seen: float | None, hours: list[str], now: float) -> dict:
    """The climb verdict for one node: reboots that count in the last
    WINDOW_S, the daily average over the archived hours before that (from
    the node's first mention, at most LOOKBACK_S back), and whether it
    climbs. `judged` is false while fewer than BASELINE_MIN_H hours are
    there to average over."""
    from .halogs import hour_start
    start = now - WINDOW_S
    floor = max(now - LOOKBACK_S, first_seen if first_seen is not None else now)
    # Whole archived hours from the one the node was first mentioned in
    # to the last that ends before the window opens.
    covered_h = sum(1 for h in hours if int(floor // 3600) * 3600 <= hour_start(h) <= start - 3600.0)
    mine = [b for b in boots if b["node"] == node and counts(b)]
    recent = sum(1 for b in mine if start < b["ts"] <= now)
    before = sum(1 for b in mine if floor <= b["ts"] <= start)
    per_day = before / (covered_h / 24.0) if covered_h else 0.0
    judged = covered_h >= BASELINE_MIN_H
    climbing = judged and recent >= CLIMB_MIN and recent >= CLIMB_RATIO * per_day
    return {"recent": recent, "baseline_per_day": round(per_day, 2), "baseline_h": covered_h,
            "judged": judged, "climbing": climbing}


def load_state(path: Path) -> dict | None:
    """reboots.json: the boots already logged (ids, within the lookback),
    and the nodes whose climb has paged. None when there is no usable
    file: the first pass then logs nothing for the week already archived."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("seen"), dict):
        return None
    climbing = data.get("climbing") if isinstance(data.get("climbing"), dict) else {}
    return {"seen": {k: v for k, v in data["seen"].items() if isinstance(v, (int, float))},
            "climbing": {k: v for k, v in climbing.items() if isinstance(v, dict)}}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=1))
    os.replace(tmp, path)


class RebootWatch:
    """Applies each archive pass's scan on the capture thread: the new
    boots as device_rebooted, then each node's climb. ``emit`` is the
    pipeline's _emit (which mutes reboots_climbing for a muted device);
    ``device(node)`` gives (address or None, name)."""

    def __init__(self, state_path: Path, *, emit, device):
        self.path = state_path
        self.emit = emit
        self.device = device
        self.state = load_state(state_path)

    def apply(self, result: dict, now: float) -> None:
        boots = distinct(result.get("boots") or [])
        first_seen = {int(k): v for k, v in (result.get("first_seen") or {}).items()}
        hours = result.get("hours") or []
        fresh = self.state is None
        state = self.state or {"seen": {}, "climbing": {}}
        for b in boots:
            bid = boot_id(b)
            if bid in state["seen"]:
                continue
            state["seen"][bid] = b["ts"]
            if not fresh:
                self._rebooted(b)
        state["seen"] = {k: v for k, v in state["seen"].items() if v >= now - LOOKBACK_S - WINDOW_S}
        for node in sorted({b["node"] for b in boots} | {int(n) for n in state["climbing"]}):
            verdict = judge(boots, node, first_seen.get(node), hours, now)
            key = str(node)
            if key in state["climbing"]:
                # One page per climb: it lasts while the window holds
                # CLIMB_MIN, however far the baseline catches up.
                if verdict["recent"] < CLIMB_MIN:
                    del state["climbing"][key]
            elif verdict["climbing"]:
                state["climbing"][key] = {"since": now, "recent": verdict["recent"]}
                self._climbing(node, boots, verdict, now)
        self.state = state
        save_state(self.path, state)

    def _who(self, node: int) -> tuple[str | None, str]:
        addr, name = self.device(node)
        return addr, name or f"Matter node 0x{node:x}"

    def _rebooted(self, b: dict) -> None:
        addr, name = self._who(b["node"])
        reason = REASONS.get(b["reason"], f"reason {b['reason']}")
        if b["crowd"]:
            note = (f"{name} restarted ({reason}) along with at least {CROWD_NODES - 1} other devices within "
                    f"{CROWD_S / 60:.0f} min: a power cut or a Matter Server restart, not this device's trouble")
        elif b["reason"] not in UNPLANNED:
            note = f"{name} restarted ({reason}): planned, a firmware update or a commanded reset"
        elif b["reason"] in (1, 2):
            note = (f"{name} restarted ({reason}): it lost power. On a battery device that is a battery "
                    "sagging under the radio's load, and the battery level Home Assistant shows can read "
                    "normal until the end")
        elif b["reason"] in (3, 4):
            note = f"{name} restarted ({reason}): its firmware stopped responding and was reset"
        else:
            note = f"{name} restarted ({reason})"
        self.emit("device_rebooted", "notice" if counts(b) else "info", b["ts"], addr=addr, name=name,
                  node_id=b["node"], reason=b["reason"], reason_name=reason, crowd=b["crowd"], note=note)

    def _climbing(self, node: int, boots: list[dict], verdict: dict, now: float) -> None:
        addr, name = self._who(node)
        recent = [b for b in boots if b["node"] == node and counts(b) and now - WINDOW_S < b["ts"] <= now]
        reasons: dict[str, int] = {}
        for b in recent:
            label = REASONS.get(b["reason"], f"reason {b['reason']}")
            reasons[label] = reasons.get(label, 0) + 1
        per_day = verdict["baseline_per_day"]
        usual = (f"{per_day:g} a day over the {verdict['baseline_h'] / 24:.0f} days before" if per_day
                 else f"none in the {verdict['baseline_h'] / 24:.0f} days before")
        power = sum(1 for b in recent if b["reason"] in (1, 2))
        watchdog = sum(1 for b in recent if b["reason"] in (3, 4))
        why = ("; most of them lost power, which on a battery device is a dying battery (its battery level "
               "can still read normal): replace it" if power * 2 > len(recent)
               else "; most were watchdog resets, which point at the firmware" if watchdog * 2 > len(recent)
               else "")
        self.emit("reboots_climbing", "warning", now, addr=addr, name=name, node_id=node,
                  reboots_24h=verdict["recent"], baseline_per_day=per_day, baseline_h=verdict["baseline_h"],
                  reasons=reasons, since=recent[0]["ts"] if recent else None,
                  note=f"{name} rebooted {verdict['recent']} times in the last 24 h against {usual}{why}")
