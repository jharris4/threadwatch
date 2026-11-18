"""The mesh's key forecast: every key switch the guard model predicts, in
time order, and every sleepy child it leaves two behind its parent. Pure:
no file, network or clock access. keyguard.derive gives each device's
state at the start from its recorded boots and switches, and
keyguard.after moves it on one simulated event at a time, so each switch
changes the follower's own guard and timer before the next is worked out.

Who hears a new number: a sleepy child only its parent; a router or a
mains child every router and mains child, and its own children.

What a device does with a higher number it hears:
- one ahead: it follows if its guard is open, else when the guard opens
  (a guard whose state is not known is taken for open);
- two or more ahead: a router or mains child takes the jump at once (on
  the old logic that leaves its timer running, so it can start the next
  number itself); a sleepy child cannot follow and is two behind, whatever
  its parent's stack;
- an unknown stack and a current-logic router follow every number at
  once, whatever their guard: the worst case for their children (forced
  updates took every such router past an armed guard in the record).

Each device also fires its own rotation when its timer runs out, stranded
or not. A rotation already overdue at the start is not fired: the record
missed a boot or a rule is wrong, and the device is listed as overdue.

A boot (a known one after the start, or a hypothetical "what if this unit
is power-cycled at T") clears the guard and restarts the timer, and a
child attaches at its parent's key, whatever the jump. A child ahead of
its parent needs no rule of its own at a boot: a parent that would be
forced up by its Child ID Request (any but an old-logic one) is a router
that follows at once anyway, and an old-logic parent has no forced path.

How far it steps. A sleepy child falls two behind only when a number
comes within one guard time of the number before it, so after each new
number the forecast steps on for GUARD_S. A stretch that long with no
number does not end it the first time: the number after it is stepped
too, with its own GUARD_S, because a boot that books a number shows its
damage only there. It ends at the second such stretch in a row (in a calm
mesh: the next two numbers), or at MAX_NUMBERS in a chain that never calms.
"""

from __future__ import annotations

from dataclasses import dataclass

from .keyguard import GUARD_S, RULES, Boot, Guard, Switch, after, derive

OWN = "own rotation"
OWN_SECOND = "own rotation, second firing"
FOLLOWED = "followed"                 # heard it with the guard open
OPENED = "guard opened"               # had refused it; took it when the guard opened
JUMPED = "jumped"                     # two or more behind: always taken
AT_ONCE = "follows at once"           # unknown stack or current-logic router: the worst case, not a rule
AT_BOOT = "at boot"                   # attached at its parent's key
FIRINGS = (OWN, OWN_SECOND)
MAX_NUMBERS = 8                       # a chain of numbers each within GUARD_S of the last is cut here
MAX_EVENTS = 20000


@dataclass(frozen=True)
class Device:
    name: str
    stack: tuple[str, str | None, str]   # stacks.device_stack's answer
    boots: tuple[Boot, ...] = ()
    switches: tuple[Switch, ...] = ()
    parent: str | None = None            # the router it is a child of; None for a router
    sleepy: bool = False                 # a child that polls: it hears its parent only


@dataclass(frozen=True)
class Step:
    """One predicted switch. ``number`` marks the first device on a new
    number: the one that starts it."""
    ts: float
    name: str
    old: int
    new: int
    why: str
    number: bool


@dataclass(frozen=True)
class Stranded:
    """A sleepy child two or more behind its parent, from ``ts``."""
    ts: float
    name: str
    key: int
    parent: str
    parent_key: int


@dataclass(frozen=True)
class Forecast:
    start: float
    end: float                             # how far it stepped: nothing is forecast past here
    steps: tuple[Step, ...]                # every predicted switch, in time order
    stranded: tuple[Stranded, ...]         # each time a sleepy child falls two behind
    guards: dict[str, Guard]               # each device's state at the start
    final: dict[str, Guard]                # and at the end
    unknown: tuple[str, ...]               # nothing forecast: unknown stack, or no key on record
    overdue: tuple[tuple[str, float], ...]  # own rotations due before the start and not on record
    cut: bool                              # stopped at MAX_NUMBERS or MAX_EVENTS, not by the rule

    @property
    def numbers(self) -> tuple[Step, ...]:
        return tuple(s for s in self.steps if s.number)

    @property
    def firings(self) -> tuple[Step, ...]:
        """Every own-rotation firing, not only the ones that start a number:
        a unit that fires alone is where a forced-path stranding starts."""
        return tuple(s for s in self.steps if s.why in FIRINGS)

    def keys(self, ts: float) -> dict[str, int]:
        """Each device's key at ``ts`` (steps at ``ts`` included)."""
        keys = {n: g.key for n, g in self.guards.items() if g.key is not None}
        for s in self.steps:
            if s.ts <= ts:
                keys[s.name] = s.new
        return keys


def forecast(devices, now: float, boots=(), max_numbers: int = MAX_NUMBERS) -> Forecast:
    """Step the mesh from ``now``. ``boots`` are (name, time) pairs at or
    after ``now``: boots known to come after the start, or hypothetical."""
    dev = {d.name: d for d in devices}
    g = {n: derive(d.stack, d.boots, d.switches) for n, d in dev.items()}
    start = dict(g)
    live = sorted(n for n in g if g[n].key is not None)
    pending = sorted((ts, n) for n, ts in boots if n in live and ts >= now)
    overdue = tuple((n, g[n].rotation_at) for n in live if g[n].rotation_at is not None and g[n].rotation_at < now)
    steps: list[Step] = []
    stranded: list[Stranded] = []
    behind: set[str] = set()
    top = max((g[n].key for n in live), default=0)

    def parent(n):
        return dev[n].parent if dev[n].parent in live else None

    def heard(n):
        if dev[n].sleepy:
            return g[parent(n)].key if parent(n) else None
        return max((g[m].key for m in live if m != n and (not dev[m].sleepy or dev[m].parent == n)), default=None)

    def at_once(n):
        return g[n].stack not in RULES or (g[n].stack == "current" and dev[n].parent is None)

    def take(n, new, t, why):
        nonlocal top
        steps.append(Step(t, n, g[n].key, new, why, new > top))
        g[n] = after(g[n], Switch(t, g[n].key, new), own=why in FIRINGS)
        top = max(top, new)

    def settle(t):
        """Everything the mesh does at once at ``t``, until nothing moves."""
        moved = True
        while moved:
            moved = False
            for n in live:
                key, new = g[n].key, heard(n)
                if new is None or new <= key:
                    continue
                if at_once(n):
                    why = AT_ONCE
                elif new - key >= 2:
                    if dev[n].sleepy:
                        if n not in behind:
                            behind.add(n)
                            stranded.append(Stranded(t, n, key, parent(n), new))
                        continue
                    why = JUMPED
                elif g[n].guard != "until" or g[n].guard_open_at <= t:
                    why = OPENED if g[n].guard_open_at == t else FOLLOWED
                else:
                    continue
                take(n, new, t, why)
                moved = True
        behind.intersection_update(n for n in behind if heard(n) - g[n].key >= 2)

    def boot(n, t):
        g[n] = after(g[n], Boot(t))
        p = parent(n)
        if p and g[p].key > g[n].key:
            take(n, g[p].key, t, AT_BOOT)

    t, end, last, calm, counted, cut = now, now, None, False, 0, False
    settle(now)                 # what the model says is already due
    for _ in range(MAX_EVENTS):
        due = [(ts, 0, n) for ts, n in pending[:1]]
        for n in live:
            if g[n].rotation_at is not None and g[n].rotation_at >= t:      # t >= now: an overdue one never fires
                due.append((g[n].rotation_at, 1, n))
            if g[n].guard == "until" and g[n].guard_open_at > t and heard(n) == g[n].key + 1 and not at_once(n):
                due.append((g[n].guard_open_at, 2, n))
        if not due:
            break
        if calm and min(due)[0] > last + GUARD_S:
            end = last + GUARD_S     # two numbers running, each with a clear guard time after it
            break
        t, kind, n = min(due)
        end, before = t, len(steps)
        if kind == 0:
            pending.pop(0)
            boot(n, t)
        elif kind == 1:
            take(n, g[n].key + 1, t, OWN_SECOND if g[n].fired else OWN)
        settle(t)
        if any(s.number for s in steps[before:]):
            calm, last, counted = last is not None and t > last + GUARD_S, t, counted + 1
            if counted >= max_numbers:
                cut = True
                break
    else:
        cut = True
    return Forecast(now, end, tuple(steps), tuple(sorted(stranded, key=lambda x: (x.ts, x.name))), start, dict(g),
                    tuple(sorted(n for n in g if g[n].key is None or g[n].stack not in RULES)), overdue, cut)
