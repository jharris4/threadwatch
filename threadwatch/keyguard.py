"""One device's key switch guard and rotation timer, worked out from its
stack, its boots and its key switches. A pure model: no file, network or
clock access. The mesh forecast (keyforecast.py) is built on it.

Two key logics are in the field (stacks.py says which a device runs).

Current OpenThread, verified from source:
- a boot clears the guard and restarts the rotation timer;
- every key switch restarts the 672 h rotation timer;
- only an exact +1 arms the 624 h guard, one taken at boot included; a
  jump of two or more leaves the guard as it was;
- forced updates (a Child ID Request, a Link Accept, a parent's response)
  ignore the guard, so a +1 taken past an armed guard is a miss no
  forecast sees coming, and the state after it is still known.

The old logic, verified from source and against recorded switches, is one
flag and one timer:
- a boot clears the flag and starts the timer;
- a +1 with the flag clear is taken, sets the flag and leaves the timer;
- a +1 with the flag set is refused until the timer reaches 624 h, and
  when taken restarts the timer;
- a jump of two or more is always taken and changes neither;
- there is no forced path, so a +1 taken with the guard closed means a
  boot nobody saw, or a wrong rule;
- its own rotation is an ordinary +1 when the timer reaches 672 h. With
  the flag clear that does not restart the timer, and it fires again an
  hour later (read from source, not yet seen on air).

Times are first observations, and a boot stamp can run late, so a switch
up to BOOT_MARGIN_S before a boot stamp counts as taken at that boot.
That margin and STAMP_SLACK_S are for recorded stamps only: after() takes
one more event exactly as given, for the forecast's simulated ones.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from .journal import BOOT_MARGIN_S

HOUR = 3600
GUARD_S = 624 * HOUR
ROTATION_S = 672 * HOUR
STAMP_SLACK_S = 120    # how far a recorded switch may run ahead of a time worked out from a boot stamp

RULES = {"current": "current logic: rules verified from source",
         "old": "old logic: rules verified from source and against recorded switches"}
KNOWN = {"reported": "stack reported by the device", "behaviour": "stack known by behaviour",
         "assumed": "stack assumed, not checked"}
NO_BOOT = "no boot seen: the guard and timer rest on the switches alone, and a boot since would have cleared them"
SECOND = "the second firing is read from source and has not been seen on air"
UNHEARD = "the switch record starts after the boot: a +1 taken in between is not on record"
FORCED = "taken past an armed guard: a forced update, which no forecast sees coming"
UNSEEN = "taken with the guard closed: the old logic has no forced path, so a boot was missed or a rule is wrong"


@dataclass(frozen=True)
class Boot:
    """A boot stamp, and the range the boot may really lie in where the
    source gives one."""
    ts: float
    earliest: float | None = None     # a first read's uptime-dated stamp may be this early
    latest: float | None = None       # the end of a range (a lock's rejoin waves)

    @property
    def lo(self) -> float:
        return self.ts if self.earliest is None else min(self.ts, self.earliest)

    @property
    def hi(self) -> float:
        return self.ts if self.latest is None else max(self.ts, self.latest)


@dataclass(frozen=True)
class Switch:
    """The first frame on a new key. ``old`` is None for the first key on
    record. ``unheard_from`` is None when the device was heard on the old
    key right up to ``ts`` (a "since"); otherwise the last time it was
    heard on it (a "by": the switch came somewhere in between)."""
    ts: float
    old: int | None
    new: int
    unheard_from: float | None = None

    @property
    def jump(self) -> int:
        return 0 if self.old is None else self.new - self.old


@dataclass(frozen=True)
class Guard:
    stack: str
    key: int | None                    # the key it is on
    boot: Boot | None                  # its last boot; None when none was seen
    flag: bool | None                  # old: the guard flag; current: the guard is armed; None: not known
    flag_set_by: Switch | None         # the +1 that set it
    timer_start: float | None          # the rotation timer's start (on the old logic the guard's too)
    timer_set_by: Boot | Switch | None
    guard: str                         # "open", "until" (guard_open_at) or "unknown"
    guard_open_at: float | None
    rotation_at: float | None          # its own rotation, if nothing changes before then
    second_rotation_at: float | None   # old logic with the flag clear: it fires again an hour later
    confidence: str                    # "normal", "low" or "none"
    reasons: tuple[str, ...]
    misses: tuple[tuple[Switch, str], ...]   # recorded +1 switches the rules had the guard refuse
    fired: bool = False                # old logic: its 672 h firing was taken with the flag clear, so 673 h is next


def one_per_boot(boots) -> list[Boot]:
    """One stamp per boot, oldest first. The same boot can be on record
    twice (a logged or seeded stamp, and a first read's uptime-dated one
    with a wide range): of stamps whose ranges come within BOOT_MARGIN_S
    of each other the better dated stays, which is the narrower range, and
    of two as good the earlier, since a boot stamp runs late if anything."""
    kept: list[Boot] = []
    for b in sorted(boots, key=lambda b: (b.hi - b.lo, b.ts)):
        if not any(b.lo - BOOT_MARGIN_S <= k.hi and k.lo <= b.hi + BOOT_MARGIN_S for k in kept):
            kept.append(b)
    return sorted(kept, key=lambda b: b.ts)


def _opens(kind: str, flag, flag_by: Switch | None, timer: float | None) -> float | None:
    """When an armed guard opens; None when it is not armed or not known."""
    if not flag:
        return None
    if kind == "current":
        return flag_by.ts + GUARD_S
    return None if timer is None else timer + GUARD_S


def derive(stack: tuple[str, str | None, str], boots, switches) -> Guard:
    """The guard state of one device. ``stack`` is stacks.device_stack's
    answer: (current, old or unknown; how that is known; why). ``boots``
    and ``switches`` are the device's own, across all its addresses."""
    kind, known, why = stack
    switches = sorted(switches, key=lambda s: s.ts)
    if kind not in RULES:
        return Guard(kind, switches[-1].new if switches else None, None, None, None, None, None, "unknown",
                     None, None, None, "none", (f"stack unknown ({why}): nothing is forecast for the device",), ())
    events = sorted([(b.lo - BOOT_MARGIN_S, 0, b) for b in one_per_boot(boots)]
                    + [(s.ts, 1, s) for s in switches], key=lambda e: e[:2])
    key = boot = flag = flag_by = timer = timer_by = None
    fired = False            # old logic: the 672 h firing was taken with the flag clear, so 673 h is next
    doubts: list[str] = []   # about the state since the last boot; a boot seen settles them
    misses = []
    for _, _, e in events:
        if isinstance(e, Boot):
            boot, flag, flag_by, timer, timer_by, fired, doubts = e, False, None, e.ts, e, False, []
            continue
        key = e.new
        if e.old is None and flag is False and e.ts > boot.hi + BOOT_MARGIN_S:
            flag = None      # first heard well after its boot: a +1 in between would not be on record
            doubts.append(UNHEARD)
        if e.jump < 1 or (e.jump > 1 and kind == "old"):
            continue
        at = max(e.ts, boot.ts) if boot else e.ts
        if e.unheard_from is not None and (kind == "current" or flag):
            doubts.append(f"the switch to {e.new} was first seen after a gap: the time it sets is the latest it can be")
        if e.jump == 1:
            opens = _opens(kind, flag, flag_by, timer)
            if opens is not None and e.ts < opens - STAMP_SLACK_S:
                misses.append((e, FORCED if kind == "current" else UNSEEN))
                if kind == "old":
                    doubts.append(f"the switch to {e.new} was {UNSEEN}")
            if flag is False and (boot.lo < boot.hi and e.ts <= boot.hi
                                  or e.unheard_from is not None and e.unheard_from < boot.hi):
                doubts.append(f"boot and switch order ambiguous: the switch to {e.new} may have come before the boot")
        flag, flag_by, timer, timer_by, fired = _take(kind, e, at, (flag, flag_by, timer, timer_by, fired))
    reasons = [RULES[kind], f"{KNOWN[known]}: {why}"] + ([NO_BOOT] if boot is None else []) + doubts
    low = known == "assumed" or boot is None or bool(doubts)
    return _guard(kind, key, boot, (flag, flag_by, timer, timer_by, fired), "low" if low else "normal",
                  reasons, tuple(misses))


def _take(kind: str, e: Switch, at: float, state: tuple, own: bool | None = None) -> tuple:
    """The rules for one switch up that the logic acts on (any on the
    current logic, a +1 on the old), applied to (flag, flag_by, timer,
    timer_by, fired). ``own`` says whether it is the device's own rotation
    firing; None for a recorded switch, where a flag-clear +1 from
    STAMP_SLACK_S before the 672 h mark on is read as one."""
    flag, flag_by, timer, timer_by, fired = state
    if kind == "current":
        return (True, e, at, e, False) if e.jump == 1 else (flag, flag_by, at, e, False)
    if flag:
        return flag, flag_by, at, e, False
    if own is None:
        own = timer is not None and e.ts >= timer + ROTATION_S - STAMP_SLACK_S
    return True, e, timer, timer_by, own


def _guard(kind: str, key, boot, state: tuple, confidence: str, reasons, misses: tuple) -> Guard:
    flag, flag_by, timer, timer_by, fired = state
    opens = _opens(kind, flag, flag_by, timer)
    rotation = None if timer is None else timer + ROTATION_S + (HOUR if fired else 0)
    second = rotation + HOUR if kind == "old" and flag is False else None
    return Guard(kind, key, boot, flag, flag_by, timer, timer_by,
                 "until" if opens is not None else "open" if flag is False else "unknown", opens,
                 rotation, second, confidence,
                 tuple(r for r in reasons if r != SECOND) + ((SECOND,) if second is not None else ()), misses, fired)


def after(g: Guard, event: Boot | Switch, own: bool = False) -> Guard:
    """``g`` one event later, the event taken exactly as given. A simulated
    boot or switch has no late stamp, so neither BOOT_MARGIN_S nor
    STAMP_SLACK_S applies: a switch a minute before a boot came before it,
    and ``own`` says outright whether a switch is the device's own rotation
    firing. An unknown stack only changes key. Confidence, reasons and
    misses stay those of the recorded history ``g`` was derived from."""
    if isinstance(event, Boot):
        if g.stack not in RULES:
            return g
        return _guard(g.stack, g.key, event, (False, None, event.ts, event, False), g.confidence, g.reasons, g.misses)
    if g.stack not in RULES:
        return replace(g, key=event.new)
    state = (g.flag, g.flag_set_by, g.timer_start, g.timer_set_by, g.fired)
    if event.jump >= 1 and (event.jump == 1 or g.stack == "current"):
        state = _take(g.stack, event, event.ts, state, own)
    return _guard(g.stack, event.new, g.boot, state, g.confidence, g.reasons, g.misses)
