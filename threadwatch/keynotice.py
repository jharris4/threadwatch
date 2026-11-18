"""What the recorder does with the key forecast (keyforecast.py), once an
hour: the stranding notice, with the remedies the forecast has tested, and
the checks that grade each recorded key switch against the last forecast
made before it. Pure: the caller hands over the forecast's devices
(keylog.devices), the time and the state kept from the run before.

The notice. When the forecast leaves a sleepy child two behind its parent,
key_stranding_forecast names the number, when, the children, and what the
forecast shows would prevent it, tested as hypothetical boots:
- a battery pull of each child (it comes back at its parent's key), only
  where the parent is ahead of it at the time, with the stretch of time in
  which it keeps the child from being two behind anywhere in the forecast;
  otherwise why it cannot help;
- a power cycle of the old-logic units that have a number booked (no +1
  since their last boot), all together, with the stretch in which nothing
  is left two behind, and only the units that stretch needs; never a unit
  that would be ahead of its parent at the time.
It goes out when first seen, when its answer changes, and when the power
cycle's stretch opens; key_stranding_cleared when no child is forecast two
behind any more, unless that is because a child it named is two behind now
(the notice is then dropped without a word: key_lag has the child). While an own rotation that fell due in the last
LAG_S + GRACE_S is not on record, none of that happens: the forecast has
dropped the number as overdue, and it is most likely only not heard yet.

The checks. Each switch is graded LAG_S after it, so the hourly boot read
can land first: as forecast within TOL_S, late or early by more, not
forecast at all, or at a boot on record. key_forecast_check (info) is one
event per new number and one for the rest of each pass;
key_switch_unforecast (notice) names the switches taken early or with no
forecast on a device whose stack is known: a boot was missed, a forced
update, or a rule is wrong.
"""

from __future__ import annotations

import time
from collections import Counter

from . import keyforecast as kf
from .journal import BOOT_MARGIN_S
from .keyguard import HOUR, RULES, one_per_boot
from .review import fmt_duration

STEP_S = 6 * HOUR    # the remedy search tries a boot this often from now to the stranding
EDGE_S = 60          # and finds each stretch's edges to this
TOL_S = 15 * 60      # a switch this close to its forecast time is as forecast
LAG_S = 75 * 60      # a switch is graded this long after it
GRACE_S = HOUR       # a forecast switch not seen this long after its time is reported missing
SAME_S = HOUR        # a notice whose times move less than this has not changed
WHERE = "See /keys, and {} in docs/ALERTING.md."


def _d(ts, fmt="%m-%d %H:%M"):
    return time.strftime(fmt, time.localtime(ts))


def _s(ts):
    return _d(ts, "%m-%d %H:%M:%S")


def _by(delta):
    return ("-" if delta < 0 else "+") + fmt_duration(abs(delta))


def _search(devs, now, fc, until, subjects, cycle):
    """For each subject (names booted together), the first stretch of
    [now, until) in which booting it leaves nothing it is watched for two
    behind: a cycle anything in the forecast, a pull its own child (a
    child already two behind at ``now`` is key_lag's, not counted). One
    forecast tests every subject at once (a pulled child moves nobody
    else), every STEP_S and either side of each switch in the forecast
    (where a stretch starts or ends), then halving to EDGE_S at each edge."""
    parent = {d.name: d.parent for d in devs}

    def fit(s, t):          # a cycle never boots a unit ahead of its parent; a pull needs the parent ahead
        k = fc.keys(t)
        return all((k[n] <= k[parent[n]]) if cycle else (k[parent[n]] > k[n])
                   for n in s if n in k and parent[n] in k)

    def works(at):
        at = {s: t for s, t in at.items() if fit(s, t)}
        if not at:
            return set()
        stranded = {x.name for x in kf.forecast(devs, now, [(n, t) for s, t in at.items() for n in s]).stranded
                    if x.ts > now}
        return {s for s in at if not (stranded if cycle else stranded & set(s))}

    grid = sorted({now + i * STEP_S for i in range(int((until - now) // STEP_S) + 1)}
                  | {t for x in fc.steps for t in (x.ts - 1, x.ts) if now < t})
    grid = [t for t in grid if t < until]
    good = {s: [] for s in subjects}
    for i, t in enumerate(grid):
        for s in works({s: t for s in subjects}):
            good[s].append(i)
    pairs = {}
    for s, idx in good.items():
        if idx:
            last = idx[0]
            while last + 1 in idx:      # the first unbroken stretch
                last += 1
            pairs[s] = [(grid[idx[0]], grid[idx[0] - 1] if idx[0] else None),
                        (grid[last], grid[last + 1] if last + 1 < len(grid) else until)]
    for side in (0, 1):     # halve every subject's edge at once
        while mids := {s: (p[side][0] + p[side][1]) / 2 for s, p in pairs.items()
                       if p[side][1] is not None and abs(p[side][0] - p[side][1]) > EDGE_S}:
            ok = works(mids)
            for s, m in mids.items():
                g, b = pairs[s][side]
                pairs[s][side] = (m, b) if s in ok else (g, m)
    return {s: (p[0][0], p[1][0]) for s, p in pairs.items()}, grid, fit


def notice(devs, now, fc=None) -> dict | None:
    """The stranding notice's fields for the first number in the forecast
    that leaves a sleepy child two behind (every child it strands, when
    its parent takes it then or later), with its remedies; None when
    nothing is. A child two behind already is key_lag's, not this."""
    fc = fc or kf.forecast(devs, now)
    future = [x for x in fc.stranded if x.ts > fc.start]
    if not future:
        return None
    first = future[0]
    group = [x for x in future if x.parent_key == first.parent_key]
    kids = sorted({x.name for x in group})
    starter = next((s.name for s in fc.numbers if s.new == first.parent_key), None)
    found, grid, fit = _search(devs, now, fc, max(x.ts for x in group), [(c,) for c in kids], cycle=False)
    pulls = {c: {"from": found[(c,)][0], "until": found[(c,)][1]} for c in kids if (c,) in found}
    left = {c: max((t for t in grid if fit((c,), t)), default=None) for c in kids if c not in pulls}
    again = {x.name: x for x in reversed(kf.forecast(
        devs, now, [(c, t) for c, t in left.items() if t is not None]).stranded) if x.ts > now} \
        if any(left.values()) else {}
    for c, t in left.items():
        x = again.get(c)
        pulls[c] = ({"parent_behind": True} if t is None or x is None
                    else {"again": x.parent_key, "at": x.ts})
    cycle = None
    units = tuple(sorted(n for n, g in fc.guards.items() if g.stack == "old" and g.flag is False
                         and g.key is not None))
    if units:
        found, _grid, fit = _search(devs, now, fc, first.ts, [units], cycle=True)
        if units in found:
            mid = sum(found[units]) / 2
            need = units
            for u in units:
                rest = tuple(x for x in need if x != u)
                if rest and fit(rest, mid) and not {x.name for x in kf.forecast(
                        devs, now, [(n, mid) for n in rest]).stranded if x.ts > now}:
                    need = rest
            if need != units:
                fewer = _search(devs, now, fc, first.ts, [need], cycle=True)[0]
                need, found = (need, fewer) if need in fewer else (units, found)    # the full set's, tested
            cycle = {"units": list(need), "from": found[need][0], "until": found[need][1]}
    return {"sequence": first.parent_key, "at": first.ts, "started_by": starter, "two_behind": kids,
            "later": len({x.name for x in future if x.parent_key != first.parent_key} - set(kids)), "pulls": pulls,
            "power_cycle": cycle}


def note(n: dict, now: float) -> str:
    kids, pulls = n["two_behind"], n["pulls"]
    text = (f"{n['sequence']}" + (f" from {n['started_by']}" if n["started_by"] else "")
            + f" on {_d(n['at'])} leaves {len(kids)} sleepy children two behind"
            + (f", and {n['later']} more later in the forecast" if n["later"] else "") + ". ")
    helped = [c for c in kids if "from" in pulls[c]]
    if helped:
        text += (f"A battery pull helps {len(helped)}: " + ", ".join(
            f"{c} ({_d(pulls[c]['from'])} to {_d(pulls[c]['until'])})" for c in helped) + ". ")
    behind = sum("parent_behind" in pulls[c] for c in kids)
    why = [f"{behind} {'has a parent' if behind == 1 else 'have parents'} never ahead of them before then, so a "
           f"pull lifts nothing"] if behind else []
    again = Counter((pulls[c]["again"], pulls[c]["at"]) for c in kids if "again" in pulls[c])
    why += [f"{k} {'is' if k == 1 else 'are'} two behind again at {seq} on {_d(at)} after any pull"
            for (seq, at), k in sorted(again.items())]
    if why:
        text += ("The others cannot be helped by a pull: " if helped else "Battery pulls cannot help: ") \
            + "; ".join(why) + ". "
    c = n["power_cycle"]
    if c:
        names = c["units"][0] if len(c["units"]) == 1 else ", ".join(c["units"][:-1]) + " and " + c["units"][-1]
        text += (f"Power-cycling {names} between {_d(c['from'])} and {_d(c['until'])} prevents it in the forecast"
                 + (" (open now)" if c["from"] <= now <= c["until"] else "") + ". ")
    else:
        text += "No power cycle the forecast tried prevents it. "
    return text + WHERE.format("key_stranding_forecast")


def same(a: dict, b: dict, now: float) -> bool:
    """Whether two notices say the same thing, times within SAME_S. A
    window that has opened is searched from the time of the search, so
    its start is not compared once both starts are past."""
    ca, cb = a["power_cycle"], b["power_cycle"]
    return (a["sequence"] == b["sequence"] and abs(a["at"] - b["at"]) <= SAME_S
            and a["two_behind"] == b["two_behind"]
            and sorted(c for c, p in a["pulls"].items() if "from" in p)
            == sorted(c for c, p in b["pulls"].items() if "from" in p)
            and (ca is None) == (cb is None)
            and (ca is None or ca["units"] == cb["units"]
                 and (abs(ca["from"] - cb["from"]) <= SAME_S or max(ca["from"], cb["from"]) <= now)
                 and abs(ca["until"] - cb["until"]) <= SAME_S))


def grade(state: dict, devs, now: float) -> list[dict]:
    """Each switch recorded since the last pass, up to LAG_S ago, against
    the ledger of forecast switches, and each forecast switch not seen
    GRACE_S after its time. Pops what it grades from state["ledger"]."""
    ledger, cursor, upto = state["ledger"], state["cursor"], now - LAG_S
    by = {d.name: d for d in devs}
    sw = sorted((s.ts, d.name, s) for d in devs for s in d.switches if s.old is not None and s.new > s.old)
    first = {}
    for ts, n, s in sw:
        first.setdefault(s.new, (ts, n))
    starts = {e[1]: (e[2], e[0]) for e in ledger.values() if e[5]}
    out = []
    for ts, n, s in sw:
        if not cursor < ts <= upto:
            continue
        e = ledger.pop(f"{n}\t{s.new}", None)
        boot = any(b.lo - BOOT_MARGIN_S <= ts <= b.hi + BOOT_MARGIN_S for b in one_per_boot(by[n].boots))
        delta = None if e is None else ts - e[2]
        kind = ("as forecast" if delta is not None and abs(delta) <= TOL_S else "at a boot" if boot
                else "not forecast" if e is None else "early" if delta < 0 else "late")
        out.append({"name": n, "old": s.old, "new": s.new, "at": ts, "forecast_at": e and e[2], "kind": kind,
                    "known": by[n].stack[0] in RULES, "starts": first[s.new] == (ts, n),
                    "number_forecast": starts.get(s.new)})
    for e in ledger.values():
        if not e[6] and e[2] + GRACE_S < upto:
            e[6] = True
            out.append({"name": e[0], "old": None, "new": e[1], "at": None, "forecast_at": e[2], "kind": "not seen",
                        "known": e[0] in by and by[e[0]].stack[0] in RULES, "starts": e[5], "number_forecast": None})
    state["cursor"] = max(cursor, upto)
    return out


def check_events(results: list[dict]) -> list[tuple[str, str, dict]]:
    """key_forecast_check per new number and one for the rest; one
    key_switch_unforecast for the known-stack switches no forecast had."""
    out = []
    head = [r for r in results if r["starts"]]
    for r in head:
        if r["kind"] == "not seen":
            text = (f"{r['new']} was forecast for {_s(r['forecast_at'])} from {r['name']} and is not on record "
                    f"{fmt_duration(GRACE_S)} later")
        else:
            p = r["number_forecast"]
            text = (f"{r['new']} started {_s(r['at'])} by {r['name']}: " + (
                "not forecast" if p is None else
                ("as forecast" if abs(r["at"] - p[0]) <= TOL_S else "missed")
                + f" ({_by(r['at'] - p[0])} against {_s(p[0])}" + (f" from {p[1]}" if p[1] != r["name"] else "")
                + ")"))
        out.append(("key_forecast_check", "info", {"name": r["name"], "sequence": r["new"], "switches": [r],
                                                   "note": text}))
    bad = [r for r in results if r["known"] and r["kind"] in ("early", "not forecast")]
    rest = [r for r in results if r not in head and r not in bad]
    if rest:
        ok = [r for r in rest if r["kind"] == "as forecast"]
        parts = [f"{len(ok)} as forecast" + (" (" + ", ".join(f"{r['name']} {r['old']}->{r['new']}" for r in ok)
                                             + ")" if len(ok) <= 3 else "")] if ok else []
        parts += [f"{r['name']} {r['kind']}" + (f" {_by(r['at'] - r['forecast_at'])}" if r["kind"] in ("late", "early")
                                                else "") for r in rest if r not in ok]
        out.append(("key_forecast_check", "info", {"name": rest[0]["name"] if len(rest) == 1 else None,
                                                   "sequence": max(r["new"] for r in rest), "switches": rest,
                                                   "note": "key switches: " + "; ".join(parts)}))
    if bad:
        out.append(("key_switch_unforecast", "notice", {
            "name": bad[0]["name"] if len(bad) == 1 else None, "switches": bad,
            "note": "; ".join(f"{r['name']} took {r['new']} at {_d(r['at'])}" + (
                f", {fmt_duration(r['forecast_at'] - r['at'])} before the forecast" if r["kind"] == "early"
                else ", not forecast") for r in bad)
            + ": a boot nothing recorded, a forced update or a wrong rule. "
            + WHERE.format("key_switch_unforecast")}))
    return out


def run(state: dict | None, devs, now: float, cache=None):
    """One hourly pass: (state, events, cache). ``state`` is what the last
    pass returned (None at first: nothing before now is graded); ``cache``
    holds the last notice for the same devices, since the remedy search
    takes some hundred forecasts."""
    state = {"ledger": {}, "cursor": now, "notice": None, **(state or {})}
    fc = kf.forecast(devs, now)
    events = check_events(grade(state, devs, now))
    # The ledger keeps, for each switch still to come, the last forecast made
    # before it. A switch the model has as due at the start, one on a
    # number whose own rotation is overdue (the forecast fires none, so it
    # forecasts nobody on it: a missed or late number), and one that has
    # come and is not graded yet keep their entries; one the forecast no
    # longer has at all (a boot changed it) is dropped. A forecast time
    # that has passed is not moved by a later forecast: the switch is
    # graded against what was forecast before it was due.
    ledger = state["ledger"]
    ahead = {f"{s.name}\t{s.new}": [s.name, s.new, s.ts, now, s.why, s.number, False]
             for s in fc.steps if s.ts > fc.start}
    due = {f"{s.name}\t{s.new}" for s in fc.steps if s.ts == fc.start}
    late = {fc.guards[n].key + 1 for n, _t in fc.overdue}     # a number whose own rotation is missed or late
    for k, e in list(ledger.items()):
        g = fc.guards.get(e[0])
        if k not in due and k not in ahead and e[1] not in late \
                and not (g is not None and g.key is not None and g.key >= e[1]):
            del ledger[k]
    ledger.update((k, e) for k, e in ahead.items() if k not in ledger or ledger[k][2] > now)   # a time passed stays
    # A rotation just due and not on record is most likely only not on
    # record yet: its first frame reaches the journal seconds to minutes
    # after, and a pass can land in between. The forecast fires no overdue
    # rotation, so for that pass it has lost the number and all that follows
    # from it. The notice is left as it is, nothing sent and nothing
    # cleared, for as long as grade() waits before calling the switch not
    # seen; after that the rotation really did not come.
    if any(t >= now - (LAG_S + GRACE_S) for _n, t in fc.overdue):
        return state, events, cache
    # The search is redone when the devices change, when the forecast's
    # first stranding does (time alone can do that: an own rotation that
    # did not come is not fired again), and when its time or window has passed.
    future = [x for x in fc.stranded if x.ts > fc.start]
    key = (hash(tuple(devs)), tuple(sorted((x.name, x.parent_key, x.ts) for x in future
                                           if x.parent_key == future[0].parent_key)) if future else ())
    old = cache[1] if cache is not None else None
    if cache is None or cache[0] != key or old is not None and (
            old["at"] <= now or old["power_cycle"] is not None and old["power_cycle"]["until"] < now):
        cache = (key, notice(devs, now, fc))
    cur, prev = cache[1], state["notice"]
    if cur is None and prev is not None:
        # Nothing forecast because the forecast changed is cleared. Nothing
        # forecast because the stranding has come (a child of the notice
        # is two behind as the forecast starts) is not: key_lag says that,
        # and "no longer forecast" would say the opposite.
        if not {x.name for x in fc.stranded if x.ts <= fc.start} & set(prev["two_behind"]):
            events.append(("key_stranding_cleared", "info", {
                "name": None, "sequence": prev["sequence"],
                "note": f"no sleepy child is forecast two behind any more ({prev['sequence']} on "
                        f"{_d(prev['at'])} was)"}))
        state["notice"] = None
    elif cur is not None:
        opened = cur["power_cycle"] is not None and cur["power_cycle"]["from"] <= now <= cur["power_cycle"]["until"]
        changed = prev is None or not same(prev, cur, now)
        if changed or opened and not prev.get("window_sent"):
            why = "first forecast" if prev is None else "changed" if changed else "power-cycle window open"
            events.append(("key_stranding_forecast", "warning", {"name": None, **cur, "why": why,
                                                                 "note": note(cur, now)}))
            state["notice"] = {**cur, "window_sent": opened}    # what later passes compare with: the one sent
    return state, events, cache
