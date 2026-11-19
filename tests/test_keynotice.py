"""keynotice: the stranding notice's remedy search and the forecast checks,
one small mesh per rule."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests  # noqa: F401  (the mDNS guard, installed on a direct run too: tests/no_lan)
from threadwatch import keynotice as kn
from threadwatch.keyforecast import Device
from threadwatch.keyguard import HOUR, Boot, Switch

OLD = ("old", "reported", "Air Monitor 2000 1.0.26")
CURRENT = ("current", "reported", "Bulb A19 5.1.45")
T = 1_800_000_000.0


def clear(name, stack, boot, key=90, **kw):
    """Booted on ``key`` and no +1 since: on the old logic a number is booked at boot + 672 h."""
    return Device(name, stack, (Boot(boot),), (Switch(boot + 1, None, key),), **kw)


def armed(name, stack, boot, at=None, key=90, **kw):
    """Took ``key`` as a +1 at ``at`` (at its boot by default)."""
    at = boot + 5 if at is None else at
    return Device(name, stack, (Boot(boot),), (Switch(boot + 1, None, key - 1), Switch(at, key - 1, key)), **kw)


def mesh(parent_of_den=None):
    """Mezzanine starts 91 at T + 72 h. Darkroom reset at T - 300 h with no +1 since: it takes 91 as its first +1,
    keeps its timer and starts 92 at T + 372 h. Hall, a current-logic router, follows each at once. Porch, a
    sleepy child of Hall, took 90 at T - 100 h and refuses 91 until T + 524 h: 92 finds it two behind."""
    return [armed("Mezzanine Monitor", OLD, T - 600 * HOUR),
            clear("Darkroom Monitor", OLD, T - 300 * HOUR, parent=parent_of_den),
            clear("Hall Bulb", CURRENT, T - 50 * HOUR),
            armed("Porch Sensor", CURRENT, T - 700 * HOUR, at=T - 100 * HOUR, parent="Hall Bulb", sleepy=True)]


class NoticeTest(unittest.TestCase):
    def test_a_booked_number_with_a_pull_and_a_power_cycle_that_prevent_it(self):
        n = kn.notice(mesh(), T)
        self.assertEqual((n["sequence"], n["at"], n["started_by"], n["two_behind"], n["later"]),
                         (92, T + 372 * HOUR, "Darkroom Monitor", ["Porch Sensor"], 0))
        # A pull lifts Porch to Hall's key, which is ahead of it from 91 on; the guard it arms then
        # outlasts 92, so it is one behind, not two.
        pull = n["pulls"]["Porch Sensor"]
        self.assertEqual(pull["from"], T + 72 * HOUR)
        self.assertAlmostEqual(pull["until"], T + 372 * HOUR, delta=kn.EDGE_S)
        self.assertLess(pull["until"], T + 372 * HOUR)
        # Power-cycling Darkroom before Mezzanine's 91 moves its 92 past Porch's guard. After 91 it would take 91 as
        # its first +1 since that boot, keep its timer and book 93 too early: the window ends at 91.
        cycle = n["power_cycle"]
        self.assertEqual((cycle["units"], cycle["from"]), (["Darkroom Monitor"], T))
        self.assertAlmostEqual(cycle["until"], T + 72 * HOUR, delta=kn.EDGE_S)
        text = kn.note(n, T)
        self.assertIn("92 from Darkroom Monitor on ", text)
        self.assertIn("leaves 1 sleepy children two behind. A battery pull helps 1: Porch Sensor (", text)
        self.assertIn("Power-cycling Darkroom Monitor between ", text)
        self.assertIn("(open now)", text)
        self.assertTrue(text.endswith("key_stranding_forecast in docs/ALERTING.md."))

    def test_no_power_cycle_for_a_unit_while_it_is_ahead_of_its_parent(self):
        # Darkroom is a mains child of Loft, which is on 89 until its guard opens at T + 50 h: Darkroom is ahead of it
        # until then, so the window opens at T + 50 h instead of now.
        loft = armed("Loft Monitor", OLD, T - 574 * HOUR, key=89)
        n = kn.notice(mesh("Loft Monitor") + [loft], T)
        cycle = n["power_cycle"]
        self.assertEqual(cycle["units"], ["Darkroom Monitor"])
        self.assertAlmostEqual(cycle["from"], T + 50 * HOUR, delta=kn.EDGE_S)
        self.assertGreaterEqual(cycle["from"], T + 50 * HOUR)
        self.assertAlmostEqual(cycle["until"], T + 72 * HOUR, delta=kn.EDGE_S)
        self.assertLess(cycle["until"], T + 72 * HOUR)

    def test_a_pull_cannot_lift_a_child_whose_parent_jumps_two(self):
        # Shed is an old-logic router that refuses 91 until long after 92, then jumps: its child never has a
        # parent ahead of it to be lifted to.
        shed = armed("Shed Monitor", OLD, T - 10 * HOUR)
        gate = armed("Gate Sensor", CURRENT, T - 700 * HOUR, at=T - 100 * HOUR, parent="Shed Monitor", sleepy=True)
        n = kn.notice(mesh() + [shed, gate], T)
        self.assertIn("Gate Sensor", n["two_behind"])
        self.assertEqual(n["pulls"]["Gate Sensor"], {"parent_behind": True})
        self.assertIn("1 has a parent never ahead of them before then, so a pull lifts nothing", kn.note(n, T))

    def test_nothing_two_behind_is_no_notice(self):
        self.assertIsNone(kn.notice(mesh()[:3], T))

    def test_the_note_says_plainly_when_nothing_helps(self):
        n = {"sequence": 94, "at": T, "started_by": None, "two_behind": ["A", "B", "C"], "later": 2,
             "pulls": {"A": {"parent_behind": True}, "B": {"again": 95, "at": T + HOUR},
                       "C": {"again": 95, "at": T + HOUR}}, "power_cycle": None}
        text = kn.note(n, T - HOUR)
        self.assertIn("94 on ", text)
        self.assertIn("and 2 more later in the forecast. Battery pulls cannot help: 1 has a parent never ahead", text)
        self.assertIn("; 2 are two behind again at 95 on ", text)
        self.assertIn("No power cycle the forecast tried prevents it.", text)

    def test_same_allows_times_to_move_less_than_an_hour(self):
        a = {"sequence": 94, "at": T, "two_behind": ["A"], "pulls": {"A": {"parent_behind": True}},
             "power_cycle": {"units": ["U"], "from": T - 9 * HOUR, "until": T - 2 * HOUR}}
        moved = {**a, "at": T + 1800, "power_cycle": {**a["power_cycle"], "from": T - 9 * HOUR + 600}}
        before = T - 20 * HOUR
        self.assertTrue(kn.same(a, moved, before))
        self.assertFalse(kn.same(a, {**a, "at": T + 2 * HOUR}, before))
        self.assertFalse(kn.same(a, {**a, "two_behind": ["A", "B"]}, before))
        self.assertFalse(kn.same(a, {**a, "pulls": {"A": {"from": T - HOUR, "until": T}}}, before))
        self.assertFalse(kn.same(a, {**a, "power_cycle": None}, before))
        # An open window searched again starts at the time of the search: not a change.
        later = {**a, "power_cycle": {**a["power_cycle"], "from": T - 3 * HOUR}}
        self.assertFalse(kn.same(a, later, before))
        self.assertTrue(kn.same(a, later, T - 3 * HOUR))

    def test_a_window_that_has_closed_is_not_open_now(self):
        n = {"sequence": 92, "at": T, "started_by": "U", "two_behind": ["A"], "later": 0,
             "pulls": {"A": {"parent_behind": True}},
             "power_cycle": {"units": ["U"], "from": T - 9 * HOUR, "until": T - 8 * HOUR}}
        self.assertIn("(open now)", kn.note(n, T - 8.5 * HOUR))
        self.assertNotIn("(open now)", kn.note(n, T - 7 * HOUR))

    def test_a_child_already_two_behind_is_left_to_key_lag(self):
        # Yard is on 88 under Hall on 90 now: stranded already, which neither starts the notice nor makes
        # every remedy for 92 look as if it failed.
        yard = armed("Yard Sensor", CURRENT, T - 700 * HOUR, key=88, parent="Hall Bulb", sleepy=True)
        n = kn.notice(mesh() + [yard], T)
        self.assertEqual((n["sequence"], n["two_behind"]), (92, ["Porch Sensor"]))
        self.assertIn("from", n["pulls"]["Porch Sensor"])
        self.assertEqual(n["power_cycle"]["units"], ["Darkroom Monitor"])

    def test_a_unit_booted_with_no_key_on_record_is_not_tried(self):
        gate = Device("Gate Door", OLD, (Boot(T - 10 * HOUR),), ())
        n = kn.notice(mesh() + [gate], T)
        self.assertEqual(n["power_cycle"]["units"], ["Darkroom Monitor"])

    def test_children_the_same_number_strands_later_are_in_the_notice(self):
        # Shed took 91 as its first +1 since its boot at T - 224 h, so its guard opens at T + 400 h: it takes
        # 92 then, and its child Gate, still on 90, is left two behind by the same number.
        shed = clear("Shed Monitor", OLD, T - 224 * HOUR)
        gate = armed("Gate Sensor", CURRENT, T - 700 * HOUR, at=T - 100 * HOUR, parent="Shed Monitor", sleepy=True)
        n = kn.notice(mesh() + [shed, gate], T)
        self.assertEqual((n["sequence"], n["at"]), (92, T + 372 * HOUR))
        self.assertEqual((n["two_behind"], n["later"]), (["Gate Sensor", "Porch Sensor"], 0))

    def test_a_booked_unit_the_whole_window_can_do_without_is_left_out(self):
        # Attic reset at T - 100 h: its number is booked for after Porch's guard has opened, so cycling Darkroom
        # alone prevents 92 at every time cycling both does.
        n = kn.notice(mesh() + [clear("Attic Monitor", OLD, T - 100 * HOUR)], T)
        cycle = n["power_cycle"]
        self.assertEqual((cycle["units"], cycle["from"]), (["Darkroom Monitor"], T))
        self.assertAlmostEqual(cycle["until"], T + 72 * HOUR, delta=kn.EDGE_S)

    def test_fewer_units_never_means_a_later_or_a_shorter_window(self):
        # Three units have a number booked. Cycling all three works from now until T + 91 h. Until Mezzanine
        # fires at T + 46 h, Darkroom and Mezzanine are enough; after it, Darkroom and Gate, or Gate alone. None of
        # those smaller sets covers the whole window, so none replaces the full set, whenever it is asked.
        unknown = ("unknown", None, "not in the table")
        devs = [armed("Loft Monitor", OLD, T - 607 * HOUR), clear("Darkroom Monitor", OLD, T - 533 * HOUR),
                armed("Shed Monitor", OLD, T - 120 * HOUR), clear("Mezzanine Monitor", OLD, T - 626 * HOUR),
                Device("Deck TV", unknown, (), (Switch(T - 400 * HOUR, None, 90),)),
                armed("Porch Sensor", OLD, T - 700 * HOUR, at=T - 295 * HOUR, parent="Darkroom Monitor", sleepy=True),
                clear("Gate Sensor", OLD, T - 153 * HOUR, parent="Deck TV", sleepy=True)]
        sent = None
        for now in (T, T + 2 * HOUR, T + 30 * HOUR):
            with self.subTest(hours=(now - T) / HOUR):
                n = kn.notice(devs, now)
                cycle = n["power_cycle"]
                self.assertEqual((n["sequence"], n["two_behind"]), (94, ["Gate Sensor"]))
                self.assertEqual(cycle["units"], ["Darkroom Monitor", "Gate Sensor", "Mezzanine Monitor"])
                self.assertEqual(cycle["from"], now)
                self.assertAlmostEqual(cycle["until"], T + 91 * HOUR, delta=kn.EDGE_S)
                self.assertTrue(sent is None or kn.same(sent, n, now))      # nothing new to send
                sent = sent or n


class NoticeFiringTest(unittest.TestCase):
    def fired(self, events):
        return [(e, f.get("why")) for e, sev, f in events if e.startswith("key_stranding")]

    def test_first_sight_then_quiet_then_the_window_opening_then_cleared(self):
        loft = armed("Loft Monitor", OLD, T - 574 * HOUR, key=89)
        devs = mesh("Loft Monitor") + [loft]
        state, events, cache = kn.run(None, devs, T)
        self.assertEqual(self.fired(events), [("key_stranding_forecast", "first forecast")])
        self.assertEqual([sev for e, sev, f in events if e == "key_stranding_forecast"], ["warning"])
        state = json.loads(json.dumps(state))        # what the recorder keeps on disk
        state, events, cache = kn.run(state, devs, T + HOUR, cache)
        self.assertEqual(self.fired(events), [])
        state, events, cache = kn.run(state, devs, T + 51 * HOUR, cache)
        self.assertEqual(self.fired(events), [("key_stranding_forecast", "power-cycle window open")])
        self.assertIn("(open now)", events[-1][2]["note"])
        state, events, cache = kn.run(state, devs, T + 52 * HOUR, cache)
        self.assertEqual(self.fired(events), [])
        # Darkroom power-cycled inside the window: nothing is forecast two behind any more.
        dk = devs[1]
        done = [Device(dk.name, dk.stack, dk.boots + (Boot(T + 53 * HOUR),), dk.switches, dk.parent)
                if d is dk else d for d in devs]
        state, events, cache = kn.run(state, done, T + 54 * HOUR, cache)
        self.assertEqual(self.fired(events), [("key_stranding_cleared", None)])
        self.assertIsNone(state["notice"])

    def test_a_changed_answer_fires_again(self):
        devs = mesh()
        state, events, cache = kn.run(None, devs, T)
        gate = armed("Gate Sensor", CURRENT, T - 700 * HOUR, at=T - 100 * HOUR, parent="Hall Bulb", sleepy=True)
        state, events, cache = kn.run(state, devs + [gate], T + HOUR, cache)
        self.assertEqual(self.fired(events), [("key_stranding_forecast", "changed")])

    def with_switches(self, devs, switches):
        return [Device(d.name, d.stack, d.boots, d.switches + tuple(switches.get(d.name, ())), d.parent, d.sleepy)
                for d in devs]

    def test_a_pass_just_after_a_rotation_falls_due_leaves_the_notice_as_it_is(self):
        # Mezzanine's 91 came as forecast. Darkroom's 92 is due at T + 372 h and a pass lands a minute after, before
        # its first frame is on record: the forecast has the rotation as overdue, fires none, and so has
        # nothing two behind. That is not news: nothing is cleared and nothing sent.
        r1, r2 = T + 72 * HOUR, T + 372 * HOUR
        taken = {n: [Switch(r1 + 5, 90, 91)] for n in ("Mezzanine Monitor", "Darkroom Monitor", "Hall Bulb")}
        devs = self.with_switches(mesh(), taken)
        state, events, cache = kn.run(None, devs, r2 - HOUR + 60)
        self.assertEqual(self.fired(events), [("key_stranding_forecast", "first forecast")])
        sent = state["notice"]
        state, events, cache = kn.run(json.loads(json.dumps(state)), devs, r2 + 60, cache)
        self.assertEqual(self.fired(events), [])
        self.assertEqual(state["notice"], sent)
        # It never comes: the notice waits as long as the check does before calling the switch not seen,
        # and only then is the stranding no longer forecast.
        waited = kn.LAG_S + kn.GRACE_S
        state, events, cache = kn.run(state, devs, r2 + waited - 60, cache)
        self.assertEqual(self.fired(events), [])
        state, events, cache = kn.run(state, devs, r2 + waited + 60, cache)
        self.assertEqual(self.fired(events), [("key_stranding_cleared", None)])
        self.assertTrue(any(f["note"].startswith("92 was forecast for ") for e, _s, f in events
                            if e == "key_forecast_check"))

    def test_a_first_notice_waits_while_a_rotation_just_due_is_not_on_record(self):
        # The same pass with nothing sent before (a recorder started then). Shed has 92 booked too, a
        # hundred hours after Darkroom: with Darkroom's rotation left out the forecast has 92 from Shed, and that is
        # not sent as a first forecast.
        r1, r2 = T + 72 * HOUR, T + 372 * HOUR
        shed = clear("Shed Monitor", OLD, T - 200 * HOUR)
        taken = {n: [Switch(r1 + 5, 90, 91)] for n in ("Mezzanine Monitor", "Darkroom Monitor",
                                                         "Hall Bulb", "Shed Monitor")}
        devs = self.with_switches(mesh() + [shed], taken)
        wrong = kn.notice(devs, r2 + 60)
        self.assertEqual((wrong["sequence"], wrong["started_by"], wrong["at"]), (92, "Shed Monitor", T + 472 * HOUR))
        state, events, cache = kn.run(None, devs, r2 + 60)
        self.assertEqual((self.fired(events), state["notice"]), ([], None))
        # Darkroom's 92 is on record by the next pass. Porch, two behind now, is key_lag's; the notice is the
        # next number's.
        taken = {**taken, "Darkroom Monitor": taken["Darkroom Monitor"] + [Switch(r2 + 90, 91, 92)],
                 "Hall Bulb": taken["Hall Bulb"] + [Switch(r2 + 95, 91, 92)]}
        state, events, cache = kn.run(state, self.with_switches(mesh() + [shed], taken), r2 + HOUR + 60, cache)
        self.assertEqual(self.fired(events), [("key_stranding_forecast", "first forecast")])
        self.assertEqual(state["notice"]["sequence"], 93)

    def test_a_stranding_that_has_come_true_is_not_cleared(self):
        # Shed refuses 91 behind a closed guard and jumps to 92 with the mesh; Gate and Yard, its sleepy
        # children of unknown stack, stay on 90. Nothing further is forecast for them.
        r1, r2 = T + 72 * HOUR, T + 372 * HOUR
        unknown = ("unknown", None, "not in the table")
        shed = armed("Shed Monitor", OLD, T - 10 * HOUR)
        kids = [Device(n, unknown, (), (Switch(T - 99 * HOUR, None, 90),), "Shed Monitor", True)
                for n in ("Gate Sensor", "Yard Sensor")]
        devs = mesh()[:3] + [shed] + kids
        state, events, cache = kn.run(None, devs, T)
        self.assertEqual(self.fired(events), [("key_stranding_forecast", "first forecast")])
        sent = state["notice"]
        self.assertEqual((sent["sequence"], sent["two_behind"]), (92, ["Gate Sensor", "Yard Sensor"]))
        taken = {n: [Switch(r1 + 5, 90, 91), Switch(r2 + 5, 91, 92)] for n in ("Darkroom Monitor", "Hall Bulb")}
        taken.update({"Mezzanine Monitor": [Switch(r1 + 5, 90, 91)], "Shed Monitor": [Switch(r2 + 5, 90, 92)]})
        came = self.with_switches(devs, taken)
        # The pass after 92: both are two behind, as forecast. That is key_lag's to say, and "no sleepy
        # child is forecast two behind any more" would say the opposite: the notice is dropped quietly.
        before = json.loads(json.dumps(state))
        state, events, cache = kn.run(state, came, r2 + 60, cache)
        self.assertEqual((self.fired(events), state["notice"]), ([], None))
        # One of its children two behind is enough: Yard was taken out of the inventory meanwhile.
        state, events, cache = kn.run(before, came[:-1], r2 + 60)
        self.assertEqual((self.fired(events), state["notice"]), ([], None))
        # With none of them two behind (92 has not come, and Shed was power-cycled, so it follows 91
        # and its children with it), the forecast did change, and that is cleared.
        shed = devs[3]
        cycled = self.with_switches(devs[:3] + [Device(shed.name, shed.stack, shed.boots + (Boot(T + HOUR),),
                                                       shed.switches)] + kids, {})
        self.assertIsNone(kn.notice(cycled, T + 2 * HOUR))
        state, events, cache = kn.run(json.loads(json.dumps(before)), cycled, T + 2 * HOUR)
        self.assertEqual(self.fired(events), [("key_stranding_cleared", None)])


class ChecksTest(unittest.TestCase):
    """Mezzanine starts 91 at T + 72 h and the routers, their guards open by then, follow; Kids Room, a sleepy
    current-logic child, is forecast to take it when its guard opens at T + 500 h. Nothing is booked."""

    def devs(self, recorded=()):
        rec = dict(recorded)

        def dev(d):
            return Device(d.name, d.stack, d.boots + rec.get(d.name, ((), ()))[0],
                          d.switches + rec.get(d.name, ((), ()))[1], d.parent, d.sleepy)
        return [dev(d) for d in (armed("Mezzanine Monitor", OLD, T - 600 * HOUR),
                                 armed("Hall Monitor", OLD, T - 590 * HOUR),
                                 armed("Attic Monitor", OLD, T - 560 * HOUR),
                                 armed("Cellar Monitor", OLD, T - 580 * HOUR),
                                 armed("Kids Room Sensor", CURRENT, T - 700 * HOUR, at=T - 124 * HOUR,
                                       parent="Hall Monitor", sleepy=True))]

    def test_each_switch_against_the_forecast_made_before_it(self):
        r1 = T + 72 * HOUR
        state, events, cache = kn.run(None, self.devs(), T)
        self.assertEqual(events, [])
        ledger = {(e[0], e[1]): (e[2], e[5]) for e in state["ledger"].values()}
        self.assertEqual(ledger[("Mezzanine Monitor", 91)], (r1, True))
        self.assertEqual(ledger[("Kids Room Sensor", 91)], (T + 500 * HOUR, False))
        state = json.loads(json.dumps(state))
        recorded = {"Mezzanine Monitor": ((), (Switch(r1 + 5, 90, 91),)),
                    "Hall Monitor": ((), (Switch(r1 + 40 * 60, 90, 91),)),                       # late
                    "Cellar Monitor": ((Boot(r1 + 2 * HOUR),), (Switch(r1 + 2 * HOUR + 30, 90, 91),)),  # at a boot
                    "Kids Room Sensor": ((), (Switch(r1 + 600, 90, 91),))}                         # 17 days early
        now = r1 + 4 * HOUR       # everything above is past the grading lag
        state, events, cache = kn.run(state, self.devs(recorded.items()), now, cache)
        by = {}
        for e, sev, f in events:
            by.setdefault(e, []).append((sev, f))
        (sev, head), (_sev, rest) = by["key_forecast_check"]
        self.assertEqual((sev, head["sequence"], head["name"]), ("info", 91, "Mezzanine Monitor"))
        self.assertIn("by Mezzanine Monitor: as forecast (+5s against ", head["note"])
        kinds = {r["name"]: r["kind"] for r in rest["switches"]}
        self.assertEqual(kinds, {"Hall Monitor": "late", "Cellar Monitor": "at a boot", "Attic Monitor": "not seen"})
        self.assertIn("Hall Monitor late +40m", rest["note"])
        [(sev, bad)] = by["key_switch_unforecast"]
        self.assertEqual((sev, bad["name"]), ("notice", "Kids Room Sensor"))
        self.assertIn("Kids Room Sensor took 91 at ", bad["note"])
        self.assertIn("before the forecast: a boot nothing recorded", bad["note"])
        # Nothing is graded twice.
        state, events, cache = kn.run(state, self.devs(recorded.items()), now + HOUR, cache)
        self.assertEqual(events, [])

    def test_a_switch_is_graded_only_once_the_lag_has_passed(self):
        r1 = T + 72 * HOUR
        state, _events, cache = kn.run(None, self.devs(), T)
        recorded = {"Mezzanine Monitor": ((), (Switch(r1 + 5, 90, 91),))}
        state, events, cache = kn.run(state, self.devs(recorded.items()), r1 + kn.LAG_S - 60, cache)
        self.assertEqual(events, [])
        state, events, cache = kn.run(state, self.devs(recorded.items()), r1 + kn.LAG_S + 60, cache)
        self.assertIn("as forecast", events[0][2]["note"])

    def test_a_missed_number_is_not_seen_and_a_late_one_is_late(self):
        r1 = T + 72 * HOUR
        state, _events, cache = kn.run(None, self.devs(), T)
        # No switch on record: the forecast now has Mezzanine's rotation as overdue and fires none.
        state, events, cache = kn.run(state, self.devs(), r1 + HOUR, cache)
        self.assertEqual(events, [])
        state, events, cache = kn.run(state, self.devs(), r1 + 3 * HOUR, cache)
        notes = [f["note"] for e, _s, f in events if e == "key_forecast_check"]
        self.assertTrue(any(n.startswith("91 was forecast for ") and "from Mezzanine Monitor" in n for n in notes))
        rest = next(f for e, _s, f in events if e == "key_forecast_check" and f["name"] is None)
        self.assertEqual({r["name"] for r in rest["switches"]}, {"Hall Monitor", "Attic Monitor", "Cellar Monitor"})
        # It comes, two and a half hours late, and the mesh follows: late, not unforecast.
        late = r1 + 2.5 * HOUR
        recorded = {n: ((), (Switch(late + i, 90, 91),)) for i, n in enumerate(
            ("Mezzanine Monitor", "Hall Monitor", "Attic Monitor", "Cellar Monitor"))}
        state, events, cache = kn.run(state, self.devs(recorded.items()), late + 2 * HOUR, cache)
        self.assertNotIn("key_switch_unforecast", [e for e, _s, _f in events])
        head = next(f for e, _s, f in events if e == "key_forecast_check" and f["name"] == "Mezzanine Monitor")
        self.assertIn("missed (+2h30m against ", head["note"])
        rest = next(f for e, _s, f in events if e == "key_forecast_check" and f["name"] is None)
        self.assertEqual({r["kind"] for r in rest["switches"]}, {"late"})

    def test_a_number_nobody_forecast(self):
        state, _events, cache = kn.run(None, self.devs(), T)
        early = T + 10 * HOUR
        recorded = {"Attic Monitor": ((), (Switch(early, 90, 91),))}
        state, events, cache = kn.run(state, self.devs(recorded.items()), early + 2 * HOUR, cache)
        head = next(f for e, _s, f in events if e == "key_forecast_check")
        self.assertIn("91 started ", head["note"])
        self.assertIn("by Attic Monitor: missed (-2d14h against ", head["note"])
        self.assertIn(" from Mezzanine Monitor)", head["note"])
        self.assertEqual([e for e, _s, _f in events].count("key_switch_unforecast"), 1)

    def test_a_number_started_early_keeps_its_forecast_start_through_the_hourly_passes(self):
        # Attic starts 91 at T + 10 h. The pass an hour later, before it is graded, forecasts Mezzanine only
        # following 91 when its guard opens: the start forecast for T + 72 h is what it is graded against.
        state, _events, cache = kn.run(None, self.devs(), T)
        early = T + 10 * HOUR
        recorded = {"Attic Monitor": ((), (Switch(early, 90, 91),))}
        for now in (early + HOUR, early + 2 * HOUR):
            state, events, cache = kn.run(json.loads(json.dumps(state)), self.devs(recorded.items()), now, cache)
        head = next(f for e, _s, f in events if e == "key_forecast_check")
        self.assertIn("by Attic Monitor: missed (-2d14h against ", head["note"])
        self.assertIn(" from Mezzanine Monitor)", head["note"])


class RecorderTest(unittest.TestCase):
    """The capture thread's side: a pass on a worker thread from copies, its
    events emitted and its state saved by the pass after, kept across a restart."""

    def setUp(self):
        import tempfile

        from threadwatch.config import Config
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([{"name": "Hall Monitor",
                                                     "extendedAddresses": ["C4E2A91D07F35B6E"]}]))
        self.cfg = Config(data_dir=d / "data", config_dir=d, devices_path=d / "devices.json")
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
        self.calls = []
        self.real = kn.run

        def fake(state, devs, now, cache=None):
            self.calls.append((state, [x.name for x in devs], now, cache))
            return ({"ledger": {}, "cursor": now, "notice": None, "n": len(self.calls)},
                    [("key_forecast_check", "info", {"name": None, "note": "key switches: 1 as forecast"})], "cache")
        kn.run = fake

    def tearDown(self):
        kn.run = self.real
        self.tmp.cleanup()

    def pipe(self):
        from threadwatch.crypto import Decryptor
        from threadwatch.events import NullEventLog
        from threadwatch.pipeline import Pipeline
        return Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)))

    def keyfc(self, pipe):
        return [r for r in pipe.events.records if r["event"].startswith("key_")]

    def step(self, pipe, now):
        pipe._poll_key_forecast(now)
        if pipe._keyfc_thread is not None:
            pipe._keyfc_thread.join()

    def test_a_pass_then_its_events_and_state_then_none_until_the_hour_is_up(self):
        pipe = self.pipe()
        self.step(pipe, T)
        self.assertEqual(self.calls, [(None, ["Hall Monitor"], T, None)])
        self.assertEqual(self.keyfc(pipe), [])
        self.step(pipe, T + 30)
        self.assertEqual([(r["event"], r["severity"]) for r in self.keyfc(pipe)], [("key_forecast_check", "info")])
        saved = json.loads((self.cfg.state_dir / "key-forecast.json").read_text())
        self.assertEqual(saved["n"], 1)
        self.step(pipe, T + 60)
        self.assertEqual(len(self.calls), 1)
        self.step(pipe, T + pipe.KEY_FORECAST_S)
        self.assertEqual(self.calls[1][0]["n"], 1)
        self.assertEqual(self.calls[1][3], "cache")
        # A restart starts from the saved state, with no cache.
        self.step(self.pipe(), T + 2 * pipe.KEY_FORECAST_S)
        self.assertEqual((self.calls[2][0]["n"], self.calls[2][3]), (1, None))

    def test_a_pass_that_fails_is_logged_and_the_next_hour_tries_again(self):
        def broken(*a, **k):
            raise ValueError("bad journal")
        kn.run = broken
        pipe = self.pipe()
        self.step(pipe, T)
        from contextlib import redirect_stderr
        from io import StringIO
        err = StringIO()
        with redirect_stderr(err):
            self.step(pipe, T + 30)
        self.assertIn("key forecast: ValueError: bad journal", err.getvalue())
        self.assertEqual(self.keyfc(pipe), [])
        self.assertFalse((self.cfg.state_dir / "key-forecast.json").exists())


if __name__ == "__main__":
    unittest.main()
