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
    """Mudroom starts 91 at T + 72 h. Den reset at T - 300 h with no +1 since: it takes 91 as its first +1,
    keeps its timer and starts 92 at T + 372 h. Hall, a current-logic router, follows each at once. Porch, a
    sleepy child of Hall, took 90 at T - 100 h and refuses 91 until T + 524 h: 92 finds it two behind."""
    return [armed("Mudroom Monitor", OLD, T - 600 * HOUR),
            clear("Den Monitor", OLD, T - 300 * HOUR, parent=parent_of_den),
            clear("Hall Bulb", CURRENT, T - 50 * HOUR),
            armed("Porch Sensor", CURRENT, T - 700 * HOUR, at=T - 100 * HOUR, parent="Hall Bulb", sleepy=True)]


class NoticeTest(unittest.TestCase):
    def test_a_booked_number_with_a_pull_and_a_power_cycle_that_prevent_it(self):
        n = kn.notice(mesh(), T)
        self.assertEqual((n["sequence"], n["at"], n["started_by"], n["two_behind"], n["later"]),
                         (92, T + 372 * HOUR, "Den Monitor", ["Porch Sensor"], 0))
        # A pull lifts Porch to Hall's key, which is ahead of it from 91 on; the guard it arms then
        # outlasts 92, so it is one behind, not two.
        pull = n["pulls"]["Porch Sensor"]
        self.assertEqual(pull["from"], T + 72 * HOUR)
        self.assertAlmostEqual(pull["until"], T + 372 * HOUR, delta=kn.EDGE_S)
        self.assertLess(pull["until"], T + 372 * HOUR)
        # Power-cycling Den before Mudroom's 91 moves its 92 past Porch's guard. After 91 it would take 91 as
        # its first +1 since that boot, keep its timer and book 93 too early: the window ends at 91.
        cycle = n["power_cycle"]
        self.assertEqual((cycle["units"], cycle["from"]), (["Den Monitor"], T))
        self.assertAlmostEqual(cycle["until"], T + 72 * HOUR, delta=kn.EDGE_S)
        text = kn.note(n, T)
        self.assertIn("92 from Den Monitor on ", text)
        self.assertIn("leaves 1 sleepy children two behind. A battery pull helps 1: Porch Sensor (", text)
        self.assertIn("Power-cycling Den Monitor between ", text)
        self.assertIn("(open now)", text)
        self.assertTrue(text.endswith("key_stranding_forecast in docs/ALERTING.md."))

    def test_no_power_cycle_for_a_unit_while_it_is_ahead_of_its_parent(self):
        # Den is a mains child of Loft, which is on 89 until its guard opens at T + 50 h: Den is ahead of it
        # until then, so the window opens at T + 50 h instead of now.
        loft = armed("Loft Monitor", OLD, T - 574 * HOUR, key=89)
        n = kn.notice(mesh("Loft Monitor") + [loft], T)
        cycle = n["power_cycle"]
        self.assertEqual(cycle["units"], ["Den Monitor"])
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
        self.assertEqual(n["power_cycle"]["units"], ["Den Monitor"])

    def test_a_unit_booted_with_no_key_on_record_is_not_tried(self):
        gate = Device("Gate Door", OLD, (Boot(T - 10 * HOUR),), ())
        n = kn.notice(mesh() + [gate], T)
        self.assertEqual(n["power_cycle"]["units"], ["Den Monitor"])

    def test_children_the_same_number_strands_later_are_in_the_notice(self):
        # Shed took 91 as its first +1 since its boot at T - 224 h, so its guard opens at T + 400 h: it takes
        # 92 then, and its child Gate, still on 90, is left two behind by the same number.
        shed = clear("Shed Monitor", OLD, T - 224 * HOUR)
        gate = armed("Gate Sensor", CURRENT, T - 700 * HOUR, at=T - 100 * HOUR, parent="Shed Monitor", sleepy=True)
        n = kn.notice(mesh() + [shed, gate], T)
        self.assertEqual((n["sequence"], n["at"]), (92, T + 372 * HOUR))
        self.assertEqual((n["two_behind"], n["later"]), (["Gate Sensor", "Porch Sensor"], 0))


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
        # Den power-cycled inside the window: nothing is forecast two behind any more.
        den = devs[1]
        done = [Device(den.name, den.stack, den.boots + (Boot(T + 53 * HOUR),), den.switches, den.parent)
                if d is den else d for d in devs]
        state, events, cache = kn.run(state, done, T + 54 * HOUR, cache)
        self.assertEqual(self.fired(events), [("key_stranding_cleared", None)])
        self.assertIsNone(state["notice"])

    def test_a_changed_answer_fires_again(self):
        devs = mesh()
        state, events, cache = kn.run(None, devs, T)
        gate = armed("Gate Sensor", CURRENT, T - 700 * HOUR, at=T - 100 * HOUR, parent="Hall Bulb", sleepy=True)
        state, events, cache = kn.run(state, devs + [gate], T + HOUR, cache)
        self.assertEqual(self.fired(events), [("key_stranding_forecast", "changed")])


class ChecksTest(unittest.TestCase):
    """Mudroom starts 91 at T + 72 h and the routers, their guards open by then, follow; Kitchen, a sleepy
    current-logic child, is forecast to take it when its guard opens at T + 500 h. Nothing is booked."""

    def devs(self, recorded=()):
        rec = dict(recorded)

        def dev(d):
            return Device(d.name, d.stack, d.boots + rec.get(d.name, ((), ()))[0],
                          d.switches + rec.get(d.name, ((), ()))[1], d.parent, d.sleepy)
        return [dev(d) for d in (armed("Mudroom Monitor", OLD, T - 600 * HOUR),
                                 armed("Hall Monitor", OLD, T - 590 * HOUR),
                                 armed("Attic Monitor", OLD, T - 560 * HOUR),
                                 armed("Cellar Monitor", OLD, T - 580 * HOUR),
                                 armed("Kitchen Sensor", CURRENT, T - 700 * HOUR, at=T - 124 * HOUR,
                                       parent="Hall Monitor", sleepy=True))]

    def test_each_switch_against_the_forecast_made_before_it(self):
        r1 = T + 72 * HOUR
        state, events, cache = kn.run(None, self.devs(), T)
        self.assertEqual(events, [])
        ledger = {(e[0], e[1]): (e[2], e[5]) for e in state["ledger"].values()}
        self.assertEqual(ledger[("Mudroom Monitor", 91)], (r1, True))
        self.assertEqual(ledger[("Kitchen Sensor", 91)], (T + 500 * HOUR, False))
        state = json.loads(json.dumps(state))
        recorded = {"Mudroom Monitor": ((), (Switch(r1 + 5, 90, 91),)),
                    "Hall Monitor": ((), (Switch(r1 + 40 * 60, 90, 91),)),                       # late
                    "Cellar Monitor": ((Boot(r1 + 2 * HOUR),), (Switch(r1 + 2 * HOUR + 30, 90, 91),)),  # at a boot
                    "Kitchen Sensor": ((), (Switch(r1 + 600, 90, 91),))}                         # 17 days early
        now = r1 + 4 * HOUR       # everything above is past the grading lag
        state, events, cache = kn.run(state, self.devs(recorded.items()), now, cache)
        by = {}
        for e, sev, f in events:
            by.setdefault(e, []).append((sev, f))
        (sev, head), (_sev, rest) = by["key_forecast_check"]
        self.assertEqual((sev, head["sequence"], head["name"]), ("info", 91, "Mudroom Monitor"))
        self.assertIn("by Mudroom Monitor: as forecast (+5s against ", head["note"])
        kinds = {r["name"]: r["kind"] for r in rest["switches"]}
        self.assertEqual(kinds, {"Hall Monitor": "late", "Cellar Monitor": "at a boot", "Attic Monitor": "not seen"})
        self.assertIn("Hall Monitor late +40m", rest["note"])
        [(sev, bad)] = by["key_switch_unforecast"]
        self.assertEqual((sev, bad["name"]), ("notice", "Kitchen Sensor"))
        self.assertIn("Kitchen Sensor took 91 at ", bad["note"])
        self.assertIn("before the forecast: a boot nothing recorded", bad["note"])
        # Nothing is graded twice.
        state, events, cache = kn.run(state, self.devs(recorded.items()), now + HOUR, cache)
        self.assertEqual(events, [])

    def test_a_switch_is_graded_only_once_the_lag_has_passed(self):
        r1 = T + 72 * HOUR
        state, _events, cache = kn.run(None, self.devs(), T)
        recorded = {"Mudroom Monitor": ((), (Switch(r1 + 5, 90, 91),))}
        state, events, cache = kn.run(state, self.devs(recorded.items()), r1 + kn.LAG_S - 60, cache)
        self.assertEqual(events, [])
        state, events, cache = kn.run(state, self.devs(recorded.items()), r1 + kn.LAG_S + 60, cache)
        self.assertIn("as forecast", events[0][2]["note"])

    def test_a_missed_number_is_not_seen_and_a_late_one_is_late(self):
        r1 = T + 72 * HOUR
        state, _events, cache = kn.run(None, self.devs(), T)
        # No switch on record: the forecast now has Mudroom's rotation as overdue and fires none.
        state, events, cache = kn.run(state, self.devs(), r1 + HOUR, cache)
        self.assertEqual(events, [])
        state, events, cache = kn.run(state, self.devs(), r1 + 3 * HOUR, cache)
        notes = [f["note"] for e, _s, f in events if e == "key_forecast_check"]
        self.assertTrue(any(n.startswith("91 was forecast for ") and "from Mudroom Monitor" in n for n in notes))
        rest = next(f for e, _s, f in events if e == "key_forecast_check" and f["name"] is None)
        self.assertEqual({r["name"] for r in rest["switches"]}, {"Hall Monitor", "Attic Monitor", "Cellar Monitor"})
        # It comes, two and a half hours late, and the mesh follows: late, not unforecast.
        late = r1 + 2.5 * HOUR
        recorded = {n: ((), (Switch(late + i, 90, 91),)) for i, n in enumerate(
            ("Mudroom Monitor", "Hall Monitor", "Attic Monitor", "Cellar Monitor"))}
        state, events, cache = kn.run(state, self.devs(recorded.items()), late + 2 * HOUR, cache)
        self.assertNotIn("key_switch_unforecast", [e for e, _s, _f in events])
        head = next(f for e, _s, f in events if e == "key_forecast_check" and f["name"] == "Mudroom Monitor")
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
        self.assertIn(" from Mudroom Monitor)", head["note"])
        self.assertEqual([e for e, _s, _f in events].count("key_switch_unforecast"), 1)


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
