"""keyforecast: the mesh forecast's rules, one small mesh per rule."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests  # noqa: F401  (the mDNS guard, installed on a direct run too: tests/no_lan)
from threadwatch import keyforecast as kf
from threadwatch.keyforecast import Device, Step, Stranded, forecast
from threadwatch.keyguard import GUARD_S, HOUR, ROTATION_S, Boot, Switch

OLD = ("old", "reported", "Air Monitor 2000 1.0.26")
CURRENT = ("current", "reported", "Bulb A19 5.1.45")
UNKNOWN = ("unknown", None, "not in the table")
T = 1_800_000_000.0
MIN = 60


def clear(name, stack, boot, key=90, **kw):
    """Booted on ``key`` and no +1 since: guard open, timer from the boot."""
    return Device(name, stack, (Boot(boot),), (Switch(boot + 1, None, key),), **kw)


def armed(name, stack, boot, at=None, key=90, **kw):
    """Took ``key`` as a +1 at ``at`` (at its boot by default). On the old
    logic that sets the flag and leaves the timer at the boot, so the guard
    opens at boot + 624 h; on the current logic it opens at ``at`` + 624 h."""
    at = boot + 5 if at is None else at
    return Device(name, stack, (Boot(boot),), (Switch(boot + 1, None, key - 1), Switch(at, key - 1, key)), **kw)


def steps(fc, until=None):
    return [(s.ts - T, s.name, s.old, s.new, s.why, s.number) for s in fc.steps if until is None or s.ts <= until]


class NumbersAndFollowersTest(unittest.TestCase):
    def test_two_numbers_from_two_units_then_a_calm_mesh(self):
        # Hall fires at boot + 672 h. Attic takes that as its first +1 since boot, which leaves its timer
        # running, so it starts the next number 38 min later. Cellar took its key at boot (flag set).
        mesh = [clear("Hall Monitor", OLD, T), clear("Attic Monitor", OLD, T + 38 * MIN),
                armed("Cellar Monitor", OLD, T + 10 * HOUR)]
        fc = forecast(mesh, T + 11 * HOUR)
        r1, r2 = ROTATION_S, ROTATION_S + 38 * MIN
        self.assertEqual(steps(fc), [
            (r1, "Hall Monitor", 90, 91, kf.OWN, True),
            (r1, "Attic Monitor", 90, 91, kf.FOLLOWED, False),
            (r1, "Cellar Monitor", 90, 91, kf.FOLLOWED, False),       # second +1: taken past 624 h, timer restarted
            (r2, "Attic Monitor", 91, 92, kf.OWN, True),
            (r2, "Hall Monitor", 91, 92, kf.FOLLOWED, False),          # flag set by its own firing: restarts, no 673 h
            (r1 + GUARD_S, "Cellar Monitor", 91, 92, kf.OPENED, False),
            (r2 + ROTATION_S, "Attic Monitor", 92, 93, kf.OWN, True),
            (r2 + ROTATION_S, "Hall Monitor", 92, 93, kf.FOLLOWED, False),
            (r1 + 2 * GUARD_S, "Cellar Monitor", 92, 93, kf.OPENED, False)])
        self.assertEqual([(s.new, s.name) for s in fc.numbers],
                         [(91, "Hall Monitor"), (92, "Attic Monitor"), (93, "Attic Monitor")])
        self.assertEqual(fc.firings, fc.numbers)
        # 93 came a clear guard time after 92 and has one after it: the forecast ends there.
        self.assertEqual((fc.start, fc.end), (T + 11 * HOUR, T + r2 + ROTATION_S + GUARD_S))
        self.assertEqual((fc.cut, fc.stranded), (False, ()))
        self.assertEqual(fc.keys(T + r2 - 1), {"Hall Monitor": 91, "Attic Monitor": 91, "Cellar Monitor": 91})
        self.assertEqual(fc.keys(T + r2), {"Hall Monitor": 92, "Attic Monitor": 92, "Cellar Monitor": 91})
        self.assertEqual(fc.guards["Cellar Monitor"].guard_open_at, T + 10 * HOUR + GUARD_S)
        self.assertEqual(fc.final["Cellar Monitor"].rotation_at, T + r1 + 2 * GUARD_S + ROTATION_S)

    def test_a_router_two_behind_jumps_at_once_and_on_the_old_logic_keeps_its_timer(self):
        # Loft refuses 91 (armed), so 92 finds it two behind: it jumps, its timer untouched, and it
        # starts 93 itself at boot + 672 h, which finds Hall two behind.
        mesh = [armed("Hall Monitor", OLD, T - 572 * HOUR), clear("Attic Monitor", OLD, T - 472 * HOUR),
                armed("Loft Monitor", OLD, T)]
        fc = forecast(mesh, T + HOUR, max_numbers=3)
        self.assertEqual(steps(fc), [
            (100 * HOUR, "Hall Monitor", 90, 91, kf.OWN, True),
            (100 * HOUR, "Attic Monitor", 90, 91, kf.FOLLOWED, False),
            (200 * HOUR, "Attic Monitor", 91, 92, kf.OWN, True),
            (200 * HOUR, "Loft Monitor", 90, 92, kf.JUMPED, False),
            (ROTATION_S, "Loft Monitor", 92, 93, kf.OWN, True),
            (ROTATION_S, "Hall Monitor", 91, 93, kf.JUMPED, False)])
        self.assertTrue(fc.cut)
        self.assertEqual(fc.final["Loft Monitor"].timer_start, T + ROTATION_S)       # its own firing, flag set
        self.assertEqual(fc.final["Hall Monitor"].rotation_at, T + 100 * HOUR + ROTATION_S)

    def test_a_unit_alone_with_its_flag_clear_fires_twice_an_hour_apart(self):
        fc = forecast([clear("Hall Monitor", OLD, T)], T + HOUR)
        self.assertEqual(steps(fc)[:3], [
            (ROTATION_S, "Hall Monitor", 90, 91, kf.OWN, True),
            (ROTATION_S + HOUR, "Hall Monitor", 91, 92, kf.OWN_SECOND, True),
            (2 * ROTATION_S + HOUR, "Hall Monitor", 92, 93, kf.OWN, True)])

    def test_a_neighbours_number_a_minute_before_a_units_672_h_mark_is_followed_by_the_units_own(self):
        # Simulated switches are exact: Attic's +1 from Hall is not read as Attic's own firing.
        mesh = [armed("Hall Monitor", OLD, T - MIN), clear("Attic Monitor", OLD, T)]
        fc = forecast(mesh, T + HOUR)
        self.assertEqual(steps(fc, T + ROTATION_S), [
            (ROTATION_S - MIN, "Hall Monitor", 90, 91, kf.OWN, True),
            (ROTATION_S - MIN, "Attic Monitor", 90, 91, kf.FOLLOWED, False),
            (ROTATION_S, "Attic Monitor", 91, 92, kf.OWN, True)])        # Hall restarted a minute ago: it refuses

    def test_a_rotation_due_at_the_instant_a_neighbours_number_arrives(self):
        mesh = [armed("Attic Monitor", OLD, T), clear("Hall Monitor", OLD, T)]
        fc = forecast(mesh, T + HOUR)
        self.assertEqual(steps(fc, T + ROTATION_S), [
            (ROTATION_S, "Attic Monitor", 90, 91, kf.OWN, True),
            (ROTATION_S, "Hall Monitor", 90, 91, kf.FOLLOWED, False),
            (ROTATION_S, "Hall Monitor", 91, 92, kf.OWN, True)])


class WhoHearsWhatTest(unittest.TestCase):
    def test_a_sleepy_child_hears_only_its_parent_and_a_mains_child_every_router(self):
        mesh = [armed("Hall Monitor", OLD, T - 572 * HOUR), armed("Cellar Monitor", OLD, T),
                clear("Cellar Door", OLD, T, parent="Cellar Monitor", sleepy=True),
                clear("Cellar Plug", OLD, T, parent="Cellar Monitor")]
        fc = forecast(mesh, T + HOUR)
        self.assertEqual(steps(fc, T + 101 * HOUR), [
            (100 * HOUR, "Hall Monitor", 90, 91, kf.OWN, True),
            (100 * HOUR, "Cellar Plug", 90, 91, kf.FOLLOWED, False)])
        # Cellar Monitor follows when its guard opens; only then does its sleepy child hear 91.
        self.assertEqual(steps(fc, T + GUARD_S)[2:], [
            (GUARD_S, "Cellar Monitor", 90, 91, kf.OPENED, False),
            (GUARD_S, "Cellar Door", 90, 91, kf.FOLLOWED, False)])

    def test_a_router_hears_its_own_child_fire_and_no_other_routers_child(self):
        # Shed Door's own rotation: its parent's guard is armed, so it fires alone and one ahead.
        mesh = [armed("Shed Monitor", OLD, T + 300 * HOUR), clear("Hall Monitor", OLD, T + 300 * HOUR),
                armed("Shed Door", OLD, T, parent="Shed Monitor", sleepy=True)]
        fc = forecast(mesh, T + 301 * HOUR)
        self.assertEqual(steps(fc, T + ROTATION_S + HOUR), [(ROTATION_S, "Shed Door", 90, 91, kf.OWN, True)])
        # With its parent's guard open the parent follows its child, and the other router its neighbour.
        mesh[0] = clear("Shed Monitor", OLD, T + 300 * HOUR)
        fc = forecast(mesh, T + 301 * HOUR)
        self.assertEqual(steps(fc, T + ROTATION_S + HOUR), [
            (ROTATION_S, "Shed Door", 90, 91, kf.OWN, True),
            (ROTATION_S, "Shed Monitor", 90, 91, kf.FOLLOWED, False),
            (ROTATION_S, "Hall Monitor", 90, 91, kf.FOLLOWED, False)])


class TwoBehindTest(unittest.TestCase):
    def mesh(self):
        """91 at T + 100 h and 92 at T + 200 h (as in the jump test), and three parents that reach 92 at
        once in their own ways, each with a sleepy child that refused 91."""
        return [armed("Hall Monitor", OLD, T - 572 * HOUR), clear("Attic Monitor", OLD, T - 472 * HOUR),
                armed("Loft Monitor", OLD, T),                                    # old logic: jumps 90 to 92
                Device("Deck TV", UNKNOWN, (), (Switch(T, None, 90),)),            # unknown: follows at once
                armed("Porch Bulb", CURRENT, T),                                  # current-logic router: the same
                armed("Loft Door", OLD, T, parent="Loft Monitor", sleepy=True),
                armed("Deck Sensor", CURRENT, T, parent="Deck TV", sleepy=True),
                armed("Porch Sensor", CURRENT, T, parent="Porch Bulb", sleepy=True),
                clear("Yard Sensor", CURRENT, T, parent="Deck TV", sleepy=True)]   # guard open: it keeps up

    def test_a_sleepy_child_whose_parent_is_two_ahead_is_two_behind_whatever_the_parents_stack(self):
        fc = forecast(self.mesh(), T + HOUR, max_numbers=2)
        self.assertEqual(steps(fc), [
            (100 * HOUR, "Hall Monitor", 90, 91, kf.OWN, True),
            (100 * HOUR, "Attic Monitor", 90, 91, kf.FOLLOWED, False),
            (100 * HOUR, "Deck TV", 90, 91, kf.AT_ONCE, False),
            (100 * HOUR, "Porch Bulb", 90, 91, kf.AT_ONCE, False),               # past its armed guard
            (100 * HOUR, "Yard Sensor", 90, 91, kf.FOLLOWED, False),
            (200 * HOUR, "Attic Monitor", 91, 92, kf.OWN, True),
            (200 * HOUR, "Deck TV", 91, 92, kf.AT_ONCE, False),
            (200 * HOUR, "Loft Monitor", 90, 92, kf.JUMPED, False),
            (200 * HOUR, "Porch Bulb", 91, 92, kf.AT_ONCE, False)])
        self.assertEqual(fc.stranded, (
            Stranded(T + 200 * HOUR, "Deck Sensor", 90, "Deck TV", 92),
            Stranded(T + 200 * HOUR, "Loft Door", 90, "Loft Monitor", 92),
            Stranded(T + 200 * HOUR, "Porch Sensor", 90, "Porch Bulb", 92)))
        self.assertEqual(fc.unknown, ("Deck TV",))

    def test_a_stranded_child_still_fires_its_own_rotation_and_can_be_stranded_again(self):
        fc = forecast(self.mesh(), T + HOUR, max_numbers=4)
        # Deck Sensor's own timer (from its +1 at T + 5 s) takes it to 91 under a parent on 93 by then.
        own = [s for s in fc.firings if s.name == "Deck Sensor"]
        self.assertEqual(own, [Step(T + 5 + ROTATION_S, "Deck Sensor", 90, 91, kf.OWN, False)])
        self.assertEqual([(x.ts, x.key, x.parent_key) for x in fc.stranded if x.name == "Deck Sensor"],
                         [(T + 200 * HOUR, 90, 92)])                 # one record while it stays two or more behind

    def test_a_child_already_two_behind_at_the_start(self):
        mesh = [clear("Hall Monitor", OLD, T, key=92),
                armed("Hall Door", CURRENT, T, parent="Hall Monitor", sleepy=True)]
        fc = forecast(mesh, T + HOUR)
        self.assertEqual(fc.stranded[0], Stranded(T + HOUR, "Hall Door", 90, "Hall Monitor", 92))


class FollowsAtOnceTest(unittest.TestCase):
    def test_a_current_logic_mains_child_keeps_to_its_guard_where_a_router_does_not(self):
        mesh = [armed("Hall Monitor", OLD, T - 572 * HOUR), armed("Porch Bulb", CURRENT, T),
                armed("Stair Bulb", CURRENT, T, parent="Porch Bulb")]
        fc = forecast(mesh, T + HOUR)
        self.assertEqual(steps(fc, T + 5 + GUARD_S), [
            (100 * HOUR, "Hall Monitor", 90, 91, kf.OWN, True),
            (100 * HOUR, "Porch Bulb", 90, 91, kf.AT_ONCE, False),
            (5 + GUARD_S, "Stair Bulb", 90, 91, kf.OPENED, False)])

    def test_a_guard_whose_state_is_not_known_is_taken_for_open(self):
        # First heard twenty days after its boot: a +1 in between would not be on record.
        late = Device("Attic Monitor", OLD, (Boot(T),), (Switch(T + 480 * HOUR, None, 90),))
        fc = forecast([armed("Hall Monitor", OLD, T - 100 * HOUR), late], T + 481 * HOUR)
        self.assertEqual(fc.guards["Attic Monitor"].guard, "unknown")
        self.assertEqual(steps(fc)[:2], [(572 * HOUR, "Hall Monitor", 90, 91, kf.OWN, True),
                                         (572 * HOUR, "Attic Monitor", 90, 91, kf.FOLLOWED, False)])


class BootsTest(unittest.TestCase):
    def mesh(self):
        """Hall starts 91 at R = T + 672 h. Deck reset on the top key at T + 400 h, so it takes 91 as its
        first +1 and starts 92 at R + 400 h. Yard Sensor armed its guard two days before R."""
        return [armed("Hall Monitor", OLD, T), clear("Deck Monitor", OLD, T + 400 * HOUR),
                Device("Deck TV", UNKNOWN, (), (Switch(T, None, 90),)),
                armed("Yard Sensor", CURRENT, T, at=T + GUARD_S, parent="Deck TV", sleepy=True)]

    def test_a_unit_that_reset_on_the_top_key_books_a_number_that_strands(self):
        fc = forecast(self.mesh(), T + 401 * HOUR)
        self.assertEqual([(s.ts - T, s.new, s.name) for s in fc.numbers][:2],
                         [(ROTATION_S, 91, "Hall Monitor"), (1072 * HOUR, 92, "Deck Monitor")])
        self.assertEqual(fc.stranded[0], Stranded(T + 1072 * HOUR, "Yard Sensor", 90, "Deck TV", 92))

    def test_a_power_cycle_just_before_the_rotation_moves_its_number_past_the_guard_time(self):
        fc = forecast(self.mesh(), T + 401 * HOUR, boots=[("Deck Monitor", T + 648 * HOUR)])
        self.assertEqual([(s.ts - T, s.new, s.name) for s in fc.numbers],
                         [(ROTATION_S, 91, "Hall Monitor"), (1320 * HOUR, 92, "Deck Monitor")])
        self.assertEqual((fc.stranded, fc.cut), ((), False))
        self.assertIn((2 * GUARD_S, "Yard Sensor", 90, 91, kf.OPENED, False), steps(fc))

    def test_a_power_cycle_just_after_the_rotation_books_a_number_an_hour_after_the_next_one(self):
        # Too late: Deck takes Hall's next number as its first +1 since the boot and fires its own an hour on.
        boot = T + ROTATION_S + HOUR
        fc = forecast(self.mesh(), T + 401 * HOUR, boots=[("Deck Monitor", boot)])
        self.assertEqual([(s.ts, s.new, s.name, s.why) for s in fc.numbers][1:3],
                         [(T + 2 * ROTATION_S, 92, "Hall Monitor", kf.OWN),
                          (boot + ROTATION_S, 93, "Deck Monitor", kf.OWN)])
        self.assertEqual(fc.stranded[0], Stranded(boot + ROTATION_S, "Yard Sensor", 91, "Deck TV", 93))

    def test_a_simulated_boot_minutes_after_a_switch_does_not_count_the_switch_as_taken_at_boot(self):
        # Deck takes 91 at R and is power-cycled 7 min later, inside the margin a recorded boot stamp is
        # given. Read as taken at that boot, the +1 would leave its flag set, and Hall's 92 at R + 672 h
        # would restart its timer. Taken exactly, the boot cleared the flag: 92 is its first +1 since,
        # its timer runs on, and it starts 93 seven minutes after 92.
        boot = T + ROTATION_S + 7 * MIN
        fc = forecast(self.mesh(), T + 401 * HOUR, boots=[("Deck Monitor", boot)])
        self.assertEqual([(s.ts, s.new, s.why, s.number) for s in fc.steps if s.name == "Deck Monitor"][:3],
                         [(T + ROTATION_S, 91, kf.FOLLOWED, False), (T + 2 * ROTATION_S, 92, kf.FOLLOWED, False),
                          (boot + ROTATION_S, 93, kf.OWN, True)])
        self.assertEqual(fc.final["Deck Monitor"].boot, Boot(boot))

    def test_a_child_attaches_at_its_parents_key_at_boot_whatever_the_jump(self):
        # The battery pull: lifted to its parent's key at that moment; an exact +1 re-arms the guard.
        mesh = [armed("Hall Monitor", OLD, T - 600 * HOUR, key=92), armed("Attic Monitor", OLD, T - 600 * HOUR, key=92),
                armed("Hall Door", CURRENT, T, key=90, parent="Hall Monitor", sleepy=True),
                armed("Attic Door", CURRENT, T, key=91, parent="Attic Monitor", sleepy=True)]
        fc = forecast(mesh, T + HOUR, boots=[("Hall Door", T + 2 * HOUR), ("Attic Door", T + 3 * HOUR)])
        self.assertEqual(steps(fc, T + 4 * HOUR), [(2 * HOUR, "Hall Door", 90, 92, kf.AT_BOOT, False),
                                                    (3 * HOUR, "Attic Door", 91, 92, kf.AT_BOOT, False)])
        self.assertEqual(fc.stranded, (Stranded(T + HOUR, "Hall Door", 90, "Hall Monitor", 92),))
        # 93 at T + 72 h finds Hall Door's guard open (a jump of two arms nothing) and Attic Door's armed.
        self.assertCountEqual([(s.name, s.why) for s in fc.steps if s.ts == T + 72 * HOUR],
                              [("Attic Monitor", kf.OWN), ("Hall Monitor", kf.FOLLOWED), ("Hall Door", kf.FOLLOWED)])
        self.assertIn((3 * HOUR + GUARD_S, "Attic Door", 92, 93, kf.OPENED, False), steps(fc))

    def test_a_router_that_boots_one_behind_takes_the_key_at_boot(self):
        mesh = [clear("Hall Monitor", OLD, T, key=91), armed("Attic Monitor", OLD, T, key=90)]
        fc = forecast(mesh, T + HOUR, boots=[("Attic Monitor", T + 2 * HOUR), ("Nobody", T + 2 * HOUR)])
        self.assertEqual(steps(fc)[0], (2 * HOUR, "Attic Monitor", 90, 91, kf.FOLLOWED, False))
        # A +1 at boot: flag set, timer from the boot, so no second firing and the guard opens at 624 h.
        self.assertEqual([(s.ts - T, s.name, s.why) for s in fc.firings][:2],
                         [(ROTATION_S, "Hall Monitor", kf.OWN), (ROTATION_S + HOUR, "Hall Monitor", kf.OWN_SECOND)])


class LimitsTest(unittest.TestCase):
    def test_a_rotation_overdue_at_the_start_is_listed_and_not_fired(self):
        mesh = [clear("Hall Monitor", OLD, T), clear("Attic Monitor", OLD, T + 100 * HOUR)]
        fc = forecast(mesh, T + ROTATION_S + 2 * HOUR)          # Hall's 672 h and 673 h marks have passed
        self.assertEqual(fc.overdue, (("Hall Monitor", T + ROTATION_S),))
        self.assertEqual(steps(fc)[:2], [(100 * HOUR + ROTATION_S, "Attic Monitor", 90, 91, kf.OWN, True),
                                         (100 * HOUR + ROTATION_S, "Hall Monitor", 90, 91, kf.FOLLOWED, False)])
        self.assertNotIn("Hall Monitor", [s.name for s in fc.firings if s.ts < T + 2 * ROTATION_S])

    def test_nothing_is_forecast_for_an_unknown_stack_or_a_device_never_heard(self):
        mesh = [Device("Deck TV", UNKNOWN, (), (Switch(T, None, 90),)), Device("Spare Plug", OLD),
                Device("Deck Sensor", UNKNOWN, (), (Switch(T, None, 90),), parent="Deck TV", sleepy=True)]
        fc = forecast(mesh, T + HOUR)
        self.assertEqual((fc.steps, fc.stranded, fc.end, fc.cut), ((), (), T + HOUR, False))
        self.assertEqual(fc.unknown, ("Deck Sensor", "Deck TV", "Spare Plug"))
        self.assertEqual(fc.keys(T + HOUR), {"Deck TV": 90, "Deck Sensor": 90})

    def test_a_chain_that_never_calms_is_cut(self):
        # Three units, each refusing the number before and jumping at the next with its timer running:
        # numbers 100 h, 100 h and 472 h apart, round and round, never a clear guard time between two.
        mesh = [armed("Hall Monitor", OLD, T - 572 * HOUR), clear("Attic Monitor", OLD, T - 472 * HOUR),
                armed("Loft Monitor", OLD, T)]
        fc = forecast(mesh, T + HOUR)
        self.assertEqual((len(fc.numbers), fc.cut), (kf.MAX_NUMBERS, True))
        self.assertEqual([round((b.ts - a.ts) / HOUR) for a, b in zip(fc.numbers, fc.numbers[1:], strict=False)],
                         [100, 472, 100, 100, 472, 100, 100])


if __name__ == "__main__":
    unittest.main()
