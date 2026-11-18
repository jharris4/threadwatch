"""keyforecast, checked from the outside: replay tests written from the key
guard plan's Model and Phase 5a sections and the forecast's interface, not
from keyforecast.py.

The rules under test, as the interface states them:
- a sleepy child hears only its parent; a router or a mains child hears
  every router and every mains child, and its own children;
- one behind what it hears, a device follows at once if its guard is open
  (an "unknown" guard counts as open), otherwise when its guard opens;
- an unknown stack, and a current-logic router, follow every number at
  once; a current-logic child keeps to its guard;
- a router-capable device two or more behind takes the jump at once (on the
  old logic the jump leaves its timer running, so it can start the next
  number itself); a sleepy child two or more behind stays, is recorded as
  stranded once, and its own timer still fires;
- a boot in ``boots`` clears the guard and restarts the timer at exactly
  that time; a child then takes its parent's key whatever the jump, and a
  router follows by the ordinary rules;
- an own rotation already due before ``now`` is listed as overdue, not
  fired;
- after each new number it steps on for 624 h, and it ends only when a
  number that came more than 624 h after the one before has had its own
  624 h with no further number;
- steps that share one instant are compared as a set.

Also keyguard.after against keyguard.derive, where the two could disagree.

All times, keys and labels are made up.
"""

import sys
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests  # noqa: F401  (the mDNS guard, installed on a direct run too: tests/no_lan)
from threadwatch.keyforecast import (
    AT_BOOT,
    AT_ONCE,
    FOLLOWED,
    JUMPED,
    OPENED,
    OWN,
    OWN_SECOND,
    Device,
    forecast,
)
from threadwatch.keyguard import GUARD_S, HOUR, ROTATION_S, Boot, Switch, after, derive

OLD = ("old", "reported", "test: old KeyManager")
CUR = ("current", "reported", "test: current KeyManager")
UNK = ("unknown", None, "test: no stack reported")
T0 = 1_900_000_000              # an arbitrary epoch, nowhere near this house's history
FIRST = T0 - 900 * HOUR         # where every device's key history starts


def h(n):
    return T0 + n * HOUR


def mins(n):
    return n * 60


# Device builders. Each gives one plain guard state at T0.

def old_set(name, key, timer, parent=None, sleepy=False):
    """Old logic, flag set, timer at ``timer``: it came back one behind at a boot
    then. Guard opens at timer + 624 h, rotation at timer + 672 h."""
    return Device(name, OLD, boots=(Boot(timer),),
                  switches=(Switch(FIRST, None, key - 1), Switch(timer + 30, key - 1, key)),
                  parent=parent, sleepy=sleepy)


def old_clear(name, key, boot, parent=None, sleepy=False):
    """Old logic, flag clear: booted on ``key`` and no +1 since. Guard open,
    rotation at boot + 672 h and again an hour later."""
    return Device(name, OLD, boots=(Boot(boot),), switches=(Switch(FIRST, None, key),),
                  parent=parent, sleepy=sleepy)


def cur_armed(name, key, plus_one, parent=None, sleepy=False):
    """Current logic, guard armed by a +1 at ``plus_one``: opens at + 624 h,
    rotation at + 672 h."""
    return Device(name, CUR, boots=(Boot(plus_one - 50 * HOUR),),
                  switches=(Switch(FIRST, None, key - 1), Switch(plus_one, key - 1, key)),
                  parent=parent, sleepy=sleepy)


def cur_open(name, key, boot, parent=None, sleepy=False):
    """Current logic, guard clear: booted on ``key``. Rotation at boot + 672 h."""
    return Device(name, CUR, boots=(Boot(boot),), switches=(Switch(FIRST, None, key),),
                  parent=parent, sleepy=sleepy)


def unknown(name, key, parent=None, sleepy=False):
    return Device(name, UNK, switches=(Switch(FIRST, None, key),), parent=parent, sleepy=sleepy)


def rows(steps):
    return {(s.ts, s.name, s.old, s.new, s.why) for s in steps}


def upto(fc, t):
    return rows(s for s in fc.steps if s.ts <= t)


def of(fc, name):
    return [(s.ts, s.old, s.new, s.why) for s in fc.steps if s.name == name]


def numbers(fc):
    return [(s.ts, s.name, s.old, s.new) for s in fc.numbers]


def stranded(fc, until=None):
    return [(r.ts, r.name, r.key, r.parent, r.parent_key) for r in fc.stranded if until is None or r.ts <= until]


def state(g):
    return (g.key, g.boot, g.flag, g.flag_set_by, g.timer_start, g.timer_set_by, g.guard, g.guard_open_at,
            g.rotation_at, g.second_rotation_at, g.fired)


class Checks(unittest.TestCase):
    def assert_consistent(self, fc, now):
        """What every forecast must hold whatever the mesh."""
        self.assertEqual(fc.start, now)
        ts = [s.ts for s in fc.steps]
        self.assertEqual(ts, sorted(ts))
        self.assertTrue(all(now <= t <= fc.end for t in ts))
        self.assertEqual(tuple(fc.numbers), tuple(s for s in fc.steps if s.number))
        self.assertEqual(tuple(fc.firings), tuple(s for s in fc.steps if s.why in (OWN, OWN_SECOND)))
        for s in fc.steps:
            self.assertGreater(s.new, s.old)
        keys = [(r.ts, r.name) for r in fc.stranded]
        self.assertEqual(keys, sorted(keys))
        for r in fc.stranded:
            self.assertGreaterEqual(r.parent_key - r.key, 2)
        # numbers climb by one each, each above every key held at the start
        top = max(g.key for g in fc.guards.values() if g.key is not None)
        for n in fc.numbers:
            self.assertEqual(n.new, top + 1)
            top = n.new


# ---------------------------------------------------------------------------
# One rule at a time


class WhoHearsTest(Checks):
    def test_a_sleepy_child_hears_only_its_parent_and_a_mains_child_hears_every_router(self):
        mesh = [old_set("Barn Monitor", 50, h(-670)),          # fires 51 at h(2)
                old_set("Barn Plug", 50, h(-100)),             # guard closed until h(524)
                cur_open("Barn Door", 50, h(-50), parent="Barn Plug", sleepy=True),
                old_clear("Barn Fan", 50, h(-60), parent="Barn Plug")]
        fc = forecast(mesh, T0)
        self.assert_consistent(fc, T0)
        self.assertEqual(upto(fc, h(600)), {
            (h(2), "Barn Monitor", 50, 51, OWN),
            (h(2), "Barn Fan", 50, 51, FOLLOWED),          # hears the other router, not only its parent
            (h(524), "Barn Plug", 50, 51, OPENED),
            (h(524), "Barn Door", 50, 51, FOLLOWED),       # waited for its parent, guard open all along
        })
        self.assertEqual(fc.keys(h(3))["Barn Door"], 50)

    def test_a_parent_hears_its_sleepy_childs_own_rotation(self):
        mesh = [old_set("Mill Contact", 50, h(-671), parent="Mill Monitor", sleepy=True),   # fires at h(1)
                old_clear("Mill Monitor", 50, h(-100)),
                cur_open("Mill Light", 50, h(-200)),
                old_set("Mill Plug", 50, h(-10)),                                          # guard closed
                cur_open("Mill Leak", 50, h(-300), parent="Mill Plug", sleepy=True)]       # own rotation h(372)
        fc = forecast(mesh, T0)
        self.assert_consistent(fc, T0)
        self.assertEqual(upto(fc, h(400)), {
            (h(1), "Mill Contact", 50, 51, OWN),
            (h(1), "Mill Monitor", 50, 51, FOLLOWED),
            (h(1), "Mill Light", 50, 51, AT_ONCE),
            (h(372), "Mill Leak", 50, 51, OWN),           # never heard the other child
        })
        self.assertEqual(numbers(fc)[0], (h(1), "Mill Contact", 50, 51))   # a sleepy child can start a number


class FollowTest(Checks):
    def test_a_guard_of_unknown_state_is_taken_for_open(self):
        # First key heard three hours after the boot: a +1 in between cannot be ruled out.
        plug = Device("Pond Plug", OLD, boots=(Boot(h(-100)),), switches=(Switch(h(-97), None, 50),))
        door = Device("Pond Door", OLD, boots=(Boot(h(-90)),), switches=(Switch(h(-85), None, 50),),
                      parent="Pond Monitor", sleepy=True)
        self.assertEqual(derive(plug.stack, plug.boots, plug.switches).guard, "unknown")
        self.assertEqual(derive(door.stack, door.boots, door.switches).guard, "unknown")
        fc = forecast([old_set("Pond Monitor", 50, h(-670)), plug, door], T0)
        self.assert_consistent(fc, T0)
        self.assertEqual(upto(fc, h(500)), {
            (h(2), "Pond Monitor", 50, 51, OWN),
            (h(2), "Pond Plug", 50, 51, FOLLOWED),
            (h(2), "Pond Door", 50, 51, FOLLOWED),
        })

    def test_a_guard_opened_before_now_is_open(self):
        # Its guard opened 76 h before the start and its rotation is overdue; it follows at once.
        mesh = [old_set("Shed Plug", 50, h(-572)), old_set("Shed Monitor", 50, h(-700))]
        fc = forecast(mesh, T0)
        self.assertIn((h(100), "Shed Monitor", 50, 51, FOLLOWED), rows(fc.steps))

    def test_a_current_logic_router_follows_past_its_armed_guard(self):
        mesh = [old_set("Hill Monitor", 50, h(-670)), cur_armed("Hill Light", 50, h(-10))]
        fc = forecast(mesh, T0)
        self.assertIn((h(2), "Hill Light", 50, 51, AT_ONCE), rows(fc.steps))

    def test_an_unknown_stack_child_follows_every_number_at_once(self):
        mesh = [old_clear("Loft Monitor", 50, h(-670)), unknown("Loft Hub", 50),
                unknown("Loft Remote", 50, parent="Loft Hub", sleepy=True)]
        fc = forecast(mesh, T0)
        self.assertLessEqual({(h(2), "Loft Remote", 50, 51, AT_ONCE), (h(3), "Loft Remote", 51, 52, AT_ONCE)},
                             rows(fc.steps))
        self.assertEqual(stranded(fc), [])


class MainsChildTest(Checks):
    """A current-logic child keeps to its guard; router-capable, it jumps when
    two behind. An old-logic jump leaves the timer, so the jumper starts the
    next number itself."""

    def test_mains_children_keep_to_the_guard_and_jump(self):
        mesh = [old_clear("Shop Monitor", 50, h(-670)),                                # 51 at h(2), 52 at h(3)
                cur_open("Shop Light", 50, h(-100)),
                cur_armed("Shop Lamp", 50, h(-200), parent="Shop Light"),             # guard until h(424)
                cur_armed("Shop Lock", 50, h(-150), parent="Shop Light", sleepy=True),  # guard until h(474)
                old_set("Shop Sensor", 50, h(-400), parent="Shop Light")]             # guard h(224), rotation h(272)
        fc = forecast(mesh, T0)
        self.assert_consistent(fc, T0)
        self.assertEqual(upto(fc, h(900)), {
            (h(2), "Shop Monitor", 50, 51, OWN),
            (h(2), "Shop Light", 50, 51, AT_ONCE),
            (h(3), "Shop Monitor", 51, 52, OWN_SECOND),
            (h(3), "Shop Light", 51, 52, AT_ONCE),
            (h(3), "Shop Lamp", 50, 52, JUMPED),
            (h(3), "Shop Sensor", 50, 52, JUMPED),
            (h(272), "Shop Sensor", 52, 53, OWN),          # its timer survived the jump
            (h(272), "Shop Light", 52, 53, AT_ONCE),
            (h(424), "Shop Lamp", 52, 53, OPENED),         # the jump left its guard armed
            (h(522), "Shop Lock", 50, 51, OWN),            # stranded, its own timer still runs
            (h(627), "Shop Monitor", 52, 53, OPENED),
        })
        self.assertEqual(numbers(fc)[:3], [(h(2), "Shop Monitor", 50, 51), (h(3), "Shop Monitor", 51, 52),
                                           (h(272), "Shop Sensor", 52, 53)])
        # Further behind at 53 and after its own firing, but one record only.
        self.assertEqual(stranded(fc, h(900)), [(h(3), "Shop Lock", 50, "Shop Light", 52)])


class SecondFiringTest(Checks):
    """Old logic with the flag clear: its own rotation does not restart the
    timer, so it fires again an hour later."""

    def mesh(self):
        return [old_clear("Loft Monitor", 50, h(-670)),
                unknown("Loft Hub", 50),
                cur_armed("Loft Lock", 50, h(-100), parent="Loft Hub", sleepy=True),   # guard until h(524)
                unknown("Loft Remote", 50, parent="Loft Hub", sleepy=True)]

    def test_two_numbers_an_hour_apart_and_a_child_left_two_behind(self):
        fc = forecast(self.mesh(), T0)
        self.assert_consistent(fc, T0)
        self.assertEqual(rows(fc.steps), {
            (h(2), "Loft Monitor", 50, 51, OWN),
            (h(2), "Loft Hub", 50, 51, AT_ONCE),
            (h(2), "Loft Remote", 50, 51, AT_ONCE),
            (h(3), "Loft Monitor", 51, 52, OWN_SECOND),
            (h(3), "Loft Hub", 51, 52, AT_ONCE),
            (h(3), "Loft Remote", 51, 52, AT_ONCE),
            (h(572), "Loft Lock", 50, 51, OWN),            # stranded, fires its own +1
            (h(675), "Loft Monitor", 52, 53, OWN),         # the second firing restarted the timer
            (h(675), "Loft Hub", 52, 53, AT_ONCE),
            (h(675), "Loft Remote", 52, 53, AT_ONCE),
            (h(1244), "Loft Lock", 51, 52, OWN),
        })
        self.assertEqual(numbers(fc), [(h(2), "Loft Monitor", 50, 51), (h(3), "Loft Monitor", 51, 52),
                                       (h(675), "Loft Monitor", 52, 53)])
        self.assertEqual([(s.ts, s.name) for s in fc.firings],
                         [(h(2), "Loft Monitor"), (h(3), "Loft Monitor"), (h(572), "Loft Lock"),
                          (h(675), "Loft Monitor"), (h(1244), "Loft Lock")])
        # One behind after its own firing, then two behind again: a second record.
        self.assertEqual(stranded(fc), [(h(3), "Loft Lock", 50, "Loft Hub", 52),
                                        (h(675), "Loft Lock", 51, "Loft Hub", 53)])
        self.assertEqual(tuple(fc.unknown), ("Loft Hub", "Loft Remote"))
        self.assertEqual(tuple(fc.overdue), ())
        # 53 came 672 h after 52 and had 624 h with nothing after it.
        self.assertEqual(fc.end, h(675) + GUARD_S)
        self.assertFalse(fc.cut)

    def test_keys_at_an_instant_include_its_steps(self):
        fc = forecast(self.mesh(), T0)
        start = {"Loft Monitor": 50, "Loft Hub": 50, "Loft Lock": 50, "Loft Remote": 50}
        self.assertEqual(fc.keys(T0), start)
        self.assertEqual(fc.keys(h(2) - 1), start)
        self.assertEqual(fc.keys(h(2)), {"Loft Monitor": 51, "Loft Hub": 51, "Loft Lock": 50, "Loft Remote": 51})
        self.assertEqual(fc.keys(h(600)), {"Loft Monitor": 52, "Loft Hub": 52, "Loft Lock": 51, "Loft Remote": 52})

    def test_guards_and_final(self):
        mesh = self.mesh()
        fc = forecast(mesh, T0)
        for d in mesh:
            self.assertEqual(fc.guards[d.name], derive(d.stack, d.boots, d.switches))
        loft, lock = mesh[0], mesh[2]
        g = derive(loft.stack, loft.boots, loft.switches)
        for s in (Switch(h(2), 50, 51), Switch(h(3), 51, 52), Switch(h(675), 52, 53)):
            g = after(g, s, own=True)
        want = (53, True, h(675), "until", h(675) + GUARD_S, h(675) + ROTATION_S, None, False)
        self.assertEqual(state(g)[:1] + state(g)[2:3] + state(g)[4:5] + state(g)[6:], want)
        self.assertEqual(state(fc.final["Loft Monitor"]), state(g))
        g = derive(lock.stack, lock.boots, lock.switches)
        for s in (Switch(h(572), 50, 51), Switch(h(1244), 51, 52)):
            g = after(g, s, own=True)
        self.assertEqual(state(fc.final["Loft Lock"]), state(g))
        self.assertEqual(fc.final["Loft Lock"].rotation_at, h(1244) + ROTATION_S)
        self.assertEqual(fc.final["Loft Hub"].key, 53)

    def test_it_is_cut_at_max_numbers(self):
        fc = forecast(self.mesh(), T0, max_numbers=2)
        self.assertTrue(fc.cut)
        self.assertEqual(numbers(fc), [(h(2), "Loft Monitor", 50, 51), (h(3), "Loft Monitor", 51, 52)])
        self.assertTrue(all(s.ts <= fc.end for s in fc.steps))

    def test_a_plus_one_inside_the_hour_cancels_the_second_firing(self):
        mesh = [old_clear("Mesa Monitor", 50, h(-670)),                # 51 at h(2)
                old_clear("Mesa Sensor", 50, h(-670) + mins(30))]      # follows, then 52 at h(2) + 30 min
        fc = forecast(mesh, T0)
        self.assert_consistent(fc, T0)
        self.assertEqual(upto(fc, h(600)), {
            (h(2), "Mesa Monitor", 50, 51, OWN),
            (h(2), "Mesa Sensor", 50, 51, FOLLOWED),
            (h(2) + mins(30), "Mesa Sensor", 51, 52, OWN),
            (h(2) + mins(30), "Mesa Monitor", 51, 52, FOLLOWED),
        })


class BootTest(Checks):
    def test_a_boot_is_taken_at_exactly_its_time(self):
        # It takes 51 five minutes before the boot; the boot clears that flag,
        # so its own rotation from the boot is a first +1 and fires twice.
        tb = h(24) + 300
        mesh = [unknown("Yard Hub", 51), old_set("Yard Monitor", 50, h(-600))]   # guard opens h(24)
        fc = forecast(mesh, T0, boots=[("Yard Monitor", tb)])
        self.assert_consistent(fc, T0)
        self.assertEqual(of(fc, "Yard Monitor")[:3], [(h(24), 50, 51, OPENED),
                                                      (tb + ROTATION_S, 51, 52, OWN),
                                                      (tb + ROTATION_S + HOUR, 52, 53, OWN_SECOND)])

    def test_the_first_number_is_stepped_however_far_off(self):
        fc = forecast([old_set("Well Monitor", 50, h(-10)), unknown("Well Hub", 50)], T0)
        self.assertEqual(numbers(fc)[0], (h(662), "Well Monitor", 50, 51))
        self.assertIn((h(662), "Well Hub", 50, 51, AT_ONCE), rows(fc.steps))


class OverdueTest(Checks):
    def test_a_rotation_due_before_now_is_listed_not_fired(self):
        light = Device("Shed Light", CUR, boots=(Boot(h(-700)),),
                       switches=(Switch(FIRST, None, 49), Switch(h(-690), 49, 50)))     # due h(-18)
        mesh = [light, old_set("Shed Plug", 50, h(-572)), old_set("Shed Monitor", 50, h(-700))]   # due h(-28)
        fc = forecast(mesh, T0)
        self.assert_consistent(fc, T0)
        self.assertEqual(set(fc.overdue), {("Shed Light", h(-18)), ("Shed Monitor", h(-28))})
        self.assertEqual(upto(fc, h(700)), {
            (h(100), "Shed Plug", 50, 51, OWN),
            (h(100), "Shed Light", 50, 51, AT_ONCE),
            (h(100), "Shed Monitor", 50, 51, FOLLOWED),
        })


class UnknownTest(Checks):
    def test_unknown_lists_unknown_stacks_and_devices_with_no_key(self):
        mesh = [old_set("Vault Monitor", 50, h(-670)), unknown("Vault Hub", 50),
                Device("Vault Spare", CUR, boots=(Boot(h(-5)),))]
        fc = forecast(mesh, T0)
        self.assertEqual(tuple(fc.unknown), ("Vault Hub", "Vault Spare"))
        self.assertIn((h(2), "Vault Hub", 50, 51, AT_ONCE), rows(fc.steps))
        self.assertFalse([s for s in fc.steps if s.name == "Vault Spare"])


# ---------------------------------------------------------------------------
# Whole stories, made up


class OneMorningTwoNumbersTest(Checks):
    """A reboot batch: one unit came back one behind (flag set), another 38
    minutes later on the top key (flag clear). The first fires at its boot +
    672 h; the second takes that as its first +1 since boot, keeps its timer,
    and fires the next number 38 minutes later. Followers of the first refuse
    the second until their guards open; a sleepy child under the first fires
    alone and one ahead of its parent."""

    NOW = h(300)

    def mesh(self):
        return [
            old_set("Early Monitor", 50, T0),
            old_clear("Booted Monitor", 50, T0 + mins(38)),
            old_clear("Slow Monitor", 50, h(200)),
            cur_open("Strip Light", 50, h(5)),
            cur_armed("Strip Lock", 50, h(20) + 40, parent="Strip Light", sleepy=True),
            old_clear("Early Contact", 50, h(1), parent="Early Monitor", sleepy=True),
            old_set("Booted Motion", 50, h(3), parent="Booted Monitor", sleepy=True),
            unknown("Box Hub", 50),
            cur_open("Box Leak", 50, h(30), parent="Box Hub", sleepy=True),
        ]

    def test_the_pair_of_numbers(self):
        fc = forecast(self.mesh(), self.NOW)
        self.assert_consistent(fc, self.NOW)
        t1, t2 = h(672), h(672) + mins(38)
        self.assertEqual(upto(fc, h(1300)), {
            (t1, "Early Monitor", 50, 51, OWN),
            (t1, "Booted Monitor", 50, 51, FOLLOWED),
            (t1, "Slow Monitor", 50, 51, FOLLOWED),
            (t1, "Strip Light", 50, 51, AT_ONCE),
            (t1, "Box Hub", 50, 51, AT_ONCE),
            (t1, "Early Contact", 50, 51, FOLLOWED),
            (t1, "Booted Motion", 50, 51, FOLLOWED),
            (t1, "Strip Lock", 50, 51, FOLLOWED),
            (t1, "Box Leak", 50, 51, FOLLOWED),
            (t2, "Booted Monitor", 51, 52, OWN),
            (t2, "Strip Light", 51, 52, AT_ONCE),
            (t2, "Box Hub", 51, 52, AT_ONCE),
            (h(673), "Early Contact", 51, 52, OWN),        # alone and one ahead of its parent
            (h(824), "Slow Monitor", 51, 52, OPENED),      # its flag was clear for 51, so its guard runs from boot
            (h(1296), "Early Monitor", 51, 52, OPENED),
            (h(1296), "Booted Motion", 51, 52, OPENED),
            (h(1296), "Strip Lock", 51, 52, OPENED),
            (h(1296), "Box Leak", 51, 52, OPENED),
        })
        self.assertEqual(numbers(fc)[:2], [(t1, "Early Monitor", 50, 51), (t2, "Booted Monitor", 51, 52)])
        self.assertEqual(stranded(fc, h(1300)), [])

    def test_a_clear_stretch_after_the_pair_does_not_end_it(self):
        # 53 comes 672 h after 52 (two units at one instant); nothing follows it within 624 h.
        fc = forecast(self.mesh(), self.NOW)
        self.assertEqual(len(fc.numbers), 3)
        self.assertEqual((fc.numbers[2].ts, fc.numbers[2].new), (h(1344) + mins(38), 53))
        self.assertIn(fc.numbers[2].name, ("Booted Monitor", "Strip Light"))
        self.assertEqual(fc.end, h(1344) + mins(38) + GUARD_S)
        self.assertFalse(fc.cut)


class BookedNumberTest(Checks):
    """A unit reset on the top key books a number 672 h later; a router two
    behind jumps and, keeping its timer, starts the number after; sleepy
    children end up two behind under an unknown-stack parent, a current-logic
    router and an old-logic router. Then the remedies."""

    def mesh(self):
        return [
            old_set("First Monitor", 60, h(-336)),        # fires 61 at h(336)
            old_clear("Reset Monitor", 60, h(-144)),      # reset on the top key: fires at h(528)
            old_set("Late Monitor", 60, h(-24)),          # guard opens h(600), rotation h(648)
            old_set("Behind Monitor", 59, h(-340)),       # one behind, guard opens h(284)
            old_set("Old Child Contact", 59, h(-339), parent="Behind Monitor", sleepy=True),
            cur_armed("New Child Motion", 59, h(-337), parent="Behind Monitor", sleepy=True),
            unknown("Hub Unknown", 60),
            cur_armed("Hub Lock", 59, h(-330), parent="Hub Unknown", sleepy=True),
            cur_armed("Hub Smoke", 60, h(-300), parent="Hub Unknown", sleepy=True),
            old_clear("Hub Monitor", 60, h(-70), parent="Hub Unknown"),   # mains child, reset on the top key
            cur_armed("Lamp", 60, h(-320)),
            old_set("Lamp Button", 59, h(-338), parent="Lamp", sleepy=True),
        ]

    def test_no_action(self):
        fc = forecast(self.mesh(), T0)
        self.assert_consistent(fc, T0)
        self.assertEqual(upto(fc, h(1000)), {
            (h(284), "Behind Monitor", 59, 60, OPENED),
            (h(285), "Old Child Contact", 59, 60, OPENED),
            (h(286), "Lamp Button", 59, 60, OPENED),
            (h(287), "New Child Motion", 59, 60, OPENED),
            (h(294), "Hub Lock", 59, 60, OPENED),
            (h(336), "First Monitor", 60, 61, OWN),
            (h(336), "Reset Monitor", 60, 61, FOLLOWED),
            (h(336), "Hub Unknown", 60, 61, AT_ONCE),
            (h(336), "Lamp", 60, 61, AT_ONCE),
            (h(336), "Hub Monitor", 60, 61, FOLLOWED),
            (h(336), "Hub Smoke", 60, 61, FOLLOWED),
            (h(528), "Reset Monitor", 61, 62, OWN),            # boot + 672 h: the booked number
            (h(528), "Late Monitor", 60, 62, JUMPED),
            (h(528), "Behind Monitor", 60, 62, JUMPED),
            (h(528), "Hub Unknown", 61, 62, AT_ONCE),
            (h(528), "Lamp", 61, 62, AT_ONCE),
            (h(554), "Hub Monitor", 61, 62, OPENED),           # a guard opening between two numbers
            (h(648), "Late Monitor", 62, 63, OWN),             # its timer survived the jump
            (h(648), "First Monitor", 61, 63, JUMPED),
            (h(648), "Hub Unknown", 62, 63, AT_ONCE),
            (h(648), "Lamp", 62, 63, AT_ONCE),
            (h(908), "Behind Monitor", 62, 63, OPENED),
            (h(957), "Old Child Contact", 60, 61, OWN),
            (h(958), "Lamp Button", 60, 61, OWN),
            (h(959), "New Child Motion", 60, 61, OWN),
            (h(966), "Hub Lock", 60, 61, OWN),
        })
        self.assertEqual(numbers(fc)[:3], [(h(336), "First Monitor", 60, 61), (h(528), "Reset Monitor", 61, 62),
                                           (h(648), "Late Monitor", 62, 63)])
        self.assertEqual(stranded(fc, h(1000)), [
            (h(528), "Hub Lock", 60, "Hub Unknown", 62),
            (h(528), "Lamp Button", 60, "Lamp", 62),
            (h(528), "New Child Motion", 60, "Behind Monitor", 62),
            (h(528), "Old Child Contact", 60, "Behind Monitor", 62),
            (h(648), "Hub Smoke", 61, "Hub Unknown", 63),
        ])
        self.assertEqual(tuple(fc.unknown), ("Hub Unknown",))
        for d in self.mesh():
            self.assertEqual(fc.guards[d.name], derive(d.stack, d.boots, d.switches))

    def test_both_booked_units_power_cycled_shortly_before_the_next_number(self):
        boots = [("Reset Monitor", h(300)), ("Hub Monitor", h(310))]
        fc = forecast(self.mesh(), T0, boots=boots)
        self.assert_consistent(fc, T0)
        self.assertEqual(rows(fc.steps), {
            (h(284), "Behind Monitor", 59, 60, OPENED),
            (h(285), "Old Child Contact", 59, 60, OPENED),
            (h(286), "Lamp Button", 59, 60, OPENED),
            (h(287), "New Child Motion", 59, 60, OPENED),
            (h(294), "Hub Lock", 59, 60, OPENED),
            (h(336), "First Monitor", 60, 61, OWN),
            (h(336), "Reset Monitor", 60, 61, FOLLOWED),
            (h(336), "Hub Unknown", 60, 61, AT_ONCE),
            (h(336), "Lamp", 60, 61, AT_ONCE),
            (h(336), "Hub Monitor", 60, 61, FOLLOWED),
            (h(336), "Hub Smoke", 60, 61, FOLLOWED),
            (h(600), "Late Monitor", 60, 61, OPENED),
            (h(908), "Behind Monitor", 60, 61, OPENED),
            (h(909), "Old Child Contact", 60, 61, OPENED),
            (h(910), "Lamp Button", 60, 61, OPENED),
            (h(911), "New Child Motion", 60, 61, OPENED),
            (h(918), "Hub Lock", 60, 61, OPENED),
            (h(972), "Reset Monitor", 61, 62, OWN),            # boot + 672 h, the rest past 624 h
            (h(972), "Hub Unknown", 61, 62, AT_ONCE),
            (h(972), "Lamp", 61, 62, AT_ONCE),
            (h(972), "First Monitor", 61, 62, FOLLOWED),
            (h(972), "Hub Monitor", 61, 62, FOLLOWED),
            (h(972), "Hub Smoke", 61, 62, FOLLOWED),
            (h(1224), "Late Monitor", 61, 62, OPENED),
            (h(1532), "Behind Monitor", 61, 62, OPENED),
            (h(1533), "Old Child Contact", 61, 62, OPENED),
            (h(1534), "Lamp Button", 61, 62, OPENED),
            (h(1535), "New Child Motion", 61, 62, OPENED),
            (h(1542), "Hub Lock", 61, 62, OPENED),
        })
        self.assertEqual(numbers(fc), [(h(336), "First Monitor", 60, 61), (h(972), "Reset Monitor", 61, 62)])
        self.assertEqual(stranded(fc), [])
        # 62 came 636 h after 61 and the next is 672 h after it: the first clear
        # stretch did not end the forecast, the second did.
        self.assertEqual(fc.end, h(972) + GUARD_S)
        self.assertFalse(fc.cut)
        g = self.mesh()[1]
        g = derive(g.stack, g.boots, g.switches)
        g = after(after(after(g, Boot(h(300))), Switch(h(336), 60, 61)), Switch(h(972), 61, 62), own=True)
        self.assertEqual(state(fc.final["Reset Monitor"]), state(g))
        self.assertEqual(fc.final["Reset Monitor"].boot.ts, h(300))

    def test_only_one_of_the_two_power_cycled_is_not_enough(self):
        fc = forecast(self.mesh(), T0, boots=[("Reset Monitor", h(300))])
        self.assert_consistent(fc, T0)
        self.assertEqual(numbers(fc)[:2], [(h(336), "First Monitor", 60, 61), (h(602), "Hub Monitor", 61, 62)])
        self.assertEqual(stranded(fc, h(700)), [
            (h(602), "Hub Lock", 60, "Hub Unknown", 62),
            (h(602), "Lamp Button", 60, "Lamp", 62),
            (h(602), "New Child Motion", 60, "Behind Monitor", 62),
            (h(602), "Old Child Contact", 60, "Behind Monitor", 62),
        ])

    def test_power_cycled_just_after_the_next_number_books_an_early_one(self):
        boots = [("Reset Monitor", h(340)), ("Hub Monitor", h(342))]
        fc = forecast(self.mesh(), T0, boots=boots)
        self.assert_consistent(fc, T0)
        self.assertEqual([(s.ts, s.new) for s in fc.numbers[:3]], [(h(336), 61), (h(1008), 62), (h(1012), 63)])
        self.assertEqual(fc.numbers[0].name, "First Monitor")
        self.assertEqual(fc.numbers[2].name, "Reset Monitor")
        self.assertEqual(stranded(fc, h(1012)), [
            (h(1012), "Hub Lock", 61, "Hub Unknown", 63),
            (h(1012), "Lamp Button", 61, "Lamp", 63),
            (h(1012), "New Child Motion", 61, "Behind Monitor", 63),
            (h(1012), "Old Child Contact", 61, "Behind Monitor", 63),
        ])
        self.assertIn((h(1012), "Late Monitor", 61, 63, JUMPED), rows(fc.steps))
        self.assertIn((h(1012), "Behind Monitor", 61, 63, JUMPED), rows(fc.steps))

    def test_a_battery_pull_on_a_stranded_child_takes_the_parents_key(self):
        fc = forecast(self.mesh(), T0, boots=[("Hub Lock", h(600)), ("Lamp Button", h(600))])
        self.assert_consistent(fc, T0)
        # A jump of two at the boot arms nothing, so both take 63 the moment it appears.
        self.assertEqual([r for r in of(fc, "Hub Lock") if r[0] < h(1000)],
                         [(h(294), 59, 60, OPENED), (h(600), 60, 62, AT_BOOT), (h(648), 62, 63, FOLLOWED)])
        self.assertEqual([r for r in of(fc, "Lamp Button") if r[0] < h(1000)],
                         [(h(286), 59, 60, OPENED), (h(600), 60, 62, AT_BOOT), (h(648), 62, 63, FOLLOWED)])
        self.assertEqual([r for r in stranded(fc, h(1000)) if r[1] in ("Hub Lock", "Lamp Button")],
                         [(h(528), "Hub Lock", 60, "Hub Unknown", 62), (h(528), "Lamp Button", 60, "Lamp", 62)])

    def test_an_early_battery_pull_lifts_a_child_only_to_its_parents_key(self):
        fc = forecast(self.mesh(), T0, boots=[("Hub Lock", h(400)), ("Lamp Button", h(400))])
        self.assert_consistent(fc, T0)
        # +1 at the boot re-arms the guard: refuses 62, two behind at 63.
        self.assertEqual([r for r in of(fc, "Hub Lock") if r[0] < h(1000)],
                         [(h(294), 59, 60, OPENED), (h(400), 60, 61, AT_BOOT)])
        self.assertEqual([r for r in of(fc, "Lamp Button") if r[0] < h(1000)],
                         [(h(286), 59, 60, OPENED), (h(400), 60, 61, AT_BOOT)])
        self.assertEqual([r for r in stranded(fc, h(1000)) if r[1] in ("Hub Lock", "Lamp Button")],
                         [(h(648), "Hub Lock", 61, "Hub Unknown", 63), (h(648), "Lamp Button", 61, "Lamp", 63)])

    def test_a_router_that_boots_behind_follows_by_the_ordinary_rules(self):
        fc = forecast(self.mesh(), T0, boots=[("Behind Monitor", h(400))])
        self.assert_consistent(fc, T0)
        self.assertEqual([r for r in of(fc, "Behind Monitor") if r[0] < h(1000)],
                         [(h(284), 59, 60, OPENED), (h(400), 60, 61, FOLLOWED), (h(648), 61, 63, JUMPED)])
        # One behind at 62 (its +1 at the boot re-armed it), so its children are left at 63, not 62.
        self.assertEqual([r for r in stranded(fc, h(1000)) if r[3] == "Behind Monitor"],
                         [(h(648), "New Child Motion", 60, "Behind Monitor", 63),
                          (h(648), "Old Child Contact", 60, "Behind Monitor", 63)])


# ---------------------------------------------------------------------------
# keyguard.after against keyguard.derive


class AfterAgainstDeriveTest(unittest.TestCase):
    """after() moves a derived guard on by one event; where the event is far
    from any stamp margin it must agree with deriving the longer history."""

    def same(self, stack, boots, history, event, own=False):
        self.assertEqual(state(after(derive(stack, boots, history), event, own=own)),
                         state(derive(stack, boots, history + [event])))

    def test_old_logic_switches(self):
        b, first = [Boot(T0)], [Switch(FIRST, None, 50)]
        self.same(OLD, b, first, Switch(h(100), 50, 51))                         # flag clear: set, timer kept
        self.same(OLD, b, first, Switch(h(100), 50, 52))                         # jump: nothing
        armed = [Switch(FIRST, None, 49), Switch(T0 + 30, 49, 50)]
        self.same(OLD, b, armed, Switch(h(630), 50, 51))                         # flag set, past 624 h: restart
        self.same(OLD, b, armed, Switch(h(100), 50, 53))

    def test_current_logic_switches(self):
        b, first = [Boot(T0)], [Switch(FIRST, None, 50)]
        self.same(CUR, b, first, Switch(h(100), 50, 51))
        self.same(CUR, b, first, Switch(h(100), 50, 52))
        armed = first + [Switch(h(10), 50, 51)]
        self.same(CUR, b, armed, Switch(h(100), 51, 53))                         # restarts the timer, keeps the guard
        self.same(CUR, b, armed, Switch(h(700), 51, 52))
        g = derive(CUR, b, armed)
        s = Switch(h(700), 51, 52)
        self.assertEqual(state(after(g, s, own=True)), state(after(g, s, own=False)))

    def test_a_refused_plus_one_is_still_taken_exactly(self):
        armed = [Switch(FIRST, None, 49), Switch(T0 + 30, 49, 50)]
        s = Switch(h(300), 50, 51)                                               # before the guard opens
        d = derive(OLD, [Boot(T0)], armed + [s])
        self.assertEqual(len(d.misses), 1)
        a = after(derive(OLD, [Boot(T0)], armed), s)
        self.assertEqual(state(a), state(d))
        self.assertEqual(a.misses, ())

    def test_boots(self):
        for stack in (OLD, CUR):
            hist = [Switch(FIRST, None, 49), Switch(T0 + 30, 49, 50)]
            b1, b2 = Boot(T0), Boot(h(200))
            self.assertEqual(state(after(derive(stack, [b1], hist), b2)), state(derive(stack, [b1, b2], hist)))
            s = Switch(b2.ts + 40, 50, 51)                                       # a +1 taken at the boot
            self.assertEqual(state(after(after(derive(stack, [b1], hist), b2), s)),
                             state(derive(stack, [b1, b2], hist + [s])))

    def test_own_firings_with_the_flag_clear(self):
        b, first = [Boot(T0)], [Switch(FIRST, None, 50)]
        own = Switch(T0 + ROTATION_S, 50, 51)
        self.same(OLD, b, first, own, own=True)
        g = after(derive(OLD, b, first), own, own=True)
        self.assertTrue(g.fired)
        self.assertEqual(g.rotation_at, T0 + ROTATION_S + HOUR)
        again = Switch(T0 + ROTATION_S + HOUR, 51, 52)
        self.assertEqual(state(after(g, again, own=True)), state(derive(OLD, b, first + [own, again])))

    def test_a_switch_minutes_before_a_boot_is_cleared_by_it(self):
        # derive counts it as taken at the boot (stamps run late); after takes events as given.
        tb = h(300)
        hist = [Switch(FIRST, None, 49)]
        s = Switch(tb - 300, 49, 50)
        self.assertIs(derive(OLD, [Boot(T0), Boot(tb)], hist + [s]).flag, True)
        g = after(after(derive(OLD, [Boot(T0)], hist), s), Boot(tb))
        self.assertIs(g.flag, False)
        self.assertEqual(g.timer_start, tb)
        self.assertEqual(g.rotation_at, tb + ROTATION_S)
        self.assertEqual(g.second_rotation_at, tb + ROTATION_S + HOUR)

    def test_a_neighbours_plus_one_just_before_the_672_h_mark(self):
        # derive reads it as the unit's own firing (within STAMP_SLACK_S); after does
        # only when told, and otherwise the unit's own firing is still due at 672 h.
        b, first = [Boot(T0)], [Switch(FIRST, None, 50)]
        s = Switch(T0 + ROTATION_S - 60, 50, 51)
        self.assertTrue(derive(OLD, b, first + [s]).fired)
        g = derive(OLD, b, first)
        self.assertEqual(after(g, s, own=True).rotation_at, T0 + ROTATION_S + HOUR)
        neighbour = after(g, s, own=False)
        self.assertFalse(neighbour.fired)
        self.assertEqual(neighbour.rotation_at, T0 + ROTATION_S)

    def test_an_unknown_stack_only_changes_key(self):
        g = derive(UNK, [Boot(T0)], [Switch(FIRST, None, 50)])
        self.assertEqual(after(g, Boot(h(10))), g)
        self.assertEqual(after(g, Switch(h(10), 50, 52)), replace(g, key=52))


if __name__ == "__main__":
    unittest.main()
