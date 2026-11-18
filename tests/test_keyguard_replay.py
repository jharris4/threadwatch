"""keyguard, checked from the outside: replay tests written from the key
guard plan's Model section and the OpenThread KeyManager source (old logic
7074a43e4/b9dcdbca4, current logic main), not from keyguard.py.

Old logic: one guard flag and one rotation timer. Starting the interface
clears the flag and starts the timer. A +1 with the flag clear is taken and
sets the flag without restarting the timer; a +1 with the flag set is
refused until the timer reaches 624 h and restarts it when taken; a jump of
two or more is taken and touches neither. Its own rotation is an ordinary
+1 at 672 h on the timer, so the first +1 since boot fires twice, an hour
apart. There is no forced path.

Current logic: a boot clears the guard and restarts the rotation timer;
every switch restarts the rotation timer; only an exact +1 arms the 624 h
guard; forced paths (and its own rotation) ignore the guard.

All times and labels are made up.
"""

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests  # noqa: F401  (the mDNS guard, installed on a direct run too: tests/no_lan)
from threadwatch import keyguard
from threadwatch.keyguard import BOOT_MARGIN_S, GUARD_S, HOUR, ROTATION_S, STAMP_SLACK_S, Boot, Switch, derive

OLD = ("old", "reported", "test: old KeyManager")
CUR = ("current", "reported", "test: current KeyManager")
T0 = 1_900_000_000          # an arbitrary epoch, nowhere near this house's history


def h(n):
    return n * HOUR


def missed(guard):
    return [m[0] for m in guard.misses]


class ConstantsTest(unittest.TestCase):
    def test_the_times_match_the_default_security_policy(self):
        self.assertEqual(HOUR, 3600)
        self.assertEqual(GUARD_S, 624 * 3600)      # 93% of the rotation time, as both stacks compute it
        self.assertEqual(ROTATION_S, 672 * 3600)
        self.assertEqual(STAMP_SLACK_S, 120)
        self.assertEqual(BOOT_MARGIN_S, 600)


class OldLogicRulesTest(unittest.TestCase):
    """One test per rule of the old KeyManager."""

    def test_a_boot_clears_the_flag_and_starts_the_timer(self):
        boot = Boot(T0)
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 50)])
        self.assertEqual(g.key, 50)
        self.assertEqual(g.boot, boot)
        self.assertIs(g.flag, False)
        self.assertIsNone(g.flag_set_by)
        self.assertEqual(g.timer_start, T0)
        self.assertEqual(g.timer_set_by, boot)
        self.assertEqual(g.guard, "open")
        self.assertEqual(g.rotation_at, T0 + ROTATION_S)
        self.assertEqual(g.second_rotation_at, T0 + ROTATION_S + HOUR)   # first +1 since boot fires twice
        self.assertEqual(g.confidence, "normal")
        self.assertEqual(g.misses, ())

    def test_a_plus_one_with_the_flag_clear_sets_it_and_leaves_the_timer(self):
        boot = Boot(T0)
        s = Switch(T0 + h(100), 50, 51)
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 50), s])
        self.assertEqual(g.key, 51)
        self.assertIs(g.flag, True)
        self.assertEqual(g.flag_set_by, s)
        self.assertEqual(g.timer_start, T0)                 # not restarted
        self.assertEqual(g.timer_set_by, boot)
        self.assertEqual(g.guard, "until")
        self.assertEqual(g.guard_open_at, T0 + GUARD_S)
        self.assertEqual(g.rotation_at, T0 + ROTATION_S)
        self.assertIsNone(g.second_rotation_at)             # the flag is set now: one firing only
        self.assertEqual(g.misses, ())

    def test_a_plus_one_with_the_flag_clear_after_624_h_still_leaves_the_timer(self):
        # The flag-clear branch never restarts the timer, however late the +1 comes.
        # So the unit still fires its own +1 at boot + 672 h, 22 h after this one.
        boot = Boot(T0)
        s = Switch(T0 + h(650), 50, 51)
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 50), s])
        self.assertIs(g.flag, True)
        self.assertEqual(g.flag_set_by, s)
        self.assertEqual(g.timer_start, T0)
        self.assertEqual(g.timer_set_by, boot)
        self.assertEqual(g.guard_open_at, T0 + GUARD_S)
        self.assertEqual(g.rotation_at, T0 + ROTATION_S)
        self.assertIsNone(g.second_rotation_at)
        self.assertEqual(g.misses, ())

    def test_a_plus_one_with_the_flag_set_before_624_h_is_a_miss(self):
        first = Switch(T0 + h(10), 50, 51)
        refused = Switch(T0 + h(300), 51, 52)
        g = derive(OLD, [Boot(T0)], [Switch(T0 - h(30), None, 50), first, refused])
        self.assertEqual(missed(g), [refused])
        self.assertEqual(g.key, 52)
        for _, text in g.misses:
            self.assertIsInstance(text, str)
            self.assertTrue(text)

    def test_a_plus_one_with_the_flag_set_after_624_h_restarts_the_timer(self):
        first = Switch(T0 + h(10), 50, 51)
        second = Switch(T0 + h(630), 51, 52)
        g = derive(OLD, [Boot(T0)], [Switch(T0 - h(30), None, 50), first, second])
        self.assertEqual(g.misses, ())
        self.assertEqual(g.key, 52)
        self.assertIs(g.flag, True)
        self.assertEqual(g.timer_start, second.ts)
        self.assertEqual(g.timer_set_by, second)
        self.assertEqual(g.guard, "until")
        self.assertEqual(g.guard_open_at, second.ts + GUARD_S)
        self.assertEqual(g.rotation_at, second.ts + ROTATION_S)
        self.assertIsNone(g.second_rotation_at)

    def test_a_plus_one_a_little_ahead_of_a_boot_worked_guard_is_on_time(self):
        # Boot stamps run late, so a switch up to STAMP_SLACK_S ahead of boot + 624 h counts.
        first = Switch(T0 + h(10), 50, 51)
        early = Switch(T0 + GUARD_S - (STAMP_SLACK_S - 20), 51, 52)
        g = derive(OLD, [Boot(T0)], [Switch(T0 - h(30), None, 50), first, early])
        self.assertEqual(g.misses, ())
        self.assertEqual(g.timer_start, early.ts)
        self.assertEqual(g.timer_set_by, early)

    def test_a_plus_one_well_ahead_of_the_guard_is_still_a_miss(self):
        first = Switch(T0 + h(10), 50, 51)
        early = Switch(T0 + GUARD_S - 900, 51, 52)
        g = derive(OLD, [Boot(T0)], [Switch(T0 - h(30), None, 50), first, early])
        self.assertEqual(missed(g), [early])

    def test_a_plus_one_taken_at_boot_counts_as_the_first(self):
        boot = Boot(T0)
        at_boot = Switch(T0 + 40, 50, 51)            # came back one behind
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 50), at_boot])
        self.assertIs(g.flag, True)
        self.assertEqual(g.flag_set_by, at_boot)
        self.assertEqual(g.timer_start, T0)
        self.assertEqual(g.timer_set_by, boot)
        self.assertEqual(g.guard_open_at, T0 + GUARD_S)
        self.assertEqual(g.rotation_at, T0 + ROTATION_S)
        self.assertIsNone(g.second_rotation_at)

    def test_a_switch_just_before_a_late_boot_stamp_is_taken_at_that_boot(self):
        boot = Boot(T0)
        at_boot = Switch(T0 - (BOOT_MARGIN_S - 100), 50, 51)
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 50), at_boot])
        self.assertIs(g.flag, True)                  # not cleared by the boot that follows the stamp
        self.assertEqual(g.flag_set_by, at_boot)
        self.assertEqual(g.timer_set_by, boot)
        self.assertTrue(T0 - BOOT_MARGIN_S <= g.timer_start <= T0)
        self.assertEqual(g.confidence, "normal")

    def test_a_switch_well_before_a_boot_is_cleared_by_it(self):
        boot = Boot(T0)
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 50), Switch(T0 - h(2), 50, 51)])
        self.assertEqual(g.key, 51)
        self.assertIs(g.flag, False)
        self.assertEqual(g.guard, "open")
        self.assertEqual(g.timer_start, T0)
        self.assertEqual(g.second_rotation_at, T0 + ROTATION_S + HOUR)

    def test_a_jump_of_two_touches_neither_flag_nor_timer(self):
        boot = Boot(T0)
        jump = Switch(T0 + h(200), 50, 52)
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 50), jump])
        self.assertEqual(g.key, 52)
        self.assertIs(g.flag, False)
        self.assertEqual(g.guard, "open")
        self.assertEqual(g.timer_start, T0)
        self.assertEqual(g.rotation_at, T0 + ROTATION_S)
        self.assertEqual(g.second_rotation_at, T0 + ROTATION_S + HOUR)
        self.assertEqual(g.misses, ())

    def test_a_jump_with_the_flag_set_is_never_refused(self):
        first = Switch(T0 + h(10), 50, 51)
        jump = Switch(T0 + h(100), 51, 53)
        g = derive(OLD, [Boot(T0)], [Switch(T0 - h(30), None, 50), first, jump])
        self.assertEqual(g.misses, ())
        self.assertEqual(g.key, 53)
        self.assertIs(g.flag, True)
        self.assertEqual(g.flag_set_by, first)
        self.assertEqual(g.timer_start, T0)
        self.assertEqual(g.guard_open_at, T0 + GUARD_S)
        self.assertEqual(g.rotation_at, T0 + ROTATION_S)

    def test_own_rotation_with_the_flag_clear_fires_again_an_hour_later(self):
        boot = Boot(T0)
        own = Switch(T0 + ROTATION_S, 50, 51)
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 50), own])
        self.assertEqual(g.misses, ())
        self.assertIs(g.flag, True)
        self.assertEqual(g.flag_set_by, own)
        self.assertEqual(g.timer_start, T0)          # the first +1 does not restart it
        # 672 h are already on the timer, so the next hourly tick fires again.
        self.assertEqual(g.rotation_at, T0 + ROTATION_S + HOUR)

    def test_the_second_firing_an_hour_later_restarts_the_timer(self):
        own = Switch(T0 + ROTATION_S, 50, 51)
        again = Switch(T0 + ROTATION_S + HOUR, 51, 52)
        g = derive(OLD, [Boot(T0)], [Switch(T0 - h(30), None, 50), own, again])
        self.assertEqual(g.misses, ())
        self.assertEqual(g.key, 52)
        self.assertIs(g.flag, True)
        self.assertEqual(g.timer_start, again.ts)
        self.assertEqual(g.timer_set_by, again)
        self.assertEqual(g.guard_open_at, again.ts + GUARD_S)
        self.assertEqual(g.rotation_at, again.ts + ROTATION_S)
        self.assertIsNone(g.second_rotation_at)

    def test_own_rotation_with_the_flag_set_restarts_the_timer_once(self):
        first = Switch(T0 + h(5), 50, 51)
        own = Switch(T0 + ROTATION_S, 51, 52)
        g = derive(OLD, [Boot(T0)], [Switch(T0 - h(30), None, 50), first, own])
        self.assertEqual(g.misses, ())
        self.assertEqual(g.timer_start, own.ts)
        self.assertEqual(g.rotation_at, own.ts + ROTATION_S)
        self.assertIsNone(g.second_rotation_at)

    def test_a_later_boot_clears_a_set_flag(self):
        b1, b2 = Boot(T0), Boot(T0 + h(200))
        g = derive(OLD, [b1, b2], [Switch(T0 - h(30), None, 50), Switch(T0 + 30, 50, 51)])
        self.assertEqual(g.boot, b2)
        self.assertIs(g.flag, False)
        self.assertEqual(g.guard, "open")
        self.assertEqual(g.timer_start, b2.ts)
        self.assertEqual(g.timer_set_by, b2)
        self.assertEqual(g.rotation_at, b2.ts + ROTATION_S)
        self.assertEqual(g.second_rotation_at, b2.ts + ROTATION_S + HOUR)

    def test_a_plus_one_after_a_fresh_boot_is_no_miss(self):
        b1, b2 = Boot(T0), Boot(T0 + h(200))
        later = Switch(T0 + h(250), 51, 52)
        g = derive(OLD, [b1, b2], [Switch(T0 - h(30), None, 50), Switch(T0 + 30, 50, 51), later])
        self.assertEqual(g.misses, ())
        self.assertEqual(g.flag_set_by, later)
        self.assertEqual(g.timer_start, b2.ts)

    def test_input_order_does_not_matter(self):
        boots = [Boot(T0), Boot(T0 + h(700))]
        switches = [Switch(T0 - h(30), None, 50), Switch(T0 + 30, 50, 51),
                    Switch(T0 + h(640), 51, 52), Switch(T0 + h(700) + 20, 52, 53),
                    Switch(T0 + h(800), 53, 55)]
        want = derive(OLD, boots, switches)
        rng = random.Random(7)
        for _ in range(5):
            b, s = boots[:], switches[:]
            rng.shuffle(b)
            rng.shuffle(s)
            self.assertEqual(derive(OLD, b, s), want)


class CurrentLogicRulesTest(unittest.TestCase):
    """One test per rule of the current KeyManager."""

    def test_a_boot_clears_the_guard_and_restarts_the_timer(self):
        boot = Boot(T0)
        g = derive(CUR, [boot], [Switch(T0 - h(30), None, 50)])
        self.assertEqual(g.key, 50)
        self.assertIs(g.flag, False)
        self.assertEqual(g.guard, "open")
        self.assertEqual(g.timer_start, T0)
        self.assertEqual(g.timer_set_by, boot)
        self.assertEqual(g.rotation_at, T0 + ROTATION_S)
        self.assertIsNone(g.second_rotation_at)
        self.assertEqual(g.confidence, "normal")
        self.assertEqual(g.misses, ())

    def test_a_boot_clears_an_armed_guard(self):
        g = derive(CUR, [Boot(T0)], [Switch(T0 - h(30), None, 50), Switch(T0 - h(3), 50, 51)])
        self.assertIs(g.flag, False)
        self.assertEqual(g.guard, "open")
        self.assertEqual(g.rotation_at, T0 + ROTATION_S)

    def test_a_plus_one_arms_the_guard_and_restarts_the_timer(self):
        s = Switch(T0 + h(100), 50, 51)
        g = derive(CUR, [Boot(T0)], [Switch(T0 - h(30), None, 50), s])
        self.assertIs(g.flag, True)
        self.assertEqual(g.flag_set_by, s)
        self.assertEqual(g.guard, "until")
        self.assertEqual(g.guard_open_at, s.ts + GUARD_S)
        self.assertEqual(g.timer_start, s.ts)
        self.assertEqual(g.timer_set_by, s)
        self.assertEqual(g.rotation_at, s.ts + ROTATION_S)
        self.assertIsNone(g.second_rotation_at)

    def test_a_plus_one_taken_at_boot_arms_the_guard(self):
        at_boot = Switch(T0 + 40, 50, 51)
        g = derive(CUR, [Boot(T0)], [Switch(T0 - h(30), None, 50), at_boot])
        self.assertIs(g.flag, True)
        self.assertEqual(g.flag_set_by, at_boot)
        self.assertEqual(g.guard_open_at, at_boot.ts + GUARD_S)
        self.assertEqual(g.rotation_at, at_boot.ts + ROTATION_S)

    def test_a_switch_just_before_a_late_boot_stamp_still_arms_the_guard(self):
        at_boot = Switch(T0 - (BOOT_MARGIN_S - 100), 50, 51)
        g = derive(CUR, [Boot(T0)], [Switch(T0 - h(30), None, 50), at_boot])
        self.assertIs(g.flag, True)
        self.assertEqual(g.flag_set_by, at_boot)
        self.assertTrue(at_boot.ts + GUARD_S <= g.guard_open_at <= T0 + GUARD_S)
        self.assertTrue(at_boot.ts + ROTATION_S <= g.rotation_at <= T0 + ROTATION_S)

    def test_a_plus_one_past_an_armed_guard_is_a_forced_miss_and_re_arms(self):
        first = Switch(T0 + h(10), 50, 51)
        forced = Switch(T0 + h(60), 51, 52)
        g = derive(CUR, [Boot(T0)], [Switch(T0 - h(30), None, 50), first, forced])
        self.assertEqual(missed(g), [forced])
        self.assertIs(g.flag, True)
        self.assertEqual(g.flag_set_by, forced)       # a forced +1 still resets the guard timer
        self.assertEqual(g.guard_open_at, forced.ts + GUARD_S)
        self.assertEqual(g.rotation_at, forced.ts + ROTATION_S)

    def test_a_plus_one_after_the_guard_runs_out_is_no_miss(self):
        first = Switch(T0 + h(10), 50, 51)
        later = Switch(T0 + h(10) + GUARD_S + 60, 51, 52)
        g = derive(CUR, [Boot(T0)], [Switch(T0 - h(30), None, 50), first, later])
        self.assertEqual(g.misses, ())
        self.assertEqual(g.flag_set_by, later)
        self.assertEqual(g.guard_open_at, later.ts + GUARD_S)

    def test_a_jump_restarts_the_timer_and_leaves_the_guard(self):
        # The guard counts down in the rotation timer's hourly ticks, and every
        # switch restarts that timer, so the source opens it up to an hour later
        # than this; the plan's rule is the +1's time + 624 h.
        first = Switch(T0 + h(10), 50, 51)
        jump = Switch(T0 + h(100), 51, 53)
        g = derive(CUR, [Boot(T0)], [Switch(T0 - h(30), None, 50), first, jump])
        self.assertEqual(g.misses, ())
        self.assertEqual(g.key, 53)
        self.assertIs(g.flag, True)
        self.assertEqual(g.flag_set_by, first)
        self.assertEqual(g.guard_open_at, first.ts + GUARD_S)
        self.assertEqual(g.timer_start, jump.ts)
        self.assertEqual(g.timer_set_by, jump)
        self.assertEqual(g.rotation_at, jump.ts + ROTATION_S)

    def test_a_jump_does_not_arm_a_clear_guard(self):
        jump = Switch(T0 + h(100), 50, 52)
        g = derive(CUR, [Boot(T0)], [Switch(T0 - h(30), None, 50), jump])
        self.assertIs(g.flag, False)
        self.assertEqual(g.guard, "open")
        self.assertEqual(g.rotation_at, jump.ts + ROTATION_S)

    def test_own_rotation_arms_the_guard(self):
        own = Switch(T0 + ROTATION_S, 50, 51)
        g = derive(CUR, [Boot(T0)], [Switch(T0 - h(30), None, 50), own])
        self.assertEqual(g.misses, ())
        self.assertIs(g.flag, True)
        self.assertEqual(g.flag_set_by, own)
        self.assertEqual(g.guard_open_at, own.ts + GUARD_S)
        self.assertEqual(g.rotation_at, own.ts + ROTATION_S)
        self.assertIsNone(g.second_rotation_at)       # no second firing on the current logic

    def test_a_plus_one_after_a_fresh_boot_is_no_miss(self):
        b1, b2 = Boot(T0), Boot(T0 + h(100))
        g = derive(CUR, [b1, b2], [Switch(T0 - h(30), None, 50), Switch(T0 + h(10), 50, 51),
                                   Switch(T0 + h(200), 51, 52)])
        self.assertEqual(g.misses, ())
        self.assertEqual(g.boot, b2)


class ConfidenceTest(unittest.TestCase):
    def test_an_unknown_stack_forecasts_nothing(self):
        g = derive(("unknown", None, "test: not checked"), [Boot(T0)],
                   [Switch(T0 - h(30), None, 50), Switch(T0 + h(5), 50, 51)])
        self.assertEqual(g.key, 51)
        self.assertEqual(g.guard, "unknown")
        self.assertIsNone(g.rotation_at)
        self.assertIsNone(g.second_rotation_at)
        self.assertEqual(g.confidence, "none")
        self.assertTrue(g.reasons)

    def test_an_assumed_stack_is_low_confidence(self):
        g = derive(("old", "assumed", "test: one unit fits"), [Boot(T0)], [Switch(T0 - h(30), None, 50)])
        self.assertEqual(g.confidence, "low")
        self.assertTrue(g.reasons)
        self.assertEqual(g.rotation_at, T0 + ROTATION_S)    # still forecast, by the old rules

    def test_a_stack_known_by_behaviour_is_normal_confidence(self):
        g = derive(("old", "behaviour", "test: fits the old rules"), [Boot(T0)], [Switch(T0 - h(30), None, 50)])
        self.assertEqual(g.confidence, "normal")

    def test_no_boot_seen_is_flagged(self):
        g = derive(CUR, [], [Switch(T0, None, 50), Switch(T0 + h(5), 50, 51)])
        self.assertIsNone(g.boot)
        self.assertEqual(g.key, 51)
        self.assertNotEqual(g.confidence, "normal")
        self.assertTrue(g.reasons)

    def test_a_switch_that_may_be_either_side_of_a_boot_is_flagged(self):
        # Not heard on the old key from 5 h before the boot to 2 h after it.
        boot = Boot(T0)
        s = Switch(T0 + h(2), 50, 51, unheard_from=T0 - h(5))
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 50), s])
        self.assertEqual(g.key, 51)
        self.assertNotEqual(g.confidence, "normal")
        self.assertTrue(g.reasons)

    def test_a_switch_inside_a_wide_boot_range_is_flagged(self):
        boot = Boot(T0, earliest=T0 - h(1), latest=T0)
        s = Switch(T0 - 1800, 50, 51)
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 50), s])
        self.assertNotEqual(g.confidence, "normal")
        self.assertTrue(g.reasons)

    def test_a_first_key_heard_long_after_the_boot_leaves_the_flag_in_doubt(self):
        # Nothing says which key it came back on, so a +1 at boot cannot be ruled out.
        g = derive(OLD, [Boot(T0)], [Switch(T0 + h(3), None, 50)])
        self.assertEqual(g.key, 50)
        self.assertNotEqual(g.confidence, "normal")

    def test_an_unheard_interval_bounds_the_guard(self):
        s = Switch(T0 + h(40), 50, 51, unheard_from=T0 + h(20))
        g = derive(CUR, [Boot(T0)], [Switch(T0 - h(30), None, 50), s])
        self.assertIs(g.flag, True)
        self.assertTrue(s.unheard_from + GUARD_S <= g.guard_open_at <= s.ts + GUARD_S)


class OnePerBootTest(unittest.TestCase):
    def test_two_stamps_of_one_boot_merge(self):
        got = keyguard.one_per_boot([Boot(T0 + 45), Boot(T0)])
        self.assertEqual(len(got), 1)

    def test_distinct_boots_stay_apart_oldest_first(self):
        a, b, c = Boot(T0), Boot(T0 + h(50)), Boot(T0 + h(400))
        got = keyguard.one_per_boot([c, a, b])
        self.assertEqual([x.ts for x in got], [a.ts, b.ts, c.ts])

    # Fails on 36c2af3, which keeps the later of two equally good stamps. Decided on
    # 2026-11-18 to keep the earlier, since boot stamps run late; see Phase 4 in the key
    # guard forecast plan. Remove the mark with the one_per_boot change: until then an
    # unexpected success fails the run.
    @unittest.expectedFailure
    def test_duplicate_stamps_do_not_change_the_guard(self):
        at_boot = Switch(T0 + 90, 50, 51)
        once = derive(OLD, [Boot(T0)], [Switch(T0 - h(30), None, 50), at_boot])
        twice = derive(OLD, [Boot(T0), Boot(T0 + 120)], [Switch(T0 - h(30), None, 50), at_boot])
        self.assertIs(twice.flag, True)            # the +1 between the stamps is still the boot's own
        self.assertEqual(twice.flag_set_by, at_boot)
        self.assertEqual(twice.guard_open_at, once.guard_open_at)
        self.assertEqual(twice.rotation_at, once.rotation_at)


class ReplayTest(unittest.TestCase):
    """Whole histories of the shapes seen on the mesh, with made-up times."""

    def test_a_pair_of_new_numbers_from_one_reboot_batch(self):
        # A boots and comes back one behind; B boots 38 minutes later already on top.
        a_boot, b_boot = Boot(T0), Boot(T0 + 38 * 60)
        a_at_boot = Switch(T0 + 30, 49, 50)
        a_own = Switch(T0 + ROTATION_S, 50, 51)                  # A's timer, flag set: fires once
        b_took = Switch(T0 + ROTATION_S + 4, 50, 51)             # B's first +1 since boot: no restart
        b_own = Switch(b_boot.ts + ROTATION_S, 51, 52)           # B's timer, flag now set: fires
        a_refused_time = b_own.ts + 2                            # A saw 52 here, but refused it

        a = derive(OLD, [a_boot], [Switch(T0 - h(30), None, 49), a_at_boot, a_own])
        self.assertEqual(a.misses, ())
        self.assertEqual(a.key, 51)
        self.assertEqual(a.timer_set_by, a_own)
        self.assertEqual(a.guard, "until")
        self.assertGreater(a.guard_open_at, a_refused_time)      # so 52 is refused
        self.assertEqual(a.guard_open_at, a_own.ts + GUARD_S)
        self.assertEqual(a.rotation_at, a_own.ts + ROTATION_S)

        # Had B taken a +1 at boot, b_took would have restarted its timer, and its
        # firing at boot + 672 h, 38 minutes later, would be refused.
        b = derive(OLD, [b_boot], [Switch(T0 - h(30), None, 49), Switch(b_boot.ts + 90, 49, 50), b_took, b_own])
        self.assertEqual(missed(b), [b_own])

        b = derive(OLD, [b_boot], [Switch(T0 - h(30), None, 50), b_took, b_own])
        self.assertEqual(b.misses, ())
        self.assertEqual(b.key, 52)
        self.assertEqual(b.flag_set_by, b_took)
        self.assertEqual(b.timer_set_by, b_own)
        self.assertEqual(b.rotation_at, b_own.ts + ROTATION_S)
        self.assertIsNone(b.second_rotation_at)

    def test_a_unit_firing_at_boot_plus_672_h_to_the_second(self):
        boot = Boot(T0)
        own = Switch(T0 + ROTATION_S - 30, 50, 51)               # a little ahead of the stamped boot
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 50), own])
        self.assertEqual(g.misses, ())
        self.assertIs(g.flag, True)
        self.assertEqual(g.timer_set_by, boot)
        # Read as its own firing: the second comes on the next hourly tick.
        self.assertTrue(T0 + ROTATION_S <= g.rotation_at <= T0 + ROTATION_S + HOUR)

    def test_a_unit_that_took_a_key_at_boot_then_refused_the_next(self):
        boot = Boot(T0)
        at_boot = Switch(T0 + 50, 49, 50)
        took = Switch(T0 + h(670), 50, 51)                       # past 624 h with the flag set: restarts
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 49), at_boot, took])
        self.assertEqual(g.misses, ())
        self.assertEqual(g.key, 51)
        self.assertEqual(g.timer_start, took.ts)
        self.assertEqual(g.timer_set_by, took)
        # No firing at boot + 672 h: the timer was restarted 2 h before.
        self.assertEqual(g.rotation_at, took.ts + ROTATION_S)
        self.assertIsNone(g.second_rotation_at)
        self.assertEqual(g.guard_open_at, took.ts + GUARD_S)
        self.assertGreater(g.guard_open_at, took.ts + h(1))       # the next number, an hour on, is refused

        refused = Switch(took.ts + h(1), 51, 52)
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 49), at_boot, took, refused])
        self.assertEqual(missed(g), [refused])

    def test_a_unit_that_took_a_key_at_boot_plus_624_h(self):
        boot = Boot(T0)
        took = Switch(T0 + h(300), 50, 51)                       # first +1: flag set, timer runs on
        opened = Switch(T0 + GUARD_S - 2, 51, 52)                # 2 s ahead of boot + 624 h
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 50), took, opened])
        self.assertEqual(g.misses, ())
        self.assertEqual(g.key, 52)
        self.assertEqual(g.flag_set_by, took)
        self.assertEqual(g.timer_set_by, opened)
        self.assertEqual(g.rotation_at, opened.ts + ROTATION_S)
        self.assertEqual(g.guard_open_at, opened.ts + GUARD_S)

    def test_a_unit_dragged_two_numbers_at_once(self):
        boot = Boot(T0)
        took = Switch(T0 + h(300), 50, 51)
        opened = Switch(T0 + GUARD_S + 5, 51, 52)
        dragged = Switch(opened.ts + h(200), 52, 54)
        g = derive(OLD, [boot], [Switch(T0 - h(30), None, 50), took, opened, dragged])
        self.assertEqual(g.misses, ())
        self.assertEqual(g.key, 54)
        self.assertEqual(g.timer_set_by, opened)                 # the jump leaves the timer alone
        self.assertEqual(g.rotation_at, opened.ts + ROTATION_S)
        self.assertEqual(g.guard_open_at, opened.ts + GUARD_S)

        # On the current logic the jump restarts the timer and leaves the guard.
        jump = Switch(took.ts + h(100), 51, 53)
        c = derive(CUR, [boot], [Switch(T0 - h(30), None, 50), took, jump])
        self.assertEqual(c.misses, ())
        self.assertEqual(c.rotation_at, jump.ts + ROTATION_S)
        self.assertEqual(c.flag_set_by, took)
        self.assertEqual(c.guard_open_at, took.ts + GUARD_S)

    def test_a_reset_on_the_top_key_books_a_number_672_h_later(self):
        g = derive(OLD, [Boot(T0), Boot(T0 + h(500))],
                   [Switch(T0 - h(30), None, 50), Switch(T0 + 20, 50, 51)])
        self.assertEqual(g.rotation_at, T0 + h(500) + ROTATION_S)
        self.assertEqual(g.second_rotation_at, T0 + h(500) + ROTATION_S + HOUR)

    def test_three_reboots_and_a_month_of_switches(self):
        boots = [Boot(T0), Boot(T0 + h(900)), Boot(T0 + h(1700))]
        s = [Switch(T0 - h(30), None, 60),
             Switch(T0 + 25, 60, 61),                    # at boot 1: flag set
             Switch(T0 + h(640), 61, 62),                # flag set, past 624 h: restart
             Switch(T0 + h(800), 62, 63),                # refused on the rules: miss
             Switch(T0 + h(900) + 60, 63, 64),           # at boot 2: flag set, no restart
             Switch(T0 + h(1000), 64, 66),               # jump: nothing
             Switch(T0 + h(1750), 66, 67)]               # after boot 3: flag set, timer from boot 3
        g = derive(OLD, boots, s)
        self.assertEqual(missed(g), [s[3]])
        self.assertEqual(g.boot, boots[2])
        self.assertEqual(g.key, 67)
        self.assertIs(g.flag, True)
        self.assertEqual(g.flag_set_by, s[6])
        self.assertEqual(g.timer_set_by, boots[2])
        self.assertEqual(g.guard_open_at, boots[2].ts + GUARD_S)
        self.assertEqual(g.rotation_at, boots[2].ts + ROTATION_S)
        self.assertIsNone(g.second_rotation_at)

        c = derive(CUR, boots, s)
        self.assertEqual(missed(c), [s[3]])
        self.assertEqual(c.flag_set_by, s[6])
        self.assertEqual(c.guard_open_at, s[6].ts + GUARD_S)
        self.assertEqual(c.rotation_at, s[6].ts + ROTATION_S)


if __name__ == "__main__":
    unittest.main()
