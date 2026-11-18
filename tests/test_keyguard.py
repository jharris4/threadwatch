"""keyguard: one test per rule of the key guard model, both stacks."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests  # noqa: F401  (the mDNS guard, installed on a direct run too: tests/no_lan)
from threadwatch import keyguard
from threadwatch.keyguard import GUARD_S, HOUR, ROTATION_S, Boot, Switch, after, derive

CURRENT = ("current", "reported", "Bulb A19 5.1.45")
OLD = ("old", "reported", "Air Monitor 2000 1.0.26")
T = 1_800_000_000.0          # a boot
DAY = 24 * HOUR


def first(key=90, ts=T - 30 * DAY):
    return Switch(ts, None, key)


class CurrentLogicTest(unittest.TestCase):
    def test_a_boot_clears_the_guard_and_restarts_the_rotation_timer(self):
        armed = Switch(T - DAY, 90, 91)
        g = derive(CURRENT, [Boot(T)], [first(), armed])
        self.assertEqual((g.guard, g.guard_open_at, g.flag, g.flag_set_by), ("open", None, False, None))
        self.assertEqual((g.timer_start, g.timer_set_by, g.rotation_at), (T, Boot(T), T + ROTATION_S))
        self.assertEqual((g.key, g.boot, g.second_rotation_at, g.confidence), (91, Boot(T), None, "normal"))

    def test_every_switch_restarts_the_rotation_timer(self):
        for old in (90, 89):                              # a +1 and a jump of two
            with self.subTest(old=old):
                s = Switch(T + 5 * DAY, old, 91)
                g = derive(CURRENT, [Boot(T)], [first(old), s])
                self.assertEqual((g.timer_start, g.timer_set_by, g.rotation_at),
                                 (s.ts, s, s.ts + ROTATION_S))

    def test_only_an_exact_plus_one_arms_the_guard(self):
        one, two = Switch(T + DAY, 90, 91), Switch(T + 3 * DAY, 91, 93)
        g = derive(CURRENT, [Boot(T)], [first(), one])
        self.assertEqual((g.guard, g.guard_open_at, g.flag, g.flag_set_by), ("until", one.ts + GUARD_S, True, one))
        # A jump of two does not arm it, and leaves a guard already armed as it was.
        g = derive(CURRENT, [Boot(T)], [first(89), Switch(T + DAY, 89, 91)])
        self.assertEqual((g.guard, g.flag), ("open", False))
        g = derive(CURRENT, [Boot(T)], [first(), one, two])
        self.assertEqual((g.guard_open_at, g.flag_set_by, g.timer_start), (one.ts + GUARD_S, one, two.ts))

    def test_a_plus_one_taken_at_boot_arms_the_guard(self):
        # Came back one behind. The first frame can be ahead of a late boot stamp.
        for at in (T + 40, T - 20):
            with self.subTest(at=at):
                s = Switch(at, 90, 91)
                g = derive(CURRENT, [Boot(T)], [first(), s])
                self.assertEqual((g.guard, g.guard_open_at, g.flag_set_by), ("until", at + GUARD_S, s))
                self.assertEqual((g.rotation_at, g.confidence), (max(T, at) + ROTATION_S, "normal"))

    def test_a_forced_update_ignores_the_guard_and_is_a_miss_not_a_doubt(self):
        one, forced = Switch(T + DAY, 90, 91), Switch(T + 2 * DAY, 91, 92)
        g = derive(CURRENT, [Boot(T)], [first(), one, forced])
        self.assertEqual(g.misses, ((forced, keyguard.FORCED),))
        self.assertEqual((g.guard_open_at, g.rotation_at, g.confidence),
                         (forced.ts + GUARD_S, forced.ts + ROTATION_S, "normal"))
        # Once the guard has run out, the next +1 is no miss.
        late = Switch(one.ts + GUARD_S + 60, 91, 92)
        self.assertEqual(derive(CURRENT, [Boot(T)], [first(), one, late]).misses, ())


class OldLogicTest(unittest.TestCase):
    def test_a_boot_clears_the_flag_and_starts_the_timer(self):
        g = derive(OLD, [Boot(T)], [first(), Switch(T - DAY, 90, 91)])
        self.assertEqual((g.flag, g.flag_set_by, g.timer_start, g.timer_set_by), (False, None, T, Boot(T)))
        # Flag clear: the guard is open, and the unit rotates at 672 h and again at 673 h.
        self.assertEqual((g.guard, g.rotation_at, g.second_rotation_at),
                         ("open", T + ROTATION_S, T + ROTATION_S + HOUR))
        self.assertIn(keyguard.SECOND, g.reasons)
        self.assertEqual(g.confidence, "normal")

    def test_a_plus_one_with_the_flag_clear_sets_it_and_leaves_the_timer(self):
        for at in (T + 5 * DAY, T + 40, T - 20):          # later, at boot, and ahead of a late boot stamp
            with self.subTest(at=at):
                s = Switch(at, 90, 91)
                g = derive(OLD, [Boot(T)], [first(), s])
                self.assertEqual((g.flag, g.flag_set_by, g.timer_start, g.timer_set_by), (True, s, T, Boot(T)))
                self.assertEqual((g.guard, g.guard_open_at, g.rotation_at, g.second_rotation_at),
                                 ("until", T + GUARD_S, T + ROTATION_S, None))
                self.assertEqual((g.misses, g.confidence), ((), "normal"))

    def test_a_plus_one_with_the_flag_set_restarts_the_timer_once_624_h_have_run(self):
        one = Switch(T + DAY, 90, 91)
        for late in (60, -2):                             # a recorded switch may run 2 s ahead of the boot stamp
            with self.subTest(late=late):
                two = Switch(T + GUARD_S + late, 91, 92)
                g = derive(OLD, [Boot(T)], [first(), one, two])
                self.assertEqual((g.flag, g.flag_set_by, g.timer_start, g.timer_set_by), (True, one, two.ts, two))
                self.assertEqual((g.guard_open_at, g.rotation_at, g.second_rotation_at),
                                 (two.ts + GUARD_S, two.ts + ROTATION_S, None))
                self.assertEqual((g.misses, g.confidence), ((), "normal"))

    def test_a_plus_one_with_the_guard_closed_has_no_forced_path(self):
        one, two = Switch(T + DAY, 90, 91), Switch(T + 2 * DAY, 91, 92)
        g = derive(OLD, [Boot(T)], [first(), one, two])
        self.assertEqual(g.misses, ((two, keyguard.UNSEEN),))
        self.assertEqual(g.confidence, "low")
        self.assertTrue(any(keyguard.UNSEEN in r for r in g.reasons))
        # A boot seen afterwards settles the state again; the miss stays on the list.
        g = derive(OLD, [Boot(T), Boot(T + 3 * DAY)], [first(), one, two])
        self.assertEqual((g.confidence, g.flag, g.timer_start, len(g.misses)), ("normal", False, T + 3 * DAY, 1))

    def test_a_jump_of_two_or_more_changes_neither_flag_nor_timer(self):
        jump = Switch(T + 2 * DAY, 91, 93)
        g = derive(OLD, [Boot(T)], [first(89), Switch(T + DAY, 89, 91)])
        self.assertEqual((g.key, g.flag, g.timer_start, g.guard), (91, False, T, "open"))
        one = Switch(T + DAY, 90, 91)
        g = derive(OLD, [Boot(T)], [first(), one, jump])
        self.assertEqual((g.key, g.flag, g.flag_set_by, g.timer_start), (93, True, one, T))
        self.assertEqual((g.guard_open_at, g.rotation_at, g.misses), (T + GUARD_S, T + ROTATION_S, ()))

    def test_its_own_rotation_with_the_flag_clear_fires_again_an_hour_later(self):
        fired = Switch(T + ROTATION_S + 3, 90, 91)        # the first +1 since boot: its own, at 672 h
        g = derive(OLD, [Boot(T)], [first(), fired])
        self.assertEqual((g.flag, g.timer_start), (True, T))
        self.assertEqual((g.rotation_at, g.second_rotation_at), (T + ROTATION_S + HOUR, None))
        again = Switch(T + ROTATION_S + HOUR + 3, 91, 92)
        g = derive(OLD, [Boot(T)], [first(), fired, again])
        self.assertEqual((g.timer_start, g.timer_set_by, g.rotation_at, g.misses),
                         (again.ts, again, again.ts + ROTATION_S, ()))

    def test_its_own_rotation_with_the_flag_set_fires_once(self):
        # A first +1 from someone else before 672 h leaves the timer, so the unit still fires at 672 h.
        early = Switch(T + ROTATION_S - 38 * 60, 90, 91)
        g = derive(OLD, [Boot(T)], [first(), early])
        self.assertEqual((g.rotation_at, g.second_rotation_at), (T + ROTATION_S, None))
        own = Switch(T + ROTATION_S, 91, 92)
        g = derive(OLD, [Boot(T)], [first(), early, own])
        self.assertEqual((g.timer_start, g.rotation_at, g.misses), (own.ts, own.ts + ROTATION_S, ()))


class ConfidenceTest(unittest.TestCase):
    def test_the_guard_runs_624_h_and_the_rotation_timer_672_h(self):
        self.assertEqual((GUARD_S, ROTATION_S, HOUR), (624 * 3600, 672 * 3600, 3600))

    def test_an_unknown_stack_forecasts_nothing(self):
        g = derive(("unknown", None, "listed by name"), [Boot(T)], [first(), Switch(T + DAY, 90, 91)])
        self.assertEqual((g.key, g.guard, g.guard_open_at, g.rotation_at, g.confidence),
                         (91, "unknown", None, None, "none"))
        self.assertIn("listed by name", g.reasons[0])

    def test_how_the_stack_is_known_is_carried_into_the_reasons(self):
        for stack in (CURRENT, OLD):
            for known, confidence in (("reported", "normal"), ("behaviour", "normal"), ("assumed", "low")):
                with self.subTest(stack=stack[0], known=known):
                    g = derive((stack[0], known, "Plug Outdoor 1.4.8"), [Boot(T)], [first()])
                    self.assertEqual(g.confidence, confidence)
                    self.assertEqual(g.reasons[:2], (keyguard.RULES[stack[0]],
                                                     f"{keyguard.KNOWN[known]}: Plug Outdoor 1.4.8"))

    def test_no_boot_seen(self):
        one, two = Switch(T + DAY, 90, 91), Switch(T + 40 * DAY, 91, 92)
        g = derive(CURRENT, [], [first()])
        self.assertEqual((g.guard, g.rotation_at, g.confidence, g.boot), ("unknown", None, "low", None))
        self.assertIn(keyguard.NO_BOOT, g.reasons)
        g = derive(CURRENT, [], [first(), one])           # the +1 on record still arms the guard
        self.assertEqual((g.guard, g.guard_open_at, g.rotation_at, g.confidence),
                         ("until", one.ts + GUARD_S, one.ts + ROTATION_S, "low"))
        g = derive(OLD, [], [first(), one])               # flag set by now, but the timer may predate the record
        self.assertEqual((g.flag, g.timer_start, g.guard, g.rotation_at, g.confidence),
                         (True, None, "unknown", None, "low"))
        g = derive(OLD, [], [first(), one, two])          # a second +1 was taken with the flag set: it restarted
        self.assertEqual((g.timer_start, g.guard, g.guard_open_at, g.misses), (two.ts, "until", two.ts + GUARD_S, ()))

    def test_a_switch_record_that_starts_after_the_boot(self):
        for stack in (CURRENT, OLD):
            with self.subTest(stack=stack[0]):
                g = derive(stack, [Boot(T)], [first(ts=T + 20 * DAY)])
                self.assertEqual((g.flag, g.guard, g.second_rotation_at, g.confidence), (None, "unknown", None, "low"))
                self.assertEqual(g.rotation_at, T + ROTATION_S)
                self.assertIn(keyguard.UNHEARD, g.reasons)
                # First heard just after its boot (a new device joining): nothing was missed.
                g = derive(stack, [Boot(T)], [first(ts=T + 90)])
                self.assertEqual((g.flag, g.guard, g.confidence), (False, "open", "normal"))

    def test_boot_and_switch_order_ambiguous(self):
        for stack in (CURRENT, OLD):
            with self.subTest(stack=stack[0]):
                # The boot is known only as a range and the +1 falls inside it.
                g = derive(stack, [Boot(T, latest=T + 360)], [first(), Switch(T + 46, 90, 91)])
                self.assertEqual((g.flag, g.confidence), (True, "low"))
                self.assertTrue(any(r.startswith("boot and switch order ambiguous") for r in g.reasons))
                # A "by": not heard from before the boot until it was on the new key.
                g = derive(stack, [Boot(T)], [first(), Switch(T + DAY, 90, 91, unheard_from=T - DAY)])
                self.assertEqual((g.flag, g.confidence), (True, "low"))
                self.assertTrue(any(r.startswith("boot and switch order ambiguous") for r in g.reasons))
                # A jump of two in the range changes nothing the order could alter.
                g = derive(stack, [Boot(T, latest=T + 360)], [first(89), Switch(T + 46, 89, 91)])
                self.assertEqual((g.flag, g.confidence), (False, "normal"))

    def test_a_switch_first_seen_after_a_gap_dates_what_it_sets_at_the_latest(self):
        one = Switch(T + DAY, 90, 91)
        late = Switch(T + GUARD_S + DAY, 91, 92, unheard_from=T + GUARD_S + HOUR)
        g = derive(OLD, [Boot(T)], [first(), one, late])  # restarts the timer at a time nobody saw
        self.assertEqual((g.timer_start, g.confidence, g.misses), (late.ts, "low", ()))
        g = derive(CURRENT, [Boot(T)], [first(), Switch(T + DAY, 90, 91, unheard_from=T + HOUR)])
        self.assertEqual((g.guard_open_at, g.confidence), (T + DAY + GUARD_S, "low"))
        # On the old logic a first +1 sets only the flag, so its time does not matter.
        g = derive(OLD, [Boot(T)], [first(), Switch(T + DAY, 90, 91, unheard_from=T + HOUR)])
        self.assertEqual((g.timer_start, g.confidence), (T, "normal"))

    def test_one_boot_recorded_twice_is_one_boot(self):
        # A first read's uptime-dated stamp, later and with a wide range, beside the logged one.
        logged, read = Boot(T), Boot(T + 1650, earliest=T - 200)
        self.assertEqual(keyguard.one_per_boot([read, logged]), [logged])
        s = Switch(T + 70, 90, 91)
        g = derive(OLD, [read, logged], [first(), s])
        self.assertEqual((g.boot, g.flag_set_by, g.timer_start, g.confidence), (logged, s, T, "normal"))
        # Its range falling just short of the better stamp is still the same boot.
        self.assertEqual(keyguard.one_per_boot([Boot(T - 3, earliest=T - 1800), logged]), [logged])
        # A lock's range, and two real boots most of an hour apart, stay as they are.
        lock, later = Boot(T, latest=T + 360), Boot(T + 2400)
        self.assertEqual(keyguard.one_per_boot([later, lock]), [lock, later])

    def test_a_time_typed_by_hand_never_replaces_one_read_from_the_device(self):
        # `threadwatch rebooted` four minutes after the fact, beside the read that dates the boot to 2 s.
        typed, read = Boot(T + 240, typed=True), Boot(T, earliest=T - 1.8)
        self.assertEqual(keyguard.one_per_boot([typed, read]), [read])
        fired = Switch(T + ROTATION_S + 3, 90, 91)
        g = derive(OLD, [typed, read], [first(), fired])
        self.assertEqual((g.boot, g.timer_start, g.fired, g.rotation_at), (read, T, True, T + ROTATION_S + HOUR))
        # Nor a first read's, wide as its range is, nor a logged or seeded stamp as exact as the typed one.
        wide, logged = Boot(T + 1650, earliest=T - 200), Boot(T + 30)
        self.assertEqual(keyguard.one_per_boot([Boot(T + 240, typed=True), wide]), [wide])
        self.assertEqual(keyguard.one_per_boot([Boot(T - 60, typed=True), logged]), [logged])
        # With nothing read from the device it stands, and of two typed for one boot the earlier.
        self.assertEqual(keyguard.one_per_boot([typed, Boot(T + 100, typed=True)]), [Boot(T + 100, typed=True)])
        # A typed boot most of an hour from the one read is another boot.
        self.assertEqual(keyguard.one_per_boot([Boot(T + 2400, typed=True), read]), [read, Boot(T + 2400, typed=True)])

    def test_a_boot_stamp_that_ran_late_still_reads_the_units_own_firing(self):
        # The stamp may be BOOT_MARGIN_S late, so the 672 h firing can come that long before stamp + 672 h.
        for boot, real in ((Boot(T + 300), T), (Boot(T + 590), T), (Boot(T + 1000, earliest=T + 200), T - 300)):
            with self.subTest(boot=boot):
                fired = Switch(real + ROTATION_S + 3, 90, 91)
                g = derive(OLD, [boot], [first(), fired])
                self.assertEqual((g.flag, g.fired, g.timer_start), (True, True, boot.ts))
                self.assertEqual((g.rotation_at, g.second_rotation_at), (boot.ts + ROTATION_S + HOUR, None))
        # Earlier than the stamp allows, it is a neighbour's: the unit still fires at 672 h.
        g = derive(OLD, [Boot(T + 300)], [first(), Switch(T + ROTATION_S - 400, 90, 91)])
        self.assertEqual((g.fired, g.rotation_at), (False, T + 300 + ROTATION_S))

    def test_a_plus_one_as_the_guard_opens_is_no_miss_on_a_boot_stamp_that_ran_late(self):
        one = Switch(T + HOUR, 90, 91)
        for boot, real in ((Boot(T + 300), T), (Boot(T + 1000, earliest=T + 200), T - 300)):
            with self.subTest(boot=boot):
                g = derive(OLD, [boot], [first(), one, Switch(real + GUARD_S + 10, 91, 92)])
                self.assertEqual((g.misses, g.confidence), ((), "normal"))
        # Before the earliest the guard can have opened, it is still one.
        early = Switch(T + GUARD_S - 400, 91, 92)
        self.assertEqual(derive(OLD, [Boot(T + 300)], [first(), one, early]).misses, ((early, keyguard.UNSEEN),))
        # A timer a switch started is dated by that switch's first frame, which runs seconds late, not minutes.
        restart = Switch(T + GUARD_S + HOUR, 91, 92)
        early = Switch(restart.ts + GUARD_S - 300, 92, 93)
        self.assertEqual(derive(OLD, [Boot(T)], [first(), one, restart, early]).misses, ((early, keyguard.UNSEEN),))


class AfterTest(unittest.TestCase):
    """after(): one more event taken exactly, for the forecast's simulated
    boots and switches. The margin and the slack are for recorded stamps."""

    def test_a_neighbours_key_a_minute_before_the_672_h_mark_is_not_the_units_own_firing(self):
        start = derive(OLD, [Boot(T)], [first()])
        s = Switch(T + ROTATION_S - 60, 90, 91)
        # Recorded, the stamp could be the unit's own firing seen early: next at 673 h.
        self.assertEqual(derive(OLD, [Boot(T)], [first(), s]).rotation_at, T + ROTATION_S + HOUR)
        # Simulated, it is known to be a neighbour's: flag set, timer running, so the unit fires at 672 h.
        g = after(start, s)
        self.assertEqual((g.key, g.flag, g.flag_set_by, g.timer_start, g.fired), (91, True, s, T, False))
        self.assertEqual((g.guard, g.guard_open_at, g.rotation_at, g.second_rotation_at),
                         ("until", T + GUARD_S, T + ROTATION_S, None))

    def test_an_own_firing_with_the_flag_clear_fires_again_an_hour_later_then_restarts(self):
        start = derive(OLD, [Boot(T)], [first()])
        self.assertEqual((start.rotation_at, start.second_rotation_at), (T + ROTATION_S, T + ROTATION_S + HOUR))
        once = after(start, Switch(T + ROTATION_S, 90, 91), own=True)
        self.assertEqual((once.flag, once.timer_start, once.fired, once.rotation_at, once.second_rotation_at),
                         (True, T, True, T + ROTATION_S + HOUR, None))
        self.assertNotIn(keyguard.SECOND, once.reasons)
        twice = after(once, Switch(once.rotation_at, 91, 92), own=True)
        self.assertEqual((twice.timer_start, twice.fired, twice.rotation_at, twice.guard_open_at),
                         (once.rotation_at, False, once.rotation_at + ROTATION_S, once.rotation_at + GUARD_S))

    def test_a_simulated_boot_is_exact(self):
        s = Switch(T + 5 * DAY - 300, 90, 91)
        for stack in (CURRENT, OLD):
            with self.subTest(stack=stack[0]):
                start = derive(stack, [Boot(T)], [first()])
                # Recorded, a +1 five minutes before a boot stamp counts as taken at that boot.
                self.assertTrue(derive(stack, [Boot(T), Boot(T + 5 * DAY)], [first(), s]).flag)
                # Simulated, it came before the boot, and the boot cleared it.
                g = after(after(start, s), Boot(T + 5 * DAY))
                self.assertEqual((g.key, g.flag, g.guard, g.boot), (91, False, "open", Boot(T + 5 * DAY)))
                self.assertEqual((g.timer_start, g.rotation_at, g.fired),
                                 (T + 5 * DAY, T + 5 * DAY + ROTATION_S, False))
                self.assertEqual(g.second_rotation_at, T + 5 * DAY + ROTATION_S + HOUR if stack is OLD else None)

    def test_it_follows_the_same_rules_as_derive(self):
        events = [Switch(T + DAY, 90, 91), Switch(T + GUARD_S + 2 * DAY, 91, 92), Switch(T + GUARD_S + 3 * DAY, 92, 94),
                  Boot(T + GUARD_S + 9 * DAY), Switch(T + GUARD_S + 12 * DAY, 94, 95)]
        fields = ("key", "boot", "flag", "flag_set_by", "timer_start", "timer_set_by", "guard", "guard_open_at",
                  "rotation_at", "second_rotation_at", "fired")
        for stack in (CURRENT, OLD):
            g = derive(stack, [Boot(T)], [first()])
            for i, e in enumerate(events):
                with self.subTest(stack=stack[0], event=i):
                    g = after(g, e)
                    whole = derive(stack, [Boot(T)] + [x for x in events[:i + 1] if isinstance(x, Boot)],
                                   [first()] + [x for x in events[:i + 1] if isinstance(x, Switch)])
                    self.assertEqual([getattr(g, f) for f in fields], [getattr(whole, f) for f in fields])

    def test_the_current_logic_arms_on_a_plus_one_and_restarts_on_any_switch(self):
        start = derive(CURRENT, [Boot(T)], [first()])
        one = Switch(T + DAY, 90, 91)
        g = after(start, one)
        self.assertEqual((g.guard_open_at, g.rotation_at), (one.ts + GUARD_S, one.ts + ROTATION_S))
        forced = Switch(T + 2 * DAY, 91, 92)              # past the armed guard: the state after it is still known
        g = after(g, forced)
        self.assertEqual((g.flag_set_by, g.guard_open_at, g.rotation_at, g.misses),
                         (forced, forced.ts + GUARD_S, forced.ts + ROTATION_S, ()))
        jump = Switch(T + 3 * DAY, 92, 94)
        g = after(g, jump)
        self.assertEqual((g.flag_set_by, g.guard_open_at, g.rotation_at),
                         (forced, forced.ts + GUARD_S, jump.ts + ROTATION_S))

    def test_an_unknown_stack_only_changes_key(self):
        start = derive(("unknown", None, "not listed"), [], [first()])
        g = after(after(start, Boot(T)), Switch(T + DAY, 90, 92))
        self.assertEqual((g.key, g.boot, g.guard, g.rotation_at, g.confidence), (92, None, "unknown", None, "none"))

    def test_confidence_reasons_and_misses_stay_those_of_the_record(self):
        start = derive(("old", "assumed", "Plug Outdoor 1.4.8"), [Boot(T)], [first(), Switch(T + DAY, 90, 91),
                                                                           Switch(T + 2 * DAY, 91, 92)])
        g = after(start, Switch(T + 30 * DAY, 92, 93))
        self.assertEqual((g.confidence, g.reasons, g.misses), (start.confidence, start.reasons, start.misses))
        self.assertEqual(len(g.misses), 1)


if __name__ == "__main__":
    unittest.main()
