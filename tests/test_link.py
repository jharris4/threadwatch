"""Slow link degradation (threadwatch.link) on a last-seen row."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.link import DAY_S, PAUSE_GAP_S, WARMUP_FRAMES, assess

T0 = 1_700_000_000.0
DROP, HOLD = 8.0, 1800.0


def row(rssi, frames=WARMUP_FRAMES, **extra):
    return {"rssi": rssi, "frames": frames, "last_seen": T0, **extra}


def heard(r, now, rssi=None, **kw):
    """A look at the row after the device was heard again: a frame more,
    heard now, its average moved to ``rssi`` when given."""
    r["frames"] += 1
    r["last_seen"] = now
    if rssi is not None:
        r["rssi"] = rssi
    return assess(r, now, DROP, HOLD, **kw)


class AssessTest(unittest.TestCase):
    def test_reference_taken_only_after_warmup(self):
        r = row(-60.0, frames=WARMUP_FRAMES - 1)
        self.assertIsNone(assess(r, T0, DROP, HOLD))
        self.assertNotIn("rssi_ref", r)
        r["frames"] = WARMUP_FRAMES
        self.assertIsNone(assess(r, T0, DROP, HOLD))
        self.assertEqual((r["rssi_ref"], r["rssi_ref_ts"]), (-60.0, T0))

    def test_drop_announced_once_it_has_held(self):
        r = row(-60.0)
        assess(r, T0, DROP, HOLD)
        self.assertIsNone(heard(r, T0 + 60, -69.0))                # clock starts
        self.assertEqual(r["rssi_low_since"], T0 + 60)
        self.assertIsNone(heard(r, T0 + 60 + HOLD - 1))
        self.assertEqual(heard(r, T0 + 60 + HOLD), "degraded")
        self.assertTrue(r["rssi_degraded"])
        self.assertIsNone(heard(r, T0 + 60 + HOLD + 600))          # announced once

    def test_flicker_at_the_threshold_does_not_restart_the_clock(self):
        r = row(-60.0)
        assess(r, T0, DROP, HOLD)
        heard(r, T0 + 60, -69.0)
        heard(r, T0 + 600, -66.0)                           # between -68 and -64: no change
        self.assertEqual(r["rssi_low_since"], T0 + 60)
        self.assertIsNone(heard(r, T0 + 700, -63.0))        # back within half the drop: clock cleared
        self.assertNotIn("rssi_low_since", r)

    def test_recovery_closes_an_announced_drop(self):
        r = row(-60.0)
        assess(r, T0, DROP, HOLD)
        heard(r, T0 + 60, -70.0)
        heard(r, T0 + 60 + HOLD)
        self.assertIsNone(heard(r, T0 + 60 + HOLD + 600, -66.0))   # not enough to count as recovered
        self.assertEqual(heard(r, T0 + 60 + HOLD + 1200, -62.0), "recovered")
        self.assertNotIn("rssi_degraded", r)
        self.assertNotIn("rssi_low_since", r)

    def test_daily_refresh_follows_drift_and_makes_a_lasting_drop_the_new_normal(self):
        r = row(-60.0)
        assess(r, T0, DROP, HOLD)
        # Heard all day (a look every ten minutes would be more; two an
        # hour is enough to keep the clocks running).
        for i in range(1, 49):
            heard(r, T0 + i * 1800, -63.0)
        self.assertEqual((r["rssi_ref"], r["rssi_ref_ts"]), (-63.0, T0 + DAY_S))
        heard(r, T0 + DAY_S + 60, -75.0)
        self.assertEqual(heard(r, T0 + DAY_S + 60 + HOLD), "degraded")
        for i in range(2, 48):
            heard(r, T0 + DAY_S + i * 1800)
        # A day after the reference, but the drop is younger than a day: keep waiting.
        self.assertIsNone(heard(r, T0 + 2 * DAY_S))
        self.assertEqual(r["rssi_ref"], -63.0)
        # The refresh adopts the low level and closes the announced drop.
        self.assertEqual(heard(r, T0 + 2 * DAY_S + 60), "recovered")
        self.assertEqual(r["rssi_ref"], -75.0)
        self.assertNotIn("rssi_degraded", r)
        self.assertNotIn("rssi_low_since", r)
        heard(r, T0 + 2 * DAY_S + 120, -84.0)               # a further drop measures from the new normal
        self.assertEqual(heard(r, T0 + 2 * DAY_S + 120 + HOLD), "degraded")

    def test_refresh_of_an_unannounced_drop_is_silent(self):
        r = row(-60.0)
        assess(r, T0, DROP, HOLD)
        for i in range(1, 49):
            self.assertIsNone(heard(r, T0 + i * 1800, -63.0))   # drift, never a drop
        self.assertNotIn("rssi_degraded", r)

    def test_disabled_or_no_rssi(self):
        r = row(-60.0)
        self.assertIsNone(assess(r, T0, 0, HOLD))
        self.assertNotIn("rssi_ref", r)
        self.assertIsNone(assess(row(None), T0, DROP, HOLD))


class StaleRowTest(unittest.TestCase):
    """BUG-09: a row nothing has been heard for is not evidence of anything."""

    def test_a_silent_device_is_neither_degraded_nor_rebased(self):
        r = {"frames": 200, "last_seen": T0, "rssi": -70.0, "rssi_ref": -50.0, "rssi_ref_ts": T0}
        verdicts = [assess(r, now, 12, 300) for now in (T0, T0 + 300, T0 + DAY_S)]
        self.assertEqual(verdicts, [None, None, None])
        self.assertEqual((r["rssi_ref"], r["rssi_ref_ts"]), (-50.0, T0))    # not re-based to a stale level
        self.assertNotIn("rssi_degraded", r)

    def test_a_quiet_spell_between_receptions_does_not_count_toward_the_hold(self):
        r = row(-60.0)
        assess(r, T0, DROP, HOLD)
        heard(r, T0 + 60, -70.0)                             # the clock starts
        heard(r, T0 + 600)                                   # nine minutes low
        self.assertIsNone(heard(r, T0 + 600 + 2 * PAUSE_GAP_S))   # back after an hour's silence: still low
        self.assertEqual(r["rssi_low_since"], T0 + 60 + 2 * PAUSE_GAP_S)   # the hour is not held time
        self.assertIsNone(heard(r, T0 + 600 + 2 * PAUSE_GAP_S + HOLD - 600))
        self.assertEqual(heard(r, T0 + 600 + 2 * PAUSE_GAP_S + HOLD - 540 + 1), "degraded")

    def test_a_gap_shorter_than_a_quiet_spell_is_ordinary_cadence(self):
        r = row(-60.0)
        assess(r, T0, DROP, HOLD)
        heard(r, T0 + 60, -70.0)
        self.assertEqual(heard(r, T0 + 60 + HOLD), "degraded")   # thirty minutes between polls: counted


if __name__ == "__main__":
    unittest.main()
