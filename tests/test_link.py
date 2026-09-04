"""Slow link degradation (threadwatch.link) on a last-seen row."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.link import DAY_S, WARMUP_FRAMES, assess  # noqa: E402

T0 = 1_700_000_000.0
DROP, HOLD = 8.0, 1800.0


def row(rssi, frames=WARMUP_FRAMES, **extra):
    return {"rssi": rssi, "frames": frames, "last_seen": T0, **extra}


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
        r["rssi"] = -69.0
        self.assertIsNone(assess(r, T0 + 60, DROP, HOLD))          # clock starts
        self.assertEqual(r["rssi_low_since"], T0 + 60)
        self.assertIsNone(assess(r, T0 + 60 + HOLD - 1, DROP, HOLD))
        self.assertEqual(assess(r, T0 + 60 + HOLD, DROP, HOLD), "degraded")
        self.assertTrue(r["rssi_degraded"])
        self.assertIsNone(assess(r, T0 + 60 + HOLD + 600, DROP, HOLD))   # announced once

    def test_flicker_at_the_threshold_does_not_restart_the_clock(self):
        r = row(-60.0)
        assess(r, T0, DROP, HOLD)
        r["rssi"] = -69.0
        assess(r, T0 + 60, DROP, HOLD)
        r["rssi"] = -66.0                                   # between -68 and -64: no change
        assess(r, T0 + 600, DROP, HOLD)
        self.assertEqual(r["rssi_low_since"], T0 + 60)
        r["rssi"] = -63.0                                   # back within half the drop: clock cleared
        self.assertIsNone(assess(r, T0 + 700, DROP, HOLD))
        self.assertNotIn("rssi_low_since", r)

    def test_recovery_closes_an_announced_drop(self):
        r = row(-60.0)
        assess(r, T0, DROP, HOLD)
        r["rssi"] = -70.0
        assess(r, T0 + 60, DROP, HOLD)
        assess(r, T0 + 60 + HOLD, DROP, HOLD)
        r["rssi"] = -66.0                                   # not enough to count as recovered
        self.assertIsNone(assess(r, T0 + 3 * HOLD, DROP, HOLD))
        r["rssi"] = -62.0
        self.assertEqual(assess(r, T0 + 4 * HOLD, DROP, HOLD), "recovered")
        self.assertNotIn("rssi_degraded", r)
        self.assertNotIn("rssi_low_since", r)

    def test_daily_refresh_follows_drift_and_makes_a_lasting_drop_the_new_normal(self):
        r = row(-60.0)
        assess(r, T0, DROP, HOLD)
        r["rssi"] = -63.0
        assess(r, T0 + DAY_S, DROP, HOLD)
        self.assertEqual((r["rssi_ref"], r["rssi_ref_ts"]), (-63.0, T0 + DAY_S))
        r["rssi"] = -75.0
        assess(r, T0 + DAY_S + 60, DROP, HOLD)
        self.assertEqual(assess(r, T0 + DAY_S + 60 + HOLD, DROP, HOLD), "degraded")
        # A day after the reference, but the drop is younger than a day: keep waiting.
        self.assertIsNone(assess(r, T0 + 2 * DAY_S, DROP, HOLD))
        self.assertEqual(r["rssi_ref"], -63.0)
        # The refresh adopts the low level and closes the announced drop.
        self.assertEqual(assess(r, T0 + 2 * DAY_S + 60, DROP, HOLD), "recovered")
        self.assertEqual(r["rssi_ref"], -75.0)
        self.assertNotIn("rssi_degraded", r)
        self.assertNotIn("rssi_low_since", r)
        r["rssi"] = -84.0                                   # a further drop measures from the new normal
        assess(r, T0 + 2 * DAY_S + 120, DROP, HOLD)
        self.assertEqual(assess(r, T0 + 2 * DAY_S + 120 + HOLD, DROP, HOLD), "degraded")

    def test_refresh_of_an_unannounced_drop_is_silent(self):
        r = row(-60.0)
        assess(r, T0, DROP, HOLD)
        r["rssi"] = -63.0                                   # drift, never a drop
        self.assertIsNone(assess(r, T0 + DAY_S, DROP, HOLD))
        self.assertNotIn("rssi_degraded", r)

    def test_disabled_or_no_rssi(self):
        r = row(-60.0)
        self.assertIsNone(assess(r, T0, 0, HOLD))
        self.assertNotIn("rssi_ref", r)
        self.assertIsNone(assess(row(None), T0, DROP, HOLD))


if __name__ == "__main__":
    unittest.main()
