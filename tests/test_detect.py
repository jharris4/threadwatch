"""Storm latching in threadwatch.detect."""

import sys
import unittest
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.detect import Detector, DetectorConfig  # noqa: E402


class StormLatchTest(unittest.TestCase):
    def _run(self, floods_at, until, calm=250, flood=1500):
        det = Detector(DetectorConfig(alert_cooldown_s=0))
        active = {}
        for w in range(0, until, 10):
            n = flood if any(t <= w < t + 10 for t in floods_at) else calm
            for i in range(n):
                det.add_frame(w + i / n)
            active[w] = det.storm_active
        return det, active

    def test_one_stray_burst_does_not_end_the_storm(self):
        # Baseline, then floods every 80 s; a stray burst 30 s after the fourth.
        floods = [200, 280, 360, 440, 470, 520, 600]
        det, active = self._run(floods, until=700)
        self.assertTrue(active[370])          # locked after three periodic onsets
        self.assertTrue(active[480])          # still active through the stray burst
        self.assertTrue(det.storm_active)

    def test_storm_persists_through_a_continuous_flood(self):
        floods = [200, 280, 360] + list(range(440, 1400, 10))   # bursts merge into one long flood
        det, active = self._run(floods, until=2000)
        self.assertTrue(active[1000])
        self.assertTrue(active[1390])
        self.assertLess(det._baseline(), 400)                  # the flood never became the baseline
        self.assertFalse(det.storm_active)                     # over, three periods after it stopped

    def test_storm_clears_when_floods_stop(self):
        det, active = self._run([200, 280, 360], until=1000)
        self.assertTrue(active[370])
        self.assertFalse(det.storm_active)    # three missed periods later

    def test_a_second_storm_reports_its_own_period_inside_the_cooldown(self):
        # Two storms in one replayed day: 80 s bursts, a quiet hour, then
        # 60 s bursts. The alert cooldown (default 30 min) is still running
        # from the first storm when the second locks, and on the wall clock
        # the whole replay is one instant. The details the pipeline reports
        # must describe the storm running now, whatever the cooldown says.
        det = Detector(DetectorConfig())
        first = [200, 280, 360]
        second = [4200, 4260, 4320]
        for w in range(0, 4400, 10):
            n = 1500 if any(t <= w < t + 10 for t in first + second) else 250
            for i in range(n):
                det.add_frame(w + i / n)
            if w == 370:
                self.assertAlmostEqual(det.storm_details["period"], 80.0)
        self.assertTrue(det.storm_active)
        self.assertAlmostEqual(det.storm_details["period"], 60.0)
        self.assertEqual(det.storm_details["onsets"], [4200.0, 4260.0, 4320.0])
        self.assertEqual(det.alerts_sent, 2)                      # the cooldown ran on the frame clock

    def test_a_timestamp_jump_costs_a_history_not_a_step_per_window(self):
        import time
        det = Detector(DetectorConfig(alert_cooldown_s=0))
        for i in range(300):
            det.add_frame(1_700_000_000.0 + i / 30)                 # one busy window
        t0 = time.monotonic()
        det.add_frame(0xFFFFFFFF + 0.5)                             # a corrupt record 2.6e9 s on
        self.assertLess(time.monotonic() - t0, 1.0)                 # was ~16 min of spinning
        self.assertLess(0xFFFFFFFF + 0.5 - det.window_start, 10)    # the window clock caught up
        self.assertEqual(det.window_count, 1)
        self.assertEqual(det._baseline(), 0.0)                      # a history of empty windows
        self.assertEqual(len(det.counts), det.counts.maxlen)
        self.assertFalse(det.in_flood or det.storm_active)

    def test_time_going_backwards_restarts_the_window_clock(self):
        det = Detector(DetectorConfig(alert_cooldown_s=0))
        t0 = 1_700_000_000.0
        for i in range(300):
            det.add_frame(t0 + i / 30)
        det.add_frame(0xFFFFFFFF + 0.5)                             # one corrupt record...
        det.add_frame(t0 + 10.5)                                    # ...and the file carries on
        self.assertEqual(det.window_start, t0 + 10.5)               # the window clock came back
        self.assertEqual(det.window_count, 1)
        for i in range(600):
            det.add_frame(t0 + 11 + i / 10)                         # a minute of ordinary traffic
        self.assertEqual(det.window_start, t0 + 70.5)               # six windows closed again...
        self.assertEqual(list(det.counts)[-3:], [100, 100, 100])    # ...with their frames in them
        det.add_frame(t0 + 71 - 0.5)                                # a little out of order: no reset
        self.assertEqual((det.window_start, det.window_count), (t0 + 70.5, 6))

    def test_a_short_gap_still_closes_every_window(self):
        det = Detector(DetectorConfig(alert_cooldown_s=0))
        det.add_frame(1000.0)
        det.add_frame(1000.0 + 65)                                  # 6 whole windows on
        self.assertEqual(list(det.counts), [1, 0, 0, 0, 0, 0])
        self.assertEqual(det.window_start, 1060.0)
        self.assertEqual(det.window_count, 1)


if __name__ == "__main__":
    unittest.main()


class DegeneratePeriodOnsetsTest(unittest.TestCase):
    def test_period_onsets_below_two_does_not_divide_by_zero(self):
        for n in (0, 1):
            det = Detector(DetectorConfig(period_onsets=n, flood_min_frames=10))
            t = 0.0
            for _ in range(7):
                for _ in range(2):
                    det.add_frame(t); t += 1.0
                t += 60.0
            for _ in range(6):
                for _ in range(40):
                    det.add_frame(t); t += 0.1
                t += 60.0


class FloodThresholdTest(unittest.TestCase):
    """A window is a flood at flood_multiplier x the calm baseline, but never
    under flood_min_frames: the floor is absolute. Inverted into a ceiling
    it would make every window on a fresh start a flood (baseline 0), and
    ordinary busy minutes on an established mesh, and phase_locked_storm
    would page and freeze the ring on normal traffic."""

    def setUp(self):
        self.det = Detector(DetectorConfig(alert_cooldown_s=0))    # x3, floor 400
        self.t = 1_700_000_000.0
        self.opened = 0

    def _windows(self, counts):
        """Feed windows of exactly these frame counts, each closed by the
        first frame of the one after it."""
        for n in counts:
            for i in range(self.opened, n):
                self.det.add_frame(self.t + i * 10 / n)
            self.t += 10
            self.det.add_frame(self.t)
            self.opened = 1
            self.assertEqual(self.det.counts[-1], n)
        return self.det

    def test_the_floor_holds_over_a_low_baseline(self):
        det = self._windows([50] * 10)                        # baseline 50: 3x is 150
        self.assertEqual(det._baseline(), 50)
        self._windows([300])                                  # over 3x, under the floor
        self.assertFalse(det.in_flood)
        self.assertEqual(list(det.onsets), [])
        self._windows([400])                                  # at the floor
        self.assertTrue(det.in_flood)
        self.assertEqual(len(det.onsets), 1)

    def test_a_fresh_start_with_an_empty_baseline_is_not_all_floods(self):
        det = self.det
        det.add_frame(self.t)
        det.add_frame(self.t + 65)                            # six windows on: five empty ones behind it
        self.assertEqual(det._baseline(), 0.0)                # a ceiling here would be a threshold of 0
        self.opened, self.t = 1, self.t + 60
        self._windows([5])                                    # the first quiet window of traffic
        self.assertFalse(det.in_flood)
        self.assertEqual(list(det.onsets), [])

    def test_a_high_baseline_raises_the_bar_above_the_floor(self):
        det = self._windows([250] * 10)                       # the calm mesh of the incident: 3x is 750
        self.assertEqual(det._baseline(), 250)
        self._windows([600])                                  # over the floor, under 3x
        self.assertFalse(det.in_flood)
        self.assertEqual(list(det.onsets), [])
        self._windows([750])
        self.assertTrue(det.in_flood)
        self.assertEqual(len(det.onsets), 1)


class SnapshotUnderMutationTest(unittest.TestCase):
    """snapshot() runs on the status thread while add_frame appends on the
    capture thread: copying a deque mid-append raises "mutated during
    iteration". The snapshot tries again, and after three collisions
    gives a reduced answer rather than take status.json down with it."""

    class _Flaky(deque):
        """A deque whose first ``failures`` iterations collide with an append."""

        def __init__(self, items, failures):
            super().__init__(items, maxlen=360)
            self.failures, self.iterations = failures, 0

        def __iter__(self):
            self.iterations += 1
            if self.failures:
                self.failures -= 1
                raise RuntimeError("deque mutated during iteration")
            return super().__iter__()

    def _detector(self, failures):
        det = Detector(DetectorConfig())
        for w in range(8):
            for i in range(250):
                det.add_frame(w * 10 + i / 250)
        det.calm = self._Flaky(det.calm, failures)       # _baseline iterates calm first
        return det

    def test_a_collision_or_two_is_retried_and_the_full_snapshot_returned(self):
        for failures in (0, 1, 2):
            det = self._detector(failures)
            snap = det.snapshot()
            self.assertEqual(snap, {"baseline_frames_per_window": 250.0, "recent_windows": [250] * 6,
                                    "storm_active": False, "flood_onsets_recent": [], "alerts_sent": 0}, failures)
            self.assertEqual(det.calm.iterations, failures + 1)

    def test_three_collisions_give_the_reduced_snapshot(self):
        det = self._detector(3)
        self.assertEqual(det.snapshot(), {"storm_active": False, "alerts_sent": 0})
        self.assertEqual(det.calm.iterations, 3)
        self.assertEqual(det.snapshot()["baseline_frames_per_window"], 250.0)   # the next call is whole again
