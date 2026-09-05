"""Storm latching in threadwatch.detect."""

import sys
import unittest
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
