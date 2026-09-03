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


if __name__ == "__main__":
    unittest.main()
