"""hacause.classify: which radio evidence explains an HA unavailability,
and that the first match wins in the documented order."""

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.hacause import classify

NOW = 1_700_000_000.0
SINCE = NOW - 900                       # HA lost the device 15 min ago


def row(**fields):
    base = {"first_seen": NOW - 86400, "last_seen": NOW - 60, "frames": 100, "rssi": -60.0}
    base.update(fields)
    return base


class ClassifyTest(unittest.TestCase):
    def test_each_cause_from_crafted_rows(self):
        parent = row(counter_seq=86, counter_ts=NOW - 30)
        self.assertEqual(classify(row(counter_seq=84, counter_ts=NOW - 30), parent, SINCE, NOW)[0], "key_lag")
        self.assertIn("generation 84, parent on 86", classify(row(counter_seq=84, counter_ts=NOW - 30),
                                                                parent, SINCE, NOW)[1])
        self.assertEqual(classify(row(starved=True), parent, SINCE, NOW)[0], "lost_parent")
        cause, text = classify(row(last_seen=SINCE - 600, quiet_reported=True), None, SINCE, NOW)
        self.assertEqual(cause, "silent")
        self.assertIn(time.strftime("%H:%M", time.localtime(SINCE - 600)), text)
        self.assertEqual(classify(row(last_seen=NOW - 120), None, SINCE, NOW)[0], "radio_ok")
        self.assertEqual(classify(None, None, SINCE, NOW)[0], "unheard")
        self.assertEqual(classify(row(last_seen=NOW - 1200, rssi=-88.0), None, SINCE, NOW)[0], "unheard")
        self.assertEqual(classify({}, None, SINCE, NOW)[0], "unheard")             # never heard: no last_seen

    def test_first_match_wins_in_the_documented_order(self):
        parent = row(counter_seq=86, counter_ts=NOW - 30)
        lagging_and_starved = row(counter_seq=84, counter_ts=NOW - 30, starved=True)
        self.assertEqual(classify(lagging_and_starved, parent, SINCE, NOW)[0], "key_lag")
        starved_and_silent = row(starved=True, last_seen=SINCE - 600, quiet_reported=True)
        self.assertEqual(classify(starved_and_silent, None, SINCE, NOW)[0], "lost_parent")
        # The recorder's own open key-lag episode is the evidence, whatever
        # the raw reading says now.
        self.assertEqual(classify(row(keylag_since=NOW - 3000, keylag_gens=[83, 86], starved=True),
                                  None, SINCE, NOW), ("key_lag", classify(row(counter_seq=83, counter_ts=NOW),
                                                                          row(counter_seq=86, counter_ts=NOW),
                                                                          SINCE, NOW)[1]))

    def test_a_stale_generation_reading_or_one_behind_is_not_a_key_lag(self):
        parent = row(counter_seq=86, counter_ts=NOW - 30)
        self.assertEqual(classify(row(counter_seq=84, counter_ts=NOW - 7200), parent, SINCE, NOW)[0], "radio_ok")
        self.assertEqual(classify(row(counter_seq=85, counter_ts=NOW - 30), parent, SINCE, NOW)[0], "radio_ok")
        self.assertEqual(classify(row(counter_seq=84, counter_ts=NOW - 30), None, SINCE, NOW)[0], "radio_ok")

    def test_a_silence_after_ha_lost_the_device_is_not_the_radio_going_first(self):
        # The last frame came after HA marked it unavailable: the radio did
        # not go first, and nothing has announced a silence yet.
        self.assertEqual(classify(row(last_seen=SINCE + 60), None, SINCE, NOW)[0], "unheard")
        # Announced quiet, but the last frame was inside the two minutes
        # before HA lost it: too close to call the radio first.
        self.assertEqual(classify(row(last_seen=SINCE - 60, quiet_reported=True), None, SINCE, NOW)[0], "unheard")


if __name__ == "__main__":
    unittest.main()


class DroppedPollsAndMismatchTest(unittest.TestCase):
    def test_the_two_causes_sit_between_key_lag_and_lost_parent(self):
        parent = row(counter_seq=86, counter_ts=NOW - 30)
        self.assertEqual(classify(row(unserved=True, starved=True), None, SINCE, NOW)[0], "dropped_polls")
        self.assertEqual(classify(row(counter_mismatch_ts=NOW - 60, unserved=True), None, SINCE, NOW)[0],
                         "counter_mismatch")
        self.assertEqual(classify(row(counter_mismatch_ts=NOW - 3 * 3600), None, SINCE, NOW)[0], "radio_ok")
        self.assertEqual(classify(row(counter_seq=84, counter_ts=NOW - 30, counter_mismatch_ts=NOW - 60),
                                  parent, SINCE, NOW)[0], "key_lag")
