"""Chronological TX observations must not inherit counter high-water semantics."""

import unittest

from threadwatch.keyfacts import HISTORY_LIMIT, facts, latest_generation, observe, summary


class KeyFactsTest(unittest.TestCase):
    def test_latest_is_chronological_highest_is_historical_and_mixed_expires(self):
        row = {}
        observe(row, "mle", 87, 100, accepted=True)
        observe(row, "mac", 85, 110, accepted=True)
        state = summary(row, 115, 20)
        self.assertEqual(latest_generation(row), (85, 110))
        self.assertEqual(state["highest_authenticated"], {"sequence": 87, "ts": 100, "legacy": False})
        self.assertEqual(state["mle"]["latest"]["ts"], 100)
        self.assertTrue(state["mixed"])
        self.assertEqual(state["recent_sequences"], [85, 87])
        self.assertFalse(summary(row, 125, 20)["mixed"])

    def test_rejected_traffic_never_becomes_latest_or_mixed_but_remains_forensic_evidence(self):
        row = {}
        observe(row, "mac", 85, 100, accepted=True)
        observe(row, "mle", 90, 110, accepted=False, reason="counter_not_advancing")
        self.assertEqual(latest_generation(row), (85, 100))
        state = summary(row, 110)
        self.assertFalse(state["mixed"])
        self.assertIsNone(state["mle"]["latest"])
        self.assertEqual(state["highest_authenticated"]["sequence"], 90)
        self.assertEqual(state["mle"]["rejected"][0]["count"], 1)
        self.assertEqual(state["recent_rejected"], 1)
        self.assertEqual(summary(row, 110 + 1801)["recent_rejected"], 0)

    def test_same_frame_mac_wins_tie_and_retries_have_separate_counts(self):
        row = {}
        observe(row, "mac", 85, 100, accepted=True)
        observe(row, "mle", 87, 100, accepted=True)
        self.assertEqual(latest_generation(row), (85, 100))
        observe(row, "mac", 85, 101, accepted=True, retry=True)
        span = facts(row)["mac"]["accepted"][0]
        self.assertEqual((span["count"], span["retries"], span["first_ts"], span["last_ts"]), (1, 1, 100, 101))

    def test_history_is_bounded_per_layer_and_decision_without_forgetting_highest(self):
        row = {}
        observe(row, "mac", 900, 1, accepted=True)
        for seq in range(HISTORY_LIMIT + 5):
            for layer in ("mac", "mle"):
                observe(row, layer, seq, seq + 10, accepted=True)
                observe(row, layer, seq, seq + 10, accepted=False)
        state = facts(row)
        self.assertEqual(state["highest_authenticated"]["sequence"], 900)
        for layer in ("mac", "mle"):
            for decision in ("accepted", "rejected"):
                self.assertEqual(len(state[layer][decision]), HISTORY_LIMIT)

    def test_late_packet_cannot_rewind_latest_or_refresh_high_sequence(self):
        row = {}
        observe(row, "mac", 87, 100, accepted=True)
        observe(row, "mac", 85, 120, accepted=True)
        observe(row, "mac", 87, 90, accepted=True)
        self.assertEqual(latest_generation(row), (85, 120))
        self.assertEqual(facts(row)["highest_authenticated"]["ts"], 100)

    def test_legacy_estimate_uses_retained_previous_counter_and_does_not_invent_counts(self):
        row = {"counter_seq": 87, "counter_ts": 100, "counter_prev": [10, 120, 85]}
        self.assertEqual(latest_generation(row), (85, 120))
        state = facts(row)
        self.assertTrue(state["mac"]["latest"]["legacy"])
        self.assertEqual(state["mac"]["accepted"], [])
        self.assertEqual(state["highest_authenticated"]["sequence"], 87)
        observe(row, "mac", 85, 130, accepted=True)
        self.assertFalse(facts(row)["mac"]["latest"]["legacy"])

    def test_invalid_saved_facts_are_ignored(self):
        row = {"key_facts": {"version": 1, "mac": {"latest": {"sequence": True, "ts": 1},
                                                     "accepted": [{"sequence": 1, "first_ts": float('nan'),
                                                                   "last_ts": 2}], "rejected": 42},
                             "mle": [], "highest_authenticated": {"sequence": -1, "ts": 2}}}
        self.assertEqual(latest_generation(row), (None, None))
        observe(row, "mac", 85, 10, accepted=True)
        self.assertEqual(latest_generation(row), (85, 10))
