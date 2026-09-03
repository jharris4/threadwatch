"""Inventory helpers: suggested entries for unknown addresses, and adopt."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.names import DeviceNames, LastSeen, adopt, load_observed_names, suggest_entries  # noqa: E402

AQ = "26976e7f7d20964a"
TV1 = "b62c32bf669272db"
TV2 = "e6c279e8f0c70298"


class SuggestTest(unittest.TestCase):
    def _report(self, state):
        seen = LastSeen(None)
        seen.touch(AQ, 1_756_800_000.0, 1, pan=0x4e21, rssi=-61.0)
        seen.touch(AQ, 1_756_803_600.0, 1, pan=0x4e21, rssi=-61.0)
        seen.touch(TV1, 1_756_800_000.0, 1, pan=0x4e21, rssi=-88.0)
        return seen.report(DeviceNames(None), quiet_after_s=3600, now=1_756_804_000.0)

    def test_entry_per_unknown_with_harvested_name_first(self):
        observed = {AQ: {"office-aq-1a2b": 12, "office-aq-1a2b-old": 2}}
        entries = suggest_entries(self._report(None)["unknown"], observed)
        self.assertEqual([e["extendedAddress"] for e in entries], [TV1.upper(), AQ.upper()])
        aq = entries[1]
        self.assertEqual(aq["name"], "office-aq-1a2b")
        self.assertIn("2 frames since", aq["note"])
        self.assertIn("good reception (-61.0 dBm)", aq["note"])
        self.assertIn("advertised as office-aq-1a2b, office-aq-1a2b-old", aq["note"])
        tv = entries[0]
        self.assertEqual(tv["name"], "")
        self.assertIn("marginal reception", tv["note"])
        self.assertNotIn("advertised", tv["note"])

    def test_blank_name_from_a_pasted_suggestion_stays_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            inv.write_text(json.dumps([{"name": "", "extendedAddress": AQ.upper(), "note": "?"}]))
            self.assertIsNone(DeviceNames(inv).name(AQ))

    def test_observed_names_missing_or_broken_is_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(load_observed_names(Path(d)), {})
            (Path(d) / "observed-names.json").write_text("{not json")
            self.assertEqual(load_observed_names(Path(d)), {})
            (Path(d) / "observed-names.json").write_text(json.dumps({AQ: {"x": 1}}))
            self.assertEqual(load_observed_names(Path(d)), {AQ: {"x": 1}})


class AdoptTest(unittest.TestCase):
    def test_creates_the_file_and_appends_entries(self):
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "config" / "devices.json"
            msg = adopt(inv, "26:97:6E:7F:7D:20:96:4A", "Office Air Quality", role="router")
            self.assertIn("added 'Office Air Quality' = " + AQ, msg)
            adopt(inv, TV1, "Living Room Apple TV")
            entries = json.loads(inv.read_text())
            self.assertEqual(entries, [
                {"name": "Office Air Quality", "extendedAddress": AQ.upper(), "role": "router"},
                {"name": "Living Room Apple TV", "extendedAddress": TV1.upper()},
            ])
            names = DeviceNames(inv)
            self.assertEqual(names.name(AQ), "Office Air Quality")
            self.assertTrue(names.is_router(AQ))

    def test_same_name_gains_a_rotated_address(self):
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            inv.write_text(json.dumps([{"name": "Living Room Apple TV", "extendedAddress": TV1.upper(),
                                        "note": "rotates"}]))
            msg = adopt(inv, TV2, "living room apple tv", role="border-router")
            self.assertIn("2 addresses", msg)
            entry = json.loads(inv.read_text())[0]
            self.assertNotIn("extendedAddress", entry)
            self.assertEqual(entry["extendedAddresses"], [TV1.upper(), TV2.upper()])
            self.assertEqual(entry["role"], "border-router")
            self.assertEqual(entry["note"], "rotates")
            self.assertEqual(DeviceNames(inv).name(TV2), "Living Room Apple TV")

    def test_already_listed(self):
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            adopt(inv, AQ, "Office Air Quality")
            self.assertIn("already listed", adopt(inv, AQ, "office air quality"))
            with self.assertRaises(ValueError) as cm:
                adopt(inv, AQ, "Bedroom Sensor")
            self.assertIn("already listed as 'Office Air Quality'", str(cm.exception))
            self.assertEqual(len(json.loads(inv.read_text())), 1)

    def test_rejects_bad_input_without_touching_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            with self.assertRaises(ValueError):
                adopt(inv, "0x1234", "Thing")
            with self.assertRaises(ValueError):
                adopt(inv, AQ, "   ")
            self.assertFalse(inv.exists())


if __name__ == "__main__":
    unittest.main()
