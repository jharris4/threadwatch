"""stacks: the [keys.stacks] table and the one lookup the key guard
forecast asks it."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests  # noqa: F401  (the mDNS guard, installed on a direct run too: tests/no_lan)
from threadwatch import config as config_mod
from threadwatch import stacks

TABLE = '''
[keys.stacks.models]
"Air Monitor 2000" = { "1.0.26" = "old, reported", "1.0.27" = "unknown" }
"Door Sensor 20XYZ" = { "3.2.1" = "old, behaviour" }
"Plug Outdoor" = { "1.4.8" = "old, assumed" }
"Bulb A19" = { "5.1.45" = "current, reported" }

[keys.stacks.devices]
"Side Door Lock" = "current, reported"
"Hall Border Router" = "unknown"
'''

HA_MAP = {
    "d1": {"name": "Hall Air Monitor", "matched": True, "model": "Air Monitor 2000", "sw_version": "1.0.26"},
    "d2": {"name": "Attic Air Monitor", "matched": True, "model": "Air Monitor 2000", "sw_version": "1.0.28"},
    "d3": {"name": "Porch Bulb", "matched": True, "model": "Bulb GU10", "sw_version": "5.1.45"},
    "d4": {"name": "Rear Door", "matched": True, "model": "Door Sensor 20XYZ", "sw_version": None},
    "d5": {"name": "Garden Plug", "matched": False, "model": "Plug Outdoor", "sw_version": "1.4.8"},
    "d6": {"name": "Shed Door", "matched": True, "model": "Door Sensor 20XYZ", "sw_version": "3.2.1"},
    "d7": {"name": "Spare Monitor", "matched": True, "model": "Air Monitor 2000", "sw_version": "1.0.27"},
}


class StackTableTest(unittest.TestCase):
    def _load(self, text):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "devices.json").write_text("[]")
            (Path(d) / "config.toml").write_text(text)
            return config_mod.load(Path(d) / "config.toml")

    def test_the_table_loads_and_is_empty_by_default(self):
        self.assertEqual(self._load("[keys]\nconfirm_s = 900\n").key_stacks, {"models": {}, "devices": {}})
        got = self._load("[keys]\nconfirm_s = 900\n" + TABLE).key_stacks
        self.assertEqual(got["models"]["Air Monitor 2000"],
                         {"1.0.26": ("old", "reported"), "1.0.27": ("unknown", None)})
        self.assertEqual(got["devices"],
                         {"Side Door Lock": ("current", "reported"), "Hall Border Router": ("unknown", None)})

    def test_a_bad_entry_is_refused_at_load(self):
        for bad in ('[keys.stacks.models]\n"M" = { "1" = "old" }\n',             # how it is known is required
                    '[keys.stacks.models]\n"M" = { "1" = "new, reported" }\n',
                    '[keys.stacks.models]\n"M" = { "1" = "old, guessed" }\n',
                    '[keys.stacks.models]\n"M" = { "1" = "unknown, assumed" }\n',
                    '[keys.stacks.models]\n"M" = "old, reported"\n',             # a model needs its version
                    '[keys.stacks.devices]\n"N" = 3\n',
                    '[keys.stacks.other]\n"N" = "unknown"\n'):
            with self.subTest(bad=bad), self.assertRaises(ValueError) as cm:
                self._load(bad)
            self.assertIn("[keys.stacks", str(cm.exception))

    def test_the_lookup_gives_the_stack_how_it_is_known_and_why(self):
        table = self._load(TABLE).key_stacks
        cases = {
            "Hall Air Monitor": ("old", "reported", "Air Monitor 2000 1.0.26"),
            "Shed Door": ("old", "behaviour", "Door Sensor 20XYZ 3.2.1"),
            # A firmware update is unknown until someone checks it.
            "Attic Air Monitor": ("unknown", None,
                                  "Air Monitor 2000 firmware 1.0.28 is not checked (the table has 1.0.26, 1.0.27)"),
            "Spare Monitor": ("unknown", None, "Air Monitor 2000 1.0.27"),
            "Porch Bulb": ("unknown", None, "model 'Bulb GU10' is not in the table"),
            "Rear Door": ("unknown", None, "Home Assistant reports no model or firmware version"),
            # Matched only by HA's own name, not the inventory's: not this device.
            "Garden Plug": ("unknown", None, "not in Home Assistant's map and not listed by name"),
            "Side Door Lock": ("current", "reported", "listed by name"),
            "Hall Border Router": ("unknown", None, "listed by name"),
        }
        for name, want in cases.items():
            with self.subTest(name=name):
                self.assertEqual(stacks.device_stack(table, name, HA_MAP), want)
        # A name entry wins over the device's HA model.
        table["devices"]["Hall Air Monitor"] = ("current", "assumed")
        self.assertEqual(stacks.device_stack(table, "Hall Air Monitor", HA_MAP),
                         ("current", "assumed", "listed by name"))


if __name__ == "__main__":
    unittest.main()
