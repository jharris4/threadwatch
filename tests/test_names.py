"""Inventory helpers: suggested entries for unknown addresses, and adopt."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.names import (DeviceNames, LastSeen, adopt, load_observed_names,  # noqa: E402
                               rotation_hints, suggest_entries)

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


class RotationHintTest(unittest.TestCase):
    T = 1_756_800_000.0
    NEW, LATER, OTHER = "0011223344556677", "8899aabbccddeeff", "1234567890abcdef"

    def _names(self, d):
        inv = Path(d) / "devices.json"
        inv.write_text(json.dumps([
            {"name": "Living Room Apple TV", "extendedAddresses": [TV1.upper(), TV2]},
            {"name": "Office AQ", "extendedAddress": AQ},
        ]))
        return DeviceNames(inv)

    def _seen(self):
        seen = LastSeen(None)
        seen.touch(TV1, self.T - 86400, 1)
        seen.touch(TV2, self.T - 3600, 1)             # the TV's current address...
        seen.touch(TV2, self.T, 1)                    # ...last heard at T
        seen.touch(AQ, self.T + 7200, 1)              # still talking
        seen.touch(self.NEW, self.T + 90, 1)          # appeared 90 s after the TV fell silent
        seen.touch(self.NEW, self.T + 7200, 1)
        seen.touch(self.LATER, self.T + 3 * 3600, 1)  # appeared hours later: no hint
        seen.touch(self.OTHER, self.T + 7100, 1)      # appeared while the AQ was still heard: no hint
        return seen

    def test_new_address_as_a_named_device_falls_silent(self):
        with tempfile.TemporaryDirectory() as d:
            names = self._names(d)
            seen = self._seen()
            report = seen.report(names, quiet_after_s=1800, now=self.T + 7300)
            hints = rotation_hints(report["unknown"], seen.table, names)
            self.assertEqual(hints, {self.NEW: {"name": "Living Room Apple TV", "previous": TV2,
                                                "delta_s": 90, "rotates": True}})
            entries = {e["extendedAddress"]: e for e in suggest_entries(report["unknown"], {}, hints)}
            self.assertIn("possibly a new address of Living Room Apple TV (which rotates): its previous "
                          f"address {TV2} fell silent 1 min after this one appeared", entries[self.NEW.upper()]["note"])
            self.assertNotIn("possibly", entries[self.LATER.upper()]["note"])
            self.assertNotIn("possibly", entries[self.OTHER.upper()]["note"])

    def test_no_hint_when_the_device_kept_talking_after(self):
        with tempfile.TemporaryDirectory() as d:
            names = self._names(d)
            seen = self._seen()
            seen.touch(TV2, self.T + 3600, 1)         # the old address was heard again an hour later
            report = seen.report(names, quiet_after_s=1800, now=self.T + 7300)
            self.assertEqual(rotation_hints(report["unknown"], seen.table, names), {})


class AdoptTest(unittest.TestCase):
    def test_creates_the_file_and_appends_entries(self):
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "config" / "devices.json"
            msg = adopt(inv, "26:97:6E:7F:7D:20:96:4A", "Office Air Quality")
            self.assertIn("added 'Office Air Quality' = " + AQ, msg)
            adopt(inv, TV1, "Living Room Apple TV")
            entries = json.loads(inv.read_text())
            self.assertEqual(entries, [
                {"name": "Office Air Quality", "extendedAddress": AQ.upper()},
                {"name": "Living Room Apple TV", "extendedAddress": TV1.upper()},
            ])
            names = DeviceNames(inv)
            self.assertEqual(names.name(AQ), "Office Air Quality")

    def test_same_name_gains_a_rotated_address(self):
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            inv.write_text(json.dumps([{"name": "Living Room Apple TV", "extendedAddress": TV1.upper(),
                                        "note": "rotates"}]))
            msg = adopt(inv, TV2, "living room apple tv")
            self.assertIn("2 addresses", msg)
            entry = json.loads(inv.read_text())[0]
            self.assertNotIn("extendedAddress", entry)
            self.assertEqual(entry["extendedAddresses"], [TV1.upper(), TV2.upper()])
            self.assertNotIn("role", entry)
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


class Rloc16RoleTest(unittest.TestCase):
    def test_router_and_child_from_the_short_address(self):
        from threadwatch.names import rloc16_role
        self.assertEqual(rloc16_role("f000"), {"rloc16": "f000", "router_id": 60, "child_id": None, "role": "router"})
        self.assertEqual(rloc16_role("c004"), {"rloc16": "c004", "router_id": 48, "child_id": 4, "role": "child"})
        self.assertIsNone(rloc16_role(None))
        self.assertIsNone(rloc16_role("zz"))


class LearnedBorderRoutersTest(unittest.TestCase):
    def test_state_file_names_a_new_address_from_the_bound_entry(self):
        from threadwatch.names import DeviceNames
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            inv.write_text(json.dumps([{"name": "Living Room Apple TV", "extendedAddress": TV1.upper()},
                                       {"name": "OTBR", "borderRouter": "otbr.local"}]))
            learned = Path(d) / "border-routers.json"
            learned.write_text(json.dumps({
                "appletv-living-room.local": {"addr": TV2, "name": "Living Room Apple TV", "instance": "AppleTV Living Room",
                                              "vendor": "Apple", "model": "BorderRouter"},
                "otbr.local": {"addr": AQ, "name": None, "instance": "OTBR #1"},
                "junk.local": {"addr": "nope"},
            }))
            names = DeviceNames(inv, learned)
            self.assertEqual(names.name(TV2), "Living Room Apple TV")
            self.assertEqual(names.addresses_of(TV1), [TV1, TV2])
            self.assertEqual(names.name(AQ), "OTBR")                       # borderRouter field, even unnamed in state
            self.assertEqual(names.border_routers[TV2]["instance"], "AppleTV Living Room")
            self.assertNotIn("nope", names.border_routers)
            self.assertIsNone(DeviceNames(inv, Path(d) / "absent.json").name(TV2))



class UnreadableStateTest(unittest.TestCase):
    """A last-seen.json that does not parse is a week of history: say so
    and keep it, rather than silently starting over."""

    def _load(self, path):
        import contextlib
        import io
        from threadwatch import names as names_mod
        names_mod._warned_unreadable.clear()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            seen = LastSeen(path)
        return seen, out.getvalue()

    def test_a_broken_table_is_announced_and_kept_aside_on_the_first_save(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "last-seen.json"
            broken = '{"' + AQ + '": {"first_seen": 1, "last_seen": 2, "frames": 3, "ty'   # cut short
            path.write_text(broken)
            seen, said = self._load(path)
            self.assertEqual(seen.table, {})
            self.assertIn("last-seen.json is unreadable", said)
            self.assertIn("last-seen.json.corrupt", said)
            import contextlib
            import io
            again = io.StringIO()
            with contextlib.redirect_stdout(again):
                LastSeen(path)                                             # the web reads it per request:
            self.assertEqual(again.getvalue(), "")                         # said once per process
            seen.touch(TV1, 10.0, 1)
            seen.save()
            self.assertEqual(json.loads(path.read_text())[TV1]["frames"], 1)
            self.assertEqual((Path(d) / "last-seen.json.corrupt").read_text(), broken)
            seen.touch(TV1, 11.0, 1)
            seen.save()                                                    # a plain save from then on
            self.assertEqual(sorted(p.name for p in Path(d).iterdir()), ["last-seen.json", "last-seen.json.corrupt"])
            # A later corruption is kept as well, never over the first.
            path.write_text("[]")                                          # a list is not a table either
            seen2, said = self._load(path)
            self.assertIn("expected an object", said)
            seen2.save()
            kept = sorted(p.name for p in Path(d).iterdir() if p.name.startswith("last-seen.json.corrupt"))
            self.assertEqual(len(kept), 2)
            self.assertEqual((Path(d) / "last-seen.json.corrupt").read_text(), broken)

    def test_a_healthy_or_absent_table_says_nothing_and_keeps_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "last-seen.json"
            seen, said = self._load(path)
            self.assertEqual((seen.table, said), ({}, ""))
            seen.touch(TV1, 10.0, 1)
            seen.save()
            seen, said = self._load(path)
            self.assertEqual((seen.table[TV1]["frames"], said), (1, ""))
            seen.save()
            self.assertEqual([p.name for p in Path(d).iterdir()], ["last-seen.json"])


class MalformedInventoryTest(unittest.TestCase):
    """One bad hand-edit must not stop capture or 500 every review page."""

    def _names(self, doc):
        d = Path(tempfile.mkdtemp()) / "devices.json"
        d.write_text(doc)
        return DeviceNames(d, None)

    def test_non_dict_entries_are_skipped(self):
        for doc in ('["00112233445566aa"]', '[null]', '[{"name": "ok",'
                    ' "extendedAddress": "00112233445566aa"}, "stray"]'):
            names = self._names(doc)
            with self.assertRaises(ValueError):
                names.resolve("nothing-matches-this")

    def test_top_level_object_is_ignored_not_fatal(self):
        names = self._names('{"a": {"name": "x"}}')
        self.assertEqual(names.entries, [])

    def test_non_string_name_does_not_crash_resolve(self):
        names = self._names('[{"name": 5, "extendedAddress": "00112233445566aa"}]')
        self.assertEqual(names.name("00112233445566aa"), "5")
        with self.assertRaises(ValueError):
            names.resolve("nothing-matches-this")
