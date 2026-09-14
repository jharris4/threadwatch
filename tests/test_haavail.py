"""haavail: the Home Assistant availability feature. This file covers the
per-device settings file (config/ha-availability.json), the HA device map
and the state poll, and the episode rules."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch import haavail
from threadwatch.haavail import SettingsError

MOTION = "3f9c2e7a4b1d4c8e9f0a1b2c3d4e5f60"
GARDEN = "a81b07d4c2e34f6a8b9c0d1e2f3a4b5c"
PLUG = "c0ffee00c0ffee00c0ffee00c0ffee00"
DEVICES = [
    {"ha_device_id": MOTION, "name": "Motion HA Name", "addr": "C233A4A5BF8391C9", "node_id": 7},
    {"ha_device_id": GARDEN, "name": "Garden Sensor", "addr": "1669674DD15CF0FA", "node_id": 8},
    {"ha_device_id": PLUG, "name": "Plug", "addr": "B62C32BF669272DB", "node_id": 9},
]
ENTRIES = [
    {"name": "Front Path Motion", "extendedAddress": "c233a4a5bf8391c9"},
    {"name": "Living Room Plug", "extendedAddresses": ["B62C32BF669272DB", "E6C279E8F0C70298"]},
]


class SettingsFileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "ha-availability.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_durations(self):
        for text, want in (("2h", 7200), ("30m", 1800), ("1h30m", 5400), ("7200", 7200), ("90s", 90),
                           ("1h 5m 2s", 3902)):
            self.assertEqual(haavail.parse_duration(text), want, text)
        for bad in ("", "soon", "2 hours", "-5"):
            with self.assertRaises(ValueError):
                haavail.parse_duration(bad)
        self.assertEqual([haavail.fmt_hold(x) for x in (None, 7200, 1800, 90)], ["default", "2h", "30m", "90s"])

    def test_a_missing_file_is_no_settings_and_the_example_loads(self):
        self.assertEqual(haavail.load_settings(self.path), {})
        example = Path(__file__).resolve().parent.parent / "config" / "ha-availability.example.json"
        loaded = haavail.load_settings(example)
        self.assertEqual(loaded[MOTION]["hold_s"], 7200)
        self.assertTrue(loaded[GARDEN]["mute"])

    def test_bad_json_or_types_stop_the_feature_with_a_clear_message(self):
        for text, want in (("{not json", "not valid JSON"),
                           ("[]", "must be a JSON object"),
                           ('{"x": 5}', "must be an object"),
                           ('{"x": {"hold": 5}}', "unknown field(s) hold"),
                           ('{"x": {"hold_s": "2h"}}', "hold_s must be a number"),
                           ('{"x": {"hold_s": -1}}', "hold_s must be a number"),
                           ('{"x": {"hold_s": true}}', "hold_s must be a number"),
                           ('{"x": {"mute": "yes"}}', "mute must be true or false"),
                           ('{"x": {"name": 3}}', "name must be a string")):
            self.path.write_text(text)
            with self.subTest(text=text), self.assertRaises(SettingsError) as cm:
                haavail.load_settings(self.path)
            self.assertIn(want, str(cm.exception))
            self.assertIn("ha-availability.json", str(cm.exception))

    def test_set_resolves_a_name_an_address_or_an_id_and_writes_under_the_lock(self):
        msg = haavail.set_device(self.path, DEVICES, ENTRIES, "Front Path Motion", hold_s=7200)
        self.assertIn("Front Path Motion", msg)
        self.assertIn("hold 7200 s", msg)
        saved = json.loads(self.path.read_text())
        self.assertEqual(saved, {MOTION: {"name": "Front Path Motion", "extendedAddress": "C233A4A5BF8391C9",
                                          "hold_s": 7200}})
        haavail.set_device(self.path, DEVICES, ENTRIES, "1669674dd15cf0fa", mute=True)      # by address
        haavail.set_device(self.path, DEVICES, ENTRIES, PLUG, hold_s=600, mute=True)         # by id
        saved = json.loads(self.path.read_text())
        self.assertEqual(saved[GARDEN], {"name": "Garden Sensor", "extendedAddress": "1669674DD15CF0FA", "mute": True})
        self.assertEqual(saved[PLUG], {"name": "Living Room Plug", "extendedAddress": "B62C32BF669272DB",
                                       "hold_s": 600, "mute": True})
        self.assertIn("unmuted", haavail.set_device(self.path, DEVICES, ENTRIES, "plug", mute=False))
        self.assertNotIn("mute", json.loads(self.path.read_text())[PLUG])
        self.assertIn("settings removed", haavail.set_device(self.path, DEVICES, ENTRIES, PLUG, clear=True))
        self.assertNotIn(PLUG, json.loads(self.path.read_text()))
        self.assertIn("had no settings", haavail.set_device(self.path, DEVICES, ENTRIES, PLUG, clear=True))
        with self.assertRaises(ValueError) as cm:
            haavail.set_device(self.path, DEVICES, ENTRIES, "nobody", hold_s=5)
        self.assertIn("ha-availability list", str(cm.exception))
        with self.assertRaises(ValueError) as cm:
            haavail.set_device(self.path, DEVICES + [{"ha_device_id": "dup", "name": "Garden Sensor 2",
                                                      "addr": "0000000000000001"}], ENTRIES, "garden", hold_s=5)
        self.assertIn("matches several", str(cm.exception))
        self.assertTrue(self.path.with_name("ha-availability.json.lock").exists())

    def test_a_rename_on_either_side_keeps_the_settings_and_import_write_refreshes_the_link(self):
        haavail.set_device(self.path, DEVICES, ENTRIES, MOTION, hold_s=7200)
        haavail.set_device(self.path, DEVICES, ENTRIES, GARDEN, mute=True)
        renamed_ha = [dict(d, name="Garden Sensor Renamed") if d["ha_device_id"] == GARDEN else d for d in DEVICES]
        renamed_inv = [dict(e, name="Porch Motion") if e["name"] == "Front Path Motion" else e for e in ENTRIES]
        lines = haavail.refresh_settings(self.path, renamed_ha, renamed_inv, write=False)
        self.assertEqual(len([line for line in lines if "->" in line]), 2)
        self.assertEqual(json.loads(self.path.read_text())[MOTION]["name"], "Front Path Motion")   # a dry run
        lines = haavail.refresh_settings(self.path, renamed_ha, renamed_inv, write=True)
        saved = json.loads(self.path.read_text())
        self.assertEqual((saved[MOTION]["name"], saved[MOTION]["hold_s"]), ("Porch Motion", 7200))
        self.assertEqual((saved[GARDEN]["name"], saved[GARDEN]["mute"]), ("Garden Sensor Renamed", True))
        self.assertTrue(any(line.startswith("wrote ") for line in lines))
        # A device HA no longer has is reported, and kept.
        lines = haavail.refresh_settings(self.path, [d for d in renamed_ha if d["ha_device_id"] != GARDEN],
                                         renamed_inv, write=True)
        self.assertTrue(any("no longer a device Home Assistant knows" in line for line in lines))
        self.assertIn(GARDEN, json.loads(self.path.read_text()))
        self.assertEqual(haavail.refresh_settings(self.path, renamed_ha, renamed_inv, write=True), [])  # settled
        self.assertEqual(haavail.refresh_settings(self.path.with_name("nothing.json"), DEVICES, ENTRIES, True), [])

    def test_list_shows_each_entry_with_its_links_and_marks_stale_and_outdated_ones(self):
        haavail.set_device(self.path, DEVICES, ENTRIES, MOTION, hold_s=7200)
        haavail.set_device(self.path, DEVICES, ENTRIES, GARDEN, mute=True)
        rows = haavail.list_settings(self.path, [d for d in DEVICES if d["ha_device_id"] != GARDEN],
                                     [dict(e, name="Porch Motion") if e["name"] == "Front Path Motion" else e
                                      for e in ENTRIES])
        by = {r["ha_device_id"]: r for r in rows}
        self.assertEqual((by[MOTION]["name"], by[MOTION]["inventory_name"], by[MOTION]["ha_name"],
                          by[MOTION]["hold_s"], by[MOTION]["mute"], by[MOTION]["stale"], by[MOTION]["outdated"]),
                         ("Front Path Motion", "Porch Motion", "Motion HA Name", 7200, False, False, True))
        self.assertEqual((by[GARDEN]["stale"], by[GARDEN]["mute"], by[GARDEN]["ha_name"]), (True, True, None))


class MapAndPollTest(unittest.TestCase):
    """The link from HA's devices to the inventory, and the reduction of
    /api/states to per-device availability."""

    REGISTRY = [
        {"id": MOTION, "name": "Motion HA Name", "identifiers": [["matter", "x-1"]]},
        {"id": GARDEN, "name": "Garden Sensor", "identifiers": [["matter", "x-2"]]},
        {"id": "wifi", "name": "Wifi Plug", "identifiers": [["matter", "x-3"]]},
    ]
    DIAGS = {MOTION: {"node_id": 7, "network_type": "thread", "mac_address": "c2:33:a4:a5:bf:83:91:c9"},
             GARDEN: {"node_id": 8, "network_type": "thread", "mac_address": "16:69:67:4d:d1:5c:f0:fa"},
             "wifi": {"node_id": 9, "network_type": "wifi", "mac_address": "aa:bb:cc:dd:ee:ff"}}
    ENTITIES = [
        {"entity_id": "binary_sensor.motion", "device_id": MOTION, "entity_category": None, "disabled_by": None},
        {"entity_id": "sensor.motion_battery", "device_id": MOTION, "entity_category": "diagnostic"},
        {"entity_id": "switch.motion_led", "device_id": MOTION, "entity_category": "config"},
        {"entity_id": "sensor.motion_old", "device_id": MOTION, "disabled_by": "user"},
        {"entity_id": "sensor.garden_battery", "device_id": GARDEN, "entity_category": "diagnostic"},
        {"entity_id": "sensor.garden_rssi", "device_id": GARDEN, "entity_category": "diagnostic",
         "disabled_by": "integration"},
        {"entity_id": "sensor.unrelated", "device_id": "other"},
    ]

    def _fake(self):
        from tests.test_ha import FakeHA
        return FakeHA({"config/device_registry/list": self.REGISTRY,
                       "matter/node_diagnostics": lambda f: self.DIAGS[f["device_id"]],
                       "config/entity_registry/list": self.ENTITIES})

    def test_devices_are_matched_to_the_inventory_by_address_and_entities_filtered(self):
        mapping = haavail.build_map(self._fake(), ENTRIES)
        self.assertEqual(sorted(mapping), sorted([MOTION, GARDEN]))                  # the Wi-Fi plug is not Thread
        self.assertEqual(mapping[MOTION], {"addr": "C233A4A5BF8391C9", "node_id": 7, "ha_name": "Motion HA Name",
                                           "name": "Front Path Motion", "matched": True,
                                           "entities": ["binary_sensor.motion"]})     # not diagnostic, config, disabled
        self.assertEqual((mapping[GARDEN]["name"], mapping[GARDEN]["matched"], mapping[GARDEN]["entities"]),
                         ("Garden Sensor", False, ["sensor.garden_battery"]))          # diagnostic only: it counts
        # The map round-trips through the state file the recorder caches it in.
        with tempfile.TemporaryDirectory() as d:
            haavail.save_map(Path(d), mapping)
            self.assertEqual(haavail.load_map(Path(d)), mapping)
            (Path(d) / "ha-map.json").write_text("nope")
            self.assertEqual(haavail.load_map(Path(d)), {})

    def test_the_states_payload_reduces_to_per_device_availability(self):
        mapping = {MOTION: {"entities": ["binary_sensor.motion", "sensor.motion_lux"]},
                   GARDEN: {"entities": ["sensor.garden_battery"]},
                   PLUG: {"entities": ["switch.plug"]},
                   "empty": {"entities": []},
                   "absent": {"entities": ["sensor.not_in_states"]}}
        states = [
            {"entity_id": "binary_sensor.motion", "state": "unavailable",
             "last_changed": "2026-09-13T21:03:12.5+00:00"},
            {"entity_id": "sensor.motion_lux", "state": "unavailable", "last_changed": "2026-09-13T21:04:00+00:00"},
            {"entity_id": "sensor.garden_battery", "state": "unknown", "last_changed": "2026-09-13T20:00:00+00:00"},
            {"entity_id": "switch.plug", "state": "unavailable", "last_changed": "2026-09-13T21:00:00Z"},
            {"entity_id": "sensor.plug_power", "state": "on"},
        ]
        got = haavail.reduce_states(states, mapping)
        from datetime import datetime, timezone
        t = lambda s: datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp()
        self.assertEqual(got[MOTION], (True, t("2026-09-13T21:04:00")))               # the newest last_changed
        self.assertEqual(got[GARDEN], (False, None))                                   # unknown is not unavailable
        self.assertEqual(got[PLUG], (True, t("2026-09-13T21:00:00")))
        self.assertNotIn("empty", got)
        self.assertNotIn("absent", got)
        # Partly unavailable is available.
        states[1]["state"] = "12"
        self.assertEqual(haavail.reduce_states(states, mapping)[MOTION], (False, None))

    def test_the_poll_is_one_get_with_the_token_and_failures_are_redacted(self):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        seen = []
        payload = json.dumps([{"entity_id": "switch.plug", "state": "unavailable",
                               "last_changed": "2026-09-13T21:00:00+00:00"}]).encode()

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get("Authorization")))
                if self.path != "/api/states":
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        httpd = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=httpd.serve_forever, args=(0.005,), daemon=True).start()
        url = f"http://127.0.0.1:{httpd.server_port}"
        try:
            result = haavail.fetch_availability(url, "tk_SECRET_TOKEN", {PLUG: {"entities": ["switch.plug"]}})
        finally:
            httpd.shutdown()
            httpd.server_close()
        self.assertEqual(seen, [("/api/states", "Bearer tk_SECRET_TOKEN")])
        self.assertTrue(result["ok"])
        self.assertEqual(result["devices"][PLUG][0], True)
        down = haavail.fetch_availability(url, "tk_SECRET_TOKEN", {})        # nothing listens any more
        self.assertFalse(down["ok"])
        self.assertNotIn("tk_SECRET_TOKEN", down["error"])
        self.assertIn("refused", down["error"].lower())


if __name__ == "__main__":
    unittest.main()
