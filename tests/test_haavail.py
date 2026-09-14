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


T0 = 1_700_000_000.0
IDS = [f"dev{i:02d}" + "0" * 27 for i in range(6)]
ADDRS = [f"{i:016x}" for i in range(1, 7)]


class TrackerTest(unittest.TestCase):
    """The episode rules, one poll result at a time."""

    def setUp(self):
        from threadwatch.config import Config
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.cfg = Config(data_dir=self.d / "data")
        self.cfg.ha_availability_enabled = True
        self.records = []
        self.rows = {a: {"first_seen": T0 - 86400, "last_seen": T0 - 30, "frames": 100, "rssi": -60.0,
                         "rloc16": f"{0x0401 + i:04x}", "rloc16_ts": T0 - 30} for i, a in enumerate(ADDRS)}
        self.rows["a" * 16] = {"first_seen": T0 - 86400, "last_seen": T0 - 5, "frames": 900, "rssi": -55.0,
                               "rloc16": "0400", "rloc16_ts": T0 - 5, "counter_seq": 86, "counter_ts": T0 - 5}
        self.mapping = {IDS[i]: {"addr": ADDRS[i].upper(), "node_id": i, "ha_name": f"HA {i}", "name": f"Device {i}",
                                 "matched": True, "entities": [f"sensor.d{i}"]} for i in range(6)}
        self.settings = {}

        class Names:
            def name(self, addr):
                return {"a" * 16: "Hall Router"}.get(addr)
        self.names = Names()

    def tearDown(self):
        self.tmp.cleanup()

    def _tracker(self, state=True):
        from threadwatch.haavail import Tracker
        return Tracker(self.cfg, self.d / "ha-availability.json" if state else None, self.settings,
                       emit=lambda event, severity, ts, **f: self.records.append({"event": event, "severity": severity,
                                                                                    "ts": ts, **f}),
                       rows=self.rows, names=self.names, mapping=self.mapping)

    def _poll(self, tracker, now, down: dict | None = None, ok=True, error=None):
        """A poll result: ``down`` maps device id -> HA's last_changed."""
        down = down or {}
        devices = {d: ((True, down[d]) if d in down else (False, None)) for d in self.mapping}
        tracker.apply({"ok": ok, "devices": devices, "error": error} if ok else {"ok": False, "error": error}, now)

    def _events(self, name):
        return [r for r in self.records if r["event"] == name]

    def test_a_device_back_inside_the_hold_is_nothing_and_past_it_is_one_warning_then_available(self):
        tr = self._tracker()
        self._poll(tr, T0)                                                      # baseline: all available
        self._poll(tr, T0 + 60, {IDS[0]: T0 + 30})
        self._poll(tr, T0 + 540, {IDS[0]: T0 + 30})                             # 8.5 min down
        self._poll(tr, T0 + 600)                                                # back inside the hold
        self.assertEqual(self.records, [])
        self._poll(tr, T0 + 1000, {IDS[1]: T0 + 990})
        for t in range(1060, 1650, 60):
            self._poll(tr, T0 + t, {IDS[1]: T0 + 990})
        evs = self._events("ha_unavailable")
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual((ev["severity"], ev["name"], ev["ha_device_id"], ev["addr"], ev["since"], ev["hold_s"],
                          ev["muted"], ev["burst_id"], ev["episode"], ev["entities"]),
                         ("warning", "Device 1", IDS[1], ADDRS[1], T0 + 990, 600, False, None, 1, ["sensor.d1"]))
        self.assertEqual(ev["unavailable_for_s"], round(ev["ts"] - (T0 + 990)))
        self.assertGreaterEqual(ev["unavailable_for_s"], 600)
        self.assertNotIn("already_unavailable_at_start", ev)
        self.assertEqual((ev["cause"], ev["role"], ev["parent"]), ("unheard", "child", "Hall Router"))
        self.assertIn("unavailable in Home Assistant for", ev["note"])
        self._poll(tr, T0 + 1700, {IDS[1]: T0 + 990})                          # still down: nothing more
        self.assertEqual(len(self._events("ha_unavailable")), 1)
        self._poll(tr, T0 + 1760)
        back = self._events("ha_available")
        self.assertEqual(len(back), 1)
        self.assertEqual((back[0]["severity"], back[0]["name"], back[0]["down_for_s"], back[0]["rejoined"]),
                         ("info", "Device 1", 770, False))
        state = json.loads((self.d / "ha-availability.json").read_text())
        self.assertEqual(state["episodes"], {})
        self.assertEqual(state["closed"][IDS[1]]["episodes"], 1)

    def test_the_cause_comes_from_the_radio_evidence(self):
        self.rows[ADDRS[0]].update(counter_seq=84, counter_ts=T0 + 1000, last_seen=T0 + 1000)
        tr = self._tracker()
        self._poll(tr, T0)
        for t in range(60, 700, 60):
            self._poll(tr, T0 + t, {IDS[0]: T0 + 10})
        ev = self._events("ha_unavailable")[0]
        self.assertEqual((ev["cause"], ev["generation"], ev["parent_generation"]), ("key_lag", 84, 86))
        self.assertIn("Cut off by a key change", ev["note"])

    def test_per_device_hold_and_mute(self):
        self.settings = {IDS[0]: {"hold_s": 7200}, IDS[1]: {"mute": True}, IDS[2]: {"mute": True}}
        tr = self._tracker()
        self._poll(tr, T0)
        for t in range(60, 3700, 60):
            self._poll(tr, T0 + t, {IDS[0]: T0 + 10, IDS[1]: T0 + 10, IDS[2]: T0 + 15, IDS[3]: T0 + 20})
        evs = self._events("ha_unavailable")
        self.assertEqual(sorted((e["name"], e["severity"], e["muted"]) for e in evs),
                         [("Device 1", "notice", True), ("Device 2", "notice", True), ("Device 3", "warning", False)])
        self.assertEqual(self._events("ha_unavailable_burst"), [])                # two muted: only one counts
        for t in range(3720, 7300, 60):
            self._poll(tr, T0 + t, {IDS[0]: T0 + 10})
        evs = self._events("ha_unavailable")
        self.assertEqual([e["name"] for e in evs if e["name"] == "Device 0"], ["Device 0"])
        self.assertEqual(next(e for e in evs if e["name"] == "Device 0")["hold_s"], 7200)

    def test_three_devices_in_eight_minutes_are_one_critical_burst_and_a_fourth_joins_it(self):
        tr = self._tracker()
        self._poll(tr, T0)
        self._poll(tr, T0 + 60, {IDS[0]: T0 + 50})
        self._poll(tr, T0 + 300, {IDS[0]: T0 + 50, IDS[1]: T0 + 290})
        self._poll(tr, T0 + 480, {IDS[0]: T0 + 50, IDS[1]: T0 + 290, IDS[2]: T0 + 470})
        self.assertEqual(self._events("ha_unavailable_burst"), [])              # the newest not yet 2 min down
        self._poll(tr, T0 + 600, {IDS[0]: T0 + 50, IDS[1]: T0 + 290, IDS[2]: T0 + 470})
        bursts = self._events("ha_unavailable_burst")
        self.assertEqual(len(bursts), 1)
        b = bursts[0]
        self.assertEqual((b["severity"], b["count"], b["window_s"], b["first_since"], b["ha_side"]),
                         ("critical", 3, 600, T0 + 50, False))
        self.assertEqual([m["name"] for m in b["devices"]], ["Device 0", "Device 1", "Device 2"])
        self.assertEqual(b["devices"][0]["cause"], "unheard")
        self.assertIn("3 devices went unavailable in Home Assistant within 10 min", b["note"])
        # The individual records are notices with the burst id; a fourth
        # device inside the window joins rather than starting another.
        self._poll(tr, T0 + 700, {IDS[0]: T0 + 50, IDS[1]: T0 + 290, IDS[2]: T0 + 470, IDS[3]: T0 + 690})
        for t in range(760, 1400, 60):
            self._poll(tr, T0 + t, {IDS[0]: T0 + 50, IDS[1]: T0 + 290, IDS[2]: T0 + 470, IDS[3]: T0 + 690})
        evs = self._events("ha_unavailable")
        self.assertEqual(sorted((e["name"], e["severity"], e["burst_id"] == b["burst_id"]) for e in evs),
                         [(f"Device {i}", "notice", True) for i in range(4)])
        self.assertEqual(len(self._events("ha_unavailable_burst")), 1)

    def test_two_devices_are_two_warnings_not_a_burst(self):
        tr = self._tracker()
        self._poll(tr, T0)
        for t in range(60, 800, 60):
            self._poll(tr, T0 + t, {IDS[0]: T0 + 10, IDS[1]: T0 + 20})
        self.assertEqual(self._events("ha_unavailable_burst"), [])
        self.assertEqual([e["severity"] for e in self._events("ha_unavailable")], ["warning", "warning"])

    def test_a_restart_blip_of_five_devices_for_a_minute_is_nothing(self):
        tr = self._tracker()
        self._poll(tr, T0)
        self._poll(tr, T0 + 60, {i: T0 + 55 for i in IDS[:5]})
        self._poll(tr, T0 + 120)
        self.assertEqual(self.records, [])

    def test_a_burst_ends_and_a_device_stuck_for_hours_does_not_suppress_the_next_one(self):
        tr = self._tracker()
        self._poll(tr, T0)
        down = {IDS[0]: T0 + 10, IDS[1]: T0 + 20, IDS[2]: T0 + 30}
        for t in range(60, 300, 60):
            self._poll(tr, T0 + t, down)
        self.assertEqual(len(self._events("ha_unavailable_burst")), 1)
        # Two recover; one stays down for a day.
        for t in range(300, 86400, 600):
            self._poll(tr, T0 + t, {IDS[0]: T0 + 10})
        # Three others drop the next day: a new burst.
        down = {IDS[0]: T0 + 10, IDS[3]: T0 + 86400 + 10, IDS[4]: T0 + 86400 + 20, IDS[5]: T0 + 86400 + 30}
        for t in range(86400 + 60, 86400 + 400, 60):
            self._poll(tr, T0 + t, down)
        bursts = self._events("ha_unavailable_burst")
        self.assertEqual(len(bursts), 2)
        self.assertEqual([m["name"] for m in bursts[1]["devices"]], ["Device 3", "Device 4", "Device 5"])
        self.assertNotEqual(bursts[0]["burst_id"], bursts[1]["burst_id"])

    def test_a_mesh_wide_drop_while_the_recorder_still_hears_the_devices_names_the_ha_side(self):
        for a in ADDRS:
            self.rows[a]["last_seen"] = T0 + 550
        tr = self._tracker()
        self._poll(tr, T0)
        down = {i: T0 + 300 for i in IDS[:5]}                                   # 5 of 6 mapped
        for t in range(360, 700, 60):
            self._poll(tr, T0 + t, down)
        b = self._events("ha_unavailable_burst")[0]
        self.assertTrue(b["ha_side"])
        self.assertIn("HA or Matter Server side", b["note"])

    def test_ten_minutes_of_refused_polls_is_one_unreachable_and_no_episode_changes(self):
        tr = self._tracker()
        self._poll(tr, T0)
        self._poll(tr, T0 + 60, {IDS[0]: T0 + 50})
        for t in range(120, 800, 60):
            self._poll(tr, T0 + t, ok=False, error="connection refused")
        unreachable = self._events("ha_unreachable")
        self.assertEqual(len(unreachable), 1)
        self.assertEqual((unreachable[0]["severity"], unreachable[0]["error"]), ("notice", "connection refused"))
        self.assertGreaterEqual(unreachable[0]["failing_for_s"], 300)
        self.assertEqual(self._events("ha_unavailable"), [])                  # the hold clock did not fire blind
        self.assertIn(IDS[0], tr.state["episodes"])
        # Recovery: ha_reachable, and the next poll is a baseline, not
        # transitions: the device that came back meanwhile closes without
        # a word, and one found down is said at notice as already down
        # (its hold has long passed), never paged.
        self._poll(tr, T0 + 900, {IDS[1]: T0 + 200})
        self.assertEqual([r["event"] for r in self.records], ["ha_unreachable", "ha_reachable", "ha_unavailable"])
        self.assertEqual(sorted(tr.state["episodes"]), [IDS[1]])
        ev = self._events("ha_unavailable")[0]
        self.assertEqual((ev["name"], ev["severity"], ev["already_unavailable_at_start"]), ("Device 1", "notice", True))
        self.assertIn("already unavailable when the recorder started", ev["note"])
        self.assertEqual(self._events("ha_available"), [])

    def test_a_restart_keeps_a_paged_episode_and_says_an_unpaged_one_at_notice(self):
        tr = self._tracker()
        self._poll(tr, T0)
        for t in range(60, 700, 60):
            self._poll(tr, T0 + t, {IDS[0]: T0 + 10})
        self.assertEqual(len(self._events("ha_unavailable")), 1)
        self.records.clear()
        tr2 = self._tracker()                                                   # restarted with the state file
        self._poll(tr2, T0 + 800, {IDS[0]: T0 + 10, IDS[1]: T0 + 100})
        self._poll(tr2, T0 + 860, {IDS[0]: T0 + 10, IDS[1]: T0 + 100})
        evs = self._events("ha_unavailable")
        self.assertEqual([(e["name"], e["severity"], e.get("already_unavailable_at_start")) for e in evs],
                         [("Device 1", "notice", True)])                       # Device 0 was paged before: kept
        self._poll(tr2, T0 + 920)
        self.assertEqual([e["name"] for e in self._events("ha_available")], ["Device 0", "Device 1"])

    def test_an_episode_reopening_within_rearm_s_is_a_notice(self):
        tr = self._tracker()
        self._poll(tr, T0)
        for t in range(60, 700, 60):
            self._poll(tr, T0 + t, {IDS[0]: T0 + 10})
        self._poll(tr, T0 + 720)
        for t in range(780, 1500, 60):
            self._poll(tr, T0 + t, {IDS[0]: T0 + 770})
        evs = self._events("ha_unavailable")
        self.assertEqual([(e["severity"], e["episode"]) for e in evs], [("warning", 1), ("notice", 2)])
        self.assertIn("Episode 2 since the last page", evs[1]["note"])

    def test_status_and_the_pages_view(self):
        from threadwatch.haavail import availability_by_addr, save_map
        tr = self._tracker()
        self._poll(tr, T0)
        self._poll(tr, T0 + 60, {IDS[0]: T0 + 50})
        st = tr.status()
        self.assertEqual((st["reachable"], st["last_poll_ts"], st["devices_mapped"], st["burst"]),
                         (True, T0 + 60, 6, None))
        self.assertEqual([(o["name"], o["since"], o["paged"]) for o in st["open"]], [("Device 0", T0 + 50, False)])
        save_map(self.d, self.mapping)
        by_addr = availability_by_addr(self.d)
        self.assertEqual(by_addr, {ADDRS[0]: {"name": "Device 0", "since": T0 + 50, "paged": False, "burst_id": None}})


class RecorderAvailabilityTest(unittest.TestCase):
    """The recorder's side: the worker polls on a thread, the capture
    thread applies, the status entry and the snapshot copies follow, and
    a bad settings file stops the feature and nothing else."""

    def setUp(self):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        from threadwatch.config import Config
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        (self.d / "devices.json").write_text(json.dumps(ENTRIES))
        self.cfg = Config(data_dir=self.d / "data", config_dir=self.d, devices_path=self.d / "devices.json")
        self.cfg.ha_availability_enabled = True
        self.cfg.ha_availability_hold_s = 0
        self.states = [{"entity_id": "binary_sensor.motion", "state": "on",
                        "last_changed": "2026-09-13T20:00:00+00:00"}]
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = json.dumps(outer.states).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, args=(0.005,), daemon=True).start()
        (self.d / "ha.env").write_text(f"HA_URL=http://127.0.0.1:{self.httpd.server_port}\nHA_TOKEN=tk_SECRET_TOKEN\n")
        # The websocket registry is faked at the module boundary.
        self.mapping = {MOTION: {"addr": "C233A4A5BF8391C9", "node_id": 7, "ha_name": "Motion HA Name",
                                 "name": "Front Path Motion", "matched": True, "entities": ["binary_sensor.motion"]}}
        self.refreshes = []
        self._real = haavail.refresh_map
        haavail.refresh_map = lambda url, token, entries, log=None: (self.refreshes.append(url), self.mapping)[1]

    def tearDown(self):
        haavail.refresh_map = self._real
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()

    def _pipe(self):
        from threadwatch.crypto import Decryptor
        from threadwatch.events import NullEventLog
        from threadwatch.pipeline import Pipeline
        return Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)))

    def _cycle(self, pipe, now):
        pipe._poll_ha_availability(now)
        self.assertIsNotNone(pipe._haavail_thread)
        pipe._haavail_thread.join(10)
        pipe._poll_ha_availability(now + 1)

    def test_the_worker_builds_the_map_once_polls_rest_and_the_capture_thread_applies(self):
        pipe = self._pipe()
        now = 1_800_000_000.0
        self._cycle(pipe, now)
        self.assertEqual(len(self.refreshes), 1)
        self.assertEqual(haavail.load_map(self.cfg.state_dir), self.mapping)             # cached
        st = pipe.ha_availability_status()
        self.assertEqual((st["enabled"], st["reachable"], st["devices_mapped"], st["open"]), (True, True, 1, []))
        # The device drops: the next cycle opens the episode and, with a
        # zero hold, says so at once, through _emit.
        self.states[0].update(state="unavailable", last_changed="2026-09-13T21:00:00+00:00")
        pipe._next_haavail = 0.0
        self._cycle(pipe, now + 60)
        evs = [r for r in pipe.events.records if r["event"] == "ha_unavailable"]
        self.assertEqual(len(evs), 1)
        self.assertEqual((evs[0]["name"], evs[0]["addr"], evs[0]["severity"]),
                         ("Front Path Motion", "c233a4a5bf8391c9", "warning"))
        self.assertEqual(len(self.refreshes), 1)                        # the map is not rebuilt at every poll
        self.assertEqual([o["name"] for o in pipe.ha_availability_status()["open"]], ["Front Path Motion"])
        state = json.loads((self.cfg.state_dir / "ha-availability.json").read_text())
        self.assertIn(MOTION, state["episodes"])
        for text in json.dumps(pipe.events.records):
            self.assertNotIn("tk_SECRET_TOKEN", text)
        # Not before poll_s.
        pipe._poll_ha_availability(now + 90)
        self.assertIsNone(pipe._haavail_thread)

    def test_a_restart_polls_from_the_cached_map_and_a_stale_map_is_rebuilt(self):
        pipe = self._pipe()
        self._cycle(pipe, 1_800_000_000.0)
        pipe2 = self._pipe()
        self.assertEqual(pipe2._haavail.mapping, self.mapping)
        pipe2._haavail_map_ts = 1_800_000_000.0 - 7200                  # older than registry_refresh_s
        self._cycle(pipe2, 1_800_000_000.0)
        self.assertEqual(len(self.refreshes), 2)

    def test_a_bad_settings_file_stops_the_feature_not_the_recorder(self):
        (self.d / "ha-availability.json").write_text('{"x": {"mute": "yes"}}')
        pipe = self._pipe()
        self.assertIsNone(pipe._haavail)
        st = pipe.ha_availability_status()
        self.assertFalse(st["enabled"])
        self.assertIn("mute must be true or false", st["reason"])
        pipe.periodic(1_800_000_000.0)
        self.assertIsNone(pipe._haavail_thread)

    def test_the_state_files_and_the_settings_copy_travel_with_a_snapshot(self):
        from threadwatch.snapshot import STATE_FILES, save_snapshot
        self.assertIn("ha-availability.json", STATE_FILES)
        self.assertIn("ha-map.json", STATE_FILES)
        (self.d / "ha-availability.json").write_text(json.dumps({MOTION: {"hold_s": 7200}}))
        pipe = self._pipe()
        self._cycle(pipe, 1_800_000_000.0)
        self.cfg.ring_dir.mkdir(parents=True, exist_ok=True)
        dest, _n = save_snapshot(self.cfg, "x")
        self.assertTrue((dest / "ha-map.json").exists())
        self.assertTrue((dest / "ha-availability.json").exists())                          # the episodes
        self.assertEqual(json.loads((dest / "ha-availability-settings.json").read_text()), {MOTION: {"hold_s": 7200}})
        self.assertEqual(json.loads((dest / "devices.json").read_text()), ENTRIES)           # untouched by all this
        self.assertNotIn("tk_SECRET_TOKEN", "".join(p.read_text() for p in dest.glob("*.json")))

    def test_off_or_replay_runs_nothing(self):
        from threadwatch.crypto import Decryptor
        from threadwatch.events import NullEventLog
        from threadwatch.pipeline import Pipeline
        replay = Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)), ephemeral=True)
        replay.periodic(1_800_000_000.0)
        self.assertIsNone(replay._haavail)
        self.assertIsNone(replay.ha_availability_status())
        self.cfg.ha_availability_enabled = False
        pipe = self._pipe()
        pipe.periodic(1_800_000_000.0)
        self.assertIsNone(pipe._haavail_thread)
        self.assertIsNone(pipe.ha_availability_status())
        self.assertEqual(self.refreshes, [])


if __name__ == "__main__":
    unittest.main()
