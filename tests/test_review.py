"""Event log day rolling, episode grouping, and the web review pages."""

import json
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.config import Config  # noqa: E402
from threadwatch.events import EventLog, day_of, list_days, migrate_legacy, read_day  # noqa: E402
from threadwatch.review import day_episodes, day_index, device_history, group_episodes  # noqa: E402
from threadwatch.web import make_server  # noqa: E402

AQ = "26976e7f7d20964a"
PLUG = "2a2d355a26ccae5f"
TV1, TV2 = "b62c32bf669272db", "e6c279e8f0c70298"
T0 = time.mktime(time.strptime("2026-09-02 12:00", "%Y-%m-%d %H:%M"))


def rec(event, severity, ts, **f):
    return {"ts": ts, "event": event, "severity": severity, **f}


class DayRollingTest(unittest.TestCase):
    def test_records_land_in_their_local_day_file(self):
        with tempfile.TemporaryDirectory() as d:
            log = EventLog(Path(d) / "events")
            log.emit("a", "info", T0)
            log.emit("b", "info", T0 + 20 * 3600)   # 08:00 next day
            self.assertEqual(list_days(log.dir), [day_of(T0), day_of(T0 + 20 * 3600)])
            self.assertEqual([r["event"] for r in read_day(log.dir, day_of(T0))], ["a"])

    def test_interrupted_migration_resumes_without_duplicates(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d)
            lines = [json.dumps({"ts": T0 + i, "event": "e%d" % i, "severity": "info"}) for i in range(4)]
            (state / "events.jsonl.migrating").write_text("\n".join(lines) + "\n")
            (state / "events").mkdir()
            (state / "events" / f"{day_of(T0)}.jsonl").write_text("\n".join(lines[:2]) + "\n")   # copied before the kill
            self.assertEqual(migrate_legacy(state / "events"), 2)
            self.assertEqual([r["event"] for r in read_day(state / "events", day_of(T0))], ["e0", "e1", "e2", "e3"])
            self.assertTrue((state / "events.jsonl.migrated").exists())

    def test_legacy_single_file_is_split_once(self):
        with tempfile.TemporaryDirectory() as d:
            state = Path(d)
            (state / "events.jsonl").write_text("\n".join(json.dumps(rec("x", "info", T0 + i * 3600 * 10))
                                                          for i in range(4)) + "\n")
            log = EventLog(state / "events")
            self.assertFalse((state / "events.jsonl").exists())
            self.assertTrue((state / "events.jsonl.migrated").exists())
            self.assertEqual(sum(len(read_day(log.dir, day)) for day in list_days(log.dir)), 4)
            self.assertEqual(migrate_legacy(log.dir), 0)   # idempotent


class EpisodeTest(unittest.TestCase):
    def test_quiet_and_returned_collapse_to_one_row(self):
        eps = group_episodes([
            rec("device_quiet", "warning", T0, addr=AQ, name="Basement AQ", reception="good", silent_for_s=1800),
            rec("device_returned", "notice", T0 + 12 * 60, addr=AQ, name="Basement AQ"),
        ])
        self.assertEqual(len(eps), 1)
        self.assertEqual(eps[0]["title"], "Basement AQ quiet for 42m")   # 30 min before noticed + 12 after
        self.assertEqual((eps[0]["start"], eps[0]["end"]), (T0, T0 + 12 * 60))

    def test_repeated_quiet_before_a_return_is_one_row(self):
        recs = [
            {"ts": T0, "event": "device_quiet", "severity": "warning", "addr": AQ, "name": "AQ", "silent_for_s": 1800},
            {"ts": T0 + 600, "event": "device_quiet", "severity": "warning", "addr": AQ, "name": "AQ", "silent_for_s": 2400},
            {"ts": T0 + 1800, "event": "device_returned", "severity": "notice", "addr": AQ, "name": "AQ"},
        ]
        eps = group_episodes(recs, now=T0 + 7200)
        self.assertEqual([(e["kind"], e["end"], e["count"]) for e in eps], [("quiet", T0 + 1800, 2)])
        self.assertEqual(eps[0]["title"], "AQ quiet for 60m")

    def test_open_quiet_says_still_quiet(self):
        eps = group_episodes([rec("device_quiet", "warning", T0, addr=AQ, name="Basement AQ")], now=T0 + 3600)
        self.assertIn("still quiet", eps[0]["title"])
        self.assertIsNone(eps[0]["end"])

    def test_repeated_retransmissions_between_a_pair_become_one_row(self):
        recs = [rec("retransmission_elevation", "notice", T0 + i * 900, rate=0.3 + i * 0.01, baseline=0.07,
                    addr=AQ, name="Basement AQ", top_sender="Basement AQ", top_target="Irrigation", top_share=0.6,
                    note="a failing link") for i in range(4)]
        recs.append(rec("retransmission_elevation", "warning", T0 + 5000, rate=0.25, baseline=0.07, top_share=0.2))
        eps = group_episodes(recs)
        self.assertEqual([(e["title"], e["count"]) for e in eps],
                         [("retransmissions: Basement AQ -> Irrigation", 4), ("retransmissions: mesh-wide", 1)])
        self.assertAlmostEqual(eps[0]["max_rate"], 0.33)

    def test_startup_first_seen_burst_is_one_row(self):
        recs = [rec("device_first_seen", "info", T0 + i, addr="%016x" % i, name=f"dev{i}") for i in range(24)]
        eps = group_episodes(recs)
        self.assertEqual(len(eps), 1)
        self.assertEqual(eps[0]["title"], "24 devices first seen")


class LongEpisodeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "events"
        self.log = EventLog(self.dir)

    def tearDown(self):
        self.tmp.cleanup()

    def test_multi_day_silence_shows_on_every_day_and_closes_everywhere(self):
        self.log.emit("device_quiet", "warning", T0 - 3 * 86400, addr=AQ, name="AQ", silent_for_s=1800)
        for d in range(-3, 1):
            eps = day_episodes(self.dir, day_of(T0 + d * 86400), now=T0)
            self.assertEqual([e["title"] for e in eps], ["AQ quiet for 3d0h (still quiet)"], d)
            self.assertEqual(eps[0]["carried_over"], d != -3)
        self.log.emit("device_returned", "notice", T0 - 3600, addr=AQ, name="AQ")
        for d in range(-3, 1):
            eps = day_episodes(self.dir, day_of(T0 + d * 86400), now=T0)
            self.assertEqual([e["title"] for e in eps], ["AQ quiet for 2d23h"], d)
        self.assertEqual(day_episodes(self.dir, day_of(T0 + 86400), now=T0 + 2 * 86400), [])

    def test_recurring_rows_split_after_a_gap_and_stay_off_empty_days(self):
        for d in (-1, 1):
            self.log.emit("mle_rejoin_attempt", "notice", T0 + d * 86400, addr=AQ, name="AQ", command="Parent Request")
        self.assertEqual(day_episodes(self.dir, day_of(T0), now=T0 + 2 * 86400), [])
        self.assertEqual(len(device_history(self.dir, AQ)), 2)
        self.log.emit("mle_rejoin_attempt", "notice", T0 + 86400 + 600, addr=AQ, name="AQ", command="Child ID Request")
        rows = device_history(self.dir, AQ)
        self.assertEqual([r["count"] for r in rows], [2, 1])


class DayViewTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Basement AQ", "extendedAddress": AQ.upper(), "threadRole": "router", "model": "IKEA ALPSTUGA"},
            {"name": "Irrigation", "extendedAddress": PLUG, "threadRole": "reed"},
            {"name": "Living Room Apple TV", "extendedAddresses": [TV1.upper(), TV2], "role": "border-router"},
        ]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")
        log = EventLog(self.cfg.events_dir)
        # Quiet at 23:00 the day before, back at 00:30: crosses midnight.
        log.emit("device_quiet", "warning", T0 - 13 * 3600, addr=AQ, name="Basement AQ", reception="good",
                 silent_for_s=1800)
        log.emit("device_returned", "notice", T0 - 12 * 3600 + 30 * 60, addr=AQ, name="Basement AQ")
        log.emit("retransmission_elevation", "notice", T0, rate=0.31, baseline=0.08, addr=AQ, name="Basement AQ",
                 top_sender="Basement AQ", top_target="Irrigation", top_share=0.62, note="failing link")
        log.emit("phase_locked_storm", "critical", T0 + 3600, period_s=60, onsets=3, baseline_frames_per_window=400)
        log.emit("mle_rejoin_attempt", "notice", T0 + 7200, command="Parent Request", src="8001")  # pre-addr record
        log.emit("device_quiet", "warning", T0 - 6 * 3600, addr=TV1, name="Living Room Apple TV", reception="good",
                 silent_for_s=1800)
        log.emit("mle_rejoin_attempt", "notice", T0 + 300, command="Announce", addr=TV2, name="Living Room Apple TV")
        (self.cfg.state_dir / "last-seen.json").write_text(json.dumps({
            AQ: {"first_seen": T0 - 86400, "last_seen": T0 + 3600, "frames": 1000, "types": {"1": 1000}, "rssi": -87.0, "pan": 0x4e21,
                 "quiet_reported": True},
            PLUG: {"first_seen": T0 - 86400, "last_seen": T0 + 3600, "frames": 500, "types": {"1": 500}, "rssi": -70.0, "pan": 0x4e21,
                   "rssi_degraded": True, "rssi_ref": -58.0},
            "72d035122fdf06f6": {"first_seen": T0, "last_seen": T0 + 3600, "frames": 50, "types": {"1": 50}, "rssi": -60.0, "pan": 0x4e21},
            "1afe3b8423f332de": {"first_seen": T0, "last_seen": T0 + 3600, "frames": 5, "types": {"1": 5}, "pan": 0x58bc},
            TV1: {"first_seen": T0 - 86400, "last_seen": T0 - 7 * 3600, "frames": 900, "types": {"1": 900}, "rssi": -55.0,
                  "pan": 0x4e21, "quiet_reported": True},
            TV2: {"first_seen": T0 - 6 * 3600, "last_seen": T0 + 3600, "frames": 400, "types": {"1": 400}, "rssi": -56.0,
                  "pan": 0x4e21, "rssi_ref": -57.0},
        }))
        (self.cfg.state_dir / "status.json").write_text(json.dumps({
            "updated": time.time(), "last_frame_age_s": 1, "channel": 25, "frames_total": 12345,
            "uptime_s": 100, "devices_tracked": 1, "deep_inspection": True, "detector": {"storm_active": False}}))

    def tearDown(self):
        self.tmp.cleanup()

    def test_cross_midnight_quiet_shows_on_both_days_with_real_duration(self):
        yesterday, todayish = day_of(T0 - 86400), day_of(T0)
        for day in (yesterday, todayish):
            eps = {e["title"]: e for e in day_episodes(self.cfg.events_dir, day)}
            self.assertIn("Basement AQ quiet for 2h00m", eps, day)
            self.assertEqual(eps["Basement AQ quiet for 2h00m"]["carried_over"], day == todayish)
        self.assertEqual([r["day"] for r in day_index(self.cfg.events_dir)], [todayish, yesterday])

    def test_now_card_lists_quiet_degraded_and_unknown_on_our_pan(self):
        from threadwatch.names import DeviceNames, LastSeen
        from threadwatch.review import now_card
        seen = LastSeen(self.cfg.state_dir / "last-seen.json")
        card = now_card(seen, DeviceNames(self.cfg.devices_path), self.cfg.events_dir,
                        self.cfg.quiet_min_rssi_dbm, day_of(T0), now=T0 + 7200)
        self.assertEqual([(i["name"], i["silent_for_s"], i["reception"]) for i in card["quiet"]],
                         [("Living Room Apple TV", 32400, "good"), ("Basement AQ", 3600, "marginal")])   # longest first
        self.assertEqual([(i["name"], i["rssi_dbm"], i["reference_dbm"]) for i in card["degraded"]],
                         [("Irrigation", -70.0, -58.0)])
        self.assertEqual([i["addr"] for i in card["unknown"]], ["72d035122fdf06f6"])   # the foreign one is not ours
        self.assertIsNone(card["summary"])
        EventLog(self.cfg.events_dir).emit("daily_summary", "notice", T0 + 8 * 3600, note="last 24 h: fine")
        card = now_card(seen, DeviceNames(self.cfg.devices_path), self.cfg.events_dir,
                        self.cfg.quiet_min_rssi_dbm, day_of(T0), now=T0 + 9 * 3600)
        self.assertEqual(card["summary"]["note"], "last 24 h: fine")

    def test_devices_filter_and_sort(self):
        from threadwatch.names import DeviceNames, LastSeen
        from threadwatch.review import device_rows, dominant_pan, select_devices
        seen = LastSeen(self.cfg.state_dir / "last-seen.json")
        rows = device_rows(seen, DeviceNames(self.cfg.devices_path), self.cfg.quiet_min_rssi_dbm, T0 + 7200)
        dom = dominant_pan(seen)
        pick = lambda **kw: [r["name"] or r["addr"] for r in select_devices(rows, dom, **kw)]
        TV = "Living Room Apple TV"
        self.assertEqual(pick(), ["Basement AQ", "Irrigation", TV, TV, "1afe3b8423f332de", "72d035122fdf06f6"])
        self.assertEqual(pick(only="unknown"), ["1afe3b8423f332de", "72d035122fdf06f6"])
        self.assertEqual(pick(only="quiet"), ["Basement AQ", TV])
        self.assertEqual(pick(only="down"), ["Irrigation"])
        self.assertEqual(pick(only="marginal"), ["Basement AQ"])
        self.assertEqual(pick(only="foreign"), ["1afe3b8423f332de"])
        self.assertEqual(pick(sort="rssi"), ["Basement AQ", "Irrigation", "72d035122fdf06f6", TV, TV, "1afe3b8423f332de"])   # weakest first, unheard last
        self.assertEqual(pick(sort="frames"), ["Basement AQ", TV, "Irrigation", TV, "72d035122fdf06f6", "1afe3b8423f332de"])
        self.assertEqual(pick(only="nonsense", sort="nonsense"), pick())

    def test_resolver_and_merged_history(self):
        from threadwatch.names import DeviceNames
        from threadwatch.review import devices_history
        names = DeviceNames(self.cfg.devices_path)
        self.assertEqual(names.resolve(TV2), ([TV2, TV1], "Living Room Apple TV"))
        self.assertEqual(names.resolve("apple tv"), ([TV1, TV2], "Living Room Apple TV"))
        self.assertEqual(names.resolve("0000000000000000"), (["0000000000000000"], "0000000000000000"))
        with self.assertRaises(ValueError) as cm:
            names.resolve("i")          # Irrigation, Living Room Apple TV
        self.assertIn("ambiguous", str(cm.exception))
        with self.assertRaises(ValueError):
            names.resolve("nothing like it")
        kinds = [(e["kind"], e["addr"]) for e in devices_history(self.cfg.events_dir, [TV1, TV2])]
        self.assertEqual(kinds, [("rejoin", TV2), ("quiet", TV1)])

    def test_incidents_and_storage(self):
        from threadwatch.review import fmt_bytes, incidents, storage
        inc = self.cfg.incidents_dir / "20260902T141500_storm"
        inc.mkdir(parents=True)
        (inc / "threadwatch-20260902-12.pcap").write_bytes(b"x" * 2048)
        (inc / "threadwatch-20260902-14.pcap").write_bytes(b"x" * 1024)
        (inc / "events").mkdir()
        (self.cfg.incidents_dir / "20260901T080000_older").mkdir()
        (self.cfg.incidents_dir / "notes.txt").write_text("not an incident")
        items = incidents(self.cfg.incidents_dir)
        self.assertEqual([i["label"] for i in items], ["storm", "older"])
        self.assertEqual((items[0]["pcaps"], items[0]["span"], items[0]["bytes"], items[0]["events"], items[0]["day"]),
                         (2, ("20260902-12", "20260902-14"), 3072, True, "2026-09-02"))
        self.assertEqual((items[1]["pcaps"], items[1]["span"]), (0, None))
        self.cfg.ring_dir.mkdir(parents=True)
        for h in ("20260903-08", "20260903-09"):
            (self.cfg.ring_dir / f"threadwatch-{h}.pcap").write_bytes(b"y" * 4096)
        sto = storage(self.cfg)
        self.assertEqual((sto["ring_files"], sto["ring_span"], sto["ring_bytes"], sto["bytes_per_hour"]),
                         (2, ("20260903-08", "20260903-09"), 8192, 4096))
        self.assertEqual(sto["incidents_bytes"], 3072 + 15)   # notes.txt is disk usage too
        self.assertGreater(sto["disk_free"], 0)
        self.assertEqual((fmt_bytes(512), fmt_bytes(2048), fmt_bytes(5 * 1024 ** 3)), ("512 B", "2 KB", "5.0 GB"))

    def test_device_history_is_newest_first(self):
        kinds = [e["kind"] for e in device_history(self.cfg.events_dir, AQ)]
        self.assertEqual(kinds, ["retransmissions", "quiet"])

    def test_pages_and_json_render(self):
        httpd = make_server(self.cfg, "127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_port}"
        try:
            def get(path):
                with urllib.request.urlopen(base + path, timeout=5) as r:
                    return r.status, r.read().decode()
            day = day_of(T0)
            status, body = get(f"/day/{day}")
            self.assertEqual(status, 200)
            self.assertIn("quiet for 2h00m", body)
            self.assertIn('<td class="t">23:00<small>yesterday</small></td>', body)   # carried over from the day before
            self.assertIn("Carried over", body)
            self.assertNotIn("yesterday", get(f"/day/{day_of(T0 - 86400)}")[1])
            self.assertIn("phase-locked storm", body)
            self.assertIn("retransmissions: Basement AQ -&gt; Irrigation", body)
            self.assertIn("capturing", body)
            self.assertIn("8001 rejoin attempt", body)
            self.assertNotIn('href="/device/8001"', body)   # a short address has no device page
            status, body = get("/devices")
            self.assertIn("Basement AQ", body)
            self.assertIn("marginal", body)
            self.assertIn(">ours<", body)
            status, body = get("/devices?only=unknown&sort=frames")
            self.assertNotIn("Basement AQ", body)
            self.assertIn("showing 2 (not in devices.json)", body)
            self.assertIn('href="/devices?only=unknown">', body)            # sort=name link keeps the filter
            self.assertIn('href="/devices?only=quiet&sort=frames"', body)  # filter links keep the sort
            self.assertIn("Basement AQ", get("/devices?only=nothing&sort=zzz")[1])   # unknown parameters: the full page
            self.assertEqual([d["name"] for d in json.loads(get("/api/devices?only=quiet")[1])["devices"]],
                             ["Basement AQ", "Living Room Apple TV"])
            status, body = get(f"/device/{AQ}")
            self.assertIn("IKEA ALPSTUGA", body)
            self.assertIn("quiet for 2h00m", body)
            status, body = get(f"/device/{TV2}")
            self.assertIn("<h1>Living Room Apple TV</h1>", body)
            self.assertIn("2 addresses (rotates)", body)
            self.assertIn(f"<code>{TV1}</code>", body)
            self.assertIn("Living Room Apple TV rejoin attempt", body)     # TV2's episode
            self.assertIn("quiet for", body)                               # TV1's episode
            self.assertIn("usually -57.0", body)
            self.assertLess(body.index(f"<code>{TV2}</code>"), body.index(f"<code>{TV1}</code>"))   # freshest first
            self.assertIn("<h1>Living Room Apple TV</h1>", get("/device/Living%20Room")[1])
            self.assertIn("<h1>which device?</h1>", get("/device/i")[1])
            self.assertIn("<h1>unknown device</h1>", get("/device/72d035122fdf06f6")[1])
            data = json.loads(get(f"/api/device/{TV1}")[1])
            self.assertEqual(data["addresses"], [TV1, TV2])
            self.assertEqual([e["kind"] for e in data["episodes"]], ["rejoin", "quiet"])
            status, body = get(f"/api/day/{day}")
            data = json.loads(body)
            self.assertEqual(len(data["records"]), 6)
            self.assertEqual(data["episodes"][0]["kind"], "quiet")
            status, body = get("/")
            self.assertEqual(status, 200)
            self.assertIn('<meta http-equiv="refresh" content="60">', body)
            self.assertNotIn('http-equiv="refresh"', get(f"/day/{day}")[1])   # only today reloads
            _, floored = get(f"/day/{day}?min=warning")
            self.assertIn("phase-locked storm", floored)
            self.assertNotIn("rejoin attempt", floored)                     # a notice
            self.assertIn("3 of 6", floored)                                # quiet x2 (warning), storm
            self.assertIn(f'href="/day/{day_of(T0 - 86400)}?min=warning"', floored)
            self.assertIn("quiet now", body)
            self.assertIn("signal down", body)
            self.assertIn('href="/devices?only=unknown">1 address</a>', body)
            self.assertNotIn("quiet now", get(f"/day/{day}")[1])   # live facts only on today's page
            self.assertEqual(get("/devices/")[0], 200)
            self.assertEqual(get(f"/day/{day}/")[0], 200)
            status, body = get("/help")
            self.assertIn("Phase-locked storm", body)
            inc = self.cfg.incidents_dir / f"{day.replace('-', '')}T141500_storm"
            inc.mkdir(parents=True)
            (inc / "threadwatch-20260902-12.pcap").write_bytes(b"x" * 100)
            status, body = get("/incidents")
            self.assertIn("<b>storm</b>", body)
            self.assertIn("1 pcaps, 20260902-12 to 20260902-12", body)
            self.assertIn(f'href="/incidents#{inc.name}"', get(f"/day/{day}")[1])
            status, body = get("/status")
            self.assertIn(">running<", body)
            self.assertIn("deep (credentials loaded", body)
            self.assertIn("free</span> of", body)
            self.assertIn("12,345 frames", body)
            self.assertIn("storage", json.loads(get("/api/status")[1]))
            self.assertEqual(json.loads(get("/api/incidents")[1])["incidents"][0]["label"], "storm")
            self.assertIn('title="', get(f"/day/{day}")[1])   # rows carry the legend as tooltips
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                get("/device/zzz")
            self.assertEqual(ctx.exception.code, 404)
            self.assertIn("no such device", ctx.exception.read().decode())
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                get("/day/2026-13-99")
            self.assertEqual(ctx.exception.code, 404)
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()


class FmtEpisodeTest(unittest.TestCase):
    def test_single_and_recurring_rows(self):
        from threadwatch.review import fmt_episode
        eps = group_episodes([
            rec("device_quiet", "warning", T0, addr=AQ, name="AQ", silent_for_s=1800),
            rec("device_returned", "notice", T0 + 600, addr=AQ, name="AQ"),
            rec("retransmission_elevation", "notice", T0, top_sender="AQ", top_target="broadcast",
                rate=0.3, note="chatter"),
            rec("retransmission_elevation", "notice", T0 + 900, top_sender="AQ", top_target="broadcast",
                rate=0.4, note="chatter"),
        ])
        lines = [fmt_episode(e) for e in eps]
        self.assertEqual(lines[0], "09-02 12:00 [warning ] AQ quiet for 40m  no frames heard")
        self.assertEqual(lines[1], "09-02 12:00 [notice  ] retransmissions: AQ -> broadcast x2 over 15m  chatter")
        self.assertTrue(fmt_episode(eps[0], "%Y-%m-%d %H:%M").startswith("2026-09-02 12:00 "))


class LinkEpisodeTest(unittest.TestCase):
    def test_degradation_and_recovery_are_one_row(self):
        eps = group_episodes([
            rec("rssi_degradation", "notice", T0, addr=AQ, name="AQ", rssi_dbm=-70.5,
                reference_dbm=-60.0, drop_db=10.5, since=T0 - 1800),
            rec("rssi_recovered", "info", T0 + 3600, addr=AQ, name="AQ", rssi_dbm=-61.0,
                reference_dbm=-60.0),
        ], now=T0 + 7200)
        self.assertEqual(len(eps), 1)
        self.assertEqual(eps[0]["kind"], "link")
        self.assertEqual(eps[0]["title"], "AQ signal down 10.5 dB for 90m")
        self.assertEqual(eps[0]["detail"], "-70.5 dBm, usually -60.0 dBm")
        self.assertEqual(eps[0]["end"], T0 + 3600)

    def test_open_drop_says_still_down(self):
        eps = group_episodes([
            rec("rssi_degradation", "notice", T0, addr=AQ, name="AQ", rssi_dbm=-70.0,
                reference_dbm=-60.0, drop_db=10.0, since=T0 - 1800),
        ], now=T0 + 1800)
        self.assertEqual(eps[0]["title"], "AQ signal down 10 dB for 60m (still down)")
        self.assertIsNone(eps[0]["end"])


class StarvedEpisodeTest(unittest.TestCase):
    def test_starvation_and_answer_are_one_row(self):
        eps = group_episodes([
            rec("poll_starvation", "warning", T0, addr=AQ, name="AQ", unanswered_polls=10, acked_polls=200,
                since=T0 - 90),
            rec("poll_answered", "notice", T0 + 600, addr=AQ, name="AQ", note="its polls are acknowledged again"),
        ])
        self.assertEqual(len(eps), 1)
        self.assertEqual((eps[0]["kind"], eps[0]["title"], eps[0]["detail"]),
                         ("starved", "AQ polls unanswered for 11m", "10 polls, 200 answered before"))
        still = group_episodes([rec("poll_starvation", "warning", T0, addr=AQ, name="AQ", unanswered_polls=10,
                                    acked_polls=200, since=T0 - 90)], now=T0 + 1800)
        self.assertEqual(still[0]["title"], "AQ polls unanswered for 31m (still unanswered)")


class SummaryEpisodeTest(unittest.TestCase):
    def test_each_summary_is_its_own_row(self):
        eps = group_episodes([
            rec("daily_summary", "notice", T0, note="last 24 h: 1 frame"),
            rec("daily_summary", "notice", T0 + 86400, note="last 24 h: 2 frames"),
        ])
        self.assertEqual([(e["kind"], e["title"], e["detail"]) for e in eps],
                         [("summary", "daily summary", "last 24 h: 1 frame"),
                          ("summary", "daily summary", "last 24 h: 2 frames")])
