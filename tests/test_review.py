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
        (self.cfg.state_dir / "last-seen.json").write_text(json.dumps({
            AQ: {"first_seen": T0 - 86400, "last_seen": T0 + 3600, "frames": 1000, "types": {"1": 1000}, "rssi": -87.0, "pan": 0x4e21},
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
            status, body = get(f"/device/{AQ}")
            self.assertIn("IKEA ALPSTUGA", body)
            self.assertIn("quiet for 2h00m", body)
            status, body = get(f"/api/day/{day}")
            data = json.loads(body)
            self.assertEqual(len(data["records"]), 4)
            self.assertEqual(data["episodes"][0]["kind"], "quiet")
            self.assertEqual(get("/")[0], 200)
            self.assertEqual(get("/devices/")[0], 200)
            self.assertEqual(get(f"/day/{day}/")[0], 200)
            status, body = get("/help")
            self.assertIn("Phase-locked storm", body)
            self.assertIn('title="', get(f"/day/{day}")[1])   # rows carry the legend as tooltips
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                get("/device/zzz")
            self.assertEqual(ctx.exception.code, 404)
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


class SummaryEpisodeTest(unittest.TestCase):
    def test_each_summary_is_its_own_row(self):
        eps = group_episodes([
            rec("daily_summary", "notice", T0, note="last 24 h: 1 frame"),
            rec("daily_summary", "notice", T0 + 86400, note="last 24 h: 2 frames"),
        ])
        self.assertEqual([(e["kind"], e["title"], e["detail"]) for e in eps],
                         [("summary", "daily summary", "last 24 h: 1 frame"),
                          ("summary", "daily summary", "last 24 h: 2 frames")])
