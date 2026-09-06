"""Event log day rolling, episode grouping, and the web review pages."""

import contextlib
import io
import json
import os
import signal
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.config import Config  # noqa: E402
from threadwatch.events import EventLog, day_bounds, day_of, list_days, migrate_legacy, read_day  # noqa: E402
from threadwatch.review import (coverage, coverage_since, day_episodes, day_index, device_history,  # noqa: E402
                                episode_blind_s, group_episodes)
from threadwatch import web  # noqa: E402
from threadwatch.web import make_server  # noqa: E402

AQ = "26976e7f7d20964a"
PLUG = "2a2d355a26ccae5f"
TV1, TV2 = "b62c32bf669272db", "e6c279e8f0c70298"
T0 = time.mktime(time.strptime("2026-09-02 12:00", "%Y-%m-%d %H:%M"))


def rec(event, severity, ts, **f):
    return {"ts": ts, "event": event, "severity": severity, **f}


# serve_forever's default poll_interval is 0.5 s, and shutdown() blocks
# until the loop next polls: every test that builds a server paid half a
# second of pure waiting on the way out, including the many that never
# make a request. Thirteen seconds of the suite's runtime sat here.
POLL_S = 0.005

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
            (state / "events" / f"{day_of(T0)}.jsonl").write_text("\n".join(lines[:2]) + "\n")  # copied before the kill
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
            {"ts": T0 + 600, "event": "device_quiet", "severity": "warning", "addr": AQ, "name": "AQ",
             "silent_for_s": 2400},
            {"ts": T0 + 1800, "event": "device_returned", "severity": "notice", "addr": AQ, "name": "AQ"},
        ]
        eps = group_episodes(recs, now=T0 + 7200)
        self.assertEqual([(e["kind"], e["end"], e["count"]) for e in eps], [("quiet", T0 + 1800, 2)])
        self.assertEqual(eps[0]["title"], "AQ quiet for 60m")

    def test_open_quiet_says_still_quiet(self):
        eps = group_episodes([rec("device_quiet", "warning", T0, addr=AQ, name="Basement AQ")], now=T0 + 3600)
        self.assertIn("still quiet", eps[0]["title"])
        self.assertIsNone(eps[0]["end"])

    def test_a_row_takes_the_worst_severity_of_its_records_whatever_the_order(self):
        # Repeats fold into one row (bump); the row's severity is the
        # highest any record reached, and never comes back down.
        base = dict(addr=AQ, name="AQ", unanswered_polls=12, acked_polls=40, since=T0)
        rising = [rec("poll_starvation", "notice", T0, **base),
                  rec("poll_starvation", "warning", T0 + 600, **base),
                  rec("poll_starvation", "critical", T0 + 1200, **base)]
        falling = [rec("poll_starvation", "critical", T0, **base),
                   rec("poll_starvation", "warning", T0 + 600, **base),
                   rec("poll_starvation", "notice", T0 + 1200, **base)]
        for recs in (rising, falling, rising[::-1]):
            eps = group_episodes(recs, now=T0 + 7200)
            self.assertEqual([(e["kind"], e["count"], e["severity"]) for e in eps], [("starved", 3, "critical")])
        eps = group_episodes(rising[:2] + [rec("poll_answered", "notice", T0 + 900, addr=AQ, name="AQ")])
        self.assertEqual([(e["count"], e["severity"], e["end"]) for e in eps], [(2, "warning", T0 + 900)])
        # The quiet row escalates the same way (its own fold, not bump).
        quiet = [rec("device_quiet", "notice", T0, addr=AQ, name="AQ", reception="marginal", silent_for_s=1800),
                 rec("device_quiet", "warning", T0 + 600, addr=AQ, name="AQ", reception="good", silent_for_s=2400)]
        for recs in (quiet, quiet[::-1]):
            self.assertEqual([e["severity"] for e in group_episodes(recs, now=T0 + 7200)], ["warning"])

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

    def test_the_quiet_row_starts_at_the_last_frame_the_record_carries(self):
        # After a recorder outage the record's silent_for_s is the wall
        # clock and last_seen is exact; the row and the "quiet now" card
        # (both from last_seen) then say the same. An older record without
        # last_seen still works from silent_for_s.
        self.log.emit("device_quiet", "warning", T0, addr=AQ, name="AQ", silent_for_s=4140, unheard_s=1800,
                      blind_s=2340, last_seen=T0 - 4140)
        self.log.emit("device_quiet", "warning", T0, addr=PLUG, name="Plug", silent_for_s=1800)
        eps = {e["name"]: e for e in day_episodes(self.dir, day_of(T0), now=T0 + 60)}
        self.assertEqual(eps["AQ"]["silent_since"], T0 - 4140)
        self.assertEqual(eps["AQ"]["title"], "AQ quiet for 70m (still quiet)")
        self.assertEqual(eps["Plug"]["silent_since"], T0 - 1800)

    def test_a_day_page_reads_a_window_not_the_whole_history(self):
        from threadwatch.review import EPISODE_WINDOW_DAYS
        far = EPISODE_WINDOW_DAYS + 10
        self.log.emit("device_quiet", "warning", T0 - far * 86400, addr=AQ, name="AQ", silent_for_s=1800)
        self.log.emit("device_quiet", "warning", T0 - 2 * 86400, addr=PLUG, name="Plug", silent_for_s=1800)
        eps = day_episodes(self.dir, day_of(T0), now=T0)
        self.assertEqual([e["title"] for e in eps], ["Plug quiet for 2d0h (still quiet)"])
        # On its own day the old silence is still there, with its duration.
        eps = day_episodes(self.dir, day_of(T0 - far * 86400), now=T0)
        self.assertEqual([e["title"] for e in eps], [f"AQ quiet for {far}d0h (still quiet)"])

    def test_recurring_rows_split_after_a_gap_and_stay_off_empty_days(self):
        for d in (-1, 1):
            self.log.emit("mle_rejoin_attempt", "notice", T0 + d * 86400, addr=AQ, name="AQ", command="Parent Request")
        self.assertEqual(day_episodes(self.dir, day_of(T0), now=T0 + 2 * 86400), [])
        self.assertEqual(len(device_history(self.dir, AQ)), 2)
        self.log.emit("mle_rejoin_attempt", "notice", T0 + 86400 + 600, addr=AQ, name="AQ", command="Child ID Request")
        rows = device_history(self.dir, AQ)
        self.assertEqual([r["count"] for r in rows], [2, 1])


class HistoryScanCostTest(unittest.TestCase):
    """Two request paths used to walk every day file on disk, once per
    address in devices_history's case. Retention is a year: the pages got
    slower every month with no plateau, on the Pi they are designed for."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name) / "events"
        self.dir.mkdir(parents=True)
        self.days = []
        for i in range(200):
            day = day_of(T0 - i * 86400)
            self.days.append(day)
            ts = day_bounds(day)[0] + 3600
            (self.dir / f"{day}.jsonl").write_text("".join(
                json.dumps({"ts": ts + n, "event": "mle_rejoin_attempt", "severity": "notice",
                            "addr": AQ if n % 2 else TV1, "name": "x", "command": "Parent Request",
                            "id": f"{day}-{n}"}) + "\n" for n in range(20)))

    def tearDown(self):
        self.tmp.cleanup()

    def _reads(self, call):
        """Which day files one call reads. events.iter_days and review both
        reach read_day, so both names are counted."""
        import threadwatch.events as events_mod
        import threadwatch.review as review_mod
        opened = []
        real = events_mod.read_day

        def counting(events_dir, day):
            opened.append(day)
            return real(events_dir, day)

        events_mod.read_day = review_mod.read_day = counting
        try:
            call()
        finally:
            events_mod.read_day = review_mod.read_day = real
        return opened

    def test_a_device_page_reads_its_window_once_however_many_addresses(self):
        from threadwatch.review import DEVICE_HISTORY_DAYS, EPISODE_WINDOW_DAYS, devices_history
        window = DEVICE_HISTORY_DAYS + EPISODE_WINDOW_DAYS + 1
        one = self._reads(lambda: devices_history(self.dir, [AQ], now=T0))
        self.assertLessEqual(len(one), window)
        self.assertLess(len(one), len(self.days))
        # A rotating hub is several addresses with one story, not several
        # walks of the history.
        five = self._reads(lambda: devices_history(self.dir, [AQ, TV1, TV2, "%016x" % 1, "%016x" % 2], now=T0))
        self.assertEqual(len(five), len(one))
        self.assertEqual(len(set(five)), len(five))
        eps = devices_history(self.dir, [AQ, TV1], now=T0)
        self.assertTrue(eps)
        self.assertTrue(all(e["start"] >= T0 - (DEVICE_HISTORY_DAYS + EPISODE_WINDOW_DAYS) * 86400 for e in eps))

    def test_the_day_index_re_counts_only_the_files_that_changed(self):
        from threadwatch.review import day_index
        first = day_index(self.dir)
        self.assertEqual(len(first), len(self.days))
        self.assertEqual(first[0]["total"], 20)
        self.assertEqual(self._reads(lambda: day_index(self.dir)), [])      # every count cached
        self.assertEqual(day_index(self.dir), first)
        changed = self.days[0]
        with open(self.dir / f"{changed}.jsonl", "a") as fh:
            fh.write(json.dumps({"ts": T0, "event": "alert_test", "severity": "critical",
                                 "name": "x", "id": "new"}) + "\n")
        self.assertEqual(self._reads(lambda: day_index(self.dir)), [changed])
        self.assertEqual(day_index(self.dir)[0], {"day": changed, "total": 21, "info": 0,
                                                  "notice": 20, "warning": 0, "critical": 1})


class DayBoundaryTest(unittest.TestCase):
    def test_a_record_at_midnight_is_the_first_row_of_the_day_it_starts(self):
        with tempfile.TemporaryDirectory() as tmp:
            events = Path(tmp) / "events"
            log = EventLog(events)
            day = day_of(T0)
            start, end = day_bounds(day)
            log.emit("alert_test", "info", start - 1, name="x", note="a second before midnight")
            log.emit("clock_step", "info", start, step_s=60, note="at midnight")
            log.emit("clock_step", "info", end - 1, step_s=60, note="a second before the next midnight")
            log.emit("clock_step", "info", end, step_s=60, note="at the next midnight")
            now = end + 3600

            def notes(which):
                return [(e["detail"], e["carried_over"]) for e in day_episodes(events, which, now)]

            self.assertEqual(notes(day), [("at midnight", False), ("a second before the next midnight", False)])
            self.assertEqual(notes(day_of(start - 1)), [("a second before midnight", False)])
            self.assertEqual(notes(day_of(end)), [("at the next midnight", False)])


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
            AQ: {"first_seen": T0 - 86400, "last_seen": T0 + 3600, "frames": 1000, "types": {"1": 1000}, "rssi": -87.0,
                 "pan": 0x4e21,
                 "quiet_reported": True, "rloc16": "f000", "rloc16_ts": T0 + 3600},
            PLUG: {"first_seen": T0 - 86400, "last_seen": T0 + 3600, "frames": 500, "types": {"1": 500}, "rssi": -70.0,
                   "pan": 0x4e21,
                   "rssi_degraded": True, "rssi_ref": -58.0, "rloc16": "f00c", "rloc16_ts": T0 + 3000},
            "72d035122fdf06f6": {"first_seen": T0, "last_seen": T0 + 3600, "frames": 50, "types": {"1": 50},
                                 "rssi": -60.0, "pan": 0x4e21},
            "1afe3b8423f332de": {"first_seen": T0, "last_seen": T0 + 3600, "frames": 5, "types": {"1": 5},
                                 "pan": 0x58bc},
            TV1: {"first_seen": T0 - 86400, "last_seen": T0 - 7 * 3600, "frames": 900, "types": {"1": 900},
                  "rssi": -55.0,
                  "pan": 0x4e21, "quiet_reported": True},
            TV2: {"first_seen": T0 - 6 * 3600, "last_seen": T0 + 3600, "frames": 400, "types": {"1": 400},
                  "rssi": -56.0,
                  "pan": 0x4e21, "rssi_ref": -57.0},
        }))
        (self.cfg.state_dir / "status.json").write_text(json.dumps({
            "updated": time.time(), "last_frame_age_s": 1, "channel": 25, "frames_total": 12345,
            "uptime_s": 100, "devices_tracked": 1, "detector": {"storm_active": False}}))

    def tearDown(self):
        self.tmp.cleanup()

    def test_cross_midnight_quiet_shows_on_both_days_with_real_duration(self):
        yesterday, todayish = day_of(T0 - 86400), day_of(T0)
        for day in (yesterday, todayish):
            eps = {e["title"]: e for e in day_episodes(self.cfg.events_dir, day)}
            self.assertIn("Basement AQ quiet for 2h00m", eps, day)
            self.assertEqual(eps["Basement AQ quiet for 2h00m"]["carried_over"], day == todayish)
        self.assertEqual([r["day"] for r in day_index(self.cfg.events_dir)], [todayish, yesterday])

    def test_the_day_page_draws_coverage_and_marks_a_silence_nobody_heard(self):
        log = EventLog(self.cfg.events_dir)
        # The recorder was killed at 00:01 and came back at 00:15, inside
        # the AQ's silence (22:30 yesterday to 00:30).
        midnight = day_bounds(day_of(T0))[0]
        log.emit("recorder_started", "notice", midnight + 900, cause="unknown", gap_s=840,
                 last_frame_ts=midnight + 60, stopped_ts=None, exit_code=None, note="not listening for 14 min")
        httpd = make_server(self.cfg, "127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, args=(POLL_S,), daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_port}"
        try:
            def get(path):
                with urllib.request.urlopen(base + path, timeout=5) as r:
                    return r.read().decode()
            body = get(f"/day/{day_of(T0)}")
            self.assertIn('<div class="cov">', body)
            self.assertIn('<div class="blind"', body)
            self.assertIn("<b>00:01-00:15</b> not listening", body)
            self.assertIn("power cut", body)
            self.assertIn("recorder off 14m of this", body)
            self.assertIn("recorder restarted (14m without frames)", body)
            self.assertIn("coverage: not recorded before", get(f"/day/{day_of(T0 - 86400)}"))
            data = json.loads(get(f"/api/day/{day_of(T0)}"))
            self.assertEqual([(s["state"], s["start"], s["end"], s["cause"]) for s in data["coverage"]],
                             [("blind", midnight + 60, midnight + 900, "unknown")])
        finally:
            httpd.shutdown()
            httpd.server_close()

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
        self.assertEqual(pick(only="routers"), ["Basement AQ"])
        self.assertEqual(pick(only="children"), ["Irrigation"])
        by = {r["name"] or r["addr"]: r for r in rows}
        self.assertEqual((by["Basement AQ"]["role"], by["Basement AQ"]["router_id"], by["Basement AQ"]["leader"]),
                         ("router", 60, False))
        self.assertEqual((by["Irrigation"]["role"], by["Irrigation"]["parent"], by["Irrigation"]["parent_addr"]),
                         ("child", "Basement AQ", AQ))
        self.assertIsNone(by[TV]["role"])
        led = device_rows(seen, DeviceNames(self.cfg.devices_path), self.cfg.quiet_min_rssi_dbm, T0 + 7200,
                          leader_router=60)
        self.assertTrue(next(r for r in led if r["addr"] == AQ)["leader"])
        # weakest first, unheard last
        self.assertEqual(pick(sort="rssi"),
                         ["Basement AQ", "Irrigation", "72d035122fdf06f6", TV, TV, "1afe3b8423f332de"])
        self.assertEqual(pick(sort="frames"),
                         ["Basement AQ", TV, "Irrigation", TV, "72d035122fdf06f6", "1afe3b8423f332de"])
        self.assertEqual(pick(only="nonsense", sort="nonsense"), pick())

    def test_resolver_and_merged_history(self):
        from threadwatch.names import DeviceNames
        from threadwatch.review import devices_history
        names = DeviceNames(self.cfg.devices_path)
        self.assertEqual(names.resolve(TV2), ([TV2, TV1], "Living Room Apple TV"))
        self.assertEqual(names.resolve("apple tv"), ([TV1, TV2], "Living Room Apple TV"))
        self.assertEqual(names.resolve("0000000000000000"), (["0000000000000000"], "0000000000000000"))
        from threadwatch.names import AmbiguousName
        with self.assertRaises(AmbiguousName) as cm:
            names.resolve("i")          # Irrigation, Living Room Apple TV
        self.assertIn("ambiguous", str(cm.exception))
        self.assertEqual(cm.exception.candidates, ["Irrigation", "Living Room Apple TV"])
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
        self.assertEqual((sto["ring_bound_bytes"], sto["ring_needs_bytes"]),
                         (self.cfg.keep_files * 4096, self.cfg.keep_files * 4096 - 8192))
        self.cfg.keep_bytes = 10000                            # keep_gb wins when it is the smaller bound...
        sto = storage(self.cfg)                                # ...plus the hour being written, never pruned
        self.assertEqual((sto["keep_bytes"], sto["ring_bound_bytes"], sto["ring_needs_bytes"]), (10000, 14096, 5904))
        self.cfg.keep_bytes = 4096                             # already over the cap: nothing more needed
        self.assertEqual(storage(self.cfg)["ring_needs_bytes"], 0)
        self.assertEqual((fmt_bytes(512), fmt_bytes(2048), fmt_bytes(5 * 1024 ** 3)), ("512 B", "2 KB", "5.0 GB"))

    def test_incidents_are_filed_by_the_days_their_packets_cover(self):
        from threadwatch.review import capture_for_day
        late = self.cfg.incidents_dir / "20260904T000500_auto-storm"      # frozen just after midnight...
        late.mkdir(parents=True)
        for h in ("20260830-22", "20260830-23", "20260831-00"):           # ...holding the storm's evening
            (late / f"threadwatch-{h}.pcap").write_bytes(b"x")
        (self.cfg.incidents_dir / "20260904T090000_empty").mkdir()          # no pcaps: its freeze day
        by_day = {d: capture_for_day(self.cfg.ring_dir, self.cfg.incidents_dir, d)["incidents"]
                  for d in ("2026-08-29", "2026-08-30", "2026-08-31", "2026-09-04")}
        self.assertEqual(by_day, {"2026-08-29": [], "2026-08-30": [late.name], "2026-08-31": [late.name],
                                  "2026-09-04": ["20260904T090000_empty"]})
        self.assertEqual(capture_for_day(self.cfg.ring_dir, Path(self.tmp.name) / "none", "2026-08-30")["incidents"],
                         [])

    def test_chooser_links_survive_url_special_characters_in_names(self):
        d = self.cfg.devices_path
        entries = json.loads(d.read_text())
        entries += [{"name": "Lamp #1", "extendedAddress": "1111111111111111"},
                    {"name": "Lamp #2", "extendedAddress": "2222222222222222"}]
        d.write_text(json.dumps(entries))
        httpd = make_server(self.cfg, "127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, args=(POLL_S,), daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_port}"
        try:
            def get(path):
                with urllib.request.urlopen(base + path, timeout=5) as r:
                    return r.status, r.read().decode()
            body = get("/device/Lamp")[1]
            self.assertIn("<h1>which device?</h1>", body)
            self.assertIn('<a href="/device/Lamp%20%231">Lamp #1</a>', body)
            self.assertIn("<h1>Lamp #1</h1>", get("/device/Lamp%20%231")[1])
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_device_page_describes_the_live_address_however_it_was_reached(self):
        from threadwatch.review import live_address
        from threadwatch.names import LastSeen
        table = LastSeen(self.cfg.state_dir / "last-seen.json").table
        self.assertEqual(live_address([TV1, TV2], table), TV2)                  # by name: inventory order
        self.assertEqual(live_address([TV2, TV1], table), TV2)                  # by address: the asked-for one first
        self.assertEqual(live_address(["0000000000000001", TV1], {}), "0000000000000001")   # nothing heard: the first
        # The recorder has bound the TV's hostname to its live address.
        (self.cfg.state_dir / "border-routers.json").write_text(json.dumps({
            "appletv-living-room.local": {"addr": TV2, "name": "Living Room Apple TV",
                                          "instance": "AppleTV Living Room",
                                          "vendor": "Apple", "model": "BorderRouter"}}))
        httpd = make_server(self.cfg, "127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, args=(POLL_S,), daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_port}"
        try:
            for path in ("/device/Living%20Room", f"/device/{TV1}", f"/device/{TV2}"):
                with urllib.request.urlopen(base + path, timeout=5) as r:
                    body = r.read().decode()
                self.assertIn("border router AppleTV Living Room (Apple BorderRouter)", body, path)
                self.assertIn(f'href="/api/device/{TV2}"', body, path)
                self.assertLess(body.index(f"<code>{TV2}</code>"), body.index(f"<code>{TV1}</code>"))
            with urllib.request.urlopen(base + "/api/device/Living%20Room", timeout=5) as r:
                data = json.loads(r.read())
            self.assertEqual((data["addr"], data["addresses"], data["live"]["border_router"]),
                             (TV2, [TV1, TV2], "appletv-living-room.local"))
        finally:
            httpd.shutdown()
            httpd.server_close()

    def test_device_history_is_newest_first(self):
        kinds = [e["kind"] for e in device_history(self.cfg.events_dir, AQ)]
        self.assertEqual(kinds, ["retransmissions", "quiet"])

    def test_pages_and_json_render(self):
        httpd = make_server(self.cfg, "127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, args=(POLL_S,), daemon=True).start()
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
            self.assertEqual(data["addr"], TV2)                                 # reached by the old address...
            self.assertEqual(data["last_seen"]["rssi"], -56.0)                  # ...described by the live one
            self.assertEqual(sorted(data["addresses_seen"]), sorted([TV1, TV2]))
            self.assertEqual(data["addresses_seen"][TV2]["rssi"], -56.0)
            self.assertEqual(json.loads(get("/api/device/Living%20Room")[1])["addresses"], [TV1, TV2])
            try:
                urllib.request.urlopen(base + "/api/device/zzz", timeout=5)
                self.fail("expected 404")
            except urllib.error.HTTPError as exc:
                self.assertEqual(exc.code, 404)
                self.assertIn("neither", json.loads(exc.read().decode())["error"])
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
            self.assertNotIn("inspection", body)
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


class WebServerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config(data_dir=Path(self.tmp.name) / "data")

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _get(base, path):
        try:
            with urllib.request.urlopen(base + path, timeout=5) as r:
                return r.status, dict(r.headers), r.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read().decode()

    def test_a_page_that_raises_is_a_500_and_the_server_goes_on_serving(self):
        real = web.Site.respond

        def respond(site, path, query_string=""):
            if path == "/boom":
                raise RuntimeError("the template broke")
            return real(site, path, query_string)

        httpd = make_server(self.cfg, "127.0.0.1", 0)
        threading.Thread(target=httpd.serve_forever, args=(POLL_S,), daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_port}"
        try:
            with mock.patch.object(web.Site, "respond", respond):
                status, headers, body = self._get(base, "/boom?x=1")
                self.assertEqual((status, body), (500, "error: RuntimeError: the template broke"))
                self.assertEqual((headers["Content-Type"], headers["Content-Length"], headers["Cache-Control"]),
                                 ("text/plain", str(len(body)), "no-store"))
                self.assertEqual(self._get(base, "/")[0], 200)                       # still up
                self.assertEqual(self._get(base, "/boom")[0], 500)                   # and again, every time
            self.assertEqual(self._get(base, "/no-such-page")[0], 404)
        finally:
            httpd.shutdown()
            httpd.server_close()

    def _serve(self, cfg):
        """serve() in this thread, as the container runs it (PID 1 and
        all): the reply and SIGTERM come from a helper thread."""
        out = io.StringIO()
        got = {}

        def client():
            deadline = time.time() + 5
            while "web: http://" not in out.getvalue() and time.time() < deadline:
                time.sleep(0.01)
            line = out.getvalue()
            port = int(line.split("http://127.0.0.1:")[1].split("/")[0])
            got["status"] = self._get(f"http://127.0.0.1:{port}", "/")[0]
            os.kill(os.getpid(), signal.SIGTERM)                           # what `docker stop` sends

        previous = signal.getsignal(signal.SIGTERM)
        t = threading.Thread(target=client, daemon=True)
        try:
            with contextlib.redirect_stdout(out):
                t.start()
                web.serve(cfg, "127.0.0.1", 0)                            # returns once SIGTERM shuts it down
        finally:
            signal.signal(signal.SIGTERM, previous)
        t.join(5)
        return got.get("status"), out.getvalue()

    def test_serve_prints_its_address_answers_and_stops_on_sigterm(self):
        status, printed = self._serve(self.cfg)
        self.assertEqual(status, 200)
        self.assertRegex(printed, r"^\[threadwatch\] web: http://127\.0\.0\.1:\d+/ \(state .*/data/state\)\n$")
        self.assertNotIn("does not exist yet", printed)

    @unittest.skipIf(os.geteuid() == 0, "root can always create the state directory")
    def test_serve_says_when_the_state_directory_cannot_exist_yet(self):
        os.makedirs(self.cfg.data_dir)
        os.chmod(self.cfg.data_dir, 0o500)                                # the web container's data:ro
        try:
            status, printed = self._serve(self.cfg)
        finally:
            os.chmod(self.cfg.data_dir, 0o700)
        self.assertEqual(status, 200)
        self.assertIn("does not exist yet, so the pages are empty until threadwatch capture has started", printed)


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
    def test_the_page_confirming_a_starvation_leaves_it_open(self):
        # BUG-06: the confirmed warning that follows the notice used to set
        # the episode's end, so an outage read as over the moment the
        # detector escalated it, and day_episodes dropped it from later days.
        recs = [
            rec("poll_starvation", "notice", T0 + 60, addr=AQ, name="AQ", unanswered_polls=10, acked_polls=200,
                since=T0, confirmed=False),
            rec("poll_starvation", "warning", T0 + 660, addr=AQ, name="AQ", unanswered_polls=40, acked_polls=200,
                since=T0, confirmed=True),
        ]
        eps = group_episodes(recs, now=T0 + 1200)
        self.assertEqual(len(eps), 1)
        self.assertIsNone(eps[0]["end"])
        self.assertEqual((eps[0]["count"], eps[0]["severity"]), (2, "warning"))
        self.assertEqual(eps[0]["title"], "AQ polls unanswered for 20m (still unanswered)")
        closed = group_episodes(recs + [rec("poll_answered", "notice", T0 + 900, addr=AQ, name="AQ")], now=T0 + 1200)
        self.assertEqual((closed[0]["end"], closed[0]["count"]), (T0 + 900, 2))
        self.assertEqual(closed[0]["title"], "AQ polls unanswered for 15m")

    def test_a_repeated_degradation_record_leaves_the_drop_open(self):
        recs = [
            rec("rssi_degradation", "notice", T0, addr=AQ, name="AQ", rssi_dbm=-70.0,
                reference_dbm=-60.0, drop_db=10.0, since=T0 - 1800),
            rec("rssi_degradation", "notice", T0 + 3600, addr=AQ, name="AQ", rssi_dbm=-72.0,
                reference_dbm=-60.0, drop_db=12.0, since=T0 - 1800),
        ]
        eps = group_episodes(recs, now=T0 + 5400)
        self.assertEqual(len(eps), 1)
        self.assertIsNone(eps[0]["end"])
        self.assertEqual(eps[0]["title"], "AQ signal down 10 dB for 2h00m (still down)")

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


def start(ts, last=None, stopped=None, cause="stalled", **f):
    gap = None if last is None else round(ts - last)
    return rec("recorder_started", "notice", ts, cause=cause, gap_s=gap, last_frame_ts=last, stopped_ts=stopped,
               exit_code=2, note=f"note at {ts}", **f)


class RecorderEpisodeTest(unittest.TestCase):
    def test_first_start_restart_and_the_restart_loop(self):
        eps = group_episodes([start(T0, cause="first_start"), start(T0 + 7200, last=T0 + 4800, stopped=T0 + 5000)])
        self.assertEqual([(e["kind"], e["title"], e["count"]) for e in eps],
                         [("recorder", "recorder started (first run)", 1),
                          ("recorder", "recorder restarted (40m without frames)", 1)])
        loop = [start(T0 + i * 210, last=T0 - 100, stopped=T0 + i * 210 - 10) for i in range(4)]
        eps = group_episodes(loop + [start(T0 + 4 * 210 + 1801, last=T0 - 100)])
        self.assertEqual([(e["title"], e["count"], e["detail"], e["start"], e["end"]) for e in eps],
                         [("recorder restarted 4 times", 4, loop[-1]["note"], T0, T0 + 630),
                          ("recorder restarted (45m without frames)", 1, f"note at {T0 + 2641}", T0 + 2641, T0 + 2641)])

    def test_a_clock_step_is_a_row_either_way(self):
        eps = group_episodes([rec("clock_step", "info", T0, step_s=7200, note="fwd"),
                              rec("clock_step", "info", T0 + 60, step_s=-300, note="back")])
        self.assertEqual([(e["kind"], e["title"], e["detail"]) for e in eps],
                         [("clock", "host clock jumped forward 2h00m", "fwd"),
                          ("clock", "host clock jumped back 5m", "back")])


class CoverageTest(unittest.TestCase):
    """Was the recorder there to hear the day? Built from the log."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = EventLog(Path(self.tmp.name) / "events")
        self.day = day_of(T0)
        self.start, self.end = day_bounds(self.day)

    def tearDown(self):
        self.tmp.cleanup()

    def _put(self, *records):
        for r in records:
            self.log.emit(r["event"], r["severity"], r["ts"], **{k: v for k, v in r.items()
                                                                  if k not in ("event", "severity", "ts")})

    def _cov(self, now=None, status=None):
        return [(s["state"], s["start"], s["end"], s["cause"], s["count"])
                for s in coverage(self.log.dir, self.day, now or self.end + 86400, status)]

    def test_a_stall_restart_is_hearing_nothing_then_not_running(self):
        self._put(start(T0 + 2400, last=T0, stopped=T0 + 190))
        self.assertEqual(self._cov(), [("uncertain", T0, T0 + 190, "no_frames", 1),
                                       ("blind", T0 + 190, T0 + 2400, "stalled", 1)])
        # A stop seconds after the last frame: only the outage.
        self._put(start(T0 + 9000, last=T0 + 7200, stopped=T0 + 7210, cause="stopped"))
        self.assertEqual(self._cov()[2:], [("blind", T0 + 7210, T0 + 9000, "stopped", 1)])

    def test_a_start_without_a_note_is_blind_from_the_last_frame(self):
        self._put(start(T0 + 600, last=T0, cause="unknown"), start(T0 + 5000, last=T0 + 4000, cause="nonsense"))
        self.assertEqual(self._cov(),
                         [("blind", T0, T0 + 600, "unknown", 1), ("blind", T0 + 4000, T0 + 5000, "unknown", 1)])
        self.assertIn("power cut", coverage(self.log.dir, self.day, self.end)[0]["note"])

    def test_the_first_start_ever_covers_nothing_before_it(self):
        self._put(start(T0, cause="first_start"))
        self.assertEqual(self._cov(), [])
        self.assertEqual(coverage_since(self.log.dir), T0)
        self.assertIsNone(coverage_since(Path(self.tmp.name) / "none"))

    def test_the_restart_loop_alternates_and_touching_pieces_merge(self):
        # Three starts from the same last frame: each run heard nothing.
        self._put(start(T0 + 200, last=T0, stopped=T0 + 190), start(T0 + 410, last=T0, stopped=T0 + 400),
                  start(T0 + 620, last=T0, stopped=T0 + 610))
        self.assertEqual(self._cov(), [("uncertain", T0, T0 + 190, "no_frames", 3),
                                       ("blind", T0 + 190, T0 + 200, "stalled", 1),
                                       ("uncertain", T0 + 200, T0 + 400, "no_frames", 3),
                                       ("blind", T0 + 400, T0 + 410, "stalled", 1),
                                       ("uncertain", T0 + 410, T0 + 610, "no_frames", 3),
                                       ("blind", T0 + 610, T0 + 620, "stalled", 1)])
        self._put(start(T0 + 700, last=T0, stopped=T0 + 620, cause="crashed"))   # touching the last: one segment
        self.assertEqual(self._cov()[-1], ("blind", T0 + 610, T0 + 700, "crashed", 2))

    def test_a_forward_clock_step_is_blind_and_a_backward_one_is_not(self):
        self._put(rec("clock_step", "info", T0 + 7200, step_s=3600, note="fwd"),
                  rec("clock_step", "info", T0 + 9000, step_s=-600, note="back"))
        self.assertEqual(self._cov(), [("blind", T0 + 3600, T0 + 7200, "clock_step", 1)])

    def test_a_silent_pan_window_is_uncertain_and_an_outage_inside_it_wins(self):
        self._put(rec("configured_pan_silent", "warning", T0 + 1800, pan="0x4e21", window_s=1800, note="n"),
                  start(T0 + 1000, last=T0 + 500, cause="unknown"))
        self.assertEqual(self._cov(), [("uncertain", T0, T0 + 500, "pan_silent", 1),
                                       ("blind", T0 + 500, T0 + 1000, "unknown", 1),
                                       ("uncertain", T0 + 1000, T0 + 1800, "pan_silent", 1)])

    def test_segments_are_clipped_to_the_day_and_to_now(self):
        # An outage that began this day and ended the next: the next day's
        # start is what records it, and the day before contributes its
        # clock step that ends in this day.
        self._put(start(T0 + 86400, last=T0 + 3600, cause="unknown"),
                  rec("clock_step", "info", self.start + 300, step_s=1200, note="fwd"))
        self.assertEqual(self._cov(), [("blind", self.start, self.start + 300, "clock_step", 1),
                                       ("blind", T0 + 3600, self.end, "unknown", 1)])
        self.assertEqual(self._cov(now=T0 + 7200)[-1], ("blind", T0 + 3600, T0 + 7200, "unknown", 1))
        self.assertEqual(coverage(self.log.dir, day_of(T0 - 86400), self.end),
                         [{"start": self.start - 900, "end": self.start, "state": "blind", "cause": "clock_step",
                           "note": coverage(self.log.dir, self.day, self.end)[0]["note"], "count": 1,
                           "credited": True}])

    def test_a_gap_that_ends_exactly_at_the_days_start_is_no_segment_at_all(self):
        # Each segment is clipped to the day and dropped `if b > a`. With
        # >= instead, a gap that ends exactly where the day begins - or
        # begins exactly where `now` is - is emitted as a zero-width band
        # on the bar and a "recorder not listening: 0s" line under it.
        # The suite did not say which, so the mutation survived.
        self._put(start(self.start, last=self.start - 3600, cause="stopped"))
        self.assertEqual(coverage(self.log.dir, self.day, self.end), [])
        # The day before owns it whole, and there it is a real segment.
        self.assertEqual([(s["start"], s["end"]) for s in
                          coverage(self.log.dir, day_of(T0 - 86400), self.end)],
                         [(self.start - 3600, self.start)])

    def test_the_scan_forward_stops_at_a_start_whose_last_frame_is_after_the_day(self):
        self._put(start(T0 + 86400, last=self.end + 60, cause="unknown"),       # heard after this day: stop here
                  start(T0 + 2 * 86400, last=T0, cause="unknown"))              # never read (would cover the day)
        self.assertEqual(self._cov(), [])
        self._put(start(T0 + 40 * 86400, last=T0 + 3600, cause="unknown"))      # past the look-ahead
        self.assertEqual(self._cov(), [])

    def test_the_status_file_adds_the_live_tail_on_today_only(self):
        now = time.time()
        today = day_of(now)
        down = {"updated": now - 400, "last_frame_age_s": 5}
        segs = coverage(self.log.dir, today, now, down)
        self.assertEqual([(s["state"], round(s["start"]), round(s["end"]), s["cause"]) for s in segs],
                         [("blind", round(max(now - 400, day_bounds(today)[0])), round(now), "down")])
        deaf = {"updated": now - 10, "last_frame_age_s": 300}
        segs = coverage(self.log.dir, today, now, deaf)
        self.assertEqual([(s["state"], round(s["start"]), round(s["end"]), s["cause"]) for s in segs],
                         [("uncertain", round(max(now - 300, day_bounds(today)[0])), round(now), "no_frames")])
        self.assertEqual(coverage(self.log.dir, day_of(now - 86400), now, down), [])
        self.assertEqual(coverage(self.log.dir, today, now, {"updated": now - 10, "last_frame_age_s": 5}), [])

    def test_how_much_of_an_episode_nobody_was_listening_for(self):
        segs = [{"start": T0 + 600, "end": T0 + 1200, "state": "blind", "credited": True},
                {"start": T0 + 1200, "end": T0 + 1500, "state": "uncertain", "credited": False},
                {"start": T0 + 3000, "end": T0 + 4000, "state": "blind", "credited": True}]
        quiet = {"start": T0 + 1800, "end": None, "silent_since": T0}          # from the device's last frame
        self.assertEqual(episode_blind_s(quiet, segs, now=T0 + 3500), 600 + 500)
        self.assertEqual(episode_blind_s({"start": T0 + 1300, "end": T0 + 2000}, segs), 0)

    def test_the_uncertain_tail_of_a_restart_counts_as_the_pipeline_counted_it(self):
        # The pipeline credits the whole span from the last frame any run
        # heard; coverage splits it, calling last_frame..stopped
        # "uncertain" (running, hearing nothing) and stopped..start
        # "blind". Counting only the blind half made the event and the day
        # page disagree about the same outage by exactly that tail.
        self._put(start(T0 + 7200, last=T0 + 1800, stopped=T0 + 3600, cause="stopped"))
        segs = coverage(self.log.dir, self.day, T0 + 7200)
        self.assertEqual([(s["state"], s["start"], s["end"], s["credited"]) for s in segs],
                         [("uncertain", T0 + 1800, T0 + 3600, True),
                          ("blind", T0 + 3600, T0 + 7200, True)])
        quiet = {"start": T0 + 1800, "end": None, "silent_since": T0 + 1800}
        self.assertEqual(episode_blind_s(quiet, segs, now=T0 + 7200), 5400)


class EveryEventKindTest(unittest.TestCase):
    """The day page is group_episodes over everything the pipeline emits.
    Five of its event kinds had never been through the grouping, so a
    broken title, a detail read off a missing field, or a grouping rule
    that swallowed a row would have shown up on the page and nowhere
    else."""

    def test_foreign_pan_sightings_group_per_pan_and_source_within_a_day(self):
        recs = [rec("possible_foreign_pan", "notice", T0, pan="0x58bc", src="3c1a", dominant_pan="0x4e21"),
                rec("possible_foreign_pan", "notice", T0 + 3600, pan="0x58bc", src="3c1a", dominant_pan="0x4e21"),
                rec("possible_foreign_pan", "notice", T0 + 7200, pan="0x1234", src="0a0b", dominant_pan="0x4e21"),
                rec("possible_foreign_pan", "notice", T0 + 2 * 86400, pan="0x58bc", src="3c1a", dominant_pan="0x4e21")]
        eps = group_episodes(recs)
        self.assertEqual([(e["kind"], e["title"], e["detail"], e["count"], e["start"], e["end"]) for e in eps],
                         [("foreign_pan", "foreign PAN 0x58bc from 3c1a", "ours is 0x4e21", 2, T0, T0 + 3600),
                          ("foreign_pan", "foreign PAN 0x1234 from 0a0b", "ours is 0x4e21", 1, T0 + 7200, T0 + 7200),
                          ("foreign_pan", "foreign PAN 0x58bc from 3c1a", "ours is 0x4e21", 1,
                           T0 + 2 * 86400, T0 + 2 * 86400)])           # a day later: a new sighting
        self.assertEqual(eps[0]["addr"], "3c1a")                       # the source stands in for an address
        self.assertEqual(eps[0]["events"], recs[:2])

    def test_join_scan_bursts_within_half_an_hour_are_one_row(self):
        recs = [rec("join_scan_activity", "notice", T0, count_60s=5, src="1234"),
                rec("join_scan_activity", "notice", T0 + 600, count_60s=7, src="1234"),
                rec("join_scan_activity", "notice", T0 + 600 + 1801, count_60s=6, src="5678")]
        eps = group_episodes(recs)
        self.assertEqual([(e["kind"], e["title"], e["detail"], e["count"], e["end"]) for e in eps],
                         [("join_scan", "join-scan beacons", "2 bursts", 2, T0 + 600),
                          ("join_scan", "join-scan beacons", "6 in 60 s", 1, T0 + 2401)])

    def test_each_partition_or_leader_change_is_its_own_row(self):
        recs = [rec("partition_or_leader_change", "warning", T0 + i * 60,
                    previous={"partition": 12345, "leader_router": 3, "leader": "Hall TV"},
                    current={"partition": 67890, "leader_router": 5, "leader": "Study Hub"},
                    note="the mesh split, merged or elected a new leader") for i in range(2)]
        eps = group_episodes(recs)
        self.assertEqual([(e["kind"], e["severity"], e["title"], e["detail"], e["count"]) for e in eps],
                         [("partition", "warning", "partition or leader change",
                           "partition 12345 leader r3 -> partition 67890 leader r5", 1)] * 2)
        self.assertEqual([e["start"] for e in eps], [T0, T0 + 60])

    def test_storm_freeze_and_alert_test_rows(self):
        eps = group_episodes([
            rec("phase_locked_storm", "critical", T0, period_s=80.5, onsets=3, baseline_frames_per_window=250.0,
                note="traffic floods recurring every 80 s"),
            rec("incident_frozen", "info", T0 + 5, label="auto-storm",
                note="6 ring files kept as 20260902T120005_auto-storm"),
            rec("incident_freeze_failed", "warning", T0 + 10, label="auto-storm", note="could not freeze the ring"),
            rec("alert_test", "warning", T0 + 20, name="Test device", note="threadwatch alert-test from pi"),
        ])
        self.assertEqual([(e["kind"], e["severity"], e["title"], e["detail"]) for e in eps],
                         [("storm", "critical", "phase-locked storm",
                           "period 80.5s, onsets 3, baseline 250.0 frames/window"),
                          ("frozen", "info", "incident frozen", "6 ring files kept as 20260902T120005_auto-storm"),
                          ("frozen", "warning", "incident freeze failed", "could not freeze the ring"),
                          ("test", "warning", "alert test", "threadwatch alert-test from pi")])

    def test_an_event_without_a_grouping_rule_is_a_row_named_after_it(self):
        recs = [rec("configured_pan_silent", "warning", T0 + 1, pan="0x4e21", note="no frame on PAN 0x4e21"),
                rec("dominant_pan_changed", "notice", T0 + 2, pan="0x4e21", note="PAN 0x4e21 adopted"),
                rec("credentials_stale", "warning", T0 + 3, failed=40, note="nothing decrypts"),
                rec("border_router_address_changed", "notice", T0 + 4, addr=TV2, name="Hall TV", note="rotated"),
                rec("border_router_unlisted", "notice", T0 + 5, addr=TV1, hostname="hub.local",
                    note="not in devices.json")]
        eps = group_episodes(recs)
        self.assertEqual([(e["kind"], e["title"], e["severity"], e["detail"], e["count"]) for e in eps],
                         [(r["event"], r["event"], r["severity"], r["note"], 1) for r in recs])
        self.assertEqual([e["addr"] for e in eps[-2:]], [TV2, TV1])

    def test_everything_the_pipeline_emits_has_a_row(self):
        import re
        source = (Path(__file__).resolve().parent.parent / "threadwatch" / "pipeline.py").read_text()
        # Both spellings: the pipeline raises its events through _emit (which
        # freezes the ring on a critical one) and the freeze path itself, and
        # the daily summary, straight through events.emit.
        emitted = sorted(set(re.findall(r'(?:events\.emit|self\._emit)\(\s*"([a-z_]+)"', source)))
        self.assertGreaterEqual(len(emitted), 20, emitted)
        for ev in emitted:
            # The fields every record carries, plus the one number a title
            # formats (rssi_degradation's drop_db, which the pipeline always sends).
            r = rec(ev, "notice", T0, addr=AQ, name="Basement AQ", note="n", drop_db=6.0)
            eps = group_episodes([r], now=T0 + 60)
            self.assertEqual(len(eps), 1, ev)
            self.assertTrue(eps[0]["title"], ev)
            self.assertEqual(eps[0]["events"], [r], ev)


if __name__ == "__main__":
    unittest.main()
