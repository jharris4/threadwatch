"""web.py: the HTTP server itself, and the page branches nobody else
drives.

test_review reaches the pages while testing review.py, which leaves
web.py at 93% with the uncovered remainder being exactly what a page
renders when something is wrong: capture stale, signal down, a retired
address, an unmatched partition leader, and the alert badges - which are
how an operator learns from a browser that alerts are retrying or have
been given up, the failure the whole spool machinery exists to survive.
"""

import json
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.config import Config
from threadwatch.events import EventLog, day_of
from threadwatch.web import make_server


class BindDefaultTest(unittest.TestCase):
    """The pages have no authentication and publish the household's device
    inventory and a per-room, per-hour occupancy trace, so reaching them
    from another machine is a deliberate act, not the default."""

    def test_nothing_serves_the_lan_until_the_operator_says_so(self):
        import inspect
        import tomllib

        from threadwatch import web
        from threadwatch.config import REPO_ROOT, Config
        self.assertEqual(Config().web_bind, "127.0.0.1")
        self.assertEqual(inspect.signature(web.serve).parameters["bind"].default, "127.0.0.1")
        example = tomllib.loads((REPO_ROOT / "config" / "config.example.toml").read_text())
        self.assertEqual(example["web"]["bind"], "127.0.0.1")
        compose = (REPO_ROOT / "compose.yaml").read_text()
        published = [line.strip().lstrip("- ").strip('"')
                     for line in compose.splitlines()
                     if line.strip().startswith("- ") and ":8080" in line and not line.strip().startswith("#")]
        self.assertEqual(published, ["127.0.0.1:8080:8080"])
        # ...and that publish is the whole restriction under Docker, so the
        # container has to bind its own 0.0.0.0: the port forwards to the
        # container's bridge address, and a server on the container's
        # loopback refuses every connection that arrives there.
        # The port is pinned on the same line, so a [web] port the server
        # would honour cannot move it off the one ports: forwards to.
        self.assertIn('command: ["serve", "--bind", "0.0.0.0", "--port", "8080"]', compose)


class RequestTimeoutTest(unittest.TestCase):
    """A thread and an fd per connection, and daemon_threads means nothing
    reaps them. Without a timeout a peer that vanishes without FIN/RST is
    held for the life of the process; at the Pi's 1024-fd limit the accept
    loop fails with EMFILE, socketserver swallows it, and the pages go dead
    while systemd still sees a healthy process."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config(data_dir=Path(self.tmp.name) / "data")
        self.httpd = make_server(self.cfg, "127.0.0.1", 0)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()

    def test_the_shipped_handler_bounds_how_long_a_request_may_take(self):
        self.assertIsNotNone(self.httpd.RequestHandlerClass.timeout)

    def test_a_connection_that_never_sends_a_request_is_dropped_not_parked(self):
        self.httpd.RequestHandlerClass.timeout = 0.5      # the shipped 30 s, sped up
        # Threads that were here already, by identity rather than by count:
        # an unrelated daemon finishing elsewhere must not read as a pass
        # or a fail. What is leaking is a thread that was not here before.
        before = {t.ident for t in threading.enumerate()}

        def leftover():
            return [t.name for t in threading.enumerate() if t.ident not in before and t.is_alive()]

        socks = []
        try:
            for _ in range(5):
                s = socket.create_connection(("127.0.0.1", self.httpd.server_port), timeout=5)
                socks.append(s)
            # connect() returns once the kernel has completed the handshake
            # into the listen backlog, which is before the server thread has
            # accepted anything: wait for the handler threads instead of
            # reading "not spawned yet" as "never spawned".
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not leftover():
                time.sleep(0.01)
            self.assertTrue(leftover())                   # a thread per connection, as designed
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and leftover():
                time.sleep(0.05)
            self.assertEqual(leftover(), [])              # ...and none of them outlives its timeout
            for s in socks:
                self.assertEqual(s.recv(1), b"")          # the server closed its end
        finally:
            for s in socks:
                s.close()


AQ = "26976e7f7d20964a"
TV1, TV2 = "b62c32bf669272db", "e6c279e8f0c70298"


class PageBranchTest(unittest.TestCase):
    """The pages an operator reads when the news is bad."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        (self.d / "devices.json").write_text(json.dumps([
            {"name": "Office AQ", "extendedAddress": AQ},
            {"name": "Living Room Apple TV", "extendedAddresses": [TV1, TV2]},
        ]))
        self.cfg = Config(data_dir=self.d / "data", devices_path=self.d / "devices.json", pan_id=0x4e21)
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
        self.now = time.time()
        self.httpd = make_server(self.cfg, "127.0.0.1", 0)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.httpd.server_port}"

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.tmp.cleanup()

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=5) as r:
            return r.status, r.read().decode()

    def status(self, **fields):
        (self.cfg.state_dir / "status.json").write_text(json.dumps(fields))

    def seen(self, table):
        (self.cfg.state_dir / "last-seen.json").write_text(json.dumps(table))

    def test_the_status_page_says_what_the_alert_dispatcher_is_holding(self):
        # The badges are the only place a browser says alerts are not
        # getting through: a sink down for hours is retrying, then given up.
        self.status(updated=self.now, last_frame_age_s=3, channel=25, port="/dev/ttyACM0",
                    frames_total=12345, uptime_s=3600, devices_tracked=7,
                    current_file="/data/ring/threadwatch-20260905-12.pcap",
                    alerts={"delivered": 4, "queued": 3, "retrying": 3, "given_up": 2, "resumed": 1})
        _st, body = self.get("/status")
        self.assertIn("4 delivered this run", body)
        self.assertIn('<span class="warn">3 retrying</span>', body)
        self.assertIn('<span class="bad">2 given up</span>', body)
        self.assertIn("1 resumed from the last run", body)
        # Nothing pending is one plain figure, no badges.
        self.status(updated=self.now, last_frame_age_s=3, alerts={"delivered": 4})
        _st, body = self.get("/status")
        self.assertIn("4 delivered this run", body)
        self.assertNotIn("retrying", body)
        self.assertNotIn("given up", body)

    def test_the_status_page_has_a_row_per_radio_and_the_devices_page_says_who_hears_whom(self):
        radios = {"hub": {"label": "hub", "port": "/dev/ttyACM0", "serial": "AA", "placement": "by the router",
                          "state": "up", "frames_total": 1200, "last_frame_age_s": 2.0, "dropped_lines": 0,
                          "lock": None},
                  "annex": {"label": "annex", "port": "/dev/ttyACM1", "serial": "BB", "placement": "",
                            "state": "up", "frames_total": 900, "last_frame_age_s": 3.0, "dropped_lines": 4,
                            "lock": {"locked": True, "offset_ms": 58.3, "ppm": 79.1, "sigma_us": 13.0,
                                     "pairs": 800, "locks": 1}},
                  "attic": {"label": "attic", "port": None, "serial": "CC", "placement": "attic",
                            "state": "missing", "frames_total": 0, "last_frame_age_s": None, "dropped_lines": 0,
                            "lock": {"locked": False, "offset_ms": None, "ppm": None, "sigma_us": None,
                                     "pairs": 0, "locks": 0}}}
        self.status(updated=self.now, last_frame_age_s=2, channel=25, port="/dev/ttyACM0", radios=radios)
        _st, body = self.get("/status")
        self.assertIn("<th>radio hub</th>", body)
        self.assertIn('<span class="ok">up</span> &middot; <code>/dev/ttyACM0</code> &middot; by the router', body)
        self.assertIn("1,200 frames", body)
        self.assertIn("clock locked: offset +58.3 ms, drift +79.1 ppm, jitter 13.0 &micro;s", body)
        self.assertIn('<span class="warn">4 serial lines dropped</span>', body)
        self.assertIn('<th>radio attic</th><td><span class="warn">not plugged in</span> &middot; attic', body)
        # A single unnamed dongle: no radio rows at all.
        self.status(updated=self.now, last_frame_age_s=2, port="/dev/ttyACM0",
                    radios={"radio": {"label": None, "port": "/dev/ttyACM0", "state": "up", "frames_total": 5}})
        _st, body = self.get("/status")
        self.assertNotIn("<th>radio", body)
        # The devices page: a heard-by column only when rows carry it.
        self.seen({AQ: {"first_seen": self.now - 3600, "last_seen": self.now - 10, "frames": 100, "types": {},
                        "pan": 0x4e21, "rssi": -60.0, "heard_by": {"hub": 100, "annex": 40},
                        "rssi_by_radio": {"hub": -60.0, "annex": -75.0}},
                   TV1: {"first_seen": self.now - 3600, "last_seen": self.now - 5, "frames": 50, "types": {},
                         "pan": 0x4e21, "rssi": -70.0, "heard_by": {"annex": 50}, "rssi_by_radio": {"annex": -70.0}}})
        _st, body = self.get("/devices")
        self.assertIn("<th>heard by</th>", body)
        self.assertIn("<td>hub 100% -60.0, annex 40% -75.0</td>", body)
        self.assertIn('<td>annex 100% -70.0, <span class="muted">hub never</span></td>', body)
        _st, body = self.get(f"/device/{AQ}")
        self.assertIn("heard by hub 100% -60.0, annex 40% -75.0", body)
        self.seen({AQ: {"first_seen": self.now - 3600, "last_seen": self.now - 10, "frames": 100, "types": {},
                        "pan": 0x4e21, "rssi": -60.0}})
        _st, body = self.get("/devices")
        self.assertNotIn("heard by", body)

    def test_the_status_page_says_which_code_is_recording(self):
        self.status(updated=self.now, last_frame_age_s=3, version="0.9.9", commit="abc1234")
        _st, body = self.get("/status")
        self.assertIn("threadwatch 0.9.9", body)
        self.assertIn("(abc1234)", body)
        # A deployed copy has no .git, so there is a version and no commit.
        self.status(updated=self.now, last_frame_age_s=3, version="0.9.9", commit=None)
        _st, body = self.get("/status")
        self.assertIn("threadwatch 0.9.9", body)
        self.assertNotIn("abc1234", body)

    def test_the_status_page_names_the_partition_leader_or_says_it_cannot(self):
        self.status(updated=self.now, last_frame_age_s=3,
                    partition={"id": 12345, "leader_router": 60, "leader_rloc16": "f000"})
        _st, body = self.get("/status")
        self.assertIn("router id 60", body)
        self.assertIn("not matched to a device yet", body)
        self.status(updated=self.now, last_frame_age_s=3,
                    partition={"id": 12345, "leader_router": 60, "leader_rloc16": "f000",
                               "leader_addr": TV1, "leader_name": "Living Room Apple TV"})
        _st, body = self.get("/status")
        self.assertIn(f'<a href="/device/{TV1}">Living Room Apple TV</a>', body)
        self.assertNotIn("not matched to a device yet", body)

    def test_the_status_page_and_the_header_say_when_recording_has_gone_stale(self):
        _st, body = self.get("/status")
        self.assertIn("no status file: the recorder has not run here", body)
        self.assertIn("no status yet", body)                       # the header too
        self.status(updated=self.now - 600, last_frame_age_s=30)
        _st, body = self.get("/status")
        self.assertIn('<span class="bad">capture stale</span>', body)
        self.assertIn('<span class="bad">not running</span>', body)
        self.status(updated=self.now, last_frame_age_s=600)
        _st, body = self.get("/status")
        self.assertIn("no frames for", body)
        self.status(updated=self.now, last_frame_age_s=3)
        _st, body = self.get("/status")
        self.assertIn('<span class="ok">capturing</span>', body)
        self.assertIn('<span class="ok">running</span>', body)
        # The header read the age at 180 s and the capture row at 90, so
        # one status file between the two made a single page say both, in
        # the middle of the outage it exists to report.
        self.status(updated=self.now - 120, last_frame_age_s=0)
        _st, body = self.get("/status")
        self.assertIn('<span class="bad">capture stale</span>', body)
        self.assertIn('<span class="bad">not running</span>', body)
        self.assertNotIn('<span class="ok">capturing</span>', body)
        self.assertNotIn('<span class="ok">running</span>', body)

    def test_the_snapshots_page_says_what_retention_actually_keeps(self):
        # It said snapshots are "kept forever", and help said packets last
        # forever in one: an operator who reads that leaves the evidence
        # here instead of exporting it, while the automatic ones are
        # capped at four by default and pruned at the next critical event.
        _st, body = self.get("/snapshots")
        self.assertNotIn("kept forever", body)
        self.assertIn("kept until you delete them", body)
        self.assertIn("capped at the newest 4", body)
        _st, body = self.get("/help")
        self.assertNotIn("forever in snapshots", body)
        self.cfg.keep_snapshots = -1
        _st, body = self.get("/snapshots")
        self.assertIn("kept for ever too", body)
        self.cfg.keep_snapshots = 0
        _st, body = self.get("/snapshots")
        self.assertIn("not kept at all", body)

    def test_the_snapshots_page_lists_the_ha_logs_a_snapshot_carries(self):
        inc = self.cfg.snapshots_dir / "20260902T141500_storm"
        inc.mkdir(parents=True)
        (inc / "threadwatch-20260902-12.pcap").write_bytes(b"x")
        (inc / "ha-logs.json").write_text(json.dumps({
            "status": "partial", "addons": {
                "core_openthread_border_router": {"file": "ha-logs/core_openthread_border_router.log.gz",
                                                  "lines": 4100, "complete": True},
                "core_matter_server": {"file": "ha-logs/core_matter_server.log.gz", "lines": 12, "complete": False}}}))
        failed = self.cfg.snapshots_dir / "20260901T080000_older"
        failed.mkdir()
        (failed / "ha-logs.json").write_text(json.dumps({"status": "failed", "addons": {}}))
        _st, body = self.get("/snapshots")
        self.assertIn("<code>ha-logs/core_openthread_border_router.log.gz</code> 4,100 lines", body)
        self.assertIn('<code>ha-logs/core_matter_server.log.gz</code> 12 lines <span class="warn">partial</span>', body)
        self.assertIn('<span class="warn">HA logs failed</span>', body)

    def test_the_devices_page_marks_a_retired_address_a_foreign_pan_and_a_fading_link(self):
        self.status(updated=self.now, last_frame_age_s=3)
        self.seen({
            AQ: {"first_seen": self.now - 7200, "last_seen": self.now - 60, "frames": 900,
                 "rssi": -78.0, "rssi_ref": -60.0, "rssi_degraded": True, "pan": 0x4e21, "types": {}},
            TV1: {"first_seen": self.now - 9000, "last_seen": self.now - 8000, "frames": 400,
                  "rssi": -55.0, "pan": 0x4e21, "rotated_to": TV2, "types": {}},
            TV2: {"first_seen": self.now - 8000, "last_seen": self.now - 30, "frames": 500,
                  "rssi": -55.0, "pan": 0x4e21, "types": {}},
            "1afe3b8423f332de": {"first_seen": self.now - 600, "last_seen": self.now - 30, "frames": 30,
                                 "rssi": -90.0, "pan": 0x1234, "types": {}},
            "72d035122fdf06f6": {"first_seen": self.now - 600, "last_seen": self.now - 30, "frames": 30,
                                 "rssi": None, "types": {}},
        })
        _st, body = self.get("/devices")
        self.assertIn(f'retired: now <a href="/device/{TV2}">{TV2}</a>', body)
        self.assertNotIn("by model", body)                          # no entry carries a model
        self.assertIn('<span class="warn">foreign 0x1234</span>', body)
        self.assertIn('<span class="muted">ours</span>', body)
        self.assertIn('<span class="muted">?</span>', body)        # a device with no PAN yet
        self.assertIn('<span class="warn">unknown</span>', body)   # not in devices.json
        self.assertIn("2 not in devices.json", body)
        phone = "72d035122fdf06f6"
        (self.d / "visitors.json").write_text(json.dumps([{"name": "Sam's iPhone", "extendedAddress": phone}]))
        self.cfg.visitors_path = self.d / "visitors.json"
        _st, body = self.get("/devices")
        self.assertIn("Sam&#x27;s iPhone <span class=\"muted\">visitor</span>", body)
        self.assertIn("1 not in devices.json", body)                # the labelled phone is not unknown
        _st, body = self.get(f"/device/{phone}")
        self.assertIn("Sam&#x27;s iPhone", body)
        self.assertIn("named in visitors.json", body)
        _st, down = self.get("/devices?only=down")
        self.assertIn("Office AQ", down)
        self.assertNotIn("Living Room Apple TV", down)
        # The device page carries the same verdict on the address itself.
        _st, page = self.get(f"/device/{AQ}")
        self.assertIn('<span class="warn">signal down</span>', page)

    def test_the_pages_show_each_devices_key_generation_and_how_far_behind_it_is(self):
        self.status(updated=self.now, last_frame_age_s=3, crypto={"key_sequence": 86},
                    keys={"highest": 86, "previous": 85, "first_sender": TV2, "highest_first_ts": self.now - 7200,
                          "suspects": [{"addr": TV2, "evidence": "first on air"},
                                       {"addr": AQ, "evidence": "ahead of its parent"}]})
        self.seen({
            TV2: {"first_seen": self.now - 8000, "last_seen": self.now - 30, "frames": 500, "rssi": -55.0,
                  "pan": 0x4e21, "types": {}, "rloc16": "0400", "rloc16_ts": self.now - 30,
                  "counter_seq": 86, "counter_ts": self.now - 30},
            AQ: {"first_seen": self.now - 7200, "last_seen": self.now - 60, "frames": 900, "rssi": -60.0,
                 "pan": 0x4e21, "types": {}, "rloc16": "0401", "rloc16_ts": self.now - 60,
                 "counter_seq": 84, "counter_ts": self.now - 60, "keylag_since": self.now - 900,
                 "key_facts": {"version": 1, "mac": {
                     "latest": {"sequence": 84, "ts": self.now - 60},
                     "accepted": [{"sequence": 84, "first_ts": self.now - 7200, "last_ts": self.now - 60,
                                   "count": 900, "retries": 0}],
                     "rejected": [{"sequence": 84, "first_ts": self.now - 700, "last_ts": self.now - 100,
                                   "count": 3, "reason": "counter_not_advancing"}]}}},
        })
        _st, body = self.get("/devices")
        self.assertIn("<th>key gen</th>", body)
        # The list page marks only what is unusual; the breakdown is on the device page.
        self.assertIn('84 <span class="warn">2 behind 86</span> <span class="bad">cut off</span> '
                      '<span class="muted">3 rejected MIC-valid</span>', body)
        self.assertNotIn("sequence observations", body)
        _st, page = self.get(f"/device/{AQ}")
        self.assertIn('key generation 84 <span class="warn">2 behind 86</span>', page)
        self.assertIn("sequence observations: <span class=\"muted\">MAC 84 at ", page)
        self.assertIn("MAC 84 rejected 3 (counter_not_advancing), ", page)
        _st, raw = self.get(f"/api/device/{AQ}")
        live = json.loads(raw)["live"]
        self.assertEqual((live["generation"], live["parent_generation"], live["mesh_generation"], live["lag"],
                          live["key_lagging"]), (84, 86, 86, 2, True))
        _st, status = self.get("/status")
        self.assertIn("<th>key generation</th>", status)
        self.assertIn(f'86 <span class="muted">first heard from <a href="/device/{TV2}">Living Room Apple TV</a>',
                      status)
        self.assertIn(f'; origin candidates: <a href="/device/{TV2}">Living Room Apple TV</a>, '
                      f'<a href="/device/{AQ}">Office AQ</a> (ahead of last known parent sequence)</span>', status)
        self.assertIn("previously 85", status)

    def test_the_pages_show_home_assistant_availability_only_when_the_recorder_polls_it(self):
        self.status(updated=self.now, last_frame_age_s=3)
        self.seen({
            TV2: {"first_seen": self.now - 8000, "last_seen": self.now - 30, "frames": 500, "rssi": -55.0,
                  "pan": 0x4e21, "types": {}},
            AQ: {"first_seen": self.now - 7200, "last_seen": self.now - 60, "frames": 900, "rssi": -60.0,
                 "pan": 0x4e21, "types": {}},
        })
        _st, body = self.get("/devices")
        self.assertNotIn("<th>HA</th>", body)                                          # feature off: no column
        (self.cfg.state_dir / "ha-map.json").write_text(json.dumps({
            "id-aq": {"addr": AQ.upper(), "ha_name": "AQ", "name": "Office AQ", "matched": True, "entities": ["s.aq"]},
            "id-tv": {"addr": TV2.upper(), "ha_name": "TV", "name": "Living Room Apple TV", "matched": True,
                      "entities": ["s.tv"]}}))
        (self.cfg.state_dir / "ha-availability.json").write_text(json.dumps({
            "episodes": {"id-aq": {"since": self.now - 900, "opened_ts": self.now - 840, "paged": True,
                                   "severity": "warning", "burst_id": None, "episode": 1}}}))
        _st, body = self.get("/devices")
        self.assertIn("<th>HA</th>", body)
        self.assertIn('<span class="bad">unavailable</span>', body)
        self.assertIn('<span class="ok">available</span>', body)
        _st, page = self.get(f"/device/{AQ}")
        self.assertIn('HA: <span class="bad">unavailable</span>', page)
        live = json.loads(self.get(f"/api/device/{AQ}")[1])["live"]
        self.assertEqual((live["ha_state"], live["ha_since"]), ("unavailable", self.now - 900))
        self.assertEqual(json.loads(self.get(f"/api/device/{TV2}")[1])["live"]["ha_state"], "available")

    def test_todays_card_names_what_is_quiet_and_what_is_fading_or_says_all_is_well(self):
        self.status(updated=self.now, last_frame_age_s=3)
        _st, body = self.get("/")
        self.assertIn("nothing quiet, nothing fading, every address named", body)
        self.seen({
            AQ: {"first_seen": self.now - 7200, "last_seen": self.now - 4000, "frames": 900,
                 "rssi": -78.0, "rssi_ref": -60.0, "rssi_degraded": True, "quiet_reported": True,
                 "pan": 0x4e21, "types": {}},
            "72d035122fdf06f6": {"first_seen": self.now - 600, "last_seen": self.now - 30,
                                 "frames": 30, "rssi": -60.0, "pan": 0x4e21, "types": {}},
        })
        _st, body = self.get("/")
        self.assertIn("quiet now", body)
        self.assertIn('<span class="k">signal down</span>', body)
        self.assertIn(">1 address</a>", body)
        self.assertIn("to add to devices.json", body)

    def test_a_day_before_the_recorder_started_says_so_and_the_day_strip_is_json_too(self):
        log = EventLog(self.cfg.events_dir)
        log.emit("device_quiet", "warning", self.now, addr=AQ, name="Office AQ", silent_for_s=1800,
                 note="no frames heard")
        today = day_of(self.now)
        _st, body = self.get(f"/day/{day_of(self.now - 40 * 86400)}")
        self.assertIn("before the recorder's first day", body)
        _st, body = self.get(f"/day/{today}?min=critical")
        self.assertIn("nothing at critical or above this day", body)
        _st, days = self.get("/api/days")
        self.assertEqual(json.loads(days)["days"],
                         [{"day": today, "total": 1, "info": 0, "notice": 0, "warning": 1, "critical": 0}])

    def test_a_path_that_is_not_a_page_is_a_404_in_the_shape_the_caller_asked_for(self):
        for path, body in (("/nope", b"not found"), ("/day/notaday", b"bad day"),
                           ("/device/%20", b"bad device"), ("/device/" + "x" * 200, b"bad device")):
            req = urllib.request.Request(self.base + path)
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(req, timeout=5)
            self.assertEqual(cm.exception.code, 404, path)
            self.assertEqual(cm.exception.read(), body, path)
        for path in ("/api/nope", "/api/device/nobody"):
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(self.base + path, timeout=5)
            self.assertEqual(cm.exception.code, 404, path)
            self.assertIn("error", json.loads(cm.exception.read()), path)


if __name__ == "__main__":
    unittest.main()


class DevicesByModelTest(unittest.TestCase):
    """The devices page tallies the inventory's models: how many of each
    are tracked and how many of them are quiet, marginal or unavailable."""

    def test_the_tally_counts_each_model_once_per_live_address(self):
        import tempfile

        from tests.test_web import AQ, TV1, TV2
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "devices.json").write_text(json.dumps([
                {"name": "Office AQ", "extendedAddress": AQ, "model": "ALPSTUGA air quality monitor"},
                {"name": "Hall AQ", "extendedAddress": "1afe3b8423f332de", "model": "ALPSTUGA air quality monitor"},
                {"name": "Living Room Apple TV", "extendedAddresses": [TV1, TV2], "model": "Apple TV 4K"},
                {"name": "Plain Outlet", "extendedAddress": "72d035122fdf06f6"},
            ]))
            cfg = Config(data_dir=d / "data", devices_path=d / "devices.json", pan_id=0x4e21)
            cfg.state_dir.mkdir(parents=True, exist_ok=True)
            now = time.time()
            (cfg.state_dir / "last-seen.json").write_text(json.dumps({
                AQ: {"first_seen": now - 7200, "last_seen": now - 60, "frames": 900, "rssi": -60.0,
                     "pan": 0x4e21, "types": {}},
                "1afe3b8423f332de": {"first_seen": now - 7200, "last_seen": now - 4000, "frames": 900,
                                     "rssi": -88.0, "pan": 0x4e21, "types": {}},
                TV1: {"first_seen": now - 9000, "last_seen": now - 8000, "frames": 400, "rssi": -55.0,
                      "pan": 0x4e21, "rotated_to": TV2, "types": {}},
                TV2: {"first_seen": now - 8000, "last_seen": now - 30, "frames": 500, "rssi": -55.0,
                      "pan": 0x4e21, "types": {}},
                "72d035122fdf06f6": {"first_seen": now - 600, "last_seen": now - 30, "frames": 30,
                                     "rssi": -60.0, "pan": 0x4e21, "types": {}},
            }))
            (cfg.state_dir / "status.json").write_text(json.dumps({"updated": now, "last_frame_age_s": 3}))
            from threadwatch.web import Site
            body = Site(cfg).devices_page()
            self.assertIn('<span class="k">by model</span> ALPSTUGA air quality monitor 2 '
                          '(<span class="bad">1 quiet</span>, 1 marginal) &middot; Apple TV 4K 1</p>', body)
