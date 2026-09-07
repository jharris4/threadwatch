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
        self.assertIn('<span class="warn">foreign 0x1234</span>', body)
        self.assertIn('<span class="muted">ours</span>', body)
        self.assertIn('<span class="muted">?</span>', body)        # a device with no PAN yet
        self.assertIn('<span class="warn">unknown</span>', body)   # not in devices.json
        _st, down = self.get("/devices?only=down")
        self.assertIn("Office AQ", down)
        self.assertNotIn("Living Room Apple TV", down)
        # The device page carries the same verdict on the address itself.
        _st, page = self.get(f"/device/{AQ}")
        self.assertIn('<span class="warn">signal down</span>', page)

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
