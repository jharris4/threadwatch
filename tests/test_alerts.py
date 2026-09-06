"""Unit tests for threadwatch.alerts (stdlib only: python3 -m unittest)."""

import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
from unittest import mock
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch import alerts  # noqa: E402
from threadwatch.events import EventLog, read_all  # noqa: E402
from tests.no_lan import setUpModule, tearDownModule  # noqa: E402, F401  (no mDNS from the suite)


class _Server:
    """Tiny HTTP server recording every request; status code selectable."""

    def __init__(self, status=200):
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                outer.requests.append({
                    "path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": self.rfile.read(n).decode(),
                })
                self.send_response(status)
                self.end_headers()
                self.wfile.write(b"ok")

            do_PUT = do_GET = do_POST

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"

    def wait(self, n, timeout=3.0):
        deadline = time.time() + timeout
        while len(self.requests) < n and time.time() < deadline:
            time.sleep(0.02)
        return self.requests

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()      # shutdown() stops serve_forever; the listening socket needs this


REC = {"ts": 1700000000.0, "event": "device_quiet", "severity": "warning",
       "addr": "1669674dd15cf0fa", "name": 'Living "Room" AQ', "silent_for_s": 1823,
       "note": "no frames heard"}


class RenderTests(unittest.TestCase):
    def test_missing_fields_render_empty(self):
        self.assertEqual(alerts.render("[{event}] {nope}|{name}", REC, False),
                         '[device_quiet] |Living "Room" AQ')

    def test_json_escaping_keeps_document_valid(self):
        body = alerts.render('{{"t": "{name}", "n": "{note}", "s": {silent_for_s}}}', REC, True)
        self.assertEqual(json.loads(body), {"t": 'Living "Room" AQ', "n": "no frames heard", "s": 1823})

    def test_summary_and_severity_value(self):
        f = alerts.template_fields(REC, {"warning": 4})
        self.assertEqual(f["summary"], 'device_quiet - Living "Room" AQ - no frames heard')
        self.assertEqual(f["severity_value"], 4)
        self.assertEqual(f["severity_index"], 2)

    def test_env_expansion_collects_missing(self):
        os.environ["TW_TEST_TOKEN"] = "abc"
        missing = set()
        out = alerts.expand_env({"h": {"Authorization": "Bearer ${TW_TEST_TOKEN}"},
                                 "u": "${TW_NOT_SET}/x"}, missing)
        self.assertEqual(out["h"]["Authorization"], "Bearer abc")
        self.assertEqual(missing, {"TW_NOT_SET"})


class SinkBuildTests(unittest.TestCase):
    def test_legacy_webhook_url_becomes_http_sink(self):
        sinks = alerts.build_sinks({"webhook_url": "http://x/hook", "min_severity": "critical"}, print)
        self.assertEqual(len(sinks), 1)
        self.assertIsInstance(sinks[0], alerts.HttpSink)
        self.assertEqual(sinks[0].min_severity, 3)
        self.assertIsNone(sinks[0].body)

    def test_missing_env_disables_sink_with_message(self):
        msgs = []
        sinks = alerts.build_sinks({"sinks": [{"name": "p", "type": "http", "url": "http://x",
                                               "headers": {"Authorization": "Bearer ${TW_MISSING}"}}]},
                                   msgs.append)
        self.assertEqual(sinks, [])
        self.assertIn("TW_MISSING", msgs[0])
        self.assertIn("'p'", msgs[0])

    def test_ntfy_preset_produces_valid_json_publish(self):
        sinks = alerts.build_sinks({"sinks": [{"type": "ntfy", "url": "https://n.example/",
                                               "topic": "alerts", "token": "tk_1"}]}, print)
        s = sinks[0]
        self.assertEqual(s.url, "https://n.example")
        self.assertEqual(s.headers["Authorization"], "Bearer tk_1")
        doc = json.loads(s.payload(REC))
        self.assertEqual(doc["topic"], "alerts")
        self.assertEqual(doc["title"], 'device_quiet: Living "Room" AQ')
        self.assertEqual(doc["message"], "no frames heard")
        self.assertEqual(doc["priority"], 4)
        self.assertEqual(doc["tags"], ["device_quiet"])

    def test_ntfy_title_falls_back_to_address_when_unnamed(self):
        sinks = alerts.build_sinks({"sinks": [{"type": "ntfy", "url": "https://n.example",
                                               "topic": "alerts"}]}, print)
        doc = json.loads(sinks[0].payload({**REC, "name": None}))
        self.assertEqual(doc["title"], "device_quiet: 1669674dd15cf0fa")

    def test_unknown_type_is_config_error(self):
        with self.assertRaises(alerts.ConfigError):
            alerts.build_sinks({"sinks": [{"type": "carrier-pigeon"}]}, print)

    def test_a_command_sink_is_built_from_a_string_or_a_list(self):
        # A string is split like a shell would; a list is taken as given,
        # every element a str; ${VAR} expands in either form.
        os.environ["TW_CMD_TOKEN"] = "tk_9"
        try:
            sinks = alerts.build_sinks({"sinks": [
                {"type": "command", "command": "notify-send -u 'Thread alert' ${TW_CMD_TOKEN}"},
                {"type": "command", "name": "list", "command": ["curl", "-m", 5, "${TW_CMD_TOKEN}"],
                 "min_severity": "critical", "cooldown_s": 60, "timeout_s": 3},
            ]}, print)
        finally:
            os.environ.pop("TW_CMD_TOKEN", None)
        self.assertEqual([type(s) for s in sinks], [alerts.CommandSink, alerts.CommandSink])
        self.assertEqual(sinks[0].name, "command-0")                  # named after its type and index
        self.assertEqual(sinks[0].command, ["notify-send", "-u", "Thread alert", "tk_9"])
        self.assertEqual((sinks[0].min_severity, sinks[0].cooldown_s, sinks[0].timeout_s), (2, 300.0, 10.0))
        self.assertEqual(sinks[1].command, ["curl", "-m", "5", "tk_9"])
        self.assertEqual((sinks[1].name, sinks[1].min_severity, sinks[1].cooldown_s, sinks[1].timeout_s),
                         ("list", 3, 60.0, 3.0))

    def test_a_command_sink_without_a_command_is_refused_by_name(self):
        for raw in ({"type": "command", "name": "hook"},
                    {"type": "command", "name": "hook", "command": ""},
                    {"type": "command", "name": "hook", "command": "   "},
                    {"type": "command", "name": "hook", "command": []}):
            with self.assertRaises(alerts.ConfigError) as cm:
                alerts.build_sinks({"sinks": [raw]}, print)
            self.assertEqual(str(cm.exception), "alert sink 'hook': command is required", raw)
        msgs = []
        self.assertEqual(alerts.build_sinks({"sinks": [{"type": "command", "command": "run ${TW_NOT_SET_CMD}"}]},
                                            msgs.append), [])           # unset variable: disabled, not built
        self.assertIn("TW_NOT_SET_CMD", msgs[0])

    def test_cooldown_is_per_sink_and_per_event(self):
        a = alerts.HttpSink(name="a", url="http://x", cooldown_s=300)
        b = alerts.HttpSink(name="b", url="http://x", cooldown_s=0)
        now = time.time()
        self.assertTrue(a.wants(REC, now))
        self.assertFalse(a.wants(REC, now + 1))
        self.assertTrue(a.wants({**REC, "event": "other"}, now + 1))
        self.assertTrue(b.wants(REC, now))
        self.assertTrue(b.wants(REC, now + 1))
        self.assertFalse(a.wants({**REC, "severity": "notice"}, now + 999))


class EventFilterTests(unittest.TestCase):
    """``events`` takes only the listed names, ``ignore_events`` every name but them."""

    NOW = 1_700_000_000.0

    def test_a_sink_without_a_filter_takes_every_name(self):
        s = alerts.HttpSink(name="a", url="http://x", cooldown_s=0)
        for ev in sorted(alerts.KNOWN_EVENTS):
            self.assertTrue(s.wants({**REC, "event": ev}, self.NOW), ev)

    def test_an_allowlist_takes_the_listed_names_and_refuses_the_rest_at_any_severity(self):
        s = alerts.HttpSink(name="a", url="http://x", cooldown_s=0,
                            events=frozenset({"device_quiet", "phase_locked_storm"}))
        self.assertTrue(s.wants(REC, self.NOW))
        self.assertTrue(s.wants({**REC, "event": "phase_locked_storm", "severity": "critical"}, self.NOW))
        self.assertFalse(s.wants({**REC, "event": "poll_starvation"}, self.NOW))
        self.assertFalse(s.wants({**REC, "event": "poll_starvation", "severity": "critical"}, self.NOW))
        self.assertFalse(s.wants({**REC, "event": "retransmission_elevation"}, self.NOW))

    def test_a_denylist_refuses_the_listed_names_and_takes_the_rest(self):
        s = alerts.HttpSink(name="a", url="http://x", cooldown_s=0,
                            ignore_events=frozenset({"poll_starvation", "retransmission_elevation"}))
        self.assertFalse(s.wants({**REC, "event": "poll_starvation"}, self.NOW))
        self.assertFalse(s.wants({**REC, "event": "retransmission_elevation", "severity": "critical"}, self.NOW))
        self.assertTrue(s.wants(REC, self.NOW))
        self.assertTrue(s.wants({**REC, "event": "phase_locked_storm"}, self.NOW))

    def test_the_severity_floor_still_applies_to_a_name_the_filter_takes(self):
        s = alerts.HttpSink(name="a", url="http://x", cooldown_s=0, events=frozenset({"device_quiet"}))
        self.assertFalse(s.wants({**REC, "severity": "notice"}, self.NOW))
        self.assertTrue(s.wants({**REC, "severity": "critical"}, self.NOW))

    def test_a_filtered_out_record_never_opens_a_window_or_joins_a_digest(self):
        s = alerts.HttpSink(name="a", url="http://x", cooldown_s=300,
                            ignore_events=frozenset({"poll_starvation"}))
        starve = {**REC, "event": "poll_starvation"}
        for i in range(5):
            self.assertFalse(s.wants(starve, self.NOW + i))
        self.assertIsNone(s.next_digest_at())
        self.assertEqual(s.due_digests(self.NOW + 10_000), [])
        # ...and the names it does take still get their own window and digest.
        self.assertTrue(s.wants(REC, self.NOW))
        self.assertFalse(s.wants(REC, self.NOW + 1))
        self.assertEqual([d["event"] for d in s.due_digests(self.NOW + 300)], ["device_quiet"])

    def test_the_filter_holds_even_when_the_cooldown_is_ignored(self):
        # alert-test bypasses the cooldown, not the filter: a phone sink that
        # ignores poll_starvation must not receive a test poll_starvation.
        s = alerts.HttpSink(name="a", url="http://x", ignore_events=frozenset({"poll_starvation"}))
        self.assertFalse(s.wants({**REC, "event": "poll_starvation"}, self.NOW, ignore_cooldown=True))
        self.assertTrue(s.wants(REC, self.NOW, ignore_cooldown=True))
        self.assertTrue(s.wants(REC, self.NOW, ignore_cooldown=True))

    def test_takes_event_is_the_filter_alone(self):
        s = alerts.HttpSink(name="a", url="http://x", events=frozenset({"device_quiet"}))
        self.assertTrue(s.takes_event("device_quiet"))
        self.assertFalse(s.takes_event("poll_starvation"))
        self.assertTrue(alerts.HttpSink(name="b", url="http://x").takes_event("anything"))

    def test_build_sink_reads_both_lists_for_http_command_and_ntfy(self):
        http = alerts.build_sink({"type": "http", "url": "http://x",
                                  "events": ["device_quiet", "phase_locked_storm"]}, 0, lambda m: None)
        self.assertEqual(http.events, frozenset({"device_quiet", "phase_locked_storm"}))
        self.assertEqual(http.ignore_events, frozenset())
        cmd = alerts.build_sink({"type": "command", "command": "true",
                                 "ignore_events": ["poll_starvation"]}, 0, lambda m: None)
        self.assertIsNone(cmd.events)
        self.assertEqual(cmd.ignore_events, frozenset({"poll_starvation"}))
        ntfy = alerts.build_sink({"type": "ntfy", "url": "http://n", "topic": "t",
                                  "ignore_events": ["poll_starvation", "retransmission_elevation"]},
                                 0, lambda m: None)
        self.assertEqual(ntfy.ignore_events, frozenset({"poll_starvation", "retransmission_elevation"}))
        self.assertFalse(ntfy.wants({**REC, "event": "poll_starvation"}, self.NOW))
        self.assertTrue(ntfy.wants(REC, self.NOW))

    def test_a_sink_without_either_key_has_no_filter(self):
        s = alerts.build_sink({"type": "http", "url": "http://x"}, 0, lambda m: None)
        self.assertIsNone(s.events)
        self.assertEqual(s.ignore_events, frozenset())
        legacy = alerts.build_sinks({"webhook_url": "http://x"}, lambda m: None)[0]
        self.assertIsNone(legacy.events)
        self.assertEqual(legacy.ignore_events, frozenset())

    def test_both_lists_on_one_sink_are_refused_by_message(self):
        with self.assertRaises(alerts.ConfigError) as cm:
            alerts.build_sink({"name": "phone", "type": "http", "url": "http://x",
                               "events": ["device_quiet"], "ignore_events": ["poll_starvation"]},
                              0, lambda m: None)
        self.assertEqual(str(cm.exception), "alert sink 'phone': give events or ignore_events, not both")

    def test_a_filter_that_is_not_a_list_of_names_is_refused_by_message(self):
        for bad in ("device_quiet", ["device_quiet", 3], [""], {"a": 1}, 7):
            with self.subTest(bad=bad), self.assertRaises(alerts.ConfigError) as cm:
                alerts.build_sink({"name": "phone", "type": "http", "url": "http://x", "events": bad},
                                  0, lambda m: None)
            self.assertIn("alert sink 'phone': events must be a list of event names", str(cm.exception))
        with self.assertRaises(alerts.ConfigError) as cm:
            alerts.build_sink({"name": "phone", "type": "http", "url": "http://x",
                               "ignore_events": "poll_starvation"}, 0, lambda m: None)
        self.assertIn("ignore_events must be a list of event names", str(cm.exception))

    def test_an_empty_allowlist_takes_nothing_and_an_empty_denylist_takes_everything(self):
        none = alerts.build_sink({"type": "http", "url": "http://x", "events": []}, 0, lambda m: None)
        self.assertFalse(none.wants(REC, self.NOW))
        every = alerts.build_sink({"type": "http", "url": "http://x", "ignore_events": []}, 0, lambda m: None)
        self.assertTrue(every.wants(REC, self.NOW))

    def test_a_name_the_recorder_never_emits_is_a_journal_line_not_an_error(self):
        msgs = []
        s = alerts.build_sink({"name": "phone", "type": "http", "url": "http://x",
                               "ignore_events": ["poll_starvations", "device_quiet", "retrans"]},
                              0, msgs.append)
        self.assertEqual(msgs, ["alert sink 'phone': ignore_events names event(s) the recorder does not "
                                "emit: poll_starvations, retrans (see docs/ALERTING.md for the list)"])
        self.assertFalse(s.wants(REC, self.NOW))                                  # the good name still works
        self.assertTrue(s.wants({**REC, "event": "poll_starvation"}, self.NOW))   # the typo filters nothing
        msgs.clear()
        alerts.build_sink({"type": "http", "url": "http://x", "events": ["device_quiet"]}, 0, msgs.append)
        self.assertEqual(msgs, [])

    def test_known_events_is_the_table_in_the_alerting_docs(self):
        doc = (Path(__file__).resolve().parent.parent / "docs" / "ALERTING.md").read_text()
        table = doc.split("## Events", 1)[1].split("\n## ", 1)[0]
        documented = {m.group(1) for m in re.finditer(r"^\| `([a-z_]+)` \|", table, re.M)}
        self.assertEqual(documented, set(alerts.KNOWN_EVENTS))

    def test_every_event_name_the_code_emits_is_known(self):
        # The names detectors pass to EventLog.emit / Detector events, wherever
        # they are spelled as a literal in the package.
        pkg = Path(__file__).resolve().parent.parent / "threadwatch"
        emitted = set()
        for py in pkg.glob("*.py"):
            src = py.read_text()
            emitted |= set(re.findall(r'"event":\s*"([a-z_]+)"', src))
            emitted |= set(re.findall(r'\.emit\(\s*"([a-z_]+)"', src))
        self.assertTrue(emitted, "no emit sites found: the pattern needs updating")
        self.assertEqual(emitted - set(alerts.KNOWN_EVENTS), set())


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.srv = _Server()

    def tearDown(self):
        self.srv.close()

    def test_http_sink_sends_headers_and_template(self):
        s = alerts.HttpSink(name="t", url=self.srv.url + "/hook",
                            headers={"Authorization": "Bearer x", "content-type": "application/json"},
                            body='{{"text": "{summary}"}}')
        s.send(REC)
        r = self.srv.wait(1)[0]
        self.assertEqual(r["path"], "/hook")
        self.assertEqual(r["headers"]["authorization"], "Bearer x")
        self.assertEqual(json.loads(r["body"]), {"text": 'device_quiet - Living "Room" AQ - no frames heard'})

    def test_ntfy_partial_priority_table_still_renders_valid_json(self):
        raw = alerts._ntfy_preset({"url": "http://x", "topic": "t", "priority": {"warning": 4, "critical": 5}})
        sink = alerts.HttpSink(name="n", url=raw["url"], body=raw["body"], severity_values=raw["severity_values"])
        body = json.loads(sink.payload({**REC, "severity": "notice"}))
        self.assertEqual(body["priority"], 3)

    def test_legacy_webhook_url_expands_env_or_is_disabled(self):
        msgs = []
        self.assertEqual(alerts.build_sinks({"webhook_url": "${TW_NOPE_HOOK}"}, msgs.append), [])
        self.assertIn("TW_NOPE_HOOK", msgs[0])
        os.environ["TW_HOOK"] = "http://hook"
        try:
            self.assertEqual(alerts.build_sinks({"webhook_url": "${TW_HOOK}"}, print)[0].url, "http://hook")
        finally:
            del os.environ["TW_HOOK"]

    def test_raw_record_when_no_template(self):
        alerts.HttpSink(name="t", url=self.srv.url).send(REC)
        self.assertEqual(json.loads(self.srv.wait(1)[0]["body"]), REC)

    def test_event_log_dispatches_in_background_and_respects_floor(self):
        with tempfile.TemporaryDirectory() as d:
            log = EventLog(Path(d) / "events",
                           [alerts.HttpSink(name="t", url=self.srv.url, min_severity=2)])
            log.emit("device_first_seen", "info", addr="x")
            log.emit("device_quiet", "warning", addr="x", name="n")
            reqs = self.srv.wait(1)
            time.sleep(0.2)
            self.assertEqual(len(reqs), 1)
            self.assertEqual(json.loads(reqs[0]["body"])["event"], "device_quiet")
            self.assertEqual(len(read_all(Path(d) / "events")), 2)

    def test_events_held_back_by_the_cooldown_arrive_as_one_digest(self):
        sink = alerts.HttpSink(name="t", url=self.srv.url, cooldown_s=0.6,
                               body='{{"event": "{event}", "who": "{who}", "note": "{note}", "count": "{count}"}}')
        d = alerts.Dispatcher([sink], print)
        for i, name in enumerate(["Stove Light", "Freezer Outlet", "Dining AQ"]):
            d.offer({**REC, "name": name, "addr": "%016x" % i})
        reqs = self.srv.wait(2)
        self.assertEqual(len(reqs), 2)
        first, digest = [json.loads(r["body"]) for r in reqs]
        self.assertEqual(first["who"], "Stove Light")
        self.assertEqual((digest["event"], digest["who"], digest["count"]), ("device_quiet", "2 more", "2"))
        self.assertIn("Freezer Outlet, Dining AQ", digest["note"])
        time.sleep(0.8)
        self.assertEqual(len(self.srv.requests), 2)   # no digest without held-back events

    def test_close_delivers_the_queue_and_every_held_back_digest(self):
        # Eight devices go quiet at once; the cooldown pages the first and
        # holds the rest for a digest due in five minutes. The watchdog
        # restarts the process long before that: close sends it now.
        sink = alerts.HttpSink(name="t", url=self.srv.url, cooldown_s=300,
                               body='{{"event": "{event}", "who": "{who}", "count": "{count}"}}')
        d = alerts.Dispatcher([sink], print)
        for i in range(8):
            d.offer({**REC, "name": f"Device {i}", "addr": "%016x" % i})
        d.offer({**REC, "event": "poll_starvation", "name": "Porch"})   # queued behind the first send
        started = time.time()
        d.close()
        self.assertLess(time.time() - started, 5)
        self.assertFalse(d._thread.is_alive())
        bodies = [json.loads(r["body"]) for r in self.srv.wait(3)]
        self.assertEqual([(b["event"], b["who"]) for b in bodies],
                         [("device_quiet", "Device 0"), ("poll_starvation", "Porch"), ("device_quiet", "7 more")])
        self.assertEqual(bodies[2]["count"], "7")
        self.assertEqual(sink._pending, {})
        alerts.Dispatcher([], print).close()                             # no sinks, no thread: instant

    def test_close_gives_up_on_a_sink_that_never_answers(self):
        # A sink that accepts the connection and then goes silent: the send
        # blocks for the sink's own timeout, and the queue behind it never
        # drains. close() must still return, or systemd's TimeoutStopSec
        # kills the recorder instead of it stopping.
        dead = socket.socket()
        dead.bind(("127.0.0.1", 0))
        dead.listen(8)
        self.addCleanup(dead.close)
        held = []                       # hold each connection open, never reply

        def accept_until_closed():
            while True:
                try:
                    held.append(dead.accept()[0])
                except OSError:
                    return              # the socket closed: the test is over

        threading.Thread(target=accept_until_closed, daemon=True).start()
        self.addCleanup(lambda: [c.close() for c in held])
        sink = alerts.HttpSink(name="blackhole", cooldown_s=300, timeout_s=1.0,
                               url="http://127.0.0.1:%d/" % dead.getsockname()[1])
        d = alerts.Dispatcher([sink], lambda *a: None)
        for i in range(8):
            d.offer({**REC, "name": f"Device {i}", "addr": "%016x" % i})
        started = time.time()
        d.close(timeout=0.5)
        elapsed = time.time() - started
        self.assertGreaterEqual(elapsed, 0.5)       # it did wait for the bound
        self.assertLess(elapsed, 5)                 # ...and no longer than that
        self.assertTrue(d._thread.is_alive())       # abandoned; capture os._exit()s over it
        self.assertEqual(alerts.Dispatcher.close.__defaults__, (15.0,))

    def test_a_sink_answering_a_byte_at_a_time_does_not_hold_the_others(self):
        # urlopen's timeout bounds each socket read, not the request: a
        # remote that accepts and then drips its reply never trips it, and
        # every other sink and record waited behind it, silently.
        class Drip(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(200)
                self.send_header("Content-Length", "1000")
                self.end_headers()
                try:
                    for _ in range(30):             # 3 s of one byte every 0.1 s
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.1)
                except OSError:
                    pass

            def log_message(self, *a):
                pass

        drip = ThreadingHTTPServer(("127.0.0.1", 0), Drip)
        threading.Thread(target=drip.serve_forever, daemon=True).start()
        self.addCleanup(drip.server_close)
        self.addCleanup(drip.shutdown)
        drip_url = f"http://127.0.0.1:{drip.server_port}/"
        logs = []
        slow = alerts.HttpSink(name="slow", cooldown_s=0, timeout_s=0.5, url=drip_url)
        good = alerts.HttpSink(name="good", cooldown_s=0, url=self.srv.url)
        d = alerts.Dispatcher([slow, good], logs.append)
        started = time.time()
        for i in range(2):
            d.offer({**REC, "name": f"Device {i}"})
        self.assertEqual(len(self.srv.wait(2, timeout=3.0)), 2)     # both records reached the healthy sink
        self.assertLess(time.time() - started, 2.0)                 # ...without waiting out the drip
        self.assertTrue(any("'slow'" in m and "no answer within 0.5 s" in m for m in logs), logs)
        self.assertTrue(any("'slow'" in m and "still not been answered" in m for m in logs), logs)
        # Heartbeats share the deadline (push_all is the runner's synchronous form).
        beats = [alerts.Heartbeat(name="drip", url=drip_url, timeout_s=0.5),
                 alerts.Heartbeat(name="good", url=self.srv.url + "/ping")]
        started = time.time()
        out = alerts.HeartbeatRunner(beats, healthy=lambda: True, log=logs.append, start=False).push_all(healthy=True)
        self.assertEqual([(b.name, err is None) for b, err in out], [("drip", False), ("good", True)])
        self.assertLess(time.time() - started, 2.0)

    def test_close_without_sinks_or_pending_is_quick(self):
        with tempfile.TemporaryDirectory() as d:
            log = EventLog(Path(d) / "events", [alerts.HttpSink(name="t", url=self.srv.url)])
            started = time.time()
            log.close()
            self.assertLess(time.time() - started, 2)
            self.assertEqual(self.srv.requests, [])

    def test_failed_sink_is_logged_not_raised(self):
        bad = _Server(status=500)
        try:
            msgs = []
            d = alerts.Dispatcher([alerts.HttpSink(name="bad", url=bad.url)], msgs.append)
            d.offer(REC)
            deadline = time.time() + 3
            while not msgs and time.time() < deadline:
                time.sleep(0.02)
            self.assertIn("HTTP 500", msgs[0])
            self.assertIn("'bad'", msgs[0])
        finally:
            bad.close()

    def test_command_sink_gets_record_on_stdin(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "out"
            s = alerts.CommandSink(name="c", command=["sh", "-c", f"cat > {out}; test \"$THREADWATCH_EVENT\" = device_quiet"])
            s.send(REC)
            self.assertEqual(json.loads(out.read_text()), REC)
            failing = alerts.CommandSink(name="f", command=["sh", "-c", "echo boom >&2; exit 3"])
            with self.assertRaises(Exception) as cm:
                failing.send(REC)
            self.assertIn("boom", alerts._describe_error(cm.exception))

    def test_heartbeat_uses_failure_url_when_unhealthy(self):
        hb = alerts.Heartbeat(name="g", url=self.srv.url + "/ok?success=true",
                              failure_url=self.srv.url + "/ok?success=false",
                              headers={"Authorization": "Bearer t"})
        hb.push(True)
        hb.push(False)
        reqs = self.srv.wait(2)
        self.assertEqual([r["path"] for r in reqs], ["/ok?success=true", "/ok?success=false"])
        self.assertEqual(reqs[0]["headers"]["authorization"], "Bearer t")

    def test_a_redirect_is_an_error_and_the_token_stays_home(self):
        # urlopen follows a 302 and re-sends Authorization to the new host:
        # whoever answers the configured URL could collect the token.
        elsewhere = _Server()
        outer = self

        class Bounce(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                outer.bounced.append(self.path)
                self.send_response(302)
                self.send_header("Location", elsewhere.url + "/stolen")
                self.end_headers()

            do_PUT = do_GET = do_POST

            def log_message(self, *a):
                pass

        self.bounced = []
        bounce = HTTPServer(("127.0.0.1", 0), Bounce)
        threading.Thread(target=bounce.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{bounce.server_port}"
            sink = alerts.HttpSink(name="s", url=url + "/hook", headers={"Authorization": "Bearer tk_SECRET"})
            with self.assertRaises(urllib.error.HTTPError) as cm:
                sink.send(REC)
            self.assertEqual(cm.exception.code, 302)
            hb = alerts.Heartbeat(name="h", url=url + "/beat", headers={"Authorization": "Bearer hb_SECRET"})
            with self.assertRaises(urllib.error.HTTPError):
                hb.push(True)
            self.assertEqual(self.bounced, ["/hook", "/beat"])
            time.sleep(0.2)
            self.assertEqual(elsewhere.requests, [])                     # nothing followed the redirect
            results = alerts.Dispatcher([sink], lambda m: None).deliver_now(REC)
            self.assertEqual([err for _s, err in results], ["HTTP 302"])   # reported, not followed
        finally:
            bounce.shutdown()
            bounce.server_close()
            elsewhere.close()

    def test_heartbeat_without_failure_url_stays_silent_when_unhealthy(self):
        hb = alerts.Heartbeat(name="hc", url=self.srv.url + "/ping")
        self.assertFalse(hb.push(False))
        self.assertTrue(hb.push(True))
        self.assertEqual([r["path"] for r in self.srv.wait(1)], ["/ping"])

    def test_heartbeats_send_nothing_while_health_is_unknown(self):
        hb = alerts.Heartbeat(name="hc", url=self.srv.url + "/ping")
        runner = alerts.HeartbeatRunner([hb], healthy=lambda: None, log=print, start=False)
        self.assertEqual(runner.push_all(), [])
        self.assertEqual(len(runner.push_all(healthy=True)), 1)
        self.assertEqual([r["path"] for r in self.srv.wait(1)], ["/ping"])

    def test_described_urls_hide_path_and_query_secrets(self):
        sink = alerts.HttpSink(name="d", url="https://discord.com/api/webhooks/123/SECRETTOKEN")
        beat = alerts.Heartbeat(name="hc", url="https://hc-ping.com/UUIDSECRET?rid=1")
        for text in (sink.describe(), beat.describe()):
            self.assertNotIn("SECRET", text)
        self.assertIn("https://discord.com/...", sink.describe())

    def test_described_sinks_hide_userinfo_and_command_arguments(self):
        # Credentials before the host (Gotify, a basic-auth proxy, Uptime
        # Kuma) and tokens on a command line (${TOKEN} is expanded before
        # the sink is built) both went to the journal at every start.
        sink = alerts.HttpSink(name="b", url="https://svc:tk_SECRET@alerts.example:8443/hook?tok=SECRET")
        self.assertEqual(sink.describe(), "b: POST https://alerts.example:8443/...")
        self.assertEqual(alerts._redact_url("https://user:SECRET@ntfy.example.org"), "https://ntfy.example.org/...")
        self.assertEqual(alerts._redact_url("https://ntfy.example.org/"), "https://ntfy.example.org")
        beat = alerts.Heartbeat(name="hc", url="https://user:SECRET@hc.example/")
        self.assertNotIn("SECRET", beat.describe())
        cmd = alerts.CommandSink(name="c", command=["curl", "-H", "Authorization: Bearer SECRET", "https://h/x"])
        self.assertEqual(cmd.describe(), "c: curl (+3 args)")
        self.assertEqual(alerts.CommandSink(name="c", command=["notify"]).describe(), "c: notify")
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"TOKEN": "tk_SECRET"}):
            built = alerts.build_sink({"type": "command", "command": ["curl", "-H", "Authorization: Bearer ${TOKEN}",
                                                                      "https://h/x"]}, 0, print)
            self.assertNotIn("SECRET", built.describe())
            self.assertIn("tk_SECRET", built.command[2])    # still sent, just not printed

    def test_partial_severity_table_never_yields_a_bare_name(self):
        table = {"warning": 5, "critical": 8}
        got = {sev: alerts.template_fields({**REC, "severity": sev}, table)["severity_value"]
               for sev in alerts.SEVERITIES}
        self.assertEqual(got, {"info": 5, "notice": 5, "warning": 5, "critical": 8})
        self.assertEqual(alerts.template_fields({**REC, "severity": "notice"})["severity_value"], "notice")

    def test_build_heartbeats_validates(self):
        with self.assertRaises(alerts.ConfigError):
            alerts.build_heartbeats([{"url": "http://x", "interval_s": 1}], print)
        with self.assertRaises(alerts.ConfigError):   # same name: only one timer would run
            alerts.build_heartbeats([{"name": "gatus", "url": "http://a"}, {"name": "gatus", "url": "http://b"}], print)
        msgs = []
        self.assertEqual(alerts.build_heartbeats([{"url": "${TW_NOPE}"}], msgs.append), [])
        self.assertIn("TW_NOPE", msgs[0])
        beats = alerts.build_heartbeats([{"name": "hc", "url": "http://x", "interval_s": 60, "method": "get"}], print)
        self.assertEqual(beats[0].method, "GET")


if __name__ == "__main__":
    unittest.main()


class FlakySink(alerts.Sink):
    """A sink that refuses the first ``fail`` sends, then takes the rest."""

    def __init__(self, name="flaky", fail=0, **kw):
        super().__init__(name=name, **kw)
        self.fail = fail
        self.sent: list[dict] = []

    def send(self, record):
        if self.fail:
            self.fail -= 1
            raise OSError("connection refused")
        self.sent.append(record)


def wait_for(cond, timeout=3.0):
    deadline = time.time() + timeout
    while not cond() and time.time() < deadline:
        time.sleep(0.02)
    return cond()


class RecordIdTest(unittest.TestCase):
    def test_the_same_record_has_the_same_id_and_the_log_carries_it(self):
        self.assertEqual(alerts.record_id(REC), alerts.record_id({**REC, "note": "different"}))
        self.assertNotEqual(alerts.record_id(REC), alerts.record_id({**REC, "ts": REC["ts"] + 1}))
        self.assertNotEqual(alerts.record_id(REC), alerts.record_id({**REC, "addr": "0" * 16}))
        self.assertEqual(len(alerts.record_id(REC)), 12)
        with tempfile.TemporaryDirectory() as d:
            log = EventLog(Path(d) / "events")
            rec = log.emit("device_quiet", "warning", 1700000000.0, addr="x")
            self.assertEqual(rec["id"], alerts.record_id(rec))
            self.assertEqual(read_all(Path(d) / "events")[0]["id"], rec["id"])
        self.assertEqual(alerts.render("{id}/{event}", REC, False), f"{alerts.record_id(REC)}/device_quiet")
        digest = alerts.digest_record("device_quiet", [REC], 300, 1700000600.0)
        self.assertEqual(digest["id"], alerts.record_id(digest))
        self.assertIn("id", alerts.TEMPLATE_FIELDS)


class RetryTest(unittest.TestCase):
    """A send that fails is tried again with backoff until the record is
    too old to be news; what is still refused when the process leaves is
    spooled for the next start."""

    def _dispatcher(self, sinks, spool=None, msgs=None, **kw):
        d = alerts.Dispatcher(sinks, (msgs if msgs is not None else []).append, spool=spool,
                              retry_delays=(0.05, 0.1), retry_cap_s=0.1, **kw)
        self.addCleanup(d.close, 2.0)
        return d

    def test_a_failed_send_is_retried_with_backoff_and_delivered(self):
        sink = FlakySink(fail=2)
        msgs = []
        d = self._dispatcher([sink], msgs=msgs)
        d.offer({**REC, "ts": time.time()})
        self.assertTrue(wait_for(lambda: sink.sent))
        self.assertEqual(sink.sent[0]["event"], "device_quiet")
        self.assertEqual([m for m in msgs if "retrying" in m],
                         ["alert sink 'flaky' failed: OSError: connection refused; retrying in 0.05 s (attempt 1)",
                          "alert sink 'flaky' failed: OSError: connection refused; retrying in 0.1 s (attempt 2)"])
        self.assertTrue(wait_for(lambda: d.stats()["queued"] == 0))
        self.assertEqual(d.stats(), {"delivered": 1, "queued": 0, "retrying": 0, "given_up": 0, "resumed": 0})

    def test_a_record_too_old_to_be_news_is_given_up_not_retried(self):
        sink = FlakySink(fail=99)
        msgs = []
        d = self._dispatcher([sink], msgs=msgs, stale_s=60)
        d.offer({**REC, "ts": time.time() - 3600})
        self.assertTrue(wait_for(lambda: d.stats()["given_up"] == 1))
        self.assertIn("given up, the record is 1.0 h old (attempt 1)", msgs[-1])
        self.assertEqual(sink.fail, 98)                                # one attempt
        time.sleep(0.2)
        self.assertEqual(sink.fail, 98)

    def test_the_queue_is_retried_while_a_digest_still_goes_out_on_time(self):
        sink = FlakySink(fail=1, cooldown_s=0.3)
        d = self._dispatcher([sink])
        now = time.time()
        d.offer({**REC, "ts": now, "name": "First"})                   # fails once, retried after 0.05 s
        d.offer({**REC, "ts": now, "name": "Second"})                  # held for the digest
        self.assertTrue(wait_for(lambda: len(sink.sent) == 2))
        self.assertEqual([r.get("name") for r in sink.sent], ["First", "1 more"])

    def test_what_a_sink_still_refuses_at_close_is_spooled_and_sent_at_the_next_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = Path(tmp) / "alert-spool.jsonl"
            sink = FlakySink(fail=99)
            msgs = []
            d = alerts.Dispatcher([sink], msgs.append, spool=spool, retry_delays=(0.05,), retry_cap_s=0.05)
            now = time.time()
            d.offer({**REC, "ts": now, "name": "A"})
            d.offer({**REC, "ts": now, "name": "B", "event": "poll_starvation"})
            self.assertTrue(wait_for(lambda: sink.fail <= 96))
            d.close()
            self.assertFalse(d._thread.is_alive())
            lines = [json.loads(l) for l in spool.read_text().splitlines()]
            self.assertEqual(sorted((l["record"]["name"], l["sinks"]) for l in lines), [("A", ["flaky"]), ("B", ["flaky"])])
            self.assertTrue(all(l["attempt"] >= 1 for l in lines))
            self.assertIn("2 undelivered record(s) kept in alert-spool.jsonl", msgs[-1])
            # The next start: the sink is back, a record is stale, one is
            # for a sink no longer configured.
            spool.write_text(spool.read_text()
                             + json.dumps({"record": {**REC, "ts": now - 7 * 3600, "name": "old"}, "sinks": ["flaky"], "attempt": 3}) + "\n"
                             + json.dumps({"record": {**REC, "ts": now, "name": "gone"}, "sinks": ["removed"], "attempt": 1}) + "\n"
                             + "not json\n")
            good = FlakySink(fail=0)
            msgs2 = []
            d2 = alerts.Dispatcher([good], msgs2.append, spool=spool)
            self.addCleanup(d2.close, 2.0)
            self.assertTrue(wait_for(lambda: len(good.sent) == 2))
            self.assertEqual(sorted(r["name"] for r in good.sent), ["A", "B"])
            self.assertFalse(spool.exists())
            self.assertEqual(d2.stats()["resumed"], 2)
            self.assertEqual(msgs2[0], "alert spool: 2 record(s) the last run could not deliver, sending now; "
                                       "1 too old, dropped; 2 unreadable or for a sink no longer configured, dropped")
            # Without sinks nothing can send: the spool stays for a run that has some.
            spool.write_text(json.dumps({"record": REC, "sinks": ["flaky"], "attempt": 1}) + "\n")
            alerts.Dispatcher([], print, spool=spool)
            self.assertTrue(spool.exists())

    def test_the_spool_stays_on_disk_until_its_records_are_delivered(self):
        # The spool was read, queued in memory and unlinked before a single
        # record was sent: a start-up failure after the log was built, an
        # OOM kill or a power cut then destroyed every alert the last run
        # had promised to send again.
        with tempfile.TemporaryDirectory() as tmp:
            spool = Path(tmp) / "alert-spool.jsonl"
            inflight = Path(tmp) / "alert-spool.jsonl.inflight"
            recs = [{**REC, "ts": time.time(), "note": f"record {i}"} for i in range(2)]
            spool.write_text("".join(json.dumps({"record": r, "sinks": ["flaky"], "attempt": 1}) + "\n"
                                     for r in recs))
            sink = FlakySink(fail=99)
            msgs = []
            d = self._dispatcher([sink], spool=spool, msgs=msgs)
            self.assertTrue(wait_for(lambda: any("retrying" in m for m in msgs)))
            # Loaded, refused, and still on disk under its in-flight name.
            self.assertFalse(spool.exists())
            self.assertEqual([json.loads(l)["record"]["note"] for l in inflight.read_text().splitlines()],
                             ["record 0", "record 1"])
            d.close(2.0)
            # Closed with them still refused: spooled again, the in-flight copy gone.
            self.assertTrue(spool.exists())
            self.assertFalse(inflight.exists())
            self.assertEqual(len(spool.read_text().splitlines()), 2)
            # A run that died mid-delivery leaves the in-flight file: the
            # next start loads it beside the spool, sends everything, and
            # removes both once the queue has drained.
            spool.replace(inflight)
            spool.write_text(json.dumps({"record": {**REC, "ts": time.time(), "note": "record 2"},
                                         "sinks": ["flaky"], "attempt": 0}) + "\n")
            good = FlakySink(fail=0)
            d2 = self._dispatcher([good], spool=spool)
            self.assertTrue(wait_for(lambda: len(good.sent) == 3))
            self.assertTrue(wait_for(lambda: not inflight.exists() and not spool.exists()))
            self.assertEqual(sorted(r["note"] for r in good.sent), ["record 0", "record 1", "record 2"])
            self.assertEqual(d2.stats()["resumed"], 3)

    def test_a_sink_still_parked_at_close_leaves_its_record_in_the_spool(self):
        with tempfile.TemporaryDirectory() as tmp:
            spool = Path(tmp) / "alert-spool.jsonl"
            gate = threading.Event()

            class Parked(alerts.Sink):
                def send(self, record):
                    gate.wait(5)

            sink = Parked(name="parked", timeout_s=5)
            d = alerts.Dispatcher([sink], lambda m: None, spool=spool)
            d.offer({**REC, "ts": time.time(), "name": "in flight"})
            d.offer({**REC, "ts": time.time(), "name": "behind it", "event": "poll_starvation"})
            time.sleep(0.1)
            d.close(timeout=0.2)
            lines = [json.loads(l) for l in spool.read_text().splitlines()]
            self.assertEqual([l["record"]["name"] for l in lines], ["in flight", "behind it"])
            gate.set()
            d._thread.join(2)                                          # let it finish before the directory goes


class AlertChainTest(unittest.TestCase):
    """config.toml -> config.load -> build_sinks -> EventLog -> Pipeline ->
    the HTTP body a sink receives. Every link has its own tests; this is
    the chain, which is the recorder's whole promise: page me when the
    mesh breaks. A renamed table, sinks not passed through, a severity
    dropped on the way to the dispatcher, all leave green tests and a
    silent phone without it."""

    def test_a_quiet_device_reaches_the_configured_sink_with_its_name(self):
        from threadwatch import config as config_mod
        from threadwatch.crypto import Decryptor
        from threadwatch.pcap import Frame
        from threadwatch.pipeline import Pipeline

        from tests.frames import psdu_for

        def frame(ts, src, rssi):
            return Frame(ts=ts, raw=b"", psdu=psdu_for(src, seq=int(ts) & 0xFF), rssi=rssi, channel=None,
                         lqi=None, ftype=1, seq=int(ts) & 0xFF, dst_pan=0x4e21, dst="0000", src_pan=0x4e21, src=src)

        srv = _Server()
        self.addCleanup(srv.close)
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "devices.json").write_text(json.dumps([
                {"name": "Living Room AQ", "extendedAddress": "1669674dd15cf0fa"},
                {"name": "Porch Sensor", "extendedAddress": "b62c32bf669272db"}]))
            (d / "config.toml").write_text(
                "[network]\npan_id = \"0x4e21\"\n"
                f"[capture]\ndata_dir = \"{d / 'data'}\"\n"
                "[devices]\ninventory = \"devices.json\"\n"
                "[quiet]\nsilence_s = 60\n"
                "[border_routers]\nbrowse_s = 0\n"
                "[summary]\nhour = -1\n"
                "[[alerts.sinks]]\nname = \"home-assistant\"\ntype = \"http\"\n"
                f"url = \"{srv.url}/api/webhook/threadwatch\"\n"
                "min_severity = \"notice\"\ncooldown_s = 0\n")
            logs = []
            cfg = config_mod.load(d / "config.toml")
            sinks = alerts.build_sinks(cfg.alerts_raw, logs.append)
            self.assertEqual([s.name for s in sinks], ["home-assistant"])
            log = EventLog(cfg.events_dir, sinks)
            pipe = Pipeline(cfg, log, Decryptor(network_key=bytes(16)))
            t0 = 1_700_000_000.0
            for i in range(40):
                pipe.ingest(frame(t0 + i, "1669674dd15cf0fa", -60.0))
                pipe.ingest(frame(t0 + i, "b62c32bf669272db", -88.0))   # barely heard: a notice, not a page
            pipe.periodic(t0 + 2 * 60)                                  # both silent past the 60 s window
            log.close()
            reqs = srv.wait(2)
            self.assertEqual(logs, [])
            self.assertEqual({r["path"] for r in reqs}, {"/api/webhook/threadwatch"})
            quiet = sorted((json.loads(r["body"]) for r in reqs if json.loads(r["body"])["event"] == "device_quiet"),
                           key=lambda b: b["name"])
            self.assertEqual([(b["name"], b["event"], b["severity"]) for b in quiet],
                             [("Living Room AQ", "device_quiet", "warning"),
                              ("Porch Sensor", "device_quiet", "notice")])
            self.assertEqual([r["event"] for r in read_all(cfg.events_dir) if r["event"] == "device_quiet"],
                             ["device_quiet", "device_quiet"])


class _LoopStop(Exception):
    pass


class LoopClock:
    """time.time()/time.sleep() for HeartbeatRunner._run under test. The
    loop parks at every sleep; step() releases one iteration and returns
    once the loop is parked again, the clock advanced by what it asked to
    sleep. No real waiting, no races with the assertions."""

    def __init__(self, start=1_000_000.0):
        self.now = start
        self.sleeps = []
        self._go = threading.Semaphore(0)
        self._parked = threading.Semaphore(0)
        self._stopping = False

    def time(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self._parked.release()
        self._go.acquire()
        if self._stopping:
            raise _LoopStop
        self.now += seconds

    def run(self, runner):
        def body():
            try:
                runner._run()
            except _LoopStop:
                pass
        threading.Thread(target=body, daemon=True).start()
        assert self._parked.acquire(timeout=3.0), "the loop never reached its first sleep"

    def step(self, n=1):
        for _ in range(n):
            self._go.release()
            assert self._parked.acquire(timeout=3.0), "the loop never slept again"

    def stop(self):
        self._stopping = True
        self._go.release()


class HeartbeatLoopTest(unittest.TestCase):
    """HeartbeatRunner._run, the thread that keeps an external monitor
    told. Two silent field failures live here: if the per-beat due time
    regresses the loop hammers the monitor twice a second, and if the
    unknown-health gate regresses to a truthiness check a restart loop
    that has never heard a frame keeps sending healthy beats."""

    def _runner(self, healthy, push, logs, interval_s=10.0):
        hb = alerts.Heartbeat(name="hc", url="http://x/ping", interval_s=interval_s)
        hb.push = push
        return alerts.HeartbeatRunner([hb], healthy=healthy, log=logs.append, start=False)

    def test_nothing_while_health_is_unknown_then_one_beat_per_interval(self):
        clock, pushes, logs, state = LoopClock(), [], [], {"healthy": None}
        runner = self._runner(lambda: state["healthy"],
                              lambda healthy: pushes.append((clock.now, healthy)) or True, logs)
        with mock.patch.object(alerts, "time", clock):
            clock.run(runner)
            clock.step(3)
            self.assertEqual(pushes, [])                          # unknown: nothing sent...
            self.assertEqual(clock.sleeps, [0.5] * 4)             # ...and checked again soon
            state["healthy"] = True
            t = clock.now + 0.5                                   # when the pending check comes round
            clock.step()
            self.assertEqual(pushes, [(t, True)])                 # the first frame: one beat
            clock.step()                                          # 5 s on: not due
            self.assertEqual(len(pushes), 1)
            clock.step()                                          # 10 s on: due
            self.assertEqual(pushes, [(t, True), (t + 10, True)])
            state["healthy"] = False
            clock.step(2)
            self.assertEqual(pushes[-1], (t + 20, False))         # a stall goes out on the same schedule
            self.assertEqual(len(pushes), 3)
            self.assertEqual(logs, [])
            clock.stop()

    def test_a_failing_beat_is_logged_once_and_its_recovery_once(self):
        clock, logs, fail = LoopClock(), [], {"on": True}

        def push(healthy):
            if fail["on"]:
                raise urllib.error.URLError("connection refused")
            return True

        runner = self._runner(lambda: True, push, logs)
        with mock.patch.object(alerts, "time", clock):
            clock.run(runner)                                     # the first beat fails
            self.assertEqual(len(logs), 1)
            self.assertIn("'hc' failed", logs[0])
            clock.step(4)                                         # two more misses, 10 s apart
            self.assertEqual(len(logs), 1)                        # the edge, not every miss
            fail["on"] = False
            clock.step(2)                                         # the next beat lands
            self.assertEqual(len(logs), 2)
            self.assertIn("'hc' recovered", logs[1])
            clock.step(2)
            self.assertEqual(len(logs), 2)
            clock.stop()


class TimeoutDefaultsTest(unittest.TestCase):
    """Ten seconds is how long one unreachable sink can hold the dispatcher,
    and every record behind it, per record. It is the bound _bounded
    enforces, for sinks and heartbeats alike."""

    def test_sinks_and_heartbeats_wait_ten_seconds_by_default(self):
        self.assertEqual(alerts.HttpSink(name="h", url="http://x").timeout_s, 10.0)
        self.assertEqual(alerts.CommandSink(name="c", command=["true"]).timeout_s, 10.0)
        self.assertEqual(alerts.build_sinks({"webhook_url": "http://x"}, print)[0].timeout_s, 10.0)
        self.assertEqual(alerts.build_sinks({"sinks": [{"url": "http://x"}]}, print)[0].timeout_s, 10.0)
        self.assertEqual(alerts.build_sinks({"sinks": [{"url": "http://x", "timeout_s": 2}]}, print)[0].timeout_s, 2.0)
        self.assertEqual(alerts.Heartbeat(name="b", url="http://x").timeout_s, 10.0)
        self.assertEqual(alerts.build_heartbeats([{"url": "http://x"}], print)[0].timeout_s, 10.0)

    def test_the_default_is_the_deadline_every_send_and_beat_runs_under(self):
        sink = alerts.HttpSink(name="h", url="http://x")
        beat = alerts.Heartbeat(name="b", url="http://x")
        with mock.patch.object(alerts, "_bounded", return_value=None) as bounded:
            alerts.Dispatcher([sink], print).deliver_now(REC)
            alerts.HeartbeatRunner([beat], healthy=lambda: True, log=print, start=False).push_all()
        self.assertEqual([(c.args[0], c.args[2]) for c in bounded.call_args_list], [(sink, 10.0), (beat, 10.0)])


class ClockStepTest(unittest.TestCase):
    """The cooldown was a wall-clock subtraction with no lower bound: after
    a step back of S seconds, now minus the window's start was negative,
    which read as "inside the cooldown" for S seconds even with the
    cooldown disabled, and what came out at the end was a digest, not
    the page. A Pi corrected by NTP after booting on its saved clock
    steps by hours, at the start a broken mesh most needs pages."""

    def test_a_backward_step_neither_holds_a_page_nor_makes_it_a_digest(self):
        t = 1_700_000_000.0
        off = alerts.HttpSink(name="t", url="http://x", cooldown_s=0)
        self.assertTrue(off.wants(REC, t))
        self.assertTrue(off.wants({**REC, "ts": t - 30}, t - 30))           # used to be held 30 s
        self.assertEqual(off._pending, {})
        sink = alerts.HttpSink(name="t", url="http://x", cooldown_s=300)
        self.assertTrue(sink.wants(REC, t))
        self.assertFalse(sink.wants({**REC, "name": "Freezer Outlet"}, t + 1))   # held, as it should be
        # The clock steps back an hour: the window that began "an hour
        # from now" is over. The next record pages and opens a new one,
        # and the held record's digest is due at once, not in an hour.
        self.assertEqual(sink.next_digest_at(t - 3600), t - 3600)
        self.assertTrue(sink.wants({**REC, "name": "Dining AQ"}, t - 3599))
        self.assertEqual([d["count"] for d in sink.due_digests(t - 3599)], [1])
        self.assertFalse(sink.wants({**REC, "name": "Hall"}, t - 3500))       # the new window holds again
        self.assertEqual(sink.next_digest_at(t - 3500), t - 3599 + 300)

    def test_a_retry_scheduled_before_the_step_is_due_now(self):
        d = alerts.Dispatcher([], print, retry_delays=(30.0, 120.0, 480.0), retry_cap_s=600.0)
        now = 1_700_000_000.0
        self.assertFalse(d._due({"due": now + 480}, now))                    # a retry, on time
        self.assertTrue(d._due({"due": now}, now))
        self.assertTrue(d._due({"due": now + 3600 + 30}, now))               # scheduled before an hour's step back
        self.assertEqual(d._next_due(now), None)
        d._queue.append({"due": now + 3600 + 30})
        self.assertEqual(d._next_due(now), now)


class DigestWindowTest(unittest.TestCase):
    """The cooldown pages the first event and holds the rest for one digest
    when the window ends. Its content is well covered; this is its timing
    and its severity, which decide whether the digest reads as a page."""

    def test_a_digest_is_due_when_its_window_ends_not_later(self):
        sink = alerts.HttpSink(name="t", url="http://x", cooldown_s=300)
        t = 1_700_000_000.0
        self.assertTrue(sink.wants(REC, t))                                   # paged; the window opens
        self.assertFalse(sink.wants({**REC, "name": "Freezer Outlet"}, t + 1))  # held back
        self.assertEqual(sink.next_digest_at(), t + 300)
        self.assertEqual(sink.due_digests(t + 299), [])
        digests = sink.due_digests(t + 300)
        self.assertEqual([(d["event"], d["count"], d["ts"]) for d in digests], [("device_quiet", 1, t + 300)])
        self.assertEqual(sink._pending, {})
        self.assertIsNone(sink.next_digest_at())
        self.assertFalse(sink.wants({**REC, "name": "Dining AQ"}, t + 301))   # the digest opened the next window
        self.assertEqual(sink.next_digest_at(), t + 600)

    def test_a_page_at_the_boundary_does_not_push_the_held_batch_back(self):
        # BUG-13: a page arriving at the window's end before the dispatcher
        # collected the digest moved the batch's deadline to the new window,
        # and every such page moved it again.
        sink = alerts.HttpSink(name="t", url="http://x", cooldown_s=300)
        self.assertTrue(sink.wants(REC, 1000))
        self.assertFalse(sink.wants({**REC, "name": "Freezer Outlet"}, 1001))
        self.assertTrue(sink.wants({**REC, "name": "Dining AQ"}, 1300))         # producer first: the next window opens
        self.assertEqual(sink.next_digest_at(), 1300)                            # the held batch is due now, not at 1600
        digests = sink.due_digests(1300)
        self.assertEqual([(d["event"], d["count"], d["ts"]) for d in digests], [("device_quiet", 1, 1300)])
        self.assertIn("Freezer Outlet", digests[0]["note"])
        self.assertEqual(sink._pending, {})
        for t in (1600, 1900):
            self.assertTrue(sink.wants({**REC, "name": f"Porch {t}"}, t))
            self.assertEqual(sink.due_digests(t), [])
        self.assertFalse(sink.wants({**REC, "name": "Stove Light"}, 1901))      # held in the window opened at 1900
        self.assertEqual(sink.next_digest_at(), 2200)

    def test_a_digest_carries_the_most_severe_event_it_stands_for(self):
        # A sink with its floor at notice holds back a mixed batch; the one
        # record that stands for them must read as urgent as the worst.
        batch = [{**REC, "severity": s, "name": n, "ts": REC["ts"] + i}
                 for i, (s, n) in enumerate((("notice", "Porch"), ("critical", "Stove Light"), ("warning", "Dining AQ")))]
        d = alerts.digest_record("device_quiet", batch, 300, REC["ts"] + 300)
        self.assertEqual((d["severity"], d["count"], d["digest"]), ("critical", 3, True))
        self.assertEqual((d["first_ts"], d["last_ts"]), (REC["ts"], REC["ts"] + 2))
        self.assertEqual(alerts.digest_record("x", batch[:1], 300, 0)["severity"], "notice")


class AlertTestCommandTest(unittest.TestCase):
    """`threadwatch alert-test` is how an operator proves the sinks and
    heartbeats in config.toml reach the phone before trusting them. It
    runs Dispatcher.deliver_now, the one synchronous delivery path, with
    every cooldown ignored: a test that was silently swallowed by a
    cooldown, or that skipped a sink and still said ok, would certify an
    alerting setup that does not page."""

    def setUp(self):
        self.ok, self.bad = _Server(), _Server(status=500)
        self.addCleanup(self.ok.close)
        self.addCleanup(self.bad.close)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        d = Path(self.tmp.name)
        (d / "config.toml").write_text(
            f"[capture]\ndata_dir = \"{d / 'data'}\"\n"
            "[[alerts.sinks]]\nname = \"phone\"\ntype = \"http\"\n"
            f"url = \"{self.ok.url}/hook\"\nmin_severity = \"notice\"\ncooldown_s = 300\n"
            "[[alerts.sinks]]\nname = \"pager\"\ntype = \"http\"\n"
            f"url = \"{self.bad.url}/page\"\nmin_severity = \"critical\"\n"
            "[[heartbeats]]\nname = \"gatus\"\n"
            f"url = \"{self.ok.url}/beat\"\n")
        self.config = str(d / "config.toml")

    def _run(self, *args):
        import contextlib
        import io
        from threadwatch.cli import main
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["--config", self.config, "alert-test", *args])
        return code, out.getvalue().splitlines()

    def test_every_eligible_sink_and_heartbeat_is_hit_once_and_the_rest_is_said(self):
        code, lines = self._run()
        self.assertEqual(code, 0)
        self.assertEqual(lines[0], "sinks (2):")
        self.assertTrue(lines[1].startswith("  ok   phone: "), lines)
        self.assertEqual(lines[2], "  skip pager (min severity above warning)")
        self.assertEqual(lines[3], "heartbeats (1):")
        self.assertTrue(lines[4].startswith("  ok   gatus: "), lines)
        self.assertEqual(len(lines), 5)
        beat, hook = sorted(self.ok.wait(2), key=lambda r: r["path"])
        self.assertEqual((beat["path"], hook["path"]), ("/beat", "/hook"))
        body = json.loads(hook["body"])
        self.assertEqual((body["event"], body["severity"], body["name"], body["addr"]),
                         ("alert_test", "warning", "Test device", "0000000000000000"))
        self.assertEqual(body["note"], f"threadwatch alert-test from {socket.gethostname()}")
        self.assertAlmostEqual(body["ts"], time.time(), delta=30)
        self.assertEqual(self.bad.requests, [])                      # a skipped sink is not contacted

    def test_a_failing_sink_fails_the_command_and_cooldowns_do_not_apply(self):
        self._run()                                                  # opens phone's 300 s cooldown window
        code, lines = self._run("--severity", "critical", "--event", "drill", "--no-heartbeats")
        self.assertEqual(code, 1)
        self.assertTrue(lines[1].startswith("  ok   phone: "), lines)   # delivered again inside the cooldown
        self.assertTrue(lines[2].startswith("  FAIL pager: "), lines)
        self.assertTrue(lines[2].endswith(" -> HTTP 500"), lines)
        self.assertEqual(len(lines), 3)                              # no heartbeats section
        self.assertEqual([json.loads(r["body"])["event"] for r in self.ok.requests if r["path"] == "/hook"],
                         ["alert_test", "drill"])
        self.assertEqual([r["path"] for r in self.ok.requests if r["path"] == "/beat"], ["/beat"])
        self.assertEqual(json.loads(self.bad.wait(1)[0]["body"])["severity"], "critical")

    def test_deliver_now_reports_per_sink_and_honours_the_cooldown_only_when_asked(self):
        good = alerts.HttpSink(name="good", url=self.ok.url + "/a", min_severity=1)
        broken = alerts.HttpSink(name="broken", url=self.bad.url + "/b", min_severity=1)
        quiet = alerts.HttpSink(name="quiet", url=self.ok.url + "/c", min_severity=3)   # critical only
        dispatcher = alerts.Dispatcher([good, broken, quiet], [].append)
        self.addCleanup(dispatcher.close)
        self.assertEqual(dispatcher.deliver_now(REC), [(good, None), (broken, "HTTP 500")])
        self.assertEqual(dispatcher.deliver_now(REC), [(good, None), (broken, "HTTP 500")])   # cooldown ignored
        self.assertEqual(dispatcher.deliver_now(REC, ignore_cooldown=False), [(good, None), (broken, "HTTP 500")])
        self.assertEqual(dispatcher.deliver_now(REC, ignore_cooldown=False), [])              # inside the window
        self.assertEqual(dispatcher.deliver_now({**REC, "severity": "critical"}, ignore_cooldown=True),
                         [(good, None), (broken, "HTTP 500"), (quiet, None)])
        self.assertEqual(len([r for r in self.ok.requests if r["path"] == "/a"]), 4)


class CooldownDefaultsTest(unittest.TestCase):
    """Five minutes per event name, per sink, is the rate limit that turns
    a 40-device outage into two messages. Every way of building a sink
    must land on it, the legacy webhook_url shorthand included: that one
    is built straight from the dataclass, so a changed default there is
    a phone that buzzes once per device."""

    def test_every_way_of_building_a_sink_gets_five_minutes(self):
        self.assertEqual(alerts.Sink.__dataclass_fields__["cooldown_s"].default, 300.0)
        self.assertEqual(alerts.HttpSink(name="h", url="http://x").cooldown_s, 300.0)
        self.assertEqual(alerts.CommandSink(name="c", command=["true"]).cooldown_s, 300.0)
        legacy = alerts.build_sinks({"webhook_url": "http://x"}, print)[0]
        self.assertEqual(legacy.cooldown_s, 300.0)
        self.assertEqual(alerts.build_sinks({"sinks": [{"url": "http://x"}]}, print)[0].cooldown_s, 300.0)
        self.assertEqual(alerts.build_sinks({"sinks": [{"type": "command", "command": "true"}]}, print)[0].cooldown_s, 300.0)
        self.assertEqual(alerts.build_sinks({"sinks": [{"url": "http://x", "cooldown_s": 0}]}, print)[0].cooldown_s, 0.0)

    def test_the_legacy_sink_holds_a_repeat_for_five_minutes(self):
        legacy = alerts.build_sinks({"webhook_url": "http://x"}, print)[0]
        now = 1_700_000_000.0
        self.assertTrue(legacy.wants(REC, now))
        self.assertFalse(legacy.wants(REC, now + 1))
        self.assertFalse(legacy.wants(REC, now + 299))
        self.assertEqual(legacy.next_digest_at(), now + 300)
        self.assertTrue(legacy.wants(REC, now + 300))
