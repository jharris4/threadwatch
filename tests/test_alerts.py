"""Unit tests for threadwatch.alerts (stdlib only: python3 -m unittest)."""

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch import alerts  # noqa: E402
from threadwatch.events import EventLog, read_all  # noqa: E402


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
