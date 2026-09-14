"""halogs: the Home Assistant add-on log fetch and its place in a
snapshot. A fake Supervisor on loopback serves verbose-format journal
lines and honours the realtime range, so every outcome the endpoint can
produce is driven here: a window that starts before the journal's
retention, an admin-only refusal, a redirect, a refused connection, and
a stream too slow for the deadline."""

import gzip
import json
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch import halogs

TOKEN = "tk_ADMIN_SECRET_9f3a"
KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


def journal_line(ts: float, text: str, unit: str = "app_core_openthread_border_router") -> str:
    ms = int(round((ts - int(ts)) * 1000))
    return f"{time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(ts))}.{ms:03d} homeassistant {unit}[697]: {text}\n"


class FakeSupervisor:
    """GET /api/hassio/addons/<slug>/logs?verbose with Range: realtime=a:b
    (or entries=:-N:N). ``lines`` is [(ts, text)] per slug; ``status``
    forces an HTTP status; ``delay_s`` sleeps between lines; ``redirect``
    answers 302 to that URL; ``retained_from`` drops lines before it, as
    a journal that has rolled does."""

    def __init__(self, lines=None, status=200, delay_s=0.0, redirect=None, retained_from=None, token=TOKEN):
        self.requests = []
        self.lines = lines or {}
        self.status, self.delay_s, self.redirect, self.retained_from = status, delay_s, redirect, retained_from
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                outer.requests.append({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}})
                if outer.redirect:
                    self.send_response(302)
                    self.send_header("Location", outer.redirect)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.headers.get("Authorization") != f"Bearer {token}":
                    self.send_response(401)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                slug = self.path.split("/addons/")[1].split("/")[0]
                if outer.status != 200 or slug not in outer.lines:
                    self.send_response(outer.status if outer.status != 200 else 404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                rng = self.headers.get("Range", "")
                rows = [(ts, text) for ts, text in outer.lines[slug]
                        if outer.retained_from is None or ts >= outer.retained_from]
                if rng.startswith("realtime="):
                    a, b = (int(x) for x in rng[len("realtime="):].split(":"))
                    rows = [(ts, text) for ts, text in rows if a <= ts < b]      # half-open, as observed
                elif rng.startswith("entries=:-"):
                    n = int(rng.split(":")[-1])
                    rows = rows[-n:]
                body = "".join(journal_line(ts, text) for ts, text in rows).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                if outer.delay_s:
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    try:
                        for ts, text in rows:
                            chunk = journal_line(ts, text).encode()
                            self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                            self.wfile.flush()
                            time.sleep(outer.delay_s)
                        self.wfile.write(b"0\r\n\r\n")
                    except (BrokenPipeError, ConnectionResetError):
                        pass                            # the client gave up first: the test's business
                    return
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, args=(0.005,), daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


T0 = 1_757_800_800.0            # 2025-09-13 22:00:00 UTC, a round hour
OTBR = "core_openthread_border_router"
MATTER = "core_matter_server"


def otbr_lines(start=T0, n=120, step=30.0):
    return [(start + i * step, f"{i // 120}d.06:{i % 60:02d}:10.452 [I] Mac-----------: line {i}") for i in range(n)]


class FetchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dest = Path(self.tmp.name) / "ha-logs" / f"{OTBR}.log.gz"

    def tearDown(self):
        self.tmp.cleanup()

    def _lines(self):
        with gzip.open(self.dest, "rt") as fh:
            return fh.read().splitlines()

    def test_the_range_is_honoured_and_the_received_window_reported(self):
        srv = FakeSupervisor({OTBR: otbr_lines()})
        try:
            r = halogs.fetch_addon_log(srv.url, TOKEN, OTBR, T0 + 600, T0 + 1200, self.dest)
        finally:
            srv.close()
        req = srv.requests[0]
        self.assertEqual(req["path"], f"/api/hassio/addons/{OTBR}/logs?verbose")
        self.assertEqual((req["headers"]["range"], req["headers"]["accept"], req["headers"]["authorization"]),
                         (f"realtime={int(T0 + 600)}:{int(T0 + 1200)}", "text/plain", f"Bearer {TOKEN}"))
        self.assertEqual((r["slug"], r["file"], r["complete"], r["error"], r["http_status"], r["interrupted"]),
                         (OTBR, f"{OTBR}.log.gz", True, None, 200, False))
        self.assertEqual(r["requested"], [T0 + 600, T0 + 1200])
        self.assertEqual(r["received"], [T0 + 600, T0 + 1170])        # 22:10:00.000 to 22:19:30.000: [since, until)
        self.assertEqual((r["lines"], r["gap_before_s"]), (20, 0))
        self.assertGreater(r["bytes_gz"], 0)
        self.assertEqual(r["bytes_gz"], self.dest.stat().st_size)
        lines = self._lines()
        self.assertEqual(len(lines), 20)
        self.assertTrue(lines[0].startswith("2025-09-13 22:10:00.000 homeassistant "
                                            "app_core_openthread_border_router[697]: "))
        self.assertFalse(self.dest.with_suffix(".part").exists())

    def test_a_window_the_journal_has_rolled_past_is_complete_with_a_gap(self):
        srv = FakeSupervisor({OTBR: otbr_lines()}, retained_from=T0 + 1800)
        try:
            r = halogs.fetch_addon_log(srv.url, TOKEN, OTBR, T0, T0 + 3600, self.dest)
        finally:
            srv.close()
        self.assertTrue(r["complete"])
        self.assertEqual((r["received"][0], r["gap_before_s"]), (T0 + 1800, 1800))

    def test_an_empty_window_is_complete_and_keeps_an_empty_file(self):
        srv = FakeSupervisor({OTBR: otbr_lines()})
        try:
            r = halogs.fetch_addon_log(srv.url, TOKEN, OTBR, T0 - 7200, T0 - 3600, self.dest)
        finally:
            srv.close()
        self.assertEqual((r["complete"], r["lines"], r["received"], r["gap_before_s"]), (True, 0, [None, None], None))
        self.assertEqual(self._lines(), [])

    def test_continuation_lines_count_and_are_written_as_they_are(self):
        srv = FakeSupervisor({OTBR: [(T0, "first")]})
        # A traceback-style continuation has no journal prefix: the fake
        # cannot emit one through journal_line, so splice it in.
        srv.lines[OTBR] = [(T0, "first\n    continued without a prefix")]
        try:
            r = halogs.fetch_addon_log(srv.url, TOKEN, OTBR, T0, T0 + 60, self.dest)
        finally:
            srv.close()
        self.assertEqual((r["lines"], r["received"]), (2, [T0, T0]))
        self.assertEqual(self._lines()[1], "    continued without a prefix")

    def test_a_refusal_is_failed_with_the_status_and_no_file(self):
        srv = FakeSupervisor({OTBR: otbr_lines()})
        try:
            r = halogs.fetch_addon_log(srv.url, "tk_not_admin", OTBR, T0, T0 + 60, self.dest)
            missing = halogs.fetch_addon_log(srv.url, TOKEN, "core_nonsense", T0, T0 + 60, self.dest)
        finally:
            srv.close()
        self.assertEqual((r["http_status"], r["complete"], r["file"], r["lines"]), (401, False, None, 0))
        self.assertIn("HTTP 401", r["error"])
        self.assertIn("admin", r["error"])
        self.assertIn(OTBR, r["error"])
        self.assertNotIn("tk_not_admin", r["error"])
        self.assertFalse(self.dest.exists())
        self.assertFalse(self.dest.with_suffix(".part").exists())
        self.assertEqual((missing["http_status"], missing["file"]), (404, None))
        self.assertIn("no such add-on", missing["error"])

    def test_a_refused_connection_is_failed_and_names_the_host_not_the_token(self):
        srv = FakeSupervisor({})
        url = srv.url
        srv.close()                                   # nothing listens there now
        r = halogs.fetch_addon_log(url, TOKEN, OTBR, T0, T0 + 60, self.dest)
        self.assertEqual((r["complete"], r["file"], r["http_status"]), (False, None, None))
        self.assertIn(OTBR, r["error"])
        self.assertIn("127.0.0.1", r["error"])
        self.assertNotIn(TOKEN, r["error"])

    def test_a_redirect_is_refused_and_the_token_is_not_sent_on(self):
        collector = FakeSupervisor({OTBR: otbr_lines()})
        bounce = FakeSupervisor({}, redirect=collector.url + f"/api/hassio/addons/{OTBR}/logs?verbose")
        try:
            r = halogs.fetch_addon_log(bounce.url, TOKEN, OTBR, T0, T0 + 60, self.dest)
        finally:
            bounce.close()
            collector.close()
        self.assertEqual((r["http_status"], r["file"]), (302, None))
        self.assertIn("redirect", r["error"])
        self.assertEqual(collector.requests, [])
        self.assertNotIn(TOKEN, r["error"])

    def test_a_stream_too_slow_for_the_deadline_keeps_what_arrived_as_partial(self):
        srv = FakeSupervisor({OTBR: otbr_lines(n=40)}, delay_s=0.05)
        progress = []
        try:
            r = halogs.fetch_addon_log(srv.url, TOKEN, OTBR, T0, T0 + 3600, self.dest, deadline_s=0.4,
                                       progress=lambda *a: progress.append(a), progress_every_s=0.1)
        finally:
            srv.close()
        self.assertFalse(r["complete"])
        self.assertIn("deadline passed", r["error"])
        self.assertGreater(r["lines"], 3)
        self.assertLess(r["lines"], 40)
        self.assertEqual(r["file"], f"{OTBR}.log.gz")
        self.assertEqual(len(self._lines()), r["lines"])
        self.assertFalse(self.dest.with_suffix(".part").exists())
        self.assertGreaterEqual(len(progress), 2)
        self.assertEqual(progress[-1][0], OTBR)
        self.assertEqual(progress[-1][1], r["lines"])

    def test_a_silent_read_past_its_timeout_is_partial_too(self):
        srv = FakeSupervisor({OTBR: otbr_lines(n=6)}, delay_s=0.6)
        try:
            r = halogs.fetch_addon_log(srv.url, TOKEN, OTBR, T0, T0 + 3600, self.dest, read_timeout_s=0.2)
        finally:
            srv.close()
        self.assertFalse(r["complete"])
        self.assertIn("timed out", r["error"])
        self.assertIn("what arrived is kept", r["error"])

    def test_planted_secrets_are_scrubbed_in_every_spelling(self):
        hexkey = KEY.hex()
        planted = [(T0, f"key {hexkey} and {hexkey.upper()}"),
                   (T0 + 1, "colons " + ":".join(f"{b:02X}" for b in KEY)),
                   (T0 + 2, "reversed " + "".join(f"{b:02x}" for b in KEY[::-1])),
                   (T0 + 3, f"token {TOKEN} and an alerts.env value ntfy_hunter22"),
                   (T0 + 4, "innocent line with 00 11 in it")]
        secrets = halogs.secret_forms(KEY, TOKEN, ["ntfy_hunter22", "ab"])
        srv = FakeSupervisor({OTBR: planted})
        try:
            r = halogs.fetch_addon_log(srv.url, TOKEN, OTBR, T0, T0 + 60, self.dest, secrets=secrets)
        finally:
            srv.close()
        self.assertEqual(r["lines"], 5)
        text = "\n".join(self._lines())
        for leak in (hexkey, hexkey.upper(), "00:11:22", "ffeeddcc", TOKEN, "ntfy_hunter22"):
            self.assertNotIn(leak, text)
        self.assertEqual(text.count("<redacted>"), 6)
        self.assertIn("innocent line with 00 11 in it", text)
        self.assertNotIn("ab", secrets)                          # too short to scrub


class KnownSecretsTest(unittest.TestCase):
    def test_the_hosts_secrets_come_from_the_credentials_and_env_files(self):
        from threadwatch.config import Config
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "credentials.toml").write_text(f'[credentials]\nnetwork_key = "{KEY.hex()}"\n')
            (d / "alerts.env").write_text("NTFY_TOKEN=tk_ntfy_secret\nSHORT=ab\n")
            (d / "ha.env").write_text(f"HA_URL=http://ha.local:8123\nHA_TOKEN={TOKEN}\n")
            cfg = Config(data_dir=d / "data", config_dir=d, credentials_path=d / "credentials.toml")
            secrets = halogs.known_secrets(cfg)
            self.assertIn(KEY.hex(), secrets)
            self.assertIn(TOKEN, secrets)
            self.assertIn("tk_ntfy_secret", secrets)
            self.assertIn("http://ha.local:8123", secrets)
            self.assertNotIn("ab", secrets)
            # Without a credentials file the key is simply not among them.
            (d / "credentials.toml").unlink()
            self.assertNotIn(KEY.hex(), halogs.known_secrets(cfg))


class SnapshotLogsTest(unittest.TestCase):
    """The logs join a snapshot only after the ring copy is final, and
    nothing that goes wrong with them touches it."""

    def setUp(self):
        from threadwatch.config import Config
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "config.toml").write_text("[network]\nchannel = 25\n")
        self.cfg = Config(data_dir=d / "data", config_dir=d, devices_path=d / "devices.json")
        self.cfg.ha_logs_enabled = True
        self.cfg.ha_logs_addons = [OTBR, MATTER]
        self.cfg.ring_dir.mkdir(parents=True)
        # Ring files named by local hour: the window starts at the oldest one.
        self.hour = time.mktime(time.strptime("2025-09-13 15:00", "%Y-%m-%d %H:%M"))
        for h in ("2025-09-13 15", "2025-09-13 16"):
            name = time.strftime("threadwatch-%Y%m%d-%H.pcap", time.strptime(h, "%Y-%m-%d %H"))
            (self.cfg.ring_dir / name).write_bytes(b"ring bytes")
        self.now = self.hour + 3600 + 1800                                    # 16:30 local
        self.lines = {OTBR: [(self.hour + i * 60, f"otbr line {i}") for i in range(90)],
                      MATTER: [(self.hour + i * 300, f"matter line {i}") for i in range(18)]}

    def tearDown(self):
        self.tmp.cleanup()

    def _env(self, url, token=TOKEN):
        (self.cfg.config_dir / "ha.env").write_text(f"HA_URL={url}\nHA_TOKEN={token}\n")

    def _snapshot(self):
        from threadwatch.snapshot import save_snapshot
        dest, _n = save_snapshot(self.cfg, "storm", now=self.now)
        return dest

    def _bytes(self, dest):
        return {p.name: p.read_bytes() for p in dest.glob("*.pcap")}

    def test_logs_join_a_final_snapshot_and_the_manifest_lists_them(self):
        srv = FakeSupervisor(self.lines)
        self._env(srv.url)
        dest = self._snapshot()
        before = self._bytes(dest)
        try:
            status = halogs.attach_logs(self.cfg, dest, now=self.now + 5)
        finally:
            srv.close()
        self.assertEqual(status["status"], "complete")
        self.assertEqual(status["requested"], [self.hour, self.now])           # oldest hour's start .. saved_at
        self.assertEqual(status["attempts"], 1)
        self.assertEqual(sorted(status["addons"]), [MATTER, OTBR])
        self.assertEqual((status["addons"][OTBR]["file"], status["addons"][OTBR]["lines"],
                          status["addons"][OTBR]["source"]), (f"ha-logs/{OTBR}.log.gz", 90, "live"))
        self.assertEqual(json.loads((dest / "ha-logs.json").read_text())["status"], "complete")
        manifest = json.loads((dest / "manifest.json").read_text())
        self.assertIn(f"ha-logs/{OTBR}.log.gz", manifest["files"])
        self.assertIn("ha-logs.json", manifest["files"])
        self.assertNotIn("manifest.json", manifest["files"])
        self.assertEqual(manifest["ha_logs"]["status"], "complete")
        self.assertEqual(manifest["ha_logs"]["addons"][MATTER]["lines"], 18)
        self.assertNotIn("slug", manifest["ha_logs"]["addons"][MATTER])
        self.assertEqual(self._bytes(dest), before)                             # the ring copy is untouched
        self.assertFalse((dest / "ha-logs.lock").exists())
        for text in ((dest / "ha-logs.json").read_text(), json.dumps(manifest)):
            self.assertNotIn(TOKEN, text)
            self.assertNotIn(srv.url, text)

    def test_the_window_is_clamped_to_max_hours(self):
        self.cfg.ha_logs_max_hours = 1
        since, until = halogs.window(self._snapshot(), self.now + 100, self.cfg.ha_logs_max_hours, self.now)
        self.assertEqual((since, until), (self.now + 100 - 3600, self.now))

    def test_a_failed_fetch_leaves_the_snapshot_whole_and_the_retry_completes_it(self):
        srv = FakeSupervisor(self.lines, status=503)
        self._env(srv.url)
        dest = self._snapshot()
        before = self._bytes(dest)
        try:
            status = halogs.attach_logs(self.cfg, dest, now=self.now + 5)
            self.assertEqual((status["status"], status["attempts"]), ("failed", 1))
            self.assertIn("HTTP 503", status["reason"])
            self.assertFalse((dest / "ha-logs").exists() and any((dest / "ha-logs").iterdir()))
            manifest = json.loads((dest / "manifest.json").read_text())
            self.assertEqual(manifest["ha_logs"]["status"], "failed")
            self.assertEqual(manifest["ring_files"], 2)
            self.assertEqual(self._bytes(dest), before)
            # Not due yet, then due at 15 min: the pass re-requests the same window.
            self.assertEqual(halogs.retries_due(self.cfg, self.now + 600), [])
            self.assertEqual(halogs.retries_due(self.cfg, self.now + 900), [dest])
            srv.status = 200
            tried = halogs.retry_pending(self.cfg, self.now + 900)
        finally:
            srv.close()
        self.assertEqual([(d.name, st["status"], final) for d, st, final in tried], [(dest.name, "complete", True)])
        self.assertEqual(srv.requests[-1]["headers"]["range"], f"realtime={int(self.hour)}:{int(self.now)}")
        status = json.loads((dest / "ha-logs.json").read_text())
        self.assertEqual((status["status"], status["attempts"]), ("complete", 2))
        manifest = json.loads((dest / "manifest.json").read_text())
        self.assertEqual(manifest["ha_logs"]["attempts"], 2)
        self.assertIn(f"ha-logs/{OTBR}.log.gz", manifest["files"])
        self.assertEqual(halogs.retries_due(self.cfg, self.now + 3600), [])

    def test_retries_stop_after_three_or_once_the_journal_cannot_have_the_window(self):
        srv = FakeSupervisor({}, status=503)
        self._env(srv.url)
        dest = self._snapshot()
        try:
            halogs.attach_logs(self.cfg, dest, now=self.now)
            for at, expect in ((899, []), (900, [dest]), (3599, []), (3600, [dest]), (14399, []), (14400, [dest])):
                with self.subTest(at=at):
                    self.assertEqual(halogs.retries_due(self.cfg, self.now + at), expect)
                if expect:
                    _d, st, final = halogs.retry_pending(self.cfg, self.now + at)[0]
                    self.assertEqual(final, at == 14400)
            self.assertEqual(json.loads((dest / "ha-logs.json").read_text())["attempts"], 4)
            self.assertEqual(halogs.retries_due(self.cfg, self.now + 20000), [])
            # A younger snapshot that failed, but the journal window has gone.
            self.cfg.ha_logs_max_hours = 0.1
            (dest / "ha-logs.json").write_text(json.dumps({**halogs.read_status(dest), "attempts": 1}))
            self.assertEqual(halogs.retries_due(self.cfg, self.now + 900), [])
        finally:
            srv.close()

    def test_a_partial_fetch_retries_only_the_addons_that_are_not_whole(self):
        srv = FakeSupervisor({OTBR: self.lines[OTBR]})                          # the Matter slug is unknown: 404
        self._env(srv.url)
        dest = self._snapshot()
        try:
            status = halogs.attach_logs(self.cfg, dest, now=self.now)
            self.assertEqual(status["status"], "partial")
            self.assertTrue(status["addons"][OTBR]["complete"])
            self.assertEqual(status["addons"][MATTER]["http_status"], 404)
            srv.lines[MATTER] = self.lines[MATTER]
            n = len(srv.requests)
            halogs.retry_pending(self.cfg, self.now + 900)
        finally:
            srv.close()
        self.assertEqual([r["path"].split("/addons/")[1].split("/")[0] for r in srv.requests[n:]], [MATTER])
        self.assertEqual(json.loads((dest / "ha-logs.json").read_text())["status"], "complete")

    def test_a_fetch_the_recorder_died_in_is_recovered_as_partial_at_the_next_start(self):
        dest = self._snapshot()
        logs = dest / "ha-logs"
        logs.mkdir()
        with gzip.open(logs / f"{OTBR}.log.part", "wb") as gz:
            gz.write(journal_line(self.hour, "arrived before the stop").encode())
        (dest / "ha-logs.json").write_text(json.dumps({
            "status": "fetching", "reason": None, "saved_at": self.now, "requested": [self.hour, self.now],
            "attempts": 1, "addons": {OTBR: {"slug": OTBR, "file": None, "complete": False, "error": None},
                                      MATTER: {"slug": MATTER, "file": None, "complete": False, "error": None}}}))
        self.assertEqual(halogs.recover_interrupted(self.cfg.snapshots_dir), [dest.name])
        status = json.loads((dest / "ha-logs.json").read_text())
        self.assertEqual(status["status"], "partial")
        self.assertEqual((status["addons"][OTBR]["file"], status["addons"][OTBR]["complete"]),
                         (f"ha-logs/{OTBR}.log.gz", False))
        self.assertIn("stopped during the fetch", status["addons"][OTBR]["error"])
        self.assertIn("stopped before", status["addons"][MATTER]["error"])
        self.assertTrue((logs / f"{OTBR}.log.gz").exists())
        self.assertFalse((logs / f"{OTBR}.log.part").exists())
        manifest = json.loads((dest / "manifest.json").read_text())
        self.assertEqual(manifest["ha_logs"]["status"], "partial")
        self.assertIn(f"ha-logs/{OTBR}.log.gz", manifest["files"])
        self.assertEqual(halogs.recover_interrupted(self.cfg.snapshots_dir), [])      # once
        self.assertEqual(halogs.retries_due(self.cfg, self.now + 900), [dest])          # and the retry takes it

    def test_a_fetch_still_running_by_hand_is_left_alone_at_start(self):
        import os

        from threadwatch.snapshot import _take_lock
        dest = self._snapshot()
        (dest / "ha-logs.json").write_text(json.dumps({"status": "fetching", "addons": {}}))
        fd = _take_lock(dest / "ha-logs.lock", wait=True)
        try:
            self.assertEqual(halogs.recover_interrupted(self.cfg.snapshots_dir), [])
        finally:
            os.close(fd)
        self.assertEqual(json.loads((dest / "ha-logs.json").read_text())["status"], "fetching")

    def test_disabled_writes_nothing_and_no_token_is_skipped(self):
        dest = self._snapshot()
        self.cfg.ha_logs_enabled = False
        self.assertIsNone(halogs.attach_logs(self.cfg, dest, now=self.now))
        self.assertFalse((dest / "ha-logs.json").exists())
        self.assertNotIn("ha_logs", json.loads((dest / "manifest.json").read_text()))
        self.cfg.ha_logs_enabled = True                                          # no ha.env at all
        status = halogs.attach_logs(self.cfg, dest, now=self.now)
        self.assertEqual(status["status"], "skipped")
        self.assertIn("no token", status["reason"])
        manifest = json.loads((dest / "manifest.json").read_text())
        self.assertEqual(manifest["ha_logs"]["status"], "skipped")
        self.assertEqual(halogs.retries_due(self.cfg, self.now + 900), [])      # nothing to retry without a token

    def test_the_manifest_rewrite_never_lists_itself_and_survives_a_missing_manifest(self):
        from threadwatch.snapshot import rewrite_manifest
        dest = self._snapshot()
        (dest / "extra.txt").write_text("x")
        manifest = rewrite_manifest(dest, ha_logs={"status": "complete"})
        self.assertIn("extra.txt", manifest["files"])
        self.assertNotIn("manifest.json", manifest["files"])
        self.assertEqual(json.loads((dest / "manifest.json").read_text())["ha_logs"], {"status": "complete"})
        (dest / "manifest.json").unlink()
        self.assertIsNone(rewrite_manifest(dest, ha_logs={}))
        self.assertFalse((dest / "manifest.json").exists())


class RecorderLogsTest(unittest.TestCase):
    """The automatic path: the logs join the snapshot on the background
    copy thread and are reported through events.emit, never _emit, and
    the recorder's 15-minute pass retries what failed."""

    def setUp(self):
        from threadwatch.config import Config
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text("[]")
        self.cfg = Config(data_dir=d / "data", config_dir=d, devices_path=d / "devices.json")
        self.cfg.ha_logs_enabled = True
        self.cfg.ha_logs_addons = [OTBR]
        self.cfg.ring_dir.mkdir(parents=True)
        hour = time.strftime("threadwatch-%Y%m%d-%H.pcap", time.localtime(time.time() - 3600))
        (self.cfg.ring_dir / hour).write_bytes(b"ring")
        self.srv = FakeSupervisor({OTBR: [(time.time() - 1800 + i, f"line {i}") for i in range(30)]})
        (d / "ha.env").write_text(f"HA_URL={self.srv.url}\nHA_TOKEN={TOKEN}\n")

    def tearDown(self):
        self.srv.close()
        self.tmp.cleanup()

    def _pipe(self):
        from threadwatch.crypto import Decryptor
        from threadwatch.events import NullEventLog
        from threadwatch.pipeline import Pipeline
        pipe = Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)))
        pipe._emit = lambda *a, **kw: self.fail("a snapshot report went through _emit")
        return pipe

    @staticmethod
    def _events(pipe, name):
        return [r for r in pipe.events.records if r["event"] == name]

    def test_the_automatic_snapshot_gets_its_logs_and_says_so_through_events_emit(self):
        pipe = self._pipe()
        pipe._save_snapshot_now("auto-phase_locked_storm", "phase_locked_storm")
        saved = self._events(pipe, "snapshot_saved")
        self.assertEqual(len(saved), 1)
        logs = self._events(pipe, "snapshot_logs_saved")
        self.assertEqual(len(logs), 1)
        ev = logs[0]
        self.assertEqual((ev["severity"], ev["label"], ev["addons"], ev["lines"]),
                         ("info", "auto-phase_locked_storm", [OTBR], {OTBR: 30}))
        self.assertIn("30 lines of HA add-on log kept beside the packets", ev["note"])
        self.assertEqual(self._events(pipe, "snapshot_logs_failed"), [])
        dest = Path(saved[0]["path"])
        self.assertEqual(json.loads((dest / "ha-logs.json").read_text())["status"], "complete")
        for text in json.dumps(pipe.events.records):
            self.assertNotIn(TOKEN, text)

    def test_a_failed_fetch_is_a_notice_and_the_retry_pass_completes_it_later(self):
        self.srv.status = 503
        pipe = self._pipe()
        pipe._save_snapshot_now("auto-phase_locked_storm", "phase_locked_storm")
        failed = self._events(pipe, "snapshot_logs_failed")
        self.assertEqual(len(failed), 1)
        self.assertEqual((failed[0]["severity"], failed[0]["status"], failed[0]["addons"]),
                         ("notice", "failed", [OTBR]))
        self.assertIn("HTTP 503", failed[0]["errors"][0])
        self.assertIn("retries at 15 min, 1 h and 4 h", failed[0]["note"])
        dest = Path(self._events(pipe, "snapshot_saved")[0]["path"])
        # Fifteen minutes on: the pass runs on a thread and reports at the
        # next periodic pass.
        status = json.loads((dest / "ha-logs.json").read_text())
        status["saved_at"] = time.time() - 1000
        (dest / "ha-logs.json").write_text(json.dumps(status))
        self.srv.status = 200
        now = time.time()
        pipe._poll_ha_logs(now)
        self.assertIsNotNone(pipe._halogs_thread)
        pipe._halogs_thread.join(5)
        pipe._poll_ha_logs(now + 30)
        logs = self._events(pipe, "snapshot_logs_saved")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["label"], "auto-phase_locked_storm")
        self.assertIn("attempt 2", logs[0]["note"])
        self.assertEqual(json.loads((dest / "ha-logs.json").read_text())["status"], "complete")
        # Not before another HA_LOGS_RETRY_S.
        pipe._poll_ha_logs(now + 60)
        self.assertIsNone(pipe._halogs_thread)

    def test_a_fetch_cut_short_by_a_stop_is_recovered_at_the_next_start(self):
        pipe = self._pipe()
        pipe._save_snapshot_now("auto-phase_locked_storm", "phase_locked_storm")
        dest = Path(self._events(pipe, "snapshot_saved")[0]["path"])
        status = json.loads((dest / "ha-logs.json").read_text())
        status["status"] = "fetching"
        (dest / "ha-logs.json").write_text(json.dumps(status))
        self._pipe()                                                            # a start
        self.assertEqual(json.loads((dest / "ha-logs.json").read_text())["status"], "complete")

    def test_off_means_no_fetch_no_thread_and_no_report(self):
        self.cfg.ha_logs_enabled = False
        pipe = self._pipe()
        pipe._save_snapshot_now("auto-phase_locked_storm", "phase_locked_storm")
        self.assertEqual(self._events(pipe, "snapshot_logs_saved") + self._events(pipe, "snapshot_logs_failed"), [])
        self.assertEqual(self.srv.requests, [])
        pipe.periodic(time.time())
        self.assertIsNone(pipe._halogs_thread)


class ArchiveTest(unittest.TestCase):
    """The hourly archive: each whole UTC hour fetched once, just after it
    ends, catch-up after an outage with one request per pass while HA is
    down, hours that roll out of the journal marked lost, retention like
    the ring's, and snapshots built from archive hours plus a live
    remainder."""

    # 2025-09-13 22:00:00 UTC: the archive names hours in UTC.
    H22 = T0

    def setUp(self):
        from threadwatch.config import Config
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        self.cfg = Config(data_dir=d / "data", config_dir=d, devices_path=d / "devices.json")
        self.cfg.ha_logs_enabled = True
        self.cfg.ha_logs_archive = True
        self.cfg.ha_logs_addons = [OTBR, MATTER]
        self.cfg.ha_logs_max_hours = 6
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
        # Six hours of journal, 16:00 to 22:00 UTC, a line every ten minutes.
        self.lines = {OTBR: [(self.H22 - 6 * 3600 + i * 600, f"otbr {i}") for i in range(37)],
                      MATTER: [(self.H22 - 6 * 3600 + i * 600, f"matter {i}") for i in range(37)]}
        self.srv = FakeSupervisor(self.lines)
        (d / "ha.env").write_text(f"HA_URL={self.srv.url}\nHA_TOKEN={TOKEN}\n")
        self.settings = (self.srv.url, TOKEN)

    def tearDown(self):
        self.srv.close()
        self.tmp.cleanup()

    def _pass(self, now, **kw):
        return halogs.archive_pass(self.cfg, now, self.settings, **kw)

    def _hours(self, slug=OTBR):
        return halogs.archived_hours(self.cfg, slug)

    def _requests(self, since=0):
        return [(r["path"].split("/addons/")[1].split("/")[0], r["headers"]["range"])
                for r in self.srv.requests[since:]]

    def test_hour_names_are_utc_and_the_span_covers_every_hour_touched(self):
        self.assertEqual(halogs.hour_name(self.H22 + 59), "20250913-22")
        self.assertEqual(halogs.hour_start("20250913-22"), self.H22)
        self.assertEqual(halogs.hours_between(self.H22 - 1800, self.H22 + 3601),
                         ["20250913-21", "20250913-22", "20250913-23"])
        self.assertEqual(halogs.hours_between(self.H22, self.H22), [])

    def test_the_first_pass_archives_the_window_and_each_later_one_the_hour_just_ended(self):
        # First pass at 22:02: the hours inside max_hours that have ended,
        # 16:00 to 21:00, oldest first, for each add-on.
        out = self._pass(self.H22 + 120)
        self.assertEqual(out["archived"], [f"{OTBR}/20250913-{h}" for h in range(16, 22)]
                         + [f"{MATTER}/20250913-{h}" for h in range(16, 22)])
        self.assertEqual((out["lost"], out["pending"], out["failed"], out["events"]), ([], [], None, []))
        self.assertEqual(self._hours(), [f"20250913-{h}" for h in range(16, 22)])
        self.assertEqual(self._requests()[0], (OTBR, f"realtime={int(self.H22 - 6 * 3600)}:{int(self.H22 - 5 * 3600)}"))
        state = json.loads((self.cfg.state_dir / "ha-logs-archive.json").read_text())
        self.assertEqual(state["addons"][OTBR]["last_archived"], "20250913-21")
        with gzip.open(self.cfg.data_dir / "ha-logs" / OTBR / "20250913-21.log.gz", "rt") as fh:
            self.assertEqual(len(fh.read().splitlines()), 6)
        # 22:00 is not whole until 23:02. A pass at 23:01 does nothing; at 23:02 it takes 22:00.
        n = len(self.srv.requests)
        self.assertEqual(self._pass(self.H22 + 3600 + 60)["archived"], [])
        self.assertEqual(len(self.srv.requests), n)
        out = self._pass(self.H22 + 3600 + 120)
        self.assertEqual(out["archived"], [f"{OTBR}/20250913-22", f"{MATTER}/20250913-22"])
        self.assertEqual(halogs.archive_status(self.cfg)[OTBR],
                         {"last_archived": "20250913-22", "hours_on_disk": 7, "pending": [], "lost": []})

    def test_while_ha_is_down_each_pass_sends_one_request_and_the_catch_up_is_oldest_first(self):
        self._pass(self.H22 + 120)
        self.srv.status = 503
        n = len(self.srv.requests)
        # Three hours go by with HA down: each 15-minute pass probes once.
        t = self.H22 + 3600 + 120
        for k in range(12):
            out = self._pass(t + k * 900)
            self.assertIsNotNone(out["failed"])
            self.assertEqual(len(self.srv.requests), n + k + 1, k)
        self.assertEqual(self._requests(n)[0], (OTBR, f"realtime={int(self.H22)}:{int(self.H22 + 3600)}"))
        self.assertEqual(sorted(out["pending"]),
                         sorted([f"{OTBR}/20250913-22", f"{OTBR}/20250913-23", f"{OTBR}/20250914-00",
                                 f"{MATTER}/20250913-22", f"{MATTER}/20250913-23", f"{MATTER}/20250914-00"]))
        state = halogs.load_archive_state(self.cfg)
        self.assertEqual(state["addons"][OTBR]["pending"]["20250913-22"]["attempts"], 12)
        self.assertIn("HTTP 503", state["addons"][OTBR]["pending"]["20250913-22"]["last_error"])
        self.assertEqual(state["addons"][MATTER]["pending"], {})          # never asked while the first slug fails
        # HA is back at 02:02: one pass catches every missed hour up (01:00
        # has ended by now too), oldest first, then the other add-on.
        self.srv.status = 200
        n = len(self.srv.requests)
        out = self._pass(t + 12 * 900)
        self.assertEqual(out["archived"], [f"{OTBR}/20250913-{h}" for h in ("22", "23")]
                         + [f"{OTBR}/20250914-0{h}" for h in (0, 1)]
                         + [f"{MATTER}/20250913-{h}" for h in ("22", "23")]
                         + [f"{MATTER}/20250914-0{h}" for h in (0, 1)])
        self.assertEqual(out["pending"], [])
        self.assertEqual(halogs.load_archive_state(self.cfg)["addons"][OTBR]["pending"], {})

    def test_exactly_one_stalled_per_outage_and_one_resumed_at_its_end(self):
        self._pass(self.H22 + 120)
        self.srv.status = 503
        t = self.H22 + 3600 + 120
        events = []
        for k in range(9):                                         # two hours of failures
            events += self._pass(t + k * 900)["events"]
        self.assertEqual([(e[0], e[1]) for e in events], [("ha_logs_archive_stalled", "notice")])
        stalled = events[0][2]
        self.assertEqual((stalled["addons"], stalled["since"]), (sorted([OTBR, MATTER]), t))
        self.assertIn(f"{OTBR}/20250913-22", stalled["pending_hours"])
        self.assertIn("HTTP 503", stalled["last_error"])
        self.assertIn("pending for 60 min", stalled["note"])
        self.srv.status = 200
        out = self._pass(t + 9 * 900)
        self.assertEqual([(e[0], e[1]) for e in out["events"]], [("ha_logs_archive_resumed", "info")])
        resumed = out["events"][0][2]
        self.assertEqual((len(resumed["archived"]), resumed["lost"], resumed["since"]), (6, [], t))   # 22, 23, 00 each
        self.assertIn("caught up after 135 min", resumed["note"])
        self.assertIn("nothing lost", resumed["note"])
        self.assertEqual(self._pass(t + 10 * 900)["events"], [])     # and nothing more
        self.assertEqual(halogs.load_archive_state(self.cfg)["outage"], {})

    def test_an_hour_that_rolls_out_of_the_journal_while_pending_is_lost_not_retried(self):
        self._pass(self.H22 + 120)
        self.srv.status = 503
        t = self.H22 + 3600 + 120
        for k in range(24):                                        # six hours down
            out = self._pass(t + k * 900)
        self.srv.status = 200
        self.srv.retained_from = self.H22 + 3600                   # the journal really has dropped 22:00
        # 05:02: the window starts at 23:02, so the whole of 22:00 is
        # beyond it and is lost; 23:00 onwards is fetched.
        out = self._pass(t + 24 * 900)
        self.assertEqual(out["lost"], [f"{OTBR}/20250913-22", f"{MATTER}/20250913-22"])
        self.assertEqual([a for a in out["archived"] if a.startswith(OTBR)],
                         [f"{OTBR}/20250913-23", f"{OTBR}/20250914-00", f"{OTBR}/20250914-01", f"{OTBR}/20250914-02",
                          f"{OTBR}/20250914-03", f"{OTBR}/20250914-04"])
        state = halogs.load_archive_state(self.cfg)
        self.assertIn("rolled out of the journal", state["addons"][OTBR]["lost"]["20250913-22"]["reason"])
        self.assertEqual(state["addons"][OTBR]["lost"]["20250913-22"]["attempts"], 24)
        self.assertNotIn("20250913-22", state["addons"][OTBR]["pending"])
        self.assertEqual(out["events"][0][2]["lost"], out["lost"])
        self.assertEqual(halogs.archive_status(self.cfg)[OTBR]["lost"], ["20250913-22"])
        # Gone is gone: the next pass asks for nothing about it.
        n = len(self.srv.requests)
        self._pass(t + 25 * 900)
        self.assertFalse(any(rng.startswith(f"realtime={int(self.H22)}:") for _s, rng in self._requests(n)))

    def test_a_recorder_that_was_off_for_longer_than_the_window_records_the_gap_as_lost(self):
        self._pass(self.H22 + 120)
        # Twelve hours later, first pass after the outage: the six hours the
        # journal cannot have are lost, the six it can are fetched.
        self.srv.lines = {s: [(self.H22 + 12 * 3600 - i * 600, f"{s} {i}") for i in range(37)] for s in (OTBR, MATTER)}
        out = self._pass(self.H22 + 12 * 3600 + 120)
        self.assertEqual([x for x in out["lost"] if x.startswith(OTBR)],
                         [f"{OTBR}/20250913-22", f"{OTBR}/20250913-23"] + [f"{OTBR}/20250914-0{h}" for h in range(4)])
        self.assertEqual([x for x in out["archived"] if x.startswith(OTBR)],
                         [f"{OTBR}/20250914-0{h}" for h in range(4, 10)])

    def test_retention_keeps_the_newest_keep_hours_per_addon_and_an_optional_byte_cap(self):
        for slug in (OTBR, MATTER):
            d = self.cfg.data_dir / "ha-logs" / slug
            d.mkdir(parents=True)
            for h in range(10):
                (d / f"2025091{h // 24}-{h % 24:02d}.log.gz").write_bytes(b"z" * 100)
        removed = halogs.prune_archive(self.cfg, keep_hours=4)
        self.assertEqual(removed, [f"{OTBR}/20250910-0{h}" for h in range(6)]
                         + [f"{MATTER}/20250910-0{h}" for h in range(6)])
        self.assertEqual(self._hours(), [f"20250910-0{h}" for h in range(6, 10)])
        removed = halogs.prune_archive(self.cfg, keep_hours=4, keep_bytes=500)
        self.assertEqual(len(removed), 3)                                   # 8 files of 100 bytes down to 5
        self.assertEqual(removed[0], f"{OTBR}/20250910-06")                # oldest hour first, whichever add-on
        self.assertEqual(halogs.prune_archive(self.cfg), [])               # keep_hours is 168: nothing to do

    def test_a_snapshot_with_the_archive_on_copies_its_hours_and_fetches_only_the_rest_live(self):
        from threadwatch.snapshot import save_snapshot
        self._pass(self.H22 + 120)                                          # 16:00-21:00 archived
        # Two ring files, local hours covering 20:30 to 22:30 UTC. Force the
        # pcap names from UTC so the test holds in any zone.
        self.cfg.ring_dir.mkdir(parents=True)
        for utc in (self.H22 - 3600 - 1800, self.H22 - 1800, self.H22 + 1800):
            (self.cfg.ring_dir / time.strftime("threadwatch-%Y%m%d-%H.pcap", time.localtime(utc))).write_bytes(b"r")
        saved = self.H22 + 1800
        dest, _n = save_snapshot(self.cfg, "storm", now=saved)
        n = len(self.srv.requests)
        status = halogs.attach_logs(self.cfg, dest, now=saved + 5)
        self.assertEqual(status["status"], "complete")
        otbr = status["addons"][OTBR]
        self.assertEqual(otbr["source"], "archive+live")
        hours = otbr["hours"]
        span_start = time.mktime(time.strptime(
            sorted(dest.glob("threadwatch-*.pcap"))[0].name[12:23], "%Y%m%d-%H"))
        expected = halogs.hours_between(span_start, saved)
        self.assertEqual(list(hours), expected)
        self.assertEqual([h for h, v in hours.items() if v["source"] == "live"], ["20250913-22"])
        for h, v in hours.items():
            if h != "20250913-22":
                self.assertEqual((v["source"], v["complete"]), ("archive", True), h)
                self.assertTrue((dest / v["file"]).exists())
        live = hours["20250913-22"]
        self.assertEqual((live["complete"], live["lines"], live["file"]),
                         (True, 1, f"ha-logs/{OTBR}/20250913-22.log.gz"))      # the journal's one line at 22:00
        # Live requests: one per add-on, for the partial hour only.
        self.assertEqual(self._requests(n), [(OTBR, f"realtime={int(self.H22)}:{int(saved)}"),
                                             (MATTER, f"realtime={int(self.H22)}:{int(saved)}")])
        self.assertEqual((otbr["archived"], otbr["live"], otbr["lost"]), (len(expected) - 1, 1, []))
        manifest = json.loads((dest / "manifest.json").read_text())
        self.assertEqual(manifest["ha_logs"]["addons"][OTBR]["hours"]["20250913-21"]["source"], "archive")
        self.assertIn(f"ha-logs/{OTBR}/20250913-21.log.gz", manifest["files"])

    def test_a_snapshot_records_pending_and_lost_hours_and_the_retry_fetches_the_pending_one(self):
        from threadwatch.snapshot import save_snapshot
        self._pass(self.H22 + 120)
        self.cfg.ring_dir.mkdir(parents=True)
        for utc in (self.H22 - 3 * 3600, self.H22 + 1800):
            (self.cfg.ring_dir / time.strftime("threadwatch-%Y%m%d-%H.pcap", time.localtime(utc))).write_bytes(b"r")
        # 20:00 is pending (HA was down for it) and 19:00 lost.
        (self.cfg.data_dir / "ha-logs" / OTBR / "20250913-20.log.gz").unlink()
        (self.cfg.data_dir / "ha-logs" / OTBR / "20250913-19.log.gz").unlink()
        state = halogs.load_archive_state(self.cfg)
        state["addons"][OTBR]["pending"]["20250913-20"] = {"attempts": 3, "last_error": "HTTP 503"}
        state["addons"][OTBR]["lost"]["20250913-19"] = {"reason": "rolled out of the journal", "ts": self.H22}
        halogs.save_archive_state(self.cfg, state)
        saved = self.H22 + 1800
        dest, _n = save_snapshot(self.cfg, "storm", now=saved)
        self.srv.status = 503
        status = halogs.attach_logs(self.cfg, dest, now=saved + 5)
        self.assertEqual(status["status"], "partial")
        hours = status["addons"][OTBR]["hours"]
        self.assertEqual((hours["20250913-19"]["source"], hours["20250913-19"]["complete"]), ("lost", True))
        self.assertEqual((hours["20250913-20"]["source"], hours["20250913-20"]["complete"]), ("live", False))
        self.assertEqual((hours["20250913-22"]["source"], hours["20250913-22"]["complete"]), ("live", False))
        self.assertEqual(hours["20250913-21"]["source"], "archive")
        self.srv.status = 200
        n = len(self.srv.requests)
        halogs.retry_pending(self.cfg, saved + 900)
        self.assertEqual(sorted(self._requests(n)),
                         sorted([(OTBR, f"realtime={int(self.H22 - 7200)}:{int(self.H22 - 3600)}"),
                                 (OTBR, f"realtime={int(self.H22)}:{int(saved)}"),
                                 (MATTER, f"realtime={int(self.H22)}:{int(saved)}")]))
        status = halogs.read_status(dest)
        self.assertEqual(status["status"], "complete")
        self.assertEqual(status["addons"][OTBR]["hours"]["20250913-20"]["complete"], True)


class RecorderArchiveTest(unittest.TestCase):
    """The recorder's side of the archive: a pass on a thread after each
    hour, its events through events.emit, its status entry, and doctor's
    view of it."""

    def setUp(self):
        from threadwatch.config import Config
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text("[]")
        self.cfg = Config(data_dir=d / "data", config_dir=d, devices_path=d / "devices.json")
        self.cfg.ha_logs_enabled = True
        self.cfg.ha_logs_archive = True
        self.cfg.ha_logs_addons = [OTBR]
        self.cfg.ha_logs_max_hours = 3
        now = time.time()
        self.srv = FakeSupervisor({OTBR: [(now - 3 * 3600 + i * 600, f"line {i}") for i in range(19)]})
        (d / "ha.env").write_text(f"HA_URL={self.srv.url}\nHA_TOKEN={TOKEN}\n")

    def tearDown(self):
        self.srv.close()
        self.tmp.cleanup()

    def _pipe(self):
        from threadwatch.crypto import Decryptor
        from threadwatch.events import NullEventLog
        from threadwatch.pipeline import Pipeline
        pipe = Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)))
        pipe._emit = lambda *a, **kw: self.fail("an archive report went through _emit")
        return pipe

    def _run_pass(self, pipe, now):
        pipe._poll_ha_archive(now)
        self.assertIsNotNone(pipe._archive_thread)
        pipe._archive_thread.join(10)
        pipe._poll_ha_archive(now + 1)

    def test_the_pass_runs_on_a_thread_and_the_status_entry_follows_it(self):
        pipe = self._pipe()
        self.assertEqual(pipe.ha_logs_archive_status()[OTBR]["last_archived"], None)
        now = time.time()
        self._run_pass(pipe, now)
        status = pipe.ha_logs_archive_status()[OTBR]
        self.assertEqual(status["last_archived"], halogs.hour_name(now - 3600 - 120))
        self.assertGreaterEqual(status["hours_on_disk"], 2)
        self.assertEqual((status["pending"], status["lost"]), ([], []))
        self.assertEqual([r["event"] for r in pipe.events.records if r["event"].startswith("ha_logs")], [])
        # Not again before the next hour boundary.
        n = len(self.srv.requests)
        pipe._poll_ha_archive(now + 60)
        self.assertIsNone(pipe._archive_thread)
        self.assertEqual(len(self.srv.requests), n)
        self.assertEqual(pipe._next_archive, (int(now // 3600) + 1) * 3600 + halogs.ARCHIVE_GRACE_S)

    def test_an_outage_is_said_once_and_its_end_once_through_events_emit(self):
        pipe = self._pipe()
        now = time.time()
        self._run_pass(pipe, now)
        self.srv.status = 503
        pipe._next_archive = 0.0
        self._run_pass(pipe, now + 3600 + 120)                      # the hour just ended fails: pending
        self.assertEqual(pipe.ha_logs_archive_status()[OTBR]["pending"], [halogs.hour_name(now)])
        self.assertLessEqual(pipe._next_archive, now + 3600 + 121 + halogs.ARCHIVE_RETRY_S)   # pulled forward
        for k in range(1, 5):                                       # an hour of 15-minute passes
            pipe._next_archive = 0.0
            self._run_pass(pipe, now + 3600 + 120 + k * 900)
        stalled = [r for r in pipe.events.records if r["event"] == "ha_logs_archive_stalled"]
        self.assertEqual(len(stalled), 1)
        self.assertEqual((stalled[0]["severity"], stalled[0]["addons"]), ("notice", [OTBR]))
        self.srv.status = 200
        pipe._next_archive = 0.0
        self._run_pass(pipe, now + 3600 + 120 + 5 * 900)
        resumed = [r for r in pipe.events.records if r["event"] == "ha_logs_archive_resumed"]
        self.assertEqual(len(resumed), 1)
        self.assertEqual(resumed[0]["severity"], "info")
        self.assertEqual(pipe.ha_logs_archive_status()[OTBR]["pending"], [])
        for text in json.dumps(pipe.events.records):
            self.assertNotIn(TOKEN, text)

    def test_doctor_warns_when_the_archive_is_behind_and_the_status_page_shows_it(self):
        from threadwatch import doctor
        from threadwatch.web import Site
        now = time.time()
        checks = doctor.check_ha_logs(self.cfg, now=now)
        self.assertEqual([c[0] for c in checks], ["ok", "warn"])             # the probe, then the empty archive
        self.assertIn("nothing yet", checks[1][2])
        pipe = self._pipe()
        self._run_pass(pipe, now)
        checks = doctor.check_ha_logs(self.cfg, now=now)
        self.assertEqual([c[0] for c in checks], ["ok", "ok"])
        self.assertIn("archive up to", checks[1][2])
        checks = doctor.check_ha_logs(self.cfg, now=now + 4 * 3600)
        self.assertEqual(checks[1][0], "warn")
        self.assertIn("has not kept up", checks[1][2])
        (self.cfg.state_dir / "status.json").write_text(json.dumps({
            "updated": now, "last_frame_age_s": 1,
            "ha_logs_archive": {OTBR: {"last_archived": "20250913-21", "hours_on_disk": 6,
                                        "pending": ["20250913-22"], "lost": ["20250913-15"]}}}))
        body = Site(self.cfg).status_page()
        self.assertIn("<th>HA log archive</th>", body)
        self.assertIn(f"{OTBR}: up to 20250913-21 UTC", body)
        self.assertIn('<span class="warn">1 pending</span>', body)
        self.assertIn('<span class="bad">1 lost</span> <span class="muted">(20250913-15)</span>', body)

    def test_with_the_archive_off_nothing_runs_and_status_is_null(self):
        self.cfg.ha_logs_archive = False
        pipe = self._pipe()
        pipe.periodic(time.time())
        self.assertIsNone(pipe._archive_thread)
        self.assertIsNone(pipe.ha_logs_archive_status())
        self.assertEqual(self.srv.requests, [])


if __name__ == "__main__":
    unittest.main()
