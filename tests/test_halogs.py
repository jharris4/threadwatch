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


if __name__ == "__main__":
    unittest.main()
