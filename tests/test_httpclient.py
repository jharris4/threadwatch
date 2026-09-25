"""httpclient: the one opener every credentialed call goes through, and
the redaction that keeps what it carried out of the journal."""

import sys
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests  # noqa: F401  (the mDNS guard, installed on a direct run too: tests/no_lan)
from threadwatch import httpclient


class _Redirector:
    """Answers every request with a 302 to ``target``, and records what
    reached it."""

    def __init__(self, target: str):
        self.requests = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append({k.lower(): v for k, v in self.headers.items()})
                self.send_response(302)
                self.send_header("Location", target)
                self.end_headers()

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, args=(0.005,), daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class OpenerTest(unittest.TestCase):
    def test_a_redirect_is_an_error_and_the_token_never_follows_it(self):
        sink = _Redirector("http://127.0.0.1:1/")     # nothing listens there; it must never be asked
        bounce = _Redirector(sink.url + "/collect")
        try:
            req = urllib.request.Request(bounce.url + "/api", headers={"Authorization": "Bearer tk_SECRET"})
            with self.assertRaises(urllib.error.HTTPError) as cm:
                httpclient.urlopen(req, timeout=2)
            self.assertEqual(cm.exception.code, 302)
            self.assertTrue(cm.exception.fp.closed)          # its socket is not left for the collector
            self.assertEqual(len(bounce.requests), 1)
            self.assertEqual(bounce.requests[0]["authorization"], "Bearer tk_SECRET")
            self.assertEqual(sink.requests, [])
        finally:
            bounce.close()
            sink.close()

    def test_redaction_keeps_hosts_and_drops_everything_else(self):
        self.assertEqual(httpclient.redact_url("http://u:pw@ha.local:8123/api/hassio/addons/x/logs?verbose"),
                         "http://ha.local:8123/...")
        self.assertEqual(httpclient.redact_url("nonsense"), "<url>")
        text = httpclient.redact_text("GET http://ha.local:8123/api/x failed, Authorization: Bearer tk_9 (tk_9)",
                                      secrets=("tk_9x", "ab"))
        self.assertNotIn("api/x", text)
        self.assertNotIn("tk_9", text.split("(")[0])
        self.assertEqual(httpclient.redact_text("token abcdefgh here", secrets=("abcdefgh",)),
                         "token <redacted> here")
        self.assertEqual(httpclient.redact_text("ab is short", secrets=("ab",)), "ab is short")


if __name__ == "__main__":
    unittest.main()
