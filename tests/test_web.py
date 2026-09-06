"""The HTTP server itself: what it does with a connection, not what the
pages say (that is test_review)."""

import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.config import Config  # noqa: E402
from threadwatch.web import make_server  # noqa: E402


class BindDefaultTest(unittest.TestCase):
    """The pages have no authentication and publish the household's device
    inventory and a per-room, per-hour occupancy trace, so reaching them
    from another machine is a deliberate act, not the default."""

    def test_nothing_serves_the_lan_until_the_operator_says_so(self):
        from threadwatch import web
        from threadwatch.config import Config, REPO_ROOT
        import inspect
        import tomllib
        self.assertEqual(Config().web_bind, "127.0.0.1")
        self.assertEqual(inspect.signature(web.serve).parameters["bind"].default, "127.0.0.1")
        example = tomllib.loads((REPO_ROOT / "config" / "config.example.toml").read_text())
        self.assertEqual(example["web"]["bind"], "127.0.0.1")
        published = [line.strip().lstrip("- ").strip('"')
                     for line in (REPO_ROOT / "compose.yaml").read_text().splitlines()
                     if line.strip().startswith("- ") and ":8080" in line and not line.strip().startswith("#")]
        self.assertEqual(published, ["127.0.0.1:8080:8080"])


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
        self.httpd.RequestHandlerClass.timeout = 0.2      # the shipped 30 s, sped up
        before = threading.active_count()
        socks = []
        try:
            for _ in range(5):
                s = socket.create_connection(("127.0.0.1", self.httpd.server_port), timeout=5)
                socks.append(s)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and threading.active_count() > before:
                time.sleep(0.05)
            self.assertEqual(threading.active_count(), before)
            for s in socks:
                self.assertEqual(s.recv(1), b"")          # the server closed its end
        finally:
            for s in socks:
                s.close()


if __name__ == "__main__":
    unittest.main()
