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
