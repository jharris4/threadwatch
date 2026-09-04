"""status.json as the capture daemon writes it, and what a later run reads back."""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.capture import _write_status, last_frame_on_record  # noqa: E402
from threadwatch.config import Config  # noqa: E402
from threadwatch.crypto import Decryptor  # noqa: E402
from threadwatch.events import NullEventLog  # noqa: E402
from threadwatch.pipeline import Pipeline  # noqa: E402


class StatusFileTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config(data_dir=Path(self.tmp.name) / "data")
        self.pipe = Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)), ephemeral=True)
        self.ring = SimpleNamespace(current_path=self.cfg.ring_dir / "threadwatch-20260904-10.pcap")

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, **kw):
        _write_status(self.cfg, "/dev/x", 12, time.time() - 100, self.pipe, self.ring, self.pipe.decryptor, **kw)
        return json.loads((self.cfg.state_dir / "status.json").read_text())

    def test_last_frame_stamp_is_written_and_read_back(self):
        self.assertIsNone(last_frame_on_record(self.cfg.state_dir))      # no file yet
        st = self._write(last_frame_age=170.0)                            # a run that heard nothing
        self.assertEqual((st["last_frame_age_s"], st["last_frame_ts"], st["frames_total"]), (170.0, None, 12))
        self.assertIsNone(last_frame_on_record(self.cfg.state_dir))
        heard = time.time() - 7200
        st = self._write(last_frame_age=170.0, last_frame_ts=heard)      # carried from an earlier run
        self.assertEqual(st["last_frame_ts"], heard)
        self.assertEqual(last_frame_on_record(self.cfg.state_dir), heard)
        self.assertEqual(st["current_file"], str(self.ring.current_path))
        (self.cfg.state_dir / "status.json").write_text("{not json")
        self.assertIsNone(last_frame_on_record(self.cfg.state_dir))


class StatusConsumersTest(unittest.TestCase):
    """One status.json, written by the daemon and read by everything that
    reads it: the web header and status page, doctor, and `threadwatch
    status`. Each consumer used to be tested against a fixture of its own,
    so the writer and the readers could drift apart unnoticed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        (self.d / "config.toml").write_text(f'[capture]\ndata_dir = "{self.d / "data"}"\n')
        self.cfg = Config(data_dir=self.d / "data")
        self.pipe = Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)), ephemeral=True)
        self.ring = SimpleNamespace(current_path=self.cfg.ring_dir / "threadwatch-20260904-10.pcap")

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_written_file_is_the_file_every_consumer_reads(self):
        import contextlib
        import io
        from threadwatch.cli import main
        from threadwatch.doctor import OK, WARN, check_daemon
        from threadwatch.web import Site
        self.pipe.decryptor.stats["mac_decrypted"] = 41
        now = time.time()
        # A run that is alive but has heard nothing for a while: the state
        # where each consumer has something of its own to say.
        _write_status(self.cfg, "/dev/tty.usbmodem1", 4210, now - 3600, self.pipe,
                      self.ring, self.pipe.decryptor, last_frame_age=170.0, last_frame_ts=now - 170)
        st = json.loads((self.cfg.state_dir / "status.json").read_text())
        self.assertEqual(sorted(st), ["channel", "crypto", "current_file", "detector", "devices_tracked",
                                      "frames_total", "last_frame_age_s", "last_frame_ts", "partition",
                                      "port", "updated", "uptime_s"])
        self.assertEqual(sorted(st["crypto"]), sorted([*self.pipe.decryptor.stats, "key_sequence"]))

        site = Site(self.cfg)
        self.assertEqual(site.status(), st)
        header = site.header()
        self.assertIn("no frames for", header)          # last_frame_age_s, not "capturing"
        self.assertIn("<b>4,210</b> frames", header)
        self.assertIn(f'ch {self.cfg.channel}', header)
        self.assertIn("41 decrypted", header)
        page = site.status_page()
        self.assertIn("threadwatch-20260904-10.pcap", page)
        self.assertIn("/dev/tty.usbmodem1", page)
        self.assertIn("mac_decrypted 41", page)         # every crypto key is printed by name

        self.assertEqual(check_daemon(self.cfg, now)[0][:2], (WARN, "capture"))
        self.assertIn("no frames for 170 s", check_daemon(self.cfg, now)[0][2])
        # ...and it reads as healthy once a frame has just arrived.
        _write_status(self.cfg, "/dev/tty.usbmodem1", 4211, now - 3600, self.pipe,
                      self.ring, self.pipe.decryptor, last_frame_age=1.0, last_frame_ts=now - 1)
        self.assertEqual(check_daemon(self.cfg, now)[0][:2], (OK, "capture"))
        self.assertIn("capturing", Site(self.cfg).header())

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main(["--config", str(self.d / "config.toml"), "status"])
        printed = json.loads(out.getvalue())
        self.assertEqual(code, 0)
        self.assertTrue(printed["daemon_alive"])
        self.assertEqual({k: v for k, v in printed.items()
                          if k not in ("status_age_s", "daemon_alive")},
                         json.loads((self.cfg.state_dir / "status.json").read_text()))


if __name__ == "__main__":
    unittest.main()
