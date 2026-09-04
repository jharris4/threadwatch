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


if __name__ == "__main__":
    unittest.main()
