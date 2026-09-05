"""config.toml values that must be refused rather than quietly misread."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch import config as config_mod  # noqa: E402
from threadwatch.capture import RingWriter  # noqa: E402


class KeepGbTest(unittest.TestCase):
    def _load(self, text):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "config.toml"
            path.write_text(text)
            return config_mod.load(path)

    def test_a_positive_cap_is_bytes(self):
        self.assertEqual(self._load("[capture]\nkeep_gb = 4\n").keep_bytes, 4 * 1024 ** 3)
        self.assertEqual(self._load("[capture]\nkeep_gb = 0.5\n").keep_bytes, 512 * 1024 ** 2)
        self.assertIsNone(self._load("[capture]\nkeep_files = 24\n").keep_bytes)

    def test_a_negative_or_zero_cap_is_refused_not_a_ring_of_one_file(self):
        # A negative keep_bytes makes RingWriter._prune's "while total >
        # keep_bytes" true for every total: one file left at every rotation.
        for bad in ("-5", "0", "-0.1"):
            with self.assertRaises(ValueError) as cm:
                self._load(f"[capture]\nkeep_gb = {bad}\n")
            self.assertIn("keep_gb", str(cm.exception))
        with self.assertRaises(ValueError):
            self._load('[capture]\nkeep_gb = "lots"\n')

    def test_the_writer_refuses_a_cap_that_would_prune_everything(self):
        with tempfile.TemporaryDirectory() as d:
            for h in ("00", "01", "02"):
                (Path(d) / f"threadwatch-20260903-{h}.pcap").write_bytes(b"x" * 1000)
            with self.assertRaises(ValueError):
                RingWriter(Path(d), keep_files=168, dlt=0, keep_bytes=-5 * 1024 ** 3)
            self.assertEqual(len(list(Path(d).glob("*.pcap"))), 3)


class ReadOnlyStateDirTest(unittest.TestCase):
    """The web container mounts data/ read-only; before capture has run
    there is no state directory, and a reader must not die creating it."""

    def test_a_state_dir_that_cannot_be_created_is_a_path_not_a_crash(self):
        import os
        import stat
        from threadwatch.config import Config
        from threadwatch.web import Site
        with tempfile.TemporaryDirectory() as d:
            data = Path(d) / "data"
            data.mkdir()
            os.chmod(data, stat.S_IRUSR | stat.S_IXUSR)      # data:ro, no state/ yet
            try:
                if os.access(data, os.W_OK):
                    self.skipTest("running as root: directory permissions do not bind")
                cfg = Config(data_dir=data)
                self.assertEqual(cfg.state_dir, data / "state")   # no EROFS/EACCES out of the property
                self.assertFalse(cfg.state_dir.exists())
                site = Site(cfg)
                for path in ("/", "/status", "/devices", "/api/status"):
                    code, _ctype, body = site.respond(path)
                    self.assertEqual(code, 200, path)
                self.assertIn(b"has not run here", site.respond("/status")[2])
            finally:
                os.chmod(data, stat.S_IRWXU)


if __name__ == "__main__":
    unittest.main()
