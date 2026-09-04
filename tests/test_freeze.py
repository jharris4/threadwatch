"""freeze_ring against a ring that keeps rotating."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.config import Config  # noqa: E402
from threadwatch import freeze  # noqa: E402


class FreezeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config(data_dir=Path(self.tmp.name) / "data")
        self.cfg.ring_dir.mkdir(parents=True)
        for h in ("00", "01", "02"):
            (self.cfg.ring_dir / f"threadwatch-20260903-{h}.pcap").write_bytes(b"x" * 100)

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_file_pruned_mid_copy_is_skipped_not_fatal(self):
        real = shutil.copy2

        def copy2(src, dst, *a, **kw):
            if src.name.endswith("-00.pcap"):
                src.unlink()                    # RingWriter._prune got there first
            return real(src, dst, *a, **kw)

        freeze.shutil.copy2 = copy2
        try:
            dest, count = freeze.freeze_ring(self.cfg, "storm")
        finally:
            freeze.shutil.copy2 = real
        self.assertEqual(count, 2)
        self.assertEqual(sorted(p.name[-7:-5] for p in dest.glob("*.pcap")), ["01", "02"])


if __name__ == "__main__":
    unittest.main()
