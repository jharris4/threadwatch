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

    def test_a_copy_that_fails_leaves_no_half_incident_behind(self):
        real = shutil.copy2

        def copy2(src, dst, *a, **kw):
            if src.name.endswith("-01.pcap"):
                raise OSError(28, "No space left on device")
            return real(src, dst, *a, **kw)

        freeze.shutil.copy2 = copy2
        try:
            with self.assertRaises(OSError) as cm:
                freeze.freeze_ring(self.cfg, "storm")
        finally:
            freeze.shutil.copy2 = real
        self.assertEqual(cm.exception.errno, 28)
        self.assertEqual(list(self.cfg.incidents_dir.iterdir()), [])          # nothing that reads as an incident
        self.assertEqual(len(list(self.cfg.ring_dir.glob("*.pcap"))), 3)     # the ring itself untouched

    def test_a_copy_in_progress_is_not_an_incident_until_it_is_whole(self):
        from threadwatch.review import incidents
        real = shutil.copy2
        seen_during = []

        def copy2(src, dst, *a, **kw):
            seen_during.append(([p.name for p in self.cfg.incidents_dir.iterdir()], incidents(self.cfg.incidents_dir)))
            return real(src, dst, *a, **kw)

        freeze.shutil.copy2 = copy2
        try:
            dest, count = freeze.freeze_ring(self.cfg, "storm")
        finally:
            freeze.shutil.copy2 = real
        self.assertEqual(count, 3)
        self.assertTrue(all(names == [dest.name + ".partial"] and listed == [] for names, listed in seen_during))
        self.assertEqual([p.name for p in self.cfg.incidents_dir.iterdir()], [dest.name])   # renamed into place
        self.assertEqual([i["label"] for i in incidents(self.cfg.incidents_dir)], ["storm"])

    def test_a_half_copy_left_by_a_dead_run_is_discarded_at_the_next_start(self):
        # os._exit (the stall watchdog, a SIGTERM) unwinds no thread: the
        # except in freeze_ring never ran, and the .partial directory stayed.
        left = self.cfg.incidents_dir / "20260904T200112_auto-storm.partial"
        left.mkdir(parents=True)
        (left / "threadwatch-20260904-19.pcap").write_bytes(b"x" * 50)
        whole = self.cfg.incidents_dir / "20260903T120000_manual"
        whole.mkdir()
        self.assertEqual(freeze.discard_partials(self.cfg.incidents_dir), ["auto-storm"])
        self.assertEqual([p.name for p in self.cfg.incidents_dir.iterdir()], [whole.name])
        self.assertEqual(freeze.discard_partials(self.cfg.incidents_dir), [])
        self.assertEqual(freeze.discard_partials(self.cfg.incidents_dir / "missing"), [])


if __name__ == "__main__":
    unittest.main()
