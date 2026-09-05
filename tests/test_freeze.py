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
        self.assertEqual([p.name for p in self.cfg.incidents_dir.iterdir()], [freeze.STAGING_DIR])   # nothing that reads as an incident
        self.assertEqual(list((self.cfg.incidents_dir / freeze.STAGING_DIR).iterdir()), [])
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
        self.assertTrue(all(names == [freeze.STAGING_DIR] and listed == [] for names, listed in seen_during))
        self.assertEqual(sorted(p.name for p in self.cfg.incidents_dir.iterdir()),
                         sorted([dest.name, freeze.STAGING_DIR]))                          # renamed into place
        self.assertEqual(list((self.cfg.incidents_dir / freeze.STAGING_DIR).iterdir()), [])
        self.assertEqual([i["label"] for i in incidents(self.cfg.incidents_dir)], ["storm"])

    def test_a_half_copy_left_by_a_dead_run_is_discarded_at_the_next_start(self):
        # os._exit (the stall watchdog, a SIGTERM) unwinds no thread: the
        # except in freeze_ring never ran, and the .partial directory stayed.
        left = self.cfg.incidents_dir / freeze.STAGING_DIR / "20260904T200112_auto-storm"
        left.mkdir(parents=True)
        (left / "threadwatch-20260904-19.pcap").write_bytes(b"x" * 50)
        whole = self.cfg.incidents_dir / "20260903T120000_manual"
        whole.mkdir()
        self.assertEqual(freeze.discard_partials(self.cfg.incidents_dir), ["auto-storm"])
        self.assertEqual(sorted(p.name for p in self.cfg.incidents_dir.iterdir()),
                         sorted([whole.name, freeze.STAGING_DIR]))
        self.assertFalse(left.exists())
        self.assertEqual(freeze.discard_partials(self.cfg.incidents_dir), [])
        self.assertEqual(freeze.discard_partials(self.cfg.incidents_dir / "missing"), [])

    def test_a_label_ending_in_partial_is_a_whole_incident_like_any_other(self):
        # BUG-01: safe_label keeps periods, so "test.partial" used to name a
        # finished incident the way a half copy was named; the listing hid
        # it and the next start deleted it.
        from threadwatch.review import incidents
        dest, count = freeze.freeze_ring(self.cfg, "test.partial", now=1_700_000_000)
        self.assertEqual(count, 3)
        self.assertEqual(dest.name.rpartition("_")[2], "test.partial")
        self.assertEqual([i["label"] for i in incidents(self.cfg.incidents_dir)], ["test.partial"])
        self.assertEqual(freeze.discard_partials(self.cfg.incidents_dir), [])          # the next start
        self.assertTrue(dest.is_dir())
        self.assertEqual(len(list(dest.glob("*.pcap"))), 3)
        self.assertEqual([i["label"] for i in incidents(self.cfg.incidents_dir)], ["test.partial"])

    def test_an_existing_incident_or_half_copy_is_never_written_into(self):
        now = 1_756_900_000.0
        dest, _count = freeze.freeze_ring(self.cfg, "storm", now=now)
        before = sorted(p.name for p in dest.iterdir())
        (dest / "threadwatch-20260903-00.pcap").write_bytes(b"kept")       # the incident as the operator left it
        with self.assertRaises(FileExistsError) as cm:
            freeze.freeze_ring(self.cfg, "storm", now=now)                 # the same label, the same second
        self.assertIn(dest.name, str(cm.exception))
        self.assertEqual(sorted(p.name for p in dest.iterdir()), before)
        self.assertEqual((dest / "threadwatch-20260903-00.pcap").read_bytes(), b"kept")
        self.assertEqual(list((self.cfg.incidents_dir / freeze.STAGING_DIR).iterdir()), [])   # no half copy left
        # A half copy under the same name (a freeze still running, or one
        # a dead run left) is not a directory to add to either.
        partial = self.cfg.incidents_dir / freeze.STAGING_DIR / dest.name.replace("storm", "quiet")
        partial.mkdir()
        (partial / "stale.pcap").write_bytes(b"x")
        with self.assertRaises(FileExistsError):
            freeze.freeze_ring(self.cfg, "quiet", now=now)
        self.assertEqual([p.name for p in partial.iterdir()], ["stale.pcap"])
        self.assertEqual(sorted(p.name for p in self.cfg.incidents_dir.iterdir()),
                         sorted([dest.name, freeze.STAGING_DIR]))


if __name__ == "__main__":
    unittest.main()
