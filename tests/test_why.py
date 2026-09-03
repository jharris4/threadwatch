"""`threadwatch why`: which ring files a time window selects."""

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.why import select_recent  # noqa: E402

NOW = time.mktime(time.strptime("2026-09-03 10:20", "%Y-%m-%d %H:%M"))


def ring(*hours):
    return [Path(f"/ring/threadwatch-{h}.pcap") for h in hours]


class SelectRecentTest(unittest.TestCase):
    FILES = ring("20260902-22", "20260902-23", "20260903-00", "20260903-08", "20260903-09", "20260903-10")

    def test_none_keeps_everything(self):
        self.assertEqual(select_recent(self.FILES, None, NOW), self.FILES)

    def test_window_keeps_files_whose_hour_ends_inside_it(self):
        # 2 h back from 10:20 is 08:20: the 08h file still covers 08:20-09:00.
        self.assertEqual(select_recent(self.FILES, 2, NOW), ring("20260903-08", "20260903-09", "20260903-10"))
        # 1.25 h back is 09:05: the 08h file ended at 09:00, so it goes.
        self.assertEqual(select_recent(self.FILES, 1.25, NOW), ring("20260903-09", "20260903-10"))

    def test_window_crosses_midnight(self):
        self.assertEqual(select_recent(self.FILES, 11, NOW),
                         ring("20260902-23", "20260903-00", "20260903-08", "20260903-09", "20260903-10"))

    def test_unparsable_name_is_kept(self):
        odd = Path("/ring/threadwatch-frozen.pcap")
        self.assertEqual(select_recent([odd, *self.FILES], 1, NOW), [odd, *ring("20260903-09", "20260903-10")])

    def test_empty_when_nothing_is_recent(self):
        self.assertEqual(select_recent(ring("20260901-10"), 1, NOW), [])


if __name__ == "__main__":
    unittest.main()
