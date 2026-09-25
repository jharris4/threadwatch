"""Ring file names: one series per radio, grouped by hour by every reader."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests  # noqa: F401  (the mDNS guard, installed on a direct run too: tests/no_lan)
from threadwatch.ring import group_files, parse_ring_name, ring_files, ring_hours, ring_labels, ring_name


class RingNameTest(unittest.TestCase):
    def test_the_primary_keeps_the_plain_name_and_a_label_is_a_suffix(self):
        self.assertEqual(ring_name("20260917-14"), "threadwatch-20260917-14.pcap")
        self.assertEqual(ring_name("20260917-14", "annex"), "threadwatch-20260917-14-annex.pcap")
        self.assertEqual(parse_ring_name("threadwatch-20260917-14.pcap"), ("20260917-14", None))
        self.assertEqual(parse_ring_name("threadwatch-20260917-14-annex.pcap"), ("20260917-14", "annex"))
        for other in ("capture.pcap", "threadwatch-20260917-14-Annex.pcap", "threadwatch-20260917-14.pcapng",
                      "threadwatch-2026091-14.pcap", "threadwatch-20260917-14-.pcap"):
            self.assertIsNone(parse_ring_name(other), other)

    def test_a_label_sorts_inside_its_hour_but_readers_group_by_the_parsed_hour(self):
        names = sorted(["threadwatch-20260917-15.pcap", "threadwatch-20260917-14-annex.pcap",
                        "threadwatch-20260917-14.pcap", "threadwatch-20260917-15-annex.pcap"])
        # The suffix sorts before ".pcap": the hour's files stay together.
        self.assertEqual([parse_ring_name(n)[0] for n in names],
                         ["20260917-14", "20260917-14", "20260917-15", "20260917-15"])


class RingDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        for name in ("threadwatch-20260917-13.pcap", "threadwatch-20260917-14.pcap",
                     "threadwatch-20260917-14-annex.pcap", "threadwatch-20260917-15-annex.pcap",
                     "notes.txt", "other.pcap"):
            (self.d / name).write_bytes(b"x")

    def tearDown(self):
        self.tmp.cleanup()

    def test_each_series_lists_only_its_own_files(self):
        self.assertEqual([p.name for p in ring_files(self.d)],
                         ["threadwatch-20260917-13.pcap", "threadwatch-20260917-14.pcap"])
        self.assertEqual([p.name for p in ring_files(self.d, "annex")],
                         ["threadwatch-20260917-14-annex.pcap", "threadwatch-20260917-15-annex.pcap"])
        self.assertEqual(ring_files(self.d, "nope"), [])
        self.assertEqual(ring_files(self.d / "missing"), [])

    def test_hours_carry_the_file_of_every_radio_that_wrote_them(self):
        hours = ring_hours(self.d)
        self.assertEqual([h for h, _ in hours], ["20260917-13", "20260917-14", "20260917-15"])
        self.assertEqual({label: p.name for label, p in hours[1][1].items()},
                         {None: "threadwatch-20260917-14.pcap", "annex": "threadwatch-20260917-14-annex.pcap"})
        self.assertEqual(list(hours[0][1]), [None])
        self.assertEqual(list(hours[2][1]), ["annex"])
        self.assertEqual(ring_labels(self.d), [None, "annex"])
        self.assertEqual(ring_hours(self.d / "missing"), [])

    def test_files_given_by_hand_group_ring_names_by_hour_and_keep_the_rest_whole(self):
        paths = [self.d / n for n in ("threadwatch-20260917-14-annex.pcap", "other.pcap",
                                      "threadwatch-20260917-13.pcap", "threadwatch-20260917-14.pcap")]
        groups = group_files(paths)
        self.assertEqual([sorted(g, key=str) for g in groups], [[None], [None, "annex"], [None]])
        self.assertEqual(groups[2][None].name, "other.pcap")
        self.assertEqual(group_files([self.d / "other.pcap"]), [{None: self.d / "other.pcap"}])


if __name__ == "__main__":
    unittest.main()
