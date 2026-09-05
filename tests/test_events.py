"""The event log survives a write cut short."""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.events import day_of, migrate_legacy, prune_days, read_day  # noqa: E402

TS = 1756944000.0


def _records(n=5):
    return [{"ts": TS + i, "event": f"e{i}", "severity": "info"} for i in range(n)]


class PartialLineTest(unittest.TestCase):
    def test_resumed_migration_keeps_the_record_after_a_cut_line(self):
        d = Path(tempfile.mkdtemp())
        events = d / "events"
        events.mkdir()
        recs = _records()
        lines = [json.dumps(r) for r in recs]
        day = day_of(TS)
        # A migration killed part-way: one whole record, then a cut one.
        (events / f"{day}.jsonl").write_text(lines[0] + "\n" + lines[1][:20])
        (d / "events.jsonl.migrating").write_text("\n".join(lines) + "\n")

        migrate_legacy(events)

        self.assertEqual([r["event"] for r in read_day(events, day)],
                         [r["event"] for r in recs])

    def test_emit_after_a_partial_line_does_not_swallow_the_record(self):
        from threadwatch.events import EventLog
        d = Path(tempfile.mkdtemp())
        events = d / "events"
        events.mkdir()
        day = day_of(TS)
        (events / f"{day}.jsonl").write_text('{"ts": %f, "event": "cut"' % TS)

        log = EventLog(events, [])
        log.emit("after", "info", ts=TS + 1)

        self.assertEqual([r["event"] for r in read_day(events, day)], ["after"])



class RetentionTest(unittest.TestCase):
    def _days(self, d, n, start=TS):
        for i in range(n):
            ts = start + i * 86400
            (d / f"{day_of(ts)}.jsonl").write_text(json.dumps({"ts": ts, "event": "e", "severity": "info"}) + "\n")

    def test_day_files_past_keep_days_go_and_zero_keeps_everything(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            self._days(d, 40)
            now = TS + 39 * 86400 + 3600
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(prune_days(d, 0, now), [])
                self.assertEqual(len(list(d.glob("*.jsonl"))), 40)
                gone = prune_days(d, 30, now)
            self.assertEqual(len(gone), 9)                         # days 0..8 are older than 30 days
            self.assertEqual(gone[0], day_of(TS))
            kept = sorted(p.stem for p in d.glob("*.jsonl"))
            self.assertEqual(len(kept), 31)
            self.assertEqual(kept[0], day_of(TS + 9 * 86400))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(prune_days(d, 30, now), [])       # idempotent

    def test_the_parsed_file_cache_is_bounded(self):
        from threadwatch import events as events_mod
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            self._days(d, events_mod.READ_CACHE_MAX + 50)
            events_mod._read_cache.clear()
            for day in sorted(p.stem for p in d.glob("*.jsonl")):
                self.assertEqual(len(read_day(d, day)), 1)
            self.assertEqual(len(events_mod._read_cache), events_mod.READ_CACHE_MAX)
            self.assertNotIn(d / f"{day_of(TS)}.jsonl", events_mod._read_cache)    # the first read went first


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(hasattr(time, "tzset"), "needs time.tzset to switch zones")
class DayArithmeticTest(unittest.TestCase):
    """next_day and prev_day step whole local calendar days, and a local
    day is 23, 24 or 25 hours long. They add 36 h and subtract 12 h so
    that both DST transitions land in the neighbouring day; 24 h either
    way turns the 25-hour day into its own successor, and the day pages
    and the day bounds every reader uses are built on them."""

    ZONES = ("America/New_York", "Europe/London", "Australia/Sydney")

    def test_every_day_of_a_dst_year_steps_to_its_neighbours(self):
        import datetime
        import os
        from threadwatch.events import day_bounds, next_day, prev_day
        saved = os.environ.get("TZ")
        try:
            for zone in self.ZONES:
                os.environ["TZ"] = zone
                time.tzset()
                lengths = set()
                d = datetime.date(2026, 1, 1)
                while d.year == 2026:
                    day = d.isoformat()
                    self.assertEqual(next_day(day), (d + datetime.timedelta(days=1)).isoformat(), (zone, day))
                    self.assertEqual(prev_day(day), (d - datetime.timedelta(days=1)).isoformat(), (zone, day))
                    start, end = day_bounds(day)
                    lengths.add(round((end - start) / 3600))
                    d += datetime.timedelta(days=1)
                self.assertEqual(lengths, {23, 24, 25}, zone)     # both transitions were in the year
        finally:
            if saved is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = saved
            time.tzset()
