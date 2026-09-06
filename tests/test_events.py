"""The event log survives a write cut short."""

import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.events import day_of, migrate_legacy, prune_days, read_day

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

    def test_a_second_legacy_log_does_not_overwrite_the_first_archive(self):
        import contextlib
        import io
        d = Path(tempfile.mkdtemp())
        events = d / "events"
        first = [json.dumps(r) for r in _records(4)]
        second = [json.dumps(r) for r in _records(2)]
        for lines in (first, second):
            (d / "events.jsonl").write_text("\n".join(lines) + "\n")
            with contextlib.redirect_stdout(io.StringIO()):
                migrate_legacy(events)

        self.assertEqual((d / "events.jsonl.migrated").read_text().splitlines(), first)
        self.assertEqual((d / "events.jsonl.migrated-2").read_text().splitlines(), second)



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


class MalformedLineTest(unittest.TestCase):
    """A line that is valid JSON and not an event record (a null, a
    number, a list, an object with no ts) was appended to read_day's
    result; the recorder's summary check then raised on it every 30 s
    inside the capture loop, and every review page for the day was a
    500. Such lines are skipped and said once per file."""

    BAD = ["null", "42", "[]", '"text"', "true", '{"event": "device_quiet"}',
           '{"ts": "yesterday", "event": "device_quiet", "severity": "warning"}',
           '{"ts": true, "event": "x", "severity": "info"}',
           '{"ts": 1700000000, "event": "x"}', "not json at all"]

    def test_lines_that_are_not_records_are_skipped_and_said_once(self):
        import contextlib
        import io

        from threadwatch import events as events_mod
        from threadwatch.review import day_episodes
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            day = day_of(TS)
            good = [{"ts": TS + 60, "event": "device_quiet", "severity": "warning", "addr": "a" * 16,
                     "name": None, "silent_for_s": 1800, "note": "quiet"},
                    {"ts": TS + 120, "event": "device_returned", "severity": "notice", "addr": "a" * 16}]
            lines = [json.dumps(good[0])] + self.BAD + [json.dumps(good[1])]
            path = d / f"{day}.jsonl"
            path.write_text("\n".join(lines) + "\n")
            events_mod._read_cache.clear()
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(read_day(d, day), good)
                self.assertEqual(read_day(d, day), good)           # cached: not said again
                path.write_text(path.read_text() + "\n")          # touched, re-read: the same count, not said again
                os.utime(path, (time.time() + 5, time.time() + 5))
                events_mod._read_cache.clear()
                self.assertEqual(read_day(d, day), good)
            self.assertEqual(out.getvalue(), f"[threadwatch] {day}.jsonl: skipped {len(self.BAD)} line(s) that "
                                             "are not event records (not JSON, or no numeric ts and severity)\n")
            # The consumers that crashed: episodes for the review page, and
            # the recorder's summary of the day.
            eps = day_episodes(d, day, now=TS + 3600)
            self.assertEqual([e["kind"] for e in eps], ["quiet"])
            from threadwatch.config import Config
            from threadwatch.crypto import Decryptor
            from threadwatch.events import EventLog
            from threadwatch.pipeline import Pipeline
            (d / "devices.json").write_text("[]")
            cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")
            log = EventLog(d, [])
            pipe = Pipeline(cfg, log, Decryptor(network_key=bytes(16)))
            summary = pipe.summary(TS + 7200)
            self.assertEqual(summary["events_24h"], {"critical": 0, "warning": 1, "notice": 1, "info": 0})


class ReadCacheTest(unittest.TestCase):
    def test_eviction_is_safe_across_reader_threads(self):
        # BUG-14: every web request thread shares the cache; once full,
        # picking the oldest entry while another thread inserted or
        # deleted raised "dictionary changed size during iteration" or a
        # KeyError, a 500 on the review page.
        import sys
        import threading

        from threadwatch import events as events_mod
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            days = []
            for i in range(events_mod.READ_CACHE_MAX + 12):
                day = day_of(TS + i * 86400)
                (d / f"{day}.jsonl").write_text(json.dumps({"ts": TS + i * 86400, "event": "x",
                                                            "severity": "info"}) + "\n")
                days.append(day)
            events_mod._read_cache.clear()
            errors = []

            def reader(offset):
                try:
                    for i in range(300):
                        if len(read_day(d, days[(offset + i) % len(days)])) != 1:
                            raise AssertionError("a day read back wrong")
                except BaseException as exc:
                    errors.append(exc)

            interval = sys.getswitchinterval()
            sys.setswitchinterval(1e-6)
            try:
                threads = [threading.Thread(target=reader, args=(i * 11,)) for i in range(12)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(60)
            finally:
                sys.setswitchinterval(interval)
            self.assertEqual(errors, [])
            self.assertLessEqual(len(events_mod._read_cache), events_mod.READ_CACHE_MAX)

    def test_an_unchanged_file_is_served_from_the_cache_and_any_rewrite_is_read_again(self):
        from threadwatch import events as events_mod
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            day = day_of(TS)
            path = d / f"{day}.jsonl"
            first = json.dumps({"ts": TS, "event": "first", "severity": "info"}) + "\n"
            again = first.replace("first", "again")                          # the same size to the byte
            path.write_text(first)
            events_mod._read_cache.clear()
            self.assertEqual([r["event"] for r in read_day(d, day)], ["first"])
            with mock.patch.object(Path, "read_text", side_effect=AssertionError("parsed again")):
                self.assertEqual([r["event"] for r in read_day(d, day)], ["first"])   # cached: not re-read
            # Rewritten whole with the same size (a migration, an edit by
            # hand); the file's mtime moves on, as it does for any write.
            path.write_text(again)
            st = path.stat()
            os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
            self.assertEqual([r["event"] for r in read_day(d, day)], ["again"])
            # ...and appended to, which changes the size alone.
            with open(path, "a") as fh:
                fh.write(first)
            os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))    # same mtime as before
            self.assertEqual([r["event"] for r in read_day(d, day)], ["again", "first"])
            self.assertEqual([r["event"] for r in read_day(d, day)], ["again", "first"])
            self.assertEqual(read_day(d, "1999-01-01"), [])                  # no file: nothing, nothing cached
            self.assertNotIn(d / "1999-01-01.jsonl", events_mod._read_cache)


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


if __name__ == "__main__":
    unittest.main()
