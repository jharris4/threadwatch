"""The event log survives a write cut short."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.events import day_of, migrate_legacy, read_day  # noqa: E402

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


if __name__ == "__main__":
    unittest.main()
