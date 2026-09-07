"""save_snapshot against a ring that keeps rotating."""

import json
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch import snapshot
from threadwatch.config import Config


class BundleTest(unittest.TestCase):
    """What travels with the packets: the inventory, the configuration
    with its secrets blanked, and a manifest naming it all."""

    def test_redaction_blanks_secret_values_and_keeps_the_shape(self):
        import tomllib
        text = ('[network]\nchannel = 25\nkeep_hours = 168\n'
                '[[alerts.sinks]]\nname = "phone"\ntype = "ntfy"\nurl = "https://ntfy.example/t-9f3a"   # topic\n'
                'token = "${NTFY_TOKEN}"\nheaders = { Authorization = "Bearer hunter2", "X-Y" = "]" }\n'
                'command = [\n  "curl", "-H", "Auth: hunter3",\n  "https://x.example/{event}",\n]\n'
                'min_severity = "warning"\n[[heartbeats]]\nfailure_url = "https://hc.example/fail"\n'
                '[credentials]\nnetwork_key = "00112233"\nfile = "credentials.toml"\n')
        out = snapshot.redact_config(text)
        for secret in ("9f3a", "hunter2", "hunter3", "NTFY_TOKEN", "hc.example", "00112233"):
            self.assertNotIn(secret, out)
        parsed = tomllib.loads(out)
        self.assertEqual(parsed["network"], {"channel": 25, "keep_hours": 168})
        self.assertEqual(parsed["alerts"]["sinks"], [{"name": "phone", "type": "ntfy", "url": "<redacted>",
                                                      "token": "<redacted>",
                                                      "headers": {"Authorization": "<redacted>", "X-Y": "<redacted>"},
                                                      "command": "<redacted>", "min_severity": "warning"}])
        self.assertEqual(parsed["heartbeats"], [{"failure_url": "<redacted>"}])
        self.assertEqual(parsed["credentials"], {"network_key": "<redacted>", "file": "credentials.toml"})
        self.assertEqual(snapshot.redact_config(""), "")

    def test_the_shapes_that_used_to_slip_past_the_redaction(self):
        # Three leaks, all in configurations an operator would write:
        # webhook_url (the whole authentication for a Home Assistant
        # webhook) matched nothing; a headers sub-table put the bearer
        # token on a line whose own key reads as innocent; and a
        # multi-line basic string opened no run, so its body was copied
        # out verbatim and left the bundle's config.toml invalid TOML.
        import tomllib
        text = ('[alerts]\nwebhook_url = "https://ha.local/api/webhook/abc123"\n'
                'note = """\nkept: two lines\nof prose\n"""\n'
                '[[alerts.sinks]]\nname = "phone"\nmin_severity = "warning"\n'
                '[alerts.sinks.headers]\nAuthorization = "Bearer hunter2"\n"X-Api-Key" = "k9"\n'
                '[credentials]\nnetwork_key = """\n00112233445566778899aabbccddeeff\n"""\n'
                'file = "credentials.toml"\n')
        out = snapshot.redact_config(text)
        for secret in ("abc123", "hunter2", "k9", "00112233"):
            self.assertNotIn(secret, out)
        parsed = tomllib.loads(out)
        self.assertEqual(parsed["alerts"]["webhook_url"], "<redacted>")
        self.assertEqual(parsed["alerts"]["note"], "kept: two lines\nof prose\n")
        self.assertEqual(parsed["alerts"]["sinks"], [{"name": "phone", "min_severity": "warning",
                                                      "headers": {"Authorization": "<redacted>",
                                                                  "X-Api-Key": "<redacted>"}}])
        self.assertEqual(parsed["credentials"], {"network_key": "<redacted>", "file": "credentials.toml"})

    def test_the_toml_forms_a_line_based_redaction_could_not_see(self):
        # Both are valid TOML the loader accepts, and both carried their
        # secret into the bundle whole while redaction worked on lines: the
        # key it looked for was inside an inline table in an array, or was
        # a dotted one whose leading segment is the sensitive part.
        import tomllib
        inline = ('[alerts]\n'
                  'sinks = [{type="http", url="https://example.invalid/FAKE_SECRET"}]\n')
        dotted = ('[[alerts.sinks]]\ntype = "http"\nurl = "https://example.invalid"\n'
                  'headers.Authorization = "Bearer FAKE_SECRET"\n')
        for text in (inline, dotted):
            out = snapshot.redact_config(text)
            self.assertNotIn("FAKE_SECRET", out)
            sink = tomllib.loads(out)["alerts"]["sinks"][0]
            self.assertEqual(sink["type"], "http")     # which sink it was still reads
            self.assertEqual(sink["url"], "<redacted>")
        self.assertEqual(tomllib.loads(snapshot.redact_config(dotted))["alerts"]["sinks"][0]["headers"],
                         {"Authorization": "<redacted>"})

    def test_the_values_that_are_not_secret_come_back_unchanged(self):
        # The round trip rewrites the file, so every type an operator can
        # write has to survive it: bool must not arrive as 1, and a nested
        # table, an array of tables and an ordinary array must all parse
        # back to what went in.
        import tomllib
        text = ('[network]\nchannel = 25\npan_id = "0x4e21"\n'
                '[record]\nsnapshot_on_critical = true\nkeep_snapshots = -1\n'
                '[detect]\nflood_multiplier = 3.0\n'
                '[[alerts.sinks]]\nname = "phone"\nevents = ["device_quiet", "phase_locked_storm"]\n'
                '[[alerts.sinks]]\nname = "script"\n"odd name" = "kept"\n')
        parsed = tomllib.loads(snapshot.redact_config(text))
        self.assertEqual(parsed["network"], {"channel": 25, "pan_id": "0x4e21"})
        self.assertIs(parsed["record"]["snapshot_on_critical"], True)
        self.assertEqual(parsed["record"]["keep_snapshots"], -1)
        self.assertEqual(parsed["detect"]["flood_multiplier"], 3.0)
        self.assertEqual([s["name"] for s in parsed["alerts"]["sinks"]], ["phone", "script"])
        self.assertEqual(parsed["alerts"]["sinks"][0]["events"], ["device_quiet", "phase_locked_storm"])
        self.assertEqual(parsed["alerts"]["sinks"][1]["odd name"], "kept")

    def test_a_configuration_that_does_not_parse_is_blanked_whole(self):
        # Nothing has looked at what is in a file tomllib cannot read, so
        # none of it travels; the copy says why it is empty.
        out = snapshot.redact_config('[alerts]\nurl = "https://example.invalid/FAKE_SECRET\n')
        self.assertNotIn("FAKE_SECRET", out)
        self.assertIn("did not parse", out)

    def test_parser_errors_cannot_copy_input_into_the_placeholder(self):
        import tomllib

        for text in (
            '["FAKE_SECRET"]\nx = 1\n["FAKE_SECRET"]\ny = 2\n',
            '[alerts]\nheaders = {"FAKE_SECRET" = 1, "FAKE_SECRET" = 2}\n',
        ):
            with self.subTest(text=text):
                with self.assertRaises(tomllib.TOMLDecodeError):
                    tomllib.loads(text)
                out = snapshot.redact_config(text)
                self.assertEqual(out, "# the configuration in force did not parse as TOML; redacted whole\n")
                self.assertEqual(tomllib.loads(out), {})

    def test_comments_cannot_carry_secrets_into_the_snapshot(self):
        import tomllib

        text = ('# old token: FAKE_SECRET_STANDALONE\n'
                '# url = "https://example.invalid/FAKE_SECRET_DISABLED"\n'
                '[network] # FAKE_SECRET_TABLE\n'
                'channel = 25 # FAKE_SECRET_INLINE\n')
        out = snapshot.redact_config(text)
        self.assertNotIn("FAKE_SECRET", out)
        self.assertEqual(tomllib.loads(out), {"network": {"channel": 25}})

    def test_the_shipped_example_config_survives_redaction_as_valid_toml(self):
        import tomllib

        from threadwatch.config import REPO_ROOT
        text = (REPO_ROOT / "config" / "config.example.toml").read_text()
        out = snapshot.redact_config(text)
        self.assertEqual(tomllib.loads(out).keys(), tomllib.loads(text).keys())
        # The operator's own comments do not survive the round trip; a note
        # saying what the copy is, and why it does not look like their file,
        # takes their place.
        self.assertIn("secret value replaced", out)

    def test_when_the_bundle_says_it_was_saved(self):
        # What a snapshot is read against: months later, "the last 90 days"
        # has to mean the 90 days before it was taken.
        import json
        with tempfile.TemporaryDirectory() as d:
            inc = Path(d) / "20260903T100000_storm"
            inc.mkdir()
            self.assertEqual(snapshot.saved_at(inc),                     # no manifest: the name says when
                             time.mktime(time.strptime("20260903T100000", "%Y%m%dT%H%M%S")))
            (inc / snapshot.MANIFEST).write_text(json.dumps({"saved_at": 1_756_800_000.0}))
            self.assertEqual(snapshot.saved_at(inc), 1_756_800_000.0)
            (inc / snapshot.MANIFEST).write_text("{ truncated")          # a copy cut short
            self.assertEqual(snapshot.saved_at(inc),
                             time.mktime(time.strptime("20260903T100000", "%Y%m%dT%H%M%S")))
            unnamed = Path(d) / "no-stamp-here"
            unnamed.mkdir()
            self.assertIsNone(snapshot.saved_at(unnamed))

    def test_the_bundle_names_everything_it_holds(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "config.toml").write_text('[network]\nchannel = 15\n[[alerts.sinks]]\nurl = "https://s"\n')
            (d / "devices.json").write_text("[]")
            cfg = Config(data_dir=d / "data", devices_path=d / "devices.json", config_path=d / "config.toml",
                         channel=15, pan_id=0x4e21)
            cfg.ring_dir.mkdir(parents=True)
            (cfg.ring_dir / "threadwatch-20260903-01.pcap").write_bytes(b"x" * 10)
            dest, count = snapshot.save_snapshot(cfg, "auto-storm", now=1_756_900_000.0, trigger="phase_locked_storm")
            m = json.loads((dest / "manifest.json").read_text())
            self.assertEqual((m["format"], m["label"], m["trigger"], m["channel"], m["pan_id"], m["ring_files"],
                              m["span"], m["inventory"], m["config"], m["events_days"], m["saved_at"]),
                             (1, "auto-storm", "phase_locked_storm", 15, "0x4e21", 1,
                              ["20260903-01", "20260903-01"], "devices.json", "config.toml", 0, 1_756_900_000.0))
            self.assertEqual(sorted(m["files"]), ["config.toml", "devices.json", "threadwatch-20260903-01.pcap"])
            self.assertNotIn("manifest.json", m["files"])                # written last, after the listing
            self.assertNotIn("https://s", (dest / "config.toml").read_text())
            self.assertIn("read_with", m)
            # Nothing to copy: the manifest says so instead of failing.
            bare = Config(data_dir=d / "data2")
            bare.ring_dir.mkdir(parents=True)
            dest, _ = snapshot.save_snapshot(bare, "bare")
            m = json.loads((dest / "manifest.json").read_text())
            self.assertEqual((m["inventory"], m["config"], m["span"], m["files"]), (None, None, None, {}))


class SnapshotTest(unittest.TestCase):
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

        snapshot.shutil.copy2 = copy2
        try:
            dest, count = snapshot.save_snapshot(self.cfg, "storm")
        finally:
            snapshot.shutil.copy2 = real
        self.assertEqual(count, 2)
        self.assertEqual(sorted(p.name[-7:-5] for p in dest.glob("*.pcap")), ["01", "02"])

    def test_a_snapshot_short_of_what_was_copied_is_a_failure_not_a_snapshot(self):
        # The last line of defence for the bundle's one promise: that it
        # holds every ring file it says it does. If it stopped firing, a
        # truncated snapshot would be written, manifested and reported as
        # whole, and nothing else would notice.
        real = shutil.copy2

        def copy2(src, dst, *a, **kw):
            out = real(src, dst, *a, **kw)
            if src.name.endswith("-01.pcap"):
                Path(dst).unlink()          # copied, then gone: the count and the directory disagree
            return out

        snapshot.shutil.copy2 = copy2
        try:
            with self.assertRaises(OSError) as cm:
                snapshot.save_snapshot(self.cfg, "storm")
        finally:
            snapshot.shutil.copy2 = real
        self.assertIn("3 ring files were copied but the snapshot holds 2", str(cm.exception))
        self.assertEqual(list(self.cfg.snapshots_dir.glob("*_storm")), [])
        self.assertEqual(list((self.cfg.snapshots_dir / snapshot.STAGING_DIR).iterdir()), [])

    def test_a_copy_that_fails_leaves_no_half_snapshot_behind(self):
        real = shutil.copy2

        def copy2(src, dst, *a, **kw):
            if src.name.endswith("-01.pcap"):
                raise OSError(28, "No space left on device")
            return real(src, dst, *a, **kw)

        snapshot.shutil.copy2 = copy2
        try:
            with self.assertRaises(OSError) as cm:
                snapshot.save_snapshot(self.cfg, "storm")
        finally:
            snapshot.shutil.copy2 = real
        self.assertEqual(cm.exception.errno, 28)
        names = [p.name for p in self.cfg.snapshots_dir.iterdir()]
        self.assertEqual(names, [snapshot.STAGING_DIR])        # nothing that reads as a snapshot
        self.assertEqual(list((self.cfg.snapshots_dir / snapshot.STAGING_DIR).iterdir()), [])
        self.assertEqual(len(list(self.cfg.ring_dir.glob("*.pcap"))), 3)     # the ring itself untouched

    def test_a_copy_in_progress_is_not_a_snapshot_until_it_is_whole(self):
        from threadwatch.review import snapshots
        real = shutil.copy2
        seen_during = []

        def copy2(src, dst, *a, **kw):
            seen_during.append(([p.name for p in self.cfg.snapshots_dir.iterdir()], snapshots(self.cfg.snapshots_dir)))
            return real(src, dst, *a, **kw)

        snapshot.shutil.copy2 = copy2
        try:
            dest, count = snapshot.save_snapshot(self.cfg, "storm")
        finally:
            snapshot.shutil.copy2 = real
        self.assertEqual(count, 3)
        self.assertTrue(all(names == [snapshot.STAGING_DIR] and listed == [] for names, listed in seen_during))
        self.assertEqual(sorted(p.name for p in self.cfg.snapshots_dir.iterdir()),
                         sorted([dest.name, snapshot.STAGING_DIR]))                          # renamed into place
        self.assertEqual(list((self.cfg.snapshots_dir / snapshot.STAGING_DIR).iterdir()), [])
        self.assertEqual([i["label"] for i in snapshots(self.cfg.snapshots_dir)], ["storm"])

    def test_a_half_copy_left_by_a_dead_run_is_discarded_at_the_next_start(self):
        # os._exit (the stall watchdog, a SIGTERM) unwinds no thread: the
        # except in save_snapshot never ran, and the .partial directory stayed.
        left = self.cfg.snapshots_dir / snapshot.STAGING_DIR / "20260904T200112_auto-storm"
        left.mkdir(parents=True)
        (left / "threadwatch-20260904-19.pcap").write_bytes(b"x" * 50)
        whole = self.cfg.snapshots_dir / "20260903T120000_manual"
        whole.mkdir()
        self.assertEqual(snapshot.discard_partials(self.cfg.snapshots_dir), ["auto-storm"])
        self.assertEqual(sorted(p.name for p in self.cfg.snapshots_dir.iterdir()),
                         sorted([whole.name, snapshot.STAGING_DIR]))
        self.assertFalse(left.exists())
        self.assertEqual(snapshot.discard_partials(self.cfg.snapshots_dir), [])
        self.assertEqual(snapshot.discard_partials(self.cfg.snapshots_dir / "missing"), [])

    def test_a_copy_still_running_is_not_a_leftover_for_the_next_start(self):
        # BUG-10: a snapshot taken by hand is another process and may overlap a
        # recorder restart, whose start-up cleanup removed its staging
        # directory mid-copy; the copies after that failed as "source
        # pruned", copytree remade the directory, and the copy reported
        # success with a count and no packets.
        import threading

        from threadwatch.review import snapshots
        cfg = self.cfg
        cfg.events_dir.mkdir(parents=True)
        (cfg.events_dir / "2026-09-03.jsonl").write_text("")
        copied, resume = threading.Event(), threading.Event()
        real = shutil.copy2

        def copy2(src, dst, *a, **kw):
            out = real(src, dst, *a, **kw)
            if src.name.endswith("-00.pcap"):
                copied.set()
                resume.wait(5)
            return out

        result = {}

        def worker():
            try:
                result["ok"] = snapshot.save_snapshot(cfg, "manual", now=1_700_000_000)
            except BaseException as exc:
                result["err"] = exc

        snapshot.shutil.copy2 = copy2
        try:
            t = threading.Thread(target=worker)
            t.start()
            self.assertTrue(copied.wait(5))
            self.assertEqual(snapshot.discard_partials(cfg.snapshots_dir), [])  # recorder starting: nothing to discard
            staging = cfg.snapshots_dir / snapshot.STAGING_DIR
            names = sorted(p.name for p in staging.iterdir())
            self.assertEqual(len(names), 2, names)                              # the copy and its held lock
            self.assertTrue(names[1] == names[0] + snapshot.LOCK_SUFFIX and (staging / names[0]).is_dir(), names)
            self.assertEqual([p.name[-7:-5] for p in (staging / names[0]).glob("*.pcap")], ["00"])   # still there
            resume.set()
            t.join(5)
        finally:
            snapshot.shutil.copy2 = real
            resume.set()
        self.assertNotIn("err", result, result.get("err"))
        dest, count = result["ok"]
        self.assertEqual(count, 3)
        self.assertEqual(sorted(p.name[-7:-5] for p in dest.glob("*.pcap")), ["00", "01", "02"])
        self.assertTrue((dest / "events").is_dir())
        self.assertEqual([i["label"] for i in snapshots(cfg.snapshots_dir)], ["manual"])
        self.assertEqual(list((cfg.snapshots_dir / snapshot.STAGING_DIR).iterdir()), [])    # lock and staging gone
        self.assertEqual(snapshot.discard_partials(cfg.snapshots_dir), [])

    def test_a_destination_that_vanishes_mid_copy_is_a_failure_not_a_success(self):
        real = shutil.copy2

        def copy2(src, dst, *a, **kw):
            if src.name.endswith("-01.pcap"):
                shutil.rmtree(dst.parent)                       # something removed the staging directory
            return real(src, dst, *a, **kw)

        snapshot.shutil.copy2 = copy2
        try:
            with self.assertRaises(FileNotFoundError):
                snapshot.save_snapshot(self.cfg, "manual")
        finally:
            snapshot.shutil.copy2 = real
        from threadwatch.review import snapshots
        self.assertEqual(snapshots(self.cfg.snapshots_dir), [])
        self.assertEqual(len(list(self.cfg.ring_dir.glob("*.pcap"))), 3)     # the sources were all there

    def test_a_dead_runs_lock_does_not_protect_its_leftover(self):
        staging = self.cfg.snapshots_dir / snapshot.STAGING_DIR
        left = staging / "20260904T200112_auto-storm"
        left.mkdir(parents=True)
        (left / "threadwatch-20260904-19.pcap").write_bytes(b"x")
        (staging / (left.name + snapshot.LOCK_SUFFIX)).write_bytes(b"")       # nobody holds it: the run is gone
        (staging / ("20260904T200500_manual" + snapshot.LOCK_SUFFIX)).write_bytes(b"")   # died before mkdir
        self.assertEqual(snapshot.discard_partials(self.cfg.snapshots_dir), ["auto-storm"])
        self.assertEqual(list(staging.iterdir()), [])

    def test_a_snapshot_right_after_a_write_holds_that_record(self):
        # BUG-02: the ring writer buffered records in Python; a snapshot copies
        # the active file through its own handle and saw a zero-byte pcap
        # early in the hour, or an older tail later in it.
        from threadwatch.pcap import Frame, PcapStreamReader
        from threadwatch.record import RingWriter
        for f in self.cfg.ring_dir.glob("*.pcap"):
            f.unlink()
        ring = RingWriter(self.cfg.ring_dir, keep_hours=10, dlt=230)
        try:
            ring.write(Frame(ts=1_700_000_000.25, raw=b"\x01\x02\x03\x04\x05", psdu=b"",
                             rssi=None, channel=None, lqi=None))
            dest, count = snapshot.save_snapshot(self.cfg, "now", now=1_700_000_010)
        finally:
            ring.close()
        self.assertEqual(count, 1)
        copied = next(dest.glob("threadwatch-*.pcap"))
        with open(copied, "rb") as fh:
            frames = list(PcapStreamReader(fh))
        self.assertEqual([(f.ts, f.raw) for f in frames], [(1_700_000_000.25, b"\x01\x02\x03\x04\x05")])

    def test_a_dead_copy_with_a_label_ending_in_lock_is_discarded_not_fatal(self):
        # safe_label keeps periods, so `threadwatch snapshot debug.lock` stages
        # a directory whose name ends in the lock suffix. Cleanup used to
        # skip it as a lock, then open it as one and raise IsADirectoryError
        # on every start until someone removed it by hand.
        staging = self.cfg.snapshots_dir / snapshot.STAGING_DIR
        left = staging / "20260905T120000_debug.lock"
        left.mkdir(parents=True)
        (left / "threadwatch-20260905-11.pcap").write_bytes(b"x")
        (staging / (left.name + snapshot.LOCK_SUFFIX)).write_bytes(b"")       # its own lock, nobody holds it
        self.assertEqual(snapshot.discard_partials(self.cfg.snapshots_dir), ["debug.lock"])
        self.assertEqual(list(staging.iterdir()), [])
        # And a finished copy with that label is a whole snapshot.
        dest, count = snapshot.save_snapshot(self.cfg, "debug.lock", now=1_700_000_000)
        self.assertEqual(count, 3)
        self.assertEqual(snapshot.discard_partials(self.cfg.snapshots_dir), [])
        self.assertTrue(dest.is_dir())

    def test_a_label_ending_in_partial_is_a_whole_snapshot_like_any_other(self):
        # BUG-01: safe_label keeps periods, so "test.partial" used to name a
        # finished snapshot the way a half copy was named; the listing hid
        # it and the next start deleted it.
        from threadwatch.review import snapshots
        dest, count = snapshot.save_snapshot(self.cfg, "test.partial", now=1_700_000_000)
        self.assertEqual(count, 3)
        self.assertEqual(dest.name.rpartition("_")[2], "test.partial")
        self.assertEqual([i["label"] for i in snapshots(self.cfg.snapshots_dir)], ["test.partial"])
        self.assertEqual(snapshot.discard_partials(self.cfg.snapshots_dir), [])          # the next start
        self.assertTrue(dest.is_dir())
        self.assertEqual(len(list(dest.glob("*.pcap"))), 3)
        self.assertEqual([i["label"] for i in snapshots(self.cfg.snapshots_dir)], ["test.partial"])

    def test_an_existing_snapshot_or_half_copy_is_never_written_into(self):
        now = 1_756_900_000.0
        dest, _count = snapshot.save_snapshot(self.cfg, "storm", now=now)
        before = sorted(p.name for p in dest.iterdir())
        (dest / "threadwatch-20260903-00.pcap").write_bytes(b"kept")       # the snapshot as the operator left it
        with self.assertRaises(FileExistsError) as cm:
            snapshot.save_snapshot(self.cfg, "storm", now=now)                 # the same label, the same second
        self.assertIn(dest.name, str(cm.exception))
        self.assertEqual(sorted(p.name for p in dest.iterdir()), before)
        self.assertEqual((dest / "threadwatch-20260903-00.pcap").read_bytes(), b"kept")
        self.assertEqual(list((self.cfg.snapshots_dir / snapshot.STAGING_DIR).iterdir()), [])   # no half copy left
        # A half copy under the same name (a copy still running, or one
        # a dead run left) is not a directory to add to either.
        partial = self.cfg.snapshots_dir / snapshot.STAGING_DIR / dest.name.replace("storm", "quiet")
        partial.mkdir()
        (partial / "stale.pcap").write_bytes(b"x")
        with self.assertRaises(FileExistsError):
            snapshot.save_snapshot(self.cfg, "quiet", now=now)
        self.assertEqual([p.name for p in partial.iterdir()], ["stale.pcap"])
        self.assertEqual(sorted(p.name for p in self.cfg.snapshots_dir.iterdir()),
                         sorted([dest.name, snapshot.STAGING_DIR]))


class SnapshotRetentionTest(unittest.TestCase):
    """Automatic snapshots are the only ones nobody remembers to delete."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config(data_dir=Path(self.tmp.name) / "data")
        self.cfg.snapshots_dir.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _snapshot(self, name: str, trigger: str = "manual") -> Path:
        d = self.cfg.snapshots_dir / name
        d.mkdir()
        (d / "threadwatch-20260903-00.pcap").write_bytes(b"x" * 100)
        (d / snapshot.MANIFEST).write_text(json.dumps({"format": 1, "label": name.partition("_")[2],
                                                       "trigger": trigger}))
        return d

    def _names(self):
        return sorted(p.name for p in self.cfg.snapshots_dir.iterdir())

    def test_the_oldest_automatic_snapshots_go_and_the_named_ones_stay(self):
        for stamp in ("20260901T000000", "20260902T000000", "20260903T000000"):
            self._snapshot(f"{stamp}_auto-storm", trigger="phase_locked_storm")
        self._snapshot("20260831T000000_the-night-it-broke")   # saved by hand, older than all of them
        self._snapshot(f"{snapshot.STAGING_DIR}")                # a copy in progress is not a snapshot
        removed = snapshot.prune_auto_snapshots(self.cfg.snapshots_dir, 2)
        self.assertEqual(removed, ["20260901T000000_auto-storm"])
        self.assertEqual(self._names(), [snapshot.STAGING_DIR, "20260831T000000_the-night-it-broke",
                                         "20260902T000000_auto-storm", "20260903T000000_auto-storm"])

    def test_keep_zero_prunes_them_all_and_a_negative_keep_is_no_cap(self):
        for stamp in ("20260901T000000", "20260902T000000"):
            self._snapshot(f"{stamp}_auto-storm", trigger="phase_locked_storm")
        self.assertEqual(snapshot.prune_auto_snapshots(self.cfg.snapshots_dir, -1), [])
        self.assertEqual(len(self._names()), 2)
        self.assertEqual(snapshot.prune_auto_snapshots(self.cfg.snapshots_dir, 0),
                         ["20260901T000000_auto-storm", "20260902T000000_auto-storm"])
        self.assertEqual(self._names(), [])
        self.assertEqual(snapshot.prune_auto_snapshots(self.cfg.snapshots_dir / "gone", 1), [])

    def test_a_snapshot_saved_by_hand_and_called_auto_is_not_pruned(self):
        # The label is the operator's to choose and the CLI reserves no
        # prefix: what makes a snapshot automatic is the trigger that
        # asked for it, in the manifest.
        self._snapshot("20260901T000000_auto-investigation")                       # typed at the CLI
        self._snapshot("20260902T000000_auto-storm", trigger="phase_locked_storm")  # the recorder's
        self.assertEqual(snapshot.prune_auto_snapshots(self.cfg.snapshots_dir, 0),
                         ["20260902T000000_auto-storm"])
        self.assertEqual(self._names(), ["20260901T000000_auto-investigation"])

    def test_a_bundle_with_no_readable_manifest_is_kept(self):
        # Only a copy cut short has no manifest, and one whose manifest
        # cannot be read cannot say who asked for it. Deleting evidence on
        # that guess is the one outcome with no way back.
        nameless = self._snapshot("20260901T000000_auto-storm", trigger="phase_locked_storm")
        (nameless / snapshot.MANIFEST).unlink()
        torn = self._snapshot("20260902T000000_auto-storm", trigger="phase_locked_storm")
        (torn / snapshot.MANIFEST).write_text("{not json")
        self.assertEqual(snapshot.prune_auto_snapshots(self.cfg.snapshots_dir, 0), [])
        self.assertEqual(len(self._names()), 2)


if __name__ == "__main__":
    unittest.main()
