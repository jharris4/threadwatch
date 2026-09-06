"""freeze_ring against a ring that keeps rotating."""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.config import Config  # noqa: E402
from threadwatch import freeze  # noqa: E402


class BundleTest(unittest.TestCase):
    """What travels with the packets: the inventory, the configuration
    with its secrets blanked, and a manifest naming it all."""

    def test_redaction_blanks_secret_values_and_keeps_the_shape(self):
        import tomllib
        text = ('[network]\nchannel = 25\nkeep_files = 168\n'
                '[[alerts.sinks]]\nname = "phone"\ntype = "ntfy"\nurl = "https://ntfy.example/t-9f3a"   # topic\n'
                'token = "${NTFY_TOKEN}"\nheaders = { Authorization = "Bearer hunter2", "X-Y" = "]" }\n'
                'command = [\n  "curl", "-H", "Auth: hunter3",\n  "https://x.example/{event}",\n]\n'
                'min_severity = "warning"\n[[heartbeats]]\nfailure_url = "https://hc.example/fail"\n'
                '[credentials]\nnetwork_key = "00112233"\nfile = "credentials.toml"\n')
        out = freeze.redact_config(text)
        for secret in ("9f3a", "hunter2", "hunter3", "NTFY_TOKEN", "hc.example", "00112233"):
            self.assertNotIn(secret, out)
        parsed = tomllib.loads(out)
        self.assertEqual(parsed["network"], {"channel": 25, "keep_files": 168})
        self.assertEqual(parsed["alerts"]["sinks"], [{"name": "phone", "type": "ntfy", "url": "<redacted>",
                                                      "token": "<redacted>", "headers": "<redacted>",
                                                      "command": "<redacted>", "min_severity": "warning"}])
        self.assertEqual(parsed["heartbeats"], [{"failure_url": "<redacted>"}])
        self.assertEqual(parsed["credentials"], {"network_key": "<redacted>", "file": "credentials.toml"})
        self.assertEqual(freeze.redact_config(""), "")

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
        out = freeze.redact_config(text)
        for secret in ("abc123", "hunter2", "k9", "00112233"):
            self.assertNotIn(secret, out)
        parsed = tomllib.loads(out)
        self.assertEqual(parsed["alerts"]["webhook_url"], "<redacted>")
        self.assertEqual(parsed["alerts"]["note"], "kept: two lines\nof prose\n")
        self.assertEqual(parsed["alerts"]["sinks"], [{"name": "phone", "min_severity": "warning",
                                                      "headers": {"Authorization": "<redacted>",
                                                                  "X-Api-Key": "<redacted>"}}])
        self.assertEqual(parsed["credentials"], {"network_key": "<redacted>", "file": "credentials.toml"})

    def test_the_shipped_example_config_survives_redaction_as_valid_toml(self):
        import tomllib
        from threadwatch.config import REPO_ROOT
        text = (REPO_ROOT / "config" / "config.example.toml").read_text()
        out = freeze.redact_config(text)
        self.assertEqual(tomllib.loads(out).keys(), tomllib.loads(text).keys())
        self.assertIn("# ", out)                       # the comments explain what was in force

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
            dest, count = freeze.freeze_ring(cfg, "auto-storm", now=1_756_900_000.0, trigger="phase_locked_storm")
            m = json.loads((dest / "manifest.json").read_text())
            self.assertEqual((m["format"], m["label"], m["trigger"], m["channel"], m["pan_id"], m["ring_files"],
                              m["span"], m["inventory"], m["config"], m["events_days"], m["frozen_at"]),
                             (1, "auto-storm", "phase_locked_storm", 15, "0x4e21", 1,
                              ["20260903-01", "20260903-01"], "devices.json", "config.toml", 0, 1_756_900_000.0))
            self.assertEqual(sorted(m["files"]), ["config.toml", "devices.json", "threadwatch-20260903-01.pcap"])
            self.assertNotIn("manifest.json", m["files"])                # written last, after the listing
            self.assertNotIn("https://s", (dest / "config.toml").read_text())
            self.assertIn("read_with", m)
            # Nothing to copy: the manifest says so instead of failing.
            bare = Config(data_dir=d / "data2")
            bare.ring_dir.mkdir(parents=True)
            dest, _ = freeze.freeze_ring(bare, "bare")
            m = json.loads((dest / "manifest.json").read_text())
            self.assertEqual((m["inventory"], m["config"], m["span"], m["files"]), (None, None, None, {}))


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

    def test_a_snapshot_short_of_what_was_copied_is_a_failure_not_an_incident(self):
        # The last line of defence for the bundle's one promise: that it
        # holds every ring file it says it does. If it stopped firing, a
        # truncated incident would be written, manifested and reported as
        # whole, and nothing else would notice.
        real = shutil.copy2

        def copy2(src, dst, *a, **kw):
            out = real(src, dst, *a, **kw)
            if src.name.endswith("-01.pcap"):
                Path(dst).unlink()          # copied, then gone: the count and the directory disagree
            return out

        freeze.shutil.copy2 = copy2
        try:
            with self.assertRaises(OSError) as cm:
                freeze.freeze_ring(self.cfg, "storm")
        finally:
            freeze.shutil.copy2 = real
        self.assertIn("3 ring files were copied but the snapshot holds 2", str(cm.exception))
        self.assertEqual(list(self.cfg.incidents_dir.glob("*_storm")), [])
        self.assertEqual(list((self.cfg.incidents_dir / freeze.STAGING_DIR).iterdir()), [])

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

    def test_a_freeze_still_running_is_not_a_leftover_for_the_next_start(self):
        # BUG-10: a manual freeze is another process and may overlap a
        # recorder restart, whose start-up cleanup removed its staging
        # directory mid-copy; the copies after that failed as "source
        # pruned", copytree remade the directory, and the freeze reported
        # success with a count and no packets.
        import threading
        from threadwatch.review import incidents
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
                result["ok"] = freeze.freeze_ring(cfg, "manual", now=1_700_000_000)
            except BaseException as exc:
                result["err"] = exc

        freeze.shutil.copy2 = copy2
        try:
            t = threading.Thread(target=worker)
            t.start()
            self.assertTrue(copied.wait(5))
            self.assertEqual(freeze.discard_partials(cfg.incidents_dir), [])     # the recorder starting: nothing to discard
            staging = cfg.incidents_dir / freeze.STAGING_DIR
            names = sorted(p.name for p in staging.iterdir())
            self.assertEqual(len(names), 2, names)                              # the copy and its held lock
            self.assertTrue(names[1] == names[0] + freeze.LOCK_SUFFIX and (staging / names[0]).is_dir(), names)
            self.assertEqual([p.name[-7:-5] for p in (staging / names[0]).glob("*.pcap")], ["00"])   # still there
            resume.set()
            t.join(5)
        finally:
            freeze.shutil.copy2 = real
            resume.set()
        self.assertNotIn("err", result, result.get("err"))
        dest, count = result["ok"]
        self.assertEqual(count, 3)
        self.assertEqual(sorted(p.name[-7:-5] for p in dest.glob("*.pcap")), ["00", "01", "02"])
        self.assertTrue((dest / "events").is_dir())
        self.assertEqual([i["label"] for i in incidents(cfg.incidents_dir)], ["manual"])
        self.assertEqual(list((cfg.incidents_dir / freeze.STAGING_DIR).iterdir()), [])    # lock and staging gone
        self.assertEqual(freeze.discard_partials(cfg.incidents_dir), [])

    def test_a_destination_that_vanishes_mid_copy_is_a_failure_not_a_success(self):
        real = shutil.copy2

        def copy2(src, dst, *a, **kw):
            if src.name.endswith("-01.pcap"):
                shutil.rmtree(dst.parent)                       # something removed the staging directory
            return real(src, dst, *a, **kw)

        freeze.shutil.copy2 = copy2
        try:
            with self.assertRaises(FileNotFoundError):
                freeze.freeze_ring(self.cfg, "manual")
        finally:
            freeze.shutil.copy2 = real
        from threadwatch.review import incidents
        self.assertEqual(incidents(self.cfg.incidents_dir), [])
        self.assertEqual(len(list(self.cfg.ring_dir.glob("*.pcap"))), 3)     # the sources were all there

    def test_a_dead_runs_lock_does_not_protect_its_leftover(self):
        staging = self.cfg.incidents_dir / freeze.STAGING_DIR
        left = staging / "20260904T200112_auto-storm"
        left.mkdir(parents=True)
        (left / "threadwatch-20260904-19.pcap").write_bytes(b"x")
        (staging / (left.name + freeze.LOCK_SUFFIX)).write_bytes(b"")       # nobody holds it: the run is gone
        (staging / ("20260904T200500_manual" + freeze.LOCK_SUFFIX)).write_bytes(b"")   # died before mkdir
        self.assertEqual(freeze.discard_partials(self.cfg.incidents_dir), ["auto-storm"])
        self.assertEqual(list(staging.iterdir()), [])

    def test_a_freeze_right_after_a_write_holds_that_record(self):
        # BUG-02: the ring writer buffered records in Python; a freeze copies
        # the active file through its own handle and saw a zero-byte pcap
        # early in the hour, or an older tail later in it.
        from threadwatch.capture import RingWriter
        from threadwatch.pcap import Frame, PcapStreamReader
        for f in self.cfg.ring_dir.glob("*.pcap"):
            f.unlink()
        ring = RingWriter(self.cfg.ring_dir, keep_files=10, dlt=230)
        try:
            ring.write(Frame(ts=1_700_000_000.25, raw=b"\x01\x02\x03\x04\x05", psdu=b"",
                             rssi=None, channel=None, lqi=None))
            dest, count = freeze.freeze_ring(self.cfg, "now", now=1_700_000_010)
        finally:
            ring.close()
        self.assertEqual(count, 1)
        copied = next(dest.glob("threadwatch-*.pcap"))
        with open(copied, "rb") as fh:
            frames = list(PcapStreamReader(fh))
        self.assertEqual([(f.ts, f.raw) for f in frames], [(1_700_000_000.25, b"\x01\x02\x03\x04\x05")])

    def test_a_dead_freeze_with_a_label_ending_in_lock_is_discarded_not_fatal(self):
        # safe_label keeps periods, so `threadwatch freeze debug.lock` stages
        # a directory whose name ends in the lock suffix. Cleanup used to
        # skip it as a lock, then open it as one and raise IsADirectoryError
        # on every start until someone removed it by hand.
        staging = self.cfg.incidents_dir / freeze.STAGING_DIR
        left = staging / "20260905T120000_debug.lock"
        left.mkdir(parents=True)
        (left / "threadwatch-20260905-11.pcap").write_bytes(b"x")
        (staging / (left.name + freeze.LOCK_SUFFIX)).write_bytes(b"")       # its own lock, nobody holds it
        self.assertEqual(freeze.discard_partials(self.cfg.incidents_dir), ["debug.lock"])
        self.assertEqual(list(staging.iterdir()), [])
        # And a finished freeze with that label is a whole incident.
        dest, count = freeze.freeze_ring(self.cfg, "debug.lock", now=1_700_000_000)
        self.assertEqual(count, 3)
        self.assertEqual(freeze.discard_partials(self.cfg.incidents_dir), [])
        self.assertTrue(dest.is_dir())

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


class IncidentRetentionTest(unittest.TestCase):
    """Automatic snapshots are the only ones nobody remembers to delete."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config(data_dir=Path(self.tmp.name) / "data")
        self.cfg.incidents_dir.mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _incident(self, name: str) -> Path:
        d = self.cfg.incidents_dir / name
        d.mkdir()
        (d / "threadwatch-20260903-00.pcap").write_bytes(b"x" * 100)
        return d

    def _names(self):
        return sorted(p.name for p in self.cfg.incidents_dir.iterdir())

    def test_the_oldest_automatic_incidents_go_and_the_named_ones_stay(self):
        for stamp in ("20260901T000000", "20260902T000000", "20260903T000000"):
            self._incident(f"{stamp}_auto-storm")
        self._incident("20260831T000000_the-night-it-broke")   # frozen by hand, older than all of them
        self._incident(f"{freeze.STAGING_DIR}")                # a copy in progress is not an incident
        removed = freeze.prune_auto_incidents(self.cfg.incidents_dir, 2)
        self.assertEqual(removed, ["20260901T000000_auto-storm"])
        self.assertEqual(self._names(), [freeze.STAGING_DIR, "20260831T000000_the-night-it-broke",
                                         "20260902T000000_auto-storm", "20260903T000000_auto-storm"])

    def test_keep_zero_prunes_them_all_and_a_negative_keep_is_no_cap(self):
        for stamp in ("20260901T000000", "20260902T000000"):
            self._incident(f"{stamp}_auto-storm")
        self.assertEqual(freeze.prune_auto_incidents(self.cfg.incidents_dir, -1), [])
        self.assertEqual(len(self._names()), 2)
        self.assertEqual(freeze.prune_auto_incidents(self.cfg.incidents_dir, 0),
                         ["20260901T000000_auto-storm", "20260902T000000_auto-storm"])
        self.assertEqual(self._names(), [])
        self.assertEqual(freeze.prune_auto_incidents(self.cfg.incidents_dir / "gone", 1), [])
