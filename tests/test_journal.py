"""Synthetic transition stories; no household identities or captured traffic."""

import gzip
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_otbr import T, log_lines
from tests.test_pipeline import SENSOR, frame, stub_decryptor
from threadwatch.config import Config
from threadwatch.events import NullEventLog
from threadwatch.journal import Journal, read_report, scan_archive, text_report, unknown_coverage
from threadwatch.keyfacts import observe
from threadwatch.otbr import SLUG, extract
from threadwatch.pipeline import Pipeline


def observation(journal, seq, ts, addr="child", layer="mac", row=None, **kwargs):
    journal.observe(addr, layer, seq, ts, row=row or {},
                    context=lambda: {"role": "router" if addr == "router" else "child"},
                    packet=lambda: {"ts": ts}, coverage=lambda *_: unknown_coverage(), **kwargs)


def advance(journal, seq, ts, addr="child", previous=None, interval=None):
    journal.event({"event": "key_sequence_advanced", "ts": ts, "sequence": seq,
                   "previous": previous, "first_sender": addr, "frame": "mac_poll",
                   "observed_interval_s": interval})


class JournalTest(unittest.TestCase):
    def test_network_and_local_intervals_and_unknown_baseline(self):
        journal = Journal()
        day8 = T - (129.4 + 100.2) * 3600
        day13 = T - 100.2 * 3600
        observation(journal, 84, day8 - 60)
        observation(journal, 85, day8)
        advance(journal, 85, day8, previous=84)
        observation(journal, 86, day13, "router")
        advance(journal, 86, day13, "router", 85, 129.4 * 3600)
        observation(journal, 86, T - 100.1 * 3600)
        observation(journal, 87, T)
        advance(journal, 87, T, previous=86, interval=100.2 * 3600)
        report = journal.report()
        first, second, third = report["incidents"]
        self.assertIsNone(first["local_observed_interval_s"])
        self.assertIsNone(second["local_observed_interval_s"])
        self.assertAlmostEqual(second["network_observed_interval_s"] / 3600, 129.4)
        self.assertAlmostEqual(third["network_observed_interval_s"] / 3600, 100.2)
        self.assertAlmostEqual(third["local_observed_interval_s"] / 3600, 100.1)
        self.assertEqual(third["repeat_origin_count"], 2)
        self.assertFalse(third["origin_proven"])
        self.assertIn("100.100 h", text_report(report))

    def test_retries_rejections_and_late_packets_do_not_create_transitions(self):
        journal = Journal()
        observation(journal, 85, 10)
        observation(journal, 86, 11, accepted=False)
        observation(journal, 86, 12, retry=True)
        observation(journal, 87, 9)
        observation(journal, 85, 13)
        observation(journal, 86, 14)
        self.assertEqual(len(journal.records), 2)
        self.assertEqual(journal.records[-1]["last_old_observation_ts"], 13)
        self.assertIsNone(journal.report()["records"][-1]["previous_local_transition"])

    def test_mac_and_mle_are_separate_and_regression_is_observable(self):
        journal = Journal()
        for seq, ts, layer in ((85, 10, "mac"), (85, 11, "mle"), (86, 20, "mle"),
                               (86, 30, "mac"), (85, 40, "mac")):
            observation(journal, seq, ts, layer=layer)
        last = journal.report()["records"][-1]
        self.assertEqual(last["previous_local_transition"]["layer"], "mac")
        self.assertEqual(last["local_observed_interval_s"], 10)
        self.assertEqual((last["old_sequence"], last["new_sequence"]), (86, 85))

    def test_pre_journal_keyfacts_are_only_baseline(self):
        row = {}
        observe(row, "mac", 85, 10, accepted=True)
        journal = Journal()
        observation(journal, 86, 20, row=row)
        last = journal.report()["records"][-1]
        self.assertEqual(last["old_sequence"], 85)
        self.assertIsNone(last["local_observed_interval_s"])
        self.assertEqual(last["history"], "earlier_switch_unknown")

    def test_parent_request_and_recovery_milestones_are_not_reboots(self):
        journal = Journal()
        observation(journal, 85, 10)
        journal.event({"event": "mle_rejoin_attempt", "ts": 11, "addr": "child", "command": "Parent Request"})
        observation(journal, 86, 12)
        advance(journal, 86, 12, previous=85)
        for event, ts in (("key_lag", 13), ("key_lag_cleared", 14), ("ha_available", 15)):
            journal.event({"event": event, "ts": ts, "addr": "child"})
        incident = journal.report()["incidents"][0]
        self.assertEqual([r["evidence"]["event"] for r in incident["milestones"]],
                         ["key_lag", "key_lag_cleared", "ha_available"])
        self.assertEqual(incident["preceding_origin_evidence"][0]["evidence"]["command"], "Parent Request")
        self.assertEqual(incident["guard"]["assessment"], "unknown")
        self.assertFalse(any(r["kind"] == "reboot" for r in journal.records))

    def test_explicit_reboot_requires_reference_and_scope(self):
        journal = Journal()
        with self.assertRaises(ValueError):
            journal.reboot({"ts": 1, "addr": "child", "source": "parent_request"})
        record = {"ts": 1, "addr": "child", "source": "operator_action",
                  "scope": "device", "reference": "maintenance log: power cycle"}
        journal.reboot(record)
        journal.reboot(record)
        self.assertEqual(len(journal.records), 1)
        self.assertEqual(journal.records[0]["evidence"]["scope"], "device")

    def test_retention_count_and_loss_of_previous_history_are_explicit(self):
        journal = Journal()
        with patch("threadwatch.journal.MAX_RECORDS", 2):
            for seq in range(5):
                observation(journal, seq, seq * 10)
        self.assertEqual(len(journal.records), 2)
        self.assertEqual(journal.dropped, 3)
        self.assertIsNone(journal.report()["records"][0]["local_observed_interval_s"])
        journal.prune(91 * 86400)
        self.assertEqual(journal.records, [])

    def test_persistence_restart_and_hand_edited_shapes(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "key-journal.json"
            journal = Journal(path)
            for seq in range(3):
                observation(journal, seq, 10 + seq)
            journal.save(20, force=True)
            restarted = Journal(path)
            observation(restarted, 3, 30)
            self.assertEqual(restarted.report()["records"][-1]["local_observed_interval_s"], 18)
            path.write_text('{"version":1,"records":[null,{"id":"bad","ts":1,"kind":"transition"}]}')
            clean = Journal(path)
            self.assertEqual(clean.load_status, "partial")
            self.assertEqual(clean.report()["records"], [])
            path.write_text('[]')
            self.assertEqual(Journal(path).load_status, "unreadable")

    def test_inventory_uses_same_source_and_preserves_instance_scope(self):
        journal = Journal()
        def sample(ts, uptime, seq, host="test"):
            return {"completed_at": ts + 2, "source": {"ssh_target": host}, "commands": {
                "uptime": {"status": "ok", "output": uptime + "\nDone\n", "observed_at": ts},
                "keysequence counter": {"status": "ok", "value": seq, "observed_at": ts},
                "keysequence guardtime": {"status": "ok", "value": 624, "observed_at": ts}}}
        journal.inventory(sample(100, "01:00:00.000", 85))
        journal.inventory(sample(700, "01:10:00.000", 85))
        self.assertEqual(len(journal.records), 1)  # not one stored sample per poll
        journal.inventory(sample(800, "00:00:10.000", 86, host="other"))
        self.assertFalse(any(r["kind"] == "reboot" for r in journal.records))
        journal.inventory(sample(1300, "00:00:10.000", 86))
        reboot = next(r for r in journal.records if r["kind"] == "reboot")
        self.assertEqual(reboot["evidence"]["scope"], "openthread_instance")
        self.assertEqual(reboot["evidence"]["device_reboot"], "unknown")
        self.assertEqual(journal.records[-1]["evidence"]["guard"]["assessment"], "consistent_with_clear_guard")

    def test_pipeline_keeps_packet_and_parent_context_without_replay_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(data_dir=Path(tmp), devices_path=Path(tmp) / "devices.json")
            pipe = Pipeline(cfg, NullEventLog(), stub_decryptor(), ephemeral=True)
            for seq, ts in ((85, T - 10), (86, T), (87, T + 10)):
                pipe.ingest(frame(ts, SENSOR, sequence=seq, counter=10))
            report = pipe.journal.report()
            self.assertEqual(report["incidents"][-1]["local_observed_interval_s"], 10)
            origin = report["incidents"][-1]["origin_observation"]
            self.assertEqual(len(origin["packet"]["psdu_sha256"]), 64)
            self.assertEqual(origin["transport"], "802.15.4")
            self.assertEqual(origin["update_class"], "unknown")
            self.assertFalse((cfg.state_dir / "key-journal.json").exists())

    def test_dense_trel_traffic_does_not_hide_key_change_in_focused_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "ha-logs" / SLUG / "20260917-23.log.gz"
            path.parent.mkdir(parents=True)
            with gzip.open(path, "wt") as stream:
                stream.write(log_lines()[1].replace("23:14:59.648", "23:14:57.000") * 1100)
                stream.writelines(log_lines())
            report = extract(root, T - 10, T + 1, changes_only=True, limit=10)
            self.assertFalse(report["limited"])
            self.assertEqual([r["kind"] for r in report["records"]], ["trel_receive", "key_sequence_change"])
            journal = Journal()
            journal.otbr(report)
            journal.otbr(report)
            self.assertEqual(len(journal.records), 1)
            e = journal.records[0]["evidence"]
            self.assertIsNone(e["new_sequence"])
            self.assertEqual(e["transport"], "unknown")
            self.assertEqual(e["nearby"][0]["transport"], "trel")
            self.assertEqual(e["candidate_update_path"], "trel_receive_near_change")

    def test_read_report_imports_events_without_creating_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(data_dir=Path(tmp))
            cfg.events_dir.mkdir(parents=True)
            record = {"event": "key_sequence_advanced", "severity": "info", "ts": T, "sequence": 87, "previous": 86,
                      "first_sender": "child", "since_previous_s": 100.2 * 3600}
            (cfg.events_dir / "2026-09-17.jsonl").write_text(json.dumps(record) + "\n")
            with patch("threadwatch.journal.time.time", return_value=T + 1):
                report = read_report(cfg)
            self.assertEqual(report["incidents"][0]["network_observed_interval_s"], 100.2 * 3600)
            self.assertIsNone(report["incidents"][0]["local_observed_interval_s"])
            self.assertFalse((cfg.state_dir / "key-journal.json").exists())

    def test_restart_baseline_does_not_replace_earlier_network_observation(self):
        journal = Journal()
        advance(journal, 85, 10, previous=84)
        advance(journal, 86, 20, previous=85, interval=10)
        advance(journal, 86, 100)  # later recorder installation's baseline
        advance(journal, 87, 120, previous=86, interval=20)
        report = journal.report()
        self.assertEqual(len(report["incidents"]), 3)
        self.assertEqual(report["incidents"][-1]["network_observed_interval_s"], 100)
        self.assertEqual(report["incidents"][-1]["network_interval_source"], "retained_first_observations")
        self.assertEqual(report["incidents"][-1]["event"]["evidence"]["observed_interval_s"], 20)

    def test_child_request_is_only_a_candidate_not_a_completed_exchange(self):
        journal = Journal()
        observation(journal, 85, 10, addr="router")
        exchange = {"sender": "child", "receiver": "router", "ts": 20, "key_sequence": 86,
                    "command": "Child ID Request", "packet": {"ts": 20}}
        journal.observe("router", "mac", 86, 20.116, row={},
                        context=lambda: {"role": "router", "preceding_exchanges": [exchange]},
                        packet=lambda: {"ts": 20.116}, coverage=lambda *_: unknown_coverage())
        record = journal.records[-1]
        self.assertEqual(record["update_class"], "authoritative")
        self.assertEqual(record["update_class_confidence"], "candidate_only")
        self.assertEqual(record["transport"], "802.15.4")
        self.assertEqual(record["source_peer"], "child")
        self.assertEqual(record["link_reestablishment"], "unknown")
        self.assertTrue(record["update_path_assumptions"])

    def test_backward_clock_starts_unknown_history_without_rewriting_evidence(self):
        journal = Journal()
        observation(journal, 85, 100)
        observation(journal, 86, 110)
        journal.event({"event": "clock_step", "ts": 50, "step_s": -60})
        observation(journal, 87, 51)
        record = next(r for r in journal.report()["records"] if r["kind"] == "transition" and r["ts"] == 51)
        self.assertEqual(record["observation_kind"], "baseline")
        self.assertIsNone(record["local_observed_interval_s"])
        self.assertEqual(journal.records[1]["ts"], 110)

    def test_save_failure_does_not_stop_observation_and_bytes_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            journal = Journal(Path(tmp) / "key-journal.json")
            with patch("threadwatch.journal.MAX_BYTES", 2500):
                for seq in range(20):
                    observation(journal, seq, seq)
                self.assertLessEqual(journal._bytes, 2500)
                self.assertGreater(journal.dropped, 0)
                with patch.object(Path, "write_text", side_effect=OSError("disk full")):
                    journal.save(30, force=True)
                self.assertTrue(journal.dirty)
                observation(journal, 21, 31)
                journal.save(32, force=True)
                self.assertLessEqual(journal.path.stat().st_size, 2500)

    def test_archive_backfill_is_bounded_and_replaced_hours_are_revisited(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = root / "ha-logs" / SLUG
            directory.mkdir(parents=True)
            for hour in (21, 22, 23):
                with gzip.open(directory / f"20260917-{hour}.log.gz", "wt") as stream:
                    stream.write(f"2026-09-17 {hour}:00:00.000 host otbr[123]: s6-rc: info: "
                                 "service otbr-agent successfully started\n")
            first = scan_archive(root, {}, limit=1)
            self.assertEqual(first["pending_files"], 2)
            self.assertIn("20260917-23.log.gz", first["files"])
            second = scan_archive(root, first["files"], limit=2)
            self.assertEqual(second["pending_files"], 0)
            journal = Journal()
            journal.apply_archive_scan(first)
            journal.apply_archive_scan(second)
            self.assertEqual(len([r for r in journal.records if r["kind"] == "reboot"]), 3)
            self.assertEqual(scan_archive(root, second["files"])["reports"], [])
            with gzip.open(directory / "20260917-23.log.gz", "at") as stream:
                stream.write("2026-09-17 23:00:01.000 host: Notifier: StateChanged [KeySeqCntr]\n")
            third = scan_archive(root, second["files"])
            self.assertEqual(len(third["reports"]), 1)

    def test_pipeline_records_before_after_child_parent_deltas_and_rejected_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(data_dir=Path(tmp), devices_path=Path(tmp) / "devices.json")
            pipe = Pipeline(cfg, NullEventLog(), stub_decryptor(), ephemeral=True)
            parent = "0011223344556677"
            pipe.seen.table[parent] = {"rloc16": "d400", "rloc16_ts": T - 5}
            observe(pipe.seen.table[parent], "mac", 85, T - 5, accepted=True)
            pipe.ingest(frame(T - 3, SENSOR, sequence=86, counter=10))
            pipe.seen.table[SENSOR].update(rloc16="d43c", rloc16_ts=T - 2)
            observe(pipe.seen.table[parent], "mle", 87, T - 1, accepted=False, reason="counter_not_advancing")
            pipe.ingest(frame(T, SENSOR, sequence=87, counter=10))
            incident = pipe.journal.report()["incidents"][-1]
            context = incident["origin_observation"]["context"]["parent"]
            self.assertEqual(context["child_minus_parent_before"], 1)
            self.assertTrue(context["child_one_ahead_before"])
            self.assertEqual(context["child_minus_parent"], 2)
            self.assertTrue(context["fresh"])
            earlier = incident["earlier_higher_sequence"]["keyfacts"]
            self.assertEqual(earlier[0]["decision"], "rejected")
            self.assertEqual(earlier[0]["sequence"], 87)


if __name__ == "__main__":
    unittest.main()
