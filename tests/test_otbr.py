"""Synthetic OTBR evidence: no captured logs, identities or credentials."""

import gzip
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from threadwatch import otbr
from threadwatch.config import Config, load

T = 1789686899.650
EXT = "0011223344556677"


def inventory(at=T - 60, rloc="ec00"):
    return {"completed_at": at + 1, "source": {"ssh_target": "test@ha", "container": "otbr"},
            "commands": {
                "trel peers": {"status": "ok", "observed_at": at, "rows": [{"extmacaddress": EXT}]},
                "router table": {"status": "ok", "observed_at": at,
                                 "rows": [{"rloc16": rloc, "extaddr": EXT}]}}}


def log_lines():
    return ["2026-09-17 23:14:59.640 host otbr[123]: preceding context\n",
            "2026-09-17 23:14:59.648 host otbr[123]: MeshForwarder-: Received IPv6 UDP msg, "
            "from:0xec00, sec:yes, radio:trel\n",
            "2026-09-17 23:14:59.649 host otbr[123]: intermediate context\n",
            "2026-09-17 23:14:59.650 host otbr[123]: Notifier: StateChanged [KeySeqCntr]\n",
            "2026-09-17 23:14:59.651 host otbr[123]: Mac: Frame rx failed, error:Security, len:97, "
            "seqnum:5, type:Data, src:0xec00, dst:0x8800\n",
            "2026-09-17 23:14:59.652 host otbr[123]: Mle: Receive Parent Request (fe80:0:0:0:1234:5678:9abc:def0)\n",
            "2026-09-17 23:14:59.653 host otbr[123]: Mle: Receive Child ID Request from 0xec01\n"]


class EvidenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "ha-logs" / otbr.SLUG / "20260917-23.log.gz"
        self.path.parent.mkdir(parents=True)
        with gzip.open(self.path, "wt") as f:
            f.writelines(log_lines())

    def tearDown(self):
        self.tmp.cleanup()

    def test_reported_timing_links_evidence_without_claiming_causality(self):
        report = otbr.extract(self.root, T - 1, T + 1, inventory={"samples": [inventory()]})
        self.assertEqual([r["kind"] for r in report["records"]], [
            "trel_receive", "key_sequence_change", "security_receive_failure", "parent_request", "child_id_request"])
        receive, change = report["records"][:2]
        self.assertEqual(receive["utc"], "2026-09-17 23:14:59.648")
        self.assertAlmostEqual(change["ts"] - receive["ts"], .002, places=5)
        self.assertEqual(change["nearby_evidence"], [receive["id"]])
        self.assertEqual((receive["file"], receive["line"]), (str(self.path), 2))
        self.assertEqual([c["line"] for c in change["context"]], [2, 3, 4, 5, 6])
        self.assertEqual([r["peer"] for r in report["records"]],
                         ["0xec00", None, "0xec00", "fe80:0:0:0:1234:5678:9abc:def0", "0xec01"])
        self.assertEqual(receive["peer_observation"]["extended_address"], EXT)
        self.assertEqual(receive["peer_observation"]["prior_adoption_path"], "unknown")
        self.assertTrue(all(r["update_class"] == "unknown" for r in report["records"]))
        self.assertEqual(change["confidence"], "temporal_proximity_only")
        self.assertFalse(report["complete"])  # absent metadata is not proof of completeness

    def test_future_stale_and_reassigned_tables_do_not_supply_incident_identity(self):
        for samples in ([inventory(T + 10)], [inventory(T - 1000)],
                        [inventory(T - 100), inventory(T - 10, "e400")]):
            with self.subTest(samples=samples):
                report = otbr.extract(self.root, T - 1, T + 1, inventory={"samples": samples})
                self.assertIsNone(report["records"][0]["peer_observation"])

    def test_missing_and_truncated_logs_keep_partial_evidence(self):
        compressed = self.path.read_bytes()
        self.path.write_bytes(compressed[:-8])
        report = otbr.extract(self.root, T - 1, T + 3600)
        self.assertFalse(report["complete"])
        self.assertEqual([f["read_status"] for f in report["files"]], ["truncated_or_unreadable", "missing"])
        self.assertEqual(report["records"][1]["kind"], "key_sequence_change")
        self.assertEqual(report["records"][1]["log_coverage"]["read_status"], "truncated_or_unreadable")

    def test_live_archive_state_supplies_coverage_for_fetched_hours(self):
        state = self.root / "state" / "ha-logs-archive.json"
        state.parent.mkdir()
        for pending, coverage, complete in (({}, "fetch_complete", True),
                                            ({"20260917-23": {"attempts": 1}}, "partial", False)):
            state.write_text(json.dumps({"addons": {otbr.SLUG: {
                "last_archived": "20260917-23", "pending": pending, "lost": {}}}}))
            with self.subTest(pending=pending):
                report = otbr.extract(self.root, T - 1, T + 1)
                self.assertEqual(report["files"][0]["coverage"], coverage)
                self.assertEqual(report["complete"], complete)
        # An hour newer than the last completed one is not vouched for.
        state.write_text(json.dumps({"addons": {otbr.SLUG: {
            "last_archived": "20260917-22", "pending": {}, "lost": {}}}}))
        self.assertEqual(otbr.extract(self.root, T - 1, T + 1)["files"][0]["coverage"], "unknown")

    def test_corrupt_compressed_payload_is_reported_instead_of_crashing(self):
        data = bytearray(self.path.read_bytes())
        data[len(data) // 2] ^= 255
        self.path.write_bytes(data)
        report = otbr.extract(self.root, T - 1, T + 1)
        self.assertEqual(report["files"][0]["read_status"], "truncated_or_unreadable")
        self.assertFalse(report["complete"])

    def test_snapshot_metadata_and_record_limits_are_explicit(self):
        (self.root / "manifest.json").write_text("{}")
        (self.root / "ha-logs.json").write_text(json.dumps({"addons": {otbr.SLUG: {"hours": {
            "20260917-23": {"complete": False, "source": "live", "error": "deadline passed"}}}}}))
        report = otbr.extract(self.root, T - 1, T + 1, limit=1)
        self.assertTrue(report["limited"])
        self.assertFalse(report["complete"])
        self.assertEqual(report["records"][0]["log_coverage"], {"coverage": "partial", "read_status": "limit"})

    def test_a_distant_receive_is_not_linked_and_missing_transport_stays_unknown(self):
        with gzip.open(self.path, "wt") as f:
            f.write(log_lines()[1].replace("23:14:59", "23:14:00"))
            f.write(log_lines()[3])
        report = otbr.extract(self.root, T - 120, T + 1)
        self.assertEqual(report["records"][1]["nearby_evidence"], [])
        self.assertEqual(report["records"][1]["transport"], "unknown")
        self.assertEqual(report["records"][1]["confidence"], "observation_only")


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config(data_dir=Path(self.tmp.name), otbr_ssh_target="test@ha", otbr_enabled=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_commands_are_fixed_and_remote_shell_parameters_cannot_be_injected(self):
        argv = otbr.command_argv(self.cfg, "trel peers")
        self.assertEqual(argv[-1], "docker exec app_core_openthread_border_router ot-ctl trel peers")
        for command in ("dataset active", "keysequence counter 99", "state; reboot"):
            with self.assertRaises(ValueError):
                otbr.command_argv(self.cfg, command)
        for target in ("-oProxyCommand=evil", "root@ha;id", "$(whoami)", "ha\nreboot"):
            self.cfg.otbr_ssh_target = target
            with self.assertRaises(ValueError):
                otbr.command_argv(self.cfg, "state")

    def test_identity_and_sudo_are_explicit_arguments_with_no_password_prompt(self):
        self.cfg.otbr_ssh_target = "hassio@ha"
        self.cfg.otbr_ssh_port = 2222
        self.cfg.otbr_ssh_identity_file = "~/.ssh/test key; literal"
        self.cfg.otbr_sudo = True
        argv = otbr.command_argv(self.cfg, "keysequence guardtime")
        self.assertEqual(argv[argv.index("-i") + 1], str(Path("~/.ssh/test key; literal").expanduser()))
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertEqual(argv[-4:-1], ["-p", "2222", "hassio@ha"])
        self.assertEqual(argv[-1], "sudo -n docker exec app_core_openthread_border_router ot-ctl keysequence guardtime")
        self.cfg.otbr_sudo = "sudo -S"
        with self.assertRaises(ValueError):
            otbr.command_argv(self.cfg, "state")

    def test_unsupported_command_keeps_other_readings_and_table_identity(self):
        calls = []
        def runner(argv):
            calls.append(argv)
            if argv[-1].endswith("uptime"):
                return {"status": "unsupported", "output": "Error 35: InvalidCommand"}
            return {"status": "ok", "output": "| RLOC16 | Extended MAC |\n|--------|--------------|\n"
                    f"| 0xec00 | {EXT} |\nDone\n"}
        sample = otbr.collect(self.cfg, runner=runner, clock=lambda: T)
        self.assertEqual(len(calls), 7)
        self.assertEqual(sample["status"], "partial")
        self.assertEqual(sample["commands"]["router table"]["rows"][0]["extendedmac"], EXT)
        self.assertEqual(sample["commands"]["state"]["status"], "ok")
        self.assertEqual(sample["commands"]["state"]["observed_at"], T)

    def test_real_cli_column_shapes_join_trel_to_router_and_parse_counter(self):
        def runner(argv):
            command = argv[-1]
            if command.endswith("trel peers"):
                output = f"| No | Ext MAC Address | IPv6 Socket Address |\n| 1 | {EXT} | [fe80::1]:1234 |\n"
            elif command.endswith("router table"):
                output = f"| ID | RLOC16 | Extended MAC |\n| 59 | 0xec00 | {EXT} |\n"
            elif "keysequence" in command:
                output = "87\n" if command.endswith("counter") else "624\n"
            else:
                output = "\n"
            return {"status": "ok", "output": output + "Done\n"}
        sample = otbr.collect(self.cfg, runner=runner, clock=lambda: T)
        peer = otbr.peer_at("ec00", T + 1, [sample])
        self.assertEqual(peer["extended_address"], EXT)
        self.assertEqual(peer["trel_peer"]["ipv6socketaddress"], "[fe80::1]:1234")
        self.assertEqual(sample["commands"]["keysequence counter"]["value"], 87)
        self.assertEqual(sample["commands"]["keysequence guardtime"]["value"], 624)

    def test_unreachable_stops_the_sample_and_persisted_backoff_survives_restart(self):
        calls = []
        def runner(argv):
            calls.append(argv)
            return {"status": "unreachable", "output": "connection refused"}
        sample = otbr.collect(self.cfg, runner=runner, clock=lambda: T)
        self.assertEqual(len(calls), 1)
        self.assertEqual(sample["status"], "failed")
        state = otbr.save_inventory(self.cfg.state_dir / otbr.STATE, {}, sample, 600)
        self.assertEqual(state["next_poll_at"], T + 1200)
        poller = otbr.InventoryPoller(self.cfg)
        with patch("threadwatch.otbr.collect", side_effect=AssertionError("polled too soon")):
            poller.tick(T + 100)
            self.assertIsNone(poller.thread)

    def test_worker_failure_does_not_escape_into_capture_and_history_is_bounded(self):
        poller = otbr.InventoryPoller(self.cfg)
        with patch("threadwatch.otbr.collect", side_effect=OSError("failed")):
            poller.tick(T)
            poller.thread.join(timeout=2)
        self.assertEqual(poller.status["status"], "failed")
        sample = {"completed_at": T, "status": "ok", "commands": {}}
        with patch("threadwatch.otbr.HISTORY_COUNT", 2):
            state = otbr.save_inventory(self.cfg.state_dir / otbr.STATE,
                                       {"samples": [{**sample, "completed_at": T - 8 * 86400}, sample, sample]},
                                       sample, 600)
        self.assertEqual(len(state["samples"]), 2)

    def test_subprocess_timeout_and_output_are_bounded(self):
        with patch("threadwatch.otbr.TIMEOUT_S", .1):
            start = time.monotonic()
            result = otbr.run_command([sys.executable, "-c", "import time; time.sleep(5)"])
        self.assertEqual(result["status"], "timeout")
        self.assertLess(time.monotonic() - start, 2)
        result = otbr.run_command([sys.executable, "-c", "print('x'*100000)"])
        self.assertEqual(result["status"], "output_limit")
        self.assertEqual(len(result["output"]), otbr.OUTPUT_LIMIT)

    def test_recorder_polling_is_optional_and_disabled_for_replay(self):
        from tests.test_pipeline import stub_decryptor
        from threadwatch.events import NullEventLog
        from threadwatch.pipeline import Pipeline

        self.cfg.border_router_browse_s = 0
        for enabled, ephemeral in ((False, False), (True, True), (True, False)):
            self.cfg.otbr_enabled = enabled
            pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor(), ephemeral=ephemeral)
            if enabled and not ephemeral:
                with patch.object(pipe._otbr_inventory, "tick") as tick:
                    pipe.periodic(T)
                    tick.assert_called_once_with(T)
            else:
                self.assertIsNone(pipe._otbr_inventory)
                pipe.periodic(T)
            self.assertEqual(pipe.seen.table, {})

    def test_inventory_travels_with_a_snapshot(self):
        from threadwatch.snapshot import save_snapshot

        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
        state = {"samples": [inventory()]}
        (self.cfg.state_dir / otbr.STATE).write_text(json.dumps(state))
        dest, _ = save_snapshot(self.cfg, "inventory", now=T)
        self.assertEqual(json.loads((dest / otbr.STATE).read_text()), state)

    def test_bad_saved_poll_time_does_not_break_recorder(self):
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg.state_dir / otbr.STATE).write_text(json.dumps({
            "samples": [None, {"completed_at": "yesterday"}], "next_poll_at": "tomorrow", "failures": "bad"}))
        poller = otbr.InventoryPoller(self.cfg)
        self.assertEqual(poller.next_poll, 0)
        self.assertIsNone(poller.status)

    def test_config_rejects_bad_limits_and_targets(self):
        path = Path(self.tmp.name) / "config.toml"
        for setting in ('enabled = true', 'poll_s = 1', 'poll_s = 901', 'poll_s = nan',
                        'ssh_target = "root@ha;id"', 'container = "otbr;id"', 'ssh_port = 0',
                        'sudo = "true"', 'ssh_identity_file = false', 'ssh_identity_file = "bad\\npath"'):
            path.write_text('[otbr]\n' + setting + '\n')
            with self.subTest(setting=setting), self.assertRaises(ValueError):
                load(path)
