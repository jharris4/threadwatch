"""Command-line subcommands that read and manage the data directory."""

import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.cli import main  # noqa: E402


class CliCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        (self.d / "config.toml").write_text(f'[capture]\ndata_dir = "{self.d / "data"}"\n')
        self.cfg = str(self.d / "config.toml")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main(["--config", self.cfg, *args])
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()


class IncidentsTest(CliCase):
    def test_list_and_delete(self):
        code, out, _ = self.run_cli("incidents")
        self.assertEqual((code, out.strip()), (0, "no frozen incidents (threadwatch freeze <label> makes one)"))
        inc = self.d / "data" / "incidents"
        for name in ("20260902T141500_storm", "20260903T090000_storm", "20260901T080000_quiet"):
            (inc / name).mkdir(parents=True)
            (inc / name / "threadwatch-20260902-12.pcap").write_bytes(b"x" * 100)
        code, out, err = self.run_cli("incidents")
        self.assertEqual(code, 0)
        self.assertEqual([l.split()[2] for l in out.splitlines()],
                         ["20260903T090000_storm", "20260902T141500_storm", "20260901T080000_quiet"])
        self.assertIn("3 incident(s), 300 B", err)
        (inc / "20260901T070000_storm-at-noon").mkdir()      # freeze wrote the label filename-safe...
        code, _, err = self.run_cli("incidents", "--delete", "storm at noon")   # ...delete takes it as typed
        self.assertEqual((code, err), (0, ""))
        self.assertFalse((inc / "20260901T070000_storm-at-noon").exists())
        code, _, err = self.run_cli("incidents", "--delete", "storm")
        self.assertEqual(code, 1)
        self.assertIn("names 2 incidents", err)
        code, out, _ = self.run_cli("incidents", "--delete", "quiet")
        self.assertEqual(code, 0)
        self.assertFalse((inc / "20260901T080000_quiet").exists())
        code, _, _ = self.run_cli("incidents", "--delete", "20260902T141500_storm/")
        self.assertEqual(code, 0)
        self.assertEqual([p.name for p in inc.iterdir()], ["20260903T090000_storm"])
        code, _, err = self.run_cli("incidents", "--delete", "nothing")
        self.assertEqual(code, 1)
        self.assertIn("no incident named", err)


class AdoptTest(CliCase):
    def test_adopted_name_is_read_back_from_beside_the_config_file(self):
        from unittest import mock
        from threadwatch import config as config_mod
        from threadwatch.names import DeviceNames
        # This checkout may carry a real config/devices.json; keep the test
        # (and adopt's write) away from it.
        with mock.patch.object(config_mod, "REPO_ROOT", self.d / "repo"):
            self.assertIsNone(config_mod.load(Path(self.cfg)).devices_path)   # no inventory anywhere yet
            code, out, _ = self.run_cli("adopt", "66417fe110ed6950", "Office AQ")
            self.assertEqual(code, 0)
            self.assertIn(str(self.d / "devices.json"), out)
            cfg = config_mod.load(Path(self.cfg))
        self.assertEqual(cfg.devices_path, (self.d / "devices.json").resolve())   # load() resolves symlinks
        self.assertEqual(DeviceNames(cfg.devices_path).name("66417fe110ed6950"), "Office AQ")


class FreezeTest(CliCase):
    def test_freeze_copies_ring_state_and_events(self):
        from threadwatch.config import load
        cfg = load(Path(self.cfg))
        cfg.ring_dir.mkdir(parents=True)
        (cfg.ring_dir / "threadwatch-20260903-08.pcap").write_bytes(b"a")
        (cfg.ring_dir / "threadwatch-20260903-09.pcap").write_bytes(b"b")
        (cfg.state_dir / "last-seen.json").write_text("{}")
        (cfg.state_dir / "border-routers.json").write_text("{}")   # the hubs' address history
        cfg.events_dir.mkdir(parents=True)
        (cfg.events_dir / "2026-09-03.jsonl").write_text("")
        code, out, _ = self.run_cli("freeze", "my label/with junk")
        self.assertEqual(code, 0)
        self.assertIn("froze 2 ring files", out)
        inc = next(cfg.incidents_dir.iterdir())
        self.assertTrue(inc.name.endswith("_my-label-with-junk"))
        self.assertEqual(sorted(p.name for p in inc.iterdir()),
                         ["border-routers.json", "events", "last-seen.json",
                          "threadwatch-20260903-08.pcap", "threadwatch-20260903-09.pcap"])
        self.assertEqual(self.run_cli("incidents")[1].count("my-label-with-junk"), 1)


class EventsFilterTest(CliCase):
    def setUp(self):
        super().setUp()
        import json
        from threadwatch.config import load
        from threadwatch.events import EventLog
        (self.d / "devices.json").write_text(json.dumps([
            {"name": "Living Room Apple TV", "extendedAddresses": ["b62c32bf669272db", "e6c279e8f0c70298"]},
            {"name": "Office AQ", "extendedAddress": "26976e7f7d20964a"},
        ]))
        (self.d / "config.toml").write_text(f'[capture]\ndata_dir = "{self.d / "data"}"\n'
                                            f'[devices]\ninventory = "devices.json"\n')
        log = EventLog(load(Path(self.cfg)).events_dir)
        t = 1_756_800_000.0
        log.emit("device_quiet", "warning", t, addr="b62c32bf669272db", name="Living Room Apple TV", silent_for_s=1800)
        log.emit("device_first_seen", "info", t + 60, addr="e6c279e8f0c70298", name="Living Room Apple TV")
        log.emit("device_quiet", "notice", t + 120, addr="26976e7f7d20964a", name="Office AQ", silent_for_s=1800)
        log.emit("mle_rejoin_attempt", "notice", t + 180, src="8001")
        log.emit("phase_locked_storm", "critical", t + 240 + 86400)

    def events(self, *args):
        code, out, err = self.run_cli("events", *args)
        self.assertEqual(code, 0, err)
        return [l.split("]")[1].split()[0] for l in out.splitlines() if "]" in l]

    def test_device_and_severity_filters(self):
        self.assertEqual(self.events("--device", "apple tv"), ["device_quiet", "device_first_seen"])
        self.assertEqual(self.events("--device", "apple tv", "--severity", "warning"), ["device_quiet"])
        self.assertEqual(self.events("--severity", "notice"),
                         ["device_quiet", "device_quiet", "mle_rejoin_attempt", "phase_locked_storm"])
        self.assertEqual(self.events("--severity", "notice", "-n", "2"), ["mle_rejoin_attempt", "phase_locked_storm"])
        self.assertEqual(self.events("--device", "26976e7f7d20964a", "--episodes"), ["Office"])
        code, out, _ = self.run_cli("events", "--device", "Office", "--severity", "critical")
        self.assertEqual((code, out.strip()), (0, "no events about 'Office' at critical or above"))
        code, _, err = self.run_cli("events", "--device", "nobody")
        self.assertEqual(code, 2)
        self.assertIn("neither a 16-hex-char address nor a known device name", err)


if __name__ == "__main__":
    unittest.main()


class ConfigValidationTest(unittest.TestCase):
    """A config mistake must fail loudly, not silently record the wrong thing."""

    def _load(self, body):
        import tempfile
        from pathlib import Path as _P
        from threadwatch import config
        d = _P(tempfile.mkdtemp())
        (d / "config.toml").write_text(body)
        return config.load(d / "config.toml")

    def test_out_of_range_and_degenerate_values_are_rejected(self):
        for body in ('[network]\nchannel = 99\n',
                     '[network]\nchannel = 3\n',
                     '[capture]\nkeep_files = 0\n',
                     '[detect]\nperiod_onsets = 1\n'):
            with self.assertRaises(ValueError):
                self._load(body)

    def test_quoted_channel_is_coerced_not_carried_as_a_string(self):
        self.assertEqual(self._load('[network]\nchannel = "25"\n').channel, 25)

    def test_data_dir_expands_environment_variables(self):
        import os
        os.environ["TW_TEST_ROOT"] = "/tmp/tw-test-root"
        cfg = self._load('[capture]\ndata_dir = "$TW_TEST_ROOT/data"\n')
        self.assertEqual(str(cfg.data_dir), "/tmp/tw-test-root/data")

    def test_doctor_warns_when_no_config_file_was_read(self):
        from threadwatch import doctor
        from threadwatch.config import Config
        levels = {name: lvl for lvl, name, _ in doctor.check_config(Config())}
        self.assertEqual(levels["config"], "warn")
