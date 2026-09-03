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
