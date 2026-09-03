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


if __name__ == "__main__":
    unittest.main()
