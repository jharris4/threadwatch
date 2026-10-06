"""bin/setup-host.sh refuses a clone path systemd would misread in the
units it renders, before it changes anything."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import tests  # noqa: F401  (the mDNS guard, installed on a direct run too: tests/no_lan)
from threadwatch.config import REPO_ROOT


def run_from(clone: Path) -> subprocess.CompletedProcess:
    (clone / "bin").mkdir(parents=True)
    shutil.copy(REPO_ROOT / "bin" / "setup-host.sh", clone / "bin" / "setup-host.sh")
    return subprocess.run(["bash", str(clone / "bin" / "setup-host.sh")], capture_output=True, text=True,
                          timeout=30)


class ClonePathTest(unittest.TestCase):
    def test_a_path_systemd_would_split_or_expand_is_refused(self):
        for name in ("thread watch", "tw%h", "tw\\x", 'tw"q', "tw'q", "tw$HOME", "tw\tx"):
            with tempfile.TemporaryDirectory() as tmp:
                out = run_from(Path(tmp) / name)
                self.assertEqual(out.returncode, 1, name)
                self.assertIn("which systemd would", out.stderr, name)

    @unittest.skipIf(os.geteuid() == 0, "past the check, root would set up this host for real")
    def test_a_plain_path_gets_past_the_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = run_from(Path(tmp) / "thread-watch_2.x")
        self.assertNotIn("which systemd would", out.stderr)
        self.assertIn("run with sudo", out.stderr)


class RelayUnitTest(unittest.TestCase):
    def test_the_relay_unit_is_the_recorders_with_relay_in_place_of_record(self):
        """The ordering and start limits threadwatch.service explains, and
        the same placeholders setup-host.sh fills in."""
        def lines(name):
            text = (REPO_ROOT / "systemd" / name).read_text()
            return {line for line in text.splitlines() if line and not line.startswith(("#", "Description="))}
        recorder, relay = lines("threadwatch.service"), lines("threadwatch-relay.service")
        self.assertEqual(recorder - relay, {"ExecStart=__REPO__/bin/threadwatch record",
                                            "EnvironmentFile=-__REPO__/config/alerts.env"})
        self.assertEqual(relay - recorder, {"ExecStart=__REPO__/bin/threadwatch relay"})


if __name__ == "__main__":
    unittest.main()
