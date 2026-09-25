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


if __name__ == "__main__":
    unittest.main()
