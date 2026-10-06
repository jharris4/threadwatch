"""bin/push-to-host.sh keeps this workstation's config/ (the recorder's,
network key included) off a relay host, and off any host with --code-only.
Run against stand-in ssh and rsync that log their arguments."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import tests  # noqa: F401  (the mDNS guard, installed on a direct run too: tests/no_lan)
from threadwatch.config import REPO_ROOT

# A file per call: the two config dry runs run at once, under comm, and
# appends to one log from both interleaved.
SSH = """#!/bin/sh
printf '%s\\n' ssh "$@" > "$(mktemp "$PUSH_LOG/call.XXXXXX")"
case "$*" in
  *"cat threadwatch/config/config.toml"*) cat "$HOST_CONFIG" 2>/dev/null || true ;;
  *) cat > /dev/null ;;
esac
"""
RSYNC = """#!/bin/sh
printf '%s\\n' rsync "$@" > "$(mktemp "$PUSH_LOG/call.XXXXXX")"
"""


class PushTest(unittest.TestCase):
    def push(self, host_config: str | None, *options: str):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            for name, body in (("ssh", SSH), ("rsync", RSYNC)):
                (d / name).write_text(body)
                (d / name).chmod(0o755)
            if host_config is not None:
                (d / "host-config.toml").write_text(host_config)
            (d / "calls").mkdir()
            env = {**os.environ, "PATH": f"{d}:{os.environ['PATH']}", "PUSH_LOG": str(d / "calls"),
                   "HOST_CONFIG": str(d / "host-config.toml")}
            env.pop("DEST_DIR", None)
            out = subprocess.run(["bash", str(REPO_ROOT / "bin" / "push-to-host.sh"), "pi@host", *options],
                                 capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=60)
            calls = [f.read_text().splitlines() for f in (d / "calls").iterdir()]
        return out, [c[1:] for c in calls if c[0] == "rsync"]

    @staticmethod
    def the_push(rsyncs):
        """The one rsync that is not a dry run."""
        (push,) = [args for args in rsyncs if "--dry-run" not in args]
        return push

    def assert_config_left_alone(self, rsyncs):
        self.assertEqual(len(rsyncs), 2)                              # the dry run for CHANGED, and the push
        self.the_push(rsyncs)
        for args in rsyncs:
            self.assertEqual(args[args.index("/config/") - 1], "--exclude")
            self.assertNotIn("P /config/***", args)

    def test_a_relay_host_gets_the_code_and_not_config(self):
        out, rsyncs = self.push('[network]\nchannel = 25\n\n[relay]  # this host\nto = "192.0.2.10:9154"\n'
                                'label = "attic"\n', "--push-only")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("is a relay", out.stdout)
        self.assert_config_left_alone(rsyncs)

    def test_code_only_leaves_any_hosts_config_alone(self):
        out, rsyncs = self.push(None, "--code-only", "--push-only")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("--code-only", out.stdout)
        self.assert_config_left_alone(rsyncs)

    def test_a_recorder_and_an_empty_relay_section_get_config(self):
        for host_config in (None, '[relay]\n# to = "192.0.2.10:9154"\n\n[alerts]\nsinks = []\n'):
            with self.subTest(host_config=host_config):
                out, rsyncs = self.push(host_config, "--push-only")
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertNotIn("relay", out.stdout)
                # Two config dry runs (the newer-on-host check), then CHANGED and the push.
                self.assertEqual(len(rsyncs), 4)
                self.assertEqual(sum("/config/**" in args for args in rsyncs), 2)
                self.assertIn("P /config/***", self.the_push(rsyncs))

    def test_an_unknown_option_pushes_nothing(self):
        out, rsyncs = self.push(None, "--codeonly")
        self.assertEqual(out.returncode, 1)
        self.assertIn("not '--codeonly'", out.stderr)
        self.assertEqual(rsyncs, [])


if __name__ == "__main__":
    unittest.main()
