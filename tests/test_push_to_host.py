"""bin/push-to-host.sh sends each host its own config: config/ to the
recorder, config/hosts/<hostname>/ to a host that has one, and nothing to
a relay without one or under --code-only. Run from a throwaway checkout
against stand-in ssh and rsync that log their arguments."""
from __future__ import annotations

import os
import shutil
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
  *"cat threadwatch/config/config.toml"*) echo "$HOST_NAME_SAID"; cat "$HOST_CONFIG" 2>/dev/null || true ;;
  *) cat > /dev/null ;;
esac
"""
RSYNC = """#!/bin/sh
printf '%s\\n' rsync "$@" > "$(mktemp "$PUSH_LOG/call.XXXXXX")"
"""
RELAY = '[network]\nchannel = 25\n\n[relay]  # this host\nto = "recorder.local:9154"\nlabel = "attic"\n'


class PushTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.d = Path(tmp.name)
        self.repo = self.d / "repo"
        (self.repo / "bin").mkdir(parents=True)
        (self.repo / "threadwatch").mkdir()
        shutil.copy(REPO_ROOT / "bin" / "push-to-host.sh", self.repo / "bin" / "push-to-host.sh")
        (self.repo / "threadwatch" / "__init__.py").write_text("")
        git = ["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@example.com"]
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run([*git, "add", "."], check=True)
        subprocess.run([*git, "commit", "-q", "-m", "x"], check=True)
        (self.repo / "config").mkdir()
        (self.repo / "config" / "config.toml").write_text("[network]\nchannel = 25\n")
        self.stubs = self.d / "stubs"
        self.stubs.mkdir()
        for name, body in (("ssh", SSH), ("rsync", RSYNC)):
            (self.stubs / name).write_text(body)
            (self.stubs / name).chmod(0o755)

    def push(self, host_config: str | None, *options: str, host_name: str = "recorderhost"):
        calls_dir = self.d / f"calls-{len(list(self.d.glob('calls-*')))}"
        calls_dir.mkdir()
        host_file = calls_dir.with_suffix(".toml")
        if host_config is not None:
            host_file.write_text(host_config)
        env = {**os.environ, "PATH": f"{self.stubs}:{os.environ['PATH']}", "PUSH_LOG": str(calls_dir),
               "HOST_CONFIG": str(host_file), "HOST_NAME_SAID": host_name}
        env.pop("DEST_DIR", None)
        out = subprocess.run(["bash", str(self.repo / "bin" / "push-to-host.sh"), "pi@host", *options],
                             capture_output=True, text=True, env=env, stdin=subprocess.DEVNULL, timeout=60)
        calls = [f.read_text().splitlines() for f in calls_dir.iterdir()]
        return out, [c[1:] for c in calls if c[0] == "rsync"]

    @staticmethod
    def tree_push(rsyncs):
        """The one rsync of the whole tree that is not a dry run."""
        (push,) = [args for args in rsyncs if "--dry-run" not in args and "--delete" in args]
        return push

    def assert_tree_carries_no_config(self, rsyncs):
        for args in rsyncs:
            if "--delete" in args:
                self.assertEqual(args[args.index("/config/") - 1], "--exclude")
                self.assertNotIn("P /config/***", args)

    def test_a_relay_host_without_a_folder_gets_the_code_and_not_config(self):
        out, rsyncs = self.push(RELAY, "--push-only")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("is a relay", out.stdout)
        self.assertEqual(len(rsyncs), 2)                              # the dry run for CHANGED, and the push
        self.assert_tree_carries_no_config(rsyncs)

    def test_code_only_sends_no_config_even_with_a_folder(self):
        (self.repo / "config" / "hosts" / "recorderhost").mkdir(parents=True)
        out, rsyncs = self.push(None, "--code-only", "--push-only")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("--code-only", out.stdout)
        self.assertEqual(len(rsyncs), 2)
        self.assert_tree_carries_no_config(rsyncs)

    def test_a_host_with_a_folder_gets_that_folder_as_its_config(self):
        folder = self.repo / "config" / "hosts" / "relayhost"
        folder.mkdir(parents=True)
        (folder / "config.toml").write_text(RELAY)
        for host_config in (None, RELAY):                             # a fresh host, and one already set up
            with self.subTest(host_config=host_config):
                out, rsyncs = self.push(host_config, "--push-only", host_name="relayhost")
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertIn("its config/ comes from config/hosts/relayhost (relay)", out.stdout)
                self.assert_tree_carries_no_config(rsyncs)
                dry = [args for args in rsyncs if "-ac" in args]
                self.assertEqual(len(dry), 2)                         # the newer-on-host check, on the folder
                for args in dry:
                    self.assertEqual(args[-2:], [f"{folder}/", "pi@host:threadwatch/config/"])
                self.assertIn(["-a", f"{folder}/", "pi@host:threadwatch/config/"], rsyncs)

    def test_the_recorder_gets_config_without_the_other_hosts_folders(self):
        (self.repo / "config" / "hosts" / "relayhost").mkdir(parents=True)
        for host_config in (None, '[relay]\n# to = "recorder.local:9154"\n\n[alerts]\nsinks = []\n'):
            with self.subTest(host_config=host_config):
                out, rsyncs = self.push(host_config, "--push-only")
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertNotIn("relay", out.stdout)
                self.assertEqual(len(rsyncs), 4)                      # two config dry runs, CHANGED, the push
                for args in rsyncs:
                    if "-ac" in args:
                        self.assertEqual(args[-2:], [f"{self.repo}/config/", "pi@host:threadwatch/config/"])
                        self.assertEqual(args[args.index("/hosts/") - 1], "--exclude")
                push = self.tree_push(rsyncs)
                self.assertIn("P /config/***", push)
                self.assertEqual(push[push.index("/config/hosts/") - 1], "--exclude")

    def test_a_hostname_that_is_not_a_plain_name_is_not_a_folder(self):
        (self.repo / "config" / "hosts").mkdir(parents=True)
        out, rsyncs = self.push(None, "--push-only", host_name="..")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotIn("config/hosts", out.stdout)
        self.assertIn("P /config/***", self.tree_push(rsyncs))

    def test_an_unknown_option_pushes_nothing(self):
        out, rsyncs = self.push(None, "--codeonly")
        self.assertEqual(out.returncode, 1)
        self.assertIn("not '--codeonly'", out.stderr)
        self.assertEqual(rsyncs, [])


if __name__ == "__main__":
    unittest.main()
