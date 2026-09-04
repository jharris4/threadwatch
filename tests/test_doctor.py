"""threadwatch doctor: the checks that read files and state."""

import json
import os
import pathlib
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.config import Config  # noqa: E402
from threadwatch import doctor  # noqa: E402


class DoctorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.cfg = Config(data_dir=self.d / "data", config_dir=self.d)

    def tearDown(self):
        self.tmp.cleanup()

    def levels(self, checks):
        return [(c[0], c[1]) for c in checks]

    def test_inventory(self):
        self.assertEqual(self.levels(doctor.check_inventory(self.cfg)), [("warn", "inventory")])
        inv = self.d / "devices.json"
        self.cfg.devices_path = inv
        inv.write_text("{not json")
        self.assertEqual(self.levels(doctor.check_inventory(self.cfg)), [("FAIL", "inventory")])
        inv.write_text(json.dumps([{"name": "A", "extendedAddress": "0011223344556677"},
                                   {"name": "B", "extendedAddresses": ["0x12", "8899aabbccddeeff"]}]))
        level, _, text = doctor.check_inventory(self.cfg)[0]
        self.assertEqual(level, "warn")
        self.assertIn("2 devices, 3 addresses; ignored (not 16 hex digits): 0x12", text)
        inv.write_text(json.dumps([{"name": "A", "extendedAddress": "0011223344556677"}]))
        self.assertEqual(doctor.check_inventory(self.cfg)[0][0], "ok")

    def test_credentials_permissions_and_key(self):
        self.cfg.credentials_path = self.d / "absent.toml"
        self.assertEqual(doctor.check_credentials(self.cfg)[0][0], "FAIL")   # none: the recorder will not start
        cred = self.d / "credentials.toml"
        self.cfg.credentials_path = cred
        cred.write_text('[credentials]\nnetwork_key = "00112233445566778899aabbccddeeff"\n')
        os.chmod(cred, 0o644)
        checks = doctor.check_credentials(self.cfg)
        self.assertEqual(self.levels(checks), [("warn", "credentials"), ("ok", "credentials")])
        self.assertIn("mode 0644", checks[0][2])
        os.chmod(cred, 0o600)
        self.assertEqual(self.levels(doctor.check_credentials(self.cfg)), [("ok", "credentials")])
        cred.write_text('[credentials]\nnetwork_key = "tooshort"\n')
        self.assertEqual(doctor.check_credentials(self.cfg)[0][0], "FAIL")

    def test_daemon_and_ring_age(self):
        now = 1_700_000_000.0
        self.assertEqual(doctor.check_daemon(self.cfg, now)[0][0], "warn")
        status = self.cfg.state_dir / "status.json"
        status.write_text(json.dumps({"updated": now - 30, "last_frame_age_s": 5, "frames_total": 42}))
        self.assertEqual(doctor.check_daemon(self.cfg, now)[0][0], "ok")
        status.write_text(json.dumps({"updated": now - 30, "last_frame_age_s": 500}))
        self.assertEqual(doctor.check_daemon(self.cfg, now)[0][0], "warn")
        status.write_text(json.dumps({"updated": now - 600, "last_frame_age_s": 5}))
        self.assertEqual(doctor.check_daemon(self.cfg, now)[0][0], "FAIL")
        self.assertEqual(doctor.check_ring(self.cfg, now)[0][0], "warn")
        self.cfg.ring_dir.mkdir(parents=True)
        f = self.cfg.ring_dir / "threadwatch-20231114-22.pcap"
        f.write_bytes(b"x")
        os.utime(f, (now - 60, now - 60))
        self.assertEqual(doctor.check_ring(self.cfg, now)[0][0], "ok")
        os.utime(f, (now - 3 * 3600, now - 3 * 3600))
        level, _, text = doctor.check_ring(self.cfg, now)[0]
        self.assertEqual(level, "FAIL")
        self.assertIn("stopped growing", text)

    def test_disk_check_honours_the_byte_cap(self):
        self.cfg.ring_dir.mkdir(parents=True)
        for h in ("20260903-08", "20260903-09"):
            (self.cfg.ring_dir / f"threadwatch-{h}.pcap").write_bytes(b"x" * 4096)
        self.cfg.keep_files = 10 ** 12                     # a ring no disk could hold...
        level, _, text = doctor.check_disk(self.cfg)[0]
        self.assertEqual(level, "FAIL")
        self.assertIn("set keep_gb", text)
        self.cfg.keep_bytes = 8192                          # ...unless keep_gb caps it
        level, _, text = doctor.check_disk(self.cfg)[0]
        self.assertEqual(level, "ok")
        self.assertIn("capped at 8 KB", text)

    def test_env_lines_systemd_would_ignore_are_warned_about_not_loaded(self):
        env = self.d / "alerts.env"
        env.write_text("export DOCTOR_TEST_EXPORTED=abc\n; a comment\nBAD-NAME=x\nDOCTOR_TEST_PLAIN=ok\n")
        os.chmod(env, 0o600)
        try:
            checks = doctor.load_env(env)
            self.assertEqual(self.levels(checks), [("warn", "alerts.env"), ("warn", "alerts.env"), ("ok", "alerts.env")])
            self.assertIn("line 1: 'export DOCTOR_TEST_EXPORTED': the systemd unit ignores this line (drop the 'export' prefix)",
                          checks[0][2])
            self.assertIn("line 3: 'BAD-NAME'", checks[1][2])
            self.assertEqual(checks[2][2], "1 secret(s) loaded for this check")
            self.assertNotIn("DOCTOR_TEST_EXPORTED", os.environ)
            self.assertEqual(os.environ.get("DOCTOR_TEST_PLAIN"), "ok")
        finally:
            os.environ.pop("DOCTOR_TEST_PLAIN", None)
            os.environ.pop("DOCTOR_TEST_EXPORTED", None)

    def test_dongle_uses_the_finder(self):
        self.assertEqual(doctor.check_dongle(self.cfg, find=lambda: "/dev/ttyACM0"),
                         [("ok", "dongle", "nRF 802.15.4 sniffer at /dev/ttyACM0")])

        def missing():
            raise SystemExit("No nRF 802.15.4 sniffer found. Is the dongle plugged in?\nmore")
        self.assertEqual(doctor.check_dongle(self.cfg, find=missing)[0][:2], ("FAIL", "dongle"))
        self.cfg.serial_port = str(self.d / "nope")
        self.assertEqual(doctor.check_dongle(self.cfg)[0][0], "FAIL")

    def test_alerts_and_writable_and_whole_run(self):
        self.assertEqual(self.levels(doctor.check_alerts(self.cfg)), [("warn", "alerts"), ("warn", "heartbeats")])
        self.cfg.alerts_raw = {"sinks": [{"name": "x", "type": "http", "url": "http://127.0.0.1:9/hook"}]}
        self.assertEqual(doctor.check_alerts(self.cfg)[0][0], "ok")
        # A sink that needs a secret builds once alerts.env supplies it.
        self.cfg.alerts_raw = {"sinks": [{"name": "y", "type": "http", "url": "http://127.0.0.1:9/hook",
                                          "headers": {"Authorization": "Bearer ${DOCTOR_TEST_TOKEN}"}}]}
        self.assertEqual(doctor.check_alerts(self.cfg)[0][0], "FAIL")
        env = self.d / "alerts.env"
        env.write_text("# secrets\nDOCTOR_TEST_TOKEN=abc\n")
        os.chmod(env, 0o600)
        try:
            checks = doctor.check_alerts(self.cfg)
            self.assertEqual(self.levels(checks)[:2], [("ok", "alerts.env"), ("ok", "alerts")])
            self.assertEqual(os.environ.get("DOCTOR_TEST_TOKEN"), "abc")
        finally:
            os.environ.pop("DOCTOR_TEST_TOKEN", None)
        self.assertEqual(doctor.check_writable(self.cfg)[0][0], "ok")
        checks = doctor.run_doctor(self.cfg, find_port=lambda: "/dev/x", now=time.time())
        subjects = [c[1] for c in checks]
        for s in ("config", "inventory", "credentials", "dongle", "capture", "ring", "last-seen", "disk",
                  "writable", "clock", "alerts", "heartbeats", "web"):
            self.assertIn(s, subjects)
        self.assertTrue(all(c[0] in ("ok", "warn", "FAIL") for c in checks))

    def test_last_seen_check_reads_the_table_and_notices_one_kept_aside(self):
        path = self.cfg.state_dir / "last-seen.json"
        self.assertEqual(doctor.check_last_seen(self.cfg)[0][:2], ("ok", "last-seen"))
        self.assertIn("not written yet", doctor.check_last_seen(self.cfg)[0][2])
        path.write_text(json.dumps({"0011223344556677": {"last": 1.0}, "8899aabbccddeeff": {"last": 2.0}}))
        self.assertEqual(doctor.check_last_seen(self.cfg), [("ok", "last-seen", "2 address(es) with a history")])
        # A list parses as JSON but is not a table: bef55e2 treats it as unreadable.
        path.write_text("[]")
        level, _, text = doctor.check_last_seen(self.cfg)[0]
        self.assertEqual(level, "FAIL")
        self.assertIn("no device has a history", text)
        path.write_text("{not json")
        self.assertEqual(doctor.check_last_seen(self.cfg)[0][0], "FAIL")
        # ...and the file the recorder kept aside is worth a line of its own.
        path.write_text("{}")
        (self.cfg.state_dir / "last-seen.json.corrupt").write_text("{oops")
        checks = doctor.check_last_seen(self.cfg)
        self.assertEqual([c[0] for c in checks], ["ok", "warn"])
        self.assertIn("last-seen.json.corrupt", checks[1][2])

    def test_a_container_is_told_what_it_cannot_check_instead_of_warned(self):
        # docs/DOCKER.md promised these two warnings were expected and meant
        # nothing, which is a warning the reader can do nothing about.
        with mock.patch.object(doctor, "_in_container", return_value=False), \
             mock.patch.object(doctor.shutil, "which", return_value=None), \
             mock.patch.object(doctor.sys, "platform", "linux"):
            self.assertEqual(doctor.check_clock(), [("warn", "clock", "no timedatectl: NTP state not checked")])
            self.assertEqual(doctor.check_web(self.cfg)[0][0], "warn")
        with mock.patch.object(doctor, "_in_container", return_value=True), \
             mock.patch.object(doctor.shutil, "which", return_value=None), \
             mock.patch.object(doctor.sys, "platform", "linux"):
            level, subject, text = doctor.check_clock()[0]
            self.assertEqual((level, subject), ("ok", "clock"))
            self.assertIn("host keeps the time", text)
            level, subject, text = doctor.check_web(self.cfg)[0]
            self.assertEqual((level, subject), ("ok", "web"))
            self.assertIn("own container", text)

    def test_container_detection_reads_the_marks_a_container_leaves(self):
        real = pathlib.Path.exists
        with mock.patch.object(doctor, "_run", return_value="none"), \
             mock.patch.object(pathlib.Path, "exists",
                               lambda self: True if str(self) == "/.dockerenv" else real(self)):
            self.assertTrue(doctor._in_container())
        with mock.patch.object(doctor, "_run", return_value="lxc"), \
             mock.patch.object(pathlib.Path, "exists", lambda self: False):
            self.assertTrue(doctor._in_container())
        with mock.patch.object(doctor, "_run", return_value="none"), \
             mock.patch.object(pathlib.Path, "exists", lambda self: False), \
             mock.patch.object(pathlib.Path, "read_text", lambda self, **k: "0::/init.scope\n"):
            self.assertFalse(doctor._in_container())


if __name__ == "__main__":
    unittest.main()


class MissingCryptographyTest(unittest.TestCase):
    """requirements.txt calls cryptography optional; the recorder needs it."""

    def test_doctor_fails_when_cryptography_is_absent(self):
        import builtins
        from threadwatch import doctor as doc
        real = builtins.__import__

        def blocked(name, *a, **k):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ModuleNotFoundError("No module named 'cryptography'")
            return real(name, *a, **k)

        builtins.__import__ = blocked
        try:
            checks = doc.check_credentials(_cfg_with_key())
        finally:
            builtins.__import__ = real
        self.assertEqual([c[0] for c in checks], ["FAIL"])
        self.assertIn("cryptography", checks[0][2])

    def test_load_decryptor_raises_credentialserror_when_absent(self):
        import builtins
        import sys as _sys
        from threadwatch.pipeline import CredentialsError, load_decryptor
        real = builtins.__import__

        def blocked(name, *a, **k):
            if name == "cryptography" or name.startswith("cryptography."):
                raise ModuleNotFoundError("No module named 'cryptography'")
            return real(name, *a, **k)

        cached = _sys.modules.pop("threadwatch.crypto", None)   # force a real import
        builtins.__import__ = blocked
        try:
            with self.assertRaises(CredentialsError):
                load_decryptor(_cfg_with_key())
        finally:
            builtins.__import__ = real
            if cached is not None:
                _sys.modules["threadwatch.crypto"] = cached


def _cfg_with_key():
    import tempfile
    from pathlib import Path as _P
    from threadwatch.config import Config
    d = _P(tempfile.mkdtemp())
    p = d / "credentials.toml"
    p.write_text('[credentials]\nnetwork_key = "000102030405060708090a0b0c0d0e0f"\n')
    p.chmod(0o600)
    cfg = Config()
    cfg.config_dir = d
    return cfg
