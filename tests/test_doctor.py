"""threadwatch doctor: the checks that read files and state."""

import json
import os
import sys
import tempfile
import time
import unittest
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
        for s in ("config", "inventory", "credentials", "dongle", "capture", "ring", "disk", "writable",
                  "clock", "alerts", "heartbeats", "web"):
            self.assertIn(s, subjects)
        self.assertTrue(all(c[0] in ("ok", "warn", "FAIL") for c in checks))


if __name__ == "__main__":
    unittest.main()
