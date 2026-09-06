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
        # A stray null or a bare string is the shape doctor exists to name;
        # calling .get() on one made it report its own AttributeError as
        # "doctor check crashed" instead.
        inv.write_text(json.dumps([{"name": "A", "extendedAddress": "0011223344556677"},
                                   None, "b62c32bf669272db"]))
        level, _, text = doctor.check_inventory(self.cfg)[0]
        self.assertEqual(level, "warn")
        self.assertIn("1 devices, 1 addresses", text)
        self.assertIn("entry 2 is null, entry 3 is a str", text)

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

    def test_disk_check_counts_the_incidents_and_the_snapshot_still_to_come(self):
        from threadwatch import review
        self.cfg.ring_dir.mkdir(parents=True)
        (self.cfg.ring_dir / "threadwatch-20260903-08.pcap").write_bytes(b"x" * 4096)
        self.cfg.incidents_dir.mkdir(parents=True)
        (self.cfg.incidents_dir / "20260903T080000_auto-storm").mkdir()
        (self.cfg.incidents_dir / "20260903T080000_auto-storm" / "a.pcap").write_bytes(b"x" * 8192)
        self.assertIn("frozen incidents hold 8 KB", doctor.check_disk(self.cfg)[0][2])
        # With freeze_on_critical on, room for one more whole copy of the
        # ring is part of the judgement: without it the recorder refuses.
        self.cfg.freeze_on_critical = True
        real = review.storage
        review.storage = lambda cfg: {**real(cfg), "disk_free": 5 * 10 ** 9, "ring_bytes": 5 * 10 ** 9,
                                      "ring_needs_bytes": 5 * 10 ** 8}
        try:
            checks = doctor.check_disk(self.cfg)
        finally:
            review.storage = real
        self.assertEqual(self.levels(checks), [("ok", "disk"), ("warn", "incidents")])
        self.assertIn("threadwatch incidents --delete", checks[1][2])

    def test_the_version_check_names_the_code_that_answered_the_others(self):
        # Every other check answers the same whether the host is running
        # the code you just pushed or a six-month-old checkout.
        from threadwatch import __version__
        level, subject, text = doctor.check_version()[0]
        self.assertEqual((level, subject), ("ok", "version"))
        self.assertIn(f"threadwatch {__version__}", text)
        from threadwatch import config as config_mod
        real = config_mod.repo_commit
        config_mod.repo_commit = lambda: None
        try:
            self.assertIn("no .git here", doctor.check_version()[0][2])
        finally:
            config_mod.repo_commit = real

    def test_env_lines_systemd_would_ignore_are_warned_about_not_loaded(self):
        env = self.d / "alerts.env"
        env.write_text("export DOCTOR_TEST_EXPORTED=abc\n; a comment\nBAD-NAME=x\nDOCTOR_TEST_PLAIN=ok\n")
        os.chmod(env, 0o600)
        try:
            checks = doctor.load_env(env)
            self.assertEqual(self.levels(checks),
                             [("warn", "alerts.env"), ("warn", "alerts.env"), ("ok", "alerts.env")])
            self.assertIn("line 1: 'export DOCTOR_TEST_EXPORTED': the systemd unit ignores "
                          "this line (drop the 'export' prefix)",
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
        # Every verdict, not just the subject names: "each level is one of
        # the three level constants" is true by construction, so a
        # regression flipping every check to warn, or losing FAIL
        # altogether, used to pass here.
        import contextlib
        import io
        # check_services reads this host's systemd, not the fixture: where
        # systemctl exists the two units are missing and it warns twice,
        # where it does not it says so once. Pin that, so the list below is
        # the same on a laptop and on a CI runner; the branch that does
        # read systemd is covered by test_services_are_read_from_systemd.
        which = doctor.shutil.which
        with mock.patch.object(doctor.shutil, "which",
                               lambda name: None if name == "systemctl" else which(name)):
            checks = doctor.run_doctor(self.cfg, find_port=lambda: "/dev/x", now=time.time())
        self.assertEqual(self.levels(checks), [
            ("ok", "config"),               # channel and data dir
            ("warn", "config"),             # no config.toml in this fixture
            ("warn", "inventory"),          # no devices.json
            ("FAIL", "credentials"),        # no network key: the recorder would not start
            ("warn", "border routers"),     # no_lan answers with an empty LAN
            ("ok", "dongle"),               # the stub finder above
            ("warn", "capture"),            # never run here
            ("warn", "ring"),               # no ring files
            ("ok", "last-seen"), ("ok", "blind-spans"),
            ("ok", "disk"),
            ("ok", "writable"),
            ("ok", "clock"),
            ("ok", "services"),
            ("ok", "alerts.env"),           # the secret the sink above needs, loaded
            ("ok", "alerts"),               # ...so the sink builds
            ("warn", "heartbeats"),
            ("warn", "web"),
            ("ok", "version"),              # which code answered all of the above
        ])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(doctor.print_report(checks), 1)         # any FAIL is exit 1
        self.assertIn("1 failing, 7 warning(s)", out.getvalue())
        ok_only = [c for c in checks if c[0] == "ok"]
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(doctor.print_report(ok_only), 0)
        self.assertIn("all good", out.getvalue())

    def test_services_are_read_from_systemd(self):
        """The units' state is the host's answer, not a config file's, so
        every branch here is one systemctl said and none of them is what
        the machine running the suite happens to have installed."""
        with mock.patch.object(doctor.shutil, "which", return_value=None):
            self.assertEqual(doctor.check_services(), [("ok", "services", "no systemd here (not checked)")])
        said = {("is-active", "threadwatch"): "active", ("is-enabled", "threadwatch"): "enabled",
                ("is-active", "threadwatch-web"): "failed", ("is-enabled", "threadwatch-web"): "enabled"}
        with mock.patch.object(doctor.shutil, "which", return_value="/usr/bin/systemctl"), \
             mock.patch.object(doctor, "_run", lambda cmd: said[(cmd[1], cmd[2])]):
            self.assertEqual(doctor.check_services(),
                             [("ok", "services", "threadwatch.service active, enabled"),
                              ("FAIL", "services", "threadwatch-web.service failed (enabled)")])
        # A host that has never run bin/setup-host.sh: systemd has never
        # heard of either unit, which is a warning and not a failure.
        with mock.patch.object(doctor.shutil, "which", return_value="/usr/bin/systemctl"), \
             mock.patch.object(doctor, "_run", return_value=None):
            checks = doctor.check_services()
        self.assertEqual(self.levels(checks), [("warn", "services"), ("warn", "services")])
        self.assertIn("setup-host.sh", checks[0][2])

    def test_a_sink_the_daemon_would_refuse_fails_the_check_and_the_exit_code(self):
        import contextlib
        import io
        for raw in ({"sinks": [{"name": "x", "type": "pigeon"}]},
                    {"sinks": [{"name": "x", "type": "http"}]},                          # no url
                    {"sinks": [{"name": "x", "type": "http", "url": "http://127.0.0.1:9/"},
                               {"name": "x", "type": "http", "url": "http://127.0.0.1:9/"}]}):
            self.cfg.alerts_raw = raw
            checks = doctor.check_alerts(self.cfg)
            self.assertEqual(checks[0][:2], ("FAIL", "alerts"), raw)
            self.assertIn("refuses to start", checks[0][2])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(doctor.print_report(
                    doctor.run_doctor(self.cfg, find_port=lambda: "/dev/x", now=time.time())), 1)
        self.cfg.alerts_raw = {}
        self.cfg.heartbeats_raw = [{"name": "h"}]                                       # no url
        checks = doctor.check_alerts(self.cfg)
        self.assertEqual(checks[0][:2], ("FAIL", "alerts"))
        self.assertIn("heartbeats", checks[0][2])

    def test_one_crashing_check_is_a_warning_line_and_hides_nothing(self):
        import contextlib
        import io

        def broken(*_a, **_k):
            raise RuntimeError("boom")

        with mock.patch.object(doctor, "check_dongle", broken), mock.patch.object(doctor, "check_clock", broken):
            checks = doctor.run_doctor(self.cfg, find_port=lambda: "/dev/x", now=time.time())
        crashed = [c for c in checks if c[1] == "doctor"]
        self.assertEqual(crashed, [(doctor.WARN, "doctor", "check crashed: RuntimeError: boom")] * 2)
        subjects = [c[1] for c in checks]
        self.assertNotIn("dongle", subjects)
        self.assertNotIn("clock", subjects)
        for s in ("config", "inventory", "credentials", "capture", "ring", "last-seen", "disk", "writable",
                  "alerts", "web"):                                       # every other check still ran
            self.assertIn(s, subjects)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(doctor.print_report(crashed), 0)              # a crashed check is not a failure
        self.assertEqual(out.getvalue().splitlines(),
                         ["warn doctor       check crashed: RuntimeError: boom"] * 2 + ["0 failing, 2 warning(s)"])

    def test_print_report_exits_one_only_for_a_failing_check(self):
        import contextlib
        import io
        cases = [([("ok", "config", "fine")], 0, "all good"),
                 ([("ok", "config", "fine"), (doctor.WARN, "ring", "thin")], 0, "0 failing, 1 warning(s)"),
                 ([(doctor.WARN, "ring", "thin"), (doctor.FAIL, "alerts", "refused"), (doctor.FAIL, "web", "down")],
                  1, "2 failing, 1 warning(s)"),
                 ([], 0, "all good")]
        for checks, code, last_line in cases:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(doctor.print_report(checks), code, checks)
            lines = out.getvalue().splitlines()
            self.assertEqual(lines[-1], last_line)
            self.assertEqual(lines[:-1], [f"{lvl:4s} {subj:12s} {text}" for lvl, subj, text in checks])

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


class HaEnvModeTest(unittest.TestCase):
    """credentials.toml and alerts.env both warn when they are readable by
    others. config/ha.env holds the Home Assistant long-lived access token
    and had no such check: setup-host.sh and push-to-host.sh chmod it on
    the capture host, so what went unchecked was the workstation copy, and
    any host where setup-host.sh never ran."""

    def test_a_world_readable_ha_env_warns_and_a_locked_one_does_not(self):
        import os
        import tempfile
        from threadwatch.config import Config
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(data_dir=Path(tmp) / "data")
            cfg.config_dir = Path(tmp)
            path = cfg.config_dir / "ha.env"
            self.assertEqual(doctor.check_ha_env(cfg), [])         # not present: nothing to say
            path.write_text("HA_TOKEN=secret\n")
            os.chmod(path, 0o644)
            level, subject, text = doctor.check_ha_env(cfg)[0]
            self.assertEqual((level, subject), ("warn", "ha.env"))
            self.assertIn("long-lived access token", text)
            os.chmod(path, 0o600)
            self.assertEqual(doctor.check_ha_env(cfg)[0][:2], ("ok", "ha.env"))

    def test_it_is_part_of_a_whole_run(self):
        import tempfile
        from threadwatch.config import Config
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Config(data_dir=Path(tmp) / "data")
            cfg.config_dir = Path(tmp)
            (cfg.config_dir / "ha.env").write_text("HA_TOKEN=secret\n")
            import os
            os.chmod(cfg.config_dir / "ha.env", 0o644)
            checks = doctor.run_doctor(cfg, find_port=lambda: "/dev/x", now=time.time())
            self.assertIn(("warn", "ha.env"), [(c[0], c[1]) for c in checks])


class BlindSpansCheckTest(unittest.TestCase):
    """blind-spans.json is what every silence is measured against. It used
    to be discarded on any read failure with no journal line and no doctor
    line, which silently recreates the bug the file was added to fix: a
    device unheard since before an outage charged for it in full, so a
    long-silent mesh pages device_quiet for every device at once."""

    def _cfg(self, tmp):
        from threadwatch.config import Config
        cfg = Config(data_dir=Path(tmp) / "data")
        cfg.state_dir.mkdir(parents=True, exist_ok=True)
        return cfg

    def test_missing_readable_and_damaged(self):
        import json
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp)
            path = cfg.state_dir / "blind-spans.json"
            self.assertEqual([(c[0], c[2]) for c in doctor.check_blind_spans(cfg)],
                             [("ok", "not written yet (no outage on record)")])
            path.write_text(json.dumps([[1000.0, 60.0], [2000.0, 120.0]]))
            self.assertEqual(doctor.check_blind_spans(cfg)[0][:2] + (doctor.check_blind_spans(cfg)[0][2],),
                             ("ok", "blind-spans", "2 outage(s) on record"))
            for junk in ("{not json", json.dumps({"a": 1}), json.dumps([["x", "y"]])):
                path.write_text(junk)
                level, subject, text = doctor.check_blind_spans(cfg)[0]
                self.assertEqual((level, subject), ("FAIL", "blind-spans"), junk)
                self.assertIn("charged to the device in full", text)

    def test_the_pipeline_says_so_too_rather_than_starting_empty_in_silence(self):
        import contextlib
        import io
        import tempfile
        from threadwatch.events import NullEventLog
        from threadwatch.crypto import Decryptor
        from threadwatch.pipeline import Pipeline
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(tmp)
            (Path(tmp) / "devices.json").write_text("[]")
            cfg.devices_path = Path(tmp) / "devices.json"
            (cfg.state_dir / "blind-spans.json").write_text("{not json")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                pipe = Pipeline(cfg, NullEventLog(), Decryptor(network_key=bytes(16)))
            self.assertEqual(pipe._blind, [])
            self.assertIn("blind-spans.json is unreadable", out.getvalue())


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


class CheckBorderRoutersTest(unittest.TestCase):
    """check_border_routers against a patched browse. The whole-run tests
    above used to reach the real mdns.browse through this check, a
    four-second multicast query per run_doctor call on whatever LAN the
    suite ran on, finding (and printing) real devices; the module now
    imports the suite's LAN guard like every other."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config(data_dir=Path(self.tmp.name) / "data", config_dir=Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def _check(self, found=None, error=None):
        from threadwatch import mdns

        def browse(timeout=4.0, **_kw):
            if error is not None:
                raise error
            return found
        with mock.patch.object(mdns, "browse", browse):
            return doctor.check_border_routers(self.cfg)

    def test_disabled_failed_empty_and_found(self):
        self.cfg.border_router_browse_s = 0
        self.assertEqual(self._check(),
                         [("ok", "border routers", "mDNS browse disabled ([border_routers] browse_s = 0)")])
        self.cfg.border_router_browse_s = 600
        level, subject, text = self._check(error=OSError("no route to host"))[0]
        self.assertEqual((level, subject), ("warn", "border routers"))
        self.assertIn("mDNS browse failed (no route to host)", text)
        level, _s, text = self._check(found=[{"instance": "hub", "ext": None}])[0]
        self.assertEqual(level, "warn")
        self.assertIn("none found over mDNS", text)
        level, _s, text = self._check(found=[{"instance": "Living Room", "ext": "b62c32bf669272db"},
                                             {"instance": "Office", "ext": "1669674dd15cf0fa"},
                                             {"instance": "no address", "ext": None}])[0]
        self.assertEqual(level, "ok")
        self.assertEqual(text, "2 found over mDNS: Living Room (b62c32bf669272db), Office (1669674dd15cf0fa)")

    def test_the_whole_run_never_opens_a_socket(self):
        # run_doctor reaches the browse through check_border_routers (the
        # default browse_s is 600); under the suite's guard it answers with
        # an empty LAN, and no socket is opened on the way.
        from threadwatch import mdns
        with mock.patch.object(mdns, "socket") as sock:
            checks = doctor.run_doctor(self.cfg, find_port=lambda: "/dev/x", now=time.time())
        self.assertEqual(sock.socket.call_count, 0)
        routers = [c for c in checks if c[1] == "border routers"]
        self.assertEqual(len(routers), 1)
        self.assertEqual(routers[0][0], "warn")
        self.assertIn("none found over mDNS", routers[0][2])


if __name__ == "__main__":
    unittest.main()
