"""config.toml values that must be refused rather than quietly misread."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch import alerts  # noqa: E402
from threadwatch import config as config_mod  # noqa: E402
from threadwatch.capture import RingWriter  # noqa: E402


class KeepGbTest(unittest.TestCase):
    def _load(self, text):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "config.toml"
            path.write_text(text)
            return config_mod.load(path)

    def test_a_positive_cap_is_bytes(self):
        self.assertEqual(self._load("[capture]\nkeep_gb = 4\n").keep_bytes, 4 * 1024 ** 3)
        self.assertEqual(self._load("[capture]\nkeep_gb = 0.5\n").keep_bytes, 512 * 1024 ** 2)
        self.assertIsNone(self._load("[capture]\nkeep_files = 24\n").keep_bytes)

    def test_a_negative_or_zero_cap_is_refused_not_a_ring_of_one_file(self):
        # A negative keep_bytes makes RingWriter._prune's "while total >
        # keep_bytes" true for every total: one file left at every rotation.
        for bad in ("-5", "0", "-0.1"):
            with self.assertRaises(ValueError) as cm:
                self._load(f"[capture]\nkeep_gb = {bad}\n")
            self.assertIn("keep_gb", str(cm.exception))
        with self.assertRaises(ValueError):
            self._load('[capture]\nkeep_gb = "lots"\n')

    def test_the_writer_refuses_a_cap_that_would_prune_everything(self):
        with tempfile.TemporaryDirectory() as d:
            for h in ("00", "01", "02"):
                (Path(d) / f"threadwatch-20260903-{h}.pcap").write_bytes(b"x" * 1000)
            with self.assertRaises(ValueError):
                RingWriter(Path(d), keep_files=168, dlt=0, keep_bytes=-5 * 1024 ** 3)
            self.assertEqual(len(list(Path(d).glob("*.pcap"))), 3)


class EventsKeepDaysTest(unittest.TestCase):
    def _load(self, text):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "config.toml"
            path.write_text(text)
            return config_mod.load(path)

    def test_default_a_year_zero_for_ever_negative_refused(self):
        self.assertEqual(self._load("[network]\nchannel = 25\n").events_keep_days, 365)
        self.assertEqual(self._load("[events]\nkeep_days = 0\n").events_keep_days, 0)
        self.assertEqual(self._load("[events]\nkeep_days = 30\n").events_keep_days, 30)
        with self.assertRaises(ValueError):
            self._load("[events]\nkeep_days = -1\n")


class ReadOnlyStateDirTest(unittest.TestCase):
    """The web container mounts data/ read-only; before capture has run
    there is no state directory, and a reader must not die creating it."""

    def test_a_state_dir_that_cannot_be_created_is_a_path_not_a_crash(self):
        import os
        import stat
        from threadwatch.config import Config
        from threadwatch.web import Site
        with tempfile.TemporaryDirectory() as d:
            data = Path(d) / "data"
            data.mkdir()
            os.chmod(data, stat.S_IRUSR | stat.S_IXUSR)      # data:ro, no state/ yet
            try:
                if os.access(data, os.W_OK):
                    self.skipTest("running as root: directory permissions do not bind")
                cfg = Config(data_dir=data)
                self.assertEqual(cfg.state_dir, data / "state")   # no EROFS/EACCES out of the property
                self.assertFalse(cfg.state_dir.exists())
                site = Site(cfg)
                for path in ("/", "/status", "/devices", "/api/status"):
                    code, _ctype, body = site.respond(path)
                    self.assertEqual(code, 200, path)
                self.assertIn(b"has not run here", site.respond("/status")[2])
            finally:
                os.chmod(data, stat.S_IRWXU)


if __name__ == "__main__":
    unittest.main()


class ExampleConfigTest(unittest.TestCase):
    """config/config.example.toml is the documentation: what users copy to
    config.toml. A key renamed in config.load and not here hands the first
    person to follow the docs a recorder on defaults, silently. So: the
    example parses, every setting it states lands where load() reads it,
    every setting it shows commented out loads too, and there is no key in
    it that load() does not read."""

    EXAMPLE = Path(__file__).resolve().parent.parent / "config" / "config.example.toml"

    # (table, key) in the example -> the Config attribute, the value the
    # example states, and a different value to prove the key is read.
    SETTINGS = {
        ("network", "channel"): ("channel", 25, 15),
        ("network", "pan_id"): ("pan_id", 0x4e21, 0x1234),
        ("capture", "serial_port"): ("serial_port", "/dev/ttyACM0", "/dev/ttyUSB3"),
        ("capture", "data_dir"): ("data_dir", Path("~/threadwatch-data").expanduser(), Path("/srv/tw")),
        ("capture", "keep_files"): ("keep_files", 168, 24),
        ("capture", "keep_gb"): ("keep_bytes", 4 * 1024 ** 3, 2 * 1024 ** 3),
        ("capture", "freeze_on_critical"): ("freeze_on_critical", True, False),
        ("devices", "inventory"): ("devices_path", "devices.json", "other.json"),
        ("quiet", "silence_s"): ("quiet_s", 1800, 600),
        ("quiet", "min_rssi_dbm"): ("quiet_min_rssi_dbm", -82, -70),
        ("polls", "rearm_s"): ("poll_rearm_s", 3600, 120),
        ("link", "drop_db"): ("link_drop_db", 8, 3),
        ("link", "hold_s"): ("link_hold_s", 1800, 120),
        ("summary", "hour"): ("summary_hour", 8, 6),
        ("summary", "severity"): ("summary_severity", "notice", "warning"),
        ("detect", "flood_multiplier"): ("detector.flood_multiplier", 3.0, 2.5),
        ("detect", "flood_min_frames"): ("detector.flood_min_frames", 400, 100),
        ("detect", "period_min_s"): ("detector.period_min_s", 40.0, 20.0),
        ("detect", "period_max_s"): ("detector.period_max_s", 180.0, 90.0),
        ("detect", "period_onsets"): ("detector.period_onsets", 3, 4),
        ("detect", "alert_cooldown_s"): ("detector.alert_cooldown_s", 1800.0, 60.0),
        ("border_routers", "browse_s"): ("border_router_browse_s", 600, 30),
        ("events", "keep_days"): ("events_keep_days", 365, 7),
        ("web", "bind"): ("web_bind", "0.0.0.0", "127.0.0.1"),
        ("web", "port"): ("web_port", 8080, 9090),
        ("credentials", "file"): ("credentials_path", "credentials.toml", "creds.toml"),
    }
    # Read verbatim into alerts_raw / heartbeats_raw and built by alerts.py.
    RAW = {("alerts", "webhook_url"), ("alerts", "sinks"), ("heartbeats",)}
    IGNORED = {("network", "network_name")}      # informational, by its own comment

    @staticmethod
    def _uncommented(text):
        """The example with every commented-out setting switched on."""
        import re
        return "".join(re.sub(r"^# (?=\[\[|[a-z_]+ = )", "", line) for line in text.splitlines(keepends=True))

    @staticmethod
    def _keys(raw):
        out = set()
        for table, body in raw.items():
            if isinstance(body, list):
                out.add((table,))
            else:
                out.update((table, k) for k in body)
        return out

    def _load(self, d, text):
        (d / "config.toml").write_text(text)
        return config_mod.load(d / "config.toml")

    def _value(self, cfg, attr, spec_value, d):
        got = cfg
        for part in attr.split("."):
            got = getattr(got, part)
        if attr in ("devices_path", "credentials_path"):
            return got, (d / spec_value).resolve()
        return got, spec_value

    def test_every_setting_in_the_example_is_one_load_reads(self):
        import tomllib
        text = self.EXAMPLE.read_text()
        shipped, full = tomllib.loads(text), tomllib.loads(self._uncommented(text))
        self.assertEqual(self._keys(shipped) | self._keys(full), set(self.SETTINGS) | self.RAW | self.IGNORED)
        for (table, key), (attr, _stated, other) in self.SETTINGS.items():
            with self.subTest(table=table, key=key), tempfile.TemporaryDirectory() as d:
                d = Path(d)
                value = f"0x{other:x}" if key == "pan_id" else other
                if key == "keep_gb":
                    value = other // 1024 ** 3
                body = f"[{table}]\n{key} = {json.dumps(str(value) if isinstance(value, Path) else value)}\n"
                got, want = self._value(self._load(d, body), attr, other, d)
                self.assertEqual(got, want)

    def test_the_example_as_shipped_loads_with_every_value_it_states(self):
        import tomllib
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            text = self.EXAMPLE.read_text()
            cfg = self._load(d, text)
            for (table, key), (attr, stated, _other) in self.SETTINGS.items():
                if key not in tomllib.loads(text).get(table, {}):
                    continue                                   # commented out as shipped
                with self.subTest(table=table, key=key):
                    got, want = self._value(cfg, attr, stated, d)
                    self.assertEqual(got, want)
            self.assertEqual((cfg.pan_id, cfg.keep_bytes, cfg.credentials_path), (None, None, None))
            self.assertEqual((cfg.alerts_raw, cfg.heartbeats_raw), ({}, []))
            self.assertEqual(alerts.build_sinks(cfg.alerts_raw, print), [])
            self.assertEqual(alerts.build_heartbeats(cfg.heartbeats_raw, print), [])

    def test_every_commented_out_setting_in_the_example_loads_too(self):
        os.environ["NTFY_TOKEN"], os.environ["GATUS_THREADWATCH_TOKEN"] = "tk_ntfy", "tk_gatus"
        self.addCleanup(lambda: [os.environ.pop(k) for k in ("NTFY_TOKEN", "GATUS_THREADWATCH_TOKEN")])
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            cfg = self._load(d, self._uncommented(self.EXAMPLE.read_text()))
            for (table, key), (attr, stated, _other) in self.SETTINGS.items():
                with self.subTest(table=table, key=key):
                    got, want = self._value(cfg, attr, stated, d)
                    self.assertEqual(got, want)
            logs = []
            sinks = alerts.build_sinks(cfg.alerts_raw, logs.append)
            self.assertEqual(logs, [])
            self.assertEqual([(s.name, type(s).__name__) for s in sinks],
                             [("webhook", "HttpSink"), ("home-assistant", "HttpSink"),
                              ("phone", "HttpSink"), ("local-script", "CommandSink")])
            self.assertEqual(sinks[2].headers["Authorization"], "Bearer tk_ntfy")
            self.assertEqual((sinks[1].min_severity, sinks[1].cooldown_s), (2, 300.0))
            self.assertEqual(sinks[3].command, ["/usr/local/bin/my-alert.sh"])
            beats = alerts.build_heartbeats(cfg.heartbeats_raw, logs.append)
            self.assertEqual(logs, [])
            self.assertEqual([(b.name, b.interval_s) for b in beats], [("gatus", 60.0)])
            self.assertIn("success=false", beats[0].failure_url)
            self.assertEqual(beats[0].headers["Authorization"], "Bearer tk_gatus")
