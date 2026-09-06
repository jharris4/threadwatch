"""Command-line subcommands that read and manage the data directory."""

import contextlib
import io
import json
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.cli import main  # noqa: E402
from tests.no_lan import setUpModule, tearDownModule  # noqa: E402, F401  (no mDNS from the suite)
from tests.frames import psdu_for, secured_psdu  # noqa: E402


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


class AlertTestFilterTest(CliCase):
    """alert-test says which sinks a named event reaches and which filter it out."""

    def setUp(self):
        super().setUp()
        (self.d / "config.toml").write_text(
            f'[capture]\ndata_dir = "{self.d / "data"}"\n'
            '[[alerts.sinks]]\nname = "all"\ntype = "command"\ncommand = ["true"]\n'
            '[[alerts.sinks]]\nname = "phone"\ntype = "command"\ncommand = ["true"]\n'
            'ignore_events = ["poll_starvation", "retransmission_elevation"]\n'
            '[[alerts.sinks]]\nname = "storms"\ntype = "command"\ncommand = ["true"]\n'
            'events = ["phase_locked_storm"]\nmin_severity = "critical"\n')

    def test_a_filtered_out_event_is_a_skip_line_and_not_a_failure(self):
        code, out, _ = self.run_cli("alert-test", "--no-heartbeats", "--event", "poll_starvation")
        self.assertEqual(code, 0, out)
        self.assertEqual(out.splitlines(), [
            "sinks (3):",
            "  ok   all: true",
            "  skip phone (does not take poll_starvation)",
            "  skip storms (min severity above warning)",
        ])

    def test_an_event_every_sink_takes_reaches_them_all(self):
        code, out, _ = self.run_cli("alert-test", "--no-heartbeats", "--event", "device_quiet")
        self.assertEqual(code, 0, out)
        self.assertEqual(out.splitlines(), [
            "sinks (3):",
            "  ok   all: true",
            "  ok   phone: true",
            "  skip storms (min severity above warning)",
        ])
        code, out, _ = self.run_cli("alert-test", "--no-heartbeats", "--event", "phase_locked_storm",
                                    "--severity", "critical")
        self.assertEqual(code, 0, out)
        self.assertEqual(out.splitlines(), ["sinks (3):", "  ok   all: true", "  ok   phone: true", "  ok   storms: true"])

    def test_the_floor_is_named_before_the_filter_when_both_would_skip(self):
        code, out, _ = self.run_cli("alert-test", "--no-heartbeats", "--event", "poll_starvation",
                                    "--severity", "notice")
        self.assertEqual(code, 0, out)
        self.assertEqual(out.splitlines()[1:], [
            "  skip all (min severity above notice)",
            "  skip phone (min severity above notice)",
            "  skip storms (min severity above notice)",
        ])


class AlertTestUnbuiltTest(CliCase):
    """A recipient a missing ${VARIABLE} kept from being built is a failure
    of the test, not a note above a clean exit."""

    def test_a_sink_or_heartbeat_that_could_not_be_built_fails_the_test(self):
        import os
        for var in ("THREADWATCH_TEST_UNSET_TOKEN", "THREADWATCH_TEST_UNSET_BEAT"):
            self.assertNotIn(var, os.environ)
        (self.d / "config.toml").write_text(
            f'[capture]\ndata_dir = "{self.d / "data"}"\n'
            '[[alerts.sinks]]\nname = "all"\ntype = "command"\ncommand = ["true"]\n'
            '[[alerts.sinks]]\nname = "phone"\ntype = "http"\nurl = "http://127.0.0.1:9/${THREADWATCH_TEST_UNSET_TOKEN}"\n'
            '[[alerts.sinks]]\nname = "off"\ntype = "http"\nenabled = false\nurl = "http://127.0.0.1:9/${THREADWATCH_TEST_UNSET_TOKEN}"\n'
            '[[heartbeats]]\nname = "gatus"\nurl = "http://127.0.0.1:9/${THREADWATCH_TEST_UNSET_BEAT}"\n')
        code, out, _ = self.run_cli("alert-test", "--no-heartbeats", "--event", "device_quiet")
        self.assertEqual(code, 1, out)
        self.assertEqual(out.splitlines(), [
            "  ! alert sink 'phone' disabled: environment variable(s) not set: THREADWATCH_TEST_UNSET_TOKEN "
            "(see config/alerts.env)",
            "sinks (2):",
            "  ok   all: true",
            "  FAIL phone: not built -> environment variable(s) not set: THREADWATCH_TEST_UNSET_TOKEN "
            "(see config/alerts.env)",
        ])
        code, out, _ = self.run_cli("alert-test", "--event", "device_quiet")
        self.assertEqual(code, 1, out)
        self.assertIn("heartbeats (1):", out)
        self.assertIn("  FAIL gatus: not built -> environment variable(s) not set: THREADWATCH_TEST_UNSET_BEAT", out)
        # With the variables set, the usable recipient alone is a pass.
        (self.d / "config.toml").write_text(
            f'[capture]\ndata_dir = "{self.d / "data"}"\n'
            '[[alerts.sinks]]\nname = "all"\ntype = "command"\ncommand = ["true"]\n'
            '[[alerts.sinks]]\nname = "off"\ntype = "http"\nenabled = false\nurl = "http://127.0.0.1:9/${THREADWATCH_TEST_UNSET_TOKEN}"\n')
        code, out, _ = self.run_cli("alert-test", "--no-heartbeats", "--event", "device_quiet")
        self.assertEqual((code, out.splitlines()), (0, ["sinks (1):", "  ok   all: true"]))


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
        (inc / "20260901T070000_storm-at-noon").mkdir()      # freeze wrote the label filename-safe...
        code, _, err = self.run_cli("incidents", "--delete", "storm at noon")   # ...delete takes it as typed
        self.assertEqual((code, err), (0, ""))
        self.assertFalse((inc / "20260901T070000_storm-at-noon").exists())
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


class AdoptTest(CliCase):
    def test_adopted_name_is_read_back_from_beside_the_config_file(self):
        from unittest import mock
        from threadwatch import config as config_mod
        from threadwatch.names import DeviceNames
        # This checkout may carry a real config/devices.json; keep the test
        # (and adopt's write) away from it.
        with mock.patch.object(config_mod, "REPO_ROOT", self.d / "repo"):
            self.assertIsNone(config_mod.load(Path(self.cfg)).devices_path)   # no inventory anywhere yet
            code, out, _ = self.run_cli("adopt", "66417fe110ed6950", "Office AQ")
            self.assertEqual(code, 0)
            self.assertIn(str(self.d / "devices.json"), out)
            cfg = config_mod.load(Path(self.cfg))
        self.assertEqual(cfg.devices_path, (self.d / "devices.json").resolve())   # load() resolves symlinks
        self.assertEqual(DeviceNames(cfg.devices_path).name("66417fe110ed6950"), "Office AQ")


class FreezeTest(CliCase):
    def test_freeze_copies_ring_state_and_events(self):
        from threadwatch.config import load
        (self.d / "config.toml").write_text(
            f'[capture]\ndata_dir = "{self.d / "data"}"\n[devices]\ninventory = "devices.json"\n'
            '[[alerts.sinks]]\nname = "phone"\ntype = "ntfy"\nurl = "https://ntfy.example/topic-9f3a"\n'
            'headers = { Authorization = "Bearer hunter2" }\n')
        (self.d / "devices.json").write_text('[{"name": "Office AQ", "extendedAddress": "26976E7F7D20964A"}]')
        cfg = load(Path(self.cfg))
        cfg.ring_dir.mkdir(parents=True)
        (cfg.ring_dir / "threadwatch-20260903-08.pcap").write_bytes(b"a")
        (cfg.ring_dir / "threadwatch-20260903-09.pcap").write_bytes(b"b")
        (cfg.state_dir / "last-seen.json").write_text("{}")
        (cfg.state_dir / "border-routers.json").write_text("{}")   # the hubs' address history
        cfg.events_dir.mkdir(parents=True)
        (cfg.events_dir / "2026-09-03.jsonl").write_text("")
        code, out, _ = self.run_cli("freeze", "my label/with junk")
        self.assertEqual(code, 0)
        self.assertIn("froze 2 ring files", out)
        inc = next(p for p in cfg.incidents_dir.iterdir() if not p.name.startswith("."))
        self.assertTrue(inc.name.endswith("_my-label-with-junk"))
        self.assertEqual(sorted(p.name for p in inc.iterdir()),
                         ["border-routers.json", "config.toml", "devices.json", "events", "last-seen.json",
                          "manifest.json", "threadwatch-20260903-08.pcap", "threadwatch-20260903-09.pcap"])
        self.assertEqual(self.run_cli("incidents")[1].count("my-label-with-junk"), 1)
        # The inventory as it was; the configuration with its secrets blanked.
        self.assertEqual((inc / "devices.json").read_text(), (self.d / "devices.json").read_text())
        frozen_cfg = (inc / "config.toml").read_text()
        self.assertNotIn("topic-9f3a", frozen_cfg)
        self.assertNotIn("hunter2", frozen_cfg)
        self.assertIn('url = "<redacted>"', frozen_cfg)
        self.assertIn('name = "phone"', frozen_cfg)
        manifest = json.loads((inc / "manifest.json").read_text())
        self.assertEqual((manifest["label"], manifest["trigger"], manifest["ring_files"], manifest["span"],
                          manifest["inventory"], manifest["config"], manifest["events_days"]),
                         ("my-label-with-junk", "manual", 2, ["20260903-08", "20260903-09"],
                          "devices.json", "config.toml", 1))
        self.assertEqual(manifest["files"]["threadwatch-20260903-08.pcap"], 1)
        self.assertIn("events/2026-09-03.jsonl", manifest["files"])
        self.assertIn("threadwatch", manifest)


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

    def test_episodes_are_grouped_before_the_severity_floor_is_applied(self):
        # The return is a notice; filtered out before grouping, the warning
        # it closed read as still open, while the day page said otherwise.
        from threadwatch.config import load
        from threadwatch.events import EventLog
        log = EventLog(load(Path(self.cfg)).events_dir)
        log.emit("device_returned", "notice", 1_756_800_000.0 + 1800, addr="b62c32bf669272db",
                 name="Living Room Apple TV")
        code, out, err = self.run_cli("events", "--episodes", "--severity", "warning")
        self.assertEqual(code, 0, err)
        lines = out.splitlines()
        self.assertEqual(len(lines), 2, out)                    # the closed quiet and the storm; not the Office notice
        self.assertIn("Living Room Apple TV quiet for 60m", lines[0])
        self.assertNotIn("went quiet", out)
        self.assertNotIn("Office", out)
        self.assertIn("[critical", lines[1])
        code, out, _ = self.run_cli("events", "--episodes", "--severity", "critical", "--device", "apple tv")
        self.assertEqual((code, out.strip()), (0, "no episodes about 'apple tv' at critical or above"))
        # Record-level filtering of the raw listing is unchanged.
        self.assertEqual(self.events("--device", "apple tv", "--severity", "warning"), ["device_quiet"])


if __name__ == "__main__":
    unittest.main()


class ReportSuggestTest(CliCase):
    """The recorder files the hostnames it harvests in observed-names.json;
    `threadwatch report --suggest` turns them into inventory entries."""

    DEV = "26976e7f7d20964a"

    def test_the_recorder_writes_observed_names_and_report_suggests_them(self):
        from threadwatch import config as config_mod
        from threadwatch.crypto import Decryptor
        from threadwatch.events import NullEventLog
        from threadwatch.pcap import Frame
        from threadwatch.pipeline import Pipeline
        (self.d / "devices.json").write_text("[]")   # an inventory of our own, not the repo's fallback
        cfg = config_mod.load(Path(self.cfg))
        self.assertEqual(cfg.devices_path, (self.d / "devices.json").resolve())
        names_file = cfg.state_dir / "observed-names.json"
        t = 1_756_800_000.0

        def run(ephemeral):
            pipe = Pipeline(cfg, NullEventLog(), Decryptor(network_key=bytes(16)), ephemeral=ephemeral)
            for i in range(5):
                pipe.ingest(Frame(ts=t + i, raw=b"", psdu=psdu_for(self.DEV, seq=i), rssi=-60.0, channel=None,
                                  lqi=None, ftype=1, seq=i, dst_pan=0x4e21, dst="0000", src_pan=0x4e21, src=self.DEV))
            for _ in range(3):
                pipe._note_observed_name(self.DEV, "office-aq-1a2b.local")
            pipe._note_observed_name(self.DEV, "junk-once.x[L(")
            pipe.periodic(t + 60)
            pipe.seen.save()
            return pipe

        run(ephemeral=True)                                          # replay: the live state is not touched
        self.assertFalse(names_file.exists())
        self.assertFalse((cfg.state_dir / "last-seen.json").exists())
        run(ephemeral=False)
        self.assertEqual(json.loads(names_file.read_text()),
                         {self.DEV: {"office-aq-1a2b.local": 3, "junk-once.x[L(": 1}})
        self.assertFalse(names_file.with_suffix(".tmp").exists())   # written whole, then renamed into place

        code, out, err = self.run_cli("report", "--suggest")
        self.assertEqual(code, 0, err)
        entries = json.loads(out)
        self.assertEqual([(e["name"], e["extendedAddress"]) for e in entries],
                         [("office-aq-1a2b.local", self.DEV.upper())])
        self.assertIn("5 frames since ", entries[0]["note"])
        self.assertIn("advertised as office-aq-1a2b.local", entries[0]["note"])
        self.assertNotIn("junk-once", entries[0]["note"])           # seen once: a regex false positive
        self.assertIn("1 entry to fill in and paste into devices.json", err)
        # Named, the address leaves the unknown list and nothing is suggested.
        self.assertEqual(self.run_cli("adopt", self.DEV, "Office AQ")[0], 0)
        code, out, err = self.run_cli("report", "--suggest")
        self.assertEqual((code, json.loads(out), err), (0, [], ""))


class ReplayTest(CliCase):
    """`threadwatch replay <pcap>` runs the whole pipeline over a file and
    prints one JSON object: what a storm looked like, what it would have
    alerted, without touching the live recorder's state."""

    DEV, OTHER = "26976e7f7d20964a", "b62c32bf669272db"
    T = 1_756_800_000.0

    def _psdu(self, addr, seq, counter=None):
        # Secured under the credentials the replay loads, with a counter
        # that climbs: what the pipeline takes for a sighting of the device.
        return secured_psdu(addr, seq + 1 if counter is None else counter, seq=seq,
                            key=bytes.fromhex("00112233445566778899aabbccddeeff"))

    def _pcap(self):
        from threadwatch.pcap import DLT_NOFCS, Frame, PcapWriter
        pcap = self.d / "storm.pcap"
        with open(pcap, "wb") as fh:
            w = PcapWriter(fh, DLT_NOFCS)
            for i in range(6):
                psdu = self._psdu(self.DEV if i % 2 else self.OTHER, i)
                w.write(Frame(ts=self.T + i, raw=psdu, psdu=psdu, rssi=None, channel=None, lqi=None))
        return pcap

    def test_replay_prints_the_run_as_json_and_writes_no_state(self):
        (self.d / "credentials.toml").write_text('[credentials]\nnetwork_key = "00112233445566778899aabbccddeeff"\n')
        code, out, err = self.run_cli("replay", str(self._pcap()))
        self.assertEqual(code, 0)
        self.assertIn("[threadwatch] credentials: loaded", err)      # stdout is the JSON alone
        run = json.loads(out)
        self.assertEqual(sorted(run), ["crypto", "detector", "duration_s", "events", "file", "files", "frames", "partition"])
        self.assertEqual((run["file"], run["files"], run["frames"], run["duration_s"], run["partition"]),
                         (str(self.d / "storm.pcap"), [str(self.d / "storm.pcap")], 6, 5.0, None))
        self.assertEqual(run["detector"]["storm_active"], False)
        self.assertEqual(run["crypto"]["key_sequence"], 0)          # the frames decrypted under sequence 0
        self.assertIn("mac_decrypted", run["crypto"])
        self.assertEqual([(e["event"], e["addr"]) for e in run["events"] if e["event"] == "device_first_seen"],
                         [("device_first_seen", self.OTHER), ("device_first_seen", self.DEV)])
        self.assertTrue(all(e["ts"] >= self.T for e in run["events"]))
        written = sorted(p.name for p in (self.d / "data").rglob("*") if p.is_file())
        self.assertEqual(written, [])                                 # ephemeral: nothing under data/

    def test_a_pcap_that_cannot_be_read_is_one_line_and_exit_1(self):
        (self.d / "credentials.toml").write_text('[credentials]\nnetwork_key = "00112233445566778899aabbccddeeff"\n')
        junk = self.d / "notes.txt"
        junk.write_text("not a capture")
        for path, reason in ((self.d / "missing.pcap", "No such file or directory"), (junk, "no pcap global header")):
            code, out, _err = self.run_cli("replay", str(path))      # SystemExit's code is the message: exit 1
            self.assertTrue(str(code).startswith(f"threadwatch replay: could not read {path}: "), code)
            self.assertIn(reason, str(code))
            self.assertEqual(out, "")                                # no JSON that reads as an empty capture

    def _write_pcap(self, name, frames, dlt):
        from threadwatch.pcap import Frame, PcapWriter
        pcap = self.d / name
        with open(pcap, "wb") as fh:
            w = PcapWriter(fh, dlt)
            for ts, raw in frames:
                w.write(Frame(ts=ts, raw=raw, psdu=raw, rssi=None, channel=None, lqi=None))
        return pcap

    def test_replay_finds_a_silence_that_ends_before_the_file_does(self):
        # BUG-03: replay ran the periodic checks once, at EOF, so a device
        # that fell silent and came back inside the file was never quiet.
        from threadwatch.pcap import DLT_NOFCS
        (self.d / "config.toml").write_text(f'[capture]\ndata_dir = "{self.d / "data"}"\n[quiet]\nsilence_s = 60\n')
        (self.d / "credentials.toml").write_text('[credentials]\nnetwork_key = "00112233445566778899aabbccddeeff"\n')
        frames = [(self.T, self._psdu(self.DEV, 0))]
        frames += [(self.T + 30 * i, self._psdu(self.OTHER, i)) for i in range(1, 7)]     # T+30 .. T+180
        frames.append((self.T + 210, self._psdu(self.DEV, 7)))
        code, out, _err = self.run_cli("replay", str(self._write_pcap("quiet.pcap", frames, DLT_NOFCS)))
        self.assertEqual(code, 0)
        events = [(e["event"], e["addr"]) for e in json.loads(out)["events"] if e.get("addr") == self.DEV]
        self.assertEqual(events, [("device_first_seen", self.DEV), ("device_quiet", self.DEV),
                                  ("device_returned", self.DEV)])

    def test_replay_judges_several_files_as_one_run(self):
        # A silence that begins in one hourly file and ends in the next is
        # one silence: judged once, across the boundary, as the recorder
        # judged it, whether the files are named or the directory is.
        from threadwatch.pcap import DLT_NOFCS
        (self.d / "config.toml").write_text(f'[capture]\ndata_dir = "{self.d / "data"}"\n[quiet]\nsilence_s = 60\n')
        (self.d / "credentials.toml").write_text('[credentials]\nnetwork_key = "00112233445566778899aabbccddeeff"\n')
        ring = self.d / "ring"
        ring.mkdir()
        first = [(self.T, self._psdu(self.DEV, 0))] + [(self.T + 30 * i, self._psdu(self.OTHER, i)) for i in range(1, 4)]
        second = [(self.T + 30 * i, self._psdu(self.OTHER, i)) for i in range(4, 7)] + [(self.T + 210, self._psdu(self.DEV, 7))]
        a = self._write_pcap("ring/threadwatch-20260903-08.pcap", first, DLT_NOFCS)
        b = self._write_pcap("ring/threadwatch-20260903-09.pcap", second, DLT_NOFCS)
        code, out, _err = self.run_cli("replay", str(a), str(b))
        self.assertEqual(code, 0)
        run = json.loads(out)
        self.assertEqual((run["file"], run["files"], run["frames"]), (None, [str(a), str(b)], 8))
        events = [(e["event"], e["addr"]) for e in run["events"] if e.get("addr") == self.DEV]
        self.assertEqual(events, [("device_first_seen", self.DEV), ("device_quiet", self.DEV),
                                  ("device_returned", self.DEV)])
        self.assertEqual(json.loads(self.run_cli("replay", str(ring))[1])["events"], run["events"])   # the directory: the same
        code, out, _err = self.run_cli("replay", str(self.d))                       # no pcaps in it
        self.assertEqual(code, f"threadwatch replay: no pcap files in {self.d}")
        self.assertEqual(self.run_cli("replay")[0], 2)                               # nothing named: usage error

    def test_replay_reads_an_incident_with_the_inventory_frozen_in_it(self):
        from threadwatch.pcap import DLT_NOFCS
        (self.d / "config.toml").write_text(f'[capture]\ndata_dir = "{self.d / "data"}"\n[devices]\ninventory = "devices.json"\n')
        (self.d / "devices.json").write_text(json.dumps([{"name": "Live Name", "extendedAddress": self.DEV}]))
        (self.d / "credentials.toml").write_text('[credentials]\nnetwork_key = "00112233445566778899aabbccddeeff"\n')
        inc = self.d / "data" / "incidents" / "20260903T100000_storm-at-noon"
        inc.mkdir(parents=True)
        self._write_pcap("data/incidents/20260903T100000_storm-at-noon/threadwatch-20260903-09.pcap",
                         [(self.T + i, self._psdu(self.DEV, i)) for i in range(3)], DLT_NOFCS)
        (inc / "devices.json").write_text(json.dumps([{"name": "Frozen Name", "extendedAddress": self.DEV}]))
        for want in ("storm-at-noon", "storm at noon", inc.name, str(inc)):
            code, out, err = self.run_cli("replay", "--incident", want)
            self.assertEqual(code, 0, (want, err))
            run = json.loads(out)
            self.assertEqual(run["files"], [str(inc / "threadwatch-20260903-09.pcap")])
            self.assertEqual([e["name"] for e in run["events"] if e["event"] == "device_first_seen"], ["Frozen Name"])
        code, _out, _err = self.run_cli("replay", "--incident", "nope")
        self.assertEqual(code, 1)
        self.assertEqual(sorted(p.name for p in (self.d / "data" / "state").rglob("*")) if (self.d / "data" / "state").exists() else [], [])

    def test_replay_finds_a_link_drop_that_holds_and_then_recovers(self):
        from threadwatch.pcap import DLT_TAP
        (self.d / "config.toml").write_text(f'[capture]\ndata_dir = "{self.d / "data"}"\n'
                                            '[link]\ndrop_db = 8\nhold_s = 60\n')
        (self.d / "credentials.toml").write_text('[credentials]\nnetwork_key = "00112233445566778899aabbccddeeff"\n')

        def tap(rssi, seq):
            return struct.pack("<HHHHf", 0, 12, 1, 4, rssi) + self._psdu(self.DEV, seq & 0xff, counter=seq + 1)

        levels = [-50.0] * 300 + [-70.0] * 150 + [-50.0] * 120       # settle, sink, come back
        frames = [(self.T + i, tap(level, i)) for i, level in enumerate(levels)]
        code, out, _err = self.run_cli("replay", str(self._write_pcap("link.pcap", frames, DLT_TAP)))
        self.assertEqual(code, 0)
        link = [(e["event"], e["ts"] - self.T) for e in json.loads(out)["events"]
                if e["event"].startswith("rssi_")]
        self.assertEqual([e for e, _ in link], ["rssi_degradation", "rssi_recovered"])
        self.assertTrue(300 < link[0][1] < 450 < link[1][1] < 570, link)   # each inside the file, not at EOF

    def test_replay_without_credentials_exits_2_with_the_reason(self):
        code, out, err = self.run_cli("replay", str(self._pcap()))
        self.assertEqual((code, out), (2, ""))
        self.assertTrue(err.startswith("threadwatch replay: "), err)
        self.assertIn("credentials", err)


class ConfigValidationTest(unittest.TestCase):
    """A config mistake must fail loudly, not silently record the wrong thing."""

    def _load(self, body):
        import tempfile
        from pathlib import Path as _P
        from threadwatch import config
        d = _P(tempfile.mkdtemp())
        (d / "config.toml").write_text(body)
        return config.load(d / "config.toml")

    def test_out_of_range_and_degenerate_values_are_rejected(self):
        for body in ('[network]\nchannel = 99\n',
                     '[network]\nchannel = 3\n',
                     '[capture]\nkeep_files = 0\n',
                     '[detect]\nperiod_onsets = 1\n'):
            with self.assertRaises(ValueError):
                self._load(body)

    def test_quoted_channel_is_coerced_not_carried_as_a_string(self):
        self.assertEqual(self._load('[network]\nchannel = "25"\n').channel, 25)

    def test_data_dir_expands_environment_variables(self):
        import os
        os.environ["TW_TEST_ROOT"] = "/tmp/tw-test-root"
        cfg = self._load('[capture]\ndata_dir = "$TW_TEST_ROOT/data"\n')
        self.assertEqual(str(cfg.data_dir), "/tmp/tw-test-root/data")

    def test_a_config_path_that_does_not_exist_is_one_line_not_a_traceback(self):
        from threadwatch.cli import main
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            main(["--config", "/nonexistent/config.toml", "status"])
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("threadwatch: ", err.getvalue())
        self.assertIn("/nonexistent/config.toml", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_doctor_warns_when_no_config_file_was_read(self):
        from threadwatch import doctor
        from threadwatch.config import Config
        levels = {name: lvl for lvl, name, _ in doctor.check_config(Config())}
        self.assertEqual(levels["config"], "warn")
