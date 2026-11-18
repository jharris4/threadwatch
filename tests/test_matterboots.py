"""matterboots: each Matter node's boots from its reboot count and uptime,
read through a fixed script; made-up nodes, products and addresses."""

import gzip
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests  # noqa: F401  (the mDNS guard)
from tests.test_halogs import journal_line
from threadwatch import matterboots as mb
from threadwatch import reboots
from threadwatch.config import Config
from threadwatch.halogs import hour_name

T0 = 1_757_800_800.0            # a round UTC hour
AIR, MOTION, PLUG = 0x10, 0x20, 0x30
PRODUCTS = {AIR: "ALPSTUGA air quality monitor", MOTION: "Motion Sensor", PLUG: "Smart Plug"}


def cfg_for(root: Path) -> Config:
    cfg = Config(data_dir=root / "data", config_dir=root, devices_path=root / "devices.json")
    cfg.otbr_ssh_target, cfg.otbr_ssh_port, cfg.otbr_sudo = "hassio@ha", 2222, True
    cfg.boots_enabled = True
    return cfg


class Runner:
    """The SSH side: one script output per call, the calls kept."""

    def __init__(self):
        self.calls, self.outputs = [], []

    def __call__(self, argv, stdin, timeout_s):
        self.calls.append((argv, stdin, timeout_s))
        return self.outputs.pop(0)


def output(at, rows, done=True):
    """rows: node -> (count, uptime, reason), or None for a node that did not answer."""
    paths = ("0/51/1", "0/51/2", "0/51/4")
    lines = [json.dumps({"node": n, "product": PRODUCTS[n], "at": at,
                         "result": r and {p: v for p, v in zip(paths, r, strict=True) if v is not None},
                         "error": "timeout" if r is None else None}) for n, r in rows.items()]
    return {"status": "incomplete", "output": "\n".join(["warming up", *lines] + ([json.dumps({"done": len(rows)})]
                                                                                    if done else []))}


def resume_line(ts, node):
    return journal_line(ts, f"\x1b[2m INFO   \x1b[0;1;90mCaseServer           \x1b[0;35m@1:{node:x}•5d67 "
                            f"\x1b[39mResumed session with \x1b[1m@1:{node:x} \x1b[0m2↔1", "app_core_matter_server")


def archive(root: Path, hour: float, lines=()):
    d = root / reboots.SLUG
    d.mkdir(parents=True, exist_ok=True)
    with gzip.open(d / f"{hour_name(hour)}.log.gz", "wt") as fh:
        for line in lines:
            fh.write(line)


class PollTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cfg, self.run, self.state = cfg_for(self.root), Runner(), {}

    def tearDown(self):
        self.tmp.cleanup()

    def poll(self, at, rows, **kw):
        self.run.outputs.append(rows if "output" in rows else output(at, rows, **kw))
        self.state, finals, summary = mb.poll(self.cfg, self.state, self.root / "ha-logs", at, self.run)
        return finals, summary

    def test_the_command_is_fixed_and_the_script_goes_on_stdin(self):
        self.poll(T0, {PLUG: (3, 100, 1)})
        argv, stdin, timeout = self.run.calls[0]
        self.assertEqual(argv[-1], "sudo -n docker exec -i app_core_matter_server node -")
        self.assertEqual(argv[-2], "hassio@ha")
        self.assertIn("BatchMode=yes", argv)
        self.assertEqual(stdin, mb.SCRIPT.encode())
        self.assertEqual(timeout, mb.TIMEOUT_S)

    def test_a_first_read_journals_the_last_boot_and_slow_clocks_are_removed(self):
        finals, summary = self.poll(T0, {AIR: (7, 1_000_000, 1), PLUG: (3, 1_000_000, None)})
        self.assertEqual(summary["status"], "ok")
        got = {b["node"]: b for b in finals}
        self.assertTrue(all(b["first_read"] for b in finals))
        self.assertEqual(got[PLUG]["ts"], T0 - 1_000_000)
        self.assertAlmostEqual(got[AIR]["ts"], T0 - 1_000_000 / (1 - 0.001526), places=3)
        self.assertEqual(got[AIR]["stamp"], "uptime")        # no archive at all: nothing to wait for
        self.assertEqual(self.state["history"], [])          # a first read is not a reboot to page on

    def test_a_count_change_and_an_uptime_going_back_are_each_a_boot(self):
        self.poll(T0, {MOTION: (5, 50_000, None), PLUG: (None, 50_000, None)})
        finals, _ = self.poll(T0 + 3600, {MOTION: (5, 53_600, None), PLUG: (None, 53_600, None)})
        self.assertEqual(finals, [])
        finals, _ = self.poll(T0 + 7200, {MOTION: (7, 600, None), PLUG: (None, 900, None)})
        got = {b["node"]: b for b in finals}
        self.assertEqual((got[MOTION]["boots"], got[MOTION]["ts"]), (2, T0 + 6600))
        self.assertEqual((got[PLUG]["boots"], got[PLUG]["ts"]), (1, T0 + 6300))
        self.assertEqual(sorted(h[1:] for h in self.state["history"]), [[MOTION, 0, 2], [PLUG, 0, 1]])

    def test_slow_clock_creep_and_read_latency_are_not_boots(self):
        self.poll(T0, {AIR: (7, 1_000_000, 1), MOTION: (5, 50_000, None)})
        week = 7 * 86400
        finals, _ = self.poll(T0 + week, {AIR: (7, (1_000_000 + week) * (1 - 0.0005), 1),
                                          MOTION: (5, 50_000 + week - 50, None)})
        self.assertEqual(finals, [])

    def test_a_failed_poll_and_a_silent_node_lose_no_boot(self):
        self.poll(T0, {MOTION: (5, 50_000, None), PLUG: (3, 50_000, 1)})
        finals, summary = self.poll(T0 + 3600, {"status": "unreachable", "output": ""})
        self.assertEqual((finals, summary["status"]), ([], "unreachable"))
        finals, summary = self.poll(T0 + 7200, {MOTION: None, PLUG: (3, 57_200, 1)})
        self.assertEqual((finals, summary["failed"]), ([], [MOTION]))
        finals, _ = self.poll(T0 + 10800, {MOTION: (6, 1000, None), PLUG: (3, 60_800, 1)})
        self.assertEqual([(b["node"], b["boots"], b["after"]) for b in finals], [(MOTION, 1, T0)])
        _, summary = self.poll(T0 + 14400, {}, done=True)
        self.assertEqual(summary["status"], "no nodes listed")

    def test_an_air_monitor_waits_for_the_session_resume_line(self):
        logs = self.root / "ha-logs"
        archive(logs, T0)
        self.poll(T0 + 1800, {AIR: (7, 1_000_000, 1)})
        boot = T0 + 3700                                     # after the newest archived hour ends
        finals, summary = self.poll(T0 + 7200, {AIR: (8, (T0 + 7200 - boot) * (1 - 0.001526) + 4, 3)})
        self.assertEqual((finals, summary["pending"]), ([], 1))
        archive(logs, T0 + 3600, [resume_line(boot + 2, AIR)])
        archive(logs, T0 + 7200)
        finals, _ = self.poll(T0 + 10800, {AIR: (8, (T0 + 10800 - boot) * (1 - 0.001526) + 4, 3)})
        self.assertEqual([(b["stamp"], b["ts"], b["read"]["reason"]) for b in finals],
                         [("session_resume_log", boot + 2, 3)])
        self.assertEqual(self.state["pending"], [])

    def test_a_stamp_never_waits_past_its_limit(self):
        archive(self.root / "ha-logs", T0)
        self.poll(T0 + 1800, {AIR: (7, 1_000_000, 1)})
        boot = T0 + 3700
        self.poll(T0 + 7200, {AIR: (8, (T0 + 7200 - boot) * (1 - 0.001526), 3)})
        finals, _ = self.poll(T0 + 7200 + mb.STAMP_WAIT_S,
                              {AIR: (8, (mb.STAMP_WAIT_S + 3500) * (1 - 0.001526), 3)})
        self.assertEqual([b["stamp"] for b in finals], ["uptime"])
        self.assertAlmostEqual(finals[0]["ts"], boot, places=3)

    def test_a_hand_broken_state_file_loads_as_nothing_known(self):
        path = self.root / mb.STATE
        path.write_text(json.dumps({"nodes": {"16": {"at": "x"}}, "pending": [None], "history": [[1, 2]]}))
        self.assertEqual(mb.load(path), {"nodes": {}, "pending": [], "history": [], "next_poll_at": 0,
                                         "last": None})


class ClimbTest(unittest.TestCase):
    def test_boots_counted_between_reads_count_toward_a_climb(self):
        now = T0 + 5 * 86400
        state = {"nodes": {str(MOTION): {"since": T0}},
                 "history": [[now - 3600 * (k + 1), MOTION, 0, 2] for k in range(3)]}
        scan = mb.climb_scan(state, now)
        verdict = reboots.judge(reboots.distinct(scan["boots"]), MOTION, T0, scan["hours"], now)
        self.assertEqual((verdict["recent"], verdict["judged"], verdict["climbing"]), (6, True, True))


class RecorderTest(unittest.TestCase):
    """The capture thread's side: the journal record, named through the HA
    map and the inventory, and device_rebooted for every boot but a first read."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Path Motion", "extendedAddresses": ["C4E2A91D07F35B6E", "9D04B1E2C3F5A607"]}]))
        self.cfg = cfg_for(d)
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg.state_dir / "ha-map.json").write_text(json.dumps({
            "dev-b": {"addr": "C4E2A91D07F35B6E", "node_id": MOTION, "name": "HA Motion", "entities": []}}))
        (self.cfg.state_dir / reboots.STATE_FILE).write_text(json.dumps({"seen": {}, "climbing": {}}))

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_boot_is_journalled_then_logged_and_a_first_read_is_only_journalled(self):
        from threadwatch.crypto import Decryptor
        from threadwatch.events import NullEventLog
        from threadwatch.pipeline import Pipeline
        pipe = Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)))
        run = Runner()
        state = {}
        for at, rows in ((T0, {MOTION: (5, 50_000, None), PLUG: (2, 50_000, 1)}),
                         (T0 + 3600, {MOTION: (6, 600, None), PLUG: (2, 53_600, 1)})):
            run.outputs.append(output(at, rows))
            state, finals, summary = mb.poll(self.cfg, state, self.cfg.data_dir / "ha-logs", at, run)
            pipe._apply_matter_boots(state, finals, summary, at)
        boots = [r for r in pipe.journal.records if r["kind"] == "reboot"]
        self.assertEqual([(r["addr"], r["evidence"]["first_read"], r["ts"]) for r in boots],
                         [("c4e2a91d07f35b6e", True, T0 - 50_000), ("matter:48", True, T0 - 50_000),
                          ("c4e2a91d07f35b6e", False, T0 + 3000)])
        self.assertEqual(boots[0]["evidence"]["addresses"], ["c4e2a91d07f35b6e", "9d04b1e2c3f5a607"])
        self.assertEqual(boots[2]["evidence"]["source"], "uptime_reset")
        logged = [r for r in pipe.events.records if r["event"] == "device_rebooted"]
        self.assertEqual([(r["name"], r["ts"], r["boots"]) for r in logged], [("Path Motion", T0 + 3000, 1)])
        self.assertEqual(pipe.matter_boots_status()["read"], 2)
        self.assertEqual(mb.load(self.cfg.state_dir / mb.STATE)["nodes"][str(MOTION)]["count"], 6)


if __name__ == "__main__":
    unittest.main()
