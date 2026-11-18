"""matterboots: each Matter node's boots from its reboot count and uptime,
read through a fixed script; made-up nodes, products and addresses."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests  # noqa: F401  (the mDNS guard)
from threadwatch import matterboots as mb
from threadwatch import reboots
from threadwatch.config import Config

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


class PollTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.cfg, self.run, self.state = cfg_for(self.root), Runner(), {}

    def tearDown(self):
        self.tmp.cleanup()

    def poll(self, at, rows, **kw):
        self.run.outputs.append(rows if "output" in rows else output(at, rows, **kw))
        self.state, finals, summary = mb.poll(self.cfg, self.state, at, self.run)
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
        self.assertEqual(got[AIR]["stamp"], "uptime")
        self.assertEqual(self.state["history"], [])          # a first read is not a reboot to page on

    def test_a_count_change_and_an_uptime_going_back_are_each_a_boot(self):
        self.poll(T0, {MOTION: (5, 50_000, None), PLUG: (None, 50_000, None)})
        finals, _ = self.poll(T0 + 3600, {MOTION: (5, 53_600, None), PLUG: (None, 53_600, None)})
        self.assertEqual(finals, [])
        finals, _ = self.poll(T0 + 7200, {MOTION: (7, 600, None), PLUG: (None, 900, None)})
        got = {b["node"]: b for b in finals}
        self.assertEqual((got[MOTION]["boots"], got[MOTION]["ts"]), (2, T0 + 6600))
        self.assertEqual((got[PLUG]["boots"], got[PLUG]["ts"]), (1, T0 + 6300))
        self.assertEqual(sorted(h[1:] for h in self.state["history"]),
                         [[MOTION, 0, 2, T0 + 3600], [PLUG, 0, 1, T0 + 3600]])

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

    def test_a_hand_broken_state_file_loads_as_nothing_known(self):
        path = self.root / mb.STATE
        path.write_text(json.dumps({"nodes": {"16": {"at": "x"}}, "pending": [None], "history": [[1, 2]]}))
        self.assertEqual(mb.load(path), {"nodes": {}, "history": [], "held": [], "read_at": None, "outage": {},
                                         "next_poll_at": 0, "last": None})

    def test_the_count_decides_so_a_clock_step_on_the_ha_host_is_no_boot(self):
        self.poll(T0, {MOTION: (5, 50_000, None)})
        finals, _ = self.poll(T0 + 3600 + 300, {MOTION: (5, 53_600, None)})     # the host's clock jumped 5 min
        self.assertEqual(finals, [])

    def test_a_pass_stamped_by_a_clock_that_disagrees_with_this_hosts_is_dropped_whole(self):
        self.poll(T0, {MOTION: (5, 50_000, None), PLUG: (None, 50_000, None)})
        before = self.state
        # The pass runs from T0 + 3600 to T0 + 3690 by this host's clock; the HA host's is behind, then ahead.
        for off, measured in ((-600, 600), (600, 510)):
            self.run.outputs.append(output(T0 + 3600 + off, {MOTION: (6, 600, None), PLUG: (None, 53_600, None)}))
            state, finals, summary = mb.poll(self.cfg, self.state, T0 + 3600, self.run, clock=lambda: T0 + 3690)
            self.assertEqual((state, finals, summary["read"]), (before, [], 0))
            self.assertEqual(summary["status"],
                             f"clock: the Home Assistant host's clock is {measured} s from this host's")
        # The clocks agree again: the boot the dropped passes saw is found, dated right, and no other.
        finals, _ = self.poll(T0 + 7200, {MOTION: (6, 4200, None), PLUG: (None, 57_200, None)})
        self.assertEqual([(b["node"], b["ts"]) for b in finals], [(MOTION, T0 + 3000)])

    def test_an_attribute_one_read_lacks_keeps_its_last_value(self):
        self.poll(T0, {MOTION: (5, 50_000, None)})
        self.poll(T0 + 3600, {MOTION: (5, None, None)})                        # no uptime this time
        finals, _ = self.poll(T0 + 7200, {MOTION: (None, 600, None)})          # no count, a short uptime
        self.assertEqual([(b["node"], b["boots"], b["ts"]) for b in finals], [(MOTION, 1, T0 + 6600)])

    def test_a_first_read_without_uptime_journals_the_boot_once_one_comes(self):
        finals, _ = self.poll(T0, {MOTION: (5, None, None)})
        self.assertEqual(finals, [])
        finals, _ = self.poll(T0 + 3600, {MOTION: (5, 53_600, None)})
        self.assertEqual([(b["first_read"], b["ts"]) for b in finals], [(True, T0 - 50_000)])
        finals, _ = self.poll(T0 + 7200, {MOTION: (5, 57_200, None)})
        self.assertEqual(finals, [])

    def test_a_node_new_since_the_last_pass_that_booted_since_is_a_boot_and_a_gone_one_is_forgotten(self):
        self.poll(T0, {MOTION: (5, 50_000, None)})
        finals, _ = self.poll(T0 + 3600, {MOTION: (5, 53_600, None), PLUG: (1, 600, 1)})   # re-paired
        self.assertEqual([(b["node"], b["first_read"], b["ts"]) for b in finals], [(PLUG, False, T0 + 3000)])
        self.assertEqual([h[1] for h in self.state["history"]], [PLUG])
        self.poll(T0 + mb.FORGET_S + 7200, {PLUG: (1, mb.FORGET_S + 4200, 1)})
        self.assertEqual(sorted(self.state["nodes"]), [str(PLUG)])

    def test_a_pass_cut_short_says_so_and_the_order_changes_each_pass(self):
        out = output(T0, {MOTION: (5, 50_000, None)})
        out["output"] += "\n" + json.dumps({"node": PLUG, "product": "Smart Plug", "at": T0, "error": "deadline"})
        _, summary = self.poll(T0, out)
        self.assertEqual((summary["status"], summary["failed"]), ("partial: the pass ran out of time", [PLUG]))
        self.assertIn("Math.random()", mb.SCRIPT)

    def test_each_boot_says_how_early_it_may_have_been(self):
        self.poll(T0, {MOTION: (5, 50_000, None), PLUG: (2, None, None)})
        finals, _ = self.poll(T0 + 3600, {MOTION: (6, 1000, None), PLUG: (3, None, None)})
        got = {b["node"]: b for b in finals}
        self.assertEqual((got[PLUG]["stamp"], got[PLUG]["ts"], got[PLUG]["earliest"]), ("read_time", T0 + 3600, T0))
        self.assertAlmostEqual(got[MOTION]["earliest"], T0 + 2600 - 0.5)


class ClimbTest(unittest.TestCase):
    def test_boots_counted_between_reads_count_toward_a_climb(self):
        now = T0 + 5 * 86400
        state = {"nodes": {str(MOTION): {"since": T0}},
                 "history": [[now - 3600 * (k + 1), MOTION, 0, 2] for k in range(3)]}
        scan = mb.climb_scan(state, now)
        verdict = reboots.judge(reboots.distinct(scan["boots"]), MOTION, T0, scan["hours"], now)
        self.assertEqual((verdict["recent"], verdict["judged"], verdict["climbing"]), (6, True, True))

    def test_boots_counted_across_days_without_a_read_are_not_a_climb_today(self):
        now = T0 + 12 * 86400
        daily = [[T0 + d * 86400 + 50_000, MOTION, 1, 1, T0 + d * 86400 + 47_000] for d in range(1, 6)]
        # Six days with no read, then one: the count is up by 6, the last boot an hour ago.
        state = {"nodes": {str(MOTION): {"since": T0}},
                 "history": daily + [[now - 3600, MOTION, 1, 6, now - 6 * 86400]]}
        scan = mb.climb_scan(state, now)
        verdict = reboots.judge(reboots.distinct(scan["boots"]), MOTION, T0, scan["hours"], now)
        self.assertEqual((verdict["recent"], verdict["climbing"]), (1, False))
        # The same six with the read before them inside the last 24 h are six today.
        state["history"][-1][4] = now - 7200
        scan = mb.climb_scan(state, now)
        verdict = reboots.judge(reboots.distinct(scan["boots"]), MOTION, T0, scan["hours"], now)
        self.assertEqual((verdict["recent"], verdict["climbing"]), (6, True))


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
        for at, rows in ((T0, {MOTION: (5, 50_000, None), PLUG: (2, 50_000, 1)}),
                         (T0 + 3600, {MOTION: (6, 600, None), PLUG: (2, 53_600, 1)})):
            run.outputs.append(output(at, rows))
            pipe._apply_matter_boots(*mb.poll(self.cfg, pipe._matter_boots.state, at, run), at)
        boots = [r for r in pipe.journal.records if r["kind"] == "reboot"]
        self.assertEqual([(r["addr"], r["evidence"]["first_read"], r["ts"]) for r in boots],
                         [("c4e2a91d07f35b6e", True, T0 - 50_000), ("c4e2a91d07f35b6e", False, T0 + 3000)])
        self.assertEqual(boots[0]["evidence"]["addresses"], ["c4e2a91d07f35b6e", "9d04b1e2c3f5a607"])
        self.assertEqual(boots[1]["evidence"]["source"], "uptime_reset")
        logged = [r for r in pipe.events.records if r["event"] == "device_rebooted"]
        self.assertEqual([(r["name"], r["ts"], r["boots"]) for r in logged], [("Path Motion", T0 + 3000, 1)])
        self.assertEqual(pipe.matter_boots_status()["read"], 2)
        self.assertEqual(mb.load(self.cfg.state_dir / mb.STATE)["nodes"][str(MOTION)]["count"], 6)
        # The plug is not in the HA map yet: its boot waits for its address, a day at most.
        self.assertEqual([b["node"] for b in pipe._matter_boots.state["held"]], [PLUG])
        held = pipe._matter_boots.state["held"][0]
        pipe._apply_matter_boots({**pipe._matter_boots.state, "held": [{**held, "node": AIR}, held]}, [],
                                 {"at": T0 + 7200, "status": "ok"}, T0 + 7200)
        self.assertEqual(len(pipe._matter_boots.state["held"]), 2)
        (self.cfg.state_dir / "ha-map.json").write_text(json.dumps({
            "dev-b": {"addr": "C4E2A91D07F35B6E", "node_id": MOTION, "name": "HA Motion", "entities": []},
            "dev-c": {"addr": "0A1B2C3D4E5F6071", "node_id": PLUG, "name": "HA Plug", "entities": []}}))
        pipe._apply_matter_boots(pipe._matter_boots.state, [], {"at": T0 + 90_000, "status": "ok"}, T0 + 90_000)
        self.assertEqual(sorted(r["addr"] for r in pipe.journal.records if r["kind"] == "reboot"),
                         ["0a1b2c3d4e5f6071", "c4e2a91d07f35b6e", "c4e2a91d07f35b6e", "matter:16"])
        self.assertEqual(pipe._matter_boots.state["held"], [])

    def test_a_lost_journal_gets_each_nodes_last_boot_again(self):
        from threadwatch.crypto import Decryptor
        from threadwatch.events import NullEventLog
        from threadwatch.pipeline import Pipeline
        pipe = Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)))
        run = Runner()
        run.outputs.append(output(T0, {MOTION: (5, 50_000, None)}))
        pipe._apply_matter_boots(*mb.poll(self.cfg, pipe._matter_boots.state, T0, run), T0)
        self.assertTrue(pipe._matter_boots.state["nodes"][str(MOTION)]["journalled"])
        (self.cfg.state_dir / "key-journal.json").write_text("{")          # cut off by a power loss
        pipe = Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)))
        run.outputs.append(output(T0 + 3600, {MOTION: (5, 53_600, None)}))
        pipe._apply_matter_boots(*mb.poll(self.cfg, pipe._matter_boots.state, T0 + 3600, run), T0 + 3600)
        boots = [r for r in pipe.journal.records if r["kind"] == "reboot"]
        self.assertEqual([(r["ts"], r["evidence"]["first_read"]) for r in boots], [(T0 - 50_000, True)])
        self.assertEqual([r for r in pipe.events.records if r["event"] == "device_rebooted"], [])

    def test_three_hours_with_no_node_read_is_said_once_and_so_is_the_first_read_after(self):
        from threadwatch.crypto import Decryptor
        from threadwatch.events import NullEventLog
        from threadwatch.pipeline import Pipeline
        pipe = Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)))
        run = Runner()

        def after(minutes, out):
            at = T0 + 60 * minutes
            run.outputs.append(out if "output" in out else output(at, out))
            pipe._apply_matter_boots(*mb.poll(self.cfg, pipe._matter_boots.state, at, run), at)
            return [(r["event"], r["severity"]) for r in pipe.events.records if r["event"].startswith("matter_boots")]

        down = {"status": "unreachable", "output": ""}
        after(0, {MOTION: (5, 50_000, None)})
        for minutes in range(15, 180, 15):
            self.assertEqual(after(minutes, down), [])
        self.assertEqual(after(180, down), [("matter_boots_stalled", "notice")])
        self.assertEqual(mb.load(self.cfg.state_dir / mb.STATE)["outage"], {"since": T0, "reported": True})
        self.assertEqual(after(195, {MOTION: None}), [("matter_boots_stalled", "notice")])     # listed, none answered
        stalled = [r for r in pipe.events.records if r["event"] == "matter_boots_stalled"][0]
        self.assertEqual((stalled["since"], stalled["status"]), (T0, "unreachable"))
        self.assertIn("for 3.0 h", stalled["note"])
        self.assertEqual(after(210, {MOTION: (6, 600, None)})[1:], [("matter_boots_resumed", "info")])
        resumed = [r for r in pipe.events.records if r["event"] == "matter_boots_resumed"][0]
        self.assertEqual((resumed["since"], resumed["stalled_for_s"], resumed["read"]), (T0, 12_600, 1))
        self.assertEqual(len(after(270, {MOTION: (6, 4200, None)})), 2)

    def test_a_failed_journal_save_logs_nothing_and_is_applied_again(self):
        from unittest.mock import patch

        from threadwatch.crypto import Decryptor
        from threadwatch.events import NullEventLog
        from threadwatch.pipeline import Pipeline
        pipe = Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)))
        run = Runner()
        run.outputs.append(output(T0, {MOTION: (5, 50_000, None)}))
        pipe._apply_matter_boots(*mb.poll(self.cfg, pipe._matter_boots.state, T0, run), T0)
        run.outputs.append(output(T0 + 3600, {MOTION: (6, 600, None)}))
        done = mb.poll(self.cfg, pipe._matter_boots.state, T0 + 3600, run)
        with patch.object(Path, "write_text", side_effect=OSError("disk full")):
            pipe._apply_matter_boots(*done, T0 + 3600)
        self.assertEqual([r for r in pipe.events.records if r["event"] == "device_rebooted"], [])
        self.assertEqual(mb.load(self.cfg.state_dir / mb.STATE)["nodes"][str(MOTION)]["count"], 5)
        again = pipe._matter_boots.tick(T0 + 3630)
        self.assertIs(again[1], done[1])
        pipe._apply_matter_boots(*again, T0 + 3630)
        self.assertEqual(len([r for r in pipe.events.records if r["event"] == "device_rebooted"]), 1)
        self.assertEqual(len([r for r in pipe.journal.records if r["kind"] == "reboot"]), 2)
        self.assertEqual(mb.load(self.cfg.state_dir / mb.STATE)["nodes"][str(MOTION)]["count"], 6)


if __name__ == "__main__":
    unittest.main()
