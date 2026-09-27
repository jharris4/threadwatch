"""reboots: device reboots read from the archived Matter Server log, one
device_rebooted per reboot and one reboots_climbing when a device's rate
climbs against its own history."""

import gzip
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests  # noqa: F401  (the mDNS guard, installed on a direct run too: tests/no_lan)
from tests.test_halogs import TOKEN, FakeSupervisor, journal_line
from threadwatch import reboots
from threadwatch.halogs import hour_name

DAY = 86400.0
T0 = 1_757_800_800.0            # a round UTC hour
UNIT = "app_core_matter_server"
BUTTON = 0x1F
SENSOR = 0x57


def boot_text(node: int, reason: int, ansi: bool = True) -> str:
    if ansi:
        return ("\x1b[2m2025-09-13 18:00:00.000 INFO   \x1b[0;1;90mClientEventEmitter   \x1b[0mReceived event "
                f"\x1b[1mgeneralDiagnostics.bootReason \x1b[0mon \x1b[1mserver-1-7c21.@1:{node:x} \x1b[0;3m"
                f"bootReason: {reason}\x1b[0m")
    return f"Received event generalDiagnostics.bootReason on server-1-7c21.@1:{node:x} bootReason: {reason}"


def write_hours(root: Path, first: float, last: float, boots=(), mentions=()) -> None:
    """Archive files for every hour in [first, last), each holding the
    boots [(ts, node, reason)] and mentions [(ts, node)] that fall in it."""
    d = root / reboots.SLUG
    d.mkdir(parents=True, exist_ok=True)
    t = first
    while t < last:
        lines = [(ts, boot_text(n, r)) for ts, n, r in boots if t <= ts < t + 3600]
        lines += [(ts, f"Subscription successful « @1:{n:x}•b140") for ts, n in mentions if t <= ts < t + 3600]
        with gzip.open(d / f"{hour_name(t)}.log.gz", "wt") as fh:
            for ts, text in sorted(lines):
                fh.write(journal_line(ts, text, UNIT))
        t += 3600


def fake_scan(first: float, last: float, boots=(), nodes=(BUTTON, SENSOR)) -> dict:
    """What scan returns for an archive of whole hours [first, last), every
    node mentioned from its first hour."""
    hours = [hour_name(t) for t in range(int(first), int(last), 3600)]
    return {"boots": [list(b) for b in boots], "first_seen": {str(n): first for n in nodes}, "hours": hours}


class ParseTest(unittest.TestCase):
    def test_a_coloured_and_a_plain_line_parse_the_same(self):
        self.assertEqual(reboots.parse_line(boot_text(0x1F, 1)), (0x1F, 1))
        self.assertEqual(reboots.parse_line(boot_text(0x57, 6, ansi=False)), (0x57, 6))
        self.assertIsNone(reboots.parse_line("Received event basicInformation.startUp on server-1-7c21.@1:1f"))

    def test_scan_reads_boots_first_mentions_and_hours(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_hours(root, T0, T0 + 3 * 3600, boots=[(T0 + 4000, BUTTON, 1)],
                        mentions=[(T0 + 100, SENSOR), (T0 + 3700, BUTTON)])
            result = reboots.scan(root)
        self.assertEqual(result["boots"], [[T0 + 4000, BUTTON, 1]])
        self.assertEqual(result["first_seen"], {str(SENSOR): T0 + 100, str(BUTTON): T0 + 3700})
        self.assertEqual(result["hours"], [hour_name(T0 + i * 3600) for i in range(3)])

    def test_a_repeated_startup_is_one_reboot_and_a_shared_one_is_a_crowd(self):
        boots = reboots.distinct([[T0, BUTTON, 1], [T0 + 0.01, BUTTON, 1], [T0 + 30, BUTTON, 1],
                                  [T0 + 5000, 1, 1], [T0 + 5060, 2, 1], [T0 + 5200, 3, 1]])
        self.assertEqual([(b["node"], b["crowd"]) for b in boots], [(BUTTON, False), (1, True), (2, True), (3, True)])


class WatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "reboots.json"
        self.events = []
        self.names = {BUTTON: ("5a17c3e0b9d24f81", "Door Button"), SENSOR: ("c4e2a91d07f35b6e", "Path Motion")}

    def tearDown(self):
        self.tmp.cleanup()

    def watch(self):
        return reboots.RebootWatch(self.path, emit=lambda ev, sev, ts, **f: self.events.append((ev, sev, ts, f)),
                                   device=lambda n: self.names.get(n, (None, None)))

    def climbs(self):
        return [e for e in self.events if e[0] == "reboots_climbing"]

    def test_the_first_pass_takes_the_archived_week_as_already_logged(self):
        start = T0 - 5 * DAY
        w = self.watch()
        w.apply(fake_scan(start, T0, [(T0 - 2 * DAY, BUTTON, 1)]), T0)
        self.assertEqual(self.events, [])
        w = self.watch()                                          # a restart reads the state back
        w.apply(fake_scan(start, T0 + 3600, [(T0 - 2 * DAY, BUTTON, 1), (T0 + 600, BUTTON, 2)]), T0 + 3720)
        self.assertEqual([(e[0], e[1], e[2]) for e in self.events], [("device_rebooted", "notice", T0 + 600)])
        fields = self.events[0][3]
        self.assertEqual((fields["name"], fields["addr"], fields["reason_name"]),
                         ("Door Button", "5a17c3e0b9d24f81", "brown-out reset"))
        self.assertIn("lost power", fields["note"])

    def test_planned_crowded_and_unmapped_reboots(self):
        w = self.watch()
        w.state = {"seen": {}, "climbing": {}}
        boots = [(T0, SENSOR, 6), (T0 + 7200, 1, 1), (T0 + 7300, 2, 1), (T0 + 7400, 3, 1), (T0 + 20000, 0x3c, 3)]
        w.apply(fake_scan(T0, T0 + 6 * 3600, boots), T0 + 6 * 3600)
        got = [(f["node_id"], sev, f["crowd"]) for ev, sev, ts, f in self.events]
        self.assertEqual(got, [(SENSOR, "info", False), (1, "info", True), (2, "info", True), (3, "info", True),
                               (0x3c, "notice", False)])
        last = self.events[-1][3]
        self.assertEqual((last["addr"], last["name"]), (None, "Matter node 0x3c"))
        self.assertIn("firmware stopped responding", last["note"])

    def _run(self, boots, first, until, step=3600.0):
        """Hourly passes from first + 4 days to ``until``, each seeing the
        boots and whole hours before it; returns the climb pages."""
        w = self.watch()
        w.state = {"seen": {}, "climbing": {}}
        now = first + 4 * DAY
        while now <= until:
            w.apply(fake_scan(first, now, [b for b in boots if b[0] < now]), now + 120)
            now += step
        return self.climbs()

    def test_a_steady_afternoon_rebooter_never_pages_and_a_climbing_one_pages_once(self):
        first = T0
        steady = [(first + d * DAY + 16 * 3600 + k * 1800, SENSOR, 1) for d in range(10) for k in range(3)]
        # The button: nothing for four days, then 1, 6, 8, 15, 25 a day.
        climbing = [(first + (4 + d) * DAY + k * DAY / n, BUTTON, 1)
                    for d, n in enumerate((1, 6, 8, 15, 25)) for k in range(n)]
        pages = self._run(steady + climbing, first, first + 10 * DAY)
        self.assertEqual([p[3]["name"] for p in pages], ["Door Button"])
        page = pages[0][3]
        self.assertGreaterEqual(page["reboots_24h"], reboots.CLIMB_MIN)
        self.assertEqual(page["reasons"], {"power-on reboot": page["reboots_24h"]})
        self.assertIn("dying battery", page["note"])
        self.assertLess(pages[0][2], first + 7 * DAY)             # days before the 25-a-day end

    def test_a_climb_stays_open_while_its_baseline_catches_up(self):
        first = T0
        # Nothing for four days, then eight a day: by day nine the average
        # over the days before is 4 a day and 8 is no longer three times it.
        boots = [(first + 4 * DAY + k * DAY / 8, BUTTON, 1) for k in range(8 * 6)]
        pages = self._run(boots, first, first + 10 * DAY)
        self.assertEqual(len(pages), 1)
        verdict = reboots.judge(reboots.distinct(boots), BUTTON, first, fake_scan(first, first + 10 * DAY)["hours"],
                                first + 10 * DAY)
        self.assertFalse(verdict["climbing"])
        self.assertIn(str(BUTTON), json.loads(self.path.read_text())["climbing"])

    def test_a_climb_closes_when_the_day_holds_fewer_than_five_and_a_new_one_pages_again(self):
        first = T0
        burst1 = [(first + 5 * DAY + k * 3600, BUTTON, 1) for k in range(6)]
        burst2 = [(first + 8 * DAY + k * 3600, BUTTON, 1) for k in range(6)]
        pages = self._run(burst1 + burst2, first, first + 9 * DAY)
        self.assertEqual(len(pages), 2)
        self.assertEqual(json.loads(self.path.read_text())["climbing"].keys(), {str(BUTTON)})

    def test_under_three_days_of_history_logs_and_does_not_page(self):
        first = T0
        boots = [(first + 2 * DAY + 600 + k * 3600, BUTTON, 1) for k in range(10)]
        w = self.watch()
        w.state = {"seen": {}, "climbing": {}}
        w.apply(fake_scan(first, first + 2 * DAY + 11 * 3600, boots), first + 2 * DAY + 11 * 3600 + 120)
        self.assertEqual(self.climbs(), [])
        self.assertEqual(len(self.events), 10)
        verdict = reboots.judge(reboots.distinct(boots), BUTTON, first, fake_scan(first, first + 3 * DAY)["hours"],
                                first + 3 * DAY)
        self.assertEqual((verdict["recent"], verdict["judged"]), (10, False))


class ReviewTest(unittest.TestCase):
    def test_reboots_hours_apart_are_one_row_and_a_climb_is_its_own(self):
        from threadwatch.review import group_episodes
        from threadwatch.web import LEGEND_BY_KIND

        def rec(ts, event, severity="notice", **f):
            return {"ts": ts, "event": event, "severity": severity, "name": "Button", **f}
        records = [rec(T0, "device_rebooted", reason_name="power-on reboot"),
                   rec(T0 + 3 * 3600, "device_rebooted", reason_name="power-on reboot"),
                   rec(T0 + 4 * 3600, "device_rebooted", reason_name="brown-out reset"),
                   rec(T0 + 4 * 3600 + 60, "reboots_climbing", "warning", reboots_24h=5),
                   rec(T0 + 11 * 3600, "device_rebooted", reason_name="power-on reboot")]
        rows = [(e["title"], e["detail"], e["severity"]) for e in group_episodes(records, now=T0 + DAY)]
        self.assertEqual(rows[:2], [("Button rebooted 3 times", "2 power-on reboot, brown-out reset", "notice"),
                                    ("Button reboots climbing: 5 in 24 h", "", "warning")])
        self.assertEqual(rows[2][0], "Button rebooted")
        self.assertIn("reboot", LEGEND_BY_KIND)


class RecorderRebootsTest(unittest.TestCase):
    """The recorder's side: the archive worker scans the Matter Server
    hours, the capture thread names the nodes through ha-map.json and the
    inventory, and mute makes the climb a notice."""

    def setUp(self):
        from threadwatch.config import Config
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Door Button", "extendedAddress": "5A17C3E0B9D24F81"},
            {"name": "Path Motion", "extendedAddress": "C4E2A91D07F35B6E", "mute": True}]))
        self.cfg = Config(data_dir=d / "data", config_dir=d, devices_path=d / "devices.json")
        self.cfg.ha_logs_enabled = True
        self.cfg.ha_logs_archive = True
        self.cfg.ha_logs_addons = [reboots.SLUG]
        self.cfg.ha_logs_max_hours = 2
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg.state_dir / "ha-map.json").write_text(json.dumps({
            "dev-a": {"addr": "5A17C3E0B9D24F81", "node_id": BUTTON, "name": "HA Button", "entities": []},
            "dev-b": {"addr": "C4E2A91D07F35B6E", "node_id": SENSOR, "name": "HA Motion", "entities": []}}))
        self.now = float(int(time.time() // 3600) * 3600 + 1800)

    def tearDown(self):
        self.tmp.cleanup()

    def _pipe(self):
        from threadwatch.crypto import Decryptor
        from threadwatch.events import NullEventLog
        from threadwatch.pipeline import Pipeline
        return Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=bytes(16)))

    def test_the_archive_pass_logs_a_reboot_the_hour_it_arrives(self):
        now = self.now
        first = now - 4 * DAY
        write_hours(self.cfg.data_dir / "ha-logs", int(first // 3600) * 3600, int(now // 3600) * 3600 - 3600,
                    mentions=[(first + 60, BUTTON)])
        (self.cfg.state_dir / reboots.STATE_FILE).write_text(json.dumps({"seen": {}, "climbing": {}}))
        boot = int(now // 3600) * 3600 - 3000                    # in the hour the pass fetches
        srv = FakeSupervisor({reboots.SLUG: [(boot, boot_text(BUTTON, 1))]})
        try:
            (Path(self.tmp.name) / "ha.env").write_text(f"HA_URL={srv.url}\nHA_TOKEN={TOKEN}\n")
            pipe = self._pipe()
            pipe._poll_ha_archive(now)
            pipe._archive_thread.join(10)
            pipe._poll_ha_archive(now + 1)
        finally:
            srv.close()
        got = [r for r in pipe.events.records if r["event"] == "device_rebooted"]
        self.assertEqual([(r["name"], r["severity"], r["ts"]) for r in got], [("Door Button", "notice", boot)])

    def test_mute_makes_the_climb_a_notice_and_names_come_from_the_inventory(self):
        now = self.now
        first = now - 5 * DAY
        boots = [(now - 3600 * (k + 1), node, 1) for node in (BUTTON, SENSOR) for k in range(6)]
        pipe = self._pipe()
        pipe._reboots = None
        (self.cfg.state_dir / reboots.STATE_FILE).write_text(json.dumps({"seen": {}, "climbing": {}}))
        pipe._apply_reboots(fake_scan(first, now, boots), now)
        climbs = {r["name"]: r for r in pipe.events.records if r["event"] == "reboots_climbing"}
        self.assertEqual(climbs["Door Button"]["severity"], "warning")
        self.assertFalse(climbs["Door Button"]["muted"])
        self.assertEqual(climbs["Path Motion"]["severity"], "notice")
        self.assertTrue(climbs["Path Motion"]["muted"])
        self.assertIn("Muted in devices.json", climbs["Path Motion"]["note"])


if __name__ == "__main__":
    unittest.main()
