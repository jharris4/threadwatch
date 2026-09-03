"""Unit tests for the quiet-device policy in threadwatch.pipeline."""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.config import Config  # noqa: E402
from threadwatch.events import NullEventLog  # noqa: E402
from threadwatch.pcap import Frame  # noqa: E402
from threadwatch.pipeline import Pipeline  # noqa: E402

ROUTER = "b62c32bf669272db"
SENSOR = "1669674dd15cf0fa"
STRANGER = "72d035122fdf06f6"
OWN_PAN, OTHER_PAN = 0x4e21, 0x58bc


def frame(ts, src, pan=OWN_PAN, rssi=-60.0):
    return Frame(ts=ts, raw=b"", psdu=b"", rssi=rssi, channel=None, lqi=None,
                 ftype=1, seq=int(ts) & 0xFF, dst_pan=pan, dst="0000", src_pan=pan, src=src)


class QuietPolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Living Room Apple TV", "extendedAddress": ROUTER.upper(),
             "threadRole": "border-router-leader"},
            {"name": "Living Room AQ", "extendedAddress": SENSOR, "threadRole": "sleepy-end-device"},
        ]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json",
                          quiet_end_device_s=90 * 60, quiet_router_s=30 * 60)

    def tearDown(self):
        self.tmp.cleanup()

    def _pipe(self):
        return Pipeline(self.cfg, NullEventLog())

    @staticmethod
    def _quiet(pipe):
        return [(r["addr"], r["profile"]) for r in pipe.events.records if r["event"] == "device_quiet"]

    def test_only_inventory_routers_get_the_short_window(self):
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(3):
            pipe.ingest(frame(t0 + i, ROUTER))
            pipe.ingest(frame(t0 + i, SENSOR))
        pipe.periodic(t0 + 31 * 60)
        self.assertEqual(self._quiet(pipe), [(ROUTER, "router")])
        pipe.periodic(t0 + 91 * 60)
        self.assertEqual(self._quiet(pipe), [(ROUTER, "router"), (SENSOR, "end-device")])
        names = [r["name"] for r in pipe.events.records if r["event"] == "device_quiet"]
        self.assertEqual(names, ["Living Room Apple TV", "Living Room AQ"])

    def test_reed_counts_as_router_and_role_key_variants_are_accepted(self):
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Light", "extendedAddress": ROUTER, "threadRole": "reed"},
            {"name": "Plug", "extendedAddress": SENSOR, "role": "Router"},
        ]))
        pipe = self._pipe()
        self.assertTrue(pipe.is_router(ROUTER))
        self.assertTrue(pipe.is_router(SENSOR))
        self.assertFalse(pipe.is_router(STRANGER))

    def test_marginal_reception_is_logged_at_notice_not_warning(self):
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(40):
            pipe.ingest(frame(t0 + i, ROUTER, rssi=-88.0))
            pipe.ingest(frame(t0 + i, SENSOR, rssi=-55.0))
        self.assertLess(pipe.seen.table[ROUTER]["rssi"], -85)
        pipe.periodic(t0 + 91 * 60)
        by_addr = {r["addr"]: r for r in pipe.events.records if r["event"] == "device_quiet"}
        self.assertEqual(by_addr[ROUTER]["severity"], "notice")
        self.assertEqual(by_addr[ROUTER]["reception"], "marginal")
        self.assertIn("edge of its range", by_addr[ROUTER]["note"])
        self.assertEqual(by_addr[SENSOR]["severity"], "warning")
        self.assertEqual(by_addr[SENSOR]["reception"], "good")

    def test_report_carries_role_and_reception(self):
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        pipe.ingest(frame(t0, ROUTER, rssi=-88.0))
        pipe.ingest(frame(t0, STRANGER, rssi=-60.0))
        rep = pipe.seen.report(pipe.names, quiet_after_s=60, now=t0 + 120, min_rssi_dbm=-82)
        rows = {r["addr"]: r for r in rep["quiet"]}
        self.assertEqual((rows[ROUTER]["role"], rows[ROUTER]["reception"]), ("border-router-leader", "marginal"))
        self.assertEqual((rows[STRANGER]["role"], rows[STRANGER]["reception"]), (None, "good"))
        self.assertEqual([r["addr"] for r in rep["unknown"]], [STRANGER])

    def test_foreign_pan_devices_are_never_reported_quiet(self):
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(10):
            pipe.ingest(frame(t0 + i, SENSOR))
        for i in range(3):
            pipe.ingest(frame(t0 + i, STRANGER, pan=OTHER_PAN))
        pipe.periodic(t0 + 24 * 3600)
        self.assertEqual(self._quiet(pipe), [(SENSOR, "end-device")])
        self.assertEqual(pipe.seen.table[STRANGER]["pan"], OTHER_PAN)

    def test_restart_seeds_only_devices_past_their_threshold(self):
        now = time.time()
        pipe = self._pipe()
        pipe.ingest(frame(now - 40 * 60, ROUTER))   # past router window: already "reported"
        pipe.ingest(frame(now - 40 * 60, SENSOR))   # inside end-device window: still eligible
        pipe.seen.save()
        pipe2 = self._pipe()
        self.assertEqual(pipe2.quiet_reported, {ROUTER})
        pipe2.periodic(now + 60 * 60)
        self.assertEqual(self._quiet(pipe2), [(SENSOR, "end-device")])

    def test_returned_device_can_go_quiet_again(self):
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        pipe.ingest(frame(t0, ROUTER))
        pipe.periodic(t0 + 31 * 60)
        pipe.ingest(frame(t0 + 32 * 60, ROUTER))
        pipe.periodic(t0 + 70 * 60)
        events = [r["event"] for r in pipe.events.records if r["addr"] == ROUTER]
        self.assertEqual(events, ["device_first_seen", "device_quiet", "device_returned", "device_quiet"])


if __name__ == "__main__":
    unittest.main()
