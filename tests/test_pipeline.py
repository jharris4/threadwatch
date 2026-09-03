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


def frame(ts, src, pan=OWN_PAN):
    return Frame(ts=ts, raw=b"", psdu=b"", rssi=None, channel=None, lqi=None,
                 ftype=1, seq=int(ts) & 0xFF, dst_pan=pan, dst="0000", src_pan=pan, src=src)


class QuietPolicyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Living Room Apple TV", "extendedAddress": ROUTER.upper(), "role": "border-router"},
            {"name": "Living Room AQ", "extendedAddress": SENSOR},
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
