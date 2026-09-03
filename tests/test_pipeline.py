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

    def test_malformed_inventory_address_is_skipped_not_fatal(self):
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Typo", "extendedAddress": "0x" + ROUTER},
            {"name": "Dashed", "extendedAddresses": ["b6-2c-32-bf-66-92-72-db", SENSOR]},
        ]))
        pipe = self._pipe()
        self.assertEqual(sorted(pipe.names.by_addr), [SENSOR])
        self.assertEqual(pipe.names.name(SENSOR), "Dashed")

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

    def test_retransmission_alert_names_the_sender_and_target(self):
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Basement AQ", "extendedAddress": SENSOR},
            {"name": "Irrigation", "extendedAddress": ROUTER},
        ]))
        pipe = self._pipe()
        t = 1_700_000_000.0
        def send(src, dst, seq, ts):
            pipe.ingest(Frame(ts=ts, raw=b"", psdu=b"", rssi=-60.0, channel=None, lqi=None,
                              ftype=1, seq=seq, dst_pan=OWN_PAN, dst=dst, src_pan=OWN_PAN, src=src))
        # Ten quiet minutes to establish a baseline of no retransmissions.
        for m in range(10):
            for i in range(120):
                send(STRANGER, "0000", i, t + m * 60 + i * 0.4)
        # Then one minute where the sensor repeats each of 20 frames four times.
        base = t + 10 * 60
        for i in range(100):
            send(STRANGER, "0000", i, base + i * 0.3)
        for i in range(20):
            for rep in range(4):
                send(SENSOR, ROUTER, i, base + i * 2.5 + rep * 0.2)
        send(STRANGER, "0000", 200, base + 61)   # closes the window
        ev = [r for r in pipe.events.records if r["event"] == "retransmission_elevation"]
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["addr"], ev[0]["name"], ev[0]["top_target"]), (SENSOR, "Basement AQ", "Irrigation"))
        self.assertEqual(ev[0]["top_share"], 1.0)
        self.assertIn("Basement AQ repeated frames to Irrigation", ev[0]["note"])
        self.assertEqual(ev[0]["severity"], "notice")   # one bad link: logged, not paged

    def test_mesh_wide_retransmissions_page(self):
        pipe = self._pipe()
        t = 1_700_000_000.0
        def send(src, dst, seq, ts):
            pipe.ingest(Frame(ts=ts, raw=b"", psdu=b"", rssi=-60.0, channel=None, lqi=None,
                              ftype=1, seq=seq, dst_pan=OWN_PAN, dst=dst, src_pan=OWN_PAN, src=src))
        for m in range(10):
            for i in range(120):
                send(STRANGER, "0000", i, t + m * 60 + i * 0.4)
        base = t + 10 * 60
        senders = ["%016x" % (0x1000 + k) for k in range(8)]
        for i in range(20):
            for k, src in enumerate(senders):   # every device retrying a little
                send(src, "ffff", i, base + i * 2.5 + k * 0.05)
                send(src, "ffff", i, base + i * 2.5 + k * 0.05 + 0.3)
        send(STRANGER, "0000", 200, base + 61)
        ev = [r for r in pipe.events.records if r["event"] == "retransmission_elevation"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["severity"], "warning")
        self.assertLess(ev[0]["top_share"], 0.5)
        self.assertEqual(ev[0]["top_target"], "broadcast")
        self.assertIn("channel contention", ev[0]["note"])

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

    def test_restart_announces_a_silence_nobody_reported(self):
        # The recorder was down (or in the no-frames restart loop, where
        # periodic never runs) while the router crossed its window.
        now = time.time()
        pipe = self._pipe()
        pipe.ingest(frame(now - 40 * 60, ROUTER))   # past router window, never announced
        pipe.ingest(frame(now - 40 * 60, SENSOR))   # inside end-device window: still eligible
        pipe.seen.save()
        pipe2 = self._pipe()
        self.assertEqual(self._quiet(pipe2), [(ROUTER, "router")])
        self.assertEqual(pipe2.quiet_reported, {ROUTER})
        pipe2.periodic(now + 60 * 60)
        self.assertEqual(self._quiet(pipe2), [(ROUTER, "router"), (SENSOR, "end-device")])
        # A third start re-announces nothing: both silences are on record.
        self.assertEqual(self._quiet(self._pipe()), [])

    def test_recorder_downtime_is_not_counted_as_device_silence(self):
        import os
        now = time.time()
        pipe = self._pipe()
        pipe.ingest(frame(now - 40 * 60, ROUTER))
        pipe.seen.save()
        # The recorder last heard anything 38 min ago (rebooted 2 min after that frame).
        path = self.cfg.state_dir / "last-seen.json"
        os.utime(path, (now - 38 * 60, now - 38 * 60))
        pipe2 = self._pipe()
        self.assertEqual(self._quiet(pipe2), [])          # only 2 min of witnessed silence
        pipe2.periodic(now + 60)
        self.assertEqual(self._quiet(pipe2), [])
        pipe2.periodic(now + 29 * 60)                     # 2 + 29 min > the 30 min window
        self.assertEqual(self._quiet(pipe2), [(ROUTER, "router")])
        rec = [r for r in pipe2.events.records if r["event"] == "device_quiet"][0]
        self.assertAlmostEqual(rec["silent_for_s"], 31 * 60, delta=5)

    def test_restart_does_not_repeat_an_announced_silence_or_a_foreign_one(self):
        now = time.time()
        pipe = self._pipe()
        for i in range(10):
            pipe.ingest(frame(now - 3 * 3600 + i, SENSOR))
        pipe.ingest(frame(now - 3 * 3600, STRANGER, pan=OTHER_PAN))
        pipe.periodic(now - 60 * 60)                # announces the sensor, skips the foreign device
        self.assertEqual(self._quiet(pipe), [(SENSOR, "end-device")])
        pipe.seen.save()
        pipe2 = self._pipe()
        self.assertEqual(self._quiet(pipe2), [])
        self.assertEqual(pipe2.quiet_reported, {SENSOR})
        pipe2.ingest(frame(now, SENSOR))
        self.assertEqual([r["event"] for r in pipe2.events.records], ["device_returned"])
        self.assertNotIn("quiet_reported", pipe2.seen.table[SENSOR])

    def test_replay_neither_reads_nor_writes_live_state(self):
        now = time.time()
        live = self._pipe()
        live.ingest(frame(now - 2 * 3600, ROUTER))
        live.seen.save()
        before = (self.cfg.state_dir / "last-seen.json").read_text()
        replay = Pipeline(self.cfg, NullEventLog(), ephemeral=True)
        replay.ingest(frame(100.0, ROUTER))
        replay.periodic(100.0)
        replay.seen.save()
        self.assertEqual([r["event"] for r in replay.events.records], ["device_first_seen"])
        self.assertEqual((self.cfg.state_dir / "last-seen.json").read_text(), before)

    def test_restart_closes_a_silence_that_ended_while_it_was_down(self):
        now = time.time()
        pipe = self._pipe()
        pipe.ingest(frame(now - 3 * 3600, SENSOR))
        pipe.periodic(now - 3600)                   # announced quiet
        pipe.seen.table[SENSOR]["last_seen"] = now - 60   # heard again, then killed before saving the return
        pipe.seen.save()
        pipe2 = self._pipe()
        ev = [(r["event"], r["ts"]) for r in pipe2.events.records]
        self.assertEqual(ev, [("device_returned", now - 60)])
        self.assertNotIn("quiet_reported", pipe2.seen.table[SENSOR])
        self.assertEqual(pipe2.quiet_reported, set())

    def test_storm_event_carries_period_onsets_and_a_note(self):
        pipe = self._pipe()
        pipe.detector.storm_active = True
        pipe.detector.last_alert_details = {"period": 80.5, "onsets": [100.0, 180.5, 261.0]}
        pipe.ingest(frame(1_700_000_000.0, ROUTER))
        rec = [r for r in pipe.events.records if r["event"] == "phase_locked_storm"][0]
        self.assertEqual((rec["period_s"], rec["onsets"]), (80.5, 3))
        self.assertIn("every 80 s", rec["note"])

    def test_beacon_requests_count_as_join_scanning(self):
        import struct
        from threadwatch.pcap import parse_frame
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        fcf = 3 | (2 << 10)                                   # command frame, short dst, no source
        req = struct.pack("<HBH", fcf, 1, 0xFFFF) + b"\xff\xff" + b"\x07"
        for i in range(5):
            f = parse_frame(t0 + i * 5, req, 230)
            self.assertEqual((f.ftype, f.cmd, f.src), (3, 7, None))
            pipe.ingest(f)
        ev = [r for r in pipe.events.records if r["event"] == "join_scan_activity"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["count_60s"], 5)

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
