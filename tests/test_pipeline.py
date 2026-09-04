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

    def test_critical_event_freezes_the_ring_once_per_cooldown(self):
        self.cfg.freeze_on_critical = True
        pipe = self._pipe()
        frozen = []
        pipe.freezer = frozen.append
        pipe.detector.storm_active = True
        pipe.detector.last_alert_details = {"period": 80.5, "onsets": [1.0, 2.0, 3.0]}
        # The detector ends a storm when flooding stops; hold it on regardless.
        pipe.detector.add_frame = lambda ts: setattr(pipe.detector, "storm_active", True)
        t0 = 1_700_000_000.0
        for dt in (0, 2 * 3600, 7 * 3600):                 # storm on; still on; past the six-hour cooldown
            pipe.ingest(frame(t0 + dt, ROUTER))
        storms = [r for r in pipe.events.records if r["event"] == "phase_locked_storm"]
        self.assertEqual([r["auto_freeze"] for r in storms], ["auto-storm", None, "auto-storm"])
        self.assertIn("being frozen as auto-storm", storms[0]["note"])
        self.assertIn("run 'threadwatch freeze'", storms[1]["note"])
        self.assertEqual(frozen, ["auto-storm", "auto-storm"])

    def test_auto_freeze_cooldown_survives_a_restart(self):
        self.cfg.freeze_on_critical = True
        t0 = 1_700_000_000.0
        for age, label in ((2 * 3600, "auto-storm"), (30 * 3600, "auto-storm"), (60, "manual")):
            stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime(t0 - age))
            (self.cfg.incidents_dir / f"{stamp}_{label}").mkdir(parents=True)
        pipe = self._pipe()                                # a restart mid-storm
        frozen = []
        pipe.freezer = frozen.append
        pipe.detector.storm_active = True
        pipe.detector.last_alert_details = {"period": 80.5, "onsets": [1.0, 2.0, 3.0]}
        pipe.detector.add_frame = lambda ts: setattr(pipe.detector, "storm_active", True)
        pipe.ingest(frame(t0, ROUTER))                     # 2 h after the last auto freeze: held
        pipe.ingest(frame(t0 + 5 * 3600, ROUTER))          # 7 h after it: frozen again
        storms = [r["auto_freeze"] for r in pipe.events.records if r["event"] == "phase_locked_storm"]
        self.assertEqual(storms, [None, "auto-storm"])
        self.assertEqual(frozen, ["auto-storm"])
        self.assertEqual(Pipeline(self.cfg, NullEventLog(), ephemeral=True)._last_auto_freeze, 0.0)

    def test_freeze_off_by_default_and_never_in_replay(self):
        for ephemeral in (False, True):
            self.cfg.freeze_on_critical = ephemeral        # on only for the replay case
            pipe = Pipeline(self.cfg, NullEventLog(), ephemeral=ephemeral)
            pipe.freezer = lambda label: self.fail("froze")
            pipe.detector.storm_active = True
            pipe.detector.last_alert_details = {"period": 60.0, "onsets": [1.0, 2.0, 3.0]}
            pipe.ingest(frame(1_700_000_000.0, ROUTER))
            rec = [r for r in pipe.events.records if r["event"] == "phase_locked_storm"][0]
            self.assertIsNone(rec["auto_freeze"])

    def test_the_background_freeze_logs_the_incident(self):
        pipe = self._pipe()
        self.cfg.ring_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg.ring_dir / "threadwatch-20231114-22.pcap").write_bytes(b"ring")
        pipe._freeze_now("auto-storm")
        rec = [r for r in pipe.events.records if r["event"] == "incident_frozen"][0]
        self.assertEqual(rec["ring_files"], 1)
        self.assertTrue(rec["path"].endswith("_auto-storm"))
        self.assertTrue((Path(rec["path"]) / "threadwatch-20231114-22.pcap").exists())

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

    def test_why_resolves_every_address_of_a_name_listed_twice(self):
        from threadwatch.why import resolve_target
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Living Room Apple TV", "extendedAddress": ROUTER.upper()},
            {"name": "Living Room Apple TV", "extendedAddress": SENSOR},
        ]))
        addrs, name = resolve_target(self.cfg, "apple tv")
        self.assertEqual((sorted(addrs), name), (sorted([ROUTER, SENSOR]), "Living Room Apple TV"))

    def test_returned_device_can_go_quiet_again(self):
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        pipe.ingest(frame(t0, ROUTER))
        pipe.periodic(t0 + 31 * 60)
        pipe.ingest(frame(t0 + 32 * 60, ROUTER))
        pipe.periodic(t0 + 70 * 60)
        events = [r["event"] for r in pipe.events.records if r.get("addr") == ROUTER]
        self.assertEqual(events, ["device_first_seen", "device_quiet", "device_returned", "device_quiet"])


if __name__ == "__main__":
    unittest.main()


def poll(ts, src, seq):
    return Frame(ts=ts, raw=b"", psdu=b"", rssi=-60.0, channel=None, lqi=None,
                 ftype=3, cmd=4, seq=seq, dst_pan=OWN_PAN, dst="0000", src_pan=OWN_PAN, src=src)


def ack(ts, seq):
    return Frame(ts=ts, raw=b"", psdu=b"", rssi=-40.0, channel=None, lqi=None, ftype=2, seq=seq)


class PollStarvationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([{"name": "Porch Sensor", "extendedAddress": SENSOR}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _events(pipe, name):
        return [r for r in pipe.events.records if r["event"] == name]

    def _answered_polls(self, pipe, t, n, seq0=0):
        for i in range(n):
            pipe.ingest(poll(t + 5 * i, SENSOR, (seq0 + i) & 0xFF))
            pipe.ingest(ack(t + 5 * i + 0.001, (seq0 + i) & 0xFF))
        return t + 5 * n

    def test_unanswered_polls_after_answered_ones_are_starvation_then_recovery(self):
        pipe = Pipeline(self.cfg, NullEventLog())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        for i in range(12):                                # 12 distinct polls, nobody answers
            pipe.ingest(poll(t + 10 * i, SENSOR, 100 + i))
            pipe.ingest(poll(t + 10 * i + 0.3, SENSOR, 100 + i))   # a MAC retry: same seq, counts once
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual((ev["severity"], ev["name"], ev["acked_polls"]), ("warning", "Porch Sensor", 5))
        self.assertEqual(ev["unanswered_polls"], 10)      # fired at the tenth, not later
        self.assertGreaterEqual(ev["starved_for_s"], 60)
        self.assertIn("no device_quiet will follow", ev["note"])
        pipe.ingest(poll(t + 200, SENSOR, 200))
        pipe.ingest(ack(t + 200.001, 200))
        rec = self._events(pipe, "poll_answered")
        self.assertEqual(len(rec), 1)
        self.assertFalse(pipe.devices[SENSOR].starved)
        self.assertEqual(pipe.devices[SENSOR].unanswered_polls, 0)
        self.assertEqual(pipe.devices[SENSOR].acked_polls, 6)

    def test_starvation_survives_a_restart_and_is_closed_by_the_first_answered_poll(self):
        pipe = Pipeline(self.cfg, NullEventLog())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        for i in range(12):
            pipe.ingest(poll(t + 10 * i, SENSOR, 100 + i))
        self.assertEqual(len(self._events(pipe, "poll_starvation")), 1)
        self.assertTrue(pipe.seen.table[SENSOR]["starved"])
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog())          # DeviceStats start empty
        pipe2.ingest(poll(t + 300, SENSOR, 200))
        pipe2.ingest(poll(t + 310, SENSOR, 201))            # still unanswered: no second announcement
        self.assertEqual(self._events(pipe2, "poll_starvation"), [])
        pipe2.ingest(poll(t + 320, SENSOR, 202))
        pipe2.ingest(ack(t + 320.001, 202))
        rec = self._events(pipe2, "poll_answered")
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0]["name"], "Porch Sensor")
        self.assertNotIn("starved", pipe2.seen.table[SENSOR])
        pipe2.ingest(poll(t + 330, SENSOR, 203))
        pipe2.ingest(ack(t + 330.001, 203))
        self.assertEqual(len(self._events(pipe2, "poll_answered")), 1)   # once

    def test_starvation_that_begins_right_after_a_restart_is_announced(self):
        pipe = Pipeline(self.cfg, NullEventLog())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        self.assertTrue(pipe.seen.table[SENSOR]["polls_acked"])
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog())          # acked_polls is zero again
        for i in range(12):
            pipe2.ingest(poll(t + 10 * i, SENSOR, 100 + i))
        evs = self._events(pipe2, "poll_starvation")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["acked_polls"], 0)
        self.assertIn("before the recorder's last restart", evs[0]["note"])

    def test_a_device_never_answered_is_not_starving(self):
        # The sniffer may simply not hear that parent's ACKs.
        pipe = Pipeline(self.cfg, NullEventLog())
        t = 1_700_000_000.0
        for i in range(40):
            pipe.ingest(poll(t + 10 * i, SENSOR, i))
        self.assertEqual(self._events(pipe, "poll_starvation"), [])

    def test_ten_quick_polls_are_not_enough_without_the_minute(self):
        pipe = Pipeline(self.cfg, NullEventLog())
        t = self._answered_polls(pipe, 1_700_000_000.0, 3)
        for i in range(11):
            pipe.ingest(poll(t + 0.5 * i, SENSOR, 50 + i))   # 11 polls in 5 s: fast-poll burst
        self.assertEqual(self._events(pipe, "poll_starvation"), [])
        pipe.ingest(poll(t + 90, SENSOR, 70))                # ...and one more, past the minute
        self.assertEqual(len(self._events(pipe, "poll_starvation")), 1)

    def _starve(self, pipe, t, seq0):
        for i in range(12):
            pipe.ingest(poll(t + 10 * i, SENSOR, (seq0 + i) & 0xFF))
        return t + 120

    def test_a_second_episode_soon_after_the_first_ended_is_a_notice_until_the_rearm_passes(self):
        # 2026-09-04: 37 episodes in six hours from one sensor, each closed
        # by an ordinary ACK. One page, then notices while it flaps.
        pipe = Pipeline(self.cfg, NullEventLog())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._starve(pipe, t, 100)
        t = self._answered_polls(pipe, t, 3, seq0=120)        # episode 1 closes
        t = self._starve(pipe, t + 300, 130)                  # 5 min later: episode 2
        t = self._answered_polls(pipe, t, 3, seq0=150)
        t = self._starve(pipe, t + 600, 160)                  # 10 min later: episode 3
        t = self._answered_polls(pipe, t, 3, seq0=180)
        t = self._starve(pipe, t + 4000, 190)                 # over an hour answered: pages again
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual([e["severity"] for e in evs], ["warning", "notice", "notice", "warning"])
        self.assertEqual([e["episode"] for e in evs], [1, 2, 3, 1])
        self.assertIsNone(evs[0]["since_previous_s"])
        self.assertAlmostEqual(evs[1]["since_previous_s"], 300 + 10, delta=15)
        self.assertIn("Episode 2 since the last page", evs[1]["note"])
        self.assertIn("logged, not paged", evs[1]["note"])
        self.assertNotIn("Episode", evs[3]["note"])
        self.assertEqual(len(self._events(pipe, "poll_answered")), 3)   # every close still logged

    def test_rearm_zero_pages_every_episode(self):
        self.cfg.poll_rearm_s = 0
        pipe = Pipeline(self.cfg, NullEventLog())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._starve(pipe, t, 100)
        t = self._answered_polls(pipe, t, 3, seq0=120)
        self._starve(pipe, t + 60, 130)
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual([e["severity"] for e in evs], ["warning", "warning"])

    def test_the_hold_down_survives_a_restart(self):
        pipe = Pipeline(self.cfg, NullEventLog())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._starve(pipe, t, 100)
        t = self._answered_polls(pipe, t, 3, seq0=120)
        self.assertIn("starve_closed", pipe.seen.table[SENSOR])
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog())
        t = self._answered_polls(pipe2, t + 60, 2, seq0=125)  # answered polls this run, then starved
        self._starve(pipe2, t, 130)
        evs = self._events(pipe2, "poll_starvation")
        self.assertEqual([e["severity"] for e in evs], ["notice"])
        self.assertEqual(evs[0]["episode"], 2)

    def test_a_marginal_device_starving_is_a_notice(self):
        pipe = Pipeline(self.cfg, NullEventLog())
        t = 1_700_000_000.0
        for i in range(5):
            f = poll(t + 5 * i, SENSOR, i)
            f.rssi = -90.0
            pipe.ingest(f)
            pipe.ingest(ack(t + 5 * i + 0.001, i))
        t += 25
        for i in range(12):
            f = poll(t + 10 * i, SENSOR, 100 + i)
            f.rssi = -90.0
            pipe.ingest(f)
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual(len(evs), 1)
        self.assertEqual((evs[0]["severity"], evs[0]["reception"], evs[0]["episode"]), ("notice", "marginal", 1))
        self.assertIn("edge of its range", evs[0]["note"])


class LinkDegradationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Hall Router", "extendedAddress": ROUTER, "role": "router"}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json",
                          link_drop_db=8.0, link_hold_s=30 * 60)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _events(pipe, name):
        return [r for r in pipe.events.records if r["event"] == name]

    def _talk(self, pipe, t0, rssi, n=300):
        for i in range(n):
            pipe.ingest(frame(t0 + i, ROUTER, rssi=rssi))
        return t0 + n

    def test_fading_device_is_logged_then_recovers(self):
        pipe = Pipeline(self.cfg, NullEventLog())
        t = self._talk(pipe, 1_700_000_000.0, -60.0)
        pipe.periodic(t)                                     # reference taken at -60
        self.assertEqual(pipe.seen.table[ROUTER]["rssi_ref"], -60.0)
        t = self._talk(pipe, t, -70.0)
        pipe.periodic(t)                                     # clock starts
        pipe.periodic(t + 20 * 60)
        self.assertEqual(self._events(pipe, "rssi_degradation"), [])
        pipe.periodic(t + 31 * 60)
        evs = self._events(pipe, "rssi_degradation")
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual((ev["severity"], ev["name"], ev["reference_dbm"]), ("notice", "Hall Router", -60.0))
        self.assertGreaterEqual(ev["drop_db"], 9.0)   # the per-frame EWMA rounds to 0.1 dB and settles ~1 dB short
        self.assertGreaterEqual(ev["low_for_s"], 31 * 60)
        self.assertIn("weaker than its usual -60 dBm", ev["note"])
        pipe.periodic(t + 60 * 60)                           # still down: no repeat
        self.assertEqual(len(self._events(pipe, "rssi_degradation")), 1)
        t = self._talk(pipe, t + 60 * 60, -60.0)
        pipe.periodic(t)
        rec = self._events(pipe, "rssi_recovered")
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0]["severity"], "info")
        self.assertNotIn("rssi_degraded", pipe.seen.table[ROUTER])

    def test_daily_refresh_of_a_lasting_drop_closes_it_as_recovered(self):
        pipe = Pipeline(self.cfg, NullEventLog())
        t = self._talk(pipe, 1_700_000_000.0, -60.0)
        pipe.periodic(t)
        t = self._talk(pipe, t, -70.0)
        pipe.periodic(t)
        pipe.periodic(t + 31 * 60)
        self.assertEqual(len(self._events(pipe, "rssi_degradation")), 1)
        pipe.periodic(t + 86400 + 1)                         # a day into the drop: re-based
        rec = self._events(pipe, "rssi_recovered")
        self.assertEqual(len(rec), 1)
        self.assertIn("reference re-based", rec[0]["note"])
        self.assertEqual(rec[0]["reference_dbm"], pipe.seen.table[ROUTER]["rssi_ref"])
        self.assertNotIn("rssi_degraded", pipe.seen.table[ROUTER])

    def test_link_state_survives_a_restart(self):
        pipe = Pipeline(self.cfg, NullEventLog())
        t = self._talk(pipe, 1_700_000_000.0, -60.0)
        pipe.periodic(t)
        t = self._talk(pipe, t, -70.0)
        pipe.periodic(t)
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog())
        row = pipe2.seen.table[ROUTER]
        self.assertEqual(row["rssi_ref"], -60.0)
        self.assertEqual(row["rssi_low_since"], t)
        pipe2.periodic(t + 31 * 60)
        self.assertEqual(len(self._events(pipe2, "rssi_degradation")), 1)

    def test_foreign_pan_devices_are_not_assessed(self):
        pipe = Pipeline(self.cfg, NullEventLog())
        t0 = 1_700_000_000.0
        for i in range(300):
            pipe.ingest(frame(t0 + i, ROUTER, rssi=-60.0))
            pipe.ingest(frame(t0 + i, STRANGER, pan=OTHER_PAN, rssi=-60.0))
        pipe.periodic(t0 + 300)
        self.assertIn("rssi_ref", pipe.seen.table[ROUTER])
        self.assertNotIn("rssi_ref", pipe.seen.table[STRANGER])


class DailySummaryTest(unittest.TestCase):
    DAY = time.mktime(time.strptime("2026-09-02 00:00", "%Y-%m-%d %H:%M"))

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Hall Router", "extendedAddress": ROUTER, "role": "router"}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json",
                          summary_hour=8, quiet_router_s=30 * 60)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _summaries(log):
        return [r for r in log.records if r["event"] == "daily_summary"]

    def test_once_per_day_at_the_hour_with_the_days_facts(self):
        pipe = Pipeline(self.cfg, NullEventLog())
        t = self.DAY + 7 * 3600
        for i in range(100):
            pipe.ingest(frame(t + i, ROUTER, rssi=-60.0))
            pipe.ingest(frame(t + i, SENSOR, rssi=-88.0))
            pipe.ingest(frame(t + i, STRANGER, pan=OTHER_PAN))
        pipe.periodic(self.DAY + 7 * 3600 + 200)            # 07:03
        self.assertEqual(self._summaries(pipe.events), [])
        pipe.periodic(self.DAY + 8 * 3600)                  # 08:00: both silent 57 min, past the 30 min window
        s = self._summaries(pipe.events)
        self.assertEqual(len(s), 1)
        s = s[0]
        self.assertEqual(s["severity"], "notice")
        self.assertEqual((s["frames_24h"], s["devices_heard_24h"], s["devices_tracked"]), (300, 2, 2))
        self.assertEqual(s["quiet"], [SENSOR, "Hall Router"])
        self.assertEqual(s["unknown"], [SENSOR])
        self.assertEqual(s["marginal"], [SENSOR])
        self.assertEqual((s["events_24h"]["warning"], s["events_24h"]["notice"]), (1, 2))   # router quiet; sensor marginal quiet, foreign PAN
        self.assertIn(f"300 frames from 2 of 2 devices; quiet: {SENSOR}, Hall Router;", s["note"])
        self.assertIn("1 unknown address; 1 heard marginally; events: 1 warning, 2 notice", s["note"])
        pipe.periodic(self.DAY + 9 * 3600)                  # later the same day: no repeat
        pipe.periodic(self.DAY + 23 * 3600)
        self.assertEqual(len(self._summaries(pipe.events)), 1)
        pipe.periodic(self.DAY + 24 * 3600 + 8 * 3600)      # next day 08:00
        self.assertEqual(len(self._summaries(pipe.events)), 2)

    def test_restart_neither_repeats_nor_loses_a_summary(self):
        from threadwatch.events import EventLog
        log = EventLog(self.cfg.events_dir)
        pipe = Pipeline(self.cfg, log)
        pipe.periodic(self.DAY + 8 * 3600)
        pipe2 = Pipeline(self.cfg, EventLog(self.cfg.events_dir))
        pipe2.periodic(self.DAY + 8 * 3600 + 900)
        from threadwatch.events import read_day
        self.assertEqual(sum(r["event"] == "daily_summary" for r in read_day(self.cfg.events_dir, "2026-09-02")), 1)
        # Down through the hour: sent late, once.
        pipe3 = Pipeline(self.cfg, EventLog(self.cfg.events_dir))
        pipe3.periodic(self.DAY + 24 * 3600 + 15 * 3600)
        self.assertEqual(sum(r["event"] == "daily_summary" for r in read_day(self.cfg.events_dir, "2026-09-03")), 1)

    def test_frame_count_survives_a_restart(self):
        pipe = Pipeline(self.cfg, NullEventLog())
        t = self.DAY + 7 * 3600
        for i in range(100):
            pipe.ingest(frame(t + i, ROUTER, rssi=-60.0))
        pipe.periodic(t + 200)                              # persists the hourly buckets
        pipe2 = Pipeline(self.cfg, NullEventLog())          # a restart
        for i in range(10):
            pipe2.ingest(frame(t + 300 + i, ROUTER, rssi=-60.0))
        pipe2.periodic(self.DAY + 8 * 3600)
        s = self._summaries(pipe2.events)
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0]["frames_24h"], 110)           # both runs, not just this one
        # Buckets older than the window are dropped on load and never counted.
        pipe2._frames_by_hour[int(t // 3600) - 30] = 999
        pipe2.periodic(self.DAY + 8 * 3600 + 60)
        pipe3 = Pipeline(self.cfg, NullEventLog())
        self.assertNotIn(int(t // 3600) - 30, pipe3._frames_by_hour)
        self.assertEqual(pipe3.summary(self.DAY + 8 * 3600 + 120)["frames_24h"], 110)
        self.assertEqual(Pipeline(self.cfg, NullEventLog(), ephemeral=True)._frames_by_hour, {})

    def test_a_summary_whose_write_failed_is_retried_next_tick(self):
        class FlakyLog(NullEventLog):
            failures = 1

            def emit(self, event, *a, **kw):
                if event == "daily_summary" and self.failures:
                    self.failures -= 1
                    raise OSError(28, "No space left on device")
                return super().emit(event, *a, **kw)

        pipe = Pipeline(self.cfg, FlakyLog())
        with self.assertRaises(OSError):
            pipe.periodic(self.DAY + 8 * 3600)
        self.assertEqual(self._summaries(pipe.events), [])
        pipe.periodic(self.DAY + 8 * 3600 + 60)             # the next tick sends it
        self.assertEqual(len(self._summaries(pipe.events)), 1)
        pipe.periodic(self.DAY + 9 * 3600)                  # and only once
        self.assertEqual(len(self._summaries(pipe.events)), 1)

    def test_disabled_and_ephemeral(self):
        self.cfg.summary_hour = -1
        pipe = Pipeline(self.cfg, NullEventLog())
        pipe.periodic(self.DAY + 9 * 3600)
        self.assertEqual(self._summaries(pipe.events), [])
        self.cfg.summary_hour = 8
        replay = Pipeline(self.cfg, NullEventLog(), ephemeral=True)
        replay.periodic(self.DAY + 9 * 3600)
        self.assertEqual(self._summaries(replay.events), [])
