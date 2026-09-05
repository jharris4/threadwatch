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
from threadwatch.crypto import Decryptor  # noqa: E402


def test_decryptor():
    """A key, so the pipeline has one; test frames carry no payload, so it never decrypts."""
    return Decryptor(network_key=bytes(16))

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
                          quiet_s=30 * 60)

    def tearDown(self):
        self.tmp.cleanup()

    def _pipe(self):
        return Pipeline(self.cfg, NullEventLog(), test_decryptor())

    @staticmethod
    def _quiet(pipe):
        return [r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"]

    def test_one_quiet_window_for_every_device_whatever_the_inventory_says(self):
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(3):
            pipe.ingest(frame(t0 + i, ROUTER))
            pipe.ingest(frame(t0 + i + 60, SENSOR))
        pipe.periodic(t0 + 29 * 60)
        self.assertEqual(self._quiet(pipe), [])
        pipe.periodic(t0 + 31 * 60)
        self.assertEqual(self._quiet(pipe), [ROUTER])          # the inventory's "leader" label buys nothing
        pipe.periodic(t0 + 32 * 60)
        self.assertEqual(self._quiet(pipe), [ROUTER, SENSOR])
        names = [r["name"] for r in pipe.events.records if r["event"] == "device_quiet"]
        self.assertEqual(names, ["Living Room Apple TV", "Living Room AQ"])
        self.assertNotIn("profile", pipe.events.records[-1])

    def test_legacy_quiet_keys_still_load(self):
        from threadwatch import config as config_mod
        d = Path(self.tmp.name)
        (d / "config.toml").write_text("[quiet]\nend_device_s = 5400\nrouter_s = 1800\n")
        self.assertEqual(config_mod.load(d / "config.toml").quiet_s, 5400)
        (d / "config.toml").write_text("[quiet]\nsilence_s = 600\n")
        self.assertEqual(config_mod.load(d / "config.toml").quiet_s, 600)

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

    def test_report_carries_reception(self):
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        pipe.ingest(frame(t0, ROUTER, rssi=-88.0))
        pipe.ingest(frame(t0, STRANGER, rssi=-60.0))
        rep = pipe.seen.report(pipe.names, quiet_after_s=60, now=t0 + 120, min_rssi_dbm=-82)
        rows = {r["addr"]: r for r in rep["quiet"]}
        self.assertEqual(rows[ROUTER]["reception"], "marginal")
        self.assertEqual(rows[STRANGER]["reception"], "good")
        self.assertNotIn("role", rows[ROUTER])
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

    def test_a_mesh_whose_normal_rate_is_high_is_not_warned_about_every_15_min(self):
        """A busy install sits above 20% retransmissions all day. That is its
        baseline, not an elevation: only a rate that doubles it is news."""
        pipe = self._pipe()
        t = 1_700_000_000.0

        def send(ts, seq):
            pipe.ingest(Frame(ts=ts, raw=b"", psdu=b"", rssi=-60.0, channel=None, lqi=None,
                              ftype=1, seq=seq, dst_pan=OWN_PAN, dst="0000",
                              src_pan=OWN_PAN, src=STRANGER))

        def window(w, dup_frac):
            """One minute of 200 frames, dup_frac of them repeats of the frame
            before them (within the 2 s the duplicate window allows)."""
            n = 200
            dups = round(n * dup_frac)
            uniq = n - dups
            base, gap = t + w * 60, 50.0 / uniq
            for j in range(uniq):
                at = base + j * gap
                send(at, j)
                for r in range((dups * (j + 1)) // uniq - (dups * j) // uniq):
                    send(at + 0.1 * (r + 1), j)

        for w in range(21):                      # 20 closed windows at ~30%
            window(w, 0.3)
        self.assertEqual(len(pipe.retrans_counts), 20)
        self.assertGreater(min(pipe.retrans_counts), 0.2)      # every one is over the flat threshold
        self.assertEqual([r for r in pipe.events.records if r["event"] == "retransmission_elevation"], [])

        window(21, 0.8)                          # and then it really does double
        window(22, 0.3)                          # (closes the spike's window)
        ev = [r for r in pipe.events.records if r["event"] == "retransmission_elevation"]
        self.assertEqual(len(ev), 1)
        self.assertGreater(ev[0]["rate"], 2 * ev[0]["baseline"])

    def test_foreign_pan_devices_are_never_reported_quiet(self):
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(10):
            pipe.ingest(frame(t0 + i, SENSOR))
        for i in range(3):
            pipe.ingest(frame(t0 + i, STRANGER, pan=OTHER_PAN))
        pipe.periodic(t0 + 24 * 3600)
        self.assertEqual(self._quiet(pipe), [SENSOR])
        self.assertEqual(pipe.seen.table[STRANGER]["pan"], OTHER_PAN)

    def test_a_device_calling_out_to_every_pan_stays_ours_and_stays_judged(self):
        # A device that has lost its parent sends parent requests and
        # announces to the broadcast PAN 0xffff. That is not a network it
        # moved to: its row keeps the mesh PAN, its silence still counts,
        # and 0xffff is never reported as a foreign PAN.
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(10):
            pipe.ingest(frame(t0 + i, ROUTER))
            pipe.ingest(frame(t0 + i, SENSOR))
        for i in range(3):
            pipe.ingest(frame(t0 + 20 + i, SENSOR, pan=0xffff))
        pipe.periodic(t0 + 3 * 3600)
        self.assertEqual(pipe.seen.table[SENSOR]["pan"], OWN_PAN)
        self.assertEqual(sorted(self._quiet(pipe)), sorted([ROUTER, SENSOR]))
        self.assertEqual(self._foreign(pipe), [])
        self.assertEqual(pipe.dominant_pan(), OWN_PAN)
        # A row a pre-fix recorder stamped 0xffff is not a foreign device either.
        pipe.seen.table[SENSOR]["pan"] = 0xffff
        pipe.seen.save()
        pipe2 = self._pipe()
        self.assertNotIn("pan", pipe2.seen.table[SENSOR])
        self.assertEqual(pipe2.dominant_pan(), OWN_PAN)

    @staticmethod
    def _foreign(pipe):
        return [(r["pan"], r["dominant_pan"], r["src"]) for r in pipe.events.records
                if r["event"] == "possible_foreign_pan"]

    def test_our_own_pan_is_never_the_foreign_one(self):
        # Start during a lull: a neighbour's mesh lands three frames first.
        # When ours reaches three the tie must flag nobody; once ours leads,
        # the neighbour's PAN is the one reported, exactly once.
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(3):
            pipe.ingest(frame(t0 + i, STRANGER, pan=OTHER_PAN))
        for i in range(400):
            pipe.ingest(frame(t0 + 10 + i, ROUTER))
        for i in range(50):
            pipe.ingest(frame(t0 + 500 + i, STRANGER, pan=OTHER_PAN))
        self.assertEqual(self._foreign(pipe), [(f"0x{OTHER_PAN:04x}", f"0x{OWN_PAN:04x}", STRANGER)])
        self.assertEqual(pipe.dominant_pan(), OWN_PAN)

    def test_a_foreign_pan_is_reported_at_its_third_sighting(self):
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(10):
            pipe.ingest(frame(t0 + i, ROUTER))
        for i in range(5):
            pipe.ingest(frame(t0 + 20 + i, STRANGER, pan=OTHER_PAN))
            if i < 2:
                self.assertEqual(self._foreign(pipe), [])
        self.assertEqual(self._foreign(pipe), [(f"0x{OTHER_PAN:04x}", f"0x{OWN_PAN:04x}", STRANGER)])

    def test_a_weeks_history_outweighs_a_neighbour_talking_first_after_a_restart(self):
        pipe = self._pipe()
        t0 = time.time() - 60
        for i in range(100):
            pipe.ingest(frame(t0 + i * 0.1, ROUTER))
        pipe.seen.save()
        pipe2 = self._pipe()                                   # a restart into a lull
        self.assertEqual(pipe2.dominant_pan(), OWN_PAN)        # known before any frame
        for i in range(3):
            pipe2.ingest(frame(t0 + 30 + i, STRANGER, pan=OTHER_PAN))
        self.assertEqual(self._foreign(pipe2), [(f"0x{OTHER_PAN:04x}", f"0x{OWN_PAN:04x}", STRANGER)])
        for i in range(400):
            pipe2.ingest(frame(t0 + 40 + i * 0.05, ROUTER))
        self.assertEqual(len(self._foreign(pipe2)), 1)         # ours never flagged, theirs not repeated

    @staticmethod
    def _adopted(pipe):
        return [(r["severity"], r["previous"], r["pan"]) for r in pipe.events.records
                if r["event"] == "dominant_pan_changed"]

    def test_a_configured_pan_is_ours_however_much_a_neighbour_talks(self):
        # A larger mesh on the same channel out-talks ours: with pan_id set
        # the guess is never consulted, our silences are still judged, the
        # neighbour's never are, and its PAN is the foreign one.
        self.cfg.pan_id = OWN_PAN
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(400):
            pipe.ingest(frame(t0 + i, STRANGER, pan=OTHER_PAN))
        for i in range(2):
            pipe.ingest(frame(t0 + i, ROUTER))
        self.assertEqual(pipe.dominant_pan(), OWN_PAN)
        self.assertEqual(self._foreign(pipe), [(f"0x{OTHER_PAN:04x}", f"0x{OWN_PAN:04x}", STRANGER)])
        pipe.periodic(t0 + 3 * 3600)
        self.assertEqual(self._quiet(pipe), [ROUTER])
        self.assertEqual(self._adopted(pipe), [])
        pipe.seen.save()
        self.assertEqual(self._pipe().dominant_pan(), OWN_PAN)   # and not the table's busiest

    def test_the_guessed_pan_needs_a_floor_and_a_margin_and_every_change_is_an_event(self):
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(9):
            pipe.ingest(frame(t0 + i, ROUTER))
        self.assertIsNone(pipe.dominant_pan())                   # too few frames to call anything ours
        pipe.ingest(frame(t0 + 9, ROUTER))
        self.assertEqual(pipe.dominant_pan(), OWN_PAN)
        self.assertEqual(self._adopted(pipe), [("notice", None, f"0x{OWN_PAN:04x}")])
        for i in range(19):                                      # the neighbour pulls ahead, but not by enough
            pipe.ingest(frame(t0 + 20 + i, STRANGER, pan=OTHER_PAN))
        self.assertEqual(pipe.dominant_pan(), OWN_PAN)
        pipe.ingest(frame(t0 + 40, STRANGER, pan=OTHER_PAN))     # twice ours: it takes over, and says so
        self.assertEqual(pipe.dominant_pan(), OTHER_PAN)
        self.assertEqual(self._adopted(pipe)[1], ("warning", f"0x{OWN_PAN:04x}", f"0x{OTHER_PAN:04x}"))
        changed = [r for r in pipe.events.records if r["event"] == "dominant_pan_changed"]
        self.assertIn("set [network] pan_id", changed[-1]["note"])
        self.assertEqual(self._foreign(pipe), [(f"0x{OTHER_PAN:04x}", f"0x{OWN_PAN:04x}", STRANGER),   # theirs while ours led...
                                               (f"0x{OWN_PAN:04x}", f"0x{OTHER_PAN:04x}", ROUTER)])   # ...then ours, by that guess
        for i in range(29):                                      # ours back in the lead, 39 to 20, under double: no flap
            pipe.ingest(frame(t0 + 50 + i, ROUTER))
        self.assertEqual(pipe.dominant_pan(), OTHER_PAN)
        self.assertEqual(len(self._adopted(pipe)), 2)

    def test_restart_announces_a_silence_nobody_reported(self):
        # The recorder heard the mesh right up to a restart (a deploy, a
        # crash) that came between the router crossing its window and the
        # periodic tick that would have said so.
        now = time.time()
        pipe = self._pipe()
        pipe.ingest(frame(now - 40 * 60, ROUTER))   # past the window, never announced
        pipe.ingest(frame(now - 20 * 60, SENSOR))   # inside the window: still eligible
        pipe.seen.save()
        self._status(updated=now, last_frame_ts=now)
        pipe2 = self._pipe()
        self.assertEqual(self._quiet(pipe2), [ROUTER])
        self.assertEqual(pipe2.quiet_reported, {ROUTER})
        pipe2.periodic(now + 60 * 60)
        self.assertEqual(self._quiet(pipe2), [ROUTER, SENSOR])
        # A third start re-announces nothing: both silences are on record.
        self.assertEqual(self._quiet(self._pipe()), [])

    def _status(self, **fields):
        (self.cfg.state_dir / "status.json").write_text(json.dumps(fields))

    def test_recorder_downtime_is_not_counted_as_device_silence(self):
        now = time.time()
        pipe = self._pipe()
        pipe.ingest(frame(now - 40 * 60, ROUTER))
        pipe.seen.save()
        # The recorder last heard anything 38 min ago (rebooted 2 min after that frame).
        self._status(updated=now - 38 * 60, last_frame_ts=now - 38 * 60)
        pipe2 = self._pipe()
        self.assertEqual(self._quiet(pipe2), [])          # only 2 min of witnessed silence
        pipe2.periodic(now + 60)
        self.assertEqual(self._quiet(pipe2), [])
        pipe2.periodic(now + 29 * 60)                     # 2 + 29 min > the 30 min window
        self.assertEqual(self._quiet(pipe2), [ROUTER])
        rec = [r for r in pipe2.events.records if r["event"] == "device_quiet"][0]
        self.assertAlmostEqual(rec["silent_for_s"], 31 * 60, delta=5)

    def test_a_restart_loop_that_hears_nothing_does_not_announce_every_device(self):
        # The mesh (or the dongle) died two hours ago. Since then the
        # watchdog has restarted the recorder every three minutes, and every
        # run wrote status.json and saved last-seen.json before leaving: file
        # times say "heard something a minute ago"; the stamps say otherwise.
        now = time.time()
        pipe = self._pipe()
        pipe.ingest(frame(now - 2 * 3600 - 5 * 60, ROUTER))
        pipe.ingest(frame(now - 2 * 3600 - 5 * 60, SENSOR))
        pipe.seen.save()                                    # mtime: now
        self._status(updated=now - 60, last_frame_age_s=170, last_frame_ts=now - 2 * 3600)
        pipe2 = self._pipe()
        self.assertEqual(self._quiet(pipe2), [])           # five minutes of witnessed silence
        pipe2.periodic(now + 20 * 60)
        self.assertEqual(self._quiet(pipe2), [])           # frames are back: 25 min so far
        pipe2.periodic(now + 26 * 60)
        self.assertEqual(sorted(self._quiet(pipe2)), sorted([ROUTER, SENSOR]))
        rec = [r for r in pipe2.events.records if r["event"] == "device_quiet"][0]
        self.assertAlmostEqual(rec["silent_for_s"], 31 * 60, delta=5)
        # A status file from before the stamp existed: the table's newest
        # last_seen stands in, and the same restart loop still pages nobody.
        pipe2.seen.save()
        self._status(updated=now - 60, last_frame_age_s=170)
        self.assertEqual(self._quiet(self._pipe()), [])

    def test_restart_does_not_repeat_an_announced_silence_or_a_foreign_one(self):
        now = time.time()
        pipe = self._pipe()
        for i in range(10):
            pipe.ingest(frame(now - 3 * 3600 + i, SENSOR))
        pipe.ingest(frame(now - 3 * 3600, STRANGER, pan=OTHER_PAN))
        pipe.periodic(now - 60 * 60)                # announces the sensor, skips the foreign device
        self.assertEqual(self._quiet(pipe), [SENSOR])
        pipe.seen.save()
        self._status(updated=now, last_frame_ts=now)   # other devices were heard until the restart
        pipe2 = self._pipe()
        self.assertEqual(self._quiet(pipe2), [])
        self.assertEqual(pipe2.quiet_reported, {SENSOR})
        pipe2.ingest(frame(now, SENSOR))
        self.assertEqual([r["event"] for r in pipe2.events.records], ["device_returned"])
        self.assertNotIn("quiet_reported", pipe2.seen.table[SENSOR])

    def test_an_announced_silence_survives_a_crash_before_the_next_save(self):
        # The flag is what stops a restart announcing the same silence twice,
        # so it is persisted with the event, not left for the 30 s save the
        # outage may arrive before. A return already persisted at once.
        now = time.time()
        pipe = self._pipe()
        for i in range(10):
            pipe.ingest(frame(now - 3 * 3600 + i, SENSOR))
        pipe.periodic(now - 60 * 60)
        self.assertEqual(self._quiet(pipe), [SENSOR])
        self.assertTrue(json.loads(pipe.seen.state_path.read_text())[SENSOR]["quiet_reported"])
        self._status(updated=now, last_frame_ts=now)
        pipe2 = self._pipe()                      # no seen.save() in between
        self.assertEqual(self._quiet(pipe2), [])  # not announced a second time
        self.assertEqual(pipe2.quiet_reported, {SENSOR})

    def test_replay_neither_reads_nor_writes_live_state(self):
        now = time.time()
        live = self._pipe()
        live.ingest(frame(now - 2 * 3600, ROUTER))
        live.seen.save()
        before = (self.cfg.state_dir / "last-seen.json").read_text()
        replay = Pipeline(self.cfg, NullEventLog(), test_decryptor(), ephemeral=True)
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
        self.assertEqual(Pipeline(self.cfg, NullEventLog(), test_decryptor(), ephemeral=True)._last_auto_freeze, 0.0)

    def test_a_failed_freeze_is_retried_after_a_hold_not_six_hours(self):
        from threadwatch import freeze as freeze_mod
        self.cfg.freeze_on_critical = True
        pipe = self._pipe()
        attempts = []

        def flaky(cfg, label):
            attempts.append(label)
            if len(attempts) == 1:
                raise OSError(28, "No space left on device")
            return cfg.incidents_dir / f"20231114T221500_{label}", 3

        original = freeze_mod.freeze_ring
        freeze_mod.freeze_ring = flaky
        try:
            pipe.freezer = pipe._freeze_now                # in this thread, so each outcome is known at once
            pipe.detector.storm_active = True
            pipe.detector.last_alert_details = {"period": 80.5, "onsets": [1.0, 2.0, 3.0]}
            pipe.detector.add_frame = lambda ts: setattr(pipe.detector, "storm_active", True)
            t0 = 1_700_000_000.0
            for dt in (0, 31 * 60, 2 * 3600):             # the storm event repeats every 30 min at most
                pipe.ingest(frame(t0 + dt, ROUTER))
        finally:
            freeze_mod.freeze_ring = original
        storms = [r["auto_freeze"] for r in pipe.events.records if r["event"] == "phase_locked_storm"]
        self.assertEqual(storms, ["auto-storm", "auto-storm", None])   # failed; retried; then the real cooldown
        self.assertEqual(attempts, ["auto-storm", "auto-storm"])
        failed = [r for r in pipe.events.records if r["event"] == "incident_freeze_failed"]
        self.assertEqual(len(failed), 1)
        self.assertIn("No space left", failed[0]["note"])
        self.assertIn("tries again", failed[0]["note"])
        self.assertEqual([r["ring_files"] for r in pipe.events.records if r["event"] == "incident_frozen"], [3])

    def test_freeze_off_by_default_and_never_in_replay(self):
        for ephemeral in (False, True):
            self.cfg.freeze_on_critical = ephemeral        # on only for the replay case
            pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor(), ephemeral=ephemeral)
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
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
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
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        for i in range(12):
            pipe.ingest(poll(t + 10 * i, SENSOR, 100 + i))
        self.assertEqual(len(self._events(pipe, "poll_starvation")), 1)
        self.assertTrue(pipe.seen.table[SENSOR]["starved"])
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog(), test_decryptor())          # DeviceStats start empty
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
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        self.assertTrue(pipe.seen.table[SENSOR]["polls_acked"])
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog(), test_decryptor())          # acked_polls is zero again
        for i in range(12):
            pipe2.ingest(poll(t + 10 * i, SENSOR, 100 + i))
        evs = self._events(pipe2, "poll_starvation")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["acked_polls"], 0)
        self.assertIn("before the recorder's last restart", evs[0]["note"])

    def test_a_broadcast_is_never_a_transmission_awaiting_an_ack(self):
        """MLE advertisements go out to ffff and are never acknowledged. If a
        broadcast left an ACK pending, the next ACK the sniffer hears - for
        somebody else's unicast, carrying the same sequence number - would be
        credited to the broadcaster, and its parent's real answers would be
        accounted to the wrong device."""
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        pipe.ingest(poll(t, SENSOR, 100))                  # unicast poll, still pending
        pipe.ingest(Frame(ts=t + 0.01, raw=b"", psdu=b"", rssi=-55.0, channel=None, lqi=None,
                          ftype=1, seq=100, dst_pan=OWN_PAN, dst="ffff",
                          src_pan=OWN_PAN, src=ROUTER))    # a router's advertisement, same seq
        pipe.ingest(ack(t + 0.02, 100))                    # the ACK the sniffer hears next
        self.assertEqual((pipe.devices[ROUTER].tx, pipe.devices[ROUTER].acked), (0, 0))
        self.assertEqual(pipe.devices[SENSOR].acked, 5)    # nothing new was credited to anyone

    def test_an_ack_a_second_late_is_not_this_polls_ack(self):
        """An ACK follows its frame in under a millisecond. Anything later is
        a different exchange, and pairing with it would keep a device whose
        parent has stopped answering looking healthy."""
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        for i in range(12):
            pipe.ingest(poll(t + 10 * i, SENSOR, 100 + i))
            pipe.ingest(ack(t + 10 * i + 1.0, 100 + i))    # a second later: not this poll's ACK
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual(len(evs), 1)
        self.assertEqual((evs[0]["unanswered_polls"], evs[0]["acked_polls"]), (10, 5))
        self.assertEqual(self._events(pipe, "poll_answered"), [])

    def test_a_device_never_answered_is_not_starving(self):
        # The sniffer may simply not hear that parent's ACKs.
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = 1_700_000_000.0
        for i in range(40):
            pipe.ingest(poll(t + 10 * i, SENSOR, i))
        self.assertEqual(self._events(pipe, "poll_starvation"), [])

    def test_ten_quick_polls_are_not_enough_without_the_minute(self):
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
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
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
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

    def test_the_parent_is_named_from_the_polls_destination(self):
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        (Path(self.tmp.name) / "devices.json").write_text(json.dumps([
            {"name": "Porch Sensor", "extendedAddress": SENSOR},
            {"name": "Hall Router", "extendedAddress": ROUTER}]))
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        self._starve(pipe, t, 100)                           # polls go to dst "0000": router 0
        ev = self._events(pipe, "poll_starvation")[0]
        self.assertEqual((ev["parent"], ev["parent_rloc16"], ev["parent_addr"]), ("router 0", "0000", None))
        self.assertIn("polled its parent router 0 (0000)", ev["note"])
        pipe.decryptor.short_to_ext["0000"] = ROUTER          # once the router's address is matched
        t = self._answered_polls(pipe, t, 3, seq0=120)
        self._starve(pipe, t + 4000, 130)
        ev = self._events(pipe, "poll_starvation")[-1]
        self.assertEqual((ev["parent"], ev["parent_addr"]), ("Hall Router", ROUTER))
        self.assertIn("polled its parent Hall Router (0000)", ev["note"])
        self.assertEqual(pipe.parent_of(SENSOR), None)        # the sensor has no RLOC16 on record yet
        pipe.seen.table[SENSOR]["rloc16"] = "0007"
        self.assertEqual(pipe.parent_of(SENSOR), {"router_id": 0, "rloc16": "0000", "addr": ROUTER, "name": "Hall Router"})

    def test_rearm_zero_pages_every_episode(self):
        self.cfg.poll_rearm_s = 0
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._starve(pipe, t, 100)
        t = self._answered_polls(pipe, t, 3, seq0=120)
        self._starve(pipe, t + 60, 130)
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual([e["severity"] for e in evs], ["warning", "warning"])

    def test_the_hold_down_survives_a_restart(self):
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._starve(pipe, t, 100)
        t = self._answered_polls(pipe, t, 3, seq0=120)
        self.assertIn("starve_closed", pipe.seen.table[SENSOR])
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = self._answered_polls(pipe2, t + 60, 2, seq0=125)  # answered polls this run, then starved
        self._starve(pipe2, t, 130)
        evs = self._events(pipe2, "poll_starvation")
        self.assertEqual([e["severity"] for e in evs], ["notice"])
        self.assertEqual(evs[0]["episode"], 2)

    def test_a_marginal_device_starving_is_a_notice(self):
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
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


class CredentialsTest(unittest.TestCase):
    """No key, no recorder; a rotated key is announced, not silently endured."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.cfg = Config(data_dir=self.d / "data", credentials_path=self.d / "credentials.toml")

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_or_malformed_key_file_refuses_to_load(self):
        from threadwatch.pipeline import CredentialsError, load_decryptor
        with self.assertRaises(CredentialsError) as cm:
            load_decryptor(self.cfg)
        self.assertIn("missing", str(cm.exception))
        self.assertIn("CREDENTIALS.md", str(cm.exception))
        (self.d / "credentials.toml").write_text('[credentials]\nnetwork_key = "tooshort"\n')
        with self.assertRaises(CredentialsError):
            load_decryptor(self.cfg)
        (self.d / "credentials.toml").write_text('[credentials]\nnetwork_key = "00112233445566778899aabbccddeeff"\n')
        self.assertEqual(load_decryptor(self.cfg).network_key, bytes.fromhex("00112233445566778899aabbccddeeff"))

    def test_a_key_that_stops_decrypting_is_reported_once_per_six_hours(self):
        dec = test_decryptor()
        pipe = Pipeline(self.cfg, NullEventLog(), dec)
        t = 1_700_000_000.0
        stale = lambda: [r for r in pipe.events.records if r["event"] == "credentials_stale"]
        dec.stats["mac_decrypted"] += 500                    # healthy: decrypting
        pipe.periodic(t)
        dec.stats["mac_failed"] += 150                       # a few failures alongside successes
        dec.stats["mle_decrypted"] += 20
        pipe.periodic(t + 30)
        self.assertEqual(stale(), [])
        dec.stats["mac_failed"] += 150                       # nothing decrypts any more...
        pipe.periodic(t + 60)
        self.assertEqual(stale(), [])                        # ...but not enough failures yet
        dec.stats["mle_failed"] += 100
        pipe.periodic(t + 90)
        self.assertEqual(len(stale()), 1)
        self.assertEqual(stale()[0]["failed"], 250)
        self.assertIn("no longer matches", stale()[0]["note"])
        dec.stats["mac_failed"] += 1000
        pipe.periodic(t + 3600)
        self.assertEqual(len(stale()), 1)                    # repeats no sooner than six hours
        pipe.periodic(t + 7 * 3600)
        self.assertEqual(len(stale()), 2)
        dec.stats["mac_decrypted"] += 1                      # the new key works again
        dec.stats["mac_failed"] += 1000
        pipe.periodic(t + 14 * 3600)
        self.assertEqual(len(stale()), 2)


class BorderRouterTest(unittest.TestCase):
    """An Apple hub reboots, takes a new Thread address, keeps its name."""

    OLD, NEW, OTBR = "c0ffee0000000001", "1234567890abcdef", "07b200000000af1b"
    HOST = "appletv-living-room.local"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Living Room Apple TV", "extendedAddress": self.OLD.upper()},
            {"name": "HA OTBR", "borderRouter": "HomeAssistant-OTBR.local."}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json", border_router_browse_s=0)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def router(host, ext, instance="AppleTV Living Room", vendor="Apple", model="BorderRouter"):
        return {"hostname": host, "ext": ext, "instance": instance, "vendor": vendor, "model": model}

    def test_rebooted_hub_keeps_its_name_and_the_old_address_retires(self):
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = time.time() - 3600                                  # real-clock times: the restart below judges silences by now
        pipe.ingest(frame(t, self.OLD))
        pipe.ingest(frame(t, self.OTBR))
        pipe._apply_border_routers([self.router(self.HOST, self.OLD),
                                    self.router("homeassistant-otbr.local", self.OTBR, "HA OTBR #AF1B", "Home Assistant")], t)
        self.assertEqual([r["event"] for r in pipe.events.records if r["event"].startswith("border_router")], [])
        self.assertEqual(pipe.routers[self.HOST]["name"], "Living Room Apple TV")          # bound by listed address
        self.assertEqual(pipe.routers["homeassistant-otbr.local"]["name"], "HA OTBR")      # bound by borderRouter
        self.assertEqual(pipe.names.name(self.OTBR), "HA OTBR")
        # Reboot: the browse sees the new address before the sniffer hears
        # it. The record waits, and the first frame from it binds the name.
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 500)
        self.assertEqual(pipe.routers[self.HOST]["addr"], self.OLD)                # not yet believed
        self.assertIsNone(pipe.names.name(self.NEW))
        pipe.ingest(frame(t + 600, self.NEW))
        first = [r for r in pipe.events.records if r["event"] == "device_first_seen" and r["addr"] == self.NEW]
        self.assertEqual(first[0]["name"], "Living Room Apple TV")
        self.assertEqual(pipe._pending_routers, {})
        ev = [r for r in pipe.events.records if r["event"] == "border_router_address_changed"]
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["addr"], ev[0]["previous"], ev[0]["name"]), (self.NEW, self.OLD, "Living Room Apple TV"))
        self.assertIn("nothing to edit", ev[0]["note"])
        self.assertEqual(pipe.names.name(self.NEW), "Living Room Apple TV")
        self.assertEqual(pipe.seen.table[self.OLD]["rotated_to"], self.NEW)
        self.assertEqual(pipe.routers[self.HOST]["previous"], [{"addr": self.OLD, "until": t + 600}])
        pipe.periodic(t + 3000)                            # 50 min on: the old address never reads as quiet
        self.assertNotIn(self.OLD, [r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"])
        pipe.ingest(frame(time.time() - 60, self.NEW))
        # The binding survives a restart, through the state file.
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        self.assertEqual(pipe2.names.name(self.NEW), "Living Room Apple TV")
        self.assertEqual(pipe2.names.border_routers[self.NEW]["hostname"], self.HOST)
        self.assertEqual(pipe2.names.resolve("living room apple tv")[0], [self.OLD, self.NEW])
        self.assertNotIn(self.OLD, [r["addr"] for r in pipe2.events.records if r["event"] == "device_quiet"])
        self.assertEqual(pipe2.routers[self.HOST]["addr"], self.NEW)

    def test_an_address_never_heard_on_air_is_not_believed(self):
        # Anyone on the LAN can advertise _meshcop._udp with any address in
        # it. A forged record must not retire the real row (silencing its
        # quiet alerts) or hand the name to the forged address.
        import contextlib
        import io
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = time.time() - 7200
        pipe.ingest(frame(t, self.OLD))
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        forged = "deadbeefdeadbeef"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            for tick in (60, 660):
                pipe._apply_border_routers([self.router(self.HOST, forged)], t + tick)
        self.assertEqual(out.getvalue().count("has not been heard on air"), 1)
        self.assertEqual(list(pipe._pending_routers), [forged])
        self.assertEqual(pipe.routers[self.HOST]["addr"], self.OLD)
        self.assertNotIn("rotated_to", pipe.seen.table[self.OLD])
        self.assertIsNone(pipe.names.name(forged))
        self.assertEqual([r["event"] for r in pipe.events.records if r["event"].startswith("border_router")], [])
        pipe.periodic(t + 31 * 60)                          # the real device's silence still counts
        self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"], [self.OLD])
        # A real reboot: the next browse gives the hostname its real new
        # address, which replaces the forged one waiting, and binds once heard.
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 40 * 60)
        self.assertEqual(list(pipe._pending_routers), [self.NEW])
        pipe.ingest(frame(t + 41 * 60, self.NEW))
        self.assertEqual((pipe.routers[self.HOST]["addr"], pipe.names.name(self.NEW)), (self.NEW, "Living Room Apple TV"))
        self.assertEqual(pipe.seen.table[self.OLD]["rotated_to"], self.NEW)

    def test_a_rotation_closes_the_silence_announced_for_the_old_address(self):
        from threadwatch.review import group_episodes
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = time.time() - 7200
        pipe.ingest(frame(t, self.OLD))
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        pipe.periodic(t + 31 * 60)                          # the hub rebooted: its old address went quiet
        self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"], [self.OLD])
        pipe.ingest(frame(t + 32 * 60, self.NEW))           # ...and it is back under a new one
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 40 * 60)
        back = [r for r in pipe.events.records if r["event"] == "device_returned"]
        self.assertEqual([(r["addr"], r["name"]) for r in back], [(self.OLD, "Living Room Apple TV")])
        self.assertIn(self.NEW, back[0]["note"])
        self.assertEqual(pipe.quiet_reported, set())
        self.assertNotIn("quiet_reported", pipe.seen.table[self.OLD])
        quiet = [e for e in group_episodes(pipe.events.records, now=t + 86400) if e["kind"] == "quiet"]
        self.assertEqual([(e["addr"], e["end"]) for e in quiet], [(self.OLD, t + 40 * 60)])
        self.assertNotIn("still quiet", quiet[0]["title"])
        pipe.periodic(t + 86400)                            # the retired address is never judged again
        about_old = [r["event"] for r in pipe.events.records if r.get("addr") == self.OLD]
        self.assertEqual(about_old, ["device_first_seen", "device_quiet", "device_returned"])

    def test_a_router_matching_no_entry_is_announced_once(self):
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = 1_700_000_000.0
        pipe.ingest(frame(t, "0011223344556677"))
        stranger = self.router("homepod-kitchen.local", "0011223344556677", "HomePod Kitchen")
        pipe._apply_border_routers([stranger], t)
        pipe._apply_border_routers([stranger], t + 600)
        ev = [r for r in pipe.events.records if r["event"] == "border_router_unlisted"]
        self.assertEqual(len(ev), 1)
        self.assertIn("homepod-kitchen.local", ev[0]["note"])
        self.assertIsNone(pipe.names.name("0011223344556677"))
        pipe.ingest(frame(t + 1100, "8899aabbccddeeff"))
        pipe._apply_border_routers([self.router("homepod-kitchen.local", "8899aabbccddeeff", "HomePod Kitchen")], t + 1200)
        ev = [r for r in pipe.events.records if r["event"] == "border_router_address_changed"]
        self.assertEqual((ev[0]["name"], ev[0]["previous"]), (None, "0011223344556677"))
        self.assertIn("Not in devices.json", ev[0]["note"])

    def test_browse_runs_in_a_thread_and_applies_on_the_next_tick(self):
        from threadwatch import mdns
        self.cfg.border_router_browse_s = 600
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        calls = []
        original = mdns.browse
        mdns.browse = lambda timeout=4.0, **kw: calls.append(timeout) or [self.router(self.HOST, self.OLD)]
        try:
            t = 1_700_000_000.0
            pipe.ingest(frame(t, self.OLD))
            pipe.periodic(t)                       # starts the browse
            pipe._browse_thread.join(5)
            self.assertEqual(pipe.routers, {})     # nothing applied until the next tick
            pipe.periodic(t + 30)                  # applies it
            self.assertEqual(calls, [4.0])
            self.assertEqual(pipe.routers[self.HOST]["name"], "Living Room Apple TV")
            pipe.periodic(t + 60)                  # not yet time for another
            self.assertIsNone(pipe._browse_thread)
            self.assertEqual(len(calls), 1)
            pipe.periodic(t + 601)
            pipe._browse_thread.join(5)
            self.assertEqual(len(calls), 2)
        finally:
            mdns.browse = original


class PartitionLeaderTest(unittest.TestCase):
    """'leader router 60' on the status page should name the device."""

    LEADER = "aabbccddeeff0011"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps(
            [{"name": "Living Room Apple TV", "extendedAddress": self.LEADER, "threadRole": "border-router-leader"}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_leader_is_named_once_its_rloc16_is_matched(self):
        from types import SimpleNamespace
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        self.assertIsNone(pipe.partition_status())
        pipe.partition = (976341733, 60)
        self.assertEqual(pipe.partition_status(),
                         {"id": 976341733, "leader_router": 60, "leader_rloc16": "f000",
                          "leader_addr": None, "leader_name": None})      # no credentials: unmatched
        self.assertEqual(pipe.leader_label(60), "r60")
        pipe.decryptor = SimpleNamespace(short_to_ext={"f000": self.LEADER})   # the leader's MLE advert
        self.assertEqual(pipe.partition_status()["leader_addr"], self.LEADER)
        self.assertEqual(pipe.partition_status()["leader_name"], "Living Room Apple TV")
        self.assertEqual(pipe.leader_label(60), "r60 (Living Room Apple TV)")
        self.assertEqual(pipe.leader_label(3), "r3")                          # 0x0c00: nobody matched


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
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
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
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
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
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = self._talk(pipe, 1_700_000_000.0, -60.0)
        pipe.periodic(t)
        t = self._talk(pipe, t, -70.0)
        pipe.periodic(t)
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        row = pipe2.seen.table[ROUTER]
        self.assertEqual(row["rssi_ref"], -60.0)
        self.assertEqual(row["rssi_low_since"], t)
        pipe2.periodic(t + 31 * 60)
        self.assertEqual(len(self._events(pipe2, "rssi_degradation")), 1)

    def test_foreign_pan_devices_are_not_assessed(self):
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
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
                          summary_hour=8, quiet_s=30 * 60)

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _summaries(log):
        return [r for r in log.records if r["event"] == "daily_summary"]

    def test_once_per_day_at_the_hour_with_the_days_facts(self):
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
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
        self.assertEqual((s["events_24h"]["warning"], s["events_24h"]["notice"]), (1, 3))   # router quiet; PAN adopted, sensor marginal quiet, foreign PAN
        self.assertIn(f"300 frames from 2 of 2 devices; quiet: {SENSOR}, Hall Router;", s["note"])
        self.assertIn("1 unknown address; 1 heard marginally; events: 1 warning, 3 notice", s["note"])
        pipe.periodic(self.DAY + 9 * 3600)                  # later the same day: no repeat
        pipe.periodic(self.DAY + 23 * 3600)
        self.assertEqual(len(self._summaries(pipe.events)), 1)
        pipe.periodic(self.DAY + 24 * 3600 + 8 * 3600)      # next day 08:00
        self.assertEqual(len(self._summaries(pipe.events)), 2)

    def test_restart_neither_repeats_nor_loses_a_summary(self):
        from threadwatch.events import EventLog
        log = EventLog(self.cfg.events_dir)
        pipe = Pipeline(self.cfg, log, test_decryptor())
        pipe.periodic(self.DAY + 8 * 3600)
        pipe2 = Pipeline(self.cfg, EventLog(self.cfg.events_dir), test_decryptor())
        pipe2.periodic(self.DAY + 8 * 3600 + 900)
        from threadwatch.events import read_day
        self.assertEqual(sum(r["event"] == "daily_summary" for r in read_day(self.cfg.events_dir, "2026-09-02")), 1)
        # Down through the hour: sent late, once.
        pipe3 = Pipeline(self.cfg, EventLog(self.cfg.events_dir), test_decryptor())
        pipe3.periodic(self.DAY + 24 * 3600 + 15 * 3600)
        self.assertEqual(sum(r["event"] == "daily_summary" for r in read_day(self.cfg.events_dir, "2026-09-03")), 1)

    def test_frame_count_survives_a_restart(self):
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        t = self.DAY + 7 * 3600
        for i in range(100):
            pipe.ingest(frame(t + i, ROUTER, rssi=-60.0))
        pipe.periodic(t + 200)                              # persists the hourly buckets
        pipe2 = Pipeline(self.cfg, NullEventLog(), test_decryptor())          # a restart
        for i in range(10):
            pipe2.ingest(frame(t + 300 + i, ROUTER, rssi=-60.0))
        pipe2.periodic(self.DAY + 8 * 3600)
        s = self._summaries(pipe2.events)
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0]["frames_24h"], 110)           # both runs, not just this one
        # Buckets older than the window are dropped on load and never counted.
        pipe2._frames_by_hour[int(t // 3600) - 30] = 999
        pipe2.periodic(self.DAY + 8 * 3600 + 60)
        pipe3 = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        self.assertNotIn(int(t // 3600) - 30, pipe3._frames_by_hour)
        self.assertEqual(pipe3.summary(self.DAY + 8 * 3600 + 120)["frames_24h"], 110)
        self.assertEqual(Pipeline(self.cfg, NullEventLog(), test_decryptor(), ephemeral=True)._frames_by_hour, {})

    def test_a_summary_whose_write_failed_is_retried_next_tick(self):
        class FlakyLog(NullEventLog):
            failures = 1

            def emit(self, event, *a, **kw):
                if event == "daily_summary" and self.failures:
                    self.failures -= 1
                    raise OSError(28, "No space left on device")
                return super().emit(event, *a, **kw)

        pipe = Pipeline(self.cfg, FlakyLog(), test_decryptor())
        with self.assertRaises(OSError):
            pipe.periodic(self.DAY + 8 * 3600)
        self.assertEqual(self._summaries(pipe.events), [])
        pipe.periodic(self.DAY + 8 * 3600 + 60)             # the next tick sends it
        self.assertEqual(len(self._summaries(pipe.events)), 1)
        pipe.periodic(self.DAY + 9 * 3600)                  # and only once
        self.assertEqual(len(self._summaries(pipe.events)), 1)

    def test_disabled_and_ephemeral(self):
        self.cfg.summary_hour = -1
        pipe = Pipeline(self.cfg, NullEventLog(), test_decryptor())
        pipe.periodic(self.DAY + 9 * 3600)
        self.assertEqual(self._summaries(pipe.events), [])
        self.cfg.summary_hour = 8
        replay = Pipeline(self.cfg, NullEventLog(), test_decryptor(), ephemeral=True)
        replay.periodic(self.DAY + 9 * 3600)
        self.assertEqual(self._summaries(replay.events), [])
