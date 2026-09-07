"""Unit tests for the quiet-device policy in threadwatch.pipeline."""

import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.frames import psdu_for
from threadwatch.config import Config
from threadwatch.crypto import Decryptor
from threadwatch.events import NullEventLog
from threadwatch.pcap import Frame
from threadwatch.pipeline import Pipeline


def stub_decryptor():
    """A key, so the pipeline has one; test frames carry no payload, so it
    never decrypts. Not named test_*: it is a helper, not a test case."""
    return Decryptor(network_key=bytes(16))

ROUTER = "b62c32bf669272db"
SENSOR = "1669674dd15cf0fa"
STRANGER = "72d035122fdf06f6"
OWN_PAN, OTHER_PAN = 0x4e21, 0x58bc


def frame(ts, src, pan=OWN_PAN, rssi=-60.0, seq=None, dst="0000", counter=None):
    """A secured data frame from ``src`` (a MIC under the test key and a
    fresh counter, so the pipeline takes it as a sighting: tests/frames.py)."""
    seq = int(ts) & 0xFF if seq is None else seq
    return Frame(ts=ts, raw=b"", psdu=psdu_for(src, seq=seq, pan=pan, dst=dst, counter=counter),
                 rssi=rssi, channel=None, lqi=None,
                 ftype=1, seq=seq, dst_pan=pan, dst=dst, src_pan=pan, src=src)


class AuthenticationHistoryCapTest(unittest.TestCase):
    def test_churn_is_bounded_and_evicted_device_replays_stay_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            pipe = Pipeline(Config(data_dir=Path(tmp), devices_path=Path(tmp) / "devices.json"),
                            NullEventLog(), stub_decryptor(), ephemeral=True)
            pipe.TRACK_MAX = 2
            pipe.AUTH_MAX = 4
            t = 1_700_000_000.0
            for i in range(20):
                pipe.ingest(frame(t + i * 10, f"{i + 1:016x}", counter=10))
            self.assertEqual(len(pipe._auth_addresses), 4)
            self.assertEqual(len(pipe._mac_counter), 4)
            self.assertLessEqual(len(pipe.seen.table), 2)
            self.assertNotIn("0000000000000001", pipe.seen.table)
            pipe.ingest(frame(t + 300, "0000000000000001", counter=9))
            self.assertNotIn("0000000000000001", pipe.seen.table)
            # A new layer for an existing address is allowed, while new
            # identities cannot bypass the shared cap through MLE.
            self.assertTrue(pipe._counter_advances(pipe._mle_counter, "0000000000000001", 10, t, "MLE", 0))
            for i in range(20, 40):
                self.assertFalse(pipe._counter_advances(pipe._mle_counter, f"{i:016x}", 1, t, "MLE", 0))
            self.assertEqual(len(pipe._mle_counter), 1)
            self.assertLessEqual(len(pipe._replay_said), 4)
            pipe.ingest(frame(t + 301, "0000000000000001", counter=11))
            self.assertIn("0000000000000001", pipe.seen.table)
            self.assertEqual(sum(r["event"] == "authentication_history_full" for r in pipe.events.records), 1)

    def test_refused_tracking_admission_still_has_bounded_counter_history(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            pipe = Pipeline(Config(data_dir=Path(tmp), devices_path=Path(tmp) / "devices.json"),
                            NullEventLog(), stub_decryptor(), ephemeral=True)
            pipe.AUTH_MAX = 3
            with patch.object(pipe, "_admit", return_value=False):
                for i in range(10):
                    pipe.ingest(frame(1_700_000_000.0 + i, f"{i + 1:016x}", counter=10))
            self.assertEqual(pipe.seen.table, {})
            self.assertEqual(len(pipe._mac_counter), 3)
            self.assertEqual(len(pipe._auth_addresses), 3)


class SnapshotCoverageTest(unittest.TestCase):
    def test_replay_uses_bundled_outages_without_future_credit_or_writes(self):
        from threadwatch.events import day_of
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            t = 1_700_000_000.0
            (root / "blind-spans.json").write_text(json.dumps([[t + 10, 3590]]))
            (root / "events").mkdir()
            event = dict(event="recorder_started", severity="info", ts=t + 3600,
                         last_frame_ts=t + 10)
            (root / "events" / (day_of(t) + ".jsonl")).write_text(json.dumps(event) + "\n")
            before = {p: p.read_bytes() for p in root.rglob("*") if p.is_file()}
            for pruned in (False, True):
                if pruned:
                    (root / "blind-spans.json").write_text("[]")
                cfg = Config(snapshot_dir=root, devices_path=root / "devices.json", pan_id=OWN_PAN)
                pipe = Pipeline(cfg, NullEventLog(), stub_decryptor(), ephemeral=True)
                self.assertEqual(pipe.seen.table, {})
                pipe.ingest(frame(t, SENSOR))
                self.assertEqual(pipe.silence_s(pipe.seen.table[SENSOR], t + 5), 5)
                pipe.ingest(frame(t + 3610, ROUTER))
                pipe.periodic(t + 3610)
                self.assertFalse(any(r["event"] == "device_quiet" for r in pipe.events.records))
                self.assertEqual(pipe.silence_s(pipe.seen.table[SENSOR], t + 3610), 20)
                if not pruned:
                    self.assertEqual(before, {p: p.read_bytes() for p in root.rglob("*") if p.is_file()})


class StateFileShapeTest(unittest.TestCase):
    """A state file that is valid JSON of the wrong shape (a list, a
    string, a number, null; a table whose rows are strings) parsed fine
    and raised AttributeError at the first .get, which no reader caught:
    the recorder could not start, and the traceback did not name the
    file. Every shape must degrade the way invalid JSON already does."""

    BODIES = ("[]", "[1, 2]", '"text"', "42", "null", "true")

    def _cfg(self, d):
        (d / "devices.json").write_text("[]")
        return Config(data_dir=d / "data", devices_path=d / "devices.json")

    def test_status_json_of_any_shape_never_stops_a_start(self):
        import contextlib
        import io

        from threadwatch.record import last_frame_on_record
        for body in self.BODIES:
            with self.subTest(body=body), tempfile.TemporaryDirectory() as tmp:
                cfg = self._cfg(Path(tmp))
                cfg.state_dir.mkdir(parents=True, exist_ok=True)
                (cfg.state_dir / "status.json").write_text(body)
                self.assertIsNone(last_frame_on_record(cfg.state_dir))
                out = io.StringIO()
                with contextlib.redirect_stderr(out):
                    pipe = Pipeline(cfg, NullEventLog(), stub_decryptor())
                    pipe.ingest(frame(1_700_000_000.0, ROUTER))
                    pipe.periodic(1_700_000_030.0)
                self.assertIn("status.json is unreadable (expected an object, got", out.getvalue())

    def test_rows_that_are_not_objects_are_dropped_from_the_tables(self):
        import contextlib
        import io

        from threadwatch.names import DeviceNames, LastSeen, load_border_routers
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(Path(tmp))
            cfg.state_dir.mkdir(parents=True, exist_ok=True)
            t0 = 1_700_000_000.0
            (cfg.state_dir / "last-seen.json").write_text(json.dumps({
                ROUTER: {"first_seen": t0, "last_seen": t0, "frames": 5, "types": {}},
                SENSOR: "a string where a row should be", STRANGER: None, "0000000000000001": 7}))
            (cfg.state_dir / "border-routers.json").write_text(json.dumps({
                "hub.local": {"addr": SENSOR, "name": "Hub"}, "other.local": "text", "third.local": []}))
            out = io.StringIO()
            with contextlib.redirect_stderr(out):
                seen = LastSeen(cfg.state_dir / "last-seen.json")
                self.assertEqual(list(seen.table), [ROUTER])
                self.assertEqual(list(load_border_routers(cfg.state_dir / "border-routers.json")), ["hub.local"])
                names = DeviceNames(cfg.devices_path, cfg.state_dir / "border-routers.json")
                self.assertEqual(list(names.border_routers), [SENSOR])
                pipe = Pipeline(cfg, NullEventLog(), stub_decryptor())
                pipe.ingest(frame(t0 + 10, ROUTER))
                pipe.periodic(t0 + 40)
                pipe.seen.save()
            self.assertIn("last-seen.json: dropping 3 row(s) that are not objects", out.getvalue())
            saved = json.loads((cfg.state_dir / "last-seen.json").read_text())
            self.assertEqual(list(saved), [ROUTER])              # the bad rows are gone from disk too


class OnePanAnswerTest(unittest.TestCase):
    """The recorder adopts a PAN at ten frames and replaces it only with
    one holding twice as many; the report and the pages recomputed the
    same fact as a bare max over the table, so they named a different
    PAN whenever a second one overtook the first without doubling it,
    and denied a quiet the recorder had paged for."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([{"name": "Living Room AQ", "extendedAddress": SENSOR}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json", quiet_s=1800)

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_pages_read_the_pan_the_recorder_judges_by(self):
        from types import SimpleNamespace

        from threadwatch.record import _write_status
        from threadwatch.review import dominant_pan, now_card
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t0 = 1_700_000_000.0
        for i in range(100):
            pipe.ingest(frame(t0 + i, SENSOR))                       # ours: 100 frames
        for i in range(150):
            pipe.ingest(frame(t0 + 100 + i, STRANGER, pan=OTHER_PAN))  # a neighbour, busier but not twice as busy
        self.assertEqual(pipe.dominant_pan(), OWN_PAN)
        pipe.periodic(t0 + 250 + 1800)
        self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"], [SENSOR])
        pipe.seen.save()
        # Without the recorder's word, the table's busiest PAN wins: the
        # old disagreement, and the reason status.json now carries it.
        self.assertEqual(dominant_pan(pipe.seen, None), OTHER_PAN)
        ring = SimpleNamespace(current_path=self.cfg.ring_dir / "threadwatch-20260904-10.pcap")
        _write_status(self.cfg, "/dev/x", 250, t0, pipe, ring, pipe.decryptor)
        status = json.loads((self.cfg.state_dir / "status.json").read_text())
        self.assertEqual(status["dominant_pan"], OWN_PAN)
        self.assertEqual(dominant_pan(pipe.seen, None, self.cfg.state_dir), OWN_PAN)
        card = now_card(pipe.seen, pipe.names, self.cfg.events_dir, self.cfg.quiet_min_rssi_dbm,
                        "2023-11-14", now=t0 + 3000, state_dir=self.cfg.state_dir)
        self.assertEqual([q["addr"] for q in card["quiet"]], [SENSOR])
        # A configured PAN wins over both, and a status file of the wrong
        # shape or without the key falls back to the count.
        self.assertEqual(dominant_pan(pipe.seen, 0x1234, self.cfg.state_dir), 0x1234)
        (self.cfg.state_dir / "status.json").write_text("[1, 2]")
        self.assertEqual(dominant_pan(pipe.seen, None, self.cfg.state_dir), OTHER_PAN)
        (self.cfg.state_dir / "status.json").write_text(json.dumps({"dominant_pan": None}))
        self.assertIsNone(dominant_pan(pipe.seen, None, self.cfg.state_dir))   # too few frames, said the recorder

    def test_the_fallback_count_has_the_recorders_floor(self):
        from threadwatch.review import dominant_pan
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t0 = 1_700_000_000.0
        for i in range(Pipeline.DOMINANT_MIN_FRAMES - 1):
            pipe.ingest(frame(t0 + i, SENSOR))
        self.assertIsNone(pipe.dominant_pan())
        self.assertIsNone(dominant_pan(pipe.seen, None))                # the pages judge everyone too
        pipe.ingest(frame(t0 + 20, SENSOR))
        self.assertEqual((pipe.dominant_pan(), dominant_pan(pipe.seen, None)), (OWN_PAN, OWN_PAN))


class AddressFloodTest(unittest.TestCase):
    """An extended source address is whatever the sender says it is, and
    every new one became a row in last-seen and a DeviceStats for ever:
    a transmitter sending from a fresh address per frame grew both until
    the Pi ran out of memory, and rewrote a growing last-seen.json every
    30 s on the way."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Living Room AQ", "extendedAddress": SENSOR, "threadRole": "sleepy-end-device"},
        ]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_the_table_stays_bounded_and_keeps_the_devices_worth_keeping(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        cap = Pipeline.TRACK_MAX
        t0 = 1_700_000_000.0
        # A named device, an unnamed neighbour heard 50 times, and a device
        # vouched for by a MIC-checked short address: none of them may go.
        for i in range(3):
            pipe.ingest(frame(t0 + i, SENSOR))
        for i in range(50):
            pipe.ingest(frame(t0 + 10 + i, STRANGER))
        pipe.ingest(frame(t0 + 70, ROUTER))
        pipe.decryptor.short_to_ext["0401"] = ROUTER
        forged = [f"{0x3000000000000000 + n:016x}" for n in range(3 * cap)]
        for n, addr in enumerate(forged):
            pipe.ingest(frame(t0 + 100 + n * 0.01, addr))
        self.assertLessEqual(len(pipe.seen.table), cap)
        self.assertLessEqual(len(pipe.devices), cap + 1)
        for keep in (SENSOR, STRANGER, ROUTER):
            self.assertIn(keep, pipe.seen.table)
            self.assertIn(keep, pipe.devices)
        self.assertEqual(pipe.seen.table[STRANGER]["frames"], 50)
        # The last forged addresses are the ones still there: the least
        # heard and longest ago went first.
        self.assertIn(forged[-1], pipe.seen.table)
        self.assertNotIn(forged[0], pipe.seen.table)
        floods = [r for r in pipe.events.records if r["event"] == "address_flood"]
        self.assertEqual(len(floods), 1)                       # once an hour, not once per eviction
        self.assertEqual(floods[0]["severity"], "warning")
        self.assertGreater(floods[0]["dropped"], 0)
        self.assertIn("ever-new extended addresses", floods[0]["note"])
        # Sightings are not announced one by one while it goes on.
        first = [r["addr"] for r in pipe.events.records if r["event"] == "device_first_seen"]
        self.assertEqual(len(first), cap)                      # the ones before the table filled
        self.assertNotIn(forged[-1], first)
        # An hour on, a new address is news again, and the warning repeats
        # once if the flood is still running.
        pipe.ingest(frame(t0 + 4000, "3fffffffffffffff"))
        self.assertIn("3fffffffffffffff", [r.get("addr") for r in pipe.events.records])
        for n in range(cap):
            pipe.ingest(frame(t0 + 4001 + n * 0.01, f"{0x4000000000000000 + n:016x}"))
        self.assertEqual(len([r for r in pipe.events.records if r["event"] == "address_flood"]), 2)
        self.assertLessEqual(len(pipe.seen.table), cap)
        # Nothing evicted lingers in the per-device state a quiet check walks.
        self.assertEqual(set(pipe.devices) - set(pipe.seen.table), set())
        self.assertEqual(pipe.quiet_reported, set())

    def test_beacons_from_ever_new_sources_do_not_grow_the_stats_either(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t0 = 1_700_000_000.0
        for n in range(Pipeline.TRACK_MAX + 50):
            f = frame(t0 + n * 0.01, f"{n:04x}")
            f.ftype, f.cmd = 3, 7
            pipe.ingest(f)
        self.assertLessEqual(len(pipe.devices), Pipeline.TRACK_MAX)


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
        return Pipeline(self.cfg, NullEventLog(), stub_decryptor())

    @staticmethod
    def _quiet(pipe):
        return [r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"]

    def test_a_rotated_device_is_not_quiet_at_the_address_it_left(self):
        """The documented rotation -- `name <new-address> <existing-name>` --
        adds an address to an existing entry, but the quiet check ran per
        address, so the older one crossed its threshold and paged while the
        device was authenticating from the newer one. Only the mDNS path sets
        rotated_to; a rotation entered by hand had nothing to say it."""
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Hall Sensor", "extendedAddresses": [SENSOR.upper(), ROUTER]},
        ]))
        pipe = self._pipe()
        t = 1_700_000_000.0
        pipe.ingest(frame(t, SENSOR))                      # the address it had
        pipe.ingest(frame(t + 2000, ROUTER))               # the address it rotated to
        pipe.periodic(t + 2000)
        self.assertEqual(self._quiet(pipe), [])
        # Silent at both, and it is reported again.
        pipe.periodic(t + 2000 + 31 * 60)
        self.assertEqual(sorted(set(self._quiet(pipe))), sorted({SENSOR, ROUTER}))

    def test_two_devices_that_merely_share_a_name_are_still_judged_apart(self):
        """Quietness spans one entry's own address list, not everything
        names.addresses_of would gather: two separate entries someone gave the
        same name are two devices, and one talking must not answer for the
        other."""
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Hall Sensor", "extendedAddress": SENSOR},
            {"name": "Hall Sensor", "extendedAddress": ROUTER},
        ]))
        pipe = self._pipe()
        t = 1_700_000_000.0
        pipe.ingest(frame(t, SENSOR))
        pipe.ingest(frame(t + 2000, ROUTER))
        pipe.periodic(t + 2000)
        self.assertEqual(self._quiet(pipe), [SENSOR])

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
            pipe.ingest(frame(ts, src, seq=seq, dst=dst))
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

    def test_a_neighbours_retransmissions_are_not_ours(self):
        # Every other detector skips foreign rows; the retransmission
        # window counted every frame on the channel, so a neighbour's mesh
        # retrying to its own router paged as ours, naming our device
        # that happened to hold the same short address as the far end.
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([{"name": "Hall Router", "extendedAddress": ROUTER}]))
        pipe = self._pipe()
        pipe.decryptor.short_to_ext["8801"] = ROUTER            # our router's RLOC16
        t = 1_700_000_000.0
        for m in range(10):
            for i in range(150):
                pipe.ingest(frame(t + m * 60 + i * 0.4, STRANGER, seq=i))          # ours, clean
        base = t + 10 * 60
        for i in range(150):
            pipe.ingest(frame(base + i * 0.4, STRANGER, seq=i))
        for k in range(3):                                      # three neighbours retrying to 8801 on their PAN
            src = f"{0x2000 + k:016x}"
            for i in range(50):
                for rep in range(3):
                    pipe.ingest(frame(base + i + rep * 0.1, src, pan=OTHER_PAN, seq=i, dst="8801"))
        pipe.ingest(frame(base + 61, STRANGER, seq=200))       # closes the window
        self.assertEqual([r for r in pipe.events.records if r["event"] == "retransmission_elevation"], [])
        # Our own repeats in the next minute are still seen, against a
        # baseline the neighbour never touched.
        base = t + 11 * 60
        for i in range(100):
            pipe.ingest(frame(base + i * 0.3, STRANGER, seq=i))
        for i in range(20):
            for rep in range(4):
                pipe.ingest(frame(base + i * 2.5 + rep * 0.2, SENSOR, seq=i, dst="8801"))
        pipe.ingest(frame(base + 61, STRANGER, seq=200))
        ev = [r for r in pipe.events.records if r["event"] == "retransmission_elevation"]
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["addr"], ev[0]["top_target"]), (SENSOR, "Hall Router"))

    def test_mesh_wide_retransmissions_page(self):
        pipe = self._pipe()
        t = 1_700_000_000.0
        def send(src, dst, seq, ts):
            pipe.ingest(frame(ts, src, seq=seq, dst=dst))
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
        # Mesh-wide is the paging kind, but one minute is logged first; the
        # page waits for [retransmissions] confirm_s (RetransmissionConfirmTest).
        self.assertEqual((ev[0]["severity"], ev[0]["confirmed"]), ("notice", False))
        self.assertLess(ev[0]["top_share"], 0.5)
        self.assertEqual(ev[0]["top_target"], "broadcast")
        self.assertIn("channel contention", ev[0]["note"])
        self.assertIn("paged if the rate is still up in 5 min", ev[0]["note"])

    def test_a_mesh_whose_normal_rate_is_high_is_not_warned_about_every_15_min(self):
        """A busy install sits above 20% retransmissions all day. That is its
        baseline, not an elevation: only a rate that doubles it is news."""
        pipe = self._pipe()
        t = 1_700_000_000.0

        def send(ts, seq):
            pipe.ingest(frame(ts, STRANGER, seq=seq))

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

    def test_a_configured_pan_falling_silent_on_a_busy_channel_is_a_warning(self):
        # The mesh was migrated to a new PAN: every frame now carries it and
        # the configured one is never heard again. Half an hour of that with
        # the channel busy is the warning; a neighbour talking alongside our
        # own frames is not, and neither is a quiet channel.
        self.cfg.pan_id = OWN_PAN
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        silent = lambda: [r for r in pipe.events.records if r["event"] == "configured_pan_silent"]
        for i in range(10):
            pipe.ingest(frame(t0 + i, ROUTER))
        for i in range(200):
            pipe.ingest(frame(t0 + 100 + i * 9, STRANGER, pan=OTHER_PAN))
        pipe.periodic(t0 + 31 * 60)                                  # ours spoke in this window
        self.assertEqual(silent(), [])
        for i in range(50):
            pipe.ingest(frame(t0 + 31 * 60 + i * 30, STRANGER, pan=OTHER_PAN))
        pipe.periodic(t0 + 62 * 60)                                  # too few frames to call the channel busy
        self.assertEqual(silent(), [])
        for i in range(200):
            pipe.ingest(frame(t0 + 62 * 60 + i * 9, STRANGER, pan=OTHER_PAN))
        pipe.periodic(t0 + 80 * 60)                                  # window not over yet
        self.assertEqual(silent(), [])
        pipe.periodic(t0 + 93 * 60)
        self.assertEqual([(r["severity"], r["pan"], r["heard_frames"], r["busiest_pan"]) for r in silent()],
                         [("warning", f"0x{OWN_PAN:04x}", 200, f"0x{OTHER_PAN:04x}")])
        self.assertIn("update pan_id and restart", silent()[0]["note"])
        for i in range(200):
            pipe.ingest(frame(t0 + 93 * 60 + i * 9, STRANGER, pan=OTHER_PAN))
        pipe.periodic(t0 + 124 * 60)                                 # still silent: no repeat inside six hours
        self.assertEqual(len(silent()), 1)
        # Without pan_id there is nothing to check against.
        self.cfg.pan_id = None
        pipe2 = self._pipe()
        for i in range(200):
            pipe2.ingest(frame(t0 + i * 9, STRANGER, pan=OTHER_PAN))
        pipe2.periodic(t0 + 31 * 60)
        self.assertEqual([r for r in pipe2.events.records if r["event"] == "configured_pan_silent"], [])

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
        expected = [(f"0x{OTHER_PAN:04x}", f"0x{OWN_PAN:04x}", STRANGER),       # theirs while ours led...
                    (f"0x{OWN_PAN:04x}", f"0x{OTHER_PAN:04x}", ROUTER)]         # ...then ours, by that guess
        self.assertEqual(self._foreign(pipe), expected)
        for i in range(29):                                     # ours back in the lead, 39 to 20, under double: no flap
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
        self.assertAlmostEqual(rec["unheard_s"], 31 * 60, delta=5)
        # What the pages show is the wall clock since the last frame, and
        # the record says the same, with the outage inside it named.
        self.assertAlmostEqual(rec["silent_for_s"], 69 * 60, delta=5)
        self.assertAlmostEqual(rec["blind_s"], 38 * 60, delta=5)
        self.assertEqual(rec["last_seen"], pipe2.seen.table[ROUTER]["last_seen"])
        self.assertIn("not listening for 38 min of the 69 min", rec["note"])

    def test_a_second_restart_still_keeps_the_first_ones_outage_off_the_devices(self):
        # Router last heard at T; the recorder stopped at T+120 and came back
        # at T+2400, which it correctly took as its own blindness. Then a
        # sensor was heard, and the recorder restarted again a second later:
        # that outage was known only to the run that had just ended, and
        # the router was charged the whole 41 minutes and announced.
        from unittest import mock
        T = time.time() - 3000
        pipe = self._pipe()
        pipe.ingest(frame(T, ROUTER))
        pipe.ingest(frame(T + 120, SENSOR))
        pipe.seen.save()
        self._status(updated=T + 120, last_frame_ts=T + 120)
        with mock.patch("threadwatch.pipeline.time.time", lambda: T + 2400):
            pipe2 = self._pipe()
        self.assertEqual(self._quiet(pipe2), [])
        self.assertAlmostEqual(pipe2.silence_s(pipe2.seen.table[ROUTER], T + 2400), 120, delta=1)
        pipe2.ingest(frame(T + 2460, SENSOR))
        pipe2.seen.save()
        self._status(updated=T + 2460, last_frame_ts=T + 2460)
        with mock.patch("threadwatch.pipeline.time.time", lambda: T + 2461):
            pipe3 = self._pipe()
        self.assertEqual(self._quiet(pipe3), [])
        self.assertAlmostEqual(pipe3.silence_s(pipe3.seen.table[ROUTER], T + 2461), 180, delta=1)
        self.assertAlmostEqual(pipe3.silence_s(pipe3.seen.table[SENSOR], T + 2461), 0, delta=1)
        pipe3.periodic(T + 2461 + 27 * 60)                      # 3 + 27 min: still inside the window
        self.assertEqual(self._quiet(pipe3), [])
        pipe3.periodic(T + 2461 + 28 * 60)
        self.assertEqual(self._quiet(pipe3), [ROUTER])
        # Once every device has been heard since a span, it is retired.
        pipe3.ingest(frame(T + 2461 + 29 * 60, ROUTER))
        pipe3._save_blind()
        self.assertEqual(json.loads(pipe3.blind_path.read_text()), [[T + 2460, 1.0]])   # the sensor's, still
        pipe3.ingest(frame(T + 2461 + 29 * 60, SENSOR))
        pipe3._save_blind()
        self.assertEqual(json.loads(pipe3.blind_path.read_text()), [])

    def test_a_clock_step_after_boot_is_the_recorders_blindness_not_the_devices(self):
        # An RTC-less Pi boots on its saved clock, about when it last heard
        # a frame, so the start-up pass sees a minute of outage; NTP then
        # steps the clock forward by the real outage with the recorder up.
        boot, outage = time.time(), 3 * 3600
        pipe = self._pipe()
        pipe.ingest(frame(boot - 120, ROUTER))
        pipe.ingest(frame(boot - 60, SENSOR))
        pipe.seen.save()
        self._status(updated=boot - 60, last_frame_ts=boot - 60)
        pipe2 = self._pipe()
        self.assertEqual(self._quiet(pipe2), [])
        clock = {"wall": boot, "mono": 0.0}
        pipe2._wall, pipe2._mono, pipe2._clock = (lambda: clock["wall"]), (lambda: clock["mono"]), (boot, 0.0)
        pipe2.ingest(frame(boot + 30, STRANGER))          # heard after boot, before the step
        clock.update(wall=boot + 60 + outage, mono=60.0)  # NTP: the wall clock jumps, monotonic does not
        pipe2.periodic(boot + 60 + outage)
        self.assertEqual(self._quiet(pipe2), [])
        steps = [r for r in pipe2.events.records if r["event"] == "clock_step"]
        self.assertEqual([r["step_s"] for r in steps], [outage])
        # From the step on, silence is counted as heard.
        clock.update(wall=boot + outage + 28 * 60, mono=28 * 60.0)
        pipe2.periodic(boot + outage + 28 * 60)
        self.assertEqual(self._quiet(pipe2), [])
        clock.update(wall=boot + outage + 32 * 60, mono=32 * 60.0)
        pipe2.periodic(boot + outage + 32 * 60)
        self.assertEqual(sorted(self._quiet(pipe2)), sorted([ROUTER, SENSOR, STRANGER]))
        self.assertEqual(len([r for r in pipe2.events.records if r["event"] == "clock_step"]), 1)
        silent = {r["addr"]: r["unheard_s"] for r in pipe2.events.records if r["event"] == "device_quiet"}
        self.assertAlmostEqual(silent[ROUTER], 33 * 60, delta=5)   # 2 min before boot, 1 min up, 32 min since
        self.assertAlmostEqual(silent[STRANGER], 31.5 * 60, delta=5)
        wall = {r["addr"]: r["silent_for_s"] for r in pipe2.events.records if r["event"] == "device_quiet"}
        self.assertAlmostEqual(wall[ROUTER], outage + 34 * 60, delta=5)
        self.assertAlmostEqual(wall[STRANGER], outage + 31.5 * 60, delta=5)

    def test_a_clock_step_back_is_not_charged_against_the_quiet_timer(self):
        # A host that booted ahead of time, corrected by NTP while recording:
        # every stamp taken before the correction sat the step ahead of the
        # clock, and a silence had to make the step up before it counted.
        T = time.time()
        pipe = self._pipe()
        clock = {"wall": T, "mono": 0.0}
        pipe._wall, pipe._mono, pipe._clock = (lambda: clock["wall"]), (lambda: clock["mono"]), (T, 0.0)
        pipe.ingest(frame(T, ROUTER))
        clock.update(wall=T + 600, mono=600.0)
        pipe.periodic(T + 600)                                   # ten minutes in, all quiet
        self.assertEqual(self._quiet(pipe), [])
        clock.update(wall=T + 600 - 1800 + 20, mono=620.0)       # the clock steps back 30 min; 20 s later, a check
        pipe.ingest(frame(clock["wall"] - 5, SENSOR))            # heard after the step, stamped by the new clock
        pipe.periodic(clock["wall"])
        steps = [r for r in pipe.events.records if r["event"] == "clock_step"]
        self.assertEqual([r["step_s"] for r in steps], [-1800])
        self.assertIn("jumped back 30 min", steps[0]["note"])
        self.assertEqual(pipe.seen.table[ROUTER]["last_seen"], T - 1800)          # moved with the clock
        self.assertEqual(pipe.seen.table[SENSOR]["last_seen"], clock["wall"] - 5)   # left where it is
        self.assertAlmostEqual(pipe.silence_s(pipe.seen.table[ROUTER], clock["wall"]), 620, delta=1)
        clock.update(wall=clock["wall"] + 20 * 60 + 40, mono=620.0 + 20 * 60 + 40)
        pipe.periodic(clock["wall"])                             # 31 min of actual silence
        self.assertEqual(self._quiet(pipe), [ROUTER])
        rec = [r for r in pipe.events.records if r["event"] == "device_quiet"][0]
        self.assertAlmostEqual(rec["unheard_s"], 31 * 60, delta=5)
        self.assertAlmostEqual(rec["silent_for_s"], 31 * 60, delta=5)
        self.assertEqual(len([r for r in pipe.events.records if r["event"] == "clock_step"]), 1)

    def test_a_silence_of_exactly_quiet_s_at_start_up_is_not_yet_quiet(self):
        # The start-up reconciliation decides a device has returned with
        # `silence_s(row, now) <= quiet_threshold_s(addr)`. Nothing said
        # which way the exact boundary falls, so changing it to < left the
        # suite green while flipping every device sitting precisely on the
        # threshold from "returned" to "quiet" at every restart. The live
        # check one screen away is `>`, so exactly quiet_s is not quiet
        # there either, and the two have to agree or a restart announces a
        # silence the running recorder would not have.
        import json as _json
        T = time.time()
        for offset, expect_quiet in ((0.0, False), (0.5, True)):
            state = self.cfg.state_dir
            state.mkdir(parents=True, exist_ok=True)
            (state / "last-seen.json").write_text(_json.dumps(
                {ROUTER: {"first_seen": T - 7200, "last_seen": T - self.cfg.quiet_s - offset,
                          "frames": 10, "types": {}, "pan": OWN_PAN}}))
            (state / "blind-spans.json").write_text("[]")
            # Something else was heard a moment ago, so the recorder is
            # credited no blindness reaching back over this silence.
            (state / "status.json").write_text(_json.dumps({"last_frame_ts": T}))
            pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
            self.assertEqual(self._quiet(pipe) == [ROUTER], expect_quiet,
                             f"silence of quiet_s + {offset}")

    def test_a_clock_step_back_moves_every_cooldown_and_deadline_with_it(self):
        # Each of these is read as `now < stamp` or `now - stamp < window`.
        # Left the step ahead of the clock, each suppresses its own check
        # for the whole length of the step: no mDNS browse, so a hub that
        # rotates its address in the window keeps the dead one and then
        # reads as quiet; no ring snapshot for a critical event; no
        # configured_pan_silent; join-scan, stale-credential and storm
        # notices held back; and maybe_save stops writing the last-seen
        # table, so a host cut in the window loses everything since.
        T = time.time()
        pipe = self._pipe()
        clock = {"wall": T, "mono": 0.0}
        pipe._wall, pipe._mono, pipe._clock = (lambda: clock["wall"]), (lambda: clock["mono"]), (T, 0.0)
        scalars = ("_next_browse", "_join_scan_evt", "_stale_evt", "_pan_silent_evt",
                   "_pan_window_start", "_last_auto_snapshot", "_storm_evt")
        for attr in scalars:
            setattr(pipe, attr, T + 60)
        pipe._resolve_after["0001"] = T + 60
        pipe._verify_after["0002"] = T + 60
        pipe._foreign_after[("0003", 0x1234)] = T + 60

        clock.update(wall=T + 20 - 1800, mono=20.0)             # the clock steps back 30 min
        pipe.periodic(clock["wall"])

        self.assertEqual([r["step_s"] for r in pipe.events.records if r["event"] == "clock_step"], [-1800])
        for attr in scalars:
            self.assertEqual(getattr(pipe, attr), T + 60 - 1800, attr)
        self.assertEqual(pipe._resolve_after["0001"], T + 60 - 1800)
        self.assertEqual(pipe._verify_after["0002"], T + 60 - 1800)
        self.assertEqual(pipe._foreign_after[("0003", 0x1234)], T + 60 - 1800)
        # maybe_save writes the table at most once a minute; with its stamp
        # a step ahead it stops writing until the clock catches up, and a
        # host cut in that window loses everything since. (periodic saves,
        # so the rewind is exercised on its own here.)
        pipe.seen._last_save = T + 60
        pipe._rewind(T + 20 - 1800, 1800, 20.0)
        self.assertEqual(pipe.seen._last_save, T + 60 - 1800)

    def test_a_clock_step_back_does_not_re_announce_a_silence_already_on_record(self):
        # The quiet flag names the device_quiet record it stands for by its
        # stamp. A backward step moves the row's measurements back with the
        # clock; the appended record cannot move, so the pointer must not
        # either, or the next start finds no record, discards the flag and
        # pages the same unbroken silence twice.
        from threadwatch.events import EventLog, read_all
        T = time.time()
        pipe = Pipeline(self.cfg, EventLog(self.cfg.state_dir / "events"), stub_decryptor())
        clock = {"wall": T, "mono": 0.0}
        pipe._wall, pipe._mono, pipe._clock = (lambda: clock["wall"]), (lambda: clock["mono"]), (T, 0.0)
        pipe.ingest(frame(T, ROUTER))
        clock.update(wall=T + 31 * 60, mono=31 * 60.0)
        pipe.periodic(clock["wall"])                             # announced quiet, flag and record stamped alike
        reported = pipe.seen.table[ROUTER]["quiet_reported_ts"]
        clock.update(wall=T + 31 * 60 - 1800 + 20, mono=31 * 60.0 + 20)
        pipe.periodic(clock["wall"])                             # the clock steps back 30 min
        events = self.cfg.state_dir / "events"

        def logged(event):
            return [r for r in read_all(events) if r["event"] == event]

        self.assertEqual([r["step_s"] for r in logged("clock_step")], [-1800])
        self.assertEqual(pipe.seen.table[ROUTER]["quiet_reported_ts"], reported)
        pipe.seen.save()
        Pipeline(self.cfg, EventLog(events), stub_decryptor())
        self.assertEqual(len(logged("device_quiet")), 1)

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
        self.assertAlmostEqual(rec["unheard_s"], 31 * 60, delta=5)
        self.assertAlmostEqual(rec["silent_for_s"], 2 * 3600 + 31 * 60, delta=5)
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
        self.assertEqual([r["event"] for r in pipe2.events.records], ["recorder_started", "device_returned"])
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

    def test_a_silence_flagged_as_announced_but_never_logged_is_announced_at_the_next_start(self):
        # The flag is saved before the event is appended (so an outage
        # right after cannot re-announce). Killed between the two, the
        # last run left the flag and no record: the next start trusted the
        # flag, and the silence had neither an event nor an alert.
        from threadwatch.events import EventLog, day_of, read_day
        now = time.time()
        pipe = Pipeline(self.cfg, EventLog(self.cfg.events_dir), stub_decryptor())
        pipe.ingest(frame(now - 40 * 60, SENSOR))
        pipe.ingest(frame(now, ROUTER))

        def cut_short(*a, **kw):
            raise OSError("killed between the save and the append")
        pipe.events.emit = cut_short
        with self.assertRaises(OSError):
            pipe.periodic(now)
        self.assertTrue(json.loads(pipe.seen.state_path.read_text())[SENSOR]["quiet_reported"])
        self.assertEqual([r for r in read_day(self.cfg.events_dir, day_of(now)) if r["event"] == "device_quiet"], [])
        self._status(updated=now, last_frame_ts=now)
        pipe2 = Pipeline(self.cfg, EventLog(self.cfg.events_dir), stub_decryptor())
        quiet = [r for r in read_day(self.cfg.events_dir, day_of(now)) if r["event"] == "device_quiet"]
        self.assertEqual([r["addr"] for r in quiet], [SENSOR])
        self.assertEqual(pipe2.quiet_reported, {SENSOR})
        self.assertEqual(json.loads(pipe2.seen.state_path.read_text())[SENSOR]["quiet_reported_ts"], quiet[0]["ts"])
        # The record is there now: a further start announces nothing again.
        Pipeline(self.cfg, EventLog(self.cfg.events_dir), stub_decryptor())
        quiet = [r for r in read_day(self.cfg.events_dir, day_of(now)) if r["event"] == "device_quiet"]
        self.assertEqual(len(quiet), 1)
        # And the ordinary case, announced and logged, is not announced twice either.
        pipe3 = Pipeline(self.cfg, EventLog(self.cfg.events_dir), stub_decryptor())
        pipe3.ingest(frame(now + 60, SENSOR))                 # returned
        pipe3.ingest(frame(now + 60, ROUTER))
        pipe3.seen.save()
        self.assertNotIn("quiet_reported_ts", pipe3.seen.table[SENSOR])
        pipe3.periodic(now + 60 + 31 * 60)                    # quiet again, announced and logged
        self._status(updated=now + 60 + 31 * 60, last_frame_ts=now + 60 + 31 * 60)
        Pipeline(self.cfg, EventLog(self.cfg.events_dir), stub_decryptor())
        quiet = [r for r in read_day(self.cfg.events_dir, day_of(now))
                 + read_day(self.cfg.events_dir, day_of(now + 3600))
                 if r["event"] == "device_quiet"]
        self.assertEqual(len({r["ts"] for r in quiet}), 2)

    def test_replay_neither_reads_nor_writes_live_state(self):
        now = time.time()
        live = self._pipe()
        live.ingest(frame(now - 2 * 3600, ROUTER))
        live.seen.save()
        before = (self.cfg.state_dir / "last-seen.json").read_text()
        replay = Pipeline(self.cfg, NullEventLog(), stub_decryptor(), ephemeral=True)
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
        self.assertEqual(ev[0][0], "recorder_started")
        self.assertEqual(ev[1:], [("device_returned", now - 60)])
        self.assertNotIn("quiet_reported", pipe2.seen.table[SENSOR])
        self.assertEqual(pipe2.quiet_reported, set())

    def test_storm_event_carries_period_onsets_and_a_note(self):
        pipe = self._pipe()
        pipe.detector.storm_active = True
        pipe.detector.storm_details = {"period": 80.5, "onsets": [100.0, 180.5, 261.0]}
        pipe.ingest(frame(1_700_000_000.0, ROUTER))
        rec = [r for r in pipe.events.records if r["event"] == "phase_locked_storm"][0]
        self.assertEqual((rec["period_s"], rec["onsets"]), (80.5, 3))
        self.assertIn("every 80 s", rec["note"])

    def test_critical_event_saves_the_ring_once_per_cooldown(self):
        self.cfg.snapshot_on_critical = True
        pipe = self._pipe()
        saved = []
        pipe.snapshotter = lambda label, trigger: saved.append((label, trigger))
        pipe.detector.storm_active = True
        pipe.detector.storm_details = {"period": 80.5, "onsets": [1.0, 2.0, 3.0]}
        # The detector ends a storm when flooding stops; hold it on regardless.
        pipe.detector.add_frame = lambda ts: setattr(pipe.detector, "storm_active", True)
        t0 = 1_700_000_000.0
        for dt in (0, 2 * 3600, 7 * 3600):                 # storm on; still on; past the six-hour cooldown
            pipe.ingest(frame(t0 + dt, ROUTER))
        storms = [r for r in pipe.events.records if r["event"] == "phase_locked_storm"]
        self.assertEqual([r["auto_snapshot"] for r in storms],
                         ["auto-phase_locked_storm", None, "auto-phase_locked_storm"])
        self.assertIn("being saved as auto-phase_locked_storm", storms[0]["note"])
        self.assertIn("run 'threadwatch snapshot'", storms[1]["note"])
        self.assertEqual(saved, [("auto-phase_locked_storm", "phase_locked_storm")] * 2)

    def test_any_critical_event_saves_and_names_itself_as_the_trigger(self):
        # The snapshot hangs off the severity, not off the storm handler: an
        # event added later at "critical" keeps its packets, and its
        # snapshot says which event asked for it.
        from threadwatch.review import snapshots
        self.cfg.snapshot_on_critical = True
        self.cfg.ring_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg.ring_dir / "threadwatch-20231114-22.pcap").write_bytes(b"ring")
        pipe = self._pipe()
        pipe.snapshotter = pipe._save_snapshot_now                    # in this thread, so the copy is done on return
        rec = pipe._emit("leader_lost", "critical", 1_700_000_000.0,
                         note="no leader has claimed the partition for 5 min")
        self.assertEqual(rec["auto_snapshot"], "auto-leader_lost")
        self.assertEqual(rec["note"], "no leader has claimed the partition for 5 min; "
                                      "the ring is being saved as auto-leader_lost")
        inc = snapshots(self.cfg.snapshots_dir)
        self.assertEqual([i["label"] for i in inc], ["auto-leader_lost"])
        manifest = json.loads((self.cfg.snapshots_dir / inc[0]["name"] / "manifest.json").read_text())
        self.assertEqual(manifest["trigger"], "leader_lost")

    def test_a_critical_event_with_no_note_still_says_where_its_packets_went(self):
        self.cfg.snapshot_on_critical = False               # off: the reader is told to save it by hand
        pipe = self._pipe()
        rec = pipe._emit("leader_lost", "critical", 1_700_000_000.0)
        self.assertIsNone(rec["auto_snapshot"])
        self.assertEqual(rec["note"], "run 'threadwatch snapshot' to keep the packets")

    def test_the_daily_summary_never_saves_however_loud_it_is_set(self):
        # [summary] severity is how loudly the digest is delivered, not a
        # claim that something critical happened.
        self.cfg.snapshot_on_critical = True
        self.cfg.summary_severity = "critical"
        self.cfg.summary_hour = 0                         # any hour of the day will do
        pipe = self._pipe()
        pipe.snapshotter = lambda label, trigger: self.fail("saved for the daily summary")
        pipe.ingest(frame(1_700_000_000.0, ROUTER))
        pipe._maybe_summarize(1_700_000_000.0 + 12 * 3600, 0x4e21)
        summaries = [r for r in pipe.events.records if r["event"] == "daily_summary"]
        self.assertEqual(len(summaries), 1)
        self.assertNotIn("auto_snapshot", summaries[0])

    def test_auto_snapshot_cooldown_survives_a_restart(self):
        self.cfg.snapshot_on_critical = True
        t0 = 1_700_000_000.0
        # The trigger in the manifest says which of these the recorder took,
        # as it does for retention: the label is the operator's to choose, and
        # "auto-investigation" below is one somebody asked for by name.
        for age, label, trigger in ((2 * 3600, "auto-storm", "phase_locked_storm"),
                                    (30 * 3600, "auto-storm", "phase_locked_storm"),
                                    (60, "auto-investigation", "manual"),
                                    (60, "manual", "manual")):
            stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime(t0 - age))
            inc = self.cfg.snapshots_dir / f"{stamp}_{label}"
            inc.mkdir(parents=True)
            (inc / "manifest.json").write_text(json.dumps({"trigger": trigger, "label": label}))
        pipe = self._pipe()                                # a restart mid-storm
        saved = []
        pipe.snapshotter = lambda label, trigger: saved.append(label)
        pipe.detector.storm_active = True
        pipe.detector.storm_details = {"period": 80.5, "onsets": [1.0, 2.0, 3.0]}
        pipe.detector.add_frame = lambda ts: setattr(pipe.detector, "storm_active", True)
        pipe.ingest(frame(t0, ROUTER))                     # 2 h after the last auto snapshot: held
        pipe.ingest(frame(t0 + 5 * 3600, ROUTER))          # 7 h after it: saved again
        storms = [r["auto_snapshot"] for r in pipe.events.records if r["event"] == "phase_locked_storm"]
        self.assertEqual(storms, [None, "auto-phase_locked_storm"])
        self.assertEqual(saved, ["auto-phase_locked_storm"])
        self.assertEqual(Pipeline(self.cfg, NullEventLog(), stub_decryptor(), ephemeral=True)._last_auto_snapshot, 0.0)

    def test_a_snapshot_named_auto_by_hand_does_not_hold_the_cooldown(self):
        """The cooldown was reconstructed from the "auto-" label while
        retention already read the manifest trigger. A snapshot somebody saved
        as `threadwatch snapshot auto-investigation` therefore suppressed
        automatic capture of a later storm for six hours after a restart --
        and it predates the incident, so it holds none of the evidence."""
        self.cfg.snapshot_on_critical = True
        t0 = 1_700_000_000.0
        stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime(t0 - 60))
        inc = self.cfg.snapshots_dir / f"{stamp}_auto-investigation"
        inc.mkdir(parents=True)
        (inc / "manifest.json").write_text(json.dumps({"trigger": "manual", "label": "auto-investigation"}))
        pipe = self._pipe()
        self.assertEqual(pipe._last_auto_snapshot, 0.0)
        saved = []
        pipe.snapshotter = lambda label, trigger: saved.append(label)
        pipe.detector.storm_active = True
        pipe.detector.storm_details = {"period": 80.5, "onsets": [1.0, 2.0, 3.0]}
        pipe.detector.add_frame = lambda ts: setattr(pipe.detector, "storm_active", True)
        pipe.ingest(frame(t0, ROUTER))
        self.assertEqual(saved, ["auto-phase_locked_storm"])

    def test_a_copy_cut_short_by_the_last_run_does_not_hold_the_cooldown(self):
        self.cfg.snapshot_on_critical = True
        t0 = 1_700_000_000.0
        stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime(t0 - 600))
        half = self.cfg.snapshots_dir / ".staging" / f"{stamp}_auto-storm"    # the run died 10 min ago, mid-copy
        half.mkdir(parents=True)
        (half / "threadwatch-20231114-21.pcap").write_bytes(b"ring")
        pipe = self._pipe()
        failed = [r for r in pipe.events.records if r["event"] == "snapshot_failed"]
        self.assertEqual([r["label"] for r in failed], ["auto-storm"])
        self.assertIn("cut short", failed[0]["note"])
        self.assertFalse(half.exists())
        self.assertEqual(pipe._last_auto_snapshot, 0.0)
        saved = []
        pipe.snapshotter = lambda label, trigger: saved.append(label)
        pipe.detector.storm_active = True
        pipe.detector.storm_details = {"period": 80.5, "onsets": [1.0, 2.0, 3.0]}
        pipe.detector.add_frame = lambda ts: setattr(pipe.detector, "storm_active", True)
        pipe.ingest(frame(t0, ROUTER))                     # the storm still running is saved now
        self.assertEqual(saved, ["auto-phase_locked_storm"])

    def test_the_snapshot_holds_the_storm_event_that_called_for_it(self):
        # BUG-11: the copy was started before the storm event was logged,
        # so a worker that reached the event directory first left the
        # snapshot without the record that explains it. Running the copy
        # in the ingest thread is the worker-first order, forced.
        from threadwatch.events import EventLog
        from threadwatch.review import snapshots
        self.cfg.snapshot_on_critical = True
        self.cfg.ring_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg.ring_dir / "threadwatch-20231114-22.pcap").write_bytes(b"ring")
        log = EventLog(self.cfg.events_dir)
        pipe = Pipeline(self.cfg, log, stub_decryptor())
        pipe.snapshotter = pipe._save_snapshot_now
        pipe.detector.storm_active = True
        pipe.detector.storm_details = {"period": 80.5, "onsets": [1.0, 2.0, 3.0]}
        pipe.detector.add_frame = lambda ts: setattr(pipe.detector, "storm_active", True)
        t0 = 1_700_000_000.0
        pipe.ingest(frame(t0, ROUTER))
        inc = snapshots(self.cfg.snapshots_dir)
        self.assertEqual([i["label"] for i in inc], ["auto-phase_locked_storm"])
        copied = self.cfg.snapshots_dir / inc[0]["name"] / "events" / log.path_for(t0).name
        recs = [json.loads(line) for line in copied.read_text().splitlines()]
        storms = [r for r in recs if r["event"] == "phase_locked_storm"]
        self.assertEqual([r["auto_snapshot"] for r in storms], ["auto-phase_locked_storm"])
        # The live log has both, the storm first.
        live = [json.loads(line) for line in log.path_for(t0).read_text().splitlines()]
        self.assertEqual([r["event"] for r in live if r["event"] == "phase_locked_storm"], ["phase_locked_storm"])

    def test_a_failed_snapshot_is_retried_after_a_hold_not_six_hours(self):
        from threadwatch import snapshot as snapshot_mod
        self.cfg.snapshot_on_critical = True
        pipe = self._pipe()
        attempts = []

        def flaky(cfg, label, trigger=None):
            attempts.append(label)
            self.assertEqual(trigger, "phase_locked_storm")
            if len(attempts) == 1:
                raise OSError(28, "No space left on device")
            return cfg.snapshots_dir / f"20231114T221500_{label}", 3

        original = snapshot_mod.save_snapshot
        snapshot_mod.save_snapshot = flaky
        try:
            pipe.snapshotter = pipe._save_snapshot_now                # in this thread, so each outcome is known at once
            pipe.detector.storm_active = True
            pipe.detector.storm_details = {"period": 80.5, "onsets": [1.0, 2.0, 3.0]}
            pipe.detector.add_frame = lambda ts: setattr(pipe.detector, "storm_active", True)
            t0 = 1_700_000_000.0
            for dt in (0, 31 * 60, 2 * 3600):             # the storm event repeats every 30 min at most
                pipe.ingest(frame(t0 + dt, ROUTER))
        finally:
            snapshot_mod.save_snapshot = original
        storms = [r["auto_snapshot"] for r in pipe.events.records if r["event"] == "phase_locked_storm"]
        self.assertEqual(storms, ["auto-phase_locked_storm",           # failed; retried; then the real cooldown
                                  "auto-phase_locked_storm", None])
        self.assertEqual(attempts, ["auto-phase_locked_storm"] * 2)
        failed = [r for r in pipe.events.records if r["event"] == "snapshot_failed"]
        self.assertEqual(len(failed), 1)
        self.assertIn("No space left", failed[0]["note"])
        self.assertIn("tries again", failed[0]["note"])
        self.assertEqual([r["ring_files"] for r in pipe.events.records if r["event"] == "snapshot_saved"], [3])

    def test_snapshots_off_by_default_and_never_in_replay(self):
        for ephemeral in (False, True):
            self.cfg.snapshot_on_critical = ephemeral        # on only for the replay case
            pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor(), ephemeral=ephemeral)
            pipe.snapshotter = lambda label, trigger: self.fail("saved")
            pipe.detector.storm_active = True
            pipe.detector.storm_details = {"period": 60.0, "onsets": [1.0, 2.0, 3.0]}
            pipe.ingest(frame(1_700_000_000.0, ROUTER))
            rec = [r for r in pipe.events.records if r["event"] == "phase_locked_storm"][0]
            self.assertIsNone(rec["auto_snapshot"])

    def test_the_background_copy_logs_the_snapshot(self):
        pipe = self._pipe()
        self.cfg.ring_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg.ring_dir / "threadwatch-20231114-22.pcap").write_bytes(b"ring")
        pipe._save_snapshot_now("auto-storm", "phase_locked_storm")
        rec = [r for r in pipe.events.records if r["event"] == "snapshot_saved"][0]
        self.assertEqual(rec["ring_files"], 1)
        self.assertTrue(rec["path"].endswith("_auto-storm"))
        self.assertTrue((Path(rec["path"]) / "threadwatch-20231114-22.pcap").exists())

    def test_each_automatic_snapshot_prunes_the_oldest_ones_before_it_copies(self):
        # Nothing but this prunes a snapshot, and each is a whole ring:
        # four automatic snapshots a day for ever fills the card the ring lives on.
        from threadwatch.review import snapshots
        pipe = self._pipe()
        self.cfg.keep_snapshots = 2
        self.cfg.ring_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg.ring_dir / "threadwatch-20231114-22.pcap").write_bytes(b"ring")
        self.cfg.snapshots_dir.mkdir(parents=True, exist_ok=True)
        for name, trigger in (("20231101T000000_auto-storm", "phase_locked_storm"),
                              ("20231102T000000_auto-storm", "phase_locked_storm"),
                              ("20231103T000000_the-night-it-broke", "manual")):
            d = self.cfg.snapshots_dir / name
            d.mkdir()
            (d / "manifest.json").write_text(json.dumps({"format": 1, "trigger": trigger}))
        pipe._save_snapshot_now("auto-storm", "phase_locked_storm")
        kept = sorted(i["name"] for i in snapshots(self.cfg.snapshots_dir))
        self.assertEqual(kept[:2], ["20231102T000000_auto-storm", "20231103T000000_the-night-it-broke"])
        self.assertTrue(kept[2].endswith("_auto-storm"))       # the one just taken
        pruned = [r for r in pipe.events.records if r["event"] == "snapshots_pruned"]
        self.assertEqual([r["removed"] for r in pruned], [["20231101T000000_auto-storm"]])

    def test_keeping_every_automatic_snapshot_deletes_none_of_them(self):
        # -1 is the no-cap sentinel. Subtracting the room for the copy about
        # to be taken turned it into 0, which deleted every automatic
        # snapshot on disk: each save destroyed the evidence it was set to
        # keep for ever.
        from threadwatch.review import snapshots
        pipe = self._pipe()
        self.cfg.keep_snapshots = -1
        self.cfg.ring_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg.ring_dir / "threadwatch-20231114-22.pcap").write_bytes(b"ring")
        self.cfg.snapshots_dir.mkdir(parents=True, exist_ok=True)
        for name in ("20231101T000000_auto-storm", "20231102T000000_auto-storm"):
            (self.cfg.snapshots_dir / name).mkdir()
        pipe._save_snapshot_now("auto-storm", "phase_locked_storm")
        kept = sorted(i["name"] for i in snapshots(self.cfg.snapshots_dir))
        self.assertEqual(kept[:2], ["20231101T000000_auto-storm", "20231102T000000_auto-storm"])
        self.assertEqual(len(kept), 3)                     # the two old ones and the new one
        self.assertEqual([r for r in pipe.events.records if r["event"] == "snapshots_pruned"], [])

    def test_keeping_no_snapshots_takes_none(self):
        # 0 is a count of snapshots to keep, so it takes none at all rather
        # than copying the whole ring and deleting it at the next storm.
        # The critical event is still logged and still alerts.
        self.cfg.snapshot_on_critical = True
        self.cfg.keep_snapshots = 0
        pipe = self._pipe()
        pipe.snapshotter = lambda label, trigger: self.fail("copied the ring with keep_snapshots = 0")
        pipe.detector.storm_active = True
        pipe.detector.storm_details = {"period": 80.5, "onsets": [1.0, 2.0, 3.0]}
        pipe.detector.add_frame = lambda ts: setattr(pipe.detector, "storm_active", True)
        pipe.ingest(frame(1_700_000_000.0, ROUTER))
        storms = [r for r in pipe.events.records if r["event"] == "phase_locked_storm"]
        self.assertEqual([r["auto_snapshot"] for r in storms], [None])
        self.assertFalse(self.cfg.snapshots_dir.exists())   # nothing was copied

    def test_a_snapshot_that_would_crowd_the_ring_out_is_refused_not_attempted(self):
        # A snapshot is a second copy of the ring. Taking one that leaves
        # the ring less room than it still needs trades a week of recording
        # for one snapshot, and the recorder exits 1 when the card fills.
        from threadwatch import review
        pipe = self._pipe()
        self.cfg.ring_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg.ring_dir / "threadwatch-20231114-22.pcap").write_bytes(b"ring")
        pipe._last_auto_snapshot = 1_700_000_000.0
        real = review.storage
        review.storage = lambda cfg: {**real(cfg), "disk_free": 1000, "ring_bytes": 900,
                                      "ring_needs_bytes": 500}
        try:
            pipe._save_snapshot_now("auto-storm", "phase_locked_storm")
        finally:
            review.storage = real
        self.assertEqual([r for r in pipe.events.records if r["event"] == "snapshot_saved"], [])
        skipped = [r for r in pipe.events.records if r["event"] == "snapshot_skipped"]
        self.assertEqual(len(skipped), 1)
        self.assertIn("delete snapshots", skipped[0]["note"])
        # Nothing was kept, so the six-hour hold must not stand either.
        self.assertEqual(pipe._last_auto_snapshot,
                         1_700_000_000.0 - pipe.AUTO_SNAPSHOT_COOLDOWN_S + pipe.AUTO_SNAPSHOT_RETRY_S)

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

    def test_device_resolves_every_address_of_a_name_listed_twice(self):
        from threadwatch.device import resolve_target
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


def poll(ts, src, seq, dst="0000", counter=None):
    """A secured data request from ``src``: the command id is authenticated
    and unreadable, as a Thread poll's is (cmd None; is_poll takes it)."""
    return Frame(ts=ts, raw=b"", psdu=psdu_for(src, ftype=3, seq=seq, dst=dst, counter=counter),
                 rssi=-60.0, channel=None, lqi=None,
                 ftype=3, cmd=None, seq=seq, dst_pan=OWN_PAN, dst=dst, src_pan=OWN_PAN, src=src)


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
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        for i in range(12):                                # 12 distinct polls, nobody answers
            pipe.ingest(poll(t + 10 * i, SENSOR, 100 + i))
            pipe.ingest(poll(t + 10 * i + 0.3, SENSOR, 100 + i))   # a MAC retry: same seq, counts once
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        # Logged at once, at notice: the page waits for [polls] confirm_s.
        self.assertEqual((ev["severity"], ev["confirmed"], ev["name"], ev["acked_polls"]),
                         ("notice", False, "Porch Sensor", 5))
        self.assertEqual(ev["unanswered_polls"], 10)      # fired at the tenth, not later
        self.assertGreaterEqual(ev["starved_for_s"], 60)
        self.assertIn("no device_quiet will follow", ev["note"])
        self.assertIn("paged if its polls are still unanswered in 10 min", ev["note"])
        self.assertEqual(pipe.devices[SENSOR].confirm_at, ev["ts"] + 600)
        self.assertEqual(pipe.seen.table[SENSOR]["starve_confirm_at"], ev["ts"] + 600)
        pipe.ingest(poll(t + 200, SENSOR, 200))
        pipe.ingest(ack(t + 200.001, 200))
        rec = self._events(pipe, "poll_answered")
        self.assertEqual(len(rec), 1)
        self.assertIn("before the starvation was confirmed: it was logged, not paged", rec[0]["note"])
        self.assertEqual(self._events(pipe, "poll_starvation"), evs)          # never paged
        self.assertFalse(pipe.devices[SENSOR].starved)
        self.assertIsNone(pipe.devices[SENSOR].confirm_at)
        for key in ("starved", "starve_confirm_at", "starve_since"):
            self.assertNotIn(key, pipe.seen.table[SENSOR])
        self.assertEqual(pipe.devices[SENSOR].unanswered_polls, 0)
        self.assertEqual(pipe.devices[SENSOR].acked_polls, 6)

    def test_starvation_survives_a_restart_and_is_closed_by_the_first_answered_poll(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        for i in range(12):
            pipe.ingest(poll(t + 10 * i, SENSOR, 100 + i))
        self.assertEqual(len(self._events(pipe, "poll_starvation")), 1)
        self.assertTrue(pipe.seen.table[SENSOR]["starved"])
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())          # DeviceStats start empty
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

    def test_an_open_starvation_is_not_announced_again_by_every_restart(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        for i in range(12):
            pipe.ingest(poll(t + 10 * i, SENSOR, 100 + i))
        self.assertEqual(len(self._events(pipe, "poll_starvation")), 1)
        logged_at = self._events(pipe, "poll_starvation")[0]["ts"]
        pipe.seen.save()
        paged = []
        for run in range(3):                                  # the watchdog restarts the daemon every 3 min
            pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
            t += 200
            for i in range(12):                               # still nobody answers
                pipe.ingest(poll(t + 10 * i, SENSOR, (run * 20 + i) & 0xFF))
            paged += self._events(pipe, "poll_starvation")
            self.assertTrue(pipe.seen.table[SENSOR]["starved"])
            pipe.seen.save()
        # The threshold is not announced again by any run; the page behind
        # confirm_s fires once, in the run whose unanswered poll passes the
        # mark the row remembered (runs 0 and 1 end before it).
        self.assertEqual([(e["severity"], e["confirmed"]) for e in paged], [("warning", True)])
        self.assertGreaterEqual(paged[0]["ts"], logged_at + 600)
        self.assertNotIn("starve_confirm_at", pipe.seen.table[SENSOR])
        pipe.ingest(poll(t + 300, SENSOR, 250))
        pipe.ingest(ack(t + 300.001, 250))
        rec = self._events(pipe, "poll_answered")
        self.assertEqual(len(rec), 1)                                      # closed once, by the ACK
        self.assertNotIn("before the starvation was confirmed", rec[0]["note"])
        self.assertNotIn("starved", pipe.seen.table[SENSOR])
        # A new episode after the close is announced again.
        before = len(self._events(pipe, "poll_starvation"))
        for i in range(12):
            pipe.ingest(poll(t + 400 + 10 * i, SENSOR, 30 + i))
        self.assertEqual(len(self._events(pipe, "poll_starvation")), before + 1)

    def test_starvation_that_begins_right_after_a_restart_is_announced(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        self.assertTrue(pipe.seen.table[SENSOR]["polls_acked"])
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())          # acked_polls is zero again
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
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        pipe.ingest(poll(t, SENSOR, 100))                  # unicast poll, still pending
        pipe.ingest(frame(t + 0.01, ROUTER, rssi=-55.0, seq=100, dst="ffff"))   # a router's advertisement, same seq
        pipe.ingest(ack(t + 0.02, 100))                    # the ACK the sniffer hears next
        self.assertEqual((pipe.devices[ROUTER].tx, pipe.devices[ROUTER].acked), (0, 0))
        self.assertEqual(pipe.devices[SENSOR].acked, 5)    # nothing new was credited to anyone

    def test_an_ack_a_second_late_is_not_this_polls_ack(self):
        """An ACK follows its frame in under a millisecond. Anything later is
        a different exchange, and pairing with it would keep a device whose
        parent has stopped answering looking healthy."""
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        for i in range(12):
            pipe.ingest(poll(t + 10 * i, SENSOR, 100 + i))
            pipe.ingest(ack(t + 10 * i + 1.0, 100 + i))    # a second later: not this poll's ACK
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual(len(evs), 1)
        self.assertEqual((evs[0]["unanswered_polls"], evs[0]["acked_polls"]), (10, 5))
        self.assertEqual(self._events(pipe, "poll_answered"), [])

    def test_an_ack_stamped_before_its_frame_is_not_that_frames_ack(self):
        """The window was one-sided: anything under 50 ms later paired, and so
        did an ACK a hundred seconds earlier. A backward clock step or an
        out-of-order imported capture inflated the ACK rate and cleared a poll
        that was still unanswered. The retry detector already required 0.0 <=."""
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = 1_700_000_000.0
        pipe.ingest(poll(t, SENSOR, 42))
        pipe.ingest(ack(t - 100.0, 42))
        self.assertEqual((pipe.devices[SENSOR].tx, pipe.devices[SENSOR].acked), (1, 0))
        self.assertEqual(pipe.devices[SENSOR].poll_pending_seq, 42)

    def test_a_device_never_answered_is_not_starving(self):
        # The sniffer may simply not hear that parent's ACKs.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = 1_700_000_000.0
        for i in range(40):
            pipe.ingest(poll(t + 10 * i, SENSOR, i))
        self.assertEqual(self._events(pipe, "poll_starvation"), [])

    def test_ten_quick_polls_are_not_enough_without_the_minute(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 3)
        for i in range(11):
            pipe.ingest(poll(t + 0.5 * i, SENSOR, 50 + i))   # 11 polls in 5 s: fast-poll burst
        self.assertEqual(self._events(pipe, "poll_starvation"), [])
        pipe.ingest(poll(t + 90, SENSOR, 70))                # ...and one more, past the minute
        self.assertEqual(len(self._events(pipe, "poll_starvation")), 1)

    def test_a_silence_before_the_polls_is_not_time_spent_polling_unanswered(self):
        # The episode clock was anchored on the previous pending poll,
        # however old: a device back from three hours of silence with one
        # poll left pending had the silence counted as unanswered polling.
        # The same burst, too short to report on its own, became a page
        # "over 10845 s", and the review row claimed three hours.
        def burst(pipe, t, seq0):
            pipe.ingest(poll(t, SENSOR, seq0))                           # one unanswered
            for i in range(1, 12):
                pipe.ingest(poll(t + 5 * i, SENSOR, (seq0 + i) & 0xFF))  # eleven more, 5 s apart: 55 s
            return t + 55
        quiet = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(quiet, 1_700_000_000.0, 5)
        burst(quiet, t, 10)
        self.assertEqual(self._events(quiet, "poll_starvation"), [])       # 55 s of evidence: not a minute
        silent = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(silent, 1_700_000_000.0, 5)
        silent.ingest(poll(t, SENSOR, 10))                                 # left pending...
        silent.periodic(t + 3600)
        self.assertEqual([r["addr"] for r in silent.events.records if r["event"] == "device_quiet"], [SENSOR])
        end = burst(silent, t + 3 * 3600, 11)                              # ...three hours of silence, same burst
        self.assertEqual(self._events(silent, "poll_starvation"), [])
        # Keep polling unanswered past the minute: reported, and the span
        # is the polling, not the silence.
        silent.ingest(poll(end + 10, SENSOR, 30))
        evs = self._events(silent, "poll_starvation")
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["unanswered_polls"], 12)
        self.assertAlmostEqual(evs[0]["starved_for_s"], 65, delta=1)
        self.assertAlmostEqual(evs[0]["since"], t + 3 * 3600, delta=1)
        self.assertIn("12 times over 65 s", evs[0]["note"])

    def _starve(self, pipe, t, seq0):
        for i in range(12):
            pipe.ingest(poll(t + 10 * i, SENSOR, (seq0 + i) & 0xFF))
        return t + 120

    def test_a_second_episode_soon_after_the_first_ended_is_a_notice_until_the_rearm_passes(self):
        self.cfg.poll_confirm_s = 0                            # the threshold record is the subject here
        # 2026-09-04: 37 episodes in six hours from one sensor, each closed
        # by an ordinary ACK. One page, then notices while it flaps.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
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
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        (Path(self.tmp.name) / "devices.json").write_text(json.dumps([
            {"name": "Porch Sensor", "extendedAddress": SENSOR},
            {"name": "Hall Router", "extendedAddress": ROUTER}]))
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
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

    def test_rearm_zero_pages_every_episode(self):
        self.cfg.poll_confirm_s = 0                            # the threshold record is the subject here
        self.cfg.poll_rearm_s = 0
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._starve(pipe, t, 100)
        t = self._answered_polls(pipe, t, 3, seq0=120)
        self._starve(pipe, t + 60, 130)
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual([e["severity"] for e in evs], ["warning", "warning"])

    def test_the_hold_down_survives_a_restart(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._starve(pipe, t, 100)
        t = self._answered_polls(pipe, t, 3, seq0=120)
        self.assertIn("starve_closed", pipe.seen.table[SENSOR])
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe2, t + 60, 2, seq0=125)  # answered polls this run, then starved
        self._starve(pipe2, t, 130)
        evs = self._events(pipe2, "poll_starvation")
        self.assertEqual([e["severity"] for e in evs], ["notice"])
        self.assertEqual(evs[0]["episode"], 2)

    def _unanswered(self, pipe, t, n, seq0, gap=10):
        for i in range(n):
            pipe.ingest(poll(t + gap * i, SENSOR, (seq0 + i) & 0xFF))
        return t + gap * n

    def test_a_starvation_still_unanswered_after_the_window_is_paged_once(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._unanswered(pipe, t, 12, 100)                 # logged at notice at the tenth poll
        logged = self._events(pipe, "poll_starvation")[0]
        t = self._unanswered(pipe, t, 70, 112, gap=10)         # 700 s more: crosses the 600 s mark
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual([(e["severity"], e["confirmed"]) for e in evs], [("notice", False), ("warning", True)])
        page = evs[1]
        self.assertGreaterEqual(page["ts"], logged["ts"] + 600)
        self.assertLess(page["ts"], logged["ts"] + 620)          # the first unanswered poll past the mark
        self.assertEqual((page["name"], page["episode"], page["since"], page["reception"]),
                         ("Porch Sensor", 1, logged["since"], "good"))
        self.assertEqual(page["starved_for_s"], round(page["ts"] - logged["since"]))
        self.assertIn("still polling its parent router 0 (0000) with no acknowledgement 10 min after "
                      "the starvation was logged", page["note"])
        self.assertIn("no device_quiet will follow", page["note"])
        self.assertIsNone(pipe.devices[SENSOR].confirm_at)
        self.assertNotIn("starve_confirm_at", pipe.seen.table[SENSOR])
        self.assertTrue(pipe.seen.table[SENSOR]["starved"])           # still open
        self._unanswered(pipe, t, 100, 200)                            # another 1000 s: no second page
        self.assertEqual(len(self._events(pipe, "poll_starvation")), 2)
        pipe.ingest(poll(t + 2000, SENSOR, 50))
        pipe.ingest(ack(t + 2000.001, 50))
        rec = self._events(pipe, "poll_answered")
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0]["note"], "its polls are acknowledged again")
        self.assertNotIn("starve_since", pipe.seen.table[SENSOR])

    def test_a_starvation_that_recovers_inside_the_window_is_never_paged(self):
        # The 2026-09-04 morning: every episode that recovered by itself did
        # so within eight minutes. Those are the log's business, not the phone's.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._unanswered(pipe, t, 12, 100)
        t = self._unanswered(pipe, t, 47, 112)                 # 470 s more, still inside 600
        t = self._answered_polls(pipe, t, 2, seq0=160)
        self.assertEqual([e["severity"] for e in self._events(pipe, "poll_starvation")], ["notice"])
        self.assertEqual(len(self._events(pipe, "poll_answered")), 1)
        # A fresh episode over an hour later starts the window over.
        t = self._unanswered(pipe, t + 4000, 12, 170)
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual([(e["severity"], e["episode"]) for e in evs], [("notice", 1), ("notice", 1)])
        self.assertEqual(pipe.devices[SENSOR].confirm_at, evs[1]["ts"] + 600)

    def test_the_page_rests_on_an_unanswered_poll_not_on_the_clock(self):
        # A device that stops polling altogether is the quiet detector's; the
        # page needs a poll past the mark that nobody answered.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._unanswered(pipe, t, 12, 100)
        pipe.periodic(t + 1200)                                # 20 min of nothing from the device
        self.assertEqual(len(self._events(pipe, "poll_starvation")), 1)
        pipe.ingest(poll(t + 1300, SENSOR, 150))               # one poll, answered: closed, never paged
        pipe.ingest(ack(t + 1300.001, 150))
        self.assertEqual([e["severity"] for e in self._events(pipe, "poll_starvation")], ["notice"])
        self.assertEqual(len(self._events(pipe, "poll_answered")), 1)
        pipe.seen.save()                                       # periodic() saved the open row; save the close too
        pipe2 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe2, t + 5000, 5, seq0=10)
        t = self._unanswered(pipe2, t, 12, 100)
        pipe2.ingest(poll(t + 1300, SENSOR, 150))              # after 20 min silent: this poll pends...
        self.assertEqual(len(self._events(pipe2, "poll_starvation")), 1)
        pipe2.ingest(poll(t + 1310, SENSOR, 151))              # ...and the next shows it went unanswered
        evs = self._events(pipe2, "poll_starvation")
        self.assertEqual([(e["severity"], e["confirmed"]) for e in evs], [("notice", False), ("warning", True)])
        self.assertEqual(evs[1]["ts"], t + 1310)

    def test_the_pending_page_survives_a_restart_and_an_ack_first_cancels_it(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._unanswered(pipe, t, 12, 100)
        logged = self._events(pipe, "poll_starvation")[0]
        pipe.seen.save()
        # Down across the mark, back up, and the device is still unanswered:
        # the second poll of the new run is the evidence, and the page names
        # the whole span from the row's remembered start.
        pipe2 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        self.assertEqual(pipe2.devices[SENSOR].confirm_at, logged["ts"] + 600)
        pipe2.ingest(poll(t + 900, SENSOR, 130))
        self.assertEqual(self._events(pipe2, "poll_starvation"), [])
        pipe2.ingest(poll(t + 910, SENSOR, 131))
        evs = self._events(pipe2, "poll_starvation")
        self.assertEqual([(e["severity"], e["confirmed"], e["acked_polls"]) for e in evs], [("warning", True, 0)])
        self.assertEqual((evs[0]["since"], evs[0]["starved_for_s"]),
                         (logged["since"], round(t + 910 - logged["since"])))
        self.assertIn("16 min after the starvation was logged", evs[0]["note"])
        self.assertNotIn("starve_confirm_at", pipe2.seen.table[SENSOR])
        # ...whereas an ACK first closes it quietly: logged, never paged.
        pipe.seen.save()                                       # back to the state before the page
        pipe3 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        pipe3.ingest(poll(t + 900, SENSOR, 130))
        pipe3.ingest(ack(t + 900.001, 130))
        self.assertEqual(self._events(pipe3, "poll_starvation"), [])
        rec = self._events(pipe3, "poll_answered")
        self.assertEqual(len(rec), 1)
        self.assertIn("before the starvation was confirmed", rec[0]["note"])
        for key in ("starved", "starve_confirm_at", "starve_since"):
            self.assertNotIn(key, pipe3.seen.table[SENSOR])
        pipe3.seen.save()
        pipe4 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        self.assertIsNone(pipe4.devices.get(SENSOR) and pipe4.devices[SENSOR].confirm_at)

    def test_confirm_zero_pages_at_the_threshold_as_before(self):
        self.cfg.poll_confirm_s = 0
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._unanswered(pipe, t, 100, 100)                # 1000 s unanswered
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual(len(evs), 1)
        self.assertEqual((evs[0]["severity"], evs[0]["unanswered_polls"]), ("warning", 10))
        self.assertNotIn("confirmed", evs[0])
        self.assertNotIn("paged if", evs[0]["note"])
        self.assertIsNone(pipe.devices[SENSOR].confirm_at)
        self.assertNotIn("starve_confirm_at", pipe.seen.table[SENSOR])

    def test_the_window_is_the_configured_length(self):
        self.cfg.poll_confirm_s = 120
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._unanswered(pipe, t, 12, 100)
        logged = self._events(pipe, "poll_starvation")[0]
        self.assertIn("still unanswered in 2 min", logged["note"])
        self._unanswered(pipe, t, 20, 112)
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual([e["severity"] for e in evs], ["notice", "warning"])
        self.assertGreaterEqual(evs[1]["ts"], logged["ts"] + 120)
        self.assertLess(evs[1]["ts"], logged["ts"] + 140)
        self.assertIn("2 min after the starvation was logged", evs[1]["note"])

    def test_a_notice_for_a_marginal_or_flapping_device_is_never_confirmed(self):
        # Those two are "logged, not paged" for their own reasons; the window
        # does not turn them into a page later.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._unanswered(pipe, t, 12, 100)
        t = self._answered_polls(pipe, t, 3, seq0=120)         # episode 1 closed inside its window
        t = self._unanswered(pipe, t + 300, 12, 130)           # episode 2, 5 min later: flapping
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual([(e["severity"], e["episode"]) for e in evs], [("notice", 1), ("notice", 2)])
        self.assertNotIn("confirmed", evs[1])
        self.assertIsNone(pipe.devices[SENSOR].confirm_at)
        self.assertNotIn("starve_confirm_at", pipe.seen.table[SENSOR])
        self._unanswered(pipe, t, 100, 150)                    # 1000 s more unanswered: still no page
        self.assertEqual(len(self._events(pipe, "poll_starvation")), 2)
        # Marginal, the same.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = 1_700_000_000.0
        for i in range(5):
            f = poll(t + 5 * i, SENSOR, i)
            f.rssi = -90.0
            pipe.ingest(f)
            pipe.ingest(ack(t + 5 * i + 0.001, i))
        for i in range(100):
            f = poll(t + 25 + 10 * i, SENSOR, (100 + i) & 0xFF)
            f.rssi = -90.0
            pipe.ingest(f)
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual([(e["severity"], e["reception"]) for e in evs], [("notice", "marginal")])
        self.assertNotIn("confirmed", evs[0])

    def test_a_confirmed_page_then_a_quick_relapse_is_a_flapping_notice(self):
        # The rearm hold-down counts from the close of an episode whether or
        # not it was paged, so the page-then-flap sequence is one page.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        t = self._unanswered(pipe, t, 80, 100)                 # 800 s: logged, then paged
        t = self._answered_polls(pipe, t, 3, seq0=200)
        t = self._unanswered(pipe, t + 300, 80, 210)           # relapse 5 min later, for another 800 s
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual([(e["severity"], e.get("confirmed"), e["episode"]) for e in evs],
                         [("notice", False, 1), ("warning", True, 1), ("notice", None, 2)])
        self.assertEqual(len(self._events(pipe, "poll_answered")), 1)

    def test_a_marginal_device_starving_is_a_notice(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
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


class RetransmissionConfirmTest(unittest.TestCase):
    """The first elevated minute is logged; the page waits until the rate has
    stayed up for [retransmissions] confirm_s."""

    T = 1_700_000_000.0
    SENDERS = ["%016x" % (0x1000 + k) for k in range(8)]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text("[]")
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")

    def tearDown(self):
        self.tmp.cleanup()

    def _pipe(self):
        return Pipeline(self.cfg, NullEventLog(), stub_decryptor())

    def window(self, pipe, w, dup_frac, frames=200, senders=None):
        """One minute of frames, dup_frac of them repeats within 2 s of the
        original, spread over eight senders to broadcast (mesh-wide) unless
        one sender is given (one link)."""
        senders = senders or self.SENDERS
        dups = round(frames * dup_frac)
        uniq = frames - dups
        base, gap = self.T + w * 60, 50.0 / max(uniq, 1)
        for j in range(uniq):
            at = base + j * gap
            src = senders[j % len(senders)]
            dst = "ffff" if len(senders) > 1 else "0000"
            pipe.ingest(frame(at, src, seq=j & 0xFF, dst=dst))
            for r in range((dups * (j + 1)) // uniq - (dups * j) // uniq):
                pipe.ingest(frame(at + 0.1 * (r + 1), src, seq=j & 0xFF, dst=dst))

    def run_minutes(self, pipe, fracs, start=0, **kw):
        """Windows start..start+len(fracs); the last one is closed by the
        first frame of the following minute, so run one more quiet window."""
        for i, frac in enumerate(fracs):
            self.window(pipe, start + i, frac, **kw)
        return start + len(fracs)

    @staticmethod
    def _events(pipe):
        return [r for r in pipe.events.records if r["event"] == "retransmission_elevation"]

    @staticmethod
    def _shape(evs):
        return [(e["severity"], e.get("confirmed")) for e in evs]

    def test_the_first_elevated_minute_is_logged_and_the_fifth_pages_with_the_baseline_frozen(self):
        pipe = self._pipe()
        w = self.run_minutes(pipe, [0.05] * 10)                 # a quiet baseline of 5%
        w = self.run_minutes(pipe, [0.5] * 20, start=w)          # twenty minutes at 50%
        self.run_minutes(pipe, [0.05], start=w)                  # closes the last one
        evs = self._events(pipe)
        self.assertEqual(self._shape(evs), [("notice", False), ("warning", True)])
        first, page = evs
        self.assertEqual(first["ts"], self.T + 11 * 60)          # the close of the first elevated minute
        self.assertEqual(page["ts"], self.T + 15 * 60)           # the close of the fifth
        self.assertEqual(page["sustained_s"], 300)
        self.assertEqual((first["baseline"], page["baseline"]), (0.05, 0.05))
        # The median of the last 30 windows is 50% by now; the frozen
        # baseline is why the elevation is still open and did not re-open
        # as a second notice after the 15 min cooldown.
        self.assertGreater(sorted(pipe.retrans_counts)[len(pipe.retrans_counts) // 2], 0.4)
        self.assertIsNotNone(pipe._retrans_since)
        self.assertIn("retransmissions elevated for 5 min: retries spread across devices", page["note"])
        self.assertLess(page["top_share"], 0.5)
        self.assertEqual(page["top_target"], "broadcast")
        self.assertIn("paged if the rate is still up in 5 min", first["note"])
        self.assertNotIn("sustained_s", first)

    def test_a_backward_clock_step_does_not_turn_ordinary_traffic_into_retransmissions(self):
        # dup_recent maps (src, seq, pan) -> ts and a frame is a repeat if
        # ts - last < 2 s. A MAC sequence number is a byte, so every device
        # re-uses each key once per 256 frames: after a step back, every
        # cached stamp sat in the future, ts - last was negative, and the
        # window rate went to 1.0 for a whole sequence cycle. A false
        # mesh-wide page, with nothing changed about the mesh.
        pipe = self._pipe()
        clock = {"wall": self.T, "mono": 0.0}
        pipe._wall, pipe._mono, pipe._clock = (lambda: clock["wall"]), (lambda: clock["mono"]), (self.T, 0.0)
        self.run_minutes(pipe, [0.0] * 12)                      # twelve clean minutes
        self.assertEqual(self._events(pipe), [])
        clock.update(wall=self.T + 12 * 60 - 1800, mono=12 * 60.0)
        pipe.periodic(clock["wall"])                            # the clock steps back 30 min
        self.assertEqual([r["step_s"] for r in pipe.events.records if r["event"] == "clock_step"], [-1800])
        self.assertEqual(pipe.dup_recent, {})
        self.run_minutes(pipe, [0.0] * 15, start=-18)           # the same clean traffic, corrected clock
        self.assertEqual(self._events(pipe), [])
        self.assertEqual(max(pipe.retrans_counts), 0.0)

    def test_the_share_that_decides_log_versus_page_is_pinned_at_a_half(self):
        # top_share >= 0.5 is the switch between "one pair hammering each
        # other, a chronic bad link at the RF edge: log it" and "retries
        # spread across the mesh, the storm precursor this detector exists
        # for: page it". Every neighbouring rule is pinned; this one was
        # not, and moving it emits a real mesh-wide storm as a notice,
        # which a sink at min_severity = warning never sees.
        A, B, C = self.SENDERS[:3]

        def first_minute(dups):
            self.cfg.retrans_confirm_s = 0        # the old detector: the first elevated minute decides
            pipe = self._pipe()
            pipe.retrans_counts.extend([0.0] * 30)
            pipe._win_dups = sum(dups.values())
            pipe._win_dup_by = dups
            pipe._retrans_window(self.T + 60, 0.5)
            evs = self._events(pipe)
            self.assertEqual(len(evs), 1, dups)
            return evs[0]["severity"], round(evs[0]["top_share"], 3)

        self.assertEqual(first_minute({(A, "ffff"): 6, (B, "ffff"): 2, (C, "ffff"): 2}), ("notice", 0.6))
        self.assertEqual(first_minute({(A, "ffff"): 5, (B, "ffff"): 3, (C, "ffff"): 2}), ("notice", 0.5))
        self.assertEqual(first_minute({(A, "ffff"): 4, (B, "ffff"): 3, (C, "ffff"): 3}), ("warning", 0.4))

        def confirmed_page(dups):
            self.cfg.retrans_confirm_s = 300
            pipe = self._pipe()
            pipe.retrans_counts.extend([0.0] * 30)
            pipe._win_dups, pipe._win_dup_by = sum(dups.values()), dups
            for minute in range(1, 8):            # the first is the notice; the fifth completes confirm_s
                pipe._retrans_window(self.T + minute * 60, 0.5)
            evs = self._events(pipe)
            self.assertEqual([e.get("confirmed") for e in evs], [False, True], dups)
            return evs[1]["severity"]

        self.assertEqual(confirmed_page({(A, "ffff"): 5, (B, "ffff"): 3, (C, "ffff"): 2}), "notice")
        self.assertEqual(confirmed_page({(A, "ffff"): 4, (B, "ffff"): 3, (C, "ffff"): 3}), "warning")

    def test_calm_low_traffic_minutes_end_an_elevation_rather_than_sustain_it(self):
        # A minute under 100 frames never reached the detector, so it could
        # not close an elevation: a one-minute burst, ten quiet minutes of
        # 40 frames each and another one-minute burst paged as twelve
        # minutes of sustained retries.
        pipe = self._pipe()
        w = self.run_minutes(pipe, [0.05] * 10)
        w = self.run_minutes(pipe, [0.5], start=w, frames=120)
        w = self.run_minutes(pipe, [0.0] * 10, start=w, frames=40)
        w = self.run_minutes(pipe, [0.5], start=w, frames=120)
        w = self.run_minutes(pipe, [0.05] * 3, start=w)
        evs = self._events(pipe)
        self.assertEqual(self._shape(evs), [("notice", False)])  # the second burst is inside the notice cooldown
        self.assertNotIn("sustained_s", evs[0])
        self.assertIsNone(pipe._retrans_since)                   # two calm full minutes closed it
        # Thin minutes for longer than the cooldown: the elevation is over,
        # and the next burst is a new one with its own notice (an open
        # elevation would have given it none).
        w = self.run_minutes(pipe, [0.05] * 12, start=w)
        w = self.run_minutes(pipe, [0.5], start=w, frames=120)
        w = self.run_minutes(pipe, [0.0] * 16, start=w, frames=40)
        w = self.run_minutes(pipe, [0.5], start=w, frames=120)
        self.run_minutes(pipe, [0.05] * 3, start=w)
        self.assertEqual(self._shape(self._events(pipe)), [("notice", False)] * 3)

    def test_a_restart_during_an_elevation_neither_loses_the_page_nor_makes_it_normal(self):
        # Restarted in the second elevated minute, the detector used to
        # start its baseline from that minute's rate, and the same rate
        # ever after was never twice the baseline: the page for a running
        # elevation was lost for as long as it ran.
        pipe = self._pipe()
        w = self.run_minutes(pipe, [0.05] * 30)
        w = self.run_minutes(pipe, [0.5], start=w)
        self.run_minutes(pipe, [0.5], start=w)                   # closes the first elevated minute: the notice
        self.assertEqual(self._shape(self._events(pipe)), [("notice", False)])
        again = self._pipe()                                     # the restart, on the same state directory
        self.assertEqual(list(again.retrans_counts), list(pipe.retrans_counts))
        self.assertEqual(again._retrans_since, pipe._retrans_since)
        self.assertEqual((again._retrans_base, again._retrans_alerted), (0.05, pipe._retrans_alerted))
        # Both hear the same minutes from here on (the restarted one the
        # minute that was open at the restart too).
        w = self.run_minutes(pipe, [0.5] * 60, start=w + 1)
        self.run_minutes(again, [0.5] * 61, start=w - 61)
        self.run_minutes(pipe, [0.05], start=w)
        self.run_minutes(again, [0.05], start=w)
        self.assertEqual(self._shape(self._events(pipe)), [("notice", False), ("warning", True)])
        self.assertEqual(self._shape(self._events(again)), [("warning", True)])
        page, page_again = self._events(pipe)[-1], self._events(again)[-1]
        self.assertEqual((page_again["ts"], page_again["sustained_s"], page_again["baseline"]),
                         (page["ts"], page["sustained_s"], page["baseline"]))
        self.assertEqual(page["sustained_s"], 300)

    def test_after_a_restart_the_page_waits_for_minutes_actually_observed(self):
        pipe = self._pipe()
        w = self.run_minutes(pipe, [0.05] * 10)
        w = self.run_minutes(pipe, [0.5] * 3, start=w)
        self.run_minutes(pipe, [0.5], start=w)                   # three elevated minutes closed, the fourth open
        self.assertEqual(self._shape(self._events(pipe)), [("notice", False)])
        again = self._pipe()
        # Down for ten minutes, then the rate is still up: the elevation
        # is the same one (no second notice), but the ten unobserved
        # minutes count for nothing, and the page waits for five more.
        w = self.run_minutes(again, [0.5] * 6, start=w + 10)     # minutes 23..28
        self.run_minutes(again, [0.05] * 3, start=w)
        evs = self._events(again)
        self.assertEqual(self._shape(evs), [("warning", True)])
        self.assertEqual(evs[0]["ts"], self.T + 25 * 60)         # the close of the fifth observed minute (24)
        self.assertEqual(evs[0]["sustained_s"], 300)
        self.assertIsNone(again._retrans_since)                  # and two calm minutes closed it

    def test_retransmission_state_that_will_not_load_starts_the_detector_afresh(self):
        pipe = self._pipe()
        self.run_minutes(pipe, [0.05] * 3)
        pipe.retrans_path.write_text("{")
        again = self._pipe()
        self.assertEqual(list(again.retrans_counts), [])
        pipe.retrans_path.write_text(json.dumps({"closed": 1, "rates": ["x"]}))
        self.assertEqual(list(self._pipe().retrans_counts), [])
        self.assertEqual(self._pipe().ephemeral, False)

    def test_a_minute_or_two_of_interference_is_logged_and_never_paged(self):
        # 2026-09-05 05:33: a microwave. One record in the log, nothing on the phone.
        pipe = self._pipe()
        w = self.run_minutes(pipe, [0.05] * 10)
        w = self.run_minutes(pipe, [0.5, 0.5], start=w)
        w = self.run_minutes(pipe, [0.05] * 16, start=w)          # quiet through the 15 min cooldown
        w = self.run_minutes(pipe, [0.6], start=w)               # another burst
        self.run_minutes(pipe, [0.05] * 3, start=w)
        evs = self._events(pipe)
        self.assertEqual(self._shape(evs), [("notice", False), ("notice", False)])
        self.assertIsNone(pipe._retrans_since)                   # both elevations closed

    def test_one_quiet_minute_inside_an_elevation_does_not_end_it_and_two_do(self):
        pipe = self._pipe()
        w = self.run_minutes(pipe, [0.05] * 10)
        # Elevated, elevated, elevated, quiet, elevated: the fifth minute
        # since the start completes the window, lull included.
        w = self.run_minutes(pipe, [0.5, 0.5, 0.5, 0.05, 0.5], start=w)
        self.run_minutes(pipe, [0.05], start=w)
        evs = self._events(pipe)
        self.assertEqual(self._shape(evs), [("notice", False), ("warning", True)])
        self.assertEqual(evs[1]["ts"], self.T + 15 * 60)
        # Two quiet minutes close it; the next elevated minute is a new
        # elevation, whose notice is due once the 15 min cooldown has passed.
        w = self.run_minutes(pipe, [0.05] * 14, start=w + 1)     # 16 quiet minutes in all since the page
        w = self.run_minutes(pipe, [0.5], start=w)
        self.run_minutes(pipe, [0.05], start=w)
        evs = self._events(pipe)
        self.assertEqual(self._shape(evs), [("notice", False), ("warning", True), ("notice", False)])

    def test_confirm_zero_is_the_old_detector(self):
        self.cfg.retrans_confirm_s = 0
        pipe = self._pipe()
        w = self.run_minutes(pipe, [0.05] * 10)
        w = self.run_minutes(pipe, [0.5] * 20, start=w)
        self.run_minutes(pipe, [0.05], start=w)
        evs = self._events(pipe)
        # Pages at the first elevated minute, and again 15 min later while it
        # lasts (the old cooldown); never a confirmed record.
        self.assertEqual([e["severity"] for e in evs], ["warning", "warning"])
        self.assertEqual([e["ts"] for e in evs], [self.T + 11 * 60, self.T + 27 * 60])
        for e in evs:
            self.assertNotIn("confirmed", e)
            self.assertNotIn("sustained_s", e)
            self.assertNotIn("paged if", e["note"])

    def test_one_bad_link_sustained_is_confirmed_at_notice(self):
        pipe = self._pipe()
        w = self.run_minutes(pipe, [0.05] * 10)
        w = self.run_minutes(pipe, [0.5] * 6, start=w, senders=[STRANGER])
        self.run_minutes(pipe, [0.05], start=w)
        evs = self._events(pipe)
        self.assertEqual(self._shape(evs), [("notice", False), ("notice", True)])
        self.assertEqual((evs[1]["top_share"], evs[1]["sustained_s"]), (1.0, 300))
        self.assertIn("a failing link between those two", evs[1]["note"])

    def test_the_window_is_the_configured_length(self):
        self.cfg.retrans_confirm_s = 120
        pipe = self._pipe()
        w = self.run_minutes(pipe, [0.05] * 10)
        w = self.run_minutes(pipe, [0.5] * 3, start=w)
        self.run_minutes(pipe, [0.05], start=w)
        evs = self._events(pipe)
        self.assertEqual(self._shape(evs), [("notice", False), ("warning", True)])
        self.assertEqual((evs[1]["ts"], evs[1]["sustained_s"]), (self.T + 12 * 60, 120))
        self.assertIn("still up in 2 min", evs[0]["note"])
        self.assertIn("elevated for 2 min", evs[1]["note"])

    def test_a_thin_minute_is_neither_elevated_nor_a_lull_nor_sustained(self):
        pipe = self._pipe()
        w = self.run_minutes(pipe, [0.05] * 10)
        w = self.run_minutes(pipe, [0.5, 0.5], start=w)
        w = self.run_minutes(pipe, [0.0] * 3, start=w, frames=20)  # too few frames to judge
        w = self.run_minutes(pipe, [0.5], start=w)
        self.run_minutes(pipe, [0.5], start=w)                    # closes the sixth minute: three seen up so far
        self.assertEqual(self._shape(self._events(pipe)), [("notice", False)])
        self.assertIsNotNone(pipe._retrans_since)                 # still the same elevation...
        w = self.run_minutes(pipe, [0.5, 0.5], start=w + 1)
        self.run_minutes(pipe, [0.05], start=w)
        evs = self._events(pipe)
        self.assertEqual(self._shape(evs), [("notice", False), ("warning", True)])
        self.assertEqual(evs[1]["ts"], self.T + 18 * 60)          # ...paged at the fifth minute seen up
        self.assertEqual(evs[1]["sustained_s"], 300)

    def test_pages_are_fifteen_minutes_apart_however_the_rate_flaps(self):
        pipe = self._pipe()
        w = self.run_minutes(pipe, [0.05] * 10)
        # Five up, two down, five up, two down, seven up: three elevations.
        w = self.run_minutes(pipe, ([0.5] * 5 + [0.05] * 2) * 2 + [0.5] * 7, start=w)
        self.run_minutes(pipe, [0.05], start=w)
        evs = self._events(pipe)
        pages = [e for e in evs if e.get("confirmed")]
        notices = [e for e in evs if e.get("confirmed") is False]
        # The second elevation (minutes 17-21) completed 14 min after the
        # first page: held back, like its opening notice. The third completed
        # at minute 29, also inside the 15 min, and pages at the first
        # elevated minute past them (16 min after the first page). Both
        # openings were inside the notice cooldown too.
        self.assertEqual([e["ts"] for e in pages], [self.T + 15 * 60, self.T + 31 * 60])
        self.assertEqual([e["ts"] for e in notices], [self.T + 11 * 60])
        self.assertEqual(pages[1]["sustained_s"], 420)

    def test_a_confirmed_page_joins_the_row_its_notice_opened(self):
        from threadwatch.review import group_episodes
        recs = [
            {"ts": self.T, "event": "retransmission_elevation", "severity": "notice", "confirmed": False,
             "rate": 0.25, "baseline": 0.05, "top_sender": "Kitchen Light", "top_target": "broadcast",
             "top_share": 0.14, "note": "retries spread across devices"},
            {"ts": self.T + 240, "event": "retransmission_elevation", "severity": "warning", "confirmed": True,
             "rate": 0.31, "baseline": 0.05, "sustained_s": 300, "top_sender": "Basement AQ",
             "top_target": "Irrigation", "top_share": 0.3, "note": "retransmissions elevated for 5 min"},
        ]
        eps = group_episodes(recs)
        self.assertEqual([(e["title"], e["count"], e["severity"], e["max_rate"]) for e in eps],
                         [("retransmissions: Kitchen Light -> broadcast", 2, "warning", 0.31)])
        # A confirmed record with nothing open within the hour is a row of its own.
        eps = group_episodes(recs[1:])
        self.assertEqual([(e["title"], e["count"]) for e in eps], [("retransmissions: Basement AQ -> Irrigation", 1)])


class RecorderStartTest(unittest.TestCase):
    """Every start says how long the recorder was not listening and how
    the run before it ended, from the note record.record_exit left."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text("[]")
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")
        self.cfg.state_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self.tmp.cleanup()

    def _start(self, at):
        from unittest import mock
        with mock.patch("threadwatch.pipeline.time.time", lambda: at):
            pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        starts = [r for r in pipe.events.records if r["event"] == "recorder_started"]
        self.assertEqual(len(starts), 1)
        return pipe, starts[0]

    def _note(self, **fields):
        (self.cfg.state_dir / "last-exit.json").write_text(json.dumps(fields))

    def _status(self, **fields):
        (self.cfg.state_dir / "status.json").write_text(json.dumps(fields))

    def test_the_first_start_ever_says_so(self):
        _pipe, rec = self._start(1_700_000_000.0)
        self.assertEqual((rec["severity"], rec["cause"], rec["gap_s"], rec["last_frame_ts"], rec["stopped_ts"]),
                         ("info", "first_start", None, None, None))
        self.assertIn("first start", rec["note"])

    def test_a_stall_restart_carries_the_gap_the_cause_and_when_the_run_left(self):
        T = 1_700_000_000.0
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        pipe.ingest(frame(T, ROUTER))
        pipe.seen.save()
        self._status(updated=T + 180, last_frame_ts=T)
        self._note(ts=T + 190, code=2, reason="stalled", last_frame_ts=T)
        _pipe, rec = self._start(T + 2400)
        self.assertEqual((rec["severity"], rec["cause"], rec["gap_s"], rec["last_frame_ts"],
                          rec["stopped_ts"], rec["exit_code"]),
                         ("notice", "stalled", 2400, T, T + 190, 2))
        self.assertIn("not listening for 40 min", rec["note"])
        self.assertIn("off for 37 min", rec["note"])
        self.assertIn("stalled", rec["note"])
        # The note is consumed: the next start does not read this run's
        # end off the one before, and without a note the end is unknown.
        self.assertFalse((self.cfg.state_dir / "last-exit.json").exists())
        _pipe, rec = self._start(T + 2500)
        self.assertEqual((rec["severity"], rec["cause"], rec["stopped_ts"]), ("notice", "unknown", None))
        self.assertIn("power cut", rec["note"])

    def test_a_requested_stop_is_only_information(self):
        T = 1_700_000_000.0
        self._status(updated=T + 5, last_frame_ts=T)
        self._note(ts=T + 5, code=0, reason="stopped", last_frame_ts=T)
        _pipe, rec = self._start(T + 60)
        self.assertEqual((rec["severity"], rec["cause"], rec["gap_s"], rec["stopped_ts"]),
                         ("info", "stopped", 60, T + 5))

    def test_a_note_stamped_outside_the_gap_or_unreadable_is_not_trusted(self):
        T = 1_700_000_000.0
        self._status(updated=T, last_frame_ts=T)
        self._note(ts=T - 100, code=0, reason="stopped")           # before the last frame: another clock
        _pipe, rec = self._start(T + 60)
        self.assertEqual((rec["cause"], rec["stopped_ts"]), ("stopped", None))
        self.assertNotIn("off for", rec["note"])
        (self.cfg.state_dir / "last-exit.json").write_text("{not json")
        _pipe, rec = self._start(T + 120)
        self.assertEqual((rec["cause"], rec["severity"]), ("unknown", "notice"))
        self.assertFalse((self.cfg.state_dir / "last-exit.json").exists())


class EventRetentionTest(unittest.TestCase):
    def test_the_recorder_prunes_the_log_once_a_day_and_replay_never(self):
        import contextlib
        import io

        from threadwatch.events import EventLog
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(data_dir=Path(d) / "data", events_keep_days=7, summary_hour=-1)
            log = EventLog(cfg.events_dir)
            now = time.time()
            for back in (30, 10, 8, 6, 1):
                log.emit("e", "info", now - back * 86400)
            with contextlib.redirect_stderr(io.StringIO()):
                pipe = Pipeline(cfg, log, stub_decryptor())
                pipe.periodic(now)
                days = sorted(p.stem for p in cfg.events_dir.glob("*.jsonl"))
                self.assertEqual(len(days), 3)                         # 6 and 1 days ago, and today's start
                log.emit("e", "info", now - 20 * 86400)
                pipe.periodic(now + 60)                                # same day: not again
                self.assertEqual(len(list(cfg.events_dir.glob("*.jsonl"))), 4)
                pipe.periodic(now + 86400)                             # the next day: pruned
                self.assertEqual(len(list(cfg.events_dir.glob("*.jsonl"))), 3)
                log.emit("e", "info", now - 20 * 86400)
                Pipeline(cfg, log, stub_decryptor(), ephemeral=True).periodic(now + 2 * 86400)
                self.assertEqual(len(list(cfg.events_dir.glob("*.jsonl"))), 4)   # replay touches nothing


class ObservedNamesTest(unittest.TestCase):
    def test_junk_names_do_not_accumulate_and_recurring_ones_stay(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(data_dir=Path(d) / "data")
            pipe = Pipeline(cfg, NullEventLog(), stub_decryptor())
            for _ in range(3):
                pipe._note_observed_name(SENSOR, "office-aq-1a2b.local")
            for i in range(500):                              # a junk match every few hours, for ever
                pipe._note_observed_name(SENSOR, f"junk{i}.x[L(")
            seen = pipe.observed_names[SENSOR]
            self.assertLessEqual(len(seen), Pipeline.OBSERVED_NAMES_MAX)
            self.assertEqual(seen["office-aq-1a2b.local"], 3)
            for _ in range(20):                               # a second real name recurs and is kept
                pipe._note_observed_name(SENSOR, "office-aq-1a2b._hap._tcp.local")
            self.assertEqual(seen["office-aq-1a2b._hap._tcp.local"], 20)
            self.assertLessEqual(len(seen), Pipeline.OBSERVED_NAMES_MAX)


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
        dec = stub_decryptor()
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
        # No browse thread outlives the Pipeline that started it. One that
        # does is still inside browse() when the next module patches an
        # mdns global, and dies there with a traceback belonging to nobody
        # (tests/no_lan).
        import threading

        def browsing():
            return [t.name for t in threading.enumerate() if t.name == "mdns-browse" and t.is_alive()]

        deadline = time.monotonic() + 2      # a stubbed browse returns at once; this is not a wait
        while time.monotonic() < deadline and browsing():
            time.sleep(0.02)
        leaked = browsing()
        self.tmp.cleanup()
        self.assertEqual(leaked, [])

    @staticmethod
    def router(host, ext, instance="AppleTV Living Room", vendor="Apple", model="BorderRouter"):
        return {"hostname": host, "ext": ext, "instance": instance, "vendor": vendor, "model": model}

    def test_rebooted_hub_keeps_its_name_and_the_old_address_retires(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 3600                              # real-clock times: the restart below judges silences by now
        pipe.ingest(frame(t, self.OLD))
        pipe.ingest(frame(t, self.OTBR))
        pipe._apply_border_routers([self.router(self.HOST, self.OLD),
                                    self.router("homeassistant-otbr.local", self.OTBR, "HA OTBR #AF1B",
                                                "Home Assistant")], t)
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
        self.assertEqual((ev[0]["addr"], ev[0]["previous"], ev[0]["name"]),
                         (self.NEW, self.OLD, "Living Room Apple TV"))
        self.assertIn("nothing to edit", ev[0]["note"])
        self.assertEqual(pipe.names.name(self.NEW), "Living Room Apple TV")
        self.assertEqual(pipe.seen.table[self.OLD]["rotated_to"], self.NEW)
        self.assertEqual(pipe.routers[self.HOST]["previous"], [{"addr": self.OLD, "until": t + 600}])
        pipe.periodic(t + 3000)                            # 50 min on: the old address never reads as quiet
        self.assertNotIn(self.OLD, [r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"])
        pipe.ingest(frame(time.time() - 60, self.NEW))
        # The binding survives a restart, through the state file.
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        self.assertEqual(pipe2.names.name(self.NEW), "Living Room Apple TV")
        self.assertEqual(pipe2.names.border_routers[self.NEW]["hostname"], self.HOST)
        self.assertEqual(pipe2.names.resolve("living room apple tv")[0], [self.OLD, self.NEW])
        self.assertNotIn(self.OLD, [r["addr"] for r in pipe2.events.records if r["event"] == "device_quiet"])
        self.assertEqual(pipe2.routers[self.HOST]["addr"], self.NEW)

    def test_the_retired_address_list_is_bounded_and_holds_each_address_once(self):
        # Every rotation appended and nothing pruned, and each entry feeds
        # DeviceNames.by_addr and the device history, where it multiplies
        # a full-history scan. Apple hubs rotate slowly, so this is years,
        # but the list had no bound at all.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 86400
        addrs = ["%016x" % (0xc0ffee0000000000 + i) for i in range(Pipeline.ROUTER_PREVIOUS_MAX + 5)]
        for i, ext in enumerate(addrs):
            pipe.ingest(frame(t + i, ext))
            pipe._apply_border_routers([self.router(self.HOST, ext)], t + i)
        kept = pipe.routers[self.HOST]["previous"]
        self.assertEqual(len(kept), Pipeline.ROUTER_PREVIOUS_MAX)
        self.assertEqual([e["addr"] for e in kept], addrs[-Pipeline.ROUTER_PREVIOUS_MAX - 1:-1])

        # A -> B -> A keeps one entry per address, with the later stamp.
        back = addrs[-2]
        pipe.ingest(frame(t + 1000, back))
        pipe._apply_border_routers([self.router(self.HOST, back)], t + 1000)
        kept = pipe.routers[self.HOST]["previous"]
        self.assertEqual(len([e for e in kept if e["addr"] == addrs[-1]]), 1)
        self.assertNotIn(back, [e["addr"] for e in kept])           # it is the live one again

    def test_a_flood_of_invented_hostnames_cannot_grow_the_router_table(self):
        """A hostname naming an address already heard on air goes past the
        pending cap into self.routers, which had no cap and no expiry. One
        authenticated address and a browse full of made-up hostnames grew RAM
        and border-routers.json without limit, and every browse rewrote the
        whole file. Hostnames cost the responder nothing."""
        import contextlib
        import io
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 3600
        pipe.ingest(frame(t, self.OLD))
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            pipe._apply_border_routers([self.router(f"fake-{i}.local", self.OLD, instance=f"Fake {i}")
                                        for i in range(1000)], t + 60)
        self.assertEqual(list(pipe.routers), [self.HOST])          # the one that already answers for it
        self.assertEqual(pipe.routers[self.HOST]["addr"], self.OLD)
        self.assertEqual(pipe.routers[self.HOST]["instance"], "AppleTV Living Room")
        self.assertEqual(out.getvalue().count("already answers for"), 1000)
        self.assertLessEqual(len(pipe.routers), pipe.ROUTERS_MAX)

    def test_an_unclaimed_binding_nothing_readvertises_expires(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 3600
        pipe.ingest(frame(t, self.OLD))
        pipe.ingest(frame(t, self.OTBR))
        pipe._apply_border_routers([self.router(self.HOST, self.OLD),
                                    self.router("homeassistant-otbr.local", self.OTBR, "HA OTBR")], t)
        self.assertEqual(sorted(pipe.routers), [self.HOST, "homeassistant-otbr.local"])
        pipe._apply_border_routers([self.router("homeassistant-otbr.local", self.OTBR, "HA OTBR")],
                                   t + pipe.ROUTER_STALE_S + 60)
        # Nothing re-advertised the Apple hub for a month and no entry names
        # its hostname, so its binding goes; the one devices.json names by
        # borderRouter stays whatever happens.
        self.assertEqual(list(pipe.routers), ["homeassistant-otbr.local"])

    def test_a_hostname_cannot_claim_an_address_the_inventory_gives_elsewhere(self):
        """Hearing an address on air proves that device exists; it does not
        prove an unauthenticated hostname advertising it belongs to that
        device. A responder could advertise a hub's hostname carrying another
        device's address: the hub's entry took that address, the other
        device's traffic was presented under the hub's name, and the hub's own
        row was retired -- which exempts it from quiet alerts for as long as
        it stays silent."""
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Living Room Apple TV", "extendedAddress": self.OLD, "borderRouter": self.HOST},
            {"name": "Hall Sensor", "extendedAddress": self.OTBR}]))
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 3600
        pipe.ingest(frame(t, self.OLD))
        pipe.ingest(frame(t + 10, self.OTBR))              # the sensor, heard most recently
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t + 20)
        self.assertEqual(pipe.routers[self.HOST]["addr"], self.OLD)
        # The forged advertisement: the hub's hostname, the sensor's address.
        pipe._apply_border_routers([self.router(self.HOST, self.OTBR)], t + 30)
        self.assertEqual(pipe.routers[self.HOST]["addr"], self.OLD)          # unmoved
        self.assertEqual(pipe.names.name(self.OTBR), "Hall Sensor")          # still its own
        self.assertNotIn("rotated_to", pipe.seen.table[self.OLD])            # the hub is not retired
        conflicts = [r for r in pipe.events.records if r["event"] == "border_router_address_conflict"]
        self.assertEqual(len(conflicts), 1)
        self.assertEqual((conflicts[0]["addr"], conflicts[0]["name"], conflicts[0]["claimed_by"]),
                         (self.OTBR, "Hall Sensor", "Living Room Apple TV"))
        pipe._apply_border_routers([self.router(self.HOST, self.OTBR)], t + 700)
        self.assertEqual(len([r for r in pipe.events.records
                              if r["event"] == "border_router_address_conflict"]), 1)   # said once
        # And the hub's own silence is still reported: nothing retired it.
        pipe.periodic(t + 31 * 60)
        self.assertIn(self.OLD, [r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"])

    def test_an_address_never_heard_on_air_is_not_believed(self):
        # Anyone on the LAN can advertise _meshcop._udp with any address in
        # it. A forged record must not retire the real row (silencing its
        # quiet alerts) or hand the name to the forged address.
        import contextlib
        import io
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 7200
        pipe.ingest(frame(t, self.OLD))
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        forged = "deadbeefdeadbeef"
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
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
        self.assertEqual((pipe.routers[self.HOST]["addr"], pipe.names.name(self.NEW)),
                         (self.NEW, "Living Room Apple TV"))
        self.assertEqual(pipe.seen.table[self.OLD]["rotated_to"], self.NEW)

    def test_forged_advertisements_cannot_grow_the_waiting_room_without_bound(self):
        import contextlib
        import io
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 3600
        pipe.ingest(frame(t, self.OLD))
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        forged = [self.router(f"h{i}.local", f"{i:016x}") for i in range(1000)]    # never heard on air
        with contextlib.redirect_stderr(io.StringIO()):
            pipe._apply_border_routers(forged, t + 1)
            pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 2)   # the real hub, rebooted
        self.assertLessEqual(len(pipe._pending_routers), Pipeline.PENDING_MAX)
        self.assertLessEqual(len(pipe._unheard_logged), Pipeline.LOGGED_MAX)
        # The newest record still waits, and binds when its address is heard.
        self.assertIn(self.NEW, pipe._pending_routers)
        pipe.ingest(frame(t + 10, self.NEW))
        self.assertEqual(pipe.names.name(self.NEW), "Living Room Apple TV")
        self.assertEqual(pipe.routers[self.HOST]["addr"], self.NEW)
        # The once-per-address memory is bounded too, at the price of a
        # repeated line past the bound; within it a record is logged once.
        few = [self.router(f"s{i}.local", f"{0xabc0000 + i:016x}") for i in range(10)]
        with contextlib.redirect_stderr(io.StringIO()) as out:
            pipe._apply_border_routers(forged, t + 20)
            pipe._apply_border_routers(few, t + 30)
            pipe._apply_border_routers(few, t + 40)
        self.assertLessEqual(len(pipe._pending_routers), Pipeline.PENDING_MAX)
        self.assertLessEqual(len(pipe._unheard_logged), Pipeline.LOGGED_MAX)
        self.assertEqual(out.getvalue().count("has not been heard on air"), len(forged) + len(few))

    def test_a_stale_answer_naming_an_old_address_does_not_retire_the_live_one(self):
        # The hub used OLD, rebooted, and uses NEW; both have been heard on
        # air. A reflector's cache (or a replay) then answers a browse with
        # the OLD record. Whichever address was heard on air last is the
        # live one: the stale record is ignored, NEW stays judged, and OLD
        # stays retired.
        import contextlib
        import io
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 7200
        pipe.ingest(frame(t, self.OLD))
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        pipe.ingest(frame(t + 600, self.NEW))
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 700)
        self.assertEqual(pipe.seen.table[self.OLD]["rotated_to"], self.NEW)
        pipe.ingest(frame(t + 800, self.NEW))
        out = io.StringIO()
        with contextlib.redirect_stderr(out):
            for tick in (900, 1500):
                pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t + tick)
        self.assertEqual(out.getvalue().count("stale record, ignored"), 1)
        self.assertNotIn("rotated_to", pipe.seen.table[self.NEW])
        self.assertEqual(pipe.seen.table[self.OLD]["rotated_to"], self.NEW)
        self.assertEqual(pipe.routers[self.HOST]["addr"], self.NEW)
        self.assertEqual(len([r for r in pipe.events.records if r["event"] == "border_router_address_changed"]), 1)
        pipe.periodic(t + 7000)                             # NEW silent since t+800: that is the silence to report
        self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"], [self.NEW])
        # A retired address heard on air is live, whatever mDNS said, and
        # its silences count again.
        with contextlib.redirect_stderr(io.StringIO()):
            pipe.ingest(frame(t + 7100, self.OLD))
        self.assertNotIn("rotated_to", pipe.seen.table[self.OLD])
        pipe.periodic(t + 7100 + 31 * 60)
        self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"], [self.NEW, self.OLD])
        # And a genuine rotation back (NEW -> OLD, OLD now the one on air)
        # retires NEW and leaves OLD judged, not both retired.
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t + 7200)
        self.assertEqual(pipe.seen.table[self.NEW]["rotated_to"], self.OLD)
        self.assertNotIn("rotated_to", pipe.seen.table[self.OLD])

    def test_a_rotation_closes_the_silence_announced_for_the_old_address(self):
        from threadwatch.review import group_episodes
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
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
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
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
        pipe._apply_border_routers([self.router("homepod-kitchen.local", "8899aabbccddeeff", "HomePod Kitchen")],
                                   t + 1200)
        ev = [r for r in pipe.events.records if r["event"] == "border_router_address_changed"]
        self.assertEqual((ev[0]["name"], ev[0]["previous"]), (None, "0011223344556677"))
        self.assertIn("Not in devices.json", ev[0]["note"])

    def test_browse_runs_in_a_thread_and_applies_on_the_next_tick(self):
        from threadwatch import mdns
        self.cfg.border_router_browse_s = 600
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
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


    def test_a_browse_that_raises_anything_is_a_log_line_not_a_dead_thread(self):
        # An mDNS responder is anyone on the LAN, so browse() parses
        # untrusted input. The thread body caught OSError only, so a
        # ValueError or struct.error past the parser's own guards escaped
        # a daemon thread nothing joins: a bare traceback on stderr, no
        # browse result, and the next tick starting another.
        import contextlib
        import io
        import struct

        from threadwatch import mdns
        self.cfg.border_router_browse_s = 600
        original = mdns.browse
        try:
            for exc in (OSError(101, "Network is unreachable"),
                        ValueError("truncated name"),
                        struct.error("unpack requires a buffer of 10 bytes"),
                        IndexError("index out of range")):
                pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())

                def raising(timeout=4.0, _exc=exc, **kw):
                    raise _exc

                mdns.browse = raising
                t = 1_700_000_000.0
                with contextlib.redirect_stderr(io.StringIO()) as out:
                    pipe.periodic(t)
                    pipe._browse_thread.join(5)
                    self.assertFalse(pipe._browse_thread.is_alive(), exc)
                    pipe.periodic(t + 30)              # the tick that reads the result
                self.assertIn(f"mdns browse failed: {type(exc).__name__}: {exc}", out.getvalue())
                self.assertIsNone(pipe._browse_result)
                self.assertEqual(pipe.routers, {})
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
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
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

    def _talk(self, pipe, t0, rssi, n=300, who=ROUTER):
        """n seconds of a frame a second, with the periodic tick every
        30 s as the capture loop runs it. Returns the time after."""
        for i in range(n):
            pipe.ingest(frame(t0 + i, who, rssi=rssi))
            if i % 30 == 29:
                pipe.periodic(t0 + i + 1)
        return t0 + n

    def _talk_through(self, pipe, t0, rssi, seconds, who=ROUTER):
        """Heard for five minutes in every thirty, for ``seconds``: the
        cadence of a device that is around, without a frame a second."""
        t = t0
        while t < t0 + seconds:
            self._talk(pipe, t, rssi, 300, who)
            t += 1800
            pipe.periodic(t)
        return t

    def test_fading_device_is_logged_then_recovers(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._talk(pipe, 1_700_000_000.0, -60.0)         # reference taken at -60
        self.assertEqual(pipe.seen.table[ROUTER]["rssi_ref"], -60.0)
        t = self._talk(pipe, t, -70.0, 20 * 60)              # the clock starts within the first minute
        self.assertEqual(self._events(pipe, "rssi_degradation"), [])
        t = self._talk(pipe, t, -70.0, 12 * 60)
        evs = self._events(pipe, "rssi_degradation")
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual((ev["severity"], ev["name"], ev["reference_dbm"]), ("notice", "Hall Router", -60.0))
        self.assertGreaterEqual(ev["drop_db"], 9.0)   # the per-frame EWMA rounds to 0.1 dB and settles ~1 dB short
        self.assertGreaterEqual(ev["low_for_s"], 30 * 60)
        self.assertIn("weaker than its usual -60 dBm", ev["note"])
        t = self._talk(pipe, t, -70.0, 60 * 60)              # still down: no repeat
        self.assertEqual(len(self._events(pipe, "rssi_degradation")), 1)
        t = self._talk(pipe, t, -60.0)
        rec = self._events(pipe, "rssi_recovered")
        self.assertEqual(len(rec), 1)
        self.assertEqual(rec[0]["severity"], "info")
        self.assertNotIn("rssi_degraded", pipe.seen.table[ROUTER])

    def test_daily_refresh_of_a_lasting_drop_closes_it_as_recovered(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._talk(pipe, 1_700_000_000.0, -60.0)
        t = self._talk(pipe, t, -70.0, 31 * 60)
        self.assertEqual(len(self._events(pipe, "rssi_degradation")), 1)
        self._talk_through(pipe, t, -70.0, 86400)            # a day into the drop, still heard: re-based
        rec = self._events(pipe, "rssi_recovered")
        self.assertEqual(len(rec), 1)
        self.assertIn("reference re-based", rec[0]["note"])
        self.assertEqual(rec[0]["reference_dbm"], pipe.seen.table[ROUTER]["rssi_ref"])
        self.assertNotIn("rssi_degraded", pipe.seen.table[ROUTER])

    def test_link_state_survives_a_restart(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._talk(pipe, 1_700_000_000.0, -60.0)
        t = self._talk(pipe, t, -70.0)
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        row = pipe2.seen.table[ROUTER]
        self.assertEqual(row["rssi_ref"], -60.0)
        self.assertLess(row["rssi_low_since"], t)
        self._talk(pipe2, t, -70.0, 31 * 60)                 # heard on, after the restart
        evs = self._events(pipe2, "rssi_degradation")
        self.assertEqual(len(evs), 1)
        self.assertLess(evs[0]["ts"], t + 30 * 60)             # the clock that started before the restart

    def test_a_silent_device_is_neither_degraded_nor_rebased(self):
        # BUG-09: with the rest of the mesh talking, a device that stopped
        # on a weak signal was announced degraded on its stale average and,
        # a day on, re-based to it as recovered, while it was quiet.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._talk(pipe, 1_700_000_000.0, -60.0)
        t = self._talk(pipe, t, -70.0)                       # the clock starts, then it falls silent
        t = self._talk_through(pipe, t, -60.0, 86400 + 3600, who=STRANGER)
        self.assertEqual([r["event"] for r in pipe.events.records if r["event"].startswith("rssi_")], [])
        self.assertEqual(pipe.seen.table[ROUTER]["rssi_ref"], -60.0)
        self.assertIn(ROUTER, [r["addr"] for r in self._events(pipe, "device_quiet")])
        # Back a day later, still weak: the hold resumes, it does not fire at once.
        t = self._talk(pipe, t, -70.0, 20 * 60)
        self.assertEqual(self._events(pipe, "rssi_degradation"), [])
        self._talk(pipe, t, -70.0, 12 * 60)
        evs = self._events(pipe, "rssi_degradation")
        self.assertEqual(len(evs), 1)
        self.assertLess(evs[0]["low_for_s"], 40 * 60)         # the day of silence is not held time

    def test_a_drop_the_device_can_no_longer_close_is_closed_for_it(self):
        # assess() judges the average per fresh frame, so once a degraded
        # device stops transmitting neither the recovery test nor the
        # daily refresh can ever run again: the flag stood for ever, on
        # the headline card, in ?only=down and in every daily summary,
        # naming a device that had simply gone quiet.
        from threadwatch.events import day_of
        from threadwatch.review import now_card
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._talk(pipe, 1_700_000_000.0, -60.0)
        t = self._talk(pipe, t, -70.0, 31 * 60)
        self.assertEqual(len(self._events(pipe, "rssi_degradation")), 1)
        self.assertTrue(pipe.seen.table[ROUTER]["rssi_degraded"])
        t = self._talk_through(pipe, t, -60.0, 3 * 3600, who=STRANGER)   # the router says nothing more
        self.assertIn(ROUTER, [r["addr"] for r in self._events(pipe, "device_quiet")])
        rec = self._events(pipe, "rssi_recovered")
        self.assertEqual(len(rec), 1)
        self.assertIn("stopped being heard altogether", rec[0]["note"])
        self.assertNotIn("rssi_degraded", pipe.seen.table[ROUTER])
        card = now_card(pipe.seen, pipe.names, self.cfg.events_dir, self.cfg.quiet_min_rssi_dbm,
                        day_of(t), now=t, pan_id=self.cfg.pan_id, state_dir=self.cfg.state_dir)
        self.assertEqual(card["degraded"], [])
        self.assertEqual([q["addr"] for q in card["quiet"]], [ROUTER])
        self.assertEqual(pipe.summary(t, OWN_PAN)["degraded"], [])

    def test_a_retired_address_does_not_read_signal_down_for_ever(self):
        # An Apple hub rotates: _apply_border_routers retires the old row,
        # which will never send another frame and so can never clear a
        # drop it was carrying.
        from threadwatch.review import device_rows
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._talk(pipe, 1_700_000_000.0, -60.0)
        t = self._talk(pipe, t, -70.0, 31 * 60)
        self.assertEqual(len(self._events(pipe, "rssi_degradation")), 1)
        pipe.seen.table[ROUTER]["rotated_to"] = SENSOR
        pipe.periodic(t + 60)
        rec = self._events(pipe, "rssi_recovered")
        self.assertEqual(len(rec), 1)
        self.assertIn("retired when the device rotated", rec[0]["note"])
        self.assertNotIn("rssi_degraded", pipe.seen.table[ROUTER])
        # ...and the pages do not read the flag off a retired row anyway.
        pipe.seen.table[ROUTER]["rssi_degraded"] = True
        rows = {r["addr"]: r for r in device_rows(pipe.seen, pipe.names, self.cfg.quiet_min_rssi_dbm, now=t)}
        self.assertFalse(rows[ROUTER]["degraded"])

    def test_a_starvation_the_device_can_no_longer_answer_is_closed_for_it(self):
        # The same shape: an unanswered poll is only closed by an answered
        # one, which a device that has stopped polling will never send.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._talk(pipe, 1_700_000_000.0, -60.0)
        pipe.seen.table[ROUTER]["starved"] = True
        pipe.seen.table[ROUTER]["starve_since"] = t
        t = self._talk_through(pipe, t, -60.0, 3 * 3600, who=STRANGER)
        answered = self._events(pipe, "poll_answered")
        self.assertEqual(len(answered), 1)
        self.assertIn("stopped polling altogether", answered[0]["note"])
        self.assertNotIn("starved", pipe.seen.table[ROUTER])

    def test_foreign_pan_devices_are_not_assessed(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
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
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
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
        # router quiet; PAN adopted, sensor marginal quiet, foreign PAN
        self.assertEqual((s["events_24h"]["warning"], s["events_24h"]["notice"]), (1, 3))
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
        pipe = Pipeline(self.cfg, log, stub_decryptor())
        pipe.periodic(self.DAY + 8 * 3600)
        pipe2 = Pipeline(self.cfg, EventLog(self.cfg.events_dir), stub_decryptor())
        pipe2.periodic(self.DAY + 8 * 3600 + 900)
        from threadwatch.events import read_day
        self.assertEqual(sum(r["event"] == "daily_summary" for r in read_day(self.cfg.events_dir, "2026-09-02")), 1)
        # Down through the hour: sent late, once.
        pipe3 = Pipeline(self.cfg, EventLog(self.cfg.events_dir), stub_decryptor())
        pipe3.periodic(self.DAY + 24 * 3600 + 15 * 3600)
        self.assertEqual(sum(r["event"] == "daily_summary" for r in read_day(self.cfg.events_dir, "2026-09-03")), 1)

    def test_frame_count_survives_a_restart(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self.DAY + 7 * 3600
        for i in range(100):
            pipe.ingest(frame(t + i, ROUTER, rssi=-60.0))
        pipe.periodic(t + 200)                              # persists the hourly buckets
        pipe2 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())          # a restart
        for i in range(10):
            pipe2.ingest(frame(t + 300 + i, ROUTER, rssi=-60.0))
        pipe2.periodic(self.DAY + 8 * 3600)
        s = self._summaries(pipe2.events)
        self.assertEqual(len(s), 1)
        self.assertEqual(s[0]["frames_24h"], 110)           # both runs, not just this one
        # Buckets older than the window are dropped on load and never counted.
        pipe2._frames_by_hour[int(t // 3600) - 30] = 999
        pipe2.periodic(self.DAY + 8 * 3600 + 60)
        pipe3 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        self.assertNotIn(int(t // 3600) - 30, pipe3._frames_by_hour)
        self.assertEqual(pipe3.summary(self.DAY + 8 * 3600 + 120)["frames_24h"], 110)
        self.assertEqual(Pipeline(self.cfg, NullEventLog(), stub_decryptor(), ephemeral=True)._frames_by_hour, {})

    def test_a_summary_whose_write_failed_is_retried_next_tick(self):
        class FlakyLog(NullEventLog):
            failures = 1

            def emit(self, event, *a, **kw):
                if event == "daily_summary" and self.failures:
                    self.failures -= 1
                    raise OSError(28, "No space left on device")
                return super().emit(event, *a, **kw)

        pipe = Pipeline(self.cfg, FlakyLog(), stub_decryptor())
        with self.assertRaises(OSError):
            pipe.periodic(self.DAY + 8 * 3600)
        self.assertEqual(self._summaries(pipe.events), [])
        pipe.periodic(self.DAY + 8 * 3600 + 60)             # the next tick sends it
        self.assertEqual(len(self._summaries(pipe.events)), 1)
        pipe.periodic(self.DAY + 9 * 3600)                  # and only once
        self.assertEqual(len(self._summaries(pipe.events)), 1)

    def test_disabled_and_ephemeral(self):
        self.cfg.summary_hour = -1
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        pipe.periodic(self.DAY + 9 * 3600)
        self.assertEqual(self._summaries(pipe.events), [])
        self.cfg.summary_hour = 8
        replay = Pipeline(self.cfg, NullEventLog(), stub_decryptor(), ephemeral=True)
        replay.periodic(self.DAY + 9 * 3600)
        self.assertEqual(self._summaries(replay.events), [])


class IngestGrowthGuardsTest(unittest.TestCase):
    """Two tables on the per-frame path would grow for as long as the
    recorder runs without their guards: the hourly frame counts (one
    bucket per hour for ever) and the retransmission window's (source,
    seq) table (every pair ever heard). A Pi that records for weeks
    notices; nothing else did."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = Config(data_dir=Path(self.tmp.name) / "data")

    def tearDown(self):
        self.tmp.cleanup()

    def test_frames_by_hour_keeps_the_last_26_hours(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor(), ephemeral=True)
        t0 = 1_700_000_000.0
        for h in range(40):
            for i in range(3):
                pipe.ingest(frame(t0 + h * 3600 + i, ROUTER))
        newest = int((t0 + 39 * 3600) // 3600)
        self.assertEqual(sorted(pipe._frames_by_hour), list(range(newest - 25, newest + 1)))
        self.assertEqual(set(pipe._frames_by_hour.values()), {3})
        # The summary's window (24 h back from now, whole buckets) fits inside what is kept.
        self.assertEqual(pipe.summary(t0 + 39 * 3600 + 3)["frames_24h"], 3 * 25)

    def test_the_retransmission_table_is_pruned_to_the_last_seconds_past_8192_pairs(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor(), ephemeral=True)
        t0 = 1_700_000_000.0
        senders = ["%016x" % (0x1000 + n) for n in range(33)]          # 33 x 256 sequence numbers > 8192
        n = 0
        for src in senders:
            for seq in range(256):
                if n == 8192:
                    break
                f = frame(t0 + n * 0.0001, src)
                f.seq = seq
                pipe.ingest(f)
                n += 1
        self.assertEqual(len(pipe.dup_recent), 8192)                   # full, nothing pruned yet
        for seq in range(10):                                          # ten seconds on: a new sender
            f = frame(t0 + 10 + seq * 0.0001, senders[32])
            f.seq = seq
            pipe.ingest(f)
        # The first of them tipped the table over: everything older than
        # four seconds went, and the table holds only these ten pairs.
        self.assertEqual(len(pipe.dup_recent), 10)
        self.assertEqual({k[0] for k in pipe.dup_recent}, {senders[32]})
        self.assertTrue(all(ts >= t0 + 10 for ts in pipe.dup_recent.values()))


class AckPairingWindowTest(unittest.TestCase):
    """An ACK is the previous frame's only within 50 ms of it: an
    802.15.4 ACK follows its frame inside a millisecond, and a wider
    window would pair a poll with a later ACK meant for someone else,
    which is exactly what poll starvation looks like on air. The window
    decides every acked count and every starvation verdict."""

    def test_an_ack_49_ms_late_is_paired_and_51_ms_is_not(self):
        with tempfile.TemporaryDirectory() as d:
            pipe = Pipeline(Config(data_dir=Path(d) / "data"), NullEventLog(), stub_decryptor(), ephemeral=True)
            t = 1_700_000_000.0
            pipe.ingest(poll(t, SENSOR, 1))
            pipe.ingest(ack(t + 0.049, 1))
            stats = pipe.devices[SENSOR]
            self.assertEqual((stats.acked, stats.acked_polls, stats.poll_pending_seq), (1, 1, None))
            pipe.ingest(poll(t + 5, SENSOR, 2))
            pipe.ingest(ack(t + 5.051, 2))
            self.assertEqual((stats.acked, stats.acked_polls, stats.poll_pending_seq), (1, 1, 2))   # still waiting
            pipe.ingest(poll(t + 10, SENSOR, 3))
            pipe.ingest(ack(t + 10.001, 3))
            self.assertEqual((stats.acked, stats.acked_polls, stats.poll_pending_seq), (2, 2, None))


class SummaryWindowTest(unittest.TestCase):
    """The daily summary reports the last 24 hours: which devices were
    heard in them, how many frames (whole hourly buckets that overlap
    the window) and which events. An hour would report most of the mesh
    as unheard every morning."""

    def test_the_summary_counts_the_last_24_hours_and_nothing_older(self):
        with tempfile.TemporaryDirectory() as d:
            pipe = Pipeline(Config(data_dir=Path(d) / "data"), NullEventLog(), stub_decryptor(), ephemeral=True)
            hour = 1_700_000_000 // 3600
            now = hour * 3600 + 600.0                                 # ten past an hour
            for i in range(11):
                pipe.ingest(frame(now - 25.5 * 3600 + i, STRANGER))   # bucket ends before the window: out
            for i in range(7):
                pipe.ingest(frame(now - 23.9 * 3600 + i, SENSOR))     # heard 23.9 h ago: in
            for i in range(5):
                pipe.ingest(frame(now - 600 + i, ROUTER))
            s = pipe.summary(now)
            self.assertEqual((s["frames_24h"], s["devices_heard_24h"], s["devices_tracked"]), (12, 2, 3))
            self.assertEqual(s["events_24h"], {"critical": 0, "warning": 0, "notice": 0, "info": 2})   # two first_seen
            self.assertTrue(s["note"].startswith("last 24 h: 12 frames from 2 of 3 devices"), s["note"])
            s = pipe.summary(now + 0.2 * 3600)                        # 24.1 h after the sensor: out
            self.assertEqual((s["frames_24h"], s["devices_heard_24h"]), (12, 1))


    @unittest.skipUnless(hasattr(time, "tzset"), "needs time.tzset to switch zones")
    def test_the_day_after_the_spring_clock_change_is_not_skipped(self):
        # A summary at 00:30 on the day after the change reaches back to
        # 23:30 two days before: three local days, and the middle one,
        # 23 hours long, was read by neither of the two files opened.
        import os
        saved = os.environ.get("TZ")
        os.environ["TZ"] = "America/Toronto"
        time.tzset()
        try:
            with tempfile.TemporaryDirectory() as d:
                pipe = Pipeline(Config(data_dir=Path(d) / "data"), NullEventLog(), stub_decryptor(), ephemeral=True)
                at = lambda stamp: time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M"))
                now = at("2026-03-09 00:30")
                self.assertEqual(now - 86400, at("2026-03-07 23:30"))
                pipe.events.emit("device_quiet", "warning", at("2026-03-08 12:00"), addr=SENSOR)
                pipe.events.emit("device_quiet", "warning", at("2026-03-07 23:00"), addr=ROUTER)   # before the window
                pipe.events.emit("device_quiet", "warning", at("2026-03-07 23:45"), addr=STRANGER)
                self.assertEqual(pipe.summary(now)["events_24h"]["warning"], 2)
        finally:
            if saved is None:
                os.environ.pop("TZ", None)
            else:
                os.environ["TZ"] = saved
            time.tzset()


class PollCountTest(unittest.TestCase):
    """The review rows' poll count is the pipeline's: a Data Request (MAC
    command 4, or a secured command, which carries no id), not every MAC
    command. The row's type-3 count takes in beacon requests and the
    like, and was labelled polls."""

    def test_only_data_requests_are_polls_on_the_row_and_in_the_review(self):
        from threadwatch.review import device_rows
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "devices.json").write_text("[]")
            cfg = Config(data_dir=Path(d) / "data", devices_path=Path(d) / "devices.json")
            pipe = Pipeline(cfg, NullEventLog(), stub_decryptor())
            t0 = 1_700_000_000.0
            pipe.ingest(poll(t0, SENSOR, 0))                       # a poll
            pipe.ingest(poll(t0 + 1, SENSOR, 1))                   # another: secured, no readable id
            pipe.ingest(Frame(ts=t0 + 2, raw=b"", psdu=b"", rssi=-60.0, channel=None, lqi=None,
                              ftype=3, seq=2, dst_pan=OWN_PAN, dst="ffff", src_pan=OWN_PAN,
                              src=SENSOR, cmd=7))                  # a beacon request: unsecured, nobody's sighting
            row = pipe.seen.table[SENSOR]
            self.assertEqual((row["polls"], row["types"]["3"], pipe.devices[SENSOR].polls), (2, 2, 2))
            rows = device_rows(pipe.seen, pipe.names, cfg.quiet_min_rssi_dbm, now=t0 + 10)
            self.assertEqual([r["polls"] for r in rows if r["addr"] == SENSOR], [2])
            # A row saved before polls were counted by name shows what it always did.
            del row["polls"]
            rows = device_rows(pipe.seen, pipe.names, cfg.quiet_min_rssi_dbm, now=t0 + 10)
            self.assertEqual([r["polls"] for r in rows if r["addr"] == SENSOR], [2])


class FramesByHourLoadTest(unittest.TestCase):
    """frames-by-hour.json is the frame count the summary and the review
    pages draw across a restart. Loading keeps the newest 26 hourly
    buckets: a day plus the margins the 24 h window needs. Trimmed
    shorter, the first summary after every restart counts a fraction of
    the day and the trend the pages draw restarts from nothing."""

    def test_load_keeps_the_26_newest_hours(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(data_dir=Path(d) / "data")
            cfg.state_dir.mkdir(parents=True, exist_ok=True)
            newest = 1_700_000_000 // 3600
            (cfg.state_dir / "frames-by-hour.json").write_text(
                json.dumps({str(newest - i): 100 + i for i in range(40)}))
            pipe = Pipeline(cfg, NullEventLog(), stub_decryptor())
            self.assertEqual(sorted(pipe._frames_by_hour), list(range(newest - 25, newest + 1)))
            self.assertEqual((pipe._frames_by_hour[newest], pipe._frames_by_hour[newest - 25]), (100, 125))
            # The first summary after the restart counts the whole day: the 25 buckets whose end is inside it.
            self.assertEqual(pipe.summary(newest * 3600 + 600.0)["frames_24h"], sum(100 + i for i in range(25)))
            for junk in ("nonsense", json.dumps({"abc": 1}), json.dumps([1, 2])):
                (cfg.state_dir / "frames-by-hour.json").write_text(junk)
                self.assertEqual(Pipeline(cfg, NullEventLog(), stub_decryptor())._frames_by_hour, {}, junk)


class StormEscalationCooldownTest(unittest.TestCase):
    """run_replay zeroes the detector's alert_cooldown_s, which is
    documented as bookkeeping ("Notification is the Pipeline's job"). The
    Pipeline borrowed the same setting as the floor of its own
    phase_locked_storm cooldown, so the identical frames through the
    identical pipeline reported 37 storm events offline against the
    recorder's 2, and anyone reconciling a snapshot against the day
    page saw two different stories."""

    def _cfg(self, tmp):
        (tmp / "devices.json").write_text("[]")
        return Config(data_dir=tmp / "data", devices_path=tmp / "devices.json")

    def test_zeroing_the_detectors_bookkeeping_does_not_move_the_event_cooldown(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(Path(d))
            pipe = Pipeline(cfg, NullEventLog(), stub_decryptor(), ephemeral=True)
            self.assertEqual(pipe.storm_event_cooldown_s, 1800.0)
            pipe.detector.cfg.alert_cooldown_s = 0          # as run_replay does
            self.assertEqual(pipe.storm_event_cooldown_s, 1800.0)

    def test_the_configured_setting_is_still_what_spaces_the_events(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = self._cfg(Path(d))
            cfg.detector.alert_cooldown_s = 300.0
            self.assertEqual(Pipeline(cfg, NullEventLog(), stub_decryptor(),
                                      ephemeral=True).storm_event_cooldown_s, 300.0)
            cfg.detector.alert_cooldown_s = 0.0             # no cooldown: the 60 s floor holds
            self.assertEqual(Pipeline(cfg, NullEventLog(), stub_decryptor(),
                                      ephemeral=True).storm_event_cooldown_s, 60.0)


class StormStateLoadTest(unittest.TestCase):
    """storm.json is what the storm detector knows across a restart. Without
    it the next start needs six windows before it will call anything a flood
    and period_onsets fresh onsets before it will call it a storm, so a
    storm already running is unreported for about five minutes; and with
    last_alert and the pipeline's phase_locked_storm stamp both back at
    zero, the same storm pages again inside its own cooldown."""

    T = 1_700_000_000.0

    def _cfg(self, d):
        (d / "devices.json").write_text("[]")
        return Config(data_dir=d / "data", devices_path=d / "devices.json")

    def _in_storm(self, pipe):
        det = pipe.detector
        det.counts.extend([250] * 40)
        det.calm.extend([250] * 40)
        det.window_start = self.T
        det.window_count = 7
        det.last_flood = self.T - 20.0
        det.in_flood = True
        det.onsets.extend([self.T - 161.0, self.T - 80.5, self.T])
        det.last_alert = self.T
        det.alerts_sent = 1
        det.storm_active = True
        det.storm_details = {"period": 80.5, "onsets": [self.T]}
        pipe._storm_evt = self.T

    def test_the_running_storm_and_its_page_come_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(Path(tmp))
            pipe = Pipeline(cfg, NullEventLog(), stub_decryptor())
            self._in_storm(pipe)
            pipe._save_storm()

            after = Pipeline(cfg, NullEventLog(), stub_decryptor())
            det = after.detector
            self.assertTrue(det.storm_active)
            self.assertEqual(det.last_alert, self.T)
            self.assertEqual(after._storm_evt, self.T)
            self.assertEqual(det.alerts_sent, 1)
            self.assertEqual(det.storm_details, {"period": 80.5, "onsets": [self.T]})
            self.assertEqual((det.last_flood, det.window_start, det.window_count), (self.T - 20.0, self.T, 7))
            self.assertTrue(det.in_flood)
            self.assertEqual(len(det.counts), 40)
            self.assertEqual(list(det.onsets), [self.T - 161.0, self.T - 80.5, self.T])

    def test_the_restart_does_not_page_the_same_storm_again(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(Path(tmp))
            pipe = Pipeline(cfg, NullEventLog(), stub_decryptor())
            self._in_storm(pipe)
            pipe._save_storm()

            class Recorder(NullEventLog):
                def __init__(self):
                    super().__init__()
                    self.names = []

                def emit(self, event, severity, ts=None, **fields):
                    self.names.append(event)
                    return super().emit(event, severity, ts=ts, **fields)

            log = Recorder()
            after = Pipeline(cfg, log, stub_decryptor())
            after.ingest(frame(self.T + 5.0, ROUTER))
            self.assertNotIn("phase_locked_storm", log.names)

    def test_an_unreadable_file_starts_the_detector_afresh(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._cfg(Path(tmp))
            cfg.state_dir.mkdir(parents=True, exist_ok=True)
            for junk in ("nonsense", json.dumps({"counts": [1]}), json.dumps([1, 2])):
                (cfg.state_dir / "storm.json").write_text(junk)
                pipe = Pipeline(cfg, NullEventLog(), stub_decryptor())
                self.assertFalse(pipe.detector.storm_active, junk)
                self.assertEqual((len(pipe.detector.counts), pipe._storm_evt), (0, 0.0), junk)


class DeviceRssiEwmaTest(unittest.TestCase):
    """DeviceStats.rssi_ewma is the same slow average the last-seen table
    keeps (19 parts old to 1 part new): it feeds the marginal-reception
    verdict on a starvation. Swapped weights would make it the last
    sample, and one frame at the noise floor would turn a page into a
    notice."""

    def test_one_deep_sample_barely_moves_the_average(self):
        with tempfile.TemporaryDirectory() as d:
            pipe = Pipeline(Config(data_dir=Path(d) / "data"), NullEventLog(), stub_decryptor(), ephemeral=True)
            t0 = 1_700_000_000.0
            for i in range(50):
                pipe.ingest(frame(t0 + i, ROUTER, rssi=-60.0))
            stats = pipe.devices[ROUTER]
            self.assertEqual(stats.rssi_ewma, -60.0)
            pipe.ingest(frame(t0 + 50, ROUTER, rssi=-95.0))
            self.assertAlmostEqual(stats.rssi_ewma, -61.75)               # 0.95 * -60 + 0.05 * -95, not -93.25
            self.assertEqual(stats.as_dict()["rssi_ewma"], -61.8)
            self.assertEqual((stats.rssi_min, stats.rssi_max), (-95.0, -60.0))
            self.assertEqual(pipe.seen.table[ROUTER]["rssi"], -61.8)      # the table's average agrees


if __name__ == "__main__":
    unittest.main()
