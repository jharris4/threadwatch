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


def frame(ts, src, pan=OWN_PAN, rssi=-60.0, seq=None, dst="0000", counter=None, sequence=0):
    """A secured data frame from ``src`` (a MIC under the test key and a
    fresh counter, so the pipeline takes it as a sighting: tests/frames.py),
    under key generation ``sequence``."""
    seq = int(ts) & 0xFF if seq is None else seq
    return Frame(ts=ts, raw=b"", psdu=psdu_for(src, seq=seq, pan=pan, dst=dst, counter=counter, sequence=sequence),
                 rssi=rssi, channel=None, lqi=None,
                 ftype=1, seq=seq, dst_pan=pan, dst=dst, src_pan=pan, src=src)


def short_frame(ts, short, ext, pan=OWN_PAN, rssi=-60.0, sequence=0):
    """A secured data frame whose header carries the sender's short address,
    as most traffic does. The MIC is still the sender's own (the nonce is its
    extended address), so the pipeline vouches for it once the decryptor maps
    the short address -- which is how a device's router id is learned."""
    seq = int(ts) & 0xFF
    return Frame(ts=ts, raw=b"", psdu=psdu_for(ext, seq=seq, pan=pan, dst="0000", sequence=sequence),
                 rssi=rssi, channel=None, lqi=None, ftype=1, seq=seq,
                 dst_pan=pan, dst="0000", src_pan=pan, src=short)


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

    def test_manual_rotation_stays_active_after_restart_and_closes_old_quiet(self):
        self.cfg.devices_path.write_text(json.dumps([
            {"name": "Hall Sensor", "extendedAddresses": [SENSOR, ROUTER]}]))
        now = time.time()
        pipe = self._pipe()
        pipe.ingest(frame(now - 2100, SENSOR))
        pipe.periodic(now - 200)
        self.assertIn(SENSOR, pipe.quiet_reported)
        pipe.ingest(frame(now - 100, ROUTER))
        self.assertNotIn(SENSOR, pipe.quiet_reported)
        returned = [r for r in pipe.events.records if r["event"] == "device_returned"]
        self.assertEqual([(r["addr"], r["ts"]) for r in returned], [(SENSOR, now - 100)])
        restarted = self._pipe()
        self.assertEqual(self._quiet(restarted), [])
        self.assertEqual(restarted.quiet_reported, set())

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

    def test_a_device_with_its_own_hold_is_judged_by_it_and_the_rest_by_the_one_window(self):
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Living Room Apple TV", "extendedAddress": ROUTER.upper(), "hold_s": 7200,
             "threadRole": "border-router-leader"},
            {"name": "Living Room AQ", "extendedAddress": SENSOR, "threadRole": "sleepy-end-device"},
        ]))
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(3):
            pipe.ingest(frame(t0 + i, ROUTER))
            pipe.ingest(frame(t0 + i, SENSOR))
        pipe.periodic(t0 + 29 * 60)
        self.assertEqual(self._quiet(pipe), [])
        pipe.periodic(t0 + 31 * 60)
        self.assertEqual(self._quiet(pipe), [SENSOR])          # the inventory's "leader" label buys nothing ...
        pipe.periodic(t0 + 119 * 60)
        self.assertEqual(self._quiet(pipe), [SENSOR])          # ... its hold_s is what keeps the hub off the list
        pipe.periodic(t0 + 121 * 60)
        self.assertEqual(self._quiet(pipe), [SENSOR, ROUTER])
        by_addr = {r["addr"]: r for r in pipe.events.records if r["event"] == "device_quiet"}
        self.assertEqual((by_addr[SENSOR]["name"], by_addr[SENSOR]["hold_s"], by_addr[SENSOR]["muted"],
                          by_addr[SENSOR]["severity"]), ("Living Room AQ", 1800, False, "warning"))
        self.assertEqual((by_addr[ROUTER]["name"], by_addr[ROUTER]["hold_s"], by_addr[ROUTER]["muted"],
                          by_addr[ROUTER]["severity"]), ("Living Room Apple TV", 7200, False, "warning"))
        self.assertNotIn("profile", pipe.events.records[-1])

    def test_a_muted_device_is_logged_at_notice_and_the_record_says_so(self):
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Living Room Apple TV", "extendedAddress": ROUTER.upper(), "mute": True},
            {"name": "Living Room AQ", "extendedAddress": SENSOR, "mute": "yes"},        # not a boolean: ignored
        ]))
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(3):
            pipe.ingest(frame(t0 + i, ROUTER))
            pipe.ingest(frame(t0 + i, SENSOR))
        pipe.periodic(t0 + 31 * 60)
        by_addr = {r["addr"]: r for r in pipe.events.records if r["event"] == "device_quiet"}
        self.assertEqual((by_addr[ROUTER]["severity"], by_addr[ROUTER]["muted"], by_addr[ROUTER]["reception"]),
                         ("notice", True, "good"))
        self.assertIn("Muted in devices.json: logged, not paged", by_addr[ROUTER]["note"])
        self.assertEqual((by_addr[SENSOR]["severity"], by_addr[SENSOR]["muted"]), ("warning", False))

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

    def test_an_unnamed_address_heard_only_briefly_is_a_visitor_not_a_quiet_device(self):
        """A phone joining the mesh for seconds to reach a HomeKit accessory
        takes an address nobody named and leaves: its visit is filed, with
        what the row knew, and the row goes, so nothing shows it as quiet or
        unnamed afterwards. A named device heard as briefly, an unnamed
        address heard for longer, and an unnamed router still page."""
        lingerer, new_router = "5a5a5a5a5a5a5a5a", "6b6b6b6b6b6b6b6b"
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(17):
            pipe.ingest(frame(t0 + i, STRANGER))
            pipe.ingest(frame(t0 + i, SENSOR))
            pipe.ingest(frame(t0 + i, new_router))
        for i in range(0, 6 * 60, 20):
            pipe.ingest(frame(t0 + i, lingerer))
        for i in range(0, 40 * 60, 60):
            pipe.ingest(frame(t0 + i, ROUTER))
        pipe.seen.table[ROUTER]["rloc16"] = "4400"          # router 17
        pipe.seen.table[STRANGER]["rloc16"] = "4403"        # its child 3
        pipe.seen.table[new_router]["rloc16"] = "4800"      # router 18, unnamed: a device, not a visitor
        pipe.periodic(t0 + 40 * 60)
        by_addr = {r["addr"]: r for r in pipe.events.records if r["event"] == "device_quiet"}
        self.assertEqual(sorted(by_addr), sorted([SENSOR, lingerer, new_router]))
        self.assertEqual({r["severity"] for r in by_addr.values()}, {"warning"})
        self.assertIn("suspect device-internal failure", by_addr[lingerer]["note"])
        visits = [r for r in pipe.events.records if r["event"] == "visitor_left"]
        self.assertEqual([(v["addr"], v["severity"], v["name"], v["heard_for_s"], v["frames"],
                           v["parent"], v["parent_addr"], v["rloc16"]) for v in visits],
                         [(STRANGER, "info", None, 16, 17, "Living Room Apple TV", ROUTER, "4403")])
        visit = visits[0]
        self.assertEqual((visit["first_seen"], visit["last_seen"], visit["silent_for_s"]),
                         (t0, t0 + 16, 40 * 60 - 16))
        self.assertEqual([g["sequence"] for g in visit["generations"]], [0])
        self.assertIsInstance(visit["generations"][0]["counter"], int)
        self.assertIn("heard for 16 s and then no more", visit["note"])
        # Nothing of it stays for the pages, the summary or the next start.
        self.assertNotIn(STRANGER, pipe.seen.table)
        self.assertNotIn(STRANGER, pipe.quiet_reported)
        self.assertNotIn(STRANGER, pipe.devices)
        s = pipe.summary(t0 + 40 * 60)
        self.assertEqual(s["unknown"], sorted([lingerer, new_router]))
        self.assertNotIn(STRANGER, s["quiet"])
        self.assertEqual(s["visits_24h"], [{"addr": STRANGER, "first_seen": t0, "heard_for_s": 16}])
        self.assertIn("1 visit by unnamed addresses", s["note"])

    def test_an_unnamed_address_silent_for_days_is_forgotten(self):
        """A device that takes a new address leaves its old one behind: on
        2026-09-18 a sensor lost its fabric and rejoined under an address
        nobody named, was reset under another the next morning, and the one
        in between stayed quiet and unknown in every daily summary. After
        [quiet] forget_unnamed_s it is dropped with a record of what was
        known; a named device, an unnamed router and a labelled phone are
        kept, as is everything while the setting is 0."""
        lingerer, new_router, phone = "5a5a5a5a5a5a5a5a", "6b6b6b6b6b6b6b6b", "7c7c7c7c7c7c7c7c"
        d = Path(self.tmp.name)
        (d / "visitors.json").write_text(json.dumps([{"name": "Sam's iPhone", "extendedAddress": phone}]))
        self.cfg.visitors_path = d / "visitors.json"
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(0, 20 * 60, 20):
            for addr in (SENSOR, lingerer, new_router, phone, ROUTER):
                pipe.ingest(frame(t0 + i, addr))
        pipe.seen.table[ROUTER]["rloc16"] = "4400"          # router 17
        pipe.seen.table[lingerer]["rloc16"] = "4403"        # its child 3
        pipe.seen.table[new_router]["rloc16"] = "4800"      # router 18, unnamed
        pipe.observed_names[lingerer] = {"default.service.arpa": 22}
        last = t0 + 20 * 60 - 20
        pipe.periodic(t0 + 2 * 86400)
        self.assertNotIn("address_forgotten", [r["event"] for r in pipe.events.records])
        self.assertIn(lingerer, pipe.summary(t0 + 2 * 86400)["unknown"])
        pipe.periodic(last + 3 * 86400)
        gone = [r for r in pipe.events.records if r["event"] == "address_forgotten"]
        self.assertEqual([(r["addr"], r["severity"], r["last_seen"], r["silent_for_s"], r["frames"],
                           r["parent"], r["parent_addr"], r["rloc16"], r["observed_names"]) for r in gone],
                         [(lingerer, "info", last, 3 * 86400, 60, "Living Room Apple TV", ROUTER, "4403",
                           {"default.service.arpa": 22})])
        self.assertIn("silent for 3.0 days", gone[0]["note"])
        self.assertNotIn(lingerer, pipe.seen.table)
        self.assertNotIn(lingerer, pipe.quiet_reported)
        self.assertNotIn(lingerer, pipe.observed_names)
        self.assertEqual(sorted(a for a in (SENSOR, new_router, phone, ROUTER) if a in pipe.seen.table),
                         sorted((SENSOR, new_router, phone, ROUTER)))
        self.assertNotIn(lingerer, pipe.summary(last + 3 * 86400)["unknown"])
        # Saved at once: a restart does not bring the row back.
        self.assertNotIn(lingerer, self._pipe().seen.table)

    def test_forget_unnamed_s_of_zero_keeps_every_address(self):
        self.cfg.quiet_forget_unnamed_s = 0
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(0, 20 * 60, 20):
            pipe.ingest(frame(t0 + i, "5a5a5a5a5a5a5a5a"))
        pipe.periodic(t0 + 30 * 86400)
        self.assertIn("5a5a5a5a5a5a5a5a", pipe.seen.table)
        self.assertNotIn("address_forgotten", [r["event"] for r in pipe.events.records])

    def test_a_labelled_visitor_is_named_in_its_visit_records_but_is_still_a_visitor(self):
        d = Path(self.tmp.name)
        (d / "visitors.json").write_text(json.dumps([{"name": "Sam's iPhone", "extendedAddress": STRANGER}]))
        self.cfg.visitors_path = d / "visitors.json"
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(10):
            pipe.ingest(frame(t0 + i, STRANGER))
        pipe.periodic(t0 + 40 * 60)
        pipe.ingest(frame(t0 + 3 * 3600, STRANGER))
        about = [(r["event"], r.get("name")) for r in pipe.events.records if r.get("addr") == STRANGER]
        self.assertEqual(about, [("device_first_seen", None), ("visitor_left", "Sam's iPhone"),
                                 ("visitor_returned", "Sam's iPhone")])
        self.assertEqual(self._quiet(pipe), [])

    def test_a_visitor_back_under_the_same_address_is_a_return_visit_not_first_seen(self):
        """Its row was dropped with the visit, but the recorder keeps a
        count per address (phones keep theirs, even across a reboot): a
        return is visitor_returned, numbered, and the next silence a second
        visit; never device_first_seen or device_returned again. The count
        survives a restart."""
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(10):
            pipe.ingest(frame(t0 + i, STRANGER))
        pipe.periodic(t0 + 40 * 60)
        for i in range(10):
            pipe.ingest(frame(t0 + 3 * 3600 + i, STRANGER))
        pipe.periodic(t0 + 3 * 3600 + 40 * 60)
        about = lambda p: [(r["event"], r.get("visit")) for r in p.events.records if r.get("addr") == STRANGER]
        self.assertEqual(about(pipe), [("device_first_seen", None), ("visitor_left", 1),
                                       ("visitor_returned", 2), ("visitor_left", 2)])
        self.assertEqual([r["first_seen"] for r in pipe.events.records if r["event"] == "visitor_left"],
                         [t0, t0 + 3 * 3600])
        back = [r for r in pipe.events.records if r["event"] == "visitor_returned"][0]
        self.assertEqual(back["last_visit"], t0 + 9)
        self.assertIn("visited 1 time before", back["note"])
        pipe2 = self._pipe()
        self.assertEqual(pipe2._visits[STRANGER]["visits"], 2)
        pipe2.ingest(frame(t0 + 6 * 3600, STRANGER))
        self.assertEqual(about(pipe2), [("visitor_returned", 3)])

    def test_visits_forget_the_longest_gone_address_past_the_cap(self):
        pipe = self._pipe()
        pipe.VISITS_MAX = 3
        t0 = 1_700_000_000.0
        pipe._visits = {f"{i:016x}": {"visits": 1, "last_visit": t0 - 3600 * i} for i in range(1, 4)}
        for i in range(10):
            pipe.ingest(frame(t0 + i, STRANGER))
        pipe.periodic(t0 + 40 * 60)
        self.assertEqual(sorted(pipe._visits), sorted([STRANGER, f"{1:016x}", f"{2:016x}"]))
        self.assertEqual(sorted(self._pipe()._visits), sorted(pipe._visits))

    def test_a_visitor_named_since_its_last_visit_is_first_seen_as_the_device(self):
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(10):
            pipe.ingest(frame(t0 + i, STRANGER))
        pipe.periodic(t0 + 40 * 60)
        d = Path(self.tmp.name)
        inventory = json.loads((d / "devices.json").read_text())
        (d / "devices.json").write_text(json.dumps(inventory + [{"name": "Hall Sensor", "extendedAddress": STRANGER}]))
        pipe2 = self._pipe()
        pipe2.ingest(frame(t0 + 3 * 3600, STRANGER))
        self.assertEqual([(r["event"], r.get("name")) for r in pipe2.events.records if r.get("addr") == STRANGER],
                         [("device_first_seen", "Hall Sensor")])
        self.assertNotIn(STRANGER, pipe2._visits)
        self.assertNotIn(STRANGER, self._pipe()._visits)

    def test_a_visitor_back_within_the_quiet_window_is_judged_by_its_latest_stretch(self):
        """The lock opened twice ten minutes apart: the phone attached twice,
        with no silence announced between. Measured from the row's first
        frame it was a device heard for ten minutes; a visit is its own
        stretch, begun by the first frame after a gap over the limit."""
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        for i in range(20):
            pipe.ingest(frame(t0 + i, STRANGER))
        for i in range(20):
            pipe.ingest(frame(t0 + 10 * 60 + i, STRANGER))
        pipe.periodic(t0 + 50 * 60)
        self.assertEqual(self._quiet(pipe), [])
        self.assertEqual([(v["first_seen"], v["heard_for_s"]) for v in pipe.events.records
                          if v["event"] == "visitor_left"], [(t0 + 10 * 60, 19)])

    def test_a_row_from_before_stretches_were_marked_takes_its_last_return_as_the_visit_start(self):
        # The Pi on 2026-09-15: the 09-14 visitor's row, first_seen 09-14
        # and flagged quiet, was still there when the phone came back under
        # the same address 44 h later for 18 s. Measured from first_seen it
        # was a device heard for 44 h, and its silence paged a warning.
        # The row carries no heard_since; the log knows when it returned.
        from threadwatch.events import EventLog, read_all
        now = time.time()
        events = self.cfg.state_dir / "events"
        log = EventLog(events)
        pipe = Pipeline(self.cfg, log, stub_decryptor())
        for i in range(17):
            pipe.ingest(frame(now - 44 * 3600 + i, STRANGER))
        for i in range(18):
            pipe.ingest(frame(now - 3600 + i, STRANGER))
        pipe.ingest(frame(now - 60, ROUTER))
        row = pipe.seen.table[STRANGER]
        del row["heard_since"]                       # saved by a run from before the field existed
        row["quiet_reported"], row["quiet_reported_ts"] = True, now - 30 * 60
        log.emit("device_quiet", "warning", now - 44 * 3600 + 1800, addr=STRANGER, name=None)
        log.emit("device_returned", "notice", now - 3600, addr=STRANGER, name=None)
        log.emit("device_quiet", "warning", now - 30 * 60, addr=STRANGER, name=None)
        pipe.seen.save()
        self._status(updated=now, last_frame_ts=now - 60)
        pipe2 = Pipeline(self.cfg, EventLog(events), stub_decryptor())
        visits = [r for r in read_all(events) if r["event"] == "visitor_left"]
        self.assertEqual([(v["addr"], v["first_seen"], v["heard_for_s"]) for v in visits],
                         [(STRANGER, now - 3600, 17)])
        self.assertNotIn(STRANGER, pipe2.seen.table)
        self.assertNotIn(STRANGER, pipe2.quiet_reported)

    def test_a_visit_a_previous_run_announced_as_quiet_is_filed_at_the_next_start(self):
        # Before visits were filed, the 2026-09-14 visitor's silence was
        # announced as device_quiet and its row flagged. Only a return
        # clears the flag and a visitor never returns, so the row stayed,
        # and the pages showed it quiet and unnamed for a month.
        now = time.time()
        pipe = self._pipe()
        for i in range(17):
            pipe.ingest(frame(now - 3 * 3600 + i, STRANGER))
        pipe.ingest(frame(now - 60, ROUTER))
        row = pipe.seen.table[STRANGER]
        row["quiet_reported"], row["quiet_reported_ts"] = True, now - 2 * 3600
        pipe.seen.save()
        self._status(updated=now, last_frame_ts=now - 60)
        pipe2 = self._pipe()
        visits = [r for r in pipe2.events.records if r["event"] == "visitor_left"]
        self.assertEqual([(v["addr"], v["heard_for_s"], v["first_seen"]) for v in visits],
                         [(STRANGER, 16, now - 3 * 3600)])
        self.assertEqual(self._quiet(pipe2), [])
        self.assertNotIn(STRANGER, pipe2.seen.table)
        self.assertNotIn(STRANGER, pipe2.quiet_reported)
        # The drop is saved with the start's batch: the next start has
        # nothing to file.
        pipe3 = self._pipe()
        self.assertEqual([r["event"] for r in pipe3.events.records if r.get("addr") == STRANGER], [])

    def _vouched_pipe(self):
        """A pipeline holding the identity tests' key, so their MLE builder
        produces messages this one decrypts."""
        from tests.test_identity import KEY as IKEY
        return Pipeline(self.cfg, NullEventLog(), Decryptor(network_key=IKEY))

    @staticmethod
    def _child_update_response(ts, parent, child, counter):
        """A fresh Child Update Response from ``parent``, unicast to
        ``child``'s extended address: the frame a parent sends only in
        reply to the child's own keep-alive."""
        from tests.frames import secured_psdu
        from tests.test_identity import ALL_NODES, LINK_LOCAL, lowpan_udp, mle_message
        from tests.test_identity import KEY as IKEY
        from threadwatch.pcap import parse_frame
        src_ip = LINK_LOCAL + Decryptor._iid_from_ext(parent)
        msg = mle_message(parent, 0, counter, src_ip, ALL_NODES, b"\x0e")
        psdu = secured_psdu(parent, counter, dst=child, seq=counter & 0xFF,
                            payload=lowpan_udp(19788, 19788, msg), key=IKEY)
        return parse_frame(ts, psdu, 230)

    def test_a_parent_answering_the_keep_alive_holds_the_quiet_until_that_is_as_old(self):
        # The Downstairs Bathroom monitor on 2026-09-09: unheard by the
        # recorder for 35 min while its parent answered its Child Update
        # Request every four minutes. Not off the mesh, just out of earshot.
        pipe = self._vouched_pipe()
        t0 = 1_700_000_000.0
        from tests.frames import secured_psdu
        from tests.test_identity import KEY as IKEY
        def heard(ts, src, counter):
            psdu = secured_psdu(src, counter, seq=counter & 0xFF, key=IKEY)
            return Frame(ts=ts, raw=b"", psdu=psdu, rssi=-60.0, channel=None, lqi=None,
                         ftype=1, seq=counter & 0xFF, dst_pan=OWN_PAN, dst="0000", src_pan=OWN_PAN, src=src)
        for i in range(10):
            pipe.ingest(heard(t0 + i, SENSOR, 1 + i))
            pipe.ingest(heard(t0 + i, ROUTER, 1 + i))
        last_heard = t0 + 9
        # The parent keeps answering, the recorder hears nothing from the child.
        for i in range(1, 8):
            pipe.ingest(self._child_update_response(t0 + i * 240, ROUTER, SENSOR, 100 + i))
        pipe.ingest(heard(t0 + 40 * 60, ROUTER, 200))
        self.assertEqual(pipe.seen.table[SENSOR]["last_seen"], last_heard)   # not a sighting
        self.assertEqual(pipe.seen.table[SENSOR]["vouched_by"], "parent")
        pipe.periodic(t0 + 40 * 60)
        self.assertEqual(self._quiet(pipe), [], "held: its parent answered it 12 min ago")
        pipe.periodic(t0 + 7 * 240 + 30 * 60 + 1)
        ev = [r for r in pipe.events.records if r["event"] == "device_quiet"]
        self.assertEqual([r["addr"] for r in ev], [SENSOR])
        self.assertEqual(ev[0]["severity"], "warning")
        self.assertEqual(ev[0]["silent_for_s"], round(t0 + 7 * 240 + 30 * 60 + 1 - last_heard))
        self.assertEqual((ev[0]["vouched_by"], ev[0]["vouched_ts"]), ("parent", t0 + 7 * 240))
        self.assertIn("its parent answered its keep-alive 30 min ago, 28 min after its last frame", ev[0]["note"])
        self.assertIn("out of the recorder's earshot", ev[0]["note"])

    def test_an_acknowledgement_from_the_device_holds_the_quiet_and_is_told(self):
        # The Upstairs Bathroom monitor on 2026-09-09: its last frame at
        # 08:21:01, its radio still acknowledging its child's polls until
        # 08:22:44, then nothing. The report waits for the acknowledgements
        # to be as old as the silence, and says how long they went on.
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        pipe.ingest(frame(t0, SENSOR))
        pipe.ingest(frame(t0, ROUTER))
        # Frames addressed to the sensor, each acknowledged within 50 ms.
        for i in range(1, 21):
            pipe.ingest(frame(t0 + 5 * i, ROUTER, seq=i, dst=SENSOR))
            pipe.ingest(ack(t0 + 5 * i + 0.001, i))
        self.assertEqual(pipe.seen.table[SENSOR]["last_seen"], t0)
        self.assertEqual((pipe.seen.table[SENSOR]["vouched_by"], pipe.seen.table[SENSOR]["vouched_ts"]),
                         ("ack", t0 + 100 + 0.001))
        # One addressed to it that nothing answers changes nothing.
        pipe.ingest(frame(t0 + 200, ROUTER, seq=99, dst=SENSOR))
        pipe.ingest(frame(t0 + 201, ROUTER, seq=100))
        self.assertEqual(pipe.seen.table[SENSOR]["vouched_ts"], t0 + 100 + 0.001)
        pipe.periodic(t0 + 31 * 60)
        self.assertEqual(self._quiet(pipe), [], "held: it acknowledged a frame 29 min ago")
        pipe.periodic(t0 + 100 + 30 * 60 + 1)
        ev = [r for r in pipe.events.records if r["event"] == "device_quiet"]
        self.assertEqual([r["addr"] for r in ev], [SENSOR])
        self.assertEqual(ev[0]["vouched_by"], "ack")
        self.assertIn("its radio acknowledged a frame 30 min ago, 2 min after its last frame heard here", ev[0]["note"])

    def test_an_acknowledgement_is_not_a_return_and_a_frame_is(self):
        pipe = self._pipe()
        t0 = 1_700_000_000.0
        pipe.ingest(frame(t0, SENSOR))
        for m in (0, 15, 30):
            pipe.ingest(frame(t0 + m * 60, ROUTER))
        pipe.periodic(t0 + 31 * 60)
        self.assertEqual(self._quiet(pipe), [SENSOR])
        pipe.ingest(frame(t0 + 32 * 60, ROUTER, seq=7, dst=SENSOR))
        pipe.ingest(ack(t0 + 32 * 60 + 0.001, 7))
        self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_returned"], [])
        pipe.ingest(frame(t0 + 33 * 60, SENSOR))
        self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_returned"], [SENSOR])

    def test_a_recent_vouch_holds_the_quiet_across_a_restart(self):
        # The start-up pass and the live tick share _is_quiet: a row whose
        # last frame is old but whose parent answered it lately is not
        # announced when the recorder comes back either.
        import json as _json
        T = time.time()
        state = self.cfg.state_dir
        state.mkdir(parents=True, exist_ok=True)
        (state / "last-seen.json").write_text(_json.dumps(
            {ROUTER: {"first_seen": T - 7200, "last_seen": T - 3 * self.cfg.quiet_s, "frames": 10,
                      "types": {}, "pan": OWN_PAN, "vouched_ts": T - 60, "vouched_by": "parent"}}))
        (state / "blind-spans.json").write_text("[]")
        (state / "status.json").write_text(_json.dumps({"last_frame_ts": T}))
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        self.assertEqual(self._quiet(pipe), [])
        pipe.periodic(T + self.cfg.quiet_s + 1)
        self.assertEqual(self._quiet(pipe), [ROUTER])

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
        # Device recovery alone no longer retires the span: the next key
        # observation still needs it to describe its interval coverage.
        pipe3.ingest(frame(T + 2461 + 29 * 60, ROUTER))
        pipe3._save_blind()
        self.assertEqual(json.loads(pipe3.blind_path.read_text()), [[T + 120, 2280.0], [T + 2460, 1.0]])
        pipe3.ingest(frame(T + 2461 + 30 * 60, ROUTER, sequence=1))
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
        pipe2.seen.table[STRANGER]["rloc16"] = "4400"     # a router: a device unnamed, not a visitor
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

    def test_a_clock_step_back_moves_the_stretch_of_presence_with_it(self):
        # heard_since was left where it was while last_seen moved back, so
        # the stretch shrank by the step: an unnamed device heard for ten
        # minutes read as heard for minus twenty, and its silence was filed
        # as a visit with a negative duration instead of paged.
        T = time.time()
        pipe = self._pipe()
        clock = {"wall": T, "mono": 0.0}
        pipe._wall, pipe._mono, pipe._clock = (lambda: clock["wall"]), (lambda: clock["mono"]), (T, 0.0)
        for i in range(0, 600, 20):
            pipe.ingest(frame(T + i, STRANGER))
        clock.update(wall=T + 600 - 1800 + 20, mono=620.0)       # the clock steps back 30 min
        pipe.periodic(clock["wall"])
        row = pipe.seen.table[STRANGER]
        self.assertEqual((row["heard_since"], row["last_seen"]), (T - 1800, T + 580 - 1800))
        clock.update(wall=clock["wall"] + 31 * 60, mono=620.0 + 31 * 60)
        pipe.periodic(clock["wall"])
        self.assertEqual(self._quiet(pipe), [STRANGER])
        self.assertNotIn("visitor_left", [r["event"] for r in pipe.events.records])

    def test_a_clock_step_back_moves_the_nested_row_stamps_and_what_they_are_rewritten_from(self):
        # The SRP grace, the counter generations, the advertised counters
        # and the key facts: each compared against now, and each left the
        # step ahead held its check back for the length of the step.
        T = time.time()
        pipe = self._pipe()
        pipe.ingest(frame(T, SENSOR, counter=5))
        row = pipe.seen.table[SENSOR]
        row["srp"] = {"refused": 2, "since": T - 60, "last_ts": T, "accepted_ts": None, "pending_ts": T}
        row["counter_prev"] = [3, T, 7]
        row["adv_mle"] = [9, 0, T, "Child ID Request"]
        pipe._advertised[SENSOR] = {"mle": {"value": 9, "sequence": 0, "ts": T, "command": "Child ID Request",
                                            "below": 3, "lowest": 4, "said_ts": T}}
        pipe._rewind(T + 20 - 1800, 1800, 20.0)
        self.assertEqual(row["counter_ts"], T - 1800)
        self.assertEqual([row["srp"][k] for k in ("since", "last_ts", "accepted_ts", "pending_ts")],
                         [T - 60 - 1800, T - 1800, None, T - 1800])
        self.assertEqual(row["counter_prev"], [3, T - 1800, 7])
        self.assertEqual(row["adv_mle"], [9, 0, T - 1800, "Child ID Request"])
        adv = pipe._advertised[SENSOR]["mle"]
        self.assertEqual((adv["ts"], adv["said_ts"]), (T - 1800, T - 1800))
        self.assertEqual({ts for gens in pipe._mac_counter[SENSOR].values() for _, ts in [gens]}, {T - 1800})
        facts = row["key_facts"]
        self.assertEqual(facts["mac"]["latest"]["ts"], T - 1800)
        self.assertEqual(facts["highest_authenticated"]["ts"], T - 1800)
        self.assertEqual([(s["first_ts"], s["last_ts"]) for s in facts["mac"]["accepted"]],
                         [(T - 1800, T - 1800)])

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
        before_keys = (self.cfg.state_dir / "key-generations.json").read_text()
        replay = Pipeline(self.cfg, NullEventLog(), stub_decryptor(), ephemeral=True)
        replay.ingest(frame(100.0, ROUTER))
        replay.periodic(100.0)
        replay.seen.save()
        # A replay starts with no key generation on record, so the first
        # one it meets is announced (previous None), and nothing is written.
        self.assertEqual([r["event"] for r in replay.events.records],
                         ["key_sequence_advanced", "device_first_seen"])
        self.assertIsNone(replay.events.records[0]["previous"])
        self.assertEqual((self.cfg.state_dir / "last-seen.json").read_text(), before)
        self.assertEqual((self.cfg.state_dir / "key-generations.json").read_text(), before_keys)

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

    def test_restart_dates_a_vouched_return_after_the_silence_it_closes(self):
        # Vouched for after the announcement but never heard again: its
        # last frame is older than the device_quiet record, and a return
        # dated there sorted ahead of the silence and closed nothing.
        now = time.time()
        pipe = self._pipe()
        pipe.ingest(frame(now - 3 * 3600, SENSOR))
        pipe.periodic(now - 3600)                   # announced quiet
        announced = pipe.seen.table[SENSOR]["quiet_reported_ts"]
        pipe.seen.table[SENSOR]["vouched_ts"] = now - 60     # its parent answered it
        pipe.seen.save()
        pipe2 = self._pipe()
        returned = [r for r in pipe2.events.records if r["event"] == "device_returned"]
        self.assertEqual([r["addr"] for r in returned], [SENSOR])
        self.assertGreater(returned[0]["ts"], announced)
        self.assertNotIn("quiet_reported", pipe2.seen.table[SENSOR])
        self.assertEqual(pipe2.quiet_reported, set())

    def test_storm_event_carries_period_onsets_and_a_note(self):
        pipe = self._pipe()
        pipe.detector.storm_active = True
        pipe.detector.storm_details = {"period": 80.5, "onsets": [100.0, 180.5, 261.0]}
        pipe.detector.storm_since = 100.0
        pipe.ingest(frame(1_700_000_000.0, ROUTER))
        rec = [r for r in pipe.events.records if r["event"] == "phase_locked_storm"][0]
        self.assertEqual((rec["period_s"], rec["onsets"], rec["severity"], rec["confirmed"]),
                         (80.5, 3, "notice", False))
        self.assertIn("every 80 s", rec["note"])
        self.assertIn("Critical if the floods persist for 10 min", rec["note"])

    def test_the_call_is_a_warning_with_the_snapshot_and_the_confirmation_a_critical_naming_it(self):
        self.cfg.snapshot_on_critical = True
        pipe = self._pipe()
        saved = []
        pipe.snapshotter = lambda label, trigger: saved.append((label, trigger))
        det = pipe.detector
        det.storm_active, det.storm_since = True, 1_700_000_000.0
        det.storm_details = {"period": 100.0, "onsets": [1_700_000_000.0, 1_700_000_100.0, 1_700_000_200.0]}
        det.add_frame = lambda ts: None                        # hold the detector's state as set
        pipe._border_router_changed = (1_700_000_000.0 - 300, "Living Room Apple TV")
        t0 = 1_700_000_200.0
        pipe.ingest(frame(t0, ROUTER))
        storms = [r for r in pipe.events.records if r["event"] == "phase_locked_storm"]
        self.assertEqual([(r["severity"], r["confirmed"], r["auto_snapshot"]) for r in storms],
                         [("notice", False, "auto-phase_locked_storm")])
        self.assertIn("began after Living Room Apple TV came back under a new address at "
                      + time.strftime("%H:%M:%S", time.localtime(1_700_000_000.0 - 300)), storms[0]["note"])
        self.assertIn("the ring is being saved as auto-phase_locked_storm", storms[0]["note"])
        self.assertEqual(saved, [("auto-phase_locked_storm", "phase_locked_storm")])
        pipe.ingest(frame(t0 + 60, ROUTER))                    # inside the cooldown: nothing new
        self.assertEqual(len([r for r in pipe.events.records if r["event"] == "phase_locked_storm"]), 1)
        # The floods persist: confirmed, and the critical goes out at once.
        det.storm_confirmed, det.last_flood = True, 1_700_000_700.0
        pipe.ingest(frame(t0 + 120, ROUTER))
        storms = [r for r in pipe.events.records if r["event"] == "phase_locked_storm"]
        self.assertEqual([(r["severity"], r["confirmed"]) for r in storms],
                         [("notice", False), ("critical", True)])
        self.assertIn("have recurred every 100 s for 11 min (3 periodic onsets since", storms[1]["note"])
        self.assertIn("the ring was saved as auto-phase_locked_storm when the storm was called", storms[1]["note"])
        self.assertIsNone(storms[1]["auto_snapshot"])
        self.assertEqual(len(saved), 1)                        # no second copy
        # The storm ends: the next storm starts its stages afresh.
        det.storm_active = False
        pipe.ingest(frame(t0 + 180, ROUTER))
        self.assertIsNone(pipe._storm_stage)

    def test_critical_event_saves_the_ring_once_per_cooldown(self):
        self.cfg.snapshot_on_critical = True
        pipe = self._pipe()
        saved = []
        pipe.snapshotter = lambda label, trigger: saved.append((label, trigger))
        pipe.detector.storm_active = True
        pipe.detector.storm_confirmed = True                   # the critical stage: the one that snapshots here
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


def poll(ts, src, seq, dst="0000", counter=None, sequence=0):
    """A secured data request from ``src``: the command id is authenticated
    and unreadable, as a Thread poll's is (cmd None; is_poll takes it)."""
    return Frame(ts=ts, raw=b"", psdu=psdu_for(src, ftype=3, seq=seq, dst=dst, counter=counter, sequence=sequence),
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

    def test_a_muted_device_starving_is_never_paged_but_its_mesh_trouble_is(self):
        (Path(self.tmp.name) / "devices.json").write_text(json.dumps(
            [{"name": "Porch Sensor", "extendedAddress": SENSOR, "mute": True}]))
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._answered_polls(pipe, 1_700_000_000.0, 5)
        for i in range(80):                                # past [polls] confirm_s, nobody answers
            pipe.ingest(poll(t + 10 * i, SENSOR, 100 + i))
        evs = self._events(pipe, "poll_starvation")
        self.assertEqual([(e["severity"], e["confirmed"], e["muted"]) for e in evs],
                         [("notice", False, True), ("notice", True, True)])
        self.assertTrue(evs[1]["note"].endswith("not on air.) Muted in devices.json: logged, not paged."))
        # Its signal fading is its own trouble too; a note with no stop gets one.
        rec = pipe._emit("rssi_degradation", "notice", t + 900, addr=SENSOR, note="the link is fading")
        self.assertEqual((rec["muted"], rec["note"]),
                         (True, "the link is fading. Muted in devices.json: logged, not paged."))
        # A refused SRP registration is about the mesh, not the device: paged.
        rec = pipe._emit("srp_refused", "warning", t + 900, addr=SENSOR, note="refused")
        self.assertEqual((rec["severity"], rec["note"]), ("warning", "refused"))
        self.assertNotIn("muted", rec)

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


ROUTER2 = "a2a2a2a2a2a2a2a2"
ROUTER3 = "a3a3a3a3a3a3a3a3"
SENSOR2 = "c2c2c2c2c2c2c2c2"


def rejoin_frame(ts, src_ext, sequence, mac_sequence=None):
    """A MAC-secured frame from ``src_ext`` carrying an MLE Parent Request
    under the same key generation: what a device sends when it has lost
    its parent. Both layers vouch for the sender, and _apply_mle stamps
    the row's rejoin_ts."""
    import struct

    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    from tests.frames import KEY, next_counter, secured_psdu
    from tests.test_identity import ALL_NODES, LINK_LOCAL, lowpan_udp
    from threadwatch.crypto import derive_keys
    from threadwatch.pcap import parse_frame
    counter = next_counter(src_ext)
    src_ip = LINK_LOCAL + Decryptor._iid_from_ext(src_ext)
    aux = bytes([5 | (2 << 3)]) + struct.pack("<L", counter) + struct.pack(">L", sequence) \
        + bytes([(sequence & 0x7f) + 1])
    mle_key, _mac = derive_keys(KEY, sequence)
    nonce = bytes.fromhex(src_ext) + struct.pack(">L", counter) + bytes([5])
    msg = bytes([0]) + aux + AESCCM(mle_key, tag_length=4).encrypt(nonce, bytes([9]), src_ip + ALL_NODES + aux)
    psdu = secured_psdu(src_ext, counter, dst="ffff", seq=int(ts) & 0xFF,
                        payload=lowpan_udp(19788, 19788, msg),
                        sequence=sequence if mac_sequence is None else mac_sequence)
    return parse_frame(ts, psdu, 230)


class MleExchangeTest(unittest.TestCase):
    """The attachment and link exchanges kept for the key-transition
    journal, matched by the names the decoder gives them."""

    def test_every_kept_command_is_a_name_the_decoder_gives(self):
        from threadwatch.crypto import MLE_COMMANDS
        from threadwatch.pipeline import MLE_EXCHANGE_COMMANDS, MLE_ROUTER_COMMANDS
        self.assertLessEqual(MLE_EXCHANGE_COMMANDS, set(MLE_COMMANDS.values()))
        self.assertLessEqual(MLE_ROUTER_COMMANDS, set(MLE_COMMANDS.values()))

    def test_a_link_accept_and_request_is_kept_for_both_ends(self):
        from types import SimpleNamespace

        from threadwatch.crypto import MLE_COMMANDS
        with tempfile.TemporaryDirectory() as tmp:
            pipe = Pipeline(Config(data_dir=Path(tmp), devices_path=Path(tmp) / "devices.json"),
                            NullEventLog(), stub_decryptor(), ephemeral=True)
            info = SimpleNamespace(command_name=MLE_COMMANDS[2], key_sequence=5, link_frame_counter=None,
                                   mle_frame_counter=None, source_addr16=None, partition_id=None)
            pipe._apply_mle(frame(1_700_000_000.0, ROUTER, dst=SENSOR), info, ROUTER)
            for addr in (ROUTER, SENSOR):
                [kept] = pipe._journal_exchanges[addr]
                self.assertEqual((kept["command"], kept["sender"], kept["receiver"]),
                                 ("Link Accept And Request", ROUTER, SENSOR))


class KeyGenerationTest(unittest.TestCase):
    """The key-generation detectors: every rotation recorded once, a
    census of who followed, and a page for a device left two or more
    generations behind (docs/ALERTING.md, key_lag). Routers hold router
    ids 1, 2 and 3 (RLOC16 0400, 0800, 0c00); the sensors are children of
    router 1 (0401, 0402)."""

    T0 = 1_700_000_000.0

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([
            {"name": "Hall Router", "extendedAddress": ROUTER},
            {"name": "Attic Router", "extendedAddress": ROUTER2},
            {"name": "Shed Router", "extendedAddress": ROUTER3},
            {"name": "Porch Sensor", "extendedAddress": SENSOR},
            {"name": "Garage Sensor", "extendedAddress": SENSOR2}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")

    def tearDown(self):
        self.tmp.cleanup()

    def _pipe(self):
        return Pipeline(self.cfg, NullEventLog(), stub_decryptor())

    @staticmethod
    def _events(pipe, name):
        return [r for r in pipe.events.records if r["event"] == name]

    def _heard(self, pipe, ts, ext, rloc16, sequence):
        """One extended-source frame (the sighting) and one from the short
        address (the role) under ``sequence``."""
        pipe.ingest(frame(ts, ext, sequence=sequence))
        pipe.ingest(short_frame(ts + 0.5, rloc16, ext, sequence=sequence))

    def _mesh(self, pipe, t, sequence, routers=(ROUTER, ROUTER2), children=(SENSOR,)):
        """Routers on ``sequence`` and children too, at ``t``."""
        for i, r in enumerate(routers):
            self._heard(pipe, t + i, r, {ROUTER: "0400", ROUTER2: "0800", ROUTER3: "0c00"}[r], sequence)
        for i, c in enumerate(children):
            self._heard(pipe, t + 10 + i, c, {SENSOR: "0401", SENSOR2: "0402"}[c], sequence)
        return t + 20

    def test_a_rotation_is_announced_once_and_never_again_after_a_restart(self):
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        first = self._events(pipe, "key_sequence_advanced")
        self.assertEqual(len(first), 1)
        self.assertEqual((first[0]["sequence"], first[0]["previous"], first[0]["first_sender"], first[0]["frame"]),
                         (5, None, ROUTER, "mac_data"))
        self.assertIn("first key generation heard: 5", first[0]["note"])
        pipe.ingest(frame(t + 100, ROUTER, sequence=6))
        pipe.ingest(frame(t + 101, ROUTER, sequence=6))
        pipe.ingest(frame(t + 102, SENSOR, sequence=5))            # a straggler on the old key: nothing
        evs = self._events(pipe, "key_sequence_advanced")
        self.assertEqual(len(evs), 2)
        ev = evs[1]
        self.assertEqual((ev["sequence"], ev["previous"], ev["first_sender"], ev["name"], ev["rloc16"],
                          ev["role"], ev["frame"], ev["since_previous_s"], ev["severity"]),
                         (6, 5, ROUTER, "Hall Router", "0400", "router", "mac_data", 120, "info"))
        self.assertIn("generation 5 -> 6, first heard from Hall Router (mac_data)", ev["note"])
        self.assertNotIn("early", ev["note"])
        state = json.loads((self.cfg.state_dir / "key-generations.json").read_text())
        self.assertEqual((state["highest"], state["previous"], state["first_sender"], state["highest_first_ts"]),
                         (6, 5, ROUTER, t + 100))
        pipe.seen.save()
        pipe2 = self._pipe()
        self.assertEqual(pipe2.keys_status()["scope"], "device")
        self.assertEqual(pipe2.keys_status()["confidence"], "observation_only")
        self.assertEqual(pipe2.keys_status()["reasons"], ev["reasons"])
        pipe2.ingest(frame(t + 200, ROUTER, sequence=6))
        pipe2.ingest(frame(t + 201, SENSOR, sequence=5))
        pipe2.ingest(poll(t + 202, SENSOR, 7, sequence=6))
        self.assertEqual(self._events(pipe2, "key_sequence_advanced"), [])
        # A poll is named as the frame kind when it is what moves the record.
        pipe2.ingest(poll(t + 300, SENSOR, 8, sequence=7))
        ev = self._events(pipe2, "key_sequence_advanced")[0]
        self.assertEqual((ev["sequence"], ev["previous"], ev["frame"], ev["role"]), (7, 6, "mac_poll", "child"))

    def test_a_child_ahead_of_its_parent_is_an_unconfirmed_candidate_and_later_ones_join_the_census(self):
        self.cfg.key_census_delay_s = 600
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        self._heard(pipe, t, SENSOR2, "0801", 5)                        # a child of the shed router
        first = self._events(pipe, "key_sequence_advanced")[0]
        self.assertEqual((first["suspects"][0]["addr"], first["suspects"][0]["evidence"]), (ROUTER, "first on air"))
        # The porch sensor polls on 6 while its parent is fresh on 5: it
        # is an origin candidate, but missed traffic or attachment could explain it.
        pipe.ingest(poll(t + 100, SENSOR, 7, sequence=6))
        ev = self._events(pipe, "key_sequence_advanced")[1]
        self.assertEqual((ev["sequence"], ev["first_sender"], ev["role"]), (6, SENSOR, "child"))
        self.assertEqual(len(ev["suspects"]), 1)
        sus = ev["suspects"][0]
        self.assertEqual((sus["addr"], sus["name"], sus["role"], sus["rloc16"], sus["frame"], sus["evidence"],
                          sus["parent"], sus["parent_addr"], sus["parent_generation"], sus["ts"]),
                         (SENSOR, "Porch Sensor", "child", "0401", "mac_poll", "ahead of its parent",
                          "Hall Router", ROUTER, 5, t + 100))
        self.assertEqual(sus["parent_heard_s"], round(t + 100 - (t - 20 + 0.5)))   # its last frame under 5
        self.assertIn("Porch Sensor was observed ahead of its last known parent sequence: Hall Router on 5, heard "
                      f"{sus['parent_heard_s']} s earlier; an origin candidate, not proof", ev["note"])
        self.assertEqual((ev["scope"], ev["confidence"]), ("device", "observation_only"))
        self.assertIn("mesh_adoption_not_established", ev["reasons"])
        self.assertEqual(sus["confidence"], "candidate_only")
        self.assertIn("missed_traffic_or_attachment_possible", sus["reasons"])
        self.assertNotIn("on its own", ev["note"])
        # The routers follow; a child heard on 6 after its parent moved
        # simply followed, and is no suspect.
        self._heard(pipe, t + 200, ROUTER, "0400", 6)
        pipe.ingest(frame(t + 210, "e5e5e5e5e5e5e5e5", sequence=6))    # unknown role: not judged
        pipe.ingest(short_frame(t + 211, "0403", "e5e5e5e5e5e5e5e5", sequence=6))
        # The garage sensor moves to 6 while the shed router is still on 5.
        pipe.ingest(frame(t + 220, SENSOR2, sequence=6))
        self._heard(pipe, t + 230, ROUTER2, "0800", 6)
        state = json.loads((self.cfg.state_dir / "key-generations.json").read_text())
        self.assertEqual([(s["addr"], s["evidence"], s["parent"], s["parent_generation"]) for s in state["suspects"]],
                         [(SENSOR, "ahead of its parent", "Hall Router", 5),
                          (SENSOR2, "ahead of its parent", "Attic Router", 5)])
        pipe.ingest(frame(t + 240, SENSOR2, sequence=6))                # again: recorded once
        pipe.seen.save()
        pipe2 = self._pipe()                                             # the census survives a restart
        pipe2.periodic(t + 100 + 600)
        census = self._events(pipe2, "key_lag_census")[0]
        self.assertEqual([s["addr"] for s in census["suspects"]], [SENSOR, SENSOR2])
        self.assertIn("origin candidates: Porch Sensor "
                      "(ahead of last known parent sequence: Hall Router on 5), "
                      "Garage Sensor (ahead of last known parent sequence: Attic Router on 5)", census["note"])
        # After the census the window is closed: a straggler moving ahead
        # of a parent that is one behind is key_lag's story, not a suspect.
        pipe2.ingest(frame(t + 800, ROUTER3, sequence=5))
        pipe2.ingest(short_frame(t + 800.5, "0c00", ROUTER3, sequence=5))
        pipe2.ingest(frame(t + 801, "d3d3d3d3d3d3d3d3", sequence=5))
        pipe2.ingest(short_frame(t + 801.5, "0c01", "d3d3d3d3d3d3d3d3", sequence=5))
        pipe2.ingest(frame(t + 802, "d3d3d3d3d3d3d3d3", sequence=6))
        state = json.loads((self.cfg.state_dir / "key-generations.json").read_text())
        self.assertEqual([s["addr"] for s in state["suspects"]], [SENSOR, SENSOR2])

    def test_initial_observation_retains_sender_when_parent_was_already_seen_at_that_sequence(self):
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        # The sequence state can be lost independently of the device table.
        pipe._keys = {}
        pipe.ingest(poll(t + 100, SENSOR, 7, sequence=5))
        ev = self._events(pipe, "key_sequence_advanced")[-1]
        suspect = ev["suspects"][0]
        self.assertEqual((ev["previous"], ev["scope"], suspect["addr"]), (None, "device", SENSOR))
        self.assertEqual(suspect["parent_generation"], 5)
        self.assertIn("parent_already_observed_at_or_above_sequence", suspect["reasons"])
        self.assertIn("origin unconfirmed", pipe._suspect_sentence(suspect))

    def test_layer_readings_stay_apart_across_a_restart(self):
        # The lag detector still judges by the newest generation on record
        # (newest_generation); the facts keep each layer's own latest reading.
        from threadwatch.keyfacts import facts, latest_generation
        from threadwatch.names import newest_generation

        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 87, children=())
        self._heard(pipe, t, SENSOR, "0401", 85)
        pipe.ingest(rejoin_frame(t + 10, SENSOR, 87, mac_sequence=85))
        row = pipe.seen.table[SENSOR]
        self.assertEqual(latest_generation(row), (85, t + 10))
        self.assertEqual(facts(row)["mle"]["latest"]["sequence"], 87)
        self.assertEqual(newest_generation(row), (87, t + 10))
        pipe.seen.save()
        restarted = self._pipe()
        later = t + self.cfg.key_fresh_s + 20
        restarted.ingest(poll(later, SENSOR, 7, sequence=85))
        row = restarted.seen.table[SENSOR]
        self.assertEqual(latest_generation(row), (85, later))
        self.assertEqual(facts(row)["mle"]["latest"]["ts"], t + 10)
        self.assertEqual(facts(row)["highest_authenticated"]["ts"], t + 10)

    def test_rejected_authenticated_frames_are_visible_without_refreshing_live_state(self):
        from threadwatch.keyfacts import facts, latest_generation

        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 85)
        pipe.ingest(frame(t + 1, SENSOR, counter=100000, sequence=85))
        row = pipe.seen.table[SENSOR]
        live = {k: row.get(k) for k in ("last_seen", "frames", "rloc16", "counter", "counter_ts")}
        count = len(self._events(pipe, "key_sequence_advanced"))
        pipe.ingest(frame(t + 30, SENSOR, counter=99999, sequence=85))
        pipe.ingest(frame(t + 31, SENSOR, counter=100001, sequence=82))
        self.assertIsNone(pipe.last_sighting)
        self.assertEqual({k: row.get(k) for k in live}, live)
        self.assertEqual(latest_generation(row), (85, t + 1))
        rejected = facts(row)["mac"]["rejected"]
        self.assertEqual([(s["sequence"], s["reason"]) for s in rejected],
                         [(85, "counter_not_advancing"), (82, "older_than_retained")])
        self.assertEqual(len(self._events(pipe, "key_sequence_advanced")), count)
        pipe.seen.save()
        restarted = self._pipe()
        self.assertEqual(facts(restarted.seen.table[SENSOR])["mac"]["rejected"], rejected)
        restarted.ingest(frame(t + 40, SENSOR, counter=99999, sequence=85))
        self.assertIsNone(restarted.last_sighting)

    def test_bad_mic_cannot_enter_sequence_facts(self):
        from dataclasses import replace

        from threadwatch.keyfacts import facts

        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 85)
        before = facts(pipe.seen.table[SENSOR])
        forged = frame(t + 1, SENSOR, sequence=90)
        forged = replace(forged, psdu=forged.psdu[:-1] + bytes([forged.psdu[-1] ^ 1]))
        pipe.ingest(forged)
        self.assertIsNone(pipe.last_sighting)
        self.assertEqual(facts(pipe.seen.table[SENSOR]), before)

    def test_fresh_mac_does_not_promote_replayed_inner_mle_to_latest(self):
        from tests.frames import next_counter, secured_psdu
        from threadwatch.keyfacts import facts
        from threadwatch.pcap import parse_frame

        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 85)
        original = rejoin_frame(t + 10, SENSOR, 87, mac_sequence=85)
        pipe.ingest(original)
        plain = pipe.decryptor.decrypt_frame_counter(original.psdu, SENSOR, None)[0]
        wrapped = secured_psdu(SENSOR, next_counter(SENSOR), dst="ffff", payload=plain, sequence=85)
        pipe.ingest(parse_frame(t + 40, wrapped, 230))
        row = pipe.seen.table[SENSOR]
        self.assertEqual(row["last_seen"], t + 40)
        self.assertEqual(row["rejoin_ts"], t + 10)
        state = facts(row)
        self.assertEqual(state["mac"]["latest"]["ts"], t + 40)
        self.assertEqual(state["mle"]["latest"]["ts"], t + 10)
        self.assertEqual(state["mle"]["rejected"][0]["sequence"], 87)

    def test_legacy_key_state_has_unknown_provenance_and_does_not_repeat_the_observation(self):
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        pipe.seen.save()
        path = self.cfg.state_dir / "key-generations.json"
        state = json.loads(path.read_text())
        for key in ("scope", "confidence", "reasons"):
            state.pop(key)
            for candidate in state["suspects"]:
                candidate.pop(key, None)
        path.write_text(json.dumps(state))
        restarted = self._pipe()
        self.assertEqual((restarted.keys_status()["scope"], restarted.keys_status()["confidence"],
                          restarted.keys_status()["reasons"]), ("unknown", "unknown", []))
        restarted.ingest(frame(t + 100, ROUTER, sequence=5))
        self.assertEqual(self._events(restarted, "key_sequence_advanced"), [])

    def test_a_first_sender_that_cannot_be_judged_is_first_on_air(self):
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        # A router first: it hears every neighbour, so it may be relaying.
        pipe.ingest(frame(t + 100, ROUTER2, sequence=6))
        ev = self._events(pipe, "key_sequence_advanced")[1]
        self.assertEqual((ev["suspects"][0]["evidence"], ev["suspects"][0]["role"]), ("first on air", "router"))
        self.assertIn("Attic Router is a router, so it may have relayed a frame the sniffer missed: suspected, "
                      "not proven", ev["note"])
        self._heard(pipe, t + 200, ROUTER, "0400", 6)
        # A child whose parent nobody is known to hold: not judged.
        pipe.ingest(frame(t + 300, "d3d3d3d3d3d3d3d3", sequence=6))
        pipe.ingest(short_frame(t + 300.5, "3c01", "d3d3d3d3d3d3d3d3", sequence=6))
        pipe.ingest(frame(t + 400, "d3d3d3d3d3d3d3d3", sequence=7))
        ev = self._events(pipe, "key_sequence_advanced")[2]
        self.assertEqual((ev["suspects"][0]["evidence"], ev["suspects"][0]["parent"]), ("first on air", None))
        self.assertIn("whether d3d3d3d3d3d3d3d3 started it or relayed it is not known: its parent is not known",
                      ev["note"])
        # A child whose parent has no fresh reading: not judged either.
        self._heard(pipe, t + 500, ROUTER, "0400", 7)
        t2 = t + 500 + self.cfg.key_fresh_s + 60
        pipe.ingest(frame(t2, SENSOR, sequence=8))
        ev = self._events(pipe, "key_sequence_advanced")[3]
        self.assertEqual((ev["suspects"][0]["evidence"], ev["suspects"][0]["parent"]), ("first on air", "Hall Router"))
        self.assertIn("its parent Hall Router had no fresh generation reading", ev["note"])

    def test_a_half_key_snapshot_left_by_a_restart_says_it_is_not_retried(self):
        from threadwatch import snapshot
        staging = self.cfg.snapshots_dir / snapshot.STAGING_DIR
        for label in ("auto-key-86-1700000010000-advance", "auto-phase_locked_storm"):
            (staging / f"20260917T192634_{label}").mkdir(parents=True)
        pipe = self._pipe()
        notes = {e["label"]: e["note"] for e in self._events(pipe, "snapshot_failed")}
        self.assertIn("not repeated after a restart", notes["auto-key-86-1700000010000-advance"])
        self.assertIn("the next storm event tries again", notes["auto-phase_locked_storm"])

    def test_key_snapshot_pair_survives_restart_and_ignores_critical_cooldown(self):
        self.cfg.snapshot_on_key_advance = True
        self.cfg.key_census_delay_s = 600
        pipe = self._pipe()
        saved = []
        pipe.snapshotter = lambda *args: saved.append(args)
        pipe._last_auto_snapshot = self.T0
        pipe.ingest(frame(self.T0, ROUTER, sequence=85))
        self.assertEqual(saved, [])  # discovery is not a rotation
        pipe.ingest(frame(self.T0 + 10, ROUTER, sequence=86))
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0][1], "key_sequence_advanced")
        pipe.seen.save()
        pipe = self._pipe()
        pipe.snapshotter = lambda *args: saved.append(args)
        pipe.ingest(frame(self.T0 + 20, ROUTER, sequence=86))
        pipe._maybe_census(self.T0 + 609, None)
        self.assertEqual(len(saved), 1)
        pipe._maybe_census(self.T0 + 610, None)
        self.assertEqual(len(saved), 2)
        self.assertEqual(saved[1][1], "key_lag_census")
        self.assertEqual(saved[0][2], {"sequence": 86, "observed_at": self.T0 + 10, "phase": "advance"})
        self.assertEqual(saved[1][2], {"sequence": 86, "observed_at": self.T0 + 10, "phase": "census"})
        pipe = self._pipe()
        pipe.snapshotter = lambda *args: self.fail("duplicated the pair after restart")
        pipe._maybe_census(self.T0 + 1000, None)

    def test_key_snapshots_coalesce_a_burst_and_link_the_original_observation(self):
        self.cfg.snapshot_on_key_advance = True
        self.cfg.key_census_delay_s = 600
        pipe = self._pipe()
        saved = []
        pipe.snapshotter = lambda *args: saved.append(args)
        for offset, sequence in ((0, 85), (10, 86), (20, 87), (30, 88)):
            pipe.ingest(frame(self.T0 + offset, ROUTER, sequence=sequence))
        self.assertEqual(len(saved), 1)
        skipped = self._events(pipe, "snapshot_skipped")
        self.assertEqual([e["sequence"] for e in skipped], [87, 88])
        self.assertTrue(all(e["reason"] == "key_advance_coalesced" for e in skipped))
        pipe._maybe_census(self.T0 + 630, None)
        self.assertEqual(len(saved), 2)
        self.assertEqual(saved[1][2]["sequence"], 86)
        pipe.ingest(frame(self.T0 + 700, ROUTER, sequence=89))
        self.assertEqual(len(saved), 3)

    def test_key_snapshot_disk_guard_and_worker_limit_report_skipped_attempts(self):
        from unittest.mock import patch
        pipe = self._pipe()
        pipe._last_auto_snapshot = self.T0
        observation = {"sequence": 86, "observed_at": self.T0, "phase": "advance"}
        with patch("threadwatch.review.storage", return_value={
                "disk_free": 0, "ring_bytes": 100, "ring_needs_bytes": 200}):
            pipe._save_snapshot_now("key-disk-full", "key_sequence_advanced", observation)
        self.assertEqual(pipe._last_auto_snapshot, self.T0)
        skipped = self._events(pipe, "snapshot_skipped")
        self.assertEqual(skipped[0]["disk_free"], 0)
        self.assertEqual(self._events(pipe, "snapshot_saved"), [])
        pipe._key_snapshot_slots.acquire()
        pipe._key_snapshot_slots.acquire()
        try:
            pipe._snapshot_in_background("key-busy", "key_lag_census", observation)
        finally:
            pipe._key_snapshot_slots.release()
            pipe._key_snapshot_slots.release()
        self.assertEqual(self._events(pipe, "snapshot_skipped")[-1]["reason"], "key_snapshot_workers_busy")

    def test_key_snapshots_are_opt_in_and_replay_has_no_side_effects(self):
        for enabled, ephemeral, keep in ((False, False, 4), (True, True, 4), (True, False, 0)):
            with self.subTest(enabled=enabled, ephemeral=ephemeral, keep=keep):
                self.cfg.snapshot_on_key_advance = enabled
                self.cfg.keep_snapshots = keep
                pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor(), ephemeral=ephemeral)
                pipe._keys = {}
                pipe.snapshotter = lambda *args: self.fail("unexpected copy")
                pipe.ingest(frame(self.T0, ROUTER, sequence=85))
                pipe.ingest(frame(self.T0 + 10, ROUTER, sequence=86))
                pipe._maybe_census(self.T0 + 10000, None)
                if enabled and not ephemeral:
                    self.assertEqual([e["reason"] for e in self._events(pipe, "snapshot_skipped")],
                                     ["keep_snapshots_zero"] * 2)

    def test_key_snapshot_manifests_and_disk_failure_keep_the_pair_bounded(self):
        from unittest.mock import patch
        self.cfg.snapshot_on_key_advance = True
        self.cfg.key_census_delay_s = 600
        pipe = self._pipe()
        pipe.snapshotter = pipe._save_snapshot_now
        pipe.ingest(frame(self.T0, ROUTER, sequence=85))
        pipe.ingest(frame(self.T0 + 10, ROUTER, sequence=86))
        pipe._maybe_census(self.T0 + 610, None)
        manifests = [json.loads(p.read_text()) for p in self.cfg.snapshots_dir.glob("*/manifest.json")]
        self.assertEqual(len(manifests), 2)
        self.assertEqual({m["key_observation"]["phase"] for m in manifests}, {"advance", "census"})
        self.assertTrue(all(m["key_observation"]["observed_at"] == self.T0 + 10 for m in manifests))
        self.assertEqual(self._pipe()._last_auto_snapshot, 0)
        pipe._last_auto_snapshot = self.T0
        with patch("threadwatch.snapshot.save_snapshot", side_effect=OSError("disk full")):
            pipe.ingest(frame(self.T0 + 700, ROUTER, sequence=87))
            pipe._maybe_census(self.T0 + 1300, None)
            pipe._maybe_census(self.T0 + 1400, None)
        self.assertEqual(len(self._events(pipe, "snapshot_failed")), 2)
        self.assertEqual(pipe._last_auto_snapshot, self.T0)
        self.assertTrue(pipe.keys_status()["snapshot_pair"]["census_claimed"])

    def test_interval_facts_baseline_single_step_and_skipped_generations(self):
        self.cfg.key_rotation_hours = 672
        pipe = self._pipe()
        for offset, generation in ((0, 85), (3600.25, 86), (7200.5, 89)):
            pipe.ingest(frame(self.T0 + offset, ROUTER, sequence=generation))
        baseline, step, jump = self._events(pipe, "key_sequence_advanced")
        self.assertEqual(baseline["observation_kind"], "baseline")
        for key in ("observed_interval_s", "sequence_delta", "previous_first_ts",
                    "early_against_configured_interval"):
            self.assertIsNone(baseline[key])
        self.assertEqual(step["observed_interval_s"], 3600.25)
        self.assertEqual(step["since_previous_s"], 3600)
        self.assertEqual(step["sequence_delta"], 1)
        self.assertEqual(jump["sequence_delta"], 3)
        self.assertEqual(jump["observed_interval_s"], 3600.25)
        self.assertEqual(jump["previous_first_ts"], self.T0 + 3600.25)
        self.assertEqual(jump["coverage"]["status"], "unknown")
        self.assertEqual(jump["coverage"]["gaps"], [])
        self.assertEqual(jump["scheduled_expectation"], {
            "rotation_hours": 672, "source": "local_config", "config_key": "keys.rotation_hours",
            "device": None, "observed_at": None, "live_telemetry": False})
        self.assertTrue(jump["early_against_configured_interval"])
        self.assertIn("previous first observation", jump["note"])
        restarted = self._pipe()
        for key in ("observed_interval_s", "sequence_delta", "coverage", "scheduled_expectation"):
            self.assertEqual(restarted.keys_status()[key], jump[key])

    def test_interval_retains_downtime_after_devices_return_and_another_restart(self):
        from unittest import mock
        pipe = self._pipe()
        pipe.ingest(frame(self.T0, ROUTER, sequence=85))
        pipe.seen.save()
        with mock.patch("threadwatch.pipeline.time.time", return_value=self.T0 + 100):
            pipe = self._pipe()
        pipe.ingest(frame(self.T0 + 120, ROUTER, sequence=85))
        pipe.seen.save()
        pipe._save_blind()
        with mock.patch("threadwatch.pipeline.time.time", return_value=self.T0 + 200):
            pipe = self._pipe()
        pipe.ingest(frame(self.T0 + 300, ROUTER, sequence=86))
        event = self._events(pipe, "key_sequence_advanced")[0]
        self.assertEqual(event["observed_interval_s"], 300)
        self.assertEqual(event["coverage"]["status"], "gapped")
        self.assertIn("recorder_restart", event["coverage"]["reasons"])
        self.assertEqual(event["coverage"]["gaps"], [
            {"start_ts": self.T0, "end_ts": self.T0 + 100, "source": "recorder_blind_span"},
            {"start_ts": self.T0 + 120, "end_ts": self.T0 + 200, "source": "recorder_blind_span"}])
        self.assertFalse(event["coverage"]["history_complete"])
        self.assertEqual(event["scheduled_expectation"]["source"], "unknown")

    def test_legacy_missing_timestamp_and_backward_time_do_not_invent_intervals(self):
        pipe = self._pipe()
        pipe._keys = {"highest": 85}
        pipe.ingest(frame(self.T0, ROUTER, sequence=86))
        event = self._events(pipe, "key_sequence_advanced")[-1]
        self.assertIsNone(event["observed_interval_s"])
        self.assertIn("previous_observation_time_unknown", event["coverage"]["reasons"])
        pipe._keys["highest_first_ts"] = self.T0 + 200
        pipe.ingest(frame(self.T0 + 100, ROUTER, sequence=87))
        event = self._events(pipe, "key_sequence_advanced")[-1]
        self.assertIsNone(event["observed_interval_s"])
        self.assertIsNone(event["since_previous_s"])
        self.assertIn("non_monotonic_observation_time", event["coverage"]["reasons"])

    def test_an_early_rotation_says_so_when_the_rotation_time_is_configured(self):
        self.cfg.key_rotation_hours = 24
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        pipe.ingest(frame(t + 3600, ROUTER, sequence=6))                 # an hour after: early
        pipe.ingest(frame(t + 3600 + 23 * 3600, ROUTER, sequence=7))      # 23 h: over 90% of 24, not early
        notes = [e["note"] for e in self._events(pipe, "key_sequence_advanced")[1:]]
        self.assertIn("early: the configured rotation time is 24 h", notes[0])
        self.assertNotIn("early", notes[1])

    def test_a_following_child_is_not_reported_and_a_stranded_one_is_paged_once(self):
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        t = self._mesh(pipe, t, 6, children=())                          # routers move to 6
        pipe.ingest(frame(t, SENSOR, sequence=5))                        # the child has not followed: normal
        pipe.periodic(t + 1)
        self.assertEqual(self._events(pipe, "key_lag"), [])
        self.assertNotIn("keylag_since", pipe.seen.table[SENSOR])
        t = self._mesh(pipe, t + 100, 7, children=())                    # ...and to 7: the child is cut off
        pipe.ingest(frame(t, SENSOR, sequence=5))
        pipe.periodic(t + 1)
        row = pipe.seen.table[SENSOR]
        self.assertEqual((row["keylag_since"], row["keylag_confirm_at"], row["keylag_parent"], row["keylag_gens"]),
                         (t + 1, t + 901, ROUTER, [5, 7]))
        self.assertEqual(self._events(pipe, "key_lag"), [])              # opened silently
        pipe.ingest(frame(t + 400, SENSOR, sequence=5))
        pipe.periodic(t + 401)
        pipe.periodic(t + 902)                                           # past the mark, but no frame since
        self.assertEqual(self._events(pipe, "key_lag"), [])
        pipe.ingest(frame(t + 950, SENSOR, sequence=5))                  # fresh evidence past the mark
        pipe.ingest(frame(t + 951, ROUTER, sequence=7))
        pipe.periodic(t + 960)
        evs = self._events(pipe, "key_lag")
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual((ev["severity"], ev["name"], ev["role"], ev["generation"], ev["parent"],
                          ev["parent_addr"], ev["parent_generation"], ev["lag"], ev["since"], ev["lagged_for_s"],
                          ev["episode"], ev["reception"], ev["polls_acked"]),
                         ("warning", "Porch Sensor", "child", 5, "Hall Router", ROUTER, 7, 2, t + 1, 959, 1,
                          "good", False))
        self.assertNotIn("mesh_generation", ev)
        self.assertIn("2 generations behind", ev["note"])
        self.assertIn("A battery pull or power cycle forces a rejoin", ev["note"])
        self.assertEqual(row["keylag_sent"], "warning")
        self.assertNotIn("keylag_confirm_at", row)
        for i in range(5):                                               # it persists: nothing more
            pipe.ingest(frame(t + 1000 + i * 100, SENSOR, sequence=5))
            pipe.periodic(t + 1001 + i * 100)
        self.assertEqual(len(self._events(pipe, "key_lag")), 1)
        self.assertEqual(self._events(pipe, "key_lag_cleared"), [])

    def test_a_rejoin_that_catches_up_clears_the_page(self):
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        t = self._mesh(pipe, t, 7, children=())
        pipe.ingest(frame(t, SENSOR, sequence=5))
        pipe.periodic(t + 1)
        pipe.ingest(frame(t + 950, SENSOR, sequence=5))
        pipe.periodic(t + 960)
        self.assertEqual(len(self._events(pipe, "key_lag")), 1)
        pipe.ingest(rejoin_frame(t + 1000, SENSOR, 5))
        self.assertEqual(pipe.seen.table[SENSOR]["rejoin_ts"], t + 1000)
        pipe.periodic(t + 1000 + 61)
        self.assertEqual(len(self._events(pipe, "mle_rejoin_attempt")), 1)
        pipe.ingest(frame(t + 1010, SENSOR, sequence=7))
        pipe.ingest(short_frame(t + 1011, "0401", SENSOR, sequence=7))
        pipe.periodic(t + 1020)
        cleared = self._events(pipe, "key_lag_cleared")
        self.assertEqual(len(cleared), 1)
        ev = cleared[0]
        self.assertEqual((ev["severity"], ev["name"], ev["generation"], ev["parent_generation"], ev["since"],
                          ev["lagged_for_s"], ev["rejoined"], ev["rejoin_ts"]),
                         ("info", "Porch Sensor", 7, 7, t + 1, 1019, True, t + 1000))
        self.assertIn("heard again under key generation 7, within one of its parent's 7; it rejoined at",
                      ev["note"])
        row = pipe.seen.table[SENSOR]
        for key in Pipeline.KEYLAG_KEYS:
            self.assertNotIn(key, row)
        self.assertEqual(row["keylag_closed"], t + 1020)

    def test_a_child_that_catches_up_inside_the_window_is_neither_paged_nor_cleared(self):
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        t = self._mesh(pipe, t, 7, children=())
        pipe.ingest(frame(t, SENSOR, sequence=5))
        pipe.periodic(t + 1)
        self.assertIn("keylag_since", pipe.seen.table[SENSOR])
        pipe.ingest(frame(t + 300, SENSOR, sequence=7))
        pipe.periodic(t + 301)
        self.assertEqual(self._events(pipe, "key_lag"), [])
        self.assertEqual(self._events(pipe, "key_lag_cleared"), [])
        self.assertNotIn("keylag_since", pipe.seen.table[SENSOR])
        self.assertNotIn("keylag_closed", pipe.seen.table[SENSOR])     # nothing was sent: no hold-down

    def test_stale_readings_are_not_judged_and_a_new_parent_on_the_same_generation_closes_silently(self):
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        # The parent moved to 7 but its reading is now older than fresh_s.
        pipe.ingest(frame(t, ROUTER, sequence=7))
        pipe.ingest(frame(t + 2000, SENSOR, sequence=5))
        pipe.periodic(t + 2001)
        self.assertNotIn("keylag_since", pipe.seen.table[SENSOR])
        # The child's own reading is stale: not judged either.
        pipe.ingest(frame(t + 2010, ROUTER, sequence=7))
        pipe.periodic(t + 2000 + 1801)
        self.assertNotIn("keylag_since", pipe.seen.table[SENSOR])
        # Both fresh: opened. Then the child re-attaches under router 2,
        # which is still on 5: closed without a word.
        pipe.ingest(frame(t + 4000, ROUTER, sequence=7))
        pipe.ingest(frame(t + 4000, ROUTER2, sequence=5))
        pipe.ingest(frame(t + 4001, SENSOR, sequence=5))
        pipe.periodic(t + 4002)
        self.assertEqual(pipe.seen.table[SENSOR]["keylag_parent"], ROUTER)
        pipe.ingest(short_frame(t + 4100, "0801", SENSOR, sequence=5))
        pipe.periodic(t + 4101)
        self.assertNotIn("keylag_since", pipe.seen.table[SENSOR])
        self.assertEqual([r["event"] for r in pipe.events.records if r["event"] in ("key_lag", "key_lag_cleared")],
                         [])

    def test_a_router_behind_the_mesh_is_critical_and_one_straggler_frame_is_not_the_mesh(self):
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5, routers=(ROUTER, ROUTER2, ROUTER3))
        # One frame from the sensor under 7 raises the decryptor's mesh
        # value; no router is on it, so nobody is judged behind it.
        pipe.ingest(frame(t, SENSOR, sequence=7))
        self.assertEqual(pipe.decryptor.key_sequence, 7)
        pipe.periodic(t + 1)
        for r in (ROUTER, ROUTER2, ROUTER3):
            self.assertNotIn("keylag_since", pipe.seen.table[r])
        # Two routers fresh on 7 make it the mesh's generation; the third,
        # still on 5, is two behind.
        t = self._mesh(pipe, t + 10, 7, routers=(ROUTER, ROUTER2), children=())
        pipe.ingest(frame(t, ROUTER3, sequence=5))
        pipe.periodic(t + 1)
        self.assertEqual(pipe.seen.table[ROUTER3]["keylag_gens"], [5, 7])
        self.assertEqual(self._events(pipe, "key_lag"), [])
        pipe.ingest(frame(t + 950, ROUTER3, sequence=5))
        pipe.periodic(t + 960)
        evs = self._events(pipe, "key_lag")
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual((ev["severity"], ev["name"], ev["role"], ev["generation"], ev["mesh_generation"],
                          ev["lag"], ev["parent"], ev["auto_snapshot"]),
                         ("critical", "Shed Router", "router", 5, 7, 2, None, None))
        self.assertNotIn("parent_generation", ev)
        self.assertIn("while the mesh is on 7", ev["note"])
        self.assertIn("cuts off every child that follows it", ev["note"])

    def test_confirm_zero_pages_on_the_frame_that_opens_the_episode(self):
        self.cfg.key_confirm_s = 0
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        t = self._mesh(pipe, t, 7, children=())
        pipe.ingest(frame(t, SENSOR, sequence=5))
        pipe.periodic(t + 1)
        evs = self._events(pipe, "key_lag")
        self.assertEqual([(e["severity"], e["lagged_for_s"]) for e in evs], [("warning", 0)])

    def test_the_open_episode_and_its_page_survive_a_restart(self):
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        t = self._mesh(pipe, t, 7, children=())
        pipe.ingest(frame(t, SENSOR, sequence=5))
        pipe.periodic(t + 1)
        pipe.seen.save()
        pipe2 = self._pipe()                                             # restarted inside the window
        pipe2.ingest(frame(t + 500, ROUTER, sequence=7))
        pipe2.ingest(frame(t + 500, ROUTER2, sequence=7))
        pipe2.ingest(frame(t + 950, SENSOR, sequence=5))
        pipe2.periodic(t + 960)
        self.assertEqual(len(self._events(pipe2, "key_lag")), 1)
        self.assertEqual(self._events(pipe2, "key_lag")[0]["since"], t + 1)
        pipe3 = self._pipe()                                             # restarted after the page: not again
        pipe3.ingest(frame(t + 1500, ROUTER, sequence=7))
        pipe3.ingest(frame(t + 1500, ROUTER2, sequence=7))
        pipe3.ingest(frame(t + 1600, SENSOR, sequence=5))
        pipe3.periodic(t + 1601)
        self.assertEqual(self._events(pipe3, "key_lag"), [])
        pipe3.ingest(frame(t + 1700, SENSOR, sequence=7))
        pipe3.periodic(t + 1701)
        self.assertEqual(len(self._events(pipe3, "key_lag_cleared")), 1)
        self.assertFalse(self._events(pipe3, "key_lag_cleared")[0]["rejoined"])

    def test_an_episode_reopening_within_rearm_s_is_a_notice(self):
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        t = self._mesh(pipe, t, 7, children=())
        pipe.ingest(frame(t, SENSOR, sequence=5))
        pipe.periodic(t + 1)
        pipe.ingest(frame(t + 950, SENSOR, sequence=5))
        pipe.periodic(t + 960)
        pipe.ingest(frame(t + 1000, SENSOR, sequence=7))                 # caught up: cleared
        pipe.periodic(t + 1001)
        self.assertEqual(len(self._events(pipe, "key_lag_cleared")), 1)
        t = self._mesh(pipe, t + 1100, 9, children=())                   # two more rotations, minutes later
        pipe.ingest(frame(t, SENSOR, sequence=7))
        pipe.periodic(t + 1)
        pipe.ingest(frame(t + 950, SENSOR, sequence=7))
        pipe.periodic(t + 960)
        evs = self._events(pipe, "key_lag")
        self.assertEqual([(e["severity"], e["episode"]) for e in evs], [("warning", 1), ("notice", 2)])
        self.assertEqual(evs[1]["since_previous_s"], (t + 1) - (self.T0 + 40 + 1001))
        self.assertIn("Episode 2 since the last page", evs[1]["note"])
        self.assertIn("logged, not paged", evs[1]["note"])

    def test_the_census_lists_who_followed_and_who_could_not_be_judged(self):
        self.cfg.key_census_delay_s = 600
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 4, routers=(ROUTER, ROUTER2, ROUTER3), children=(SENSOR, SENSOR2))
        for dt in (0, 200, 400):                                         # heard for 400 s, long ago: unknown
            pipe.ingest(frame(t + dt, "d4d4d4d4d4d4d4d4", sequence=4))  # (past the visit limit: a device)
        t += 3600
        t = self._mesh(pipe, t, 5, routers=(ROUTER, ROUTER2, ROUTER3), children=(SENSOR,))
        pipe.ingest(frame(t, SENSOR2, sequence=4))                       # the garage sensor never followed
        pipe.periodic(t)                                                 # the census for 5 is not yet due
        self.assertEqual(self._events(pipe, "key_lag_census"), [])
        t = self._mesh(pipe, t, 6, routers=(ROUTER, ROUTER2), children=())    # rotation to 6
        due = self._events(pipe, "key_sequence_advanced")[-1]["ts"] + 600
        pipe.ingest(frame(t, ROUTER3, sequence=5))                      # a router one behind
        pipe.ingest(frame(t + 1, SENSOR, sequence=5))                    # a child one behind its parent
        pipe.ingest(frame(t + 2, SENSOR2, sequence=4))                   # a child two behind: cut off
        pipe.periodic(due - 1)
        self.assertEqual(self._events(pipe, "key_lag_census"), [])
        pipe.periodic(due)
        evs = self._events(pipe, "key_lag_census")
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual((ev["severity"], ev["sequence"], ev["mesh_generation"], ev["counts"]),
                         ("info", 6, 6, {"6": 2, "5": 2, "4": 1}))
        self.assertEqual([(i["name"], i["generation"], i["parent"], i["parent_generation"], i["lag"])
                          for i in ev["behind_parent_1"]], [("Porch Sensor", 5, "Hall Router", 6, 1)])
        self.assertEqual([(i["name"], i["generation"], i["lag"]) for i in ev["behind_parent_2plus"]],
                         [("Garage Sensor", 4, 2)])
        self.assertEqual([(i["name"], i["generation"], i["mesh_generation"], i["lag"]) for i in ev["routers_behind"]],
                         [("Shed Router", 5, 6, 1)])
        self.assertEqual(ev["unknown"], ["d4d4d4d4d4d4d4d4"])
        self.assertIn("one behind: Porch Sensor", ev["note"])
        self.assertIn("cut off (2+ behind): Garage Sensor", ev["note"])
        self.assertIn("routers behind the mesh: Shed Router", ev["note"])
        self.assertIn("1 not judged", ev["note"])
        pipe.periodic(due + 3600)                                        # once per rotation
        self.assertEqual(len(self._events(pipe, "key_lag_census")), 1)
        # The daily summary carries the same reading.
        summary = pipe.summary(due + 10)
        self.assertEqual((summary["key_generation"], summary["key_lag_1"], summary["key_lag_2plus"]),
                         (6, ["Porch Sensor", "Shed Router"], ["Garage Sensor"]))
        self.assertIn("key generation 6: 2 one behind, cut off: Garage Sensor", summary["note"])

    def test_the_census_survives_a_restart_and_the_state_file_is_in_snapshots(self):
        from threadwatch.snapshot import STATE_FILES
        self.assertIn("key-generations.json", STATE_FILES)
        self.cfg.key_census_delay_s = 600
        pipe = self._pipe()
        t = self._mesh(pipe, self.T0, 5)
        pipe.seen.save()
        pipe2 = self._pipe()
        self.assertEqual(pipe2._keys["census_at"], self.T0 + 600)
        pipe2.ingest(frame(t + 700, ROUTER, sequence=5))
        pipe2.periodic(t + 700)
        self.assertEqual(len(self._events(pipe2, "key_lag_census")), 1)
        self.assertIsNone(json.loads((self.cfg.state_dir / "key-generations.json").read_text())["census_at"])


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

    def test_a_saved_count_that_is_not_a_whole_number_is_dropped_at_load(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Config(data_dir=Path(d) / "data", devices_path=Path(d) / "devices.json")
            cfg.state_dir.mkdir(parents=True, exist_ok=True)
            row = {"first_seen": 1.0, "last_seen": 2.0, "frames": 1, "types": {}}
            (cfg.state_dir / "last-seen.json").write_text(json.dumps({SENSOR: row}))
            (cfg.state_dir / "observed-names.json").write_text(json.dumps(
                {SENSOR: {"porch.local": "x", "den.local": True, "hall.local": 2}}))
            pipe = Pipeline(cfg, NullEventLog(), stub_decryptor())
            self.assertEqual(pipe.observed_names, {SENSOR: {"hall.local": 2}})
            pipe._note_observed_name(SENSOR, "porch.local")         # raised on "x" += 1
            self.assertEqual(pipe.observed_names[SENSOR], {"hall.local": 2, "porch.local": 1})


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

    @staticmethod
    def heard(pipe, addr, first, rssi=-60.0, n=Pipeline.ROTATION_MIN_FRAMES, every=1.0):
        """``addr`` on air from ``first``, as a border router is: enough
        frames for the row to carry a signal level worth comparing. Returns
        when it was last heard."""
        for i in range(n):
            pipe.ingest(frame(first + i * every, addr, rssi=rssi))
        return first + (n - 1) * every

    def test_rebooted_hub_keeps_its_name_and_the_old_address_retires(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 3600                              # real-clock times: the restart below judges silences by now
        self.heard(pipe, self.OLD, t)
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
        # The frame that binds the name is the only one the new address has:
        # no router id yet, and no average worth comparing. Nothing is
        # retired on that, and nothing is reported either, because a look
        # with nothing to go on is not a look that doubts the claim.
        self.assertNotIn("rotated_to", pipe.seen.table[self.OLD])
        self.assertEqual([r["event"] for r in pipe.events.records
                          if r["event"].startswith("border_router")], [])
        # Once it has stood up on air, the next browse retires the old one.
        self.heard(pipe, self.NEW, t + 601)
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 700)
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

    def rotate_without_corroboration(self, pipe, t, old_rloc16=None):
        """Ingest a rotation the radio contradicts: OLD went on transmitting
        after NEW started, and NEW is heard 30 dB away from where OLD was.
        Returns the time of the browse that claims it. OLD's last frame stays
        older than NEW's, so this is a claim to judge, not a stale record."""
        self.heard(pipe, self.OLD, t, rssi=-50.0)
        if old_rloc16:
            self.hold_rloc16(pipe, self.OLD, old_rloc16, t + 50, rssi=-50.0)
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        self.heard(pipe, self.NEW, t + 100, rssi=-80.0)
        self.heard(pipe, self.OLD, t + 300, rssi=-50.0)
        self.heard(pipe, self.NEW, t + 400, rssi=-80.0)
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 500)
        return t + 500

    @staticmethod
    def hold_rloc16(pipe, ext, short, ts, rssi=-60.0):
        """``ext`` heard answering to the router id ``short``, the way the
        recorder learns one: a short-source frame the decryptor can map and
        the MIC vouches for."""
        pipe.decryptor.short_to_ext[short] = ext
        pipe.ingest(short_frame(ts, short, ext, rssi=rssi))

    def test_a_rotation_the_radio_contradicts_is_named_but_not_retired(self):
        # Naming and retiring are split on purpose. mDNS carries the name
        # across; only the radio takes an address out of the quiet checks,
        # because a wrong retirement is a device that can never page again.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 7200
        at = self.rotate_without_corroboration(pipe, t)
        self.assertEqual(pipe.names.name(self.NEW), "Living Room Apple TV")   # named
        self.assertEqual(pipe.routers[self.HOST]["addr"], self.NEW)
        self.assertNotIn("rotated_to", pipe.seen.table[self.OLD])             # not retired
        self.assertEqual([r["event"] for r in pipe.events.records
                          if r["event"] == "border_router_address_changed"], [])
        ev = [r for r in pipe.events.records if r["event"] == "border_router_rotation_unverified"]
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["addr"], ev[0]["previous"]), (self.NEW, self.OLD))
        self.assertIn("on air together", ev[0]["missing"])
        self.assertIn("dB from the old address", ev[0]["missing"])
        self.assertIn(f'threadwatch name {self.NEW} "Living Room Apple TV"', ev[0]["note"])
        # And the old address goes on being judged: the silence it is in is
        # reported, which is the whole point of not retiring it.
        pipe.periodic(at + 1700)
        self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"], [self.OLD])

    def test_a_later_browse_corroborates_the_rotation_and_retires_it(self):
        # An address heard once has no router id and no settled level, so the
        # browse that first reports a real rotation often cannot corroborate
        # it. Each later browse looks again.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 7200
        at = self.rotate_without_corroboration(pipe, t, old_rloc16="1c00")
        self.hold_rloc16(pipe, self.NEW, "1c00", at + 100)      # the id it asked the leader for back
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], at + 200)
        self.assertEqual(pipe.seen.table[self.OLD]["rotated_to"], self.NEW)
        ev = [r for r in pipe.events.records if r["event"] == "border_router_address_changed"]
        self.assertEqual(len(ev), 1)
        self.assertIn("kept router id 1c00", ev[0]["evidence"])
        self.assertIn("corroborated by a later browse", ev[0]["note"])
        self.assertNotIn("unverified_previous", pipe.routers[self.HOST])
        pipe.periodic(at + 3600)            # retired now: no quiet for the old address
        self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"], [self.NEW])

    def test_a_kept_router_id_corroborates_a_rotation_on_its_own(self):
        # Nothing off the mesh can arrange for the new address to answer to
        # the id the old one held, so it does not need the weaker signs.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 7200
        pipe.ingest(frame(t, self.OLD, rssi=-50.0))
        self.hold_rloc16(pipe, self.OLD, "1c00", t + 50, rssi=-50.0)
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        pipe.ingest(frame(t + 100, self.NEW, rssi=-80.0))       # 30 dB away
        pipe.ingest(frame(t + 300, self.OLD, rssi=-50.0))       # and overlapping
        self.hold_rloc16(pipe, self.NEW, "1c00", t + 400, rssi=-80.0)
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 500)
        self.assertEqual(pipe.seen.table[self.OLD]["rotated_to"], self.NEW)
        ev = [r for r in pipe.events.records if r["event"] == "border_router_address_changed"]
        self.assertEqual(ev[0]["evidence"], "kept router id 1c00")

    def test_an_uncorroborated_claim_stops_being_looked_at_after_six_hours(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 86400
        at = self.rotate_without_corroboration(pipe, t)
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], at + 600)
        self.assertEqual(pipe.routers[self.HOST]["unverified_previous"], self.OLD)   # still looking
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)],
                                   at + Pipeline.ROTATION_RECHECK_S + 60)
        self.assertNotIn("unverified_previous", pipe.routers[self.HOST])
        self.assertNotIn("rotated_to", pipe.seen.table[self.OLD])                    # and never retired
        # Reported once, when it was claimed; the looking is silent.
        self.assertEqual(len([r for r in pipe.events.records
                              if r["event"] == "border_router_rotation_unverified"]), 1)

    def test_a_device_that_turned_up_later_cannot_be_claimed_as_the_rotation(self):
        # "The old address stopped before the new one started" is true of
        # every device that ever joined the mesh afterwards. Without a bound
        # on the gap, a forged advertisement naming any such address -- at a
        # similar level, which says nothing on its own -- retired the hub.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 200000
        stranger = "aaaaaaaaaaaaaaaa"
        self.heard(pipe, self.OLD, t, rssi=-60.0)
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        self.heard(pipe, stranger, t + 86400, rssi=-60.0)            # a day later, same level
        pipe._apply_border_routers([self.router(self.HOST, stranger)], t + 86500)
        self.assertNotIn("rotated_to", pipe.seen.table[self.OLD])
        ev = [r for r in pipe.events.records if r["event"] == "border_router_rotation_unverified"]
        self.assertIn("after the old one stopped", ev[0]["missing"])
        pipe.periodic(t + 86500)                                     # and the hub's silence is still reported
        self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"], [self.OLD])

    def test_an_unverified_name_does_not_answer_for_the_old_address_silence(self):
        # Naming binds the address to the entry, and the entry is what
        # decides whose announced silence a frame ends. An address mDNS
        # alone put there must not end anybody's: the hub is still gone.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 7200
        at = self.rotate_without_corroboration(pipe, t)
        pipe.periodic(at + 1700)
        self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"], [self.OLD])
        pipe.ingest(frame(at + 1800, self.NEW, rssi=-80.0))          # only the candidate is talking
        self.assertEqual([r["event"] for r in pipe.events.records if r["event"] == "device_returned"], [])
        self.assertEqual(pipe.quiet_reported, {self.OLD})            # the episode stays open
        self.assertEqual(pipe.names.entry_addresses_of(self.NEW), [self.NEW])
        self.assertEqual(pipe.names.name(self.NEW), "Living Room Apple TV")   # still named, though

    def test_corroboration_arriving_after_the_window_does_not_retire(self):
        # The window has to bind the corroborating case too, or it is not a
        # window: it only ever stopped the looking when the looking failed.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 200000
        at = self.rotate_without_corroboration(pipe, t, old_rloc16="1c00")
        self.hold_rloc16(pipe, self.NEW, "1c00", at + 7 * 3600)
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], at + 7 * 3600 + 60)
        self.assertNotIn("rotated_to", pipe.seen.table[self.OLD])
        self.assertNotIn("unverified_previous", pipe.routers[self.HOST])
        # The same evidence inside the window does retire it.
        pipe2 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        at = self.rotate_without_corroboration(pipe2, t, old_rloc16="1c00")
        self.hold_rloc16(pipe2, self.NEW, "1c00", at + 3600)
        pipe2._apply_border_routers([self.router(self.HOST, self.NEW)], at + 3660)
        self.assertEqual(pipe2.seen.table[self.OLD]["rotated_to"], self.NEW)

    def test_a_claim_nothing_argues_against_is_reported_only_when_it_runs_out(self):
        # A claim the radio merely knows nothing about is the ordinary state
        # of a real rotation on the browse that binds it. Reporting that at
        # once would put a notice on every reboot, so it waits.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 200000
        self.heard(pipe, self.OLD, t)
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        pipe.ingest(frame(t + 80, self.NEW))            # heard twice and no more: nothing to compare,
        pipe.ingest(frame(t + 81, self.NEW))            # but nothing against it either
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 100)
        self.assertNotIn("rotated_to", pipe.seen.table[self.OLD])
        self.assertEqual([r["event"] for r in pipe.events.records
                          if r["event"].startswith("border_router")], [])          # silent
        self.assertEqual(pipe.routers[self.HOST]["unverified_previous"], self.OLD)
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)],
                                   t + 100 + Pipeline.ROTATION_RECHECK_S + 60)
        ev = [r for r in pipe.events.records if r["event"] == "border_router_rotation_unverified"]
        self.assertEqual(len(ev), 1)                                                # said once, at the end
        self.assertIn("too few to compare", ev[0]["missing"])
        self.assertNotIn("unverified_previous", pipe.routers[self.HOST])

    def test_the_browse_does_not_undo_a_rotation_the_operator_confirmed(self):
        # `threadwatch name` writes the new address into the entry, and that
        # is the confirmation an unverified rotation asks for. The next
        # browse names the same address again: the same binding with more
        # behind it, not an mDNS claim that demotes what the operator wrote.
        (Path(self.tmp.name) / "devices.json").write_text(json.dumps([
            {"name": "Living Room Apple TV",
             "extendedAddresses": [self.OLD.upper(), self.NEW.upper()]}]))
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 7200
        self.heard(pipe, self.OLD, t)
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        pipe.periodic(t + 31 * 60)
        self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"], [self.OLD])
        pipe.ingest(frame(t + 32 * 60, self.NEW))
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 33 * 60)
        self.assertEqual(pipe.names.learned, set())
        self.assertEqual(pipe.names.entry_addresses_of(self.NEW), [self.NEW, self.OLD])
        # The silence announced for the old address is over: its device is
        # transmitting under the address the operator vouched for.
        pipe.quiet_reported.add(self.OLD)
        pipe.seen.table[self.OLD]["quiet_reported"] = True
        pipe.ingest(frame(t + 34 * 60, self.NEW))
        self.assertEqual(pipe.quiet_reported, set())

    def test_a_contradiction_only_a_later_look_can_see_is_reported_then(self):
        # The old address talking on after the new one started is the
        # contradiction that takes a second look to see: at the browse that
        # bound the claim there was nothing to go on either way.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 200000
        self.heard(pipe, self.OLD, t, rssi=-60.0)
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        pipe.ingest(frame(t + 80, self.NEW, rssi=-60.0))
        pipe.ingest(frame(t + 81, self.NEW, rssi=-60.0))
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 100)
        self.assertEqual([r["event"] for r in pipe.events.records
                          if r["event"].startswith("border_router")], [])
        self.heard(pipe, self.OLD, t + 400, rssi=-60.0)      # the old address is plainly still alive
        self.heard(pipe, self.NEW, t + 600, rssi=-60.0)
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 700)
        ev = [r for r in pipe.events.records if r["event"] == "border_router_rotation_unverified"]
        self.assertEqual(len(ev), 1)
        self.assertIn("on air together", ev[0]["missing"])
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 1300)
        self.assertEqual(len([r for r in pipe.events.records
                              if r["event"] == "border_router_rotation_unverified"]), 1)   # said once
        self.assertNotIn("rotated_to", pipe.seen.table[self.OLD])

    def test_an_old_address_no_longer_tracked_is_not_held_back(self):
        # The gate exists to stop a claim silencing a row that is still being
        # judged. A row the track cap evicted is judged by nobody, so there
        # is nothing to hold back and the rotation is reported as usual.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 7200
        pipe.ingest(frame(t, self.OLD, rssi=-50.0))
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        pipe.ingest(frame(t + 100, self.NEW, rssi=-80.0))
        del pipe.seen.table[self.OLD]
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 200)
        ev = [r for r in pipe.events.records if r["event"] == "border_router_address_changed"]
        self.assertEqual(ev[0]["evidence"], "the old address is no longer tracked")
        self.assertEqual([r["event"] for r in pipe.events.records
                          if r["event"] == "border_router_rotation_unverified"], [])

    def test_trusted_retires_on_the_advertisement_alone(self):
        import dataclasses
        cfg = dataclasses.replace(self.cfg, border_router_rotation="trusted")
        pipe = Pipeline(cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 7200
        self.rotate_without_corroboration(pipe, t)
        self.assertEqual(pipe.seen.table[self.OLD]["rotated_to"], self.NEW)
        ev = [r for r in pipe.events.records if r["event"] == "border_router_address_changed"]
        self.assertIn('rotation = "trusted"', ev[0]["note"])
        self.assertEqual([r["event"] for r in pipe.events.records
                          if r["event"] == "border_router_rotation_unverified"], [])

    def test_an_address_never_heard_on_air_is_not_believed(self):
        # Anyone on the LAN can advertise _meshcop._udp with any address in
        # it. A forged record must not retire the real row (silencing its
        # quiet alerts) or hand the name to the forged address.
        import contextlib
        import io
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = time.time() - 7200
        self.heard(pipe, self.OLD, t)
        self.hold_rloc16(pipe, self.OLD, "1c00", t + 50)
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
        # Named on the advertisement; retired once the hub is heard holding
        # the router id it had before the reboot.
        self.assertNotIn("rotated_to", pipe.seen.table[self.OLD])
        self.heard(pipe, self.NEW, t + 42 * 60)
        self.hold_rloc16(pipe, self.NEW, "1c00", t + 43 * 60)
        pipe._apply_border_routers([self.router(self.HOST, self.NEW)], t + 50 * 60)
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
        self.heard(pipe, self.OLD, t)
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        self.heard(pipe, self.NEW, t + 600)
        self.hold_rloc16(pipe, self.NEW, "1c00", t + 650)
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
            self.heard(pipe, self.OLD, t + 7100)
            self.hold_rloc16(pipe, self.OLD, "1c00", t + 7150)   # rebooted: it asks for its id back
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
        self.heard(pipe, self.OLD, t)
        self.hold_rloc16(pipe, self.OLD, "1c00", t + 50)
        pipe._apply_border_routers([self.router(self.HOST, self.OLD)], t)
        pipe.periodic(t + 31 * 60)                          # the hub rebooted: its old address went quiet
        self.assertEqual([r["addr"] for r in pipe.events.records if r["event"] == "device_quiet"], [self.OLD])
        # ...and it is back under a new one. The outage was longer than any
        # handover window -- it had to be, to have been reported at all -- so
        # the router id it asked the leader for back is what carries this one.
        self.heard(pipe, self.NEW, t + 32 * 60)
        self.hold_rloc16(pipe, self.NEW, "1c00", t + 33 * 60)
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
        self.heard(pipe, "0011223344556677", t)
        stranger = self.router("homepod-kitchen.local", "0011223344556677", "HomePod Kitchen")
        pipe._apply_border_routers([stranger], t)
        pipe._apply_border_routers([stranger], t + 600)
        ev = [r for r in pipe.events.records if r["event"] == "border_router_unlisted"]
        self.assertEqual(len(ev), 1)
        self.assertIn("homepod-kitchen.local", ev[0]["note"])
        self.assertIsNone(pipe.names.name("0011223344556677"))
        self.heard(pipe, "8899aabbccddeeff", t + 100)
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
                          "leader_addr": None, "leader_name": None,        # no credentials: unmatched
                          "id_sequence": None, "sequence_advanced_ts": None, "stalled": False})
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
            pipe.ingest(frame(t + 4 * i, SENSOR, rssi=-88.0))     # unnamed: heard past the visit limit
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


class RadiosTest(unittest.TestCase):
    """What the pipeline keeps per radio, and what a radio going down
    changes about a silence."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        # Named: an unnamed address heard briefly is a visitor, not quiet.
        (d / "devices.json").write_text(json.dumps([
            {"name": "Router", "extendedAddress": ROUTER}, {"name": "Sensor", "extendedAddress": SENSOR},
            {"name": "Stranger", "extendedAddress": STRANGER}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")
        self.pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _heard(f, **copies):
        """f as the merger builds it: copies by radio label with their own RSSI."""
        from dataclasses import replace
        heard = {label: replace(f, rssi=rssi, radio=label) for label, rssi in copies.items()}
        best = max(copies, key=copies.get)
        return replace(f, rssi=copies[best], radio=best, heard=heard)

    def test_rows_keep_each_radios_count_stamp_and_level_beside_the_best_ear(self):
        t0 = 1_700_000_000.0
        for i in range(10):
            self.pipe.ingest(self._heard(frame(t0 + i, ROUTER), hub=-70.0, annex=-60.0))
        self.pipe.ingest(self._heard(frame(t0 + 10, ROUTER), hub=-71.0))
        row = self.pipe.seen.table[ROUTER]
        self.assertEqual(row["heard_by"], {"hub": 11, "annex": 10})
        self.assertEqual(row["last_seen_by"], {"hub": t0 + 10, "annex": t0 + 9})
        self.assertLess(row["rssi_by_radio"]["hub"], -69.9)
        self.assertEqual(row["rssi_by_radio"]["annex"], -60.0)
        self.assertLess(row["rssi"], -60.0)              # the best ear's average, a little off since annex missed one
        self.assertGreater(row["rssi"], -62.0)
        # A single unnamed dongle leaves rows exactly as they were.
        self.pipe.ingest(frame(t0 + 11, SENSOR))
        self.assertNotIn("heard_by", self.pipe.seen.table[SENSOR])
        from dataclasses import replace
        f = frame(t0 + 12, SENSOR)
        self.pipe.ingest(replace(f, radio=None, heard={None: f}))
        self.assertNotIn("heard_by", self.pipe.seen.table[SENSOR])

    def test_a_device_only_a_down_radio_was_hearing_is_a_notice_not_a_page(self):
        t0 = 1_700_000_000.0
        self.pipe.radio_changed("hub", "up", t0)
        self.pipe.radio_changed("annex", "up", t0)
        for i in range(40):
            self.pipe.ingest(self._heard(frame(t0 + i, ROUTER), annex=-60.0))            # annex alone hears it
            self.pipe.ingest(self._heard(frame(t0 + i, SENSOR), hub=-55.0, annex=-65.0))  # both hear this one
        self.pipe.radio_changed("annex", "down", t0 + 60)
        self.pipe.periodic(t0 + 91 * 60)
        by_addr = {r["addr"]: r for r in self.pipe.events.records if r["event"] == "device_quiet"}
        self.assertEqual((by_addr[ROUTER]["severity"], by_addr[ROUTER]["reception"], by_addr[ROUTER]["radio_down"]),
                         ("notice", "unheard", "annex"))
        self.assertIn("the only radio that heard this device lately (annex) is down", by_addr[ROUTER]["note"])
        self.assertEqual((by_addr[SENSOR]["severity"], by_addr[SENSOR]["reception"]), ("warning", "good"))
        # With the radio back up, the same silence is the device's.
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        pipe.radio_changed("hub", "up", t0)
        pipe.radio_changed("annex", "up", t0)
        for i in range(40):
            pipe.ingest(self._heard(frame(t0 + 100 + i, STRANGER), annex=-60.0))
        pipe.periodic(t0 + 100 + 91 * 60)
        evs = [r for r in pipe.events.records if r["event"] == "device_quiet" and r["addr"] == STRANGER]
        self.assertEqual([(e["severity"], e["reception"]) for e in evs], [("warning", "good")])

    def test_losing_the_best_ear_re_bases_the_link_reference_instead_of_fading_every_device(self):
        t0 = 1_700_000_000.0
        self.pipe.radio_changed("hub", "up", t0)
        self.pipe.radio_changed("annex", "up", t0)
        for i in range(300):
            self.pipe.ingest(self._heard(frame(t0 + i, ROUTER), hub=-78.0, annex=-60.0))
        self.pipe.periodic(t0 + 300)                    # the link reference is taken at the annex's level
        row = self.pipe.seen.table[ROUTER]
        self.assertEqual(row["rssi_ref"], row["rssi"])
        self.assertAlmostEqual(row["rssi_ref"], -60.0, delta=0.5)
        self.pipe.radio_changed("annex", "down", t0 + 301)
        self.assertEqual((row["rssi_ref"], row["rssi_ref_ts"]), (-78.0, t0 + 301))
        # An hour of hub-only frames at its own level: no degradation.
        for i in range(3600):
            self.pipe.ingest(self._heard(frame(t0 + 400 + i, ROUTER), hub=-78.0))
            if i % 30 == 0:
                self.pipe.periodic(t0 + 400 + i)
        self.assertEqual([r["event"] for r in self.pipe.events.records if r["event"] == "rssi_degradation"], [])


def pending_ack(ts, seq):
    """An ACK with Frame Pending set: the parent's radio promising a frame."""
    return Frame(ts=ts, raw=b"", psdu=b"", rssi=-40.0, channel=None, lqi=None, ftype=2, seq=seq, pending=True)


def mle_frame(ts, src_ext, sequence, body, mle_counter=None, mac_counter=None):
    """A MAC-secured frame from ``src_ext`` carrying a secured MLE message
    with the given body (command byte plus TLVs) under one key generation.
    The counters default to the next for the source; a test that wants the
    message to advertise something other than the truth sets them."""
    import struct

    from cryptography.hazmat.primitives.ciphers.aead import AESCCM

    from tests.frames import KEY, next_counter, secured_psdu
    from tests.test_identity import ALL_NODES, LINK_LOCAL, lowpan_udp
    from threadwatch.crypto import derive_keys
    from threadwatch.pcap import parse_frame
    mac_counter = next_counter(src_ext) if mac_counter is None else mac_counter
    mle_counter = mac_counter if mle_counter is None else mle_counter
    src_ip = LINK_LOCAL + Decryptor._iid_from_ext(src_ext)
    aux = bytes([5 | (2 << 3)]) + struct.pack("<L", mle_counter) + struct.pack(">L", sequence) \
        + bytes([(sequence & 0x7f) + 1])
    mle_key, _mac = derive_keys(KEY, sequence)
    nonce = bytes.fromhex(src_ext) + struct.pack(">L", mle_counter) + bytes([5])
    msg = bytes([0]) + aux + AESCCM(mle_key, tag_length=4).encrypt(nonce, body, src_ip + ALL_NODES + aux)
    psdu = secured_psdu(src_ext, mac_counter, dst="ffff", seq=int(ts) & 0xFF,
                        payload=lowpan_udp(19788, 19788, msg), sequence=sequence)
    return parse_frame(ts, psdu, 230)


class FragmentedMleTest(unittest.TestCase):
    """An MLE message too big for one frame (a Data Response carrying
    Network Data) is decrypted once, when its last fragment is in; the
    FRAG1 alone is not a failed decryption."""

    def test_the_frag1_alone_is_neither_decrypted_nor_failed(self):
        import struct

        from cryptography.hazmat.primitives.ciphers.aead import AESCCM

        from tests.frames import KEY, next_counter, secured_psdu
        from tests.test_identity import ALL_NODES, LINK_LOCAL, lowpan_udp
        from tests.test_srp import lowpan_fragments
        from threadwatch.crypto import derive_keys
        from threadwatch.pcap import parse_frame
        # Data Response: Source Address, Leader Data, 160 bytes of Network Data.
        body = (bytes([8, 0, 2, 0x04, 0x00, 11, 8]) + struct.pack(">LBBBB", 0xCAFEF00D, 64, 1, 1, 5)
                + bytes([12, 160]) + bytes(160))
        counter = next_counter(ROUTER)
        aux = bytes([5 | (2 << 3)]) + struct.pack("<L", counter) + struct.pack(">L", 0) + bytes([1])
        mle_key, _mac = derive_keys(KEY, 0)
        nonce = bytes.fromhex(ROUTER) + struct.pack(">L", counter) + bytes([5])
        src_ip = LINK_LOCAL + Decryptor._iid_from_ext(ROUTER)
        msg = bytes([0]) + aux + AESCCM(mle_key, tag_length=4).encrypt(nonce, body, src_ip + ALL_NODES + aux)
        frags = lowpan_fragments(lowpan_udp(19788, 19788, msg), 10, first_chunk=64, chunk=128)
        self.assertEqual(len(frags), 2)
        with tempfile.TemporaryDirectory() as tmp:
            dec = Decryptor(network_key=KEY)
            pipe = Pipeline(Config(data_dir=Path(tmp), devices_path=Path(tmp) / "devices.json"),
                            NullEventLog(), dec, ephemeral=True)
            got = []
            for i, frag in enumerate(frags):
                c = counter if i == 0 else next_counter(ROUTER)
                psdu = secured_psdu(ROUTER, c, dst="ffff", seq=i, payload=frag)
                pipe.ingest(parse_frame(1_700_000_000.0 + i * 0.01, psdu, 230))
                got.append((dec.stats["mle_decrypted"], dec.stats["mle_failed"]))
        self.assertEqual(got, [(0, 0), (1, 0)])


def child_id_request(link_counter, mle_counter):
    """An MLE Child ID Request body advertising the two frame counters."""
    import struct
    return (bytes([11]) + bytes([5, 4]) + struct.pack(">L", link_counter)
            + bytes([8, 4]) + struct.pack(">L", mle_counter))


class PollUnservedTest(unittest.TestCase):
    """poll_unserved / poll_served: polls the parent's radio acknowledges
    with Frame Pending and the parent's stack never follows up on
    (docs/ALERTING.md). The child is Porch Sensor; its parent is Hall
    Router, whose data frames to the child are the deliveries."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([{"name": "Porch Sensor", "extendedAddress": SENSOR},
                                                    {"name": "Hall Router", "extendedAddress": ROUTER}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")

    def tearDown(self):
        self.tmp.cleanup()

    @staticmethod
    def _events(pipe, name):
        return [r for r in pipe.events.records if r["event"] == name]

    def _served_polls(self, pipe, t, n, seq0=0):
        """n polls, each acknowledged with data pending and then served."""
        for i in range(n):
            seq = (seq0 + i) & 0xFF
            pipe.ingest(poll(t + 5 * i, SENSOR, seq))
            pipe.ingest(pending_ack(t + 5 * i + 0.001, seq))
            pipe.ingest(frame(t + 5 * i + 0.02, ROUTER, dst=SENSOR))
        return t + 5 * n

    def _unserved_polls(self, pipe, t, n, seq0=100, gap=10.0):
        """n polls acknowledged with data pending and nothing after."""
        for i in range(n):
            seq = (seq0 + i) & 0xFF
            pipe.ingest(poll(t + gap * i, SENSOR, seq))
            pipe.ingest(pending_ack(t + gap * i + 0.001, seq))
        return t + gap * n

    def test_served_polls_and_plain_acknowledgements_report_nothing(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._served_polls(pipe, 1_700_000_000.0, 20)
        for i in range(20):                              # nothing pending: nothing owed
            pipe.ingest(poll(t + 5 * i, SENSOR, 50 + i))
            pipe.ingest(ack(t + 5 * i + 0.001, 50 + i))
        self.assertEqual(self._events(pipe, "poll_unserved"), [])
        stats = pipe.devices[SENSOR]
        self.assertEqual((stats.served_polls, stats.unserved_polls, stats.unserved), (20, 0, False))
        self.assertTrue(pipe.seen.table[SENSOR]["polls_served"])

    def test_pending_acknowledgements_nothing_follows_is_logged_then_paged_then_closed(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t0 = 1_700_000_000.0
        t = self._served_polls(pipe, t0, 5)
        t = self._unserved_polls(pipe, t, 12)            # each judged by the next: 11 unserved by the 12th
        evs = self._events(pipe, "poll_unserved")
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual((ev["severity"], ev["confirmed"], ev["name"], ev["served_polls"], ev["unserved_polls"],
                          ev["parent_rloc16"], ev["episode"], ev["reception"]),
                         ("notice", False, "Porch Sensor", 5, 10, "0000", 1, "good"))
        self.assertEqual(ev["since"], t0 + 25 + 0.001)   # the first pending ACK nothing followed
        self.assertIn("acknowledged 10 polls over 100 s with data pending", ev["note"])
        self.assertIn("frame_counter_mismatch", ev["note"])
        row = pipe.seen.table[SENSOR]
        self.assertTrue(row["unserved"])
        self.assertEqual(row["unserved_confirm_at"], ev["ts"] + self.cfg.poll_confirm_s)
        # Still going past the mark: the page, on a poll acknowledged after it.
        t = self._unserved_polls(pipe, t, 70, seq0=120)
        evs = self._events(pipe, "poll_unserved")
        self.assertEqual(len(evs), 2)
        self.assertEqual((evs[1]["severity"], evs[1]["confirmed"], evs[1]["since"]), ("warning", True, ev["since"]))
        self.assertGreaterEqual(evs[1]["unserved_for_s"], self.cfg.poll_confirm_s)
        self.assertNotIn("unserved_confirm_at", row)
        # The parent delivers: closed, and the close time is kept.
        pipe.ingest(poll(t, SENSOR, 200))
        pipe.ingest(pending_ack(t + 0.001, 200))
        pipe.ingest(frame(t + 0.02, ROUTER, dst=SENSOR))
        served = self._events(pipe, "poll_served")
        self.assertEqual(len(served), 1)
        self.assertEqual(served[0]["name"], "Porch Sensor")
        self.assertNotIn("unserved", row)
        self.assertEqual(row["unserved_closed"], t + 0.02)
        self.assertEqual(len(self._events(pipe, "poll_unserved")), 2)
        # A delivery to the child's short address counts too.
        pipe.ingest(short_frame(t + 1, "0401", SENSOR))
        pipe.ingest(poll(t + 2, SENSOR, 201, dst="0400"))
        pipe.ingest(pending_ack(t + 2.001, 201))
        pipe.ingest(frame(t + 2.02, ROUTER, dst="0401"))
        self.assertEqual(pipe.devices[SENSOR].served_polls, 7)

    def test_a_restart_keeps_the_open_episode_and_the_first_delivery_closes_it(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._served_polls(pipe, 1_700_000_000.0, 5)
        t = self._unserved_polls(pipe, t, 12)
        self.assertEqual(len(self._events(pipe, "poll_unserved")), 1)
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        self.assertTrue(pipe2.devices[SENSOR].unserved)
        t = self._unserved_polls(pipe2, t, 12, seq0=150)       # not announced again
        self.assertEqual(self._events(pipe2, "poll_unserved"), [])
        pipe2.ingest(poll(t, SENSOR, 200))
        pipe2.ingest(pending_ack(t + 0.001, 200))
        pipe2.ingest(frame(t + 0.02, ROUTER, dst=SENSOR))
        self.assertEqual(len(self._events(pipe2, "poll_served")), 1)
        self.assertIn("before it was confirmed", self._events(pipe2, "poll_served")[0]["note"])

    def test_a_child_never_served_before_is_not_reported(self):
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        self._unserved_polls(pipe, 1_700_000_000.0, 30)
        self.assertEqual(self._events(pipe, "poll_unserved"), [])

    def test_the_ha_cause_reads_the_open_episode(self):
        from threadwatch.hacause import classify
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._served_polls(pipe, 1_700_000_000.0, 5)
        t = self._unserved_polls(pipe, t, 12)
        cause, sentence = classify(pipe.seen.table[SENSOR], None, t - 900, t)
        self.assertEqual(cause, "dropped_polls")
        self.assertIn("poll_unserved", sentence)

    def test_an_episode_the_device_can_no_longer_close_is_closed_on_silence(self):
        # Only a delivered frame closes it, and a device that has stopped
        # polling is owed none: left open, the HA cause blames the parent.
        from threadwatch.hacause import classify
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t = self._served_polls(pipe, 1_700_000_000.0, 5)
        t = self._unserved_polls(pipe, t, 12)
        self.assertEqual(len(self._events(pipe, "poll_unserved")), 1)
        for i in range(1, 7):                            # the parent stays audible; the child does not
            pipe.ingest(frame(t + 600 * i, ROUTER))
            pipe.periodic(t + 600 * i)
        served = self._events(pipe, "poll_served")
        self.assertEqual(len(served), 1)
        self.assertIn("stopped polling altogether", served[0]["note"])
        row = pipe.seen.table[SENSOR]
        self.assertNotIn("unserved", row)
        self.assertNotIn("unserved_confirm_at", row)
        self.assertEqual(row["unserved_closed"], served[0]["ts"])
        self.assertFalse(pipe.devices[SENSOR].unserved)
        self.assertNotIn(SENSOR, pipe._awaiting_delivery.values())
        cause, _ = classify(row, None, t + 3000, t + 3600)
        self.assertNotEqual(cause, "dropped_polls")


class FrameCounterMismatchTest(unittest.TestCase):
    """frame_counter_mismatch: a device's accepted frames run below the
    counter it advertised for them (docs/ALERTING.md)."""

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

    def test_polls_below_the_advertised_link_counter_are_reported_once_an_hour(self):
        from tests.frames import next_counter
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t0 = 1_700_000_000.0
        pipe.ingest(frame(t0, SENSOR))                                    # known before it attaches
        c0 = next_counter(SENSOR)
        pipe.ingest(mle_frame(t0 + 1, SENSOR, 0, child_id_request(1_280_176_180, 1029),
                              mac_counter=c0, mle_counter=1029))
        row = pipe.seen.table[SENSOR]
        self.assertEqual(row["adv_mac"], [1_280_176_180, 0, t0 + 1, "Child ID Request"])
        self.assertEqual(row["adv_mle"], [1029, 0, t0 + 1, "Child ID Request"])
        for i in range(2):                                                # two below: queued frames, maybe
            pipe.ingest(poll(t0 + 2 + i, SENSOR, i, counter=c0 + 1 + i))
        self.assertEqual(self._events(pipe, "frame_counter_mismatch"), [])
        pipe.ingest(poll(t0 + 4, SENSOR, 2, counter=c0 + 3))
        evs = self._events(pipe, "frame_counter_mismatch")
        self.assertEqual(len(evs), 1)
        ev = evs[0]
        self.assertEqual((ev["severity"], ev["name"], ev["layer"], ev["key_sequence"], ev["advertised"],
                          ev["advertised_in"], ev["advertised_ts"], ev["counter"], ev["lowest"],
                          ev["shortfall"], ev["frames_below"]),
                         ("warning", "Porch Sensor", "mac", 0, 1_280_176_180, "Child ID Request", t0 + 1,
                          c0 + 3, c0 + 1, 1_280_176_180 - c0 - 3, 3))
        self.assertIn("device-side defect to report to the vendor", ev["note"])
        self.assertEqual(row["counter_mismatch_ts"], t0 + 4)
        for i in range(20):                                               # it goes on: said again after an hour
            pipe.ingest(poll(t0 + 10 + 300 * i, SENSOR, 10 + i, counter=c0 + 10 + i))
        evs = self._events(pipe, "frame_counter_mismatch")
        self.assertEqual(len(evs), 2)                                     # once, then the hour mark
        self.assertEqual((evs[1]["frames_below"], evs[1]["ts"]), (16, t0 + 10 + 300 * 12))
        # Advertised again, this time truthfully: the floor moves, nothing more.
        c1 = c0 + 100
        pipe.ingest(mle_frame(t0 + 7000, SENSOR, 0, child_id_request(c1 + 1, 1030), mac_counter=c1, mle_counter=1030))
        for i in range(5):
            pipe.ingest(poll(t0 + 7001 + i, SENSOR, 40 + i, counter=c1 + 1 + i))
        self.assertEqual(len(self._events(pipe, "frame_counter_mismatch")), 2)
        from threadwatch.hacause import classify
        self.assertEqual(classify(row, None, t0 + 7000, t0 + 7010)[0], "counter_mismatch")
        self.assertNotEqual(classify(row, None, t0 + 20000, t0 + 20010)[0], "counter_mismatch")

    def test_re_advertising_the_same_wrong_counter_continues_the_episode(self):
        from tests.frames import next_counter
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t0 = 1_700_000_000.0
        pipe.ingest(frame(t0, SENSOR))
        c = next_counter(SENSOR)
        # Refused by its parent, the child times out and re-attaches every
        # four minutes; each Child ID Request repeats the wrong link counter
        # and three polls follow it.
        for i in range(20):
            t = t0 + 240 * i
            pipe.ingest(mle_frame(t, SENSOR, 0, child_id_request(1_280_176_180, 1029 + i),
                                  mac_counter=c, mle_counter=1029 + i))
            for j in range(3):
                c += 1
                pipe.ingest(poll(t + 1 + j, SENSOR, (4 * i + j) & 0xFF, counter=c))
            c += 1
        evs = self._events(pipe, "frame_counter_mismatch")
        self.assertEqual([e["ts"] for e in evs], [t0 + 3, t0 + 3600 + 3])   # once, then the hour mark
        # The hour-mark record counts every frame below since the first
        # advertisement: three polls, then a request and three polls per re-attachment.
        self.assertEqual((evs[1]["frames_below"], evs[1]["advertised_in"], evs[1]["advertised_ts"]),
                         (3 + 15 * 4, "Child ID Request", t0 + 3600))
        self.assertEqual(pipe.seen.table[SENSOR]["counter_mismatch_ts"], t0 + 3600 + 3)

    def test_queued_frames_behind_honest_advertisements_do_not_add_up(self):
        from tests.frames import next_counter
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t0 = 1_700_000_000.0
        pipe.ingest(frame(t0, SENSOR))
        c = next_counter(SENSOR)
        # Three attachments, each advertising two frames ahead of the poll
        # the device had already queued: two below each time, never three.
        for i in range(3):
            t = t0 + 3600 * i
            pipe.ingest(mle_frame(t, SENSOR, 0, child_id_request(c + 3, 1029 + i), mac_counter=c, mle_counter=1029 + i))
            pipe.ingest(poll(t + 1, SENSOR, 2 * i, counter=c + 1))
            pipe.ingest(poll(t + 2, SENSOR, 2 * i + 1, counter=c + 2))
            c += 10
        self.assertEqual(self._events(pipe, "frame_counter_mismatch"), [])

    def test_mle_messages_below_the_advertised_mle_counter_are_reported(self):
        from tests.frames import next_counter
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t0 = 1_700_000_000.0
        pipe.ingest(frame(t0, SENSOR))
        pipe.ingest(mle_frame(t0 + 1, SENSOR, 0, child_id_request(next_counter(SENSOR) + 1, 5000), mle_counter=100))
        for i in range(3):
            pipe.ingest(mle_frame(t0 + 2 + i, SENSOR, 0, bytes([13]), mle_counter=101 + i))   # Child Update Requests
        evs = self._events(pipe, "frame_counter_mismatch")
        self.assertEqual([(e["layer"], e["advertised"], e["counter"], e["frames_below"]) for e in evs],
                         [("mle", 5000, 103, 3)])

    def test_the_floor_survives_a_restart_and_a_new_generation_is_judged_apart(self):
        from tests.frames import next_counter
        pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        t0 = 1_700_000_000.0
        pipe.ingest(frame(t0, SENSOR))
        c0 = next_counter(SENSOR)
        pipe.ingest(mle_frame(t0 + 1, SENSOR, 0, child_id_request(1_000_000_000, 7), mac_counter=c0, mle_counter=7))
        pipe.seen.save()
        pipe2 = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        self.assertEqual(pipe2._advertised[SENSOR]["mac"]["value"], 1_000_000_000)
        for i in range(3):                                               # under generation 1: another floor
            pipe2.ingest(poll(t0 + 2 + i, SENSOR, i, counter=c0 + 1 + i, sequence=1))
        self.assertEqual(self._events(pipe2, "frame_counter_mismatch"), [])
        for i in range(3):
            pipe2.ingest(poll(t0 + 10 + i, SENSOR, 10 + i, counter=c0 + 10 + i))
        self.assertEqual(len(self._events(pipe2, "frame_counter_mismatch")), 1)


def leader_data(partition_id, router_id):
    """An MLE Leader Data TLV."""
    import struct
    return bytes([11, 8]) + struct.pack(">L", partition_id) + b"\x00\x00\x00" + bytes([router_id])


def route64(id_sequence):
    """An MLE Route64 TLV with just the ID sequence and an empty router mask."""
    return bytes([9, 9, id_sequence]) + bytes(8)


def advertisement(partition_id, router_id, id_sequence=None):
    body = b"\x04" + leader_data(partition_id, router_id)
    return body if id_sequence is None else body + route64(id_sequence)


class LeaderAndPartitionTest(unittest.TestCase):
    """leader_stalled / leader_resumed and the settled partition events
    (docs/ALERTING.md). Hall Router is the leader, router id 60 (RLOC16
    0xf000); Porch Sensor and two more routers repeat its sequence."""

    R2 = "a2a2a2a2a2a2a2a2"
    R3 = "a3a3a3a3a3a3a3a3"
    PART = 0x3a31cae5

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([{"name": "Hall Router", "extendedAddress": ROUTER},
                                                    {"name": "Den Router", "extendedAddress": self.R2},
                                                    {"name": "Loft Router", "extendedAddress": self.R3}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")
        self.pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())

    def tearDown(self):
        self.tmp.cleanup()

    def _events(self, name):
        return [r for r in self.pipe.events.records if r["event"] == name]

    def _adv(self, ts, src, seq, partition=PART, leader=60):
        # The leader's own advertisement carries its RLOC16 so the pipeline can name it.
        body = advertisement(partition, leader, seq)
        if src == ROUTER:
            body += bytes([0, 2]) + bytes.fromhex("f000")
        self.pipe.ingest(mle_frame(ts, src, 0, body))

    def test_a_leader_whose_sequence_stops_is_named_before_the_routers_give_it_up(self):
        t0 = 1_700_000_000.0
        for i, seq in enumerate((160, 162, 164)):
            self._adv(t0 + 30 * i, ROUTER, seq)
            self._adv(t0 + 30 * i + 5, self.R2, seq)
        self.pipe.periodic(t0 + 65)
        self.assertEqual(self._events("leader_stalled"), [])
        # From here the other routers keep repeating 164 and the leader is heard
        # (a Link Accept, say) without advancing it.
        for i in range(1, 5):
            self._adv(t0 + 60 + 20 * i, self.R2, 164)
            self._adv(t0 + 60 + 20 * i + 3, self.R3, 164)
            self._adv(t0 + 60 + 20 * i + 6, ROUTER, 164)
        self.pipe.periodic(t0 + 60 + 55)
        self.assertEqual(self._events("leader_stalled"), [])           # 55 s: under the threshold
        self.pipe.periodic(t0 + 60 + 62)
        stalled = self._events("leader_stalled")
        self.assertEqual(len(stalled), 1)
        rec = stalled[0]
        self.assertEqual((rec["leader_router"], rec["leader"], rec["addr"], rec["name"], rec["id_sequence"]),
                         (60, "r60 (Hall Router)", ROUTER, "Hall Router", 164))
        self.assertEqual(rec["since"], t0 + 60)
        self.assertEqual(rec["stalled_for_s"], 62)
        self.assertIn("has not advanced the router-id sequence (164) for 62 s", rec["note"])
        self.assertIn("its stack still answers while its leader timer has stopped", rec["note"])
        self.assertIn("120 s after the last advance", rec["note"])
        self.assertTrue(self.pipe.partition_status()["stalled"])
        self.pipe.periodic(t0 + 60 + 92)
        self.assertEqual(len(self._events("leader_stalled")), 1)      # said once per stall
        # The sequence moves again: the episode closes.
        self._adv(t0 + 60 + 100, self.R3, 165)
        resumed = self._events("leader_resumed")
        self.assertEqual(len(resumed), 1)
        self.assertEqual(resumed[0]["stalled_for_s"], 100)
        self.assertIn("the sequence is advancing again after 100 s", resumed[0]["note"])
        self.assertFalse(self.pipe.partition_status()["stalled"])
        self.assertEqual(self.pipe.partition_status()["id_sequence"], 165)

    def test_a_leader_not_heard_at_all_is_called_gone(self):
        t0 = 1_700_000_000.0
        self._adv(t0, ROUTER, 10)
        self._adv(t0 + 30, self.R2, 12)
        for i in range(1, 6):
            self._adv(t0 + 30 + 20 * i, self.R2, 12)
        self.pipe.periodic(t0 + 30 + 100)
        rec = self._events("leader_stalled")[0]
        self.assertIn("has not been heard for 130 s: it is gone", rec["note"])
        self.assertEqual(rec["leader_silent_for_s"], 130)

    def test_a_hole_in_the_capture_restarts_the_pulse_instead_of_stalling_the_leader(self):
        t0 = 1_700_000_000.0
        self._adv(t0, ROUTER, 10)
        self._adv(t0 + 20, self.R2, 12)
        # Forty-five minutes of nothing (a ring copied with an hour missing), then the mesh again.
        self._adv(t0 + 20 + 2700, self.R2, 12)
        self._adv(t0 + 20 + 2705, ROUTER, 12)
        self.pipe.periodic(t0 + 20 + 2710)
        self.assertEqual(self._events("leader_stalled"), [])
        self.assertEqual(self.pipe.partition_status()["sequence_advanced_ts"], t0 + 20 + 2700)
        # ...and from there the stall is judged afresh.
        for i in range(1, 5):
            self._adv(t0 + 20 + 2700 + 20 * i, self.R2, 12)
        self.pipe.periodic(t0 + 20 + 2700 + 85)
        self.assertEqual(len(self._events("leader_stalled")), 1)

    def test_a_stalled_sequence_is_not_judged_while_the_sniffer_hears_nothing(self):
        t0 = 1_700_000_000.0
        self._adv(t0, ROUTER, 10)
        self._adv(t0 + 10, self.R2, 10)
        self.pipe.periodic(t0 + 10 + 300)                                 # silence all round: the sniffer's problem
        self.assertEqual(self._events("leader_stalled"), [])

    def test_a_childs_stale_leader_data_is_not_a_change(self):
        t0 = 1_700_000_000.0
        self._adv(t0, ROUTER, 10)
        self._adv(t0 + 5, self.R2, 10)

        def child_update_request(src, rloc16, partition, leader):
            body = bytes([13, 0, 2]) + bytes.fromhex(rloc16) + leader_data(partition, leader)
            self.pipe.ingest(mle_frame(t0 + 10, src, 0, body))

        # Porch Sensor is attached to Hall Router (child 1 of router 60).
        child_update_request(SENSOR, "f001", self.PART, 60)
        # The mesh merges under Den Router; the change settles.
        self._adv(t0 + 30, self.R2, 12, partition=0x51119999, leader=11)
        self._adv(t0 + 40, ROUTER, 12, partition=0x51119999, leader=11)
        self.pipe.periodic(t0 + 71)
        self.assertEqual(len(self._events("partition_or_leader_change")), 1)
        # The sleepy child's next update still repeats what its parent told
        # it before the merge: not a flip, and no storm once a router speaks.
        child_update_request(SENSOR, "f001", self.PART, 60)
        self.assertEqual(self.pipe.partition, (0x51119999, 11))
        self._adv(t0 + 75, self.R2, 12, partition=0x51119999, leader=11)
        self.pipe.periodic(t0 + 75 + 31)
        self.assertEqual(self._events("partition_storm"), [])
        self.assertEqual(len(self._events("partition_or_leader_change")), 1)
        # A parent's own Child Update Request (a router's RLOC16) is its
        # current view, and is followed.
        child_update_request(ROUTER, "f000", 0x11111111, 3)
        self.assertEqual(self.pipe.partition, (0x11111111, 3))

    def test_one_change_that_holds_is_a_partition_or_leader_change_after_the_window(self):
        t0 = 1_700_000_000.0
        self._adv(t0, ROUTER, 10)
        self._adv(t0 + 30, self.R2, 12, partition=0x51119999, leader=11)
        self.assertEqual(self._events("partition_or_leader_change"), [])  # held
        self._adv(t0 + 45, self.R3, 12, partition=0x51119999, leader=11)
        self.assertEqual(self._events("partition_or_leader_change"), [])
        self.pipe.periodic(t0 + 30 + 31)
        chg = self._events("partition_or_leader_change")
        self.assertEqual(len(chg), 1)
        self.assertEqual(chg[0]["ts"], t0 + 30)
        self.assertEqual((chg[0]["previous"]["leader"], chg[0]["current"]["leader"]),
                         ("r60 (Hall Router)", "r11"))
        self.assertEqual(self._events("partition_storm"), [])
        self.assertEqual(self.pipe._lost_leader["addr"], ROUTER)
        # The new partition's own sequence is followed from the change on.
        self.assertEqual(self.pipe.partition_status()["id_sequence"], 12)
        self.assertEqual(self.pipe.partition_status()["sequence_advanced_ts"], t0 + 30)

    def test_many_changes_inside_the_window_are_one_storm(self):
        t0 = 1_700_000_000.0
        self._adv(t0, ROUTER, 10)
        flips = [(0x7ff4debb, 49), (0x1d3b3701, 51), (self.PART, 60), (0x709985ad, 57),
                 (0x1d3b3701, 51), (0x709985ad, 57)]
        for i, (pid, rid) in enumerate(flips):
            self._adv(t0 + 100 + 0.5 * i, self.R2 if i % 2 else self.R3, 0, partition=pid, leader=rid)
        self.pipe.periodic(t0 + 100 + 20)
        self.assertEqual(self._events("partition_storm"), [])            # still settling
        self._adv(t0 + 100 + 25, self.R2, 1, partition=0x709985ad, leader=57)   # same state: no flip
        self.pipe.periodic(t0 + 100 + 60)
        self.assertEqual(self._events("partition_or_leader_change"), [])
        storm = self._events("partition_storm")
        self.assertEqual(len(storm), 1)
        rec = storm[0]
        self.assertEqual(rec["ts"], t0 + 100)
        self.assertEqual((rec["partitions"], rec["changes"], rec["duration_s"]), (4, 6, 2.5))
        self.assertEqual(rec["previous"]["leader"], "r60 (Hall Router)")
        self.assertEqual(rec["current"], {"partition": 0x709985ad, "leader_router": 57, "leader": "r57"})
        self.assertEqual(rec["leaders"], ["r60 (Hall Router)", "r49", "r51", "r57"])
        self.assertIn("leader r60 (Hall Router) lost: 4 partitions each led by a router of its own for 2 s "
                      "(6 flips) before the mesh merged under r57", rec["note"])
        self.assertEqual(self.pipe._lost_leader["name"], "Hall Router")
        # A split that comes back under the same leader says so.
        self._adv(t0 + 400, self.R2, 2, partition=0x11111111, leader=3)
        self._adv(t0 + 401, self.R3, 2, partition=0x709985ad, leader=57)
        self.pipe.periodic(t0 + 440)
        rec = self._events("partition_storm")[1]
        self.assertIn("split into 2 partitions and merged back under r57 after 1 s (2 flips)", rec["note"])

    def test_settle_zero_logs_every_flip_at_once(self):
        self.cfg.partition_settle_s = 0
        t0 = 1_700_000_000.0
        self._adv(t0, ROUTER, 10)
        self._adv(t0 + 1, self.R2, 0, partition=0x7ff4debb, leader=49)
        self._adv(t0 + 2, self.R2, 0, partition=0x7ff4debb, leader=49)
        self.assertEqual(len(self._events("partition_or_leader_change")), 1)


class RejoinWaveTest(unittest.TestCase):
    """rejoin_wave: a batch of Parent / Child ID Requests from several
    devices is one record; a small batch is the notices it always was
    (docs/ALERTING.md)."""

    S2 = "c2c2c2c2c2c2c2c2"
    S3 = "c3c3c3c3c3c3c3c3"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([{"name": "Porch Sensor", "extendedAddress": SENSOR},
                                                    {"name": "Hall Router", "extendedAddress": ROUTER},
                                                    {"name": "Loft Sensor", "extendedAddress": self.S2}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")
        self.pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())

    def tearDown(self):
        self.tmp.cleanup()

    def _events(self, name):
        return [r for r in self.pipe.events.records if r["event"] == name]

    def _rejoin(self, ts, src, command=9):
        self.pipe.ingest(mle_frame(ts, src, 0, bytes([command])))

    def test_three_devices_inside_the_window_are_one_wave(self):
        t0 = 1_700_000_000.0
        self._rejoin(t0, SENSOR)                       # Parent Request
        self._rejoin(t0 + 2, SENSOR, 11)               # Child ID Request
        self._rejoin(t0 + 10, self.S2)
        self._rejoin(t0 + 40, self.S3)                 # not in the inventory: named by address
        self.pipe.periodic(t0 + 70)
        self.assertEqual(self._events("rejoin_wave"), [])          # 30 s since the last: still open
        self.pipe.periodic(t0 + 101)
        wave = self._events("rejoin_wave")
        self.assertEqual(len(wave), 1)
        rec = wave[0]
        self.assertEqual((rec["ts"], rec["devices"], rec["attempts"], rec["duration_s"], rec["trigger"]),
                         (t0, 3, 4, 40.0, None))
        self.assertEqual(rec["commands"], {"Parent Request": 3, "Child ID Request": 1})
        self.assertEqual(rec["names"], ["Porch Sensor", "Loft Sensor", self.S3])
        self.assertIn("3 devices re-attached over 40 s: Porch Sensor, Loft Sensor, " + self.S3, rec["note"])
        self.assertIn("No partition change was seen", rec["note"])
        self.assertEqual(self._events("mle_rejoin_attempt"), [])     # replaced in the log
        self.assertEqual(self.pipe.seen.table[SENSOR]["rejoin_ts"], t0 + 2)   # the per-device fact is kept
        # ...and the key journal still received each attempt.
        attempts = [r for r in self.pipe.journal.records
                    if r.get("kind") == "event" and r["evidence"].get("event") == "mle_rejoin_attempt"]
        self.assertEqual(len(attempts), 4)

    def test_one_device_is_its_own_notices_once_the_window_has_passed(self):
        t0 = 1_700_000_000.0
        self._rejoin(t0, SENSOR)
        self._rejoin(t0 + 5, SENSOR, 11)
        self.assertEqual(self._events("mle_rejoin_attempt"), [])    # held
        self.pipe.periodic(t0 + 66)
        ev = self._events("mle_rejoin_attempt")
        self.assertEqual([(e["ts"], e["command"], e["name"]) for e in ev],
                         [(t0, "Parent Request", "Porch Sensor"), (t0 + 5, "Child ID Request", "Porch Sensor")])
        self.assertIn("trying to get back", ev[0]["note"])
        self.assertEqual(self._events("rejoin_wave"), [])

    def test_two_devices_after_a_partition_change_are_a_wave_with_the_trigger(self):
        t0 = 1_700_000_000.0
        self.pipe.ingest(mle_frame(t0, ROUTER, 0, advertisement(0x3a31cae5, 60, 10)))
        self.pipe.ingest(mle_frame(t0 + 100, ROUTER, 0, advertisement(0x709985ad, 57, 3)))
        self._rejoin(t0 + 111, SENSOR)
        self._rejoin(t0 + 130, self.S2, 11)
        self.pipe.periodic(t0 + 200)
        rec = self._events("rejoin_wave")[0]
        self.assertEqual(rec["devices"], 2)
        self.assertEqual(rec["trigger"],
                         "the partition change at " + time.strftime("%H:%M:%S", time.localtime(t0 + 100)))
        self.assertIn("after the partition change at", rec["note"])
        self.assertIn("Their parents detached and came back", rec["note"])

    def test_the_last_periodic_of_a_replay_logs_what_is_still_held(self):
        t0 = 1_700_000_000.0
        self._rejoin(t0, SENSOR)
        self.pipe.periodic(t0 + 5, final=True)
        self.assertEqual(len(self._events("mle_rejoin_attempt")), 1)

    def test_wave_s_zero_logs_every_attempt_at_once(self):
        self.cfg.rejoin_wave_s = 0
        self._rejoin(1_700_000_000.0, SENSOR)
        self.assertEqual(len(self._events("mle_rejoin_attempt")), 1)

    def test_retransmissions_during_a_wave_are_attributed_to_it(self):
        t0 = 1_700_000_000.0
        for i, src in enumerate((SENSOR, self.S2, self.S3)):
            self._rejoin(t0 + i, src)
        self.pipe._win_start = t0 + 30
        self.pipe._win_dups = 20
        self.pipe._win_dup_by = {(SENSOR, ROUTER): 3, (self.S2, ROUTER): 3, (self.S3, "ffff"): 2}
        att = self.pipe._retrans_attribution()
        self.assertEqual(att["cause"], "rejoin_wave")
        self.assertIn("while 3 devices re-attaching after a rejoin wave: the rejoin wave, not interference",
                      att["note"])
        # One pair hammering one target is still that pair's link, wave or not.
        self.pipe._win_dup_by = {(SENSOR, ROUTER): 15, (self.S2, ROUTER): 5}
        att = self.pipe._retrans_attribution()
        self.assertNotIn("cause", att)
        self.assertIn("a failing link between those two", att["note"])
        # Six minutes on, with the wave long closed, retries are interference again.
        self.pipe.periodic(t0 + 100)
        self.pipe._win_start = t0 + 100 + 360
        self.pipe._win_dup_by = {(SENSOR, ROUTER): 3, (self.S2, ROUTER): 3, (self.S3, "ffff"): 2}
        self.assertNotIn("cause", self.pipe._retrans_attribution())


def dns_update(dns_id, rcode=None):
    """A DNS UPDATE (SRP) header: a request when rcode is None, else the
    response carrying that code. No records: the pipeline reads the header."""
    import struct
    flags = 5 << 11
    if rcode is not None:
        flags |= 0x8000 | rcode
    return struct.pack(">HHHHHH", dns_id, flags, 0, 0, 0, 0)


class SrpRefusedTest(unittest.TestCase):
    """srp_refused / srp_accepted: a device's SRP registrations coming back
    refused (docs/ALERTING.md). Porch Sensor registers through its parent
    Hall Router; the server's answers come back down the same path."""

    R2 = "a2a2a2a2a2a2a2a2"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([{"name": "Porch Sensor", "extendedAddress": SENSOR},
                                                    {"name": "Hall Router", "extendedAddress": ROUTER},
                                                    {"name": "Den Router", "extendedAddress": self.R2}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")
        self.pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())

    def tearDown(self):
        self.tmp.cleanup()

    def _events(self, name):
        return [r for r in self.pipe.events.records if r["event"] == name]

    def _frame(self, ts, src, dst, sport, dport, payload, mesh=None):
        from tests.frames import next_counter, secured_psdu
        from tests.test_identity import lowpan_udp
        from threadwatch.pcap import parse_frame
        plain = lowpan_udp(sport, dport, payload)
        if mesh is not None:                    # a relayed hop: originator and final destination (short)
            plain = bytes([0x85]) + bytes.fromhex(mesh[0]) + bytes.fromhex(mesh[1]) + plain
        return parse_frame(ts, secured_psdu(src, next_counter(src), dst=dst, payload=plain), 230)

    def _request(self, ts, dns_id, src=SENSOR, via=ROUTER):
        self.pipe.ingest(self._frame(ts, src, via, 49152, 53, dns_update(dns_id)))

    def _response(self, ts, dns_id, rcode, src=ROUTER, dst=SENSOR, mesh=None):
        self.pipe.ingest(self._frame(ts, src, dst, 53, 49152, dns_update(dns_id, rcode), mesh))

    def test_three_refusals_in_a_row_are_a_warning_and_the_next_acceptance_closes_it(self):
        t0 = 1_700_000_000.0
        self.pipe.ingest(frame(t0 - 10, SENSOR))
        self._request(t0, 1); self._response(t0 + 0.2, 1, 2)
        self._request(t0 + 2, 2); self._response(t0 + 2.2, 2, 2)
        self.assertEqual(self._events("srp_refused"), [])
        self._request(t0 + 5, 3); self._response(t0 + 5.2, 3, 2)
        self.assertEqual(self._events("srp_refused"), [])                 # the grace: a retry may get through
        self.pipe.periodic(t0 + 40)
        self.assertEqual(self._events("srp_refused"), [])
        self.pipe.periodic(t0 + 70)
        warned = self._events("srp_refused")
        self.assertEqual(len(warned), 1)
        rec = warned[0]
        self.assertEqual((rec["addr"], rec["name"], rec["rcode"], rec["rcode_name"], rec["refusals"], rec["since"],
                          rec["refused_for_s"], rec["ts"]),
                         (SENSOR, "Porch Sensor", 2, "SERVFAIL", 3, t0 + 0.2, 5, t0 + 70))
        self.assertIn("Porch Sensor's SRP registration has been refused 3 times over 5 s (SERVFAIL); "
                      "no accepted registration of its has been heard", rec["note"])
        self.assertIn("Apple Home", rec["note"])
        self._request(t0 + 9, 4); self._response(t0 + 9.2, 4, 2)
        self.assertEqual(len(self._events("srp_refused")), 1)             # once per streak
        self.assertEqual(self.pipe.seen.table[SENSOR]["srp"]["refused"], 4)
        self._request(t0 + 3600, 5); self._response(t0 + 3600.2, 5, 0)
        ok = self._events("srp_accepted")
        self.assertEqual(len(ok), 1)
        self.assertEqual((ok[0]["refusals"], ok[0]["since"], ok[0]["refused_for_s"]), (4, t0 + 0.2, 3600))
        self.assertIn("accepted after 4 refusals over 60 min", ok[0]["note"])
        state = self.pipe.seen.table[SENSOR]["srp"]
        self.assertEqual((state["refused"], state["reported"], state["accepted_ts"]), (0, False, t0 + 3600.2))
        # A new streak starts from zero, and its warning says when the last acceptance was;
        # a refusal past the grace says it without waiting for the periodic pass.
        for i, dns_id in enumerate((6, 7, 8)):
            self._request(t0 + 7200 + i, dns_id); self._response(t0 + 7200 + i + 0.2, dns_id, 5)
        self.assertEqual(len(self._events("srp_refused")), 1)
        self._request(t0 + 7300, 9); self._response(t0 + 7300.2, 9, 5)
        rec = self._events("srp_refused")[1]
        self.assertEqual((rec["rcode_name"], rec["accepted_ts"], rec["refusals"]), ("REFUSED", t0 + 3600.2, 4))
        self.assertIn("its last accepted registration was 61 min ago", rec["note"])

    def test_an_acceptance_inside_the_grace_means_nothing_was_said(self):
        t0 = 1_700_000_000.0
        self.pipe.ingest(frame(t0 - 10, SENSOR))
        for i, dns_id in enumerate((1, 2, 3)):
            self._request(t0 + 3600 * i, dns_id); self._response(t0 + 3600 * i + 0.2, dns_id, 2)
        self._request(t0 + 7210, 4); self._response(t0 + 7210.2, 4, 0)      # the retry got through
        self.pipe.periodic(t0 + 7300)
        self.assertEqual(self._events("srp_refused"), [])
        self.assertEqual(self._events("srp_accepted"), [])
        state = self.pipe.seen.table[SENSOR]["srp"]
        self.assertEqual((state["refused"], state["pending_ts"], state["reported"]), (0, None, False))

    def test_a_relayed_answer_is_credited_to_the_device_that_asked_and_counted_once(self):
        t0 = 1_700_000_000.0
        self.pipe.ingest(frame(t0 - 10, SENSOR))
        self.pipe.decryptor.short_to_ext["c407"] = SENSOR
        for i, dns_id in enumerate((11, 12, 13)):
            t = t0 + 10 * i
            self._request(t, dns_id)                                           # the sensor asks its parent
            # The server's answer comes over the mesh: Den Router hands it to
            # Hall Router with a mesh header naming the sensor...
            self._response(t + 0.1, dns_id, 2, src=self.R2, dst=ROUTER, mesh=("fc11", "c407"))
            # ...and Hall Router hands it to the sensor: the same answer again.
            self._response(t + 0.2, dns_id, 2)
        self.pipe.periodic(t0 + 100)
        rec = self._events("srp_refused")
        self.assertEqual(len(rec), 1)
        self.assertEqual((rec[0]["addr"], rec[0]["refusals"]), (SENSOR, 3))
        self.assertNotIn("srp", self.pipe.seen.table[ROUTER])                 # the relay is not the client
        self.assertNotIn("srp", self.pipe.seen.table.get(self.R2, {}))

    def test_an_old_unanswered_request_does_not_take_a_later_answer_with_its_id(self):
        t0 = 1_700_000_000.0
        self.pipe.ingest(frame(t0 - 10, SENSOR))
        self.pipe.ingest(frame(t0 - 10, self.R2))
        self._request(t0, 7, src=self.R2)                  # its answer is never heard
        self._request(t0 + 3600, 7)                        # the sensor draws the same id an hour later
        self._response(t0 + 3600.2, 7, 2)
        self.assertEqual(self.pipe.seen.table[SENSOR]["srp"]["refused"], 1)
        self.assertNotIn("srp", self.pipe.seen.table[self.R2])
        # The same when the sensor's own request was missed too: the answer
        # goes to its destination, not the hour-old request.
        self._request(t0 + 7200, 9, src=self.R2)
        self._response(t0 + 10800, 9, 0)
        self.assertEqual(self.pipe.seen.table[SENSOR]["srp"]["accepted_ts"], t0 + 10800)
        self.assertNotIn("srp", self.pipe.seen.table[self.R2])

    def test_a_response_whose_request_was_missed_goes_to_the_mesh_destination(self):
        t0 = 1_700_000_000.0
        self.pipe.ingest(frame(t0 - 10, SENSOR))
        self.pipe.decryptor.short_to_ext["c407"] = SENSOR
        for i, dns_id in enumerate((21, 22, 23)):
            self._response(t0 + i, dns_id, 2, src=self.R2, dst=ROUTER, mesh=("fc11", "c407"))
        self.pipe.periodic(t0 + 100)
        self.assertEqual(self._events("srp_refused")[0]["addr"], SENSOR)

    def _register(self, ts, src, dns_id, instances, via=ROUTER):
        """A registration as a device sends one: three to six fragments
        of one DNS UPDATE naming its host and its Matter services."""
        from tests.frames import next_counter, secured_psdu
        from tests.test_identity import lowpan_udp
        from tests.test_srp import lowpan_fragments, srp_update
        from threadwatch.pcap import parse_frame
        packet = lowpan_udp(49152, 53, srp_update(dns_id, src.upper(), instances))
        for i, frag in enumerate(lowpan_fragments(packet, 10, tag=dns_id)):
            self.pipe.ingest(parse_frame(ts + i * 0.01, secured_psdu(src, next_counter(src), dst=via, payload=frag),
                                         230))

    def test_a_registration_from_a_new_address_names_it_after_the_device_it_was(self):
        """2026-09-22: a climate sensor came back from a firmware update
        under a new extended address, registered the same Matter service
        names, was refused (the names still belonged to the old address's
        key), and the warning named an address nobody recognised."""
        from threadwatch.names import DeviceNames
        NEW = "e17f3a9b2c4d5e6f"
        FABRIC, APPLE = "1A2B3C4D5E6F7081-0000000000000067", "0F1E2D3C4B5A6978-00000000ABCDEF01"
        t0 = 1_700_000_000.0
        self.pipe.ingest(frame(t0 - 10, SENSOR))
        self._register(t0, SENSOR, 31, [FABRIC, APPLE]); self._response(t0 + 0.3, 31, 0)
        row = self.pipe.seen.table[SENSOR]
        self.assertEqual(row["matter_instances"], [f"{APPLE.lower()}._matter._tcp.default.service.arpa",
                                                   f"{FABRIC.lower()}._matter._tcp.default.service.arpa"])
        self.assertEqual(row["srp_host"], SENSOR.upper())
        self.assertEqual(self._events("device_address_changed"), [])
        # An hour later the same names arrive from an address nobody knows.
        self._register(t0 + 3600, NEW, 32, [FABRIC, APPLE])
        rot = self._events("device_address_changed")
        self.assertEqual(len(rot), 1)
        self.assertEqual((rot[0]["addr"], rot[0]["name"], rot[0]["previous"]), (NEW, "Porch Sensor", SENSOR))
        self.assertRegex(rot[0]["note"], f"carries the Matter service name (?:{APPLE.lower()}|{FABRIC.lower()}) "
                                         f"that {SENSOR} registered")
        self.assertIn(f'confirm with: threadwatch name {NEW} "Porch Sensor"', rot[0]["note"])
        self.assertEqual(self.pipe.names.name(NEW), "Porch Sensor")
        self.assertEqual(self.pipe.seen.table[SENSOR]["rotated_to"], NEW)
        self.assertNotIn("rotated_to", self.pipe.seen.table[NEW])
        # The refusals that follow name the device, not the address.
        for i, dns_id in enumerate((33, 34, 35)):
            self._response(t0 + 3601 + i, dns_id, 6, dst=NEW)
        self.pipe.periodic(t0 + 3700)
        rec = self._events("srp_refused")
        self.assertEqual((rec[0]["addr"], rec[0]["name"], rec[0]["rcode_name"]), (NEW, "Porch Sensor", "YXDOMAIN"))
        # Every later process names it too, and the hourly re-registration is not news.
        again = DeviceNames(self.cfg.devices_path, None, self.cfg.state_dir / "device-rotations.json")
        self.assertEqual(again.name(NEW), "Porch Sensor")
        self._register(t0 + 7200, NEW, 36, [FABRIC, APPLE])
        self.assertEqual(len(self._events("device_address_changed")), 1)

    def test_a_registration_with_a_fragment_missing_still_gives_the_names_it_carried(self):
        from tests.frames import next_counter, secured_psdu
        from tests.test_identity import lowpan_udp
        from tests.test_srp import lowpan_fragments, srp_update
        from threadwatch.pcap import parse_frame
        NEW = "e17f3a9b2c4d5e6f"
        FABRIC = "1A2B3C4D5E6F7081-0000000000000067"
        t0 = 1_700_000_000.0
        self.pipe.ingest(frame(t0 - 10, SENSOR))
        self._register(t0, SENSOR, 61, [FABRIC]); self._response(t0 + 0.3, 61, 0)
        self.pipe.ingest(frame(t0 + 3600, NEW))
        packet = lowpan_udp(49152, 53, srp_update(62, NEW.upper(), [FABRIC]))
        frags = lowpan_fragments(packet, 10, tag=62)
        self.assertGreaterEqual(len(frags), 3)
        for i, frag in enumerate(frags[:-1]):                       # the last fragment was never heard
            self.pipe.ingest(parse_frame(t0 + 3601 + i * 0.01,
                                         secured_psdu(NEW, next_counter(NEW), dst=ROUTER, payload=frag), 230))
        row = self.pipe.seen.table[NEW]
        self.assertEqual(row["matter_instances"], [f"{FABRIC.lower()}._matter._tcp.default.service.arpa"])
        self.assertIsNone(row["srp_host"])                            # the host waits for a whole one
        rot = self._events("device_address_changed")
        self.assertEqual([(r["addr"], r["previous"], r["name"]) for r in rot], [(NEW, SENSOR, "Porch Sensor")])
        self.assertEqual(self.pipe.names.name(NEW), "Porch Sensor")

    def _forward(self, ts, router, host, dns_id, instances, iid, drop_last=False):
        """A registration as a router forwards its child's to the SRP
        server one hop away: the router's MAC source, no mesh header, and
        the child's own IPv6 source carried inline (context-based, as the
        mesh-local and OMR addresses are)."""
        import struct

        from tests.frames import next_counter, secured_psdu
        from tests.test_srp import lowpan_fragments, srp_update
        from threadwatch.pcap import parse_frame
        iphc = (0b011 << 13) | (3 << 11) | (1 << 10) | (2 << 8) | (1 << 6) | (1 << 4) | (1 << 3) | 3
        packet = (struct.pack(">H", iphc) + bytes.fromhex(iid) + b"\x01" + b"\xf0"
                  + struct.pack(">HH", 49152, 53) + b"\x00\x00" + srp_update(dns_id, host.upper(), instances))
        frags = lowpan_fragments(packet, 18, tag=dns_id)
        for i, frag in enumerate(frags[:-1] if drop_last else frags):
            self.pipe.ingest(parse_frame(ts + i * 0.01, secured_psdu(router, next_counter(router), dst=self.R2,
                                                                     payload=frag), 230))

    def _hall_router_routes(self, ts):
        self.pipe.ingest(frame(ts, ROUTER))
        self.pipe.seen.table[ROUTER]["rloc16"] = "c400"

    def test_a_registration_a_router_forwards_is_the_childs_not_the_routers(self):
        """2026-09-23: two climate sensors' registrations, forwarded by
        their parent routers, were credited to the routers; when the
        sensors rotated, the routers were named as the devices that had."""
        NEW = "e17f3a9b2c4d5e6f"
        FABRIC = "1A2B3C4D5E6F7081-0000000000000069"
        t0 = 1_700_000_000.0
        self.pipe.ingest(frame(t0 - 10, SENSOR))
        self._hall_router_routes(t0 - 5)
        self._register(t0, SENSOR, 71, [FABRIC])                         # the sensor to its parent
        self._forward(t0 + 0.1, ROUTER, SENSOR, 71, [FABRIC], "0a1b2c3d4e5f6071")   # the parent onward
        self.assertNotIn("matter_instances", self.pipe.seen.table[ROUTER])
        self.assertIsNone(self.pipe.seen.table[ROUTER].get("srp_host"))
        self.assertEqual(self.pipe.seen.table[SENSOR]["srp_host"], SENSOR.upper())
        self._response(t0 + 0.3, 71, 2, src=self.R2, dst=ROUTER)
        self.assertNotIn("srp", self.pipe.seen.table[ROUTER])
        self.assertEqual(self.pipe.seen.table[SENSOR]["srp"]["refused"], 1)
        # The sensor reboots under a new address and registers the same name.
        self.pipe.ingest(frame(t0 + 3600, NEW))
        self._register(t0 + 3601, NEW, 72, [FABRIC])
        rot = self._events("device_address_changed")
        self.assertEqual([(r["addr"], r["previous"], r["name"]) for r in rot], [(NEW, SENSOR, "Porch Sensor")])

    def test_a_fragment_a_router_carries_is_credited_by_its_source_or_not_at_all(self):
        FABRIC, APPLE = "1A2B3C4D5E6F7081-0000000000000069", "0F1E2D3C4B5A6978-00000000ABCDEF01"
        t0 = 1_700_000_000.0
        self.pipe.ingest(frame(t0 - 10, SENSOR))
        self._hall_router_routes(t0 - 5)
        self._forward(t0, ROUTER, SENSOR, 81, [FABRIC], "0a1b2c3d4e5f6071")
        # A registration the sniffer heard only part of, from a source it
        # knows: the sensor's. From one it does not: nobody's.
        self._forward(t0 + 60, ROUTER, SENSOR, 82, [FABRIC, APPLE], "0a1b2c3d4e5f6071", drop_last=True)
        self.assertIn(f"{APPLE.lower()}._matter._tcp.default.service.arpa",
                      self.pipe.seen.table[SENSOR]["matter_instances"])
        self._forward(t0 + 120, ROUTER, "0b0b0b0b0b0b0b0b", 83, ["2B3C4D5E6F708192-0000000000000070"],
                      "7766554433221100", drop_last=True)
        self.assertNotIn("matter_instances", self.pipe.seen.table[ROUTER])

    def test_an_address_still_on_air_is_not_the_one_a_device_rotated_from(self):
        NEW = "e17f3a9b2c4d5e6f"
        FABRIC = "1A2B3C4D5E6F7081-0000000000000067"
        t0 = 1_700_000_000.0
        self.pipe.ingest(frame(t0 - 10, SENSOR))
        self._register(t0, SENSOR, 91, [FABRIC])
        self.pipe.ingest(frame(t0 + 3600, NEW))
        self.pipe.ingest(frame(t0 + 3601, SENSOR))                     # the old address talks on
        self._register(t0 + 3602, NEW, 92, [FABRIC])
        self.assertEqual(self._events("device_address_changed"), [])
        self.assertIsNone(self.pipe.names.name(NEW))
        self.assertNotIn("rotated_to", self.pipe.seen.table[SENSOR])

    def test_a_first_fragment_alone_still_attributes_the_answer_and_names_nothing(self):
        from tests.frames import next_counter, secured_psdu
        from tests.test_identity import lowpan_udp
        from tests.test_srp import lowpan_fragments, srp_update
        from threadwatch.pcap import parse_frame
        t0 = 1_700_000_000.0
        self.pipe.ingest(frame(t0 - 10, SENSOR))
        packet = lowpan_udp(49152, 53, srp_update(41, SENSOR.upper(), ["1A2B3C4D5E6F7081-0000000000000067"]))
        first = lowpan_fragments(packet, 10)[0]                        # the rest was never heard
        self.pipe.ingest(parse_frame(t0, secured_psdu(SENSOR, next_counter(SENSOR), dst=ROUTER, payload=first), 230))
        self._response(t0 + 0.2, 41, 2)
        self.assertEqual(self.pipe.seen.table[SENSOR]["srp"]["refused"], 1)
        self.assertNotIn("matter_instances", self.pipe.seen.table[SENSOR])

    def test_the_ha_map_reporting_a_new_address_rotates_the_device_too(self):
        t0 = 1_700_000_000.0
        NEW = "e17f3a9b2c4d5e6f"
        self.pipe.ingest(frame(t0 - 10, SENSOR))
        self.pipe.ingest(frame(t0, NEW))
        name = self.pipe._device_rotated(SENSOR, NEW, t0 + 1,
                                         "Home Assistant's Matter node diagnostics report the new address")
        self.assertEqual(name, "Porch Sensor")
        rot = self._events("device_address_changed")
        self.assertEqual((rot[0]["addr"], rot[0]["previous"], rot[0]["name"]), (NEW, SENSOR, "Porch Sensor"))
        self.assertIn("Home Assistant's Matter node diagnostics", rot[0]["note"])
        self.assertEqual(self.pipe.seen.table[SENSOR]["rotated_to"], NEW)
        # Said once: the registration that follows finds the rotation already known.
        self._register(t0 + 5, NEW, 51, ["1A2B3C4D5E6F7081-0000000000000067"])
        self.assertEqual(len(self._events("device_address_changed")), 1)
        # devices.json naming both addresses differently is a conflict the inventory settles.
        OTHER = "0a0a0a0a0a0a0a0a"
        self.pipe.ingest(frame(t0 + 10, OTHER))
        self.pipe.names.by_addr[OTHER] = {"name": "Shed Sensor", "extendedAddress": OTHER}
        self.assertEqual(self.pipe._device_rotated(SENSOR, OTHER, t0 + 11, "a test"), "Shed Sensor")
        self.assertEqual(len(self._events("device_address_changed")), 1)
        self.assertNotIn("rotated_to", self.pipe.seen.table[OTHER])

    def test_plain_dns_queries_on_port_53_are_not_registrations(self):
        import struct
        t0 = 1_700_000_000.0
        self.pipe.ingest(frame(t0 - 10, SENSOR))
        query = struct.pack(">HHHHHH", 31, 0x0000, 1, 0, 0, 0)
        answer = struct.pack(">HHHHHH", 31, 0x8003, 1, 0, 0, 0)               # NXDOMAIN, opcode QUERY
        for i in range(3):
            self.pipe.ingest(self._frame(t0 + i, SENSOR, ROUTER, 49153, 53, query))
            self.pipe.ingest(self._frame(t0 + i + 0.1, ROUTER, SENSOR, 53, 49153, answer))
        self.assertEqual(self._events("srp_refused"), [])
        self.assertNotIn("srp", self.pipe.seen.table[SENSOR])


class CorroboratedQuietTest(unittest.TestCase):
    """device_quiet keeps its warning for a marginal device when the rest
    of the recorder already knows it failed: the leader the mesh lost, or
    a device Home Assistant has marked unavailable (docs/ALERTING.md)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([{"name": "Hall Router", "extendedAddress": ROUTER}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")
        self.pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())

    def tearDown(self):
        self.tmp.cleanup()

    def _quiet(self):
        return [r for r in self.pipe.events.records if r["event"] == "device_quiet"]

    def _marginal_silence(self, t0):
        for i in range(20):
            self.pipe.ingest(frame(t0 + i, ROUTER, rssi=-88.0))
        self.pipe.periodic(t0 + 20 + self.cfg.quiet_s + 1)

    def test_a_marginal_silence_alone_is_a_notice(self):
        t0 = 1_700_000_000.0
        self._marginal_silence(t0)
        rec = self._quiet()[0]
        self.assertEqual((rec["severity"], rec["reception"], rec["was_leader"], rec["ha_unavailable_since"]),
                         ("notice", "marginal", False, None))
        self.assertTrue(rec["note"].startswith("sniffer hears this device at the edge of its range"))

    def test_the_leader_the_mesh_lost_is_a_warning_however_faint(self):
        t0 = 1_700_000_000.0
        self.pipe._lost_leader = {"addr": ROUTER, "name": "Hall Router", "leader_router": 60,
                                  "partition": 1, "ts": t0 + 25, "leader": "r60 (Hall Router)",
                                  "successor": "r57 (Den Router)"}
        self._marginal_silence(t0)
        rec = self._quiet()[0]
        self.assertEqual((rec["severity"], rec["reception"], rec["was_leader"]), ("warning", "marginal", True))
        self.assertTrue(rec["note"].startswith(
            "it was the mesh leader: it stopped leading at " + time.strftime("%H:%M:%S", time.localtime(t0 + 25))
            + " and the routers re-elected r57 (Den Router): the device failed, whatever the signal here. "
            "sniffer hears this device at the edge of its range"))
        # A leader lost long before this silence is a different story.
        self.pipe.events.records.clear()
        self.pipe.quiet_reported.discard(ROUTER)
        self.pipe._lost_leader["ts"] = t0 - 7200
        self.pipe.seen.table[ROUTER]["quiet_reported"] = False
        self.pipe._report_quiet(ROUTER, self.pipe.seen.table[ROUTER], t0 + 4000)
        rec = self._quiet()[0]
        self.assertEqual((rec["severity"], rec["was_leader"]), ("notice", False))

    def test_a_device_home_assistant_has_lost_is_a_warning(self):
        t0 = 1_700_000_000.0
        self.pipe._ha_unavailable_since = lambda addr: t0 + 600 if addr == ROUTER else None
        self._marginal_silence(t0)
        rec = self._quiet()[0]
        self.assertEqual((rec["severity"], rec["ha_unavailable_since"]), ("warning", t0 + 600))
        self.assertIn("Home Assistant has had it unavailable since "
                      + time.strftime("%H:%M:%S", time.localtime(t0 + 600)) + ": the device failed", rec["note"])


class RouterSetChangedTest(unittest.TestCase):
    """router_set_changed: router ids appearing or vanishing between two
    OTBR inventory samples (docs/ALERTING.md)."""

    R2 = "a2a2a2a2a2a2a2a2"
    R3 = "a3a3a3a3a3a3a3a3"
    HEADER = ("| ID | RLOC16 | Next Hop | Path Cost | LQ In | LQ Out | Age | Extended MAC     | Link |\n"
              "+----+--------+----------+-----------+-------+--------+-----+------------------+------+\n")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        (d / "devices.json").write_text(json.dumps([{"name": "Hall Router", "extendedAddress": ROUTER},
                                                    {"name": "Den Router", "extendedAddress": self.R2}]))
        self.cfg = Config(data_dir=d / "data", devices_path=d / "devices.json")
        self.pipe = Pipeline(self.cfg, NullEventLog(), stub_decryptor())
        self.samples = []

        class Inventory:
            history = {"samples": self.samples}

            def tick(self, now):
                pass
        self.pipe._otbr_inventory = Inventory()

    def tearDown(self):
        self.tmp.cleanup()

    def _sample(self, ts, routers, status="ok"):
        from threadwatch.otbr import table_rows
        text = self.HEADER + "".join(f"| {rid:2d} | 0x{rid << 10:04x} |       57 |         1 |     3 |     3 |   5 | "
                                     f"{ext} |    1 |\n" for rid, ext in routers)
        self.samples.append({"started_at": ts, "status": status,
                             "commands": {"router table": {"status": status, "output": text,
                                                           "rows": table_rows(text) if status == "ok" else []}}})

    def _events(self):
        return [r for r in self.pipe.events.records if r["event"] == "router_set_changed"]

    def test_promotions_and_demotions_between_two_samples_are_one_notice(self):
        t0 = 1_700_000_000.0
        self._sample(t0, [(60, ROUTER), (57, self.R2), (51, "0" * 16)])
        self.pipe.periodic(t0 + 1)                                   # the first sample: remembered, not judged
        self.assertEqual(self._events(), [])
        self.pipe.periodic(t0 + 30)                                  # the same sample again: nothing
        self._sample(t0 + 600, [(57, self.R2), (51, "0" * 16), (36, self.R3)])
        self.pipe.periodic(t0 + 601)
        ev = self._events()
        self.assertEqual(len(ev), 1)
        rec = ev[0]
        self.assertEqual(rec["ts"], t0 + 600)
        self.assertEqual([d["label"] for d in rec["promoted"]], [self.R3 + " r36"])
        self.assertEqual([d["label"] for d in rec["demoted"]], ["Hall Router r60"])
        self.assertEqual((rec["routers"], rec["previous_routers"], rec["demoted"][0]["rloc16"]), (3, 3, "f000"))
        self.assertIn("1 promoted (" + self.R3 + " r36), 1 demoted (Hall Router r60); 3 routers now", rec["note"])
        self.assertNotIn("partition change", rec["note"])
        self.pipe.periodic(t0 + 700)                                 # judged once
        self.assertEqual(len(self._events()), 1)

    def test_an_unchanged_or_failed_sample_says_nothing_and_a_storm_is_named(self):
        t0 = 1_700_000_000.0
        self._sample(t0, [(60, ROUTER), (57, self.R2)])
        self.pipe.periodic(t0 + 1)
        self._sample(t0 + 600, [(60, ROUTER), (57, self.R2)])
        self._sample(t0 + 1200, [], status="failed")
        self.pipe.periodic(t0 + 1201)
        self.assertEqual(self._events(), [])
        self.pipe._partition_changed_ts = t0 + 1500
        self._sample(t0 + 1800, [(57, self.R2)])
        self.pipe.periodic(t0 + 1801)
        rec = self._events()[0]
        self.assertEqual(rec["previous_sample_ts"], t0 + 600)        # the failed sample was skipped over
        self.assertIn("after the partition change at " + time.strftime("%H:%M:%S", time.localtime(t0 + 1500)),
                      rec["note"])
