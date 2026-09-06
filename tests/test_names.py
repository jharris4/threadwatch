"""Inventory helpers: suggested entries for unknown addresses, and adopt."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.names import DeviceNames, LastSeen, adopt, load_observed_names, rotation_hints, suggest_entries

AQ = "26976e7f7d20964a"
TV1 = "b62c32bf669272db"
PLUG = "2a2d355a26ccae5f"
TV2 = "e6c279e8f0c70298"


class SuggestTest(unittest.TestCase):
    def _report(self, state):
        seen = LastSeen(None)
        seen.touch(AQ, 1_756_800_000.0, 1, pan=0x4e21, rssi=-61.0)
        seen.touch(AQ, 1_756_803_600.0, 1, pan=0x4e21, rssi=-61.0)
        seen.touch(TV1, 1_756_800_000.0, 1, pan=0x4e21, rssi=-88.0)
        return seen.report(DeviceNames(None), quiet_after_s=3600, now=1_756_804_000.0)

    def test_entry_per_unknown_with_harvested_name_first(self):
        observed = {AQ: {"office-aq-1a2b": 12, "office-aq-1a2b-old": 2}}
        entries = suggest_entries(self._report(None)["unknown"], observed)
        self.assertEqual([e["extendedAddress"] for e in entries], [TV1.upper(), AQ.upper()])
        aq = entries[1]
        self.assertEqual(aq["name"], "office-aq-1a2b")
        self.assertIn("2 frames since", aq["note"])
        self.assertIn("good reception (-61.0 dBm)", aq["note"])
        self.assertIn("advertised as office-aq-1a2b, office-aq-1a2b-old", aq["note"])
        tv = entries[0]
        self.assertEqual(tv["name"], "")
        self.assertIn("marginal reception", tv["note"])
        self.assertNotIn("advertised", tv["note"])

    def test_a_name_seen_once_is_not_suggested(self):
        # The scraper matches random ciphertext now and then; one sighting
        # is not a hostname, and must not become the proposed name.
        observed = {AQ: {'nwof-w.y[L(': 1, "office-aq-1a2b": 2, 'kIC.Kl5$cK': 1}}
        aq = suggest_entries(self._report(None)["unknown"], observed)[1]
        self.assertEqual(aq["name"], "office-aq-1a2b")
        self.assertIn("advertised as office-aq-1a2b" + ";", aq["note"] + ";")
        self.assertNotIn("nwof", aq["note"])
        only_junk = {AQ: {'C%.L:Uk"E': 1}}
        aq = suggest_entries(self._report(None)["unknown"], only_junk)[1]
        self.assertEqual(aq["name"], "")
        self.assertNotIn("advertised", aq["note"])

    def test_blank_name_from_a_pasted_suggestion_stays_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            inv.write_text(json.dumps([{"name": "", "extendedAddress": AQ.upper(), "note": "?"}]))
            self.assertIsNone(DeviceNames(inv).name(AQ))

    def test_observed_names_missing_or_broken_is_empty(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(load_observed_names(Path(d)), {})
            (Path(d) / "observed-names.json").write_text("{not json")
            self.assertEqual(load_observed_names(Path(d)), {})
            (Path(d) / "observed-names.json").write_text(json.dumps({AQ: {"x": 1}}))
            self.assertEqual(load_observed_names(Path(d)), {AQ: {"x": 1}})


class ReportQuietTest(unittest.TestCase):
    """threadwatch devices's "quiet" is the recorder's own announcement,
    the same set the pages show, not a third window of its own."""

    def _seen(self):
        seen = LastSeen(None)
        now = 1_756_804_000.0
        seen.touch(AQ, now - 5 * 3600, 1, pan=0x4e21)          # announced quiet by the recorder
        seen.table[AQ]["quiet_reported"] = True
        seen.touch(PLUG, now - 5 * 3600, 1, pan=0x4e21)        # silent as long, not (yet) announced
        seen.touch(TV1, now - 5 * 3600, 1, pan=0x4e21)         # a hub's retired address
        seen.table[TV1]["rotated_to"] = TV2
        seen.touch(TV2, now - 60, 1, pan=0x4e21)
        seen.touch("72d035122fdf06f6", now - 5 * 3600, 1, pan=0x58bc)   # a neighbour's device, flagged by an old run
        seen.table["72d035122fdf06f6"]["quiet_reported"] = True
        return seen, now

    def test_default_is_what_the_recorder_announced_minus_retired_and_foreign(self):
        seen, now = self._seen()
        rep = seen.report(DeviceNames(None), now=now, dominant=0x4e21)
        self.assertEqual([i["addr"] for i in rep["quiet"]], [AQ])
        self.assertEqual(rep["active_count"], 2)                       # PLUG and TV2; TV1 retired, the stranger foreign
        self.assertEqual(len(rep["unknown"]), 5)                       # naming is a separate question

    def test_an_explicit_window_is_the_wall_clock_and_still_skips_retired_and_foreign(self):
        seen, now = self._seen()
        rep = seen.report(DeviceNames(None), quiet_after_s=3600, now=now, dominant=0x4e21)
        self.assertEqual(sorted(i["addr"] for i in rep["quiet"]), sorted([AQ, PLUG]))
        rep = seen.report(DeviceNames(None), quiet_after_s=3600, now=now)   # no PAN known: everyone is judged
        self.assertEqual(sorted(i["addr"] for i in rep["quiet"]), sorted([AQ, PLUG, "72d035122fdf06f6"]))


class RssiSmoothingTest(unittest.TestCase):
    """The stored RSSI is a slow EWMA, not the last sample. A device at the
    edge drops a frame or two to the floor all the time; if that moved the
    stored value, `reception()` would flip between good and marginal frame
    by frame and every fade alert would fire and clear on single frames."""

    def _seen(self, samples, ts0=1_756_800_000.0):
        seen = LastSeen(None)
        for i, rssi in enumerate(samples):
            seen.touch(AQ, ts0 + i, 1, pan=0x4e21, rssi=rssi)
        return seen.table[AQ]["rssi"]

    def test_one_deep_sample_barely_moves_a_steady_reading(self):
        from threadwatch.names import reception
        self.assertEqual(self._seen([-60.0] * 50), -60.0)
        smoothed = self._seen([-60.0] * 50 + [-95.0])
        self.assertEqual(smoothed, -61.8)                        # 0.95 * -60 + 0.05 * -95
        self.assertEqual(reception(smoothed, -82.0), "good")

    def test_a_sustained_fade_does_move_it(self):
        from threadwatch.names import reception
        faded = self._seen([-60.0] * 50 + [-95.0] * 40)
        self.assertLess(faded, -82.0)
        self.assertEqual(reception(faded, -82.0), "marginal")


class RotationHintTest(unittest.TestCase):
    T = 1_756_800_000.0
    NEW, LATER, OTHER = "0011223344556677", "8899aabbccddeeff", "1234567890abcdef"

    def _names(self, d):
        inv = Path(d) / "devices.json"
        inv.write_text(json.dumps([
            {"name": "Living Room Apple TV", "extendedAddresses": [TV1.upper(), TV2]},
            {"name": "Office AQ", "extendedAddress": AQ},
        ]))
        return DeviceNames(inv)

    def _seen(self):
        seen = LastSeen(None)
        seen.touch(TV1, self.T - 86400, 1)
        seen.touch(TV2, self.T - 3600, 1)             # the TV's current address...
        seen.touch(TV2, self.T, 1)                    # ...last heard at T
        seen.touch(AQ, self.T + 7200, 1)              # still talking
        seen.touch(self.NEW, self.T + 90, 1)          # appeared 90 s after the TV fell silent
        seen.touch(self.NEW, self.T + 7200, 1)
        seen.touch(self.LATER, self.T + 3 * 3600, 1)  # appeared hours later: no hint
        seen.touch(self.OTHER, self.T + 7100, 1)      # appeared while the AQ was still heard: no hint
        return seen

    def test_new_address_as_a_named_device_falls_silent(self):
        with tempfile.TemporaryDirectory() as d:
            names = self._names(d)
            seen = self._seen()
            report = seen.report(names, quiet_after_s=1800, now=self.T + 7300)
            hints = rotation_hints(report["unknown"], seen.table, names)
            self.assertEqual(hints, {self.NEW: {"name": "Living Room Apple TV", "previous": TV2,
                                                "delta_s": 90, "rotates": True}})
            entries = {e["extendedAddress"]: e for e in suggest_entries(report["unknown"], {}, hints)}
            self.assertIn("possibly a new address of Living Room Apple TV (which rotates): its previous "
                          f"address {TV2} fell silent 1 min after this one appeared", entries[self.NEW.upper()]["note"])
            self.assertNotIn("possibly", entries[self.LATER.upper()]["note"])
            self.assertNotIn("possibly", entries[self.OTHER.upper()]["note"])

    def test_no_hint_when_the_device_kept_talking_after(self):
        with tempfile.TemporaryDirectory() as d:
            names = self._names(d)
            seen = self._seen()
            seen.touch(TV2, self.T + 3600, 1)         # the old address was heard again an hour later
            report = seen.report(names, quiet_after_s=1800, now=self.T + 7300)
            self.assertEqual(rotation_hints(report["unknown"], seen.table, names), {})


class AdoptTest(unittest.TestCase):
    def test_creates_the_file_and_appends_entries(self):
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "config" / "devices.json"
            msg = adopt(inv, "26:97:6E:7F:7D:20:96:4A", "Office Air Quality")
            self.assertIn("added 'Office Air Quality' = " + AQ, msg)
            adopt(inv, TV1, "Living Room Apple TV")
            entries = json.loads(inv.read_text())
            self.assertEqual(entries, [
                {"name": "Office Air Quality", "extendedAddress": AQ.upper()},
                {"name": "Living Room Apple TV", "extendedAddress": TV1.upper()},
            ])
            names = DeviceNames(inv)
            self.assertEqual(names.name(AQ), "Office Air Quality")

    def test_same_name_gains_a_rotated_address(self):
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            inv.write_text(json.dumps([{"name": "Living Room Apple TV", "extendedAddress": TV1.upper(),
                                        "note": "rotates"}]))
            msg = adopt(inv, TV2, "living room apple tv")
            self.assertIn("2 addresses", msg)
            entry = json.loads(inv.read_text())[0]
            self.assertNotIn("extendedAddress", entry)
            self.assertEqual(entry["extendedAddresses"], [TV1.upper(), TV2.upper()])
            self.assertNotIn("role", entry)
            self.assertEqual(entry["note"], "rotates")
            self.assertEqual(DeviceNames(inv).name(TV2), "Living Room Apple TV")

    def test_two_adopts_at_once_both_land(self):
        # BUG-12: adopt read, changed and replaced the file with nothing to
        # stop two of them reading the same base and the later write
        # discarding the earlier, acknowledged, change.
        import threading

        from threadwatch import names as names_mod
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            real = names_mod.read_inventory
            both_read = threading.Barrier(2)

            def read_then_wait(path):
                entries = real(path)
                try:
                    both_read.wait(0.5)         # met only when nothing serialises the two transactions
                except threading.BrokenBarrierError:
                    pass
                return entries

            msgs = {}

            def run(addr, name):
                msgs[name] = adopt(inv, addr, name)

            names_mod.read_inventory = read_then_wait
            try:
                threads = [threading.Thread(target=run, args=a) for a in (("0000000000000001", "A"),
                                                                            ("0000000000000002", "B"))]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(5)
            finally:
                names_mod.read_inventory = real
            self.assertEqual(sorted(msgs.values()), ["added 'A' = 0000000000000001", "added 'B' = 0000000000000002"])
            self.assertEqual(sorted(e["name"] for e in json.loads(inv.read_text())), ["A", "B"])

    def test_already_listed(self):
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            adopt(inv, AQ, "Office Air Quality")
            self.assertIn("already listed", adopt(inv, AQ, "office air quality"))
            with self.assertRaises(ValueError) as cm:
                adopt(inv, AQ, "Bedroom Sensor")
            self.assertIn("already listed as 'Office Air Quality'", str(cm.exception))
            self.assertEqual(len(json.loads(inv.read_text())), 1)

    def test_a_stray_null_is_named_not_a_traceback(self):
        # The recorder skips a null or a bare string and keeps going; a
        # command that rewrites the file must say which entry is wrong
        # rather than crash, and must not drop it on the way out.
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            before = json.dumps([{"name": "Office Air Quality", "extendedAddress": AQ.upper()}, None])
            inv.write_text(before)
            with self.assertRaises(ValueError) as cm:
                adopt(inv, TV1, "Living Room Apple TV")
            self.assertIn("devices.json: entry 2 is null, not a device object", str(cm.exception))
            self.assertEqual(inv.read_text(), before)
            inv.write_text(json.dumps(["Hall Router"]))
            with self.assertRaises(ValueError) as cm:
                adopt(inv, TV1, "Living Room Apple TV")
            self.assertIn("entry 1 is a str", str(cm.exception))

    def test_rejects_bad_input_without_touching_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            with self.assertRaises(ValueError):
                adopt(inv, "0x1234", "Thing")
            with self.assertRaises(ValueError):
                adopt(inv, AQ, "   ")
            self.assertFalse(inv.exists())


class Rloc16RoleTest(unittest.TestCase):
    def test_router_and_child_from_the_short_address(self):
        from threadwatch.names import rloc16_role
        self.assertEqual(rloc16_role("f000"), {"rloc16": "f000", "router_id": 60, "child_id": None, "role": "router"})
        self.assertEqual(rloc16_role("c004"), {"rloc16": "c004", "router_id": 48, "child_id": 4, "role": "child"})
        self.assertIsNone(rloc16_role(None))
        self.assertIsNone(rloc16_role("zz"))


class LearnedBorderRoutersTest(unittest.TestCase):
    def test_state_file_names_a_new_address_from_the_bound_entry(self):
        from threadwatch.names import DeviceNames
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            inv.write_text(json.dumps([{"name": "Living Room Apple TV", "extendedAddress": TV1.upper()},
                                       {"name": "OTBR", "borderRouter": "otbr.local"}]))
            learned = Path(d) / "border-routers.json"
            learned.write_text(json.dumps({
                "appletv-living-room.local": {"addr": TV2, "name": "Living Room Apple TV",
                                              "instance": "AppleTV Living Room",
                                              "vendor": "Apple", "model": "BorderRouter"},
                "otbr.local": {"addr": AQ, "name": None, "instance": "OTBR #1"},
                "junk.local": {"addr": "nope"},
            }))
            names = DeviceNames(inv, learned)
            self.assertEqual(names.name(TV2), "Living Room Apple TV")
            self.assertEqual(names.addresses_of(TV1), [TV1, TV2])
            self.assertEqual(names.name(AQ), "OTBR")                       # borderRouter field, even unnamed in state
            self.assertEqual(names.border_routers[TV2]["instance"], "AppleTV Living Room")
            self.assertNotIn("nope", names.border_routers)
            self.assertIsNone(DeviceNames(inv, Path(d) / "absent.json").name(TV2))

    def test_retired_addresses_keep_their_name_in_every_process(self):
        # The recorder writes each rotation to `previous`; a process that
        # did not see it happen (the web pages, why, report) must still
        # name the old addresses, or the device's history splits.
        from threadwatch.names import DeviceNames
        OLDER = "0011223344556677"
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            inv.write_text(json.dumps([{"name": "Living Room Apple TV", "extendedAddress": TV1.upper()}]))
            learned = Path(d) / "border-routers.json"
            learned.write_text(json.dumps({
                "appletv-living-room.local": {"addr": AQ, "name": "Living Room Apple TV", "instance": "AppleTV",
                                              "previous": [{"addr": OLDER, "until": 1.0}, {"addr": TV2, "until": 2.0},
                                                           "junk", {"addr": "nope"}]},
            }))
            names = DeviceNames(inv, learned)
            self.assertEqual([names.name(a) for a in (AQ, TV2, OLDER)], ["Living Room Apple TV"] * 3)
            self.assertEqual(names.addresses_of(TV1), [TV1, AQ, TV2, OLDER])
            self.assertEqual(names.resolve("living room")[0], [TV1, AQ, TV2, OLDER])
            self.assertFalse(names.border_routers[AQ]["retired"])
            self.assertTrue(names.border_routers[TV2]["retired"])
            self.assertEqual(names.border_routers[OLDER]["hostname"], "appletv-living-room.local")
            self.assertNotIn("nope", names.border_routers)



class UnreadableStateTest(unittest.TestCase):
    """A last-seen.json that does not parse is a week of history: say so
    and keep it, rather than silently starting over."""

    def _load(self, path):
        import contextlib
        import io

        from threadwatch import names as names_mod
        names_mod._warned_unreadable.clear()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            seen = LastSeen(path)
        return seen, out.getvalue()

    def test_a_broken_table_is_announced_and_kept_aside_on_the_first_save(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "last-seen.json"
            broken = '{"' + AQ + '": {"first_seen": 1, "last_seen": 2, "frames": 3, "ty'   # cut short
            path.write_text(broken)
            seen, said = self._load(path)
            self.assertEqual(seen.table, {})
            self.assertIn("last-seen.json is unreadable", said)
            self.assertIn("last-seen.json.corrupt", said)
            import contextlib
            import io
            again = io.StringIO()
            with contextlib.redirect_stdout(again):
                LastSeen(path)                                             # the web reads it per request:
            self.assertEqual(again.getvalue(), "")                         # said once per process
            seen.touch(TV1, 10.0, 1)
            seen.save()
            self.assertEqual(json.loads(path.read_text())[TV1]["frames"], 1)
            self.assertEqual((Path(d) / "last-seen.json.corrupt").read_text(), broken)
            seen.touch(TV1, 11.0, 1)
            seen.save()                                                    # a plain save from then on
            self.assertEqual(sorted(p.name for p in Path(d).iterdir()), ["last-seen.json", "last-seen.json.corrupt"])
            # A later corruption is kept as well, never over the first.
            path.write_text("[]")                                          # a list is not a table either
            seen2, said = self._load(path)
            self.assertIn("expected an object", said)
            seen2.save()
            kept = sorted(p.name for p in Path(d).iterdir() if p.name.startswith("last-seen.json.corrupt"))
            self.assertEqual(len(kept), 2)
            self.assertEqual((Path(d) / "last-seen.json.corrupt").read_text(), broken)

    def test_a_healthy_or_absent_table_says_nothing_and_keeps_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "last-seen.json"
            seen, said = self._load(path)
            self.assertEqual((seen.table, said), ({}, ""))
            seen.touch(TV1, 10.0, 1)
            seen.save()
            seen, said = self._load(path)
            self.assertEqual((seen.table[TV1]["frames"], said), (1, ""))
            seen.save()
            self.assertEqual([p.name for p in Path(d).iterdir()], ["last-seen.json"])


class MalformedInventoryTest(unittest.TestCase):
    """One bad hand-edit must not stop capture or 500 every review page."""

    def _names(self, doc):
        d = Path(tempfile.mkdtemp()) / "devices.json"
        d.write_text(doc)
        return DeviceNames(d, None)

    def test_non_dict_entries_are_skipped(self):
        for doc in ('["00112233445566aa"]', '[null]', '[{"name": "ok",'
                    ' "extendedAddress": "00112233445566aa"}, "stray"]'):
            names = self._names(doc)
            with self.assertRaises(ValueError):
                names.resolve("nothing-matches-this")

    def test_a_syntax_error_is_announced_and_ignored_not_fatal(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            inv.write_text('[{"name": "AQ", "extendedAddress": "%s"},]' % AQ.upper())   # a trailing comma
            with contextlib.redirect_stdout(io.StringIO()) as out:
                names = DeviceNames(inv)
            self.assertIsNone(names.name(AQ))
            self.assertEqual(names.entries, [])
            self.assertIn("not valid JSON", out.getvalue())
            self.assertIn("devices.json", out.getvalue())

    def test_top_level_object_is_ignored_not_fatal(self):
        names = self._names('{"a": {"name": "x"}}')
        self.assertEqual(names.entries, [])

    def test_non_string_name_does_not_crash_resolve(self):
        names = self._names('[{"name": 5, "extendedAddress": "00112233445566aa"}]')
        self.assertEqual(names.name("00112233445566aa"), "5")
        with self.assertRaises(ValueError):
            names.resolve("nothing-matches-this")


class SaveIntervalTest(unittest.TestCase):
    """last-seen.json is what every quiet decision is computed from after a
    restart; maybe_save writes it every 30 s while anything changed. A
    crash costs at most that much history."""

    def test_the_table_is_saved_every_30_s_while_dirty(self):
        import json
        import tempfile
        import time
        from pathlib import Path

        from threadwatch.names import LastSeen
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "last-seen.json"
            seen = LastSeen(path)
            seen.touch("b62c32bf669272db", 1000.0, 1)
            seen.maybe_save()                                  # never saved: at once
            first = path.read_text()
            seen.touch("b62c32bf669272db", 1001.0, 1)
            seen.maybe_save()                                  # a moment later: not yet
            self.assertEqual(path.read_text(), first)
            seen._last_save = time.time() - 29
            seen.maybe_save()
            self.assertEqual(path.read_text(), first)
            seen._last_save = time.time() - 31
            seen.maybe_save()
            self.assertEqual(json.loads(path.read_text())["b62c32bf669272db"]["last_seen"], 1001.0)
            self.assertEqual(LastSeen.maybe_save.__defaults__, (30.0,))


class SaveUnderConcurrentTouchTest(unittest.TestCase):
    """The watchdog's stalled-exit ladder saves the table from its own
    thread, to "keep the last frames and what they taught us". The capture
    thread may still be adding rows, and serialising the live table raises
    "dictionary changed size during iteration"; the ladder wraps every
    step in except Exception, so the save the step exists for was dropped
    without a word."""

    def test_the_table_is_copied_first_and_the_write_is_retried(self):
        import json
        import tempfile
        from pathlib import Path
        from unittest import mock

        from threadwatch.names import LastSeen
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "last-seen.json"
            seen = LastSeen(path)
            seen.touch("b62c32bf669272db", 1000.0, 1)

            real, seen_args = json.dumps, []

            def flaky(obj, *a, **kw):
                seen_args.append(obj)
                if len(seen_args) == 1:
                    raise RuntimeError("dictionary changed size during iteration")
                return real(obj, *a, **kw)

            with mock.patch("threadwatch.names.json.dumps", flaky):
                seen.save()

            self.assertEqual(len(seen_args), 2)                  # retried, not lost
            self.assertIsNot(seen_args[0], seen.table)           # a copy, not the live table
            self.assertEqual(json.loads(path.read_text())["b62c32bf669272db"]["last_seen"], 1000.0)


class TouchExtendedOnlyTest(unittest.TestCase):
    """The table is keyed by extended address. A short address (an RLOC16)
    is reassigned whenever a parent restarts, so a row under one would
    follow the address to the next device that inherits it, and every
    frame from an unresolved sleepy device would add a row that is nobody."""

    def test_only_a_16_hex_extended_address_gets_a_row(self):
        seen = LastSeen(None)
        for addr in (None, "", "3c1a", "fffe", AQ[:15], AQ + "0"):
            seen.touch(addr, 1_756_800_000.0, 1, pan=0x4e21, rssi=-60.0)
        self.assertEqual(seen.table, {})
        self.assertFalse(seen._dirty)
        seen.touch(AQ, 1_756_800_000.0, 1, pan=0x4e21, rssi=-60.0)
        self.assertEqual(list(seen.table), [AQ])
        self.assertTrue(seen._dirty)

    def test_a_frame_from_an_unresolved_short_address_adds_no_row(self):
        from threadwatch.config import Config
        from threadwatch.crypto import Decryptor
        from threadwatch.events import NullEventLog
        from threadwatch.pcap import Frame
        from threadwatch.pipeline import Pipeline
        with tempfile.TemporaryDirectory() as d:
            pipe = Pipeline(Config(data_dir=Path(d) / "data"), NullEventLog(), Decryptor(network_key=bytes(16)),
                            ephemeral=True)
            for i in range(3):
                pipe.ingest(Frame(ts=1_756_800_000.0 + i, raw=b"", psdu=b"", rssi=-60.0, channel=None, lqi=None,
                                  ftype=1, seq=i, dst_pan=0x4e21, dst="0000", src_pan=0x4e21, src="3c1a"))
            self.assertEqual(pipe.seen.table, {})


if __name__ == "__main__":
    unittest.main()
