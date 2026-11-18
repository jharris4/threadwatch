"""keylog: the key journal's records as each device's boots and switches."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tests  # noqa: F401  (the mDNS guard, installed on a direct run too: tests/no_lan)
from threadwatch import keyguard, keylog, stacks
from threadwatch.keyfacts import SWITCH_GAP_S
from threadwatch.keyguard import Boot, Switch

T = 1_800_000_000.0
HALL, HALL2, DOOR, TV, GUEST = (f"aa0000000000000{n}" for n in range(1, 6))
ENTRIES = [{"name": "Hall Air Monitor", "extendedAddresses": ["AA:00:00:00:00:00:00:01", HALL2]},
           {"name": "Side Door Lock", "extendedAddress": DOOR},
           {"name": "Deck TV"},                                  # named by mDNS: no address listed
           {"name": "Hall Border Router", "extendedAddress": "aa00000000000009"}]


def moved(addr, ts, old, new, layer="mac", last=None, name=None):
    return {"id": f"{addr}{layer}{new}{ts}", "kind": "transition", "addr": addr, "layer": layer, "ts": ts,
            "new_sequence": new, "old_sequence": old, "last_old_observation_ts": last,
            "context": {"name": name} if name else {}}


def booted(addr, ts, source="uptime_reset", **evidence):
    return {"id": f"reboot{addr}{ts}", "kind": "reboot", "addr": addr, "ts": ts,
            "evidence": {"ts": ts, "addr": addr, "source": source, **evidence}}


def counter(ts, old, new, before=None):
    return {"id": f"inventory{ts}", "kind": "inventory", "addr": "otbr:0123abcd", "ts": ts,
            "evidence": {"before": {"ts": before} if before else None, "after": {"ts": ts},
                         "old_sequence": old, "new_sequence": new}}


class ByDeviceTest(unittest.TestCase):
    def test_records_join_on_the_inventory_entry_across_its_addresses(self):
        a, b = moved(HALL, T, None, 90), moved(HALL2.upper(), T + 50, None, 91)
        other = {"id": "e", "kind": "event", "ts": T, "addr": HALL, "evidence": {}}
        self.assertEqual(keylog.by_device([a, other, b, moved(GUEST, T, None, 90)], ENTRIES),
                         {"Hall Air Monitor": [a, b]})

    def test_the_otbrs_records_go_to_the_name_the_caller_gives(self):
        c, r = counter(T, 90, 91), booted("otbr:log", T + 5, "service_log")
        sniffed = moved("aa00000000000009", T + 9, 90, 91)
        self.assertEqual(keylog.by_device([c, r, sniffed], ENTRIES, otbr="Hall Border Router"),
                         {"Hall Border Router": [c, r, sniffed]})
        self.assertEqual(keylog.by_device([c, r, sniffed], ENTRIES), {"Hall Border Router": [sniffed]})

    def test_a_reboot_entered_by_name_joins_by_that_name(self):
        r = booted("aa000000000000ff", T, "operator_action", name="Side Door Lock")
        stray = booted("aa000000000000fe", T, "operator_action", name="Nobody")
        self.assertEqual(keylog.by_device([r, stray], ENTRIES), {"Side Door Lock": [r]})

    def test_a_device_named_only_in_a_transitions_context_takes_every_record_of_that_address(self):
        # The first record has no name yet (a baseline), a later one does: both join.
        first, named = moved(TV, T, None, 90), moved(TV, T + 500, 90, 91, name="Deck TV")
        visitor = moved(GUEST, T, None, 90, name="Someone's Phone")          # a name the inventory does not have
        self.assertEqual(keylog.by_device([first, visitor, named], ENTRIES), {"Deck TV": [first, named]})
        # A listed address wins over a name in a record.
        wrong = moved(HALL, T, None, 90, name="Deck TV")
        self.assertEqual(keylog.by_device([wrong], ENTRIES), {"Hall Air Monitor": [wrong]})


class SwitchLogTest(unittest.TestCase):
    def test_mac_and_mle_merge_into_one_switch_per_key(self):
        records = [moved(HALL, T, None, 90, "mle"), moved(HALL, T + 3, None, 90, "mac"),
                   moved(HALL, T + 1000, 90, 91, "mac", last=T + 990),
                   moved(HALL, T + 1040, 90, 91, "mle", last=T + 700),       # the other layer catching up
                   moved(HALL, T + 5000, 91, 93, "mle", last=T + 4990)]
        self.assertEqual(keylog.switch_log(reversed(records)),
                         [Switch(T, None, 90), Switch(T + 1000, 90, 91), Switch(T + 5000, 91, 93)])
        self.assertEqual([s.jump for s in keylog.switch_log(records)], [0, 1, 2])
        self.assertEqual(keylog.switch_log([]), [])

    def test_a_switch_first_seen_after_a_gap_names_when_the_old_key_was_last_heard(self):
        gap = SWITCH_GAP_S + 1
        records = [moved(HALL, T, None, 90), moved(HALL, T + 5000, 90, 91, last=T + 5000 - gap)]
        self.assertEqual(keylog.switch_log(records)[1], Switch(T + 5000, 90, 91, unheard_from=T + 5000 - gap))
        records[1]["last_old_observation_ts"] = T + 5000 - SWITCH_GAP_S
        self.assertEqual(keylog.switch_log(records)[1], Switch(T + 5000, 90, 91))
        # The old key's last frame on either layer counts, whichever record names it.
        records = [moved(HALL, T, None, 90), moved(HALL, T + 5000, 90, 91, "mle", last=T + 100),
                   moved(HALL, T + 5020, 90, 91, "mac", last=T + 4995)]
        self.assertEqual(keylog.switch_log(records)[1], Switch(T + 5000, 90, 91))

    def test_a_new_address_first_heard_on_a_higher_key_is_a_switch_after_a_gap(self):
        # The address rotated: the new one's first record has no old key. Last heard on 90 when it arrived there.
        records = [moved(HALL, T, None, 89), moved(HALL, T + 100, 89, 90, last=T + 99),
                   moved(HALL2, T + 9000, None, 91)]
        self.assertEqual(keylog.switch_log(records)[2], Switch(T + 9000, 90, 91, unheard_from=T + 100))
        # A new address on the same key is no switch at all.
        self.assertEqual(len(keylog.switch_log(records + [moved(HALL2, T + 9500, None, 91, "mle")])), 3)

    def test_the_otbrs_key_counter_merges_with_its_sniffed_frames(self):
        records = [counter(T, None, 90), moved(DOOR, T + 40, None, 90),
                   moved(DOOR, T + 3000, 90, 91, last=T + 2990), counter(T + 3400, 90, 91, before=T + 2800),
                   counter(T + 9000, 91, 92, before=T + 8400)]             # on 91 at the sample ten minutes before
        self.assertEqual(keylog.switch_log(records), [Switch(T, None, 90), Switch(T + 3000, 90, 91),
                                                      Switch(T + 9000, 91, 92, unheard_from=T + 8400)])

    def test_two_records_with_one_stamp_and_one_key(self):
        # Sorting them must not come down to comparing an old key or a last-heard time with None.
        records = [moved(HALL, T, None, 90, "mle"), moved(HALL, T, 89, 90, "mac", last=T - 1),
                   moved(HALL, T + 100, 90, 91, "mle"), moved(HALL, T + 100, 90, 91, "mac", last=T + 99)]
        self.assertEqual(keylog.switch_log(records), [Switch(T, None, 90), Switch(T + 100, 90, 91)])

    def test_a_record_without_a_key_number_is_skipped(self):
        broken = moved(HALL, T + 5, 90, None)
        self.assertEqual(keylog.switch_log([moved(HALL, T, None, 90), broken]), [Switch(T, None, 90)])


class BootLogTest(unittest.TestCase):
    def test_each_stamp_carries_the_range_its_source_gives(self):
        records = [booted(HALL, T + 900, earliest=T + 100), booted(DOOR, T, "operator_action", until=T + 360),
                   booted(HALL, T - 5000, "service_log"), moved(HALL, T, None, 90)]
        self.assertEqual(keylog.boot_log(records),
                         [Boot(T - 5000), Boot(T, latest=T + 360), Boot(T + 900, earliest=T + 100)])

    def test_the_otbrs_uptime_reset_ranges_back_to_the_sample_before(self):
        # Stamped with the sample that noticed it, ten minutes after the sample before; the log has the second.
        noticed = booted("otbr:0123abcd", T + 600, before={"ts": T, "uptime_s": 5000.0}, after={"ts": T + 600})
        logged = booted("otbr:log", T + 130, "service_log")
        boots = keylog.boot_log([noticed, logged])
        self.assertEqual(boots, [Boot(T + 130), Boot(T + 600, earliest=T)])
        self.assertEqual(keyguard.one_per_boot(boots), [Boot(T + 130)])   # without the range the later stamp would win
        # A Matter node's uptime reset keeps its own `earliest`, whatever else its evidence holds.
        self.assertEqual(keylog.boot_log([booted(HALL, T + 600, earliest=T + 400, before={"ts": T})]),
                         [Boot(T + 600, earliest=T + 400)])


class DevicesTest(unittest.TestCase):
    TABLE = stacks.parse({"models": {"Air Monitor 2000": {"1.0.26": "old, reported"}},
                          "devices": {"Side Door Lock": "current, reported"}})
    HA_MAP = {"d1": {"name": "Hall Air Monitor", "matched": True, "model": "Air Monitor 2000", "sw_version": "1.0.26"}}

    def test_every_inventory_device_with_its_stack_boots_switches_and_links(self):
        records = [moved(HALL, T, None, 90), booted(HALL, T + 50, "service_log"),
                   moved(HALL2, T + 60, 90, 91, last=T + 55), moved(DOOR, T + 9, None, 90),
                   moved(TV, T + 4, None, 91, name="Deck TV"), counter(T + 7, None, 91)]
        links = {"Side Door Lock": ("Hall Air Monitor", True), "Hall Air Monitor": (None, False)}
        devs = {d.name: d for d in keylog.devices(records, ENTRIES, self.TABLE, self.HA_MAP, links,
                                                  otbr="Hall Border Router")}
        self.assertEqual(list(devs), ["Deck TV", "Hall Air Monitor", "Hall Border Router", "Side Door Lock"])
        hall, door = devs["Hall Air Monitor"], devs["Side Door Lock"]
        self.assertEqual((hall.stack, hall.boots, hall.switches, hall.parent, hall.sleepy),
                         (("old", "reported", "Air Monitor 2000 1.0.26"), (Boot(T + 50),),
                          (Switch(T, None, 90), Switch(T + 60, 90, 91)), None, False))
        self.assertEqual((door.stack[:2], door.switches, door.parent, door.sleepy),
                         (("current", "reported"), (Switch(T + 9, None, 90),), "Hall Air Monitor", True))
        self.assertEqual((devs["Deck TV"].stack[0], devs["Deck TV"].switches, devs["Deck TV"].parent),
                         ("unknown", (Switch(T + 4, None, 91),), None))
        self.assertEqual(devs["Hall Border Router"].switches, (Switch(T + 7, None, 91),))
        # From a past state: records after `until` are left out.
        past = {d.name: d for d in keylog.devices(records, ENTRIES, self.TABLE, self.HA_MAP, links, until=T + 20)}
        hall = past["Hall Air Monitor"]
        self.assertEqual((hall.boots, hall.switches), ((), (Switch(T, None, 90),)))
        # A record with no time is left out, not compared with `until`.
        broken = {"id": "x", "kind": "reboot", "addr": HALL, "ts": None, "evidence": {}}
        past = keylog.devices([*records, broken], ENTRIES, self.TABLE, self.HA_MAP, links, until=T + 20)
        self.assertEqual(len(past), 4)


if __name__ == "__main__":
    unittest.main()
