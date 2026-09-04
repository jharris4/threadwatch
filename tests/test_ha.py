import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from threadwatch import ha  # noqa: E402
from threadwatch.ha import (FrameReader, HAError, connection_settings, encode_frame, load_env,  # noqa: E402
                            normalize_ext, parse_dataset_tlv, select_dataset,
                            thread_dataset, thread_devices, write_private)
from threadwatch.importer import plan_border_routers, plan_inventory, run_import  # noqa: E402


class EnvFileTest(unittest.TestCase):
    def test_env_file_forms(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ha.env"
            p.write_text('# comment\nHA_URL="http://ha.local:8123/"\nexport HA_TOKEN=abc.def\n\nBROKEN\n')
            self.assertEqual(load_env(p), {"HA_URL": "http://ha.local:8123/", "HA_TOKEN": "abc.def"})
            url, token = connection_settings(p)
            self.assertEqual((url, token), ("http://ha.local:8123", "abc.def"))
            self.assertEqual(connection_settings(p, "http://other:8123")[0], "http://other:8123")
            self.assertEqual(load_env(Path(d) / "missing.env"), {})

    def test_missing_token_says_how_to_get_one(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "ha.env"
            p.write_text("HA_URL=http://ha.local:8123\n")
            saved = os.environ.pop("HA_TOKEN", None)
            try:
                with self.assertRaises(HAError) as cm:
                    connection_settings(p)
                self.assertIn("HA_TOKEN", str(cm.exception))
                self.assertIn("profile page", str(cm.exception))
                os.environ["HA_TOKEN"] = "from-env"
                self.assertEqual(connection_settings(p)[1], "from-env")
            finally:
                os.environ.pop("HA_TOKEN", None)
                if saved is not None:
                    os.environ["HA_TOKEN"] = saved


def server_frame(opcode: int, payload: bytes, fin: bool = True) -> bytes:
    """An unmasked frame, as a server sends them."""
    n = len(payload)
    head = bytes([(0x80 if fin else 0) | opcode])
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + struct.pack(">H", n)
    else:
        head += bytes([127]) + struct.pack(">Q", n)
    return head + payload


class FakeSocket:
    def __init__(self, incoming: bytes):
        self.incoming, self.sent = incoming, b""

    def recv(self, n):
        out, self.incoming = self.incoming[:n], self.incoming[n:]
        return out

    def sendall(self, data):
        self.sent += data


def unmask(frame: bytes) -> tuple[int, bytes]:
    opcode = frame[0] & 0x0F
    n = frame[1] & 0x7F
    off = 2
    if n == 126:
        n, off = struct.unpack(">H", frame[2:4])[0], 4
    elif n == 127:
        n, off = struct.unpack(">Q", frame[2:10])[0], 10
    mask, data = frame[off:off + 4], frame[off + 4:off + 4 + n]
    return opcode, bytes(b ^ mask[i & 3] for i, b in enumerate(data))


class WebSocketFramingTest(unittest.TestCase):
    def test_client_frames_are_masked_and_sized(self):
        for size in (5, 300, 70000):
            opcode, data = unmask(encode_frame(0x1, b"x" * size))
            self.assertEqual((opcode, data), (0x1, b"x" * size))

    def test_reader_reassembles_and_answers_pings(self):
        big = json.dumps({"k": "v" * 70000}).encode()
        stream = (server_frame(0x9, b"hi") + server_frame(0x1, b'{"a":', fin=False)
                  + server_frame(0x0, b" 1}") + server_frame(0xA, b"") + server_frame(0x1, big))
        sock = FakeSocket(stream)
        reader = FrameReader(sock.recv, sock.sendall)
        self.assertEqual(json.loads(reader.message()), {"a": 1})
        self.assertEqual(unmask(sock.sent), (0xA, b"hi"))          # the ping was answered
        self.assertEqual(json.loads(reader.message()), {"k": "v" * 70000})
        with self.assertRaises(HAError):                            # EOF
            reader.message()

    def test_close_frame_is_an_error_with_the_reason(self):
        sock = FakeSocket(server_frame(0x8, struct.pack(">H", 1008) + b"policy"))
        with self.assertRaises(HAError) as cm:
            FrameReader(sock.recv, sock.sendall).message()
        self.assertIn("policy", str(cm.exception))


class FakeHA:
    """Stands in for HomeAssistant.call with canned results per command."""

    def __init__(self, responses):
        self.responses, self.calls = responses, []

    def call(self, type_, **fields):
        self.calls.append((type_, fields))
        r = self.responses[type_]
        r = r(fields) if callable(r) else r
        if isinstance(r, HAError):
            raise r
        return r


class ThreadDevicesTest(unittest.TestCase):
    def test_matter_over_thread_devices_with_names_and_addresses(self):
        registry = [
            {"id": "d1", "name": "Eve Motion", "name_by_user": "Living Room Motion", "model": "Eve Motion 20EBY9901",
             "manufacturer": "Eve Systems", "identifiers": [["matter", "deviceid_x-1"]]},
            {"id": "d2", "name": "Wifi Plug", "name_by_user": None, "model": "P100", "identifiers": [["matter", "deviceid_x-2"]]},
            {"id": "d3", "name": "Hue Bridge", "identifiers": [["hue", "abc"]]},
            {"id": "d4", "name": "Odd", "identifiers": [["matter", "deviceid_x-4"]]},
            {"id": "d5", "name": "Broken", "identifiers": [["matter", "deviceid_x-5"]]},
        ]
        diags = {
            "d1": {"node_id": 1, "network_type": "thread", "mac_address": "f0:0d:00:00:00:00:00:01", "available": True},
            "d2": {"node_id": 2, "network_type": "wifi", "mac_address": "aa:bb:cc:dd:ee:ff"},
            "d4": {"node_id": 4, "network_type": "thread", "mac_address": None},
            "d5": HAError("matter/node_diagnostics: node not found"),
        }
        fake = FakeHA({"config/device_registry/list": registry,
                       "matter/node_diagnostics": lambda f: diags[f["device_id"]]})
        notes = []
        found = thread_devices(fake, log=notes.append)
        self.assertEqual(found, [{"name": "Living Room Motion", "model": "Eve Motion 20EBY9901", "manufacturer": "Eve Systems",
                                  "addr": "F00D000000000001", "node_id": 1, "available": True}])
        self.assertEqual([t for t, _ in fake.calls].count("matter/node_diagnostics"), 4)   # not for the Hue bridge
        self.assertTrue(any("Odd" in n and "no extended address" in n for n in notes))
        self.assertTrue(any("Broken" in n for n in notes))

    def test_normalize_ext(self):
        self.assertEqual(normalize_ext("f0:0d:00:00:00:00:00:01"), "F00D000000000001")
        self.assertIsNone(normalize_ext("aa:bb:cc:dd:ee:ff"))
        self.assertIsNone(normalize_ext(None))


def tlv(t, val):
    return bytes([t, len(val)]) + val


class DatasetTest(unittest.TestCase):
    KEY = bytes(range(16))

    def dataset_hex(self):
        return (tlv(14, b"\x00" * 8) + tlv(0, b"\x00\x00\x19") + tlv(1, b"\xab\xcd") + tlv(2, b"\x32\x57" * 4)
                + tlv(3, b"MyHome") + tlv(5, self.KEY) + tlv(4, b"\x11" * 16)).hex()

    def test_tlv_parse(self):
        d = parse_dataset_tlv(self.dataset_hex())
        self.assertEqual(d, {"channel": 25, "pan_id": 0xabcd, "ext_pan_id": "3257" * 4,
                             "network_name": "MyHome", "network_key": self.KEY.hex()})

    def test_select_dataset(self):
        a, b = {"dataset_id": "A", "preferred": False, "network_name": "a"}, {"dataset_id": "B", "preferred": True, "network_name": "b"}
        self.assertEqual(select_dataset([a, b]), b)
        self.assertEqual(select_dataset([a]), a)
        self.assertEqual(select_dataset([a, b], "A"), a)
        with self.assertRaises(HAError):
            select_dataset([a, dict(b, preferred=False)])
        with self.assertRaises(HAError):
            select_dataset([])
        with self.assertRaises(HAError):
            select_dataset([a], "Z")

    def test_thread_dataset_end_to_end(self):
        fake = FakeHA({"thread/list_datasets": {"datasets": [{"dataset_id": "B", "preferred": True, "network_name": "MyHome"}]},
                       "thread/get_dataset_tlv": lambda f: {"tlv": self.dataset_hex()} if f["dataset_id"] == "B" else None})
        d = thread_dataset(fake)
        self.assertEqual((d["network_key"], d["channel"], d["dataset_id"]), (self.KEY.hex(), 25, "B"))
        fake = FakeHA({"thread/list_datasets": {"datasets": [{"dataset_id": "B", "preferred": True, "network_name": "x"}]},
                       "thread/get_dataset_tlv": {"tlv": tlv(3, b"x").hex()}})
        with self.assertRaises(HAError) as cm:
            thread_dataset(fake)
        self.assertIn("no network key", str(cm.exception))


class PlanInventoryTest(unittest.TestCase):
    def test_merge_keeps_hand_written_entries_and_reports_each_change(self):
        existing = [
            {"name": "Living Room Motion", "extendedAddress": "F00D000000000001", "note": "by the window"},
            {"name": "Old Name", "extendedAddress": "F00D000000000002"},
            {"name": "Living Room Apple TV", "extendedAddresses": ["B62C32BF669272DB"]},
            {"name": "Back Door Lock", "extendedAddress": "0000000000000001", "note": "HomeKit-only"},
        ]
        found = [
            {"name": "Living Room Motion", "model": "Eve Motion", "addr": "F00D000000000001"},
            {"name": "Den Stairs Motion", "model": "Eve Motion", "addr": "F00D000000000002"},
            {"name": "Living Room Apple TV", "model": "Apple TV", "addr": "E6C279E8F0C70298"},
            {"name": "Kitchen Plug", "model": None, "addr": "AAAAAAAAAAAAAAAA"},
        ]
        planned, changes = plan_inventory(existing, found)
        self.assertEqual(changes, [
            "Living Room Motion: model 'Eve Motion'",
            "rename 'Old Name' -> 'Den Stairs Motion' (F00D000000000002)",
            "Den Stairs Motion: model 'Eve Motion'",
            "Living Room Apple TV: new address E6C279E8F0C70298 (now 2 addresses)",
            "Living Room Apple TV: model 'Apple TV'",
            "add 'Kitchen Plug' = AAAAAAAAAAAAAAAA",
        ])
        self.assertEqual(planned[0], {"name": "Living Room Motion", "extendedAddress": "F00D000000000001",
                                      "note": "by the window", "model": "Eve Motion"})
        self.assertEqual(planned[2]["extendedAddresses"], ["B62C32BF669272DB", "E6C279E8F0C70298"])
        self.assertEqual(planned[3], existing[3])                       # untouched
        self.assertEqual(planned[4], {"name": "Kitchen Plug", "extendedAddress": "AAAAAAAAAAAAAAAA"})
        self.assertEqual(existing[1]["name"], "Old Name")               # the input list is not mutated
        again, changes = plan_inventory(planned, found)
        self.assertEqual((again, changes), (planned, []))               # idempotent


class WritePrivateTest(unittest.TestCase):
    def test_file_is_owner_read_only_and_replaced_atomically(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "credentials.toml"
            write_private(p, "[credentials]\nnetwork_key = \"00\"\n")
            self.assertEqual(oct(p.stat().st_mode & 0o777), "0o600")
            write_private(p, "[credentials]\nnetwork_key = \"11\"\n")
            self.assertIn('"11"', p.read_text())
            self.assertEqual(oct(p.stat().st_mode & 0o777), "0o600")
            self.assertEqual(ha.current_key(p), "11")
            self.assertEqual(sorted(x.name for x in Path(d).iterdir()), ["credentials.toml"])



class PlanBorderRoutersTest(unittest.TestCase):
    R = {"hostname": "appletv-living-room.local", "ext": "c0ffee0000000001", "instance": "AppleTV Living Room",
         "vendor": "Apple", "model": "BorderRouter"}

    def test_match_by_hostname_address_or_name_else_add(self):
        existing = [
            {"name": "Living Room Apple TV", "extendedAddresses": ["C0FFEE0000000000", "C0FFEE0000000001"], "note": "hub"},
            {"name": "HA OTBR", "borderRouter": "homeassistant-otbr.local"},
            {"name": "HomePod Kitchen"},
        ]
        routers = [self.R,
                   {"hostname": "homeassistant-otbr.local", "ext": "07b200000000af1b", "instance": "HA OTBR #AF1B",
                    "vendor": "Home Assistant", "model": "OpenThread Border Router"},
                   {"hostname": "homepod-kitchen.local", "ext": "0011223344556677", "instance": "HomePod Kitchen",
                    "vendor": "Apple", "model": "BorderRouter"},
                   {"hostname": "homepod-den.local", "ext": "8899aabbccddeeff", "instance": "HomePod Den",
                    "vendor": "Apple", "model": "BorderRouter"},
                   {"hostname": "broken.local", "ext": None, "instance": "Broken"}]
        planned, changes = plan_border_routers(existing, routers)
        self.assertEqual(changes, [
            "Living Room Apple TV: border router appletv-living-room.local",        # matched by listed address
            "Living Room Apple TV: model 'Apple BorderRouter'",
            "HA OTBR: new address 07B200000000AF1B (now 1 addresses)",             # matched by hostname
            "HA OTBR: model 'Home Assistant OpenThread Border Router'",
            "HomePod Kitchen: border router homepod-kitchen.local",                 # matched by name
            "HomePod Kitchen: new address 0011223344556677 (now 1 addresses)",
            "HomePod Kitchen: model 'Apple BorderRouter'",
            "add 'HomePod Den' = 8899AABBCCDDEEFF (border router homepod-den.local)",
        ])
        self.assertEqual(planned[0]["extendedAddresses"], ["C0FFEE0000000000", "C0FFEE0000000001"])   # kept, in order
        self.assertEqual(planned[0]["note"], "hub")
        self.assertEqual(planned[1]["extendedAddresses"], ["07B200000000AF1B"])
        self.assertEqual(planned[3], {"name": "HomePod Den", "borderRouter": "homepod-den.local",
                                      "extendedAddress": "8899AABBCCDDEEFF", "model": "Apple BorderRouter"})
        self.assertEqual(existing[2], {"name": "HomePod Kitchen"})                  # input untouched
        self.assertEqual(plan_border_routers(planned, routers), (planned, []))       # idempotent

    def test_a_reboot_appends_the_new_address_and_keeps_the_name(self):
        entry = {"name": "Living Room Apple TV", "borderRouter": "appletv-living-room.local",
                 "extendedAddress": "C0FFEE0000000001"}
        planned, changes = plan_border_routers([entry], [dict(self.R, ext="1234567890abcdef", instance="AppleTV Living Room")])
        self.assertEqual(changes, ["Living Room Apple TV: new address 1234567890ABCDEF (now 2 addresses)",
                                   "Living Room Apple TV: model 'Apple BorderRouter'"])
        self.assertEqual(planned[0]["name"], "Living Room Apple TV")


class RunImportTest(unittest.TestCase):
    """The command end to end, with both sources faked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        (self.d / "ha.env").write_text("HA_URL=http://ha.test:8123\nHA_TOKEN=tok\n")
        from threadwatch.config import Config
        self.cfg = Config(data_dir=self.d / "data", config_dir=self.d, devices_path=self.d / "devices.json",
                          credentials_path=self.d / "credentials.toml", channel=25)
        import threadwatch.ha as ha_mod
        import threadwatch.mdns as mdns_mod
        self.saved = (ha_mod.HomeAssistant, ha_mod.thread_devices, ha_mod.thread_dataset, mdns_mod.browse)
        self.calls = []

        class FakeHA:
            def __init__(s, url, token):
                self.calls.append(("connect", url, token))

            def __enter__(s):
                return s

            def __exit__(s, *a):
                pass

        ha_mod.HomeAssistant = FakeHA
        ha_mod.thread_devices = lambda ha, log=None: [{"name": "Living Room Motion", "model": "Eve Motion",
                                                       "addr": "F00D000000000001"}]
        ha_mod.thread_dataset = lambda ha, dataset_id=None: {"network_name": "MyHome", "channel": 25, "pan_id": 0xabcd,
                                                             "ext_pan_id": "32572a6010074654",
                                                             "network_key": "00112233445566778899aabbccddeeff"}
        mdns_mod.browse = lambda timeout=3.0, log=None: [PlanBorderRoutersTest.R]

    def tearDown(self):
        import threadwatch.ha as ha_mod
        import threadwatch.mdns as mdns_mod
        ha_mod.HomeAssistant, ha_mod.thread_devices, ha_mod.thread_dataset, mdns_mod.browse = self.saved
        self.tmp.cleanup()

    def test_plan_then_write(self):
        lines = []
        run_import(self.cfg, self.d / "devices.json", out=lines.append)
        text = "\n".join(lines)
        self.assertIn("mDNS: 1 border router(s): AppleTV Living Room", text)
        self.assertIn("Home Assistant: 1 Matter-over-Thread devices", text)
        self.assertIn("add 'AppleTV Living Room' = C0FFEE0000000001 (border router appletv-living-room.local)", text)
        self.assertIn("add 'Living Room Motion' = F00D000000000001", text)
        self.assertIn("network key: not in credentials.toml; --write stores it", text)
        self.assertIn("nothing written", text)
        self.assertFalse((self.d / "devices.json").exists())
        lines.clear()
        run_import(self.cfg, self.d / "devices.json", write=True, out=lines.append)
        entries = json.loads((self.d / "devices.json").read_text())
        self.assertEqual([e["name"] for e in entries], ["AppleTV Living Room", "Living Room Motion"])
        self.assertEqual(entries[0]["borderRouter"], "appletv-living-room.local")
        self.assertIn("00112233445566778899aabbccddeeff", (self.d / "credentials.toml").read_text())
        self.assertIn("restart it", "\n".join(lines))
        lines.clear()
        run_import(self.cfg, self.d / "devices.json", out=lines.append)      # now a no-op
        text = "\n".join(lines)
        self.assertIn("nothing to change", text)
        self.assertIn("already holds it", text)

    def test_sources_can_be_skipped(self):
        lines = []
        run_import(self.cfg, self.d / "devices.json", use_ha=False, out=lines.append)
        self.assertEqual(self.calls, [])                                        # HA never contacted
        self.assertIn("AppleTV Living Room", "\n".join(lines))
        lines.clear()
        import threadwatch.mdns as mdns_mod
        mdns_mod.browse = lambda timeout=3.0, log=None: []
        run_import(self.cfg, self.d / "devices.json", credentials=False, out=lines.append)
        text = "\n".join(lines)
        self.assertIn("no border routers answered", text)
        self.assertIn("Living Room Motion", text)
        self.assertNotIn("network key", text)


if __name__ == "__main__":
    unittest.main()

