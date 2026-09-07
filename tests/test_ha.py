import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from threadwatch import ha
from threadwatch.ha import (
    FrameReader,
    HAError,
    connection_settings,
    encode_frame,
    load_env,
    normalize_ext,
    parse_dataset_tlv,
    select_dataset,
    thread_dataset,
    thread_devices,
    write_private,
)
from threadwatch.importer import plan_border_routers, plan_inventory, run_import


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

    def test_sixteen_bit_lengths_are_read_as_such(self):
        # A Home Assistant result is nearly always 126..65535 bytes: the
        # length lives in the two bytes after the header, not in the 7 bits.
        for size in (126, 127, 300, 65535):
            head_text, tail_text = b'{"n": %d, "pad": "' % size, b'"}'
            payload = head_text + b"x" * (size - len(head_text) - len(tail_text)) + tail_text
            self.assertEqual(len(payload), size)
            head = server_frame(0x1, payload)[:4]
            self.assertEqual((head[1] & 0x7F, struct.unpack(">H", head[2:4])[0]), (126, size))
            sock = FakeSocket(server_frame(0x1, payload) + server_frame(0x1, b'{"after":1}'))
            reader = FrameReader(sock.recv, sock.sendall)
            self.assertEqual(json.loads(reader.message())["n"], size, size)
            self.assertEqual(json.loads(reader.message()), {"after": 1})          # nothing of it left over
        # A masked one (a peer that masks anyway) unmasks to the same text.
        text = b"y" * 500
        mask = b"\x12\x34\x56\x78"
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(text))
        sock = FakeSocket(bytes([0x81, 0x80 | 126]) + struct.pack(">H", 500) + mask + masked)
        self.assertEqual(FrameReader(sock.recv, sock.sendall).message(), text.decode())

    def test_a_declared_length_is_not_trusted_for_the_allocation(self):
        # The 64-bit length comes from the peer, and the default HA_URL is
        # plaintext HTTP to an mDNS-resolved name, so the peer is not
        # necessarily Home Assistant. 2 GiB declared used to be 2 GiB
        # allocated, and the recorder runs on the same 1 GB Pi.
        asked = []

        class Counting(FakeSocket):
            def recv(self, n):
                asked.append(n)
                return super().recv(n)

        header = bytes([0x81, 127]) + struct.pack(">Q", 2 * 1024 ** 3)
        with self.assertRaises(HAError) as cm:
            FrameReader(Counting(header).recv, lambda b: None).message()
        self.assertIn("over the", str(cm.exception))
        self.assertLessEqual(max(asked), ha.RECV_CHUNK)
        # A frame within the limit still reads, in chunks of RECV_CHUNK.
        asked.clear()
        payload = json.dumps({"k": "v" * 200_000}).encode()
        sock = Counting(server_frame(0x1, payload))
        self.assertEqual(json.loads(FrameReader(sock.recv, lambda b: None).message()),
                         {"k": "v" * 200_000})
        self.assertLessEqual(max(asked), ha.RECV_CHUNK)
        # ...and neither can a run of continuation frames add up past it.
        parts = b"".join(server_frame(0x1 if i == 0 else 0x0, b"x" * (1024 ** 2), fin=False)
                         for i in range(ha.MAX_FRAME_BYTES // 1024 ** 2 + 1))
        with self.assertRaises(HAError) as cm:
            FrameReader(FakeSocket(parts).recv, lambda b: None).message()
        self.assertIn("over the", str(cm.exception))

    def test_a_hung_or_lost_peer_is_an_haerror_not_a_traceback(self):
        # The socket timeout fires as TimeoutError inside recv; a reset
        # arrives as ConnectionResetError. Both reach the caller as the
        # HAError the module promises, with the reason in the message.
        def timing_out(n):
            raise socket.timeout("timed out")
        with self.assertRaises(HAError) as cm:
            FrameReader(timing_out, lambda b: None).message()
        self.assertIn("stopped answering", str(cm.exception))

        def reset(n):
            raise ConnectionResetError(104, "Connection reset by peer")
        with self.assertRaises(HAError) as cm:
            FrameReader(reset, lambda b: None).message()
        self.assertIn("lost the connection", str(cm.exception))

        def broken_pipe(self, b):
            raise BrokenPipeError(32, "Broken pipe")
        client = ha.HomeAssistant("ws://ha.local:8123", "token")
        client._sock = type("Sock", (), {"sendall": broken_pipe})()
        with self.assertRaises(HAError):
            client._send_json({"type": "ping"})

    def test_a_handshake_that_stalls_is_an_haerror(self):
        # A server that accepts and then says nothing: the hung-HA case.
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        try:
            with self.assertRaises(HAError) as cm:
                ha.ws_connect(f"http://127.0.0.1:{srv.getsockname()[1]}", timeout=0.3)
            self.assertIn("did not answer the websocket handshake", str(cm.exception))
        finally:
            srv.close()

    def test_close_frame_is_an_error_with_the_reason(self):
        sock = FakeSocket(server_frame(0x8, struct.pack(">H", 1008) + b"policy"))
        with self.assertRaises(HAError) as cm:
            FrameReader(sock.recv, sock.sendall).message()
        self.assertIn("policy", str(cm.exception))


class CallDeadlineTest(unittest.TestCase):
    @staticmethod
    def _client(messages):
        client = ha.HomeAssistant("ws://ha.local:8123", "token")
        sent = []
        client._sock = type("Sock", (), {"sendall": lambda self, b: sent.append(b)})()
        client._reader = type("Reader", (), {"message": lambda self, deadline=None: next(messages)})()
        return client, sent

    def test_a_peer_that_streams_events_and_never_answers_is_given_up_on(self):
        # The socket timeout bounds silence only; a Home Assistant pushing
        # events every millisecond resets it for ever.
        client, sent = self._client(iter(lambda: '{"type": "event", "event": {}}', None))
        t0 = time.monotonic()
        with self.assertRaises(HAError) as cm:
            client.call_many([("config/device_registry/list", {}), ("matter/node_diagnostics", {"device_id": "d1"})],
                             deadline_s=0.2)
        self.assertLess(time.monotonic() - t0, 5.0)
        self.assertIn("2 of 2 request(s)", str(cm.exception))
        self.assertIn("matter/node_diagnostics", str(cm.exception))
        self.assertEqual(len(sent), 2)                          # both commands had gone out

    def test_a_peer_that_pings_forever_does_not_outlast_the_deadline(self):
        """call_many checked its deadline only between whole messages, and
        FrameReader.message() answers pings and skips pushed events without
        returning. Every read also renewed the socket's own timeout, so an
        endpoint that kept sending held the reader inside one message() call
        for as long as it liked -- and the import held the inventory lock
        for exactly that long."""
        clock = [1000.0]
        timeouts = []

        class PingForever:
            """A socket that answers every read with another ping, and whose
            clock advances a second per read."""

            def __init__(self):
                self.buf = b""
                self.sent = b""

            def recv(self, n):
                clock[0] += 1.0
                if not self.buf:
                    self.buf = server_frame(0x9, b"ping")
                out, self.buf = self.buf[:n], self.buf[n:]
                return out

            def sendall(self, data):
                self.sent += data

        sock = PingForever()
        real = time.monotonic
        time.monotonic = lambda: clock[0]
        try:
            reader = ha.FrameReader(sock.recv, sock.sendall, set_timeout=timeouts.append, timeout=20.0)
            with self.assertRaises(ha.HADeadline):
                reader.message(deadline=clock[0] + 5.0)
            client = ha.HomeAssistant("ws://ha.local:8123", "token")
            client._sock = type("Sock", (), {"sendall": lambda self, b: None})()
            client._reader = ha.FrameReader(sock.recv, sock.sendall, set_timeout=timeouts.append, timeout=20.0)
            with self.assertRaises(HAError) as cm:
                client.call_many([("matter/node_diagnostics", {"device_id": "d1"})], deadline_s=3.0)
        finally:
            time.monotonic = real
        self.assertNotIsInstance(cm.exception, ha.HADeadline)    # said in the caller's terms
        self.assertIn("1 of 1 request(s)", str(cm.exception))
        self.assertIn("within 3 s", str(cm.exception))
        # Each read was bounded by what was left, and the socket got its own
        # timeout back for the sends that share it.
        self.assertTrue(all(t <= 20.0 for t in timeouts), timeouts)
        self.assertEqual(timeouts[-1], 20.0)

    def test_results_arriving_before_the_deadline_are_collected(self):
        client, _sent = self._client(iter([
            '{"type": "event"}', '{"id": 2, "type": "result", "success": true, "result": "two"}',
            '{"id": 1, "type": "result", "success": false, "error": {"message": "nope"}}']))
        one, two = client.call_many([("a", {}), ("b", {})], deadline_s=5.0)
        self.assertEqual((str(one), two), ("a: nope", "two"))


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

    def call_many(self, requests):
        out = []
        for type_, fields in requests:
            try:
                out.append(self.call(type_, **fields))
            except HAError as exc:
                out.append(exc)
        return out


class ThreadDevicesTest(unittest.TestCase):
    def test_matter_over_thread_devices_with_names_and_addresses(self):
        registry = [
            {"id": "d1", "name": "Eve Motion", "name_by_user": "Living Room Motion", "model": "Eve Motion 20EBY9901",
             "manufacturer": "Eve Systems", "identifiers": [["matter", "deviceid_x-1"]]},
            {"id": "d2", "name": "Wifi Plug", "name_by_user": None, "model": "P100",
             "identifiers": [["matter", "deviceid_x-2"]]},
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
        self.assertEqual(found,
                         [{"name": "Living Room Motion", "model": "Eve Motion 20EBY9901", "manufacturer": "Eve Systems",
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
        a, b = {"dataset_id": "A", "preferred": False, "network_name": "a"}, {"dataset_id": "B", "preferred": True,
                                                                              "network_name": "b"}
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
        fake = FakeHA({"thread/list_datasets":
                       {"datasets": [{"dataset_id": "B", "preferred": True, "network_name": "MyHome"}]},
                       "thread/get_dataset_tlv":
                           lambda f: {"tlv": self.dataset_hex()} if f["dataset_id"] == "B" else None})
        d = thread_dataset(fake)
        self.assertEqual((d["network_key"], d["channel"], d["dataset_id"]), (self.KEY.hex(), 25, "B"))
        fake = FakeHA({"thread/list_datasets":
                       {"datasets": [{"dataset_id": "B", "preferred": True, "network_name": "x"}]},
                       "thread/get_dataset_tlv": {"tlv": tlv(3, b"x").hex()}})
        with self.assertRaises(HAError) as cm:
            thread_dataset(fake)
        self.assertIn("no network key", str(cm.exception))


class PlanInventoryTest(unittest.TestCase):
    def test_merged_entry_is_refused_without_losing_metadata(self):
        import copy
        existing = [{"name": "Merged", "extendedAddresses": ["00:11:22:33:44:55:66:77", "8899AABBCCDDEEFF"],
                     "note": "history", "borderRouter": "hub.local"}]
        before = copy.deepcopy(existing)
        for names in (("Sensor", "Router"), ("Sensor", "Sensor")):
            found = [{"name": names[0], "addr": "0011223344556677"},
                     {"name": names[1], "addr": "8899AABBCCDDEEFF"}]
            for ordered in (found, found[::-1]):
                with self.assertRaisesRegex(ValueError, "inventory conflict.*split this entry"):
                    plan_inventory(existing, ordered)
                self.assertEqual(existing, before)

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

    def test_devices_sharing_a_name_stay_separate_devices(self):
        # Three contact sensors all named "Contact Sensor" in HA, one of
        # them already in the file: not one rotating device with three
        # addresses, but three entries, each with the address it has.
        existing = [{"name": "Contact Sensor", "extendedAddress": "1111111111111111", "note": "front door"},
                    {"name": "Living Room Apple TV", "extendedAddress": "B62C32BF669272DB"}]
        found = [{"name": "Contact Sensor", "model": "Eve Door", "addr": a}
                 for a in ("1111111111111111", "2222222222222222", "3333333333333333")]
        found.append({"name": "Living Room Apple TV", "model": "Apple TV", "addr": "E6C279E8F0C70298"})
        planned, changes = plan_inventory(existing, found)
        self.assertEqual([e["name"] for e in planned],
                         ["Contact Sensor (1111)", "Living Room Apple TV", "Contact Sensor (2222)",
                          "Contact Sensor (3333)"])
        self.assertEqual([len(_addrs(e)) for e in planned], [1, 2, 1, 1])   # only the TV rotates
        self.assertEqual(planned[0]["note"], "front door")
        self.assertIn("'Contact Sensor' names 3 devices in Home Assistant", changes[0])
        self.assertIn("rename them there", changes[0])
        self.assertIn("rename 'Contact Sensor' -> 'Contact Sensor (1111)'", changes[1])
        self.assertIn("add 'Contact Sensor (2222)' = 2222222222222222", changes)
        self.assertIn("Living Room Apple TV: new address E6C279E8F0C70298 (now 2 addresses)", changes)
        again, changes = plan_inventory(planned, found)
        self.assertEqual(again, planned)
        self.assertEqual(len(changes), 1)                              # only the reminder to rename in HA
        # Renamed apart in HA: the entries follow, by address.
        found[1]["name"], found[2]["name"] = "Back Door", "Garage Door"
        renamed, changes = plan_inventory(planned, found)
        self.assertEqual([e["name"] for e in renamed],
                         ["Contact Sensor", "Living Room Apple TV", "Back Door", "Garage Door"])


    def test_shared_names_are_told_apart_even_when_address_tails_match(self):
        # BUG-08: two devices HA calls "Sensor" whose addresses end in the
        # same four characters were given one name, and the second was
        # then filed under the first as its rotated address.
        found = [{"name": "Sensor", "model": None, "addr": "001122334455abcd"},
                 {"name": "Sensor", "model": None, "addr": "8899aabbccddabcd"}]
        planned, changes = plan_inventory([], found)
        self.assertEqual(planned, [{"name": "Sensor (55ABCD)", "extendedAddress": "001122334455ABCD"},
                                   {"name": "Sensor (DDABCD)", "extendedAddress": "8899AABBCCDDABCD"}])
        self.assertIn("add 'Sensor (55ABCD)' = 001122334455ABCD", changes)
        self.assertIn("add 'Sensor (DDABCD)' = 8899AABBCCDDABCD", changes)
        self.assertEqual(plan_inventory(planned, found), (planned, changes[:1]))     # idempotent
        # A generated name must not land on an unrelated entry either, or
        # the name fallback would file the device under it.
        existing = [{"name": "Sensor (ABCD)", "extendedAddress": "FFFFFFFFFFFFFFFF", "note": "mine"}]
        found = [{"name": "Sensor", "model": None, "addr": "001122334455abcd"},
                 {"name": "Sensor", "model": None, "addr": "0000000000001234"}]
        planned, changes = plan_inventory(existing, found)
        self.assertEqual(planned[0], existing[0])
        self.assertEqual([e["name"] for e in planned], ["Sensor (ABCD)", "Sensor (55ABCD)", "Sensor (001234)"])
        self.assertEqual([len(_addrs(e)) for e in planned], [1, 1, 1])

    def test_a_rename_and_a_new_device_taking_the_old_name_stay_two_devices(self):
        # A device renamed in HA while a different one takes its former
        # name. Read in HA's order, the new device arrived first, matched
        # the old entry by name and was written into it as a rotated
        # address; the renamed device then found that same entry by its
        # own address and renamed it, so one entry held both devices and
        # the new one lost its identity. Address before name settles it,
        # whichever order HA answers in.
        existing = [{"name": "Kitchen", "extendedAddress": "1111111111111111", "note": "by the sink"}]
        order = [{"name": "Kitchen", "model": None, "addr": "2222222222222222"},
                 {"name": "Hall", "model": None, "addr": "1111111111111111"}]
        for found in (order, list(reversed(order))):
            planned, changes = plan_inventory(existing, found)
            self.assertEqual([e["name"] for e in planned], ["Hall", "Kitchen"])
            self.assertEqual([_addrs(e) for e in planned],
                             [["1111111111111111"], ["2222222222222222"]])
            self.assertEqual(planned[0]["note"], "by the sink")     # the note stays with its address
            self.assertIn("rename 'Kitchen' -> 'Hall' (1111111111111111)", changes)
            self.assertIn("add 'Kitchen' = 2222222222222222", changes)

    def test_a_colon_formatted_address_is_the_same_address(self):
        # BUG-07: the loader takes 00:11:22:... but the importer matched
        # addresses as written, so HA's 001122... never found the entry and
        # a second one was made, taking the name and stranding the note.
        import tempfile

        from threadwatch.importer import plan_border_routers
        from threadwatch.names import DeviceNames
        existing = [{"name": "Old name", "extendedAddress": "00:11:22:33:44:55:66:77", "note": "retain me"}]
        planned, changes = plan_inventory(existing, [{"name": "New name", "addr": "0011223344556677"}])
        self.assertEqual(changes, ["rename 'Old name' -> 'New name' (0011223344556677)"])
        self.assertEqual(planned, [{"name": "New name", "extendedAddress": "00:11:22:33:44:55:66:77",
                                    "note": "retain me"}])                      # as written, note kept
        with tempfile.TemporaryDirectory() as d:
            inv = Path(d) / "devices.json"
            inv.write_text(json.dumps(planned))
            names = DeviceNames(inv)
            self.assertEqual(names.name("0011223344556677"), "New name")
            self.assertEqual(names.resolve("New name")[0], ["0011223344556677"])
        # The border-router merge matches by address the same way.
        planned, changes = plan_border_routers(existing, [{"hostname": "hub.local", "ext": "0011223344556677",
                                                           "instance": "Hub"}])
        self.assertEqual(changes, ["Old name: border router hub.local"])
        self.assertEqual(_addrs(planned[0]), ["00:11:22:33:44:55:66:77"])


def _addrs(entry):
    from threadwatch.names import entry_addresses
    return entry_addresses(entry)


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

    def test_a_pre_existing_permissive_temp_file_is_not_written_through(self):
        """os.open's mode applies only when it creates the file. A leftover or
        planted credentials.toml.tmp at 0644 took the new key and stayed
        world-readable until the chmod -- and stayed that way for good if the
        write raised first. Nothing is written to a name chosen in advance."""
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "credentials.toml"
            planted = Path(d) / "credentials.toml.tmp"
            planted.write_text("")
            os.chmod(planted, 0o644)
            secret = "[credentials]\nnetwork_key = \"%s\"\n" % ("ab" * 16)
            write_private(p, secret)
            self.assertEqual(p.read_text(), secret)
            self.assertEqual(oct(p.stat().st_mode & 0o777), "0o600")
            self.assertEqual(planted.read_text(), "")           # untouched
            self.assertEqual(sorted(x.name for x in Path(d).iterdir()),
                             ["credentials.toml", "credentials.toml.tmp"])

    def test_a_failed_write_leaves_no_secret_behind(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "credentials.toml"
            with self.assertRaises(TypeError):
                write_private(p, None)
            self.assertEqual(list(Path(d).iterdir()), [])



class PlanBorderRoutersTest(unittest.TestCase):
    R = {"hostname": "appletv-living-room.local", "ext": "c0ffee0000000001", "instance": "AppleTV Living Room",
         "vendor": "Apple", "model": "BorderRouter"}

    def test_match_by_hostname_address_or_name_else_add(self):
        existing = [
            {"name": "Living Room Apple TV", "extendedAddresses": ["C0FFEE0000000000", "C0FFEE0000000001"],
             "note": "hub"},
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

    def test_a_second_hub_under_the_same_display_name_is_a_second_entry(self):
        # The name fallback used to match an entry already bound to another
        # hostname, rebind it and append the new address: two hubs read as
        # one that rotated, and the first hub's binding was gone.
        first = {"hostname": "hub-a.local", "ext": "1111111111111111", "instance": "HomePod"}
        planned, _ = plan_border_routers([], [first])
        self.assertEqual(planned, [{"name": "HomePod", "borderRouter": "hub-a.local",
                                    "extendedAddress": "1111111111111111"}])
        second = {"hostname": "hub-b.local", "ext": "2222222222222222", "instance": "HomePod"}
        planned, changes = plan_border_routers(planned, [second])
        self.assertEqual(changes, ["add 'HomePod (2222)' = 2222222222222222 (border router hub-b.local; "
                                   "'HomePod' already names another border router)"])
        self.assertEqual(planned, [
            {"name": "HomePod", "borderRouter": "hub-a.local", "extendedAddress": "1111111111111111"},
            {"name": "HomePod (2222)", "borderRouter": "hub-b.local", "extendedAddress": "2222222222222222"},
        ])
        self.assertEqual(plan_border_routers(planned, [first, second]), (planned, []))     # idempotent
        # The first hub rebooting to a new address is still a rotation of its own entry.
        planned, changes = plan_border_routers(planned, [dict(first, ext="3333333333333333")])
        self.assertEqual(changes, ["HomePod: new address 3333333333333333 (now 2 addresses)"])
        self.assertEqual(planned[0]["extendedAddresses"], ["1111111111111111", "3333333333333333"])

    def test_a_reboot_appends_the_new_address_and_keeps_the_name(self):
        entry = {"name": "Living Room Apple TV", "borderRouter": "appletv-living-room.local",
                 "extendedAddress": "C0FFEE0000000001"}
        planned, changes = plan_border_routers([entry],
                                               [dict(self.R, ext="1234567890abcdef", instance="AppleTV Living Room")])
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

    def test_conflict_does_not_write_inventory_or_credentials(self):
        import threadwatch.ha as ha_mod
        ha_mod.thread_devices = lambda ha, log=None: [
            {"name": "Sensor", "addr": "0011223344556677"},
            {"name": "Router", "addr": "8899AABBCCDDEEFF"}]
        original = json.dumps([{"name": "Merged", "extendedAddresses": [
            "0011223344556677", "8899AABBCCDDEEFF"], "note": "keep"}])
        self.cfg.devices_path.write_text(original)
        with self.assertRaisesRegex(ValueError, "inventory conflict"):
            run_import(self.cfg, self.cfg.devices_path, write=True, out=lambda line: None)
        self.assertEqual(self.cfg.devices_path.read_text(), original)
        self.assertFalse(self.cfg.credentials_path.exists())

    def test_the_inventory_lock_is_held_for_the_whole_run(self):
        # BUG-12: an import overlapping an adopt is the other lost-update
        # pair; both take names.inventory_lock, import for the whole run.
        import contextlib

        import threadwatch.importer as importer_mod
        from threadwatch.importer import run_import
        held = []

        @contextlib.contextmanager
        def recording(path):
            held.append(("locked", path.name))
            yield
            held.append(("released", path.name))

        saved = importer_mod.inventory_lock
        importer_mod.inventory_lock = recording
        try:
            lines = []
            run_import(self.cfg, self.d / "devices.json", use_ha=False, use_mdns=False, out=lines.append)
            self.assertEqual(held, [("locked", "devices.json"), ("released", "devices.json")])
            held.clear()
            run_import(self.cfg, self.d / "devices.json", use_ha=False, use_mdns=False, devices=False,
                       out=lines.append)
            self.assertEqual(held, [])                       # nothing to write: nothing to lock
        finally:
            importer_mod.inventory_lock = saved

    def test_a_malformed_inventory_is_named_before_anything_is_asked(self):
        # A stray null the recorder skips must not become an AttributeError
        # deep in the planner: the file and entry are named, nothing written.
        inv = self.d / "devices.json"
        inv.write_text(json.dumps([{"name": "Living Room Motion", "extendedAddress": "F00D000000000001"}, None]))
        with self.assertRaises(ValueError) as cm:
            run_import(self.cfg, inv, write=True, out=lambda line: None)
        self.assertIn("devices.json: entry 2 is null, not a device object", str(cm.exception))
        self.assertIsNone(json.loads(inv.read_text())[1])

    def test_credentials_only_import_does_not_need_a_readable_inventory(self):
        # `import --no-devices --write` is the way back to a network key
        # after losing credentials.toml; it neither reads nor writes
        # devices.json, so a broken one must not stand in its way.
        inv = self.d / "devices.json"
        inv.write_text("[invalid")
        lines = []
        run_import(self.cfg, inv, devices=False, use_mdns=False, write=True, out=lines.append)
        self.assertIn("network key", "\n".join(lines))
        self.assertIn('network_key = "00112233445566778899aabbccddeeff"', (self.d / "credentials.toml").read_text())
        self.assertEqual(inv.read_text(), "[invalid")
        with self.assertRaises(ValueError):                  # importing devices still names the problem
            run_import(self.cfg, inv, use_mdns=False, out=lines.append)

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

    def test_the_datasets_pan_id_is_checked_against_config(self):
        lines = []
        run_import(self.cfg, self.d / "devices.json", out=lines.append)
        self.assertIn("[network] pan_id is unset; the dataset says 0xabcd", "\n".join(lines))
        self.cfg.pan_id = 0xabcd
        lines.clear()
        run_import(self.cfg, self.d / "devices.json", out=lines.append)
        self.assertNotIn("pan_id", "\n".join(lines))
        self.cfg.pan_id = 0x4e21
        lines.clear()
        run_import(self.cfg, self.d / "devices.json", out=lines.append)
        self.assertIn("! config.toml says pan_id 0x4e21; the dataset says 0xabcd", "\n".join(lines))

    def test_a_run_with_only_the_duplicate_name_reminder_leaves_the_file_alone(self):
        import threadwatch.ha as ha_mod
        ha_mod.thread_devices = lambda ha, log=None: [
            {"name": "Contact Sensor", "model": "Eve Door", "addr": "1111111111111111"},
            {"name": "Contact Sensor", "model": "Eve Door", "addr": "2222222222222222"}]
        run_import(self.cfg, self.d / "devices.json", write=True, out=lambda _: None)
        path = self.d / "devices.json"
        before, before_mtime = path.read_text(), path.stat().st_mtime_ns
        # HA still shares the name -- the reminder repeats, since the fix is
        # in HA -- but no entry changes, so nothing is rewritten.
        lines = []
        run_import(self.cfg, path, write=True, out=lines.append)
        text = "\n".join(lines)
        self.assertIn("names 2 devices in Home Assistant", text)
        self.assertIn("nothing to write: no entry changes", text)
        self.assertNotIn("wrote", text)
        self.assertNotIn("restart it", text)
        self.assertEqual(path.read_text(), before)
        self.assertEqual(path.stat().st_mtime_ns, before_mtime)

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



class CallManyTest(unittest.TestCase):
    def test_results_come_back_in_request_order_whatever_the_reply_order(self):
        from threadwatch.ha import HomeAssistant
        ha = HomeAssistant("http://x", "t")
        sent = []
        replies = [{"id": 2, "type": "result", "success": True, "result": "two"},
                   {"id": 9, "type": "event", "event": {}},
                   {"id": 3, "type": "result", "success": False, "error": {"message": "nope"}},
                   {"id": 1, "type": "result", "success": True, "result": "one"}]
        ha._send_json = lambda obj: sent.append(obj)
        ha._recv_json = lambda deadline=None: replies.pop(0)
        out = ha.call_many([("a", {"x": 1}), ("b", {}), ("c", {})])
        self.assertEqual([m["id"] for m in sent], [1, 2, 3])
        self.assertEqual(sent[0], {"id": 1, "type": "a", "x": 1})
        self.assertEqual(out[:2], ["one", "two"])
        self.assertIsInstance(out[2], HAError)
        self.assertIn("c: nope", str(out[2]))
        replies.append({"id": 4, "type": "result", "success": True, "result": "four"})
        self.assertEqual(ha.call("d"), "four")


class DatasetTlvTest(unittest.TestCase):
    def test_truncated_tlv_yields_no_field_instead_of_raising(self):
        for bad in ("0003", "004b", "00ff01"):
            self.assertEqual(parse_dataset_tlv(bad), {})

    def test_non_hex_dataset_raises_haerror(self):
        with self.assertRaises(HAError):
            parse_dataset_tlv("zzzz")

    def test_well_formed_dataset_still_parses(self):
        import struct
        body = (bytes([0, 3, 0]) + struct.pack(">H", 25)
                + bytes([1, 2]) + struct.pack(">H", 0x1234)
                + bytes([2, 8]) + bytes(range(8))
                + bytes([3, 4]) + b"Home"
                + bytes([5, 16]) + bytes(range(16)))
        self.assertEqual(parse_dataset_tlv(body.hex()), {
            "channel": 25, "pan_id": 0x1234, "ext_pan_id": "0001020304050607",
            "network_name": "Home",
            "network_key": "000102030405060708090a0b0c0d0e0f"})


def _serve(handler):
    """A one-connection server on localhost. ``handler(conn, request)`` runs
    on its own thread once the HTTP request head has arrived (request is
    b"" if the client sent nothing). Returns the URL to connect to."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(5.0)

    def run():
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        finally:
            srv.close()
        with conn:
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
            try:
                handler(conn, buf)
            except OSError:
                pass

    threading.Thread(target=run, daemon=True).start()
    return f"http://127.0.0.1:{srv.getsockname()[1]}"


def _accept_for(request: bytes) -> str:
    import base64
    import hashlib
    key = next(l.split(b":", 1)[1].strip() for l in request.split(b"\r\n")
               if l.lower().startswith(b"sec-websocket-key:"))
    return base64.b64encode(hashlib.sha1(key + ha.WS_GUID.encode()).digest()).decode()


def _upgrade(request: bytes, extra: bytes = b"") -> bytes:
    return (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + _accept_for(request).encode() + b"\r\n\r\n" + extra)


class HandshakeTest(unittest.TestCase):
    """ws_connect against a real socket: the upgrade request it sends,
    the reply it accepts, and the message for each way the reply can be
    wrong. Every one of these is what `threadwatch import` prints when
    HA_URL points at the wrong thing, and each was untested."""

    def test_the_upgrade_request_and_a_good_reply(self):
        seen = {}

        def handler(conn, request):
            seen["request"] = request
            conn.sendall(_upgrade(request, extra=b"\x81\x02{}"))      # a frame arriving with the headers

        url = _serve(handler)
        sock, rest = ha.ws_connect(url)
        sock.close()
        self.assertEqual(rest, b"\x81\x02{}")
        lines = seen["request"].decode().split("\r\n")
        self.assertEqual(lines[0], "GET /api/websocket HTTP/1.1")
        headers = {l.split(":", 1)[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:] if ":" in l}
        self.assertEqual(headers["host"], url[len("http://"):])
        self.assertEqual((headers["upgrade"], headers["connection"], headers["sec-websocket-version"]),
                         ("websocket", "Upgrade", "13"))
        import base64
        self.assertEqual(len(base64.b64decode(headers["sec-websocket-key"])), 16)

    def test_each_wrong_reply_has_its_own_message(self):
        cases = [
            (lambda conn, req: conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
             "Home Assistant refused the websocket upgrade: HTTP/1.1 200 OK (is HA_URL the HA address?)"),
            (lambda conn, req: conn.sendall(b"HTTP/1.1 401 Unauthorized\r\n\r\n"),
             "refused the websocket upgrade: HTTP/1.1 401 Unauthorized"),
            (lambda conn, req: conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: bogus\r\n\r\n"),
             "websocket handshake: bad Sec-WebSocket-Accept"),
            (lambda conn, req: None,                                          # closed without a word
             "Home Assistant closed the connection during the websocket handshake"),
            (lambda conn, req: conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nX-Pad: " + b"x" * 70000),
             "websocket handshake: response too large"),
        ]
        for handler, message in cases:
            with self.assertRaises(HAError) as cm:
                ha.ws_connect(_serve(handler))
            self.assertIn(message, str(cm.exception))

    def test_nothing_listening_names_the_host_and_port(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        with self.assertRaises(HAError) as cm:
            ha.ws_connect(f"http://127.0.0.1:{port}")
        self.assertIn(f"cannot reach Home Assistant at 127.0.0.1:{port} (", str(cm.exception))
        self.assertIn("HA_URL wrong, or not on this network?", str(cm.exception))

    def _ha(self, greeting, reply_to_auth):
        """A server that upgrades, greets, reads the auth message and answers it."""
        seen = {}

        def handler(conn, request):
            conn.sendall(_upgrade(request))
            conn.sendall(server_frame(0x1, json.dumps(greeting).encode()))
            if reply_to_auth is None:
                return
            opcode, data = unmask(conn.recv(4096))
            seen["auth"] = (opcode, json.loads(data))
            conn.sendall(server_frame(0x1, json.dumps(reply_to_auth).encode()))
            seen["after"] = conn.recv(4096)                             # the close frame, or EOF

        return _serve(handler), seen

    def test_connect_authenticates_with_the_token_and_close_sends_a_close_frame(self):
        url, seen = self._ha({"type": "auth_required", "ha_version": "2026.9.0"},
                             {"type": "auth_ok", "ha_version": "2026.9.0"})
        with ha.HomeAssistant(url, "tok.en") as client:
            self.assertIs(client, client.connect.__self__)
            self.assertIsNotNone(client._sock)
        self.assertEqual(seen["auth"], (0x1, {"type": "auth", "access_token": "tok.en"}))
        time.sleep(0.05)
        self.assertEqual(unmask(seen["after"]), (0x8, struct.pack(">H", 1000)))

    def test_a_rejected_token_says_to_make_a_new_one(self):
        url, _seen = self._ha({"type": "auth_required"}, {"type": "auth_invalid", "message": "Invalid access token"})
        client = ha.HomeAssistant(url, "stale")
        with self.assertRaises(HAError) as cm:
            client.connect()
        self.assertEqual(str(cm.exception), "Home Assistant rejected the token (Invalid access token); "
                                            "create a new long-lived access token and update HA_TOKEN")
        self.assertIsNone(client._sock)                                 # closed on the way out

    def test_a_broken_connection_is_still_closed_when_the_close_frame_fails(self):
        """Sending the close frame and closing the socket shared one try, so
        an OSError from sendall -- a connection already broken, the usual
        reason to be closing -- skipped the close and dropped the only
        reference to the descriptor."""
        closed = []

        class BrokenSocket:
            def sendall(self, data):
                raise OSError("broken pipe")

            def close(self):
                closed.append(True)

            def recv(self, n):
                return b""

        client = ha.HomeAssistant("ws://ha.local:8123/api/websocket", "tok")
        sock = BrokenSocket()
        client._sock = sock
        client._reader = ha.FrameReader(sock.recv, sock.sendall)
        client.close()
        self.assertEqual(closed, [True])
        self.assertIsNone(client._sock)
        self.assertIsNone(client._reader)

    def test_an_unexpected_greeting_is_named(self):
        url, _seen = self._ha({"type": "event", "event": {}}, None)
        client = ha.HomeAssistant(url, "tok")
        with self.assertRaises(HAError) as cm:
            client.connect()
        self.assertEqual(str(cm.exception), "unexpected first message from Home Assistant: event")
        self.assertIsNone(client._sock)


if __name__ == "__main__":
    unittest.main()
