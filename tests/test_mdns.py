import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from threadwatch.mdns import (SERVICE, TYPE_A, TYPE_PTR, TYPE_SRV, TYPE_TXT, build_query,  # noqa: E402
                              collect_routers, encode_name, parse_message, read_name)

EXT = bytes.fromhex("c0ffee0000000001")


def txt(*items: bytes) -> bytes:
    return b"".join(bytes([len(i)]) + i for i in items)


def rr(name: bytes, rtype: int, rdata: bytes, ttl: int = 120) -> bytes:
    return name + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata


def response(records: list[bytes]) -> bytes:
    return struct.pack(">HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


class WireTest(unittest.TestCase):
    def test_query_sets_the_unicast_bit(self):
        q = build_query([(SERVICE, TYPE_PTR)])
        self.assertEqual(q[:12], struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0))
        self.assertEqual(q[12:], encode_name(SERVICE) + struct.pack(">HH", TYPE_PTR, 0x8001))
        self.assertTrue(build_query([("a.local", TYPE_A)], unicast_reply=False).endswith(struct.pack(">HH", TYPE_A, 1)))

    def test_compressed_names_and_record_types(self):
        # The service name once, then every other name points back into it.
        service = encode_name(SERVICE)                          # at offset 12
        inst = b"\x13AppleTV Living Room" + b"\xc0\x0c"          # "AppleTV Living Room" + pointer to the service
        inst_off = 12 + len(service) + 10                       # where the PTR rdata (the instance name) sits
        inst_ptr = bytes([0xC0, inst_off])
        host = encode_name("AppleTV-Living-Room.local")
        msg = response([
            rr(service, TYPE_PTR, inst),
            rr(inst_ptr, TYPE_SRV, struct.pack(">HHH", 0, 0, 49153) + host),
            rr(inst_ptr, TYPE_TXT, txt(b"rv=1", b"xa=" + EXT, b"nn=MyHome", b"xp=" + bytes(range(8)), b"vn=Apple",
                                       b"mn=BorderRouter")),
            rr(host, TYPE_A, bytes([192, 0, 2, 73])),
            rr(host, TYPE_A, bytes([192, 0, 2, 73])),        # answered twice (both queries): listed once
        ])
        recs = parse_message(msg)
        self.assertEqual(recs[0], (SERVICE, TYPE_PTR, "AppleTV Living Room." + SERVICE))
        self.assertEqual(recs[1], ("AppleTV Living Room." + SERVICE, TYPE_SRV, (49153, "AppleTV-Living-Room.local")))
        self.assertEqual(recs[2][1], TYPE_TXT)
        self.assertEqual(recs[2][2]["xa"], EXT)
        self.assertEqual(recs[3], ("AppleTV-Living-Room.local", TYPE_A, "192.0.2.73"))
        self.assertEqual(len(recs), 5)
        routers = collect_routers(recs)
        self.assertEqual(list(routers), ["appletv living room." + SERVICE])
        r = routers["appletv living room." + SERVICE]
        self.assertEqual((r["instance"], r["hostname"], r["port"], r["ext"], r["network_name"], r["vendor"], r["model"],
                          r["addresses"], r["complete"]),
                         ("AppleTV Living Room", "appletv-living-room.local", 49153, EXT.hex(), "MyHome", "Apple",
                          "BorderRouter", ["192.0.2.73"], True))
        self.assertEqual(r["ext_pan_id"], bytes(range(8)).hex())

    def test_instance_without_details_is_incomplete_and_bad_xa_is_none(self):
        service = encode_name(SERVICE)
        inst = b"\x03OTB" + b"\xc0\x0c"
        routers = collect_routers(parse_message(response([rr(service, TYPE_PTR, inst)])))
        r = routers["otb." + SERVICE]
        self.assertEqual((r["instance"], r["hostname"], r["ext"], r["complete"]), ("OTB", None, None, False))
        # A later answer completes it, but a malformed xa is no address.
        full = encode_name("OTB." + SERVICE)                    # no pointer: it would loop in this message
        more = response([rr(full, TYPE_TXT, txt(b"xa=short")),
                         rr(full, TYPE_SRV, struct.pack(">HHH", 0, 0, 1) + encode_name("otbr.local"))])
        r = collect_routers(parse_message(response([rr(service, TYPE_PTR, inst)])) + parse_message(more))["otb." + SERVICE]
        self.assertEqual((r["hostname"], r["ext"], r["complete"]), ("otbr.local", None, True))

    def test_truncated_or_looping_names_raise_cleanly(self):
        with self.assertRaises(ValueError):
            read_name(b"\x05abc", 0)
        with self.assertRaises(ValueError):
            read_name(b"\xc0\x00", 0)
        self.assertEqual(parse_message(b"\x00" * 5), [])


if __name__ == "__main__":
    unittest.main()
