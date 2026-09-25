"""srp: a device's SRP registration read whole from its 6LoWPAN fragments,
and what it says (the host name, the Matter service names, the leases)."""

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch import srp
from threadwatch.crypto import Decryptor

ZONE = "default.service.arpa"
FABRIC = "1A2B3C4D5E6F7081"
APPLE = "0F1E2D3C4B5A6978"


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def srp_update(dns_id: int, host: str, instances: list[str], lease: int | None = 7200,
               key_lease: int | None = 1209600, zone: str = ZONE, plain: bool = False) -> bytes:
    """A DNS UPDATE laid out as an OpenThread SRP client sends it (checked
    against a registration captured on air): the zone; per service a PTR
    whose rdata is the instance label and a pointer back to the
    ``_matter._tcp`` before it, the fabric's sub-type PTR, a delete-all,
    the SRV and the TXT, all owned by a pointer to that instance label;
    then the host's delete-all, AAAA and KEY; then the Update Lease
    option. The first SRV target writes the host name out, later mentions
    point at it. ``plain`` writes every name out in full instead."""
    msg = bytearray(struct.pack(">6H", dns_id, 5 << 11, 1, 0, 0, 1))
    zone_at = len(msg)
    msg += dns_name(zone) + struct.pack(">HH", 6, 1)
    count = 0

    def rr(owner: bytes, rtype: int, rdata: bytes, cls: int = 1, ttl: int = 7200) -> int:
        """Appends a record; returns where its rdata starts."""
        nonlocal count
        msg.extend(owner + struct.pack(">HHIH", rtype, cls, ttl, len(rdata)))
        count += 1
        msg.extend(rdata)
        return len(msg) - len(rdata)

    def ptr(at: int) -> bytes:
        return struct.pack(">H", 0xC000 | at)

    def labels(name: str) -> bytes:
        return dns_name(name)[:-1]

    host_fqdn = f"{host}.{zone}"
    host_at = None
    for inst in instances:
        fqdn = f"{inst}._matter._tcp.{zone}"
        if plain:
            rr(dns_name(f"_matter._tcp.{zone}"), 12, dns_name(fqdn))
            rr(dns_name(fqdn), 33, struct.pack(">HHH", 0, 0, 5540) + dns_name(host_fqdn))
            rr(dns_name(fqdn), 16, b"\x05SII=5")
            continue
        service_at = len(msg)
        inst_at = rr(labels("_matter._tcp") + ptr(zone_at), 12, labels(inst) + ptr(service_at))
        rr(labels(f"_I{inst.split('-')[0]}._sub") + ptr(service_at), 12, ptr(inst_at))
        rr(ptr(inst_at), 255, b"", cls=255, ttl=0)
        target = ptr(host_at) if host_at is not None else labels(host) + ptr(zone_at)
        at = rr(ptr(inst_at), 33, struct.pack(">HHH", 0, 0, 5540) + target)
        host_at = host_at if host_at is not None else at + 6
        rr(ptr(inst_at), 16, b"\x05SII=5")
    if plain or host_at is None:
        host_owner = dns_name(host_fqdn)
    else:
        host_owner = ptr(host_at)
        rr(host_owner, 255, b"", cls=255, ttl=0)
    rr(host_owner, 28, bytes(range(16)))
    rr(host_owner, 25, b"\x02\x00\x03\x0d" + b"\x11" * 64)
    option = b""
    if lease is not None:
        data = struct.pack(">I", lease) + (struct.pack(">I", key_lease) if key_lease is not None else b"")
        option = struct.pack(">HH", srp.OPT_UPDATE_LEASE, len(data)) + data
    msg += b"\x00" + struct.pack(">HHIH", 41, 1232, 0, len(option)) + option
    struct.pack_into(">H", msg, 8, count)
    return bytes(msg)


def lowpan_fragments(packet: bytes, header_len: int, first_chunk: int = 40, chunk: int = 64,
                     tag: int = 0x1234) -> list[bytes]:
    """Split a compressed 6LoWPAN packet (``header_len`` bytes of IPHC and
    UDP-NHC, then the UDP payload) into FRAG1 and FRAGN payloads as a
    Thread device sends them: offsets count the uncompressed datagram."""
    payload = packet[header_len:]
    size = srp.UNCOMPRESSED_HEADERS + len(payload)
    frag1 = bytes([0xC0 | (size >> 8), size & 0xFF, tag >> 8, tag & 0xFF]) + packet[:header_len + first_chunk]
    out = [frag1]
    pos = first_chunk
    while pos < len(payload):
        offset = (srp.UNCOMPRESSED_HEADERS + pos) // 8
        out.append(bytes([0xE0 | (size >> 8), size & 0xFF, tag >> 8, tag & 0xFF, offset]) + payload[pos:pos + chunk])
        pos += chunk
    return out


class ParseUpdateTest(unittest.TestCase):
    def test_a_registration_yields_host_service_names_and_leases(self):
        msg = srp_update(7, "E17F3A9B2C4D5E6F", [f"{FABRIC}-0000000000000067", f"{APPLE}-00000000ABCDEF01"])
        got = srp.parse_update(msg)
        self.assertEqual(got, {"id": 7, "zone": ZONE, "host": "E17F3A9B2C4D5E6F",
                               "instances": [f"{APPLE.lower()}-00000000abcdef01._matter._tcp.{ZONE}",
                                             f"{FABRIC.lower()}-0000000000000067._matter._tcp.{ZONE}"],
                               "lease": 7200, "key_lease": 1209600})

    def test_names_written_out_in_full_are_read_too(self):
        msg = srp_update(8, "E17F3A9B2C4D5E6F", [f"{FABRIC}-0000000000000067", f"{APPLE}-00000000ABCDEF01"],
                         plain=True)
        got = srp.parse_update(msg)
        self.assertEqual((got["host"], len(got["instances"])), ("E17F3A9B2C4D5E6F", 2))
        self.assertEqual(srp.matter_instances_in(msg, ZONE, 0), got["instances"])

    def test_a_host_only_registration_has_no_instances_and_a_lease_without_key_lease_is_read(self):
        msg = srp_update(9, "E17F3A9B2C4D5E6F", [], lease=0, key_lease=None)
        self.assertEqual(srp.parse_update(msg), {"id": 9, "zone": ZONE, "host": "E17F3A9B2C4D5E6F",
                                                 "instances": [], "lease": 0, "key_lease": None})

    def test_queries_responses_and_damage_are_not_registrations(self):
        msg = srp_update(10, "AA", [f"{FABRIC}-0000000000000001"])
        self.assertIsNone(srp.parse_update(struct.pack(">HH", 10, 0x0000) + msg[4:]))      # a query
        self.assertIsNone(srp.parse_update(struct.pack(">HH", 10, 0x8000 | 5 << 11) + msg[4:]))   # the answer
        self.assertIsNone(srp.parse_update(msg[:40]))                                       # truncated
        self.assertIsNone(srp.parse_update(b""))
        looped = bytearray(msg)
        looped[12:14] = b"\xc0\x0c"                                    # the zone name points at itself
        self.assertIsNone(srp.parse_update(bytes(looped)))


class ReassemblerTest(unittest.TestCase):
    """Thread fragments an SRP update over three to six frames; the
    recorder puts them back in whatever order the sniffer heard them."""

    def setUp(self):
        from tests.test_identity import lowpan_udp
        self.msg = srp_update(11, "E17F3A9B2C4D5E6F", [f"{FABRIC}-0000000000000067", f"{APPLE}-00000000ABCDEF01",
                                                       "5A5A5A5A5A5A5A5A-0000000012345678"])
        self.packet = lowpan_udp(49152, 53, self.msg)
        self.frags = lowpan_fragments(self.packet, 10)
        self.assertGreaterEqual(len(self.frags), 4)

    def _first(self, frag):
        return Decryptor.udp_ports(frag, mac_src_ext="e17f3a9b2c4d5e6f")

    def test_fragments_in_order_give_the_whole_datagram(self):
        r = srp.Reassembler()
        got = None
        for i, frag in enumerate(self.frags):
            f = srp.fragment(frag)
            self.assertEqual(f[0], "first" if i == 0 else "next")
            got = r.add("f63e", f, self._first(frag) if i == 0 else None, 100.0 + i * 0.01)
            if i < len(self.frags) - 1:
                self.assertIsNone(got)
        sport, dport, payload, _sip, _dip = got
        self.assertEqual((sport, dport, payload), (49152, 53, self.msg))
        self.assertEqual(r.pending, {})

    def test_out_of_order_fragments_and_a_mesh_header_still_complete(self):
        r = srp.Reassembler()
        mesh = bytes([0xB5, 0xd4, 0x05, 0xfc, 0x11])            # V=F=1: short originator and final
        order = [self.frags[0]] + self.frags[1:][::-1]
        got = None
        for i, frag in enumerate(order):
            f = srp.fragment(mesh + frag)
            got = r.add("f63e", f, self._first(mesh + frag) if f[0] == "first" else None, 100.0 + i * 0.01)
        self.assertEqual(got[2], self.msg)

    def test_a_fragn_without_its_frag1_and_a_stale_datagram_are_dropped(self):
        r = srp.Reassembler()
        self.assertIsNone(r.add("f63e", srp.fragment(self.frags[1]), None, 100.0))
        self.assertEqual(r.pending, {})
        r.add("f63e", srp.fragment(self.frags[0]), self._first(self.frags[0]), 100.0)
        self.assertEqual(len(r.pending), 1)
        self.assertIsNone(r.add("f63e", srp.fragment(self.frags[1]), None, 100.0 + srp.Reassembler.HOLD_S + 1))
        self.assertEqual(r.pending, {})                    # too late: the FRAG1 was let go
        self.assertIsNone(srp.fragment(self.packet))       # an unfragmented packet is not a fragment

    def test_a_fragment_of_a_pending_registration_still_names_the_services(self):
        r = srp.Reassembler()
        r.add("e17f", srp.fragment(self.frags[0]), self._first(self.frags[0]), 100.0)
        self.assertIsNone(r.last_update)
        # The fourth fragment was missed; what the others carry is read
        # across their adjacent pieces, never across the hole.
        heard = [f for i, f in enumerate(self.frags) if i not in (0, 3)]
        for frag in heard:
            self.assertIsNone(r.add("e17f", srp.fragment(frag), None, 100.1))
            self.assertEqual((r.last_update["id"], r.last_update["zone"]), (11, ZONE))
        pieces = r.last_update["pieces"]
        self.assertEqual(pieces, [(0, self.msg[:40 + 2 * 64]), (40 + 3 * 64, self.msg[40 + 3 * 64:])])
        names = sorted({n for at, piece in pieces for n in srp.matter_instances_in(piece, ZONE, at)})
        self.assertTrue(set(names) <= set(srp.parse_update(self.msg)["instances"]))
        self.assertGreaterEqual(len(names), 2)
        self.assertIsNone(r.add("e17f", srp.fragment(self.frags[1] + b"\x00"), None, 100.2))   # a stray tag
        r.add("e17f", srp.fragment(bytes([0xE0, 0x00, 0xff, 0xff, 5]) + b"x" * 8), None, 100.3)   # unknown tag
        self.assertIsNone(r.last_update)
        # A fragment of something that is not a registration says nothing.
        from tests.test_identity import lowpan_udp
        other = lowpan_fragments(lowpan_udp(5540, 5540, b"\x15" * 300), 10, tag=9)
        r.add("e17f", srp.fragment(other[0]), self._first(other[0]), 101.0)
        r.add("e17f", srp.fragment(other[1]), None, 101.1)
        self.assertIsNone(r.last_update)

    def test_instance_names_are_read_from_raw_bytes(self):
        body = (b"\x21" + f"{FABRIC}-000000000000002A".encode() + b"\x07_matter\x04_tcp\xc0\x0c"
                + b"junk\x21" + f"{APPLE}-00000000ABCDEF01".encode() + b"\x07_matter\x04_tcp\x07default\x00")
        self.assertEqual(srp.matter_instances_in(body, ZONE),
                         [f"{APPLE.lower()}-00000000abcdef01._matter._tcp.{ZONE}",
                          f"{FABRIC.lower()}-000000000000002a._matter._tcp.{ZONE}"])
        self.assertEqual(srp.matter_instances_in(b"\x21" + b"Z" * 33 + b"\x07_matter\x04_tcp", ZONE), [])

    def test_instance_names_followed_by_a_pointer_are_read_where_it_can_point_back(self):
        msg = srp_update(12, "E17F3A9B2C4D5E6F", [f"{FABRIC}-0000000000000067", f"{APPLE}-00000000ABCDEF01"])
        self.assertNotIn(f"{FABRIC}-0000000000000067".encode() + b"\x07_matter", msg)
        self.assertEqual(srp.matter_instances_in(msg, ZONE, 0), srp.parse_update(msg)["instances"])
        label = b"\x21" + f"{FABRIC}-000000000000002A".encode()
        name = f"{FABRIC.lower()}-000000000000002a._matter._tcp.{ZONE}"
        service = b"\x07_matter\x04_tcp\xc0\x0c"
        # Where the piece sits is unknown, or the pointer lands before it: read.
        self.assertEqual(srp.matter_instances_in(label + b"\xc0\x26", ZONE), [name])
        self.assertEqual(srp.matter_instances_in(b"xx" + label + b"\xc0\x26", ZONE, 100), [name])
        # It lands on _matter._tcp inside the piece: read.
        self.assertEqual(srp.matter_instances_in(service + label + b"\xc0\x64", ZONE, 100), [name])
        # It lands on something else, on the label itself, or ahead: not an instance name.
        self.assertEqual(srp.matter_instances_in(b"\x05other" + label + b"\xc0\x64", ZONE, 100), [])
        self.assertEqual(srp.matter_instances_in(label + b"\xc0\x64", ZONE, 100), [])
        self.assertEqual(srp.matter_instances_in(label + b"\xc1\x00", ZONE, 100), [])

    def _fresh_tags(self, r, count, ts):
        for i in range(count):
            frag = self.frags[0][:2] + bytes([i >> 8, i & 0xFF]) + self.frags[0][4:]   # a fresh tag each
            r.add("f63e", srp.fragment(frag), self._first(frag), ts(i))

    def test_the_table_of_partial_datagrams_is_bounded(self):
        # Spread out, the age prune alone keeps the table small.
        r = srp.Reassembler()
        self._fresh_tags(r, srp.Reassembler.MAX + 10, lambda i: 100.0 + i)
        self.assertLessEqual(len(r.pending), srp.Reassembler.MAX)
        # A flood inside HOLD_S leaves nothing old enough to prune: the
        # hard cap lets the oldest go, one for each new tag.
        r = srp.Reassembler()
        self._fresh_tags(r, srp.Reassembler.MAX + 10, lambda i: 100.0)
        self.assertEqual(len(r.pending), srp.Reassembler.MAX)
        self.assertEqual(sorted(tag for _sender, tag in r.pending), list(range(10, srp.Reassembler.MAX + 10)))


if __name__ == "__main__":
    unittest.main()
