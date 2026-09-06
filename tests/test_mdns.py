import errno
import struct
import sys
import time
import types
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from threadwatch import mdns  # noqa: E402
from tests import no_lan  # noqa: E402
from tests.no_lan import real_browse  # noqa: E402  (this module tests the browse itself)
from threadwatch.mdns import (SERVICE, clean_text, TYPE_A, TYPE_PTR, TYPE_SRV, TYPE_TXT, build_query,  # noqa: E402
                              collect_routers, encode_name, parse_message, read_name)

EXT = bytes.fromhex("c0ffee0000000001")


def txt(*items: bytes) -> bytes:
    return b"".join(bytes([len(i)]) + i for i in items)


def rr(name: bytes, rtype: int, rdata: bytes, ttl: int = 120) -> bytes:
    return name + struct.pack(">HHIH", rtype, 1, ttl, len(rdata)) + rdata


def response(records: list[bytes]) -> bytes:
    return struct.pack(">HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


class GuardTest(unittest.TestCase):
    def test_the_suite_cannot_browse_the_lan_without_asking(self):
        # tests/__init__.py installs the guard before any test module, so
        # a module that never heard of no_lan still cannot send multicast.
        # Only real_browse() below gets the real one back.
        self.assertIs(mdns.browse, no_lan.no_browse)
        with real_browse():
            self.assertIsNot(mdns.browse, no_lan.no_browse)
        self.assertIs(mdns.browse, no_lan.no_browse)


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
        r = collect_routers(parse_message(response([rr(service, TYPE_PTR, inst)]))
                            + parse_message(more))["otb." + SERVICE]
        self.assertEqual((r["hostname"], r["ext"], r["complete"]), ("otbr.local", None, True))

    def test_names_and_txt_off_the_network_cannot_write_journal_lines(self):
        # Anyone on the LAN answers mDNS. A hostname or instance carrying a
        # newline would otherwise be printed as the recorder's own lines.
        evil = b"\n[threadwatch] CRITICAL: phase_locked_storm\x1b[31m"
        service = encode_name(SERVICE)
        inst = bytes([len(evil)]) + evil + b"\xc0\x0c"
        full = bytes([len(evil)]) + evil + service
        host = b"\x0dhost\ninjected\x00"
        records = parse_message(response([
            rr(service, TYPE_PTR, inst),
            rr(full, TYPE_SRV, struct.pack(">HHH", 0, 0, 1) + host),
            rr(full, TYPE_TXT, txt(b"xa=" + bytes(8), b"vn=Ven\rdor", b"mn=" + b"M" * 250, b"nn=Net\nwork")),
        ]))
        (r,) = collect_routers(records).values()
        for text in (r["instance"], r["hostname"], r["vendor"], r["model"], r["network_name"]):
            self.assertNotRegex(text, r"[\x00-\x1f\x7f]", text)
        self.assertEqual(r["vendor"], "Ven?dor")
        self.assertEqual(r["hostname"], "host?injected")
        self.assertEqual(r["model"], "M" * 250)
        self.assertEqual(clean_text(b"M" * 400), "M" * 255)  # cut to what DNS allows
        self.assertTrue(r["instance"].startswith("?[threadwatch] CRITICAL"))

    def test_truncated_or_looping_names_raise_cleanly(self):
        with self.assertRaises(ValueError):
            read_name(b"\x05abc", 0)
        with self.assertRaises(ValueError):
            read_name(b"\xc0\x00", 0)
        self.assertEqual(parse_message(b"\x00" * 5), [])


class BrowseTest(unittest.TestCase):
    """browse() over fake sockets: what arrives from the LAN is whatever the
    LAN sends, and one bad datagram must not end the browse."""

    def _browse(self, inbox, group_bind_fails=False, timeout=0.3, query_setup_fails=False, made=None):
        made = [] if made is None else made

        class FakeSock:
            def __init__(self, *_a):
                self.inbox = inbox if not made else []          # the query socket is made first
                self.sent, self.closed = [], False
                self.first = not made
                made.append(self)

            def setsockopt(self, *_a):
                if query_setup_fails and self.first:
                    raise OSError(errno.EMFILE, "Too many open files")

            def bind(self, addr):
                if group_bind_fails and addr[1] == mdns.MDNS_PORT:
                    raise OSError(errno.EADDRINUSE, "Address already in use")

            def sendto(self, data, addr):
                self.sent.append((data, addr))

            def recvfrom(self, _n):
                item = self.inbox.pop(0)
                if isinstance(item, Exception):
                    raise item
                return item, ("192.0.2.9", mdns.MDNS_PORT)

            def close(self):
                self.closed = True

        def fake_select(socks, _w, _x, wait):
            ready = [s for s in socks if s.inbox]
            if not ready:
                time.sleep(min(wait, 0.02))
            return ready, [], []

        fake_socket = types.SimpleNamespace(**{k: getattr(mdns.socket, k) for k in dir(mdns.socket)
                                               if not k.startswith("__")})
        fake_socket.socket = FakeSock
        log = []
        with real_browse(), mock.patch.object(mdns, "socket", fake_socket), \
                mock.patch.object(mdns, "select", types.SimpleNamespace(select=fake_select)):
            found = mdns.browse(timeout=timeout, log=log.append)
        return found, made, log

    def _answers(self):
        service = encode_name(SERVICE)
        full = encode_name("OTB." + SERVICE)
        ptr_only = response([rr(service, TYPE_PTR, b"\x03OTB" + b"\xc0\x0c")])
        details = response([rr(full, TYPE_SRV, struct.pack(">HHH", 0, 0, 49153) + encode_name("otbr.local")),
                            rr(full, TYPE_TXT, txt(b"xa=" + EXT, b"nn=MyHome")),
                            rr(encode_name("otbr.local"), TYPE_A, bytes([192, 0, 2, 73]))])
        return ptr_only, details

    def test_every_truncation_the_parser_rejects_is_skipped_not_fatal(self):
        # An mDNS responder is anyone on the LAN, so these four rejections
        # are the boundary between a hostile or broken responder and
        # something parsed as a border router. All four were uncovered.
        service = encode_name(SERVICE)
        cases = {
            # A name whose last label runs past the end of the datagram.
            "truncated name": struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\x03OTB",
            # A compression pointer with only its first byte present.
            "truncated compression pointer":
                struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\x03OTB\xc0",
            # A question whose four type/class bytes are not all there.
            "truncated question":
                struct.pack(">HHHHHH", 0, 0x8400, 1, 0, 0, 0) + service + b"\x00\x0c",
            # A record header (type, class, ttl, rdlength) cut short.
            "truncated resource record":
                struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + service + b"\x00\x0c\x00",
        }
        for message, data in cases.items():
            with self.subTest(message):
                with self.assertRaises(ValueError) as cm:
                    parse_message(data)
                self.assertEqual(str(cm.exception), message)
        # And a browse that receives all four still reports the good one.
        ptr_only, details = self._answers()
        found, _made, log = self._browse(list(cases.values()) + [ptr_only, details])
        self.assertEqual([r["instance"] for r in found], ["OTB"])
        self.assertEqual(log, [])

    def test_a_refused_read_and_a_cut_datagram_do_not_end_the_browse(self):
        ptr_only, details = self._answers()
        cut = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + b"\x05abc"   # one answer, name cut short
        self.assertRaises(ValueError, parse_message, cut)
        found, made, log = self._browse([OSError(errno.ECONNREFUSED, "Connection refused"), cut, ptr_only, details])
        self.assertEqual([(r["instance"], r["hostname"], r["port"], r["ext"], r["network_name"], r["addresses"])
                          for r in found],
                         [("OTB", "otbr.local", 49153, EXT.hex(), "MyHome", ["192.0.2.73"])])
        self.assertEqual(log, [])
        query, group = made
        self.assertTrue(query.closed and group.closed)
        self.assertEqual(query.inbox, [])                                    # everything was read
        # Two service queries at the start, then the SRV/TXT of the instance
        # the PTR-only answer left incomplete; nothing more once complete.
        sent = [data for data, addr in query.sent]
        self.assertEqual([addr for _d, addr in query.sent], [(mdns.MDNS_GROUP, mdns.MDNS_PORT)] * 3)
        self.assertEqual(sent[:2], [build_query([(SERVICE, TYPE_PTR)]),
                                    build_query([(SERVICE, TYPE_PTR)], unicast_reply=False)])
        self.assertEqual(sent[2], build_query([("otb." + SERVICE, TYPE_SRV), ("otb." + SERVICE, TYPE_TXT)]))
        self.assertEqual(group.sent, [])

    def test_without_the_multicast_group_the_browse_says_so_and_carries_on(self):
        ptr_only, details = self._answers()
        found, made, log = self._browse([ptr_only, details], group_bind_fails=True)
        self.assertEqual([r["hostname"] for r in found], ["otbr.local"])
        self.assertEqual(len(log), 1)
        self.assertIn("not listening on the multicast group", log[0])
        self.assertIn("unicast replies only", log[0])
        self.assertEqual(len(made), 2)
        self.assertTrue(all(s.closed for s in made))   # the group socket too: a browse every 10 min must not leak one

    def test_a_query_socket_that_cannot_be_configured_is_still_closed(self):
        # query_sock used to be created, configured and bound before it was
        # appended to the list the finally closes, so a raise from
        # setsockopt or bind leaked the descriptor. Realistically only fd
        # exhaustion gets there, which is exactly when leaking one more
        # matters, and the recorder browses for the life of the process.
        made = []
        with self.assertRaises(OSError):
            self._browse([], query_setup_fails=True, made=made)
        self.assertEqual(len(made), 1)
        self.assertTrue(made[0].closed)

    def test_nothing_answering_is_an_empty_list_after_the_timeout(self):
        t0 = time.monotonic()
        found, made, log = self._browse([], timeout=0.2)
        self.assertEqual((found, log), ([], []))
        self.assertGreaterEqual(time.monotonic() - t0, 0.2)
        self.assertEqual(len(made[0].sent), 2)                              # asked once; nothing to ask about


if __name__ == "__main__":
    unittest.main()
