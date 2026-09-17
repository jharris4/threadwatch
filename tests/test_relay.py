"""`threadwatch relay`: a dongle on another host, streamed to the recorder."""

import io
import json
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch import relay
from threadwatch.relay import handshake_line, read_handshake, records, relay_stream


def pcap_bytes(n: int, dlt: int = 230) -> bytes:
    """A pcap global header and n records of growing size."""
    out = struct.pack("<LHHIILL", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, dlt)
    for i in range(n):
        data = bytes([i]) * (3 + i)
        out += struct.pack("<LLLL", 1000 + i, 0, len(data), len(data)) + data
    return out


class FakeSocket:
    def __init__(self, fail_after: int | None = None):
        self.sent = b""
        self.fail_after = fail_after      # sendall calls before the connection "drops"
        self.calls = 0
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.calls += 1
        if self.fail_after is not None and self.calls > self.fail_after:
            raise OSError("connection reset")
        self.sent += data

    def close(self) -> None:
        self.closed = True


class HandshakeTest(unittest.TestCase):
    def test_the_line_round_trips_and_a_bad_one_says_why(self):
        hs = read_handshake(io.BytesIO(handshake_line("annex", "aa", 25) + b"\x00\x01"))
        self.assertEqual((hs["label"], hs["serial"], hs["channel"], hs["threadwatch_relay"]), ("annex", "aa", 25, 1))
        for what, line in {"no line": b"\xd4\xc3\xb2\xa1", "not json": b"hello\n",
                           "wrong version": json.dumps({"threadwatch_relay": 2, "label": "a",
                                                        "channel": 1}).encode() + b"\n",
                           "no label": json.dumps({"threadwatch_relay": 1, "channel": 1}).encode() + b"\n",
                           "channel not a number": json.dumps({"threadwatch_relay": 1, "label": "a",
                                                               "channel": "25"}).encode() + b"\n"}.items():
            with self.subTest(what), self.assertRaises(ValueError):
                read_handshake(io.BytesIO(line))


class RecordsTest(unittest.TestCase):
    def test_records_come_whole_and_a_cut_tail_ends_the_walk(self):
        data = pcap_bytes(3)
        got = list(records(io.BytesIO(data)))
        self.assertEqual(len(got), 4)                    # the header and three records
        self.assertEqual(b"".join(got), data)
        self.assertEqual(len(list(records(io.BytesIO(data[:-2])))), 3)   # the last record cut: not sent
        self.assertEqual(list(records(io.BytesIO(b"short"))), [])


class RelayStreamTest(unittest.TestCase):
    def test_every_connection_opens_with_the_handshake_and_header_and_drops_are_counted(self):
        data = pcap_bytes(6)
        hs = handshake_line("annex", "AA", 25)
        sockets = [FakeSocket(fail_after=2), OSError("refused"), FakeSocket()]
        logs, sleeps = [], []

        def connect():
            nxt = sockets.pop(0)
            if isinstance(nxt, Exception):
                raise nxt
            return nxt
        stats = relay_stream(io.BytesIO(data), connect, hs, logs.append, sleep=sleeps.append)
        self.assertEqual(stats["connections"], 2)
        self.assertTrue(logs[0].startswith("connected"))
        self.assertIn("connection to the recorder lost", logs[1])
        # The refused reconnect is not a line of its own: the loss said "reconnecting".
        self.assertTrue(logs[2].startswith("reconnected; 2 frames were dropped"))
        self.assertEqual(len(logs), 3)
        self.assertEqual(sleeps, [2.0])                                  # one backoff, the first delay
        # 6 records: 1 sent on the first connection, 1 lost to the drop, 1 lost to the refused
        # connect, 3 on the second connection.
        self.assertEqual((stats["sent"], stats["dropped"]), (4, 2))

    def test_the_second_connection_starts_with_the_header_again(self):
        data = pcap_bytes(4)
        hs = handshake_line("annex", None, 25)
        first, second = FakeSocket(fail_after=2), FakeSocket()
        sockets = [first, second]
        relay_stream(io.BytesIO(data), lambda: sockets.pop(0), hs, lambda m: None, sleep=lambda s: None)
        header = data[:24]
        self.assertTrue(first.sent.startswith(hs + header))
        self.assertTrue(second.sent.startswith(hs + header))
        self.assertTrue(first.closed)
        # Together the two connections carried every record but the one lost to the drop.
        recs = list(records(io.BytesIO(data)))[1:]
        carried = first.sent[len(hs) + 24:] + second.sent[len(hs) + 24:]
        self.assertEqual(carried, recs[0] + recs[2] + recs[3])

    def test_backoff_doubles_to_the_ceiling(self):
        data = pcap_bytes(8)
        sleeps = []
        calls = {"n": 0}

        def connect():
            calls["n"] += 1
            if calls["n"] < 8:
                raise OSError("down")
            return FakeSocket()
        relay_stream(io.BytesIO(data), connect, b"{}\n", lambda m: None, sleep=sleeps.append)
        self.assertEqual(sleeps, [2.0, 4.0, 8.0, 16.0, 30.0, 30.0, 30.0])
        self.assertEqual(relay.BACKOFF_S, (2.0, 30.0))


if __name__ == "__main__":
    unittest.main()
