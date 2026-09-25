"""`threadwatch relay`: a dongle on another host, streamed to the recorder."""

import io
import json
import struct
import sys
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

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
    def wait(self, event):
        self.assertTrue(event.wait(2), "relay worker did not reach the expected state")

    def test_capture_drains_during_connect_and_backoff_without_replaying_the_outage(self):
        connecting, finish_connect = threading.Event(), threading.Event()
        backing_off, retry = threading.Event(), threading.Event()
        connected, sent = threading.Event(), threading.Event()
        header, *recs = records(io.BytesIO(pcap_bytes(3)))
        hs = handshake_line("annex", "AA", 25)
        sock = FakeSocket()
        calls, sleeps = [], []

        def connect():
            calls.append(1)
            if len(calls) == 1:
                connecting.set()
                self.wait(finish_connect)
                raise OSError("offline")
            return sock

        def sleep(delay):
            sleeps.append(delay)
            backing_off.set()
            self.wait(retry)

        def source(_stream):
            yield header
            self.wait(connecting)
            for _ in range(1000):
                yield recs[0]
            finish_connect.set()
            self.wait(backing_off)
            for _ in range(1000):
                yield recs[1]
            retry.set()
            self.wait(connected)
            yield recs[2]
            self.wait(sent)

        original_send = sock.sendall

        def send(data):
            original_send(data)
            if data == recs[2]:
                sent.set()

        with mock.patch.object(relay, "records", source), mock.patch.object(sock, "sendall", send):
            stats = relay_stream(io.BytesIO(), connect, hs,
                                 lambda msg: connected.set() if msg.startswith("reconnected") else None, sleep)
        self.assertEqual(stats, {"sent": 1, "dropped": 2000, "connections": 1})
        self.assertEqual(sock.sent, hs + header + recs[2])
        self.assertTrue(sock.closed)
        self.assertEqual(sleeps, [2.0])

    def test_connection_loss_discards_pending_records_and_restarts_with_a_header(self):
        connected, first_sent, failed, retry = (threading.Event() for _ in range(4))
        header, *recs = records(io.BytesIO(pcap_bytes(3)))
        hs = handshake_line("annex", None, 25)
        first, second = FakeSocket(fail_after=2), FakeSocket()
        sockets = iter([first, second])
        original_send = first.sendall

        def send(data):
            original_send(data)
            if data == recs[0]:
                first_sent.set()

        def sleep(_delay):
            failed.set()
            self.wait(retry)

        def source(_stream):
            yield header
            self.wait(connected)
            connected.clear()
            yield recs[0]
            self.wait(first_sent)
            yield recs[1]  # the socket fails on this record
            self.wait(failed)
            yield recs[1]  # an outage record, also discarded
            retry.set()
            self.wait(connected)
            yield recs[2]

        with mock.patch.object(relay, "records", source), mock.patch.object(first, "sendall", send):
            stats = relay_stream(io.BytesIO(), lambda: next(sockets), hs,
                                 lambda msg: connected.set() if "connected" in msg else None, sleep)
        self.assertEqual(stats, {"sent": 2, "dropped": 2, "connections": 2})
        self.assertEqual(first.sent, hs + header + recs[0])
        self.assertEqual(second.sent, hs + header + recs[2])
        self.assertTrue(first.closed and second.closed)

    def test_backoff_doubles_to_the_ceiling_and_failed_handshake_closes_socket(self):
        connected = threading.Event()
        sleeps, calls = [], []
        broken, healthy = FakeSocket(fail_after=0), FakeSocket()
        header, rec = records(io.BytesIO(pcap_bytes(1)))

        def connect():
            calls.append(1)
            if len(calls) == 1:
                return broken
            if len(calls) < 8:
                raise OSError("down")
            return healthy

        def source(_stream):
            yield header
            self.wait(connected)
            yield rec

        with mock.patch.object(relay, "records", source):
            stats = relay_stream(io.BytesIO(), connect, b"{}\n",
                                 lambda msg: connected.set() if msg.startswith("connected") else None,
                                 sleeps.append)
        self.assertEqual(sleeps, [2.0, 4.0, 8.0, 16.0, 30.0, 30.0, 30.0])
        self.assertEqual(stats, {"sent": 1, "dropped": 0, "connections": 1})
        self.assertTrue(broken.closed and healthy.closed)

    def test_end_of_capture_interrupts_backoff(self):
        failed = threading.Event()
        header, rec = records(io.BytesIO(pcap_bytes(1)))

        def connect():
            raise OSError("down")

        def source(_stream):
            yield header
            self.wait(failed)
            yield rec

        start = time.monotonic()
        with mock.patch.object(relay, "records", source), mock.patch.object(relay, "BACKOFF_S", (30, 30)):
            stats = relay_stream(io.BytesIO(), connect, b"{}\n", lambda msg: failed.set())
        self.assertLess(time.monotonic() - start, 2)
        self.assertEqual(stats, {"sent": 0, "dropped": 1, "connections": 0})

    def test_a_blocked_socket_cannot_build_an_unbounded_capture_queue(self):
        connected, sending, resume = (threading.Event() for _ in range(3))
        header, *recs = records(io.BytesIO(pcap_bytes(5)))
        sock = FakeSocket()
        original_send = sock.sendall

        def send(data):
            if data == recs[0]:
                sending.set()
                self.wait(resume)
            original_send(data)

        def source(_stream):
            yield header
            self.wait(connected)
            yield recs[0]
            self.wait(sending)
            for rec in recs[1:]:
                yield rec
            resume.set()

        with mock.patch.object(relay, "records", source), mock.patch.object(sock, "sendall", send), \
                mock.patch.object(relay, "MAX_PENDING_RECORDS", 2):
            stats = relay_stream(io.BytesIO(), lambda: sock, b"{}\n", lambda msg: connected.set())
        self.assertEqual(stats, {"sent": 3, "dropped": 2, "connections": 1})
        self.assertEqual(sock.sent, b"{}\n" + header + recs[0] + recs[3] + recs[4])

    def test_records_that_waited_past_the_merge_hold_are_dropped(self):
        connected, sending, resume = (threading.Event() for _ in range(3))
        header, *recs = records(io.BytesIO(pcap_bytes(2)))
        sock = FakeSocket()
        original_send = sock.sendall
        now = [0.0]

        def send(data):
            if data == recs[0]:
                sending.set()
                self.wait(resume)
            original_send(data)

        def source(_stream):
            yield header
            self.wait(connected)
            yield recs[0]
            self.wait(sending)
            yield recs[1]
            now[0] = 1.0
            resume.set()

        with mock.patch.object(relay, "records", source), mock.patch.object(sock, "sendall", send), \
                mock.patch.object(relay.time, "monotonic", lambda: now[0]):
            stats = relay_stream(io.BytesIO(), lambda: sock, b"{}\n", lambda msg: connected.set())
        self.assertEqual(stats, {"sent": 1, "dropped": 1, "connections": 1})
        self.assertEqual(sock.sent, b"{}\n" + header + recs[0])


class RunRelayTest(unittest.TestCase):
    """`threadwatch relay` end to end: the vendored sniffer faked as
    test_record fakes it, writing a capture into the FIFO, and a listener
    on localhost standing in for the recorder."""

    def test_the_dongle_is_streamed_to_the_recorder_and_the_end_of_capture_exits_3(self):
        import contextlib
        import os
        import socket
        import tempfile
        import types

        from threadwatch.cli import main
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        d = Path(tmp.name)
        (d / "config.toml").write_text(f'[record]\ndata_dir = "{d / "data"}"\n')
        (d / "devices.json").write_text("[]")
        capture = pcap_bytes(3)
        srv = socket.create_server(("127.0.0.1", 0))
        srv.settimeout(10)
        self.addCleanup(srv.close)
        received = []

        def recorder():
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(10)
                buf = b""
                while chunk := conn.recv(65536):
                    buf += chunk
                received.append(buf)

        listener = threading.Thread(target=recorder, daemon=True)
        listener.start()
        calls, connected = [], threading.Event()

        class FakeSniffer:
            def start_threaded(self, fifo, dev, channel, metadata=None):
                calls.append(("start", dev, channel, metadata, os.path.exists(fifo)))

                def run():
                    with open(fifo, "wb") as fh:
                        fh.write(capture[:24])
                        fh.flush()
                        connected.wait(10)            # records read before the connection are dropped
                        fh.write(capture[24:])
                threading.Thread(target=run, daemon=True).start()

            def _stop(self):
                calls.append(("stop",))

        real_stream = relay.relay_stream

        def stream(fh, connect, handshake, log, sleep=None):
            def spy(msg):
                log(msg)
                if msg == "connected to the recorder":
                    connected.set()
            return real_stream(fh, connect, handshake, spy, sleep)

        module = types.ModuleType("nrf802154_sniffer")
        module.Nrf802154Sniffer = FakeSniffer
        err = io.StringIO()
        with mock.patch.dict(sys.modules, {"nrf802154_sniffer": module}), \
                mock.patch.object(sys, "path", list(sys.path)), \
                mock.patch("threadwatch.record.find_sniffers", return_value=[("/dev/fake", "0123456789ABCDEF")]), \
                mock.patch.object(relay, "relay_stream", stream), contextlib.redirect_stderr(err):
            code = main(["--config", str(d / "config.toml"), "relay", "--label", "annex",
                         "--to", f"127.0.0.1:{srv.getsockname()[1]}", "--serial-port", "/dev/fake"])
        listener.join(10)
        self.assertEqual(code, 3)
        self.assertEqual(calls, [("start", "/dev/fake", 25, "ieee802154-tap", True), ("stop",)])
        self.assertEqual(received, [handshake_line("annex", "0123456789ABCDEF", 25) + capture])
        self.assertFalse((d / "data" / "state" / "relay-annex.fifo").exists())
        self.assertIn("capturing channel 25 from /dev/fake as radio annex", err.getvalue())
        self.assertIn("after 3 frames sent, 0 dropped", err.getvalue())

    def test_ctrl_c_releases_the_vendors_consumer_thread(self):
        # The vendor's consumer is a non-daemon thread in queue.get()
        # holding the FIFO's write end, or still opening it when the
        # interrupt came first. _stop() alone left it there, and the
        # interpreter waited on it at exit until a second Ctrl-C or a kill.
        import os
        for where in ("while streaming", "before the FIFO was opened"):
            with self.subTest(where=where):
                received, sniffer, streamed, fifo, exit_event = self._interrupt(where)
                self.assertEqual([type(r) for r in received], [exit_event])
                self.assertFalse(sniffer.thread.is_alive())
                self.assertFalse(os.path.exists(fifo))
                self.assertEqual(streamed, where == "while streaming")

    def _interrupt(self, where: str):
        """run_relay with a Ctrl-C at ``where``; what the fake consumer
        received, the sniffer, whether the stream was read, the FIFO path
        and the exit sentinel's class."""
        import contextlib
        import queue
        import tempfile
        import types

        from threadwatch.config import Config
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        received, sniffers, streaming = [], [], threading.Event()

        class ExitEvent:
            pass

        class FakeSniffer:
            def start_threaded(self, fifo, dev, channel, metadata=None):
                sniffers.append(self)
                self.queue = queue.Queue()

                def consumer():                   # the vendor's: header written, then waiting for packets
                    with open(fifo, "wb") as fh:
                        fh.write(pcap_bytes(0))
                        fh.flush()
                        received.append(self.queue.get(timeout=10))
                # Daemon here only so a failure cannot hang the suite.
                self.thread = threading.Thread(target=consumer, daemon=True)
                self.thread.start()

            def _stop(self):
                pass

        def interrupted(fh, *_args):
            fh.read(24)
            streaming.set()
            raise KeyboardInterrupt

        module = types.ModuleType("nrf802154_sniffer")
        module.Nrf802154Sniffer, module.ExitEvent = FakeSniffer, ExitEvent
        cfg = Config(data_dir=Path(tmp.name) / "data")
        cut = (mock.patch.object(relay, "relay_stream", interrupted) if where == "while streaming"
               else mock.patch.object(relay, "open", side_effect=KeyboardInterrupt, create=True))
        with mock.patch.dict(sys.modules, {"nrf802154_sniffer": module}), \
                mock.patch.object(sys, "path", list(sys.path)), \
                mock.patch("threadwatch.record.find_sniffers", return_value=[]), cut, \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(KeyboardInterrupt):
            relay.run_relay(cfg, "annex", "127.0.0.1:1", serial_port="/dev/fake")
        return received, sniffers[0], streaming.is_set(), cfg.state_dir / "relay-annex.fifo", ExitEvent

    def test_a_to_without_a_port_is_refused_before_the_sniffer_starts(self):
        from threadwatch.config import Config
        with mock.patch.object(sys, "path", list(sys.path)), self.assertRaises(SystemExit) as cm:
            relay.run_relay(Config(), "annex", "recorder.local")
        self.assertIn("--to must be host:port", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
