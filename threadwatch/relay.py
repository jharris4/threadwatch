"""A dongle on another host: `threadwatch relay` streams what it hears.

The recorder takes each radio as a stream of pcap records read by a
thread (record.Radio). A dongle on another host is the same stream over
TCP: this end runs the vendored sniffer exactly as the recorder does,
reads the FIFO it writes, and copies the records to the recorder, which
listens on the address of the matching `[[record.radios]]` entry
(source = "tcp", listen = "host:port"). Every connection starts with one
JSON line (the handshake: label, serial, channel, version) and the pcap
global header, then records; a dropped connection is retried with
backoff, and the records read while there was none are dropped and
counted, since the recorder cannot use what it did not hear when it
happened. Alignment and merging happen at the recorder and do not care
where the bytes came from: the stamps are the dongle's own.

Nothing here authenticates. The stream is 802.15.4 frames as captured,
encrypted on air and without the key, plus their timing; keep the
listener on a LAN address, firewalled, or carry it over an ssh tunnel.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import threading
import time
from collections import deque
from pathlib import Path
from typing import BinaryIO, Callable

from . import __version__

HANDSHAKE_VERSION = 1
BACKOFF_S = (2.0, 30.0)          # first retry, and the most between retries
CONNECT_TIMEOUT_S = 10.0
MAX_PENDING_RECORDS = 256
MAX_PENDING_AGE_S = 0.25


def handshake_line(label: str, serial: str | None, channel: int) -> bytes:
    return (json.dumps({"threadwatch_relay": HANDSHAKE_VERSION, "label": label, "serial": serial,
                        "channel": channel, "version": __version__}) + "\n").encode()


def read_handshake(fh: BinaryIO) -> dict:
    """The first line of a connection, or a ValueError saying what is
    wrong with it: the recorder closes such a connection and logs why."""
    line = fh.readline(4096)
    if not line.endswith(b"\n"):
        raise ValueError("no handshake line (not a threadwatch relay?)")
    try:
        hs = json.loads(line)
    except ValueError:
        raise ValueError("handshake is not JSON (not a threadwatch relay?)") from None
    if not isinstance(hs, dict) or hs.get("threadwatch_relay") != HANDSHAKE_VERSION:
        raise ValueError(f"handshake version {hs.get('threadwatch_relay') if isinstance(hs, dict) else '?'}, "
                         f"this recorder speaks {HANDSHAKE_VERSION}")
    for key, kind in (("label", str), ("channel", int)):
        if not isinstance(hs.get(key), kind):
            raise ValueError(f"handshake without a {key}")
    if hs.get("serial") is not None and not isinstance(hs["serial"], str):
        raise ValueError("handshake serial is not text")
    return hs


def records(stream: BinaryIO):
    """The pcap global header, then each record whole (header and data),
    from a pcap byte stream; ends at EOF or a record cut short."""
    header = _exact(stream, 24)
    if len(header) < 24:
        return
    yield header
    while True:
        rec = _exact(stream, 16)
        if len(rec) < 16:
            return
        incl = struct.unpack("<L", rec[8:12])[0]
        data = _exact(stream, incl)
        if len(data) < incl:
            return
        yield rec + data


def _exact(stream: BinaryIO, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def relay_stream(stream: BinaryIO, connect: Callable[[], socket.socket], handshake: bytes, log,
                 sleep: Callable[[float], None] | None = None) -> dict:
    """Drain capture independently of connection attempts and socket writes.

    Disconnected records are counted and discarded immediately. The small
    connected queue also has an age limit: a slow network must not build a
    backlog that is replayed after the recorder has released its copies.
    """
    stats = {"sent": 0, "dropped": 0, "connections": 0}
    it = records(stream)
    header = next(it, None)
    if header is None:
        return stats
    pending: deque = deque()
    changed = threading.Condition()
    done = threading.Event()
    ready = False
    errors = []

    def sender():
        nonlocal ready
        sock = None
        delay = BACKOFF_S[0]
        reported_drops = 0
        try:
            while True:
                with changed:
                    if done.is_set() and not pending:
                        break
                try:
                    if sock is None:
                        sock = connect()
                        sock.sendall(handshake + header)
                        with changed:
                            ready = True
                            stats["connections"] += 1
                            dropped = stats["dropped"] - reported_drops
                            reported_drops = stats["dropped"]
                        delay = BACKOFF_S[0]
                        log(f"reconnected; {dropped} frames were dropped while disconnected"
                            if dropped else "connected to the recorder")
                    with changed:
                        changed.wait_for(lambda: pending or done.is_set())
                        if not pending:
                            break
                        captured, rec = pending.popleft()
                        if time.monotonic() - captured > MAX_PENDING_AGE_S:
                            stats["dropped"] += 1
                            continue
                    try:
                        sock.sendall(rec)
                    except OSError:
                        with changed:
                            stats["dropped"] += 1
                        raise
                    with changed:
                        stats["sent"] += 1
                except OSError as exc:
                    with changed:
                        ready = False
                        stats["dropped"] += len(pending)
                        pending.clear()
                    if sock is not None:
                        sock.close()
                        sock = None
                    log(f"cannot reach the recorder ({exc}); retrying, dropping frames meanwhile")
                    # Production waits are interruptible when capture ends.
                    (sleep or done.wait)(delay)
                    delay = min(BACKOFF_S[1], delay * 2)
        except BaseException as exc:
            errors.append(exc)
        finally:
            with changed:
                ready = False
                stats["dropped"] += len(pending)
                pending.clear()
            if sock is not None:
                sock.close()

    worker = threading.Thread(target=sender, daemon=True, name="relay-sender")
    worker.start()
    try:
        for rec in it:
            with changed:
                if not ready:
                    stats["dropped"] += 1
                else:
                    if len(pending) >= MAX_PENDING_RECORDS:
                        pending.popleft()
                        stats["dropped"] += 1
                    pending.append((time.monotonic(), rec))
                    changed.notify()
    finally:
        done.set()
        with changed:
            changed.notify()
        # connect() and sendall() use CONNECT_TIMEOUT_S on real sockets.
        worker.join()
    if errors:
        raise errors[0]
    return stats


def run_relay(cfg, label: str, to: str, serial_port: str | None = None) -> int:
    """Run the sniffer on this host's dongle and stream it to the recorder
    at ``to`` (host:port) as radio ``label``. Returns 3 when the capture
    stream ends (dongle unplugged, sniffer died), for a supervisor to
    restart; runs until then."""
    from .record import find_sniffer_port, find_sniffers

    def _log(msg: str) -> None:
        print(f"[threadwatch relay] {msg}", file=sys.stderr, flush=True)

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vendor"))
    from nrf802154_sniffer import Nrf802154Sniffer
    host, _, port = to.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit(f"threadwatch relay: --to must be host:port, not {to!r}")
    port_name = serial_port or cfg.serial_port or find_sniffer_port()
    serial = next((s for p, s in find_sniffers() if p == port_name), None)
    cfg.state_dir.mkdir(parents=True, exist_ok=True)
    fifo = cfg.state_dir / f"relay-{label}.fifo"
    fifo.unlink(missing_ok=True)
    os.mkfifo(fifo)
    sniffer = Nrf802154Sniffer()
    sniffer.start_threaded(str(fifo), port_name, cfg.channel, metadata="ieee802154-tap")
    _log(f"capturing channel {cfg.channel} from {port_name} as radio {label}, for {host}:{port}")

    def connect() -> socket.socket:
        return socket.create_connection((host.strip("[]"), int(port)), timeout=CONNECT_TIMEOUT_S)

    try:
        with open(fifo, "rb") as stream:
            stats = relay_stream(stream, connect, handshake_line(label, serial, cfg.channel), _log)
    finally:
        try:
            sniffer._stop()
        except Exception as exc:
            _log(f"sniffer stop failed: {exc}")
        fifo.unlink(missing_ok=True)
    _log(f"capture stream ended (dongle unplugged? sniffer died?) after {stats['sent']} frames sent, "
         f"{stats['dropped']} dropped")
    return 3
