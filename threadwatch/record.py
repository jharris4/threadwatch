"""The recorder: dongle -> ring buffer pcaps + live pipeline."""

from __future__ import annotations

import json
import os
import queue
import signal
import socket
import sys
import threading
import time
import traceback
from pathlib import Path

from . import __version__
from .alerts import HeartbeatRunner, build_heartbeats, build_sinks
from .config import Config, running_commit
from .events import EventLog, NullEventLog
from .pcap import DLT_TAP, Frame, PcapFormatError, PcapStreamReader, PcapWriter, scan_file
from .pipeline import Pipeline, load_decryptor
from .ring import ring_files, ring_name


def find_sniffers(comports=None) -> list[tuple[str, str | None]]:
    """Every nRF 802.15.4 sniffer dongle enumerated, as (port, serial),
    one entry per dongle, sorted by port. The serial is the USB one udev
    prints as ID_SERIAL_SHORT and /dev/serial/by-id embeds; it follows
    the dongle across ports and re-enumerations, which the port name does
    not. macOS lists each dongle twice, as /dev/tty.* and /dev/cu.*; the
    cu. one is kept, as it always was."""
    if comports is None:
        from serial.tools import list_ports
        comports = list_ports.comports
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vendor"))
    from nrf802154_sniffer import Nrf802154Sniffer
    by_dongle: dict[str, tuple[str, str | None]] = {}
    for port in comports():
        if port.vid != Nrf802154Sniffer.NORDICSEMI_VID or port.pid != Nrf802154Sniffer.SNIFFER_802154_PID:
            continue
        serial = port.serial_number.upper() if isinstance(port.serial_number, str) and port.serial_number else None
        device = port.device
        # One dongle, two names on macOS: keyed so they collapse, cu. winning.
        key = serial or device.replace("/tty.", "/cu.")
        if key not in by_dongle or "/cu." in device:
            by_dongle[key] = (device, serial)
    return sorted(by_dongle.values())


def find_sniffer_port(comports=None) -> str:
    """The one sniffer dongle's port, for a recorder with no [record]
    radios table. Two dongles and no table is refused rather than guessed:
    the order pyserial lists them in is not stable across restarts, and a
    recorder that came back on the other dongle would have moved its
    microphone without a word in the log."""
    found = find_sniffers(comports)
    if not found:
        raise SystemExit(
            "No nRF 802.15.4 sniffer found. Is the dongle plugged in and flashed "
            "with the sniffer firmware? (see SETUP.md; flash with bin/flash-dongle.sh)"
        )
    if len(found) > 1:
        listing = ", ".join(f"{serial or 'no serial'} at {port}" for port, serial in found)
        raise SystemExit(
            f"{len(found)} nRF 802.15.4 sniffers found ({listing}): name them in [record] radios in "
            "config.toml (one [[record.radios]] table each, by serial), or pin one with serial_port"
        )
    return found[0][0]


def resolve_radio_port(serial: str, comports=None) -> str | None:
    """The port a configured radio is on now, by its serial; None when no
    dongle with that serial is enumerated."""
    for port, found in find_sniffers(comports):
        if found == serial.upper():
            return port
    return None


class RingWriter:
    """Hourly pcap files in a ring directory, oldest pruned beyond
    keep_hours, and beyond keep_bytes of total size when that is set (a
    small SD card is a harder limit than a week).

    The byte cap is kept while the hour's file grows, not only at the
    rotation: every PRUNE_STEP bytes written the oldest closed files go
    until the ring, the open file included, is back under it. Pruned
    only at rotation, the ring sat over the cap for the rest of the
    hour, by as much as the hour brought. What remains is the open file
    itself, which is never pruned: one hour heavier than the whole cap
    exceeds it on its own (review.storage allows an hour for that)."""

    PRUNE_STEP = 4 * 1024 * 1024

    def __init__(self, ring_dir: Path, keep_hours: int, dlt: int, keep_bytes: int | None = None,
                 label: str | None = None):
        if keep_bytes is not None and keep_bytes <= 0:
            # _prune would otherwise delete every file but the current one
            # at every rotation and call it a size cap.
            raise ValueError(f"keep_bytes must be positive or None, not {keep_bytes}")
        self.ring_dir = ring_dir
        self.keep_hours = keep_hours
        self.keep_bytes = keep_bytes
        # A small cap is checked in proportion (a 64 KiB step under a few
        # MiB), a large one every few MiB: a stat of every ring file each.
        self._prune_step = max(65536, min(self.PRUNE_STEP, keep_bytes // 32)) if keep_bytes else None
        self._pruned_at = 0
        self.dlt = dlt
        # Which radio's series this is: None for the primary (the plain
        # threadwatch-YYYYMMDD-HH.pcap names), else the label suffix. Each
        # series prunes only its own files (ring.ring_files).
        self.label = label
        self.current_hour = None
        self.fh = None
        self.writer = None
        self.current_path = None
        ring_dir.mkdir(parents=True, exist_ok=True)

    def write(self, frame: Frame) -> None:
        hour = time.strftime("%Y%m%d-%H", time.localtime(frame.ts))
        if hour != self.current_hour:
            self._rotate(hour)
        self.writer.write(frame)
        # Hand each record to the OS as it is written. A snapshot (ones taken by hand
        # run in another process) copies the active file through its own
        # handle and sees only what has left this buffer: without this, the
        # packets right before a snapshot's trigger, or the whole file
        # early in the hour, were missing from the snapshot. This is a
        # write(2) per frame, not a sync: the kernel still writes the card
        # back on its own schedule.
        self.fh.flush()
        if self._prune_step is not None and self.fh.tell() - self._pruned_at >= self._prune_step:
            self._pruned_at = self.fh.tell()
            self._prune()

    def _rotate(self, hour: str) -> None:
        if self.fh:
            self.fh.close()
        self.current_hour = hour
        self.current_path = self.ring_dir / ring_name(hour, self.label)
        # Resuming an hour file after a restart: a previous run killed
        # mid-write leaves a partial record at the tail, and appending after
        # it would make every later frame unreadable. Drop the fragment.
        # A bad record in the middle of the file (a flipped byte on a
        # wearing card) is another matter: the readers step over it, and
        # cutting the file there would delete every record after it.
        # Resuming appends bare records under the existing global header,
        # so that header has to be the one this writer would have written.
        # A file whose header says another link type (an older firmware's
        # DLT, a foreign pcap dropped in under the hour's name) would take
        # our records and hand every later reader the wrong parse: a TAP
        # TLV header read as the MAC PSDU, and the RSSI and channel a
        # detector works from read out of frame bytes. A big-endian file
        # is the same problem in the record headers. Neither is written
        # into; the hour starts over, and says so.
        scan = scan_file(self.current_path) if self.current_path.exists() else None
        good = scan.good if scan else 0
        mismatch = good and (scan.dlt != self.dlt or scan.endian != "<")
        if mismatch:
            order = "big-endian" if scan.endian == ">" else "little-endian"
            print(f"[threadwatch] {self.current_path.name}: a {order} pcap of link type "
                  f"{scan.dlt}, not the {self.dlt} being recorded; starting the hour's file "
                  "over rather than appending frames it would misread", file=sys.stderr, flush=True)
            good = 0
        if good:
            size = self.current_path.stat().st_size
            if scan.skipped_bytes:
                print(f"[threadwatch] {self.current_path.name}: {scan.skipped_bytes} bytes in "
                      f"{scan.gaps} place(s) are not readable records; left in place, "
                      "readers skip them", file=sys.stderr, flush=True)
            if size > good:
                print(f"[threadwatch] {self.current_path.name}: dropping {size - good} "
                      "trailing bytes of a record cut short by the last run", file=sys.stderr, flush=True)
                with open(self.current_path, "r+b") as fh:
                    fh.truncate(good)
            self.fh = open(self.current_path, "ab")   # noqa: SIM115  (the ring writer owns this until rotation)
            self.writer = PcapWriter.__new__(PcapWriter)
            self.writer.stream = self.fh
            self.writer.dlt = self.dlt
        else:
            if self.current_path.exists() and self.current_path.stat().st_size:
                # Not a pcap this recorder can read (no usable global
                # header): nothing in it is a frame to anyone, but it is
                # not replaced in silence.
                if not mismatch:
                    print(f"[threadwatch] {self.current_path.name}: {self.current_path.stat().st_size} bytes "
                          "with no usable pcap header; starting the hour's file over", file=sys.stderr, flush=True)
            self.fh = open(self.current_path, "wb")   # noqa: SIM115  (the ring writer owns this until rotation)
            self.writer = PcapWriter(self.fh, self.dlt)
        self.fh.flush()                     # the header, so an early snapshot copies a readable pcap
        self._prune()
        self._pruned_at = self.fh.tell()

    def _prune(self) -> None:
        # The file being written is never a candidate: it does not always sort
        # last, since a clock step back names it before the ring's oldest.
        files = ring_files(self.ring_dir, self.label)
        current = self.current_path if self.current_path in files else None
        candidates = [f for f in files if f != current]
        drop = min(max(0, len(files) - self.keep_hours), len(candidates))
        if self.keep_bytes is not None:
            sizes = [f.stat().st_size if f.exists() else 0 for f in candidates]
            held = current.stat().st_size if current and current.exists() else 0
            total = sum(sizes[drop:]) + held       # only what the count cap is keeping
            floor = len(candidates) if current else len(candidates) - 1
            while total > self.keep_bytes and drop < floor:
                total -= sizes[drop]
                drop += 1
        for old in candidates[:drop]:
            old.unlink(missing_ok=True)

    def close(self) -> None:
        if self.fh:
            self.fh.close()


# How long the capture may go without a frame before the watchdog gives up
# on it: long enough to sit out a quiet channel, short enough that a dead
# dongle or a host sleep/wake costs minutes of the flight record, not more.
STALL_TIMEOUT_S = 180.0


def capture_stalled(age: float, timeout: float = STALL_TIMEOUT_S) -> bool:
    """The watchdog's decision: `age` seconds since the last frame (or since
    start-up, before any) is a stall once it passes the timeout."""
    return age > timeout


# The watchdog's exit codes, so the journal says which way the capture went.
EXIT_STALLED = 2            # no frames for STALL_TIMEOUT_S
EXIT_SNIFFER_DIED = 4       # the sniffer thread died before delivering any data
# A run that ended the way it meant to, but could not put all of it away:
# the ring would not close, the last-seen table would not save. The
# journal names the step; the status must not read as a clean stop.
EXIT_CLEANUP_FAILED = 5
# How a run ended, by its exit code, as the note it leaves for the next
# start says it (record_exit). Every other code is "exit_<code>".
EXIT_REASONS = {0: "stopped", 1: "crashed", EXIT_STALLED: "stalled", 3: "stream_ended",
                EXIT_SNIFFER_DIED: "sniffer_died", EXIT_CLEANUP_FAILED: "cleanup_failed"}
EXIT_FILE = "last-exit.json"


def record_exit(state_dir: Path, code: int, last_frame_ts: float | None = None,
                now: float | None = None) -> str | None:
    """Leave a note of how this run ended for the next start to read:
    the Pipeline announces the restart with the cause and the gap, and
    the review's coverage tells the recorder's own outage from a
    device's silence by it. Written whole and renamed into place. A run
    that never got to write one (a power cut, a SIGKILL) leaves nothing,
    which the next start reads as an end it knows nothing about, and the
    start that reads the note removes it, so it can only ever describe
    the run just before. Returns the reason written, None when the file
    could not be (a full disk must not keep the process from leaving)."""
    reason = EXIT_REASONS.get(code, f"exit_{code}")
    record = {"ts": now if now is not None else time.time(), "code": code, "reason": reason,
              "last_frame_ts": last_frame_ts}
    try:
        tmp = state_dir / "last-exit.tmp"
        tmp.write_text(json.dumps(record))
        tmp.replace(state_dir / EXIT_FILE)
    except OSError:
        return None
    return reason


def watchdog_verdict(age: float, ring_open: bool, sniffer_alive: bool) -> int | None:
    """What the watchdog does on this tick: an exit code, or None to keep
    waiting. A sniffer thread that died before the ring opened never got
    the serial port (held by a stale process, or gone after enumeration):
    left alone, the main thread sits in the FIFO open for the whole stall
    timeout behind a misleading message. With the ring open, a dead
    sniffer closes the FIFO and the main loop leaves on its own."""
    if not ring_open and not sniffer_alive:
        return EXIT_SNIFFER_DIED
    if capture_stalled(age):
        return EXIT_STALLED
    return None


# The main loop looks at the frame clock every TICK_S and runs
# Pipeline.periodic (quiet checks, link checks, the state saves, the daily
# summary) once per PERIODIC_S of it: every quiet decision and every save
# waits on this, so it is as slow as it can be and no slower.
TICK_S = 10.0
PERIODIC_S = 30


def periodic_due(last_tick: float, now: float) -> bool:
    """Whether a tick at `now` is the first inside a new PERIODIC_S period
    since the tick before it. Nothing is due on the loop's first tick
    (`last_tick` 0.0)."""
    return bool(last_tick) and int(last_tick) // PERIODIC_S != int(now) // PERIODIC_S


class Housekeeping:
    """The main loop's tick clock. Ticks are spaced by the monotonic clock,
    which a step of the host clock in either direction cannot stretch: on
    the frame clock alone, a step back of an hour held every quiet check,
    link check and state save until the wall clock had caught up with the
    last tick. Which PERIODIC_S period a tick falls in is still judged on
    the frame clock (periodic_due), the clock the pipeline is handed."""

    def __init__(self) -> None:
        self.last_tick = 0.0             # frame clock at the last tick
        self.last_mono: float | None = None

    def due(self, now: float, mono: float) -> bool:
        """Called per frame with its wall-clock stamp and the monotonic
        clock: True when Pipeline.periodic(now) should run."""
        if self.last_mono is not None and mono - self.last_mono < TICK_S:
            return False
        run = periodic_due(self.last_tick, now)
        self.last_tick, self.last_mono = now, mono
        return run


class RadioClock:
    """Keeps the radio's own packet timing, and manages the epoch offset.

    The sniffer stamps every frame from the dongle's clock and converts it
    to epoch time once, at its first packet (vendor correct_time), so the
    intervals between frames as they leave the sniffer are the intervals the
    radio heard. The recorder used to replace each stamp with time.time() at
    the moment Python got round to it, which threw those intervals away: a
    disk stall, CPU contention or a FIFO backlog -- during the very storm
    being investigated -- collapsed seconds of traffic into milliseconds,
    and the pcap kept no trace of the real timing for Wireshark or replay to
    recover. Flood periodicity, retry classification, ACK timing and poll
    cadence are all read off those intervals.

    Queue latency cannot distinguish drift from a clock jump. Only a host
    wall/monotonic discontinuity or a backwards radio timestamp can step
    the offset; ordinary disagreement is slewed at a bounded rate.
    """

    STEP_S = 2.0            # host wall/monotonic discontinuity threshold
    MAX_SLEW = 1e-3         # 1 ms per captured second; crystal drift is under 100 ppm

    def __init__(self, wall=time.time, step_s: float = STEP_S, max_slew: float = MAX_SLEW,
                 mono=time.monotonic):
        self._wall, self.step_s, self.max_slew = wall, step_s, max_slew
        self._mono = mono
        self._host_clock: tuple[float, float] | None = None
        self.offset: float | None = None
        self._last_raw: float | None = None
        self.steps = 0                       # re-anchorings this run
        self.last_step_s = 0.0               # how far the last one moved

    def stamp(self, raw_ts: float) -> float:
        """The epoch timestamp to record for a frame the sniffer stamped
        ``raw_ts``. Sets ``last_step_s`` non-zero on the frame that stepped."""
        now, mono = self._wall(), self._mono()
        previous_host = self._host_clock
        self._host_clock = (now, mono)
        self.last_step_s = 0.0
        if self.offset is None:
            self.offset = now - raw_ts       # the first frame lands at wall clock
            self._last_raw = raw_ts
            return raw_ts + self.offset
        error = now - (raw_ts + self.offset)
        host_step = (now - previous_host[0]) - (mono - previous_host[1])
        if raw_ts < self._last_raw:
            self.offset += error           # the radio restarted its timebase
            self.steps += 1
            self.last_step_s = error
        elif abs(host_step) > self.step_s:
            self.offset += host_step       # preserve any outstanding queue delay
            self.steps += 1
            self.last_step_s = host_step
        else:
            # Bounded by captured time, not by how many frames arrived: a
            # burst must not buy the correction a bigger budget.
            room = self.max_slew * max(0.0, raw_ts - self._last_raw)
            self.offset += max(-room, min(room, error))
        self._last_raw = raw_ts
        return raw_ts + self.offset


def capture_healthy(last_frame_mono: float | None, now: float,
                    timeout: float = STALL_TIMEOUT_S) -> bool | None:
    """The heartbeat's answer: unknown (None) until this run has heard a
    frame, then healthy while the last one is fresher than the stall
    timeout, so the beat stops before the watchdog exits."""
    if last_frame_mono is None:
        return None
    return now - last_frame_mono < timeout


# How long a configured radio that is missing or down waits before the
# recorder looks for its dongle again. The dongle may come back on another
# port; its serial finds it.
REATTACH_S = 60.0


class Radio:
    """One dongle of the recorder: its configuration, its vendor sniffer
    and FIFO while attached, the thread reading its stream, its clock,
    its ring series and its counters. ``label`` None is the unnamed single
    dongle of a recorder without [record] radios, on the port it was
    given; every other radio is found by serial each time it attaches.

    Attach and detach both open the dongle's port, and the vendored driver
    forks its reader process right after: a fork taken while another
    radio's port is open in this process inherits that descriptor and its
    exclusive lock, and the other radio's reader can never lock its port
    (found on 2026-09-17 with two dongles). So the two run under one lock
    for all radios, and attach waits for the fork before it returns."""

    def __init__(self, label: str | None, serial: str | None, placement: str, port: str | None,
                 fifo: Path, log, source: str = "usb", listen: str | None = None, channel: int | None = None) -> None:
        self.label, self.serial, self.placement = label, serial, placement
        self.port = port
        self.fifo = fifo
        self._owns_fifo = False
        self.log = log
        # A relay from another host (relay.py): the listener is opened once
        # and kept; each connection is one attachment, its socket the
        # token the reader's items carry, as the sniffer is for a dongle.
        self.source, self.listen, self.channel = source, listen, channel
        self.listener: socket.socket | None = None
        self.conn: socket.socket | None = None
        self.peer: str | None = None
        self.state = "missing"            # missing | up | down
        self.state_mono = 0.0
        self.sniffer = None
        self.thread: threading.Thread | None = None
        self.accept_thread: threading.Thread | None = None
        self.clock = RadioClock()
        self.writer: RingWriter | None = None
        self.dlt: int | None = None
        self.frames = 0
        self.dropped = 0                  # parse failures of sniffers that have gone
        self.last_frame_mono: float | None = None
        self.last_frame_ts: float | None = None
        self.stopped_ok = True

    @property
    def key(self) -> str:
        return self.label if self.label is not None else "radio"

    def describe(self) -> str:
        who = f"radio {self.label}" if self.label is not None else "the dongle"
        where = f" ({self.placement})" if self.placement else ""
        return f"{who}{where}"

    def attach(self, sniffer_cls, channel: int, q, lock: threading.Lock, mono: float) -> bool:
        """Find the dongle and start capturing from it. False when a radio
        named by serial is not enumerated (the single unnamed dongle's port
        was found before the run started, so it always starts here; a port
        that cannot be opened shows up as a sniffer that died). A tcp radio
        opens its listener here and is attached when its relay connects
        (adopt), so this returns False for it: missing until then."""
        if self.source == "tcp":
            self._listen(q)
            if self.state != "up":
                self.state, self.state_mono = "missing", mono
            return False
        with lock:
            if self.serial is not None:
                port = resolve_radio_port(self.serial)
                if port is None:
                    self.state, self.state_mono = "missing", mono
                    return False
                self.port = port
            self.fifo.unlink(missing_ok=True)
            os.mkfifo(self.fifo)
            self._owns_fifo = True
            self.sniffer = sniffer_cls()
            self.sniffer.start_threaded(str(self.fifo), self.port, channel, metadata="ieee802154-tap")
            self.thread = threading.Thread(target=self._read, args=(q, self.sniffer), daemon=True,
                                           name=f"radio-{self.key}")
            self.thread.start()
            # Until the vendor's reader process has forked, no other port
            # may be opened in this process (see the class docstring).
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not self._forked():
                time.sleep(0.02)
            self.state, self.state_mono = "up", mono
            self.last_frame_mono = None
            return True

    def _listen(self, q) -> None:
        """Open the tcp radio's listener once, with a thread accepting
        connections: each one's handshake is read and checked there, and
        a good one is handed to the main loop as an item to adopt."""
        if self.listener is not None:
            return
        from .relay import read_handshake
        host, _, port = self.listen.rpartition(":")
        host = host.strip("[]")
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.listener = socket.socket(family, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((host, int(port)))
        self.listener.listen(2)
        self.port = f"tcp {self.listen}"
        listener = self.listener

        def accept():
            while True:
                try:
                    conn, addr = listener.accept()
                except OSError:
                    return                        # the listener was closed: the run is over
                peer = f"{addr[0]}:{addr[1]}"
                try:
                    conn.settimeout(10.0)
                    # Unbuffered: a buffered file reads ahead past the line
                    # into the pcap stream, and the reader thread, opening
                    # its own file on the socket, then starts mid-record.
                    hs = read_handshake(conn.makefile("rb", buffering=0))
                    if hs["label"] != self.label:
                        raise ValueError(f"relay is radio {hs['label']!r}, this listener is {self.label!r}")
                    if self.channel is not None and hs["channel"] != self.channel:
                        raise ValueError(f"relay captures channel {hs['channel']}, this recorder channel "
                                         f"{self.channel}")
                    if self.serial and hs.get("serial") and hs["serial"].upper() != self.serial:
                        raise ValueError(f"relay's dongle has serial {hs['serial']}, [record] radios says "
                                         f"{self.serial}")
                    conn.settimeout(None)
                except (ValueError, OSError) as exc:
                    self.log(f"{self.describe()}: connection from {peer} refused: {exc}")
                    conn.close()
                    continue
                if self.listener is listener:
                    q.put((self.label, "connect", time.monotonic(), (conn, peer, hs)))
                else:
                    conn.close()

        self.accept_thread = threading.Thread(target=accept, daemon=True, name=f"radio-{self.key}-accept")
        self.accept_thread.start()

    def adopt(self, conn, peer: str, hs: dict, q, mono: float) -> None:
        """A relay's connection becomes this radio's stream. A connection
        already up is replaced: the relay restarted, or two are running,
        and the newer one is the one still talking."""
        if self.conn is not None:
            self._close_conn()
        self.conn, self.peer = conn, peer
        if self.serial is None and hs.get("serial"):
            self.serial = hs["serial"].upper()
        self.dlt = None
        self.thread = threading.Thread(target=self._read_socket, args=(q, conn), daemon=True,
                                       name=f"radio-{self.key}")
        self.thread.start()
        self.state, self.state_mono = "up", mono
        self.last_frame_mono = None
        self.log(f"{self.describe()}: relay connected from {peer}")

    def _read_socket(self, q, conn) -> None:
        try:
            with conn.makefile("rb") as stream:
                reader = PcapStreamReader(stream)
                self.dlt = reader.dlt
                for frame in reader:
                    q.put((self.label, frame, time.monotonic(), conn))
        except (OSError, PcapFormatError) as exc:
            self.log(f"{self.describe()}: relay stream unreadable: {exc}")
        finally:
            q.put((self.label, None, time.monotonic(), conn))

    def _close_conn(self) -> None:
        if self.conn is not None:
            try:
                self.conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                self.conn.close()
            except OSError:
                pass
        self.conn = None

    def close_listener(self) -> None:
        if self.listener is not None:
            listener, self.listener = self.listener, None
            try:
                listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            listener.close()

    def abort_start(self) -> None:
        """Unwind even a sniffer whose FIFO reader failed to start.

        _stop() kills the serial process but does not wake the vendor's
        non-daemon consumer. Give it its exit sentinel and a temporary
        FIFO peer, then bound the join; the caller exits if it stays alive.
        """
        fd = None
        try:
            if self._owns_fifo and self.fifo.exists():
                fd = os.open(self.fifo, os.O_RDWR | os.O_NONBLOCK)
            try:
                self.stop_sniffer()
            finally:
                if getattr(self.sniffer, "queue", None) is not None:
                    from nrf802154_sniffer import ExitEvent
                    self.sniffer.queue.put(ExitEvent())
                thread = getattr(self.sniffer, "thread", None)
                if thread is not None and thread.ident is not None:
                    thread.join(timeout=1.0)
        finally:
            if fd is not None:
                os.close(fd)
            try:
                if self._owns_fifo:
                    self.fifo.unlink(missing_ok=True)
                    self._owns_fifo = False
            finally:
                self.close_listener()

    def _forked(self) -> bool:
        processes = getattr(self.sniffer, "processes", None)
        if processes is None:
            return True                   # a stand-in sniffer with no process of its own
        return bool(processes) and all(p.is_alive() for p in processes)

    def _read(self, q, sniffer) -> None:
        """The reader thread: the sniffer's pcap stream, frame by frame,
        into the recorder's queue; then one end marker, whatever ended it."""
        try:
            with open(self.fifo, "rb") as fifo:
                reader = PcapStreamReader(fifo)
                self.dlt = reader.dlt
                for frame in reader:
                    q.put((self.label, frame, time.monotonic(), sniffer))
        except (OSError, PcapFormatError) as exc:
            self.log(f"{self.describe()}: capture stream unreadable: {exc}")
        finally:
            q.put((self.label, None, time.monotonic(), sniffer))

    def stop_sniffer(self) -> None:
        """The vendor's stop: the port opened once more to put the radio to
        sleep, its reader process killed. Raises what it raises. For a tcp
        radio: its connection closed, so the relay reconnects."""
        if self.source == "tcp":
            self._close_conn()
            return
        if self.sniffer is not None:
            self.sniffer._stop()

    def token(self):
        """What the reader's queue items carry to say which attachment
        they belong to: the sniffer, or the relay's connection."""
        return self.conn if self.source == "tcp" else self.sniffer

    def detach(self, lock: threading.Lock, mono: float, reason: str) -> None:
        """Stop capturing from this dongle and forget its sniffer. The
        FIFO is opened once for writing so a reader thread still waiting
        in open() sees its end, then removed."""
        if self.source == "tcp":
            self._close_conn()
            self.state, self.state_mono = "down", mono
            self.log(f"{self.describe()} detached: {reason}")
            return
        with lock:
            self.dropped += getattr(self.sniffer, "parse_failures", 0)
            try:
                self.stop_sniffer()
            except Exception as exc:  # a dongle that is gone raises on the way out
                self.log(f"{self.describe()}: sniffer stop failed: {exc}")
            try:
                fd = os.open(self.fifo, os.O_WRONLY | os.O_NONBLOCK)
                os.close(fd)
            except OSError:
                pass
            self.fifo.unlink(missing_ok=True)
            self.sniffer = None
            self.state, self.state_mono = "down", mono
            self.log(f"{self.describe()} detached: {reason}")

    def dropped_lines(self) -> int:
        return self.dropped + getattr(self.sniffer, "parse_failures", 0)

    def sniffer_alive(self) -> bool:
        if self.source == "tcp":
            # A listener waiting for its relay is alive: the relay may be
            # down for a while, and until the stall timeout that is waiting,
            # not a sniffer that died. Read as dead, a recorder with only
            # relays exited 30 s into every start with none connected, fast
            # enough for systemd's start limit to leave it failed for good.
            return any(t is not None and t.is_alive() for t in (self.thread, self.accept_thread))
        thread = getattr(self.sniffer, "thread", None)
        return bool(thread is not None and thread.is_alive())

    def status(self, mono: float, aligner_status: dict | None) -> dict:
        age = None
        if self.state == "up":
            age = round(mono - (self.last_frame_mono if self.last_frame_mono is not None else self.state_mono), 1)
        return {"label": self.label, "port": self.port, "serial": self.serial, "placement": self.placement,
                "source": self.source, "peer": self.peer if self.state == "up" else None,
                "state": self.state, "since_s": round(mono - self.state_mono, 1) if self.state_mono else None,
                "frames_total": self.frames, "last_frame_age_s": age, "last_frame_ts": self.last_frame_ts,
                "dropped_lines": self.dropped_lines(),
                "current_file": str(self.writer.current_path) if self.writer and self.writer.current_path else None,
                "lock": aligner_status}


def plan_radios(cfg: Config, log) -> list[Radio]:
    """The recorder's radios from its configuration: the [record] radios
    table, or the one unnamed dongle, on serial_port or the one sniffer
    found (two found and no table is refused here, before anything
    starts, as it always was)."""
    if not cfg.radios:
        port = cfg.serial_port or find_sniffer_port()
        return [Radio(None, None, "", port, cfg.state_dir / "capture.fifo", log)]
    return [Radio(r.label, r.serial, r.placement, None, cfg.state_dir / f"capture-{r.label}.fifo", log,
                  source=r.source, listen=r.listen, channel=cfg.channel)
            for r in cfg.radios]


def run_record(cfg: Config) -> None:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "vendor"))
    from nrf802154_sniffer import Nrf802154Sniffer

    from .merge import HOLD_S, Merger
    # Set on the way out, so the watchdog stops ticking rather than writing
    # status.json or taking an exit decision while the main thread is saving
    # state and closing files. One per run, not module state: a watchdog
    # outliving its own run must not be able to stop a later one's.
    watchdog_stop = threading.Event()

    def _log(msg: str) -> None:
        print(f"[threadwatch] {msg}", file=sys.stderr, flush=True)

    # Everything that can fail on configuration is built before any
    # sniffer starts. The vendored sniffer runs a non-daemon thread that
    # blocks until this process opens the FIFO, so an exception raised
    # after start_threaded() would leave the interpreter waiting on that
    # thread forever: a live process that systemd never restarts, holding
    # the port.
    radios = plan_radios(cfg, _log)
    by_label = {r.label: r for r in radios}
    primary = radios[0]
    # Read now, while the checkout is still the one this process imported
    # its modules from: every status write reports it (running_commit).
    _log(f"threadwatch {__version__} ({running_commit() or 'no .git and no REVISION here'})")
    sinks = build_sinks(cfg.alerts_raw, _log)
    events = EventLog(cfg.events_dir, sinks)
    for s in sinks:
        _log(f"alert sink {s.describe()} (min {['info', 'notice', 'warning', 'critical'][s.min_severity]})")
    if not sinks:
        _log("no alert sinks configured (events go to the event log only; see docs/ALERTING.md)")
    # The log's dispatcher has taken the last run's undelivered alerts
    # from the spool by now; a failure anywhere below (credentials.toml
    # unreadable, the FIFO's directory gone, the port busy) leaves before
    # the finally that closes it, so it is closed here, and the records go
    # back to the spool rather than out with the heap.
    frames_q: queue.Queue = queue.Queue()
    attach_lock = threading.Lock()
    try:
        decryptor = load_decryptor(cfg)      # raises CredentialsError: no key, no recorder
        _log("credentials: loaded")
        pipe = Pipeline(cfg, events, decryptor)
        heartbeats = build_heartbeats(cfg.heartbeats_raw, _log)
        for b in heartbeats:
            _log(f"heartbeat {b.describe()}")
        # Refuse an occupied/unavailable listener before starting any USB
        # worker. All resources still unwind below if a later attach fails.
        for r in radios:
            if r.source == "tcp":
                r._listen(frames_q)
        for r in radios:
            if r.attach(Nrf802154Sniffer, cfg.channel, frames_q, attach_lock, time.monotonic()):
                _log(f"capturing channel {cfg.channel} from {r.port}"
                     + (f" ({r.describe()})" if r.label is not None else ""))
            elif r.source == "tcp":
                _log(f"{r.describe()}: listening on {r.listen} for its relay")
            else:
                _log(f"{r.describe()}: no sniffer with serial {r.serial} is plugged in; "
                     f"starting without it and looking again every {REATTACH_S:.0f} s")
        if not any(r.state == "up" or r.source == "tcp" for r in radios):
            raise SystemExit("none of the radios in [record] radios is plugged in: "
                             + ", ".join(f"{r.label} (serial {r.serial})" for r in radios)
                             + "; check 'threadwatch doctor'")
    except BaseException:
        for r in radios:
            try:
                r.abort_start()
            except Exception as exc:
                _log(f"startup cleanup for {r.describe()} failed: {exc}")
        # A relay may have completed its handshake before startup failed.
        while not frames_q.empty():
            _label, frame, _mono, attachment = frames_q.get_nowait()
            if isinstance(frame, str) and frame == "connect":
                attachment[0].close()
        try:
            events.close()
        finally:
            if any(r.sniffer_alive() for r in radios):
                traceback.print_exc()
                _log("startup failed with a capture worker still alive; exiting for supervisor restart")
                os._exit(1)
        raise

    # Raising from the handler interrupts the blocking queue read, so
    # `systemctl stop` works even when the channel is silent. The finally
    # block below closes files. The watchdog's os._exit path flushes the
    # ring but can still leave a partial record: readers stop cleanly there
    # and RingWriter trims it before appending.
    main_pid = os.getpid()

    def _sig(_signo, _frame):
        # The sniffer forks a serial-reader child that inherits this handler
        # and wraps its read loop in a bare except: a SystemExit raised there
        # is swallowed and the child keeps the port, so systemd waits 90 s
        # and SIGKILLs. In a child, just leave.
        if os.getpid() != main_pid:
            os._exit(0)
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)

    total = 0
    started = time.time()
    started_mono = time.monotonic()
    housekeeping = Housekeeping()
    # Shared with the watchdog thread; benign races (status snapshot only).
    # last_frame is the wall clock (None until the first frame), for the
    # record; the stall clock and the heartbeat's health run on the
    # monotonic stamp beside it, which NTP stepping the host clock forward
    # after boot cannot turn into a three-hour "stall".
    beat = {"last_frame": None, "last_frame_mono": None, "total": 0, "ring": None}
    # When any run last heard a frame, carried through runs that hear
    # nothing: the next start credits the gap since then as its own
    # blindness, not the devices' silence (Pipeline._last_frame_heard).
    prior_frame = last_frame_on_record(cfg.state_dir)

    # The radios' copies become one stream here. Copies of the primary go
    # through its RadioClock as they always did; a locked radio's copies
    # are mapped into the primary's stamp domain first, so both series
    # share one epoch mapping; an unlocked radio's copies use its own.
    merger = Merger(primary.label, [r.label for r in radios], hold_s=HOLD_S,
                    epoch=lambda label, raw: raw + (by_label[label].clock.offset or 0.0),
                    stamp=lambda label, raw: by_label[label].clock.stamp(raw))
    # What the pipeline may ask about the radios (per-radio blindness).
    for r in radios:
        pipe.radio_changed(r.label, r.state, time.time())

    def _radio_event(r: Radio, event: str, severity: str, note: str) -> None:
        pipe.radio_changed(r.label, r.state, time.time())
        try:
            events.emit(event, severity, radio=r.label, serial=r.serial, port=r.port, placement=r.placement,
                        note=note)
        except Exception as exc:  # a full disk must not take the capture with it
            _log(f"{event} not logged: {exc}")

    for r in radios:
        if r.state == "missing":
            _radio_event(r, "radio_missing", "notice",
                         f"{r.describe()}: waiting for its relay to connect to {r.listen}" if r.source == "tcp"
                         else f"{r.describe()}: no sniffer with serial {r.serial} is plugged in; the recorder "
                              f"runs without it and looks again every {REATTACH_S:.0f} s")

    def _supervise(mono: float) -> None:
        """The watchdog's per-radio work, with more than one radio: a radio
        that stalled while another hears is detached and reported, not the
        whole run restarted; a radio missing or down is looked for again.
        With one radio the whole-run verdicts below are the supervision."""
        if len(radios) < 2:
            return
        hearing = [r for r in radios if r.state == "up" and r.last_frame_mono is not None
                   and not capture_stalled(mono - r.last_frame_mono)]
        for r in radios:
            if r.state == "up" and hearing and r not in hearing:
                age = mono - (r.last_frame_mono if r.last_frame_mono is not None else r.state_mono)
                dead = not r.sniffer_alive() and r.last_frame_mono is None
                if capture_stalled(age) or dead:
                    why = ("its sniffer died before delivering a frame (port busy or gone?)" if dead
                           else f"no frames for {age:.0f} s while {', '.join(h.describe() for h in hearing)} hears")
                    r.detach(attach_lock, mono, why)
                    merger.end(r.label)
                    _radio_event(r, "radio_lost", "warning",
                                 f"{r.describe()} stopped delivering: {why}; the recorder carries on with the "
                                 f"rest and looks for it every {REATTACH_S:.0f} s")
        for r in radios:
            if r.source == "tcp":
                continue                                     # its relay reconnects by itself
            if r.state in ("missing", "down") and mono - r.state_mono >= REATTACH_S:
                was = r.state
                if r.attach(Nrf802154Sniffer, cfg.channel, frames_q, attach_lock, mono):
                    _log(f"capturing channel {cfg.channel} from {r.port} ({r.describe()})")
                    _radio_event(r, "radio_returned" if was == "down" else "radio_attached", "info",
                                 f"{r.describe()} is capturing again from {r.port}" if was == "down"
                                 else f"{r.describe()} found at {r.port} and capturing")
                else:
                    r.state_mono = mono                      # look again in REATTACH_S

    def _watchdog():
        # The main loop blocks reading the queue, so a stalled stream (host
        # sleep/wake, dongle unplug, sniffer process death) looks alive
        # forever without this. Exit non-zero so a supervisor restarts us.
        # Also keeps status.json fresh when the channel is merely quiet.
        while True:
            time.sleep(30)
            if watchdog_stop.is_set():
                return          # shutting down: the main thread owns the state now
            mono = time.monotonic()
            age = status_tick(cfg, primary.port, beat, started, started_mono, pipe, decryptor, prior_frame, _log,
                              radios=radios, merger=merger)
            try:
                _supervise(mono)
            except Exception as exc:  # supervision must not take the watchdog down
                _log(f"radio supervision failed: {exc}")
            verdict = watchdog_verdict(age, ring_open=beat["ring"] is not None,
                                       sniffer_alive=any(r.sniffer_alive() for r in radios))
            if verdict == EXIT_SNIFFER_DIED:
                _log("sniffer thread died before delivering any data (serial port busy or gone? "
                     "see the traceback above); exiting for supervisor restart")
                record_exit(cfg.state_dir, EXIT_SNIFFER_DIED, beat["last_frame"] or prior_frame)
                events.close()      # the start-up quiet announcements, if any
                os._exit(EXIT_SNIFFER_DIED)
            if verdict == EXIT_STALLED:
                _log(f"no frames for {age:.0f}s - capture stalled (host slept? "
                     "dongle gone?); exiting for supervisor restart")
                # The main thread is blocked in the queue read, so nothing is
                # being written: keep the last frames and what they taught us,
                # deliver the alerts still queued or held for a digest, and
                # take the sniffers' children (which hold the ports) with us.
                # Each step is allowed to fail without taking the rest
                # with it, but never in silence: the whole point of the
                # ladder is that what it saved is what the next run reads.
                def flush_rings():
                    for r in radios:
                        if r.writer and r.writer.fh:
                            r.writer.fh.flush()

                def stop_sniffers():
                    for r in radios:
                        r.stop_sniffer()

                for what, step in (("ring flush", flush_rings),
                                   ("last-seen save", pipe.seen.save),
                                   ("key journal save", lambda: pipe.journal.save(force=True)),
                                   ("exit note", lambda: record_exit(cfg.state_dir, EXIT_STALLED,
                                                                     beat["last_frame"] or prior_frame)),
                                   ("alert delivery", events.close),
                                   ("sniffer stop", stop_sniffers)):
                    try:
                        step()
                    except Exception as exc:
                        _log(f"stalled exit: {what} failed: {exc}")
                os._exit(EXIT_STALLED)

    threading.Thread(target=_watchdog, daemon=True, name="watchdog").start()

    # Liveness heartbeats: "healthy" means frames are still flowing, and
    # unknown (nothing sent) until this run has heard its first frame, so a
    # restart loop that never hears one cannot keep a monitor reassured.
    # Once the stall timeout passes the watchdog exits anyway.
    HeartbeatRunner(heartbeats,
                    healthy=lambda: capture_healthy(beat["last_frame_mono"], time.monotonic()),
                    log=_log)

    def _take(out: Frame) -> None:
        """One merged frame: every radio's copy into that radio's ring
        series, the frame itself into the pipeline."""
        nonlocal total
        for label, copy in out.heard.items():
            r = by_label[label]
            if r.writer is None:
                # One series per radio, the count cap per series and the
                # byte cap shared out between them.
                share = cfg.keep_bytes // len(radios) if cfg.keep_bytes else None
                r.writer = RingWriter(cfg.ring_dir, cfg.keep_hours, r.dlt, share,
                                      label=None if r is primary else r.label)
                if r is primary or beat["ring"] is None:
                    beat["ring"] = r.writer
            r.writer.write(copy)
            pipe._journal_files[label] = r.writer.current_path
            r.last_frame_ts = copy.ts
        for r in radios:
            if r.clock.last_step_s:
                _log(f"capture clock re-anchored by {r.clock.last_step_s:+.3f} s "
                     "(sniffer restarted, or the host clock stepped)")
                r.clock.last_step_s = 0.0
        pipe.ingest(out)
        total += 1
        beat["last_frame"] = out.ts
        beat["last_frame_mono"] = time.monotonic()
        beat["total"] = total
        if housekeeping.due(out.ts, beat["last_frame_mono"]):
            pipe.periodic(out.ts)

    # Exit status: 0 for a requested stop, otherwise non-zero so the journal
    # and the supervisor see a failure, and the traceback is printed here
    # because the os._exit in finally would otherwise swallow it.
    exit_code = 0
    streams = {}                         # attachment tokens, owned by the capture loop
    try:
        while True:
            # Copies waiting for another radio's are released on the next
            # arrival, or by their age: on a quiet channel that is this
            # timeout, not the next frame.
            try:
                label, frame, mono, sniffer = frames_q.get(timeout=HOLD_S if merger.pending() else TICK_S)
            except queue.Empty:
                for out in merger.release(time.monotonic()):
                    _take(out)
                continue
            r = by_label[label]
            if isinstance(frame, str) and frame == "connect":
                # A relay connected: this radio's stream, from now.
                conn, peer, hs = sniffer
                was = r.state
                r.adopt(conn, peer, hs, frames_q, mono)
                _radio_event(r, "radio_returned" if was == "down" else "radio_attached", "info",
                             f"{r.describe()}: relay connected from {peer}" + (
                                 f" (dongle serial {hs['serial']})" if hs.get("serial") else ""))
                continue
            if r.token() is not sniffer:
                continue                      # an end marker of a sniffer already detached
            if frame is None:
                # The sniffer closed its end of the FIFO: dongle unplugged or
                # the sniffer process died. With another radio still up, that
                # radio goes on; alone, not a clean stop.
                r.detach(attach_lock, mono, "capture stream ended")
                merger.end(label)
                for out in merger.release(mono):
                    _take(out)
                # A relay's radio counts as present only while its relay is
                # connected: with every radio down the run ends and the
                # supervisor restarts it, listener and all, and the relay
                # reconnects with its own backoff.
                if any(x.state == "up" for x in radios):
                    _radio_event(r, "radio_lost", "warning",
                                 f"{r.describe()} closed its capture stream ("
                                 + ("relay disconnected; it reconnects by itself" if r.source == "tcp" else
                                    f"dongle unplugged? sniffer died?); the recorder carries on with the rest "
                                    f"and looks for it every {REATTACH_S:.0f} s"))
                    continue
                _log("capture stream ended (dongle unplugged? sniffer died?); exiting for supervisor restart")
                exit_code = 3
                break
            if streams.get(label) is not sniffer:
                # Drain with the old clocks before replacing them. USB
                # reattachment runs on the watchdog; domain changes belong
                # here, in queue order, just like a relay's first frame.
                if label in streams:
                    merger.reset(label)
                    for out in merger.release(mono):
                        _take(out)
                r.clock = RadioClock()
                streams[label] = sniffer
            r.frames += 1
            r.last_frame_mono = mono
            if r.writer is None and r.dlt is None:
                r.dlt = DLT_TAP
            merger.push(label, frame, mono)
            for out in merger.release(mono):
                _take(out)
    except SystemExit as exc:
        exit_code = exc.code if isinstance(exc.code, int) else 0
    except BaseException:
        traceback.print_exc()
        _log("recorder crashed; exiting for supervisor restart")
        exit_code = 1
    finally:
        # A second Ctrl-C here (or a SIGTERM racing a Ctrl-C) would raise
        # SystemExit out of this block, skip the os._exit below, and leave
        # the interpreter hanging on the sniffer's non-daemon thread until
        # a kill -9. Everything below is quick: hold the signals until it
        # is done. (The sniffer's children keep their own handler.)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            # Each step may fail without taking the rest with it, as the
            # stalled exit above does it. A full disk out of ring.close()
            # used to propagate from here: no alerts drained or spooled,
            # no exit note, the FIFO left behind, and no os._exit - with
            # both signals ignored by then and the sniffer's non-daemon
            # thread still alive, which is a recorder nothing can stop.
            def cleanup(what, step) -> bool:
                try:
                    step()
                    return False
                except Exception as exc:
                    _log(f"exit: {what} failed: {exc}")
                    return True

            def stop_sniffers():
                failed = []
                for r in radios:
                    try:
                        r.stop_sniffer()
                    except Exception as exc:
                        failed.append(f"{r.describe()}: {exc}")
                if failed:
                    raise RuntimeError("; ".join(failed))

            def close_rings():
                failed = []
                for r in radios:
                    if r.writer:
                        try:
                            r.writer.close()
                        except Exception as exc:
                            failed.append(f"{r.describe()}: {exc}")
                if failed:
                    raise RuntimeError("; ".join(failed))

            def remove_fifos():
                for r in radios:
                    r.fifo.unlink(missing_ok=True)
                    r.close_listener()

            # What the merger still holds goes into the rings and the
            # pipeline before the rings close: the last quarter second.
            cleanup("merger flush", lambda: [_take(out) for out in merger.release(flush=True)])
            lost = cleanup("sniffer stop", stop_sniffers)
            watchdog_stop.set()
            lost |= cleanup("last-seen save", pipe.seen.save)
            lost |= cleanup("key journal save", lambda: pipe.journal.save(force=True))
            lost |= cleanup("ring close", close_rings)
            lost |= cleanup("FIFO cleanup", remove_fifos)
            if lost and exit_code == 0:
                # Something of this run did not land. The journal says
                # which step; the status must not read as a clean stop,
                # and the note the next start reads says so too.
                exit_code = EXIT_CLEANUP_FAILED
            cleanup("exit note", lambda: record_exit(cfg.state_dir, exit_code,
                                                     beat["last_frame"] or prior_frame))
            # os._exit skips thread joins: the alert thread's queue and the
            # digests its cooldowns hold would go with it.
            cleanup("alert delivery", events.close)
            _log(f"stopped after {total} frames")
        finally:
            # The vendored sniffer starts a non-daemon thread and worker
            # processes that outlive _stop(); everything of ours is closed
            # and saved by now, so end the process outright rather than
            # hang - whatever happened above.
            os._exit(exit_code)


def status_tick(cfg, port, beat: dict, started: float, started_mono: float, pipe: Pipeline,
                decryptor, prior_frame: float | None, log, sniffer=None, radios=None, merger=None) -> float:
    """One watchdog tick: refresh status.json once the ring is open, and
    return the stall clock's reading (seconds since this run's last frame,
    or since it started). The file's last_frame_ts is when a frame was
    last heard by any run: this run's, else the stamp the previous run's
    status.json carried (prior_frame), else None. Never the time now: a
    stalled recorder reports a stale frame, which is the fact a reader of
    the file needs."""
    mono = time.monotonic()
    age = mono - (beat["last_frame_mono"] or started_mono)
    if beat["ring"] is not None:
        dropped = getattr(sniffer, "parse_failures", 0)
        radios_status = merge_status = None
        if radios:
            dropped = sum(r.dropped_lines() for r in radios)
            aligners = merger.aligners if merger is not None else {}
            radios_status = {r.key: r.status(mono, aligners[r.label].status() if r.label in aligners else None)
                             for r in radios}
            if merger is not None:
                st = merger.status()
                merge_status = {"merged": st["merged"], "duplicates": st["duplicates"], "pending": st["pending"]}
        try:
            _write_status(cfg, port, beat["total"], started, pipe, beat["ring"], decryptor,
                          last_frame_age=age, last_frame_ts=beat["last_frame"] or prior_frame,
                          dropped_lines=dropped, radios=radios_status, merge=merge_status)
        except Exception as exc:   # a full disk must not take the stall check with it
            log(f"status.json not written: {exc}")
    return age


def last_frame_on_record(state_dir: Path) -> float | None:
    """When the recorder last heard a frame, as the status.json of a
    previous run recorded it; None when no run has heard one."""
    try:
        st = json.loads((state_dir / "status.json").read_text())
        if not isinstance(st, dict):
            return None             # valid JSON of another shape: a list has no .get
        return float(st["last_frame_ts"]) if st.get("last_frame_ts") is not None else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


def _write_status(cfg, port, total, started, pipe: Pipeline, ring, decryptor,
                  last_frame_age: float = 0.0, last_frame_ts: float | None = None,
                  dropped_lines: int = 0, radios: dict | None = None, merge: dict | None = None) -> None:
    # last_frame_age_s is this run's view (the watchdog's stall clock);
    # last_frame_ts is the wall-clock time of the last frame any run heard,
    # which does not move while nothing is heard.
    status = {
        "updated": time.time(),
        # Which code is recording: a restart that did not happen, or a
        # deploy that did not land, is invisible in everything else here.
        # The revision this process started on, not the checkout's now: a
        # git pull under a running recorder used to make every status
        # write claim the new commit while the old code was still running.
        "version": __version__,
        "commit": running_commit(),
        "last_frame_age_s": round(last_frame_age, 1),
        "last_frame_ts": last_frame_ts,
        "port": port,
        "channel": cfg.channel,
        "frames_total": total,
        # Serial lines the sniffer could not parse: frames the dongle sent
        # and nothing recorded. Steadily climbing means a cable or a
        # baud-rate problem, not a quiet mesh.
        "dropped_lines": dropped_lines,
        "uptime_s": round(time.time() - started, 1),
        # None until the first frame opens an hour file: a tick in the
        # first 30 s of a silent channel used to write the string "None".
        "current_file": str(ring.current_path) if ring.current_path else None,
        "devices_tracked": len(pipe.devices),
        # The PAN the recorder judges by (configured, or adopted with the
        # pipeline's floor and hysteresis): the report and the pages read
        # it here, so "quiet" and "foreign" mean the same thing everywhere.
        "dominant_pan": pipe.dominant_pan(),
        "partition": pipe.partition_status(),
        "detector": pipe.detector.snapshot(),
        "alerts": pipe.events.dispatcher.stats(),
        # The highest key generation heard, from whom and when (the
        # status page reads it; crypto.key_sequence below is the
        # decryptor's own, which a straggler frame can also raise).
        "keys": pipe.keys_status(),
        # With [ha_logs] archive on: per add-on the last hour archived, the
        # hours pending and lost; null otherwise.
        "ha_logs_archive": pipe.ha_logs_archive_status(),
        "otbr_inventory": pipe.otbr_inventory_status(),
        # With [ha_availability] on: HA reachability, the last poll and
        # the open episodes; null otherwise.
        "ha_availability": pipe.ha_availability_status(),
        # Every radio by label ("radio" for the unnamed single dongle):
        # its port, serial, placement, state (up, down, missing), frames,
        # last-frame age, its own current ring file, and for every radio
        # but the primary the merger's lock on its clock (offset, drift,
        # jitter). None from a writer that has no radios to report.
        "radios": radios,
        # The merger's totals this run: frames handed to the pipeline,
        # copies folded into another radio's frame, copies waiting. With
        # two radios, merged is between the larger radio's frames_total
        # and the two added together; duplicates is what they both heard.
        "merge": merge,
    }
    status["crypto"] = {**decryptor.stats, "key_sequence": decryptor.key_sequence}
    tmp = cfg.state_dir / "status.tmp"
    tmp.write_text(json.dumps(status, indent=1))
    tmp.replace(cfg.state_dir / "status.json")


def replay_files(paths: list[Path]) -> list[Path]:
    """The pcaps a replay reads, in order: a file as given, a directory
    (a snapshot, or the ring) as every pcap in it by name, which for
    ring files is by hour. Nothing to read is an error, not an empty run."""
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            found = sorted(p.glob("*.pcap"))
            if not found:
                raise SystemExit(f"threadwatch replay: no pcap files in {p}")
            out.extend(found)
        else:
            out.append(p)
    if not out:
        raise SystemExit("threadwatch replay: nothing to read")
    return out


def run_replay(cfg: Config, pcap_path: Path | list[Path], *, journal=None, output=True) -> dict:
    """Run the full pipeline over existing pcaps, one file or several in
    order (a directory is every pcap in it), as one run: a silence or a
    storm that spans two hourly files is judged once, across the
    boundary, as the recorder judged it. Prints events + summary."""
    from contextlib import ExitStack

    from .merge import merge_readers
    from .ring import group_files
    files = replay_files(pcap_path if isinstance(pcap_path, list) else [pcap_path])
    events = NullEventLog()
    decryptor = load_decryptor(cfg)
    print("[threadwatch] credentials: loaded", file=sys.stderr, flush=True)   # stdout is the JSON
    pipe = Pipeline(cfg, events, decryptor, ephemeral=True)
    if journal is not None:
        pipe.journal = journal
    pipe.detector.cfg.alert_cooldown_s = 0
    total = 0
    first = last = None
    # The housekeeping the live loop runs on the frame clock (quiet checks,
    # link assessment) runs here on the packets' own clock at the same
    # cadence: a silence that ends before EOF, or a drop that holds and
    # then recovers, is only found by looking between the frames, not
    # once at the end.
    last_tick = 0.0
    # An hour recorded by several radios is several files, read together:
    # what the recorder judged once is judged once here too (merge.py).
    for group in group_files(files):
        pipe._journal_files = group
        try:
            with ExitStack() as stack:
                readers = {label: PcapStreamReader(stack.enter_context(open(path, "rb")))
                           for label, path in group.items()}
                for frame in merge_readers(readers, primary=None if None in readers else next(iter(readers))):
                    if first is None:
                        first = frame.ts
                    last = frame.ts
                    pipe.ingest(frame)
                    total += 1
                    now = frame.ts
                    if now < last_tick:
                        last_tick = now       # stamps stepped back: keep ticking from here
                    if now - last_tick >= TICK_S:
                        if periodic_due(last_tick, now):
                            pipe.periodic(now)
                        last_tick = now
                for label, reader in readers.items():
                    path = group[label]
                    if reader.skipped_bytes:
                        print(f"[threadwatch] {path}: skipped {reader.skipped_bytes} bytes in {reader.gaps} "
                              "place(s) that are not readable records", file=sys.stderr, flush=True)
                    if reader.tail_bytes:
                        print(f"[threadwatch] {path}: the last {reader.tail_bytes} bytes hold no readable "
                              "record and were not read", file=sys.stderr, flush=True)
        except (OSError, PcapFormatError) as exc:
            # A path that does not exist, cannot be read, or is not a pcap:
            # one line and exit 1 (as `device` does), not a traceback and not a
            # zero-frame JSON that reads as a quiet capture.
            path = getattr(exc, "filename", None) or ", ".join(str(p) for p in group.values())
            raise SystemExit(f"threadwatch replay: could not read {path}: {exc}") from None
    if last:
        pipe.periodic(last, final=True)
    out = {
        "file": str(files[0]) if len(files) == 1 else None,
        "files": [str(f) for f in files],
        "frames": total,
        "duration_s": round(last - first, 1) if first else 0,
        "partition": pipe.partition_status(),
        "detector": pipe.detector.snapshot(),
        "events": events.records,
    }
    out["crypto"] = {**decryptor.stats, "key_sequence": decryptor.key_sequence}
    if journal is not None:
        out["key_journal"] = journal.report()
    if output:
        print(json.dumps(out, indent=1))
    return out
