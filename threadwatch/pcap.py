"""Classic pcap stream reading/writing and minimal 802.15.4 parsing.

Supports the two link types the Nordic nRF 802.15.4 sniffer emits:
DLT 283 (IEEE802_15_4_TAP, carries RSSI/LQI/channel TLVs) and
DLT 230 (IEEE802_15_4_NOFCS). Stdlib only.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

DLT_TAP = 283
DLT_NOFCS = 230
DLT_WITHFCS = 195       # IEEE802_15_4_WITHFCS: every frame ends in a 2-byte FCS
# TAP TLV 0 (FCS type) says whether a frame ends in one: 1 is CRC-16 (two
# bytes), 2 CRC-32 (four). The vendored sniffer strips the FCS and writes
# no such TLV; a capture from another tool may carry it.
_TAP_FCS_LEN = {1: 2, 2: 4}

PCAP_MAGIC_LE_US = 0xA1B2C3D4  # microsecond timestamps, little-endian file
# Match the writer's snapshot limit, independently of untrusted file headers.
MAX_RECORD_BYTES = 0xFFFF


class PcapFormatError(Exception):
    pass


# The destination PAN of a frame addressed to every network on the channel
# (a parent request, an announce, a beacon request). With PAN-ID
# compression it reads back as the source PAN too, and says nothing about
# which network the sender belongs to.
BROADCAST_PAN = 0xffff


@dataclass
class Frame:
    ts: float                 # epoch seconds (float)
    raw: bytes                # bytes as captured (including TAP header if DLT 283)
    psdu: bytes               # 802.15.4 PHY payload (MAC frame)
    rssi: float | None     # dBm, TAP only
    channel: int | None    # TAP only
    lqi: int | None        # TAP only
    # MAC header fields (None when not present / not parseable)
    ftype: int | None = None      # 0 beacon, 1 data, 2 ack, 3 command
    seq: int | None = None
    dst_pan: int | None = None
    dst: str | None = None        # hex string, 4 chars (short) or 16 (extended)
    src_pan: int | None = None
    src: str | None = None
    cmd: int | None = None        # MAC command id, unsecured command frames only


def _read_exact(stream: BinaryIO, n: int) -> bytes:
    """Read n bytes; fewer only at EOF (a truncated tail record)."""
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _record_is_plausible(incl: int, snaplen: int) -> bool:
    """A record header a writer of ours could have produced. Sixteen NUL
    bytes unpack to a well-formed header of a zero-length record, and a
    power cut on ext4 leaves exactly that: a tail the file system had
    extended but never written. Every frame the sniffer emits has at least
    a TAP or MAC header, so a zero length is the end of the good data, and
    so is a length past the file's own snaplen."""
    return 0 < incl <= min(snaplen or MAX_RECORD_BYTES, MAX_RECORD_BYTES)


# How far back and forward a record's stamp may sit from the one before
# it and still be believed - when a header has to earn belief, which is
# only where one is being looked for rather than read at the offset the
# record before it ended at (see _Records). A ring file holds an hour and
# its stamps are the host clock; a capture given to `device` or `replay`
# may hold days.
_STAMP_BACK_S = 86400
_STAMP_AHEAD_S = 7 * 86400


class _Records:
    """Walk the records of a pcap stream, past whatever a crash or a bad
    block left in it.

    A record header the writer could not have produced is the end of the
    data when it is the tail (a run of NULs from a power cut, garbage the
    file system left) and one bad record when it is not (a flipped byte
    on a card that is wearing out). The two look the same from the header
    alone, so both are treated the same way: scan forward for the next
    header that could be a record, and take it once the header after it
    agrees. A tail yields nothing more and the walk ends there; a bad
    record in the middle costs that record and the walk goes on. What was
    skipped is counted, so no reader answers for a file as if it had read
    all of it.

    A file's headers are held to more than the snaplen bound: a length
    within the original length, a whole number of microseconds, since a
    flipped bit that leaves a length within the snaplen would otherwise
    swallow the records that follow as one frame's payload. A FIFO is not
    read ahead of the frame in hand, or the recorder would hand frames on
    late, so the sniffer's stream is taken on the snaplen bound alone, as
    it always was.

    The stamp test is evidence for a header nothing else vouches for -
    one found by scanning - and is not applied to a header sitting exactly
    where the record before it ended. Applied there, it discarded valid
    data: two records a week apart, which a filtered or concatenated
    capture legitimately holds, ended the read at the first of them, and
    the rest of the file was taken for a tail and not even counted.

    good is the offset just past the last record read whole: what a writer
    resuming the file may append at, and what the reader has left out (a
    record cut short by a crash, a tail of NULs, records no scan could
    recover) begins there. tail_bytes is how much that is, so a reader
    that answers for a file can say it did not read all of it."""

    def __init__(self, stream: BinaryIO, endian: str, snaplen: int, seekable: bool):
        self.stream = stream
        self.endian = endian
        self.snaplen = snaplen
        self.seekable = seekable
        # A file is read ahead by the block; a FIFO by the byte it needs.
        self._chunk = 4096 if seekable else 0
        self._buf = b""
        self.pos = 24              # stream offset of _buf[0]
        self.good = 24
        self.skipped_bytes = 0
        self.gaps = 0
        self.tail_bytes = 0        # after good: unread, and no record found in it
        self._last_sec: int | None = None

    def _need(self, n: int) -> bool:
        while len(self._buf) < n:
            chunk = self.stream.read(max(n - len(self._buf), self._chunk))
            if not chunk:
                return False
            self._buf += chunk
        return True

    def _take(self, n: int) -> None:
        self._buf = self._buf[n:]
        self.pos += n

    def _header(self, at: int, last_sec: int | None, strict: bool) -> tuple | None:
        """The record header at _buf[at:], if it could be one: (sec, usec,
        incl). The lax test is the writer's own snaplen bound; the strict
        one asks the header to agree with the record before it."""
        sec, usec, incl, orig = struct.unpack_from(self.endian + "LLLL", self._buf, at)
        if not _record_is_plausible(incl, self.snaplen):
            return None
        if strict:
            if usec >= 1_000_000 or not incl <= orig <= MAX_RECORD_BYTES:
                return None
            if last_sec is not None and not last_sec - _STAMP_BACK_S <= sec <= last_sec + _STAMP_AHEAD_S:
                return None
        return sec, usec, incl

    def _record(self, at: int, strict: bool, confirm: bool = False, stamp: bool = True) -> tuple | None:
        """The record at _buf[at:], if it is one that can be taken: its
        header, its data all here, and, with confirm, the header after it
        agreeing with it (or the stream ending there). ``stamp`` asks it
        to sit near the record before it, which only a header found by
        scanning has to prove."""
        if not self._need(at + 16):
            return None
        hdr = self._header(at, self._last_sec if stamp else None, strict)
        if hdr is None:
            return None
        sec, _usec, incl = hdr
        next_at = at + 16 + incl
        if not confirm:
            return hdr if self._need(next_at) else None
        more = self._need(next_at + 16)
        if len(self._buf) < next_at:
            return None                                # cut short: the tail
        if more and self._header(next_at, sec, strict=True) is None:
            return None
        return hdr

    def _resync(self) -> tuple | None:
        """Scan forward from _buf[1:] for a record to take. Returns its
        header with the buffer at it, the bytes passed over counted as a
        gap; or None, with nothing counted, when the stream ends first:
        that is a tail, and it begins at good."""
        at, passed = 1, 0
        while self._need(at + 16):
            if at >= 65536:                # keep the buffer short on a long run of garbage
                self._take(at)
                passed, at = passed + at, 0
            hdr = self._record(at, strict=True, confirm=True)
            if hdr is not None:
                self._take(at)
                self.skipped_bytes += passed + at
                self.gaps += 1
                return hdr
            at += 1
        # Nothing more to be had: whatever is left is the tail, and it
        # begins at good. Counted, not skipped over - a reader that says
        # what it stepped over inside a file owes the same for what it
        # never got past at the end of one.
        self.tail_bytes = passed + len(self._buf)
        return None

    def __iter__(self) -> Iterator[tuple[float, bytes]]:
        while True:
            # No stamp test here: this offset is where the last record
            # ended, so the header is not being guessed at.
            hdr = self._record(0, strict=self.seekable, stamp=False)
            if hdr is None:
                if not self._need(16) or not self.seekable:
                    self.tail_bytes = len(self._buf)
                    return                 # EOF, or a record cut short by a crash mid-write
                hdr = self._resync()
                if hdr is None:
                    return                 # a NUL tail from a power cut, or garbage to the end
            sec, usec, incl = hdr
            data = self._buf[16:16 + incl]
            self._take(16 + incl)
            self.good = self.pos
            self._last_sec = sec
            yield sec + usec / 1e6, data


def _open_header(header: bytes) -> tuple[str, int, int] | None:
    """(endian, snaplen, dlt) of a classic pcap global header, or None."""
    if len(header) < 24:
        return None
    if struct.unpack("<L", header[:4])[0] == PCAP_MAGIC_LE_US:
        endian = "<"
    elif struct.unpack(">L", header[:4])[0] == PCAP_MAGIC_LE_US:
        endian = ">"
    else:
        return None
    snaplen, dlt = struct.unpack(endian + "LL", header[16:24])
    return endian, snaplen, dlt


@dataclass
class PcapScan:
    good: int              # bytes up to the last whole record; 0 with no usable global header
    skipped_bytes: int     # bytes inside that no reader takes for a record
    gaps: int              # runs of them
    # The global header a writer appending to the file would be appending
    # under, so it can refuse a file whose records mean something else.
    # None with no usable header.
    dlt: int | None = None
    endian: str | None = None


def scan_file(path) -> PcapScan:
    """Where the good data of a pcap file ends, and what lies inside it that
    is not a record.

    A capture killed mid-write leaves a partial record at the tail, and a
    power cut leaves a run of NULs; a writer that appends after either
    would bury every later frame behind bytes no reader can get past (the
    NULs read as phantom zero-length frames at 1970). Those come after
    good. A bad record in the middle of the file is inside good, and left
    there: the readers step over it, and cutting the file at it would
    throw away every record after it. good is 0 with no usable global
    header."""
    with open(path, "rb") as fh:
        opened = _open_header(fh.read(24))
        if opened is None:
            return PcapScan(0, 0, 0)
        endian, snaplen, dlt = opened
        records = _Records(fh, endian, snaplen, seekable=True)
        for _ in records:
            pass
        return PcapScan(records.good, records.skipped_bytes, records.gaps, dlt, endian)


def complete_length(path) -> int:
    """Bytes of a pcap file up to its last complete record (see scan_file)."""
    return scan_file(path).good


class PcapStreamReader:
    """Reads classic pcap records from a blocking stream (file or FIFO).

    skipped_bytes and gaps say what the stream held that was not a record,
    and tail_bytes what it ended with that never became one (see
    _Records); a reader that reports on a file owes them a mention."""

    def __init__(self, stream: BinaryIO):
        self.stream = stream
        header = _read_exact(stream, 24)
        if len(header) < 24:
            raise PcapFormatError("no pcap global header")
        opened = _open_header(header)
        if opened is None:
            magic = struct.unpack("<L", header[:4])[0]
            raise PcapFormatError(f"unsupported pcap magic {magic:#x} (pcapng? convert with: tshark -F pcap)")
        self.endian, self.snaplen, self.dlt = opened
        try:
            seekable = stream.seekable()
        except (AttributeError, ValueError):
            seekable = False
        self._records = _Records(stream, self.endian, self.snaplen, seekable)

    @property
    def skipped_bytes(self) -> int:
        return self._records.skipped_bytes

    @property
    def gaps(self) -> int:
        return self._records.gaps

    @property
    def tail_bytes(self) -> int:
        return self._records.tail_bytes

    def __iter__(self) -> Iterator[Frame]:
        for ts, data in self._records:
            yield parse_frame(ts, data, self.dlt)


class PcapWriter:
    def __init__(self, stream: BinaryIO, dlt: int):
        self.stream = stream
        self.dlt = dlt
        stream.write(struct.pack("<LHHIILL", PCAP_MAGIC_LE_US, 2, 4, 0, 0, MAX_RECORD_BYTES, dlt))

    def write(self, frame: Frame) -> None:
        ts_sec = int(frame.ts)
        ts_usec = int(round((frame.ts - ts_sec) * 1e6))
        if ts_usec >= 1_000_000:   # rounding carried into the next second
            ts_sec, ts_usec = ts_sec + 1, ts_usec - 1_000_000
        # One write per record, so a reader copying the file sees a record
        # whole or not at all once the stream is flushed.
        self.stream.write(struct.pack("<LLLL", ts_sec, ts_usec, len(frame.raw), len(frame.raw)) + frame.raw)


def is_poll(f: "Frame") -> bool:
    """Is this frame a Data Request, the MAC command a sleepy end device
    polls its parent with? The command id is 4; a secured command carries
    no readable id, and the secured MAC commands a Thread device sends are
    its polls. The one place this is decided: the live pipeline, `device` and
    the review rows count polls with it, so a beacon request (command 7,
    a join scan) is a poll to none of them."""
    return f.ftype == 3 and f.cmd in (None, 4)


def parse_frame(ts: float, data: bytes, dlt: int) -> Frame:
    rssi = channel = lqi = None
    psdu = data
    # A frame is handed on as its on-air bytes without the FCS: the
    # decryptor's MIC covers the frame before it, and an MLE message in
    # an unsecured frame is authenticated over the whole payload, so a
    # trailing FCS made every advertisement in an imported capture
    # unreadable while the secured frames still decrypted (a trimmed
    # retry covers those).
    fcs_len = 2 if dlt == DLT_WITHFCS else 0
    if dlt == DLT_TAP:
        # An incomplete envelope is not a MAC frame or usable metadata.
        if len(data) < 4:
            return Frame(ts, data, b"", None, None, None)
        tap_len = struct.unpack("<H", data[2:4])[0]
        if not 4 <= tap_len <= len(data):
            return Frame(ts, data, b"", None, None, None)
        off = 4
        while off + 4 <= tap_len:
            tlv_type, tlv_len = struct.unpack("<HH", data[off:off + 4])
            next_off = off + 4 + ((tlv_len + 3) & ~3)
            if next_off > tap_len:
                break   # Never borrow bytes from the MAC payload for a TLV.
            val = data[off + 4:off + 4 + tlv_len]
            if tlv_type == 1 and len(val) >= 4:
                value = struct.unpack("<f", val[:4])[0]
                if math.isfinite(value):
                    rssi = value
            elif tlv_type == 3 and len(val) >= 2:
                channel = struct.unpack("<H", val[:2])[0]
            elif tlv_type == 10 and len(val) >= 1:
                lqi = val[0]
            elif tlv_type == 0 and len(val) >= 1:
                fcs_len = _TAP_FCS_LEN.get(val[0], 0)
            off = next_off
        psdu = data[tap_len:]
    if fcs_len:
        psdu = psdu[:-fcs_len] if len(psdu) > fcs_len else b""
    frame = Frame(ts=ts, raw=data, psdu=psdu, rssi=rssi, channel=channel, lqi=lqi)
    _parse_mac(frame)
    return frame


def _addr_hex(b: bytes) -> str:
    return b[::-1].hex()  # 802.15.4 addresses are little-endian on air


def _parse_mac(f: Frame) -> None:
    p = f.psdu
    if len(p) < 3:
        return
    fcf = struct.unpack("<H", p[0:2])[0]
    f.ftype = fcf & 0x7
    f.seq = p[2]
    pan_comp = bool(fcf & 0x0040)
    dst_mode = (fcf >> 10) & 0x3
    src_mode = (fcf >> 14) & 0x3
    off = 3

    def address(n: int) -> str:
        # A slice never raises: a frame cut short inside an extended
        # address would read back as 4 hex digits, which is a short
        # address to everything downstream (identity, RLOC16 learning,
        # parent naming). Fewer bytes than declared is no address.
        chunk = p[off:off + n]
        if len(chunk) < n:
            raise struct.error("address cut short")
        return _addr_hex(chunk)

    try:
        if dst_mode in (2, 3):
            f.dst_pan = struct.unpack("<H", p[off:off + 2])[0]
            off += 2
            n = 2 if dst_mode == 2 else 8
            f.dst = address(n)
            off += n
        if src_mode in (2, 3):
            if not (pan_comp and dst_mode in (2, 3)):
                f.src_pan = struct.unpack("<H", p[off:off + 2])[0]
                off += 2
            elif f.dst_pan is not None:
                f.src_pan = f.dst_pan
            n = 2 if src_mode == 2 else 8
            f.src = address(n)
            off += n
        if f.ftype == 3 and not (fcf & 0x0008) and off < len(p):
            f.cmd = p[off]   # 0x04 data request (poll), 0x07 beacon request
    except struct.error:
        # Truncated or non-standard header; keep what we have.
        pass
