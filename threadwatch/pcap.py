"""Classic pcap stream reading/writing and minimal 802.15.4 parsing.

Supports the two link types the Nordic nRF 802.15.4 sniffer emits:
DLT 283 (IEEE802_15_4_TAP, carries RSSI/LQI/channel TLVs) and
DLT 230 (IEEE802_15_4_NOFCS). Stdlib only.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional

DLT_TAP = 283
DLT_NOFCS = 230

PCAP_MAGIC_LE_US = 0xA1B2C3D4  # microsecond timestamps, little-endian file


class PcapFormatError(Exception):
    pass


@dataclass
class Frame:
    ts: float                 # epoch seconds (float)
    raw: bytes                # bytes as captured (including TAP header if DLT 283)
    psdu: bytes               # 802.15.4 PHY payload (MAC frame)
    rssi: Optional[float]     # dBm, TAP only
    channel: Optional[int]    # TAP only
    lqi: Optional[int]        # TAP only
    # MAC header fields (None when not present / not parseable)
    ftype: Optional[int] = None      # 0 beacon, 1 data, 2 ack, 3 command
    seq: Optional[int] = None
    dst_pan: Optional[int] = None
    dst: Optional[str] = None        # hex string, 4 chars (short) or 16 (extended)
    src_pan: Optional[int] = None
    src: Optional[str] = None
    cmd: Optional[int] = None        # MAC command id, unsecured command frames only


def _read_exact(stream: BinaryIO, n: int) -> bytes:
    """Read n bytes; fewer only at EOF (a truncated tail record)."""
    buf = b""
    while len(buf) < n:
        chunk = stream.read(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def complete_length(path) -> int:
    """Bytes of a pcap file up to its last complete record.

    A capture killed mid-write leaves a partial record at the tail; a
    writer that appends after it would bury every later frame behind bytes
    no reader can get past. 0 means there is no usable global header."""
    with open(path, "rb") as fh:
        header = fh.read(24)
        if len(header) < 24:
            return 0
        magic = struct.unpack("<L", header[:4])[0]
        if magic == PCAP_MAGIC_LE_US:
            endian = "<"
        elif struct.unpack(">L", header[:4])[0] == PCAP_MAGIC_LE_US:
            endian = ">"
        else:
            return 0
        good = 24
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                return good
            incl = struct.unpack(endian + "LLLL", rec)[2]
            if len(fh.read(incl)) < incl:
                return good
            good += 16 + incl


class PcapStreamReader:
    """Reads classic pcap records from a blocking stream (file or FIFO)."""

    def __init__(self, stream: BinaryIO):
        self.stream = stream
        header = _read_exact(stream, 24)
        if len(header) < 24:
            raise PcapFormatError("no pcap global header")
        magic = struct.unpack("<L", header[:4])[0]
        if magic == PCAP_MAGIC_LE_US:
            self.endian = "<"
        elif struct.unpack(">L", header[:4])[0] == PCAP_MAGIC_LE_US:
            self.endian = ">"
        else:
            raise PcapFormatError(f"unsupported pcap magic {magic:#x} (pcapng? convert with: tshark -F pcap)")
        self.dlt = struct.unpack(self.endian + "L", header[20:24])[0]

    def __iter__(self) -> Iterator[Frame]:
        while True:
            rec = _read_exact(self.stream, 16)
            if len(rec) < 16:
                return   # EOF, or a record cut short by a crash mid-write
            ts_sec, ts_usec, incl, _orig = struct.unpack(self.endian + "LLLL", rec)
            data = _read_exact(self.stream, incl)
            if len(data) < incl:
                return
            yield parse_frame(ts_sec + ts_usec / 1e6, data, self.dlt)


class PcapWriter:
    def __init__(self, stream: BinaryIO, dlt: int):
        self.stream = stream
        self.dlt = dlt
        stream.write(struct.pack("<LHHIILL", PCAP_MAGIC_LE_US, 2, 4, 0, 0, 0x0000FFFF, dlt))

    def write(self, frame: Frame) -> None:
        ts_sec = int(frame.ts)
        ts_usec = int(round((frame.ts - ts_sec) * 1e6))
        if ts_usec >= 1_000_000:   # rounding carried into the next second
            ts_sec, ts_usec = ts_sec + 1, ts_usec - 1_000_000
        self.stream.write(struct.pack("<LLLL", ts_sec, ts_usec, len(frame.raw), len(frame.raw)))
        self.stream.write(frame.raw)


def parse_frame(ts: float, data: bytes, dlt: int) -> Frame:
    rssi = channel = lqi = None
    psdu = data
    if dlt == DLT_TAP and len(data) >= 4:
        tap_len = struct.unpack("<H", data[2:4])[0]
        off = 4
        while off + 4 <= min(tap_len, len(data)):
            tlv_type, tlv_len = struct.unpack("<HH", data[off:off + 4])
            # A record cut short leaves fewer bytes than the TLV declares:
            # measure what is actually there, not what the header claims.
            val = data[off + 4:off + 4 + tlv_len]
            if tlv_type == 1 and len(val) >= 4:
                rssi = struct.unpack("<f", val[:4])[0]
            elif tlv_type == 3 and len(val) >= 2:
                channel = struct.unpack("<H", val[:2])[0]
            elif tlv_type == 10 and len(val) >= 1:
                lqi = val[0]
            off += 4 + ((tlv_len + 3) & ~3)
        # A tap_len under 4 is not a header at all; slicing from it would
        # reparse the TAP bytes as a MAC frame and invent devices and PANs.
        psdu = data[tap_len:] if tap_len >= 4 else b""
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
    try:
        if dst_mode in (2, 3):
            f.dst_pan = struct.unpack("<H", p[off:off + 2])[0]
            off += 2
            n = 2 if dst_mode == 2 else 8
            f.dst = _addr_hex(p[off:off + n])
            off += n
        if src_mode in (2, 3):
            if not (pan_comp and dst_mode in (2, 3)):
                f.src_pan = struct.unpack("<H", p[off:off + 2])[0]
                off += 2
            elif f.dst_pan is not None:
                f.src_pan = f.dst_pan
            n = 2 if src_mode == 2 else 8
            f.src = _addr_hex(p[off:off + n])
            off += n
        if f.ftype == 3 and not (fcf & 0x0008) and off < len(p):
            f.cmd = p[off]   # 0x04 data request (poll), 0x07 beacon request
    except struct.error:
        # Truncated or non-standard header; keep what we have.
        pass
