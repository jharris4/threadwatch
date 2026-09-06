"""The ring survives a capture killed mid-write."""

import contextlib
import io
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch.capture import RingWriter
from threadwatch.pcap import DLT_NOFCS, DLT_TAP, Frame, PcapStreamReader, PcapWriter, complete_length


class RingSizeCapTest(unittest.TestCase):
    def test_oldest_go_until_under_the_byte_cap_but_never_the_current_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ring = RingWriter(Path(d), keep_files=10, dlt=0, keep_bytes=2500)
            for h in ("00", "01", "02", "03"):
                (Path(d) / f"threadwatch-20260903-{h}.pcap").write_bytes(b"x" * 1000)
            ring._prune()
            self.assertEqual(sorted(p.name[-7:-5] for p in Path(d).glob("*.pcap")), ["02", "03"])
            (Path(d) / "threadwatch-20260903-03.pcap").write_bytes(b"x" * 9000)   # one huge current file
            ring._prune()
            self.assertEqual(sorted(p.name[-7:-5] for p in Path(d).glob("*.pcap")), ["03"])
            ring = RingWriter(Path(d), keep_files=10, dlt=0)                        # no cap: files only
            (Path(d) / "threadwatch-20260903-04.pcap").write_bytes(b"x" * 9000)
            ring._prune()
            self.assertEqual(len(list(Path(d).glob("*.pcap"))), 2)

    def test_the_byte_cap_holds_while_the_hour_grows_not_only_at_the_rotation(self):
        # Pruned only at rotation, the ring sat over the cap for the whole
        # hour, by as much as the hour brought.
        import tempfile
        import time

        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "threadwatch-20260904-08.pcap").write_bytes(b"x" * 50_000)
            (Path(d) / "threadwatch-20260904-09.pcap").write_bytes(b"x" * 50_000)
            ring = RingWriter(Path(d), keep_files=168, dlt=0, keep_bytes=150_000)
            self.assertEqual(ring._prune_step, 65536)
            ts = time.mktime(time.strptime("2026-09-04 10:00:00", "%Y-%m-%d %H:%M:%S"))
            frame = lambda i: Frame(ts=ts + i, raw=b"\x00" * 1000, psdu=b"", rssi=None, channel=None, lqi=None)
            total = lambda: sum(p.stat().st_size for p in Path(d).glob("*.pcap"))
            for i in range(40):                     # 40 KB into the hour: 140 KB, under the cap, all three stay
                ring.write(frame(i))
            self.assertEqual(len(list(Path(d).glob("*.pcap"))), 3)
            for i in range(40, 200):                # the hour keeps coming; no rotation
                ring.write(frame(i))
                self.assertLessEqual(total(), 150_000 + ring._prune_step, f"frame {i}")
            self.assertEqual(sorted(p.name[-7:-5] for p in Path(d).glob("*.pcap")), ["10"])
            self.assertTrue(ring.current_path.exists())
            ring.close()

    def test_current_file_survives_a_clock_step_back(self):
        import tempfile
        import time

        with tempfile.TemporaryDirectory() as d:
            for h in ("12", "13", "14", "15"):
                (Path(d) / f"threadwatch-20260904-{h}.pcap").write_bytes(b"x" * 1000)
            ring = RingWriter(Path(d), keep_files=4, dlt=0)
            ts = time.mktime(time.strptime("2026-09-04 09:30:00", "%Y-%m-%d %H:%M:%S"))
            ring.write(Frame(ts=ts, raw=b"\x00" * 20, psdu=b"", rssi=None, channel=None, lqi=None))
            self.assertTrue(ring.current_path.exists())
            self.assertEqual(len(list(Path(d).glob("*.pcap"))), 4)

    def test_keep_files_zero_does_not_delete_the_file_being_written(self):
        import tempfile
        import time

        with tempfile.TemporaryDirectory() as d:
            ring = RingWriter(Path(d), keep_files=0, dlt=0)
            ts = time.mktime(time.strptime("2026-09-04 10:00:00", "%Y-%m-%d %H:%M:%S"))
            ring.write(Frame(ts=ts, raw=b"\x00" * 20, psdu=b"", rssi=None, channel=None, lqi=None))
            self.assertTrue(ring.current_path.exists())

    def test_byte_cap_counts_only_what_the_file_cap_keeps(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            ring = RingWriter(Path(d), keep_files=2, dlt=0, keep_bytes=2500)
            for h in ("00", "01", "02", "03"):
                (Path(d) / f"threadwatch-20260903-{h}.pcap").write_bytes(b"x" * 1000)
            ring._prune()
            # The two newest total 2000 bytes, under the cap: both stay.
            self.assertEqual(sorted(p.name[-7:-5] for p in Path(d).glob("*.pcap")), ["02", "03"])

    def test_the_count_cap_prunes_the_oldest_with_no_byte_cap_set(self):
        import tempfile
        # keep_bytes unset is the default; nothing else bounds the ring, so
        # the count cap alone has to prune or the card fills.
        with tempfile.TemporaryDirectory() as d:
            for h in ("00", "01", "02", "03", "04", "05"):
                (Path(d) / f"threadwatch-20260903-{h}.pcap").write_bytes(b"x" * 1000)
            ring = RingWriter(Path(d), keep_files=3, dlt=0)
            ring._prune()
            self.assertEqual(sorted(p.name[-7:-5] for p in Path(d).glob("*.pcap")), ["03", "04", "05"])


def frame(ts):
    return Frame(ts=ts, raw=b"\x41\x88\x01\xcd\xab\x01\x00\x02\x00", psdu=b"",
                 rssi=None, channel=None, lqi=None)


class TruncatedRingTest(unittest.TestCase):
    def test_reader_stops_cleanly_at_a_partial_tail_record(self):
        buf = io.BytesIO()
        w = PcapWriter(buf, DLT_NOFCS)
        w.write(frame(1.0)); w.write(frame(2.0))
        cut = buf.getvalue()[:-3]
        self.assertEqual(len(list(PcapStreamReader(io.BytesIO(cut)))), 1)
        self.assertEqual(complete_length_of(cut), 24 + 16 + 9)   # header + one whole record

    def test_a_nul_tail_from_a_power_cut_is_not_a_run_of_records(self):
        # ext4 extends the file before the data lands: a power cut leaves
        # NULs, and sixteen NULs unpack to a zero-length record at 1970.
        buf = io.BytesIO()
        w = PcapWriter(buf, DLT_NOFCS)
        w.write(frame(1.0)); w.write(frame(2.0))
        whole = buf.getvalue()
        data = whole + b"\x00" * 4096
        self.assertEqual(complete_length_of(data), len(whole))
        self.assertEqual([round(f.ts) for f in PcapStreamReader(io.BytesIO(data))], [1, 2])
        # A length past the file's snaplen is garbage too, not a record.
        huge = whole + struct.pack("<LLLL", 1, 0, 0x7FFFFFFF, 0x7FFFFFFF) + b"x" * 32
        self.assertEqual(complete_length_of(huge), len(whole))
        with tempfile.TemporaryDirectory() as d:
            ring = RingWriter(Path(d), keep_files=5, dlt=DLT_NOFCS)
            ring.write(frame(1_700_000_000.0)); ring.close()
            path = ring.current_path
            with open(path, "ab") as fh:
                fh.write(b"\x00" * 4096)
            ring2 = RingWriter(Path(d), keep_files=5, dlt=DLT_NOFCS)     # the resume trims the NULs
            ring2.write(frame(1_700_000_002.0)); ring2.close()
            with open(path, "rb") as fh:
                self.assertEqual([round(f.ts) for f in PcapStreamReader(fh)], [1_700_000_000, 1_700_000_002])
            self.assertEqual(complete_length(path), path.stat().st_size)

    def test_microseconds_never_round_to_a_full_second(self):
        buf = io.BytesIO()
        PcapWriter(buf, DLT_NOFCS).write(frame(1700000000.9999996))
        f = next(iter(PcapStreamReader(io.BytesIO(buf.getvalue()))))
        self.assertEqual(f.ts, 1700000001.0)
        self.assertLess(int.from_bytes(buf.getvalue()[28:32], "little"), 1_000_000)

    def test_resumed_hour_file_drops_the_fragment_before_appending(self):
        with tempfile.TemporaryDirectory() as d:
            ring = RingWriter(Path(d), keep_files=5, dlt=DLT_NOFCS)
            ring.write(frame(1_700_000_000.0)); ring.write(frame(1_700_000_001.0))
            ring.close()
            path = ring.current_path
            with open(path, "r+b") as fh:
                fh.truncate(path.stat().st_size - 3)   # killed mid-record
            ring2 = RingWriter(Path(d), keep_files=5, dlt=DLT_NOFCS)
            ring2.write(frame(1_700_000_002.0))
            ring2.close()
            with open(path, "rb") as fh:
                seen = [round(f.ts) for f in PcapStreamReader(fh)]
            self.assertEqual(seen, [1_700_000_000, 1_700_000_002])
            self.assertEqual(complete_length(path), path.stat().st_size)


class ResumeHeaderMatchTest(unittest.TestCase):
    """Resuming an hour file appends bare records under whatever global
    header is already there. A file written under another link type, or
    a big-endian one, would take those records and hand every later
    reader the wrong parse of them, silently: the worst outcome for a
    flight recorder, since the frames still read back."""

    def _rewritten(self, d, existing_dlt=None, endian="<"):
        ring = RingWriter(Path(d), keep_files=5, dlt=DLT_TAP)
        ring.write(frame(1_700_000_000.0))
        ring.close()
        path = ring.current_path
        data = bytearray(path.read_bytes())
        if existing_dlt is not None:
            data[20:24] = struct.pack("<L", existing_dlt)
        if endian == ">":
            data[:4] = struct.pack(">L", 0xA1B2C3D4)
        path.write_bytes(bytes(data))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            ring2 = RingWriter(Path(d), keep_files=5, dlt=DLT_TAP)
            ring2.write(frame(1_700_000_002.0))
            ring2.close()
        return path, out.getvalue()

    def test_a_file_of_another_link_type_is_started_over_not_appended_to(self):
        with tempfile.TemporaryDirectory() as d:
            path, said = self._rewritten(d, existing_dlt=DLT_NOFCS)
            self.assertEqual(struct.unpack("<L", path.read_bytes()[20:24])[0], DLT_TAP)
            self.assertEqual([round(f.ts) for f in PcapStreamReader(io.BytesIO(path.read_bytes()))],
                             [1_700_000_002])
            self.assertIn("link type 230", said)

    def test_a_big_endian_file_is_started_over_too(self):
        with tempfile.TemporaryDirectory() as d:
            path, said = self._rewritten(d, endian=">")
            self.assertEqual(path.read_bytes()[:4], struct.pack("<L", 0xA1B2C3D4))
            self.assertIn("big-endian", said)

    def test_a_matching_header_still_resumes(self):
        with tempfile.TemporaryDirectory() as d:
            path, said = self._rewritten(d)
            self.assertEqual([round(f.ts) for f in PcapStreamReader(io.BytesIO(path.read_bytes()))],
                             [1_700_000_000, 1_700_000_002])
            self.assertEqual(said, "")


class CorruptRecordMidFileTest(unittest.TestCase):
    """One bad caplen byte in the middle of a ring file used to end every
    read there, silently, and the resuming writer then cut the file at it
    and deleted every record after it, calling them a record cut short."""

    def _file(self, n=40, bad=20):
        buf = io.BytesIO()
        w = PcapWriter(buf, DLT_NOFCS)
        for i in range(n):
            w.write(frame(1_700_000_000.0 + i))
        data = bytearray(buf.getvalue())
        at = 24 + bad * (16 + 9) + 8            # the caplen field of record `bad`
        data[at + 1] ^= 0x40                    # one flipped bit: caplen 9 -> 16393, past snaplen
        return bytes(data)

    def test_the_reader_steps_over_the_bad_record_and_counts_it(self):
        data = self._file()
        reader = PcapStreamReader(io.BytesIO(data))
        seen = [round(f.ts) - 1_700_000_000 for f in reader]
        self.assertEqual(seen, [i for i in range(40) if i != 20])
        self.assertEqual((reader.skipped_bytes, reader.gaps), (16 + 9, 1))
        # Whole and readable to the end: nothing trailing to drop, one gap inside.
        scan = scan_file_of(data)
        self.assertEqual((scan.good, scan.skipped_bytes, scan.gaps), (len(data), 25, 1))
        # A NUL tail is still a tail, not a gap: nothing was skipped inside the data.
        reader = PcapStreamReader(io.BytesIO(data + b"\x00" * 4096))
        self.assertEqual(len(list(reader)), 39)
        self.assertEqual((reader.skipped_bytes, reader.gaps), (25, 1))
        self.assertEqual(scan_file_of(data + b"\x00" * 4096).good, len(data))

    def test_a_garbage_run_and_a_bad_first_record_are_stepped_over_too(self):
        buf = io.BytesIO()
        w = PcapWriter(buf, DLT_NOFCS)
        w.write(frame(1.0)); w.write(frame(2.0))
        head = buf.getvalue()
        buf = io.BytesIO()
        w = PcapWriter(buf, DLT_NOFCS)
        w.write(frame(3.0)); w.write(frame(4.0))
        tail = buf.getvalue()[24:]
        junk = bytes(range(256)) * 300          # 76800 bytes: longer than the scanner's buffer step
        data = head + junk + tail
        reader = PcapStreamReader(io.BytesIO(data))
        self.assertEqual([f.ts for f in reader], [1.0, 2.0, 3.0, 4.0])
        self.assertEqual((reader.skipped_bytes, reader.gaps), (len(junk), 1))
        reader = PcapStreamReader(io.BytesIO(head[:24] + junk + tail))
        self.assertEqual([f.ts for f in reader], [3.0, 4.0])
        self.assertEqual(scan_file_of(head[:24] + junk + tail).good, len(head[:24] + junk + tail))

    def test_the_resuming_writer_leaves_the_file_whole_and_says_so(self):
        import contextlib
        data = self._file()
        with tempfile.TemporaryDirectory() as d:
            ring = RingWriter(Path(d), keep_files=5, dlt=DLT_NOFCS)
            ring.write(frame(1_700_000_000.0)); ring.close()
            path = ring.current_path
            path.write_bytes(data)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                ring2 = RingWriter(Path(d), keep_files=5, dlt=DLT_NOFCS)
                ring2.write(frame(1_700_000_040.0)); ring2.close()
            self.assertEqual(out.getvalue(), f"[threadwatch] {path.name}: 25 bytes in 1 place(s) are not "
                                             "readable records; left in place, readers skip them\n")
            self.assertEqual(path.stat().st_size, len(data) + 16 + 9)     # nothing deleted
            with open(path, "rb") as fh:
                seen = [round(f.ts) - 1_700_000_000 for f in PcapStreamReader(fh)]
            self.assertEqual(seen, [i for i in range(41) if i != 20])
            # A partial tail record after the gap is still dropped on resume.
            with open(path, "r+b") as fh:
                fh.truncate(path.stat().st_size - 3)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                ring3 = RingWriter(Path(d), keep_files=5, dlt=DLT_NOFCS)
                ring3.write(frame(1_700_000_041.0)); ring3.close()
            self.assertIn("dropping 22 trailing bytes of a record cut short", out.getvalue())
            with open(path, "rb") as fh:
                seen = [round(f.ts) - 1_700_000_000 for f in PcapStreamReader(fh)]
            self.assertEqual(seen, [i for i in range(42) if i not in (20, 40)])


def scan_file_of(data: bytes):
    from threadwatch.pcap import scan_file
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(data); tmp.flush()
        return scan_file(tmp.name)


def complete_length_of(data: bytes) -> int:
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(data); tmp.flush()
        return complete_length(tmp.name)


class TapHeaderTest(unittest.TestCase):
    """DLT 283 is what the dongle actually produces; a corrupt ring file
    must not take the parser with it."""

    def _tap(self, body: bytes):
        from threadwatch.pcap import DLT_TAP, parse_frame
        return parse_frame(0.0, body, DLT_TAP)

    def test_tlv_cut_short_does_not_raise(self):
        for body in ("0000080001000400", "0000080003000200", "000008000a000100"):
            f = self._tap(bytes.fromhex(body))
            self.assertIsNone(f.rssi)
            self.assertIsNone(f.channel)
            self.assertIsNone(f.lqi)

    def test_tap_len_below_header_yields_no_psdu(self):
        self.assertEqual(self._tap(bytes.fromhex("00000200") + b"\xff" * 8).psdu, b"")

    def test_a_real_dongle_frame_off_the_ring(self):
        """The production entry point: DLT 283 out of a ring file, read the
        way capture reads it. These 48 bytes are one record from
        data/ring/threadwatch-20260902-02.pcap - a 28-byte TAP header of
        RSSI, channel and LQI TLVs (each padded to four bytes) in front of a
        20-byte secured MAC command frame."""
        import io

        from threadwatch.pcap import DLT_TAP, PcapStreamReader, PcapWriter
        raw = bytes.fromhex("00001c0001000400000094c203000300190000000a000100"
                            "4c0000006b98f28473003c1a3c0d5a3901005504cb7ef338")
        buf = io.BytesIO()
        PcapWriter(buf, DLT_TAP).write(Frame(ts=1_756_800_000.0, raw=raw, psdu=b"",
                                             rssi=None, channel=None, lqi=None))
        f = next(iter(PcapStreamReader(io.BytesIO(buf.getvalue()))))
        self.assertEqual((f.rssi, f.channel, f.lqi), (-74.0, 25, 76))
        self.assertEqual(len(f.psdu), 20)                 # the TAP header is off the front
        self.assertEqual(f.psdu, raw[28:])
        self.assertEqual((f.ftype, f.seq, f.src, f.dst), (3, 242, "3c1a", "3c00"))

    def test_an_address_cut_short_is_no_address_not_a_short_one(self):
        from threadwatch.pcap import DLT_NOFCS, parse_frame
        # Data frame, PAN compression, extended destination and source.
        head = struct.pack("<H", 0x0001 | 0x0040 | (3 << 10) | (3 << 14)) + b"\x07" + struct.pack("<H", 0x4e21)
        dst, src = bytes(range(0x50, 0x58)), bytes(range(0xa0, 0xa8))
        whole = parse_frame(0.0, head + dst + src, DLT_NOFCS)
        self.assertEqual((len(whole.dst), len(whole.src)), (16, 16))
        for cut in range(1, 9):                       # anywhere inside the source address
            f = parse_frame(0.0, (head + dst + src)[:-cut], DLT_NOFCS)
            self.assertEqual((f.dst, f.src, f.src_pan), (whole.dst, None, 0x4e21), cut)
        f = parse_frame(0.0, (head + dst)[:-2], DLT_NOFCS)   # inside the destination
        self.assertEqual((f.dst_pan, f.dst, f.src), (0x4e21, None, None))

    def test_well_formed_tap_header_still_parses(self):
        import struct
        body = (struct.pack("<HH", 0, 20)                       # version/reserved, tap_len
                + struct.pack("<HH", 1, 4) + struct.pack("<f", -61.0)      # RSSI
                + struct.pack("<HH", 3, 2) + struct.pack("<H", 25) + b"\x00\x00"   # channel
                + b"\xab" * 6)                                  # PSDU
        f = self._tap(body)
        self.assertEqual(round(f.rssi), -61)
        self.assertEqual(f.channel, 25)
        self.assertEqual(f.psdu, b"\xab" * 6)


class FcsTest(unittest.TestCase):
    """A capture that keeps the FCS (DLT 195, or TAP declaring one) is read
    as its on-air bytes: the MIC on a secured frame and the MLE MIC in an
    unsecured one both end before the FCS, and the ring's own frames
    (DLT 230 / TAP without the TLV) carry none to strip."""

    MAC = struct.pack("<HBH", 1 | (3 << 14), 7, 0x4e21) + bytes(range(8)) + b"\x7f\x33"

    def test_dlt_195_ends_in_an_fcs_and_tap_only_when_it_says_so(self):
        from threadwatch.pcap import DLT_TAP, DLT_WITHFCS, parse_frame
        with_fcs = self.MAC + b"\xab\xcd"
        self.assertEqual(parse_frame(1, with_fcs, DLT_WITHFCS).psdu, self.MAC)
        self.assertEqual(parse_frame(1, with_fcs, DLT_NOFCS).psdu, with_fcs)        # the ring: nothing to strip
        declared = struct.pack("<HHHHI", 0, 12, 0, 1, 1) + with_fcs                 # TAP: FCS type 1, CRC-16
        f = parse_frame(1, declared, DLT_TAP)
        self.assertEqual((f.psdu, f.src), (self.MAC, bytes(range(8))[::-1].hex()))
        crc32 = struct.pack("<HHHHI", 0, 12, 0, 1, 2) + self.MAC + b"\x01\x02\x03\x04"
        self.assertEqual(parse_frame(1, crc32, DLT_TAP).psdu, self.MAC)
        undeclared = struct.pack("<HHHHf", 0, 12, 1, 4, -60.0) + with_fcs              # the sniffer's own TAP
        self.assertEqual(parse_frame(1, undeclared, DLT_TAP).psdu, with_fcs)
        self.assertEqual(parse_frame(1, b"\x01", DLT_WITHFCS).psdu, b"")               # shorter than its FCS


class RingHourNamingTest(unittest.TestCase):
    """One file per local hour. The name is a contract: `why.select_recent`
    parses it to pick a window, and per-file retention drops one hour at a
    time rather than a whole day."""

    def test_two_hours_of_one_day_become_two_files_why_can_window(self):
        import time

        from threadwatch.why import RING_NAME, select_recent
        with tempfile.TemporaryDirectory() as d:
            ring = RingWriter(Path(d), keep_files=10, dlt=DLT_NOFCS)
            for stamp in ("2026-09-04 08:30:00", "2026-09-04 09:10:00"):
                ring.write(frame(time.mktime(time.strptime(stamp, "%Y-%m-%d %H:%M:%S"))))
            ring.close()
            names = sorted(p.name for p in Path(d).glob("*.pcap"))
            self.assertEqual(names, ["threadwatch-20260904-08.pcap", "threadwatch-20260904-09.pcap"])
            for name in names:
                time.strptime(name, RING_NAME)       # the name `why` has to parse
            now = time.mktime(time.strptime("2026-09-04 09:40:00", "%Y-%m-%d %H:%M:%S"))
            recent = select_recent(sorted(Path(d).glob("*.pcap")), 0.5, now)
            self.assertEqual([p.name for p in recent], ["threadwatch-20260904-09.pcap"])


class PanCompressionTest(unittest.TestCase):
    """PAN ID compression (FCF bit 6) means the source PAN is the
    destination's and is left off the wire, which is only so when there
    is a destination. With the bit set and no destination address the
    source PAN is on the wire, and a parser that skipped it would read
    the PAN bytes as the start of the address and invent a device."""

    SRC = bytes(range(0xa0, 0xa8))

    def _frame(self, fcf, body):
        from threadwatch.pcap import DLT_NOFCS, parse_frame
        return parse_frame(0.0, struct.pack("<H", fcf) + b"\x07" + body, DLT_NOFCS)

    def test_compression_without_a_destination_leaves_the_source_pan_on_the_wire(self):
        f = self._frame(0x0001 | 0x0040 | (0 << 10) | (3 << 14), struct.pack("<H", 0x4e21) + self.SRC)
        self.assertEqual((f.dst_pan, f.dst, f.src_pan, f.src), (None, None, 0x4e21, "a7a6a5a4a3a2a1a0"))
        # A MAC command the same way: the command id follows the address it found.
        f = self._frame(0x0003 | 0x0040 | (0 << 10) | (3 << 14), struct.pack("<H", 0x4e21) + self.SRC + b"\x04")
        self.assertEqual((f.src_pan, f.src, f.cmd), (0x4e21, "a7a6a5a4a3a2a1a0", 4))

    def test_compression_with_a_destination_copies_its_pan(self):
        f = self._frame(0x0001 | 0x0040 | (2 << 10) | (3 << 14), struct.pack("<H", 0x4e21) + b"\x00\xcc" + self.SRC)
        self.assertEqual((f.dst_pan, f.dst, f.src_pan, f.src), (0x4e21, "cc00", 0x4e21, "a7a6a5a4a3a2a1a0"))

    def test_no_compression_reads_both_pans(self):
        f = self._frame(0x0001 | (2 << 10) | (2 << 14),
                        struct.pack("<H", 0x4e21) + b"\x00\xcc" + struct.pack("<H", 0x58bc) + b"\x1a\x3c")
        self.assertEqual((f.dst_pan, f.dst, f.src_pan, f.src), (0x4e21, "cc00", 0x58bc, "3c1a"))


class FormatRejectionTest(unittest.TestCase):
    """What the reader and complete_length make of a file that is not a
    pcap of ours: a pcapng, a nanosecond pcap, a file cut inside the
    global header, and (the one shape that is ours) a big-endian file.
    The ring writer asks complete_length where the good data ends before
    appending, and 0 means it starts the hour's file over: that must be
    said, and must never happen to a file a reader can still read."""

    def _reader(self, data):
        return PcapStreamReader(io.BytesIO(data))

    def test_no_header_and_foreign_magics_are_format_errors_and_zero_good_bytes(self):
        from threadwatch.pcap import PcapFormatError
        for data in (b"", b"\xd4\xc3\xb2\xa1" + b"\x00" * 10):          # empty, or cut inside the header
            with self.assertRaises(PcapFormatError) as cm:
                self._reader(data)
            self.assertIn("no pcap global header", str(cm.exception))
            self.assertEqual(complete_length_of(data), 0)
        pcapng = struct.pack("<L", 0x0A0D0D0A) + b"\x00" * 28
        with self.assertRaises(PcapFormatError) as cm:
            self._reader(pcapng)
        self.assertIn("unsupported pcap magic 0xa0d0d0a", str(cm.exception))
        self.assertIn("pcapng", str(cm.exception))
        self.assertEqual(complete_length_of(pcapng), 0)
        nanos = struct.pack("<LHHIILL", 0xA1B23C4D, 2, 4, 0, 0, 0xFFFF, DLT_NOFCS)
        with self.assertRaises(PcapFormatError):
            self._reader(nanos)
        self.assertEqual(complete_length_of(nanos), 0)

    def test_a_big_endian_file_reads_whole(self):
        raw = b"\x41\x88\x01\xcd\xab\x01\x00\x02\x00"
        data = struct.pack(">LHHIILL", 0xA1B2C3D4, 2, 4, 0, 0, 0xFFFF, DLT_NOFCS)
        for sec in (1, 2):
            data += struct.pack(">LLLL", sec, 500000, len(raw), len(raw)) + raw
        reader = self._reader(data)
        self.assertEqual((reader.endian, reader.dlt, reader.snaplen), (">", DLT_NOFCS, 0xFFFF))
        self.assertEqual([f.ts for f in reader], [1.5, 2.5])
        self.assertEqual(complete_length_of(data), len(data))
        self.assertEqual(complete_length_of(data[:-4]), len(data) - 16 - len(raw))   # the cut record is not good data

    def test_the_ring_says_so_when_it_starts_an_unreadable_hour_file_over(self):
        import contextlib
        with tempfile.TemporaryDirectory() as d:
            ring = RingWriter(Path(d), keep_files=5, dlt=DLT_NOFCS)
            ring.write(frame(1_700_000_000.0)); ring.close()
            path = ring.current_path
            path.write_bytes(b"not a capture at all" * 5)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                ring2 = RingWriter(Path(d), keep_files=5, dlt=DLT_NOFCS)
                ring2.write(frame(1_700_000_002.0)); ring2.close()
            self.assertEqual(out.getvalue(), f"[threadwatch] {path.name}: 100 bytes with no usable pcap header; "
                                             "starting the hour's file over\n")
            with open(path, "rb") as fh:
                self.assertEqual([round(f.ts) for f in PcapStreamReader(fh)], [1_700_000_002])
            # An empty file (a run killed between open and header) is started over without comment.
            path.write_bytes(b"")
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                ring3 = RingWriter(Path(d), keep_files=5, dlt=DLT_NOFCS)
                ring3.write(frame(1_700_000_003.0)); ring3.close()
            self.assertEqual(out.getvalue(), "")
            with open(path, "rb") as fh:
                self.assertEqual([round(f.ts) for f in PcapStreamReader(fh)], [1_700_000_003])


if __name__ == "__main__":
    unittest.main()
