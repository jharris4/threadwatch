#!/usr/bin/env python3

# Copyright (c) 2019, Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form, except as embedded into a Nordic
#    Semiconductor ASA integrated circuit in a product or a software update for
#    such product, must reproduce the above copyright notice, this list of
#    conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of Nordic Semiconductor ASA nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# 4. This software, with or without modification, must only be used with a
#    Nordic Semiconductor ASA integrated circuit.
#
# 5. Any software provided in binary form under this license must not be reverse
#    engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import sys
import os

is_standalone = __name__ == "__main__"


if is_standalone:
    sys.path.insert(0, os.getcwd())

import re
import signal
import struct
import threading
import time
import logging
from argparse import ArgumentParser
from binascii import a2b_hex
from serial import Serial, SerialException
from serial.tools.list_ports import comports
from multiprocessing import Queue, Process, freeze_support
from dataclasses import dataclass
from threading import Thread
from enum import IntEnum


@dataclass
class SnifferPacket:
    content: bytes
    timestamp: int
    lqi: int
    rssi: int

@dataclass
class ControlPacket:
    content: bytes


@dataclass
class ExitEvent:
    reason: str = ""


# threadwatch local change: a serial line the packet regex does not match
# used to be dropped by a bare except with nothing counting it. A flight
# recorder that drops frames without counting them cannot tell you it
# did, so the reader sends one of these instead and the consumer, which
# runs in the recorder's own process, keeps the total.
@dataclass
class ParseFailure:
    pass


class DLT(IntEnum):
    # Various options for pcap files: http://www.tcpdump.org/linktypes.html
    DLT_IEEE802_15_4_NOFCS = 230
    DLT_IEEE802_15_4_TAP = 283


class Nrf802154Sniffer:

    # USB device identification.
    NORDICSEMI_VID = 0x1915
    SNIFFER_802154_PID = 0x154B

    # Helpers for Wireshark argument parsing.
    CTRL_ARG_CHANNEL = 0
    CTRL_ARG_LOGGER = 6

    # Pattern for packets being printed over serial.
    # threadwatch local change: was searched in the bytes' repr with
    # nothing after the time required, so a line that lost bytes and ran
    # into the next one still parsed, its time cut short or made of the
    # next line's digits (2026-10-11, a stamp 4.6 days off). The firmware
    # prints `received: %s power: %d lqi: %u time: %llu\n`: the time is
    # unsigned and ends the line, so only whitespace may follow it.
    RCV_REGEX = r"received:\s+([0-9a-fA-F]+)\s+power:\s+(-?\d+)\s+lqi:\s+(\d+)\s+time:\s+(\d+)\s*$"
    # threadwatch local change: a PSDU with its FCS is 5 (an ACK) to 127
    # bytes; RSSI is an int8 in dBm, nothing a dongle hears is above
    # +20; LQI is a uint8. A value outside these is a garbled line.
    PSDU_HEX_MIN, PSDU_HEX_MAX = 10, 254
    RSSI_MIN, RSSI_MAX = -128, 20
    LQI_MAX = 255
    # threadwatch local change: microseconds since the dongle booted; 10**15
    # is 31 years. A time with more digits is a garbled line, and one that
    # reached pcap_packet raised there and ended the capture.
    TIME_MAX = 10**15
    # threadwatch local change: the radio driver's NRF_802154_NO_TIMESTAMP.
    # "Due to a race condition, the timestamp may be invalid", and the
    # firmware prints it as is: a real frame reading as heard at boot.
    NO_TIMESTAMP = 0
    # threadwatch local change: frames whose last two bytes are checked
    # against the CRC once per run, to learn whether this firmware passes
    # the real FCS (the driver says it "may be modified by the hardware").
    FCS_SAMPLE = 1000

    TIMER_MAX = 2**32

    def __init__(self, connection_open_timeout=None):
        self.queue = Queue()
        self.logger = logging.getLogger(__name__)
        self.dev = None
        self.channel = 11
        self.control_in = None
        self.control_out = None
        self.fifo = None
        self.dlt = DLT.DLT_IEEE802_15_4_TAP
        self.processes: list[Process] = []
        self.windows_mode = is_standalone and os.name == "nt"
        self.first_local_timestamp = None
        self.first_sniffer_timestamp = None
        self.thread = None
        # threadwatch local change: serial lines the packet regex did not
        # match, counted for status.json. Written by the consumer thread
        # in this process, read by the watchdog.
        self.parse_failures = 0
        # threadwatch local change: frames pcap_or_none could not record.
        self.unrecordable = 0

    def pcap_or_none(self, content, timestamp, lqi, rssi):
        """threadwatch local change: the pcap record, or None (counted as a
        parse failure) for a stamp the record cannot hold, which raised
        out of the consumer loop and ended the capture for one frame."""
        try:
            return self.pcap_packet(content, self.dlt, self.channel, rssi, lqi, self.correct_time(timestamp))
        except (struct.error, OverflowError, ValueError):
            self.parse_failures += 1
            self.unrecordable += 1
            n = self.unrecordable
            if n & (n - 1) == 0:                     # the 1st, 2nd, 4th, 8th...: never a flood
                sys.stderr.write(f"[nrf802154_sniffer] frame {n} this run stamped {timestamp} us cannot be "
                                 "recorded; dropped\n")
            return None

    def correct_time(self, sniffer_timestamp):
        """
        Sniffer timestamps are relative to device boot.
        Wireshark expects the packets to have UNIX timestamp.
        This function converts sniffer timestamps to UNIX time.
        """
        if self.first_local_timestamp is None:
            # First received packets - set the reference time and convert to microseconds.
            self.first_local_timestamp = int(time.time()*(10**6))
            self.first_sniffer_timestamp = sniffer_timestamp
            return self.first_local_timestamp
        else:
            return self.first_local_timestamp - self.first_sniffer_timestamp + sniffer_timestamp

    @classmethod
    def serial_reader(
        cls,
        serial_port: str,
        queue: Queue,
    ) -> None:
        serial = Serial(serial_port, exclusive=True)
        # threadwatch local change: the raw serial line of a frame whose
        # dongle time went backwards (with the line before it), and of a
        # line the packet pattern does not match, go to stderr, so a
        # garbled stamp leaves its bytes in the journal. At most one line
        # of each kind a minute, and never an exception: one raised here
        # would read as a disconnected dongle below.
        last_ts, last_line, failures, said = None, b"", 0, {}
        # threadwatch local change: when the last frame was read, for a
        # frame without a timestamp; and the FCS sample (see FCS_SAMPLE).
        last_mono, no_time, fcs_seen, fcs_ok = None, 0, 0, 0

        def say(kind, msg):
            try:
                now = time.monotonic()
                if now - said.get(kind, -60.0) >= 60.0:
                    said[kind] = now
                    sys.stderr.write(f"[nrf802154_sniffer] {serial_port}: {msg}\n")
                    sys.stderr.flush()
            except Exception:
                pass

        while True:
            try:
                value = serial.readline()
                try:
                    packet = cls.parse_packet(value)
                except:
                    # threadwatch local change: was `...`, so a garbled
                    # line was a dropped frame nothing recorded.
                    queue.put(ParseFailure())
                    failures += 1
                    say("garbled", f"serial line {failures} this run the packet pattern does not match: "
                                   f"{value[:300]!r}")
                    continue
                now = time.monotonic()
                if packet.timestamp == cls.NO_TIMESTAMP:
                    # threadwatch local change: see NO_TIMESTAMP. Stamped
                    # from when it was read, after the last frame, less a
                    # second: a USB batch can read it later than it was
                    # heard, and a stamp past the next frame's would read
                    # as the dongle's time going back. Early is harmless
                    # (late is never suspect). The first frame of a run
                    # has nothing to go by and is dropped, as an anchor at
                    # boot would skew every stamp.
                    no_time += 1
                    if last_ts is None:
                        queue.put(ParseFailure())
                        say("no_time", f"the run's first frame carries no timestamp; dropped: {value[:300]!r}")
                        continue
                    since = max(1, int((now - last_mono) * 1e6) - 1_000_000)
                    packet = SnifferPacket(content=packet.content, timestamp=last_ts + since,
                                           lqi=packet.lqi, rssi=packet.rssi)
                    say("no_time", f"frame {no_time} this run without a timestamp (the radio driver's race); "
                                   f"stamped from its arrival: {value[:300]!r}")
                queue.put(packet)
                if last_ts is not None and packet.timestamp < last_ts:
                    say("backwards", f"dongle time went back {last_ts - packet.timestamp} us: {value[:300]!r} "
                                     f"after {last_line[:300]!r}")
                last_ts, last_line, last_mono = packet.timestamp, value, now
                if fcs_seen < cls.FCS_SAMPLE:
                    fcs_seen += 1
                    fcs_ok += cls.fcs_matches(value)
                    if fcs_seen == cls.FCS_SAMPLE:
                        say("fcs", f"the last two bytes match the CRC in {fcs_ok} of {fcs_seen} frames"
                                   + (": the firmware passes the real FCS" if fcs_ok == fcs_seen else ""))
            except:
                queue.put(ExitEvent(f"Sniffer device {serial_port} was disconnected."))
                # threadwatch local change: was a fall-through, so a
                # disconnected dongle span here filling the queue with
                # ExitEvents at whatever rate the failing read returned.
                return

    @classmethod
    def fcs_matches(cls, value: bytes) -> bool:
        """threadwatch local change: does the line's PSDU end in its own
        802.15.4 FCS (CRC-16/KERMIT, low byte first)? Never raises."""
        try:
            m = re.search(cls.RCV_REGEX, value.decode("ascii", "replace"))
            data = bytes.fromhex(m.group(1))
            crc = 0
            for b in data[:-2]:
                crc ^= b
                for _ in range(8):
                    crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
            return crc == int.from_bytes(data[-2:], "little")
        except Exception:
            return False

    @classmethod
    def parse_packet(cls, value: bytes) -> SnifferPacket:
        text = value.decode("ascii", "replace") if isinstance(value, (bytes, bytearray)) else str(value)
        m = re.search(cls.RCV_REGEX, text)
        if m:
            hexdata = m.group(1)
            rssi = int(m.group(2))
            lqi = int(m.group(3))
            timestamp = int(m.group(4))
            if not (cls.PSDU_HEX_MIN <= len(hexdata) <= cls.PSDU_HEX_MAX and cls.RSSI_MIN <= rssi <= cls.RSSI_MAX
                    and lqi <= cls.LQI_MAX and timestamp <= cls.TIME_MAX):
                raise Exception()
            packet = a2b_hex(hexdata[:-4])
            return SnifferPacket(
                content=packet, timestamp=timestamp, lqi=lqi, rssi=rssi
            )
        else:
            raise Exception()

    @classmethod
    def control_reader(
        cls,
        control_in: str,
        queue: Queue,
    ) -> None:
        with open(control_in, "rb", 0) as control_in_fifo:
            try:
                while True:
                    value = control_in_fifo.read()
            except:
                queue.put(ExitEvent("Wireshark connection lost."))

    @staticmethod
    def parse_control(value: bytes) -> ControlPacket:
        return ControlPacket(content=value)

    def stop_sig_handler(self, *args, **kwargs):
        """
        Deprecated method kept for compatibility.
        Use stop_thread instead when running in non-standalone mode.
        """
        self.stop_thread()

    def _stop_and_exit(self, *args, **kwargs):
        self._stop()
        exit(0)

    def stop_thread(self):
        """
        Stop the threaded capture.
        """
        self._stop()
        self.queue.put(ExitEvent())
        self.thread.join()

    def _stop(self):
        for process in self.processes:
            process.kill()
            process.join()

        self.processes = []

        try:
            if self.dev:
                serial = Serial(self.dev, exclusive=True, timeout=0.1)
                serial.write(b"\r\n")
                serial.write(b"sleep\r\n")
                serial.flush()
                serial.read(100000)
                serial.reset_input_buffer()
                serial.close()
        except SerialException:
            pass

    @staticmethod
    def extcap_interfaces():
        """
        Wireshark-related method that returns configuration options.
        :return: string with wireshark-compatible information
        """
        res = []
        res.append(
            "extcap {version=0.8.0}{help=https://github.com/NordicSemiconductor/nRF-Sniffer-for-802.15.4}{display=nRF Sniffer for 802.15.4}"
        )
        for port in comports():
            if (
                port.vid == Nrf802154Sniffer.NORDICSEMI_VID
                and port.pid == Nrf802154Sniffer.SNIFFER_802154_PID
            ):
                res.append(
                    "interface {value=%s}{display=nRF Sniffer for 802.15.4}"
                    % (port.device,)
                )

        res.append(
            "control {number=%d}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}"
            % Nrf802154Sniffer.CTRL_ARG_LOGGER
        )

        return "\n".join(res)

    @staticmethod
    def extcap_dlts():
        """
        Wireshark-related method that returns configuration options.
        :return: string with wireshark-compatible information
        """
        res = []
        res.append(
            "dlt {number=%d}{name=IEEE802_15_4_TAP}{display=IEEE 802.15.4 TAP}"
            % DLT.DLT_IEEE802_15_4_TAP
        )
        res.append(
            "dlt {number=%d}{name=IEEE802_15_4_NOFCS}{display=IEEE 802.15.4 without FCS}"
            % DLT.DLT_IEEE802_15_4_NOFCS
        )

        return "\n".join(res)

    @staticmethod
    def extcap_config(option):
        """
        Wireshark-related method that returns configuration options.
        :return: string with wireshark-compatible information
        """
        args = []
        values = []
        res = []

        args.append(
            (
                0,
                "--channel",
                "Channel",
                "IEEE 802.15.4 channel",
                "selector",
                "{required=true}{default=11}",
            )
        )
        args.append(
            (
                1,
                "--metadata",
                "Out-Of-Band meta-data",
                "Packet header containing out-of-band meta-data for channel, RSSI and LQI",
                "selector",
                "{default=none}",
            )
        )

        if len(option) <= 0:
            for arg in args:
                res.append(
                    "arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s" % arg
                )

            values = values + [
                (0, "%d" % i, "%d" % i, "true" if i == 11 else "false")
                for i in range(11, 27)
            ]

            values.append((1, "ieee802154-tap", "IEEE 802.15.4 TAP", "true"))
            values.append((1, "none", "None", "false"))

        for value in values:
            res.append("value {arg=%d}{value=%s}{display=%s}{default=%s}" % value)
        res.append(
            "control {number=4}{type=button}{role=logger}{display=Log}{tooltip=Show capture log}"
        )
        return "\n".join(res)

    def pcap_header(self):
        """
        Returns pcap header to be written into pcap file.
        """
        header = bytearray()
        header += struct.pack("<L", int("a1b2c3d4", 16))
        header += struct.pack("<H", 2)  # Pcap Major Version
        header += struct.pack("<H", 4)  # Pcap Minor Version
        header += struct.pack("<I", int(0))  # Timezone
        header += struct.pack("<I", int(0))  # Accurancy of timestamps
        header += struct.pack("<L", int("000000ff", 16))  # Max Length of capture frame
        header += struct.pack("<L", self.dlt)  # DLT
        return header

    @staticmethod
    def pcap_packet(
        frame: bytes, dlt, channel: int, rssi: int, lqi: int, timestamp: int
    ) -> bytes:
        """
        Creates pcap packet to be seved in pcap file.
        """
        pcap = bytearray()

        caplength = len(frame)

        if dlt == DLT.DLT_IEEE802_15_4_TAP:
            caplength += 28

        pcap += struct.pack("<L", timestamp // 1000000)  # Timestamp seconds
        pcap += struct.pack("<L", timestamp % 1000000)  # Timestamp microseconds
        pcap += struct.pack("<L", caplength)  # Length captured
        pcap += struct.pack("<L", caplength)  # Length in frame

        if dlt == DLT.DLT_IEEE802_15_4_TAP:
            # Append TLVs according to 802.15.4 TAP specification:
            # https://github.com/jkcko/ieee802.15.4-tap
            pcap += struct.pack("<HH", 0, 28)
            pcap += struct.pack("<HHf", 1, 4, rssi)
            pcap += struct.pack("<HHHH", 3, 3, channel, 0)
            pcap += struct.pack("<HHI", 10, 1, lqi)

        pcap += frame

        return bytes(pcap)

    def append_process(self, target, args):
        # Given all the multiplatform quirks, using subprocesses is the
        # best bet at making things somewhat clean.
        self.processes.append(Process(target=target, args=args, daemon=True))

    def start_processes(self):
        for process in self.processes:
            process.start()

    def _start(
        self, fifo, dev, channel, metadata=None, control_in=None, control_out=None
    ):
        """
        This method starts the sniffer capture and blocks until the process is killed.
        """
        self.channel = channel
        self.dev = dev
        self.control_in = control_in
        self.control_out = control_out
        self.fifo = fifo

        if metadata == "ieee802154-tap":
            # For Wireshark 3.0 and later
            self.dlt = DLT.DLT_IEEE802_15_4_TAP
        else:
            self.dlt = DLT.DLT_IEEE802_15_4_NOFCS

        serial = Serial(self.dev, exclusive=True, timeout=0.1)
        serial.write(b"sleep\r\n")
        serial.write(b"shell echo off\r\n")
        serial.flush()
        serial.readall()
        serial.write(b"channel " + bytes(str(self.channel).encode()) + b"\r\n")
        serial.write(b"receive\r\n")
        serial.flush()
        serial.close()

        self.append_process(target=self.serial_reader, args=(self.dev, self.queue))

        if self.control_in:
            self.append_process(
                target=self.control_reader, args=(self.control_in, self.queue)
            )

        if self.control_out:
            fh = open(self.control_out, "wb", 0)

        self.start_processes()

        try:
            with open(self.fifo, "wb", 0) as fifo:
                fifo.write(self.pcap_header())
                fifo.flush()

                while packet := self.queue.get():
                    match packet:
                        case SnifferPacket(content, timestamp, lqi, rssi):
                            pcap = self.pcap_or_none(content, timestamp, lqi, rssi)
                            if pcap is not None:
                                fifo.write(pcap)
                        case ParseFailure():
                            # threadwatch local change: see ParseFailure.
                            self.parse_failures += 1
                        case ExitEvent(reason):
                            if reason:
                                sys.stderr.write(reason)
                            self._stop()
                            break
        except BrokenPipeError:
            self._stop()

    def start_threaded(
        self, fifo, dev, channel, metadata=None, control_in=None, control_out=None
    ):
        """
        This method starts the sniffer capture in a separate thread.
        Use .stop_threaded to end the process.
        """
        self.thread = Thread(target=self._start, args=(fifo, dev, channel, metadata, control_in, control_out))
        self.thread.start()

    def extcap_capture(
        self, fifo, dev, channel, metadata=None, control_in=None, control_out=None
    ):
        """
        Deprecated method kept for compatibility.
        Use .start_threaded instead.
        """
        self.start_threaded(fifo, dev, channel, metadata, control_in, control_out)

    @staticmethod
    def parse_args():
        """
        Helper methods to make the standalone script work in console and wireshark.
        """
        parser = ArgumentParser(
            description="Extcap program for the nRF Sniffer for 802.15.4"
        )

        parser.add_argument(
            "--extcap-interfaces",
            help="Provide a list of interfaces to capture from",
            action="store_true",
        )
        parser.add_argument(
            "--extcap-interface", help="Provide the interface to capture from"
        )
        parser.add_argument(
            "--extcap-dlts",
            help="Provide a list of dlts for the given interface",
            action="store_true",
        )
        parser.add_argument(
            "--extcap-config",
            help="Provide a list of configurations for the given interface",
            action="store_true",
        )
        parser.add_argument(
            "--extcap-reload-option", help="Reload elements for the given option"
        )
        parser.add_argument(
            "--capture", help="_Start the capture routine", action="store_true"
        )
        parser.add_argument(
            "--fifo",
            help="Use together with capture to provide the fifo to dump data to",
        )
        parser.add_argument(
            "--extcap-capture-filter",
            help="Used together with capture to provide a capture filter",
        )
        parser.add_argument(
            "--extcap-control-in", help="Used to get control messages from toolbar"
        )
        parser.add_argument(
            "--extcap-control-out", help="Used to send control messages to toolbar"
        )

        parser.add_argument("--channel", help="IEEE 802.15.4 capture channel [11-26]")
        parser.add_argument(
            "--metadata", help="Meta-Data type to use for captured packets"
        )

        result, unknown = parser.parse_known_args()

        if result.capture and not result.extcap_interface:
            parser.error("--extcap-interface is required if --capture is present")

        return result

    def __str__(self):
        return "{} ({}) channel {}".format(type(self).__name__, self.dev, self.channel)

    def __repr__(self):
        return self.__str__()


if is_standalone:
    freeze_support()
    args = Nrf802154Sniffer.parse_args()

    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(message)s", level=logging.INFO
    )

    sniffer_comm = Nrf802154Sniffer()

    if args.extcap_interfaces:
        print(sniffer_comm.extcap_interfaces())

    if args.extcap_dlts:
        print(sniffer_comm.extcap_dlts())

    if args.extcap_config:
        if args.extcap_reload_option and len(args.extcap_reload_option) > 0:
            option = args.extcap_reload_option
        else:
            option = ""
        print(sniffer_comm.extcap_config(option))

    if args.capture and args.fifo:
        channel = int(args.channel) if args.channel else 11
        signal.signal(signal.SIGINT, sniffer_comm._stop_and_exit)
        signal.signal(signal.SIGTERM, sniffer_comm._stop_and_exit)
        sniffer_comm._start(
            args.fifo,
            args.extcap_interface,
            channel,
            args.metadata,
            args.extcap_control_in,
            args.extcap_control_out,
        )
