# Dongle setup (nRF52840 Dongle / PCA10059)

One-time: flash the dongle with Nordic's **nRF Sniffer for 802.15.4**
firmware. Works on Linux (incl. the Pi itself) and macOS — no nRF
Connect for Desktop needed; the firmware and a pre-built DFU package
ship in `firmware/` (provenance in `firmware/README.md`).

## Flash

```bash
bin/flash-dongle.sh
```

The script waits for the bootloader, flashes, and tells you what to do.
The physical steps it will ask of you:

1. **Enter the bootloader**: press the small **sideways** reset button —
   it's near the ID sticker, aimed at the board edge (NOT the white
   button on top). The red LED pulses slowly in bootloader mode.
2. **After flashing: unplug and replug the dongle.** It does not
   re-enumerate by itself after DFU — this is normal.

After replug the dongle enumerates as **"nRF 802154 Sniffer"**
(`lsusb`: Nordic Semiconductor; a `/dev/ttyACM*` / `/dev/cu.usbmodem*`
serial port appears). The firmware persists across power cycles — you
flash once, not per boot.

## Hardware quirks learned the hard way

- The dongle's USB plug is bare PCB and sits loose in some ports/hubs.
  A cheap USB-2 hub powered the bootloader but never enumerated the
  application firmware; a direct port or quality adapter fixed it. If
  the dongle "disappears" after flashing, suspect the connector first.
- If no LED lights at all: it's a connection problem, not firmware.
- Bootloader can always be re-entered with the sideways reset button,
  so you cannot brick it with a bad flash.

## Verify

```bash
bin/threadwatch capture   # should print: capturing channel N from /dev/...
# Ctrl-C after a few seconds; or check frames_total:
bin/threadwatch status
```

You can also open the pcaps under `data/ring/` in Wireshark — with the
dongle near an active Thread mesh you'll see MLE/data/ack traffic
immediately.

## Other radios

Anything Wireshark-capable can substitute for ad-hoc work (an ESP32-C6
running an energy-scan sketch makes a good walk-around RSSI probe), but
this repo's recorder expects the Nordic sniffer firmware's serial
protocol, i.e. an nRF52840 Dongle / DK.
