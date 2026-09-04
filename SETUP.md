# Dongle setup (nRF52840 Dongle / PCA10059)

One-time: flash the dongle with Nordic's **nRF Sniffer for 802.15.4**
firmware. The firmware and a pre-built DFU package ship in `firmware/`
(provenance in `firmware/README.md`). The dongle keeps the firmware
across power cycles, so this is done once, from whichever machine is
convenient, and need not be the recorder host.

## Flash

```bash
bin/flash-dongle.sh
```

It runs on **64-bit Linux (x86_64 or aarch64) and both Mac
architectures** — the recorder host itself included, so a 64-bit
Raspberry Pi can flash its own dongle. It uses Nordic's `nrfutil`
binary: set `NRFUTIL` to point at one you already have, or let the
script download it into `.nrfutil-bin/` (gitignored) and reuse it. The
first run needs network — the launcher fetches about 29 MB of device
commands into `~/.nrfutil` — and nothing after that.

Nordic ships no `nrfutil` for 32-bit ARM or Windows. On those, flash
`firmware/sniffer-dfu.zip` with the Programmer app in nRF Connect for
Desktop; the physical steps below are the same.

The script waits for the bootloader, flashes, and tells you what to do.
The physical steps it will ask of you:

1. **Enter the bootloader**: press the small **sideways** reset button —
   it's near the ID sticker, aimed at the board edge (NOT the white
   button on top). The red LED pulses slowly in bootloader mode.

That is the only one. `nrfutil` returns the dongle to application mode
itself, so no unplug/replug is needed (the pip `nrfutil` this script
used to drive did need it).

Afterwards the dongle enumerates as **"nRF 802154 Sniffer"**
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
