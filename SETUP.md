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
script download it into `.nrfutil-bin/` (gitignored) and reuse it. An
`nrfutil` already on your PATH is used only when there is no cached
build and it runs on this machine: an Intel build left behind on an
Apple silicon Mac is skipped, not run. The first run needs network — the launcher fetches about 29 MB of device
commands into `~/.nrfutil` — and nothing after that.

The download is pinned to one Nordic release, and its sha256 is in
`firmware/nrfutil.sha256`. A download that does not match is thrown away
rather than run. Updating the pin: `firmware/README.md`. (The 29 MB of
device commands the launcher fetches afterwards is Nordic's own, and is
not covered by this.)

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

The flash is good when the dongle enumerates as an **nRF 802154
Sniffer** (above): `bin/flash-dongle.sh` lists it itself, and a
`/dev/ttyACM*` / `/dev/cu.usbmodem*` port appears. On the recorder
host, once `INSTALL.md` is done:

```bash
bin/threadwatch doctor    # the "dongle" line names the port; other lines say what is still missing
bin/threadwatch status    # frames_total climbing: the service is capturing already
```

If the service is running (INSTALL.md enables and starts it), `status` is
the check and there is nothing to run by hand. To see capture start for
yourself, stop the service first: two capture processes on one dongle
page the household with false quiet alerts before the second one fails
(docs/OPERATIONS.md, "One capture process per host"):

```bash
sudo systemctl stop threadwatch
bin/threadwatch record    # prints: capturing channel N from /dev/...; Ctrl-C after a few seconds
sudo systemctl start threadwatch
```

`record` needs the Python packages and the Thread network key
(`INSTALL.md`, `docs/CREDENTIALS.md`) and exits before it touches the
dongle without them; that is not a failed flash. `doctor` is read-only
and names each missing piece.

You can also open the pcaps under `data/ring/` in Wireshark — with the
dongle near an active Thread mesh you'll see MLE/data/ack traffic
immediately.

## A second dongle

Flash it the same way; the firmware is per dongle. Then find its USB
serial, which is how the recorder tells the two apart (a port name such
as `/dev/ttyACM1` changes with every replug and re-enumeration; the
serial follows the dongle):

```bash
bin/threadwatch doctor        # with no [record] radios yet: FAIL, "2 nRF 802.15.4 sniffers found (<serial> at /dev/ttyACM0, <serial> at /dev/ttyACM1)"
ls /dev/serial/by-id/         # Linux: usb-Nordic_Semiconductor_ASA_nRF_802154_Sniffer_<serial>-if00
ls /dev/cu.usbmodem*          # macOS: the serial is in the name
```

Name both in `config/config.toml`, and leave `serial_port` unset:

```toml
[[record.radios]]
label = "hub"                        # short: names ring files, events and page columns
serial = "0123456789ABCDEF"
placement = "next to the border router"

[[record.radios]]
label = "annex"
serial = "FEDCBA9876543210"
placement = "upstairs landing, on a 5 m extension"
```

The first is the primary: its ring files keep their plain names, so a
recorder that already has a week of ring keeps it. Restart the service;
`threadwatch status` shows a `radios` block with both, and the status
page a row each. The recorder starts with whichever of them is plugged
in, reports the other as missing and looks for it every minute, and a
dongle that stops delivering while the other hears is reported (`radio_lost`,
a warning) and looked for again, rather than restarting the run
(docs/OPERATIONS.md, "Several radios").

Cabling: the dongle is a USB full-speed device, and USB allows 5 m of
passive cable per segment. One 5 m extension is fine; two chained are
not, and beyond that the options are a powered hub at the end of a 5 m
cable or an active repeater cable (each counts as a hub, five deep at
most). The dongle's bare-PCB plug sits loose in some sockets (above): a
short pigtail with a firm socket at the far end of the extension is
worth having. Keep both dongles a little away from the host itself; a
Pi 4's USB 3 controller is a 2.4 GHz noise source.

Two dongles side by side, on the same host, still each miss 5-12 % of
what the other hears (measured over an hour on a 50-device mesh), so a
second radio adds coverage before it goes anywhere.

## A dongle on another host

A dongle plugged into another machine on the LAN (a second Pi, the one
by the far end of the house) can be one of the recorder's radios too.
On that machine, install threadwatch the same way (INSTALL.md; it needs
no network key, only the channel in its config.toml and the dongle) and
run the relay instead of the recorder:

```bash
bin/threadwatch relay --to recorder-host:9154 --label annex
```

On the recorder, the radio is a `[[record.radios]]` entry with
`source = "tcp"` and the address the relay connects to:

```toml
[[record.radios]]
label = "annex"
source = "tcp"
listen = "192.0.2.10:9154"          # this host's LAN address; the relay connects here
placement = "far end, second Pi"
# serial = "FEDCBA9876543210"       # optional: refuse a relay whose dongle is another
```

The relay streams the dongle's capture as it is, stamped by the
dongle's own clock, and the recorder aligns and merges it like a local
one. A dropped connection is retried with backoff (2 s doubling to 30 s)
and the frames heard meanwhile are dropped and counted; the recorder
reports the radio lost and back. Nothing authenticates the stream, which
is the encrypted frames and their timing without the key: keep `listen`
on a LAN address behind a firewall, or carry it over `ssh -R`. A systemd
unit for the relay is the recorder's with `relay --to ... --label ...`
in place of `record`.

## Other radios

Anything Wireshark-capable can substitute for ad-hoc work (an ESP32-C6
running an energy-scan sketch makes a good walk-around RSSI probe), but
this repo's recorder expects the Nordic sniffer firmware's serial
protocol, i.e. an nRF52840 Dongle / DK.
