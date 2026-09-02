# thread-debugger

Turn a $10 nRF52840 USB dongle into an always-on Thread network flight
recorder: continuous 802.15.4 packet capture with a rolling ring buffer,
plus live detection of the traffic-storm signature that takes Thread
meshes down — so that when devices drop, the evidence of *why* already
exists.

Born from a real incident (2026-09-01) where a nine-hour "RF
interference" hunt turned out to be the home's own HomeKit hub
re-subscribing every Matter accessory in lock-step after a switch
reboot, phase-locking their report timers into channel-saturating
floods every 80 seconds. With this recorder running, that diagnosis is
one `threadwatch replay` instead of an evening.

## What it does

- **Continuous capture** on your Thread channel into hourly pcap files,
  keeping a rolling week (configurable). ~30 MB/hour for a ~45-node mesh.
- **Storm detection**: watches for periodic traffic floods (the
  phase-locked-subscription signature) and POSTs a JSON alert to any
  webhook (Home Assistant automation, ntfy, etc.).
- **Device last-seen tracking** from cleartext MAC headers — including
  HomeKit-only Thread devices that never appear in Home Assistant.
  `threadwatch report` lists devices gone quiet, and unknown addresses
  to help you label them.
- **Incident freeze**: `threadwatch freeze my-label` snapshots the ring
  buffer before it rolls over.
- **Offline analysis**: `threadwatch replay file.pcap` runs the same
  detection over any capture; the pcaps open in Wireshark for deep dives
  (see docs/ANALYSIS.md for a filter cookbook).

## What it deliberately does not do

- **No credentials.** Everything here works from unencrypted 802.15.4
  MAC headers. The Thread network key is never needed or stored; frame
  payloads in the pcaps remain encrypted.
- **No controller dependency.** Home Assistant integration is an
  optional bonus (docs/HOME-ASSISTANT.md), not a requirement.

## Hardware

- Nordic nRF52840 Dongle (PCA10059) — the radio.
- Any always-on Linux box for the recorder; a Raspberry Pi 4 is plenty
  (macOS works too, for portable/desk use).
- Placement matters: put the dongle near your border router so captures
  reflect what *its* radio hears.

## Quick start

1. `SETUP.md` — flash the dongle with the sniffer firmware (any OS, no
   Nordic desktop apps needed).
2. `INSTALL.md` — set up the recorder host (Raspberry Pi walkthrough).
3. `cp config/config.example.toml config/config.toml` and set your
   channel; optionally seed `config/devices.json` with your device names.
4. `bin/threadwatch capture` (or enable the systemd unit).
5. When something feels wrong: `bin/threadwatch status`, and
   `bin/threadwatch freeze` before the evidence rolls off.

## Naming devices (the human-readable problem)

802.15.4 frames carry extended addresses, not names, and Thread devices
use randomized addresses (Apple TVs rotate them over time — record every
address you've seen per device, the inventory format supports it).
`threadwatch report` surfaces unknown addresses with behavioural hints
(sleepy/polling vs data-heavy) and first/last-seen times; identify a
device by power-cycling it and watching which address disappears and
returns, then add it to `config/devices.json`. If you run Home
Assistant + OTBR, its Thread panel and the OTBR REST API map most
addresses to names for you (see docs/HOME-ASSISTANT.md).

## Repository layout

    threadwatch/   the Python package (stdlib + pyserial only)
    vendor/        Nordic's sniffer extcap module (BSD, unmodified)
    firmware/      sniffer firmware hex + prebuilt DFU package
    bin/           threadwatch CLI shim, flash-dongle.sh
    systemd/       service unit for the Pi
    config/        examples for config.toml and devices.json
    docs/          analysis cookbook, Home Assistant extension
