# threadwatch

Turn a $10 nRF52840 USB dongle into an always-on Thread network flight
recorder: continuous 802.15.4 packet capture with a rolling ring buffer,
plus a general library of health detectors — so that when *any* device
drops off your mesh, the evidence of why already exists.

The goal is broad Thread diagnosis — RF storms, device-internal radio
death, failed rejoins, parent/partition churn, slow link degradation,
sleepy-device starvation — not one failure mode. It grew out of a real
incident (see docs/ANALYSIS.md) but is built to answer the general
question: *why did this device go offline?*

## What it does

- **Continuous capture** on your Thread channel into hourly pcap files,
  keeping a rolling week (configurable). About 7 MB/hour for a 50-node
  mesh at rest; budget 30 MB/hour for storms.
- **A health event log** (one JSON-lines file per day) fed by several detectors:
  - devices going quiet / returning (a quiet without a rejoin points at the
    device rather than the radio);
  - foreign-PAN frames and join-scan bursts;
  - traffic floods and phase-locked periodicity (the storm signature);
  - MAC retransmission-rate elevation, attributed to the sender and target;
  - slow link degradation: a device still talking but heard well below
    its usual level, the precursor of a silence with no rejoin;
  - sleepy-device starvation: a child polling a parent that no longer
    answers, which never shows up as a silence.
  A daily summary event (frames, devices heard, quiet and unknown ones,
  event counts) says the recorder is still watching.
  Per-device RSSI trend, ACK-success rate and poll cadence are tracked too
  and shown by `threadwatch why`, not logged as events.
  Warning/critical events go to any number of alert sinks (plain HTTP with
  headers and a body template, or a local command), so Home Assistant,
  ntfy, Gotify, Discord and friends all work; heartbeats let Gatus,
  Healthchecks.io or Uptime Kuma page when the recorder itself dies
  (docs/ALERTING.md).
- **`threadwatch why <device>`** — reconstructs one device's story from
  the ring: hour-by-hour cadence, RSSI, ACKs, silences, and rejoin
  attempts. This is the "why did X go offline"
  command; `--hours 6` reads only the recent ring files, which on a Pi is
  the difference between seconds and minutes. The device's episodes from
  the event log (kept long after the packets roll off) follow, so a
  repeat offender shows as one.
- **Device tracking without a controller** — including HomeKit-only
  Thread devices that never appear in Home Assistant. `threadwatch
  report` lists quiet devices and unknown addresses to label. "Quiet"
  means one thing everywhere (the alert, the report, the review pages):
  the recorder heard nothing from the device for `[quiet] silence_s` (30
  min by default) while it was itself up and listening. Apple hubs,
  which take a new Thread address on every reboot, are followed over
  mDNS and keep their names without anyone editing the inventory.
- **Decryption** (`docs/CREDENTIALS.md`): the recorder needs the Thread
  network key and does not start without it. It decrypts MLE and 6LoWPAN
  on the fly, which is where sleepy devices' identities, rejoin attempts,
  poll starvation, the partition and its leader, and SRP-based
  auto-naming live. The pcaps are stored exactly as received, so the key
  is applied on read and payloads at rest stay encrypted.
- **Incident freeze**: `threadwatch freeze my-label` snapshots the ring
  buffer before it rolls over; with `freeze_on_critical` in config.toml
  the recorder does it by itself when a storm fires (the one critical
  event today), at most once per six hours. `threadwatch incidents`
  lists and deletes them.
- **Offline analysis**: `threadwatch replay file.pcap` runs the whole
  pipeline over any capture; pcaps also open in Wireshark (see
  docs/ANALYSIS.md for a filter cookbook and the storm case study).

## What it deliberately does not do

- **No key in the pcaps.** Frames are written exactly as received and
  decrypted on read. The network key lives in one owner-only file on the
  capture host and is never logged or written anywhere else.
- **No controller dependency.** Home Assistant integration is an
  optional bonus (docs/HOME-ASSISTANT.md), not a requirement.

## Hardware

- Nordic nRF52840 Dongle (PCA10059) — the radio.
- Any always-on Linux box for the recorder: a Raspberry Pi 4 is plenty, so
  is a NAS or mini PC via Docker (docs/DOCKER.md); macOS works for
  portable/desk use.
- Placement matters: put the dongle near your border router so captures
  reflect what *its* radio hears.

## Quick start

1. `SETUP.md` — flash the dongle with the sniffer firmware, once, from
   the recorder host itself or any 64-bit Linux or Mac machine (or with
   Nordic's Programmer app anywhere).
2. `INSTALL.md` — set up the recorder host: clone, one setup script,
   systemd units; Docker and Raspberry-Pi-from-scratch variants included.
3. `cp config/config.example.toml config/config.toml` and set your
   channel; optionally seed `config/devices.json` with your device names.
4. `bin/threadwatch capture` (or enable the systemd unit).
5. `bin/threadwatch doctor` says whether the box is fit to record.
6. When something feels wrong: `bin/threadwatch status`, and
   `bin/threadwatch freeze` before the evidence rolls off.

## Naming devices (the human-readable problem)

802.15.4 frames carry extended addresses, not names, and Thread devices
use randomized addresses (Apple TVs rotate them over time — record every
address you've seen per device, the inventory format supports it).
`threadwatch report` surfaces unknown addresses with how well the
sniffer hears them and first/last-seen times; identify a
device by power-cycling it and watching which address disappears and
returns, then name it:

    bin/threadwatch adopt 66417fe110ed6950 "Office Air Quality"
    bin/threadwatch report --suggest    # ready-to-paste entries for every unknown

`adopt` appends to `config/devices.json` (an existing name gains the
address, which is how a rotation is recorded); `--suggest` prefills names
from SRP hostnames, and flags an unknown
address that appeared just as a named device's last address fell silent
as probably that device's new address, with the `adopt` line to run. If
Home Assistant is your Thread controller, `threadwatch import` fills
devices.json from it and from the LAN's border routers, and
credentials.toml too (docs/HOME-ASSISTANT.md).

## Repository layout

    threadwatch/   the Python package
      pcap.py      classic-pcap I/O + 802.15.4 MAC header parsing
      pipeline.py  the shared per-frame health pipeline (detectors, stats)
      detect.py    flood / phase-lock storm detector
      crypto.py    optional Thread decryption (MLE, 6LoWPAN, SRP names)
      events.py    append-only event log, one file per day
      review.py    events -> episodes, day index, device summaries
      web.py       read-only review pages (threadwatch web)
      alerts.py    alert sinks (http/command/ntfy preset) + heartbeats
      names.py     address->name inventory, last-seen tracking
      why.py       per-device history reconstruction
      doctor.py    preflight checks (threadwatch doctor)
      capture.py   live daemon (ring buffer) + replay
      cli.py       command-line interface
    vendor/        Nordic's sniffer extcap module (BSD, unmodified)
    firmware/      sniffer firmware hex + prebuilt DFU package
    bin/           threadwatch CLI shim, flash-dongle.sh
    systemd/       service unit templates (capture, web review)
    Dockerfile, compose.yaml   the container alternative (docs/DOCKER.md)
    config/        examples for config.toml and devices.json
    docs/          analysis cookbook, alerting, Docker, Home Assistant extension
