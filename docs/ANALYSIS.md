# Analyzing captures

The ring pcaps open directly in Wireshark (link type IEEE 802.15.4 TAP —
per-frame RSSI, LQI and channel included). Payloads are stored encrypted,
exactly as received (the recorder applies the key on read and never
writes it into a pcap); MAC headers are cleartext and are enough for
every technique below — all of which were used to solve a real incident.
Give Wireshark the key (docs/CREDENTIALS.md, last section) and MLE,
6LoWPAN and CoAP dissect too.

## Wireshark / tshark filter cookbook

Your own network's PAN ID is in every frame; find it once
(`wpan.src_pan` on any data frame) and substitute below.

| Question | Filter |
| --- | --- |
| Any foreign 802.15.4 network on my channel? | `wpan.src_pan && wpan.src_pan != 0x4e21` |
| Who is scanning/joining? | `wpan.frame_type == 0x0 \|\| (wpan.frame_type == 0x3 && wpan.cmd == 0x07)` (beacons, beacon requests) |
| Everything one device sent | `wpan.src64 == 66:41:7f:e1:10:ed:69:50` |
| Sleepy children polling their parents | `wpan.frame_type == 0x3 && wpan.cmd == 0x04` |
| Traffic converging on one node (e.g. a hub) | `wpan.dst16 == 0x8400` |

Useful tshark one-liners:

```bash
# frames per 10 s (spot floods):
tshark -r f.pcap -T fields -e frame.time_epoch |
  awk '{print int($1/10)}' | uniq -c

# top talkers:
tshark -r f.pcap -T fields -e wpan.src64 | grep -v '^$' | sort | uniq -c | sort -rn | head

# retransmission rate (same src+seq within moments = MAC retry):
tshark -r f.pcap -T fields -e wpan.src64 -e wpan.seq_no | sort | uniq -c | sort -rn | head
```

## The storm signature (what the detector automates)

A phase-locked subscription storm looks like:

- frames/10 s jumping from a calm baseline (~250 for a 45-node mesh) to
  1,200–2,000, in bursts lasting 30–50 s;
- bursts recurring with a **stable period** (~80.5 s observed; the
  detector accepts 40–180 s);
- MAC retransmission (duplicate src+seq) rate tripling inside bursts;
- traffic converging on one MAC destination — the subscribing hub.

Root cause pattern: a controller (observed: Apple TV HomeKit hub) loses
connectivity and re-subscribes to every Matter accessory simultaneously,
phase-locking their max-interval report timers. Proven cure: power-cycle
that hub while the channel is otherwise calm; on re-subscription over a
quiet channel the timers spread out naturally.

## Identifying a device without a controller

1. `threadwatch report` — unknown addresses with frame counts,
   reception quality (RSSI at the sniffer) and first/last-seen.
2. Power-cycle the suspect device; watch which address goes silent and
   returns (`threadwatch report` again, or live in Wireshark).
3. Record the mapping in `config/devices.json`. Keep old addresses —
   some devices (Apple TVs) rotate their extended address.

## Replaying a capture

`bin/threadwatch replay file.pcap` runs the whole pipeline over one pcap
(a ring file, an incident's hour, a capture from another dongle) and
prints one JSON object on stdout (`credentials: loaded` goes to stderr,
so the output pipes into `jq`):

| field | meaning |
| --- | --- |
| `file`, `frames`, `duration_s` | what was read: the path, the frame count, first to last timestamp |
| `partition` | the partition id and leader as of the last frame, as `threadwatch status` shows them (null without MLE traffic) |
| `detector` | the storm detector's final state: baseline, the last windows, `storm_active`, `alerts_sent` |
| `events` | every event the pipeline would have logged, in order, in the event log's record format (docs/ALERTING.md) |
| `crypto` | the decryption counters and `key_sequence` (docs/OPERATIONS.md, "Reading threadwatch status"): all zero decrypted means the key does not fit this capture |

It is read-only in every direction. The pipeline runs in its ephemeral
mode: it starts from an empty last-seen table (so the first frame from
every device is a `device_first_seen`, and no `device_quiet` refers to
history from before the file), writes nothing under `data/state`, browses
no mDNS, freezes nothing, and sends nothing to any alert sink; the events
are collected in memory and printed. Running it against a live recorder's
ring file, on the recorder itself, disturbs neither the recorder nor the
household. One difference from live: the storm detector's alert cooldown
is zeroed, so every `phase_locked_storm` in the file shows rather than
the first per half hour.

## Frozen incidents

`threadwatch freeze <label>` copies the ring before it rolls over, and so
does the recorder itself when `[capture] freeze_on_critical` is set and a
`phase_locked_storm` fires (at most once per six hours, counted from the
newest automatic incident on disk). Each incident is one directory:

    data/incidents/20260901T031500_storm-at-noon/
      threadwatch-20260825-04.pcap ... threadwatch-20260901-03.pcap   every ring file, as it was
      status.json            the daemon's status at freeze time
      last-seen.json         the last-seen table: first/last heard, frames, RSSI per address
      observed-names.json    SRP hostnames harvested from the mesh
      frames-by-hour.json    the frame counts behind the daily summary
      events/                a copy of the whole event log, one file per day

The name is the freeze time (local, `YYYYMMDDTHHMMSS`) and the label
reduced to filename-safe characters: letters, digits, `.`, `_` and `-`,
with any run of anything else replaced by `-` (`storm at noon` becomes
`storm-at-noon`; an empty label becomes `incident`). Automatic ones are
labelled `auto-storm`. The ring file being written is copied as it is, so
its last record can be cut short; readers stop cleanly there.
`border-routers.json` is not copied today. A directory ending in
`.partial` is a copy still running or one cut short by a restart; the
listing ignores it and the daemon deletes it at its next start.

Nothing prunes an incident: each one is the size of the ring (about
1.2 GB for a week at rest) and stays until `threadwatch incidents --delete
<name or label>` removes it. `threadwatch incidents` and the `/incidents`
page list them with the hours their packets cover, and a day page says
when an incident holds that day's packets after the ring has let it go.

No command reads an incident as a whole. `replay` and `why --pcap` each
take one pcap, so loop over the directory, or merge first:

```bash
INC=data/incidents/20260901T031500_storm-at-noon
for f in "$INC"/*.pcap; do bin/threadwatch replay "$f"; done     # detector + events per hour
bin/threadwatch why "Office AQ" --pcap "$INC"/threadwatch-20260901-02.pcap   # one device, one hour
mergecap -w "$INC.pcap" "$INC"/*.pcap && wireshark "$INC.pcap"    # the week in one Wireshark window
```

`replay` judges each file on its own, so a silence or a storm that spans
two hourly files is seen twice or split; for one device across the whole
span, `why` with the merged file is the better tool. The state files are
plain JSON (`python3 -m json.tool "$INC"/last-seen.json`), and the copied
event log is what `threadwatch events` would have shown at freeze time,
readable with `jq` or any JSON-lines tool; `threadwatch events` itself
reads only the live log.

## RSSI

TAP frames carry per-frame RSSI *at the dongle*. If the dongle sits next
to your border router, that approximates what the border router hears —
which is what matters for CCA/channel-access failures. For localization
walks, a laptop + the same dongle in Wireshark, or an ESP32-C6 energy
scanner, works room by room.
