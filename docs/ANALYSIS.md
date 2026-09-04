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
| Who is scanning/joining? | `wpan.frame_type == 0x0` (beacons/beacon requests) |
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

1. `threadwatch report` — unknown addresses with inventory role,
   reception quality (RSSI at the sniffer) and first/last-seen.
2. Power-cycle the suspect device; watch which address goes silent and
   returns (`threadwatch report` again, or live in Wireshark).
3. Record the mapping in `config/devices.json`. Keep old addresses —
   some devices (Apple TVs) rotate their extended address.

## RSSI

TAP frames carry per-frame RSSI *at the dongle*. If the dongle sits next
to your border router, that approximates what the border router hears —
which is what matters for CCA/channel-access failures. For localization
walks, a laptop + the same dongle in Wireshark, or an ESP32-C6 energy
scanner, works room by room.
