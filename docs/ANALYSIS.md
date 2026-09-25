# Analyzing captures

The ring pcaps open directly in Wireshark (link type IEEE 802.15.4 TAP —
per-frame RSSI, LQI and channel included). Payloads are stored encrypted,
exactly as received (the recorder applies the key on read and never
writes it into a pcap); MAC headers are cleartext and are enough for
every technique below — all of which were used to solve a real incident.

Timestamps are the radio's, carried on the host's epoch. The dongle
stamps each frame and the recorder keeps the intervals between them,
managing only the offset between the dongle's clock and the host's: it is
corrected by at most a millisecond per captured second, which is well
clear of crystal drift and far too small to distort an interval, and an actual
host wall/monotonic clock discontinuity or backwards radio timestamp is
stepped and logged (`capture clock re-anchored`). Queue latency alone
never triggers a step, even when a backlog spans many seconds. So a burst that arrives at Python in a rush, behind a disk stall or
a busy CPU, still reads as the seconds of traffic it was: every interval
measurement below, and the detector's own periodicity, depends on that.
Give Wireshark the key (docs/CREDENTIALS.md, last section) and MLE,
6LoWPAN and CoAP dissect too.

## Wireshark / tshark filter cookbook

Your own network's PAN ID is in every frame; find it once
(`wpan.src_pan` on any data frame) and substitute below.

| Question | Filter |
| --- | --- |
| Any foreign 802.15.4 network on my channel? | `wpan.src_pan && wpan.src_pan != 0x4e21` |
| Who is scanning/joining? | `wpan.frame_type == 0x0 \|\| (wpan.frame_type == 0x3 && wpan.cmd == 0x07)` (beacons, beacon requests) |
| What one device sent under its extended address | `wpan.src64 == 66:41:7f:e1:10:ed:69:50` |
| ...and under its short one (add its 0x address) | `wpan.src64 == 66:41:7f:e1:10:ed:69:50 \|\| wpan.src16 == 0x3401` |
| Sleepy children polling their parents | `wpan.frame_type == 0x3 && wpan.cmd == 0x04` |
| Traffic converging on one node (e.g. a hub) | `wpan.dst16 == 0x8400` |

**`wpan.src64` alone is not everything one device sent.** A device sends
from its extended address while it attaches and from the short address
its parent gave it afterwards, and for a sleepy end device that short
address carries the bulk of what it sends, polls included. Filtering on
the 64-bit source alone therefore shows a working sleepy device as nearly
silent, and hides the unanswered polls that say its parent has stopped
answering.

Find the short address the device holds now -- `threadwatch report`, the
review pages, or `wpan.src16` on frames next to one of its extended-source
frames -- and add it to the filter. Two cautions come with it: a short
address is unique within one PAN and is reassigned when a device
re-attaches, so an old one in a long capture may be somebody else by the
end, and a device that rotates its extended address has more than one
64-bit source over the same window.

For attribution the recorder has already done, rather than a filter you
have to keep current, use `threadwatch device "<name>"`: it resolves short
sources back to the extended address by MAC nonce and counts only frames
the network key vouches for.

Useful tshark one-liners:

```bash
# frames per 10 s (spot floods):
tshark -r f.pcap -T fields -e frame.time_epoch |
  awk '{print int($1/10)}' | uniq -c

# top talkers:
tshark -r f.pcap -T fields -e wpan.src64 | grep -v '^$' | sort | uniq -c | sort -rn | head

# retransmission rate: a frame repeated by the same sender with the same
# sequence number within two seconds is a MAC retry. Sorting src+seq and
# counting duplicates cannot tell one from a sequence number coming round
# again hours later, and gives no denominator to be a rate of, so keep the
# timestamps, keep the order, and count against the frames read. Short and
# extended sources are both here: a sleepy device sends from its short one.
tshark -r f.pcap -T fields -e frame.time_epoch -e wpan.src64 -e wpan.src16 -e wpan.seq_no |
  awk -F'\t' '$4 != "" { k = $2 $3 "/" $4; if (k in t && $1 - t[k] < 2) r++; t[k] = $1; n++ }
              END { printf "%d retries in %d frames (%.1f%%)\n", r, n, n ? 100*r/n : 0 }'
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

1. `threadwatch devices` — unknown addresses with frame counts,
   reception quality (RSSI at the sniffer) and first/last-seen.
2. Power-cycle the suspect device; watch which address goes silent and
   returns (`threadwatch devices` again, or live in Wireshark).
3. Record the mapping in `config/devices.json`. Keep old addresses —
   some devices (Apple TVs) rotate their extended address.

## Replaying a capture

`bin/threadwatch replay file.pcap` runs the whole pipeline over a pcap
(a ring file, a snapshot's hour, a capture from another dongle) and
prints one JSON object on stdout (everything the run says for itself —
`credentials: loaded`, a replayed counter, an unreadable state file —
goes to stderr, so the output pipes into `jq`). Several files, or a directory of them
(the ring, a snapshot), are one run in name order, which for ring files
is hour order: a silence or a storm that spans two hourly files is judged
once, across the boundary, as the recorder judged it.
`replay --snapshot <name or label>` reads a saved snapshot with the
inventory and state saved in it ("Snapshots", below). A capture that keeps the FCS on each
frame (link type 195, or TAP with an FCS-type field) is read with it
stripped, so its secured frames decrypt and its MLE messages verify
as the ring's own do; the FCS itself is not checked:

| field | meaning |
| --- | --- |
| `file`, `files`, `frames`, `duration_s` | what was read: the path (null for several), every path in order, the frame count, first to last timestamp |
| `partition` | the partition id and leader as of the last frame, as `threadwatch status` shows them (null without MLE traffic) |
| `detector` | the storm detector's final state: baseline, the last windows, `storm_active`, `alerts_sent` |
| `events` | every event the pipeline would have logged, in order, in the event log's record format (docs/ALERTING.md) |
| `crypto` | the decryption counters and `key_sequence` (docs/OPERATIONS.md, "Reading threadwatch status"): all zero decrypted means the key does not fit this capture |

It is read-only in every direction. The pipeline runs in its ephemeral
mode: it starts from an empty last-seen table (so the first frame from
every device is a `device_first_seen`, and no `device_quiet` refers to
history from before the file), writes nothing under `data/state`, browses
no mDNS, saves nothing, and sends nothing to any alert sink; the events
are collected in memory and printed. Running it against a live recorder's
ring file, on the recorder itself, disturbs neither the recorder nor the
household. One difference from live: the storm detector's own alert
cooldown is zeroed, so its `alerts_sent` counts every storm in the file
rather than one per window. The `phase_locked_storm` events in the list
are not affected -- they keep the `[detect] alert_cooldown_s` cadence
(never under a minute) the recorder would have logged them at, which is
what makes a replay's event list comparable with the day it replays.

## Snapshots

`threadwatch snapshot <label>` saves the ring before it rolls over, and so
does the recorder itself when `[record] snapshot_on_critical` is set and
any event of `critical` severity fires — `phase_locked_storm` is the only
one today (at most once per six hours, counted from the newest automatic
snapshot on disk). Automatic snapshots are capped by
`[record] keep_snapshots` (4 by default): the oldest of the ones the
recorder took go before each new snapshot is taken, told apart by the
`trigger` in their manifests rather than by their labels, so a snapshot
you saved by hand and called `auto-anything` is still yours to delete. One whose Home Assistant logs
are still being fetched is left until the next. `-1` keeps every automatic snapshot,
and `0` takes none of them at all — the critical event is still logged
and still alerts, and `threadwatch snapshot <label>` still saves by hand. Snapshots you saved by hand are never
pruned, so delete them yourself with `threadwatch snapshots --delete`. A
snapshot that would leave the ring less room than it still needs is
refused, with a `snapshot_skipped` warning saying so.

Each snapshot is one directory:

    data/snapshots/20260901T031500_storm-at-noon/
      threadwatch-20260825-04.pcap ... threadwatch-20260901-03.pcap   every ring file, as it was
      threadwatch-20260825-04-annex.pcap ...                          and every further radio's, by label
      manifest.json          what the bundle holds: threadwatch version and commit, when and why it
                             was saved, channel and PAN, the hours the packets span, every file
                             with its size, and the commands that read it
      devices.json           the inventory as it was: the names to judge these packets by
      config.toml            the configuration in force at the time (a record: it is not loaded when
                             the snapshot is read, see below), with every url, header, command, body, token,
                             topic, password and key blanked to "<redacted>" at whatever depth it
                             was written — a body template goes whole, because a form-encoded
                             receiver is authenticated inside it (credentials.toml, alerts.env and
                             ha.env are never copied). Written back out from the parsed file, so the settings are
                             all here but your own comments and layout are not (comments can contain
                             secrets too). Invalid TOML is replaced by a fixed placeholder
      status.json            the recorder's status at the time
      last-seen.json         the last-seen table: first/last heard, frames, RSSI per address
      observed-names.json    SRP hostnames harvested from the mesh
      frames-by-hour.json    the frame counts behind the daily summary
      border-routers.json    each border router's hostname, address and retired addresses
      device-rotations.json  each address a device was seen to move to, and from which (docs/ALERTING.md,
                             device_address_changed)
      blind-spans.json       when the recorder was not listening, as far as a silence still reached
      retransmissions.json   the retransmission detector's baseline and open elevation
      storm.json             the storm detector's windows, onsets and last page
      key-generations.json   the highest key generation heard, the one before, who was heard
                             first under it and the origin candidates
                             (docs/ALERTING.md, key_sequence_advanced)
      events/                a copy of the whole event log, one file per day
      ha-map.json            with [ha_availability]: HA device id -> address, names and entities (the link
                             the availability check uses; devices.json itself carries nothing of HA's)
      ha-availability.json   with [ha_availability]: the episodes open when the snapshot was saved
      ha-logs/<slug>.log.gz  with [ha_logs] enabled: the Home Assistant add-on logs for the snapshot's
                             window, one gzip per add-on (core_openthread_border_router,
                             core_matter_server), journal lines with a UTC wall-clock stamp
      ha-logs.json           what arrived: status (complete, partial, failed, skipped, or fetching
                             while a copy runs), the window requested, and per add-on the file,
                             lines, the received window, gap_before_s (how far the journal had
                             already rolled past the start), any error, and attempts. With
                             [ha_logs] archive on the logs are one file per UTC hour instead,
                             ha-logs/<slug>/<YYYYMMDD-HH>.log.gz, and each hour says where it
                             came from: archive (copied from data/ha-logs/, no HA needed), live
                             (fetched for this snapshot: the current partial hour, or an hour the
                             archive was still missing) or lost (it rolled out of HA's journal
                             before anything could fetch it)

The manifest lists the logs among its `files` and summarises `ha-logs.json`
under `ha_logs`; a snapshot that never asked for logs (`[ha_logs]` off) has
neither. `threadwatch snapshots` marks a snapshot that has them `+ha-logs`
(`+ha-logs partial` or `failed` when it does not have them whole).

**The add-on logs.** The border router's own view of the mesh is what
closes an incident (a `ChannelAccessFailure` beside a flood window, a
Matter node going unreachable beside a `key_lag` page), and Home
Assistant's journal keeps it for about 11.5 hours with the OTBR at log
level info, so every snapshot copies it while it exists. The logs are
added *after* the snapshot is final: a slow or failed fetch never delays,
invalidates or removes the ring copy, and the recorder retries a failed or
partial fetch at 15 min, 1 h and 4 h after the snapshot while the journal
can still have the window (`[ha_logs] retry`). What to know when reading
one:

- Every line starts with the journal's wall-clock stamp, **in UTC**
  (`2026-09-13 22:09:43.197 homeassistant app_core_openthread_border_router[697]: ...`),
  while ring files are named by local hour and Wireshark shows local time.
  To set a log line beside a frame, convert one side: `date -u -d
  @<frame epoch>` gives the journal's form of a pcap timestamp, and
  `TZ=UTC` in front of `tshark -t ad` prints frames in the journal's zone.
- The OTBR's own uptime stamp (`4d.03:52:00.671`) follows the prefix and is
  kept: it is what the add-on's other diagnostics quote.
- `received` in `ha-logs.json` is the first and last stamp that arrived;
  `gap_before_s` above zero means the journal had already dropped the start
  of the window. Raising the OTBR's log level fills the journal faster and
  shortens its retention for every add-on, the Matter Server's included.
- The token, the network key in any spelling and the values in
  `alerts.env` are scrubbed from the text before it is written; a
  `<redacted>` marks where one stood.
- **The archive** (`[ha_logs] archive = true`) is how a snapshot taken a day
  after an incident still has the border router's log for it: the
  recorder fetches every whole UTC hour into `data/ha-logs/` two minutes
  after it ends, keeps as many hours as the ring does, and a snapshot
  copies the hours covering its whole ring span from there, instantly and
  without HA, fetching live only the current partial hour and any hour the
  archive still lacks. Hours HA was down for are retried every 15 minutes
  (one request per pass while it stays down) and recorded as lost once the
  journal cannot have them; `ha-logs-archive.json` under `data/state/` and
  the `ha_logs_archive` entry of `threadwatch status` say where the archive
  stands. Whether a full HA host reboot keeps the journal from before the
  reboot is not yet verified; until it is, treat hours not archived before
  a reboot as possibly unrecoverable.

```bash
SNAP=data/snapshots/20260901T031500_storm-at-noon
zcat "$SNAP"/ha-logs/core_openthread_border_router.log.gz | grep -c ChannelAccessFailure
zcat "$SNAP"/ha-logs/core_openthread_border_router.log.gz | awk '$1" "$2 >= "2026-09-01 06:55"' | head
```

The name is the time it was saved (local, `YYYYMMDDTHHMMSS`) and the label
reduced to filename-safe characters: letters, digits, `.`, `_` and `-`,
with any run of anything else replaced by `-` (`storm at noon` becomes
`storm-at-noon`; an empty label becomes `snapshot`). Automatic ones are
labelled `auto-` and the event that called for it
(`auto-phase_locked_storm`), and the manifest's `trigger` names that event
too. The ring file being written is copied as it is, so
its last record can be cut short; readers stop cleanly there.
A copy still running is built under `data/snapshots/.staging/` and
renamed into place once whole; one cut short by a restart stays there,
where the listing never sees it, and the recorder deletes it at its next
start. A copy still running when the recorder starts (one taken by hand that
overlaps a restart) holds a lock on it and is left to finish.

Nothing prunes a snapshot you saved by hand: each one is the size of the
ring (about 1.2 GB for a week at rest) and stays until
`threadwatch snapshots --delete <name or label>` removes it. The
automatic ones are the exception, capped by `[record] keep_snapshots` as
above. `threadwatch snapshots` and the `/snapshots`
page list them with the hours their packets cover, and a day page says
when a snapshot holds that day's packets after the ring has let it go.

A snapshot is read as a whole, with what was saved in it:

```bash
bin/threadwatch replay --snapshot storm-at-noon              # every hour as one run: detector + events
bin/threadwatch device "Office AQ" --snapshot storm-at-noon  # one device across the whole span
bin/threadwatch device "Office AQ" --snapshot storm-at-noon --hours 6   # its last six hours
SNAP=data/snapshots/20260901T031500_storm-at-noon
mergecap -w "$SNAP.pcap" "$SNAP"/*.pcap && wireshark "$SNAP.pcap"   # the week in one Wireshark window
mergecap -I none -w "$SNAP.pcapng" "$SNAP"/*-04*.pcap               # two radios' copies of one hour, one
                                                                    # interface each (frame.interface_id)
```

With several radios an hour is one file per radio, each holding that
radio's copies with its own RSSI, stamped on one timeline: `replay` and
`device` read them together and merge the copies as the recorder did,
and `mergecap -I none` keeps them apart in Wireshark by interface.

`--snapshot` takes the directory name, the label as typed at the time,
or a path to the directory. Names come from the snapshot's own
`devices.json` and `border-routers.json`, and `device`'s history from its
copy of the event log: a snapshot read after a device rotated its
address, or was renamed, is still judged by what was true when it was
saved. `device` marks each silence with how much of it the recorder was not
listening for (from the log's coverage, docs/REVIEW.md), so a gap the
recorder slept through is not read as the device's. `--hours` counts
back from the snapshot's newest file, not from now. Nothing is written
to the snapshot or to the live state; the live credentials are used, as
they are the only ones.

The *settings* are the live ones too. What comes from the bundle is what
was saved in it — the names, the state and the event log — while the
detector thresholds, `[quiet] silence_s`, the channel and the configured
PAN come from the `config.toml` this host runs on now. The snapshot's own
`config.toml` is a record of what judged those packets when they were
captured, and is deliberately not loaded: its sinks and URLs are
redacted, and reading a bundle — possibly one somebody else saved — must
not turn a file inside it into settings this host acts on. So a replay
run after you have changed a threshold can reach a different verdict
from the one in the snapshot's event log. To reproduce the original
analysis, compare the two files and line the settings up:

```bash
SNAP=data/snapshots/20260901T031500_storm-at-noon
diff "$SNAP"/config.toml config/config.toml     # what has changed since it was saved
```

The state files are plain JSON
(`python3 -m json.tool "$SNAP"/last-seen.json`), and the copied event log
is what `threadwatch events` would have shown at the time, readable
with `jq` or any JSON-lines tool; `threadwatch events` itself reads only
the live log.

## RSSI

TAP frames carry per-frame RSSI *at the dongle*. If the dongle sits next
to your border router, that approximates what the border router hears —
which is what matters for CCA/channel-access failures. With several
radios every judgement is made on the best ear's RSSI, and each radio's
own average per device is on the devices page and in `threadwatch
device` ("heard by"); the same frame measured by two dongles a few
metres apart differs by ±11 dB frame to frame, so one radio's figure is
a noisier number than it looks. For localization
walks, a laptop + the same dongle in Wireshark, or an ESP32-C6 energy
scanner, works room by room.

### Snapshot capture provenance

New recorder runs save `capture-provenance.json`: the redacted configuration
loaded at startup, loaded inventory, channel/PAN, start time, and cached running
revision. Automatic and separately requested snapshots use this record, so edits
awaiting a restart do not replace the capture settings. The manifest identifies
this as `recorder_start`. It describes that run; a ring spanning several recorder
runs may contain packets captured with earlier settings. For legacy captures
without this record, the manifest labels the inputs as belonging to the snapshot
process and says capture provenance is unavailable. Such inputs are not proof of
what captured the packets. Replay still uses the selected analysis configuration.


### Key advance snapshot pairs and log time ranges

Enable `[record] snapshot_on_key_advance = true` to preserve an advance and
its census automatically (details and failure semantics in
[ALERTING.md](ALERTING.md)). The two manifests carry the same sequence and
first-observation epoch under `key_observation`, and a distinct `phase`.
Keep at least two snapshots to retain both; the usual disk and retention
limits still apply.

New manifests record `capture_window.start_ts` from the earliest first
packet among the ring files, rounded down to a UTC hour. Both live-log
requests and archive selection use this epoch, so another host's timezone,
local midnight, multiple radios and repeated DST hours do not change which
UTC archive hours are selected. Older bundles are read from packet epochs
when available. Unreadable or empty files fall back to local filename
interpretation, explicitly labeled `legacy_local_filename_or_fallback` with
`uncertain_files`; that fallback cannot establish the capture timezone.
The saved epoch bounds the end of the request. The active partial hour is
fetched live; existing complete archive hours are copied locally.

`ha-logs.json` and the manifest expose `window_provenance`, requested epochs,
and per-hour source, received bounds and leading gaps. An archive hour
known to be lost makes the bundle status partial, even when all remaining
fetches finished; terminal lost hours are not retried. A completed HTTP
response does not prove that every log line survived journal retention.
A week of packets cannot recover add-on logs that already rolled away.


### OTBR adoption evidence

`threadwatch otbr-evidence` reads the existing UTC hourly OTBR log archive
without contacting Home Assistant or replaying packets. Use explicit timezone
offsets and a narrow incident window:

```sh
bin/threadwatch otbr-evidence --since 2026-09-17T23:14:58Z --until 2026-09-17T23:15:01Z
bin/threadwatch otbr-evidence --snapshot 20260917T192634_auto-ha_unavailable_burst \
  --since 2026-09-17T23:14:58Z --until 2026-09-17T23:15:01Z --json
```

The extractor selects `KeySeqCntr`, MeshForwarder TREL receives, security
receive failures, and received Parent Request / Child ID Request messages.
JSON retains original UTC timestamps, source paths and line numbers, peer
identifiers and two surrounding lines on either side. A key-change record
links preceding TREL receives within one second (up to 32 candidates). This
is temporal evidence, not proof of the receiver's update path. Update class
and the peer's preceding adoption path remain unknown. Missing packets do
not imply TREL, and security failures do not prove link re-establishment.

Each source has separate coverage metadata and read status. Missing files,
truncated gzip streams, pending/lost archive hours, and absent coverage
metadata are explicit. `fetch_complete` means the saved metadata reports a
finished fetch, not that the journal retained all traffic. Partial evidence
survives a truncated stream. The current, unarchived hour is reported missing;
this command never fetches it implicitly. Extraction is bounded to seven
days, 256 MiB of decompressed text, 8 KiB per line, and 1,000 matched records
by default (`--limit` can raise this to 10,000). A limit is reported, not
silently treated as a complete result. Only the hourly archive layout is
supported; older single-file add-on exports need separate inspection.

Optional `[otbr]` inventory (below) travels in snapshots as
`otbr-inventory.json`. A log peer's RLOC can be associated with an extended
MAC observed in a router/neighbor table and the TREL table, only when both
observations precede the event and are at most 15 minutes old. The sample's
source and individual table timestamps stay attached. A later inventory
cannot establish a historical RLOC assignment; stale or missing identities
remain unknown. This corroboration does not change trusted packet state,
parent relationships, key-lag decisions or device names.
