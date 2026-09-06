# Reviewing what happened

Alerts are for things that need a look now. Everything else lands in the
event log, and the review pages are how you read it back later: what
happened on a day, and what one device has been doing.

    bin/threadwatch web            # http://127.0.0.1:8080/, or [web] in config.toml
    bin/threadwatch web --bind 0.0.0.0 --port 8081     # for one run, over the config

`setup-host.sh` installs it as `threadwatch-web.service`, a separate
read-only process from capture, so a page bug can never cost frames.

There is no authentication of any kind, and the pages carry every device
name and address, each device's role and parent, and the whole event
history, which reads as a per-room, per-hour trace of who was home. So
the default bind is loopback: only the recorder's own host can read them.
To read them from your laptop, forward the port over ssh:

    ssh -L 8080:127.0.0.1:8080 pi@host        # then http://localhost:8080/

Or set `[web] bind = "0.0.0.0"` and keep the port on your LAN or behind a
proxy that authenticates.

## Pages

- **/** and **/day/YYYY-MM-DD**: the day's *episodes* with previous / next
  links and a strip of recent days with their event counts. Under the
  headline card, a coverage bar says whether the recorder was there to
  hear the day ("Coverage", below). Whether the
  packets for that day still exist (ring files last a week; frozen
  incidents last forever) is shown at the top. Today's page opens with a
  *right now* card: devices quiet at this moment (the ones the recorder
  has announced, after `[quiet] silence_s` of silence it was up to hear;
  `threadwatch report` and the daily summary list the same set), devices
  whose signal is down, and unnamed addresses; any day that has a daily
  summary shows it under that. Today's page reloads itself every minute.
  `?min=notice` or `?min=warning` hides the rows below that severity
  (the first-seen bursts, the marginal quiets) and carries through the
  previous / next links.
- **/help**: what every episode kind and severity means; every row on a
  day page carries the same text as a tooltip.
- **/devices**: every address the recorder tracks, with its inventory
  name, its live role, how well the sniffer hears it, when it was last
  heard, and whether it is on your PAN. The role comes from the RLOC16 the
  device was last seen using (the top six bits are a router id; the low
  ten, when non-zero, a child id): *router 33*, *leader · router 60*, or
  *child of Mudroom Air Quality*, each with the address and how long ago
  it was confirmed, since a re-attach changes it and a sleepy child only
  refreshes it when it next talks.
  A border router carries its mDNS identity (instance, vendor, model),
  and an Apple hub's retired address, after a reboot gave it a new one,
  says which address it became.
  `?only=unknown|quiet|marginal|down|foreign|routers|children` narrows
  it and `?sort=last|rssi|frames` orders it (longest unheard, weakest,
  busiest); the links at the top of the page set both. `/api/devices`
  takes the same parameters.
- **/device/<addr>** or **/device/<name>**: one device's history over the
  last 90 days, as episodes, merged over every address it has used (a
  rotating device is several addresses with one story), with a card per
  address: last heard, signal level against its usual, frames. Part of a
  name works; a text that matches several names offers the choice.
  Retention is a year, so anything older is still on its day page; the
  page says where it stopped and `/api/device/` reports the window as
  `episode_days`.
- **/status**: the daemon's status file in prose (alive, last frame,
  channel and port, this run's frames, the threadwatch version and commit
  that is recording, partition and
  which device leads it (linked, once its RLOC16 has been matched),
  storm detector, crypto counters) plus storage: ring size and hourly
  rate, incidents and event log size, and free disk against what a full
  ring still needs (keep_files hours at the measured rate, or keep_gb
  plus one hour when set, since the hour being written is never pruned;
  the doctor's disk check uses the same figure).
- **/incidents**: every frozen incident with when it was frozen, the
  hours its packets cover, and its size. Day pages link to it.
- **/api/status** (with a `storage` block), **/api/incidents**,
  **/api/days**, **/api/day/YYYY-MM-DD**, **/api/devices**,
  **/api/device/<addr or name>**:
  the same data as JSON, for Home Assistant or anything else. The day
  response carries `coverage`: the segments of the day the recorder was
  not listening (`state` `blind`) or may not have been (`uncertain`),
  each with `start`, `end`, `cause` and a `note`. `/api/days`
  is the day strip: one row per day that has an event file, newest first,
  with `day`, `total` and a count per severity (`info`, `notice`,
  `warning`, `critical`), so a sensor that wants "warnings today" reads
  one row instead of paging through `/api/day/`. The device
  response carries `addr` and `last_seen` (the address heard most recently
  and its last-seen row, whichever address or name the request named: a
  rotating device is described by the address it is using now), `addresses`
  (every address the name has had),
  `addresses_seen` (a last-seen row per address), `name`, `live` (`role`,
  `rloc16`, `rloc16_ts`, `router_id`, `leader`, `parent`, `parent_addr`),
  `episode_days` (how far back `episodes` goes) and `episodes`. An address or name that resolves to nothing is a 404 with an
  `error` field, as is an ambiguous name.

## Episodes, not records

The raw log is the wrong unit for people, so the pages group it:

| records | episode |
| --- | --- |
| `device_quiet` ... `device_returned` | one row: *X quiet for 42m* (or *still quiet*) |
| `retransmission_elevation` x N, same sender and target | one row with the count and the worst rate |
| `possible_foreign_pan` x N, same PAN and source | one row with the count |
| `mle_rejoin_attempt` x N, same device | one row listing the MLE commands seen |
| `device_first_seen` burst (daemon start) | one row: *24 devices first seen* |
| `poll_starvation` ... `poll_answered` | one row: *X polls unanswered for 12m* (or *still unanswered*) |
| `rssi_degradation` ... `rssi_recovered` | one row: *X signal down 9 dB for 2h10m* (or *still down*) |
| `partition_or_leader_change`, `phase_locked_storm`, `daily_summary` | one row each, always |

A quiet spell that started yesterday and ended today appears on both days
with its real duration, because the day page reads a month either side of
the day it shows (an episode older than that shows from its first record
inside the window).
The same grouping is available on the command line:

    bin/threadwatch events --episodes            # latest records, grouped
    bin/threadwatch events --day 2026-09-02      # one day, raw
    bin/threadwatch events --device "Apple TV" --severity warning -n 10   # one device, paged things only
    bin/threadwatch why "Office AQ"              # one device: ring narrative, then its episodes

## Coverage

A silence on a day page has two possible explanations: the device said
nothing, or nobody was there to hear it. The recorder cannot tell them
apart after the fact unless it kept track of itself, so every start logs
a `recorder_started` event saying when the last frame before it was
heard, and how and when the run before it ended (from the note each exit
path leaves in `data/state/last-exit.json`; a power cut or a kill leaves
none, and the start says so). A forward step of the host clock logs
`clock_step`, and a half hour of frames from other PANs only logs
`configured_pan_silent`.

The day page draws these as a bar across the day: green while the
recorder was listening, red where it was not (**blind**: not running, or
a stretch of wall-clock time the clock jumped over), amber where it was
running but may not have heard anything (**uncertain**: no frames from
the last one to the exit the stall watchdog forced, or frames from other
PANs only), blank for the rest of today. One line per gap follows, with
its cause. On today's page the daemon's status file adds the live tail:
a recorder that is down or hearing nothing right now has not logged that
yet. A row whose span overlaps a red gap says how much of it the recorder
was off for ("recorder off 14m of this"): a device quiet for an hour
with the recorder off for fifty minutes of it is not much evidence
against the device. `threadwatch events --day` prints the same gaps
before the day's records.

Days before the first `recorder_started` on record say "coverage: not
recorded" rather than showing a clean bar, since a start that was not
logged cannot be told from a day without one. A stall (three minutes
without frames) cannot say whether the channel was quiet or the dongle
had stopped hearing, which is why that stretch is amber, not red.

## Storage

`data/state/events/YYYY-MM-DD.jsonl`, one small file per local day (a
busy day is a few kilobytes), kept for `[events] keep_days` (a year by
default; 0 keeps them for ever) and pruned by the capture daemon at start
and once a day. `threadwatch freeze` copies the whole directory into the
incident. A single `events.jsonl` from before
day rolling is split into day files automatically the first time the
capture daemon (or `threadwatch events`) runs; the web process only reads.
