# Reviewing what happened

Alerts are for things that need a look now. Everything else lands in the
event log, and the review pages are how you read it back later: what
happened on a day, and what one device has been doing.

    bin/threadwatch web            # http://<host>:8080/, or [web] in config.toml

`setup-host.sh` installs it as `threadwatch-web.service`, a separate
read-only process from capture, so a page bug can never cost frames. There
is no authentication: keep it on your LAN or behind your own proxy.

## Pages

- **/** and **/day/YYYY-MM-DD**: the day's *episodes* with previous / next
  links and a strip of recent days with their event counts. Whether the
  packets for that day still exist (ring files last a week; frozen
  incidents last forever) is shown at the top. Today's page opens with a
  *right now* card: devices quiet at this moment, devices whose signal
  is down, and unnamed addresses; any day that has a daily summary shows
  it under that. Today's page reloads itself every minute.
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
  `?only=unknown|quiet|marginal|down|foreign|routers|children` narrows
  it and `?sort=last|rssi|frames` orders it (longest unheard, weakest,
  busiest); the links at the top of the page set both. `/api/devices`
  takes the same parameters.
- **/device/<addr>** or **/device/<name>**: one device's history across
  every day, as episodes, merged over every address it has used (a
  rotating device is several addresses with one story), with a card per
  address: last heard, signal level against its usual, frames. Part of a
  name works; a text that matches several names offers the choice.
- **/status**: the daemon's status file in prose (alive, last frame,
  channel and port, this run's frames, partition and
  which device leads it (linked, once its RLOC16 has been matched),
  storm detector, crypto counters) plus storage: ring size and hourly
  rate, incidents and event log size, and free disk against what a full
  ring still needs (keep_files hours at the measured rate, and no more
  than keep_gb when set; the doctor's disk check uses the same figure).
- **/incidents**: every frozen incident with when it was frozen, the
  hours its packets cover, and its size. Day pages link to it.
- **/api/status** (with a `storage` block), **/api/incidents**,
  **/api/day/YYYY-MM-DD**, **/api/devices**, **/api/device/<addr or name>**:
  the same data as JSON, for Home Assistant or anything else. The device
  response carries `addr` and `last_seen` (the primary address and its
  last-seen row, as before), `addresses` (every address the name has had),
  `addresses_seen` (a last-seen row per address), `name`, `live` (`role`,
  `rloc16`, `rloc16_ts`, `router_id`, `leader`, `parent`, `parent_addr`)
  and `episodes`. An address or name that resolves to nothing is a 404 with an
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
with its real duration, because the day page reads the previous day too.
The same grouping is available on the command line:

    bin/threadwatch events --episodes            # latest records, grouped
    bin/threadwatch events --day 2026-09-02      # one day, raw
    bin/threadwatch events --device "Apple TV" --severity warning -n 10   # one device, paged things only
    bin/threadwatch why "Office AQ"              # one device: ring narrative, then its episodes

## Storage

`data/state/events/YYYY-MM-DD.jsonl`, one small file per local day, kept
forever (a busy day is a few kilobytes). `threadwatch freeze` copies the
whole directory into the incident. A single `events.jsonl` from before
day rolling is split into day files automatically the first time the
capture daemon (or `threadwatch events`) runs; the web process only reads.
