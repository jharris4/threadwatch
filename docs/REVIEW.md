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
  incidents last forever) is shown at the top.
- **/help**: what every episode kind and severity means; every row on a
  day page carries the same text as a tooltip.
- **/devices**: every address the recorder tracks, with inventory name and
  role, how well the sniffer hears it, when it was last heard, and whether
  it is on your PAN.
- **/device/<addr>**: one device's history across every day, as episodes.
- **/api/status**, **/api/day/YYYY-MM-DD**, **/api/devices**,
  **/api/device/<addr>**: the same data as JSON, for Home Assistant or
  anything else.

## Episodes, not records

The raw log is the wrong unit for people, so the pages group it:

| records | episode |
| --- | --- |
| `device_quiet` ... `device_returned` | one row: *X quiet for 42m* (or *still quiet*) |
| `retransmission_elevation` x N, same sender and target | one row with the count and the worst rate |
| `possible_foreign_pan` x N, same PAN and source | one row with the count |
| `mle_rejoin_attempt` x N, same device | one row listing the MLE commands seen |
| `device_first_seen` burst (daemon start) | one row: *24 devices first seen* |
| `partition_or_leader_change`, `phase_locked_storm` | one row each, always |

A quiet spell that started yesterday and ended today appears on both days
with its real duration, because the day page reads the previous day too.
The same grouping is available on the command line:

    bin/threadwatch events --episodes            # latest records, grouped
    bin/threadwatch events --day 2026-09-02      # one day, raw
    bin/threadwatch why "Office AQ"              # one device: ring narrative, then its episodes

## Storage

`data/state/events/YYYY-MM-DD.jsonl`, one small file per local day, kept
forever (a busy day is a few kilobytes). `threadwatch freeze` copies the
whole directory into the incident. A single `events.jsonl` from before
day rolling is split into day files automatically the first time the
capture daemon (or `threadwatch events`) runs; the web process only reads.
