# Alerting and liveness

threadwatch pushes two kinds of signal out of the box, and is deliberately
ignorant of which service is on the other end:

- **Alert sinks** receive events at or above a severity floor (device went
  quiet, retransmissions elevated, partition changed, phase-locked storm).
- **Heartbeats** tell an external monitor "still capturing" on an interval,
  so the monitor can page when the *recorder* dies, not just the mesh.

Both are plain HTTP with optional headers and a body template, so any
receiver that accepts a URL works: Home Assistant, ntfy, Gotify, Discord,
Slack, Pushover, Gatus, Healthchecks.io, Uptime Kuma, Cronitor. A `command`
sink covers everything else.

Configure in `config.toml`; put secrets in `config/alerts.env`; verify with

```sh
bin/threadwatch alert-test              # sends a synthetic warning + one heartbeat push each
bin/threadwatch alert-test --severity critical
bin/threadwatch alert-test --event device_quiet --no-heartbeats   # a named event, sinks only
```

`--event` sets the record's `event` field, so a receiver that routes on
the event name (an HA automation with a condition on it) can be tried
with the real name; `--no-heartbeats` leaves the monitors alone, for
testing a sink without reassuring a heartbeat that should be failing. The
command exits 1 when any delivery fails.

Delivery runs on a background thread, never blocks capture, and never raises:
a dead endpoint costs a journal line, not frames, and the page is not
lost. A send that fails is tried again after 30 s, then 2 min, then 8 min,
then every 10 min, until the record is six hours old, when it is given up
and the journal says so (`given up, the record is 6.2 h old`): a quiet
alert from a morning outage is still news at lunch, a daily summary from
yesterday is not. The age is read immediately before each sink retry as well as after each
failure, so a record that went stale while it waited -- for its retry, for
a sleeping host to wake, behind other deliveries -- is dropped rather than
delivered by an endpoint that has since recovered. Every record still gets
its first attempt however old it is. What a sink still refuses when the recorder stops (a
watchdog restart, a reboot, the house network down with the mesh) is
written to `data/state/alert-spool.jsonl`, and the next start sends it,
less what has gone stale, to the sinks it was for by name. Every record
carries an `id` that is the same on every retry (`{id}` in templates), so
a receiver that keeps what it has seen can drop a repeat of a page that
did arrive; HTTP sinks send it as `Idempotency-Key` as well.

A send that runs out of `timeout_s` is the exception to the schedule: the
request was on the wire before any answer was due, so the receiver may
already have it, and a retry would be a second notification rather than a
redelivery. Those get one more try and are then let go, with the journal
saying why. A refused connection, a name that does not resolve, an error
status and a command that exits non-zero all mean nothing was delivered,
and keep the full schedule. `threadwatch status` and the status page count what this run
delivered, holds for retry, gave up and resumed from the spool;
`threadwatch doctor` warns while a spool is waiting for a start.

## Events

Every event is one JSON record in `data/state/events/YYYY-MM-DD.jsonl`
(one file per local day), and the same record is what sinks receive.
`bin/threadwatch events --day 2026-09-02 --episodes` or the web review
pages (docs/REVIEW.md) are the way to read them back. Fields common to all: `ts` (unix seconds),
`event`, `severity` (`info` < `notice` < `warning` < `critical`).

| event | severity | extra fields |
| --- | --- | --- |
| `device_first_seen` | info | `addr`, `name` |
| `device_returned` | notice | `addr`, `name` |
| `join_scan_activity` | notice | `count_60s`, `src` |
| `address_flood` | warning | `dropped`, `kept`, `note` (something in range is transmitting from ever-new extended addresses; the least-heard unnamed rows were dropped from the device table to keep it bounded, and `device_first_seen` is not emitted while it goes on; once an hour) |
| `possible_foreign_pan` | notice | `pan`, `src`, `dominant_pan`, `note` |
| `dominant_pan_changed` | notice when first guessed, warning when the guess changes | `pan`, `previous`, `frames`, `note` |
| `configured_pan_silent` | warning | `pan`, `heard_frames`, `window_s`, `busiest_pan`, `note` |
| `mle_rejoin_attempt` | notice | `command`, `src`, `name` |
| `device_quiet` | warning, or notice when `reception` is `marginal` | `addr`, `name`, `silent_for_s` (wall clock since the device's last frame, as the pages show it), `unheard_s` (the part the recorder was listening for, the figure judged against `[quiet] silence_s`), `blind_s` (the difference: the recorder's own outage or clock step), `last_seen`, `rssi_dbm`, `reception`, `note`; when something proved the device alive after its last frame, `vouched_ts` and `vouched_by` (`parent`: its parent answered its keep-alive; `ack`: its radio acknowledged a frame) |
| `poll_starvation` | notice when first logged, warning once `[polls] confirm_s` later the polls are still unanswered (`confirmed`); notice only when `reception` is `marginal` or `episode` > 1 | `addr`, `name`, `unanswered_polls`, `since`, `starved_for_s`, `acked_polls`, `rssi_dbm`, `reception`, `episode`, `since_previous_s`, `confirmed`, `parent`, `parent_rloc16`, `parent_addr`, `note` |
| `poll_answered` | notice | `addr`, `name`, `note` |
| `rssi_degradation` | notice | `addr`, `name`, `rssi_dbm`, `reference_dbm`, `drop_db`, `since`, `low_for_s`, `note` |
| `rssi_recovered` | info | `addr`, `name`, `rssi_dbm`, `reference_dbm`, `note` |
| `key_sequence_advanced` | info | `sequence` (the new key generation), `previous` (null the first time a generation is ever heard), `first_sender`, `name`, `rloc16`, `role`, `frame` (`mac_data`, `mac_poll` or `mle:<command>`, whichever was accepted first under it), `since_previous_s`, `note` (says "early" when `[keys] rotation_hours` is set and the rotation came under 90% of it) |
| `key_lag_census` | info | `sequence`, `mesh_generation`, `counts` (devices per generation, fresh ones only), `behind_parent_1`, `behind_parent_2plus`, `routers_behind` (each: `name`, `addr`, `generation`, `lag`, and `parent` / `parent_generation` or `mesh_generation`), `unknown` (no fresh frame: not judged), `note`; `[keys] census_delay_s` after each rotation |
| `key_lag` | warning for a child, critical for a router; notice when `episode` > 1 (reopened within `[keys] rearm_s`) | `addr`, `name`, `role`, `generation`, `parent`, `parent_addr`, `parent_generation` (a child) or `mesh_generation` (a router), `lag`, `since`, `lagged_for_s`, `rssi_dbm`, `reception`, `polls_acked`, `episode`, `since_previous_s`, `note` |
| `key_lag_cleared` | info | `addr`, `name`, `role`, `generation`, `parent`, `parent_addr`, `parent_generation` or `mesh_generation`, `since`, `lagged_for_s`, `rejoined`, `rejoin_ts`, `note`; only after a `key_lag` went out |
| `retransmission_elevation` | notice for the first elevated minute, warning once the rate has stayed up for `[retransmissions] confirm_s` (`confirmed`); notice regardless when one sender-target pair is `top_share` >= 0.5 of the retries (a chronic bad link, not a storm precursor) | `rate`, `baseline`, `addr`, `name`, `top_sender`, `top_target`, `top_share`, `confirmed`, `sustained_s`, `note` |
| `partition_or_leader_change` | warning | `previous`, `current`, each with `partition`, `leader_router` and `leader` (the router id with the device's name once the MLE layer has matched it) |
| `credentials_stale` | warning | `failed`, `note` |
| `clock_step` | info | `step_s` (signed), `note`. The host clock jumped, NTP correcting a boot without an RTC. Forward: silences spanning the jump are not counted against any device. Backward: every timestamp the recorder holds, `last-seen.json` included, is moved back with it |
| `recorder_started` | info after a requested stop or on the first start ever, notice when the last run ended any other way | `cause` (`stopped`, `stalled`, `sniffer_died`, `stream_ended`, `crashed`, `unknown` for a run that left no note: a power cut or a kill, `first_start`), `gap_s` (since the last frame any run heard), `last_frame_ts`, `stopped_ts` (when the last run ended, if it left the note), `exit_code`, `note` |
| `border_router_address_changed` | notice | `addr`, `name`, `previous`, `hostname`, `evidence` (what corroborated the rotation), `note` |
| `border_router_unlisted` | notice | `addr`, `hostname`, `note` |
| `border_router_address_conflict` | warning | `addr`, `name` (the entry devices.json gives the address to), `hostname`, `claimed_by` (the entry the hostname belongs to), `note` |
| `border_router_rotation_unverified` | notice | `addr`, `name`, `previous`, `hostname`, `evidence` (what held, when anything did), `missing` (what did not), `note` |
| `phase_locked_storm` | critical | detector snapshot (`period_s`, `onsets`, ...) |
| `snapshot_saved` | info | `label`, `path`, `ring_files`, `note` (with `[record] snapshot_on_critical`) |
| `snapshot_failed` | warning | `label`, `note` |
| `snapshot_skipped` | warning | `label`, `disk_free`, `ring_bytes`, `ring_needs_bytes`, `note` |
| `snapshots_pruned` | info | `removed`, `note` |
| `snapshot_logs_saved` | info | `label`, `path`, `addons`, `lines` (per add-on), `note`; the HA add-on logs joined an automatic snapshot, or a retry completed them (with `[ha_logs] enabled`) |
| `snapshot_logs_failed` | notice | `label`, `addons`, `errors`, `status` (`failed`, `partial` or `skipped`), `note` (whether and when the recorder retries) |
| `ha_logs_archive_stalled` | notice | `addons`, `pending_hours` (`<slug>/<YYYYMMDD-HH>`, UTC), `since`, `last_error`, `note`; once per outage, when the hourly archive (`[ha_logs] archive`) has had hours pending for an hour |
| `ha_logs_archive_resumed` | info | `archived`, `lost` (hour names), `since`, `note`; once, when the catch-up after an outage completes |
| `ha_unavailable` | warning once a device has been unavailable in Home Assistant for its hold; notice when `muted`, part of a burst (`burst_id`), reopened within `[ha_availability] rearm_s` (`episode` > 1) or `already_unavailable_at_start` | `addr`, `name`, `ha_device_id`, `entities`, `since`, `unavailable_for_s`, `hold_s`, `muted`, `burst_id`, `episode`, `cause` (`key_lag`, `lost_parent`, `silent`, `radio_ok`, `unheard`), the radio evidence (`last_seen`, `silent_for_s`, `rssi_dbm`, `reception`, `starved`, `role`, `parent`, `generation`, `parent_generation`, `rejoin_ts`), `note` (with `[ha_availability] enabled`) |
| `ha_unavailable_burst` | critical | `burst_id`, `devices` (each `name`, `addr`, `since`, `cause`), `count`, `window_s`, `first_since`, `note` (the causes, and "HA or Matter Server side" when most mapped devices dropped at once while the recorder still heard them); once per burst, with the automatic snapshot |
| `ha_available` | info | `addr`, `name`, `ha_device_id`, `since`, `down_for_s`, `rejoined`, `generation`, `note`; only after an `ha_unavailable` went out |
| `ha_unreachable` | notice | `failing_for_s`, `error`, `note`; once, after five minutes of failed polls |
| `ha_reachable` | info | `unreachable_for_s`, `note`; the next poll is a baseline, not transitions |
| `daily_summary` | `[summary] severity` (notice) | `frames_24h`, `devices_heard_24h`, `devices_tracked`, `quiet`, `unknown`, `marginal`, `degraded`, `storm_active`, `events_24h`, `key_generation` (the mesh's), `key_lag_1` and `key_lag_2plus` (device names one, and two or more, generations behind right now), `note` |
| `alert_test` | as requested | `name`, `addr`, `note` (from `alert-test`) |

`name` is null for addresses not in `devices.json`.

`device_quiet` fires after `[quiet] silence_s` of silence (default 30
min). Routers advertise every few seconds and sleepy end devices poll
every few, so from the sniffer's point of view neither is quiet for long
and one window serves both. Silence is what the recorder itself heard,
but a device can be out of its earshot and still on the mesh, and two
things say so: its parent answering its keep-alive (an MLE Child Update
Response is only ever a reply), and its radio acknowledging a frame
addressed to it. Either holds the report until that evidence is as old
as the silence; the event then carries `vouched_ts`/`vouched_by` and the
note says how long it went on, which is also the difference between a
device whose radio kept acknowledging for a minute after its last frame
(a hung stack) and one whose parent answered it for an hour (reception).
Neither counts as hearing the device: `last_seen`, the pages'
"silent for" and `device_returned` stay the recorder's own. Two silences
are deliberately not paged: addresses whose frames carry a foreign PAN id
(someone else's mesh) are never reported, and devices whose average RSSI
at the sniffer is below `[quiet] min_rssi_dbm` (default -82) are logged at
notice severity, because a device at the edge of the sniffer's range drops
out for tens of minutes whenever the link fades.

Which PAN is yours comes from `[network] pan_id` in config.toml (`threadwatch
import` prints it). Without it the recorder guesses: the PAN it has heard
the most frames on, adopted once that is ten frames and replaced only by
one with twice as many. A busier Thread or Zigbee network on the same
channel can win that guess, which would leave your own devices unjudged, so
every adoption or change is a `dominant_pan_changed` event; set `pan_id`
if it names a neighbour. With `pan_id` set, half an hour without a frame on
it while other PANs stay busy is a `configured_pan_silent` warning (repeated
every six hours): the mesh has been re-commissioned or migrated, and every
device counts as foreign until `pan_id` is updated. `threadwatch import`
prints the dataset's PAN and says when it disagrees with the file.

`poll_starvation` is the sleepy-device failure the quiet detector cannot
see: the device keeps polling, so it never goes quiet, but nothing
acknowledges its polls. Ten distinct polls (MAC retries of one poll
share a sequence number and count once) over at least a minute with no
ACK, from a device whose polls were answered before (in this run, or in an
earlier one: the fact is kept with the last-seen rows), log the starvation;
the first acknowledged poll after that logs `poll_answered` (the open
starvation is remembered with the last-seen rows, so a recorder restart in
between still closes it). A device
that just moved to a parent the sniffer cannot hear looks the same from
the sniffer's chair: a `mle_rejoin_attempt` right before it is the tell.

The page waits. The record at the threshold is a notice with `confirmed =
false`, so it is in the log and on the review pages at once, and the
warning follows only if the polls are still unanswered `[polls] confirm_s`
later (default 10 min): a second `poll_starvation` record for the same
device, `confirmed = true`, `starved_for_s` counted from the original start,
folded into the same row on the review pages. The evidence is the first
poll sent after the mark that nobody answers, not a clock: a device that
fell silent and comes back with an answered poll is closed, not paged, and
a recorder that was down across the mark pages from the first unanswered
poll it hears after starting (the pending page is kept with the last-seen
rows). Every starvation in the first days of running that recovered by
itself did so within minutes, while a device that has lost its parent
stays unanswered far longer, so nearly every page this saves is one that
would have been followed by `poll_answered` before you had read it. The
`poll_answered` note says when a starvation closed unconfirmed. `confirm_s
= 0` pages at the threshold, as before, and the records carry no
`confirmed` field.

Two starvations are logged at notice rather than paged, and never
confirmed, for the same reason the quiet detector holds back: the sniffer,
not the device, is the likely cause. A device heard below `[quiet] min_rssi_dbm` has a parent
whose ACKs are heard even less reliably. And an episode that opens within
`[polls] rearm_s` (default 60 min) of the previous one's close is flapping:
a device that really lost its parent gives up after a handful of polls and
rejoins, while one that recovers every few minutes with an ordinary ACK is
sitting where the sniffer only sometimes hears its parent. The record
carries `episode` (1 for the page, counting up through the notices) and
`since_previous_s`; the first episode after the device has stayed answered
for `rearm_s` pages again. The poll's destination is the parent's RLOC16,
so the record names the parent (`parent`, with its address when the
recorder has matched that short address to a device), which is the first
thing to look at: is it the parent that died, or a link the sniffer
cannot hear? The close time is kept with the last-seen rows,
so a restart does not re-page a flapping device.

`key_sequence_advanced`, `key_lag_census`, `key_lag` and `key_lag_cleared`
are the key-generation detectors, for the failure neither of the two above
can see. The mesh rotates its network key on a schedule (OpenThread's
default is 28 days; this mesh has been doing it about every 5.4 days), and
every device follows the rotation the next time it hears the new key in
use. OpenThread accepts a MAC frame only under its own generation, the one
before and the one after. One generation behind is therefore normal: a
device that has not yet followed still hears its parent and is still
heard, and that state can last weeks (a device ignores the next +1 for
most of a rotation period after it last followed). Two behind is a cut-off:
every frame the device sends is dropped by its parent, while the parent's
radio still acknowledges its polls, because the ACK goes out before the
security check. So the device looks alive to the sniffer: it is not quiet,
it is not starving, and it delivers nothing. On 2026-09-13 four devices
went unavailable in Home Assistant this way and nothing alerted.

The recorder reads the generation off every authenticated frame (the
last-seen rows carry it as `counter_seq` and `mle_counter_seq`, with when
it was read). Four records follow from it, and the budget is that a normal
week pages nothing:

- `key_sequence_advanced` (info) is the rotation itself: the first frame
  accepted under a generation above any on record, who sent it and under
  what (`mac_data`, `mac_poll`, `mle:<command>`), and how long after the
  previous rotation. Once per generation, ever: the highest generation is
  kept in `data/state/key-generations.json`, so a restart does not announce
  it again, and a replay (which starts with no record) announces the first
  generation it meets with `previous` null. With `[keys] rotation_hours`
  set, a rotation under 90% of it after the previous one says "early" in
  the note, which is how a rotation the operator did not schedule shows.
- `key_lag_census` (info) comes `[keys] census_delay_s` (default 60 min)
  after each rotation: how many devices are on each generation, the
  children one behind their parent (normal), the children two or more
  behind (cut off), the routers behind the mesh, and the devices with no
  frame fresh enough to judge. It is the roll call to read after a
  rotation; nothing in it pages.
- `key_lag` is the page, once per device per episode. A device whose
  freshest reading is within `[keys] fresh_s` (default 30 min) is judged
  against its live parent's reading, when that is fresh too: the parent is
  the holder of the router id in the device's own RLOC16, as the devices
  page shows it. A router is judged against the mesh's generation (the
  highest any frame has decrypted under, `crypto.key_sequence` in status),
  and only once two routers are fresh on that generation, so one straggler
  frame cannot raise the bar for everyone. A lag of two or more opens an
  episode on the row without a word, and the page waits, as
  `poll_starvation`'s does: it goes out at the first pass after
  `[keys] confirm_s` (default 15 min) in which the device has sent a
  frame past that mark and is still two or more behind. The evidence is a
  frame, not a clock. Warning for a child; critical for a router, which
  also reserves the automatic snapshot, because a router this far behind
  cuts off every child that follows it. The record carries both
  generations, the lag, how long the episode has been open, the parent,
  and `polls_acked`, which is the point: the device still looks alive.
  `confirm_s = 0` pages on the pass that opens the episode.
- `key_lag_cleared` (info) closes an episode that paged: the device was
  heard within one generation of its reference again. `rejoined` says a
  `mle_rejoin_attempt` fell inside the episode, which is what a battery
  pull or a power cycle produces and what the `key_lag` note asks for. An
  episode that closes before its page is dropped silently, so a device
  that catches up inside the window costs nothing.

What is deliberately not judged: a device or a parent with no reading
within `fresh_s` (a silence is `device_quiet`'s story), a device whose role
is not known, a router while fewer than two are on the mesh generation. A
child whose parent changed (a new RLOC16, or the router id taken over by
another device) closes its episode and is judged against the new parent
from the next pass; in practice a re-attach fetches the current key, so the
new reading is within a generation and the episode simply ends. Reception
does not demote the page: the reading is the device's own authenticated
frame, so a marginal signal cannot make it wrong, and a cut-off smoke
detector at -85 dBm still matters; the record carries `reception` all the
same. An episode that reopens within `[keys] rearm_s` (default 60 min) of
its close is logged at notice with `episode` > 1, like a flapping
starvation. Nothing is ever emitted for one generation behind: that would
fire after every rotation. It shows on the devices page, in the census and
in `daily_summary`'s `key_lag_1` instead.

The budget, then: a normal week is about two info records per rotation and
no page. A rotation like 2026-09-13's is one `key_lag` per stranded device
(several devices within a sink's cooldown fold into one digest), one
critical if a router is among them, and info closures as each is power
cycled. If only the critical should reach the phone, give the phone sink
`min_severity = "critical"` or leave `key_lag` out of its `events` list;
the devices page and `threadwatch device` (which prints the generations a
device has sent under, with the first and last frame under each) carry the
rest.

`retransmission_elevation` is the storm precursor: in one minute more than
20% of frames were repeats (same sender and sequence number within 2 s, a
frame whose ACK never came) and that is over twice the baseline, the median
of the last 30 minutes. Interference looks the same in a single minute as a
storm building, and only the duration tells them apart, so the first
elevated minute is a notice with `confirmed = false` and the warning waits
until the rate has stayed up for `[retransmissions] confirm_s` (default 5
min): a second record, `confirmed = true`, with `sustained_s`, folded into
the same row on the review pages. The baseline is frozen for as long as an
elevation lasts (a long one would otherwise raise the median under itself
and end its own alarm), one sub-threshold minute inside an elevation does
not end it, and two do. Whichever record it is, one sender-target pair with
half or more of the retries makes it a notice: a failing link between two
devices, not the mesh. Repeats are held back: an opening notice within 15
min of the last, or a page within 15 min of the last page, is not sent.
`confirm_s = 0` pages at the first elevated minute, as before, and the
records carry no `confirmed` field.

`daily_summary` goes out once per local day, the first time `periodic`
runs at or after `[summary] hour` (default 8; -1 disables). The event log
is the record of whether today's went out: a restart neither repeats it
nor loses it, and a recorder that was down at the hour sends it late. It
is a notice by default, so it lands in the log and the review pages; set
`[summary] severity = "warning"` to have it delivered by the sinks that
page you, or give it a sink of its own with `min_severity = "notice"`.

`rssi_degradation` is the slow version of the same story: the device is
still heard, but its average RSSI at the sniffer has sat more than
`[link] drop_db` (default 8) below its own daily reference for
`[link] hold_s` (default 30 min). The reference is taken once a device has
been heard 200 frames and refreshed once a day, so a drop that lasts a day
becomes the new normal. `rssi_recovered` closes it, either because the
signal came back or because the refresh re-based the reference (the note
says which). Both clocks run only while the device is heard: a silence
longer than `[quiet] silence_s` between its frames counts toward neither
the hold nor the refresh, and a device that has stopped talking is neither
announced degraded on its last level nor re-based to it (`device_quiet`
tells that story). `drop_db = 0` turns the detector off.

`border_router_address_changed` is an Apple hub rebooting: Apple TVs and
HomePods take a new Thread extended address every time. The recorder
asks the LAN over mDNS every `[border_routers] browse_s` (default 10 min)
which address each border router has now, keyed by its stable hostname,
and names the new address from the same devices.json entry; the old
address is retired rather than reported quiet, and `evidence` says what
corroborated that. `border_router_unlisted`,
once per router, is one that matches no entry: `threadwatch import --write`
creates the entry (or `threadwatch name` names it).
`border_router_address_conflict` is that rotation refused: the hostname
belongs to one entry and the address it advertises belongs to another.
mDNS is unauthenticated, so anyone on the LAN can advertise any address
under any hostname, and hearing that address on air proves only that the
device exists, not whose hostname it answers to. The inventory stands and
nothing is renamed or retired; if the device really did move, correct
devices.json. Both need the
recorder to hear the routers' mDNS, which is link-local: the same subnet,
or a network that reflects mDNS between VLANs. `threadwatch doctor` says
whether it can.

`border_router_rotation_unverified` is a rotation believed only as far as
the name. Naming an address and retiring one are separate acts with very
different costs: a wrong name mislabels a row, where a wrong retirement
takes the old address out of the quiet, link and starvation checks for
good, so a device that later dies can never page. The hostname's claim
carries the name across; the radio decides the retirement.

It corroborates when the new address answers to the router id the old one
held: a rebooting router asks the leader for the id it had, and nothing
off the mesh can arrange that. Failing that, two weaker signs together --
the old address stopped as the new one started (they may interleave by
2 min, and the new address must speak within 15 min of the old one's last
frame), and the new address is heard within 10 dB of the level the old one
was, with at least 20 frames behind each average. Those two are
circumstantial: they are a physical signature the LAN cannot arrange, not
proof of identity, and they are bounded tightly for that reason. An
address the mesh happens to supply -- one that joined an hour later, or a
neighbour at a similar level -- should fail them, and the bounds are what
makes that so.

Until then the old address keeps its name and stays judged, so expect it
to report quiet, and each later browse looks again for six hours. Nothing
that turns up after those six hours retires it, corroboration included: by
then the evidence is a coincidence the mesh supplied rather than the
rotation being witnessed. The event itself is emitted once per claim, when
the traffic argues against the claim (the addresses overlapped, the gap
was too long, the levels are far apart, the router id changed) and
otherwise only when the six hours run out -- an address is bound to its
name by its very first frame, which carries no router id and no average
worth comparing, so a real rotation is almost always merely unproven at
first and reporting that would put a notice on every reboot. A later look
that finds the contradiction reports it then: the old address talking on
after the new one started is exactly the sign no first look can see.

To settle it by hand, confirm the rotation into the inventory with
`threadwatch name <new-address> "<name>"` and restart the recorder: a
rotation the operator has vouched for is covered across the entry's
addresses without any retirement. `[border_routers] rotation = "trusted"`
restores the old behaviour, where the advertisement alone retires the old
address.

`snapshot_logs_saved` and `snapshot_logs_failed` report the Home Assistant
add-on logs that join a snapshot with `[ha_logs] enabled` (docs/ANALYSIS.md,
"Snapshots"): the first when the OTBR and Matter Server logs for the
snapshot's window are whole, the second (a notice, so nothing pages) when a
fetch failed or was cut short, saying whether the recorder retries. A
missing log is a record, not an emergency: the packets are already safe,
and the recorder tries again at 15 min, 1 h and 4 h while HA's journal can
still have the window. With `[ha_logs] archive` on, `ha_logs_archive_stalled`
(notice) says once per outage that the hourly archive has had hours pending
for an hour, with the hours and the last error, and
`ha_logs_archive_resumed` (info) says once when the catch-up completes,
listing the hours archived and any lost to the journal meanwhile; nothing
is emitted per failed attempt or per hour, and a down Home Assistant costs
one request per 15-minute pass, whatever the backlog.

`credentials_stale` means the network key no longer matches the mesh,
usually because it was re-commissioned: frames keep failing to decrypt and
none succeed. Capture continues and the ring keeps every frame, but
everything that reads inside them (sleepy-device identity, rejoins,
starvation, the partition) has stopped. It repeats every six hours until
`config/credentials.toml` is updated and the recorder restarted.

## Secrets

`config/alerts.env` is a `NAME=value` file (see `config/alerts.example.env`);
no `export` prefix, since systemd's EnvironmentFile drops such a line and
`threadwatch doctor` warns about it.
The systemd unit loads it; `bin/threadwatch alert-test` needs it in the
environment too (`set -a; . config/alerts.env; set +a` or run under
`systemd-run`). Reference variables anywhere in a sink or heartbeat as
`${NAME}`. A definition whose variables are unset is **disabled with a
journal line**, not an error, so the recorder keeps running while you sort
out credentials. `alerts.env` is gitignored; keep it 0600 on your
workstation, and `setup-host.sh` and `push-to-host.sh` lock it to 0400 on
the host, where nobody edits it.

## Alert sinks

```toml
[[alerts.sinks]]
name = "phone"                 # for journal lines and alert-test output
type = "http"                  # http | command | ntfy (preset)
min_severity = "warning"       # default warning
# events = ["device_quiet", "phase_locked_storm"]   # only these names (see Choosing events)
# ignore_events = ["poll_starvation"]               # or every name but these
cooldown_s = 300               # per event name, per sink; default 300 (see Digests)
timeout_s = 10                 # for the whole request, connect to reply
enabled = true
```

`timeout_s` bounds the whole request. A sink that has not answered by then
is given up on and logged, and is skipped until that request has finished,
so one stalled endpoint never holds back the records or the other sinks
queued behind it.

### Choosing events

The severity floor is one axis; the event name is the other. A sink takes
every name by default. `events` narrows it to a list of names, and
`ignore_events` takes every name but the listed ones; a sink has one or the
other, not both. The filter is checked before the cooldown, so a name a sink
does not take never opens a window and never turns up in a digest.

The typical use is two sinks for two audiences: the phone takes the few
warnings that need a person now, a chat channel or a second, silent ntfy
topic takes everything at warning and above, and the review pages have the
rest.

```toml
[[alerts.sinks]]
name = "phone"
type = "ntfy"
url = "https://ntfy.example.net"
topic = "alerts"
events = ["device_quiet", "configured_pan_silent", "credentials_stale", "phase_locked_storm"]

[[alerts.sinks]]
name = "everything"
type = "ntfy"
url = "https://ntfy.example.net"
topic = "threadwatch"          # muted on the phone, read when curious
```

A name in either list that the recorder does not emit is logged at start
(`alert sink 'phone': events names event(s) the recorder does not emit: ...`),
since a misspelt filter would otherwise fail silently: the page you meant to
stop keeps coming. The names are the `event` column of the table above.
`alert-test --event poll_starvation` shows which sinks take a name (`skip phone
(does not take poll_starvation)`).

### Digests

The cooldown is per event name: the first `device_quiet` pages at once, and
further `device_quiet` records inside the window are held back. When the
window ends, whatever was held back goes out as one **digest** record: the
same event name, `digest = true`, `count`, `name` = "N more", and the device
names in `note`. So a second device failing three minutes after the first
still reaches the phone within the cooldown, and a mesh-wide outage costs two
messages instead of one per device. The digest opens the next window, and a
batch goes out when the window it was held in ends even if a new page has
already opened the next window at that moment. A Home Assistant automation
can key on `digest` to treat them differently.

### `type = "http"`

| key | default | notes |
| --- | --- | --- |
| `url` | required | |
| `method` | `POST` | |
| `headers` | `{}` | `Content-Type` defaults to `application/json` |
| `body` | raw record | template, see below |
| `severity_values` | `{}` | table mapping severity name to `{severity_value}` |

Without `body`, the sink POSTs the event record as JSON, exactly as
the event log has it. That is what Home Assistant's webhook trigger and most
"generic webhook" receivers expect.

With `body`, the text is a Python `str.format` template over the record plus
these derived fields:

| field | value |
| --- | --- |
| `{event}` `{severity}` `{ts}` | as in the record |
| `{id}` | a stable id for the record, the same on every retry: for receivers that dedupe |
| `{severity_index}` | 0..3 |
| `{severity_value}` | severity looked up in the sink's `severity_values`; a severity missing from a partial table takes the nearest lower listed value (else the lowest listed); with no table, the name |
| `{time}` | local `YYYY-MM-DD HH:MM:SS` |
| `{name}` `{addr}` `{note}` | empty string when absent (`addr` falls back to `src`) |
| `{who}` | `name`, else `addr`, else empty |
| `{summary}` | `event - name-or-addr - note`, the one-liner for chat channels |
| `{record_json}` | the whole record, as a JSON string |
| `{hostname}` | capture host |

Any other record field (`{silent_for_s}`, `{rate}`, ...) works too; unknown
fields render empty. Literal braces in the template must be doubled (`{{`
`}}`), which is why JSON bodies look like `'{{"text": "{summary}"}}'`. When
the `Content-Type` contains `json`, substituted values are JSON-escaped, so a
device name with a quote cannot break the document.

### `type = "ntfy"` (preset)

Expands into an `http` sink using ntfy's JSON publish API. No separate code
path; if you need something the preset lacks, write the `http` form.

```toml
[[alerts.sinks]]
name = "phone"
type = "ntfy"
url = "https://ntfy.example.net"      # server root, not the topic URL
topic = "alerts"
token = "${NTFY_TOKEN}"               # omit for servers that allow anonymous publish
# title = "{event}: {who}"            # defaults shown; {who} = name, else address
# message = "{note}"
# tags = ["{event}"]
# priority = { info = 2, notice = 3, warning = 4, critical = 5 }
```

### `type = "command"`

```toml
[[alerts.sinks]]
name = "buzzer"
type = "command"
command = ["/usr/local/bin/thread-alert.sh"]   # or a string; shlex-split
```

The record is on stdin as JSON. `THREADWATCH_EVENT`, `THREADWATCH_SEVERITY`
and `THREADWATCH_SUMMARY` are in the environment, along with everything
from `alerts.env`. Non-zero exit is logged with the command's stderr, with
any URL in it cut back to scheme and host: `curl` echoing an address it
could not reach would otherwise put the topic or webhook id in the journal.
Anything else your command prints to stderr is logged as written.

### Legacy shorthand

`webhook_url = "..."` (plus optional `min_severity`) under `[alerts]` still
works and is equivalent to one `http` sink named `webhook` with no template.

## Heartbeats

```toml
[[heartbeats]]
name = "gatus"
url = "..."                    # hit while capture is healthy
failure_url = "..."            # optional: hit instead when frames have stalled
interval_s = 60                # minimum 10
method = "POST"
headers = { Authorization = "Bearer ${GATUS_THREADWATCH_TOKEN}" }
# body = "..."                 # optional, sent verbatim (text/plain)
# timeout_s = 10               # for the whole request, as for sinks
# enabled = true               # false keeps the entry and switches it off, as for sinks
```

"Healthy" means a frame arrived within the last three minutes; until a run has
heard its first frame nothing is sent at all, so a daemon stuck restarting
without a working dongle cannot keep the monitor reassured. After that the
built-in watchdog exits the process for systemd to restart, so a monitor sees
either a `failure_url` hit or silence, never a reassuring beat from a stalled
capture. Each heartbeat runs on its own timer in one daemon thread; failures
are logged on the transition (first miss, then recovery), not every interval.
A beat with no answer inside `timeout_s` is given up on, so one stalled
monitor does not hold the beats to the others.

## Recipes

### Home Assistant

Automation (Settings > Automations > new > YAML mode). The webhook ID is the
only secret, so make it unguessable:

```yaml
alias: Threadwatch alert
triggers:
  - trigger: webhook
    webhook_id: threadwatch-<random-suffix>
    local_only: true
    allowed_methods: [POST]
actions:
  - action: notify.notify
    data:
      title: "Thread {{ trigger.json.severity }}: {{ trigger.json.event }}"
      message: "{{ trigger.json.name or trigger.json.addr or '' }} {{ trigger.json.note or '' }}"
```

```toml
[[alerts.sinks]]
name = "home-assistant"
type = "http"
url = "http://homeassistant.local:8123/api/webhook/threadwatch-<random-suffix>"
```

### ntfy

See the preset above. Self-hosted servers with `auth-default-access:
deny-all` need a token with write access to the topic; put it in `alerts.env`
as `NTFY_TOKEN`.

### Gotify

```toml
[[alerts.sinks]]
name = "gotify"
type = "http"
url = "https://gotify.example.net/message"
headers = { "X-Gotify-Key" = "${GOTIFY_TOKEN}" }
body = '{{"title": "{event}: {name}", "message": "{note}", "priority": {severity_value}}}'
severity_values = { warning = 5, critical = 8 }
```

### Discord / Slack incoming webhook

```toml
[[alerts.sinks]]
name = "discord"
type = "http"
url = "${DISCORD_WEBHOOK_URL}"
body = '{{"content": "**{severity}** {summary}"}}'        # Slack: "text" instead of "content"
```

### Gatus (external endpoint with heartbeat)

Gatus side, in its config (reloads on the fly):

```yaml
external-endpoints:
  - name: threadwatch
    group: iot
    token: "<long random token>"
    heartbeat:
      interval: 5m
    alerts:
      - type: ntfy
        description: "Thread flight recorder stopped reporting"
        failure-threshold: 1
        success-threshold: 1
        send-on-resolved: true
```

The endpoint key is `<group>_<name>`. Recorder side:

```toml
[[heartbeats]]
name = "gatus"
url = "http://gatus.example.net:8080/api/v1/endpoints/iot_threadwatch/external?success=true"
failure_url = "http://gatus.example.net:8080/api/v1/endpoints/iot_threadwatch/external?success=false&error=capture+stalled"
headers = { Authorization = "Bearer ${GATUS_THREADWATCH_TOKEN}" }
interval_s = 60
```

Running two Gatus nodes that each alert independently? Add one `[[heartbeats]]`
per node, addressed directly; a shared virtual IP would starve the standby
node and make it page.

### Healthchecks.io

```toml
[[heartbeats]]
name = "healthchecks"
url = "https://hc-ping.com/<uuid>"
failure_url = "https://hc-ping.com/<uuid>/fail"
interval_s = 60
```

### Uptime Kuma (push monitor)

```toml
[[heartbeats]]
name = "uptime-kuma"
method = "GET"
url = "https://kuma.example.net/api/push/<token>?status=up&msg=capturing"
failure_url = "https://kuma.example.net/api/push/<token>?status=down&msg=capture+stalled"
interval_s = 60
```

### Cronitor

```toml
[[heartbeats]]
name = "cronitor"
method = "GET"
url = "https://cronitor.link/p/<api-key>/<monitor>?state=run"
failure_url = "https://cronitor.link/p/<api-key>/<monitor>?state=fail"
interval_s = 60
```

### Authentication history capacity

`authentication_history_full` warns (at most hourly) when a recorder run has
accepted 16,384 distinct authenticated extended addresses. MAC and MLE share this
limit; each retains at most two key generations per address. Device-table eviction
does not erase replay counters. At capacity, known addresses continue to advance
and reject replays, but new addresses cannot establish liveness or device stats.
Raw packets still enter the ring. Invalid MICs cannot consume this capacity.

This counts addresses, not packets: 100 stable addresses use 100 slots regardless
of traffic volume. Starting from 100 addresses, 10 new addresses per day take
about 4.5 years to fill it; one new authenticated address per second takes about
4.5 hours. These are illustrative rates, not measured network behavior. Churn
also includes legitimate address rotations. Investigate the source before
restarting or raising `Pipeline.AUTH_MAX`. As before, restart restores counters
only for persisted last-seen rows; history of evicted/refused rows is not durable,
so restarting is not a replay-safe way to clear capacity. No automatic expiry is
used within a run.

The mDNS browse retains at most 4,096 distinct DNS records, deduplicates repeated
answers, and logs once when it refuses new records at that limit. Existing
record updates still apply. This bounds memory before the pipeline's separate
64-router retention cap; a saturated browse may omit newly advertised routers
until a later browse succeeds.
