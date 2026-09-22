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
| `mle_rejoin_attempt` | notice | `command`, `src`, `addr`, `name`; logged once `[rejoins] wave_s` has passed without another attempt, unless the batch became a `rejoin_wave` |
| `rejoin_wave` | notice | `devices`, `attempts`, `commands` (count per MLE command), `names`, `since`, `until`, `duration_s`, `trigger` (the partition change it followed, or null), `note`; replaces the batch's individual `mle_rejoin_attempt` records in the log (the key journal still gets each attempt) |
| `device_quiet` | warning, or notice when `reception` is `marginal` unless corroborated (`was_leader`, `ha_unavailable_since`) | `addr`, `name`, `silent_for_s` (wall clock since the device's last frame, as the pages show it), `unheard_s` (the part the recorder was listening for, the figure judged against `[quiet] silence_s`), `blind_s` (the difference: the recorder's own outage or clock step), `last_seen`, `rssi_dbm`, `reception`, `was_leader` (the leader a partition change replaced, silent since around then), `ha_unavailable_since` (Home Assistant's open episode, when the check is on), `note`; when something proved the device alive after its last frame, `vouched_ts` and `vouched_by` (`parent`: its parent answered its keep-alive; `ack`: its radio acknowledged a frame) |
| `visitor_left` | info | `addr` (never in `devices.json`; `name` is its label from `config/visitors.json`, else null), `first_seen`, `last_seen`, `heard_for_s`, `silent_for_s`, `frames`, `rloc16`, `parent`, `parent_addr`, `rssi_dbm`, `generations` (each key generation the address sent under, with the highest MAC `counter` and `mle_counter` heard), `note`. An address not in the inventory, heard for under 5 min as a child in its latest stretch of presence (a gap of over 5 min between frames starts a new stretch, so a phone that attaches twice in an evening is two visits), then silent for `[quiet] silence_s`: a phone or tablet reaching a HomeKit accessory. `visit` counts the address's visits (`data/state/visits.json`, kept by the recorder). Filed instead of `device_quiet`; the address is dropped from the device table at the same time, so it is never counted quiet or unnamed |
| `visitor_returned` | info | `addr`, `name` (label from `config/visitors.json`, else null), `visit`, `last_visit`, `note`: an address that has visited before is heard again (phones keep their extended address, even across a reboot); raised in place of `device_first_seen`, whose row the last visit dropped |
| `poll_starvation` | notice when first logged, warning once `[polls] confirm_s` later the polls are still unanswered (`confirmed`); notice only when `reception` is `marginal` or `episode` > 1 | `addr`, `name`, `unanswered_polls`, `since`, `starved_for_s`, `acked_polls`, `rssi_dbm`, `reception`, `episode`, `since_previous_s`, `confirmed`, `parent`, `parent_rloc16`, `parent_addr`, `note` |
| `poll_answered` | notice | `addr`, `name`, `note` |
| `poll_unserved` | notice when first logged, warning once `[polls] confirm_s` later the polls are still unserved (`confirmed`); notice only when `reception` is `marginal` or `episode` > 1 | `addr`, `name`, `unserved_polls`, `since`, `unserved_for_s`, `served_polls`, `rssi_dbm`, `reception`, `episode`, `since_previous_s`, `confirmed`, `parent`, `parent_rloc16`, `parent_addr`, `note` |
| `poll_served` | notice | `addr`, `name`, `note` |
| `frame_counter_mismatch` | warning | `addr`, `name`, `layer` (`mac` or `mle`), `key_sequence`, `advertised`, `advertised_ts`, `advertised_in` (the MLE command that carried it), `counter`, `lowest`, `shortfall`, `frames_below`, `note` |
| `rssi_degradation` | notice | `addr`, `name`, `rssi_dbm`, `reference_dbm`, `drop_db`, `since`, `low_for_s`, `note` |
| `rssi_recovered` | info | `addr`, `name`, `rssi_dbm`, `reference_dbm`, `note` |
| `key_sequence_advanced` | info | `sequence`, `previous`, `first_sender`, `name`, `rloc16`, `role`, `frame`, `since_previous_s`, `observed_interval_s`, `sequence_delta`, `observation_kind`, `previous_first_ts`, `coverage`, `scheduled_expectation`, `early_against_configured_interval`, `scope`, `confidence`, `reasons`, `suspects`, `note`. The first frame accepted under a new generation; the census says whether the mesh followed. Suspects retain `addr`, `name`, `rloc16`, `role`, `ts`, `frame`, legacy `evidence`, parent fields, and add candidate `confidence`/`reasons`. See the key-generation section below. |
| `key_lag_census` | info | `sequence`, `mesh_generation`, `counts` (devices per generation, fresh ones only), `behind_parent_1`, `behind_parent_2plus`, `routers_behind` (each: `name`, `addr`, `generation`, `lag`, and `parent` / `parent_generation` or `mesh_generation`), `unknown` (no fresh frame: not judged), `suspects` (the observation's first sender, then every device whose first frame on the new generation came while its parent was still fresh on the old one, entries as in `key_sequence_advanced`), `note`; `[keys] census_delay_s` after each advance |
| `key_lag` | warning for a child, critical for a router; notice when `episode` > 1 (reopened within `[keys] rearm_s`) | `addr`, `name`, `role`, `generation`, `parent`, `parent_addr`, `parent_generation` (a child) or `mesh_generation` (a router), `lag`, `since`, `lagged_for_s`, `rssi_dbm`, `reception`, `polls_acked`, `episode`, `since_previous_s`, `note` |
| `key_lag_cleared` | info | `addr`, `name`, `role`, `generation`, `parent`, `parent_addr`, `parent_generation` or `mesh_generation`, `since`, `lagged_for_s`, `rejoined`, `rejoin_ts`, `note`; only after a `key_lag` went out |
| `retransmission_elevation` | notice for the first elevated minute, warning once the rate has stayed up for `[retransmissions] confirm_s` (`confirmed`); notice regardless when one sender-target pair is `top_share` >= 0.5 of the retries (a chronic bad link, not a storm precursor) | `rate`, `baseline`, `addr`, `name`, `top_sender`, `top_target`, `top_share`, `confirmed`, `sustained_s`, `cause` (`rejoin_wave` when the mesh was re-attaching after a partition change inside the last five minutes), `note` |
| `partition_or_leader_change` | warning | `previous`, `current`, each with `partition`, `leader_router` and `leader` (the router id with the device's name once the MLE layer has matched it); logged once the change has held for `[partition] settle_s` |
| `partition_storm` | warning | `previous`, `current` (as above), `partitions` (distinct states seen), `leaders`, `changes` (flips), `since`, `until`, `duration_s`, `note`; several changes inside `[partition] settle_s`, logged as one |
| `leader_stalled` | warning | `partition`, `leader_router`, `leader`, `addr`, `name`, `id_sequence`, `since`, `stalled_for_s`, `last_carried_by`, `leader_last_seen`, `leader_silent_for_s`, `note` |
| `router_set_changed` | notice | `promoted`, `demoted` (each a list of `router_id`, `rloc16`, `addr`, `name`, `label`), `routers`, `previous_routers`, `previous_sample_ts`, `sample_ts`, `note`; from the `[otbr]` inventory's router table, one per pair of samples that differ |
| `leader_resumed` | info | `partition`, `leader_router`, `leader`, `addr`, `name`, `since`, `stalled_for_s`, `note`; closes a `leader_stalled` |
| `srp_refused` | warning | `addr`, `name`, `rcode`, `rcode_name`, `refusals`, `since`, `refused_for_s`, `accepted_ts` (the last accepted registration, if one was heard), `server` (the anycast locator answered from, when readable), `note`; once per streak |
| `srp_accepted` | info | `addr`, `name`, `refusals`, `since`, `refused_for_s`, `server`, `note`; only after an `srp_refused` went out |
| `credentials_stale` | warning | `failed`, `note` |
| `clock_step` | info | `step_s` (signed), `note`. The host clock jumped, NTP correcting a boot without an RTC. Forward: silences spanning the jump are not counted against any device. Backward: every timestamp the recorder holds, `last-seen.json` included, is moved back with it |
| `recorder_started` | info after a requested stop or on the first start ever, notice when the last run ended any other way | `cause` (`stopped`, `stalled`, `sniffer_died`, `stream_ended`, `crashed`, `unknown` for a run that left no note: a power cut or a kill, `first_start`), `gap_s` (since the last frame any run heard), `last_frame_ts`, `stopped_ts` (when the last run ended, if it left the note), `exit_code`, `note` |
| `border_router_address_changed` | notice | `addr`, `name`, `previous`, `hostname`, `evidence` (what corroborated the rotation), `note` |
| `device_address_changed` | notice | `addr` (the new address), `name`, `previous`, `evidence` (the SRP registration that carried the same Matter service name, or Home Assistant's node diagnostics), `note`; once per rotation |
| `border_router_unlisted` | notice | `addr`, `hostname`, `note` |
| `border_router_address_conflict` | warning | `addr`, `name` (the entry devices.json gives the address to), `hostname`, `claimed_by` (the entry the hostname belongs to), `note` |
| `border_router_rotation_unverified` | notice | `addr`, `name`, `previous`, `hostname`, `evidence` (what held, when anything did), `missing` (what did not), `note` |
| `phase_locked_storm` | warning at `[detect] period_onsets` periodic onsets (`confirmed` false, with the snapshot), critical once the floods have persisted `[detect] confirm_s` (`confirmed` true) | `period_s`, `onsets`, `onset_times`, `confirmed`, `storm_since`, `follows` (what the surge came after, on the warning), `auto_snapshot`, detector snapshot (`baseline_frames_per_window`, `recent_windows`, `storm_active`, `storm_confirmed`, `flood_onsets_recent`) |
| `snapshot_requested` | info | `label`, `trigger`, `key_observation` (`sequence`, `observed_at`, `phase`): a key snapshot attempt was reserved |
| `snapshot_saved` | info | `label`, `path`, `ring_files`, `note` (with either automatic snapshot option) |
| `snapshot_failed` | warning | `label`, `note` |
| `snapshot_skipped` | info/warning | `label` when assigned, `note`; disk refusals include `disk_free`, `ring_bytes`, `ring_needs_bytes`; key coalescing/disabled/busy attempts include `reason` and `key_observation` |
| `snapshots_pruned` | info | `removed`, `note` |
| `snapshot_logs_saved` | info | `label`, `path`, `addons`, `lines` (per add-on), `note`; the HA add-on logs joined an automatic snapshot, or a retry completed them (with `[ha_logs] enabled`) |
| `snapshot_logs_failed` | notice | `label`, `addons`, `errors`, `status` (`failed`, `partial` or `skipped`), `note` (whether and when the recorder retries) |
| `ha_logs_archive_stalled` | notice | `addons`, `pending_hours` (`<slug>/<YYYYMMDD-HH>`, UTC), `since`, `last_error`, `note`; once per outage, when the hourly archive (`[ha_logs] archive`) has had hours pending for an hour |
| `ha_logs_archive_resumed` | info | `archived`, `lost` (hour names), `since`, `note`; once, when the catch-up after an outage completes |
| `ha_unavailable` | warning once a device has been unavailable in Home Assistant for its hold; notice when `muted`, part of a burst (`burst_id`), reopened within `[ha_availability] rearm_s` (`episode` > 1) or `already_unavailable_at_start` | `addr`, `name`, `ha_device_id`, `entities`, `since`, `unavailable_for_s`, `hold_s`, `muted`, `burst_id`, `episode`, `cause` (`key_lag`, `counter_mismatch`, `dropped_polls`, `lost_parent`, `leader_lost`, `silent`, `radio_ok`, `unheard`), the radio evidence (`last_seen`, `silent_for_s`, `rssi_dbm`, `reception`, `starved`, `unserved`, `role`, `parent`, `generation`, `parent_generation`, `rejoin_ts`), `note` (with `[ha_availability] enabled`) |
| `ha_unavailable_burst` | critical | `burst_id`, `devices` (each `name`, `addr`, `since`, `cause`), `count`, `window_s`, `first_since`, `note` (the causes, and "HA or Matter Server side" when most mapped devices dropped at once while the recorder still heard them); once per burst, with the automatic snapshot |
| `ha_available` | info | `addr`, `name`, `ha_device_id`, `since`, `down_for_s`, `rejoined`, `generation`, `note`; only after an `ha_unavailable` went out |
| `ha_unreachable` | notice | `failing_for_s`, `error`, `note`; once, after five minutes of failed polls |
| `ha_reachable` | info | `unreachable_for_s`, `note`; the next poll is a baseline, not transitions |
| `daily_summary` | `[summary] severity` (notice) | `frames_24h`, `devices_heard_24h`, `devices_tracked`, `quiet`, `unknown`, `marginal`, `degraded`, `storm_active`, `events_24h`, `key_generation` (the mesh's), `key_lag_1` and `key_lag_2plus` (device names one, and two or more, generations behind right now), `ha_unavailable_24h` (with `[ha_availability]`: the day's Home Assistant unavailabilities, each `name`, `down_for_s`, `open`), `note` |
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
"silent for" and `device_returned` stay the recorder's own. Three silences
are deliberately not paged: addresses whose frames carry a foreign PAN id
(someone else's mesh) are never reported; devices whose average RSSI
at the sniffer is below `[quiet] min_rssi_dbm` (default -82) are logged at
notice severity, because a device at the edge of the sniffer's range drops
out for tens of minutes whenever the link fades; and an address not in
`devices.json` that was heard for less than 5 minutes, as a child, in its
latest stretch of presence before going silent is not quiet at all but a
visitor that left (a phone or tablet
with a Thread radio joins the mesh for seconds to reach a HomeKit accessory,
and leaves): its visit is logged as `visitor_left` at info, with what was
known about it, and the address is dropped from the device table, so it is
never listed quiet or unnamed and does not grow the table by one row per
visit. An unnamed address that held a router id is a device missing from
the inventory, however briefly it was heard, and still pages. A start-up
finds any visit an earlier run announced as `device_quiet` and files it
the same way, closing that row on the day pages. A silence the rest of the recorder can already explain is not softened by reception: the leader a partition change or storm replaced, silent since around then, or a device Home Assistant has marked unavailable, is a warning with the corroboration in its note and in `was_leader` / `ha_unavailable_since`, however faintly the sniffer heard it. On 2026-09-22 the dead leader was heard at -87 dBm and its quiet was a notice blaming reception, twenty minutes after the storm had named it.

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

`poll_unserved` is the failure starvation cannot see, because the polls
*are* acknowledged. A parent's radio answers a poll from its own
source-match table before the poll reaches the parent's stack, and when
it has a frame queued for the child the ACK carries Frame Pending: a
promise that the stack will now send it. When the stack drops the poll
instead, the promise is never kept, the child polls again, is promised
again, and so on: acknowledged every time, served never. That is what the
sniffer saw on 2026-09-13, when a key rotation left four sleepy children
two generations behind their parents (the parents' stacks rejected their
polls as unauthenticated, the radios kept acknowledging them) and the
recorder raised nothing; it is also what a child looks like when it has
advertised a frame counter above the ones it sends with
(`frame_counter_mismatch`), and what a parent looks like whose stack has
hung while its radio still answers. The rule mirrors starvation's: ten
distinct polls in a row acknowledged with Frame Pending and followed by no
frame to the child before its next poll, over at least a minute, from a
device whose promised frames used to arrive (`served_polls`, kept with
the last-seen rows across a restart). Over the hour before the 09-13
rotation no child ran to more than two such polls; the stranded ones ran
to 1,700 in the hour after it. The record names the parent as
`poll_starvation`'s does, and is logged at notice, paged `[polls]
confirm_s` later if still going (`confirmed`), demoted for a marginal
signal or an episode that reopens within `[polls] rearm_s`, and closed
by `poll_served` on the first frame the parent delivers. It says that the
parent is dropping the polls, not why: read it beside `key_lag` and
`frame_counter_mismatch` for the device, and when neither is there, the
parent's stack has hung (its own `device_quiet` follows if its radio
goes too) or the sniffer cannot hear the parent's frames.

`frame_counter_mismatch` is the one device-side defect the sniffer can
prove. An attaching child (Child ID Request), a router establishing a
link (Link Request, Link Accept) and a child updating its parent (Child
Update) advertise their current frame counters in Link Layer Frame
Counter and MLE Frame Counter TLVs, and the receiver takes each as the
floor below which the sender's later frames are replays. The recorder
reads the TLVs from the decrypted message and then judges the device's
own accepted frames under the same key generation against them
(`layer` is `mac` for the link-layer counter on secured MAC frames, `mle`
for the counter on secured MLE messages). Three accepted frames below the
advertisement (one or two can be frames the device had queued when it
advertised) are the record: `advertised`, `advertised_in` and
`advertised_ts` say what the device claimed and where, `counter` and
`shortfall` what it then sent, `frames_below` how many. Every parent
that takes such an advertisement drops everything the device sends
until it reboots, so `poll_unserved` follows for a sleepy device. The
stack writes the advertisement and the radio driver writes the counters,
so the two have lost sync inside the device, which is a firmware defect
to report to the vendor: openthread/openthread#13599 documents one on an
IKEA MYGGSPRAY (a Child ID Request advertising 1,280,176,180, then polls
at 4,708). Said again at most once an hour while it goes on; the last
advertisement is kept with the last-seen rows (`adv_mac`, `adv_mle`), so
the floor survives a restart.

`key_sequence_advanced`, `key_lag_census`, `key_lag` and `key_lag_cleared`
are the key-generation detectors, for the failure neither of the two above
can see. Scheduled rotation defaults to 28 days in OpenThread; this mesh
has shown higher sequences about every 5.4 days. Observing those sequences
does not establish scheduled rotation or adoption by every device.
OpenThread's ordinary mode-1 MAC receive window covers its current,
previous and next generation. Two generations behind the actual parent
can therefore explain rejected data while polls still receive ACKs.
An ACK alone does not prove security acceptance or application delivery.
MLE attachment or resynchronization can recover a device; sequence catch-up
alone does not establish that Home Assistant is available again. The
September 13 incident motivated the lag detector.

The recorder reads the generation off every authenticated frame (the
last-seen rows carry it as `counter_seq` and `mle_counter_seq`, with when
it was read). Four records follow from it, and the budget is that a normal
week pages nothing:

- `key_sequence_advanced` (info) is the advance itself: the first frame
  accepted under a generation above any on record, who sent it and under
  what (`mac_data`, `mac_poll`, `mle:<command>`), and how long after the
  previous advance. Once per generation, ever: the highest generation is
  kept in `data/state/key-generations.json`, so a restart does not announce
  it again, and a replay (which starts with no record) announces the first
  generation it meets with `previous` null. With `[keys] rotation_hours`
  set, an advance under 90% of it after the previous one says "early" in
  the note; set that from the active dataset's Security Policy rotation
  time (672 h by default), not the keysequence guardtime (624 h), which is
  a different setting. `since_previous_s` is between first observations,
  not between internal timer expiries; missed traffic at either endpoint can
  distort that interval. `observed_interval_s` preserves the elapsed seconds,
  `previous_first_ts` identifies the preceding observation, and `sequence_delta`
  records the jump. Initial discovery is a `baseline` with no interval or delta;
  a +3 advance is one observed jump, not three witnessed rotations.
  `coverage` lists retained recorder blind spans (downtime or forward clock
  steps) intersecting the interval, with `status=gapped` when present. Otherwise
  coverage is `unknown`, never assumed continuous. History is bounded and
  incomplete; restarts are labeled, and negative timestamp intervals are unknown.
  `scheduled_expectation` labels `rotation_hours` as a local configuration
  annotation, not live telemetry; device and observation time remain null
  because the recorder does not collect Security Policy observations. The
  reported 672 h active policy can inform that setting but is not independently
  measured by this event. `early_against_configured_interval` uses the same 90%
  comparison as the note, and does not establish a protocol violation.
  The record also says who is suspected of starting it, as `suspects`, each
  with `confidence=candidate_only` and `reasons`. An advance is started by
  whichever device's own rotation timer fires first, and the mesh follows
  it; the first sender is that device only if it could not have learned
  the new key from anyone. A child hears nobody but its parent, so a child
  heard on the new generation while its parent's freshest reading (within
  `[keys] fresh_s`) is still the old one is the strongest candidate the
  sniffer gets: `evidence` is `ahead of its parent`, the note says
  "ahead of its last known parent sequence", and the reasons carry
  `ahead_of_last_parent_observation` and `missed_traffic_or_attachment_possible`,
  because a frame the sniffer missed, an attachment in progress or a stale
  parent mapping can produce the same picture. On 2026-09-17 that was Front
  Door, an Eve contact sensor polling on 87 with frame counter 0 while its
  parent was still on 85 and nothing else was on 87, and nothing but ACKs
  had been sent to it for the previous 95 s; it lost its parent, and its
  Child ID Request to a new one forced that router onto 87 (an attaching
  child's Child ID Request is authoritative). The border router took 87
  two seconds later from a frame another router sent it over TREL, the
  Thread link over the IP backbone, which the sniffer cannot see: its key
  switch guard was clear because it had rebooted three days earlier, so
  the ordinary guarded path accepted a +1 from a valid neighbour. Routers
  two behind re-established their links and followed; routers one behind
  with an armed guard refused and stayed. A router first on air may be relaying
  a frame the sniffer missed, and a child whose parent has no fresh reading
  cannot be judged: `first on air`, with `parent_unknown` or
  `parent_sequence_not_fresh`. Until the census, every further device whose
  first frame on the new generation comes while its parent is still fresh
  on the old one joins the suspects (Front Door Button did the same 74 s
  after Front Door, under a parent still two behind); a child heard on it
  after its parent moved simply followed, `parent_already_observed_at_or_above_sequence`.
  The event carries `scope=device`, `confidence=observation_only` and
  `reasons` (`accepted_authenticated_frame`, `mesh_adoption_not_established`,
  `origin_not_established`): it records one device's frame, and the census
  is what says whether the mesh followed. The other scope values
  (`router_group`, `otbr_confirmed`, `unknown`) are reserved; legacy state
  loads with `confidence=unknown`. Old events and snapshots still render.
- `key_lag_census` (info) comes `[keys] census_delay_s` (default 60 min)
  after each advance: how many devices are on each generation, the
  children one behind their parent (normal), the children two or more
  behind (cut off), the routers behind the mesh, and the devices with no
  frame fresh enough to judge. It is the roll call to read after a
  rotation, and the suspects: the first sender and every device that
  moved ahead of its parent since. Nothing in it pages.
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

`leader_stalled` is the leader failing while it still answers. The leader
increments the Route64 ID sequence every few seconds as long as its timers
run, and every router repeats the newest it has heard in its own
Advertisements, so the sniffer sees the sequence advance from wherever it
sits. When it stops for `[partition] stall_s` (default 60 s) while the
mesh is still heard, the warning names the leader, the stuck sequence,
which router last carried it, and when the leader itself was last heard:
"its stack still answers while its leader timer has stopped" when its own
frames are recent, "it is gone" when they are not. Routers give a leader up
120 s after the last advance they saw and each becomes the leader of a
partition of its own, so the warning lands about a minute before that
storm. On 2026-09-22 an ALPSTUGA leader stopped advertising at 11:44:32,
kept its sequence at 164 from 11:46 and answered Link Requests until it
died at 11:48:25; every router timed out at 11:48:13. `leader_resumed`
(info) closes the episode when the sequence moves again or the partition
changes.

`partition_or_leader_change` and `partition_storm` are the same detector
with a settling window. A change of partition id or leader router id is
held for `[partition] settle_s` (default 30 s). If nothing else changes in
that time it is logged as `partition_or_leader_change`, as before but 30 s
later. If more changes arrive inside the window they are one
`partition_storm`: `partitions` distinct states, `leaders` in the order
seen, `changes` flips, `since`/`until`/`duration_s`, and a note that says
whether the mesh split and merged back under the same leader or lost its
leader to a successor. The 09-22 storm was 90 warnings in three seconds
for 14 partitions; it is one record now. `settle_s = 0` logs every flip at
once, as before.

`rejoin_wave` is the minute after a partition change, or after a parent
router dropped its children, seen as one record instead of one notice per
Parent Request. Attempts are held for `[rejoins] wave_s` (default 60 s)
after the last one; a batch from `wave_devices` (default 3) or more
devices, or from two or more inside five minutes of a partition change, is
logged as one `rejoin_wave` with the devices named, the attempts per
command, the span and the trigger. A smaller batch is logged as the
individual `mle_rejoin_attempt` notices, each at its own time. The key
journal receives every attempt either way. The retransmission detector
reads the same window: retries that rise while a wave is running, or
inside five minutes of a partition change, are attributed to the wave
(`cause = rejoin_wave`) rather than to interference. On 2026-09-22 the
minute after the leader died was 70 rejoin notices and a retransmission
notice blaming contention; it is one wave of 18 devices now, and the
retransmission note names it.

`srp_refused` is a device the border routers will not register. Every
Matter device on the mesh publishes its host and `_matter._tcp` service
by SRP: a DNS UPDATE to the SRP server's anycast locator, answered by an
Apple TV or the OTBR, which advertises the records on the LAN by mDNS.
Controllers that find devices that way (Apple Home) lose a device once
its last accepted registration expires; Home Assistant keeps the address
it already has and is the last to notice. The recorder reads the
responses (rcode) and credits each to the device that sent the request,
even when it is heard relayed by the device's parent, and logs
`srp_refused` once a device has been refused `[srp] refusals` (default 3)
times in a row and the streak has outlasted `grace_s` (default 60 s) with
no acceptance, with the response code and when its last accepted
registration was heard. The grace is for the retry that follows a
refusal within seconds and gets through: on 2026-09-22 a two-hour
SERVFAIL streak paged on its third refusal, ten seconds before the retry
that was accepted. The streak is kept with the device's last-seen
row, since a refused client retries hourly and a recorder restart must
not forget it. `srp_accepted` closes the episode. On 2026-09-17 22:15 a
smoke sensor's registrations started coming back SERVFAIL, hourly, from
the same server that accepted its siblings; Apple Home lost it five days
later, after a partition change broke the session it still had.

`device_address_changed` is a device that took a new extended address:
on 2026-09-22 a climate sensor came back from a firmware update under
one, registered the same three `_matter._tcp` service names it always
had, and was refused (YXDOMAIN: the names still belonged to the old
address's SRP key), and the warning named an address nobody recognised.
A registration is three to six 6LoWPAN fragments; the recorder now reads
it whole and keeps the service names (`<compressed fabric id>-<node id>`,
one per fabric) with the device's row as its identity. An address that
registers a name another address holds is that device under a new
address: the new address takes the name from the old one's devices.json
entry, the old row is retired rather than reported quiet, and the
rotation is remembered in `device-rotations.json` so every later process
and page names it too. The `[ha_availability]` map refresh is the second
witness: Home Assistant's Matter node diagnostics carry the address the
Matter Server read from the device, and a device whose address moved
between two refreshes is rotated the same way. Either way it is said
once, with the `threadwatch name` command that confirms it in
devices.json. Unlike an mDNS advertisement, both witnesses are inside
the trust boundary: the registration was decrypted under the network
key from a frame with a fresh counter, and the Matter Server read the
address over its own session, so the retirement needs no further
corroboration. If devices.json names both addresses, differently, the
inventory stands and nothing is renamed or retired.

`router_set_changed` is the mesh's router roster moving. The `[otbr]`
inventory reads `ot-ctl router table` every `poll_s`, and that table
lists every router id the leader has allocated, not just the OTBR's
neighbours; each new sample is compared with the one before it and a
router id that appeared or vanished is logged with the device's name
(from its extended address), as a promotion or a demotion. The 09-22
storm demoted three routers to children and promoted three others, which
only a reading of two samples by hand showed at the time. The note names
the partition change when one fell in the half hour before the sample.
The first sample after a start is only remembered, so a restart announces
nothing that happened while it was down.

`phase_locked_storm` is the 2026-09-01 outage: every accessory's periodic
report converging on the hub in the same window every 80.5 s, for hours,
after a LAN outage; only powering the hub off ended it. The detector calls
it at `[detect] period_onsets` (3) flood onsets with a stable period, and
that call is now a warning: it saves the ring (the packets matter whether
or not the storm confirms), says in `follows` what the surge came after
when a border router changed address or the partition changed in the
previous 15 minutes, and says the critical is coming if the floods
persist. The critical follows once the newest flood is `[detect]
confirm_s` (10 min) past the first periodic onset, cooldown or not, and
names the warning's snapshot instead of taking another. On 2026-09-22 a
hub re-establishing its sessions after the other Apple TV was restarted
produced three onsets 100 s apart and stopped after six minutes: a
warning now, not the critical page and snapshot it was. Later that day the
tail of one burst gave three onsets 110 s and 90 s apart, a 100 s period
the mesh never had, and the bursts that followed came five minutes apart
and faded: the gap check refuses the confirmation, and the flag drops
three measured periods after the last flood (300 s there, not the 540 s
it used to wait), so those bursts are fresh onsets too far apart to call.
`confirm_s = 0` pages critical at the call, as before.

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

`ha_unavailable`, `ha_unavailable_burst`, `ha_available`, `ha_unreachable`
and `ha_reachable` are the Home Assistant availability check
(`[ha_availability] enabled`; docs/HOME-ASSISTANT.md). HA's "unavailable"
is the outage a person actually notices, and the radio detectors can miss
it: on 2026-09-13 five devices went unavailable while their radios looked
healthy. So the recorder polls HA's states once a minute (one small
`GET /api/states`; the device map behind it is rebuilt over the websocket
once an hour) and, when a device has been unavailable for its hold, says
so with the recorder's own evidence for why: `cause` is `key_lag` (cut off
by a key change, radio alive on an old generation), `counter_mismatch`
(a `frame_counter_mismatch` in the last two hours: its parent drops
everything it sends), `dropped_polls` (an open `poll_unserved`: its polls
are acknowledged with data pending and nothing follows), `lost_parent` (polling
a parent that no longer answers), `leader_lost` (it was the leader a partition
change or storm replaced and its radio went quiet around then: the leader's
stack hung, then died), `silent` (the radio went quiet before HA
lost it: the device died, lost power or left the mesh), `radio_ok` (heard
in the last five minutes, so the fault is the Matter, IP or HA side) or
`unheard` (the sniffer cannot hear it). Only Matter-over-Thread devices HA
knows are covered; HomeKit-only Thread devices stay with the radio
detectors. `devices.json` learns nothing: the link from HA's device ids to
the inventory is built at runtime by extended address, and a device with no
inventory entry is watched under its HA name.

The hold is `[ha_availability] hold_s` (default 10 min), or the device's
own `hold_s` in `devices.json` (`threadwatch hold`), the same hold
`device_quiet` judges its silence by: a sensor that goes unavailable for
half an hour in the afternoon sun gets two hours there and still pages
when it really fails. A device that recovers inside its hold produces
nothing at all. `mute` (`threadwatch mute`) makes every record for a
device a notice, `device_quiet` included, and keeps it out of bursts. Several
devices dropping together are a network problem, not a device:
`burst_devices` (default 3) non-muted devices going unavailable within
`burst_window_s` (10 min), the newest of them down for `burst_hold_s`
(2 min, which filters the blip of a Home Assistant or Matter Server
restart), is one critical `ha_unavailable_burst` with the automatic
snapshot; the members' own `ha_unavailable` records are notices carrying
the `burst_id`, a device dropping while the burst is live joins it rather
than starting another, and the burst ends when fewer than `burst_devices`
members are still down or the window passes without a new one, so one
device stuck for hours never suppresses the next outage. When most of the
mapped devices are down at once while the recorder heard most of them in
the last five minutes, the burst's note says "HA or Matter Server side":
still critical, because the devices really are down, but the cause points
away from the mesh. A device already unavailable when the recorder starts
opens an episode without paging (a notice with
`already_unavailable_at_start`, unless a persisted episode says it was
paged before the restart), and an episode reopening within `rearm_s` of
its close is a notice with `episode` > 1, like a flapping starvation.

Home Assistant being down is not a device being down: a failed poll (a
refused connection, a 5xx while HA restarts) opens and closes nothing,
five minutes of them are one `ha_unreachable` notice, recovery is
`ha_reachable`, and the first poll after is a baseline, not transitions.
If HA automations already notify on unavailability, keep `ha_unavailable`
off the phone sink with `ignore_events = ["ha_unavailable"]` and let the
burst through; the devices page shows `HA: available` or `unavailable
since` either way.

With `[record] snapshot_on_key_advance = true` (off by default), an
accepted advance saves the ring immediately and again at the existing
`[keys] census_delay_s` census. Initial discovery does not save anything.
The manifest and `snapshot_requested` event link both attempts through
`key_observation.sequence` and `observed_at`, with phase `advance` or `census`.
These attempts bypass the critical-event cooldown and share automatic
retention and disk-space checks. Keep at least two automatic snapshots if
you want both retained; critical snapshots share that budget.

Further advances while a census is outstanding coalesce into that pair;
the follow-up runs at the latest advance's census, while its link still
identifies the original observation. Each coalesced advance records
`snapshot_skipped` with `reason=key_advance_coalesced`. A completed pair
also holds new pairs for five minutes from its first observation. At most
two key workers run; busy or disabled saves are explicitly recorded as
skipped. Copying and pruning are serialized, and log fetching runs after
the copy on the worker thread.

Reservations are persisted before starting each worker, and the existing
census deadline survives restart. Each phase is attempted at most once:
a crash between reservation and completion can lose that attempt, but
cannot duplicate it after restart. Existing partial-copy cleanup reports
interrupted copies. Disk-full and copy failures are reported without
retrying the ring copy; the other phase remains independent. HA log
fetches retain their existing bounded retry schedule. Replay never starts
these workers.

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
