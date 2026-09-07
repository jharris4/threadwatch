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
yesterday is not. The age is read before each retry as well as after each
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
| `device_quiet` | warning, or notice when `reception` is `marginal` | `addr`, `name`, `silent_for_s` (wall clock since the device's last frame, as the pages show it), `unheard_s` (the part the recorder was listening for, the figure judged against `[quiet] silence_s`), `blind_s` (the difference: the recorder's own outage or clock step), `last_seen`, `rssi_dbm`, `reception`, `note` |
| `poll_starvation` | notice when first logged, warning once `[polls] confirm_s` later the polls are still unanswered (`confirmed`); notice only when `reception` is `marginal` or `episode` > 1 | `addr`, `name`, `unanswered_polls`, `since`, `starved_for_s`, `acked_polls`, `rssi_dbm`, `reception`, `episode`, `since_previous_s`, `confirmed`, `parent`, `parent_rloc16`, `parent_addr`, `note` |
| `poll_answered` | notice | `addr`, `name`, `note` |
| `rssi_degradation` | notice | `addr`, `name`, `rssi_dbm`, `reference_dbm`, `drop_db`, `since`, `low_for_s`, `note` |
| `rssi_recovered` | info | `addr`, `name`, `rssi_dbm`, `reference_dbm`, `note` |
| `retransmission_elevation` | notice for the first elevated minute, warning once the rate has stayed up for `[retransmissions] confirm_s` (`confirmed`); notice regardless when one sender-target pair is `top_share` >= 0.5 of the retries (a chronic bad link, not a storm precursor) | `rate`, `baseline`, `addr`, `name`, `top_sender`, `top_target`, `top_share`, `confirmed`, `sustained_s`, `note` |
| `partition_or_leader_change` | warning | `previous`, `current`, each with `partition`, `leader_router` and `leader` (the router id with the device's name once the MLE layer has matched it) |
| `credentials_stale` | warning | `failed`, `note` |
| `clock_step` | info | `step_s` (signed), `note`. The host clock jumped, NTP correcting a boot without an RTC. Forward: silences spanning the jump are not counted against any device. Backward: every timestamp the recorder holds, `last-seen.json` included, is moved back with it |
| `recorder_started` | info after a requested stop or on the first start ever, notice when the last run ended any other way | `cause` (`stopped`, `stalled`, `sniffer_died`, `stream_ended`, `crashed`, `unknown` for a run that left no note: a power cut or a kill, `first_start`), `gap_s` (since the last frame any run heard), `last_frame_ts`, `stopped_ts` (when the last run ended, if it left the note), `exit_code`, `note` |
| `border_router_address_changed` | notice | `addr`, `name`, `previous`, `hostname`, `note` |
| `border_router_unlisted` | notice | `addr`, `hostname`, `note` |
| `phase_locked_storm` | critical | detector snapshot (`period_s`, `onsets`, ...) |
| `snapshot_saved` | info | `label`, `path`, `ring_files`, `note` (with `[record] snapshot_on_critical`) |
| `snapshot_failed` | warning | `label`, `note` |
| `snapshot_skipped` | warning | `label`, `disk_free`, `ring_bytes`, `ring_needs_bytes`, `note` |
| `snapshots_pruned` | info | `removed`, `note` |
| `daily_summary` | `[summary] severity` (notice) | `frames_24h`, `devices_heard_24h`, `devices_tracked`, `quiet`, `unknown`, `marginal`, `degraded`, `storm_active`, `events_24h`, `note` |
| `alert_test` | as requested | `name`, `addr`, `note` (from `alert-test`) |

`name` is null for addresses not in `devices.json`.

`device_quiet` fires after `[quiet] silence_s` of silence (default 30
min). Routers advertise every few seconds and sleepy end devices poll
every few, so from the sniffer's point of view neither is quiet for long
and one window serves both. Two silences
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
address is retired rather than reported quiet. `border_router_unlisted`,
once per router, is one that matches no entry: `threadwatch import --write`
creates the entry (or `threadwatch name` names it). Both need the
recorder to hear the routers' mDNS, which is link-local: the same subnet,
or a network that reflects mDNS between VLANs. `threadwatch doctor` says
whether it can.

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
