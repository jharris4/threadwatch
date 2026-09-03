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
```

Delivery runs on a background thread, never blocks capture, and never raises:
a dead endpoint costs one journal line per failure (`alert sink 'x' failed:
...`), not frames.

## Events

Every event is one JSON record in `data/state/events.jsonl`, and the same
record is what sinks receive. Fields common to all: `ts` (unix seconds),
`event`, `severity` (`info` < `notice` < `warning` < `critical`).

| event | severity | extra fields |
| --- | --- | --- |
| `device_first_seen` | info | `addr`, `name` |
| `device_returned` | notice | `addr`, `name` |
| `join_scan_activity` | notice | `count_60s`, `src` |
| `possible_foreign_pan` | notice | `pan`, `src`, `dominant_pan`, `note` |
| `mle_rejoin_attempt` | notice | `command`, `src`, `name` (credentials only) |
| `device_quiet` | warning, or notice when `reception` is `marginal` | `addr`, `name`, `silent_for_s`, `profile` (`router` / `end-device`), `rssi_dbm`, `reception`, `note` |
| `retransmission_elevation` | warning | `rate`, `baseline` |
| `partition_or_leader_change` | warning | `previous`, `current` (credentials only) |
| `phase_locked_storm` | critical | detector snapshot (`period_s`, `onsets`, ...) |
| `alert_test` | as requested | `name`, `addr`, `note` (from `alert-test`) |

`name` is null for addresses not in `devices.json`.

`device_quiet` fires after `[quiet] end_device_s` of silence, or
`[quiet] router_s` for entries whose `role` / `threadRole` in
`devices.json` is `router`, `reed`, `border-router` or
`border-router-leader` (both default 30 min; sleepy end devices poll every
few seconds, so they are not quiet from the sniffer's point of view). Cleartext headers cannot tell the two apart (polls
are sent from the short address), so the inventory decides. Two silences
are deliberately not paged: addresses whose frames carry a foreign PAN id
(someone else's mesh) are never reported, and devices whose average RSSI
at the sniffer is below `[quiet] min_rssi_dbm` (default -82) are logged at
notice severity, because a device at the edge of the sniffer's range drops
out for tens of minutes whenever the link fades.

Sleepy end devices are covered only when credentials are configured; see
docs/CREDENTIALS.md for why their frames are otherwise anonymous.

## Secrets

`config/alerts.env` is a `NAME=value` file (see `config/alerts.example.env`).
The systemd unit loads it; `bin/threadwatch alert-test` needs it in the
environment too (`set -a; . config/alerts.env; set +a` or run under
`systemd-run`). Reference variables anywhere in a sink or heartbeat as
`${NAME}`. A definition whose variables are unset is **disabled with a
journal line**, not an error, so the recorder keeps running while you sort
out credentials. `alerts.env` is gitignored; `setup-host.sh` and
`push-to-host.sh` lock it to mode 0400.

## Alert sinks

```toml
[[alerts.sinks]]
name = "phone"                 # for journal lines and alert-test output
type = "http"                  # http | command | ntfy (preset)
min_severity = "warning"       # default warning
cooldown_s = 300               # per event name, per sink; default 300
timeout_s = 10
enabled = true
```

### `type = "http"`

| key | default | notes |
| --- | --- | --- |
| `url` | required | |
| `method` | `POST` | |
| `headers` | `{}` | `Content-Type` defaults to `application/json` |
| `body` | raw record | template, see below |
| `severity_values` | `{}` | table mapping severity name to `{severity_value}` |

Without `body`, the sink POSTs the event record as JSON, exactly as
`events.jsonl` has it. That is what Home Assistant's webhook trigger and most
"generic webhook" receivers expect.

With `body`, the text is a Python `str.format` template over the record plus
these derived fields:

| field | value |
| --- | --- |
| `{event}` `{severity}` `{ts}` | as in the record |
| `{severity_index}` | 0..3 |
| `{severity_value}` | severity looked up in the sink's `severity_values`, else the name |
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
and `THREADWATCH_SUMMARY` are in the environment. Non-zero exit is logged
with the command's stderr.

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
```

"Healthy" means a frame arrived within the last three minutes. After that the
built-in watchdog exits the process for systemd to restart, so a monitor sees
either a `failure_url` hit or silence, never a reassuring beat from a stalled
capture. Each heartbeat runs on its own timer in one daemon thread; failures
are logged on the transition (first miss, then recovery), not every interval.

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
