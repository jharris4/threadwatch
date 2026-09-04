# Home Assistant

threadwatch does not depend on Home Assistant. But if HA is your Thread
controller, it already holds the two things the recorder needs from you,
the device names and the network key, and one command fetches both.

## 0. Import names and the network key

```bash
cp config/ha.example.env config/ha.env
# edit config/ha.env: HA_URL and HA_TOKEN (below)
chmod 600 config/ha.env
bin/threadwatch import-ha            # shows what would change
bin/threadwatch import-ha --write    # writes devices.json and credentials.toml
```

**The token.** In Home Assistant open your profile (click your name at the
bottom of the sidebar), scroll to the bottom to *Long-lived access
tokens*, click *Create token*, name it `threadwatch`, and copy the token
once; HA does not show it again. Paste it into `config/ha.env` as
`HA_TOKEN`. It is valid for ten years and can be revoked from the same
list. `HA_URL` is how this machine reaches HA, usually
`http://homeassistant.local:8123` or the LAN address.

**What it fetches**, over HA's websocket API with that token:

- `devices.json`: every Matter-over-Thread device in HA's device registry,
  with the name you gave it in HA and its extended address (from the
  node's diagnostics). Existing entries are kept: a device already listed
  under that address is renamed to the HA name if it differs, a known name
  seen with a new address gains it (Apple TVs rotate), and hand-written
  entries such as HomeKit-only devices are untouched. The plan is printed
  first; `--write` applies it.
- `credentials.toml`: the network key from HA's preferred Thread dataset
  (the one your border router runs). It is written at mode 0600 and never
  printed; the command reports the network name, channel and PAN id, and
  warns when `config.toml` listens on a different channel.

The daemon reads both files at start, so restart it afterwards. Re-run
the command whenever you add or rename devices; it is safe to repeat.

`config/ha.env` is gitignored and carried to the recorder host by
`push-to-host.sh` like the other secrets, so the command runs from either
machine. Mode 0600 on your workstation keeps it private and editable;
`setup-host.sh` locks it to 0400 on the host, where nobody edits it.

HomeKit-only Thread devices never appear in HA; name those with
`threadwatch report --suggest` and `threadwatch adopt`, or the power-cycle
method in docs/ANALYSIS.md.

## 1. Receive alerts in HA

`config.toml` (full reference and other receivers: docs/ALERTING.md):

```toml
[[alerts.sinks]]
name = "home-assistant"
type = "http"
url = "http://homeassistant.local:8123/api/webhook/threadwatch-<random-suffix>"
min_severity = "warning"
```

HA automation. The webhook ID is the only secret, so make it unguessable and
keep `local_only`:

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
      message: >-
        {{ trigger.json.name or trigger.json.addr or '' }}
        {{ trigger.json.note or '' }}
```

The body is the raw event record (`ts`, `event`, `severity`, plus the
event's own fields such as `name`, `addr`, `note`, `silent_for_s`); there is
no `message` field. Check the wiring with `bin/threadwatch alert-test`.

## 2. Blast-radius detection inside HA (belt and suspenders)

Independently of threadwatch, alert when several Thread devices go
unavailable together — the visible symptom of a channel-level problem:

```yaml
alias: Multiple Thread devices dropped
triggers:
  - trigger: state
    entity_id:
      # a handful of always-powered Thread-based entities spread around the house
      - sensor.office_air_quality_pm2_5
      - sensor.garage_air_quality_pm2_5
      - switch.fridge_outlet
    to: "unavailable"
    for: "00:03:00"
conditions:
  - condition: template
    value_template: >
      {{ ['sensor.office_air_quality_pm2_5','sensor.garage_air_quality_pm2_5',
          'switch.fridge_outlet']
         | select('is_state','unavailable') | list | count >= 2 }}
actions:
  - action: notify.notify
    data:
      title: "Thread mesh problem"
      message: "2+ Thread devices unavailable — check threadwatch status / freeze the ring buffer."
```

## 3. Without the import command

The OTBR add-on's REST API maps extended addresses to Thread records,
and HA's device registry has the names. Manual route: in an SSH session
on the HA host,

```bash
curl -s http://core-openthread-border-router:8081/api/devices
```

gives every `extAddress` the border router knows; cross-reference with
the HA UI (Settings → Devices → your Thread devices) and write
`config/devices.json` entries. Then let `threadwatch report`'s
unknown-address list catch newcomers and address rotations (Apple TVs
rotate; append, never replace, addresses: `threadwatch adopt <new-addr>
"Living Room Apple TV"` does exactly that).

## 4. Reading HA/OTBR evidence during an incident

The OTBR add-on journal (`ha addons logs core_openthread_border_router`)
is the border router's own view — `ChannelAccessFailure` lines there
correlating with threadwatch's flood windows is exactly the
cross-instrument proof that closed the 2026-09-01 incident.
