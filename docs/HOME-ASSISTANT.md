# Optional Home Assistant integration

threadwatch needs none of this to work. But if you run Home Assistant
(especially with the OTBR add-on), these extensions make it stronger in
both directions.

## 1. Receive storm alerts in HA

`config.toml`:

```toml
[alerts]
webhook_url = "http://homeassistant.local:8123/api/webhook/threadwatch-storm"
```

HA automation:

```yaml
alias: Threadwatch storm alert
triggers:
  - trigger: webhook
    webhook_id: threadwatch-storm
    local_only: true
actions:
  - action: notify.notify
    data:
      title: "Thread storm detected"
      message: "{{ trigger.json.message }}"
```

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

## 3. Seed devices.json from OTBR (name mapping)

The OTBR add-on's REST API maps extended addresses to Thread records,
and HA's device registry has the names. Practical manual route: in an
SSH session on the HA host,

```bash
curl -s http://core-openthread-border-router:8081/api/devices
```

gives every `extAddress` the border router knows; cross-reference with
the HA UI (Settings → Devices → your Thread devices) and write
`config/devices.json` entries. Do this once, then let
`threadwatch report`'s unknown-address list catch newcomers and address
rotations (Apple TVs rotate; append, never replace, addresses).

HomeKit-only Thread devices never appear in HA — name those with the
power-cycle method in docs/ANALYSIS.md.

## 4. Reading HA/OTBR evidence during an incident

The OTBR add-on journal (`ha addons logs core_openthread_border_router`)
is the border router's own view — `ChannelAccessFailure` lines there
correlating with threadwatch's flood windows is exactly the
cross-instrument proof that closed the 2026-09-01 incident.
