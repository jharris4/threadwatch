# Home Assistant

threadwatch does not depend on Home Assistant. But if HA is your Thread
controller, it already holds the two things the recorder needs from you,
the device names and the network key, and one command fetches both.

## 0. Import names, border routers and the network key

```bash
cp config/ha.example.env config/ha.env
# edit config/ha.env: HA_URL and HA_TOKEN (below)
chmod 600 config/ha.env
bin/threadwatch import            # shows what would change
bin/threadwatch import --write    # writes devices.json and credentials.toml
```

`threadwatch import` has two sources, each skippable (`--no-ha`,
`--no-mdns`): Home Assistant for the Matter devices and the key, and the
LAN itself (mDNS) for the border routers, which HA does not list (see
"Apple TVs" below). One plan, one `--write`. The rest of its options:

| option | when |
| --- | --- |
| `--url URL` | HA is not where `HA_URL` says (default `http://homeassistant.local:8123`) |
| `--env-file FILE` | the token lives somewhere other than `config/ha.env` |
| `--dataset-id ID` | HA holds several Thread datasets and none is preferred: the import stops and lists them, and this picks one |
| `--no-devices` / `--no-credentials` | write only the other file (the key without touching names, or names on a host that must not hold the key) |
| `--mdns-seconds N` | how long to wait for border routers to answer (default 4; raise it on a slow or reflected network) |

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
  node's diagnostics). HA is where you named them, so HA wins on those
  names: a device already listed under that address is renamed to the HA
  name if it differs (the plan says so before `--write`). A known name
  seen with a new address gains it, a missing model is filled in, and
  everything else is carried through: notes, extra addresses, entries no
  source knows such as HomeKit-only locks. Entries are never deleted.
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

**Apple TVs and HomePods are not in HA's Matter registry**, and they
change their Thread extended address on every reboot. The import's mDNS
source covers them: every border router advertises a stable hostname and
its current address, and the entry it writes carries both, for example

```json
{"name": "AppleTV Living Room", "borderRouter": "appletv-living-room.local",
 "extendedAddress": "C0FFEE0000000001", "model": "Apple BorderRouter"}
```

The name comes from mDNS only when the entry is created; rename it in the
file and your name stays. The recorder then asks the LAN every ten
minutes and, after a reboot, names the new address from the hostname
automatically (a `border_router_address_changed` notice says so); the
addresses in the entry are the fallback that still names the device if
mDNS is ever out of reach. mDNS is link-local: the host running the
import or the recorder must be on the routers' subnet, or your network
must reflect mDNS between VLANs (UniFi: the mDNS setting on the networks
involved; a Linux router: avahi's reflector). `threadwatch doctor` and
`threadwatch border-routers` report what the host can see (the latter
waits `--seconds N` for answers, 4 by default, and exits 1 when nothing
answers). HomeKit-only
end devices such as locks never appear anywhere: name those with
`threadwatch devices --suggest` and `threadwatch name`, or the
power-cycle method in docs/ANALYSIS.md.

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
      message: "2+ Thread devices unavailable — check threadwatch status / snapshot the ring buffer."
```

## 3. Without the import command

The OTBR add-on's REST API (rooted at `/node/...` and `/diagnostics`,
the same root `docs/CREDENTIALS.md` uses for the key) knows the mesh's
extended addresses, and HA's device registry has the names. Manual
route: in an SSH session on the HA host,

```bash
curl -s http://core-openthread-border-router:8081/diagnostics
```

gives every router's `ExtAddress` (children appear in their parent's
`ChildTable` by id only; `ot-ctl child table` on the border router
lists its own children's addresses); cross-reference with
the HA UI (Settings → Devices → your Thread devices) and write
`config/devices.json` entries. Then let `threadwatch devices`'s
unknown-address list catch newcomers and address rotations (Apple TVs
rotate; append, never replace, addresses: `threadwatch name <new-addr>
"Living Room Apple TV"` does exactly that).

## 4. Reading HA/OTBR evidence during an incident

The OTBR add-on journal (`ha addons logs core_openthread_border_router`)
is the border router's own view — `ChannelAccessFailure` lines there
correlating with threadwatch's flood windows is exactly the
cross-instrument proof that closed the 2026-09-01 incident.

If Home Assistant identifies multiple devices whose addresses already share one
inventory entry, import stops without writing inventory or credentials. Split the
named entry in `devices.json`, assigning notes, router hostname and historical
addresses to the appropriate device, then retry. This also applies when the HA
devices share a display name; names alone cannot settle ownership of history.
