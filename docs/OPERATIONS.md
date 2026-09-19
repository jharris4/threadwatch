# Operating the recorder

What to do once the recorder is installed and something is off: where its
logs are, how to restart it, and what each line of `threadwatch doctor` or
the journal is asking you to do. Installation is INSTALL.md; the review
pages are docs/REVIEW.md; alerts are docs/ALERTING.md.

## Where the logs are

The daemon writes one line per thing worth knowing, each prefixed
`[threadwatch]`, to standard output. Under systemd that is the journal:

```bash
journalctl -u threadwatch -f          # live
journalctl -u threadwatch -n 200      # the last 200 lines, start-up included
journalctl -u threadwatch --since -1h # or since a time
journalctl -u threadwatch-web -n 50   # the review pages' own log
```

Under Docker it is `docker compose logs -f recorder` (and `web`); without a
supervisor it is the terminal you started `bin/threadwatch record` in. The
start-up lines say what was loaded (sinks, heartbeats, `credentials:
loaded`, `capturing channel N from /dev/...`), and every exit says why it
left (the "Exit codes" section below). Storm alerts, quiet devices and the
rest are events, not log lines: `bin/threadwatch events` and the review
pages read those back.

## Restarting

```bash
sudo systemctl restart threadwatch                 # the recorder
sudo systemctl restart threadwatch threadwatch-web # both, after a config or code change
docker compose restart recorder                    # the Docker equivalent
docker compose up -d --force-recreate recorder     # Docker, after editing config/alerts.env: a restart
                                                   # keeps the environment the container was created with
```

A restart is safe at any time. On SIGTERM the daemon saves the last-seen
table, closes the ring file and delivers the alerts it still holds before
leaving, and the quiet detector treats the seconds it was down as its own
blindness, not any device's silence. A unit that failed fast ten times in
ten minutes sits in `failed` and stays there until told otherwise:

```bash
systemctl is-failed threadwatch                       # "failed" means the start limit hit
journalctl -u threadwatch -n 50                       # ...and this says why
sudo systemctl reset-failed threadwatch && sudo systemctl restart threadwatch
```

`sudo bin/setup-host.sh` does the reset and the restart itself and reports
either unit that is not running afterwards.

## One recorder per host

Exactly one `threadwatch record` may run against a dongle and a data
directory. Nothing stops a second one, and it does damage before it
fails: it grabs the same auto-detected port, deletes and recreates the
shared `capture.fifo` (`capture-<label>.fifo` per radio with `[record]
radios`), and, before it has heard a frame, judges the shared
last-seen table as if it were the recorder and sends `device_quiet` and
`device_returned` events through the real sinks, so the household is
paged for nothing; then its sniffer thread cannot open the port the
service holds and it exits 4, saving the table on the way out. So before
running the recorder by hand, stop the service, and start it again after:

```bash
sudo systemctl stop threadwatch
bin/threadwatch record         # Ctrl-C when done
sudo systemctl start threadwatch
```

(Docker: `docker compose stop recorder`.) Everything else is safe beside
a running recorder: `doctor`, `status`, `devices`, `device`, `replay`,
`events`, `snapshots`, `snapshot`, `border-routers`, `alert-test`, `serve`,
and `name` and `import`, which write `config/` files the recorder reads
only at its next start. `replay` and `device` run the pipeline in a mode that
writes nothing to `data/state` and sends nothing to any sink.

## Exit codes and restarts

The daemon leaves with a code and a line saying why; the line is the
authority, since two failures share code 2. Under systemd `systemctl
status threadwatch` shows the code and `journalctl -u threadwatch -n 20`
the line; under Docker, `docker compose ps` and the log.

| exit | last line | meaning |
| --- | --- | --- |
| 0 | `stopped after N frames` | a requested stop (`systemctl stop`, Ctrl-C) |
| 1 | a traceback, then `recorder crashed` | an unexpected error; or, before capture began, `No nRF 802.15.4 sniffer found`, `2 nRF 802.15.4 sniffers found` with no `[record] radios` table, `none of the radios in [record] radios is plugged in`, or a refused `[alerts]` table |
| 2 | `threadwatch record: credentials.toml ...` or `threadwatch: [network] ...` | refused before capture began: no or bad network key, or a config value out of range |
| 2 | `no frames for Ns - capture stalled` | the watchdog: three minutes without a frame after capture had begun |
| 3 | `capture stream ended` | the sniffer closed the stream: dongle unplugged, or its process died. With several radios, only when the last of them went: one radio's stream ending is `radio_lost` and the run goes on |
| 4 | `sniffer thread died before delivering any data` | the serial port could not be opened: held by another process, or gone |
| 5 | `exit: <step> failed: ...` | the run ended the way it meant to, but a step of its shutdown did not: the ring would not close, or the last-seen table would not save (a full disk). What could still be saved was; the line names the step |

Every way out but a kill leaves `data/state/last-exit.json` saying which
of these it was; the next start logs a `recorder_started` event with that
cause and the time it was not listening, which is how a day page tells
the recorder's outage from a device's silence (docs/REVIEW.md, "Coverage").
A start that finds no note (a power cut, a SIGKILL) says the end is unknown.

Every non-zero exit asks the supervisor for a restart, and the systemd
unit gives one after ten seconds plus a two-second wait for udev. The
stall exit is the designed answer to a host sleep, a dongle that
re-enumerated or a sniffer that hung: a restart every few minutes with
`capture stalled` between is the recorder working as intended around a
dongle that hears nothing, not a fault in itself, and a dongle that does
hear frames ends the loop by itself. What the restart cannot fix is a
refused start (codes 1 and 2 before capture began): those repeat every
twelve seconds until the unit's start limit (ten in ten minutes) settles
it into `failed`, which is where "Restarting" above picks up. Before
leaving on the stall path the daemon flushes the ring file, saves the
last-seen table and delivers the alerts it holds, so a stall costs the
frames of the stall itself and nothing on disk.

### The other commands

The table above is `record`'s. It is not the only command whose exit
status means something: `bin/threadwatch <command> || notify` works for
each of these too.

| command | exit 1 | exit 2 |
| --- | --- | --- |
| `status` | no status file: the daemon has never run here, or `data_dir` points elsewhere. A clean liveness probe | |
| `doctor` | any `FAIL` line | |
| `alert-test` | any sink or heartbeat failed | |
| `border-routers` | none answered over mDNS | |
| `import` | Home Assistant refused, or `devices.json` will not parse | |
| `name` | the address is already listed under another name | |
| `device` | some of the pcap files could not be read (the report covers the rest) | no network key, or one that cannot be read |
| `replay` | | the same |
| `record` | | the same, or a config value out of range |
| `replay`, `device`, `snapshots --delete` | `--snapshot NAME` matches no snapshot, or more than one | |

`ha-availability set <device> (--hold DURATION | --mute | --clear)` and
`ha-availability list` edit and show `config/ha-availability.json`
(docs/HOME-ASSISTANT.md), resolving `<device>` through Home Assistant by
inventory name, extended address or HA device id; exit 1 when HA refuses,
the device is unknown or ambiguous, or the duration does not parse.

`snapshot [label]` exits 0 once the ring is copied, whatever became of the
Home Assistant add-on logs it copies afterwards with `[ha_logs] enabled`
(docs/ANALYSIS.md, "Snapshots"): it prints one progress line per add-on
while they arrive (lines, MB, elapsed, refreshed every 5 s on a terminal),
then the outcome, `ha-logs: complete` or `partial` / `failed` with the
reason; the recorder retries the latter. `--no-ha-logs` skips the copy, and
Ctrl-C during it keeps the snapshot and what arrived, marked partial.


## Troubleshooting

`bin/threadwatch doctor` is the first move: read-only, one line per check,
`ok` / `warn` / `FAIL`. Its exit status is 1 when any line is `FAIL` and
0 otherwise; a `warn` never fails it, and a check that crashes is a
`warn` too, so a cron job, a monitor or a CI step can run it and act on
the status alone (`bin/threadwatch doctor || notify`). What each
non-`ok` line means and what to do about it:

| doctor line | meaning | what to do |
| --- | --- | --- |
| `config` no config.toml was read | the built-in defaults are running, channel 25 included | `cp config/config.example.toml config/config.toml` and set your channel |
| `inventory` no devices.json | every address will be reported as unknown; the recorder runs fine | name devices: README "Naming devices" |
| `inventory` is not valid JSON / must be a JSON list | the recorder ignores the file, so every device is unknown until it is fixed | `python3 -m json.tool config/devices.json` names the line; fix it, restart |
| `inventory` ignored (not 16 hex digits) | that address is dropped and its device unnamed | fix the address (16 hex digits, no `0x`, no colons) |
| `inventory` with a blank name | those addresses still count as unknown | fill the names in |
| `credentials` the 'cryptography' package is missing | the interpreter doctor ran under cannot decrypt, and neither can the recorder | `sudo bin/setup-host.sh`, or `python3 -m venv .venv && .venv/bin/pip install -r requirements.txt` (`bin/threadwatch` prefers `.venv`) |
| `credentials` missing | no Thread network key: the recorder does not start | docs/CREDENTIALS.md, or `bin/threadwatch import --write` with Home Assistant |
| `credentials` is mode NNNN: readable by others | the key is world- or group-readable | `chmod 600 config/credentials.toml` |
| `credentials` network_key must be 32 hex digits / unusable | the file is there but the key is not | recreate it (docs/CREDENTIALS.md); a key from `ot-ctl networkkey` is 32 hex digits |
| `border routers` none found over mDNS | this host cannot hear the border routers' mDNS; an Apple hub's new address after a reboot will stay unnamed | put the host on the routers' subnet or reflect mDNS between VLANs (docs/HOME-ASSISTANT.md); `browse_s = 0` silences it if you have no Apple hubs |
| `dongle` configured port does not exist | `serial_port` in config.toml names a port that is gone | `ls /dev/serial/by-id/ /dev/ttyACM*`; fix or unset `serial_port` |
| `dongle` pyserial is not installed | as for `cryptography` above | same fix |
| `dongle` No nRF 802.15.4 sniffer found | nothing with the sniffer firmware is enumerated | `lsusb` should list Nordic Semiconductor; replug on a direct port; reflash if it is not an "nRF 802154 Sniffer" (SETUP.md) |
| `dongle` 2 nRF 802.15.4 sniffers found | two dongles and no `[record] radios` table: the recorder will not guess which is which | name both by serial (SETUP.md, "A second dongle"), or unplug one |
| `dongle` radio X: no sniffer with serial ... is plugged in | a configured radio's dongle is not enumerated | plug it in (any port); the recorder runs without it and looks for it every minute |
| `dongle` a sniffer with serial ... is not in [record] radios | a dongle the table does not name | add a `[[record.radios]]` table for it, or unplug it |
| `recorder` no status.json | the recorder has never run on this data directory | start it (`sudo systemctl start threadwatch`, or `bin/setup-host.sh`) |
| `recorder` not running: status last written N min ago | the recorder is down | `systemctl status threadwatch`; the journal says why it left (exit codes above) |
| `recorder` alive but no frames for N s | the dongle is up but hears nothing: wrong channel, or a silent mesh | check `[network] channel` against your border router's dataset (`threadwatch import` prints it); the watchdog restarts the recorder after 180 s regardless |
| `ring` no ring files yet | nothing captured yet | as for `recorder` |
| `ring` the ring stopped growing | no new hourly file in two hours | the `recorder` line says whether it is down or deaf |
| `last-seen` is unreadable | the last-seen table is damaged: no device has a history and none can go quiet | "What lives under data/" below |
| `last-seen` kept aside as last-seen.json.corrupt | an earlier table was moved aside after failing to parse | repair and put it back, or delete it (same section) |
| `blind-spans` is unreadable | the recorder does not know when it was last off, so a silence that spans one of its own outages is charged to the device in full | delete the file: the next outage rebuilds it, at the price of one round of `device_quiet` for anything quiet since before it |
| `disk` it will not fit | free space is below what a full ring needs | lower `keep_hours`, set `keep_gb`, or move `data_dir` |
| `disk` under 1 GB to spare | it fits, barely | same, before it does not |
| `writable` state / ring / snapshots dir | the service user cannot write there | `chown -R <user> data/`, or check the mount |
| `clock` NTP not synchronized | timestamps will not line up with other logs | `timedatectl`; `sudo timedatectl set-ntp true`; check the network |
| `services` not installed | the systemd units are not there | `sudo bin/setup-host.sh` |
| `services` failed / inactive | a unit is down | the journal says why; `reset-failed` and restart as above |
| `alerts.env` mode / `export` prefix | the file is readable by others, or has a line systemd will drop | `chmod 600`; write `NAME=value` |
| `ha.env` mode NNNN: readable by others | the Home Assistant long-lived access token is world- or group-readable | `chmod 600 config/ha.env` |
| `ha-logs` enabled but config/ha.env has no HA_TOKEN | `[ha_logs] enabled` and nothing to authenticate with: snapshots carry no add-on logs | put an admin user's token in `config/ha.env` (docs/HOME-ASSISTANT.md) |
| `ha-logs` HTTP 401 / 403: the token is not an admin user's | the add-on log endpoint goes through the Supervisor, which refuses non-admin tokens | create the token from an admin user's profile |
| `ha-logs` HTTP 404: no such add-on | an `[ha_logs] addons` slug HA does not know | `ha addons` on the HA host lists the slugs; the defaults are `core_openthread_border_router` and `core_matter_server` |
| `ha-logs` not reachable | HA did not answer at `HA_URL` within 10 s | check `HA_URL` in `config/ha.env` and that HA is up; the recorder retries snapshot fetches by itself |
| `ha-logs` newest line N min ago: the add-on looks stopped | the add-on's log has not moved in over ten minutes | start the add-on in HA; a stopped OTBR is a mesh with no border router |
| `ha-avail` ha-availability.json ... : the availability check is off | the per-device settings file does not parse or has a wrong type; the recorder runs without the check | fix the entry named (`hold_s` a number, `mute` true/false), restart |
| `ha-avail` enabled but config/ha.env has no HA_TOKEN | nothing is polled | put a token in `config/ha.env` (docs/HOME-ASSISTANT.md) |
| `ha-avail` GET /api/states ... failed | HA did not answer the poll endpoint | check `HA_URL` and that HA is up; the recorder logs `ha_unreachable` after five minutes of this |
| `ha-avail` N not in devices.json, watched under their HA names | HA has Thread devices the inventory does not | `threadwatch import --write` adds them |
| `ha-avail` device(s) with no usable entity, so never judged | every entity of the device is disabled, or HA lists none | enable one in HA, or accept that the device is not judged |
| `ha-avail` entries for device id(s) Home Assistant no longer has | stale settings for a removed device | delete them from `config/ha-availability.json`, or leave them: they do nothing |
| `ha-avail` name or extendedAddress out of date | a device was renamed in HA or in devices.json | `threadwatch import --write` refreshes them |
| `ha-logs` the hourly archive has nothing yet | `[ha_logs] archive` is on and no hour has been archived | it fills two minutes after the next hour while the recorder runs; check the recorder is up |
| `ha-logs` archive up to H UTC (N min behind): the archive has not kept up | the newest archived hour ended more than two hours ago | the recorder is down, or HA has not answered (the `ha_logs_archive_stalled` event says since when); the pending hours are retried every 15 min while the journal can still have them |
| `alerts` alert sink 'x' disabled: environment variable(s) not set | a `${NAME}` the sink references is not in `config/alerts.env`; the daemon runs without that sink | add it to alerts.env, restart |
| `alerts` the recorder refuses to start on this table | a sink or heartbeat with no url, an unknown type, or two sharing a name | fix `[alerts]` / `[[heartbeats]]` in config.toml (docs/ALERTING.md) |
| `alerts` no sinks / `heartbeats` none | nothing pages you, or nothing pages when the recorder dies | optional; docs/ALERTING.md |
| `web` nothing answers on port N | the review pages are not up | `systemctl status threadwatch-web`; `[web] port` in config.toml |
| `version` threadwatch X (commit), service started T | which code is on this host and since when | never a failure; it is how you tell a deploy that landed from one that did not, since every other line answers the same either way |

Every hint in the doctor line itself is also the fix.

## Journal lines that mean something

The daemon's own diagnostics, with what to do when one keeps appearing:

- **`sniffer thread died before delivering any data (serial port busy or
  gone?)`**, then exit 4: the dongle's port could not be opened. Usually a
  second recorder holds it (`ps ax | grep 'threadwatch record'`; see
  "One recorder per host" above), or the dongle left between
  enumeration and open. Stop the extra process, or replug the dongle.
- **`no frames for Ns - capture stalled (host slept? dongle gone?)`**, then
  exit 2: three minutes without a frame. systemd restarts the daemon after
  ten seconds and that usually is the fix (a host that slept, a dongle that
  re-enumerated). Repeating every few minutes: the dongle hears nothing at
  all. Check the channel, then the dongle (`lsusb`; replug; SETUP.md's
  connector notes).
- **`capture stream ended (dongle unplugged? sniffer died?)`**, then exit
  3: the sniffer closed the stream. Replug; if the dongle no longer
  enumerates as an nRF 802154 Sniffer, reflash (SETUP.md).
- **`credentials.toml is missing`** / **`network_key must be 32 hex
  digits`**, then exit 2 before capture starts: docs/CREDENTIALS.md.
- **`devices.json is not valid JSON`**: the recorder runs with no names.
  Fix the file, restart.
- **`last-seen.json is unreadable ... starting from an empty table`**: see
  "What lives under data/".
- **`alert sink 'x' failed: ...`**: one delivery to that sink did not go
  through; capture is unaffected. `bin/threadwatch alert-test` reproduces it
  from a shell with `config/alerts.env` loaded.
- **`mdns browse failed`** or **`mdns: X advertises Y, which has not been
  heard`**: the LAN answered oddly; the recorder ignores the answer. Only a
  problem if a rebooted Apple hub stays unnamed (docs/HOME-ASSISTANT.md).

## Several radios

With `[record] radios` in config.toml (SETUP.md, "A second dongle") the
recorder captures from every dongle named there, by serial, and judges
one merged stream: a frame two radios heard reaches the detectors once,
with each radio's reception kept; a MAC retry of the same bytes is still
two frames, told apart by time (the radios' clocks are aligned to within
tens of microseconds, and a retry is milliseconds later). Each radio
writes its own ring series, `threadwatch-YYYYMMDD-HH-<label>.pcap`
beside the primary's plain names, and everything that reads the ring
(`replay`, `device`, snapshots) reads an hour's files together.

What changes in operation:

- A radio named in the table but not plugged in at start is
  `radio_missing` (notice); the run starts with the rest and looks for
  it by serial every minute, so it may come back on any port. Nothing
  plugged in at all is a refused start (exit 1).
- A radio that stops delivering for three minutes while another still
  hears, or whose dongle goes away, is `radio_lost` (warning): it is
  detached, the run goes on, and it is looked for every minute;
  `radio_returned` when it is back. The whole-run stall and
  stream-ended exits apply only when every radio is gone.
- A device whose recent sightings all came from a radio now down is out
  of the recorder's earshot, which cannot be told from silent: its
  `device_quiet` (and a confirmed `poll_starvation`) is logged at notice
  with `reception: unheard` and the radio named, not paged, until
  another radio hears it.
- `status.json` carries a `radios` block (below) and the status page a
  row per radio: state, port, placement, last frame, frames, and for
  every radio but the primary the clock lock (offset, drift in ppm,
  jitter). `doctor` prints a line per configured radio and warns about
  a plugged-in dongle the table does not name, serial included.
- The devices page and `threadwatch device` say which radios hear each
  device, how much of it, and at what level.

A radio with `source = "tcp"` is a `threadwatch relay` on another host
(SETUP.md, "A dongle on another host"): the recorder listens on its
`listen` address, checks each connection's handshake (the radio's
label, the channel, the dongle's serial when configured) and refuses
one that does not match, with the reason in the journal; a relay
connecting is `radio_attached` or `radio_returned`, one disconnecting
`radio_lost`, and the relay reconnects by itself. The relay exits 3
when its own dongle's stream ends, for its supervisor to restart.

Attaching a dongle opens its port and forks the sniffer's reader
process; the recorder does this one radio at a time, because a fork
taken while another radio's port is open in the process inherits that
port's lock and the other radio can never open it. That is the
recorder's problem to get right, not yours, but it is why a second
radio takes a moment longer to start.

## Reading `threadwatch status`

`bin/threadwatch status` prints `data/state/status.json`, which the daemon
rewrites every 30 seconds, plus two fields it works out on the spot:
`status_age_s`, how old the file is, and `daemon_alive`, true when it is
under 90 seconds old — three missed writes. An empty or damaged status
file is not a fresh one: it prints one line and exits 1 rather than
reporting a recorder it has no evidence of. That one age is what the
page header, the status page, `doctor` and the coverage timeline all read
the file by, so they cannot disagree about whether the recorder is
running. (`/status` and `/api/status` on the review pages show the same
file.) The fields:

| field | meaning |
| --- | --- |
| `updated` | when the file was written (unix seconds) |
| `version`, `commit` | the threadwatch version and git commit that is recording. This is how you tell a deploy that landed from one that did not; `bin/threadwatch --version` prints the same pair for the checkout you are standing in, and `doctor`'s `version` line for the host |
| `last_frame_age_s` | seconds since this run last heard a frame, on the daemon's own clock; the watchdog exits at 180 |
| `last_frame_ts` | when any run last heard a frame (unix seconds); unlike the age it spans restarts, and stays put while nothing is heard |
| `port`, `channel` | the dongle's serial port (the primary's, with several) and the channel being captured |
| `merge` | with `[record] radios`: `merged`, frames handed to the detectors this run; `duplicates`, copies folded into another radio's frame (what both heard); `pending`, copies waiting for the other radio. `merged` sits between the busier radio's `frames_total` and the radios' totals added together |
| `radios` | with `[record] radios`: one entry per radio by label with its `port`, `serial`, `placement`, `state` (`up`, `down`, `missing`), `since_s`, `frames_total`, `last_frame_age_s`, `dropped_lines`, its own `current_file`, and `lock`: `null` for the primary, else the merger's alignment of its clock to the primary's (`locked`, `offset_ms`, `ppm`, `sigma_us`, `pairs`, `locks`). A single unnamed dongle shows one entry, `radio` |
| `frames_total` | frames this run; it should climb between two runs of `status` |
| `dropped_lines` | serial lines from the dongle the sniffer could not parse this run: frames nobody recorded. A steady climb is a cable or firmware problem, not a quiet mesh |
| `uptime_s` | this run's age |
| `current_file` | the ring file being written; `null` until this run's first frame opens one |
| `devices_tracked` | addresses heard this run |
| `dominant_pan` | the PAN the recorder judges by: `[network] pan_id`, else the one it adopted (ten frames to adopt, twice as many to replace); `null` before it has one. `devices` and the review pages read it here, so quiet and foreign mean the same thing everywhere |
| `partition` | null until the MLE layer has seen an advertisement, then `id`, `leader_router` (the leader's router id), `leader_rloc16`, and `leader_addr` / `leader_name` once that router id has been matched to a device |
| `detector` | the storm detector: `baseline_frames_per_window` (calm frames per 10 s), `recent_windows` (the last six counts), `storm_active`, `flood_onsets_recent`, `alerts_sent` |
| `crypto` | the decryption counters, below, and `key_sequence`, the highest Thread key sequence a frame has decrypted under (null until one has) |
| `ha_availability` | null unless `[ha_availability]` is on; then `enabled` (false with a `reason` when the settings file would not load), `reachable`, `last_poll_ts`, `last_ok_ts`, `devices_mapped`, `burst` (the live burst's id) and `open`: the devices unavailable in HA right now, each with `name`, `addr`, `since`, `paged`, `severity`, `burst_id` |
| `ha_logs_archive` | null unless `[ha_logs] archive` is on; then per add-on `last_archived` (the newest hour in `data/ha-logs/`, a UTC hour name), `hours_on_disk`, `pending` (hours a fetch has failed for and will be retried) and `lost` (hours that rolled out of HA's journal before they could be fetched) |
| `keys` | the key generations as the recorder records them (docs/ALERTING.md, `key_sequence_advanced`): `highest` and `previous`, `highest_first_ts` and `previous_first_ts` (when each was first heard), `first_sender` (which address was heard first under the highest), `suspects` (unconfirmed origin candidates: the first sender, and every device since whose first frame on the new generation came while its parent was still on the old one; each with `evidence`, `parent` and `parent_generation`, as `key_sequence_advanced` records them) and `scope`, `confidence`, `reasons` (observation provenance; legacy state defaults to unknown), the interval facts of the last advance (`observed_interval_s`, `sequence_delta`, `observation_kind`, `coverage`, `scheduled_expectation`, `early_against_configured_interval`, as `key_sequence_advanced` records them; absent in legacy state), plus `census_at` (when the census for it is due, null once sent). Empty until a frame has been accepted under any generation. `highest` can trail `crypto.key_sequence` for a moment: the decryptor's value moves on any frame that decrypts, this one on a frame the pipeline accepted as a sighting |
| `alerts` | this run's deliveries: `delivered`, `queued` (held for a send or a retry), `retrying` (failed at least once), `given_up` (too old to retry), `resumed` (taken from the spool the last run left; docs/ALERTING.md) |

**The crypto counters** say whether the network key is right. Per MAC
frame: `plaintext` (unsecured, nothing to do), `mac_decrypted`,
`mac_failed`, `mac_no_ext_addr` (a frame from a short address the
recorder has not yet matched to an extended one, so it could not try),
and `mac_unsupported` (secured some other way than Thread's ENC-MIC-32
with key index mode, or cut short inside its security header: never
tried, so it counts as neither decrypted nor failed).
Per MLE message: `mle_decrypted`, `mle_failed`, `mle_unsecured`.
`short_resolved` / `short_unresolved` count the short-address searches
that found and did not find a sender; `parse_failed` is frames the
6LoWPAN layer could not walk.

- Healthy: `mac_decrypted` and `mle_decrypted` climb; `mac_failed` and
  `mle_failed` climb too, more slowly, from devices on neighbouring meshes
  and frames caught mid-air. A third of MLE failures is unremarkable when
  another mesh is in range.
- Wrong or rotated key: `mac_decrypted` and `mle_decrypted` stay at 0 (or
  stop climbing) while the two `failed` counters keep going. After 200
  such failures with no success the recorder logs `credentials_stale`
  (docs/CREDENTIALS.md); `status` shows it sooner.
- Sleepy devices unattributed: `mac_no_ext_addr` and `short_unresolved`
  climbing with `short_resolved` flat means the senders are not in
  `devices.json`, which is where the search takes its candidates.

## What lives under data/

`data/` (or `[record] data_dir`) is everything the recorder knows. Back
it up if you care about the history; nothing else holds it.

    data/
      ring/threadwatch-YYYYMMDD-HH.pcap   hourly captures, the oldest pruned past keep_hours / keep_gb
      snapshots/<stamp>_<label>/          saved copies of the ring (docs/ANALYSIS.md)
      ha-logs/<slug>/YYYYMMDD-HH.log.gz   with [ha_logs] archive: one gzip per UTC hour of each Home Assistant
                                          add-on's log (core_openthread_border_router, core_matter_server),
                                          fetched two minutes after the hour ends; as many hours as the ring
                                          keeps ([record] keep_hours), the oldest pruned. UTC because the
                                          journal stamps are, where ring files are named by local hour
      state/
        status.json          the daemon's status, rewritten every 30 s (below)
        last-seen.json       one row per extended address: first and last heard, frame count,
                             PAN, average RSSI, the RLOC16 it last used, whether its silence
                             or its poll starvation has been announced, and the highest frame
                             counter accepted under each of the last two key generations, so a
                             restart takes neither a replay for a sighting nor a key rotation
                             for silence. counter_seq / counter_ts (and the mle_ pair) are the
                             newest generation the device sent under and when, which the
                             key-lag detector judges; an open key-lag episode lives on the row
                             as keylag_since, keylag_confirm_at, keylag_parent, keylag_role,
                             keylag_gens and keylag_sent, with keylag_closed and
                             keylag_episodes for the hold-down; rejoin_ts is the device's last
                             MLE rejoin attempt. A backward clock step
                             (clock_step with a negative step_s) moves every timestamp in this
                             file back with the clock: it is the one thing that rewrites history
                             here rather than adding to it
        observed-names.json  SRP hostnames harvested from the mesh (devices --suggest uses them)
        frames-by-hour.json  frames per hour, the last day or so, for the daily summary
        retransmissions.json the retransmission detector's last 30 minute rates and the
                             elevation in progress, so a restart mid-elevation keeps its baseline
        storm.json           the storm detector's traffic windows, onsets and last page, so a
                             restart mid-storm is not blind for five minutes and does not page
                             the same storm again
        key-generations.json the highest key generation heard, the one before, when each was
                             first heard and from whom, and when the census for it is due: a
                             restart never announces a rotation twice (docs/ALERTING.md,
                             key_sequence_advanced)
        ha-logs-archive.json with [ha_logs] archive: per add-on the last hour archived, the hours
                             still pending (attempts, last error) and the hours lost, plus the
                             outage in progress, so a restart carries on where the archive stopped
        ha-map.json          with [ha_availability]: HA device id -> extended address, HA name, the
                             inventory's name for it, and the entities whose state counts; rebuilt
                             over the websocket once an hour and cached so a restart polls at once
        ha-availability.json with [ha_availability]: the open episodes (since, paged, burst), the
                             recent closes (for the flap guard), the live burst and whether HA is
                             reachable, so a restart neither re-pages nor forgets an outage
        blind-spans.json     when the recorder was not listening (its own outages, clock steps),
                             kept while a device's silence still reaches back over one
        last-exit.json       how the last run ended (stopped, stalled, crashed, ...) and when; the
                             next start reads it into its recorder_started event and removes it
        alert-spool.jsonl    alerts a sink still refused when the last run stopped; the next start
                             sends them and removes the file (docs/ALERTING.md)
        border-routers.json  mDNS hostname -> current address of each border router, with the
                             addresses it retired (how a rebooted Apple hub keeps its name)
        capture.fifo         the pipe the sniffer writes into; recreated at every start
        events/YYYY-MM-DD.jsonl   the event log (docs/REVIEW.md, "Storage")
        events.jsonl.migrated     a pre-day-rolling events.jsonl, kept after it was split into
                                  day files. Never pruned, and safe to delete: every record in
                                  it is in the day files

Every state file is written whole and renamed into place, so a power cut
leaves the previous version, never half of one. The daemon owns them:
edit or remove one only while it is stopped, since it rewrites them every
30 seconds and at exit.

**Deleting state.** With the daemon stopped, any of these can go, at a
price. `status.json` comes back within 30 s. `capture.fifo` is recreated
at start. `observed-names.json` is re-learned as devices re-register
(hours to a day). `frames-by-hour.json` costs the next daily summary an
accurate frame count. `storm.json` costs the next start about five minutes of
blindness to a storm already running, and one repeat page for it.
`key-generations.json` costs one repeated `key_sequence_advanced` (info) for
the generation the mesh is on, and the census that follows it.
`ha-logs-archive.json` costs the memory of which hours were lost and how
often a pending one was tried; the next pass starts the catch-up at the
edge of `[ha_logs] max_hours`, and every hour the archive already holds is
left alone. `ha-logs/` is the archive itself: delete it and the hours it
held are gone for good, since HA's journal has long since let them go.
`ha-map.json` is rebuilt at the next poll; `ha-availability.json` costs
one `already_unavailable_at_start` notice per device down at the time and
one repeated page for an episode already paged. `border-routers.json` is rebuilt at the next mDNS
browse, but the retired addresses in it are forgotten, so an Apple hub's
history from before its last reboot loses its name. `last-seen.json` is
the expensive one, below. The event log and the ring are your history and
are never worth deleting; the ring prunes itself.

**A damaged last-seen table.** When `last-seen.json` does not parse the
daemon says so in the journal, starts from an empty table, and at its
first save moves the broken file to `last-seen.json.corrupt` (a
`.corrupt-<epoch>` name if one is already there) instead of writing over
it; `threadwatch doctor` reports the unreadable file as a `FAIL` and the
kept copy as a `warn` until it is gone. What the loss costs: every
device's first-seen date, frame counts and RSSI average; which silences
and starvations were announced, so a device that died while the table was
broken is never reported quiet (there is no history to judge it against)
until it has been heard again and gone quiet again; and the short-address
mappings that let sleepy devices be attributed from their first frame,
which are re-learned within minutes. To put it back:

```bash
sudo systemctl stop threadwatch
python3 -m json.tool data/state/last-seen.json.corrupt   # says where it breaks
# fix it in an editor (a truncated tail: close the last complete row's braces),
# until json.tool prints the table; it is one JSON object keyed by address
mv data/state/last-seen.json.corrupt data/state/last-seen.json
sudo systemctl start threadwatch
bin/threadwatch doctor                                   # last-seen: N address(es) with a history
```

A file that cannot be repaired is worth nothing: delete the `.corrupt`
copy and doctor stops warning. Either way the empty table the daemon
started with fills itself as devices are heard, and the review pages
carry on from the event log, which is untouched.

## The dongle stops responding

Unplug it and plug it back in, on a direct port rather than a hub. It
re-enumerates, the watchdog exits the daemon within three minutes if it
had not already, and systemd starts it again (its unit waits two seconds
for udev). With several radios the daemon does not exit for one of them:
it logs `radio_lost`, carries on with the rest, and picks the dongle up
again by serial within a minute of its return (`radio_returned`). Then:

```bash
lsusb                                  # Nordic Semiconductor ... nRF 802154 Sniffer
ls /dev/serial/by-id/ /dev/ttyACM*     # a port appears
bin/threadwatch doctor                 # the dongle line names it
```

No LED at all is the connector, not the firmware; a dongle that enumerates
as something other than the sniffer has lost its firmware and wants
`bin/flash-dongle.sh` (SETUP.md). Nothing else is needed: the ring, the
event log and the last-seen table are all on disk, and the restart gap is
not counted against any device.
