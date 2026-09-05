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

Under Docker it is `docker compose logs -f capture` (and `web`); without a
supervisor it is the terminal you started `bin/threadwatch capture` in. The
start-up lines say what was loaded (sinks, heartbeats, `credentials:
loaded`, `capturing channel N from /dev/...`), and every exit says why it
left (the "Exit codes" section below). Storm alerts, quiet devices and the
rest are events, not log lines: `bin/threadwatch events` and the review
pages read those back.

## Restarting

```bash
sudo systemctl restart threadwatch                 # the recorder
sudo systemctl restart threadwatch threadwatch-web # both, after a config or code change
docker compose restart capture                     # the Docker equivalent
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

## Troubleshooting

`bin/threadwatch doctor` is the first move: read-only, one line per check,
`ok` / `warn` / `FAIL`, exit status 1 when anything fails. What each
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
| `capture` no status.json | the daemon has never run on this data directory | start it (`sudo systemctl start threadwatch`, or `bin/setup-host.sh`) |
| `capture` daemon not running: status last written N min ago | the daemon is down | `systemctl status threadwatch`; the journal says why it left (exit codes below) |
| `capture` daemon alive but no frames for N s | the dongle is up but hears nothing: wrong channel, or a silent mesh | check `[network] channel` against your border router's dataset (`threadwatch import` prints it); the watchdog restarts the daemon after 180 s regardless |
| `ring` no ring files yet | nothing captured yet | as for `capture` |
| `ring` the ring stopped growing | no new hourly file in two hours | the `capture` line says whether the daemon is down or deaf |
| `last-seen` is unreadable | the last-seen table is damaged: no device has a history and none can go quiet | "What lives under data/" below |
| `last-seen` kept aside as last-seen.json.corrupt | an earlier table was moved aside after failing to parse | repair and put it back, or delete it (same section) |
| `disk` it will not fit | free space is below what a full ring needs | lower `keep_files`, set `keep_gb`, or move `data_dir` |
| `disk` under 1 GB to spare | it fits, barely | same, before it does not |
| `writable` state / ring / incidents dir | the service user cannot write there | `chown -R <user> data/`, or check the mount |
| `clock` NTP not synchronized | timestamps will not line up with other logs | `timedatectl`; `sudo timedatectl set-ntp true`; check the network |
| `services` not installed | the systemd units are not there | `sudo bin/setup-host.sh` |
| `services` failed / inactive | a unit is down | the journal says why; `reset-failed` and restart as above |
| `alerts.env` mode / `export` prefix | the file is readable by others, or has a line systemd will drop | `chmod 600`; write `NAME=value` |
| `alerts` alert sink 'x' disabled: environment variable(s) not set | a `${NAME}` the sink references is not in `config/alerts.env`; the daemon runs without that sink | add it to alerts.env, restart |
| `alerts` the recorder refuses to start on this table | a sink or heartbeat with no url, an unknown type, or two sharing a name | fix `[alerts]` / `[[heartbeats]]` in config.toml (docs/ALERTING.md) |
| `alerts` no sinks / `heartbeats` none | nothing pages you, or nothing pages when the recorder dies | optional; docs/ALERTING.md |
| `web` nothing answers on port N | the review pages are not up | `systemctl status threadwatch-web`; `[web] port` in config.toml |

Every hint in the doctor line itself is also the fix.

## Journal lines that mean something

The daemon's own diagnostics, with what to do when one keeps appearing:

- **`sniffer thread died before delivering any data (serial port busy or
  gone?)`**, then exit 4: the dongle's port could not be opened. Usually a
  second capture process holds it (`ps ax | grep 'threadwatch capture'`; see
  "One capture process per host" below), or the dongle left between
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

## The dongle stops responding

Unplug it and plug it back in, on a direct port rather than a hub. It
re-enumerates, the watchdog exits the daemon within three minutes if it
had not already, and systemd starts it again (its unit waits two seconds
for udev). Then:

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
