# Thread credentials

threadwatch needs the Thread network key, and the recorder does not start
without it (`threadwatch doctor` says so; so does `threadwatch record`).
Most of what it watches lives behind MAC-layer encryption:

- Sleepy end devices poll and talk from their 16-bit short address and
  only use the extended address while attaching: the 2026-09-02 soak saw
  22 sleepy devices send ~250k frames in 9 h with zero extended-address
  frames among them. With the key, the recorder identifies a short address
  by trying every known extended address as the MAC nonce (a 32-bit MIC
  check per candidate, rate-limited per short address) and from then on
  attributes polls, RSSI, quiet/returned and poll starvation to the device.
- MLE messages are encrypted with a key derived from it: rejoin attempts,
  the partition and its leader, every router's RLOC16.
- SRP registrations, which name devices, sit inside 6LoWPAN.

Matter *application* payloads (sensor readings, commands) stay encrypted
even with the key: Matter has its own layer above Thread. You get
control-plane visibility and message flow, not device data.

## What the key does NOT expose

The key never leaves your capture host, is never logged, and is not
written into pcaps: frames are stored exactly as received and decrypted
on read, so payloads at rest remain encrypted. The web pages and the
event log carry names, addresses and MLE facts, never key material.

## Setup

Store the key in a **separate, gitignored, owner-only** file, never in
config.toml and never in git. `config/credentials.toml` is gitignored by
this repo and is the default path, so nothing in config.toml needs to
change.

**With Home Assistant:** `bin/threadwatch import --write` fetches the
key from HA's Thread dataset and writes the file at mode 0600 without
ever printing it (docs/HOME-ASSISTANT.md, including the token setup).

**By hand**, from any OpenThread border router:

```bash
# `ot-ctl networkkey` on the border router; or with the HA OTBR add-on,
# from an SSH session on the HA host,
#   curl -s http://core-openthread-border-router:8081/node/dataset/active
# and read "networkKey".

cat > config/credentials.toml <<'TOML'
[credentials]
network_key = "PUT_32_HEX_CHARS_HERE"
TOML
chmod 600 config/credentials.toml
```

`bin/push-to-host.sh` carries the file to the capture host with the rest
of the local config, overwriting the host's copy when both machines have
one and leaving a file that only the host has in place (INSTALL.md,
"Updating"); `setup-host.sh` locks it to mode 0400 there, where nobody
edits it (0600 here keeps it private and editable). To keep it somewhere
else, point config.toml at it:

```toml
[credentials]
file = "credentials.toml"     # relative to the config directory
```

`threadwatch record`, `replay` and `device` print `credentials: loaded` when
the file is good (`replay` and `why` on stderr, so their output stays
usable), and stop with the reason when it is missing or malformed.

## If the key rotates

Re-commissioning the Thread network gives it a new key. Capture keeps
running (the ring keeps every frame, encrypted as received), but nothing
decrypts any more; once a stretch of frames has failed with none
succeeding, the recorder logs `credentials_stale` at warning severity, so
it pages, and repeats it every six hours until the file is updated and
the recorder restarted.

## Every file that holds a secret

| file | holds | mode | travels |
| --- | --- | --- | --- |
| `config/credentials.toml` | the Thread network key | 0600 on a workstation, 0400 on the host | gitignored; `push-to-host.sh` carries it; never in the Docker image |
| `config/alerts.env` | tokens for alert sinks and heartbeats (ntfy, Gatus, Gotify, ...) | 0600 / 0400 | gitignored; carried; loaded into the daemon's environment |
| `config/ha.env` | the Home Assistant long-lived token and URL | 0600 / 0400 | gitignored; carried; read only by `threadwatch import` |
| `config/config.toml` | a Home Assistant webhook id in a sink URL, if you use one; nothing else | ordinary | gitignored; carried |

`data/` holds no secret: the pcaps are encrypted as received, the event
log and state files carry names, addresses and MLE facts. What the
recorder prints is safe to paste into a bug report: sink and heartbeat
URLs appear in the journal as scheme, host and port only, a command sink
as its program name, and `import`, `doctor`, `status` and `report` never
print a key or a token. The three things worth checking before pasting
are a `config.toml` with a webhook URL in it, a shell transcript that
`cat`ted one of the files above, and a pcap you share together with the
key that decrypts it.

## If a secret leaks

A config pasted whole into a bug report, a commit that went out before
`.gitignore` did, a laptop gone: per secret,

- **The network key.** Anyone holding it who can also hear your radio
  reads your Thread control plane (not Matter payloads, which have their
  own layer). The only remedy is a new key: re-commission the Thread
  network from your border router (with Home Assistant's OTBR add-on,
  create a new network in the Thread panel and re-add the devices; with a
  standalone OTBR, a new active dataset). Then `bin/threadwatch import
  --write`, or edit `credentials.toml` by hand, and restart the recorder;
  until then it logs `credentials_stale`. Old pcaps stay decryptable
  with the old key, which is what a leak means for them.
- **The Home Assistant token.** Revoke it where it was made (your HA
  profile, *Long-lived access tokens*), create a new one, put it in
  `config/ha.env`. It is only ever read by `import`, so nothing to
  restart.
- **A sink or heartbeat token.** Revoke and reissue it at the service
  (ntfy, Gatus, Gotify, Healthchecks, ...), update `config/alerts.env`,
  restart the daemon so the new environment loads.
- **A webhook id.** Change it in the HA automation and in the sink URL
  in `config.toml`, restart the daemon; `bin/threadwatch alert-test`
  confirms the new one.

Then push the corrected files to the host (`bin/push-to-host.sh`) and
run `bin/threadwatch doctor` there. A secret that reached git history
stays there after the file is deleted: rotate it, and rewrite or discard
the history only if the repository is shared.

## Decrypting old pcaps in Wireshark

Wireshark can decrypt the ring pcaps too: Preferences → Protocols → IEEE
802.15.4 → Decryption keys → add your key with key type "Thread hash".
Set (Protocols → Thread) the correct security suite. Then MLE, 6LoWPAN
and CoAP dissect in the GUI for any capture, retroactively.
