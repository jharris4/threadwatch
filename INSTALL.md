# Recorder host setup

Any Linux with Python ≥ 3.11 and a USB port works. macOS works the same
way (skip the systemd part and run `bin/threadwatch capture` in a
terminal or launchd job). The walkthrough below is a Raspberry Pi 4.

## 1. Image the Pi

Raspberry Pi Imager → Raspberry Pi OS **Lite (64-bit)** → Edit settings:

- Hostname: `threadwatch`
- Username: `pi`
- Wi-Fi: prefer a 5 GHz SSID if you have one, so the Pi's own radio adds
  nothing to 2.4 GHz near your Thread network (Wi-Fi ch 1–11 sits below
  Thread ch 25/2475 MHz, so this is a nicety, not a requirement)
- Services: enable SSH, public-key auth, paste your `~/.ssh/id_*.pub`

Boot it and confirm `ssh pi@threadwatch.local` works.

## 2. Install (reproducible, two commands)

From your workstation, with this repo checked out (this also carries your
local config.toml / devices.json / credentials.toml, which git never sees):

```bash
bin/push-to-host.sh pi@threadwatch.local
```

That rsyncs the repo to the host and runs `sudo bin/setup-host.sh` there,
which is idempotent and does everything: apt packages (python3-serial,
python3-cryptography), dialout group, config scaffolding, credentials file
permissions, systemd unit install + enable. Re-run either script any time.

Two gotchas the scripts assume you've handled once:

- **Passwordless sudo**: current Raspberry Pi OS images may not grant it.
  One-time fix (typing the Pi password once):
  `ssh -t pi@threadwatch.local 'sudo sh -c "echo \"pi ALL=(ALL) NOPASSWD: ALL\" > /etc/sudoers.d/010_pi-nopasswd"'`
- **The Imager's SSH key field wants the key CONTENT** (the one-line
  `ssh-ed25519 AAAA... user@host` from `cat ~/.ssh/id_ed25519.pub`),
  not a file path.

Manual/cloning alternative: `git clone` works too (while the repo is
private the host needs auth - gh login or a deploy key), then run
`sudo bin/setup-host.sh` on the host.

## 3. Dongle

Flash it with the sniffer firmware if not already done — see `SETUP.md`
(`bin/flash-dongle.sh` runs on the Pi itself; no other computer needed).
Plug it in; `lsusb` should show *Nordic Semiconductor* and
`ls /dev/ttyACM*` a serial port.

## 4. Run as a service

```bash
sudo cp systemd/threadwatch.service /etc/systemd/system/
# edit it if your username/clone path differ
sudo systemctl daemon-reload
sudo systemctl enable --now threadwatch
bin/threadwatch status        # frames_total should be climbing
journalctl -u threadwatch -f  # live log incl. storm alerts
```

## 5. Placement & storage notes

- Put the Pi + dongle **near your Thread border router** — the capture
  should represent what the border router's radio hears.
- Storage: ~30 MB/hour ≈ 5 GB/week for a mid-sized mesh, pruned
  automatically (`keep_files`; `keep_gb` caps the total size when the
  card is the harder limit). That write rate is fine for a good SD
  card; a small USB SSD is nicer if you have one. Set
  `data_dir` in config.toml to point at it.
- Time sync (NTP) is on by default in Raspberry Pi OS — leave it; pcap
  timestamps that match your other logs are half the value.

## 6. Day-2 operations

```bash
bin/threadwatch doctor          # dongle, key file, disk, clock, services, ring, sinks: ok/warn/FAIL
bin/threadwatch status          # daemon alive? frames flowing? storm state?
bin/threadwatch report          # who's gone quiet; unknown addresses to name
bin/threadwatch adopt <addr> "<name>"   # ...and name one (report --suggest drafts entries)
bin/threadwatch events --episodes   # what happened lately, grouped
bin/threadwatch why "<name>" --hours 6  # one device's story from the recent ring files
# ...or open http://<pi>:8080/ for the same thing day by day (docs/REVIEW.md)
bin/threadwatch freeze mylabel  # preserve the ring buffer NOW (incident!)
bin/threadwatch incidents       # what is frozen and how big; --delete <name or label> when done with one
bin/threadwatch replay f.pcap   # run detection over any pcap
```
