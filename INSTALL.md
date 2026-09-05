# Recorder host setup

Any always-on Linux box with Python ≥ 3.11 and a USB port. systemd is
used when present and optional otherwise. Debian and Raspberry Pi OS are
the tested path; Fedora, Arch and openSUSE are handled by the same
script. A Raspberry Pi 4 is plenty and the from-scratch walkthrough for
one is at the end. Two alternatives: [Docker](docs/DOCKER.md) for
NAS-style hosts, and macOS for desk use (see below).

## 1. Get the code

```bash
git clone https://github.com/jharris4/threadwatch.git
cd threadwatch
```

## 2. Set up the host (one command, idempotent)

```bash
sudo bin/setup-host.sh              # the recorder runs as you
sudo bin/setup-host.sh --user bob   # ...or as another user
```

It does everything after the OS is installed: the two Python packages
(pyserial, cryptography) from your distro, falling back to a repo-local
venv where there is no apt/dnf/pacman/zypper; serial-port group
membership (dialout or uucp); `config/config.toml` from the example if
missing; credentials and alerts.env locked to 0400 if present; the two
systemd units installed, enabled and started with your user and clone
path filled in. Re-run it after any change, including an update.

Then edit `config/config.toml`: at minimum the Thread **channel**, and
create `config/credentials.toml` with the Thread **network key**
(docs/CREDENTIALS.md says where to find it): the recorder does not start
without it. Log out and in once if the group membership was new.

**Without setup-host.sh**, the equivalent by hand is: install pyserial
and cryptography (or `python3 -m venv .venv && .venv/bin/pip install -r
requirements.txt`, which `bin/threadwatch` picks up automatically), add
yourself to the serial group, copy the example config, and install the
units with the one-liner in the header of `systemd/threadwatch.service`.

## 3. Dongle

Flash it with the sniffer firmware if not already done: `SETUP.md`
(`bin/flash-dongle.sh` runs here, on this host — 64-bit Linux and macOS
alike; the dongle keeps the firmware, so it is once per dongle). Plug it
in; `lsusb` should show *Nordic Semiconductor* and `ls /dev/ttyACM*` a
serial port. Auto-detection finds it by USB id;
`serial_port` in config.toml pins one if you have several.

## 4. Check

```bash
bin/threadwatch doctor        # every line ok, including "services"
bin/threadwatch status        # frames_total should be climbing
journalctl -u threadwatch -f  # live log incl. storm alerts
```

The review pages are at `http://<host>:8080/` (`[web]` in config.toml).

A recorder that cannot start at all (no credentials, no dongle, a config
it refuses) is restarted every 12 s until systemd's start limit (ten
starts in ten minutes) settles it into `failed`, where `systemctl
is-failed threadwatch` and `setup-host.sh` say so. Once the cause is
fixed: `sudo systemctl reset-failed threadwatch && sudo systemctl restart
threadwatch` (`setup-host.sh` does both). The stall watchdog's restarts
are minutes apart and never reach the limit.

## 5. Updating

```bash
git pull
sudo systemctl restart threadwatch threadwatch-web   # or: sudo bin/setup-host.sh
```

The old code keeps running until you restart both units; `bin/threadwatch
doctor` afterwards is the check that the deploy landed. State (last-seen
table, event log, ring) lives under `data/`, so a restart loses nothing
but the few seconds the daemon is down; the quiet detector knows about
that gap and does not count it against any device.

If you develop on a workstation and deploy to the host, `bin/push-to-host.sh
user@host --push-only` rsyncs what git tracks, plus `config/` with its
gitignored secrets, then restart as above. An uncommitted edit to a tracked
file still ships; a file that was never committed does not, and the script
warns when one of those is a `.py` or lives in `bin/`. Without `--push-only`
it also runs setup-host.sh for you.

`config/` travels one way, and the workstation's copy wins. Every file
under `config/` on the workstation overwrites the host's file of that
name, newer or not; a file only the host has (a `credentials.toml` that
`threadwatch import` wrote there, a `config.toml` edited over ssh) is
left in place, never deleted, and so is everything under `data/`. So the
workstation's `config/` is authoritative for whatever it contains: an
edit made on the host to a file the workstation also holds is undone by
the next push, and a workstation holding an old network key replaces the
host's good one (the recorder then logs `credentials_stale`). Keep one
place to edit, the workstation, and copy a host-side edit back (`scp`)
before pushing again. A push from a clone with no secrets removes none
from the host. To remove a config file from the host, delete it there.

## 6. Placement and storage

- Put the recorder and dongle **near your Thread border router**: the
  capture should represent what the border router's radio hears.
- Storage: about 7 MB/hour, 1.2 GB/week, measured on a 50-device mesh
  at rest; a storm multiplies that, and 30 MB/hour is a safe ceiling to
  budget for (it is what `doctor` assumes until the ring has measured
  itself). Pruned automatically (`keep_files`; `keep_gb` caps the total
  size when the disk is the harder limit). Set `data_dir` in config.toml
  to put it on a bigger or faster disk.
- Keep NTP on. pcap timestamps that match your other logs are half the
  value; `doctor` checks. A Pi has no clock of its own and boots on the
  time it last saved, so `setup-host.sh` also makes the services wait, up
  to two minutes, for NTP to correct it before capture starts
  (`systemd-time-wait-sync`); offline, capture starts anyway and the
  recorder allows for the correction when it comes (a `clock_step` event).

## 7. Day-2 operations

```bash
bin/threadwatch doctor          # dongle, key file, disk, clock, services, ring, sinks: ok/warn/FAIL
bin/threadwatch status          # daemon alive? frames flowing? storm state?
bin/threadwatch report          # who's gone quiet; unknown addresses to name
bin/threadwatch adopt <addr> "<name>"   # ...and name one (report --suggest drafts entries)
bin/threadwatch events --episodes   # what happened lately, grouped
bin/threadwatch why "<name>" --hours 6  # one device's story from the recent ring files
# ...or open http://<host>:8080/ for the same thing day by day (docs/REVIEW.md)
bin/threadwatch freeze mylabel  # preserve the ring buffer NOW (incident!)
bin/threadwatch incidents       # what is frozen and how big; --delete <name or label> when done with one
bin/threadwatch replay f.pcap   # run detection over any pcap
```

When a line of `doctor` is not `ok`, or the daemon keeps restarting,
docs/OPERATIONS.md says what each line and each journal message means and
what to do about it.

## Without systemd (macOS, or a Linux without it)

Everything runs the same; you supply the supervisor. `bin/threadwatch
capture` and `bin/threadwatch web` in two terminals is enough for desk
use; on macOS a launchd job keeps them up. `doctor` reports "no systemd
here (not checked)" and moves on. `bin/flash-dongle.sh` works on both Mac
architectures (`SETUP.md`).

## Appendix: a Raspberry Pi from scratch

The from-nothing walkthrough for the tested reference host.

**Image it.** Raspberry Pi Imager → Raspberry Pi OS **Lite (64-bit)** →
Edit settings:

- Hostname: `threadwatch`
- Username: `pi` (any name works; the setup script uses whoever runs it)
- Wi-Fi: prefer a 5 GHz SSID if you have one, so the Pi's own radio adds
  nothing to 2.4 GHz near your Thread network (Wi-Fi ch 1–11 sits below
  Thread ch 25/2475 MHz, so this is a nicety, not a requirement)
- Services: enable SSH, public-key auth, paste your `~/.ssh/id_*.pub`.
  The field wants the key **content** (the one-line `ssh-ed25519 AAAA...`
  from `cat ~/.ssh/id_ed25519.pub`), not a file path.

Boot it and confirm `ssh pi@threadwatch.local` works.

**Install.** Either steps 1 to 4 above over ssh, or, from a workstation
that has this repo checked out with your config and secrets already in
place, the two-command version:

```bash
bin/push-to-host.sh pi@threadwatch.local     # rsync + sudo bin/setup-host.sh on the host
```

That needs passwordless sudo on the Pi, which current Raspberry Pi OS
images may not grant. One-time fix, typing the Pi password once:

```bash
ssh -t pi@threadwatch.local 'sudo sh -c "echo \"pi ALL=(ALL) NOPASSWD: ALL\" > /etc/sudoers.d/010_pi-nopasswd"'
```

**Storage.** Either measured rate is fine for a good SD card; a small
USB SSD is nicer if you have one (`data_dir` in config.toml). NTP is on
by default in Raspberry Pi OS; leave it.
