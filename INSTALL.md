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

## 2. Install

```bash
sudo apt update
sudo apt install -y git python3-serial python3-cryptography
# Note: while this repository is private, the Pi needs auth to clone it -
# either `gh auth login` on the Pi, an SSH deploy key, or make the repo
# public. (python3-cryptography is only needed for the optional
# credentials/decryption features - see docs/CREDENTIALS.md.)
git clone https://github.com/jharris4/thread-debugger.git
cd thread-debugger
cp config/config.example.toml config/config.toml
# edit config/config.toml: set your Thread channel (and webhook if wanted)
# optionally: create config/devices.json from config/devices.example.json
```

Serial port permission (log out/in after):

```bash
sudo usermod -aG dialout pi
```

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
  automatically (`keep_files`). That write rate is fine for a good SD
  card; a small USB SSD is nicer if you have one. Set
  `data_dir` in config.toml to point at it.
- Time sync (NTP) is on by default in Raspberry Pi OS — leave it; pcap
  timestamps that match your other logs are half the value.

## 6. Day-2 operations

```bash
bin/threadwatch status          # daemon alive? frames flowing? storm state?
bin/threadwatch report          # who's gone quiet; unknown addresses to name
bin/threadwatch freeze mylabel  # preserve the ring buffer NOW (incident!)
bin/threadwatch replay f.pcap   # run detection over any pcap
```
