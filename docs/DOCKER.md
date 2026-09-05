# Running in Docker

An alternative to the native install in `INSTALL.md`, for hosts where
installing things natively is awkward: a NAS, Unraid, a Proxmox LXC, a
box you'd rather not put Python packages on. Same code, same commands,
same `config/` and `data/` layout; only the process supervisor changes.

Not the better choice on a Raspberry Pi or any box you control fully:
native puts nothing between the daemon and the USB device or the disk,
and `journalctl` is the log. Nothing else in threadwatch depends on
Docker being installed.

**Linux hosts only.** The dongle reaches the container as a passed-through
device, which Docker Desktop on macOS and Windows cannot do.

## Start

```bash
git clone https://github.com/jharris4/threadwatch.git && cd threadwatch
cp config/config.example.toml config/config.toml    # set your channel
printf '[credentials]\nnetwork_key = "%s"\n' "<32 hex digits>" > config/credentials.toml
chmod 600 config/credentials.toml                   # the Thread network key: docs/CREDENTIALS.md
ls /dev/serial/by-id/                                # find the dongle
```

The recorder does not start without the network key (the container would
restart forever, exit code 2 in `docker compose logs capture`);
`docs/CREDENTIALS.md` says where to find it, and `threadwatch import
--write` (run as a one-off container, below, with `config/ha.env` holding
a Home Assistant token) fetches it from Home Assistant along with your
device names.

The dongle shows as `usb-Nordic_Semiconductor_nRF_802154_Sniffer_..-if00`
(flash it first if not: `SETUP.md`; `bin/flash-dongle.sh` runs on the host,
not in the container). Put that path on the left side of the `devices:`
line in `compose.yaml`; it survives re-enumeration, where `/dev/ttyACM0`
only works while it is the sole such device. Then:

```bash
docker compose up -d --build
docker compose run --rm --no-deps capture doctor    # all ok
docker compose logs -f capture
```

Doctor knows it is in a container and says so on two checks it cannot
make from inside one: `clock` reads `ok in a container: the host keeps
the time (not checked)` (no `timedatectl` in the image) and, when the
review pages do not answer at 127.0.0.1, `web` reads `ok review pages
run in their own container (not checked from in here)`, because doctor
cannot tell that container from one that is down. Anything else that is
not `ok` is real.

The `capture` service runs on the host's network (`network_mode: host`
in `compose.yaml`) because the recorder finds border routers over mDNS,
which is link-local multicast that the default bridge network never
carries to the LAN; without it `border routers` warns `none found over
mDNS` on every host and Apple hubs' address changes go unnamed
(`[border_routers]` in config.toml). One-off commands such as `doctor`
and `import` inherit it. The daemon listens on no port of its own.

The review pages are on port 8080 (`ports:` in `compose.yaml` to change).

## Layout

- `./config` is mounted read-write into `capture` (so `adopt` can write
  `devices.json`) and read-only into `web`.
- `./data` holds the ring, state and incidents, exactly as native.
- `config/alerts.env` is loaded as the container's environment when
  present, the equivalent of the systemd unit's `EnvironmentFile`.
- The image contains no config or secrets (`.dockerignore`).

## Everyday commands

The image's entrypoint is `bin/threadwatch`, so any CLI command works as
a one-off container over the same volumes:

```bash
docker compose run --rm --no-deps capture status
docker compose run --rm --no-deps capture report --suggest
docker compose run --rm --no-deps capture why "Office AQ" --hours 6
docker compose run --rm --no-deps capture freeze mylabel
```

## Update

```bash
git pull && docker compose up -d --build
```

`data/` is untouched; the quiet detector knows about the restart gap.
