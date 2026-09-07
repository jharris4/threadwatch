# Running in Docker

An alternative to the native install in `INSTALL.md`, for hosts where
installing things natively is awkward: a NAS, Unraid, a Proxmox LXC, a
box you'd rather not put Python packages on. Same code, same commands,
same `config/` and `data/` layout; only the process supervisor changes.

Same layout, but not the same file ownership: read "Layout" below before
switching a host between the two.

Not the better choice on a Raspberry Pi or any box you control fully:
native puts nothing between the daemon and the USB device or the disk,
and `journalctl` is the log. Nothing else in threadwatch depends on
Docker being installed.

**Linux hosts only.** The dongle reaches the container as a passed-through
device, which Docker Desktop on macOS and Windows cannot do.

**Needs Docker Compose 2.24.0 or newer** (`docker compose version`).
`compose.yaml` marks `config/alerts.env` optional with `env_file`'s
`required: false`, which Docker documents as arriving in 2.24.0. An older
`docker compose`, or the legacy Python `docker-compose` still shipped on
some NAS and Unraid boxes, rejects the whole file with a schema error
naming `env_file`, which reads like a corrupt compose file rather than a
missing feature. To run on one, create an empty `config/alerts.env` and
replace those three lines with the classic form:

```yaml
    env_file:
      - ./config/alerts.env
```

## Start

```bash
git clone https://github.com/jharris4/threadwatch.git && cd threadwatch
mkdir -p data && chown -R 1000:1000 config data     # the uid the container runs as ("Layout")
cp config/config.example.toml config/config.toml    # set your channel
printf '[credentials]\nnetwork_key = "%s"\n' "<32 hex digits>" > config/credentials.toml
chmod 600 config/credentials.toml                   # the Thread network key: docs/CREDENTIALS.md
ls /dev/serial/by-id/                                # find the dongle
```

The recorder does not start without the network key (the container would
restart forever, `credentials.toml is missing` and exit code 2 in
`docker compose logs recorder`; the same code with `capture stalled` is
the watchdog, not the key: docs/OPERATIONS.md, "Exit codes");
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
docker compose run --rm --no-deps recorder doctor   # all ok
docker compose logs -f recorder
```

Doctor knows it is in a container and says so on two checks it cannot
make from inside one: `clock` reads `ok in a container: the host keeps
the time (not checked)` (no `timedatectl` in the image) and, when the
review pages do not answer at 127.0.0.1, `web` reads `ok review pages
run in their own container (not checked from in here)`, because doctor
cannot tell that container from one that is down. Anything else that is
not `ok` is real.

The `recorder` service runs on the host's network (`network_mode: host`
in `compose.yaml`) because the recorder finds border routers over mDNS,
which is link-local multicast that the default bridge network never
carries to the LAN; without it `border routers` warns `none found over
mDNS` on every host and Apple hubs' address changes go unnamed
(`[border_routers]` in config.toml). One-off commands such as `doctor`
and `import` inherit it. The daemon listens on no port of its own.

The review pages are published on `127.0.0.1:8080` (`ports:` in
`compose.yaml`). They have no authentication, and on a Linux host a plain
`8080:8080` installs DNAT rules in the `DOCKER` chain, which is traversed
before `ufw`'s `INPUT` rules: a host firewall you believe is closing the
port would not be. Read them over `ssh -L 8080:127.0.0.1:8080 user@host`,
or widen the mapping once something in front of it authenticates.

Inside the container the server binds `0.0.0.0` (`command:` in
`compose.yaml`), which is not the LAN bind the `[web]` comment in
config.toml warns about: that `0.0.0.0` is the container's own network
namespace, and the published port forwards to the container's bridge
address, so a server on the container's loopback would refuse every
connection. Here it is the publish, not the bind, that says who can
reach the pages.

## Layout

- `./config` is mounted read-write into `recorder` (so `name` can write
  `devices.json`) and read-only into `web`. `web` also runs as uid 65534
  (`nobody`), not 1000: it is the only published process and nothing in
  front of it authenticates, and `credentials.toml`, `alerts.env` and
  `ha.env` are 0400 owner-only, so that user cannot open them. Everything
  `web` does read is world-readable. If your host writes with umask 077,
  the pages fail to load: set `web`'s `user:` to the same uid:gid as
  `recorder`.
- `./data` holds the ring, state and snapshots, exactly as native.
- The container runs as uid 1000, not root, so the ring files, state,
  snapshots and any `devices.json` it writes belong to an ordinary user
  and a native install can read and write the same `data/` afterwards.
  1000 is the first ordinary user on Raspberry Pi OS, Debian and most NAS
  images. If yours is someone else, set `user:` in `compose.yaml` to their
  uid and gid and `chown` the two directories to match, or the recorder
  cannot write and exits. `ls -ln config data` shows who owns them now.
- The dongle is usually `root:dialout` mode 660, so `compose.yaml` adds
  group 20 (`group_add`), which is `dialout` on Debian and Raspberry Pi
  OS. Check yours with `stat -c %g /dev/ttyACM0`; a wrong group is
  `permission denied` opening the serial port.
- **Ownership is the one thing that is not the same as native.** The
  native install runs as you and chowns `config/` to you; the container
  runs as whatever uid you gave it, and Docker creates a missing bind
  mount as `root`. Before the first `up`, make the directories yourself
  so they belong to the right user:

  ```bash
  mkdir -p data && chown -R 1000:1000 config data    # or your uid:gid
  ls -ln config data                                  # who owns them now
  ```

  This matters in three places. `name` and `import` run outside the
  container write `devices.json` as you, and fail on one the container
  owns. Backing up `data/` needs the same user or `sudo`. And a host
  moving from Docker to the native install meets `doctor`'s `writable`
  FAIL, whose fix is `sudo chown -R <user> data config`.
- `config/alerts.env` is loaded as the container's environment when
  present, the equivalent of the systemd unit's `EnvironmentFile`. Compose
  reads it when it *creates* the container, and a restart keeps the
  environment the container was created with: after editing or rotating
  a value in `alerts.env`, recreate it with `docker compose up -d
  --force-recreate recorder`. A plain restart leaves the old token in use
  and a newly added variable absent, and the sink that references it
  is reported disabled.
- The files in `config/` are read when a container starts: after editing
  `config.toml`, `credentials.toml` or `devices.json`, `docker compose
  restart recorder` (and `web` for `[web]`).
- The image holds the code and nothing else: `.dockerignore` is an
  allowlist, so config, secrets, `data/` and anything else in the
  working tree stay out without being named.

## Time zone

Neither container inherits the host's time zone, and a container with
none runs in UTC. threadwatch reads the *local* day and hour in several
places: the hourly ring filenames (`threadwatch-20260907-08.pcap`), the
daily event files (`events/2026-09-07.jsonl`), the day the review pages
walk back through, and `[summary] hour`. On a host that is not on UTC,
`hour = 8` therefore pages at 08:00 UTC rather than at eight in the
morning where you are, and a day on the review pages ends at the wrong
midnight. Moving the same `data/` between a native install and a
container changes how its hour-based filenames read, for the same reason.

Give both services the same zone as the host. Mounting the host's own
zone file needs nothing installed in the image:

```yaml
services:
  recorder:
    volumes:
      - /etc/localtime:/etc/localtime:ro
  web:
    volumes:
      - /etc/localtime:/etc/localtime:ro
```

`compose.yaml` carries both lines commented out, because turning this on
moves the day and hour boundaries of a recorder already running: the
switch belongs to you, not to a `git pull`. Setting `TZ=Europe/London`
in `environment:` instead works only where the image has the zone files
(`python:3.12-slim` does not install `tzdata`), and quietly falls back to
UTC where it does not -- which is the failure this section is about, so
prefer the mount, or add `tzdata` to the image and use `TZ`.

Check what each container actually thinks the time is, which is the only
answer that settles it:

```bash
docker compose exec recorder date
docker compose exec web date
date                                   # the host, for comparison
```

`docker compose run --rm --no-deps recorder status` prints stamps in the
recorder's zone as well. Change the setting and both containers need
recreating (`docker compose up -d --force-recreate`), not restarting.

## Everyday commands

The image's entrypoint is `bin/threadwatch`, so any CLI command works as
a one-off container over the same volumes:

```bash
docker compose run --rm --no-deps recorder status
docker compose run --rm --no-deps recorder devices --suggest
docker compose run --rm --no-deps recorder device "Office AQ" --hours 6
docker compose run --rm --no-deps recorder snapshot mylabel
```

## Update

```bash
git pull && docker compose up -d --build
```

`data/` is untouched; the quiet detector knows about the restart gap.
