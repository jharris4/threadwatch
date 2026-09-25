# threadwatch in a container. Native install (INSTALL.md) is the primary path
# and the better one on a Pi; this is for hosts where installing things natively
# is awkward (NAS, Unraid, an LXC). Linux hosts only: the dongle is passed
# through as a device, which Docker Desktop on macOS/Windows cannot do.
#
#   docker compose up -d           # recorder + web, see compose.yaml
#   docker compose run --rm recorder doctor
FROM python:3.12-slim
# openssh-client is for the optional [otbr] inventory (docs/OPERATIONS.md),
# which runs ot-ctl on the border router over ssh. The slim image has no
# ssh at all, so without this every poll fails before it tries the host.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# .dockerignore is an allowlist: this copies the package, vendor/, the
# entrypoint and requirements.txt, nothing else. config/ (config.toml,
# devices.json, credentials.toml, alerts.env, ha.env) and data/ are
# volumes, never part of the image; so is whatever else the working tree
# holds. A new directory the container needs is added there.
COPY . .
# "Is the host running the code I pushed?" is answered by repo_commit(),
# which reads .git or, where there is none, a REVISION file. Neither is in
# the image by default: .git is deliberately not copied, so without this
# --version, status and doctor report no commit at all for a container.
# compose.yaml passes this from the environment (docs/DOCKER.md); a
# REVISION file already in the build context is copied above and stands
# when the argument is empty.
ARG REVISION=""
RUN if [ -n "$REVISION" ]; then printf '%s\n' "$REVISION" > /app/REVISION; fi
# Not root. Everything the container writes goes into the bind-mounted
# config/ and data/ on the host, and as uid 0 those become a data/ the
# native recorder - an unprivileged user, systemd/threadwatch.service -
# cannot write to afterwards. 1000 is the first ordinary user on
# Raspberry Pi OS, Debian and most NAS images; where the host's owner is
# someone else, set compose's `user:` and chown the two directories to
# match (docs/DOCKER.md). Reading the dongle needs its group, which
# compose's `group_add` supplies. The home is where ssh looks for the
# [otbr] key, known_hosts and config: compose.yaml mounts a host
# directory over /home/threadwatch/.ssh, read-only (docs/DOCKER.md).
RUN useradd --uid 1000 --user-group --create-home --shell /usr/sbin/nologin threadwatch
USER threadwatch
VOLUME ["/app/config", "/app/data"]
EXPOSE 8080
ENTRYPOINT ["/app/bin/threadwatch"]
CMD ["record"]
