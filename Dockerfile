# threadwatch in a container. Native install (INSTALL.md) is the primary path
# and the better one on a Pi; this is for hosts where installing things natively
# is awkward (NAS, Unraid, an LXC). Linux hosts only: the dongle is passed
# through as a device, which Docker Desktop on macOS/Windows cannot do.
#
#   docker compose up -d           # capture + web, see compose.yaml
#   docker compose run --rm capture doctor
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# .dockerignore is an allowlist: this copies the package, vendor/, the
# entrypoint and requirements.txt, nothing else. config/ (config.toml,
# devices.json, credentials.toml, alerts.env, ha.env) and data/ are
# volumes, never part of the image; so is whatever else the working tree
# holds. A new directory the container needs is added there.
COPY . .
VOLUME ["/app/config", "/app/data"]
EXPOSE 8080
ENTRYPOINT ["/app/bin/threadwatch"]
CMD ["capture"]
