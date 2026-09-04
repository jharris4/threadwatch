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
COPY . .
# config/ (config.toml, devices.json, credentials.toml) and data/ are volumes.
VOLUME ["/app/config", "/app/data"]
EXPOSE 8080
ENTRYPOINT ["/app/bin/threadwatch"]
CMD ["capture"]
