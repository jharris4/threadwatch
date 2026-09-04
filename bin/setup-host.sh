#!/usr/bin/env bash
# One-shot, idempotent host setup for the threadwatch recorder.
# Run ON the capture host (Raspberry Pi / any Debian-ish Linux), as root:
#
#     sudo bin/setup-host.sh
#
# Does everything after the OS is imaged and this repo is present:
# packages, serial permissions, credentials permissions, systemd service.
# Safe to re-run after any change.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
RUN_USER="${SUDO_USER:-pi}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run with sudo: sudo $0" >&2
  exit 1
fi

echo "==> Packages"
apt-get update -qq
apt-get install -y -qq python3-serial python3-cryptography > /dev/null
echo "    python3-serial, python3-cryptography installed"

echo "==> Serial port access for $RUN_USER"
usermod -aG dialout "$RUN_USER"

echo "==> Config"
if [ ! -f "$REPO/config/config.toml" ]; then
  cp "$REPO/config/config.example.toml" "$REPO/config/config.toml"
  chown "$RUN_USER": "$REPO/config/config.toml"
  echo "    created config/config.toml from example - EDIT IT (channel!)"
else
  echo "    config/config.toml present"
fi
for secret in ha.env; do
  if [ -f "$REPO/config/$secret" ]; then
    chown "$RUN_USER": "$REPO/config/$secret"
    chmod 400 "$REPO/config/$secret"
    echo "    $secret locked to 0400"
  fi
done
if [ -f "$REPO/config/credentials.toml" ]; then
  chown "$RUN_USER": "$REPO/config/credentials.toml"
  chmod 400 "$REPO/config/credentials.toml"
  echo "    credentials.toml locked to 0400"
else
  echo "    WARNING: no config/credentials.toml: the recorder will not start without the Thread network key (docs/CREDENTIALS.md)"
fi
if [ -f "$REPO/config/alerts.env" ]; then
  chown "$RUN_USER": "$REPO/config/alerts.env"
  chmod 400 "$REPO/config/alerts.env"
  echo "    alerts.env locked to 0400"
else
  echo "    no alerts.env (fine unless a sink references \${VARS}; see docs/ALERTING.md)"
fi

echo "==> systemd services"
for unit in threadwatch threadwatch-web; do
  sed -e "s|^User=.*|User=$RUN_USER|" \
      -e "s|/home/pi/threadwatch|$REPO|g" \
      "$REPO/systemd/$unit.service" > "/etc/systemd/system/$unit.service"
done
systemctl daemon-reload
systemctl enable threadwatch threadwatch-web
# restart, not enable --now: an already-running unit must pick up the new code
systemctl restart threadwatch threadwatch-web
sleep 3
systemctl --no-pager --lines=5 status threadwatch || true
systemctl --no-pager --lines=3 status threadwatch-web || true

cat <<EOF

Done. Useful commands:
    $REPO/bin/threadwatch status
    $REPO/bin/threadwatch events
    journalctl -u threadwatch -f
EOF
