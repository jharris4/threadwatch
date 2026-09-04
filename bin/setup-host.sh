#!/usr/bin/env bash
# One-shot, idempotent host setup for the threadwatch recorder.
# Run ON the capture host (any systemd Linux; Debian/Raspberry Pi OS is the
# tested path), as root via sudo so the invoking user becomes the service user:
#
#     sudo bin/setup-host.sh              # service runs as $SUDO_USER
#     sudo bin/setup-host.sh --user bob   # ...or as a named user
#
# Does everything after the OS is installed and this repo is present:
# Python deps, serial permissions, credentials permissions, systemd units.
# Safe to re-run after any change.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
RUN_USER="${SUDO_USER:-}"
if [ "${1:-}" = "--user" ]; then RUN_USER="${2:?--user needs a name}"; fi

if [ "$(id -u)" -ne 0 ]; then
  echo "run with sudo: sudo $0" >&2
  exit 1
fi
if [ -z "$RUN_USER" ] || [ "$RUN_USER" = "root" ]; then
  echo "which user should run the recorder? run via sudo from that user, or pass --user NAME" >&2
  exit 1
fi
id "$RUN_USER" >/dev/null 2>&1 || { echo "no such user: $RUN_USER" >&2; exit 1; }

echo "==> Python"
if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
  echo "    python3 >= 3.11 required (tomllib); found: $(python3 --version 2>&1 || echo none)" >&2
  exit 1
fi
echo "    $(python3 --version)"

echo "==> Python packages (pyserial, cryptography)"
if command -v apt-get >/dev/null; then
  apt-get update -qq
  apt-get install -y -qq python3-serial python3-cryptography > /dev/null
  echo "    apt: python3-serial, python3-cryptography"
elif command -v dnf >/dev/null; then
  dnf install -y -q python3-pyserial python3-cryptography
  echo "    dnf: python3-pyserial, python3-cryptography"
elif command -v pacman >/dev/null; then
  pacman -S --needed --noconfirm --quiet python-pyserial python-cryptography
  echo "    pacman: python-pyserial, python-cryptography"
elif command -v zypper >/dev/null; then
  zypper --quiet install -y python3-pyserial python3-cryptography
  echo "    zypper: python3-pyserial, python3-cryptography"
else
  # No known package manager: a repo-local venv, which bin/threadwatch prefers
  # over the system python3 whenever it exists.
  VENV="$REPO/.venv"
  [ -x "$VENV/bin/python3" ] || sudo -u "$RUN_USER" python3 -m venv "$VENV"
  sudo -u "$RUN_USER" "$VENV/bin/pip" install --quiet -r "$REPO/requirements.txt"
  echo "    no apt/dnf/pacman/zypper: installed into $VENV"
fi

echo "==> Serial port access for $RUN_USER"
SERIAL_GROUP=""
for g in dialout uucp; do
  if getent group "$g" >/dev/null; then SERIAL_GROUP="$g"; break; fi
done
if [ -n "$SERIAL_GROUP" ]; then
  usermod -aG "$SERIAL_GROUP" "$RUN_USER"
  echo "    $RUN_USER added to $SERIAL_GROUP"
else
  echo "    WARN: no dialout/uucp group; grant $RUN_USER access to the dongle's tty yourself (udev rule)"
fi

echo "==> Config"
if [ ! -f "$REPO/config/config.toml" ]; then
  cp "$REPO/config/config.example.toml" "$REPO/config/config.toml"
  chown "$RUN_USER": "$REPO/config/config.toml"
  echo "    created config/config.toml from example - EDIT IT (channel!)"
else
  echo "    config/config.toml present"
fi
if [ -f "$REPO/config/credentials.toml" ]; then
  chown "$RUN_USER": "$REPO/config/credentials.toml"
  chmod 400 "$REPO/config/credentials.toml"
  echo "    credentials.toml locked to 0400"
else
  echo "    no credentials.toml (fine: header-level analysis only; see docs/CREDENTIALS.md)"
fi
if [ -f "$REPO/config/alerts.env" ]; then
  chown "$RUN_USER": "$REPO/config/alerts.env"
  chmod 400 "$REPO/config/alerts.env"
  echo "    alerts.env locked to 0400"
else
  echo "    no alerts.env (fine unless a sink references \${VARS}; see docs/ALERTING.md)"
fi

echo "==> systemd services"
if ! command -v systemctl >/dev/null; then
  echo "    no systemd on this host: run '$REPO/bin/threadwatch capture' and 'web' under your own supervisor"
else
  for unit in threadwatch threadwatch-web; do
    sed -e "s|__USER__|$RUN_USER|g" \
        -e "s|__REPO__|$REPO|g" \
        "$REPO/systemd/$unit.service" > "/etc/systemd/system/$unit.service"
  done
  systemctl daemon-reload
  systemctl enable threadwatch threadwatch-web
  # restart, not enable --now: an already-running unit must pick up the new code
  systemctl restart threadwatch threadwatch-web
  sleep 3
  systemctl --no-pager --lines=5 status threadwatch || true
  systemctl --no-pager --lines=3 status threadwatch-web || true
fi

cat <<DONE

Done. Useful commands:
    $REPO/bin/threadwatch doctor
    $REPO/bin/threadwatch status
    $REPO/bin/threadwatch events
$(command -v systemctl >/dev/null && echo "    journalctl -u threadwatch -f")
DONE
