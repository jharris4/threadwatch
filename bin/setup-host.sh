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
# The interpreter the service runs is the one bin/threadwatch picks: the
# repo-local .venv when it exists, else the system python3. The version
# check, the packages and the import check below are all about that one
# interpreter. A venv does not see the system site-packages, so distro
# packages installed for python3 never reached a half-made .venv that the
# launcher then preferred: setup reported success and the recorder failed
# its imports, run after run.
VENV="$REPO/.venv"
if [ -x "$VENV/bin/python3" ]; then PY="$VENV/bin/python3"; else PY="$(command -v python3 || true)"; fi
if [ -z "$PY" ] || ! "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
  echo "    python3 >= 3.11 required (tomllib); found: $("${PY:-python3}" --version 2>&1 || echo none) (${PY:-python3})" >&2
  if [ "$PY" = "$VENV/bin/python3" ]; then
    echo "    that is the repo's .venv, which bin/threadwatch prefers over the system python3: remove it (rm -rf $VENV) and re-run" >&2
  fi
  exit 1
fi
echo "    $("$PY" --version) ($PY)"

echo "==> Python packages (pyserial, cryptography)"
if [ "$PY" = "$VENV/bin/python3" ]; then
  # An existing venv is the service's interpreter whatever package manager
  # the host has: repair it in place.
  sudo -u "$RUN_USER" "$PY" -m pip install --quiet -r "$REPO/requirements.txt"
  echo "    installed into $VENV (bin/threadwatch prefers it over the system python3)"
elif command -v apt-get >/dev/null; then
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
  sudo -u "$RUN_USER" "$PY" -m venv "$VENV"
  PY="$VENV/bin/python3"
  sudo -u "$RUN_USER" "$PY" -m pip install --quiet -r "$REPO/requirements.txt"
  echo "    no apt/dnf/pacman/zypper: installed into $VENV"
fi
# What the service will do at its first import, done here where the
# failure names the interpreter rather than in the journal.
if ! "$PY" -c 'import serial, cryptography' 2>/dev/null; then
  echo "    ERROR: $PY cannot import pyserial and cryptography after the install above; the recorder would not start" >&2
  exit 1
fi
echo "    $PY imports pyserial and cryptography"

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
if ! command -v systemctl >/dev/null; then
  echo "    no systemd on this host: run '$REPO/bin/threadwatch capture' and 'web' under your own supervisor"
else
  for unit in threadwatch threadwatch-web; do
    sed -e "s|__USER__|$RUN_USER|g" \
        -e "s|__REPO__|$REPO|g" \
        "$REPO/systemd/$unit.service" > "/etc/systemd/system/$unit.service"
  done
  # The units start after time-sync.target. As shipped that target is
  # reached when timesyncd has *started*, not when the clock is right, and
  # a Pi has no RTC: it boots on its saved clock and NTP steps it forward
  # later, so frames, events and ring files stamped before the step are
  # wrong. systemd-time-wait-sync holds the target for an actual sync. Its
  # own timeout is infinity, which offline would mean no capture at all;
  # the drop-in bounds the wait, after which the recorder starts on the
  # clock it has and its clock-step guard takes over. Nothing else on a
  # stock host is ordered after time-sync.target, so only these units wait.
  if systemctl cat systemd-time-wait-sync.service >/dev/null 2>&1; then
    mkdir -p /etc/systemd/system/systemd-time-wait-sync.service.d
    cat > /etc/systemd/system/systemd-time-wait-sync.service.d/threadwatch.conf <<'CONF'
# Installed by threadwatch/bin/setup-host.sh: wait for the clock to be
# NTP-synchronised before threadwatch starts, but not for ever.
[Service]
TimeoutStartSec=120
CONF
    systemctl enable systemd-time-wait-sync.service
    echo "    systemd-time-wait-sync enabled (capture waits up to 120 s for an NTP-synchronised clock)"
  else
    echo "    no systemd-time-wait-sync on this host: capture starts as soon as timesyncd has, synced or not"
  fi
  systemctl daemon-reload
  systemctl enable threadwatch threadwatch-web
  # A unit that hit its start limit on the previous configuration stays
  # failed until told otherwise; this run may be the fix for it.
  systemctl reset-failed threadwatch threadwatch-web 2>/dev/null || true
  # restart, not enable --now: an already-running unit must pick up the new code
  systemctl restart threadwatch threadwatch-web
  # For Type=simple, restart returns as soon as the process is forked: a
  # recorder refusing its configuration dies a few seconds later. Wait
  # past ExecStartPre (2 s) and start-up, then ask, and say so and exit
  # non-zero when either unit is not running, so a dead recorder is not
  # reported as "Done".
  sleep 8
  BROKEN=""
  for unit in threadwatch threadwatch-web; do
    if ! systemctl is-active --quiet "$unit"; then
      BROKEN="$BROKEN $unit"
    fi
  done
  systemctl --no-pager --lines=5 status threadwatch || true
  systemctl --no-pager --lines=3 status threadwatch-web || true
  if [ -n "$BROKEN" ]; then
    echo >&2
    echo "NOT RUNNING:$BROKEN. See the status above and: journalctl -u threadwatch -n 50" >&2
    echo "After fixing the cause: systemctl reset-failed$BROKEN && systemctl restart$BROKEN" >&2
    exit 1
  fi
fi

cat <<DONE

Done. Useful commands:
    $REPO/bin/threadwatch doctor
    $REPO/bin/threadwatch status
    $REPO/bin/threadwatch events
$(command -v systemctl >/dev/null && echo "    journalctl -u threadwatch -f")
DONE
