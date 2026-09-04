#!/usr/bin/env bash
# Flash the nRF52840 Dongle with the nRF Sniffer for 802.15.4 firmware,
# from an x86_64 Linux box or an Intel Mac, without nRF Connect for Desktop.
#
# Uses the pre-built DFU package in firmware/sniffer-dfu.zip (provenance in
# firmware/README.md). Requires a USB port and, for Nordic's pip nrfutil
# 6.1.7 (the last release with 'dfu usb-serial'): Python 3.7-3.10 with venv,
# on an x86_64 host (Linux, an Intel Mac, or an Apple Silicon Mac under
# Rosetta), because its pc-ble-driver-py dependency ships wheels for
# nothing else. A 64-bit Raspberry Pi or a native Apple Silicon Python
# cannot run it; SETUP.md lists the alternatives. The dongle keeps the
# firmware, so any one machine that qualifies does the job once.
#
# The dongle must be in its Open DFU bootloader to accept the flash:
# press the small SIDEWAYS reset button (near the ID sticker, aimed at the
# board edge - NOT the white top button). The red LED pulses slowly in
# bootloader mode. After flashing, UNPLUG AND REPLUG the dongle - it does
# not re-enumerate by itself.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PKG="$REPO/firmware/sniffer-dfu.zip"
VENV="$REPO/.venv-flash"

if [ ! -f "$PKG" ]; then
  echo "missing $PKG" >&2; exit 1
fi

find_python() {
  # The newest interpreter nrfutil 6.1.7 accepts (requires_python >=3.7,<3.11).
  for py in python3.10 python3.9 python3.8 python3.7 python3; do
    if command -v "$py" >/dev/null 2>&1 \
       && "$py" -c 'import sys; sys.exit(0 if (3, 7) <= sys.version_info[:2] <= (3, 10) else 1)' 2>/dev/null; then
      echo "$py"; return
    fi
  done
}

if [ ! -x "$VENV/bin/nrfutil" ]; then
  PY="$(find_python || true)"
  ARCH="$(uname -m)"
  if [ -z "$PY" ] || { [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "amd64" ]; }; then
    cat >&2 <<EOM
This flasher uses Nordic's pip nrfutil 6.1.7, which installs only under
Python 3.7-3.10 on an x86_64 host (Linux, an Intel Mac, or an Apple Silicon
Mac under Rosetta). This host: $ARCH, $(python3 --version 2>&1)${PY:+, usable interpreter: $PY}.

The dongle is flashed once and keeps the firmware, so any one of these works:
  - run bin/flash-dongle.sh on a machine that qualifies (an x86_64 Linux box,
    an Intel Mac, or on Apple Silicon: arch -x86_64 zsh, then a Rosetta
    Homebrew python@3.10 on PATH);
  - flash firmware/sniffer-dfu.zip with Nordic's tools: the Programmer app in
    nRF Connect for Desktop (any OS), or the current nrfutil binary
    (nrfutil install device; nrfutil device program --firmware
    firmware/sniffer-dfu.zip --traits nordicDfu).
Either way: sideways reset button first, unplug and replug afterwards (below).
EOM
    exit 1
  fi
  echo "==> Creating flashing venv with $PY (one-time; installs pip nrfutil 6.x)..."
  "$PY" -m venv "$VENV"
  "$VENV/bin/pip" install --quiet --upgrade pip
  # nrfutil 6.1.7 is the last pip-installable version with 'dfu usb-serial'.
  # It needs an older protobuf; pin both.
  "$VENV/bin/pip" install --quiet "nrfutil==6.1.7" "protobuf==3.20.3"
fi

find_bootloader_port() {
  # Open DFU bootloader enumerates as a CDC ACM device (VID 1915, PID 521f).
  if [ "$(uname)" = "Darwin" ]; then
    ls /dev/cu.usbmodem* 2>/dev/null | head -1
  else
    for d in /dev/serial/by-id/*Open_DFU*; do
      [ -e "$d" ] && { echo "$d"; return; }
    done
    ls /dev/ttyACM* 2>/dev/null | head -1
  fi
}

echo "==> Press the dongle's sideways RESET button now (red LED should pulse slowly)."
echo "    Waiting up to 60 s for the bootloader..."
PORT=""
for _ in $(seq 1 30); do
  PORT="$(find_bootloader_port || true)"
  [ -n "$PORT" ] && break
  sleep 2
done
if [ -z "$PORT" ]; then
  echo "No bootloader serial port found. Check the connection and try again." >&2
  echo "(Linux: your user may need dialout group membership: sudo usermod -aG dialout \$USER)" >&2
  exit 1
fi

echo "==> Flashing sniffer firmware via $PORT ..."
"$VENV/bin/nrfutil" dfu usb-serial -pkg "$PKG" -p "$PORT"
echo "==> Done. UNPLUG and REPLUG the dongle now."
echo "    It should re-enumerate as 'nRF 802154 Sniffer'."
echo "    Verify with: bin/threadwatch status  (after starting capture)"
