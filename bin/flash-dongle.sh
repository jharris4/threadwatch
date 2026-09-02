#!/usr/bin/env bash
# Flash the nRF52840 Dongle with the nRF Sniffer for 802.15.4 firmware,
# on Linux (incl. Raspberry Pi) or macOS, without nRF Connect for Desktop.
#
# Uses the pre-built DFU package in firmware/sniffer-dfu.zip (provenance in
# firmware/README.md). Requires: python3 (>=3.8), python3-venv, a USB port.
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

if [ ! -x "$VENV/bin/nrfutil" ]; then
  echo "==> Creating flashing venv (one-time; installs pip nrfutil 6.x)..."
  python3 -m venv "$VENV"
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
