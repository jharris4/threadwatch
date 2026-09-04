#!/usr/bin/env bash
# Flash the nRF52840 Dongle with the nRF Sniffer for 802.15.4 firmware, from
# the recorder host itself or any machine with a USB port.
#
# Uses the pre-built DFU package in firmware/sniffer-dfu.zip (provenance in
# firmware/README.md) and Nordic's nrfutil binary, which ships for 64-bit
# Linux (x86_64 and aarch64) and both Mac architectures -- a 64-bit Raspberry
# Pi included, so the recorder can flash its own dongle. Set NRFUTIL to use an
# nrfutil you already have; otherwise one is downloaded into .nrfutil-bin/ and
# reused. First run needs network: the launcher then fetches ~29 MB of device
# commands into ~/.nrfutil. The dongle keeps the firmware, so this is once per
# dongle, not per boot.
#
# The dongle must be in its Open DFU bootloader to accept the flash: press the
# small SIDEWAYS reset button (near the ID sticker, aimed at the board edge -
# NOT the white top button). The red LED pulses slowly in bootloader mode.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PKG="$REPO/firmware/sniffer-dfu.zip"
CACHE="$REPO/.nrfutil-bin"
BASE="https://files.nordicsemi.com/artifactory/swtools/external/nrfutil/executables"

if [ ! -f "$PKG" ]; then
  echo "missing $PKG" >&2; exit 1
fi

# Nordic's own target triples. There is no build for 32-bit ARM or Windows;
# those hosts use the Programmer app instead.
target_triple() {
  case "$(uname -s)/$(uname -m)" in
    Linux/x86_64|Linux/amd64)   echo x86_64-unknown-linux-gnu ;;
    Linux/aarch64|Linux/arm64)  echo aarch64-unknown-linux-gnu ;;
    Darwin/arm64)               echo aarch64-apple-darwin ;;
    Darwin/x86_64)              echo x86_64-apple-darwin ;;
    *)                          echo "" ;;
  esac
}

NRFUTIL="${NRFUTIL:-}"
if [ -z "$NRFUTIL" ] && command -v nrfutil >/dev/null 2>&1; then
  NRFUTIL="$(command -v nrfutil)"
fi
if [ -z "$NRFUTIL" ] && [ -x "$CACHE/nrfutil" ]; then
  NRFUTIL="$CACHE/nrfutil"
fi
if [ -z "$NRFUTIL" ]; then
  TRIPLE="$(target_triple)"
  if [ -z "$TRIPLE" ]; then
    cat >&2 <<EOM
Nordic ships no nrfutil for this host ($(uname -s) $(uname -m)); 64-bit Linux
and macOS only. The dongle is flashed once and keeps the firmware, so either
run this on a machine Nordic supports, or flash firmware/sniffer-dfu.zip with
the Programmer app in nRF Connect for Desktop (any OS). The physical steps
below are the same either way.
EOM
    exit 1
  fi
  echo "==> Fetching nrfutil for $TRIPLE (one-time, into .nrfutil-bin/)..."
  mkdir -p "$CACHE"
  curl -sSfL --retry 2 -o "$CACHE/nrfutil.part" "$BASE/$TRIPLE/nrfutil"
  chmod +x "$CACHE/nrfutil.part"
  mv "$CACHE/nrfutil.part" "$CACHE/nrfutil"
  NRFUTIL="$CACHE/nrfutil"
fi

# nrfutil is a launcher: the commands it runs are installed separately, and
# 'install' is a no-op once they are there.
if ! "$NRFUTIL" list 2>/dev/null | grep -q '^device '; then
  echo "==> Installing the nrfutil device command (~29 MB, one-time)..."
  "$NRFUTIL" install device
fi
echo "==> $("$NRFUTIL" --version 2>/dev/null | head -1) at $NRFUTIL"

# The J-Link warning is about debuggers; DFU over USB does not use one.
nrfutil_quiet() { "$NRFUTIL" "$@" 2>&1 | grep -v 'JLinkARM\|SEGGER J-Link'; }

echo "==> Press the dongle's sideways RESET button now (red LED should pulse slowly)."
echo "    Waiting up to 60 s for the bootloader..."
for _ in $(seq 1 30); do
  if nrfutil_quiet device list --traits nordicDfu | grep -q 'Open DFU Bootloader'; then
    FOUND=1; break
  fi
  sleep 2
done
if [ -z "${FOUND:-}" ]; then
  echo "No dongle in DFU bootloader mode found. Press the SIDEWAYS button (not the" >&2
  echo "top one) until the red LED pulses, check the connection, and try again." >&2
  echo "(Linux: your user may need dialout group membership: sudo usermod -aG dialout \$USER)" >&2
  exit 1
fi

echo "==> Flashing sniffer firmware..."
nrfutil_quiet device program --firmware "$PKG" --traits nordicDfu

# Unlike the old pip nrfutil, this one returns the dongle to application mode
# itself, so no unplug/replug is needed -- but re-enumeration takes a couple of
# seconds, and listing too early reports nothing and reads like a failed flash.
echo "==> Flashed. Waiting for the dongle to re-enumerate..."
for _ in $(seq 1 15); do
  if nrfutil_quiet device list | grep -q 'nRF 802154 Sniffer'; then
    BACK=1; break
  fi
  sleep 1
done
if [ -n "${BACK:-}" ]; then
  echo "==> Done. The dongle is an 'nRF 802154 Sniffer':"
  nrfutil_quiet device list | sed 's/^/    /'
  echo "    Verify with: bin/threadwatch doctor"
else
  echo "The flash reported success, but no sniffer appeared within 15 s." >&2
  echo "Unplug and replug the dongle, then check: nrfutil device list" >&2
  exit 1
fi
