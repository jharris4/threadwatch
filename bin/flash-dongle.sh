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

_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d" " -f1
  else
    shasum -a 256 "$1" | cut -d" " -f1      # macOS
  fi
}

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
  # --proto/--proto-redir: -L follows redirects, and without these a
  # redirect off the vendor's TLS host to plain http would be followed.
  curl -sSfL --proto '=https' --proto-redir '=https' --retry 2 \
    -o "$CACHE/nrfutil.part" "$BASE/$TRIPLE/nrfutil"
  # Nordic serves this path without a version in it, so what arrives is
  # whatever they publish today. firmware/nrfutil.sha256 is what pins it:
  # a recorded hash for this triple is checked here, and the binary is
  # never made executable before it matches. With no line for the triple
  # the download is unverified and says so, with the hash to record.
  GOT="$(_sha256 "$CACHE/nrfutil.part")"
  WANT="$(awk -v tri="$TRIPLE" '$2 == tri {print $1}' "$REPO/firmware/nrfutil.sha256" 2>/dev/null || true)"
  if [ -n "$WANT" ] && [ "$GOT" != "$WANT" ]; then
    rm -f "$CACHE/nrfutil.part"
    echo "ERROR: the nrfutil Nordic served does not match firmware/nrfutil.sha256" >&2
    echo "  expected $WANT" >&2
    echo "  got      $GOT" >&2
    echo "  Nordic publishes this path without a version, so a new release changes it." >&2
    echo "  Check the release, then update the line for $TRIPLE if the new one is what you want." >&2
    exit 1
  fi
  if [ -z "$WANT" ]; then
    echo "  WARNING: nothing recorded for $TRIPLE in firmware/nrfutil.sha256, so this" >&2
    echo "           binary is unverified. To pin what you just downloaded, add:" >&2
    echo "             $GOT  $TRIPLE" >&2
  else
    echo "  sha256 matches firmware/nrfutil.sha256"
  fi
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
# The status is nrfutil's own (pipefail), never grep's: grep -v exits 1
# when it prints nothing, which is exactly what a successful command with
# no output, or only the filtered warning, looks like, and under set -e
# that aborted the script right after a flash that had worked.
nrfutil_quiet() { "$NRFUTIL" "$@" 2>&1 | { grep -v 'JLinkARM\|SEGGER J-Link' || true; }; }

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
if ! nrfutil_quiet device program --firmware "$PKG" --traits nordicDfu; then
  echo "nrfutil reported a failed flash (see above). Press the sideways reset button" >&2
  echo "again so the red LED pulses, and re-run." >&2
  exit 1
fi

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
