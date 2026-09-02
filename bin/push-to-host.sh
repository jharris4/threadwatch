#!/usr/bin/env bash
# Push this repo (including local config + credentials, which are gitignored)
# from your workstation to a capture host, then run remote setup.
#
#     bin/push-to-host.sh pi@192.168.1.50            # push + setup
#     bin/push-to-host.sh pi@threadwatch.local --push-only
#
# Use this instead of git-cloning on the host while the GitHub repo is
# private; it also carries config/config.toml, config/devices.json and
# config/credentials.toml, which git deliberately never sees.
set -euo pipefail

TARGET="${1:?usage: push-to-host.sh user@host [--push-only]}"
MODE="${2:-}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
DEST_DIR="thread-debugger"

rsync -a --delete \
  --exclude 'data/' --exclude '.venv-flash/' \
  --exclude '__pycache__/' --exclude '*.pyc' --exclude '.git/' \
  "$REPO/" "$TARGET:$DEST_DIR/"
ssh "$TARGET" "chmod 400 $DEST_DIR/config/credentials.toml 2>/dev/null || true"
echo "pushed to $TARGET:$DEST_DIR"

if [ "$MODE" != "--push-only" ]; then
  echo "running remote setup (needs passwordless sudo on the host)..."
  ssh -t "$TARGET" "sudo $DEST_DIR/bin/setup-host.sh"
fi
