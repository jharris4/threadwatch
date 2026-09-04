#!/usr/bin/env bash
# Developer deploy: rsync this working tree from your workstation to a capture
# host, then (optionally) run setup-host.sh there.
#
#     bin/push-to-host.sh pi@192.168.1.50            # push + setup (restarts the units)
#     bin/push-to-host.sh pi@threadwatch.local --push-only
#
# A first install does not need this: `git clone` on the host and
# `sudo bin/setup-host.sh` is enough (INSTALL.md). What this script adds is
# that it also carries config/config.toml, config/devices.json,
# config/credentials.toml and config/alerts.env, which git deliberately never
# sees, and it lets you deploy an uncommitted change. data/ on the host is
# never touched.
set -euo pipefail

TARGET="${1:?usage: push-to-host.sh user@host [--push-only]}"
MODE="${2:-}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
DEST_DIR="${DEST_DIR:-threadwatch}"   # path on the host, relative to $HOME

rsync -a --delete \
  --exclude 'data/' --exclude '.venv/' --exclude '.venv-flash/' \
  --exclude '__pycache__/' --exclude '*.pyc' --exclude '.git/' \
  "$REPO/" "$TARGET:$DEST_DIR/"
ssh "$TARGET" "chmod 400 $DEST_DIR/config/credentials.toml $DEST_DIR/config/alerts.env 2>/dev/null || true"
echo "pushed to $TARGET:$DEST_DIR"

if [ "$MODE" != "--push-only" ]; then
  echo "running remote setup (needs passwordless sudo on the host)..."
  ssh -t "$TARGET" "sudo $DEST_DIR/bin/setup-host.sh"
fi
