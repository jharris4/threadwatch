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
# never touched, and a config/ file the host has but this workstation does
# not (a fresh clone, a second machine, a credentials.toml written on the
# host by `threadwatch import`) is left in place rather than deleted: for
# the network key that may be the only copy.
#
# What deploys is what git tracks, plus config/. Everything else in the working
# tree -- caches, scratch notes, data/, .venv/ -- stays on the workstation. That
# list comes from git rather than a hand-kept set of --exclude flags, so new
# junk needs no edit here; an uncommitted edit to a tracked file still ships.
set -euo pipefail

TARGET="${1:?usage: push-to-host.sh user@host [--push-only]}"
MODE="${2:-}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
DEST_DIR="${DEST_DIR:-threadwatch}"   # path on the host, relative to $HOME

# Untracked paths, ignored ones included, anchored to the transfer root. config/
# is held back from this list: git never sees it, but the host needs it.
EXCLUDES="$(mktemp)"
trap 'rm -f "$EXCLUDES"' EXIT
{ git -C "$REPO" ls-files --others --directory | grep -v '^config/' | sed 's,^,/,'; } > "$EXCLUDES" || true

# A new source file that was never committed would be skipped silently, which
# looks exactly like a deploy that did not take. Notes and caches stay quiet.
UNCOMMITTED_CODE="$(git -C "$REPO" ls-files --others --exclude-standard --directory \
  | grep -Ev '^config/' | grep -E '\.py$|^bin/' || true)"
if [ -n "$UNCOMMITTED_CODE" ]; then
  echo "warning: these are untracked, so they are NOT being deployed:" >&2
  printf '  %s\n' $UNCOMMITTED_CODE >&2
  echo "  commit them if they belong on the host." >&2
fi

# --delete removes what the workstation lacks; the protect filter exempts
# config/ on the receiving side, so a file there is only ever overwritten by
# a newer workstation copy, never removed. Remove one on the host by hand.
rsync -a --delete \
  --exclude-from "$EXCLUDES" \
  --exclude 'data/' --exclude '.git/' \
  --filter 'P /config/***' \
  "$REPO/" "$TARGET:$DEST_DIR/"
ssh "$TARGET" "chmod 400 $DEST_DIR/config/credentials.toml $DEST_DIR/config/alerts.env $DEST_DIR/config/ha.env 2>/dev/null || true"
echo "pushed to $TARGET:$DEST_DIR"

if [ "$MODE" != "--push-only" ]; then
  echo "running remote setup (needs passwordless sudo on the host)..."
  ssh -t "$TARGET" "sudo $DEST_DIR/bin/setup-host.sh"
fi
