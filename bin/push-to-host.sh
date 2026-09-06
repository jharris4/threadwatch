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

# The exclude list comes from git, so git has to be answering: with it
# failing (not installed, or $REPO is an exported tree rather than a clone)
# the list would come out empty, rsync would ship .venv/, caches and every
# scratch note, and the report at the end would still say "pushed". The
# `|| true` below cover an empty grep, never git: its output is captured
# first, on its own, where set -e sees a failure.
git -C "$REPO" rev-parse --is-inside-work-tree >/dev/null \
  || { echo "push-to-host.sh: $REPO is not a git working tree (or git is missing); nothing pushed" >&2; exit 1; }
UNTRACKED="$(git -C "$REPO" ls-files --others --directory)"
UNTRACKED_UNIGNORED="$(git -C "$REPO" ls-files --others --exclude-standard --directory)"

# Untracked paths, ignored ones included, anchored to the transfer root. config/
# is held back from this list: git never sees it, but the host needs it.
EXCLUDES="$(mktemp)"
trap 'rm -f "$EXCLUDES"' EXIT
{ printf '%s\n' "$UNTRACKED" | grep -v '^config/' | grep -v '^$' | sed 's,^,/,'; } > "$EXCLUDES" || true

# A new source file that was never committed would be skipped silently, which
# looks exactly like a deploy that did not take. Notes and caches stay quiet.
UNCOMMITTED_CODE="$(printf '%s\n' "$UNTRACKED_UNIGNORED" | grep -Ev '^config/' | grep -E '\.py$|^bin/' || true)"
if [ -n "$UNCOMMITTED_CODE" ]; then
  echo "warning: these are untracked, so they are NOT being deployed:" >&2
  printf '  %s\n' $UNCOMMITTED_CODE >&2
  echo "  commit them if they belong on the host." >&2
fi

# --delete removes what the workstation lacks; the protect filter exempts
# config/ on the receiving side, so a file there is never removed - remove
# one on the host by hand. It is still overwritten: the protect filter only
# holds off --delete, and rsync -a is not -u, so a config/ file the
# workstation also has is replaced whichever copy is newer. That is the
# documented design (INSTALL.md, "Updating": the workstation's config/ is
# authoritative), so a credentials.toml or devices.json written on the host
# by import or adopt must be copied back here before the next push, or the
# push reverts it. Do not read this filter as --update.
# .venv/ is the host's Python runtime (bin/threadwatch prefers it whenever
# it exists) and is named here on its own: the git-derived exclude list only
# covers it when this workstation happens to have one, and a push from a
# checkout without one used to delete the host's.
# Which config/ files this push would replace with an older copy: what a
# plain run sends, less what --update would send. config/ is a handful of
# small files, so the two dry runs cost nothing, and they turn a silent
# revert of a host-written credentials.toml or devices.json into a line
# the operator sees before it happens.
config_would_send() {
  rsync -a --dry-run --out-format='%n' "$@" \
    --include '/config/' --include '/config/**' --exclude '*' \
    "$REPO/" "$TARGET:$DEST_DIR/" 2>/dev/null | grep -v '/$' | sort -u || true
}
REVERTS="$(comm -23 <(config_would_send) <(config_would_send --update))"
if [ -n "$REVERTS" ]; then
  echo "warning: the host has a NEWER copy of these, and this push replaces them:" >&2
  printf '  %s\n' $REVERTS >&2
  echo "  copy them back here first if the host's version is the one you want." >&2
fi

rsync -a --delete \
  --exclude-from "$EXCLUDES" \
  --exclude 'data/' --exclude '.git/' --exclude '.venv/' \
  --filter 'P /config/***' --filter 'P /.venv/***' \
  "$REPO/" "$TARGET:$DEST_DIR/"
ssh "$TARGET" "chmod 400 $DEST_DIR/config/credentials.toml $DEST_DIR/config/alerts.env $DEST_DIR/config/ha.env 2>/dev/null || true"
echo "pushed to $TARGET:$DEST_DIR"

if [ "$MODE" != "--push-only" ]; then
  echo "running remote setup (needs passwordless sudo on the host)..."
  ssh -t "$TARGET" "sudo $DEST_DIR/bin/setup-host.sh"
fi
