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
# config/visitors.json, config/credentials.toml and config/alerts.env, which git deliberately never
# sees, and it lets you deploy an uncommitted change. data/ on the host is
# never touched, and a config/ file the host has but this workstation does
# not (a fresh clone, a second machine, a credentials.toml written on the
# host by `threadwatch import`) is left in place rather than deleted: for
# the network key that may be the only copy. A config/ file the host holds
# a newer, different copy of (a devices.json written there by `threadwatch
# name`, a credentials.toml from `threadwatch import`) stops the push until
# it is copied back, or FORCE_CONFIG=1 says the workstation's copy wins.
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
# Checked before anything runs. It goes verbatim into an rsync --delete
# destination, into an unquoted position in a remote chmod, and into the
# remote setup-host.sh path: DEST_DIR=. or DEST_DIR=/ turns this push into
# an rsync --delete over the host's home directory or its root. Nothing
# untrusted reaches it; this is a foot-gun on a script whose whole job is
# --delete.
case "$DEST_DIR" in
  "" | "." | ".." | ../* | */../* | */.. | /* | */ | *[!A-Za-z0-9._/-]*)
    echo "push-to-host.sh: DEST_DIR must be a plain relative path under the host's home" >&2
    echo "  (letters, digits, . _ - and /, no leading or trailing slash), not '$DEST_DIR'; nothing pushed" >&2
    exit 1 ;;
esac

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
  # Indented with sed, not printf '  %s\n' $VAR: unquoted, a filename with
  # a space printed as two lines and one holding *, ? or [...] was
  # glob-expanded against the working directory, so the list of what is
  # NOT being deployed named files that do not exist.
  printf '%s\n' "$UNCOMMITTED_CODE" | sed 's/^/  /' >&2
  echo "  commit them if they belong on the host." >&2
fi

# --delete removes what the workstation lacks; the protect filter exempts
# config/ on the receiving side, so a file there is never removed - remove
# one on the host by hand. It is still overwritten: the protect filter only
# holds off --delete, and rsync -a is not -u, so a config/ file the
# workstation also has is replaced whichever copy is newer. That is the
# documented design (INSTALL.md, "Updating": the workstation's config/ is
# authoritative); the check below is what keeps it from silently reverting
# a credentials.toml or devices.json written on the host by import or
# name. Do not read this filter as --update.
# .venv/ is the host's Python runtime (bin/threadwatch prefers it whenever
# it exists) and is named here on its own: the git-derived exclude list only
# covers it when this workstation happens to have one, and a push from a
# checkout without one used to delete the host's.
# Which config/ files this push would replace with an older copy: what a
# plain run sends, less what --update would send. -c compares content, so
# a host file that only carries a newer timestamp over the same bytes
# (a push copies mtimes; an editor's save-without-change does not) is not
# counted. config/ is a handful of small files, so the two dry runs cost
# nothing. The push used to warn and carry on, and the warning scrolled
# past above the rsync output; a host-written devices.json or the only
# copy of a network key was then gone. Now it stops, prints the copy-back
# commands, and FORCE_CONFIG=1 is the one way to say the workstation's
# copies are the ones wanted.
config_would_send() {
  rsync -ac --dry-run --out-format='%n' "$@" \
    --include '/config/' --include '/config/**' --exclude '*' \
    "$REPO/" "$TARGET:$DEST_DIR/" 2>/dev/null | grep -v '/$' | sort -u || true
}
REVERTS="$(comm -23 <(config_would_send) <(config_would_send --update))"
if [ -n "$REVERTS" ]; then
  if [ "${FORCE_CONFIG:-}" = "1" ]; then
    echo "warning: FORCE_CONFIG=1: replacing the host's NEWER copy of these:" >&2
    printf '%s\n' "$REVERTS" | sed 's/^/  /' >&2
  else
    echo "push-to-host.sh: the host has a NEWER, different copy of these; nothing pushed:" >&2
    printf '%s\n' "$REVERTS" | sed 's/^/  /' >&2
    echo "  copy them back first:" >&2
    while IFS= read -r f; do
      printf '    scp %q %q\n' "$TARGET:$DEST_DIR/$f" "$REPO/$f" >&2
    done <<< "$REVERTS"
    echo "  or FORCE_CONFIG=1 to replace them with this workstation's copies." >&2
    exit 1
  fi
fi

CHANGED="$(rsync -a --delete --dry-run --out-format='%n' \
  --exclude-from "$EXCLUDES" \
  --exclude 'data/' --exclude '.git/' --exclude '.venv/' \
  --filter 'P /config/***' --filter 'P /.venv/***' \
  "$REPO/" "$TARGET:$DEST_DIR/" 2>/dev/null | grep -E '^threadwatch/.*\.py$' || true)"

rsync -a --delete \
  --exclude-from "$EXCLUDES" \
  --exclude 'data/' --exclude '.git/' --exclude '.venv/' \
  --filter 'P /config/***' --filter 'P /.venv/***' \
  "$REPO/" "$TARGET:$DEST_DIR/"
ssh "$TARGET" "chmod 400 $DEST_DIR/config/credentials.toml $DEST_DIR/config/alerts.env $DEST_DIR/config/ha.env 2>/dev/null || true"

# What the host holds, written on the host: rsync ships no .git, so
# --version, doctor and the status page would otherwise have nothing to
# say about which code is there - the one question a deploy asks. Written
# after the transfer, since --delete removes it (it is not in the source
# tree) and nothing untracked may be added to this working tree. The "+"
# is this script's own subject: an uncommitted edit ships too, and then
# the commit alone does not describe what is running there.
REVISION="$(git -C "$REPO" rev-parse --short HEAD)"
if [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no)" ]; then
  REVISION="$REVISION+"
fi
printf '%s\n' "$REVISION" | ssh "$TARGET" "cat > $DEST_DIR/REVISION"
echo "pushed to $TARGET:$DEST_DIR ($REVISION)"

# rsync renames each changed file into place, so the running units keep the
# old code only for the modules they have already imported. Anything they
# import later comes from the new file: one process, two versions.
if [ "$MODE" = "--push-only" ] && [ -n "$CHANGED" ]; then
  echo "RESTART REQUIRED: this push changed $(printf '%s\n' "$CHANGED" | wc -l | tr -d ' ') module(s):" >&2
  printf '%s\n' "$CHANGED" | sed 's/^/  /' >&2
  echo "  the running units are on the old code until:" >&2
  echo "    ssh $TARGET 'sudo systemctl restart threadwatch threadwatch-web'" >&2
fi

if [ "$MODE" != "--push-only" ]; then
  echo "running remote setup (needs passwordless sudo on the host)..."
  ssh -t "$TARGET" "sudo $DEST_DIR/bin/setup-host.sh"
fi
