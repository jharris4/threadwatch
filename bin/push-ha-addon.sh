#!/usr/bin/env bash
# Copy the threadwatch relay add-on (ha-addon/, DOCS.md) to a Home
# Assistant host's /addons, where the Supervisor builds it as a local
# add-on. The ssh target is any shell on that host that can write /addons:
# the "Advanced SSH & Web Terminal" or "Terminal & SSH" add-on.
#
#     bin/push-ha-addon.sh hassio@homeassistant.local
#     bin/push-ha-addon.sh hassio@192.0.2.20 -p 2222 -i ~/.ssh/ha_key
#
# Everything after the target is passed to ssh. What deploys is what git
# tracks of the package, the vendored sniffer, the entrypoint and
# requirements.txt, as push-to-host.sh does (an uncommitted edit to a
# tracked file ships; an untracked file does not), plus ha-addon/ and a
# REVISION. This only copies: installing, rebuilding and starting are the
# Supervisor's, from its UI (DOCS.md), as its CLI needs a token an ssh
# session does not have.
set -euo pipefail

TARGET="${1:?usage: push-ha-addon.sh user@host [ssh options...]}"
case "$TARGET" in
  -*) echo "usage: push-ha-addon.sh user@host [ssh options...] (the host comes first, not '$TARGET'); nothing pushed" >&2
      exit 1 ;;
esac
shift
REPO="$(cd "$(dirname "$0")/.." && pwd)"
SLUG=threadwatch_relay

git -C "$REPO" rev-parse --is-inside-work-tree >/dev/null \
  || { echo "push-ha-addon.sh: $REPO is not a git working tree (or git is missing); nothing pushed" >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
(cd "$REPO" && git ls-files -z -- threadwatch vendor bin/threadwatch requirements.txt | tar --null -T - -cf -) \
  | tar -C "$STAGE" -xf -
cp -R "$REPO/ha-addon/." "$STAGE/"
REVISION="$(git -C "$REPO" rev-parse --short HEAD)"
if [ -n "$(git -C "$REPO" status --porcelain --untracked-files=no -- threadwatch vendor bin/threadwatch requirements.txt ha-addon)" ]; then
  REVISION="$REVISION+"
fi
printf '%s\n' "$REVISION" > "$STAGE/REVISION"

# Unpacked in full before the old folder is replaced, so a copy cut off
# midway leaves the add-on as it was; sudo where the shell is not root.
# shellcheck disable=SC2016  # expanded on the host, not here
REMOTE='set -e
S=; [ "$(id -u)" = 0 ] || S="sudo -n"
T=$($S mktemp -d)
$S tar -C "$T" -xf -
$S rm -rf /addons/'"$SLUG"'
$S mv "$T" /addons/'"$SLUG"'
$S chmod 755 /addons/'"$SLUG"
# No macOS metadata: ._ files and xattr headers the host's tar warns about.
# shellcheck disable=SC2029  # $REMOTE is meant to be expanded here, into the command
COPYFILE_DISABLE=1 tar --no-xattrs -C "$STAGE" -cf - . | ssh "$@" "$TARGET" "sh -c '$REMOTE'" \
  || { echo "push-ha-addon.sh: copying to $TARGET:/addons/$SLUG failed" >&2; exit 1; }

cat <<EOF
pushed to $TARGET:/addons/$SLUG ($REVISION)
In Home Assistant, Settings > Add-ons > Add-on store, menu > Check for updates, then:
  first time: Local add-ons > threadwatch relay > Install, set its options (DOCS.md), Start
  after that: threadwatch relay > Rebuild (it restarts on the new code)
EOF
