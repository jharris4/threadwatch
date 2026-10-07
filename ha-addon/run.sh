#!/bin/sh
# The add-on's entrypoint: the options set in Home Assistant, which the
# Supervisor writes to /data/options.json, become `threadwatch relay` flags.
set -eu
eval "set -- $(python3 -c '
import json, shlex
o = json.load(open("/data/options.json"))
args = ["--to", o["to"], "--label", o["label"], "--channel", str(o["channel"])]
if o.get("serial_port"):
    args += ["--serial-port", o["serial_port"]]
print(shlex.join(args))
')"
echo "[run.sh] threadwatch $(cat /app/REVISION 2>/dev/null || echo '(no REVISION)')" >&2
# The Supervisor stops the add-on with SIGTERM: pass it on to the relay.
pid=
trap '[ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; exit 0' TERM INT
while :; do
  /app/bin/threadwatch relay "$@" &
  pid=$!
  code=0
  wait "$pid" || code=$?
  # 2 is an option the relay refuses: the same options would fail again.
  [ "$code" -eq 2 ] && exit 2
  echo "[run.sh] the relay exited $code; starting it again in 10 s" >&2
  sleep 10
done
