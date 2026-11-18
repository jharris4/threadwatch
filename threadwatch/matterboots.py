"""Every Matter node's boots, read from the node over the [otbr] SSH access.

The Matter Server stopped logging generalDiagnostics.bootReason (add-on
9.3.0, matter.js based; none after 2026-10-28), so reboots.scan finds
nothing in new archives. Each node's General Diagnostics reboot count
(0/51/1), uptime (0/51/2) and boot reason (0/51/4) are read instead, every
[matter_boots] poll_s, by SCRIPT: a fixed node script on the stdin of
`docker exec -i <container> node -` that lists the nodes and reads those
three attributes over the server's WebSocket on localhost. It only reads,
and nothing from the recorder goes into it.

A boot is a reboot count that changed, or a boot time (read time minus
uptime) that moved later than the last read put it. It goes into the key
journal as an `uptime_reset` reboot and is a device_rebooted notice;
reboots_climbing is judged on these boots. A node's first read puts its
last boot in the journal without a notice.

A failed poll, or a node that does not answer, changes nothing: the next
good read compares with the last good one. The count misses no boot, but
of several boots between two good reads only the last has a time and a
reason (`boots` counts them all). Without a count, uptime sees only the
last of them. A node that gives neither is not judged.

The stamp is the read time minus uptime, with the slow clock in CLOCKS
removed: within a second for a boot found within the hour. The Matter
Server's `CaseServer ... Resumed session` line after an ALPSTUGA reset is
no better (it is the reconnect, up to 6 s after the reset by uptime) and
would hold the notice until the hourly archive had it.
"""

from __future__ import annotations

import copy
import json
import math
import threading
import time
from pathlib import Path

from .otbr import run_command, ssh_argv

STATE = "matter-boots.json"
TIMEOUT_S = 360.0                    # the whole pass; 45 nodes took about 80 s on 2026-11-17
CLOCKS = {"ALPSTUGA": 0.001526}      # product name part -> fraction its uptime runs slow
SLACK_S = 60.0                       # read latency in the boot time a read implies
# Boots kept for the climb, which looks back reboots.LOOKBACK_S (7 days):
# inside the 8 days reboots.json remembers a boot as logged, so a boot
# still held here is never logged twice.
HISTORY_S = 7 * 86400.0 + 3600.0
RETRY_S = 900.0                      # after a failed poll

SCRIPT = r"""// threadwatch matterboots: read-only.
setTimeout(() => process.exit(2), 330000);
const ws = new WebSocket('ws://127.0.0.1:5580/ws');
const end = Date.now() + 300000, pending = new Map();
let id = 0;
const call = (command, args, ms) => new Promise((resolve) => {
  const mid = String(++id);
  const timer = setTimeout(() => { pending.delete(mid); resolve({ error_code: 'timeout' }); }, ms);
  pending.set(mid, (m) => { clearTimeout(timer); resolve(m); });
  ws.send(JSON.stringify({ message_id: mid, command, args }));
});
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data), f = pending.get(m.message_id);
  if (f) { pending.delete(m.message_id); f(m); }
};
ws.onerror = () => { console.log(JSON.stringify({ error: 'websocket' })); process.exit(1); };
ws.onopen = async () => {
  const nodes = (await call('get_nodes', {}, 60000)).result || [];
  for (const n of nodes) {
    const left = end - Date.now();
    const r = left > 0 ? await call('read_attribute', { node_id: n.node_id,
      attribute_path: ['0/51/1', '0/51/2', '0/51/4'] }, Math.min(30000, left)) : { error_code: 'deadline' };
    console.log(JSON.stringify({ node: n.node_id, product: (n.attributes || {})['0/40/3'],
      at: Date.now() / 1000, result: r.result, error: r.error_code }));
  }
  console.log(JSON.stringify({ done: nodes.length }));
  process.exit(0);
};
"""


def _count(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def read(cfg, runner=run_command) -> tuple[dict[int, dict], str]:
    """Each node's read, and "ok" when the script listed the nodes and finished."""
    result = runner(ssh_argv(cfg, cfg.boots_container, ["node", "-"], stdin=True), SCRIPT.encode(), TIMEOUT_S)
    reads, done = {}, None
    for line in result.get("output", "").splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if not isinstance(m, dict):
            continue
        done = m["done"] if _count(m.get("done")) else done
        got = m.get("result") if isinstance(m.get("result"), dict) else {}
        if _count(m.get("node")) and _number(m.get("at")):
            uptime = got.get("0/51/2")
            reads[m["node"]] = {"at": float(m["at"]), "product": m.get("product") if isinstance(m.get("product"), str)
                                else "", "count": got.get("0/51/1") if _count(got.get("0/51/1")) else None,
                                "uptime": float(uptime) if _number(uptime) and uptime >= 0 else None,
                                "reason": got.get("0/51/4") if _count(got.get("0/51/4")) else None}
    return reads, "ok" if done else ("no nodes listed" if done == 0 else result.get("status", "failed"))


def boot_time(r: dict) -> float | None:
    """When the node booted by its uptime, its slow clock removed."""
    if r["uptime"] is None:
        return None
    return r["at"] - r["uptime"] / (1 - next((v for k, v in CLOCKS.items() if k in r["product"]), 0.0))


def boots_between(prev: dict, r: dict, est: float | None) -> int:
    """The boots a read shows since the node's last good read."""
    if r["count"] is not None and prev.get("count") is not None and r["count"] != prev["count"]:
        return r["count"] - prev["count"] if r["count"] > prev["count"] else 1
    if est is not None and _number(prev.get("boot")) and est - prev["boot"] > SLACK_S + 0.002 * (r["at"] - prev["at"]):
        return 1
    return 0


def poll(cfg, state: dict, now: float, runner=run_command) -> tuple[dict, list[dict], dict]:
    """One pass on a copy of ``state``: the new state, the boots found, and
    a summary for status.json."""
    state = copy.deepcopy(state)
    nodes, finals, failed = state.setdefault("nodes", {}), [], []
    reads, status = read(cfg, runner)
    for node, r in sorted(reads.items()):
        est = boot_time(r)
        if est is None and r["count"] is None:
            failed.append(node)
            continue
        prev = nodes.get(str(node))
        n = 1 if prev is None and est is not None else boots_between(prev, r, est) if prev else 0
        if n:
            finals.append({"node": node, "boots": n, "first_read": prev is None, "after": prev["at"] if prev else None,
                           "read": r, "ts": est if est is not None else r["at"],
                           "stamp": "uptime" if est is not None else "read_time"})
        nodes[str(node)] = {"at": r["at"], "count": r["count"], "boot": est, "product": r["product"],
                            "since": prev.get("since", r["at"]) if prev else r["at"]}
    state["history"] = [h for h in state.get("history", []) if h[0] >= now - HISTORY_S] + [
        [b["ts"], b["node"], b["read"]["reason"] or 0, b["boots"]] for b in finals if not b["first_read"]]
    return state, finals, {"at": now, "status": status, "nodes": len(reads), "read": len(reads) - len(failed),
                           "failed": failed}


def climb_scan(state: dict, now: float) -> dict:
    """reboots.RebootWatch's input: every node is covered from its first
    read, since the count misses no boot between reads."""
    since = {k: v["since"] for k, v in state.get("nodes", {}).items()}
    start = max(min(since.values(), default=now), now - HISTORY_S)
    return {"boots": state.get("history", []), "first_seen": since,
            "hours": [time.strftime("%Y%m%d-%H", time.gmtime(h))
                      for h in range(int(start // 3600) * 3600, int(now // 3600) * 3600, 3600)]}


def load(path: Path) -> dict:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    nodes = data.get("nodes") if isinstance(data.get("nodes"), dict) else {}
    return {"nodes": {k: v for k, v in nodes.items() if isinstance(v, dict) and _number(v.get("at"))
                      and _number(v.get("since")) and isinstance(v.get("product"), str)},
            "history": [h for h in data.get("history") or [] if isinstance(h, list) and len(h) == 4
                        and all(_number(x) for x in h)],
            "next_poll_at": data.get("next_poll_at") if _number(data.get("next_poll_at")) else 0,
            "last": data.get("last") if isinstance(data.get("last"), dict) else None}


class BootPoller:
    """One worker for the SSH read; the capture
    thread applies the result (Pipeline._apply_matter_boots) and then
    commits the state, so a boot is never marked seen before it is journalled."""

    def __init__(self, cfg):
        self.cfg, self.path = cfg, cfg.state_dir / STATE
        self.state = load(self.path)
        self.thread = self.result = None

    def tick(self, now: float):
        """The finished pass (state, boots, summary) once; else None, and
        the next pass started when it is due."""
        if self.thread is not None:
            if self.thread.is_alive():
                return None
            self.thread.join()
            self.thread, done, self.result = None, self.result, None
            return done
        if now < self.state.get("next_poll_at", 0) <= now + self.cfg.boots_poll_s:
            return None
        state = self.state

        def run():
            try:
                self.result = poll(self.cfg, state, time.time())
            except Exception as exc:
                self.result = (state, [], {"at": time.time(), "status": f"failed: {type(exc).__name__}: {exc}"})

        self.thread = threading.Thread(target=run, name="matter-boots", daemon=True)
        self.thread.start()
        return None

    def commit(self, state: dict, summary: dict) -> None:
        before = (self.state.get("last") or {}).get("status"), (self.state.get("last") or {}).get("read")
        ok = summary["status"] == "ok"
        self.state = {**state, "last": summary,
                      "next_poll_at": summary["at"] + (self.cfg.boots_poll_s if ok else RETRY_S)}
        if before != (summary["status"], summary.get("read")):
            print(f"[threadwatch] matter boots: {summary['status']}, read {summary.get('read', 0)} of "
                  f"{summary.get('nodes', 0)} nodes" + (f", no answer from {summary['failed']}"
                                                         if summary.get("failed") else ""), flush=True)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.state))
            tmp.replace(self.path)
        except OSError as exc:
            print(f"[threadwatch] matter boots: state save failed: {exc}", flush=True)
