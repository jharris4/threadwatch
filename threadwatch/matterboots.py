"""Every Matter node's boots, read from the node over the [otbr] SSH access.

The Matter Server stopped logging generalDiagnostics.bootReason (add-on
9.3.0, matter.js based; none after 2026-10-28), so reboots.scan finds
nothing in new archives. Each node's General Diagnostics reboot count
(0/51/1), uptime (0/51/2) and boot reason (0/51/4) are read instead, every
[matter_boots] poll_s, by SCRIPT: a fixed node script on the stdin of
`docker exec -i <container> node -` that lists the nodes and reads those
three attributes over the server's WebSocket on localhost. It only reads,
and nothing from the recorder goes into it.

A boot is a reboot count that changed; with the count unchanged, an
uptime lower than the node's own uptime at its last read that had one
(the device's number against its own earlier number, so no host clock is
involved); or, for a node that does not give a count both times, a boot
time (read time minus uptime) that moved later than the last read put it.
A clock step on the HA host moves every boot time and changes neither a
count nor an uptime, so it is no boot where there is a count. A boot goes
into the key journal as an `uptime_reset` reboot and is a device_rebooted
notice; reboots_climbing is judged on these boots. A node's first read with an uptime puts its last
boot in the journal without a notice, unless that boot came after the
previous pass (a node re-paired under a new id): that is a boot like any
other. A node unread for FORGET_S is dropped.

A failed poll, or a node that does not answer, changes nothing: the next
good read compares with the last good one, and an attribute one read
lacks keeps its last value. STALLED_S with no node read at all is a
matter_boots_stalled notice, once, and the first pass that reads one after
it a matter_boots_resumed: a poller that has stopped working is otherwise
only a line in status.json. The count misses no boot, but
of several boots between two good reads only the last has a time and a
reason (`boots` counts them all). Without a count, uptime sees only the
last of them. A node that gives neither is not judged.

The read time is the HA host's clock and the switches a boot is set
against carry this host's, so each pass is checked: a pass with a read
stamped more than SKEW_S before it started or after it ended, by this
host's clock, is dropped whole and retried. No boot is dated, and no
uptime-only boot found, against a clock that disagrees.

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
RETRY_S = 900.0                      # after a failed or cut-short poll
SKEW_S = 60.0                        # how far the HA host's clock may be from this host's
STALLED_S = 3 * 3600.0               # this long with no node read is a matter_boots_stalled notice
FORGET_S = 30 * 86400.0              # a node unread this long is gone (re-paired, removed)
# How slow an uptime clock may run that CLOCKS does not correct (Phase 0:
# 0.01% to 0.05% on BILRESA, MYGG and TOFSMYGGA): a boot may be this
# fraction of its uptime earlier than read time minus uptime says.
SLOW_BOUND = 0.0005

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
  for (let i = nodes.length - 1; i > 0; i--) {   // a new order each pass: a deadline starves no one node
    const j = Math.floor(Math.random() * (i + 1)); [nodes[i], nodes[j]] = [nodes[j], nodes[i]];
  }
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
    """Each node's read, and "ok" when the script listed the nodes and read
    them all before its deadline."""
    result = runner(ssh_argv(cfg, cfg.boots_container, ["node", "-"], stdin=True), SCRIPT.encode(), TIMEOUT_S)
    reads, done, cut = {}, None, False
    for line in result.get("output", "").splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if not isinstance(m, dict):
            continue
        done = m["done"] if _count(m.get("done")) else done
        cut |= m.get("error") == "deadline"
        got = m.get("result") if isinstance(m.get("result"), dict) else {}
        if _count(m.get("node")) and _number(m.get("at")):
            uptime = got.get("0/51/2")
            reads[m["node"]] = {"at": float(m["at"]), "product": m.get("product") if isinstance(m.get("product"), str)
                                else "", "count": got.get("0/51/1") if _count(got.get("0/51/1")) else None,
                                "uptime": float(uptime) if _number(uptime) and uptime >= 0 else None,
                                "reason": got.get("0/51/4") if _count(got.get("0/51/4")) else None}
    if done and cut:
        return reads, "partial: the pass ran out of time"
    return reads, "ok" if done else ("no nodes listed" if done == 0 else result.get("status", "failed"))


def boot_time(r: dict) -> float | None:
    """When the node booted by its uptime, its slow clock removed."""
    if r["uptime"] is None:
        return None
    return r["at"] - r["uptime"] / (1 - next((v for k, v in CLOCKS.items() if k in r["product"]), 0.0))


def boots_between(prev: dict, r: dict, est: float | None) -> int:
    """The boots a read shows since the node's last good read: when both
    reads have a count, the count, and with the count unchanged the
    device's own uptime going down (no host clock in that); the boot time
    the uptime implies only when one read has no count."""
    if r["count"] is not None and prev.get("count") is not None:
        if r["count"] == prev["count"]:
            return int(r["uptime"] is not None and _number(prev.get("uptime")) and r["uptime"] < prev["uptime"])
        return r["count"] - prev["count"] if r["count"] > prev["count"] else 1
    if est is not None and _number(prev.get("boot")) and est - prev["boot"] > SLACK_S + 0.002 * (r["at"] - prev["at"]):
        return 1
    return 0


def poll(cfg, state: dict, now: float, runner=run_command, clock=time.time) -> tuple[dict, list[dict], dict]:
    """One pass on a copy of ``state``: the new state, the boots found, and
    a summary for status.json. Each boot carries ``earliest``, how early
    the boot may really have been. ``now`` is this host's clock as the
    pass starts and ``clock`` reads it as the pass ends."""
    state = copy.deepcopy(state)
    nodes, finals, failed = state.setdefault("nodes", {}), [], []
    last_pass = state.get("read_at")               # the last pass that read anything
    reads, status = read(cfg, runner)
    end = clock()
    off = max((d for r in reads.values() for d in (now - r["at"], r["at"] - end)), default=0.0)
    if off > SKEW_S:
        return state, [], {"at": now, "nodes": len(reads), "read": 0, "failed": [],
                           "status": f"clock: the Home Assistant host's clock is {off:.0f} s from this host's"}
    for node, r in sorted(reads.items()):
        est = boot_time(r)
        if est is None and r["count"] is None:
            failed.append(node)
            continue
        prev = nodes.get(str(node)) or {}
        n = boots_between(prev, r, est) if prev else 0
        if not prev and est is not None and _number(last_pass) and est > last_pass:
            n = 1                                  # new to us, booted since the last pass: re-paired
        first = not n and not prev.get("journalled") and est is not None
        if n or first:
            finals.append({"node": node, "boots": n or 1, "first_read": first, "after": prev.get("at"),
                           "read": r, "ts": est if est is not None else r["at"],
                           "earliest": est - SLOW_BOUND * r["uptime"] if est is not None else prev.get("at"),
                           "stamp": "uptime" if est is not None else "read_time"})
        carry = not n                              # no boot: what this read lacks has not changed
        nodes[str(node)] = {"at": r["at"], "product": r["product"] or prev.get("product", ""),
                            "count": prev.get("count") if carry and r["count"] is None else r["count"],
                            "uptime": prev.get("uptime") if carry and r["uptime"] is None else r["uptime"],
                            "boot": prev.get("boot") if carry and est is None else est,
                            "since": prev.get("since", r["at"]),
                            "journalled": bool(prev.get("journalled") or n or first)}
    state["nodes"] = {k: v for k, v in nodes.items() if v["at"] >= now - FORGET_S}
    state["read_at"] = now if len(reads) > len(failed) else last_pass
    state["history"] = [h for h in state.get("history", []) if h[0] >= now - HISTORY_S] + [
        [b["ts"], b["node"], b["read"]["reason"] or 0, b["boots"], b["after"] if _number(b["after"]) else b["ts"]]
        for b in finals if not b["first_read"]]             # the last: the read before, which bounds the undated boots
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
            "history": [h for h in data.get("history") or [] if isinstance(h, list) and len(h) == 5
                        and all(_number(x) for x in h)],
            "held": [b for b in data.get("held") or [] if isinstance(b, dict) and _count(b.get("node"))
                     and _number(b.get("ts")) and isinstance(b.get("read"), dict)],
            "read_at": data.get("read_at") if _number(data.get("read_at")) else None,
            "outage": data.get("outage") if isinstance(data.get("outage"), dict)
            and _number(data["outage"].get("since")) else {},
            "next_poll_at": data.get("next_poll_at") if _number(data.get("next_poll_at")) else 0,
            "last": data.get("last") if isinstance(data.get("last"), dict) else None}


class BootPoller:
    """One worker for the SSH read; the capture thread applies the result
    (Pipeline._apply_matter_boots) and then commits the state, so a boot is
    never marked seen before it is journalled. A result whose journal save
    failed is handed back (``retry``) and applied again on the next tick,
    before any new pass."""

    def __init__(self, cfg):
        self.cfg, self.path = cfg, cfg.state_dir / STATE
        self.state = load(self.path)
        self.thread = self.result = self.retry = None

    def rejournal(self) -> None:
        """The key journal starts empty (new, lost or unreadable) while this
        state says each node's last boot is in it: every node's next read
        journals its last boot again, as a first read does. That read is
        due at once and the cleared marks are saved, so a restart before it
        (the new journal then loads as any other) does not lose them."""
        for node in self.state.get("nodes", {}).values():
            node["journalled"] = False
        self.state["next_poll_at"] = 0
        self._save()

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.state))
            tmp.replace(self.path)
        except OSError as exc:
            print(f"[threadwatch] matter boots: state save failed: {exc}", flush=True)

    def tick(self, now: float):
        """The finished pass (state, boots, summary) once; else None, and
        the next pass started when it is due. ``now`` is this host's clock,
        as commit's schedule is, not the frame clock."""
        if self.retry is not None:
            done, self.retry = self.retry, None
            return done
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

    def commit(self, state: dict, summary: dict) -> list[tuple[str, str, dict]]:
        """The pass's state kept and saved. Returns the events it calls
        for, as (name, severity, fields): matter_boots_stalled once when no
        node has been read for STALLED_S (from the last pass that read one,
        or the first failure when none ever did), matter_boots_resumed when
        one is read after that."""
        before = (self.state.get("last") or {}).get("status"), (self.state.get("last") or {}).get("read")
        ok = summary["status"] == "ok"
        events, outage = [], dict(state.get("outage") or {})
        if summary.get("read"):
            if outage.get("reported"):
                gone = summary["at"] - outage["since"]
                events.append(("matter_boots_resumed", "info", {
                    "since": outage["since"], "stalled_for_s": round(gone), "nodes": summary.get("nodes", 0),
                    "read": summary["read"],
                    "note": (f"Matter boots are read again after {gone / 3600:.1f} h: {summary['read']} of "
                             f"{summary.get('nodes', 0)} nodes answered. Boots in between are counted; only each "
                             "device's last has a time")}))
            outage = {}
        else:
            outage.setdefault("since", state["read_at"] if _number(state.get("read_at")) else summary["at"])
            gone = summary["at"] - outage["since"]
            if not outage.get("reported") and gone >= STALLED_S:
                outage["reported"] = True
                events.append(("matter_boots_stalled", "notice", {
                    "since": outage["since"], "status": summary["status"],
                    "note": (f"no Matter node has given its boots for {gone / 3600:.1f} h (last poll: "
                             f"{summary['status']}): device_rebooted and reboots_climbing see nothing, and the "
                             f"key journal's last boots go stale, until a poll succeeds; retried every "
                             f"{RETRY_S / 60:.0f} min (docs/OPERATIONS.md, Matter boots over the same SSH)")}))
        self.state = {**state, "outage": outage, "last": summary,
                      "next_poll_at": summary["at"] + (self.cfg.boots_poll_s if ok else RETRY_S)}
        if before != (summary["status"], summary.get("read")):
            print(f"[threadwatch] matter boots: {summary['status']}, read {summary.get('read', 0)} of "
                  f"{summary.get('nodes', 0)} nodes" + (f", no answer from {summary['failed']}"
                                                         if summary.get("failed") else ""), flush=True)
        self._save()
        return events
