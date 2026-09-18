"""Bounded sequence observations, separate from replay-protection counters.

Counts cover each retained sequence's first/last observation span, not a
rolling time bucket. Rejected MIC-valid traffic is forensic evidence only.
"""

from __future__ import annotations

import math

HISTORY_LIMIT = 8                    # per layer, per acceptance decision
LAYERS = (("mac", "counter"), ("mle", "mle_counter"))


def _int(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xffffffff


def _time(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def _point(value):
    if isinstance(value, dict) and _int(value.get("sequence")) and _time(value.get("ts")):
        return {"sequence": value["sequence"], "ts": value["ts"],
                "legacy": value.get("legacy") is True}
    return None


def _legacy(row, key):
    points = [_point({"sequence": row.get(key + "_seq"), "ts": row.get(key + "_ts"), "legacy": True})]
    prev = row.get(key + "_prev")
    if isinstance(prev, list) and len(prev) == 3:
        points.append(_point({"sequence": prev[2], "ts": prev[1], "legacy": True}))
    return [p for p in points if p is not None]


def facts(row: dict) -> dict:
    """Return a validated copy; legacy counter timestamps are estimates.

    Legacy rows have no counts. Never invent historical counts or use
    rejected evidence to initialize latest accepted transmission state.
    """
    raw = row.get("key_facts")
    raw = raw if isinstance(raw, dict) and raw.get("version") == 1 else {}
    out = {"version": 1}
    highest = []
    for layer, key in LAYERS:
        old = _legacy(row, key)
        highest.extend(old)
        data = raw.get(layer)
        data = data if isinstance(data, dict) else {}
        latest = _point(data.get("latest"))
        if latest is None and old:
            latest = max(old, key=lambda p: p["ts"])
        entry = {"latest": latest}
        if latest:
            highest.append(latest)
        for decision in ("accepted", "rejected"):
            spans = data.get(decision)
            clean = []
            for span in spans if isinstance(spans, list) else []:
                if not isinstance(span, dict) or not _int(span.get("sequence")):
                    continue
                if not all(_time(span.get(k)) for k in ("first_ts", "last_ts")):
                    continue
                if span["first_ts"] > span["last_ts"]:
                    continue
                item = {k: span[k] for k in ("sequence", "first_ts", "last_ts")}
                for k in ("count", "retries"):
                    v = span.get(k)
                    item[k] = v if isinstance(v, int) and not isinstance(v, bool) and v >= 0 else 0
                if decision == "rejected":
                    reason = span.get("reason")
                    item["reason"] = reason if reason in (
                        "counter_not_advancing", "older_than_retained", "authentication_history_full") else "unknown"
                clean.append(item)
            entry[decision] = sorted(clean, key=lambda s: s["last_ts"])[-HISTORY_LIMIT:]
        out[layer] = entry
    point = _point(raw.get("highest_authenticated"))
    if point:
        highest.append(point)
    out["highest_authenticated"] = max(highest, key=lambda p: (p["sequence"], p["ts"])) if highest else None
    return out


def observe(row: dict, layer: str, sequence: int, ts: float, *, accepted: bool,
            retry: bool = False, reason: str | None = None) -> None:
    """Record an authenticated observation on an already admitted row.

    Neither this state nor its highest sequence feeds replay protection.
    A late packet cannot rewind latest TX; lower-sequence packets cannot
    refresh the timestamp attached to the highest authenticated sequence.
    """
    if not _int(sequence) or not _time(ts):
        return
    state = facts(row)
    point = {"sequence": sequence, "ts": ts, "legacy": False}
    high = state["highest_authenticated"]
    if high is None or (sequence, ts) >= (high["sequence"], high["ts"]):
        state["highest_authenticated"] = point
    entry = state[layer]
    latest = entry["latest"]
    if accepted and (latest is None or ts >= latest["ts"]):
        entry["latest"] = point
    spans = entry["accepted" if accepted else "rejected"]
    span = next((s for s in spans if s["sequence"] == sequence), None)
    if span is None:
        span = {"sequence": sequence, "first_ts": ts, "last_ts": ts, "count": 0, "retries": 0}
        spans.append(span)
    span["first_ts"] = min(span["first_ts"], ts)
    span["last_ts"] = max(span["last_ts"], ts)
    span["retries" if accepted and retry else "count"] += 1
    if not accepted:
        span["reason"] = reason or "unknown"
    spans.sort(key=lambda s: s["last_ts"])
    del spans[:-HISTORY_LIMIT]
    row["key_facts"] = state


def latest_generation(row: dict) -> tuple[int | None, float | None]:
    """Latest accepted TX across layers; MAC wins equal timestamps.

    A frame's MAC sequence describes its link transmission even when the
    inner MLE message uses a different sequence. Both remain visible.
    """
    state = facts(row)
    points = [state[layer]["latest"] for layer, _ in LAYERS if state[layer]["latest"]]
    latest = max(points, key=lambda p: p["ts"]) if points else None
    return (latest["sequence"], latest["ts"]) if latest else (None, None)


def summary(row: dict, now: float, fresh_s: float = 1800) -> dict:
    state = facts(row)
    recent = set()
    for layer, _ in LAYERS:
        entry = state[layer]
        latest = entry["latest"]
        if latest and 0 <= now - latest["ts"] <= fresh_s:
            recent.add(latest["sequence"])
        for span in entry["accepted"]:
            if 0 <= now - span["last_ts"] <= fresh_s:
                recent.add(span["sequence"])
    state["mixed"] = len(recent) > 1
    state["recent_sequences"] = sorted(recent)
    state["recent_rejected"] = sum(span["count"] for layer, _ in LAYERS for span in state[layer]["rejected"]
                                   if 0 <= now - span["last_ts"] <= fresh_s)
    state["fresh_s"] = fresh_s
    return state
