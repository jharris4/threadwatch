"""Compact, bounded key-transition evidence; never an input to detection.

Times are first *observations*, not device switch times. Baselines and
MAC/MLE observations remain separate. No packet payloads or key material
are retained here. Reporting and historical imports are read-only.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import sys
import time
from collections import Counter
from pathlib import Path

from .keyfacts import _int, _time, facts

STATE = "key-journal.json"
KEEP_S = 90 * 86400
MAX_RECORDS = 8192
MAX_BYTES = 16 * 1024 * 1024
MAX_DEVICES = 1024
EVENTS = frozenset(("key_sequence_advanced", "key_lag", "key_lag_cleared", "key_lag_census",
                    "mle_rejoin_attempt", "ha_unavailable", "ha_available",
                    "partition_or_leader_change", "partition_storm", "leader_stalled",
                    "clock_step", "recorder_started",
                    "snapshot_requested", "snapshot_saved", "snapshot_skipped"))


def _id(*values):
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()[:24]


def unknown_coverage(reason="capture_completeness_not_measured"):
    return {"status": "unknown", "history_complete": False, "reasons": [reason]}


def guard():
    return {"assessment": "unknown", "assumptions": [],
            "reason": "device_guard_state_and_reset_history_not_observed"}


class Journal:
    def __init__(self, path: Path | None = None):
        self.path = path
        self.records = []
        self.latest = {}
        self.inventory_latest = {}
        self.archive_scan = {"files": {}, "pending_files": None}
        self.dropped = 0
        self.load_status = "new"
        self.dirty = False
        self.saved_at = 0.0
        if path is not None and path.exists():
            try:
                if path.stat().st_size > MAX_BYTES:
                    raise ValueError("journal exceeds size bound")
                state = json.loads(path.read_text())
                if not isinstance(state, dict) or state.get("version") != 1:
                    raise ValueError("unsupported journal")
                records = state.get("records")
                if not isinstance(records, list):
                    raise ValueError("invalid records")
                self.records = [r for r in records[-MAX_RECORDS:] if self._valid(r)]
                # Points are rebuilt from validated records: hand-edited nested
                # state cannot fabricate a prior transition or break capture.
                self.load_status = "loaded" if len(self.records) == len(records) else "partial"
                self.dropped = state.get("dropped", 0)
                if not isinstance(self.dropped, int) or self.dropped < 0:
                    self.dropped = 0
                for r in self.records:
                    if r["kind"] == "transition":
                        self.latest[(r["addr"], r["layer"])] = {
                            "sequence": r["new_sequence"], "ts": r["ts"], "record": r["id"]}
                    elif r["kind"] == "event" and r["evidence"].get("event") == "clock_step":
                        if _time(r["evidence"].get("step_s")) and r["evidence"]["step_s"] < 0:
                            self.latest.clear()
                points = state.get("inventory_latest", {})
                if isinstance(points, dict):
                    self.inventory_latest = {k: v for k, v in list(points.items())[:16]
                                             if isinstance(v, dict) and _time(v.get("ts"))
                                             and isinstance(v.get("source"), dict)
                                             and (v.get("uptime_s") is None or _time(v["uptime_s"]))
                                             and (v.get("sequence") is None or _int(v["sequence"]))
                                             and (v.get("guard_hours") is None or _int(v["guard_hours"]))}
            except (OSError, ValueError, TypeError):
                self.load_status = "unreadable"
        if path is not None and self.load_status in ("loaded", "partial"):
            scan = state.get("archive_scan")
            if isinstance(scan, dict) and isinstance(scan.get("files"), dict):
                self.archive_scan = {"files": {k: v for k, v in list(scan["files"].items())[-2160:]
                                               if isinstance(v, dict) and isinstance(v.get("signature"), list)},
                                     "pending_files": scan.get("pending_files")}
        self.ids = {r["id"] for r in self.records}
        self._sizes = {r["id"]: len(json.dumps(r).encode()) for r in self.records}
        self._bytes = sum(self._sizes.values())

    @staticmethod
    def _valid(r):
        if not isinstance(r, dict) or not isinstance(r.get("id"), str) or not _time(r.get("ts")):
            return False
        if r.get("addr") is not None and not isinstance(r["addr"], str):
            return False
        if r.get("kind") not in ("transition", "event", "otbr", "reboot", "inventory", "topology"):
            return False
        if r["kind"] == "transition":
            return (isinstance(r.get("addr"), str) and r.get("layer") in ("mac", "mle")
                    and _int(r.get("new_sequence")) and isinstance(r.get("context"), dict)
                    and isinstance(r.get("coverage"), dict)
                    and (r.get("old_sequence") is None or _int(r["old_sequence"]))
                    and all(k in r for k in ("old_sequence", "packet", "source_peer", "candidate_update_path",
                                             "transport", "update_class", "link_reestablishment"))
                    and (r["context"].get("parent") is None or isinstance(r["context"]["parent"], dict))
                    and (r.get("previous_record") is None or isinstance(r["previous_record"], str))
                    and r.get("observation_kind") in ("baseline", "transition"))
        e = r.get("evidence")
        if not isinstance(e, dict):
            return False
        if r["kind"] == "event":
            return (e.get("event") in EVENTS and (e.get("sequence") is None or _int(e["sequence"]))
                    and (e.get("first_sender") is None or isinstance(e["first_sender"], str))
                    and (e.get("step_s") is None or _time(e["step_s"]))
                    and all(e.get(k) is None or _time(e[k]) for k in ("observed_interval_s", "since_previous_s")))
        if r["kind"] == "otbr":
            return (isinstance(e.get("change"), dict) and all(k in e["change"] for k in ("utc", "file", "line"))
                    and isinstance(e.get("candidate_update_path"), str))
        if r["kind"] == "inventory":
            return (all(k in e for k in ("old_sequence", "new_sequence", "before", "after"))
                    and isinstance(e.get("guard"), dict) and "assessment" in e["guard"])
        if r["kind"] == "reboot":
            return all(isinstance(e.get(k), str) for k in ("source", "scope", "reference"))
        return True

    def add(self, record):
        if not self._valid(record):
            self.dropped += 1
            self.dirty = True
            return
        if record["id"] in self.ids:
            return
        size = len(json.dumps(record).encode())
        if size > 65536:
            self.dropped += 1
            self.dirty = True
            return
        self.records.append(copy.deepcopy(record))
        self.ids.add(record["id"])
        self._sizes[record["id"]] = size
        self._bytes += size
        self.dirty = True
        if len(self.records) > MAX_RECORDS or self._bytes > MAX_BYTES:
            self.prune(max(r["ts"] for r in self.records))

    def prune(self, now):
        before = len(self.records)
        self.records = sorted((r for r in self.records if r["ts"] >= now - KEEP_S),
                              key=lambda r: r["ts"])[-MAX_RECORDS:]
        size = sum(self._sizes.get(r["id"], 0) for r in self.records)
        while self.records and size > MAX_BYTES:
            size -= self._sizes.get(self.records.pop(0)["id"], 0)
        self.ids = {r["id"] for r in self.records}
        self._sizes = {k: v for k, v in self._sizes.items() if k in self.ids}
        self._bytes = sum(self._sizes.values())
        self.latest = {k: v for k, v in self.latest.items() if v["record"] in self.ids}
        self.dropped += before - len(self.records)
        self.dirty |= before != len(self.records)

    def observe(self, addr, layer, sequence, ts, *, row, context, packet, coverage,
                accepted=True, retry=False):
        """Only accepted chronological changes. Context is evaluated on change.

        Existing keyfacts can establish a bounded baseline, never a switch.
        The previous local transition always refers to the same source layer.
        """
        if not accepted or retry or not _int(sequence) or not _time(ts):
            return
        key = (addr, layer)
        previous = self.latest.get(key)
        if previous is None:
            if len(self.latest) >= MAX_DEVICES * 2:
                return
            point = facts(row)[layer]["latest"]
            if point and point["ts"] < ts:
                self._transition(addr, layer, point["sequence"], point["ts"], None,
                                 {}, None, unknown_coverage("pre_journal_baseline"))
                previous = self.latest[key]
        if previous and ts <= previous["ts"]:
            return
        if previous and previous["sequence"] == sequence:
            previous["ts"] = ts
            return
        self._transition(addr, layer, sequence, ts, previous, context(), packet(),
                         coverage(previous["ts"] if previous else None, ts))

    def _transition(self, addr, layer, sequence, ts, previous, context, packet, coverage):
        record = {"id": _id("transition", addr, layer, sequence, ts), "kind": "transition",
                  "addr": addr, "layer": layer, "ts": ts, "new_sequence": sequence,
                  "old_sequence": previous["sequence"] if previous else None,
                  "observation_kind": "transition" if previous else "baseline",
                  "previous_record": previous["record"] if previous else None,
                  "last_old_observation_ts": previous["ts"] if previous else None,
                  "context": context, "packet": packet, "coverage": coverage,
                  "transport": "802.15.4" if packet else "unknown", "update_class": "unknown",
                  "candidate_update_path": "unknown", "source_peer": None,
                  "link_reestablishment": "unknown", "guard": guard()}
        exchanges = context.get("preceding_exchanges", [])
        candidates = [e for e in exchanges if e.get("receiver") == addr
                      and e.get("key_sequence") == sequence and 0 <= ts - e["ts"] <= 2
                      and e.get("command") == "Child ID Request"]
        if candidates:
            preceding = candidates[-1]
            record.update(source_peer=preceding["sender"], update_class="authoritative",
                          candidate_update_path="child_id_request_before_first_use",
                          update_class_confidence="candidate_only",
                          update_path_evidence=preceding,
                          update_path_assumptions=["request_processed_in_valid_attachment_state",
                                                   "no_unobserved_competing_update"])
        record["link_messages"] = [e for e in exchanges if str(e.get("command", "")).startswith("Link ")]
        self.add(record)
        self.latest[(addr, layer)] = {"sequence": sequence, "ts": ts, "record": record["id"]}

    def event(self, record, *, source="event_log"):
        if record.get("event") not in EVENTS or not _time(record.get("ts")):
            return
        # Census population lists can be large; per-device milestones and
        # transitions retain the useful evidence without copying every census.
        fields = ("event", "id", "addr", "name", "sequence", "previous", "first_sender", "role",
                  "rloc16", "frame", "since_previous_s", "observed_interval_s", "sequence_delta",
                  "previous_first_ts", "coverage", "observation_kind", "suspects", "command",
                  "parent", "parent_addr", "generation", "parent_generation", "step_s",
                  "key_observation", "label", "path", "reason", "current", "previous_rloc16")
        fields += ("earlier_higher_sequence", "lag", "since", "lagged_for_s", "mesh_generation", "note")
        evidence = {k: record[k] for k in fields if k in record}
        self.add({"id": "event:" + (record.get("id") or _id(evidence, record["ts"])), "kind": "event",
                  "ts": record["ts"], "addr": record.get("addr"), "evidence": evidence,
                  "event_reference": {"id": record.get("id"), "source": source,
                                      "file": record.get("_journal_file")}})
        if record.get("event") == "clock_step" and _time(record.get("step_s")) and record["step_s"] < 0:
            # Existing records retain original clocks. Start a new bounded
            # baseline rather than inventing an interval across a rewind.
            self.latest.clear()

    def otbr(self, report):
        records = report.get("records", [])
        if not isinstance(records, list) or any(
                not isinstance(r, dict) or not isinstance(r.get("id"), str) or not _time(r.get("ts"))
                or not all(k in r for k in ("kind", "file", "line", "raw")) for r in records):
            raise ValueError("invalid OTBR evidence records")
        by_id = {r["id"]: r for r in records}
        for r in by_id.values():
            if r.get("kind") == "service_started":
                self.reboot({"ts": r["ts"], "addr": "otbr:log", "source": "service_log", "scope": "process",
                             "reference": f"{r['file']}:{r['line']}", "log": r,
                             "device_reboot": "unknown", "identity": "monitored_addon_not_physical_device"})
                continue
            if r.get("kind") != "key_sequence_change":
                continue
            nearby = [by_id[i] for i in r.get("nearby_evidence", []) if i in by_id]
            self.add({"id": "otbr:" + _id(r["ts"], r["raw"]), "kind": "otbr", "ts": r["ts"], "addr": "otbr:log",
                      "evidence": {"change": r, "nearby": nearby, "old_sequence": None,
                                   "new_sequence": None, "source_peer": None, "transport": "unknown",
                                   "candidate_update_path": "trel_receive_near_change" if nearby else "unknown",
                                   "update_class": "unknown", "link_reestablishment": "unknown",
                                   "guard": guard(), "extraction_limited": report.get("limited", False)}})

    def apply_archive_scan(self, scan):
        for report in scan["reports"]:
            self.otbr(report)
        self.archive_scan = {k: scan[k] for k in ("files", "pending_files")}
        self.dirty = True

    def topology(self, addr, previous, current, ts):
        self.add({"id": _id("rloc", addr, previous, current, ts), "kind": "topology", "ts": ts,
                  "addr": addr, "evidence": {"previous_rloc16": previous, "rloc16": current,
                                            "interpretation": "parent_mapping_inferred_from_rloc; "
                                                              "attachment_completion_unknown"}})

    def reboot(self, evidence):
        """Explicit evidence supplied by an operator, never inferred from a
        Parent Request. Scope must say device, process, or OT instance.
        Reporting imports do not modify the recorder's journal.
        """
        if (not isinstance(evidence, dict) or not _time(evidence.get("ts"))
                or not isinstance(evidence.get("addr"), str)
                or evidence.get("source") not in ("operator_action", "service_log", "uptime_reset")
                or evidence.get("scope") not in ("device", "process", "openthread_instance")
                or not isinstance(evidence.get("reference"), str) or not evidence["reference"]):
            raise ValueError("reboot evidence needs ts, addr, source (operator_action/service_log/uptime_reset), "
                             "scope (device/process/openthread_instance), and a nonempty reference")
        self.add({"id": "reboot:" + _id(evidence), "kind": "reboot", "ts": evidence["ts"],
                  "addr": evidence["addr"], "evidence": evidence})

    def inventory(self, sample):
        """Retain changes and uptime resets, not every periodic table sample."""
        source = sample.get("source", {})
        if not isinstance(source, dict) or not _time(sample.get("completed_at")):
            return
        key = _id(source)
        if key not in self.inventory_latest and len(self.inventory_latest) >= 16:
            return
        commands = sample.get("commands", {})
        point = {"ts": sample["completed_at"], "source": source}
        for field, name in (("sequence", "keysequence counter"), ("guard_hours", "keysequence guardtime")):
            c = commands.get(name, {})
            point[field] = c.get("value") if c.get("status") == "ok" and _int(c.get("value")) else None
            point[field + "_observed_at"] = c.get("observed_at")
        uptime = commands.get("uptime", {})
        match = re.search(r"^\s*(?:(\d+)d\.)?(\d+):(\d{2}):(\d{2}(?:\.\d+)?)\s*$",
                          uptime.get("output", ""), re.M) if uptime.get("status") == "ok" else None
        point["uptime_s"] = (int(match[1] or 0) * 86400 + int(match[2]) * 3600
                             + int(match[3]) * 60 + float(match[4])) if match else None
        point["uptime_observed_at"] = uptime.get("observed_at")
        before = self.inventory_latest.get(key)
        if before and point["ts"] <= before["ts"]:
            return
        reset = False
        if before and all(_time(p.get(k)) for p in (before, point)
                          for k in ("uptime_s", "uptime_observed_at")):
            elapsed = point["uptime_observed_at"] - before["uptime_observed_at"]
            # A decrease establishes a reset. An apparent shortfall against
            # wall-clock elapsed time could instead be a clock step or SSH
            # latency; do not promote that to confirmed reset evidence.
            reset = elapsed >= 0 and point["uptime_s"] < before["uptime_s"] - 1
            if reset:
                self.reboot({"ts": point["ts"], "addr": "otbr:" + key, "source": "uptime_reset",
                             "scope": "openthread_instance", "reference": "otbr-inventory.json:uptime",
                             "before": before, "after": point,
                             "reset_time": "bounded_between_samples", "device_reboot": "unknown"})
        changed = not before or any(point[k] != before[k] for k in ("sequence", "guard_hours"))
        if changed and point["sequence"] is not None:
            assessment = guard()
            if reset:
                assessment = {"assessment": "consistent_with_clear_guard",
                              "assumptions": ["uptime_reset_reinitialized_guard", "no_intervening_guard_activation"],
                              "reason": "instance_uptime_reset_between_samples"}
            elif before and point["guard_hours"] is not None and point["guard_hours"] == before["guard_hours"]:
                prior = next((r for r in reversed(self.records) if r["kind"] == "inventory"
                              and r.get("addr") == "otbr:" + key), None)
                if prior:
                    e = prior["evidence"]
                    old, new = e.get("old_sequence"), e.get("new_sequence")
                    if (_int(old) and _int(new) and new - old == 1
                            and 0 <= point["ts"] - prior["ts"] < point["guard_hours"] * 3600):
                        assessment = {"assessment": "consistent_with_active_guard",
                                      "assumptions": ["previous_plus_one_update_armed_guard",
                                                      "guard_duration_unchanged_between_samples",
                                                      "no_unobserved_reset_or_guard_clear"],
                                      "reason": "prior_observed_plus_one_within_configured_guard_duration"}
            self.add({"id": "inventory:" + _id(key, point["ts"]), "kind": "inventory", "ts": point["ts"],
                      "addr": "otbr:" + key, "evidence": {"before": before, "after": point,
                        "old_sequence": before["sequence"] if before else None, "new_sequence": point["sequence"],
                        "source_peer": None, "transport": "unknown", "update_class": "unknown",
                        "candidate_update_path": "unknown", "link_reestablishment": "unknown", "guard": assessment}})
        self.inventory_latest[key] = point
        self.dirty = True

    def state(self):
        return {"version": 1, "records": self.records, "dropped": self.dropped,
                "inventory_latest": self.inventory_latest, "archive_scan": self.archive_scan}

    def save(self, now=None, *, force=False):
        now = time.time() if now is None else now
        if self.path is None or (not force and now - self.saved_at < 60):
            return
        self.prune(now)
        if not self.dirty:
            return
        try:
            encoded = json.dumps(self.state(), separators=(",", ":"))
            while len(encoded.encode()) > MAX_BYTES and self.records:
                self.records.pop(0)
                self.dropped += 1
                encoded = json.dumps(self.state(), separators=(",", ":"))
            self.prune(now)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.state(), separators=(",", ":")))
            tmp.replace(self.path)
            self.dirty = False
        except OSError as exc:
            print(f"[threadwatch] key journal save failed: {exc}", file=sys.stderr, flush=True)
        self.saved_at = now

    def report(self):
        records = copy.deepcopy(sorted(self.records, key=lambda r: r["ts"]))
        by_id = {r["id"]: r for r in records}
        transitions = [r for r in records if r["kind"] == "transition"]
        advances = []
        sequences = set()
        for r in records:
            if r["kind"] == "event" and r["evidence"].get("event") == "key_sequence_advanced":
                sequence = r["evidence"].get("sequence")
                if sequence not in sequences:
                    advances.append(r)
                    sequences.add(sequence)
        counts = Counter()
        incidents = []
        for r in transitions:
            previous = by_id.get(r.get("previous_record"))
            known = (previous and previous.get("observation_kind") == "transition"
                     and previous.get("addr") == r["addr"] and previous.get("layer") == r["layer"]
                     and previous.get("new_sequence") == r["old_sequence"] and previous["ts"] < r["ts"])
            r["previous_local_transition"] = ({k: previous[k] for k in
                                               ("id", "new_sequence", "ts", "layer", "coverage")}
                                              if known else None)
            r["local_observed_interval_s"] = r["ts"] - previous["ts"] if known else None
            r["switch_time"] = "unknown"
            r["history"] = "observed_transition" if known else "earlier_switch_unknown"
        for index, event in enumerate(advances):
            e, ts = event["evidence"], event["ts"]
            seq, addr = e.get("sequence"), e.get("first_sender")
            end = advances[index + 1]["ts"] if index + 1 < len(advances) else math.inf
            matches = [r for r in transitions if r["addr"] == addr and r["new_sequence"] == seq
                       and r["ts"] == ts]
            # Match the layer used by the network event, not the greatest
            # sequence found on some other layer of the same packet.
            layer = "mle" if str(e.get("frame", "")).startswith("mle:") else "mac"
            origin = next((r for r in matches if r["layer"] == layer), None)
            identity = (origin or {}).get("context", {}).get("physical_identity")
            key = identity.get("id") if isinstance(identity, dict) and isinstance(identity.get("id"), str) else addr
            baseline = e.get("previous") is None
            if not baseline:
                counts[key] += 1
            adoptions = {}
            for r in transitions:
                if ts <= r["ts"] < end and r["new_sequence"] == seq and r["context"].get("role") == "router":
                    adoption = adoptions.setdefault(r["addr"], {
                        "addr": r["addr"], "first_observed_at": r["ts"], "old_sequence": r["old_sequence"],
                        "new_sequence": seq, "transport": r["transport"], "update_class": r["update_class"],
                        "source_peer": r["source_peer"], "candidate_update_path": r["candidate_update_path"],
                        "link_reestablishment": r["link_reestablishment"], "packet": r["packet"],
                        "observations": []})
                    adoption["observations"].append(r["id"])
            milestones = [r for r in records if ts <= r["ts"] < end and r["kind"] in ("event", "reboot", "topology")
                          and r["id"] != event["id"]]
            preceding = advances[index - 1] if index else None
            network_interval = e.get("observed_interval_s", e.get("since_previous_s"))
            interval_source = "event"
            if preceding and preceding["evidence"].get("sequence") == e.get("previous"):
                network_interval = ts - preceding["ts"] if ts >= preceding["ts"] else None
                interval_source = "retained_first_observations"
            incidents.append({"event": event, "origin_observation": origin,
                              "network_observed_interval_s": network_interval,
                              "network_interval_source": interval_source,
                              "local_observed_interval_s": origin.get("local_observed_interval_s") if origin else None,
                              "repeat_origin_count": counts[key], "origin_proven": False,
                              "other_candidates": e.get("suspects", []),
                              "earlier_higher_sequence": {
                                  "transition_refs": [r["id"] for r in transitions
                                                      if r["ts"] < ts and _int(seq) and r["new_sequence"] >= seq],
                                  "keyfacts": e.get("earlier_higher_sequence", []),
                                  "coverage": "bounded_retained_history"},
                              "adopting_routers": list(adoptions.values()),
                              "otbr_changes": [r for r in records if r["kind"] in ("otbr", "inventory")
                                               and ts <= r["ts"] < end],
                              "milestones": milestones,
                              "preceding_origin_evidence": [r for r in records if r.get("addr") == addr
                                                            and ts - 7 * 86400 <= r["ts"] <= ts
                                                            and r["kind"] in ("event", "reboot")],
                              "guard": guard()})
        devices = {}
        for r in records:
            addr = r.get("addr")
            if not addr:
                continue
            device = devices.setdefault(addr, {"addr": addr, "transitions": [], "reboots": [],
                                                "reattachment_attempts": [], "outcomes": []})
            if r["kind"] == "transition":
                device["transitions"].append(r["id"])
            elif r["kind"] == "reboot":
                device["reboots"].append(r["id"])
            elif r["kind"] == "topology":
                device["outcomes"].append({"kind": "rloc_changed", "ts": r["ts"], "evidence": r["id"]})
            elif r["kind"] == "event":
                event = r["evidence"].get("event")
                if event == "mle_rejoin_attempt":
                    device["reattachment_attempts"].append(r["id"])
                if event in ("key_lag", "key_lag_cleared", "ha_unavailable", "ha_available"):
                    device["outcomes"].append({"kind": event, "ts": r["ts"], "evidence": r["id"]})
        return {"version": 1, "retention": {"days": 90, "max_records": MAX_RECORDS, "max_bytes": MAX_BYTES,
                                            "dropped": self.dropped, "load_status": self.load_status},
                "incidents": incidents, "devices": list(devices.values()), "records": records,
                "archive_scan": copy.deepcopy(self.archive_scan),
                "interpretation": "First observed use is not switch time or proof of origin. Parent Requests "
                                  "are attempts, not reboot or completed attachment. Missing radio traffic "
                                  "does not establish TREL. Ordering across radios/hosts may be uncertain."}


def text_report(report):
    lines = []
    for incident in report["incidents"]:
        e = incident["event"]["evidence"]
        def hours(value):
            return "unknown" if value is None else f"{value / 3600:.3f} h"
        lines.append(f"{e.get('previous')} -> {e.get('sequence')}: {e.get('name') or e.get('first_sender')}; "
                     f"network interval {hours(incident['network_observed_interval_s'])}; "
                     f"sender local interval {hours(incident['local_observed_interval_s'])}; "
                     f"origin candidate seen {incident['repeat_origin_count']} time(s)")
        for adoption in incident["adopting_routers"]:
            lines.append(f"  router {adoption['addr']}: first use {adoption['first_observed_at']}; "
                         f"evidence {', '.join(adoption['observations'])}")
        origin = incident.get("origin_observation")
        if origin:
            parent = origin["context"].get("parent", {})
            if parent.get("addr"):
                lines.append(f"  parent {parent['addr']} last sequence {parent.get('sequence')}, "
                             f"age {parent.get('age_s')} s; child-parent delta "
                             f"{parent.get('child_minus_parent_before')} before / "
                             f"{parent.get('child_minus_parent')} after")
        for change in incident["otbr_changes"]:
            r = change["evidence"].get("change")
            if r is None:
                e = change["evidence"]
                lines.append(f"  OTBR sampled {e['old_sequence']} -> {e['new_sequence']}; "
                             f"guard {e['guard']['assessment']}; transport unknown")
                continue
            lines.append(f"  OTBR change {r['utc']} UTC; sequence unknown; {r['file']}:{r['line']}; "
                         f"path {change['evidence']['candidate_update_path']} (proximity only)")
        for evidence in incident["preceding_origin_evidence"]:
            e = evidence["evidence"]
            if evidence["kind"] == "reboot":
                lines.append(f"  preceding reset: {e['source']} ({e['scope']}), {e['reference']}")
            elif e.get("event") == "mle_rejoin_attempt":
                lines.append(f"  preceding reattachment attempt: {e.get('command')}; completion unknown")
    for device in report.get("devices", []):
        if device["outcomes"]:
            lines.append(f"{device['addr']} outcomes: " + ", ".join(
                f"{r['kind']} at {r['ts']} ({r['evidence']})" for r in device["outcomes"]))
    lines.append(report["interpretation"])
    lines.append(f"History: {report['retention']}")
    return "\n".join(lines)


def read_report(cfg, *, replay_paths=(), event_dirs=(), evidence_paths=(), otbr_paths=(), logs=False):
    """Build a report without persisting imports, dispatching alerts, or polling
    HA. Explicit replay is the only operation that decodes packet files.
    """
    from .events import iter_days
    from .otbr import extract, load_inventory

    journal = Journal(None if replay_paths else cfg.state_dir / STATE)
    roots = [cfg.snapshot_dir or cfg.data_dir]
    if replay_paths:
        from .record import replay_files, run_replay
        files = replay_files(list(replay_paths))
        # Saved rings overlap. For a repeated radio/hour use the most
        # complete copy, never feed the same recording twice.
        unique = {}
        for path in files:
            old = unique.get(path.name)
            if old is None or path.stat().st_size > old.stat().st_size:
                unique[path.name] = path
        run_replay(cfg, sorted(unique.values(), key=lambda p: p.name), journal=journal, output=False)
        roots.extend(p for p in replay_paths if p.is_dir() and (p / "manifest.json").exists())
    imports = []
    dirs = dict.fromkeys([cfg.events_dir, *event_dirs, *(r / "events" for r in roots)])
    for directory in dirs:
        for day, records in iter_days(directory):
            imports.extend({**r, "_journal_file": str(directory / f"{day}.jsonl")}
                           for r in records if r.get("event") in EVENTS and _time(r.get("ts")))
    # Keep recorded events verbatim beside replay observations. The report
    # selects the earliest retained observation of each network generation;
    # a restart baseline must not displace an earlier observed advance.
    for record in sorted(imports, key=lambda r: r["ts"]):
        journal.event(record)
    for path in evidence_paths:
        if path.stat().st_size > 1024 * 1024:
            raise ValueError("reboot evidence file exceeds 1 MiB")
        values = json.loads(path.read_text())
        if not isinstance(values, list):
            raise ValueError("reboot evidence must be a JSON list")
        for value in values:
            journal.reboot(value)
    for path in otbr_paths:
        if path.stat().st_size > MAX_BYTES:
            raise ValueError("OTBR evidence report exceeds 16 MiB")
        evidence = json.loads(path.read_text())
        if not isinstance(evidence, dict) or not isinstance(evidence.get("records"), list):
            raise ValueError("expected an otbr-evidence JSON report")
        journal.otbr(evidence)
    log_files = []
    bundles = []
    for root in dict.fromkeys(roots):
        snapshot = (root / "manifest.json").exists()
        inventory = load_inventory(root / ("otbr-inventory.json" if snapshot else "state/otbr-inventory.json"))
        for sample in inventory.get("samples", []):
            journal.inventory(sample)
        if snapshot:
            bundles.append({"path": str(root), "retained": root.exists(), "manifest": str(root / "manifest.json")})
        if logs:
            for event in list(journal.records):
                if event["kind"] != "event" or event["evidence"].get("event") != "key_sequence_advanced":
                    continue
                evidence = extract(root, event["ts"] - 60, event["ts"] + 600, changes_only=True)
                journal.otbr(evidence)
                log_files.extend(evidence["files"])
    known_bundles = {b["path"] for b in bundles}
    for manifest in sorted(cfg.snapshots_dir.glob("*/manifest.json")):
        if str(manifest.parent) not in known_bundles:
            bundles.append({"path": str(manifest.parent), "retained": True, "manifest": str(manifest)})
    for bundle in bundles:
        manifest = Path(bundle["manifest"])
        try:
            if manifest.stat().st_size <= 1024 * 1024:
                metadata = json.loads(manifest.read_text())
                bundle["key_observation"] = metadata.get("key_observation")
                bundle["span"] = metadata.get("span")
                bundle["saved_at"] = metadata.get("saved_at")
        except (OSError, ValueError, AttributeError):
            bundle["metadata_status"] = "unreadable"
    # Snapshot/replay reports retain the historical window, not today's
    # wall clock. Live reports enforce the same 90-day retention as capture.
    cutoff = max((r["ts"] for r in journal.records), default=0) if cfg.snapshot_dir or replay_paths else time.time()
    journal.prune(cutoff)
    report = journal.report()
    if replay_paths:
        report["reconstruction"] = {"files": [str(p) for p in unique.values()], "coverage": "unknown",
                                    "reason": "only_supplied_packets_decoded; gaps_and_missed_traffic_possible"}
    report["bundles"] = bundles
    report["log_files"] = log_files
    if logs:
        report["log_window"] = "60 seconds before through 600 seconds after each network observation"
    return report


def scan_archive(root: Path, previous: dict, *, limit=4):
    """Worker-only, bounded incremental scans of newly fetched/replaced hours.

    Newest hours go first. Backfill progresses on later archive passes and
    pending_files says how much remains. A truncated/limited file's status
    stays visible; an unchanged bad file cannot starve all older hours.
    """
    from .halogs import hour_start
    from .otbr import SLUG, extract

    files = sorted((root / "ha-logs" / SLUG).glob("????????-??.log.gz"), reverse=True)[:2160]
    state = {}
    reports = []
    pending = 0
    for path in files:
        try:
            stat = path.stat()
        except OSError:
            continue
        signature = [stat.st_size, stat.st_mtime_ns]
        old = previous.get(path.name, {})
        if old.get("signature") == signature:
            state[path.name] = old
            continue
        if len(reports) >= limit:
            pending += 1
            continue
        start = hour_start(path.name[:11])
        report = extract(root, start, start + 3600, changes_only=True)
        reports.append(report)
        state[path.name] = {"signature": signature, "limited": report["limited"],
                            "complete": report["complete"],
                            "read_status": report["files"][0]["read_status"],
                            "coverage": report["files"][0]["coverage"]}
    return {"reports": reports, "files": state, "pending_files": pending}
