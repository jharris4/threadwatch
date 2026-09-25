"""Read-only OTBR inventory and evidence from the existing UTC log archive.

Inventory is corroboration at its observation time, never live topology for
packet detection. Nearby log lines are linked evidence, not a causal verdict.
"""

from __future__ import annotations

import gzip
import json
import math
import os
import re
import select
import shlex
import subprocess
import threading
import time
import zlib
from collections import deque
from pathlib import Path

from .halogs import hours_between, journal_stamp

SLUG = "core_openthread_border_router"
STATE = "otbr-inventory.json"
COMMANDS = ("trel peers", "router table", "neighbor table", "keysequence counter",
            "keysequence guardtime", "uptime", "state")
OUTPUT_LIMIT = 32768
TIMEOUT_S = 10
HISTORY_BYTES = 8 * 1024 * 1024
HISTORY_COUNT = 2016
LOG_BYTES = 256 * 1024 * 1024
LINE_BYTES = 8192


def validate_target(target: str, port: int, container: str) -> None:
    pattern = r"(?:[A-Za-z0-9_][A-Za-z0-9_.-]*@)?[A-Za-z0-9][A-Za-z0-9_.-]*"
    if not isinstance(target, str) or not re.fullmatch(pattern, target):
        raise ValueError("[otbr] ssh_target must be a hostname or user@hostname, without SSH options")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("[otbr] ssh_port must be an integer from 1 to 65535")
    if not isinstance(container, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", container):
        raise ValueError("[otbr] container must be a Docker container name")


def validate_access(identity_file: str, sudo: bool) -> None:
    if not isinstance(identity_file, str) or any(c in identity_file for c in "\x00\r\n"):
        raise ValueError("[otbr] ssh_identity_file must be a path string without control characters")
    if not isinstance(sudo, bool):
        raise ValueError("[otbr] sudo must be true or false")


def command_argv(cfg, command: str) -> list[str]:
    if command not in COMMANDS:
        raise ValueError("OTBR command is not allowlisted")
    validate_target(cfg.otbr_ssh_target, cfg.otbr_ssh_port, cfg.otbr_container)
    validate_access(cfg.otbr_ssh_identity_file, cfg.otbr_sudo)
    remote = shlex.join([*(["sudo", "-n"] if cfg.otbr_sudo else []),
                         "docker", "exec", cfg.otbr_container, "ot-ctl", *command.split()])
    identity = (["-o", "IdentitiesOnly=yes", "-i", str(Path(cfg.otbr_ssh_identity_file).expanduser())]
                if cfg.otbr_ssh_identity_file else [])
    return ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=1",
            "-o", "ClearAllForwardings=yes", *identity, "-p", str(cfg.otbr_ssh_port), cfg.otbr_ssh_target, remote]


def run_command(argv: list[str]) -> dict:
    """Bound output in memory and execution time; never invoke a local shell."""
    started = time.monotonic()
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except FileNotFoundError as exc:
        # No ssh client on this host at all (a container image without
        # openssh-client): nothing about the border router was tried, so
        # not "unreachable", which reads as a host, port or key problem.
        return {"status": "no_ssh", "output": "", "error": f"no ssh client on this host: {exc}"}
    except OSError as exc:
        return {"status": "unreachable", "output": "", "error": str(exc)}
    status = None
    output = bytearray()
    try:
        while True:
            remaining = TIMEOUT_S - (time.monotonic() - started)
            if remaining <= 0:
                status = "timeout"
                break
            readable, _, _ = select.select([process.stdout], [], [], remaining)
            if not readable:
                status = "timeout"
                break
            chunk = os.read(process.stdout.fileno(), min(4096, OUTPUT_LIMIT + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > OUTPUT_LIMIT:
                status = "output_limit"
                break
    finally:
        process.stdout.close()
        if process.poll() is None:
            # EOF can precede exit very slightly. Allow normal exit within
            # the original deadline before killing a stuck SSH process.
            try:
                process.wait(timeout=max(0, TIMEOUT_S - (time.monotonic() - started)) if status is None else 0)
            except subprocess.TimeoutExpired:
                status = status or "timeout"
                process.kill()
        process.wait()
    size = len(output)
    text = output[:OUTPUT_LIMIT].decode("utf-8", "replace")
    if status is None:
        if process.returncode == 255:
            status = "unreachable"
        elif re.search(r"InvalidCommand|not found|not implemented", text, re.I):
            status = "unsupported"
        elif process.returncode or re.search(r"^Error\b", text, re.M):
            status = "error"
        else:
            status = "ok" if re.search(r"^Done\s*$", text, re.M) else "incomplete"
    return {"status": status, "output": text, "returncode": process.returncode,
            "truncated": size > OUTPUT_LIMIT}


def table_rows(text: str) -> list[dict]:
    """Keep named columns across CLI versions; unknown layouts stay raw."""
    header = None
    rows = []
    for line in text.splitlines():
        if "|" not in line:
            continue
        cells = [part.strip() for part in line.strip().strip("|").split("|")]
        if all(re.fullmatch(r"[-+: ]*", part) for part in cells):
            continue
        if header is None:
            header = [re.sub(r"[^a-z0-9]", "", part.lower()) for part in cells]
        elif len(cells) == len(header):
            rows.append(dict(zip(header, cells, strict=True)))
    return rows


def _ext(row: dict) -> str | None:
    for key in ("extaddr", "extmacaddress", "extendedmac", "extendedaddress", "extaddress"):
        value = row.get(key, "").lower().replace(":", "").removeprefix("0x")
        if re.fullmatch(r"[0-9a-f]{16}", value):
            return value
    return None


def _rloc(row: dict) -> str | None:
    value = row.get("rloc16", "").lower().removeprefix("0x")
    return value if re.fullmatch(r"[0-9a-f]{4}", value) else None


def collect(cfg, runner=run_command, clock=time.time) -> dict:
    sample = {"started_at": clock(), "source": {"ssh_target": cfg.otbr_ssh_target,
              "ssh_port": cfg.otbr_ssh_port, "container": cfg.otbr_container}, "commands": {}}
    disconnected = False
    for command in COMMANDS:
        started = clock()
        if disconnected:
            result = {"status": "skipped", "error": "SSH unavailable earlier in this sample", "output": ""}
        else:
            result = runner(command_argv(cfg, command))
        result = {**result, "observed_at": started, "completed_at": clock()}
        if command.endswith(("table", "peers")):
            result["rows"] = table_rows(result.get("output", "")) if result["status"] == "ok" else []
        if result["status"] == "ok" and command.startswith("keysequence "):
            values = re.findall(r"^\s*(\d+)\s*$", result.get("output", ""), re.M)
            result["value"] = int(values[0]) if len(values) == 1 else None
        sample["commands"][command] = result
        disconnected |= result["status"] in ("unreachable", "timeout", "no_ssh")
    statuses = [r["status"] for r in sample["commands"].values()]
    sample["status"] = "ok" if all(s == "ok" for s in statuses) else "partial" if "ok" in statuses else "failed"
    sample["completed_at"] = clock()
    return sample


def load_inventory(path: Path) -> dict:
    try:
        if path.stat().st_size > HISTORY_BYTES:
            return {}
        value = json.loads(path.read_text())
        if not isinstance(value, dict) or not isinstance(value.get("samples"), list):
            return {}
        number = lambda n: isinstance(n, (float, int)) and not isinstance(n, bool) and math.isfinite(n)
        value["samples"] = [s for s in value["samples"] if isinstance(s, dict)
                            and number(s.get("completed_at")) and isinstance(s.get("commands"), dict)][-HISTORY_COUNT:]
        # Each command's result is read as the poll wrote it (an object,
        # its output a string, its table rows objects) by the periodic
        # loop and the journal; a retained sample of another shape raised
        # there on every pass, so what does not fit is dropped here.
        for sample in value["samples"]:
            sample["commands"] = {k: r for k, r in sample["commands"].items() if isinstance(r, dict)}
            for result in sample["commands"].values():
                if not isinstance(result.get("output", ""), str):
                    result["output"] = ""
                if "rows" in result:
                    rows = result["rows"]
                    result["rows"] = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
        if not number(value.get("next_poll_at")):
            value["next_poll_at"] = 0
        if not isinstance(value.get("failures"), int) or not 0 <= value["failures"] <= 4:
            value["failures"] = 0
        return value
    except (OSError, ValueError):
        return {}


def save_inventory(path: Path, history: dict, sample: dict, poll_s: float) -> dict:
    failures = min(4, int(history.get("failures", 0)) + 1) if sample["status"] == "failed" else 0
    end = sample["completed_at"]
    samples = [s for s in history.get("samples", []) if isinstance(s, dict)
               and isinstance(s.get("completed_at"), (float, int)) and end - 7 * 86400 <= s["completed_at"] <= end]
    samples = (samples + [sample])[-HISTORY_COUNT:]
    state = {"samples": samples, "failures": failures,
             "next_poll_at": end + min(3600, poll_s * 2 ** failures)}
    encoded = json.dumps(state)
    while len(encoded.encode()) > HISTORY_BYTES and len(samples) > 1:
        del samples[0]
        encoded = json.dumps(state)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(encoded)
    tmp.replace(path)
    return state


class InventoryPoller:
    """One worker; all remote I/O and persistence stay off capture."""

    def __init__(self, cfg):
        self.cfg = cfg
        self.history = load_inventory(cfg.state_dir / STATE)
        self.next_poll = self.history.get("next_poll_at", 0)
        self.thread = None
        self.status = self._summary(self.history["samples"][-1]) if self.history.get("samples") else None

    @staticmethod
    def _summary(sample: dict) -> dict:
        return {"status": sample.get("status"), "started_at": sample.get("started_at"),
                "completed_at": sample.get("completed_at"),
                "commands": {k: r.get("status") for k, r in sample["commands"].items() if isinstance(r, dict)}}

    def tick(self, now: float) -> None:
        if self.thread is not None:
            if self.thread.is_alive():
                return
            self.thread.join()
            self.thread = None
        # A bad/future saved clock must not suppress this optional collector forever.
        if now < self.next_poll <= now + 3600:
            return
        self.next_poll = now + self.cfg.otbr_poll_s

        def run():
            before = self.status
            try:
                sample = collect(self.cfg)
                self.history = save_inventory(self.cfg.state_dir / STATE, self.history, sample, self.cfg.otbr_poll_s)
                self.next_poll = self.history["next_poll_at"]
                self.status = self._summary(sample)
            except Exception as exc:
                self.next_poll = time.time() + min(3600, self.cfg.otbr_poll_s * 2)
                self.status = {"status": "failed", "error": f"{type(exc).__name__}: {exc}"}
            self._announce(before, self.status)

        self.thread = threading.Thread(target=run, name="otbr-inventory", daemon=True)
        self.thread.start()

    def _announce(self, before: dict | None, after: dict) -> None:
        """One journal line when the outcome changes, none while it holds:
        a failing inventory is otherwise visible only in status.json."""
        was, now = (before or {}).get("status"), after.get("status")
        if was == now:
            return
        if now == "ok":
            text = f"ok, all {len(after.get('commands', {}))} commands answered"
        elif "error" in after:
            text = f"failed: {after['error']}"
        else:
            bad = ", ".join(f"{k} {v}" for k, v in after.get("commands", {}).items() if v != "ok")
            text = f"{now}: {bad}"
        wait = self.next_poll - time.time()
        print(f"[threadwatch] otbr inventory {self.cfg.otbr_ssh_target}: {text}"
              + (f" (was {was})" if was else "") + (f"; next poll in {wait / 60:.0f} min" if wait > 0 else ""),
              flush=True)


def peer_at(rloc: str | None, ts: float, samples: list[dict]) -> dict | None:
    """Only preceding, fresh table observations may associate an identity.

    Even these are observations at separate times, not an incident-time proof.
    A later table never gets projected back into a historical adoption.
    """
    if rloc is None:
        return None
    for sample in sorted(samples, key=lambda s: s.get("completed_at", 0), reverse=True):
        end = sample.get("completed_at", 0)
        if not 0 <= ts - end <= 900:
            continue
        commands = sample.get("commands", {})
        trel = commands.get("trel peers", {})
        if (trel.get("status") != "ok" or not isinstance(trel.get("observed_at"), (float, int))
                or not 0 <= ts - trel["observed_at"] <= 900):
            continue
        peers = {_ext(r): r for r in trel.get("rows", []) if _ext(r)}
        for name in ("neighbor table", "router table"):
            table = commands.get(name, {})
            if (table.get("status") != "ok" or not isinstance(table.get("observed_at"), (float, int))
                    or not 0 <= ts - table["observed_at"] <= 900):
                continue
            for row in table.get("rows", []):
                ext = _ext(row)
                if _rloc(row) == rloc and ext in peers:
                    return {"extended_address": ext, "rloc16": rloc, "name": None,
                            "table_observed_at": table.get("observed_at"),
                            "trel_observed_at": trel.get("observed_at"), "source": sample.get("source"),
                            "trel_peer": peers[ext],
                            "confidence": "preceding_table_observation", "prior_adoption_path": "unknown"}
        # A more recent table without a match must not revive an old RLOC assignment.
        return None
    return None


def _kind(line: str) -> str | None:
    if "service otbr-agent successfully started" in line:
        return "service_started"
    if "KeySeqCntr" in line:
        return "key_sequence_change"
    lower = line.lower()
    if "meshforwarder" in lower and "received" in lower and "radio:trel" in lower:
        return "trel_receive"
    if "security" in lower and re.search(r"rx failed|receive.*fail|failed.*receiv", lower):
        return "security_receive_failure"
    if re.search(r"receiv(?:e|ed).*parent request", lower):
        return "parent_request"
    if re.search(r"receiv(?:e|ed).*child id request", lower):
        return "child_id_request"
    return None


def extract(root: Path, since: float, until: float, *, inventory: dict | None = None, limit: int = 1000,
            changes_only: bool = False) -> dict:
    """Bounded, offline extraction from a data directory or a saved snapshot."""
    if not 0 < until - since <= 7 * 86400 or not 1 <= limit <= 10000:
        raise ValueError("request a positive window of at most seven days and a limit from 1 to 10000")
    snapshot = (root / "manifest.json").exists()
    metadata_path = root / "ha-logs.json" if snapshot else root / "state/ha-logs-archive.json"
    try:
        metadata = json.loads(metadata_path.read_text())
    except (OSError, ValueError):
        metadata = {}
    if not isinstance(metadata, dict) or not isinstance(metadata.get("addons", {}), dict):
        metadata = {}
    entry = metadata.get("addons", {}).get(SLUG, {})
    if not isinstance(entry, dict):
        entry = {}
    inventory = inventory if inventory is not None else load_inventory(root / (STATE if snapshot else f"state/{STATE}"))
    samples = [s for s in inventory.get("samples", []) if isinstance(s, dict)]
    report = {"since": since, "until": until, "records": [], "files": [], "limited": False,
              "interpretation": "Temporal proximity is evidence, not proof of an adoption path; "
                                "prior peer adoption unknown."}
    records = report["records"]
    recent_trel = deque(maxlen=32)
    budget = LOG_BYTES
    for hour in hours_between(since, until):
        path = root / "ha-logs" / SLUG / f"{hour}.log.gz"
        meta = entry.get("hours", {}).get(hour, {}) if snapshot else {}
        meta = meta if isinstance(meta, dict) else {}
        # The live archive state names the newest completed hour and the
        # pending/lost ones; every other hour up to it was fetched complete.
        last = entry.get("last_archived")
        archived = not snapshot and isinstance(last, str) and hour <= last
        coverage = ("lost" if hour in entry.get("lost", {}) or meta.get("source") == "lost" else
                    "partial" if hour in entry.get("pending", {}) or meta.get("complete") is False else
                    "fetch_complete" if meta.get("complete") is True or archived else "unknown")
        file = {"file": str(path), "hour_utc": hour, "coverage": coverage,
                "metadata_file": str(metadata_path),
                "metadata": meta if snapshot else {
                    "pending": entry.get("pending", {}).get(hour), "lost": entry.get("lost", {}).get(hour)},
                "read_status": "read", "first_ts": None, "last_ts": None}
        report["files"].append(file)
        before = deque(maxlen=2)
        pending = []
        try:
            with gzip.open(path, "rt", errors="replace") as stream:
                n = 0
                while True:
                    line = stream.readline(LINE_BYTES + 1)
                    if not line:
                        break
                    n += 1
                    budget -= len(line.encode())
                    if budget < 0 or len(line) > LINE_BYTES:
                        file["read_status"] = "limit"
                        report["limited"] = True
                        break
                    raw = line.rstrip("\n")
                    stamp = journal_stamp(line)
                    if stamp is not None:
                        file["first_ts"] = stamp if file["first_ts"] is None else file["first_ts"]
                        file["last_ts"] = stamp
                    context = {"line": n, "raw": raw}
                    pending = [r for r in pending if n - r["line"] <= 2]
                    for record in pending:
                        record["context"].append(context)
                    kind = _kind(line)
                    if kind and stamp is not None and since <= stamp < until:
                        if len(records) >= limit and (not changes_only or kind in (
                                "key_sequence_change", "service_started")):
                            report["limited"] = True
                            file["read_status"] = "limit"
                            break
                        # from:0xec00 / src:0xec00 (MeshForwarder, Mac), or the MLE
                        # form "Receive Parent Request (fe80:...)".
                        peer = re.search(r"\b(?:from|src)[:= ]+(0x[0-9a-fA-F]+|[0-9a-fA-F:]+)"
                                         r"|\(([0-9a-fA-F:]+)\)", line)
                        peer = (peer.group(1) or peer.group(2)).lower() if peer else None
                        rloc = peer.removeprefix("0x") if peer else None
                        rloc = rloc if rloc and re.fullmatch(r"[0-9a-f]{4}", rloc) else None
                        record = {"id": f"{hour}:{n}", "kind": kind, "ts": stamp, "utc": line[:23],
                                  "file": str(path), "line": n, "raw": raw, "context": [*before, context],
                                  "peer": peer, "rloc16": rloc,
                                  "transport": "trel" if kind == "trel_receive" else "unknown",
                                  "update_class": "unknown", "nearby_evidence": [],
                                  "peer_observation": peer_at(rloc, stamp, samples)}
                        if kind == "key_sequence_change":
                            record["nearby_evidence"] = [r["id"] for r in recent_trel if 0 <= stamp - r["ts"] <= 1]
                            record["confidence"] = ("temporal_proximity_only" if record["nearby_evidence"]
                                                    else "observation_only")
                        if kind == "trel_receive":
                            recent_trel.append(record)
                        if changes_only and kind == "key_sequence_change":
                            existing = {r["id"] for r in records}
                            links = [r for r in recent_trel if r["id"] in record["nearby_evidence"]
                                     and r["id"] not in existing]
                            if len(records) + len(links) + 1 > limit:
                                report["limited"] = True
                                file["read_status"] = "limit"
                                break
                            records.extend(links)
                        if not changes_only or kind in ("key_sequence_change", "service_started"):
                            records.append(record)
                        pending.append(record)
                    before.append(context)
        except FileNotFoundError:
            file["read_status"] = "missing"
        except (OSError, EOFError, zlib.error) as exc:
            file["read_status"] = "truncated_or_unreadable"
            file["error"] = str(exc)
        if report["limited"]:
            break
    by_file = {f["file"]: f for f in report["files"]}
    for record in records:
        file = by_file[record["file"]]
        record["log_coverage"] = {"coverage": file["coverage"], "read_status": file["read_status"]}
    report["complete"] = not report["limited"] and all(
        f["read_status"] == "read" and f["coverage"] == "fetch_complete" for f in report["files"])
    return report
