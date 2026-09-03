"""The shared frame-analysis pipeline used by live capture and replay.

General-purpose Thread health tracking, one frame at a time:

Key-free (always on):
  - per-device stats: frame counts, RSSI trend, poll cadence, ACK success
  - device went-quiet / returned / silent-without-rejoin events
  - foreign-PAN frames, beacon (join-scan) bursts
  - traffic floods and phase-locked periodicity (storm signature)
  - MAC retransmission-rate elevation

With Thread credentials (optional):
  - short-address identity: sleepy end devices (which never use their
    extended address once attached) get their polls, RSSI and quiet /
    returned events attributed to them
  - MLE visibility: rejoin attempts (Parent/Child ID Request), partition and
    leader changes, per-device RLOC learning
  - SRP/DNS-SD name harvesting for auto-naming hints
"""

from __future__ import annotations

import json
import struct
import time
from collections import deque
from pathlib import Path
from typing import Optional

from .detect import Detector
from .events import EventLog
from .names import DeviceNames, LastSeen, reception
from .pcap import Frame

MLE_REJOIN_COMMANDS = {"Parent Request", "Child ID Request", "Announce"}


class DeviceStats:
    """Rolling per-device health from cleartext headers only."""

    __slots__ = ("rssi_ewma", "rssi_min", "rssi_max", "polls", "last_poll_ts",
                 "poll_intervals", "tx", "acked", "ack_pending_seq",
                 "ack_pending_ts", "beacons")

    def __init__(self):
        self.rssi_ewma = None
        self.rssi_min = None
        self.rssi_max = None
        self.polls = 0
        self.last_poll_ts = None
        self.poll_intervals = deque(maxlen=32)
        self.tx = 0
        self.acked = 0
        self.ack_pending_seq = None
        self.ack_pending_ts = 0.0
        self.beacons = 0

    def as_dict(self):
        ivals = sorted(self.poll_intervals)
        return {
            "rssi_ewma": round(self.rssi_ewma, 1) if self.rssi_ewma is not None else None,
            "rssi_min": self.rssi_min, "rssi_max": self.rssi_max,
            "tx": self.tx, "acked": self.acked,
            "ack_rate": round(self.acked / self.tx, 3) if self.tx else None,
            "polls": self.polls,
            "median_poll_interval_s": round(ivals[len(ivals) // 2], 1) if ivals else None,
            "beacons": self.beacons,
        }


class Pipeline:
    def __init__(self, cfg, events: EventLog, decryptor=None, ephemeral: bool = False):
        """``ephemeral``: judge frames on their own (replay), starting from
        an empty last-seen table and persisting nothing to the state dir."""
        self.cfg = cfg
        self.events = events
        self.ephemeral = ephemeral
        self.names = DeviceNames(cfg.devices_path)
        self.seen = LastSeen(None if ephemeral else cfg.state_dir / "last-seen.json")
        self.detector = Detector(cfg.detector)
        self.decryptor = decryptor
        self.devices: dict[str, DeviceStats] = {}
        self.own_pans: dict[int, int] = {}
        self.partition: Optional[tuple] = None
        self.last_frame: Optional[Frame] = None
        self._last_who: Optional[str] = None
        self.beacon_times = deque(maxlen=16)
        self._join_scan_evt = 0.0
        self.dup_recent = {}                    # (src, seq) -> ts
        self.retrans_counts = deque(maxlen=30)  # per-window (dups, frames)
        self._win_dups = 0
        self._win_frames = 0
        self._win_dup_by: dict[tuple, int] = {}  # (sender identity, dst) -> dups this window
        self._win_start = 0.0
        self._retrans_alerted = 0.0
        self.quiet_reported: set[str] = set()
        self._resolve_after: dict[str, float] = {}   # short addr -> next attempt ts
        self._verify_after: dict[str, float] = {}    # short addr -> next re-check of its mapping
        self.mle_names_path = cfg.state_dir / "observed-names.json"
        self.observed_names = {}
        if not ephemeral and self.mle_names_path.exists():
            try:
                self.observed_names = json.loads(self.mle_names_path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        # Silences that crossed their threshold while the recorder was down
        # (or while it sat in the no-frames watchdog restart loop, where
        # periodic() never runs) are announced now, once: the row carries a
        # persisted "announced" flag, so a restart neither re-announces every
        # quiet device nor swallows a silence nobody has heard about. Rows
        # inside their threshold are left alone for periodic() to judge.
        # The recorder only witnessed silence while it was hearing frames:
        # the gap between its last frame and now (a reboot, a dead dongle,
        # the stall restart loop) is its own blindness, not the devices',
        # and is not counted towards any silence that spans it.
        self._blind_from, self._blind_s = time.time(), 0.0
        if not ephemeral:
            now = time.time()
            last_alive = self._last_frame_heard()
            if last_alive is not None:
                self._blind_from, self._blind_s = last_alive, max(0.0, now - last_alive)
            dominant = self._persisted_dominant_pan()
            announced = 0
            for addr, row in self.seen.table.items():
                if self.silence_s(row, now) <= self.quiet_threshold_s(addr):
                    if row.pop("quiet_reported", None):
                        # Heard again after its announced silence, but the
                        # recorder died before saying so: close the silence
                        # at the moment it was actually heard.
                        self.events.emit("device_returned", "notice", row["last_seen"],
                                         addr=addr, name=self.names.name(addr))
                        announced += 1
                    continue
                if row.get("quiet_reported"):
                    self.quiet_reported.add(addr)
                elif dominant is None or row.get("pan") in (None, dominant):
                    self._report_quiet(addr, row, now)
                    announced += 1
            if announced:
                self.seen.save()

    def _last_frame_heard(self) -> Optional[float]:
        """When the previous run last heard a frame: from status.json (which
        records the frame age at each write), else the last-seen save time."""
        stamps = []
        try:
            st = json.loads((self.cfg.state_dir / "status.json").read_text())
            stamps.append(float(st["updated"]) - float(st.get("last_frame_age_s", 0)))
        except (OSError, ValueError, KeyError, TypeError):
            pass
        try:
            stamps.append(self.seen.state_path.stat().st_mtime)
        except (OSError, AttributeError):
            pass
        return max(stamps) if stamps else None

    def silence_s(self, row: dict, now: float) -> float:
        """How long the recorder has actually heard nothing from a device."""
        silent = now - row["last_seen"]
        if self._blind_s and row["last_seen"] <= self._blind_from:
            silent -= self._blind_s
        return silent

    def _persisted_dominant_pan(self) -> Optional[int]:
        """Best guess at this network's PAN before any frame arrives: the one
        the persisted rows have sent the most frames on."""
        weight: dict[int, int] = {}
        for row in self.seen.table.values():
            if row.get("pan") is not None:
                weight[row["pan"]] = weight.get(row["pan"], 0) + row.get("frames", 0)
        return max(weight, key=weight.get) if weight else None

    # ------------------------------------------------------- quiet policy

    def is_router(self, addr: str) -> bool:
        """True when the inventory tags the address as an always-on device.

        Cleartext headers cannot tell a router from a busy end device: data
        requests (polls) are sent from the short address, so per-extended-
        address poll counts are always zero.
        """
        return self.names.is_router(addr)

    def quiet_threshold_s(self, addr: str) -> float:
        return self.cfg.quiet_router_s if self.is_router(addr) else self.cfg.quiet_end_device_s

    def dominant_pan(self) -> Optional[int]:
        return max(self.own_pans, key=self.own_pans.get) if self.own_pans else None

    # ---------------------------------------------------------- identity

    RESOLVE_RETRY_S = 30.0

    def identity(self, f: Frame) -> Optional[str]:
        """The extended address a frame came from, when we can know it.

        Frames with an extended source answer themselves. Short-source
        frames are the bulk of traffic and the only kind sleepy end devices
        send outside of attaching; with credentials the decryptor maps them
        by trying every known extended address as the MAC nonce (see
        Decryptor.resolve_short), rate-limited per short address so a storm
        of unmapped frames cannot burn the CPU. Without credentials they
        stay anonymous.
        """
        src = f.src
        if not src:
            return None
        if len(src) == 16:
            return src
        if self.decryptor is None or f.ftype not in (1, 3):
            return None
        ext = self.decryptor.short_to_ext.get(src)
        if ext:
            # A short address is reassigned when a parent restarts, so the
            # cached mapping is re-checked against the MIC now and then and
            # dropped when it no longer fits; the new holder then resolves.
            if f.ts < self._verify_after.get(src, 0.0) or not self.decryptor.resolvable(f.psdu):
                return ext
            self._verify_after[src] = f.ts + self.RESOLVE_RETRY_S
            if self.decryptor.verify_short(f.psdu, ext):
                return ext
            del self.decryptor.short_to_ext[src]
            self._resolve_after.pop(src, None)
        if f.ts < self._resolve_after.get(src, 0.0) or not self.decryptor.resolvable(f.psdu):
            return None
        self._resolve_after[src] = f.ts + self.RESOLVE_RETRY_S
        candidates = dict.fromkeys([*self.names.by_addr, *self.seen.table])  # ordered, unique
        return self.decryptor.resolve_short(f.psdu, src, candidates)

    # ------------------------------------------------------------ ingest

    def ingest(self, f: Frame) -> None:
        ts = f.ts
        self.detector.add_frame(ts)

        who = self.identity(f)

        # ACK pairing: an ACK within 10 ms bearing the pending seq.
        prev = self.last_frame
        if (f.ftype == 2 and prev is not None and prev.src
                and prev.seq == f.seq and ts - prev.ts < 0.05):
            stats = self.devices.get(self._last_who or prev.src)
            if stats and stats.ack_pending_seq == f.seq:
                stats.acked += 1
                stats.ack_pending_seq = None
        self._last_who = who

        if who:
            stats = self.devices.setdefault(who, DeviceStats())
            if f.ftype in (1, 3) and f.dst not in (None, "ffff"):
                # Broadcasts (MLE advertisements every few seconds) are
                # never acknowledged; counting them made every router's
                # ACK rate look broken.
                stats.tx += 1
                stats.ack_pending_seq = f.seq
                stats.ack_pending_ts = ts
            if f.rssi is not None:
                stats.rssi_ewma = f.rssi if stats.rssi_ewma is None \
                    else 0.95 * stats.rssi_ewma + 0.05 * f.rssi
                stats.rssi_min = f.rssi if stats.rssi_min is None else min(stats.rssi_min, f.rssi)
                stats.rssi_max = f.rssi if stats.rssi_max is None else max(stats.rssi_max, f.rssi)
            if f.ftype == 3 and f.cmd in (None, 4):   # data request (poll); secured ones carry no cmd
                if stats.last_poll_ts is not None:
                    stats.poll_intervals.append(ts - stats.last_poll_ts)
                stats.last_poll_ts = ts
                stats.polls += 1
            was_new = who not in self.seen.table
            self.seen.touch(who, ts, f.ftype, pan=f.src_pan, rssi=f.rssi)
            if was_new:
                self.events.emit("device_first_seen", "info", ts, addr=who,
                                 name=self.names.name(who))
            if who in self.quiet_reported:
                self.quiet_reported.discard(who)
                self.seen.table[who].pop("quiet_reported", None)
                self.events.emit("device_returned", "notice", ts, addr=who,
                                 name=self.names.name(who))
                # Persist at once: a crash before the next 30 s save would
                # leave the row flagged and a restart would announce this
                # return a second time. Returns are rare, saves are cheap.
                self.seen.save()

        # Beacons, or beacon requests (an unsecured MAC command, id 7):
        # someone scanning to join. Thread itself discovers over MLE, so
        # these are Zigbee or factory-reset devices sweeping the channel.
        if f.ftype == 0 or (f.ftype == 3 and f.cmd == 7):
            if f.src:
                self.devices.setdefault(f.src, DeviceStats()).beacons += 1
            self.beacon_times.append(ts)
            recent = [t for t in self.beacon_times if ts - t <= 60]
            if len(recent) >= 5 and ts - self._join_scan_evt > 300:
                self._join_scan_evt = ts
                self.events.emit("join_scan_activity", "notice", ts,
                                 count_60s=len(recent), src=f.src,
                                 note=f"{len(recent)} beacons in 60 s: something is scanning to join a network")

        # Foreign PAN: a source PAN that is not the dominant one, sighted
        # repeatedly (single hits are usually dissection edge cases - verify
        # candidates in Wireshark with: wpan.src_pan != <dominant>).
        if f.src_pan is not None:
            self.own_pans[f.src_pan] = self.own_pans.get(f.src_pan, 0) + 1
            if len(self.own_pans) > 1:
                dominant = max(self.own_pans, key=self.own_pans.get)
                if f.src_pan != dominant and self.own_pans[f.src_pan] == 3:
                    self.events.emit("possible_foreign_pan", "notice", ts,
                                     pan=f"0x{f.src_pan:04x}", src=f.src,
                                     dominant_pan=f"0x{dominant:04x}",
                                     note="repeated foreign-PAN sightings; verify in Wireshark")

        # Retransmission-rate window (duplicate src+seq within 2 s).
        if self._win_start == 0.0:
            self._win_start = ts
        if f.ftype in (1, 3) and f.src and f.seq is not None:
            key = (f.src, f.seq)
            last = self.dup_recent.get(key)
            if last is not None and ts - last < 2.0:
                self._win_dups += 1
                pair = (who or f.src, f.dst)
                self._win_dup_by[pair] = self._win_dup_by.get(pair, 0) + 1
            self.dup_recent[key] = ts
            self._win_frames += 1
            if len(self.dup_recent) > 8192:
                cutoff = ts - 4
                self.dup_recent = {k: v for k, v in self.dup_recent.items() if v > cutoff}
        if ts - self._win_start >= 60:
            if self._win_frames >= 100:
                rate = self._win_dups / self._win_frames
                self.retrans_counts.append(rate)
                base = sorted(self.retrans_counts)[len(self.retrans_counts) // 2]
                if rate > 0.2 and rate > 2 * base and ts - self._retrans_alerted > 900:
                    self._retrans_alerted = ts
                    attribution = self._retrans_attribution()
                    # One pair hammering each other is a chronic bad link
                    # between two devices at the RF edge: worth a log line,
                    # not a page. Retries spread across the mesh are the
                    # storm precursor this detector exists for.
                    one_link = attribution.get("top_share", 0) >= 0.5
                    self.events.emit("retransmission_elevation",
                                     "notice" if one_link else "warning", ts,
                                     rate=round(rate, 3), baseline=round(base, 3),
                                     **attribution)
            self._win_start = ts
            self._win_dups = self._win_frames = 0
            self._win_dup_by = {}

        # Storm detector escalation to the event log (own cooldown, never
        # per-frame even when the detector's alert cooldown is zeroed).
        if self.detector.storm_active and ts - getattr(self, "_storm_evt", 0) > max(60.0, self.cfg.detector.alert_cooldown_s):
            self._storm_evt = ts
            details = self.detector.last_alert_details
            period = details.get("period")
            onsets = details.get("onsets") or []
            self.events.emit("phase_locked_storm", "critical", ts,
                             period_s=round(period, 1) if period else None, onsets=len(onsets),
                             onset_times=onsets,
                             note=(f"traffic floods recurring every {period:.0f} s ({len(onsets)} onsets): "
                                   "the broadcast-storm signature; run 'threadwatch freeze' to keep the packets"
                                   if period else "phase-locked traffic floods"),
                             **self.detector.snapshot())

        # Credentialed visibility.
        if self.decryptor is not None and f.ftype == 1:
            self._deep_inspect(f)

        self.last_frame = f

    def _label(self, addr: Optional[str]) -> Optional[str]:
        """Name for any address form: extended, or a short one the decryptor
        has mapped; falls back to the address itself."""
        if not addr:
            return None
        ext = addr if len(addr) == 16 else (self.decryptor.short_to_ext.get(addr) if self.decryptor else None)
        return (self.names.name(ext) if ext else None) or addr

    def _retrans_attribution(self) -> dict:
        """Who did the repeating this window, and to whom. One sender hammering
        one neighbour (a failing link between two devices at the RF edge)
        reads very differently from everyone retrying a little (channel
        contention), and the phone message should say which."""
        if not self._win_dup_by or not self._win_dups:
            return {}
        (sender, dst), n = max(self._win_dup_by.items(), key=lambda kv: kv[1])
        share = n / self._win_dups
        sender_ext = sender if len(sender) == 16 else None
        target = "broadcast" if dst in (None, "ffff") else self._label(dst)
        who = self._label(sender)
        if share >= 0.5:
            note = (f"{who} repeated frames to {target} ({share:.0%} of this minute's "
                    f"retransmissions): a failing link between those two, not channel-wide")
        else:
            note = (f"retries spread across devices (top: {who} -> {target}, {share:.0%}): "
                    f"channel contention or interference rather than one bad link")
        return {"addr": sender_ext, "name": self.names.name(sender_ext) if sender_ext else None,
                "top_sender": who, "top_target": target, "top_share": round(share, 2), "note": note}

    # ------------------------------------------------- credentialed layer

    def _deep_inspect(self, f: Frame) -> None:
        from .crypto import Decryptor, MLE_UDP_PORT
        ext = f.src if f.src and len(f.src) == 16 else None
        short = f.src if f.src and len(f.src) == 4 else None
        dext = f.dst if f.dst and len(f.dst) == 16 else None
        dshort = f.dst if f.dst and len(f.dst) == 4 else None
        plain = self.decryptor.decrypt_frame(f.psdu, ext, short)
        if plain is None:
            return
        # Unsecured frames are unauthenticated bytes from anyone on the
        # channel; a parse failure there must not take the capture down.
        try:
            r = Decryptor.udp_ports(plain, mac_src_ext=ext, mac_dst_ext=dext, mac_dst_short=dshort)
            if not r:
                return
            sport, dport, payload, sip, dip = r
            info = None
            if MLE_UDP_PORT in (sport, dport):
                src_for_mle = ext or self.decryptor.short_to_ext.get(short or "")
                info = self.decryptor.parse_mle(payload, src_for_mle, sip, dip)
        except (struct.error, IndexError, ValueError):
            self.decryptor.stats["parse_failed"] += 1
            return
        if MLE_UDP_PORT in (sport, dport):
            if not info:
                return
            if info.command_name in MLE_REJOIN_COMMANDS:
                # addr is the extended address (the review pages key on it);
                # src is whatever the frame carried, often a short address.
                name = self.names.name(src_for_mle) if src_for_mle else None
                self.events.emit("mle_rejoin_attempt", "notice", f.ts,
                                 command=info.command_name, src=f.src, addr=src_for_mle, name=name,
                                 note=f"{info.command_name} from {name or src_for_mle or f.src}: "
                                      "it lost its parent or its network and is trying to get back")
            if info.partition_id is not None:
                cur = (info.partition_id, info.leader_router_id)
                if self.partition is not None and cur != self.partition:
                    self.events.emit("partition_or_leader_change", "warning", f.ts,
                                     previous={"partition": self.partition[0],
                                               "leader_router": self.partition[1]},
                                     current={"partition": cur[0],
                                              "leader_router": cur[1]},
                                     note=f"partition {self.partition[0]} leader r{self.partition[1]} -> "
                                          f"partition {cur[0]} leader r{cur[1]}: the mesh split, merged "
                                          "or elected a new leader")
                self.partition = cur
        else:
            # Keyed by the extended address: a short address is reassigned
            # when a parent restarts, and device_summary looks up by ext.
            owner = ext or self.decryptor.short_to_ext.get(short or "")
            if owner:
                for n in Decryptor.harvest_names(payload):
                    if len(n) > 8 and not n.startswith("_"):
                        self.observed_names.setdefault(owner, {})[n] = \
                            self.observed_names.get(owner, {}).get(n, 0) + 1

    # ------------------------------------------------------- housekeeping

    def periodic(self, now: float) -> None:
        """Run every ~30 s in live capture: quiet checks, persistence."""
        self.seen.maybe_save()
        # Devices on another PAN (a neighbour's mesh, an unpaired device
        # announcing itself) are tracked for the report but never alerted on:
        # their absence says nothing about this network.
        dominant = self.dominant_pan()
        for addr, row in self.seen.table.items():
            if addr in self.quiet_reported:
                continue
            pan = row.get("pan")
            if dominant is not None and pan is not None and pan != dominant:
                continue
            if self.silence_s(row, now) > self.quiet_threshold_s(addr):
                self._report_quiet(addr, row, now)
        if self.observed_names and not self.ephemeral:
            tmp = self.mle_names_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.observed_names, indent=1))
            tmp.replace(self.mle_names_path)

    def _report_quiet(self, addr: str, row: dict, now: float) -> None:
        """Emit device_quiet once and remember, in memory and in the row
        (persisted with last-seen.json), that it has been announced."""
        self.quiet_reported.add(addr)
        row["quiet_reported"] = True
        self.seen._dirty = True
        silent = self.silence_s(row, now)
        # A device the sniffer barely hears goes "quiet" whenever the link
        # fades; log it, but do not page for it.
        rssi = row.get("rssi")
        marginal = reception(rssi, self.cfg.quiet_min_rssi_dbm) == "marginal"
        self.events.emit(
            "device_quiet", "notice" if marginal else "warning", now, addr=addr,
            name=self.names.name(addr), silent_for_s=round(silent),
            profile="router" if self.is_router(addr) else "end-device",
            rssi_dbm=rssi, reception="marginal" if marginal else "good",
            note=("sniffer hears this device at the edge of its range; "
                  "silence is more likely reception than failure" if marginal else
                  "no frames heard; if no mle_rejoin_attempt follows, "
                  "suspect device-internal failure rather than RF"))

    def device_summary(self) -> dict:
        out = {}
        for addr, stats in self.devices.items():
            out[addr] = {"name": self.names.name(addr), **stats.as_dict(),
                         "observed_names": list(self.observed_names.get(addr, {}))[:3]}
        return out


def load_decryptor(cfg):
    """Return a Decryptor if credentials are configured, else None."""
    cred_path = Path(cfg.credentials_path) if getattr(cfg, "credentials_path", None) \
        else (cfg.config_dir / "credentials.toml" if hasattr(cfg, "config_dir") else None)
    if cred_path is None or not cred_path.exists():
        return None
    import tomllib
    try:
        raw = tomllib.loads(cred_path.read_text())
        key_hex = raw.get("credentials", {}).get("network_key", "")
        if len(key_hex) != 32:
            return None
        from .crypto import Decryptor
        return Decryptor(network_key=bytes.fromhex(key_hex))
    except Exception as exc:
        print(f"[threadwatch] credentials unusable ({exc}); continuing key-free", flush=True)
        return None
