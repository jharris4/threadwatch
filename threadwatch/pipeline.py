"""The shared frame-analysis pipeline used by live capture and replay.

General-purpose Thread health tracking, one frame at a time:

Key-free (always on):
  - per-device stats: frame counts, RSSI trend, poll cadence, ACK success
  - device went-quiet / returned / silent-without-rejoin events
  - foreign-PAN frames, beacon (join-scan) bursts
  - traffic floods and phase-locked periodicity (storm signature)
  - MAC retransmission-rate elevation
  - slow link degradation: RSSI at the sniffer well below the device's usual
  - a daily summary event: frames, devices heard, quiet, unknown, degraded,
    and the day's event counts, once per local day

With Thread credentials (optional):
  - short-address identity: sleepy end devices (which never use their
    extended address once attached) get their polls, RSSI and quiet /
    returned events attributed to them
  - MLE visibility: rejoin attempts (Parent/Child ID Request), partition and
    leader changes, per-device RLOC learning
  - SRP/DNS-SD name harvesting for auto-naming hints
  - sleepy-device starvation: a child polling its parent with no
    acknowledgement, after its polls used to be answered (its parent died
    or the link to it broke, and it has not noticed yet)
"""

from __future__ import annotations

import json
import struct
import threading
import time
from collections import deque
from pathlib import Path
from typing import Optional

from .detect import Detector
from .events import EventLog, day_of, read_day
from .link import assess as assess_link
from .names import _EXT_ADDR, DeviceNames, LastSeen, load_border_routers, reception, rloc16_role
from .pcap import BROADCAST_PAN, Frame

MLE_REJOIN_COMMANDS = {"Parent Request", "Child ID Request", "Announce"}

# Starvation: this many distinct polls (MAC retries of one poll share a
# sequence number and count once) with no ACK, spanning at least this long.
STARVED_POLLS = 10
STARVED_MIN_S = 60.0


class DeviceStats:
    """Rolling per-device health from cleartext headers only."""

    __slots__ = ("rssi_ewma", "rssi_min", "rssi_max", "polls", "last_poll_ts",
                 "poll_intervals", "tx", "acked", "ack_pending_seq",
                 "ack_pending_ts", "beacons", "poll_pending_seq", "poll_pending_ts",
                 "acked_polls", "unanswered_polls", "unanswered_since", "starved")

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
        self.poll_pending_seq = None      # the last poll's seq until its ACK arrives
        self.poll_pending_ts = 0.0
        self.acked_polls = 0
        self.unanswered_polls = 0         # distinct polls since the last answered one
        self.unanswered_since = None
        self.starved = False

    def as_dict(self):
        ivals = sorted(self.poll_intervals)
        return {
            "rssi_ewma": round(self.rssi_ewma, 1) if self.rssi_ewma is not None else None,
            "rssi_min": self.rssi_min, "rssi_max": self.rssi_max,
            "tx": self.tx, "acked": self.acked,
            "ack_rate": round(self.acked / self.tx, 3) if self.tx else None,
            "polls": self.polls,
            "median_poll_interval_s": round(ivals[len(ivals) // 2], 1) if ivals else None,
            "acked_polls": self.acked_polls, "unanswered_polls": self.unanswered_polls,
            "starved": self.starved,
            "beacons": self.beacons,
        }


class Pipeline:
    def __init__(self, cfg, events: EventLog, decryptor, ephemeral: bool = False):
        """``ephemeral``: judge frames on their own (replay), starting from
        an empty last-seen table and persisting nothing to the state dir."""
        self.cfg = cfg
        self.events = events
        self.ephemeral = ephemeral
        self.names = DeviceNames(cfg.devices_path, None if ephemeral else cfg.state_dir / "border-routers.json")
        self.seen = LastSeen(None if ephemeral else cfg.state_dir / "last-seen.json")
        self.detector = Detector(cfg.detector)
        self.decryptor = decryptor
        self.devices: dict[str, DeviceStats] = {}
        # Frames heard per source PAN. The one with the most is ours: it
        # decides which PANs are foreign and whose silences count. Seeded
        # from the table so a week of history outweighs a start-up lull in
        # which a neighbour's mesh happens to talk first.
        self.own_pans: dict[int, int] = {}
        for row in self.seen.table.values():
            if row.get("pan") == BROADCAST_PAN:
                # Stamped by a recorder from before broadcast frames were
                # told apart from a move to another network: not a PAN.
                del row["pan"]
                self.seen._dirty = True
            if row.get("pan") is not None:
                self.own_pans[row["pan"]] = self.own_pans.get(row["pan"], 0) + int(row.get("frames") or 0)
        self._dominant: Optional[int] = None
        self._update_dominant(None)
        self._pan_window: dict[int, int] = {}     # frames per source PAN since the window opened
        self._pan_window_start: Optional[float] = None
        self._pan_silent_evt = 0.0
        self._foreign_reported: set[int] = set()
        self._last_src_by_pan: dict[int, Optional[str]] = {}
        # All three are fed straight from mDNS answers, which anyone on the
        # LAN can forge in any number, so each is bounded (PENDING_MAX,
        # LOGGED_MAX): a LAN has a handful of border routers, not hundreds.
        self._unheard_logged: set[str] = set()      # mDNS addresses never heard on air, complained about once
        self._stale_logged: set[tuple] = set()      # (hostname, address) stale mDNS answers, complained about once
        self._pending_routers: dict[str, dict] = {}  # ext -> the mDNS record waiting for that address to be heard
        self.partition: Optional[tuple] = None
        self._crypto_mark = (0, 0)          # (decrypted, failed) when decryption last worked
        self._stale_evt = 0.0
        # Border routers on the LAN: hostname -> current address (mDNS).
        self.routers_path = cfg.state_dir / "border-routers.json"
        self.routers: dict[str, dict] = {} if ephemeral else load_border_routers(self.routers_path)
        self._browse_thread = None
        self._browse_result: Optional[list] = None
        self._next_browse = 0.0
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
        # Hour bucket -> frames, last ~25 h, for the daily summary's frame
        # count. Persisted (frames-by-hour.json) so a summary sent soon
        # after a restart still counts the whole day, not just this run.
        self.frames_by_hour_path = cfg.state_dir / "frames-by-hour.json"
        self._frames_by_hour: dict[int, int] = {} if ephemeral else self._load_frames_by_hour()
        if not ephemeral:
            # A freeze the last run did not finish (os._exit unwinds no
            # thread) is a half copy nothing marks as such: discard it and
            # say so, and let the cooldown below see only whole incidents,
            # so the storm still running gets its snapshot.
            from .freeze import discard_partials
            for label in discard_partials(cfg.incidents_dir):
                self.events.emit("incident_freeze_failed", "warning", time.time(), label=label,
                                 note=(f"the freeze for {label} was cut short when the recorder last stopped; "
                                       "the half copy was discarded, and the next storm event tries again"))
        self._last_auto_freeze = 0.0 if ephemeral else self._last_auto_freeze_on_disk()
        # How a critical event freezes the ring: in the background, so the
        # copy (gigabytes on a Pi) never stalls capture. Tests swap it.
        self.freezer = self._freeze_in_background
        self._summary_day: Optional[str] = None      # local day whose summary is settled
        self._resolve_after: dict[str, float] = {}   # short addr -> next attempt ts
        self._verify_after: dict[str, float] = {}    # short addr -> next re-check of its mapping
        self.extra_candidates: list[str] = []        # ext addrs to try first in the nonce search (why)
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
        # and is not counted towards any silence that spans it. Each span
        # is (last stamp taken before it, its length); a forward step of
        # the host clock adds one (see _check_clock). Signed, and clamped
        # as a sum: an RTC-less Pi boots on a saved clock that can trail
        # the last frame, and the step that follows makes up the rest.
        self._blind: list[tuple[float, float]] = []
        self._wall, self._mono = time.time, time.monotonic   # swapped by tests
        self._clock = (self._wall(), self._mono())
        if not ephemeral:
            now = self._clock[0]
            # Short addresses learned last run: seed the decryptor so sleepy
            # devices are attributed from the first frame. A wrong seed (the
            # address was reassigned while the recorder was down) fails the
            # MIC re-check on its first resolvable frame and is dropped.
            for addr, row in sorted(self.seen.table.items(), key=lambda kv: kv[1].get("rloc16_ts") or 0):
                if row.get("rloc16"):
                    self.decryptor.short_to_ext[row["rloc16"]] = addr
                if row.get("starved"):
                    # A starvation announced by an earlier run and not yet
                    # closed: the row remembers it (as quiet_reported does
                    # for a silence) so the first answered poll closes it,
                    # and so that this run's unanswered polls do not
                    # announce the same unbroken episode again.
                    self.devices.setdefault(addr, DeviceStats()).starved = True
            last_alive = self._last_frame_heard()
            if last_alive is not None:
                self._blind.append((last_alive, now - last_alive))
            dominant = self.dominant_pan()       # best guess before any frame arrives
            announced = 0
            for addr, row in self.seen.table.items():
                if row.get("rotated_to"):
                    continue          # an Apple hub's old address: retired, not quiet
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
                    self._report_quiet(addr, row, now, persist=False)
                    announced += 1
            if announced:
                self.seen.save()

    def _load_frames_by_hour(self) -> dict[int, int]:
        try:
            raw = json.loads(self.frames_by_hour_path.read_text())
            newest = max(int(b) for b in raw)
            return {int(b): int(n) for b, n in raw.items() if int(b) >= newest - 25}
        except (OSError, ValueError, TypeError):
            return {}

    def _save_frames_by_hour(self) -> None:
        tmp = self.frames_by_hour_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({str(b): n for b, n in self._frames_by_hour.items()}))
        tmp.replace(self.frames_by_hour_path)

    def _last_auto_freeze_on_disk(self) -> float:
        """When the newest auto-* incident was frozen, so the cooldown holds
        across a restart: a daemon that comes back mid-storm must not copy
        the whole ring (gigabytes) a second time and fill the card."""
        from .review import incidents
        try:
            for inc in incidents(self.cfg.incidents_dir):      # newest first
                if inc["label"].startswith("auto-"):
                    return float(inc["frozen"])
        except OSError:
            pass
        return 0.0

    def _last_frame_heard(self) -> Optional[float]:
        """When a previous run last heard a frame: the stamp status.json
        carries across runs (capture.last_frame_on_record), or the newest
        last_seen in the table. Both stand still while nothing is heard.
        The status file's write time and the table's save time do not: a
        run that hears nothing still writes both before the watchdog
        restarts it, so judging by them credits a two-hour outage as the
        three minutes of the last restart and pages for every device."""
        stamps = []
        try:
            st = json.loads((self.cfg.state_dir / "status.json").read_text())
            if st.get("last_frame_ts") is not None:
                stamps.append(float(st["last_frame_ts"]))
        except (OSError, ValueError, TypeError):
            pass
        stamps.extend(row["last_seen"] for row in self.seen.table.values() if row.get("last_seen") is not None)
        return max(stamps) if stamps else None

    def silence_s(self, row: dict, now: float) -> float:
        """How long the recorder has actually heard nothing from a device."""
        silent = now - row["last_seen"]
        blind = sum(length for since, length in self._blind if row["last_seen"] <= since)
        return silent - max(0.0, blind)

    # A wall-clock jump this large against the monotonic clock is a step
    # (NTP correcting a Pi that booted on its saved time), not slew.
    CLOCK_STEP_MIN_S = 60.0

    def _check_clock(self, now: float) -> None:
        """A Pi has no RTC: it boots on the clock it shut down with, and
        NTP steps it to the true time minutes later, after the recorder is
        up. Every stamp taken before the step (last-seen rows, the start-up
        blindness) then sits the whole step behind the clock, and every
        device would cross its quiet threshold on the same tick. The step
        is measured against the monotonic clock and credited as blindness
        to everything heard before it."""
        wall, mono = self._wall(), self._mono()
        step = (wall - self._clock[0]) - (mono - self._clock[1])
        self._clock = (wall, mono)
        if step < self.CLOCK_STEP_MIN_S:
            return
        self._blind.append((wall - step, step))
        self.events.emit("clock_step", "info", now, step_s=round(step),
                         note=(f"the host clock jumped forward {round(step / 60)} min (NTP after boot?); "
                               "silences that span the jump are not counted against any device"))

    # ------------------------------------------------------- quiet policy

    def quiet_threshold_s(self, addr: str) -> float:
        """One window for everyone: the 2026-09-02 soak showed routers and
        sleepy devices alike never silent for long from the sniffer's chair.
        (Kept as a method so a per-device rule has somewhere to go.)"""
        return self.cfg.quiet_s

    # Without [network] pan_id the recorder guesses: a PAN is taken for ours
    # once it has this many frames, and gives way only to one with this
    # many times as many, so two networks trading the lead frame by frame
    # do not swap whose silences count on every tick. Either way the
    # change is an event, never silent: a busier neighbour on the same
    # channel can win this guess, and the fix is to set pan_id.
    DOMINANT_MIN_FRAMES = 10
    DOMINANT_LEAD = 2

    def dominant_pan(self) -> Optional[int]:
        """This network's PAN: the configured one, else the guess so far."""
        return self.cfg.pan_id if self.cfg.pan_id is not None else self._dominant

    # With pan_id set, the check that it still matches the mesh: a router
    # advertises every few seconds, so our PAN never goes a window without
    # a frame while the channel stays busy. A re-commission or a dataset
    # migration moves every device to a new PAN, where each counts as
    # foreign and none is judged, and nothing else would say so above a
    # notice.
    PAN_SILENT_WINDOW_S = 30 * 60
    PAN_SILENT_MIN_FRAMES = 100
    PAN_SILENT_REPEAT_S = 6 * 3600

    def _check_configured_pan(self, now: float) -> None:
        if self.cfg.pan_id is None or self._pan_window_start is None:
            return
        if now - self._pan_window_start < self.PAN_SILENT_WINDOW_S:
            return
        ours = self._pan_window.get(self.cfg.pan_id, 0)
        others = sum(n for pan, n in self._pan_window.items() if pan != self.cfg.pan_id)
        self._pan_window, self._pan_window_start = {}, now
        if ours or others < self.PAN_SILENT_MIN_FRAMES or now - self._pan_silent_evt < self.PAN_SILENT_REPEAT_S:
            return
        self._pan_silent_evt = now
        busiest = max(self.own_pans, key=self.own_pans.get) if self.own_pans else None
        self.events.emit("configured_pan_silent", "warning", now, pan=f"0x{self.cfg.pan_id:04x}",
                         heard_frames=others, window_s=self.PAN_SILENT_WINDOW_S,
                         busiest_pan=None if busiest is None else f"0x{busiest:04x}",
                         note=(f"no frame on PAN 0x{self.cfg.pan_id:04x} ([network] pan_id) in the last "
                               f"{self.PAN_SILENT_WINDOW_S // 60} min while {others} were heard on other PANs. "
                               "If the network was re-commissioned or migrated, every device now counts as "
                               "foreign and none is judged: threadwatch import prints the dataset's PAN; "
                               "update pan_id and restart."))

    def _update_dominant(self, ts: Optional[float]) -> None:
        """Adopt or replace the guessed PAN from the frame tally. ``ts`` is
        None at start-up, when the tally is the table's history."""
        if self.cfg.pan_id is not None or not self.own_pans:
            return
        leader = max(self.own_pans, key=self.own_pans.get)
        n = self.own_pans[leader]
        prev = self._dominant
        if prev is None:
            if n < self.DOMINANT_MIN_FRAMES:
                return
        elif leader == prev or n < self.DOMINANT_LEAD * self.own_pans.get(prev, 0):
            return
        self._dominant = leader
        if ts is None:
            print(f"[threadwatch] PAN 0x{leader:04x} taken for ours ({n} frames on record); "
                  "set [network] pan_id in config.toml if that is wrong", flush=True)
            return
        self.events.emit("dominant_pan_changed", "notice" if prev is None else "warning", ts,
                         pan=f"0x{leader:04x}", previous=None if prev is None else f"0x{prev:04x}",
                         frames=n,
                         note=(f"PAN 0x{leader:04x} is now taken for this network's"
                               + ("" if prev is None else f", instead of 0x{prev:04x}")
                               + f": it has sent the most frames ({n}). Quiet checks and foreign-PAN notices "
                                 "follow it. If it is a neighbour's network, set [network] pan_id in "
                                 "config.toml and restart."))

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
        if f.ftype not in (1, 3):
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
        candidates = dict.fromkeys([*self.extra_candidates, *self.names.by_addr, *self.seen.table])
        return self.decryptor.resolve_short(f.psdu, src, candidates)

    # ------------------------------------------------------------ ingest

    def ingest(self, f: Frame) -> None:
        ts = f.ts
        self.detector.add_frame(ts)
        bucket = int(ts // 3600)
        self._frames_by_hour[bucket] = self._frames_by_hour.get(bucket, 0) + 1
        if len(self._frames_by_hour) > 26:
            for old in [b for b in self._frames_by_hour if b < bucket - 25]:
                del self._frames_by_hour[old]

        who = self.identity(f)
        # A frame to the broadcast PAN (a parent request, an announce, a
        # beacon request: what a device sends when it has lost its network)
        # names no source PAN at all. Taking 0xffff for one would move the
        # sender to a "foreign" network and end its quiet checks, exactly
        # when its disappearance is the thing to report.
        pan = f.src_pan if f.src_pan != BROADCAST_PAN else None

        # ACK pairing: an ACK within 10 ms bearing the pending seq.
        prev = self.last_frame
        if (f.ftype == 2 and prev is not None and prev.src
                and prev.seq == f.seq and ts - prev.ts < 0.05):
            stats = self.devices.get(self._last_who or prev.src)
            if stats and stats.ack_pending_seq == f.seq:
                stats.acked += 1
                stats.ack_pending_seq = None
                if stats.poll_pending_seq == f.seq:
                    self._poll_answered(self._last_who or prev.src, stats, ts)
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
                self._poll_sent(who, stats, f.seq, ts, f.dst)
            was_new = who not in self.seen.table
            self.seen.touch(who, ts, f.ftype, pan=pan, rssi=f.rssi)
            if self.seen.table[who].pop("rotated_to", None):
                # Retired as a hub's old address, yet on air: it is live,
                # whatever mDNS said, so its silences count again. A retired
                # row is skipped by every quiet check, so nothing else could
                # bring it back.
                print(f"[threadwatch] {self.names.name(who) or who} heard on air after its address was "
                      "retired: judged again", flush=True)
            if len(f.src) == 4:
                self._note_rloc16(who, f.src, ts)
            pending = self._pending_routers.pop(who, None)
            if pending is not None:
                # A border router mDNS advertised before it was heard on air
                # (a rebooted hub, seen by the browse first): now that it is,
                # bind it, so the first_seen below already carries its name.
                self._apply_border_routers([pending], ts)
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
        # candidates in Wireshark with: wpan.src_pan != <dominant>). Once
        # per PAN, and only against a dominant that strictly leads it: a
        # tie (a neighbour's three frames before ours at start-up) flags
        # nobody, so our own PAN is never the one reported, and the
        # neighbour's is reported as soon as ours pulls ahead.
        if pan is not None:
            self.own_pans[pan] = self.own_pans.get(pan, 0) + 1
            self._last_src_by_pan[pan] = f.src
            self._pan_window[pan] = self._pan_window.get(pan, 0) + 1
            if self._pan_window_start is None:
                self._pan_window_start = ts
            self._update_dominant(ts)
            dominant = self.dominant_pan()
            if dominant is not None and len(self.own_pans) > 1:
                # A configured PAN is ours however little it talks; a
                # guessed one must strictly lead before anything is foreign.
                lead = float("inf") if self.cfg.pan_id is not None else self.own_pans.get(dominant, 0)
                for pan, n in self.own_pans.items():
                    if pan != dominant and 3 <= n < lead and pan not in self._foreign_reported:
                        self._foreign_reported.add(pan)
                        self.events.emit("possible_foreign_pan", "notice", ts,
                                         pan=f"0x{pan:04x}", src=self._last_src_by_pan.get(pan),
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
            # Docs say a "critical event" freezes the ring; the storm is the
            # only critical event today, so this is the only call. A new
            # critical event needs its own call here.
            label = self._auto_freeze(ts, "storm")
            keep = (f"the ring is being frozen as {label}" if label
                    else "run 'threadwatch freeze' to keep the packets")
            self.events.emit("phase_locked_storm", "critical", ts,
                             period_s=round(period, 1) if period else None, onsets=len(onsets),
                             onset_times=onsets, auto_freeze=label,
                             note=(f"traffic floods recurring every {period:.0f} s ({len(onsets)} onsets): "
                                   f"the broadcast-storm signature; {keep}"
                                   if period else "phase-locked traffic floods"),
                             **self.detector.snapshot())

        # Credentialed visibility.
        if f.ftype == 1:
            self._deep_inspect(f)

        self.last_frame = f

    # -------------------------------------------------- poll starvation

    def _note_rloc16(self, ext: str, short: str, ts: float) -> None:
        """Remember which short address a device answers to, with when it
        was last confirmed: the web pages read router/child/parent from it
        and the next run seeds the decryptor with it."""
        row = self.seen.table.get(ext)
        if row is None:
            return
        if row.get("rloc16") != short:
            row["rloc16"] = short
            self.seen._dirty = True
        row["rloc16_ts"] = ts

    def parent_of(self, ext: str) -> Optional[dict]:
        """A child's parent, from its RLOC16: the router id in the top six
        bits, and the device holding that router's address if known."""
        role = rloc16_role((self.seen.table.get(ext) or {}).get("rloc16"))
        if not role or role["role"] != "child":
            return None
        short = f"{role['router_id'] << 10:04x}"
        addr = self.decryptor.short_to_ext.get(short)
        return {"router_id": role["router_id"], "rloc16": short, "addr": addr,
                "name": (self.names.name(addr) if addr else None)}

    def _poll_sent(self, who: str, stats: DeviceStats, seq: Optional[int], ts: float,
                   dst: Optional[str] = None) -> None:
        """A poll went out. If the previous one is still waiting for its ACK
        and this is not a MAC retry of it (same seq), that one went
        unanswered; enough of those in a row, from a device whose polls
        used to be answered, is starvation."""
        if stats.poll_pending_seq is not None and seq != stats.poll_pending_seq:
            stats.unanswered_polls += 1
            if stats.unanswered_since is None:
                stats.unanswered_since = stats.poll_pending_ts
            # "Used to be answered" is judged from this run's count or, after
            # a restart has zeroed it, from the row's persisted marker, so a
            # parent that dies in the first minutes after a restart is not
            # missed.
            row = self.seen.table.get(who)
            answered_before = stats.acked_polls > 0 or bool(row and row.get("polls_acked"))
            if (not stats.starved and answered_before
                    and stats.unanswered_polls >= STARVED_POLLS
                    and ts - stats.unanswered_since >= STARVED_MIN_S):
                stats.starved = True
                # Remembered on the last-seen row too (like quiet_reported):
                # a restart rebuilds DeviceStats empty, and without the row
                # the first answered poll after it would never close the
                # episode.
                if row is not None:
                    row["starved"] = True
                    self.seen._dirty = True
                span = round(ts - stats.unanswered_since)
                history = (f"after {stats.acked_polls} answered polls" if stats.acked_polls
                           else "after answered polls before the recorder's last restart")
                # The poll's destination is the parent's RLOC16; name it, so
                # the question "whose ACKs are missing" is answered here.
                parent_addr = self.decryptor.short_to_ext.get(dst) if dst and len(dst) == 4 else None
                parent = ((self.names.name(parent_addr) or parent_addr) if parent_addr
                          else (f"router {int(dst, 16) >> 10}" if dst and len(dst) == 4 else None))
                whom = f"its parent {parent} ({dst})" if parent else "its parent"
                note = (f"polled {whom} {stats.unanswered_polls} times over {span} s with no "
                        f"acknowledgement, {history}: the parent is gone "
                        "or the link to it broke and the device has not noticed; it still looks alive, "
                        "so no device_quiet will follow, and a rejoin attempt should. (If it just moved "
                        "to a parent the sniffer cannot hear, the ACKs are missing here, not on air.)")
                # Two reasons to log rather than page. A device the sniffer
                # barely hears has a parent whose ACKs it hears even less
                # (same rule as device_quiet). And a device whose previous
                # episode ended only minutes ago, with a plain ACK and no
                # rejoin, is flapping at the sniffer's edge, not losing its
                # parent: one warning, then notices until it has stayed
                # answered for [polls] rearm_s.
                rssi = row.get("rssi") if row else stats.rssi_ewma
                marginal = reception(rssi, self.cfg.quiet_min_rssi_dbm) == "marginal"
                closed = row.get("starve_closed") if row else None
                gap = stats.unanswered_since - closed if closed is not None else None
                flapping = (gap is not None and self.cfg.poll_rearm_s > 0
                            and gap < self.cfg.poll_rearm_s)
                episode = ((row.get("starve_episodes") or 0) + 1) if flapping else 1
                if row is not None and row.get("starve_episodes") != episode:
                    row["starve_episodes"] = episode
                    self.seen._dirty = True
                if marginal:
                    note += (f" The sniffer hears this device at {rssi:.0f} dBm, the edge of its range, "
                             "so the ACKs are more likely out of earshot here than missing on air: logged, not paged.")
                if flapping:
                    note += (f" Episode {episode} since the last page, {gap / 60:.0f} min after the previous one "
                             "ended with an ordinary ACK and no rejoin: a device that flaps like this has a "
                             "parent the sniffer only sometimes hears; logged, not paged, until its polls "
                             f"have stayed answered for {self.cfg.poll_rearm_s / 60:.0f} min.")
                self.events.emit(
                    "poll_starvation", "notice" if (marginal or flapping) else "warning", ts,
                    addr=who, name=self.names.name(who),
                    unanswered_polls=stats.unanswered_polls, since=stats.unanswered_since,
                    starved_for_s=span, acked_polls=stats.acked_polls,
                    rssi_dbm=rssi, reception="marginal" if marginal else "good",
                    episode=episode, since_previous_s=round(gap) if gap is not None else None,
                    parent_rloc16=dst if dst and len(dst) == 4 else None, parent_addr=parent_addr,
                    parent=parent, note=note)
        stats.poll_pending_seq, stats.poll_pending_ts = seq, ts

    def _poll_answered(self, who: str, stats: DeviceStats, ts: float) -> None:
        stats.poll_pending_seq = None
        stats.acked_polls += 1
        stats.unanswered_polls, stats.unanswered_since = 0, None
        row = self.seen.table.get(who)
        announced = stats.starved or (row is not None and row.get("starved"))
        stats.starved = False
        if row is not None:
            if row.pop("starved", None):
                self.seen._dirty = True
            if announced:
                # When this episode ended: the next one is judged against it.
                row["starve_closed"] = ts
                self.seen._dirty = True
            if not row.get("polls_acked"):
                row["polls_acked"] = True
                self.seen._dirty = True
        if announced:
            self.events.emit("poll_answered", "notice", ts, addr=who, name=self.names.name(who),
                             note="its polls are acknowledged again")

    def leader_device(self, router_id: Optional[int] = None) -> dict:
        """Which device holds a router id (the leader's, by default), as far
        as the sniffer knows. A router id is the top six bits of an RLOC16,
        so router 60 answers to short address 0xF000; the MLE layer learns
        which extended address that is the first time the device itself
        sends an MLE frame (its advertisements carry its RLOC16)."""
        rid = router_id if router_id is not None else (self.partition[1] if self.partition else None)
        if rid is None:
            return {}
        short = f"{rid << 10:04x}"
        ext = self.decryptor.short_to_ext.get(short)
        return {"leader_rloc16": short, "leader_addr": ext,
                "leader_name": self.names.name(ext) if ext else None}

    def leader_label(self, router_id: int) -> str:
        """'r60 (Living Room Apple TV)', or just 'r60' until it is known."""
        who = self.leader_device(router_id)
        label = who.get("leader_name") or who.get("leader_addr")
        return f"r{router_id} ({label})" if label else f"r{router_id}"

    def partition_status(self) -> Optional[dict]:
        """The 'partition' entry of status.json and the replay summary."""
        if not self.partition:
            return None
        return {"id": self.partition[0], "leader_router": self.partition[1], **self.leader_device()}

    def _label(self, addr: Optional[str]) -> Optional[str]:
        """Name for any address form: extended, or a short one the decryptor
        has mapped; falls back to the address itself."""
        if not addr:
            return None
        ext = addr if len(addr) == 16 else self.decryptor.short_to_ext.get(addr)
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
            # Only a message that passed its MIC says anything about the
            # mesh: an unsecured one is bytes from anyone on the channel,
            # and acting on it would let a stranger page for a partition
            # change, invent a rejoin, or claim another device's address.
            if not info or not info.secured:
                return
            if info.source_addr16 is not None and src_for_mle:
                self._note_rloc16(src_for_mle, f"{info.source_addr16:04x}", f.ts)
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
                    before, after = self.leader_label(self.partition[1]), self.leader_label(cur[1])
                    self.events.emit("partition_or_leader_change", "warning", f.ts,
                                     previous={"partition": self.partition[0],
                                               "leader_router": self.partition[1], "leader": before},
                                     current={"partition": cur[0],
                                              "leader_router": cur[1], "leader": after},
                                     note=f"partition {self.partition[0]} leader {before} -> "
                                          f"partition {cur[0]} leader {after}: the mesh split, merged "
                                          "or elected a new leader")
                self.partition = cur
        else:
            # Keyed by the extended address: a short address is reassigned
            # when a parent restarts, so a name filed under one would follow
            # the address to whichever device inherits it.
            owner = ext or self.decryptor.short_to_ext.get(short or "")
            if owner:
                for n in Decryptor.harvest_names(payload):
                    if len(n) > 8 and not n.startswith("_"):
                        self._note_observed_name(owner, n)

    # The name scraper is a regex over decrypted UDP payloads, most of
    # which are ciphertext: it fires on random bytes now and then, and an
    # address would otherwise collect a junk "name" every few hours for
    # ever. A real SRP registration recurs (leases are renewed), so only
    # what has been seen twice is a name to suggest (names.MIN_SIGHTINGS),
    # and each address keeps at most this many, the least-sighted going
    # first when a new one arrives.
    OBSERVED_NAMES_MAX = 16

    def _note_observed_name(self, owner: str, name: str) -> None:
        seen = self.observed_names.setdefault(owner, {})
        if name in seen:
            seen[name] += 1
            return
        if len(seen) >= self.OBSERVED_NAMES_MAX:
            weakest = min(seen, key=lambda n: (seen[n], n))
            if seen[weakest] > 1:
                return          # every kept name has recurred: a one-off does not displace one
            del seen[weakest]
        seen[name] = 1

    # ------------------------------------------------------- housekeeping

    def periodic(self, now: float) -> None:
        """Run every ~30 s in live capture: quiet checks, persistence."""
        self._check_clock(now)
        self.seen.maybe_save()
        self._check_credentials(now)
        self._check_configured_pan(now)
        if not self.ephemeral and self.cfg.border_router_browse_s > 0:
            self._poll_border_routers(now)
        # Devices on another PAN (a neighbour's mesh, an unpaired device
        # announcing itself) are tracked for the report but never alerted on:
        # their absence says nothing about this network.
        dominant = self.dominant_pan()
        for addr, row in self.seen.table.items():
            if addr in self.quiet_reported or row.get("rotated_to"):
                continue
            pan = row.get("pan")
            if dominant is not None and pan is not None and pan != dominant:
                continue
            if self.silence_s(row, now) > self.quiet_threshold_s(addr):
                self._report_quiet(addr, row, now)
        self._check_links(now, dominant)
        if not self.ephemeral:
            self._maybe_summarize(now, dominant)
            if self._frames_by_hour:
                self._save_frames_by_hour()
        if self.observed_names and not self.ephemeral:
            tmp = self.mle_names_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.observed_names, indent=1))
            tmp.replace(self.mle_names_path)

    def _check_links(self, now: float, dominant: Optional[int]) -> None:
        """Slow link degradation (link.py) for every device on our PAN."""
        for addr, row in self.seen.table.items():
            pan = row.get("pan")
            if dominant is not None and pan is not None and pan != dominant:
                continue
            verdict = assess_link(row, now, self.cfg.link_drop_db, self.cfg.link_hold_s)
            if verdict is None:
                continue
            self.seen._dirty = True
            name = self.names.name(addr)
            rssi, ref = row.get("rssi"), row.get("rssi_ref")
            if verdict == "degraded":
                drop = round(ref - rssi, 1)
                since = row.get("rssi_low_since", now)
                self.events.emit(
                    "rssi_degradation", "notice", now, addr=addr, name=name,
                    rssi_dbm=rssi, reference_dbm=ref, drop_db=drop,
                    since=since, low_for_s=round(now - since),
                    note=(f"heard {drop:g} dB weaker than its usual {ref:g} dBm for "
                          f"{round((now - since) / 60)} min ({rssi:g} dBm now): the link is "
                          "fading (moved, obstructed, interference nearby) while the device "
                          "still talks; a silence without a rejoin may follow"))
            else:
                # A reference taken this very tick means the daily refresh
                # closed the drop by adopting the lower level, not that the
                # signal came back.
                rebased = row.get("rssi_ref_ts") == now
                self.events.emit("rssi_recovered", "info", now, addr=addr, name=name,
                                 rssi_dbm=rssi, reference_dbm=ref,
                                 note=(f"reference re-based to {ref:g} dBm: the drop held a day "
                                       "and is the new normal" if rebased else
                                       f"back to its usual {ref:g} dBm"))

    # -------------------------------------------------- freeze on critical

    AUTO_FREEZE_COOLDOWN_S = 6 * 3600
    AUTO_FREEZE_RETRY_S = 30 * 60      # after a failed freeze: the next storm event tries again

    def _auto_freeze(self, ts: float, reason: str) -> Optional[str]:
        """Snapshot the ring for a critical event, at most once per cooldown
        (one storm is one incident, however long it rumbles). Returns the
        incident label, or None when off, replaying, or inside the cooldown.
        The cooldown is armed before the copy starts, so the storm events
        that fire while it runs do not start more copies; a copy that
        fails shortens it to AUTO_FREEZE_RETRY_S (see _freeze_now)."""
        if not self.cfg.freeze_on_critical or self.ephemeral:
            return None
        if ts - self._last_auto_freeze < self.AUTO_FREEZE_COOLDOWN_S:
            return None
        self._last_auto_freeze = ts
        label = f"auto-{reason}"
        self.freezer(label)
        return label

    def _freeze_in_background(self, label: str) -> None:
        threading.Thread(target=self._freeze_now, args=(label,), daemon=True).start()

    def _freeze_now(self, label: str) -> None:
        from .freeze import freeze_ring
        try:
            dest, count = freeze_ring(self.cfg, label)
        except Exception as exc:
            # Nothing was kept (freeze_ring removes a half copy), so the
            # six-hour cooldown armed for this attempt must not stand: the
            # next storm event after the retry hold tries again.
            self._last_auto_freeze -= self.AUTO_FREEZE_COOLDOWN_S - self.AUTO_FREEZE_RETRY_S
            self.events.emit("incident_freeze_failed", "warning", time.time(), label=label,
                             note=(f"could not freeze the ring for {label}: {exc}; nothing was kept, and "
                                   f"the next storm event after {self.AUTO_FREEZE_RETRY_S // 60} min tries again"))
            return
        self.events.emit("incident_frozen", "info", time.time(), label=label, path=str(dest),
                         ring_files=count, note=f"{count} ring files kept as {dest.name}")

    # ------------------------------------------------------ daily summary

    def _maybe_summarize(self, now: float, dominant: Optional[int]) -> None:
        """One daily_summary per local day, at [summary] hour. The event log
        is the record of whether today's went out, so a restart neither
        repeats it nor loses it; a recorder that was down at the hour
        sends it late rather than not at all."""
        if self.cfg.summary_hour < 0:
            return
        day = day_of(now)
        if day == self._summary_day or time.localtime(now).tm_hour < self.cfg.summary_hour:
            return
        if not any(r.get("event") == "daily_summary" for r in self._records_of(day)):
            self.events.emit("daily_summary", self.cfg.summary_severity, now,
                             **self.summary(now, dominant))
        # Settled only once the record is written: a failed write (disk
        # full) leaves the day open, so the next periodic() tries again.
        self._summary_day = day

    def _records_of(self, day: str) -> list[dict]:
        events_dir = getattr(self.events, "dir", None)
        if events_dir is not None:
            return read_day(events_dir, day)
        return [r for r in getattr(self.events, "records", []) if day_of(r["ts"]) == day]

    def summary(self, now: float, dominant: Optional[int] = None) -> dict:
        """The last 24 hours in one record: what the recorder saw, who it
        has lost track of, and what it logged. Devices on a foreign PAN
        are left out, as everywhere else."""
        since = now - 86400
        ours = {a: r for a, r in self.seen.table.items()
                if dominant is None or r.get("pan") in (None, dominant)}
        heard = {a: r for a, r in ours.items() if r["last_seen"] >= since}
        label = lambda a: self.names.name(a) or a
        quiet = sorted(label(a) for a in ours if a in self.quiet_reported)
        unknown = sorted(a for a in ours if self.names.name(a) is None)
        marginal = sorted(label(a) for a, r in heard.items()
                          if reception(r.get("rssi"), self.cfg.quiet_min_rssi_dbm) == "marginal")
        degraded = sorted(label(a) for a, r in ours.items() if r.get("rssi_degraded"))
        counts = {"critical": 0, "warning": 0, "notice": 0, "info": 0}
        for day in dict.fromkeys((day_of(since), day_of(now))):
            for r in self._records_of(day):
                if r["ts"] >= since and r.get("event") != "daily_summary":
                    counts[r.get("severity", "info")] = counts.get(r.get("severity", "info"), 0) + 1
        frames = sum(n for b, n in self._frames_by_hour.items() if (b + 1) * 3600 > since)
        parts = [f"{frames:,} frames from {len(heard)} of {len(ours)} devices"]
        parts.append("quiet: " + ", ".join(quiet) if quiet else "nothing quiet")
        if unknown:
            parts.append(f"{len(unknown)} unknown address{'es' if len(unknown) != 1 else ''}")
        if marginal:
            parts.append(f"{len(marginal)} heard marginally")
        if degraded:
            parts.append("signal down: " + ", ".join(degraded))
        if self.detector.storm_active:
            parts.append("STORM ACTIVE")
        logged = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n and sev != "info")
        parts.append("events: " + (logged or "none above info"))
        return {"frames_24h": frames, "devices_heard_24h": len(heard), "devices_tracked": len(ours),
                "quiet": quiet, "unknown": unknown, "marginal": marginal, "degraded": degraded,
                "storm_active": bool(self.detector.storm_active), "events_24h": counts,
                "note": "last 24 h: " + "; ".join(parts)}

    # ------------------------------------------------- border routers

    def _poll_border_routers(self, now: float) -> None:
        """Browse in a thread (the capture loop must not block on the LAN
        for three seconds) and apply the last result when it is in."""
        import threading
        if self._browse_thread is not None:
            if self._browse_thread.is_alive():
                return
            self._browse_thread.join()
            self._browse_thread = None
            result, self._browse_result = self._browse_result, None
            if result is not None:
                self._apply_border_routers(result, now)
            return
        if now < self._next_browse:
            return
        self._next_browse = now + self.cfg.border_router_browse_s

        def run():
            from . import mdns
            try:
                self._browse_result = mdns.browse()
            except OSError as exc:
                print(f"[threadwatch] mdns browse failed: {exc}", flush=True)
                self._browse_result = None

        self._browse_thread = threading.Thread(target=run, name="mdns-browse", daemon=True)
        self._browse_thread.start()

    # How many mDNS records can wait for their address to be heard on air,
    # and how many addresses the once-per-address log lines remember. Past
    # these the oldest record is dropped (a real hub's is re-advertised
    # every browse) and the log memory starts over (a repeated line is the
    # worst case).
    PENDING_MAX = 32
    LOGGED_MAX = 256

    def _apply_border_routers(self, found: list[dict], now: float) -> None:
        """Bind each discovered border router to an inventory entry (by its
        borderRouter hostname, by an address the entry already lists, or
        by the binding remembered from an earlier browse) and notice when
        its address has changed: the new one takes the name, the old row
        is retired so it never reads as quiet."""
        dirty = False
        for r in found:
            host, ext = r.get("hostname"), (r.get("ext") or "").lower()
            if not host or not _EXT_ADDR.match(ext):
                continue
            if ext not in self.seen.table:
                # mDNS is unauthenticated: any host on the LAN can advertise
                # any address under any hostname. Nothing is bound to, and
                # no row is retired for, an address the sniffer has not
                # heard on air, so a forged record cannot silence a device's
                # quiet alerts or take its name. The record waits instead,
                # and ingest() applies it the moment the address is heard
                # (a rebooted hub the browse saw first); a later browse
                # giving the hostname another address replaces it.
                for stale in [a for a, rec in self._pending_routers.items() if rec.get("hostname") == host]:
                    del self._pending_routers[stale]
                self._pending_routers.pop(ext, None)          # re-inserted last: the newest
                self._pending_routers[ext] = r
                while len(self._pending_routers) > self.PENDING_MAX:
                    del self._pending_routers[next(iter(self._pending_routers))]
                if ext not in self._unheard_logged:
                    if len(self._unheard_logged) >= self.LOGGED_MAX:
                        self._unheard_logged.clear()
                    self._unheard_logged.add(ext)
                    print(f"[threadwatch] mdns: {r.get('instance') or host} advertises {ext}, which has not "
                          "been heard on air; held until it is", flush=True)
                continue
            rec = self.routers.get(host) or {}
            entry = (self.names.entry_for_border_router(host) or self.names.by_addr.get(ext)
                     or (self.names.entry_named(rec["name"]) if rec.get("name") else None))
            name = entry.get("name") if entry else None
            prev = (rec.get("addr") or "").lower() or None
            changed = prev is not None and prev != ext
            if changed:
                # mDNS is cached and reflected as well as unauthenticated: a
                # record naming an address the hub used before, while the
                # one it has now is the one heard on air more recently, is
                # a stale answer, not a rotation back. Believing it would
                # retire the live address, and nothing else would judge it.
                old_row, new_row = self.seen.table.get(prev), self.seen.table[ext]
                if old_row is not None and old_row.get("last_seen", 0) > new_row.get("last_seen", 0):
                    if (host, ext) not in self._stale_logged:
                        if len(self._stale_logged) >= self.LOGGED_MAX:
                            self._stale_logged.clear()
                        self._stale_logged.add((host, ext))
                        print(f"[threadwatch] mdns: {r.get('instance') or host} advertises {ext}, but {prev} "
                              "was heard on air more recently; stale record, ignored", flush=True)
                    continue
            new = {"addr": ext, "name": name, "instance": r.get("instance"), "vendor": r.get("vendor"),
                   "model": r.get("model"), "since": now if (changed or not rec) else rec.get("since", now),
                   "seen": now, "previous": list(rec.get("previous") or []), "announced": rec.get("announced", False)}
            if changed:
                new["previous"].append({"addr": prev, "until": now})
            if entry is not None:
                self.names.learn(ext, entry)
            if changed:
                # The address it rotated to is live by definition, even if
                # it was itself retired once (an A -> B -> A sequence).
                if self.seen.table[ext].pop("rotated_to", None):
                    self.seen._dirty = True
                old_row = self.seen.table.get(prev)
                if old_row is not None:
                    old_row["rotated_to"] = ext
                    was_quiet = old_row.pop("quiet_reported", None) or prev in self.quiet_reported
                    self.quiet_reported.discard(prev)
                    self.seen._dirty = True
                    if was_quiet:
                        # The silence announced for the old address is over:
                        # the device is back under the new one. A retired row
                        # is never judged again, so nothing else could close
                        # the episode, and every day page would carry it open.
                        self.events.emit("device_returned", "notice", now, addr=prev, name=name,
                                         note=f"back under a new address, {ext}")
                who = name or r.get("instance") or host
                self.events.emit("border_router_address_changed", "notice", now, addr=ext, name=name,
                                 previous=prev, hostname=host,
                                 note=(f"{who} now answers to {ext}, was {prev}: an Apple hub takes a new Thread "
                                       "address on every reboot. " + ("Named from its entry; nothing to edit." if name
                                       else "Not in devices.json: see the devices page.")))
            elif entry is None and not new["announced"]:
                new["announced"] = True
                self.events.emit("border_router_unlisted", "notice", now, addr=ext, name=None, hostname=host,
                                 note=(f"border router {r.get('instance') or host} ({r.get('vendor')} {r.get('model')}) "
                                       f"at {ext} is not in devices.json: name it with "
                                       f"threadwatch adopt {ext} \"<name>\", or give an entry "
                                       f"\"borderRouter\": \"{host}\""))
            if new != rec:
                self.routers[host] = new
                dirty = True
        if dirty:
            self._save_border_routers()

    def _save_border_routers(self) -> None:
        if self.ephemeral:
            return
        tmp = self.routers_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.routers, indent=1))
        tmp.replace(self.routers_path)

    STALE_FAILED_FRAMES = 200
    STALE_REPEAT_S = 6 * 3600

    def _check_credentials(self, now: float) -> None:
        """A rotated network key does not stop capture (the ring keeps every
        frame, encrypted as received) but silently ends everything that
        reads inside the frames. Nothing decrypting while frames keep
        failing is that signature: say so, and keep saying so."""
        st = self.decryptor.stats
        ok = st["mac_decrypted"] + st["mle_decrypted"]
        bad = st["mac_failed"] + st["mle_failed"]
        prev_ok, prev_bad = self._crypto_mark
        if ok > prev_ok:
            self._crypto_mark = (ok, bad)
            return
        failed = bad - prev_bad
        if failed < self.STALE_FAILED_FRAMES or now - self._stale_evt < self.STALE_REPEAT_S:
            return
        self._stale_evt = now
        self._crypto_mark = (ok, bad)
        self.events.emit("credentials_stale", "warning", now, failed=failed,
                         note=(f"{failed} frames failed to decrypt and none succeeded since decryption last "
                               "worked: the network key in credentials.toml no longer matches the mesh "
                               "(re-commissioned?). Capture continues and the ring keeps every frame, but "
                               "rejoin, starvation, partition and sleepy-device tracking have stopped until "
                               "the file is updated and the recorder restarted."))

    def _report_quiet(self, addr: str, row: dict, now: float, persist: bool = True) -> None:
        """Emit device_quiet once and remember, in memory and in the row
        (persisted with last-seen.json), that it has been announced.

        Persist at once, as a return does: the flag is what stops a restart
        announcing this silence a second time, and waiting for the next 30 s
        save leaves a window where the outage that follows costs the flag but
        not the silence. Quiets are rare, saves are cheap. The startup pass
        passes persist=False and saves once for the batch it announces."""
        self.quiet_reported.add(addr)
        row["quiet_reported"] = True
        self.seen._dirty = True
        if persist:
            self.seen.save()
        silent = self.silence_s(row, now)
        # A device the sniffer barely hears goes "quiet" whenever the link
        # fades; log it, but do not page for it.
        rssi = row.get("rssi")
        marginal = reception(rssi, self.cfg.quiet_min_rssi_dbm) == "marginal"
        self.events.emit(
            "device_quiet", "notice" if marginal else "warning", now, addr=addr,
            name=self.names.name(addr), silent_for_s=round(silent),
            rssi_dbm=rssi, reception="marginal" if marginal else "good",
            note=("sniffer hears this device at the edge of its range; "
                  "silence is more likely reception than failure" if marginal else
                  "no frames heard; if no mle_rejoin_attempt follows, "
                  "suspect device-internal failure rather than RF"))


class CredentialsError(RuntimeError):
    """No usable network key: the recorder cannot do its job without one."""


def credentials_path(cfg) -> Path:
    return Path(cfg.credentials_path) if getattr(cfg, "credentials_path", None) \
        else cfg.config_dir / "credentials.toml"


def load_decryptor(cfg):
    """The Decryptor for the configured network key. Raises CredentialsError,
    with the fix in the message, when the key file is missing or unusable:
    sleepy devices, rejoins, starvation and the partition all live behind
    it, so running without one would record frames and watch nothing."""
    cred_path = credentials_path(cfg)
    how = "see docs/CREDENTIALS.md; threadwatch doctor checks it"
    if not cred_path.exists():
        raise CredentialsError(f"{cred_path} is missing: the Thread network key is required ({how})")
    import tomllib
    try:
        raw = tomllib.loads(cred_path.read_text())
    except Exception as exc:
        raise CredentialsError(f"{cred_path} is unreadable ({exc}); {how}") from exc
    key_hex = str(raw.get("credentials", {}).get("network_key", ""))
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        key = b""
    if len(key) != 16:
        raise CredentialsError(f"{cred_path}: network_key must be 32 hex digits ({how})")
    try:
        from .crypto import Decryptor
    except ModuleNotFoundError as exc:
        raise CredentialsError(f"decryption needs the 'cryptography' package ({exc}); "
                               "pip install cryptography, or apt install python3-cryptography "
                               "into the interpreter bin/threadwatch uses") from exc
    return Decryptor(network_key=key)
