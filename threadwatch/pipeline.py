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
import sys
import threading
import time
from collections import deque
from pathlib import Path

from .detect import Detector
from .events import EventLog, day_of, prune_days, read_day
from .link import assess as assess_link
from .names import _EXT_ADDR, DeviceNames, LastSeen, load_border_routers, reception
from .pcap import BROADCAST_PAN, Frame, is_poll

MLE_REJOIN_COMMANDS = {"Parent Request", "Child ID Request", "Announce"}

# Starvation: this many distinct polls (MAC retries of one poll share a
# sequence number and count once) with no ACK, spanning at least this long.
STARVED_POLLS = 10
STARVED_MIN_S = 60.0


def _whole(value) -> int | None:
    """A whole number from a state file, or None for anything else (a bool,
    a string, a missing key). Rows are JSON somebody can edit."""
    return None if isinstance(value, bool) or not isinstance(value, int) else value


def _seconds(value) -> float:
    """A timestamp from a state file, or 0.0 when it is not a number."""
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0


class DeviceStats:
    """Rolling per-device health from cleartext headers only."""

    __slots__ = ("rssi_ewma", "rssi_min", "rssi_max", "polls", "last_poll_ts",
                 "poll_intervals", "tx", "acked", "ack_pending_seq",
                 "ack_pending_ts", "beacons", "poll_pending_seq", "poll_pending_ts",
                 "acked_polls", "unanswered_polls", "unanswered_since", "starved", "confirm_at")

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
        self.confirm_at = None            # when a logged starvation becomes a page, if still unanswered

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
        # The learned identities are read even offline, and from the
        # snapshot's own copy when --snapshot redirected the state dir:
        # a hub that rotated its address is named by border-routers.json
        # and by nothing else, so replaying without it loses the name of
        # the device most worth reading, and leaves its address out of the
        # candidates a short-source frame is identified from. DeviceNames
        # only reads; nothing here writes the file back (_save_border_routers
        # returns on ephemeral, and no browse runs offline).
        self.names = DeviceNames(cfg.devices_path, cfg.state_dir / "border-routers.json")
        self.seen = LastSeen(None if ephemeral else cfg.state_dir / "last-seen.json")
        self.detector = Detector(cfg.detector)
        # How often a storm that rumbles on is escalated to the event log,
        # which is what [detect] alert_cooldown_s documents itself as.
        # Taken once, here: the detector's own copy of the setting is
        # bookkeeping for alerts_sent and run_replay zeroes it so an
        # offline pass counts every storm in the day, which used to drop
        # this to the 60 s floor as well and make the same packets report
        # 37 storm events against the recorder's 2.
        self.storm_event_cooldown_s = max(60.0, cfg.detector.alert_cooldown_s)
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
        self._dominant: int | None = None
        self._update_dominant(None)
        self._pan_window: dict[int, int] = {}     # frames per source PAN since the window opened
        self._pan_window_start: float | None = None
        self._pan_silent_evt = 0.0
        self._foreign_reported: set[int] = set()
        self._last_src_by_pan: dict[int, str | None] = {}
        # All three are fed straight from mDNS answers, which anyone on the
        # LAN can forge in any number, so each is bounded (PENDING_MAX,
        # LOGGED_MAX): a LAN has a handful of border routers, not hundreds.
        self._unheard_logged: set[str] = set()      # mDNS addresses never heard on air, complained about once
        self._stale_logged: set[tuple] = set()      # (hostname, address) stale mDNS answers, complained about once
        self._conflict_logged: set[tuple] = set()   # (hostname, address) claims on another entry's device, said once
        self._pending_routers: dict[str, dict] = {}  # ext -> the mDNS record waiting for that address to be heard
        self.partition: tuple | None = None
        self._crypto_mark = (0, 0)          # (decrypted, failed) when decryption last worked
        self._stale_evt = 0.0
        # Border routers on the LAN: hostname -> current address (mDNS).
        self.routers_path = cfg.state_dir / "border-routers.json"
        self.routers: dict[str, dict] = {} if ephemeral else load_border_routers(self.routers_path)
        self._browse_thread = None
        self._browse_result: list | None = None
        self._next_browse = 0.0
        self.last_frame: Frame | None = None
        self._last_who: str | None = None
        # The address the last frame ingested was attributed to and that it
        # also vouched for (see ingest). Attribution alone is 64 bits the
        # sender asserts; this is the frame the pipeline counted.
        self.last_sighting: str | None = None
        # The MLE message the last frame carried, if it carried one, as
        # (info, fresh): fresh means secured and its counter ahead of the
        # last accepted, which is what _apply_mle acts on. Read by
        # `device`, so a report decodes no frame a second time - decoding
        # it again bound the short address the message asserts without
        # this check, and a replayed message then moved an address the
        # pipeline had refused to move.
        self.last_mle: tuple | None = None
        self.beacon_times = deque(maxlen=16)
        self._join_scan_evt = 0.0
        self.dup_recent = {}                    # (src, seq, pan) -> ts
        self.retrans_counts = deque(maxlen=30)  # per-window (dups, frames)
        self._win_dups = 0
        self._win_frames = 0
        self._win_dup_by: dict[tuple, int] = {}  # (sender identity, dst) -> dups this window
        self._win_start = 0.0
        self._retrans_alerted = 0.0             # last opening record (notice, or the page with confirm_s = 0)
        self._retrans_paged = 0.0               # last confirmed page
        # The elevation in progress, if any: when its first elevated minute
        # began, the baseline frozen then, sub-threshold minutes since the
        # last elevated one, and whether it has paged.
        self._retrans_since: float | None = None
        self._retrans_base = 0.0
        self._retrans_lull = 0
        self._retrans_confirmed = False
        self._retrans_up = 0.0                  # close of the last elevated minute
        # All of the above persist (retransmissions.json) and come back at
        # the next start. Without them a restart in the middle of an
        # elevation made the elevated rate the whole baseline: the first
        # minute's rate is the median of a history of one, twice that is
        # never reached, and the same rate a minute later, however high,
        # was normal for the rest of the elevation. The close of the last
        # window before the restart is kept so the first window after it
        # can subtract the unobserved gap from the elevation's age.
        self.retrans_path = cfg.state_dir / "retransmissions.json"
        self._retrans_closed: float | None = None
        if not ephemeral:
            self._load_retrans()
        # The storm detector as the last run left it, for the same reason
        # the retransmission detector is kept: a restart in the middle of
        # a storm otherwise starts blind. The detector needs six windows
        # before it will call anything a flood and period_onsets fresh
        # onsets before it will call it a storm - about five minutes of a
        # storm that is still running - and a reset last_alert lets the
        # same storm page again inside its own cooldown.
        self.storm_path = cfg.state_dir / "storm.json"
        self._storm_evt = 0.0                   # last phase_locked_storm event
        if not ephemeral:
            self._load_storm()
        self.quiet_reported: set[str] = set()
        # Hour bucket -> frames, last ~25 h, for the daily summary's frame
        # count. Persisted (frames-by-hour.json) so a summary sent soon
        # after a restart still counts the whole day, not just this run.
        self.frames_by_hour_path = cfg.state_dir / "frames-by-hour.json"
        self._frames_by_hour: dict[int, int] = {} if ephemeral else self._load_frames_by_hour()
        if not ephemeral:
            # A copy the last run did not finish (os._exit unwinds no
            # thread) is a half copy nothing marks as such: discard it and
            # say so, and let the cooldown below see only whole snapshots,
            # so the storm still running gets its snapshot.
            from .snapshot import discard_partials
            for label in discard_partials(cfg.snapshots_dir):
                # events.emit, not _emit: this is the snapshot path reporting
                # on itself, and self.snapshotter is not set until below.
                self.events.emit("snapshot_failed", "warning", time.time(), label=label,
                                 note=(f"the copy for {label} was cut short when the recorder last stopped; "
                                       "the half copy was discarded, and the next storm event tries again"))
        self._last_auto_snapshot = 0.0 if ephemeral else self._last_auto_snapshot_on_disk()
        if not ephemeral and cfg.border_router_browse_s > 0:
            # Imported here rather than at the first browse, minutes in. A
            # deploy rsyncs each changed file into place, giving the path a
            # new inode while this process keeps the old one only for what
            # it has already loaded, so a module first imported after a
            # push-to-host --push-only is the new code loading into an old
            # process. Everything else the pipeline reaches lazily (snapshot,
            # review, crypto) is already loaded by the time a run is up;
            # this was the one that was not.
            from . import mdns  # noqa: F401  (warmed, used in _poll_border_routers)
        # How a critical event saves the ring: in the background, so the
        # copy (gigabytes on a Pi) never stalls capture. Tests swap it.
        self.snapshotter = self._snapshot_in_background
        self._summary_day: str | None = None      # local day whose summary is settled
        self._pruned_day: str | None = None       # local day the event log was last pruned on
        self._capped_at: float | None = None      # when rows were last dropped to stay under TRACK_MAX
        # The highest frame counter accepted from each device, MAC and MLE,
        # with when, per key generation (see _verify and _counter_advances);
        # seeded from the rows so a restart does not take a replay of
        # yesterday's frames for the device. A row written before generations
        # were recorded seeds the None generation, which the first frame
        # after the restart is judged against and which then gives way.
        self._mac_counter: dict[str, dict[int | None, tuple[int, float]]] = {}
        self._mle_counter: dict[str, dict[int | None, tuple[int, float]]] = {}
        for addr, row in self.seen.table.items():
            for key, table in (("counter", self._mac_counter), ("mle_counter", self._mle_counter)):
                gens = {}
                if isinstance(row.get(key), int) and not isinstance(row.get(key), bool):
                    gens[_whole(row.get(key + "_seq"))] = (row[key], _seconds(row.get(key + "_ts")))
                prev = row.get(key + "_prev")
                if isinstance(prev, list) and len(prev) == 3 and isinstance(prev[0], int) \
                        and not isinstance(prev[0], bool) and _whole(prev[2]) is not None:
                    gens.setdefault(_whole(prev[2]), (prev[0], _seconds(prev[1])))
                if gens:
                    table[addr] = gens
        self.replayed = 0                            # frames refused as replays this run
        self._replay_said: dict[str, float] = {}     # addr -> when its replays were last mentioned
        self._counter_was_retry = False              # last counter decision was a retry (see _counter_advances)
        self._resolve_after: dict[str, float] = {}   # short addr -> next attempt ts
        self._resolve_fails: dict[str, int] = {}     # short addr -> searches that found nobody, in a row
        self._resolve_tokens = float(self.RESOLVE_TRIALS_BURST)   # candidate trials in hand (see identity)
        self._resolve_tokens_ts: float | None = None
        self._candidates_built: float | None = None
        self._candidates: list[str] = []
        self._verify_after: dict[str, float] = {}    # short addr -> next re-check of its mapping
        self._foreign_after: dict[tuple, float] = {}  # (short addr, other PAN) -> next MIC check against it
        self.extra_candidates: list[str] = []        # ext addrs to try first in the nonce search (device)
        self.mle_names_path = cfg.state_dir / "observed-names.json"
        self.observed_names = {}
        if not ephemeral and self.mle_names_path.exists():
            try:
                loaded = json.loads(self.mle_names_path.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                print(f"[threadwatch] {self.mle_names_path.name} is unreadable ({exc}): the SRP hostnames "
                      "harvested from the mesh are forgotten and re-learned as devices re-register",
                      file=sys.stderr, flush=True)
                loaded = {}
            # Owners map to {name: count}; any other shape would raise at
            # the first name observed, in the capture loop. Only owners the
            # device table still holds are kept: names are harvested for a
            # tracked device, `devices --suggest` reads them for one, and a
            # file written before the owners were bounded must not carry
            # the growth back in.
            self.observed_names = {k: v for k, v in loaded.items()
                                   if isinstance(v, dict) and k in self.seen.table} \
                if isinstance(loaded, dict) else {}
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
        # Persisted (blind-spans.json): a span is needed for as long as a
        # silence reaches back over it, and a run only knows the gap it
        # started with. Kept in memory alone, the outage before the last
        # start was forgotten at the next one as soon as any device had
        # advanced the last frame, and a device unheard since before that
        # outage was charged for it in full.
        self._blind: list[tuple[float, float]] = []
        self.blind_path = cfg.state_dir / "blind-spans.json"
        self._wall, self._mono = time.time, time.monotonic   # swapped by tests
        self._clock = (self._wall(), self._mono())
        if not ephemeral:
            now = self._clock[0]
            self._blind = self._load_blind()
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
                    stats = self.devices.setdefault(addr, DeviceStats())
                    stats.starved = True
                    stats.confirm_at = row.get("starve_confirm_at")
            last_alive = self._last_frame_heard()
            if last_alive is not None:
                # A span an earlier start recorded from this same last frame
                # (the watchdog restart loop) lies inside this one.
                self._blind = [span for span in self._blind if span[0] < last_alive]
                self._blind.append((last_alive, now - last_alive))
            self._announce_start(now, last_alive)
            dominant = self.dominant_pan()       # best guess before any frame arrives
            announced = 0
            for addr, row in self.seen.table.items():
                if row.get("rotated_to"):
                    continue          # an Apple hub's old address: retired, not quiet
                if self.silence_s(row, now) <= self.quiet_threshold_s(addr):
                    row.pop("quiet_reported_ts", None)
                    if row.pop("quiet_reported", None):
                        # Heard again after its announced silence, but the
                        # recorder died before saying so: close the silence
                        # at the moment it was actually heard.
                        self._emit("device_returned", "notice", row["last_seen"],
                                   addr=addr, name=self.names.name(addr))
                        announced += 1
                    continue
                if row.get("quiet_reported"):
                    # The flag is saved before the event is appended, so a
                    # run killed between the two left a silence flagged as
                    # announced that nobody was told about. The flag names
                    # the record it stands for; a flag without its record
                    # is announced now.
                    stamp = row.get("quiet_reported_ts")
                    if stamp is None or self.events.on_record("device_quiet", stamp, addr):
                        self.quiet_reported.add(addr)
                        continue
                    row.pop("quiet_reported", None)
                    row.pop("quiet_reported_ts", None)
                if dominant is None or row.get("pan") in (None, dominant):
                    self._report_quiet(addr, row, now, persist=False)
                    announced += 1
            if announced:
                self.seen.save()
            self._save_blind()

    BLIND_MAX = 64

    # Retired border-router addresses kept per host. Every rotation used
    # to append and nothing pruned, and each entry feeds
    # DeviceNames.by_addr and the device history, where it multiplies a
    # full-history scan. An Apple hub rotates on reboot, so this is years
    # of them; what is dropped is only the name on an address nothing has
    # heard in that long.
    ROUTER_PREVIOUS_MAX = 32

    # The note record.record_exit leaves about how the last run ended.
    EXIT_FILE = "last-exit.json"
    # How a start describes the end of the run before it, by the reason
    # the note carries; a note-less end (power cut, SIGKILL, a run that
    # could not write one) is "unknown".
    ENDED = {"stopped": "the last run was stopped",
             "stalled": "the last run left when no frames arrived for 3 min (stalled)",
             "sniffer_died": "the last run left when its sniffer thread died",
             "stream_ended": "the last run left when the capture stream ended (dongle unplugged?)",
             "crashed": "the last run crashed",
             "cleanup_failed": "the last run ended as asked but could not put all of it away "
                               "(see its journal: the ring, the last-seen table)",
             "unknown": "the last run left no note of how it ended (power cut, or killed)"}

    def _announce_start(self, now: float, last_alive: float | None) -> None:
        """One record per start: how long the recorder was not listening
        (since the last frame any run heard) and why the last run ended,
        read from the note it left (record.record_exit) and removed here,
        so the next start cannot read this run's end off the one before.
        The review's coverage is built from these records, together with
        the clock steps: they are what tells a recorder outage from a
        device's silence on a day page. Info for a stop that was asked
        for and for the first start ever; notice when the last run ended
        any other way, since a restart the supervisor had to make is
        worth a line on the phone (a restart loop is digested by the
        sinks' cooldown)."""
        path = self.cfg.state_dir / self.EXIT_FILE
        ended = None
        try:
            ended = json.loads(path.read_text())
        except (OSError, ValueError):
            pass
        try:
            path.unlink()
        except OSError:
            pass
        if not isinstance(ended, dict):
            ended = {}
        reason = ended.get("reason")
        cause = reason if isinstance(reason, str) and reason else "unknown"
        stopped = ended.get("ts")
        if not isinstance(stopped, (int, float)) or isinstance(stopped, bool):
            stopped = None
        if last_alive is None:
            gap = None
            if not ended:
                cause = "first_start"
        else:
            gap = max(0.0, now - last_alive)
            # A note stamped before the last frame, or after now (a clock
            # that stepped back across the restart), says nothing usable
            # about when the run ended.
            if stopped is not None and not last_alive <= stopped <= now:
                stopped = None
        if cause == "first_start":
            note = "first start: no earlier frame on record"
        else:
            ended_how = self.ENDED.get(cause, f"the last run ended with {cause}")
            if gap is None:
                note = f"{ended_how}; no frame on record before this start"
            else:
                off = "" if stopped is None else f", off for {round((now - stopped) / 60)} min"
                note = (f"not listening for {round(gap / 60)} min since the last frame at "
                        f"{time.strftime('%H:%M', time.localtime(last_alive))}{off}; {ended_how}")
        severity = "info" if cause in ("stopped", "first_start") else "notice"
        self._emit("recorder_started", severity, now, cause=cause, gap_s=None if gap is None else round(gap),
                   last_frame_ts=last_alive, stopped_ts=stopped, exit_code=ended.get("code"), note=note)

    def _load_blind(self) -> list[tuple[float, float]]:
        try:
            raw = json.loads(self.blind_path.read_text())
            return [(float(since), float(length)) for since, length in raw][-self.BLIND_MAX:]
        except FileNotFoundError:
            return []                   # the first run, or nothing missed yet
        except (OSError, ValueError, TypeError) as exc:
            # Losing this file silently recreates the bug it was added to
            # fix, quoted in its own comment: a device unheard since
            # before an outage is charged for it in full, so a long-silent
            # mesh pages device_quiet for every device at once with
            # nothing saying why. Said as LastSeen says it, and doctor
            # reports the file too.
            print(f"[threadwatch] {self.blind_path.name} is unreadable ({exc}): the recorder does not know "
                  "when it was last off, so a silence that spans one of its own outages is charged to the "
                  "device in full", file=sys.stderr, flush=True)
            return []

    def _save_blind(self) -> None:
        """Write the blind spans, less those no silence reaches back over
        (every row was heard after them) and beyond the newest BLIND_MAX."""
        if self.ephemeral:
            return
        stamps = [row.get("last_seen") for row in self.seen.table.values()]
        stamps = [t for t in stamps if isinstance(t, (int, float))]
        oldest = min(stamps) if stamps else None
        keep = [span for span in self._blind if oldest is None or span[0] >= oldest][-self.BLIND_MAX:]
        tmp = self.blind_path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(keep))
            tmp.replace(self.blind_path)
        except OSError as exc:
            print(f"[threadwatch] {self.blind_path.name} not written: {exc}", file=sys.stderr, flush=True)

    def _load_retrans(self) -> None:
        """The retransmission detector as the last run left it (_save_retrans).
        An unreadable file starts it afresh, as before the file existed."""
        try:
            raw = json.loads(self.retrans_path.read_text())
            rates = [float(r) for r in raw["rates"]][-self.retrans_counts.maxlen:]
            since = raw.get("since")
            state = (None if since is None else float(since), float(raw.get("base") or 0.0),
                     int(raw.get("lull") or 0), bool(raw.get("confirmed")),
                     float(raw.get("alerted") or 0.0), float(raw.get("paged") or 0.0), float(raw["closed"]),
                     float(raw.get("up") or 0.0))
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            return
        self.retrans_counts.extend(rates)
        (self._retrans_since, self._retrans_base, self._retrans_lull, self._retrans_confirmed,
         self._retrans_alerted, self._retrans_paged, self._retrans_closed, self._retrans_up) = state

    def _save_retrans(self, closed: float) -> None:
        tmp = self.retrans_path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps({
                "closed": closed, "rates": list(self.retrans_counts), "since": self._retrans_since,
                "base": self._retrans_base, "lull": self._retrans_lull, "confirmed": self._retrans_confirmed,
                "alerted": self._retrans_alerted, "paged": self._retrans_paged, "up": self._retrans_up}))
            tmp.replace(self.retrans_path)
        except OSError as exc:
            print(f"[threadwatch] {self.retrans_path.name} not written: {exc}", file=sys.stderr, flush=True)

    def _load_storm(self) -> None:
        """The storm detector as the last run left it (_save_storm). An
        unreadable file starts it afresh, as before the file existed.

        Nothing here needs ageing for the time the recorder was down:
        add_frame closes one empty window per window_seconds up to the
        history's length, so a long outage flushes the baseline and the
        storm ends on its own three-period timeout, while a quick restart
        keeps both.
        """
        try:
            raw = json.loads(self.storm_path.read_text())
            d = self.detector
            counts = [int(c) for c in raw["counts"]][-d.counts.maxlen:]
            calm = [int(c) for c in raw["calm"]][-d.calm.maxlen:]
            onsets = [float(o) for o in raw["onsets"]][-d.onsets.maxlen:]
            last_alert = raw.get("last_alert")
            state = (float(raw["last_flood"]), float(raw["window_start"]), int(raw["window_count"]),
                     bool(raw["in_flood"]), None if last_alert is None else float(last_alert),
                     int(raw["alerts_sent"]), bool(raw["storm_active"]),
                     dict(raw.get("storm_details") or {}), float(raw.get("storm_evt") or 0.0))
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            return
        d.counts.extend(counts)
        d.calm.extend(calm)
        d.onsets.extend(onsets)
        (d.last_flood, d.window_start, d.window_count, d.in_flood, d.last_alert,
         d.alerts_sent, d.storm_active, d.storm_details, self._storm_evt) = state

    def _save_storm(self) -> None:
        d = self.detector
        tmp = self.storm_path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps({
                "counts": list(d.counts), "calm": list(d.calm), "onsets": list(d.onsets),
                "last_flood": d.last_flood, "window_start": d.window_start,
                "window_count": d.window_count, "in_flood": d.in_flood,
                "last_alert": d.last_alert, "alerts_sent": d.alerts_sent,
                "storm_active": d.storm_active, "storm_details": d.storm_details,
                "storm_evt": self._storm_evt}))
            tmp.replace(self.storm_path)
        except OSError as exc:
            print(f"[threadwatch] {self.storm_path.name} not written: {exc}", file=sys.stderr, flush=True)

    def _load_frames_by_hour(self) -> dict[int, int]:
        try:
            raw = json.loads(self.frames_by_hour_path.read_text())
            newest = max(int(b) for b in raw)
            return {int(b): int(n) for b, n in raw.items() if int(b) >= newest - 25}
        except (OSError, ValueError, TypeError, AttributeError):    # unreadable, or not an object of counts
            return {}

    def _save_frames_by_hour(self) -> None:
        tmp = self.frames_by_hour_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({str(b): n for b, n in self._frames_by_hour.items()}))
        tmp.replace(self.frames_by_hour_path)

    def _last_auto_snapshot_on_disk(self) -> float:
        """When the newest automatic snapshot was saved, so the cooldown holds
        across a restart: a daemon that comes back mid-storm must not copy
        the whole ring (gigabytes) a second time and fill the card.

        Which snapshots are automatic is the manifest trigger's to say, as it
        is for retention (snapshot.is_auto_snapshot). Reading it off the
        "auto-" label instead meant `threadwatch snapshot auto-investigation`,
        a perfectly good name, started the next restart inside a six-hour
        cooldown and let a real storm go unpreserved."""
        from .review import snapshots
        from .snapshot import is_auto_snapshot
        try:
            for inc in snapshots(self.cfg.snapshots_dir):      # newest first
                if is_auto_snapshot(self.cfg.snapshots_dir / inc["name"]):
                    return float(inc["saved"])
        except OSError:
            pass
        return 0.0

    def _last_frame_heard(self) -> float | None:
        """When a previous run last heard a frame: the stamp status.json
        carries across runs (record.last_frame_on_record), or the newest
        last_seen in the table. Both stand still while nothing is heard.
        The status file's write time and the table's save time do not: a
        run that hears nothing still writes both before the watchdog
        restarts it, so judging by them credits a two-hour outage as the
        three minutes of the last restart and pages for every device."""
        stamps = []
        try:
            st = json.loads((self.cfg.state_dir / "status.json").read_text())
            if not isinstance(st, dict):
                raise ValueError(f"expected an object, got {type(st).__name__}")
            if st.get("last_frame_ts") is not None:
                stamps.append(float(st["last_frame_ts"]))
        except OSError:
            pass                        # no run has written one yet
        except (ValueError, TypeError) as exc:
            # Valid JSON of the wrong shape parsed fine and raised
            # AttributeError at the .get, which nothing caught: the
            # recorder could not start, and the traceback did not say
            # which file. Named here, and the table stands in for it.
            print(f"[threadwatch] status.json is unreadable ({exc}): when the last run last heard a "
                  "frame is taken from last-seen.json instead", file=sys.stderr, flush=True)
        stamps.extend(row["last_seen"] for row in self.seen.table.values() if row.get("last_seen") is not None)
        return max(stamps) if stamps else None

    def silence_s(self, row: dict, now: float) -> float:
        """How long the recorder has actually heard nothing from a device."""
        silent = now - row["last_seen"]
        blind = sum(length for since, length in self._blind if row["last_seen"] <= since)
        return silent - max(0.0, blind)

    def _identity_silence_s(self, addr: str, row: dict, now: float) -> float:
        """Silence across every address the device's inventory entry lists.

        The documented rotation workflow -- `name <new-address>
        <existing-name>` -- adds an address to an existing entry, but the
        quiet check ran on each address alone, so the entry's older address
        crossed its threshold and paged while the device was sending
        authenticated traffic from the newer one. Only the mDNS path sets
        rotated_to; a rotation entered by hand had nothing to say it.

        The entry's own list, not names.addresses_of: a device is not
        inferred from a shared name here, because that would let one device's
        traffic keep an unrelated one from ever being reported quiet.
        """
        silence = self.silence_s(row, now)
        for other in self.names.entry_addresses_of(addr)[1:]:
            sibling = self.seen.table.get(other)
            if sibling is not None and "last_seen" in sibling:
                silence = min(silence, self.silence_s(sibling, now))
        return silence

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
        to everything heard before it.

        A step back (a host that booted ahead of time, corrected while
        recording) leaves every stamp taken before it the whole step ahead
        of the clock, and a silence has to make the step up before it
        counts: the quiet alert came a step late. Blindness cannot say
        that (its sum is clamped at zero, and stamps from either side of
        the step overlap), so the stamps are moved instead (_rewind)."""
        wall, mono = self._wall(), self._mono()
        step = (wall - self._clock[0]) - (mono - self._clock[1])
        since_check = mono - self._clock[1]
        self._clock = (wall, mono)
        if abs(step) < self.CLOCK_STEP_MIN_S:
            return
        if step > 0:
            self._blind.append((wall - step, step))
            self._save_blind()
            self._emit("clock_step", "info", now, step_s=round(step),
                       note=(f"the host clock jumped forward {round(step / 60)} min (NTP after boot?); "
                             "silences that span the jump are not counted against any device"))
            return
        self._rewind(wall, -step, since_check)
        self._emit("clock_step", "info", now, step_s=round(step),
                   note=(f"the host clock jumped back {round(-step / 60)} min (NTP correcting a clock that "
                         "ran ahead?); every stamp taken before the jump was moved back with it, so "
                         "silences are counted as heard"))

    # The stamps a last-seen row carries on the wall clock. quiet_reported_ts
    # is deliberately not one of them: it is not a measurement but a pointer
    # at an appended device_quiet record, which the step does not move. Moving
    # the pointer alone makes the start-up reconciliation miss the record,
    # discard the flag, and page the same unbroken silence a second time.
    ROW_STAMPS = ("first_seen", "last_seen", "rloc16_ts", "rssi_heard_ts", "rssi_ref_ts",
                  "starve_confirm_at")
    STATS_STAMPS = ("last_poll_ts", "ack_pending_ts", "poll_pending_ts", "unanswered_since", "confirm_at")

    def _rewind(self, now: float, back: float, since_check: float) -> None:
        """Move every stamp taken before a backward step of ``back`` seconds
        back with the clock: last-seen rows, blindness, the retransmission
        elevation and its cooldowns, the per-device poll state, every
        pipeline cooldown and deadline, and when the last-seen table was
        last written. A stamp is
        from before the step when it is later than now, or older than the
        last check: a frame stamped by the corrected clock is at most
        ``since_check`` old. The stamps in between are left where they
        are: a device last heard in that band about ``back`` before the
        step keeps its silence short by the step until it is heard again,
        rather than a device heard since being charged the whole step."""
        def before(t) -> bool:
            return isinstance(t, (int, float)) and not isinstance(t, bool) and (t > now or t < now - since_check)

        for row in self.seen.table.values():
            for key in self.ROW_STAMPS:
                if before(row.get(key)):
                    row[key] -= back
        self.seen._dirty = True
        self._blind = [(since - back if before(since) else since, length) for since, length in self._blind]
        self._save_blind()
        for stats in self.devices.values():
            for attr in self.STATS_STAMPS:
                t = getattr(stats, attr)
                if t and before(t):
                    setattr(stats, attr, t - back)
        # Every wall-clock scalar the pipeline compares against, whether it
        # is a stamp ("when this last happened") or a deadline ("not before
        # this"). Each is read as `now < stamp` or `now - stamp < window`,
        # so one left the step ahead of the clock suppresses its check for
        # the whole length of the step: no mDNS browse, so a hub that
        # rotates its address in the window keeps the dead one and then
        # reads as quiet; no ring snapshot for a critical event; no
        # configured_pan_silent; join-scan, stale-credential and storm
        # notices all held back.
        for attr in ("_retrans_since", "_retrans_alerted", "_retrans_paged", "_retrans_up", "_retrans_closed",
                     "_win_start", "_next_browse", "_join_scan_evt", "_stale_evt", "_pan_silent_evt",
                     "_pan_window_start", "_last_auto_snapshot", "_storm_evt"):
            t = getattr(self, attr)
            if t and before(t):
                setattr(self, attr, t - back)
        # The per-short-address retry deadlines, same test: left in the
        # future, an unresolved address is not retried until the clock
        # climbs back and its frames stay unattributed until then.
        for deadlines in (self._resolve_after, self._verify_after, self._foreign_after):
            for key, t in list(deadlines.items()):
                if before(t):
                    deadlines[key] = t - back
        # maybe_save writes the last-seen table at most once a minute; with
        # its stamp a step ahead it stops writing until the clock catches
        # up, and a host cut in that window loses everything since.
        if before(self.seen._last_save):
            self.seen._last_save -= back
        # The duplicate window is two seconds wide, so there is nothing in
        # it worth moving: dropping it costs at most one window of genuine
        # retransmission detection, and keeps stamps from before the step
        # out of the comparison entirely.
        self.dup_recent.clear()

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

    def dominant_pan(self) -> int | None:
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
        self._emit("configured_pan_silent", "warning", now, pan=f"0x{self.cfg.pan_id:04x}",
                   heard_frames=others, window_s=self.PAN_SILENT_WINDOW_S,
                   busiest_pan=None if busiest is None else f"0x{busiest:04x}",
                   note=(f"no frame on PAN 0x{self.cfg.pan_id:04x} ([network] pan_id) in the last "
                         f"{self.PAN_SILENT_WINDOW_S // 60} min while {others} were heard on other PANs. "
                         "If the network was re-commissioned or migrated, every device now counts as "
                         "foreign and none is judged: threadwatch import prints the dataset's PAN; "
                         "update pan_id and restart."))

    def _update_dominant(self, ts: float | None) -> None:
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
                  "set [network] pan_id in config.toml if that is wrong", file=sys.stderr, flush=True)
            return
        self._emit("dominant_pan_changed", "notice" if prev is None else "warning", ts,
                   pan=f"0x{leader:04x}", previous=None if prev is None else f"0x{prev:04x}",
                   frames=n,
                   note=(f"PAN 0x{leader:04x} is now taken for this network's"
                         + ("" if prev is None else f", instead of 0x{prev:04x}")
                         + f": it has sent the most frames ({n}). Quiet checks and foreign-PAN notices "
                           "follow it. If it is a neighbour's network, set [network] pan_id in "
                           "config.toml and restart."))

    # ---------------------------------------------------------- tracking

    # An extended source address is 64 bits the sender asserts, and every
    # new one used to become a row in the last-seen table and a DeviceStats
    # for ever: a transmitter in range sending from a fresh address per
    # frame (a broken address generator, or someone doing it on purpose)
    # grew both without bound, at a couple of KB of RAM and a rewrite of
    # last-seen.json per address, until the Pi ran out of memory. A mesh
    # has tens of devices, a busy street of neighbours a few hundred; at
    # this many rows the least-heard unnamed ones make room.
    TRACK_MAX = 2000
    CAP_NOTE_S = 3600.0        # one warning per hour while addresses keep coming

    def _admit(self, addr: str, ts: float) -> bool:
        """Room for a row for ``addr``, dropping the addresses least worth
        keeping when the table is full: not in the inventory or bound to a
        border router, not holding a short address (a MIC has vouched for
        those), not a hub's retired address; the fewest frames and the
        oldest sighting first, half of them at a time so the sort is paid
        once per thousand new addresses, not once per frame."""
        if len(self.seen.table) < self.TRACK_MAX:
            return True
        vouched = set(self.decryptor.short_to_ext.values())
        evictable = sorted((row.get("frames") or 0, row.get("last_seen") or 0.0, a)
                           for a, row in self.seen.table.items()
                           if a not in vouched and a not in self.names.by_addr and not row.get("rotated_to"))
        if not evictable:
            return False
        dropped = evictable[:max(1, len(evictable) // 2)]
        for _frames, _last, a in dropped:
            self._forget(a)
        if self._capped_at is None or ts - self._capped_at >= self.CAP_NOTE_S:
            self._emit("address_flood", "warning", ts, dropped=len(dropped), kept=len(self.seen.table),
                       note=(f"{len(dropped)} addresses heard once or twice were dropped from the "
                             f"device table to keep it at {self.TRACK_MAX} rows: something in range "
                             "is transmitting from ever-new extended addresses. Named devices and "
                             "devices holding a short address are kept; new addresses are not "
                             "announced one by one while this goes on."))
        self._capped_at = ts
        return True

    def _forget(self, addr: str) -> None:
        del self.seen.table[addr]
        self.seen._dirty = True
        self.devices.pop(addr, None)
        self.quiet_reported.discard(addr)
        self._pending_routers.pop(addr, None)
        # The names harvested for it go too: kept, they would outlive the
        # row in observed-names.json and be suggested for an address the
        # recorder no longer tracks.
        self.observed_names.pop(addr, None)

    def _flooded(self, ts: float) -> bool:
        return self._capped_at is not None and ts - self._capped_at < self.CAP_NOTE_S

    # ------------------------------------------------------- authenticity

    # A MAC retry carries the frame unchanged, counter and all, within
    # milliseconds of the first copy; the same counter this long after the
    # first accepted copy is a replay.
    RETRY_WINDOW_S = 2.0

    def _verify(self, f: Frame, who: str | None) -> tuple[bytes | None, bool]:
        """Does this frame vouch for its sender? An extended address is
        64 bits the sender asserts, so a frame counts as a sighting of
        the device only when the MIC says the sender holds the network
        key and used that address as its nonce, and the frame counter is
        above the last accepted, so a recording of the device played back
        after it died does not keep it "heard". Returns the MAC payload
        (decrypted, or the plaintext of an unsecured frame) for the
        credentialed layer, and whether the MAC layer vouched. An
        unsecured frame vouches for nothing here; a secured MLE message
        inside one may (ingest asks _deep_inspect)."""
        self._counter_was_retry = False      # cleared here too: _verify has early returns
        if not who or not f.psdu:
            return None, False
        plain, counter, sequence = self.decryptor.decrypt_frame_counter(f.psdu, who, None)
        if counter is None:
            return plain, False
        return plain, self._counter_advances(self._mac_counter, who, counter, f.ts, "frame", sequence)

    # A frame counter only means anything within the key generation it was
    # authenticated under: the network rotates its key and every device
    # restarts both its MAC and its MLE counter at zero (OpenThread's
    # SetCurrentKeySequence does exactly that). Comparing across the
    # rotation refused every frame a healthy device sent under the new key
    # until its counter climbed past the old one's, which on a device with
    # a long-lived counter is days of silence that never happened. Two
    # generations are kept per device: the newest heard, and the one before
    # it, which a device that has not rotated yet is still sending under.
    KEEP_GENERATIONS = 2

    def _counter_advances(self, table: dict, who: str, counter: int, ts: float, what: str,
                          sequence: int | None) -> bool:
        # Set for the caller that has just asked, and read straight after.
        self._counter_was_retry = False
        gens = table.setdefault(who, {})
        if sequence is None:
            # Nothing said which generation authenticated this one. Judge it
            # against the newest known rather than opening a bucket that
            # sorts against none of them.
            sequence = max((g for g in gens if g is not None), default=None)
        last = gens.get(sequence)
        if last is None:
            # A counter seeded from a state file written before generations
            # were recorded. It judges the first frame after that restart,
            # and then gives way whichever way that frame goes: a device
            # whose key rotated while the recorder was down must not stay
            # refused for ever on the strength of a counter nothing can
            # place.
            last = gens.pop(None, None)
        if last is None:
            if gens and sequence is not None and sequence < min(g for g in gens if g is not None):
                self._say_replay(who, ts, f"a secured {what} under key generation {sequence}, older than any "
                                          f"this device has been heard under ({min(gens)}), is not counted as "
                                          "a sighting: a recording from before the network rotated its key")
                return False
            return self._accept_counter(gens, sequence, counter, ts)
        if counter > last[0]:
            return self._accept_counter(gens, sequence, counter, ts)
        if counter == last[0] and 0.0 <= ts - last[1] < self.RETRY_WINDOW_S:
            # A MAC retry of the copy just accepted. It is the same sighting
            # of a live device, so it still counts as one -- but it is not a
            # second message, and anything counting independent evidence has
            # to know the difference (see _note_observed_name).
            self._counter_was_retry = True
            return True
        self._say_replay(who, ts, f"a secured {what} with counter {counter} at or below the last accepted "
                                  f"({last[0]}) under key generation {sequence} is not counted as a sighting: "
                                  "a replay of an earlier frame, or the device's counter went backwards")
        return False

    def _accept_counter(self, gens: dict, sequence: int | None, counter: int, ts: float) -> bool:
        """Record the counter as the highest accepted in its generation, and
        forget every generation but the newest KEEP_GENERATIONS."""
        gens[sequence] = (counter, ts)
        for old in sorted(g for g in gens if g is not None)[:-self.KEEP_GENERATIONS]:
            del gens[old]
        return True

    def _say_replay(self, who: str, ts: float, note: str) -> None:
        """Count a refused frame and say why, once an hour per device."""
        self.replayed += 1
        if ts - self._replay_said.get(who, -1e12) >= 3600.0:
            self._replay_said[who] = ts
            print(f"[threadwatch] {self.names.name(who) or who}: {note} (said once an hour)",
                  file=sys.stderr, flush=True)

    # ---------------------------------------------------------- identity

    RESOLVE_RETRY_S = 30.0
    RESOLVE_RETRY_MAX_S = 1800.0      # the backoff on a short address nobody in the table sent from
    # Failures counted per short address, and so the largest doubling the
    # backoff ever computes. The cap above is applied to the result, but
    # the exponential was worked out first and the count grew without
    # limit: a device permanently unresolvable reached 2**1024 after about
    # three weeks of half-hourly retries, and converting that to a float
    # raised OverflowError out of ingest and took the recorder down.
    RESOLVE_FAILS_MAX = 16
    # The nonce search is the one thing in the capture loop whose cost the
    # sender chooses: every unmappable short source costs a MIC check per
    # candidate, up to sixteen AES-CCM operations each, and there are
    # 65,536 short addresses to send from. The candidates are the
    # addresses most heard on our PAN, this many at most, and the searches
    # draw on one budget of trials refilled at this rate: a start-up that
    # has the whole mesh to name spends the burst, a flood of forged short
    # sources is throttled to a fraction of a core, and the ring keeps up.
    RESOLVE_CANDIDATES_MAX = 256
    RESOLVE_TRIALS_PER_S = 500.0
    RESOLVE_TRIALS_BURST = 4000.0
    RESOLVE_CANDIDATES_CACHE_S = 5.0

    def _resolve_candidates(self, ts: float) -> list[str]:
        """The extended addresses worth trying as a short-source frame's
        nonce: the caller's (device), the inventory's, then the table's rows
        on our PAN by frames heard, so a forged address heard once never
        displaces a device; ranked again every few seconds, not per frame."""
        built = self._candidates_built
        if built is None or not 0.0 <= ts - built < self.RESOLVE_CANDIDATES_CACHE_S:
            dominant = self.dominant_pan()
            rows = [(row.get("frames") or 0, a) for a, row in self.seen.table.items()
                    if dominant is None or row.get("pan") in (None, dominant)]
            rows.sort(reverse=True)
            self._candidates = list(dict.fromkeys(
                [*self.extra_candidates, *self.names.by_addr, *(a for _n, a in rows[:self.RESOLVE_CANDIDATES_MAX])]))
            self._candidates_built = ts
        return self._candidates

    def _resolve_budget(self, ts: float) -> bool:
        """Refill the trial budget to now; True when a search may start."""
        last = self._resolve_tokens_ts
        if last is None or ts < last:
            last = ts
        self._resolve_tokens = min(self.RESOLVE_TRIALS_BURST,
                                   self._resolve_tokens + (ts - last) * self.RESOLVE_TRIALS_PER_S)
        self._resolve_tokens_ts = ts
        return self._resolve_tokens >= 1.0

    def identity(self, f: Frame) -> str | None:
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
            # A short address is unique within one PAN only. A frame from
            # another PAN bearing the short address one of our devices
            # holds is a neighbour's device until its MIC says otherwise:
            # taken on the cached mapping, it would stamp our device with
            # the foreign PAN (ending its quiet checks) and its frames and
            # signal. So the cooldown fast path below is not for it: the
            # MIC is checked, rate-limited per (address, PAN) so a busy
            # neighbour costs one attempt every RESOLVE_RETRY_S, and a
            # failure leaves the mapping alone (our device still holds the
            # address on our PAN) and the frame unattributed. A device that
            # really moved to that PAN passes the check, and its row's PAN
            # follows it.
            pan = f.src_pan if f.src_pan != BROADCAST_PAN else None
            known = self.seen.table.get(ext, {}).get("pan")
            if known is None:
                known = self.dominant_pan()
            if pan is not None and known is not None and pan != known:
                key = (src, pan)
                if f.ts < self._foreign_after.get(key, 0.0) or not self.decryptor.resolvable(f.psdu):
                    return None
                self._foreign_after[key] = f.ts + self.RESOLVE_RETRY_S
                return ext if self.decryptor.verify_short(f.psdu, ext) else None
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
        pan = f.src_pan if f.src_pan != BROADCAST_PAN else None
        dominant = self.dominant_pan()
        if pan is not None and dominant is not None and pan != dominant:
            return None          # a neighbour's device: our key cannot name it, and need not
        if not self._resolve_budget(f.ts):
            return None          # the budget is spent: this one waits, the ring does not
        fails = self._resolve_fails.get(src, 0)
        self._resolve_after[src] = f.ts + min(self.RESOLVE_RETRY_S * 2 ** min(fails, self.RESOLVE_FAILS_MAX),
                                              self.RESOLVE_RETRY_MAX_S)
        tried = self.decryptor.stats["short_candidates_tried"]
        ext = self.decryptor.resolve_short(f.psdu, src, self._resolve_candidates(f.ts))
        self._resolve_tokens -= self.decryptor.stats["short_candidates_tried"] - tried
        if ext is None:
            # Counted no further than the cap: past it the backoff is the
            # maximum either way, and the number is only ever an exponent.
            self._resolve_fails[src] = min(fails + 1, self.RESOLVE_FAILS_MAX)
        else:
            self._resolve_fails.pop(src, None)
        return ext

    # ------------------------------------------------------------ ingest

    def ingest(self, f: Frame) -> str | None:
        """Take one frame. Returns the extended address it was attributed
        to (identity), or None, so a caller walking a capture for one
        device (the command) can filter on the same answer without a second
        pass. Attribution is not the same as a sighting: a replayed or
        forged frame is attributed and refused. ``last_sighting`` holds the
        address when this frame also vouched for it, and None when it did
        not, so a caller can count what the pipeline counted."""
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

        # ACK pairing: an ACK within 50 ms bearing the pending seq. 0.0 <= as
        # the retry detector reads it: an ACK stamped before the frame it
        # answers is a backward clock step or an out-of-order import, not an
        # answer. Counting it inflated the ACK rate and cleared a pending poll.
        prev = self.last_frame
        if (f.ftype == 2 and prev is not None and prev.src
                and prev.seq == f.seq and 0.0 <= ts - prev.ts < 0.05):
            stats = self.devices.get(self._last_who or prev.src)
            if stats and stats.ack_pending_seq == f.seq:
                stats.acked += 1
                stats.ack_pending_seq = None
                if stats.poll_pending_seq == f.seq:
                    self._poll_answered(self._last_who or prev.src, stats, ts)
        self._last_who = who

        # Only a frame that vouches for its sender (_verify) feeds the row
        # and the stats below: the sender's liveness, signal and polls are
        # its own, not those of whatever put its address on the air.
        plain, live = self._verify(f, who)
        retry = self._counter_was_retry
        info, src_for_mle, names = (self._deep_inspect(f, plain) if f.ftype == 1 and plain is not None
                                    else (None, None, ()))
        # A secured MLE message vouches for the sender of the unsecured
        # frame that carries it, and only while its own counter says it is
        # not a recording. The check runs even when the MAC layer already
        # vouched: what the message asserts about the mesh - the sender's
        # short address, the partition, a rejoin - is only acted on when
        # the message itself is fresh.
        fresh_mle = False
        if who and info is not None and info.secured and info.counter is not None:
            fresh_mle = self._counter_advances(self._mle_counter, who, info.counter, ts, "MLE message",
                                               info.key_sequence)
            retry = retry or self._counter_was_retry
            live = live or fresh_mle
        if info is not None and info.secured and fresh_mle:
            self._apply_mle(f, info, src_for_mle)
        if who and live and who not in self.seen.table and not self._admit(who, ts):
            live = False        # every row is one worth keeping: this frame goes uncounted
        if who and live:
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
            if is_poll(f):
                if stats.last_poll_ts is not None:
                    stats.poll_intervals.append(ts - stats.last_poll_ts)
                stats.last_poll_ts = ts
                stats.polls += 1
                self._poll_sent(who, stats, f.seq, ts, f.dst)
            # Filed here rather than where they were read: harvesting from
            # MAC-unsecured plaintext let anything on the channel put an
            # owner in the table, forged name and all, without ever
            # reaching the admission that bounds the device table. Now a
            # name is only kept for a sender this frame vouched for and
            # that the table has room for.
            for name in names:
                self._note_observed_name(who, name, repeat=retry)
            was_new = who not in self.seen.table
            self.seen.touch(who, ts, f.ftype, pan=pan, rssi=f.rssi)
            row = self.seen.table[who]
            for key, table in (("counter", self._mac_counter), ("mle_counter", self._mle_counter)):
                gens = table.get(who)
                if not gens:
                    continue
                # The newest generation is the one a restart has to judge
                # the next frame against; its key sequence travels with it,
                # so a rotation while the recorder was down is not read as
                # a replay.
                newest, *older = sorted(gens, key=lambda s: (s is not None, s or 0), reverse=True)
                counter, counter_ts = gens[newest]
                if row.get(key) != counter or row.get(key + "_seq") != newest:
                    row[key], row[key + "_ts"], row[key + "_seq"] = counter, counter_ts, newest
                # The generation before it goes too, so a device still
                # sending under the old key after a rotation is judged
                # within that generation across a restart rather than
                # refused as older than anything on record.
                if older and older[0] is not None:
                    row[key + "_prev"] = [*gens[older[0]], older[0]]
                else:
                    row.pop(key + "_prev", None)
            if is_poll(f):
                # Polls by name for the review pages: the row's count of
                # type-3 frames takes in every MAC command, beacon requests
                # and all, and was labelled polls.
                row = self.seen.table[who]
                row["polls"] = row.get("polls", 0) + 1
            if self.seen.table[who].pop("rotated_to", None):
                # Retired as a hub's old address, yet on air: it is live,
                # whatever mDNS said, so its silences count again. A retired
                # row is skipped by every quiet check, so nothing else could
                # bring it back.
                print(f"[threadwatch] {self.names.name(who) or who} heard on air after its address was "
                      "retired: judged again", file=sys.stderr, flush=True)
            if len(f.src) == 4:
                self._note_rloc16(who, f.src, ts)
            pending = self._pending_routers.pop(who, None)
            if pending is not None:
                # A border router mDNS advertised before it was heard on air
                # (a rebooted hub, seen by the browse first): now that it is,
                # bind it, so the first_seen below already carries its name.
                self._apply_border_routers([pending], ts)
            if was_new and not self._flooded(ts):
                self._emit("device_first_seen", "info", ts, addr=who,
                           name=self.names.name(who))
            if who in self.quiet_reported:
                self.quiet_reported.discard(who)
                self.seen.table[who].pop("quiet_reported", None)
                self.seen.table[who].pop("quiet_reported_ts", None)
                self._emit("device_returned", "notice", ts, addr=who,
                           name=self.names.name(who))
                # Persist at once: a crash before the next 30 s save would
                # leave the row flagged and a restart would announce this
                # return a second time. Returns are rare, saves are cheap.
                self.seen.save()

        # Beacons, or beacon requests (an unsecured MAC command, id 7):
        # someone scanning to join. Thread itself discovers over MLE, so
        # these are Zigbee or factory-reset devices sweeping the channel.
        if f.ftype == 0 or (f.ftype == 3 and f.cmd == 7):
            if f.src and (f.src in self.devices or len(self.devices) < self.TRACK_MAX):
                self.devices.setdefault(f.src, DeviceStats()).beacons += 1
            self.beacon_times.append(ts)
            recent = [t for t in self.beacon_times if ts - t <= 60]
            if len(recent) >= 5 and ts - self._join_scan_evt > 300:
                self._join_scan_evt = ts
                self._emit("join_scan_activity", "notice", ts,
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
                for other, n in self.own_pans.items():       # not `pan`: the frame's own PAN is read below
                    if other != dominant and 3 <= n < lead and other not in self._foreign_reported:
                        self._foreign_reported.add(other)
                        self._emit("possible_foreign_pan", "notice", ts,
                                   pan=f"0x{other:04x}", src=self._last_src_by_pan.get(other),
                                   dominant_pan=f"0x{dominant:04x}",
                                   note="repeated foreign-PAN sightings; verify in Wireshark")

        # Retransmission-rate window (duplicate src+seq within 2 s). Frames
        # from another PAN are left out, as every other judgement leaves
        # them out: a neighbour's mesh retrying to its own router paged
        # for a problem on someone else's network, blamed on whichever of
        # our devices held the same short address (RLOC16s come from the
        # same small space in every mesh), and dragged the baseline about
        # so a real elevation of ours could hide behind a noisy neighbour.
        if self._win_start == 0.0:
            self._win_start = ts
        dominant = self.dominant_pan()
        foreign = pan is not None and dominant is not None and pan != dominant
        if f.ftype in (1, 3) and f.src and f.seq is not None and not foreign:
            key = (f.src, f.seq, pan)
            last = self.dup_recent.get(key)
            # 0 <= : a stamp in the future is not a repeat. A sequence
            # number is a byte, so every device re-uses each key once per
            # 256 frames; without the floor a cached stamp left ahead of
            # the clock makes every frame from every device score as a
            # duplicate until the cycle comes round.
            if last is not None and 0 <= ts - last < 2.0:
                self._win_dups += 1
                pair = (who or f.src, f.dst)
                self._win_dup_by[pair] = self._win_dup_by.get(pair, 0) + 1
            self.dup_recent[key] = ts
            self._win_frames += 1
            if len(self.dup_recent) > 8192:
                cutoff = ts - 4
                self.dup_recent = {k: v for k, v in self.dup_recent.items() if v > cutoff}
        if ts - self._win_start >= 60:
            self._retrans_resume(self._win_start)
            if self._win_frames >= 100:
                self._retrans_window(ts, self._win_dups / self._win_frames)
            else:
                self._retrans_thin(self._win_start, ts)
            if not self.ephemeral:
                self._save_retrans(ts)
                self._save_storm()
            self._win_start = ts
            self._win_dups = self._win_frames = 0
            self._win_dup_by = {}

        # Storm detector escalation to the event log (own cooldown, never
        # per-frame even when the detector's alert cooldown is zeroed).
        if self.detector.storm_active and ts - self._storm_evt > self.storm_event_cooldown_s:
            self._storm_evt = ts
            if not self.ephemeral:
                # Now, not at the next window close: this is the record a
                # restart in the next minute must not repeat.
                self._save_storm()
            details = self.detector.storm_details
            period = details.get("period")
            onsets = details.get("onsets") or []
            # The snapshot is _emit's doing, off the "critical" severity: it
            # adds the auto_snapshot field and the sentence about where the
            # packets went, and starts the copy afterwards.
            self._emit("phase_locked_storm", "critical", ts,
                 period_s=round(period, 1) if period else None, onsets=len(onsets),
                 onset_times=onsets,
                 note=(f"traffic floods recurring every {period:.0f} s ({len(onsets)} onsets): "
                       f"the broadcast-storm signature"
                       if period else "phase-locked traffic floods"),
                 **self.detector.snapshot())

        self.last_frame = f
        self.last_sighting = who if (who and live) else None
        self.last_mle = (info, fresh_mle) if info is not None else None
        return who

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

    def _poll_sent(self, who: str, stats: DeviceStats, seq: int | None, ts: float,
                   dst: str | None = None) -> None:
        """A poll went out. If the previous one is still waiting for its ACK
        and this is not a MAC retry of it (same seq), that one went
        unanswered; enough of those in a row, from a device whose polls
        used to be answered, is starvation."""
        if (stats.poll_pending_seq is not None and seq != stats.poll_pending_seq
                and not 0.0 <= ts - stats.poll_pending_ts <= self.quiet_threshold_s(who)):
            # The pending poll is from the far side of a silence (the
            # device stopped transmitting, and device_quiet has judged
            # that): it says nothing about whether polls are answered
            # now. Anchored on it, the episode clock counted the whole
            # silence as unanswered polling, so a burst too short to
            # report became a page "over 10845 s". The run starts afresh
            # with this poll, as it does after an answered one.
            stats.poll_pending_seq = None
            stats.unanswered_polls, stats.unanswered_since = 0, None
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
            if stats.starved and stats.confirm_at is not None and stats.poll_pending_ts >= stats.confirm_at:
                # Logged [polls] confirm_s ago and still nobody answers. The
                # evidence is a poll sent after the mark that went unanswered
                # (this one proves it), not a poll from before the mark that
                # a silent stretch left pending: a device back from twenty
                # minutes of silence with an answered poll is not paged.
                self._confirm_starvation(who, stats, row, ts, dst)
            elif (not stats.starved and answered_before
                    and stats.unanswered_polls >= STARVED_POLLS
                    and ts - stats.unanswered_since >= STARVED_MIN_S):
                stats.starved = True
                # Remembered on the last-seen row too (like quiet_reported):
                # a restart rebuilds DeviceStats empty, and without the row
                # the first answered poll after it would never close the
                # episode.
                if row is not None:
                    row["starved"] = True
                    row["starve_since"] = stats.unanswered_since
                    self.seen._dirty = True
                span = round(ts - stats.unanswered_since)
                history = (f"after {stats.acked_polls} answered polls" if stats.acked_polls
                           else "after answered polls before the recorder's last restart")
                parent, parent_addr, whom = self._parent_of(dst)
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
                # A third: not yet. A starvation that would page is logged
                # now and paged only if the polls are still unanswered
                # [polls] confirm_s later (the first poll sent past that
                # mark that goes unanswered, so the page rests on evidence,
                # not on a timer that outlived the recorder). Every
                # starvation that recovered by itself has done so well
                # inside the window.
                hold = 0.0 if (marginal or flapping) else self.cfg.poll_confirm_s
                extra = {}
                if hold > 0:
                    stats.confirm_at = ts + hold
                    if row is not None:
                        row["starve_confirm_at"] = stats.confirm_at
                        self.seen._dirty = True
                    extra["confirmed"] = False
                    note += (f" Logged now; paged if its polls are still unanswered in {hold / 60:.0f} min "
                             "(a starvation that recovers by itself does so within minutes).")
                self._emit(
                    "poll_starvation", "notice" if (marginal or flapping or hold > 0) else "warning", ts,
                    addr=who, name=self.names.name(who),
                    unanswered_polls=stats.unanswered_polls, since=stats.unanswered_since,
                    starved_for_s=span, acked_polls=stats.acked_polls,
                    rssi_dbm=rssi, reception="marginal" if marginal else "good",
                    episode=episode, since_previous_s=round(gap) if gap is not None else None,
                    parent_rloc16=dst if dst and len(dst) == 4 else None, parent_addr=parent_addr,
                    parent=parent, note=note, **extra)
        stats.poll_pending_seq, stats.poll_pending_ts = seq, ts

    def _parent_of(self, dst: str | None) -> tuple:
        """The poll's destination is the parent's RLOC16: name it, so the
        question "whose ACKs are missing" is answered in the record.
        Returns (parent label, parent's extended address, 'its parent ...')."""
        short = dst if dst and len(dst) == 4 else None
        parent_addr = self.decryptor.short_to_ext.get(short) if short else None
        parent = ((self.names.name(parent_addr) or parent_addr) if parent_addr
                  else (f"router {int(short, 16) >> 10}" if short else None))
        whom = f"its parent {parent} ({dst})" if parent else "its parent"
        return parent, parent_addr, whom

    def _confirm_starvation(self, who: str, stats: DeviceStats, row: dict | None,
                            ts: float, dst: str | None) -> None:
        """The page behind [polls] confirm_s: the starvation logged at notice
        is still open and another poll has just gone unanswered."""
        held = ts - (stats.confirm_at - self.cfg.poll_confirm_s)
        stats.confirm_at = None
        since = (row.get("starve_since") if row else None) or stats.unanswered_since or ts
        if row is not None:
            row.pop("starve_confirm_at", None)
            self.seen._dirty = True
        parent, parent_addr, whom = self._parent_of(dst)
        rssi = row.get("rssi") if row else stats.rssi_ewma
        note = (f"still polling {whom} with no acknowledgement {held / 60:.0f} min after the starvation "
                f"was logged ({round(ts - since)} s in all): the parent is gone or the link to it broke "
                "and the device has not noticed; it still looks alive, so no device_quiet will follow, "
                "and a rejoin attempt should. (If it just moved to a parent the sniffer cannot hear, "
                "the ACKs are missing here, not on air.)")
        self._emit(
            "poll_starvation", "warning", ts, addr=who, name=self.names.name(who),
            unanswered_polls=stats.unanswered_polls, since=since,
            starved_for_s=round(ts - since), acked_polls=stats.acked_polls,
            rssi_dbm=rssi, reception=reception(rssi, self.cfg.quiet_min_rssi_dbm),
            episode=(row.get("starve_episodes") if row else None) or 1,
            since_previous_s=None, confirmed=True,
            parent_rloc16=dst if dst and len(dst) == 4 else None, parent_addr=parent_addr,
            parent=parent, note=note)

    def _poll_answered(self, who: str, stats: DeviceStats, ts: float) -> None:
        stats.poll_pending_seq = None
        stats.acked_polls += 1
        stats.unanswered_polls, stats.unanswered_since = 0, None
        row = self.seen.table.get(who)
        announced = stats.starved or (row is not None and row.get("starved"))
        unconfirmed = stats.confirm_at is not None or bool(row and row.get("starve_confirm_at"))
        stats.starved = False
        stats.confirm_at = None
        if row is not None:
            if row.pop("starved", None):
                self.seen._dirty = True
            for key in ("starve_confirm_at", "starve_since"):
                if row.pop(key, None) is not None:
                    self.seen._dirty = True
            if announced:
                # When this episode ended: the next one is judged against it.
                row["starve_closed"] = ts
                self.seen._dirty = True
            if not row.get("polls_acked"):
                row["polls_acked"] = True
                self.seen._dirty = True
        if announced:
            self._emit("poll_answered", "notice", ts, addr=who, name=self.names.name(who),
                       note="its polls are acknowledged again"
                       + (" (before the starvation was confirmed: it was logged, not paged)"
                          if unconfirmed else ""))

    def leader_device(self, router_id: int | None = None) -> dict:
        """Which device holds a router id (the leader's, by default), as far
        as the sniffer knows. A router id is the top six bits of an RLOC16,
        so router 60 answers to short address 0xF000; the MLE layer learns
        which extended address that is the first time the device itself
        sends an MLE frame (its advertisements carry its RLOC16)."""
        part = self.partition       # read once: the capture thread reassigns it
        rid = router_id if router_id is not None else (part[1] if part else None)
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

    def partition_status(self) -> dict | None:
        """The 'partition' entry of status.json and the replay summary."""
        # Read once: the watchdog thread calls this while the capture
        # thread may replace self.partition between the test and the
        # indexing, and the raise costs a status.json write. Two missed
        # writes in a row show a false "capture stale" banner on the web
        # header, which treats a status file older than 180 s as stale.
        part = self.partition
        if not part:
            return None
        return {"id": part[0], "leader_router": part[1], **self.leader_device()}

    def _label(self, addr: str | None) -> str | None:
        """Name for any address form: extended, or a short one the decryptor
        has mapped; falls back to the address itself."""
        if not addr:
            return None
        ext = addr if len(addr) == 16 else self.decryptor.short_to_ext.get(addr)
        return (self.names.name(ext) if ext else None) or addr

    def _retrans_window(self, ts: float, rate: float) -> None:
        """One closed minute of the retransmission-rate window.

        A minute is elevated when more than 20% of frames were repeats and
        that is over twice the baseline: the median of the last 30 minutes,
        frozen for as long as an elevation lasts (a long one would otherwise
        pull the median up under itself and end its own alarm). The first
        elevated minute is logged (a notice, held back 15 min from the last
        one); the warning waits until the rate has stayed up for
        [retransmissions] confirm_s, judged at the minute that completes it
        (and held back 15 min from the last page), because one elevated
        minute is a microwave and a storm building keeps the rate up. One
        sub-threshold minute inside an elevation does not end it; two do.
        confirm_s = 0 is the old detector: the first elevated minute pages,
        and a long elevation pages again every 15 min.

        Across a restart the history, the frozen baseline and the open
        elevation are the last run's (_load_retrans, _retrans_resume).
        A minute with too few frames to measure never gets here; see
        _retrans_thin for what it does to an elevation."""
        self.retrans_counts.append(rate)
        median = sorted(self.retrans_counts)[len(self.retrans_counts) // 2]
        base = self._retrans_base if self._retrans_since is not None else median
        elevated = rate > 0.2 and rate > 2 * base
        if not elevated:
            if self._retrans_since is not None:
                self._retrans_lull += 1
                if self._retrans_lull > 1:
                    self._retrans_since = None
            return
        self._retrans_up = ts
        attribution = self._retrans_attribution()
        # One pair hammering each other is a chronic bad link between two
        # devices at the RF edge: worth a log line, not a page. Retries
        # spread across the mesh are the storm precursor this detector
        # exists for.
        one_link = attribution.get("top_share", 0) >= 0.5
        confirm_s = self.cfg.retrans_confirm_s
        if self._retrans_since is None:
            self._retrans_since = ts - 60             # this minute's start
            self._retrans_base = base
            self._retrans_lull = 0
            self._retrans_confirmed = confirm_s <= 0
            if ts - self._retrans_alerted > 900:
                self._retrans_alerted = ts
                extra = {}
                if confirm_s > 0:
                    extra["confirmed"] = False
                    attribution["note"] = (attribution.get("note", "elevated retransmissions") +
                                           f". Logged now; paged if the rate is still up in {confirm_s / 60:.0f} min "
                                           "(a minute of interference passes, a storm building does not).")
                self._emit("retransmission_elevation",
                           "notice" if (one_link or confirm_s > 0) else "warning", ts,
                           rate=round(rate, 3), baseline=round(base, 3), **attribution, **extra)
            return
        self._retrans_lull = 0
        if confirm_s <= 0:
            # The old detector: a long elevation is a warning every 15 min.
            if ts - self._retrans_alerted > 900:
                self._retrans_alerted = ts
                self._emit("retransmission_elevation", "notice" if one_link else "warning", ts,
                           rate=round(rate, 3), baseline=round(base, 3), **attribution)
            return
        if (not self._retrans_confirmed and ts - self._retrans_since >= confirm_s
                and ts - self._retrans_paged > 900):
            self._retrans_confirmed = True
            self._retrans_paged = ts
            sustained = round(ts - self._retrans_since)
            attribution["note"] = (f"retransmissions elevated for {sustained / 60:.0f} min: "
                                   + attribution.get("note", "more than 20% of frames were repeats"))
            self._emit("retransmission_elevation", "notice" if one_link else "warning", ts,
                       rate=round(rate, 3), baseline=round(base, 3), sustained_s=sustained,
                       confirmed=True, **attribution)

    def _retrans_resume(self, start: float) -> None:
        """The first window after a restart: the recorder saw nothing
        between the last run's last closed window and this one's start,
        so that gap is not elevated time. The open elevation's start moves
        past it, and the page waits for confirm_s of minutes actually
        observed; whether the elevation is still on is judged the usual
        way, against the frozen baseline, and two calm minutes close it."""
        if self._retrans_closed is None:
            return
        gap = max(0.0, start - self._retrans_closed)
        self._retrans_closed = None
        if self._retrans_since is not None:
            self._retrans_since += gap

    # An elevation not seen up for this long is over, however few frames
    # the minutes in between carried (the notice and page cooldown, so a
    # burst that follows is a new elevation with its own notice).
    RETRANS_UNSEEN_S = 900.0

    def _retrans_thin(self, start: float, ts: float) -> None:
        """A closed window with fewer than 100 frames: too few to measure
        a rate, so it neither joins the baseline nor counts as elevated,
        and it is not a lull either (a quiet mesh at night is not the
        storm ending). But it is time in which the rate was not seen to be
        up, and it must not count as sustained elevation: the elevation's
        start moves past it, so the page waits for confirm_s of minutes in
        which the rate was measured and up. Skipped outright, ten quiet
        low-traffic minutes between two one-minute bursts paged as twelve
        minutes of sustained retries nobody had observed. An elevation not
        seen up for RETRANS_UNSEEN_S is closed."""
        if self._retrans_since is None:
            return
        if ts - self._retrans_up > self.RETRANS_UNSEEN_S:
            self._retrans_since = None
            return
        self._retrans_since += ts - start

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

    def _deep_inspect(self, f: Frame, plain: bytes):
        """The credentialed layer: what the MAC payload (decrypted by
        _verify, or the plaintext of an unsecured frame) says about the
        mesh. Reads; it does not act. Returns the MLE message found, if
        any, the extended address it came from, and the SRP-style names
        the payload advertises: ingest can take a secured message as
        vouching for an unsecured frame's sender, hands both to _apply_mle
        once its counter has been checked, and files the names only under
        a sender the frame vouched for."""
        from .crypto import MLE_UDP_PORT, Decryptor
        ext = f.src if f.src and len(f.src) == 16 else None
        short = f.src if f.src and len(f.src) == 4 else None
        dext = f.dst if f.dst and len(f.dst) == 16 else None
        dshort = f.dst if f.dst and len(f.dst) == 4 else None
        # Unsecured frames are unauthenticated bytes from anyone on the
        # channel; a parse failure there must not take the capture down.
        try:
            r = Decryptor.udp_ports(plain, mac_src_ext=ext, mac_dst_ext=dext, mac_dst_short=dshort)
            if not r:
                return None, None, ()
            sport, dport, payload, sip, dip = r
            info = src_for_mle = None
            if MLE_UDP_PORT in (sport, dport):
                src_for_mle = ext or self.decryptor.short_to_ext.get(short or "")
                # bind_short=False: the mapping this message asserts is
                # applied in _apply_mle, once its counter has been checked.
                info = self.decryptor.parse_mle(payload, src_for_mle, sip, dip, bind_short=False)
        except (struct.error, IndexError, ValueError):
            self.decryptor.stats["parse_failed"] += 1
            return None, None, ()
        if MLE_UDP_PORT in (sport, dport):
            return info, src_for_mle, ()
        return None, None, tuple(n for n in Decryptor.harvest_names(payload)
                                 if len(n) > 8 and not n.startswith("_"))

    def _apply_mle(self, f: Frame, info, src_for_mle: str | None) -> None:
        """What a fresh, authenticated MLE message changes: the sender's
        short address, the partition it reports, and the rejoin it
        announces. Kept apart from decoding because a MIC alone does not
        make a message current - a recording of one carries the same MIC.
        Applied on a stale message, this reverted the partition and the
        device's RLOC to what they were when it was captured and paged for
        a change that never happened."""
        if info.source_addr16 is not None and src_for_mle:
            short = f"{info.source_addr16:04x}"
            self._note_rloc16(src_for_mle, short, f.ts)
            self.decryptor.short_to_ext[short] = src_for_mle
        if info.command_name in MLE_REJOIN_COMMANDS:
            # addr is the extended address (the review pages key on it);
            # src is whatever the frame carried, often a short address.
            name = self.names.name(src_for_mle) if src_for_mle else None
            self._emit("mle_rejoin_attempt", "notice", f.ts,
                       command=info.command_name, src=f.src, addr=src_for_mle, name=name,
                       note=f"{info.command_name} from {name or src_for_mle or f.src}: "
                            "it lost its parent or its network and is trying to get back")
        if info.partition_id is not None:
            cur = (info.partition_id, info.leader_router_id)
            if self.partition is not None and cur != self.partition:
                before, after = self.leader_label(self.partition[1]), self.leader_label(cur[1])
                self._emit("partition_or_leader_change", "warning", f.ts,
                           previous={"partition": self.partition[0],
                                     "leader_router": self.partition[1], "leader": before},
                           current={"partition": cur[0],
                                    "leader_router": cur[1], "leader": after},
                           note=f"partition {self.partition[0]} leader {before} -> "
                                f"partition {cur[0]} leader {after}: the mesh split, merged "
                                "or elected a new leader")
            self.partition = cur

    # The name scraper is a regex over decrypted UDP payloads, most of
    # which are ciphertext: it fires on random bytes now and then, and an
    # address would otherwise collect a junk "name" every few hours for
    # ever. A real SRP registration recurs (leases are renewed), so only
    # what has been seen twice is a name to suggest (names.MIN_SIGHTINGS),
    # and each address keeps at most this many, the least-sighted going
    # first when a new one arrives.
    OBSERVED_NAMES_MAX = 16

    def _note_observed_name(self, owner: str, name: str, repeat: bool = False) -> None:
        """``repeat`` marks a frame the MAC layer accepted as a retry: the
        same bytes again, milliseconds later.

        The count is what names.MIN_SIGHTINGS reads to tell a hostname a
        device really registered from a DNS-shaped accident in encrypted
        application data, and a retransmission carries the identical payload.
        Counting it made one accidental match its own corroboration and put
        it up as an inventory suggestion, which is exactly what asking for
        two sightings was meant to prevent. A retry still records a name not
        seen before -- it is a sighting, just not a second one."""
        seen = self.observed_names.setdefault(owner, {})
        if name in seen:
            if not repeat:
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
            if self._identity_silence_s(addr, row, now) > self.quiet_threshold_s(addr):
                self._report_quiet(addr, row, now)
        self._check_links(now, dominant)
        if not self.ephemeral:
            self._maybe_summarize(now, dominant)
            self._maybe_prune_events(now)
            if self._frames_by_hour:
                self._save_frames_by_hour()
        if self.observed_names and not self.ephemeral:
            tmp = self.mle_names_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.observed_names, indent=1))
            tmp.replace(self.mle_names_path)

    def _check_links(self, now: float, dominant: int | None) -> None:
        """Slow link degradation (link.py) for every device on our PAN."""
        for addr, row in self.seen.table.items():
            pan = row.get("pan")
            if dominant is not None and pan is not None and pan != dominant:
                continue
            # assess() judges the RSSI average per fresh frame, so a device
            # that stops transmitting can never clear its own flag: both
            # the recovery test and the daily refresh want frames it will
            # not send. A retired address (a hub that rotated) will not
            # send them either. Left open, the drop is on the headline
            # card, in ?only=down and in every daily summary for ever,
            # naming a healthy device. It is closed here instead, and the
            # silence - or the rotation - is the story from then on.
            retired = bool(row.get("rotated_to"))
            gone = retired or self.silence_s(row, now) > self.quiet_threshold_s(addr)
            if gone:
                if row.get("rssi_degraded"):
                    self._close_degradation(addr, row, now, retired)
                if row.get("starved"):
                    self._close_starvation(addr, row, now, retired)
                continue
            verdict = assess_link(row, now, self.cfg.link_drop_db, self.cfg.link_hold_s,
                                  pause_gap_s=self.quiet_threshold_s(addr))
            if verdict is None:
                continue
            self.seen._dirty = True
            name = self.names.name(addr)
            rssi, ref = row.get("rssi"), row.get("rssi_ref")
            if verdict == "degraded":
                drop = round(ref - rssi, 1)
                since = row.get("rssi_low_since", now)
                self._emit(
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
                self._emit("rssi_recovered", "info", now, addr=addr, name=name,
                           rssi_dbm=rssi, reference_dbm=ref,
                           note=(f"reference re-based to {ref:g} dBm: the drop held a day "
                                 "and is the new normal" if rebased else
                                 f"back to its usual {ref:g} dBm"))

    def _close_degradation(self, addr: str, row: dict, now: float, retired: bool) -> None:
        """End an announced signal drop the device itself can no longer end."""
        for key in ("rssi_degraded", "rssi_low_since"):
            row.pop(key, None)
        self.seen._dirty = True
        self._emit("rssi_recovered", "info", now, addr=addr, name=self.names.name(addr),
                   rssi_dbm=row.get("rssi"), reference_dbm=row.get("rssi_ref"),
                   note=("this address was retired when the device rotated: the signal drop it "
                         "was carrying is closed with it" if retired else
                         "the device has stopped being heard altogether: the signal drop is "
                         "closed here, and the silence is the story from now on"))

    def _close_starvation(self, addr: str, row: dict, now: float, retired: bool) -> None:
        """The same for an announced starvation: an unanswered poll is only
        closed by an answered one, which a device that has stopped polling
        will never send."""
        for key in ("starved", "starve_confirm_at", "starve_since"):
            row.pop(key, None)
        row["starve_closed"] = now
        self.seen._dirty = True
        stats = self.devices.get(addr)
        if stats is not None:
            stats.starved, stats.confirm_at = False, None
        self._emit("poll_answered", "notice", now, addr=addr, name=self.names.name(addr),
                   note=("this address was retired when the device rotated: the unanswered polls "
                         "it was carrying are closed with it" if retired else
                         "the device has stopped polling altogether: the unanswered polls are "
                         "closed here, and the silence is the story from now on"))

    # ------------------------------------------------ snapshot on critical

    AUTO_SNAPSHOT_COOLDOWN_S = 6 * 3600
    AUTO_SNAPSHOT_RETRY_S = 30 * 60      # after a failed copy: the next critical event tries again

    def _emit(self, event: str, severity: str = "info", ts: float | None = None,
              **fields) -> dict:
        """Log an event, and save the ring when it is a critical one. Every
        event the pipeline raises goes through here rather than straight to
        events.emit, so what keeps the packets is the severity and not a
        call some future handler has to remember to make. The two paths
        that stay on events.emit say why where they are.

        A critical event carries auto_snapshot (the snapshot label, or None
        when saving is off, replaying, or inside the cooldown) and a
        closing sentence saying where its packets went."""
        ts = time.time() if ts is None else ts
        label = None
        if severity == "critical":
            label = self._auto_snapshot(ts, event)
            fields["auto_snapshot"] = label
            keep = (f"the ring is being saved as {label}" if label
                    else "run 'threadwatch snapshot' to keep the packets")
            note = fields.get("note")
            fields["note"] = f"{note}; {keep}" if note else keep
        record = self.events.emit(event, severity, ts, **fields)
        if label:
            # The copy starts only once the event that called for it is in
            # the log: the snapshot copies the log, and a worker that got
            # to it first left the snapshot without the record that
            # explains it.
            self.snapshotter(label, event)
        return record

    def _auto_snapshot(self, ts: float, event: str) -> str | None:
        """Reserve a snapshot of the ring for a critical event, at most once
        per cooldown (one storm is one snapshot, however long it rumbles).
        Returns the snapshot label for _emit to log and then hand to
        self.snapshotter, or None when off, replaying, or inside the cooldown.
        The cooldown is armed here, before the copy starts, so the critical
        events that fire while it runs do not start more copies; a copy
        that fails shortens it to AUTO_SNAPSHOT_RETRY_S (see _save_snapshot_now).
        The label carries the event that called for it, so a snapshots
        listing says which one without opening the manifest."""
        if not self.cfg.snapshot_on_critical or self.ephemeral:
            return None
        if self.cfg.keep_snapshots == 0:
            # Keeping none of them: taking one to delete it at the next
            # storm is the ring copied for nothing. Snapshots saved by hand
            # are a different path and are not affected.
            return None
        if ts - self._last_auto_snapshot < self.AUTO_SNAPSHOT_COOLDOWN_S:
            return None
        self._last_auto_snapshot = ts
        return f"auto-{event}"

    def _snapshot_in_background(self, label: str, trigger: str) -> None:
        threading.Thread(target=self._save_snapshot_now, args=(label, trigger), daemon=True).start()

    def _save_snapshot_now(self, label: str, trigger: str) -> None:
        """Take the snapshot _emit reserved. ``trigger`` is the event that
        called for it, recorded in the snapshot's manifest. What this path
        logs goes to events.emit rather than _emit: a snapshot reporting on
        itself must never start another one, least of all from the
        background thread the last one is running on."""
        from .snapshot import prune_auto_snapshots, save_snapshot
        # Oldest automatic snapshots go before this one is taken, not
        # after: the room they free is the room this copy needs.
        keep = self.cfg.keep_snapshots
        # One less, to leave room for the copy about to be taken - but -1 is
        # the no-cap sentinel and has to stay -1 through that subtraction:
        # the 0 it used to become deleted every automatic snapshot on disk,
        # which is the opposite of what -1 asks for.
        dropped = prune_auto_snapshots(self.cfg.snapshots_dir, keep - 1 if keep > 0 else keep)
        if dropped:
            self.events.emit("snapshots_pruned", "info", time.time(), removed=dropped,
                             note=(f"{len(dropped)} older automatic snapshot(s) removed to keep "
                                   f"[record] keep_snapshots = {self.cfg.keep_snapshots}: "
                                   + ", ".join(dropped)))
        if not self._room_for_snapshot(label):
            return
        try:
            dest, count = save_snapshot(self.cfg, label, trigger=trigger)
        except Exception as exc:
            # Nothing was kept (save_snapshot removes a half copy), so the
            # six-hour cooldown armed for this attempt must not stand: the
            # next storm event after the retry hold tries again.
            self._last_auto_snapshot -= self.AUTO_SNAPSHOT_COOLDOWN_S - self.AUTO_SNAPSHOT_RETRY_S
            self.events.emit("snapshot_failed", "warning", time.time(), label=label,
                             note=(f"could not save the ring for {label}: {exc}; nothing was kept, and "
                                   f"the next critical event after {self.AUTO_SNAPSHOT_RETRY_S // 60} min "
                                   f"tries again"))
            return
        self.events.emit("snapshot_saved", "info", time.time(), label=label, path=str(dest),
                         ring_files=count, note=f"{count} ring files kept as {dest.name}")

    def _room_for_snapshot(self, label: str) -> bool:
        """A snapshot is a second copy of the ring. Taking one that leaves
        the ring less room than it still needs trades a week of recording
        for one snapshot, and the recorder exits 1 the moment the card
        fills. Refuse it and say so; the ring keeps running."""
        from .review import fmt_bytes, storage
        sto = storage(self.cfg)
        free, need = sto.get("disk_free"), sto["ring_needs_bytes"]
        if free is None or free - sto["ring_bytes"] >= need:
            return True
        self._last_auto_snapshot -= self.AUTO_SNAPSHOT_COOLDOWN_S - self.AUTO_SNAPSHOT_RETRY_S
        self.events.emit("snapshot_skipped", "warning", time.time(), label=label,
                         disk_free=free, ring_bytes=sto["ring_bytes"], ring_needs_bytes=need,
                         note=(f"not saving {label}: a copy of the ring ({fmt_bytes(sto['ring_bytes'])}) "
                               f"would leave less than the {fmt_bytes(need)} the ring still needs out of "
                               f"{fmt_bytes(free)} free; delete snapshots or lower keep_hours"))
        return False

    # ------------------------------------------------------ daily summary

    def _maybe_summarize(self, now: float, dominant: int | None) -> None:
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
            # events.emit, not _emit: [summary] severity is how loudly the
            # user wants the digest delivered, not a statement that
            # something critical happened, and a daily digest is no reason
            # to keep a second copy of the ring.
            self.events.emit("daily_summary", self.cfg.summary_severity, now,
                             **self.summary(now, dominant))
        # Settled only once the record is written: a failed write (disk
        # full) leaves the day open, so the next periodic() tries again.
        self._summary_day = day

    def _maybe_prune_events(self, now: float) -> None:
        """Drop day files past [events] keep_days, once per local day."""
        day = day_of(now)
        events_dir = getattr(self.events, "dir", None)
        if day == self._pruned_day or events_dir is None:
            return
        self._pruned_day = day
        prune_days(events_dir, self.cfg.events_keep_days, now)

    def _records_of(self, day: str) -> list[dict]:
        events_dir = getattr(self.events, "dir", None)
        if events_dir is not None:
            return read_day(events_dir, day)
        return [r for r in getattr(self.events, "records", []) if day_of(r["ts"]) == day]

    def summary(self, now: float, dominant: int | None = None) -> dict:
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
        # A retired address (a hub that rotated) carries whatever flag it
        # held when it stopped being used; the quiet set is already
        # filtered by quiet_reported, and the degraded set needs the same.
        degraded = sorted(label(a) for a, r in ours.items()
                          if r.get("rssi_degraded") and not r.get("rotated_to"))
        counts = {"critical": 0, "warning": 0, "notice": 0, "info": 0}
        # Every local day the window touches: after the spring clock change
        # 24 hours can span three of them, and reading the first and last
        # day's files alone dropped the whole middle day's events.
        days = dict.fromkeys(day_of(t) for t in [since + h * 3600 for h in range(25)] + [now])
        for day in days:
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
        for the browse's four-second wait) and apply the last result when it is in."""
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
            except Exception as exc:
                # Not OSError alone. An mDNS responder is anyone on the LAN,
                # so browse() parses untrusted input, and a ValueError,
                # struct.error or IndexError getting past its own guards
                # would escape a daemon thread nothing joins: a bare
                # traceback on stderr and a browse that never reports. A
                # LAN nobody can parse must not be louder than one nobody
                # answers on.
                print(f"[threadwatch] mdns browse failed: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
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
                          "been heard on air; held until it is", file=sys.stderr, flush=True)
                continue
            rec = self.routers.get(host) or {}
            entry = (self.names.entry_for_border_router(host) or self.names.by_addr.get(ext)
                     or (self.names.entry_named(rec["name"]) if rec.get("name") else None))
            # Hearing an address on air proves that device exists. It does not
            # prove that an unauthenticated hostname advertising the address
            # belongs to it. A responder that knows two addresses could
            # advertise a hub's hostname carrying a sensor's address: the
            # hostname's entry took the sensor's address, the sensor's traffic
            # was then presented under the hub's name, and the hub's real row
            # was retired -- which exempts it from quiet alerts for as long as
            # it stays silent. An address the inventory already gives to
            # somebody else is a conflict, not a rotation, and it needs
            # evidence mDNS cannot supply.
            owner = self.names.by_addr.get(ext)
            if entry is not None and owner is not None and owner is not entry:
                if (host, ext) not in self._conflict_logged:
                    if len(self._conflict_logged) >= self.LOGGED_MAX:
                        self._conflict_logged.clear()
                    self._conflict_logged.add((host, ext))
                    self._emit("border_router_address_conflict", "warning", now, addr=ext,
                               name=owner.get("name"), hostname=host,
                               claimed_by=entry.get("name"),
                               note=(f"{r.get('instance') or host} advertises {ext}, which devices.json "
                                     f"gives to {owner.get('name')!r}, as {entry.get('name')!r}. mDNS is "
                                     "unauthenticated and cannot settle this: the inventory stands. If the "
                                     "device really did move, correct devices.json."))
                continue
            # One address, one hostname. Hostnames cost a responder nothing to
            # invent, and any one of them naming an address already heard on
            # air goes straight past the pending cap into self.routers, which
            # had no cap and no expiry: RAM, the whole file rewritten on every
            # browse, and a longer load at every start, growing for as long as
            # somebody kept browsing. A border router does not answer to a
            # second hostname, so the one already holding the address keeps
            # it -- unless the inventory names the newcomer itself.
            holder = next((h for h, other in self.routers.items()
                           if h != host and (other.get("addr") or "").lower() == ext), None)
            if holder is not None and self.names.entry_for_border_router(host) is None:
                if (host, ext) not in self._conflict_logged:
                    if len(self._conflict_logged) >= self.LOGGED_MAX:
                        self._conflict_logged.clear()
                    self._conflict_logged.add((host, ext))
                    print(f"[threadwatch] mdns: {r.get('instance') or host} advertises {ext}, which "
                          f"{holder} already answers for; ignored", file=sys.stderr, flush=True)
                continue
            if holder is not None:
                del self.routers[holder]        # the inventory named this one instead
                dirty = True
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
                              "was heard on air more recently; stale record, ignored", file=sys.stderr, flush=True)
                    continue
            new = {"addr": ext, "name": name, "instance": r.get("instance"), "vendor": r.get("vendor"),
                   "model": r.get("model"), "since": now if (changed or not rec) else rec.get("since", now),
                   "seen": now, "previous": list(rec.get("previous") or []), "announced": rec.get("announced", False)}
            if changed:
                # One entry per address, newest last, and never the live
                # one: an A -> B -> A rotation would otherwise leave two
                # entries for A and B and grow by one on every hop.
                retired = {prev, ext}
                new["previous"] = [e for e in new["previous"]
                                   if not (isinstance(e, dict) and (e.get("addr") or "").lower() in retired)]
                new["previous"].append({"addr": prev, "until": now})
                new["previous"] = new["previous"][-self.ROUTER_PREVIOUS_MAX:]
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
                    old_row.pop("quiet_reported_ts", None)
                    was_quiet = old_row.pop("quiet_reported", None) or prev in self.quiet_reported
                    self.quiet_reported.discard(prev)
                    self.seen._dirty = True
                    if was_quiet:
                        # The silence announced for the old address is over:
                        # the device is back under the new one. A retired row
                        # is never judged again, so nothing else could close
                        # the episode, and every day page would carry it open.
                        self._emit("device_returned", "notice", now, addr=prev, name=name,
                                   note=f"back under a new address, {ext}")
                who = name or r.get("instance") or host
                self._emit("border_router_address_changed", "notice", now, addr=ext, name=name,
                           previous=prev, hostname=host,
                           note=(f"{who} now answers to {ext}, was {prev}: an Apple hub takes a new Thread "
                                 "address on every reboot. " + ("Named from its entry; nothing to edit." if name
                                 else "Not in devices.json: see the devices page.")))
            elif entry is None and not new["announced"]:
                new["announced"] = True
                self._emit("border_router_unlisted", "notice", now, addr=ext, name=None, hostname=host,
                           note=(f"border router {r.get('instance') or host} ({r.get('vendor')} {r.get('model')}) "
                                 f"at {ext} is not in devices.json: name it with "
                                 f"threadwatch name {ext} \"<name>\", or give an entry "
                                 f"\"borderRouter\": \"{host}\""))
            if new != rec:
                self.routers[host] = new
                dirty = True
        if self._bound_routers(now):
            dirty = True
        if dirty:
            self._save_border_routers()

    # A backstop under the one-address-one-hostname rule above: bindings for
    # addresses that are never heard again would otherwise sit in the file
    # for good, and nothing put a ceiling on the table at all. Hostnames the
    # inventory names explicitly are kept whatever happens to the rest.
    ROUTERS_MAX = 64
    ROUTER_STALE_S = 30 * 86400

    def _bound_routers(self, now: float) -> bool:
        """Expire and cap discovered host bindings. Returns what changed."""
        def configured(host: str) -> bool:
            return self.names.entry_for_border_router(host) is not None

        gone = [host for host, rec in self.routers.items()
                if not configured(host) and now - (rec.get("seen") or 0) > self.ROUTER_STALE_S]
        for host in gone:
            del self.routers[host]
        if len(self.routers) > self.ROUTERS_MAX:
            order = sorted(self.routers.items(),
                           key=lambda kv: (not configured(kv[0]), -(kv[1].get("seen") or 0), kv[0]))
            for host, _rec in order[self.ROUTERS_MAX:]:
                del self.routers[host]
                gone.append(host)
        return bool(gone)

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
        self._emit("credentials_stale", "warning", now, failed=failed,
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
        row["quiet_reported_ts"] = now      # the record this flag stands for (checked at the next start)
        self.seen._dirty = True
        if persist:
            self.seen.save()
        # silent_for_s is the wall clock since the device's last frame,
        # which is what every other view of the silence shows (the
        # "quiet now" card, the device rows, the day page's row, all
        # computed from last_seen), so an alert and the pages agree.
        # unheard_s is the part the recorder was up to witness, the
        # figure judged against the window; blind_s is the difference,
        # the recorder's own outage or clock step inside the silence.
        wall = now - row["last_seen"]
        unheard = self.silence_s(row, now)
        blind = max(0.0, wall - unheard)
        # A device the sniffer barely hears goes "quiet" whenever the link
        # fades; log it, but do not page for it.
        rssi = row.get("rssi")
        marginal = reception(rssi, self.cfg.quiet_min_rssi_dbm) == "marginal"
        note = ("sniffer hears this device at the edge of its range; "
                "silence is more likely reception than failure" if marginal else
                "no frames heard; if no mle_rejoin_attempt follows, "
                "suspect device-internal failure rather than RF")
        if blind >= 60:
            note += (f" (the recorder itself was not listening for {round(blind / 60)} min of the "
                     f"{round(wall / 60)} min: a restart, a stalled dongle or a clock step)")
        self._emit(
            "device_quiet", "notice" if marginal else "warning", now, addr=addr,
            name=self.names.name(addr), silent_for_s=round(wall), unheard_s=round(unheard),
            blind_s=round(blind), last_seen=row["last_seen"],
            rssi_dbm=rssi, reception="marginal" if marginal else "good", note=note)


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
