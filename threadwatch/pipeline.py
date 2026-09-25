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
  - key generations: every rotation of the network key is recorded, with
    a census of who followed it, and a device left two or more
    generations behind its parent (or the mesh, for a router) is paged:
    its frames are dropped while its polls are still acknowledged, so
    nothing else notices
"""

from __future__ import annotations

import json
import math
import struct
import sys
import threading
import time
from collections import deque
from pathlib import Path

from .detect import Detector
from .events import EventLog, day_of, prune_days, read_day
from .link import assess as assess_link
from .names import (
    _EXT_ADDR,
    DeviceNames,
    LastSeen,
    VisitorNames,
    load_border_routers,
    newest_generation,
    parent_address,
    reception,
    rloc16_role,
    router_holders,
)
from .pcap import BROADCAST_PAN, Frame, is_poll
from .srp import Reassembler, fragment, matter_instances_in, parse_update

MLE_REJOIN_COMMANDS = {"Parent Request", "Child ID Request", "Announce"}
# The MLE commands only a router (or a router-eligible device keeping up
# with one) sends, whose Leader Data is the sender's own current view of
# the partition. A child's Child Update Request repeats what its parent
# last told it.
MLE_ROUTER_COMMANDS = {
    "Link Request", "Link Accept", "Link Accept And Request", "Advertisement",
    "Data Response", "Parent Response", "Child ID Response"}
# The attachment and link exchanges kept for the key-transition journal,
# spelled as crypto.MLE_COMMANDS names them (a test holds them to it).
MLE_EXCHANGE_COMMANDS = {
    "Parent Request", "Parent Response", "Child ID Request", "Child ID Response",
    "Child Update Request", "Child Update Response", "Link Request", "Link Accept",
    "Link Accept And Request"}

# Starvation: this many distinct polls (MAC retries of one poll share a
# sequence number and count once) with no ACK, spanning at least this long.
STARVED_POLLS = 10
STARVED_MIN_S = 60.0


def _whole(value) -> int | None:
    """A whole number from a state file, or None for anything else (a bool,
    a string, a missing key). Rows are JSON somebody can edit."""
    return None if isinstance(value, bool) or not isinstance(value, int) else value


def fmt_span(seconds: float) -> str:
    """'42 s', '3 min', '2 h 05 min': the spans the notes quote."""
    seconds = max(0, int(round(seconds)))
    if seconds < 180:
        return f"{seconds} s"
    minutes = seconds // 60
    if minutes < 120:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes:02d} min"


def _seconds(value) -> float:
    """A timestamp from a state file, or 0.0 when it is not a number."""
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else 0.0


class DeviceStats:
    """Rolling per-device health from cleartext headers only."""

    __slots__ = ("rssi_ewma", "rssi_min", "rssi_max", "polls", "last_poll_ts",
                 "poll_intervals", "tx", "acked", "ack_pending_seq",
                 "ack_pending_ts", "beacons", "poll_pending_seq", "poll_pending_ts",
                 "acked_polls", "unanswered_polls", "unanswered_since", "starved", "confirm_at",
                 "served_wait_seq", "served_wait_ts", "served_wait_keys", "served_polls",
                 "unserved_polls", "unserved_since", "unserved", "unserved_confirm_at")

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
        # A poll the parent's radio acknowledged with Frame Pending set,
        # whose frame the parent's stack has not yet sent (_delivery_expected).
        self.served_wait_seq = None
        self.served_wait_ts = None
        self.served_wait_keys = ()        # the child's addresses registered in _awaiting_delivery
        self.served_polls = 0             # pending acknowledgements a frame did follow
        self.unserved_polls = 0           # ...and, since the last one, those nothing followed
        self.unserved_since = None
        self.unserved = False             # announced (poll_unserved), not yet closed
        self.unserved_confirm_at = None

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
            "served_polls": self.served_polls, "unserved_polls": self.unserved_polls,
            "unserved": self.unserved,
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
        self.names = DeviceNames(cfg.devices_path, cfg.state_dir / "border-routers.json",
                                 cfg.state_dir / "device-rotations.json")
        self.names.persist_rotations = not ephemeral
        # Labels for visiting addresses (config/visitors.json). Never the
        # inventory: an inventory entry makes an address a device whose
        # silence pages; a label only changes what a visit is called.
        self.visitor_names = VisitorNames(getattr(cfg, "visitors_path", None))
        if not ephemeral:
            from .snapshot import remember_capture
            remember_capture(cfg, self.names.entries)
        self.seen = LastSeen(None if ephemeral else cfg.state_dir / "last-seen.json")
        # Matter service instance names by the address that last registered
        # them (a row's matter_instances, from the SRP updates heard whole):
        # the identity an address that rotated is recognised by.
        self._matter_owner: dict[str, tuple[str, float]] = {}
        for addr, row in self.seen.table.items():
            when = (row.get("srp") or {}).get("last_ts") or row.get("last_seen") or 0.0
            for inst in row.get("matter_instances") or []:
                if inst not in self._matter_owner or self._matter_owner[inst][1] < when:
                    self._matter_owner[inst] = (addr, when)
        self._reassembly = Reassembler()
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
        # The leader's pulse: the newest Route64 ID sequence heard for the
        # current partition, when it last advanced (frame time) and who
        # carried it. _leader_stalled holds the open leader_stalled episode.
        self._leader_seq: int | None = None
        self._leader_seq_ts: float | None = None
        self._leader_seq_from: str | None = None
        self._leader_stalled: dict | None = None
        # Partition changes held for [partition] settle_s: previous state,
        # the states seen since, the count of flips and when the last one
        # was. One state inside the window is a change; more is a storm.
        self._partition_hold: dict | None = None
        # The leader a change or storm replaced, for the detectors that
        # judge that device's silence afterwards (device_quiet, ha causes).
        self._lost_leader: dict | None = None
        # When the partition or leader last flipped (the first flip of a
        # storm): the rejoin and retransmission detectors read it to say
        # what a burst that follows is.
        self._partition_changed_ts: float | None = None
        # Rejoin attempts held for [rejoins] wave_s after the last one:
        # devices by address, the records the batch would have logged, and
        # the last batch that went out as a wave (for the attributions).
        self._rejoin_wave: dict | None = None
        self._last_rejoin_wave: dict | None = None
        # The newest OTBR inventory sample whose router table has been
        # compared (its started_at): each new sample is judged against the
        # one before it, once. Seeded at start so a restart announces
        # nothing that happened before it.
        self._router_set_ts: float | None = None
        # SRP (DNS UPDATE) transactions in flight, by DNS id: the client
        # that sent the request, so a relayed response is credited to the
        # device it is for and not to the router that carried it; and the
        # ids answered lately, so a response heard on two hops counts once.
        self._srp_requests: dict[int, tuple[str | None, float]] = {}
        self._srp_answered: dict[int, float] = {}
        # The IPv6 source of each registration heard whole, by the device
        # its host name says sent it: what a router's fragment of one is
        # credited by, when it may be carrying a child's (_registrant).
        self._srp_sources: dict[bytes, str] = {}
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
        self._storm_stage: str | None = None    # "warning" or "critical": what the running storm has been paged as
        self._storm_snapshot: str | None = None # the snapshot the warning took, for the critical to name
        self._border_router_changed: tuple | None = None   # (ts, name) of the last address change
        if not ephemeral:
            self._load_storm()
        self.quiet_reported: set[str] = set()
        # The key generations the mesh has been heard under: the highest
        # (persisted, so a restart never announces a rotation twice), who
        # was heard first under it and when, and the census still owed for
        # it. Replay starts from nothing and announces the first generation
        # it meets. See _note_generation.
        self.keys_path = cfg.state_dir / "key-generations.json"
        self._keys: dict = {} if ephemeral else self._load_keys()
        self._keys_reloaded = bool(self._keys)
        from .journal import STATE as JOURNAL_STATE
        from .journal import Journal
        self.journal = Journal(None if ephemeral else cfg.state_dir / JOURNAL_STATE)
        self._journal_exchanges: dict[str, deque] = {}
        self._journal_files: dict = {}       # replay supplies actual source files
        # Addresses that have visited: how many times, first and last
        # (data/state/visits.json; config/visitors.json is the labels). A
        # visit drops the address's row, so without this a phone back
        # under the same address (they keep it, even across a reboot) was
        # "first seen" again on every visit.
        self.visits_path = cfg.state_dir / "visits.json"
        self._visits: dict[str, dict] = {} if ephemeral else self._load_visits()
        # The key generation the last frame ingested was accepted under
        # (None when it vouched for nobody): `device` reads it to print a
        # generation history without decoding anything twice.
        self.last_generation: int | None = None
        self._last_mac_sequence: int | None = None
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
                # discard_partials returns the label (after the stamp's "_").
                next_attempt = ("a key snapshot attempt is not repeated after a restart"
                                if label.startswith("auto-key-") else "the next storm event tries again")
                self.events.emit("snapshot_failed", "warning", time.time(), label=label,
                                 note=(f"the copy for {label} was cut short when the recorder last stopped; "
                                       f"the half copy was discarded; {next_attempt}"))
            # A log fetch the last run died in: what arrived is kept as a
            # partial log, and the retry pass takes it from there.
            from .halogs import recover_interrupted
            for name in recover_interrupted(cfg.snapshots_dir):
                print(f"[threadwatch] {name}: the HA log fetch was cut short when the recorder last stopped; "
                      "what arrived is kept as partial, and the retry pass tries again", file=sys.stderr, flush=True)
        # The HA log retry pass (halogs.retry_pending) runs on a thread
        # every HA_LOGS_RETRY_S and reports on the capture thread, as the
        # border-router browse does.
        self._halogs_thread = None
        self._halogs_result: list | None = None
        self._next_halogs = 0.0
        # The hourly archive of the same logs ([ha_logs] archive): a pass
        # just after each hour ends, every ARCHIVE_RETRY_S while anything
        # is pending, on a thread; its events and its status entry are
        # applied on the capture thread.
        self._archive_thread = None
        self._archive_result: dict | None = None
        self._next_archive = 0.0
        self._archive_status: dict | None = None
        self._otbr_inventory = None
        if not ephemeral and cfg.otbr_enabled:
            from .otbr import InventoryPoller
            self._otbr_inventory = InventoryPoller(cfg)
        # Home Assistant availability ([ha_availability]): a worker polls
        # /api/states every poll_s (and rebuilds the device map over the
        # websocket every registry_refresh_s); the next periodic pass
        # applies the result on this thread, where the device table lives.
        self._haavail = None
        self._haavail_thread = None
        self._haavail_result: dict | None = None
        self._next_haavail = 0.0
        self._haavail_map_ts: float | None = None
        # Addresses with no name that registered over SRP, waiting on an
        # early map refresh to say which device they are (_want_identity).
        self._identify: dict[str, dict] = {}
        self._identify_done: set[str] = set()
        if not ephemeral and cfg.ha_availability_enabled:
            self._init_ha_availability()
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
        self._snapshot_lock = threading.Lock()
        self._key_snapshot_slots = threading.BoundedSemaphore(2)
        self.snapshotter = self._snapshot_in_background
        self._summary_day: str | None = None      # local day whose summary is settled
        self._pruned_day: str | None = None       # local day the event log was last pruned on
        self._capped_at: float | None = None      # when rows were last dropped to stay under TRACK_MAX
        self._flood_said_at: float | None = None  # when address_flood was last emitted
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
        # What each device last advertised its counters to be, per layer
        # (_note_advertised), seeded from the rows so the floor a parent
        # holds survives a restart.
        self._advertised: dict[str, dict[str, dict]] = {}
        for addr, row in self.seen.table.items():
            for layer in ("mac", "mle"):
                adv = row.get(f"adv_{layer}")
                if (isinstance(adv, list) and len(adv) == 4 and _whole(adv[0]) is not None
                        and _whole(adv[1]) is not None):
                    self._advertised.setdefault(addr, {})[layer] = {
                        "value": adv[0], "sequence": adv[1], "ts": _seconds(adv[2]), "command": str(adv[3]),
                        "below": 0, "lowest": None, "said_ts": None}
        # A child's addresses (extended, and the short one it polled with)
        # while its parent owes it a frame: a data frame to either is the
        # delivery (_delivered).
        self._awaiting_delivery: dict[str, str] = {}
        self._last_mac_counter: int | None = None
        self._auth_addresses = set(self._mac_counter) | set(self._mle_counter)
        if len(self._auth_addresses) > self.AUTH_MAX:
            raise ValueError("saved authentication history exceeds AUTH_MAX; increase the cap before restarting")
        self._auth_capped_at: float | None = None
        self.replayed = 0                            # frames refused as replays this run
        self._replay_said: dict[str, float] = {}     # addr -> when its replays were last mentioned
        self._counter_was_retry = False              # last counter decision was a retry (see _counter_advances)
        self._counter_rejection_reason: str | None = None
        self._key_observations: list[tuple] = []
        self._resolve_after: dict[str, float] = {}   # short addr -> next attempt ts
        self._resolve_fails: dict[str, int] = {}     # short addr -> searches that found nobody, in a row
        self._resolve_tokens = float(self.RESOLVE_TRIALS_BURST)   # candidate trials in hand (see identity)
        self._resolve_tokens_ts: float | None = None
        self._candidates_built: float | None = None
        self._candidates: list[str] = []
        self._verify_after: dict[str, float] = {}    # short addr -> next re-check of its mapping
        self._foreign_after: dict[tuple, float] = {}  # (short addr, other PAN) -> next MIC check against it
        self.extra_candidates: list[str] = []        # ext addrs to try first in the nonce search (device)
        # The recorder's radios by label and state (up, down, missing),
        # kept current by radio_changed; empty for a single unnamed dongle
        # and offline. What a silence means depends on it: a device only
        # a radio now down was hearing is out of the recorder's earshot,
        # not necessarily quiet (_unheard_radio).
        self.radios: dict = {}
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
            # Owners map to {name: count}; any other shape, a count that is
            # not a whole number included, would raise at the first name
            # observed, in the capture loop. Only owners the device table
            # still holds are kept: names are harvested for a tracked
            # device, `devices --suggest` reads them for one, and a file
            # written before the owners were bounded must not carry the
            # growth back in.
            self.observed_names = {
                k: {n: c for n, c in v.items() if isinstance(c, int) and not isinstance(c, bool)}
                for k, v in loaded.items() if isinstance(v, dict) and k in self.seen.table} \
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
        if ephemeral and cfg.snapshot_dir is not None:
            self._blind = self._load_snapshot_blind()
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
                if row.get("unserved"):
                    # The same for polls acknowledged and not served: the
                    # first delivered frame closes it.
                    stats = self.devices.setdefault(addr, DeviceStats())
                    stats.unserved = True
                    stats.unserved_confirm_at = row.get("unserved_confirm_at")
            last_alive = self._last_frame_heard()
            if last_alive is not None:
                # A span an earlier start recorded from this same last frame
                # (the watchdog restart loop) lies inside this one.
                self._blind = [span for span in self._blind if span[0] < last_alive]
                self._blind.append((last_alive, now - last_alive))
            self._announce_start(now, last_alive)
            dominant = self.dominant_pan()       # best guess before any frame arrives
            announced = 0
            for addr, row in list(self.seen.table.items()):     # a filed visit drops its row
                if row.get("rotated_to"):
                    continue          # an Apple hub's old address: retired, not quiet
                if not self._is_quiet(addr, row, now):
                    announced_at = row.pop("quiet_reported_ts", None)
                    if row.pop("quiet_reported", None):
                        # Heard again after its announced silence, but the
                        # recorder died before saying so: close the silence
                        # at the moment it was actually heard. Not heard
                        # since the announcement (a parent vouched for it,
                        # or a frame this flag missed), that moment is
                        # before the device_quiet record, and a return
                        # logged ahead of its silence closed nothing: the
                        # day pages showed two devices still quiet for days
                        # while they were answering. Such a return is dated
                        # now, when this start found it.
                        returned = max(self.seen.table[a]["last_seen"]
                                       for a in self.names.entry_addresses_of(addr) if a in self.seen.table)
                        if announced_at is not None and returned <= announced_at:
                            returned = now
                        self._emit("device_returned", "notice", returned,
                                   addr=addr, name=self.names.name(addr))
                        announced += 1
                    continue
                ours = dominant is None or row.get("pan") in (None, dominant)
                if ours and "heard_since" not in row:
                    self._mark_stretch_from_log(addr, row)
                if ours and self._brief_visit(addr, row) is not None:
                    # A visitor, announced or not: a run from before visits
                    # were filed flagged its silence as device_quiet and
                    # left the row to show "still quiet" for a month.
                    self._file_visit(addr, row, now, persist=False)
                    announced += 1
                    continue
                if row.get("quiet_reported"):
                    # The flag is saved before the event is appended, so a
                    # run killed between the two left a silence flagged as
                    # announced that nobody was told about. The flag names
                    # the record it stands for; a flag without its record
                    # is announced now. A record on a day past [events]
                    # keep_days was pruned, not lost: a silence that
                    # outlived retention was paged again at every start. A
                    # missing day file alone does not say which, since a
                    # run killed before a day's first append leaves none.
                    stamp = row.get("quiet_reported_ts")
                    keep = self.cfg.events_keep_days
                    if stamp is None or (keep > 0 and day_of(stamp) < day_of(now - keep * 86400)) \
                            or self.events.on_record("device_quiet", stamp, addr):
                        self.quiet_reported.add(addr)
                        continue
                    row.pop("quiet_reported", None)
                    row.pop("quiet_reported_ts", None)
                if ours:
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

    def _load_snapshot_blind(self) -> list[tuple[float, float]]:
        """Recover pruned outages from bundled events; union overlapping evidence."""
        from .events import read_all
        spans = self._load_blind()
        for rec in read_all(self.cfg.events_dir):
            if rec["event"] == "recorder_started":
                start = rec.get("last_frame_ts")
                if isinstance(start, (int, float)) and start < rec["ts"]:
                    spans.append((start, rec["ts"] - start))
            elif rec["event"] == "clock_step":
                step = rec.get("step_s")
                if isinstance(step, (int, float)) and step > 0:
                    spans.append((rec["ts"] - step, step))
        merged = []
        for start, end in sorted((s, s + n) for s, n in spans if n > 0):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
            else:
                merged.append((start, end))
        return [(s, e - s) for s, e in merged]

    def _save_blind(self) -> None:
        """Keep spans needed by device silence or the current key interval,
        bounded to the newest BLIND_MAX."""
        if self.ephemeral:
            return
        stamps = [row.get("last_seen") for row in self.seen.table.values()]
        stamps = [t for t in stamps if isinstance(t, (int, float))]
        # Preserve outage evidence back to the current generation's first
        # observation even after every device has been heard again.
        if self._keys.get("highest_first_ts") is not None:
            stamps.append(self._keys["highest_first_ts"])
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
                     dict(raw.get("storm_details") or {}), float(raw.get("storm_evt") or 0.0),
                     float(raw.get("storm_since") or 0.0), bool(raw.get("storm_confirmed")),
                     raw.get("storm_stage"), raw.get("storm_snapshot"), float(raw.get("storm_gap_max") or 0.0))
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            return
        d.counts.extend(counts)
        d.calm.extend(calm)
        d.onsets.extend(onsets)
        (d.last_flood, d.window_start, d.window_count, d.in_flood, d.last_alert,
         d.alerts_sent, d.storm_active, d.storm_details, self._storm_evt,
         d.storm_since, d.storm_confirmed, self._storm_stage, self._storm_snapshot, d.storm_gap_max) = state
        if self._storm_stage is None and self._storm_evt and d.storm_active:
            # A file from before the two stages existed: the storm it holds
            # was paged, at the stage its confirmation implies, and a
            # restart must not page it again.
            self._storm_stage = "critical" if d.storm_confirmed else "warning"

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
                "storm_evt": self._storm_evt, "storm_since": d.storm_since,
                "storm_confirmed": d.storm_confirmed, "storm_stage": self._storm_stage,
                "storm_snapshot": self._storm_snapshot, "storm_gap_max": d.storm_gap_max}))
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

    KEYS_STAMPS = ("highest_first_ts", "previous_first_ts", "census_at")

    def _load_visits(self) -> dict[str, dict]:
        """visits.json: {addr: {visits, first_visit, last_visit, ...}}.
        Unreadable or shapeless: start afresh, which costs one
        device_first_seen where a visitor_returned was due and nothing
        else. Keys the recorder does not know (a label someone added by
        hand) are kept as they are."""
        try:
            data = json.loads(self.visits_path.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            print(f"[threadwatch] {self.visits_path.name} is unreadable ({exc}): earlier visits are "
                  "forgotten, so the next visit by each address is first seen again", file=sys.stderr, flush=True)
            return {}
        if not isinstance(data, dict):
            return {}
        return {a: v for a, v in data.items() if isinstance(a, str) and isinstance(v, dict)}

    def _save_visits(self) -> None:
        if self.ephemeral:
            return
        self.visits_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.visits_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._visits, indent=1))
        tmp.replace(self.visits_path)

    def _load_keys(self) -> dict:
        """key-generations.json: {highest, previous, highest_first_ts,
        previous_first_ts, first_sender, census_at, suspects, scope,
        confidence, reasons} plus the interval facts of the last advance
        (observed_interval_s, sequence_delta, observation_kind, coverage,
        scheduled_expectation, early_against_configured_interval).
        Unreadable or shapeless: start afresh, which costs one repeated
        key_sequence_advanced (info) and nothing else."""
        try:
            data = json.loads(self.keys_path.read_text())
        except FileNotFoundError:
            return {}
        except (OSError, ValueError) as exc:
            print(f"[threadwatch] {self.keys_path.name} is unreadable ({exc}): the highest key generation heard "
                  "is forgotten, so the current one is announced again", file=sys.stderr, flush=True)
            return {}
        if not isinstance(data, dict) or _whole(data.get("highest")) is None:
            return {}
        keys = {"highest": _whole(data["highest"]), "previous": _whole(data.get("previous")),
                "first_sender": data.get("first_sender") if isinstance(data.get("first_sender"), str) else None}
        for key in self.KEYS_STAMPS:
            value = data.get(key)
            keys[key] = float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None
        suspects = data.get("suspects")
        keys["suspects"] = [s for s in suspects if isinstance(s, dict) and isinstance(s.get("addr"), str)] \
            if isinstance(suspects, list) else []
        keys["scope"] = data.get("scope") if data.get("scope") in (
            "device", "router_group", "otbr_confirmed", "unknown") else "unknown"
        keys["confidence"] = "observation_only" if data.get("confidence") == "observation_only" else "unknown"
        reasons = data.get("reasons")
        keys["reasons"] = [r for r in reasons if isinstance(r, str)] if isinstance(reasons, list) else []
        # Interval facts (P0.3): kept as recorded, when they have the shape
        # they were written with; a shapeless one is left out, not guessed.
        number = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)
        for key, ok in (("observed_interval_s", number),
                        ("sequence_delta", lambda v: _whole(v) is not None),
                        ("observation_kind", lambda v: v in ("baseline", "advance")),
                        ("coverage", lambda v: isinstance(v, dict)),
                        ("scheduled_expectation", lambda v: isinstance(v, dict)),
                        ("early_against_configured_interval", lambda v: isinstance(v, bool))):
            value = data.get(key)
            if value is None or ok(value):
                keys[key] = value
        pair = data.get("snapshot_pair")
        if (isinstance(pair, dict) and _whole(pair.get("sequence")) is not None
                and number(pair.get("observed_at")) and math.isfinite(pair["observed_at"])
                and isinstance(pair.get("census_claimed"), bool)):
            keys["snapshot_pair"] = pair
        return keys

    def _save_keys(self) -> None:
        if self.ephemeral:
            return
        tmp = self.keys_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._keys, indent=1))
        tmp.replace(self.keys_path)

    def keys_status(self) -> dict:
        """The 'keys' entry of status.json: the highest generation heard,
        when and from whom, and when the census for it is due."""
        return dict(self._keys)

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
                directory = self.cfg.snapshots_dir / inc["name"]
                if is_auto_snapshot(directory):
                    try:
                        manifest = json.loads((directory / "manifest.json").read_text())
                        if manifest.get("trigger") in ("key_sequence_advanced", "key_lag_census"):
                            continue
                    except (OSError, ValueError):
                        continue
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

    def silence_s(self, row: dict, now: float, since: float | None = None) -> float:
        """How long the recorder has actually heard nothing from a device
        (or, with ``since``, since that moment rather than its last frame)."""
        last = row["last_seen"] if since is None else since
        silent = now - last
        if self.ephemeral and self.cfg.snapshot_dir is not None:
            blind = sum(max(0.0, min(now, start + length) - max(last, start))
                        for start, length in self._blind)
        else:
            blind = sum(length for start, length in self._blind if last <= start)
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

    def _vouched_silence_s(self, row: dict, now: float) -> float:
        """How long since something other than its own frame proved the
        device alive (_vouch): its parent answering its keep-alive, or its
        radio acknowledging a frame. Infinite when nothing has since its
        last frame, so the recorder's own silence alone decides."""
        vouched = row.get("vouched_ts")
        if vouched is None or vouched <= row["last_seen"]:
            return float("inf")
        return self.silence_s(row, now, since=vouched)

    def _is_quiet(self, addr: str, row: dict, now: float) -> bool:
        """The one rule for device_quiet, at start-up and on every tick: the
        recorder heard nothing from the device for the window while it was
        listening, and nothing else proved the device alive for as long.

        A device whose parent keeps answering it is out of the recorder's
        earshot, not off the mesh: on 2026-09-09 the Downstairs Bathroom Air
        Quality paged a warning-level silence while its parent answered its
        keep-alive every four minutes, the same day two other monitors
        really died. The report waits until the proxy evidence is as old
        as the silence, and then says how long it lasted."""
        threshold = self.quiet_threshold_s(addr)
        return (self._identity_silence_s(addr, row, now) > threshold
                and self._vouched_silence_s(row, now) > threshold)

    def _vouch(self, addr: str | None, ts: float, how: str) -> None:
        """Note that the device at ``addr`` (extended, or a short address the
        decryptor can resolve) was alive at ``ts`` on evidence that is not a
        frame of its own. Not a sighting: last_seen, RSSI and the stats stay
        what the recorder heard, so every page still shows when the device
        was last heard, and device_returned still means heard again."""
        if not addr:
            return
        ext = addr if len(addr) == 16 else self.decryptor.short_to_ext.get(addr)
        row = self.seen.table.get(ext) if ext else None
        if row is None or ts <= row.get("last_seen", 0.0) or ts <= (row.get("vouched_ts") or 0.0):
            return
        row["vouched_ts"] = ts
        row["vouched_by"] = how
        self.seen._dirty = True

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
    ROW_STAMPS = ("first_seen", "last_seen", "heard_since", "rloc16_ts", "rssi_heard_ts", "rssi_ref_ts",
                  "starve_confirm_at", "starve_closed", "resumed_ts", "vouched_ts", "rejoin_ts",
                  "keylag_since", "keylag_confirm_at", "keylag_closed",
                  "unserved_confirm_at", "unserved_closed", "counter_ts", "mle_counter_ts",
                  "counter_mismatch_ts")
    # The stamps nested inside a row: the SRP refusal streak, and the
    # [value, ts, sequence] and [value, sequence, ts, command] lists.
    SRP_STAMPS = ("since", "last_ts", "accepted_ts", "pending_ts")
    ROW_LIST_STAMPS = (("counter_prev", 1), ("mle_counter_prev", 1), ("adv_mac", 2), ("adv_mle", 2))
    STATS_STAMPS = ("last_poll_ts", "ack_pending_ts", "poll_pending_ts", "unanswered_since", "confirm_at",
                    "served_wait_ts", "unserved_since", "unserved_confirm_at")

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
            for label, t in list((row.get("last_seen_by") or {}).items()):
                if before(t):
                    row["last_seen_by"][label] = t - back
            srp = row.get("srp")
            if isinstance(srp, dict):
                for key in self.SRP_STAMPS:
                    if before(srp.get(key)):
                        srp[key] -= back
            for key, i in self.ROW_LIST_STAMPS:
                stamped = row.get(key)
                if isinstance(stamped, list) and len(stamped) > i and before(stamped[i]):
                    stamped[i] -= back
            self._rewind_key_facts(row.get("key_facts"), before, back)
        self.seen._dirty = True
        # What the row's counter and advertisement stamps are rewritten
        # from at the next frame.
        for table in (self._mac_counter, self._mle_counter):
            for gens in table.values():
                for seq, (counter, t) in list(gens.items()):
                    if before(t):
                        gens[seq] = (counter, t - back)
        for layers in self._advertised.values():
            for adv in layers.values():
                for key in ("ts", "said_ts"):
                    if before(adv.get(key)):
                        adv[key] -= back
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
                     "_win_start", "_next_browse", "_next_halogs", "_next_archive", "_next_haavail",
                     "_join_scan_evt", "_stale_evt",
                     "_pan_silent_evt",
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
        for key in self.KEYS_STAMPS:
            t = self._keys.get(key)
            if t and before(t):
                self._keys[key] = t - back
        # The duplicate window is two seconds wide, so there is nothing in
        # it worth moving: dropping it costs at most one window of genuine
        # retransmission detection, and keeps stamps from before the step
        # out of the comparison entirely.
        self.dup_recent.clear()

    @staticmethod
    def _rewind_key_facts(state, before, back: float) -> None:
        """The key-facts stamps, moved as _rewind moves the row's: the
        latest accepted transmission per layer, which keyfacts.observe
        refuses to replace with anything older, the highest authenticated,
        and each span's first and last sighting. A span whose last sighting
        moves and whose first does not is closed up to it rather than left
        inverted, which keyfacts.facts would discard."""
        if not isinstance(state, dict):
            return
        points = [state.get("highest_authenticated")]
        spans = []
        for layer in ("mac", "mle"):
            entry = state.get(layer)
            if isinstance(entry, dict):
                points.append(entry.get("latest"))
                for decision in ("accepted", "rejected"):
                    spans.extend(s for s in entry.get(decision) or () if isinstance(s, dict))
        for point in points:
            if isinstance(point, dict) and before(point.get("ts")):
                point["ts"] -= back
        for span in spans:
            for key in ("first_ts", "last_ts"):
                if before(span.get(key)):
                    span[key] -= back
            first, last = span.get("first_ts"), span.get("last_ts")
            if isinstance(first, (int, float)) and isinstance(last, (int, float)) and first > last:
                span["first_ts"] = last

    # ------------------------------------------------------------ radios

    # A radio that heard the device this recently before its last sighting
    # counts as one of the radios that were hearing it.
    RADIO_RECENT_S = 300.0

    def radio_changed(self, label: str | None, state: str, now: float) -> None:
        """The recorder's word that a radio is up, down or missing. A
        radio going down takes the best ear from every device it was
        the best ear for: the row's RSSI average sinks toward the other
        radios' level and the link detector would call that a
        degradation. Their reference is re-based to the surviving best
        radio's level now, as the daily refresh does, so the loss of the
        radio is not reported as every device fading at once."""
        self.radios[label] = state
        if state == "up":
            return
        key = label if label is not None else "radio"
        for row in self.seen.table.values():
            levels = row.get("rssi_by_radio") or {}
            if key not in levels or len(levels) < 2:
                continue
            best = max(levels, key=lambda k: levels[k])
            if best != key:
                continue
            others = [v for k, v in levels.items() if k != key and self.radios.get(k if k != "radio" else None) == "up"]
            if others and row.get("rssi_ref") is not None:
                row["rssi_ref"], row["rssi_ref_ts"] = max(others), now
                row.pop("rssi_low_since", None)
                self.seen._dirty = True

    def _unheard_radio(self, row: dict) -> str | None:
        """The radio a silent device's last sightings came from, when
        every radio that heard it in the RADIO_RECENT_S before its last
        frame is now down or missing: its silence here may be the
        recorder's, not the device's. None otherwise, and always None
        for a single unnamed dongle (the recorder's own blindness covers
        that)."""
        by = row.get("last_seen_by")
        if not by or not self.radios:
            return None
        down = {label if label is not None else "radio" for label, state in self.radios.items() if state != "up"}
        if not down:
            return None
        last = row.get("last_seen")
        if last is None:
            return None
        recent = {label for label, t in by.items() if t >= last - self.RADIO_RECENT_S}
        if recent and recent <= down:
            return ", ".join(sorted(recent))
        return None

    # ------------------------------------------------------- quiet policy

    def quiet_threshold_s(self, addr: str) -> float:
        """The device's own hold_s from its inventory entry, else [quiet]
        silence_s. One window serves everyone otherwise: the 2026-09-02
        soak showed routers and sleepy devices alike never silent for long
        from the sniffer's chair. The hold is a person's judgement of one
        device (a sensor that drops out in the afternoon sun), the same
        figure the Home Assistant availability check honours."""
        hold = self.names.hold_s(addr)
        return self.cfg.quiet_s if hold is None else hold

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
        if self._flood_said_at is None or ts - self._flood_said_at >= self.CAP_NOTE_S:
            self._flood_said_at = ts
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
        self._last_mac_sequence = None
        self._last_mac_counter = None
        if not who or not f.psdu:
            return None, False
        plain, counter, sequence = self.decryptor.decrypt_frame_counter(f.psdu, who, None)
        if counter is None:
            return plain, False
        self._last_mac_counter = counter
        live = self._counter_advances(self._mac_counter, who, counter, f.ts, "frame", sequence)
        self._key_observations.append(("mac", sequence, f.ts, live,
                                       self._counter_was_retry, self._counter_rejection_reason))
        if live:
            self._last_mac_sequence = sequence
        return plain, live

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
    # Do not evict counters with device rows: that would make a captured
    # frame fresh again. Bound the shared MAC/MLE address population instead.
    AUTH_MAX = 16_384

    def _counter_advances(self, table: dict, who: str, counter: int, ts: float, what: str,
                          sequence: int | None) -> bool:
        # Set for the caller that has just asked, and read straight after.
        self._counter_was_retry = False
        self._counter_rejection_reason = None
        if who not in self._auth_addresses:
            if len(self._auth_addresses) >= self.AUTH_MAX:
                self._counter_rejection_reason = "authentication_history_full"
                if self._auth_capped_at is None or ts - self._auth_capped_at >= self.CAP_NOTE_S:
                    self._auth_capped_at = ts
                    self._emit("authentication_history_full", "warning", ts, limit=self.AUTH_MAX,
                               note="authentication history is full: new addresses are not counted as live; "
                                    "existing replay counters are retained and raw capture continues. "
                                    "Investigate authenticated address churn before restarting.")
                return False
            self._auth_addresses.add(who)
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
                self._counter_rejection_reason = "older_than_retained"
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
        self._counter_rejection_reason = "counter_not_advancing"
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
        if who in self._auth_addresses and ts - self._replay_said.get(who, -1e12) >= 3600.0:
            self._replay_said[who] = ts
            print(f"[threadwatch] {self.names.name(who) or who}: {note} (said once an hour)",
                  file=sys.stderr, flush=True)

    # ---------------------------------------------------------- identity

    def _record_key_facts(self, who: str, f: Frame) -> None:
        """Forensic facts cannot admit devices or refresh liveness/topology."""
        from .keyfacts import observe
        row = self.seen.table.get(who)
        if row is None:
            return
        for layer, sequence, ts, accepted, retry, reason in self._key_observations:
            self.journal.observe(who, layer, sequence, ts, row=row, accepted=accepted, retry=retry,
                                 context=lambda seq=sequence, src=layer: self._journal_context(who, row, f, seq, src),
                                 packet=lambda: self._journal_packet(f), coverage=self._generation_coverage)
            observe(row, layer, sequence, ts, accepted=accepted, retry=retry, reason=reason)
        if self._key_observations:
            self.seen._dirty = True

    def _journal_packet(self, f: Frame) -> dict:
        import hashlib
        return {"ts": f.ts, "src": f.src, "dst": f.dst, "mac_sequence": f.seq,
                "radio": f.radio, "psdu_sha256": hashlib.sha256(f.psdu).hexdigest(),
                "file": str(self._journal_files[f.radio]) if f.radio in self._journal_files else None,
                "radio_timestamps": [{"radio": label, "ts": copy.ts} for label, copy in (f.heard or {}).items()],
                "locator": "timestamp_and_psdu_hash", "retained": "unknown"}

    def _journal_context(self, who: str, row: dict, f: Frame, sequence: int, layer: str) -> dict:
        from .keyfacts import facts, latest_generation
        entry = self.names.by_addr.get(who, {})
        addresses = sorted(self.names.entry_addresses_of(who))
        known = bool(entry) and who not in self.names.learned
        # The frame's authenticated short address can be newer than the
        # topology row, which ingest updates after recording key facts.
        short = f.src if f.src and len(f.src) == 4 else row.get("rloc16")
        topology = {**row, "rloc16": short}
        role = (rloc16_role(short) or {}).get("role")
        parent = parent_address(topology, router_holders(self.seen.table))
        prow = self.seen.table.get(parent, {})
        pseq, pts = latest_generation(prow)
        age = f.ts - pts if pts is not None and pts <= f.ts else None
        delta = sequence - pseq if pseq is not None else None
        previous = facts(row)[layer]["latest"]
        oldseq = previous["sequence"] if previous else None
        olddelta = oldseq - pseq if oldseq is not None and pseq is not None else None
        exchanges = [r for r in self._journal_exchanges.get(who, ()) if 0 <= f.ts - r["ts"] <= 1800]
        return {"name": self.names.name(who), "model": entry.get("model"),
                "firmware": entry.get("firmware"), "role": role, "rloc16": short,
                "role_observed_at": f.ts if f.src == short else row.get("rloc16_ts"),
                "physical_identity": {"id": ",".join(addresses) if known else who,
                                      "addresses": addresses, "source": "inventory" if known else "address_only",
                                      "physical_device_known": known},
                "partition": self.partition_status(), "partition_scope": "last_observed_network_context",
                "parent": {"addr": parent, "sequence": pseq, "observed_at": pts, "age_s": age,
                           "fresh": age is not None and age <= self.cfg.key_fresh_s,
                           "child_minus_parent": delta, "child_one_ahead": delta == 1 if delta is not None else None,
                           "child_sequence_before": oldseq, "child_minus_parent_before": olddelta,
                           "child_one_ahead_before": olddelta == 1 if olddelta is not None else None,
                           "mapping_observed_at": row.get("rloc16_ts"),
                           "mapping_confidence": "last_known_rloc_inference" if parent else "unknown"},
                "preceding_exchanges": exchanges,
                "earlier_highest_authenticated": facts(row)["highest_authenticated"],
                "uncertainties": ["parent_and_role_may_have_changed", "missed_traffic_possible",
                                  "multi_radio_and_host_clock_ordering_not_proven"]}

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
        self._key_observations = []
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
                    if f.pending:
                        self._delivery_expected(self._last_who or prev.src, stats, prev.src, f.seq, ts)
            # The radio that answered is the frame's destination: alive at
            # this moment, whether or not the recorder hears its own frames.
            if prev.dst not in (None, "ffff"):
                self._vouch(prev.dst, ts, "ack")
        self._last_who = who
        if f.ftype == 1 and f.dst and self._awaiting_delivery:
            # A data frame to a child whose parent owes it one: served.
            child = self._awaiting_delivery.get(f.dst)
            if child is not None:
                self._delivered(child, ts)

        # Only a frame that vouches for its sender (_verify) feeds the row
        # and the stats below: the sender's liveness, signal and polls are
        # its own, not those of whatever put its address on the air.
        plain, live = self._verify(f, who)
        retry = self._counter_was_retry
        if who and live and self._last_mac_counter is not None:
            self._check_advertised(who, "mac", self._last_mac_sequence, self._last_mac_counter, ts)
        info, src_for_mle, names, srp = (self._deep_inspect(f, plain) if f.ftype == 1 and plain is not None
                                         else (None, None, (), None))
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
            self._key_observations.append(("mle", info.key_sequence, ts, fresh_mle,
                                           self._counter_was_retry, self._counter_rejection_reason))
            retry = retry or self._counter_was_retry
            live = live or fresh_mle
            if fresh_mle:
                self._check_advertised(who, "mle", info.key_sequence, info.counter, ts)
        if info is not None and info.secured and fresh_mle:
            self._apply_mle(f, info, src_for_mle)
        if srp is not None:
            self._note_srp(srp, ts, live)
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
            prev_seen = None if was_new else self.seen.table[who].get("last_seen")
            self.seen.touch(who, ts, f.ftype, pan=pan, rssi=f.rssi, heard=f.heard)
            row = self.seen.table[who]
            if prev_seen is None or ts - prev_seen > self.BRIEF_VISIT_S:
                # A new stretch of presence: the first frame ever, or the
                # first after a gap. A visit is judged by its own stretch,
                # not by the row's whole life: the 09-14 visitor came back
                # under the same address 44 h later, for 18 s, and was
                # read as a device heard for 44 h.
                row["heard_since"] = ts
            before = newest_generation(row)[0]
            self._record_key_facts(who, f)
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
            # The generation this frame was accepted under, MAC or MLE,
            # the newer of the two when both vouched. It is what
            # _note_generation judges against the highest on record.
            generation, kind = self._last_mac_sequence, "mac_poll" if is_poll(f) else "mac_data"
            if fresh_mle and info.key_sequence is not None and (generation is None or info.key_sequence > generation):
                generation, kind = info.key_sequence, f"mle:{info.command_name}"
            self.last_generation = generation
            if generation is not None:
                self._note_generation(who, row, generation, kind, ts)
                if before is None or before < generation:
                    self._note_suspect(who, row, generation, kind, ts)
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
                # bring it back. This frame starts the address's current
                # life, which is what a later rotation back to it has to be
                # judged against: first_seen is the first sighting ever, and
                # in an A -> B -> A sequence that one is older than B.
                self.seen.table[who]["resumed_ts"] = ts
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
                known = self._visits.get(who)
                if known and self.names.name(who) is not None:
                    # A visitor the operator has since named is a device
                    # now, first seen under its name; its visits are over.
                    del self._visits[who]
                    self._save_visits()
                    known = None
                if known:
                    # Back for another visit: its row went with the last
                    # one, but the recorder has not forgotten it.
                    self._emit("visitor_returned", "info", ts, addr=who, name=self.visitor_names.name(who),
                               visit=int(known.get("visits") or 0) + 1, last_visit=known.get("last_visit"),
                               note=f"an address that has visited {known.get('visits')} time"
                                    f"{'s' if known.get('visits') != 1 else ''} before, last "
                                    f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(known.get('last_visit') or ts))}")
                else:
                    self._emit("device_first_seen", "info", ts, addr=who,
                               name=self.names.name(who))
            returned = False
            for addr in self.names.entry_addresses_of(who):
                if addr not in self.quiet_reported:
                    continue
                self.quiet_reported.discard(addr)
                self.seen.table[addr].pop("quiet_reported", None)
                self.seen.table[addr].pop("quiet_reported_ts", None)
                self._emit("device_returned", "notice", ts, addr=addr,
                           name=self.names.name(addr))
                returned = True
            if returned:
                # Close existing per-address episodes even when the identity
                # returned under a new address. Persist before a restart.
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
        # per-frame even when the detector's alert cooldown is zeroed). Two
        # stages: the call at period_onsets is a notice that keeps the
        # packets; the confirmation ([detect] confirm_s of floods) is the
        # critical, at once, cooldown or not.
        if self.detector.storm_active:
            stage = "critical" if self.detector.storm_confirmed else "warning"
            if stage != self._storm_stage or ts - self._storm_evt > self.storm_event_cooldown_s:
                self._storm_stage = stage
                self._storm_evt = ts
                if not self.ephemeral:
                    # Now, not at the next window close: this is the record a
                    # restart in the next minute must not repeat.
                    self._save_storm()
                self._emit_storm(stage, ts)
        elif self._storm_stage is not None:
            self._storm_stage = None
            self._storm_snapshot = None

        self.last_frame = f
        self.last_sighting = who if (who and live) else None
        if not (who and live):
            if who:
                self._record_key_facts(who, f)
            self.last_generation = None
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
            if row.get("rloc16") is not None:
                self.journal.topology(ext, row["rloc16"], short, ts)
            row["rloc16"] = short
            self.seen._dirty = True
        row["rloc16_ts"] = ts

    def _poll_sent(self, who: str, stats: DeviceStats, seq: int | None, ts: float,
                   dst: str | None = None) -> None:
        """A poll went out. If the previous one is still waiting for its ACK
        and this is not a MAC retry of it (same seq), that one went
        unanswered; enough of those in a row, from a device whose polls
        used to be answered, is starvation."""
        if stats.served_wait_ts is not None and seq != stats.served_wait_seq:
            # The last poll was acknowledged with data pending, and here is
            # the next distinct poll with no frame in between.
            self._poll_unserved(who, stats, ts, dst)
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
        # The ACKs may be missing at a radio that is down, not on air.
        unheard = self._unheard_radio(row) if row else None
        if unheard:
            note += (f" The only radio that heard this device lately ({unheard}) is down, so the "
                     "acknowledgements may be missing here and not on air: logged, not paged.")
        self._emit(
            "poll_starvation", "notice" if unheard else "warning", ts, addr=who, name=self.names.name(who),
            unanswered_polls=stats.unanswered_polls, since=since,
            starved_for_s=round(ts - since), acked_polls=stats.acked_polls,
            rssi_dbm=rssi, reception="unheard" if unheard else reception(rssi, self.cfg.quiet_min_rssi_dbm),
            radio_down=unheard,
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

    # ------------------------------ polls acknowledged, nothing delivered
    #
    # The failure the starvation detector cannot see. A parent's radio
    # answers a poll from its source-match table, before the poll reaches
    # the parent's stack: the ACK, Frame Pending set, promises a frame the
    # stack then has to send. When the stack drops the poll instead (a
    # child two or more key generations behind, 2026-09-13; a child that
    # advertised a link frame counter above the ones it polls with,
    # frame_counter_mismatch; a stack that has hung behind a live
    # radio), the child is acknowledged every time and served never, looks
    # alive here, and Home Assistant loses it. Over the hour before the
    # 09-13 rotation no child had more than two pending acknowledgements
    # in a row without a frame; the three stranded children had 1,700 each
    # in the hour after it.

    def _delivery_expected(self, who: str, stats: DeviceStats, poll_src: str | None,
                           seq: int | None, ts: float) -> None:
        """The parent's radio acknowledged the poll with Frame Pending set:
        a frame is owed. Remembered until one arrives, or until the child's
        next distinct poll says none did."""
        self._clear_wait(who, stats)
        stats.served_wait_seq, stats.served_wait_ts = seq, ts
        row = self.seen.table.get(who)
        short = row.get("rloc16") if row else None
        stats.served_wait_keys = tuple(k for k in dict.fromkeys((who, poll_src, short)) if k)
        for key in stats.served_wait_keys:
            self._awaiting_delivery[key] = who

    def _clear_wait(self, who: str, stats: DeviceStats) -> None:
        for key in stats.served_wait_keys:
            if self._awaiting_delivery.get(key) == who:
                del self._awaiting_delivery[key]
        stats.served_wait_seq = stats.served_wait_ts = None
        stats.served_wait_keys = ()

    def _delivered(self, who: str, ts: float) -> None:
        """A frame reached the child while its parent owed it one."""
        stats = self.devices.get(who)
        if stats is None or stats.served_wait_ts is None:
            return
        self._clear_wait(who, stats)
        stats.served_polls += 1
        stats.unserved_polls, stats.unserved_since = 0, None
        row = self.seen.table.get(who)
        announced = stats.unserved or (row is not None and bool(row.get("unserved")))
        unconfirmed = stats.unserved_confirm_at is not None or bool(row and row.get("unserved_confirm_at"))
        stats.unserved = False
        stats.unserved_confirm_at = None
        if row is not None:
            for key in ("unserved", "unserved_confirm_at", "unserved_since"):
                if row.pop(key, None) is not None:
                    self.seen._dirty = True
            if announced:
                row["unserved_closed"] = ts
                self.seen._dirty = True
            if not row.get("polls_served"):
                row["polls_served"] = True
                self.seen._dirty = True
        if announced:
            self._emit("poll_served", "notice", ts, addr=who, name=self.names.name(who),
                       note="its parent delivers again after acknowledging its polls with data pending"
                       + (" (before it was confirmed: it was logged, not paged)" if unconfirmed else ""))

    def _poll_unserved(self, who: str, stats: DeviceStats, ts: float, dst: str | None) -> None:
        """The child polled again with the last pending acknowledgement
        still owed a frame: that poll was acknowledged and never served.
        Enough of those in a row, from a child whose parent used to follow
        through, is a parent whose stack drops what its radio accepts."""
        waited = stats.served_wait_ts
        self._clear_wait(who, stats)
        if not 0.0 <= ts - waited <= self.quiet_threshold_s(who):
            # From the far side of a silence: it says nothing about now
            # (_poll_sent applies the same rule to an unanswered poll).
            stats.unserved_polls, stats.unserved_since = 0, None
            return
        stats.unserved_polls += 1
        if stats.unserved_since is None:
            stats.unserved_since = waited
        row = self.seen.table.get(who)
        served_before = stats.served_polls > 0 or bool(row and row.get("polls_served"))
        if stats.unserved and stats.unserved_confirm_at is not None and waited >= stats.unserved_confirm_at:
            self._confirm_unserved(who, stats, row, ts, dst)
            return
        if (stats.unserved or not served_before or stats.unserved_polls < STARVED_POLLS
                or ts - stats.unserved_since < STARVED_MIN_S):
            return
        stats.unserved = True
        if row is not None:
            row["unserved"] = True
            row["unserved_since"] = stats.unserved_since
            self.seen._dirty = True
        span = round(ts - stats.unserved_since)
        history = (f"after {stats.served_polls} served polls" if stats.served_polls
                   else "after served polls before the recorder's last restart")
        parent, parent_addr, whom = self._parent_of(dst)
        note = (f"{whom} acknowledged {stats.unserved_polls} polls over {span} s with data pending and sent "
                f"nothing after any of them, {history}: the parent's radio accepts the polls and its stack "
                "drops them, so Home Assistant loses the device while it still looks alive here. Read it "
                "beside key_lag and frame_counter_mismatch for this device; with neither, the parent's stack "
                "has hung. (If the sniffer simply cannot hear the parent, the frames are missing here, not "
                "on air.)")
        rssi = row.get("rssi") if row else stats.rssi_ewma
        marginal = reception(rssi, self.cfg.quiet_min_rssi_dbm) == "marginal"
        closed = row.get("unserved_closed") if row else None
        gap = stats.unserved_since - closed if closed is not None else None
        flapping = gap is not None and self.cfg.poll_rearm_s > 0 and gap < self.cfg.poll_rearm_s
        episode = ((row.get("unserved_episodes") or 0) + 1) if flapping else 1
        if row is not None and row.get("unserved_episodes") != episode:
            row["unserved_episodes"] = episode
            self.seen._dirty = True
        if marginal:
            note += (f" The sniffer hears this device at {rssi:.0f} dBm, the edge of its range, so the "
                     "parent's frames are more likely out of earshot here than missing on air: logged, not paged.")
        if flapping:
            note += (f" Episode {episode} since the last page, {gap / 60:.0f} min after the previous one ended "
                     "with a delivered frame: a parent the sniffer only sometimes hears; logged, not paged, "
                     f"until its polls have stayed served for {self.cfg.poll_rearm_s / 60:.0f} min.")
        hold = 0.0 if (marginal or flapping) else self.cfg.poll_confirm_s
        extra = {}
        if hold > 0:
            stats.unserved_confirm_at = ts + hold
            if row is not None:
                row["unserved_confirm_at"] = stats.unserved_confirm_at
                self.seen._dirty = True
            extra["confirmed"] = False
            note += f" Logged now; paged if its polls are still unserved in {hold / 60:.0f} min."
        self._emit("poll_unserved", "notice" if (marginal or flapping or hold > 0) else "warning", ts,
                   addr=who, name=self.names.name(who),
                   unserved_polls=stats.unserved_polls, since=stats.unserved_since, unserved_for_s=span,
                   served_polls=stats.served_polls, rssi_dbm=rssi,
                   reception="marginal" if marginal else "good", episode=episode,
                   since_previous_s=round(gap) if gap is not None else None,
                   parent_rloc16=dst if dst and len(dst) == 4 else None, parent_addr=parent_addr,
                   parent=parent, note=note, **extra)

    def _confirm_unserved(self, who: str, stats: DeviceStats, row: dict | None,
                          ts: float, dst: str | None) -> None:
        """The page behind [polls] confirm_s: the episode logged at notice is
        still open and another acknowledged poll has just gone unserved."""
        held = ts - (stats.unserved_confirm_at - self.cfg.poll_confirm_s)
        stats.unserved_confirm_at = None
        since = (row.get("unserved_since") if row else None) or stats.unserved_since or ts
        if row is not None:
            row.pop("unserved_confirm_at", None)
            self.seen._dirty = True
        parent, parent_addr, whom = self._parent_of(dst)
        rssi = row.get("rssi") if row else stats.rssi_ewma
        note = (f"{whom} is still acknowledging its polls with data pending and sending nothing "
                f"{held / 60:.0f} min after this was logged ({round(ts - since)} s in all): the parent's stack "
                "is dropping polls its radio accepts. Read it beside key_lag and frame_counter_mismatch for "
                "this device; with neither, the parent's stack has hung or the sniffer cannot hear it.")
        unheard = self._unheard_radio(row) if row else None
        if unheard:
            note += (f" The only radio that heard this device lately ({unheard}) is down, so the "
                     "parent's frames may be missing here and not on air: logged, not paged.")
        self._emit(
            "poll_unserved", "notice" if unheard else "warning", ts, addr=who, name=self.names.name(who),
            unserved_polls=stats.unserved_polls, since=since, unserved_for_s=round(ts - since),
            served_polls=stats.served_polls, rssi_dbm=rssi,
            reception="unheard" if unheard else reception(rssi, self.cfg.quiet_min_rssi_dbm),
            radio_down=unheard, episode=(row.get("unserved_episodes") if row else None) or 1,
            since_previous_s=None, confirmed=True,
            parent_rloc16=dst if dst and len(dst) == 4 else None, parent_addr=parent_addr,
            parent=parent, note=note)

    # ------------------------------------------------ advertised counters
    #
    # An attaching child, a router establishing a link and a child
    # updating its parent each advertise their frame counters (Link Layer
    # Frame Counter and MLE Frame Counter TLVs); the receiver takes them as
    # the floor below which the sender's later frames are replays and
    # drops them. The stack writes the advertisement and the radio driver
    # the counters on the frames, and a device whose two have parted (a
    # Child ID Request advertising 1,280,176,180, then polls at 4,708) is
    # refused by every parent until it reboots. Only the sniffer sees both
    # numbers side by side; docs/ALERTING.md has the reported case.

    # Accepted frames below the advertisement before it is said: one or
    # two can be frames the device had queued when it advertised.
    COUNTER_BELOW_FRAMES = 3

    def _note_advertised(self, who: str, layer: str, sequence: int | None, value: int,
                         command: str, ts: float) -> None:
        if sequence is None:
            return
        state = {"value": value, "sequence": sequence, "ts": ts, "command": command,
                 "below": 0, "lowest": None, "said_ts": None}
        prev = self._advertised.get(who, {}).get(layer)
        if prev is not None and prev["sequence"] == sequence and prev["below"] >= self.COUNTER_BELOW_FRAMES:
            # A confirmed mismatch re-advertised under the same key
            # generation is the same fault going on: a refused child times
            # out and re-attaches, and every Child ID Request repeats the
            # wrong counter. The count and the hourly guard carry over,
            # or the warning would go out again at each re-attachment.
            # Below the threshold nothing carries: a frame or two queued
            # behind each honest advertisement must not add up to a page.
            state.update(below=prev["below"], lowest=prev["lowest"], said_ts=prev["said_ts"])
        self._advertised.setdefault(who, {})[layer] = state
        row = self.seen.table.get(who)
        if row is not None:
            row[f"adv_{layer}"] = [value, sequence, ts, command]
            self.seen._dirty = True

    def _check_advertised(self, who: str, layer: str, sequence: int | None, counter: int, ts: float) -> None:
        """An accepted frame from the device: is its counter below what the
        device last advertised under the same key generation?"""
        adv = self._advertised.get(who, {}).get(layer)
        if adv is None or sequence is None or adv["sequence"] != sequence or counter >= adv["value"]:
            return
        adv["below"] += 1
        adv["lowest"] = counter if adv["lowest"] is None else min(adv["lowest"], counter)
        if adv["below"] < self.COUNTER_BELOW_FRAMES:
            return
        if adv["said_ts"] is not None and ts - adv["said_ts"] < 3600.0:
            return
        adv["said_ts"] = ts
        row = self.seen.table.get(who)
        if row is not None:
            row["counter_mismatch_ts"] = ts
            self.seen._dirty = True
        what = "link-layer" if layer == "mac" else "MLE"
        when = time.strftime("%H:%M:%S", time.localtime(adv["ts"]))
        shortfall = adv["value"] - counter
        note = (f"advertised a {what} frame counter of {adv['value']} in its {adv['command']} at {when} under "
                f"key generation {sequence}, then sent {adv['below']} secured {what} frames below it (this one "
                f"{counter}, {shortfall} below): its parent rejects every frame it sends as stale until it "
                "reboots. The advertisement and the counters come from different parts of the device's "
                "firmware, so this is a device-side defect to report to the vendor (frame_counter_mismatch in "
                "docs/ALERTING.md). Said at most once an hour while it goes on.")
        self._emit("frame_counter_mismatch", "warning", ts, addr=who, name=self.names.name(who),
                   layer=layer, key_sequence=sequence, advertised=adv["value"], advertised_ts=adv["ts"],
                   advertised_in=adv["command"], counter=counter, lowest=adv["lowest"],
                   shortfall=shortfall, frames_below=adv["below"], note=note)

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
        seq_ts = self._leader_seq_ts
        return {"id": part[0], "leader_router": part[1], **self.leader_device(),
                "id_sequence": self._leader_seq, "sequence_advanced_ts": seq_ts,
                "stalled": self._leader_stalled is not None}

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
        out = {"addr": sender_ext, "name": self.names.name(sender_ext) if sender_ext else None,
               "top_sender": who, "top_target": target, "top_share": round(share, 2), "note": note}
        if share < 0.5:
            context = self._rejoin_context(self._win_start + 60 if self._win_start else time.time())
            if context:
                trigger = context.get("trigger") or "a rejoin wave"
                many = (f"{context['devices']} devices re-attaching" if context.get("devices")
                        else "the mesh re-attaching")
                out["cause"] = "rejoin_wave"
                out["note"] = (f"retries spread across devices (top: {who} -> {target}, {share:.0%}) while "
                               f"{many} after {trigger}: the rejoin wave, not interference")
        return out

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
        partial = False
        try:
            frag = fragment(plain)
            if frag is None:
                r = Decryptor.udp_ports(plain, mac_src_ext=ext, mac_dst_ext=dext, mac_dst_short=dshort)
            else:
                # A fragment of a larger datagram (an SRP registration is
                # three to six frames): read whole once every piece is in.
                # A FRAG1 on its own still gives what it always did, the
                # header and the first records, in case the rest is never
                # heard.
                first = (Decryptor.udp_ports(plain, mac_src_ext=ext, mac_dst_ext=dext, mac_dst_short=dshort)
                         if frag[0] == "first" else None)
                r = self._reassembly.add(f.src or "", frag, first, f.ts)
                if r is None:
                    if first is None:
                        return None, None, (), self._partial_registration(plain, frag, ext, short)
                    r, partial = first, True
            if not r:
                return None, None, (), None
            sport, dport, payload, sip, dip = r
            info = src_for_mle = None
            if MLE_UDP_PORT in (sport, dport):
                src_for_mle = ext or self.decryptor.short_to_ext.get(short or "")
                # bind_short=False: the mapping this message asserts is
                # applied in _apply_mle, once its counter has been checked.
                # A FRAG1 on its own is a message cut short: its MIC cannot
                # check, and the FRAGN that completes it is read whole.
                if not partial:
                    info = self.decryptor.parse_mle(payload, src_for_mle, sip, dip, bind_short=False)
        except (struct.error, IndexError, ValueError):
            self.decryptor.stats["parse_failed"] += 1
            return None, None, (), None
        if MLE_UDP_PORT in (sport, dport):
            return info, src_for_mle, (), None
        srp = None
        if 53 in (sport, dport) and len(payload) >= 12:
            dns_id, flags = struct.unpack(">HH", payload[:4])
            if (flags >> 11) & 0xF == 5:                    # opcode UPDATE: SRP, not a DNS-SD query
                mesh = self._mesh_endpoints(plain)
                if flags & 0x8000:                          # a response: for the mesh destination
                    client = (self.decryptor.short_to_ext.get(mesh[1]) if mesh
                              else dext or self.decryptor.short_to_ext.get(dshort or ""))
                    srp = {"kind": "response", "id": dns_id, "rcode": flags & 0xF, "client": client,
                           "server": self._aloc_label(sip)}
                else:                                       # a request: from the device it registers
                    update = None if partial else parse_update(payload)
                    client = self._registrant(update and update["host"], plain, sip, ext, short)
                    srp = {"kind": "request", "id": dns_id, "rcode": None, "client": client,
                           "server": self._aloc_label(dip)}
                    if update is not None:
                        srp.update(host=update["host"], instances=update["instances"],
                                   lease=update["lease"], key_lease=update["key_lease"])
        return None, None, tuple(n for n in Decryptor.harvest_names(payload)
                                 if len(n) > 8 and not n.startswith("_")), srp

    def _partial_registration(self, plain: bytes, frag: tuple, ext: str | None, short: str | None) -> dict | None:
        """A later fragment of an SRP registration whose FRAG1 was heard
        but whose whole may never be: the sniffer misses a frame in many
        a nine-fragment registration. The names written out in this piece
        are still the device's, so they count (partial), with the request
        id and zone the FRAG1 gave; the host and leases wait for a whole
        one."""
        pending = self._reassembly.last_update
        if pending is None:
            return None
        instances = sorted({n for at, piece in pending["pieces"]
                            for n in matter_instances_in(piece, pending["zone"], at)})
        if not instances:
            return None
        client = self._registrant(None, plain, pending.get("sip"), ext, short)
        return {"kind": "request", "id": pending["id"], "rcode": None, "client": client,
                "server": self._aloc_label(pending["dip"]), "instances": instances, "partial": True}

    SRP_SOURCES_MAX = 512

    def _registrant(self, host: str | None, plain: bytes, sip: bytes | None,
                    ext: str | None, short: str | None) -> str | None:
        """The device a registration is from. The frame's MAC source is only
        this hop's sender, and a router forwards its children's registrations
        to the SRP server one hop away with no mesh header: on 2026-09-23 two
        climate sensors' registrations were credited to their parent routers,
        and when the sensors rotated the routers were named as the devices
        that had. A Matter device's SRP host name is its own extended address,
        so a registration heard whole names its sender; one read in part from
        a router is that router's only if its IPv6 source is one the router's
        own whole registrations used. A child forwards nothing, so its MAC
        source stands."""
        who = (host or "").lower()
        if _EXT_ADDR.match(who) and who in self.seen.table:
            if sip:
                if len(self._srp_sources) >= self.SRP_SOURCES_MAX:
                    self._srp_sources.pop(next(iter(self._srp_sources)))
                self._srp_sources[bytes(sip)] = who
            return who
        mesh = self._mesh_endpoints(plain)
        if mesh:
            return self.decryptor.short_to_ext.get(mesh[0])
        sender = ext or self.decryptor.short_to_ext.get(short or "")
        rloc16 = short or ((self.seen.table.get(sender) or {}).get("rloc16") if sender else None)
        if (rloc16_role(rloc16) or {}).get("role") != "router":
            return sender
        return self._srp_sources.get(bytes(sip)) if sip else None

    @staticmethod
    def _mesh_endpoints(plain: bytes) -> tuple[str, str] | None:
        """The 6LoWPAN mesh header's originator and final destination
        (short addresses, hex), when the frame carries one: a frame on a
        multi-hop path names the devices at its ends there, and its MAC
        addresses name only this hop's."""
        if not plain or (plain[0] >> 6) != 0b10:
            return None
        deep = (plain[0] & 0x0F) == 0x0F
        off = 1 + (1 if deep else 0)
        if len(plain) < off + 4:
            return None
        return plain[off:off + 2].hex(), plain[off + 2:off + 4].hex()

    @staticmethod
    def _aloc_label(ip: bytes | None) -> str | None:
        """'anycast fc11' for a Thread service anycast locator, else None."""
        if ip is None or len(ip) != 16 or ip[8:14] != b"\x00\x00\x00\xff\xfe\x00" or ip[14] != 0xfc:
            return None
        return f"anycast {ip[14]:02x}{ip[15]:02x}"

    MATTER_INSTANCES_MAX = 8

    def _note_matter_identity(self, client: str, srp: dict, ts: float) -> None:
        """The ``_matter._tcp`` service names a device registers, one per
        fabric, are its identity across the extended addresses it may use:
        a reboot after a firmware update gave one a new address on
        2026-09-22, and its registration under it carried the same three
        names. They are kept with the row, and an address registering a
        name another address holds is that device under a new address."""
        row = self.seen.table.get(client)
        if row is None:
            return          # not heard on its own yet (the first frame of a new address): next time
        instances = {str(i).lower() for i in srp["instances"]}
        host = srp.get("host")
        if srp.get("partial"):
            # A fragment of a registration: what it names is added to
            # what is known; the host waits for a registration heard whole.
            instances |= set(row.get("matter_instances") or [])
            host = row.get("srp_host")
        instances = sorted(instances)[:self.MATTER_INSTANCES_MAX]
        if row.get("srp_host") != host or row.get("matter_instances") != instances:
            row["srp_host"], row["matter_instances"] = host, instances
            self.seen._dirty = True
        previous = None
        for inst in instances:
            holder = self._matter_owner.get(inst)
            self._matter_owner[inst] = (client, ts)
            if (holder is not None and holder[0] != client and holder[1] <= ts and previous is None
                    and not self._heard_since_start(holder[0], client)):
                previous = (holder[0], inst.split(".")[0])
        if previous is not None:
            self._device_rotated(previous[0], client, ts,
                                 f"its SRP registration carries the Matter service name {previous[1]} "
                                 f"that {previous[0]} registered")

    def _heard_since_start(self, old: str, new: str) -> bool:
        """Whether ``old`` was on air after ``new`` began: two devices, not
        one that rebooted under a new address. A rotation is a reboot, so the
        old address falls silent before the new one's first frame."""
        old_row, new_row = self.seen.table.get(old), self.seen.table.get(new)
        if old_row is None or new_row is None:
            return False
        started = max(new_row.get("first_seen", 0.0), new_row.get("resumed_ts", 0.0))
        return old_row.get("last_seen", 0.0) > started

    def _device_rotated(self, previous: str, addr: str, now: float, evidence: str) -> str | None:
        """``addr`` is the device that was ``previous``. The new address
        takes the name (names.rotate: learned, and remembered in
        device-rotations.json), the old row is retired so it is not
        reported quiet, and the rotation is said once. Returns the name.

        Retiring an address on a claim is what the mDNS path refuses to
        do without the radio's corroboration, because mDNS is anyone on
        the LAN. This evidence is not: an SRP registration arrives inside
        the mesh, decrypted under the network key from a frame whose
        counter was fresh, naming the device's own Matter identity; and
        the HA map's address comes from the Matter Server, which read it
        from the device over its own session. Whoever could forge either
        is already on the mesh with the key, past what the recorder
        guards against."""
        old_name, new_name = self.names.name(previous), self.names.name(addr)
        if old_name and new_name and old_name != new_name:
            # devices.json names both, differently: the inventory stands.
            # It may be wrong, but that is the operator's to settle.
            print(f"[threadwatch] {addr} registered as {old_name!r} ({previous}) but devices.json calls it "
                  f"{new_name!r}; the inventory stands", file=sys.stderr, flush=True)
            return new_name
        name, fresh = self.names.rotate(addr, previous, evidence, now)
        self._retire_rotated(previous, addr, name, now)
        if fresh:
            label = name or addr
            fix = f'threadwatch name {addr} "{name}"' if name else f'threadwatch name {addr} "<name>"'
            self._emit("device_address_changed", "notice", now, addr=addr, name=name, previous=previous,
                       evidence=evidence,
                       note=(f"{label} now answers to {addr}, was {previous}: {evidence}, so it is the same "
                             f"device under a new extended address (a reboot after a firmware update can do "
                             f"this). {previous} is retired, not reported quiet. "
                             + (f"Named from its entry; confirm with: {fix}" if name
                                else f"Not in devices.json: {fix}")))
        return name

    def _retire_rotated(self, previous: str, addr: str, name: str | None, now: float) -> None:
        """rotated_to on the old row: out of the quiet, link and starvation
        checks, and the devices page says where it went. The new address
        is live by definition, even if it was itself retired once."""
        new_row = self.seen.table.get(addr)
        if new_row is not None and new_row.pop("rotated_to", None):
            self.seen._dirty = True
        old_row = self.seen.table.get(previous)
        if old_row is None or old_row.get("rotated_to") == addr:
            return
        old_row["rotated_to"] = addr
        old_row.pop("quiet_reported_ts", None)
        was_quiet = old_row.pop("quiet_reported", None) or previous in self.quiet_reported
        self.quiet_reported.discard(previous)
        self.seen._dirty = True
        if was_quiet:
            self._emit("device_returned", "notice", now, addr=previous, name=name,
                       note=f"back under a new address, {addr}")

    # How long a registration's request stands for its answer. Answers come
    # back within a second or two; a request whose answer the sniffer missed
    # must not stand for longer, or the next device to draw the same 16-bit
    # id has its answer credited to the one that asked hours ago.
    SRP_REQUEST_S = 120

    SRP_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
                  6: "YXDOMAIN", 7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE"}

    def _note_srp(self, srp: dict, ts: float, vouched: bool = False) -> None:
        """An SRP registration (DNS UPDATE) request or response. A device
        refused [srp] refusals times in a row is srp_refused (warning);
        the next accepted registration is srp_accepted (info). The streak
        lives in the device's last-seen row, so it survives a restart, as
        it must: a refused client retries hourly. A request heard whole
        also says which Matter service names the device registers, its
        identity across addresses (_note_matter_identity), but only from
        a frame the MAC layer vouched for (``vouched``)."""
        # Bound the transaction tables: ids are 16 bits and a mesh
        # registers a few dozen times an hour.
        if len(self._srp_requests) > 256:
            cutoff = ts - self.SRP_REQUEST_S
            self._srp_requests = {k: v for k, v in self._srp_requests.items() if v[1] >= cutoff}
        if len(self._srp_answered) > 256:
            cutoff = ts - 120
            self._srp_answered = {k: v for k, v in self._srp_answered.items() if v >= cutoff}
        if srp["kind"] == "request":
            if srp["client"]:
                self._want_identity(srp["client"], ts)
            prior = self._srp_requests.get(srp["id"])
            if srp["client"] and (prior is None or ts - prior[1] > self.SRP_REQUEST_S):
                self._srp_requests[srp["id"]] = (srp["client"], ts)
            if vouched and srp["client"] and srp.get("instances"):
                self._note_matter_identity(srp["client"], srp, ts)
            return
        answered = self._srp_answered.get(srp["id"])
        if answered is not None and ts - answered < 30:
            return                                      # the same answer on its next hop
        self._srp_answered[srp["id"]] = ts
        request = self._srp_requests.pop(srp["id"], None)
        if request is not None and ts - request[1] > self.SRP_REQUEST_S:
            request = None                              # an old one whose answer went unheard
        client = request[0] if request else srp["client"]
        if not client or client not in self.seen.table:
            return
        row = self.seen.table[client]
        state = row.setdefault("srp", {"refused": 0, "since": None, "last_rcode": None,
                                       "last_ts": None, "accepted_ts": None, "reported": False})
        rcode = srp["rcode"]
        state["last_rcode"], state["last_ts"] = rcode, ts
        self.seen._dirty = True
        name = self.names.name(client)
        label = name or client
        if rcode == 0:
            if state["reported"]:
                since = state["since"] or ts
                self._emit("srp_accepted", "info", ts, addr=client, name=name, refusals=state["refused"],
                           since=since, refused_for_s=round(ts - since), server=srp.get("server"),
                           note=f"{label}'s SRP registration was accepted after {state['refused']} refusals "
                                f"over {fmt_span(ts - since)}: its host and service records are current again")
            # A streak that ended inside its grace was never said: nothing to close.
            state.update({"refused": 0, "since": None, "accepted_ts": ts, "reported": False, "pending_ts": None})
            return
        state["refused"] += 1
        state["last_rcode"], state["server"] = rcode, srp.get("server")
        if state["since"] is None:
            state["since"] = ts
        if state["reported"] or state["refused"] < self.cfg.srp_refusals:
            return
        # Enough refusals: said once the streak has outlasted [srp] grace_s
        # with no acceptance (periodic), or at the next refusal past it.
        # On 2026-09-22 the third refusal of a two-hour streak paged ten
        # seconds before the retry that was accepted.
        if state.get("pending_ts") is None:
            state["pending_ts"] = ts
        if ts - state["pending_ts"] >= self.cfg.srp_grace_s:
            self._emit_srp_refused(client, state, ts)

    def _emit_srp_refused(self, client: str, state: dict, now: float) -> None:
        state["reported"], state["pending_ts"] = True, None
        name = self.names.name(client)
        label = name or client
        code = self.SRP_RCODES.get(state["last_rcode"], f"rcode {state['last_rcode']}")
        since, last = state["since"], state["last_ts"]
        accepted = state.get("accepted_ts")
        last_ok = (f"its last accepted registration was {fmt_span(last - accepted)} ago" if accepted
                   else "no accepted registration of its has been heard")
        self._emit("srp_refused", "warning", now, addr=client, name=name, rcode=state["last_rcode"],
                   rcode_name=code, refusals=state["refused"], since=since, refused_for_s=round(last - since),
                   accepted_ts=accepted, server=state.get("server"),
                   note=f"{label}'s SRP registration has been refused {state['refused']} times over "
                        f"{fmt_span(last - since)} ({code}); {last_ok}. The SRP server (a border router: an "
                        "Apple TV or the OTBR) will not take its host and Matter service records, so a "
                        "controller that finds it through mDNS (Apple Home) loses it once the last accepted "
                        "registration expires, while Home Assistant keeps the address it has and may not "
                        "notice. The device retries with backoff, hourly at the cap; the refusal is the "
                        "server's to explain")

    def _check_srp_pending(self, now: float) -> None:
        """Refusal streaks past the count whose grace has run out with no
        acceptance heard: said now."""
        for addr, row in self.seen.table.items():
            state = row.get("srp")
            if not state or state.get("reported") or state.get("pending_ts") is None:
                continue
            if now - state["pending_ts"] >= self.cfg.srp_grace_s:
                self._emit_srp_refused(addr, state, now)
                self.seen._dirty = True

    def _apply_mle(self, f: Frame, info, src_for_mle: str | None) -> None:
        """What a fresh, authenticated MLE message changes: the sender's
        short address, the partition it reports, and the rejoin it
        announces. Kept apart from decoding because a MIC alone does not
        make a message current - a recording of one carries the same MIC.
        Applied on a stale message, this reverted the partition and the
        device's RLOC to what they were when it was captured and paged for
        a change that never happened."""
        if src_for_mle and info.command_name in MLE_EXCHANGE_COMMANDS:
            peer = f.dst if f.dst and len(f.dst) == 16 else self.decryptor.short_to_ext.get(f.dst)
            exchange = {"ts": f.ts, "command": info.command_name, "sender": src_for_mle,
                        "receiver": peer, "packet": self._journal_packet(f),
                        "key_sequence": info.key_sequence,
                        "completed_attachment": "unknown"}
            for addr in (src_for_mle, peer):
                if addr and (addr in self._journal_exchanges or len(self._journal_exchanges) < 1024):
                    self._journal_exchanges.setdefault(addr, deque(maxlen=8)).append(exchange)
        if src_for_mle and src_for_mle in self.seen.table:
            for layer, value in (("mac", info.link_frame_counter), ("mle", info.mle_frame_counter)):
                if value is not None:
                    self._note_advertised(src_for_mle, layer, info.key_sequence, value, info.command_name, f.ts)
        if info.source_addr16 is not None and src_for_mle:
            short = f"{info.source_addr16:04x}"
            self._note_rloc16(src_for_mle, short, f.ts)
            self.decryptor.short_to_ext[short] = src_for_mle
        if info.command_name == "Child Update Response" and f.dst not in (None, "ffff"):
            # Only ever a reply: the child asked within the last second.
            self._vouch(f.dst, f.ts, "parent")
        if info.command_name in MLE_REJOIN_COMMANDS:
            # addr is the extended address (the review pages key on it);
            # src is whatever the frame carried, often a short address.
            name = self.names.name(src_for_mle) if src_for_mle else None
            row = self.seen.table.get(src_for_mle) if src_for_mle else None
            if row is not None:
                # When the device last tried to get back: the key-lag
                # detector reads it to say a cleared lag followed a rejoin,
                # and the HA availability check reads it the same way.
                row["rejoin_ts"] = f.ts
                self.seen._dirty = True
            self._note_rejoin(f.ts, info.command_name, f.src, src_for_mle, name)
        if info.partition_id is not None and self._leader_data_is_current(info, src_for_mle):
            self._note_partition((info.partition_id, info.leader_router_id), f.ts,
                                 src_for_mle, info.route_id_sequence)

    def _leader_data_is_current(self, info, sender: str | None) -> bool:
        """Whether the message's Leader Data is the sender's own view of the
        partition: a command only routers send, or a sender holding a
        router's RLOC16 (the message's Source Address, else the row's).
        A child's Child Update Request repeats what its parent last told
        it; after a merge that keeps children attached, each sleepy
        child's next update still names the old partition, which flipped
        the tracker there and back and paged a storm that never happened."""
        if info.command_name in MLE_ROUTER_COMMANDS:
            return True
        if info.source_addr16 is not None:
            short = f"{info.source_addr16:04x}"
        else:
            row = self.seen.table.get(sender) if sender else None
            short = row.get("rloc16") if row else None
        return (rloc16_role(short) or {}).get("role") == "router"

    # The name scraper is a regex over decrypted UDP payloads, most of
    # which are ciphertext: it fires on random bytes now and then, and an
    # address would otherwise collect a junk "name" every few hours for
    # ever. A real SRP registration recurs (leases are renewed), so only
    # what has been seen twice is a name to suggest (names.MIN_SIGHTINGS),
    # and each address keeps at most this many, the least-sighted going
    # first when a new one arrives.
    OBSERVED_NAMES_MAX = 16

    # ------------------------------------------------- partition and leader

    def _note_partition(self, cur: tuple, ts: float, sender: str | None, sequence: int | None) -> None:
        """A fresh MLE message's Leader Data (partition id, leader router
        id) and Route64 ID sequence. A change of partition or leader is
        held for [partition] settle_s and judged in _settle_partition: one
        state inside the window is a change, several are a storm. The ID
        sequence is followed only while the partition is stable, since a
        storm's flips each carry their own leader's count."""
        if self.partition is None:
            self.partition = cur
            self._reset_leader_pulse(sequence, ts, sender)
            return
        # A hole in the capture (a stalled dongle, a copy of the ring with
        # an hour missing) is not the leader falling silent: the pulse
        # starts over at the first sequence heard after it.
        last = self.last_frame
        if last is not None and ts - last.ts > self.cfg.partition_stall_s:
            self._reset_leader_pulse(None, ts, None)
        hold = self._partition_hold
        if cur != self.partition:
            if hold is None:
                hold = self._partition_hold = {"previous": self.partition, "first_ts": ts,
                                               "last_ts": ts, "states": [], "changes": 0}
                self._partition_changed_ts = ts
            if cur not in (state for state, _ in hold["states"]):
                hold["states"].append((cur, ts))
            hold["changes"] += 1
            hold["last_ts"] = ts
            self.partition = cur
            self._close_leader_stall(ts, "the partition or its leader changed")
            self._reset_leader_pulse(sequence, ts, sender)
            return
        if hold is not None and ts - hold["last_ts"] >= self.cfg.partition_settle_s:
            self._settle_partition(ts)
        elif hold is None:
            self._note_route_sequence(sequence, ts, sender)

    # ------------------------------------------------------- router set

    @staticmethod
    def _router_set(sample: dict) -> dict[int, dict] | None:
        """router id -> {rloc16, addr} from a sample's router table, or
        None when the sample has no usable table."""
        from .otbr import _ext, _rloc
        result = (sample.get("commands") or {}).get("router table") or {}
        if result.get("status") != "ok":
            return None
        routers = {}
        for row in result.get("rows") or []:
            rid = row.get("id")
            if rid is None or not str(rid).isdigit():
                continue
            ext = _ext(row)
            routers[int(rid)] = {"rloc16": _rloc(row), "addr": None if ext in (None, "0" * 16) else ext}
        return routers

    def _check_router_set(self, samples: list[dict], now: float) -> None:
        """router_set_changed: the OTBR's router table gained or lost
        router ids between two inventory samples. The table lists every
        router id the leader has allocated, so a change is a promotion or
        a demotion somewhere on the mesh, which nothing on air says
        plainly. Compared once per new sample; the first sample after a
        start is only remembered."""
        usable = [x for x in samples if self._router_set(x) is not None]
        if not usable:
            return
        newest = usable[-1]
        ts = newest.get("started_at")
        if self._router_set_ts is None or ts is None:
            self._router_set_ts = ts
            return
        if ts <= self._router_set_ts:
            return
        previous = None
        for x in reversed(usable[:-1]):
            if (x.get("started_at") or 0) <= self._router_set_ts:
                previous = x
                break
        self._router_set_ts = ts
        if previous is None:
            return
        before, after = self._router_set(previous), self._router_set(newest)
        promoted = [rid for rid in sorted(after) if rid not in before]
        demoted = [rid for rid in sorted(before) if rid not in after]
        if not promoted and not demoted:
            return

        def describe(rid, table):
            entry = table[rid]
            addr = entry.get("addr")
            name = self.names.name(addr) if addr else None
            return {"router_id": rid, "rloc16": entry.get("rloc16"), "addr": addr, "name": name,
                    "label": f"{name or addr or '?'} r{rid}"}
        up = [describe(r, after) for r in promoted]
        down = [describe(r, before) for r in demoted]
        changed = self._partition_changed_ts
        follows = (f", after the partition change at {time.strftime('%H:%M:%S', time.localtime(changed))}"
                   if changed is not None and 0 <= ts - changed <= 1800 else "")
        parts = []
        if up:
            parts.append(f"{len(up)} promoted ({', '.join(d['label'] for d in up)})")
        if down:
            parts.append(f"{len(down)} demoted ({', '.join(d['label'] for d in down)})")
        self._emit("router_set_changed", "notice", ts, promoted=up, demoted=down, routers=len(after),
                   previous_routers=len(before), previous_sample_ts=previous.get("started_at"), sample_ts=ts,
                   note=f"router set changed between the OTBR inventory samples of "
                        f"{time.strftime('%H:%M', time.localtime(previous.get('started_at') or ts))} and "
                        f"{time.strftime('%H:%M', time.localtime(ts))}: " + ", ".join(parts)
                        + f"; {len(after)} routers now{follows}")

    def lost_leader_for(self, addr: str | None) -> dict | None:
        """The record of the leader a partition change or storm replaced,
        when it is this device: what device_quiet and the HA cause read
        to say that its silence is the leader dying, not reception."""
        lost = self._lost_leader
        if not addr or not lost or lost.get("addr") != addr:
            return None
        return lost

    def _ha_unavailable_since(self, addr: str) -> float | None:
        """When Home Assistant marked this device unavailable, if its
        episode is open; None otherwise or without the check."""
        tracker = self._haavail
        if tracker is None:
            return None
        for ep in tracker.status().get("open", ()):
            if (ep.get("addr") or "").lower() == addr:
                return ep.get("since")
        return None

    def _reset_leader_pulse(self, sequence: int | None, ts: float, sender: str | None) -> None:
        self._leader_seq = sequence
        self._leader_seq_ts = ts if sequence is not None else None
        self._leader_seq_from = sender if sequence is not None else None

    def _note_route_sequence(self, sequence: int | None, ts: float, sender: str | None) -> None:
        """The ID sequence is a byte that wraps: newer is one to 127 ahead."""
        if sequence is None:
            return
        if self._leader_seq is None or 0 < ((sequence - self._leader_seq) & 0xFF) < 128:
            self._leader_seq, self._leader_seq_ts, self._leader_seq_from = sequence, ts, sender
            self._close_leader_stall(ts, "the sequence is advancing again")

    def _close_leader_stall(self, ts: float, how: str) -> None:
        ep = self._leader_stalled
        if ep is None:
            return
        self._leader_stalled = None
        self._emit("leader_resumed", "info", ts, partition=ep["partition"],
                   leader_router=ep["leader_router"], leader=ep["leader"], addr=ep.get("addr"),
                   name=ep.get("name"), since=ep["since"], stalled_for_s=round(ts - ep["since"]),
                   note=f"leader {ep['leader']}: {how} after {fmt_span(ts - ep['since'])}")

    def _check_leader(self, now: float) -> None:
        """leader_stalled: the current partition's ID sequence has not
        advanced for [partition] stall_s although the mesh is still heard.
        The leader increments it every few seconds while its timers run;
        the routers give it up 120 s after the last advance they saw and
        each starts a partition of its own, so this is the warning before
        that storm, with the leader named."""
        part = self.partition
        seq_ts = self._leader_seq_ts
        if part is None or seq_ts is None or self._partition_hold is not None or self._leader_stalled is not None:
            return
        stalled = now - seq_ts
        if stalled < self.cfg.partition_stall_s:
            return
        heard = self._last_frame_heard()
        if heard is None or now - heard > self.cfg.partition_stall_s:
            return                      # nothing is heard: the sniffer is the one that is silent
        who = self.leader_device(part[1])
        addr = who.get("leader_addr")
        row = self.seen.table.get(addr) if addr else None
        last_seen = row.get("last_seen") if row else None
        label = self.leader_label(part[1])
        silent = None if last_seen is None else max(0.0, now - last_seen)
        if silent is None:
            tail = "the sniffer has no frame from the leader itself to date it by"
        elif silent > self.cfg.partition_stall_s:
            tail = f"the leader itself has not been heard for {fmt_span(silent)}: it is gone"
        else:
            tail = (f"the leader's own last frame was {fmt_span(silent)} ago: its stack still answers "
                    "while its leader timer has stopped")
        self._leader_stalled = {"partition": part[0], "leader_router": part[1], "leader": label,
                                "addr": addr, "name": who.get("leader_name"), "since": seq_ts}
        self._emit("leader_stalled", "warning", now, partition=part[0], leader_router=part[1],
                   leader=label, addr=addr, name=who.get("leader_name"), id_sequence=self._leader_seq,
                   since=seq_ts, stalled_for_s=round(stalled), last_carried_by=self._label(self._leader_seq_from),
                   leader_last_seen=last_seen, leader_silent_for_s=None if silent is None else round(silent),
                   note=f"leader {label} has not advanced the router-id sequence ({self._leader_seq}) for "
                        f"{fmt_span(stalled)} while the mesh is still heard; {tail}. The routers give a "
                        "leader up 120 s after the last advance and each starts a partition of its own")

    def _settle_partition(self, now: float) -> None:
        """Log the held partition change(s): one state is a change, more
        is a storm. Called once the window has passed without a flip."""
        hold = self._partition_hold
        if hold is None:
            return
        self._partition_hold = None
        prev, cur = hold["previous"], self.partition
        before, after = self.leader_label(prev[1]), self.leader_label(cur[1])
        previous = {"partition": prev[0], "leader_router": prev[1], "leader": before}
        current = {"partition": cur[0], "leader_router": cur[1], "leader": after}
        if prev[1] != cur[1]:
            who = self.leader_device(prev[1])
            self._lost_leader = {"addr": who.get("leader_addr"), "name": who.get("leader_name"),
                                 "leader_router": prev[1], "partition": prev[0], "ts": hold["first_ts"],
                                 "leader": before, "successor": after}
        states = hold["states"]
        if len(states) == 1 and hold["changes"] == 1:
            self._emit("partition_or_leader_change", "warning", hold["first_ts"],
                       previous=previous, current=current,
                       note=f"partition {prev[0]} leader {before} -> partition {cur[0]} leader {after}: "
                            "the mesh split, merged or elected a new leader")
            return
        seen = [prev] + [state for state, _ in states]
        leaders = []
        for state in seen:
            label = self.leader_label(state[1])
            if label not in leaders:
                leaders.append(label)
        duration = hold["last_ts"] - hold["first_ts"]
        if prev[1] == cur[1] and prev[0] == cur[0]:
            what = (f"the mesh split into {len(states)} partitions and merged back under {after} "
                    f"after {fmt_span(duration)} ({hold['changes']} flips)")
        elif prev[1] == cur[1]:
            what = (f"the mesh split into {len(states)} partitions and merged under the same leader {after}, "
                    f"partition {cur[0]}, after {fmt_span(duration)} ({hold['changes']} flips)")
        else:
            what = (f"leader {before} lost: {len(states)} partitions each led by a router of its own "
                    f"for {fmt_span(duration)} ({hold['changes']} flips) before the mesh merged under {after}")
        self._emit("partition_storm", "warning", hold["first_ts"], previous=previous, current=current,
                   partitions=len(states), leaders=leaders, changes=hold["changes"],
                   since=hold["first_ts"], until=hold["last_ts"], duration_s=round(duration, 1),
                   note=f"{what}: every router hit the leader-age timeout together and re-elected; "
                        "sleepy children re-attach in the minute after")

    # ------------------------------------------------------------ rejoins

    def _note_rejoin(self, ts: float, command: str, src: str | None, addr: str | None,
                     name: str | None) -> None:
        """A Parent Request or Child ID Request. Held for [rejoins] wave_s
        after the last one: a batch from several devices is one
        rejoin_wave, a smaller batch goes out as the mle_rejoin_attempt
        notices it always was (_settle_rejoins)."""
        fields = {"command": command, "src": src, "addr": addr, "name": name,
                  "note": f"{command} from {name or addr or src}: it lost its parent or its "
                          "network and is trying to get back"}
        if self.cfg.rejoin_wave_s <= 0:
            self._emit("mle_rejoin_attempt", "notice", ts, **fields)
            return
        wave = self._rejoin_wave
        if wave is not None and ts - wave["last_ts"] > self.cfg.rejoin_wave_s:
            self._settle_rejoins(ts)
            wave = None
        if wave is None:
            wave = self._rejoin_wave = {"first_ts": ts, "last_ts": ts, "devices": {}, "records": []}
        wave["last_ts"] = max(wave["last_ts"], ts)
        key = addr or src or "?"
        dev = wave["devices"].setdefault(key, {"addr": addr, "src": src, "name": name,
                                               "first": ts, "last": ts, "attempts": 0, "commands": {}})
        dev["last"] = max(dev["last"], ts)
        dev["attempts"] += 1
        dev["commands"][command] = dev["commands"].get(command, 0) + 1
        wave["records"].append((ts, fields))

    def _rejoin_trigger(self, first_ts: float) -> str | None:
        """What a batch of rejoins that started at first_ts follows: a
        partition change or storm inside five minutes either side, or
        nothing the recorder saw."""
        changed = self._partition_changed_ts
        if changed is not None and abs(first_ts - changed) <= 300:
            return f"the partition change at {time.strftime('%H:%M:%S', time.localtime(changed))}"
        return None

    def _settle_rejoins(self, now: float) -> None:
        """Log the held rejoin batch: one rejoin_wave for several devices
        (the per-device attempts still reach the key journal), the
        individual notices for a small one."""
        wave = self._rejoin_wave
        if wave is None:
            return
        self._rejoin_wave = None
        devices = wave["devices"]
        trigger = self._rejoin_trigger(wave["first_ts"])
        if len(devices) < self.cfg.rejoin_wave_devices and not (trigger and len(devices) >= 2):
            for ts, fields in wave["records"]:
                self._emit("mle_rejoin_attempt", "notice", ts, **fields)
            return
        from .alerts import record_id
        rows = sorted(devices.values(), key=lambda d: d["first"])
        commands: dict[str, int] = {}
        for d in rows:
            for c, n in d["commands"].items():
                commands[c] = commands.get(c, 0) + n
        names = [d["name"] or d["addr"] or d["src"] or "?" for d in rows]
        listed = ", ".join(names[:12]) + (f" and {len(names) - 12} more" if len(names) > 12 else "")
        duration = wave["last_ts"] - wave["first_ts"]
        cause = f" after {trigger}" if trigger else ""
        self._last_rejoin_wave = {"first_ts": wave["first_ts"], "last_ts": wave["last_ts"],
                                  "devices": len(rows), "trigger": trigger}
        self._emit("rejoin_wave", "notice", wave["first_ts"], devices=len(rows),
                   attempts=sum(d["attempts"] for d in rows), commands=commands, names=names,
                   since=wave["first_ts"], until=wave["last_ts"], duration_s=round(duration, 1),
                   trigger=trigger,
                   note=f"{len(rows)} devices re-attached over {fmt_span(duration)}{cause}: {listed}. "
                        + ("Their parents detached and came back; each child found a parent again."
                           if trigger else
                           "No partition change was seen: a parent router of theirs rebooted or "
                           "dropped them, or the sniffer missed the change."))
        # The key journal keeps each device's attempt as evidence, as it did
        # when every attempt was its own record.
        for ts, fields in wave["records"]:
            record = {"ts": ts, "event": "mle_rejoin_attempt", "severity": "notice", **fields}
            record["id"] = record_id(record)
            self.journal.event(record, source="replay" if self.ephemeral else "event_log")

    def _rejoin_context(self, ts: float) -> dict:
        """What the retransmission detector should say when retries rise
        while the mesh is re-attaching: the rejoin wave or partition
        change inside the last five minutes, if any."""
        wave = self._rejoin_wave
        if wave is not None and ts - wave["first_ts"] <= 300 \
                and len(wave["devices"]) >= self.cfg.rejoin_wave_devices:
            return {"devices": len(wave["devices"]), "since": wave["first_ts"],
                    "trigger": self._rejoin_trigger(wave["first_ts"])}
        last = self._last_rejoin_wave
        if last is not None and ts - last["last_ts"] <= 300:
            return {"devices": last["devices"], "since": last["first_ts"], "trigger": last["trigger"]}
        changed = self._partition_changed_ts
        if changed is not None and ts - changed <= 300:
            return {"devices": 0, "since": changed,
                    "trigger": f"the partition change at {time.strftime('%H:%M:%S', time.localtime(changed))}"}
        return {}

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

    def periodic(self, now: float, final: bool = False) -> None:
        """Run every ~30 s in live capture: quiet checks, persistence.
        final: the last call of a replay, which logs what is still held."""
        self._check_clock(now)
        hold = self._partition_hold
        if hold is not None and (final or now - hold["last_ts"] >= self.cfg.partition_settle_s):
            self._settle_partition(now)
        self._check_leader(now)
        self._check_srp_pending(now)
        wave = self._rejoin_wave
        if wave is not None and (final or now - wave["last_ts"] >= self.cfg.rejoin_wave_s):
            self._settle_rejoins(now)
        self.seen.maybe_save()
        self.journal.save(now)
        self._check_credentials(now)
        self._check_configured_pan(now)
        if not self.ephemeral and self.cfg.border_router_browse_s > 0:
            self._poll_border_routers(now)
        if not self.ephemeral and self.cfg.ha_logs_enabled and self.cfg.ha_logs_retry:
            self._poll_ha_logs(now)
        if not self.ephemeral and self.cfg.ha_logs_enabled and self.cfg.ha_logs_archive:
            self._poll_ha_archive(now)
        if not self.ephemeral and self.cfg.ha_availability_enabled:
            self._poll_ha_availability(now)
        if self._otbr_inventory is not None:
            self._otbr_inventory.tick(now)
            samples = self._otbr_inventory.history.get("samples", [])
            if samples:
                self.journal.inventory(samples[-1])
                self._check_router_set(samples, now)
        # Devices on another PAN (a neighbour's mesh, an unpaired device
        # announcing itself) are tracked for the report but never alerted on:
        # their absence says nothing about this network.
        dominant = self.dominant_pan()
        for addr, row in list(self.seen.table.items()):      # a filed visit drops its row
            if addr in self.quiet_reported or row.get("rotated_to"):
                continue
            pan = row.get("pan")
            if dominant is not None and pan is not None and pan != dominant:
                continue
            if self._is_quiet(addr, row, now):
                self._report_quiet(addr, row, now)
        self._forget_unnamed(now)
        self._check_links(now, dominant)
        self._check_key_lag(now, dominant)
        self._maybe_census(now, dominant)
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
                if row.get("unserved"):
                    self._close_unserved(addr, row, now, retired)
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

    def _close_unserved(self, addr: str, row: dict, now: float, retired: bool) -> None:
        """And for an announced poll_unserved: only a delivered frame closes
        it, and a device that has stopped polling is owed none. Left open,
        hacause would blame the parent for the device's own death."""
        for key in ("unserved", "unserved_confirm_at", "unserved_since"):
            row.pop(key, None)
        row["unserved_closed"] = now
        self.seen._dirty = True
        stats = self.devices.get(addr)
        if stats is not None:
            self._clear_wait(addr, stats)
            stats.unserved, stats.unserved_confirm_at = False, None
            stats.unserved_polls, stats.unserved_since = 0, None
        self._emit("poll_served", "notice", now, addr=addr, name=self.names.name(addr),
                   note=("this address was retired when the device rotated: the undelivered polls "
                         "it was carrying are closed with it" if retired else
                         "the device has stopped polling altogether: the undelivered polls are "
                         "closed here, and the silence is the story from now on"))

    # ------------------------------------------------ snapshot on critical

    AUTO_SNAPSHOT_COOLDOWN_S = 6 * 3600
    AUTO_SNAPSHOT_RETRY_S = 30 * 60      # after a failed copy: the next critical event tries again

    def _emit_storm(self, stage: str, ts: float) -> None:
        """phase_locked_storm at its two stages. The call is a notice, not a
        page: Home Assistant's Matter Server sweeping every node and a hub
        re-establishing its sessions both look like the storm for a few
        onsets and are over before it confirms. It takes the snapshot the
        critical used to take (the packets matter whether or not the storm
        confirms) and says what the floods followed; the critical says how
        long they have persisted and names that snapshot rather than
        reserving a second one."""
        det = self.detector
        details = det.storm_details
        period = details.get("period")
        onsets = details.get("onsets") or []
        since = det.storm_since or (onsets[0] if onsets else ts)
        confirm = self.cfg.detector.confirm_s
        fields = dict(period_s=round(period, 1) if period else None, onsets=len(onsets), onset_times=onsets,
                      confirmed=stage == "critical", **det.snapshot())
        fields["storm_since"] = since
        every = f"every {period:.0f} s" if period else "at a steady period"
        if stage == "warning":
            context = self._storm_context(since)
            fields["note"] = (f"traffic floods recurring {every} ({len(onsets)} onsets): the storm signature"
                              + (f"; began {context}" if context else "")
                              + (f". Critical if the floods persist for {fmt_span(confirm)}; a hub "
                                 "re-establishing its sessions after a border router restart looks the same "
                                 "and clears before that" if confirm > 0 else ""))
            fields["follows"] = context
            label = self._auto_snapshot(ts, "phase_locked_storm")
            self._storm_snapshot = label
            fields["auto_snapshot"] = label
            fields["note"] += (f"; the ring is being saved as {label}" if label
                               else "; run 'threadwatch snapshot' to keep the packets")
            self._emit("phase_locked_storm", "notice", ts, **fields)
            if label:
                self.snapshotter(label, "phase_locked_storm")
            return
        lasted = max(0.0, det.last_flood - since)
        fields["note"] = (f"traffic floods have recurred {every} for {fmt_span(lasted)} ({len(onsets)} periodic "
                          f"onsets since {time.strftime('%H:%M:%S', time.localtime(since))}): the phase-locked "
                          "storm; on 2026-09-01 only powering the hub off ended it")
        if self._storm_snapshot:
            fields["keep_packets"] = f"the ring was saved as {self._storm_snapshot} when the storm was called"
        self._emit("phase_locked_storm", "critical", ts, **fields)

    def _storm_context(self, since: float) -> str | None:
        """What a surge that began at ``since`` followed inside the
        previous 15 minutes: a border router changing address (a hub
        rebooted), a partition change, or nothing the recorder saw."""
        changed = self._border_router_changed
        if changed and 0 <= since - changed[0] <= 900:
            return (f"after {changed[1] or 'a border router'} came back under a new address at "
                    f"{time.strftime('%H:%M:%S', time.localtime(changed[0]))}")
        part = self._partition_changed_ts
        if part is not None and abs(since - part) <= 900:
            return f"around the partition change at {time.strftime('%H:%M:%S', time.localtime(part))}"
        return None

    # What `mute` in devices.json covers: the records a flaky device makes
    # about itself (ha_unavailable, the fourth, is haavail's). Mesh trouble
    # a muted device is part of (key_lag, frame_counter_mismatch,
    # srp_refused) and its parent dropping its polls (poll_unserved) still
    # page: those are about more than the device.
    MUTED_EVENTS = frozenset({"device_quiet", "poll_starvation", "rssi_degradation"})

    def _emit(self, event: str, severity: str = "info", ts: float | None = None,
              **fields) -> dict:
        """Log an event, and save the ring when it is a critical one. Every
        event the pipeline raises goes through here rather than straight to
        events.emit, so what keeps the packets is the severity and not a
        call some future handler has to remember to make. The two paths
        that stay on events.emit say why where they are.

        A MUTED_EVENTS record carries `muted`; for a device the inventory
        mutes it is at most a notice, and its note says so.

        A critical event carries auto_snapshot (the snapshot label, or None
        when saving is off, replaying, or inside the cooldown) and a
        closing sentence saying where its packets went."""
        ts = time.time() if ts is None else ts
        if event in self.MUTED_EVENTS:
            muted = self.names.muted(fields["addr"])
            fields["muted"] = muted
            if muted:
                if severity in ("warning", "critical"):
                    severity = "notice"
                note = fields.get("note") or ""
                sep = " " if note.endswith((".", ".)")) or not note else ". "
                fields["note"] = f"{note}{sep}Muted in devices.json: logged, not paged."
        label = None
        if severity == "critical":
            # keep_packets: the caller already has the packets (a notice
            # stage took the snapshot) and says so; no second reservation.
            earlier = fields.pop("keep_packets", None)
            if earlier:
                fields["auto_snapshot"] = None
                keep = earlier
            else:
                label = self._auto_snapshot(ts, event)
                fields["auto_snapshot"] = label
                keep = (f"the ring is being saved as {label}" if label
                        else "run 'threadwatch snapshot' to keep the packets")
            note = fields.get("note")
            fields["note"] = f"{note}; {keep}" if note else keep
        record = self.events.emit(event, severity, ts, **fields)
        self.journal.event(record, source="replay" if self.ephemeral else "event_log")
        if event == "key_sequence_advanced":
            self.journal.save(ts, force=True)
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

    def _snapshot_in_background(self, label: str, trigger: str, key_observation: dict | None = None) -> None:
        if key_observation is None:
            threading.Thread(target=self._save_snapshot_now, args=(label, trigger), daemon=True).start()
            return
        if not self._key_snapshot_slots.acquire(blocking=False):
            self.events.emit("snapshot_skipped", "warning", time.time(), label=label,
                             key_observation=key_observation, reason="key_snapshot_workers_busy",
                             note="both key snapshot workers are busy; this attempt was skipped")
            return

        def run():
            try:
                self._save_snapshot_now(label, trigger, key_observation)
            finally:
                self._key_snapshot_slots.release()

        threading.Thread(target=run, daemon=True).start()

    def _save_snapshot_now(self, label: str, trigger: str, key_observation: dict | None = None) -> None:
        # Serialize pruning and copying, including critical events that race
        # the pair. Log fetching stays off the capture thread too.
        with self._snapshot_lock:
            dest = self._save_snapshot_locked(label, trigger, key_observation)
        if dest is not None:
            self._attach_snapshot_logs(label, dest)

    def _save_snapshot_locked(self, label: str, trigger: str, key_observation: dict | None = None) -> Path | None:
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
        try:
            dropped = prune_auto_snapshots(self.cfg.snapshots_dir, keep - 1 if keep > 0 else keep)
            if dropped:
                self.events.emit("snapshots_pruned", "info", time.time(), removed=dropped,
                                 note=(f"{len(dropped)} older automatic snapshot(s) removed to keep "
                                       f"[record] keep_snapshots = {self.cfg.keep_snapshots}: "
                                       + ", ".join(dropped)))
            if not self._room_for_snapshot(label, key_observation is None):
                return
            kwargs = {"key_observation": key_observation} if key_observation is not None else {}
            dest, count = save_snapshot(self.cfg, label, trigger=trigger, **kwargs)
        except Exception as exc:
            # Nothing was kept (save_snapshot removes a half copy), so the
            # six-hour cooldown armed for this attempt must not stand: the
            # next storm event after the retry hold tries again.
            if key_observation is None:
                self._last_auto_snapshot -= self.AUTO_SNAPSHOT_COOLDOWN_S - self.AUTO_SNAPSHOT_RETRY_S
            retry_note = ("this key snapshot attempt is not retried; the other phase is independent"
                          if key_observation is not None else
                          f"the next critical event after {self.AUTO_SNAPSHOT_RETRY_S // 60} min tries again")
            self.events.emit("snapshot_failed", "warning", time.time(), label=label,
                             note=(f"could not save the ring for {label}: {exc}; nothing was kept, and "
                                   + retry_note))
            return
        self.events.emit("snapshot_saved", "info", time.time(), label=label, path=str(dest),
                         ring_files=count, note=f"{count} ring files kept as {dest.name}")
        return dest

    def _attach_snapshot_logs(self, label: str, dest: Path) -> None:
        # The HA add-on logs join the snapshot now that it is final, on
        # this same background thread: a slow fetch costs capture nothing,
        # and the ring copy is already whole whatever happens here.
        if self.cfg.ha_logs_enabled:
            from .halogs import attach_logs
            try:
                status = attach_logs(self.cfg, dest, secrets=self._halogs_secrets())
            except Exception as exc:
                self.events.emit("snapshot_logs_failed", "notice", time.time(), label=label, addons=[],
                                 errors=[f"{type(exc).__name__}: {exc}"],
                                 note=f"the HA log fetch for {label} raised {type(exc).__name__}: {exc}")
                return
            self._report_ha_logs(label, dest, status, final=False)

    def _halogs_secrets(self, token: str | None = None) -> tuple:
        from .halogs import known_secrets
        return known_secrets(self.cfg, network_key=getattr(self.decryptor, "network_key", None), token=token)

    def _report_ha_logs(self, label: str, dest: Path, status: dict | None, final: bool) -> None:
        """snapshot_logs_saved / snapshot_logs_failed for one fetch round,
        through events.emit: a report on a snapshot must never start
        another. ``final`` says no retry remains, so a failure is the last
        word on it."""
        if status is None:
            return
        addons = sorted(status.get("addons", {}))
        lines = {slug: r.get("lines") for slug, r in status.get("addons", {}).items()}
        if status.get("status") == "complete":
            total = sum(n for n in lines.values() if isinstance(n, int))
            self.events.emit("snapshot_logs_saved", "info", time.time(), label=label, path=str(dest),
                             addons=addons, lines=lines,
                             note=(f"{total:,} lines of HA add-on log kept beside the packets of {dest.name} "
                                   f"({', '.join(addons)})" + (f", attempt {status['attempts']}"
                                                                if status.get("attempts", 1) > 1 else "")))
            return
        errors = [r["error"] for r in status.get("addons", {}).values() if r.get("error")] or \
            [status.get("reason") or "nothing arrived"]
        kept = [slug for slug, r in status.get("addons", {}).items() if r.get("file")]
        final = final or bool(addons) and all(r.get("complete") for r in status.get("addons", {}).values())
        how = ("the fetch is not retried: [ha_logs] retry is off" if not self.cfg.ha_logs_retry
               else "no retry remains" if final
               else "the recorder retries at 15 min, 1 h and 4 h after the snapshot while the journal "
                    "can still have the window")
        self.events.emit("snapshot_logs_failed", "notice", time.time(), label=label, addons=addons,
                         errors=errors, status=status.get("status"),
                         note=(f"the HA add-on logs for {dest.name} are {status.get('status')}"
                               + (f" ({', '.join(kept)} kept)" if kept else "")
                               + f": {'; '.join(errors)}; {how}"))

    HA_LOGS_RETRY_S = 15 * 60

    # ------------------------------------------- Home Assistant availability

    def _init_ha_availability(self) -> None:
        from .haavail import MAP_FILE, STATE_FILE, Tracker, load_map
        mapping = load_map(self.cfg.state_dir)
        try:
            self._haavail_map_ts = (self.cfg.state_dir / MAP_FILE).stat().st_mtime if mapping else None
        except OSError:
            self._haavail_map_ts = None
        self._haavail = Tracker(self.cfg, self.cfg.state_dir / STATE_FILE, emit=self._emit,
                                rows=self.seen.table, names=self.names, mapping=mapping,
                                lost_leader=self.lost_leader_for)

    def _poll_ha_availability(self, now: float) -> None:
        """Every [ha_availability] poll_s: the worker's result from last
        time is applied (Tracker.apply), then the next poll starts."""
        if self._haavail is None:
            return
        if self._haavail_thread is not None:
            if self._haavail_thread.is_alive():
                return
            self._haavail_thread.join()
            self._haavail_thread = None
            result, self._haavail_result = self._haavail_result, None
            if result is not None:
                if isinstance(result.get("map"), dict):
                    self._haavail_map_ts = now
                    self._identified(result["map"])
                self._haavail.apply(result, now)
                for rot in self._haavail.rotations:
                    name = self._device_rotated(rot["previous"], rot["addr"], now,
                                                "Home Assistant's Matter node diagnostics report the new address")
                    info = self._haavail.mapping.get(rot["ha_device_id"])
                    if info is not None and name and not info.get("matched"):
                        info["name"] = name     # the tracker's label, without waiting for devices.json
                self._haavail.rotations.clear()
            return
        early = self._identify_due(now)
        if now < self._next_haavail and not early:
            return
        self._next_haavail = now + self.cfg.ha_availability_poll_s
        mapping = dict(self._haavail.mapping)
        entries = list(self.names.entries)
        map_age = now - self._haavail_map_ts if self._haavail_map_ts is not None and not early else None

        def run():
            from .haavail import poll_once
            try:
                self._haavail_result = poll_once(self.cfg, mapping, entries, map_age_s=map_age, now=now,
                                                 log=lambda m: print(f"[threadwatch] ha-availability: {m}",
                                                                     file=sys.stderr, flush=True))
            except Exception as exc:
                self._haavail_result = {"ok": False, "error": f"{type(exc).__name__}: {exc}", "polled_ts": now}

        self._haavail_thread = threading.Thread(target=run, name="ha-availability", daemon=True)
        self._haavail_thread.start()

    # When an unnamed address's first registration is heard, the map is
    # rebuilt this long after it (the Matter Server has the device's new
    # address within seconds of its session resuming) and once more
    # IDENTIFY_RETRY_S later if that one did not have it; then the hourly
    # refresh is left to it.
    IDENTIFY_DELAY_S = 30.0
    IDENTIFY_RETRY_S = 300.0
    IDENTIFY_TRIES = 2

    def _want_identity(self, addr: str, ts: float) -> None:
        """An address with no name registered over SRP: a Matter device,
        most likely one that took a new address after a firmware update
        (2026-09-23). Its registration names it only when the sniffer hears
        the fragments carrying its Matter service names, and the next hourly
        map refresh left its srp_refused unnamed and its old address to
        report quiet. Home Assistant's map names it as soon as it is rebuilt."""
        if (self._haavail is None or addr in self._identify or addr in self._identify_done
                or self.names.name(addr) or self.visitor_names.name(addr)):
            return
        self._identify[addr] = {"due": ts + self.IDENTIFY_DELAY_S, "tries": 0}

    def _identify_due(self, now: float) -> bool:
        """Whether an early map refresh is due; counts it as a try for every
        address it is for."""
        due = [a for a, w in self._identify.items() if w["due"] <= now]
        for a in due:
            w = self._identify[a]
            w["tries"] += 1
            if w["tries"] >= self.IDENTIFY_TRIES:
                del self._identify[a]
                self._identify_done.add(a)
            else:
                w["due"] = now + self.IDENTIFY_RETRY_S
        return bool(due)

    def _identified(self, new_map: dict) -> None:
        """Addresses the rebuilt map carries are known to Home Assistant:
        a rotation, if any, has been applied from it, so no retry."""
        seen = {str(i.get("addr") or "").lower() for i in new_map.values() if isinstance(i, dict)}
        for a in [a for a in self._identify if a in seen]:
            del self._identify[a]
            self._identify_done.add(a)

    def ha_availability_status(self) -> dict | None:
        """The 'ha_availability' entry of status.json: reachability, the
        last poll, the open episodes; or why the feature is off. None
        with [ha_availability] disabled."""
        if not self.cfg.ha_availability_enabled or self.ephemeral:
            return None
        if self._haavail is None:
            return {"enabled": False}
        return {"enabled": True, **self._haavail.status()}

    def _poll_ha_archive(self, now: float) -> None:
        """The hourly archive pass (halogs.archive_pass) on a thread: due
        ARCHIVE_GRACE_S after each hour boundary, and every ARCHIVE_RETRY_S
        while hours are pending. The next periodic pass emits the events
        the pass produced and refreshes the status entry."""
        from .halogs import ARCHIVE_GRACE_S, ARCHIVE_RETRY_S, archive_status
        if self._archive_thread is not None:
            if self._archive_thread.is_alive():
                return
            self._archive_thread.join()
            self._archive_thread = None
            result, self._archive_result = self._archive_result, None
            if result is not None:
                if result.get("key_journal_scan") is not None:
                    self.journal.apply_archive_scan(result["key_journal_scan"])
                for event, severity, fields in result.get("events", []):
                    # events.emit: a report on the archive is never a
                    # reason to snapshot, and never pages.
                    self.events.emit(event, severity, now, **fields)
                self._archive_status = archive_status(self.cfg, result.get("state"))
                if result.get("pending"):
                    self._next_archive = min(self._next_archive, now + ARCHIVE_RETRY_S)
            return
        if now < self._next_archive:
            return
        # The next hour boundary plus the grace; a pending backlog pulls it
        # forward when the result comes in (above).
        self._next_archive = (int(now // 3600) + 1) * 3600 + ARCHIVE_GRACE_S
        secrets = self._halogs_secrets()
        journal_scanned = dict(self.journal.archive_scan["files"])

        def run():
            from .halogs import archive_pass, credentials, prune_archive
            try:
                result = archive_pass(self.cfg, now, credentials(self.cfg), secrets=secrets,
                                      log=lambda msg: print(f"[threadwatch] {msg}", file=sys.stderr, flush=True))
                # The newest completed hours first; bounded backfill on
                # subsequent passes. No gzip scans on the capture path.
                from .journal import scan_archive
                result["key_journal_scan"] = scan_archive(self.cfg.data_dir, journal_scanned)
                pruned = prune_archive(self.cfg)
                if pruned:
                    print(f"[threadwatch] ha-logs archive: dropped {len(pruned)} hour(s) past [record] keep_hours",
                          file=sys.stderr, flush=True)
                self._archive_result = result
            except Exception as exc:
                print(f"[threadwatch] HA log archive pass failed: {type(exc).__name__}: {exc}",
                      file=sys.stderr, flush=True)
                self._archive_result = None

        self._archive_thread = threading.Thread(target=run, name="ha-logs-archive", daemon=True)
        self._archive_thread.start()

    def otbr_inventory_status(self) -> dict | None:
        return self._otbr_inventory.status if self._otbr_inventory is not None else None

    def ha_logs_archive_status(self) -> dict | None:
        """The 'ha_logs_archive' entry of status.json: per add-on the last
        hour archived, the hours on disk, pending and lost; None with the
        archive off."""
        if not (self.cfg.ha_logs_enabled and self.cfg.ha_logs_archive):
            return None
        if self._archive_status is None:
            from .halogs import archive_status
            self._archive_status = archive_status(self.cfg)
        return self._archive_status

    def _poll_ha_logs(self, now: float) -> None:
        """Every HA_LOGS_RETRY_S, on a thread, retry the failed or partial
        log fetches of recent snapshots (halogs.retry_pending); the next
        pass reports what the last one did, on the capture thread."""
        if self._halogs_thread is not None:
            if self._halogs_thread.is_alive():
                return
            self._halogs_thread.join()
            self._halogs_thread = None
            result, self._halogs_result = self._halogs_result, None
            for dest, status, final in result or []:
                self._report_ha_logs(status.get("label") or dest.name.partition("_")[2] or dest.name,
                                     dest, status, final)
            return
        if now < self._next_halogs:
            return
        self._next_halogs = now + self.HA_LOGS_RETRY_S
        secrets = self._halogs_secrets()

        def run():
            from .halogs import retry_pending
            try:
                self._halogs_result = retry_pending(self.cfg, secrets=secrets)
            except Exception as exc:
                print(f"[threadwatch] HA log retry pass failed: {type(exc).__name__}: {exc}",
                      file=sys.stderr, flush=True)
                self._halogs_result = None

        self._halogs_thread = threading.Thread(target=run, name="ha-logs-retry", daemon=True)
        self._halogs_thread.start()

    def _room_for_snapshot(self, label: str, critical: bool = True) -> bool:
        """A snapshot is a second copy of the ring. Taking one that leaves
        the ring less room than it still needs trades a week of recording
        for one snapshot, and the recorder exits 1 the moment the card
        fills. Refuse it and say so; the ring keeps running."""
        from .review import fmt_bytes, storage
        sto = storage(self.cfg)
        free, need = sto.get("disk_free"), sto["ring_needs_bytes"]
        copy = sto["ring_bytes"] + sto.get("snapshot_extra_bytes", 0)     # the ring, plus the HA logs when on
        if free is None or free - copy >= need:
            return True
        if critical:
            self._last_auto_snapshot -= self.AUTO_SNAPSHOT_COOLDOWN_S - self.AUTO_SNAPSHOT_RETRY_S
        self.events.emit("snapshot_skipped", "warning", time.time(), label=label,
                         disk_free=free, ring_bytes=sto["ring_bytes"], ring_needs_bytes=need,
                         note=(f"not saving {label}: a copy of the ring ({fmt_bytes(copy)}"
                               + (" with the HA logs" if copy != sto["ring_bytes"] else "") + ") "
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
        # Home Assistant unavailabilities in the window: closed ones from
        # the log (ha_available carries the duration), open ones from the
        # tracker.
        ha_down: list[dict] = []
        visits: list[dict] = []
        lags = self._key_lags(now, dominant)
        lag_1 = sorted(e["name"] or e["addr"] for e in lags if e["lag"] == 1)
        lag_2plus = sorted(e["name"] or e["addr"] for e in lags if e["lag"] is not None and e["lag"] >= 2)
        counts = {"critical": 0, "warning": 0, "notice": 0, "info": 0}
        # Every local day the window touches: after the spring clock change
        # 24 hours can span three of them, and reading the first and last
        # day's files alone dropped the whole middle day's events.
        days = dict.fromkeys(day_of(t) for t in [since + h * 3600 for h in range(25)] + [now])
        for day in days:
            for r in self._records_of(day):
                if r["ts"] >= since and r.get("event") != "daily_summary":
                    counts[r.get("severity", "info")] = counts.get(r.get("severity", "info"), 0) + 1
                if r["ts"] >= since and r.get("event") == "ha_available":
                    ha_down.append({"name": r.get("name") or r.get("addr"), "down_for_s": r.get("down_for_s"),
                                    "open": False})
                if r["ts"] >= since and r.get("event") == "visitor_left":
                    visits.append({"addr": r.get("addr"), "first_seen": r.get("first_seen"),
                                   "heard_for_s": r.get("heard_for_s")})
        if self._haavail is not None:
            ha_down.extend({"name": o["name"], "down_for_s": round(now - o["since"]), "open": True}
                           for o in self._haavail.status()["open"])
        frames = sum(n for b, n in self._frames_by_hour.items() if (b + 1) * 3600 > since)
        parts = [f"{frames:,} frames from {len(heard)} of {len(ours)} devices"]
        parts.append("quiet: " + ", ".join(quiet) if quiet else "nothing quiet")
        if unknown:
            parts.append(f"{len(unknown)} unknown address{'es' if len(unknown) != 1 else ''}")
        if marginal:
            parts.append(f"{len(marginal)} heard marginally")
        if degraded:
            parts.append("signal down: " + ", ".join(degraded))
        if visits:
            parts.append(f"{len(visits)} visit{'s' if len(visits) != 1 else ''} by unnamed addresses")
        if self.detector.storm_active:
            parts.append("STORM ACTIVE")
        if ha_down:
            parts.append("HA unavailable: " + ", ".join(
                f"{d['name']} ({round((d['down_for_s'] or 0) / 60)} min{', still' if d['open'] else ''})"
                for d in ha_down[:8]) + (" ..." if len(ha_down) > 8 else ""))
        mesh = self.decryptor.key_sequence
        if mesh is not None and (lag_1 or lag_2plus):
            parts.append(f"key generation {mesh}: "
                         + ", ".join(p for p in (f"{len(lag_1)} one behind" if lag_1 else "",
                                                 "cut off: " + ", ".join(lag_2plus) if lag_2plus else "") if p))
        logged = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n and sev != "info")
        parts.append("events: " + (logged or "none above info"))
        return {"frames_24h": frames, "devices_heard_24h": len(heard), "devices_tracked": len(ours),
                "quiet": quiet, "unknown": unknown, "marginal": marginal, "degraded": degraded,
                "storm_active": bool(self.detector.storm_active), "events_24h": counts,
                "key_generation": mesh, "key_lag_1": lag_1, "key_lag_2plus": lag_2plus,
                "ha_unavailable_24h": ha_down, "visits_24h": visits,
                "note": "last 24 h: " + "; ".join(parts)}

    # ------------------------------------------------ key generations

    def _key_snapshot(self, ts: float, phase: str) -> None:
        """At-most-once reservations, persisted before launching a copy.

        A crash between reservation and copy may lose an attempt, never
        duplicate it. Rapid advances share the outstanding census bundle;
        a completed pair also holds new advances for five minutes.
        """
        if self.ephemeral or not self.cfg.snapshot_on_key_advance:
            return
        pair = self._keys.get("snapshot_pair")
        if phase == "advance":
            if pair and (not pair["census_claimed"] or 0 <= ts - pair["observed_at"] < 300):
                self.events.emit("snapshot_skipped", "info", ts, reason="key_advance_coalesced",
                                 sequence=self._keys["highest"], key_observation=dict(pair),
                                 note="key advance coalesced into the preceding snapshot pair")
                return
            pair = {"sequence": self._keys["highest"], "observed_at": self._keys["highest_first_ts"],
                    "census_claimed": False}
            self._keys["snapshot_pair"] = pair
        elif not pair or pair["census_claimed"]:
            return
        else:
            pair["census_claimed"] = True
        self._save_keys()
        observation = {"sequence": pair["sequence"], "observed_at": pair["observed_at"], "phase": phase}
        label = f"auto-key-{pair['sequence']}-{int(pair['observed_at'] * 1000)}-{phase}"
        if self.cfg.keep_snapshots == 0:
            self.events.emit("snapshot_skipped", "info", ts, label=label, key_observation=observation,
                             reason="keep_snapshots_zero", note="key snapshot disabled by keep_snapshots = 0")
            return
        trigger = "key_sequence_advanced" if phase == "advance" else "key_lag_census"
        record = self.events.emit("snapshot_requested", "info", ts, label=label, trigger=trigger,
                                  key_observation=observation, note=f"saving the ring for key {phase} as {label}")
        self.journal.event(record)
        self.journal.save(ts, force=True)
        self.snapshotter(label, trigger, observation)

    def _generation_coverage(self, previous_ts: float | None, ts: float) -> dict:
        """Known blind spans are evidence of gaps, never proof of full coverage.

        The bounded blind history includes downtime and forward clock steps;
        it cannot distinguish those or establish radio/transport coverage.
        """
        reasons = ["capture_completeness_not_measured"]
        gaps = []
        if previous_ts is None:
            reasons.append("initial_discovery" if not self._keys else "previous_observation_time_unknown")
        elif ts < previous_ts:
            reasons.append("non_monotonic_observation_time")
        else:
            for start, length in self._blind:
                end = min(ts, start + length)
                start = max(previous_ts, start)
                if end > start:
                    gaps.append({"start_ts": start, "end_ts": end,
                                 "source": "recorder_blind_span"})
        if self._keys_reloaded:
            reasons.append("recorder_restart")
        return {"status": "gapped" if gaps else "unknown", "gaps": gaps[-self.BLIND_MAX:],
                "reasons": reasons, "history_complete": False}

    def _note_generation(self, who: str, row: dict, generation: int, frame: str, ts: float) -> None:
        """A frame accepted under a key generation above the highest on
        record: a new highest sequence was observed (or this is the first
        generation ever heard). Announced once per generation, ever; the
        record is persisted before the event so a restart never repeats
        it. This proves use by the sender, not mesh-wide adoption or who
        initiated the change. _origin records candidates for investigation;
        missing traffic, attachment, and stale parent mappings limit attribution."""
        highest = self._keys.get("highest")
        if highest is not None and generation <= highest:
            return
        previous_ts = self._keys.get("highest_first_ts")
        since = ts - previous_ts if highest is not None and previous_ts is not None and ts >= previous_ts else None
        expected = self.cfg.key_rotation_hours
        interval_facts = {
            "observed_interval_s": since,
            "sequence_delta": generation - highest if highest is not None else None,
            "observation_kind": "baseline" if highest is None else "advance",
            "coverage": self._generation_coverage(previous_ts, ts),
            "scheduled_expectation": {
                "rotation_hours": expected,
                "source": "local_config" if expected is not None else "unknown",
                "config_key": "keys.rotation_hours" if expected is not None else None,
                "device": None, "observed_at": None, "live_telemetry": False,
            },
            "early_against_configured_interval": (
                since < 0.9 * expected * 3600 if expected is not None and since is not None else None),
        }
        suspect = self._origin(who, row, generation, frame, ts, first=True)
        evidence = {"scope": "device", "confidence": "observation_only",
                    "reasons": ["accepted_authenticated_frame", "mesh_adoption_not_established",
                                "origin_not_established"]}
        from .keyfacts import facts
        earlier = []
        for addr, observed in self.seen.table.items():
            history = facts(observed)
            for layer in ("mac", "mle"):
                for decision in ("accepted", "rejected"):
                    for span in history[layer][decision]:
                        if span["sequence"] >= generation and span["first_ts"] < ts:
                            earlier.append({"addr": addr, "layer": layer, "decision": decision,
                                            "sequence": span["sequence"], "ts": span["first_ts"],
                                            "reason": span.get("reason"), "source": "bounded_keyfacts_history"})
        earlier = sorted(earlier, key=lambda r: r["ts"])[-64:]
        pair = self._keys.get("snapshot_pair")
        self._keys = {"highest": generation, "previous": highest, "highest_first_ts": ts,
                      "previous_first_ts": previous_ts, "first_sender": who,
                      "census_at": ts + self.cfg.key_census_delay_s, "suspects": [suspect],
                      **evidence, **interval_facts}
        if pair is not None:
            self._keys["snapshot_pair"] = pair
        self._save_keys()
        self._keys_reloaded = False
        name = self.names.name(who)
        role = rloc16_role(row.get("rloc16"))
        label = name or who
        if highest is None:
            note = (f"first key generation heard: {generation}, from {label} ({frame}); the mesh's key "
                    "sequence is recorded from here on")
        else:
            note = (f"key sequence advanced: generation {highest} -> {generation}, first heard from {label} "
                    f"({frame})")
            if since is not None:
                note += f", {since / 86400:.1f} days after the previous first observation"
            if expected is not None and since is not None and since < 0.9 * expected * 3600:
                note += f" -- early: the configured rotation time is {expected:g} h"
            note += "; " + self._suspect_sentence(suspect)
            note += f"; the generation census comes in {self.cfg.key_census_delay_s / 60:.0f} min"
        self._emit("key_sequence_advanced", "info", ts, sequence=generation, previous=highest,
                   first_sender=who, name=name, rloc16=row.get("rloc16"), role=role["role"] if role else None,
                   frame=frame, since_previous_s=round(since) if since is not None else None,
                   suspects=[suspect], previous_first_ts=previous_ts, earlier_higher_sequence=earlier,
                   **interval_facts, **evidence, note=note)
        if highest is not None:
            self._key_snapshot(ts, "advance")

    def _origin(self, who: str, row: dict, generation: int, frame: str, ts: float, first: bool) -> dict | None:
        """Record origin candidates, never proof of independent advancement.

        Legacy evidence strings remain stable for consumers. A parent's
        fresh observation is still only its last known sequence. Always
        retain the first sender, even when its parent is already ahead;
        later senders qualify only when observed ahead of their parent.
        """
        role = (rloc16_role(row.get("rloc16")) or {}).get("role")
        entry = {"addr": who, "name": self.names.name(who), "rloc16": row.get("rloc16"), "role": role,
                 "ts": ts, "frame": frame, "evidence": "first on air", "parent": None, "parent_addr": None,
                 "parent_generation": None, "parent_heard_s": None,
                 "confidence": "candidate_only", "reasons": ["first_observed_sender"] if first else []}
        parent = parent_address(row, router_holders(self.seen.table))
        if parent is not None:
            entry["parent_addr"] = parent
            entry["parent"] = self.names.name(parent) or parent
            prow = self.seen.table.get(parent)
            pseq, pts = self._generation(prow, ts) if prow is not None else (None, None)
            if pseq is not None:
                entry.update(parent_generation=pseq, parent_heard_s=round(ts - pts))
            if pseq is not None and pseq < generation:
                entry.update(evidence="ahead of its parent")
                entry["reasons"].extend(["ahead_of_last_parent_observation", "missed_traffic_or_attachment_possible"])
                return entry
            if pseq is not None:
                entry["reasons"].append("parent_already_observed_at_or_above_sequence")
                return entry if first else None
            entry["reasons"].append("parent_sequence_not_fresh")
        else:
            entry["reasons"].append("parent_unknown")
        return entry if first else None

    def _note_suspect(self, who: str, row: dict, generation: int, frame: str, ts: float) -> None:
        """A device's first frame on the highest generation, while the
        census for it is still to come: a second device found ahead of its
        parent (Front Door Button, 74 s after Front Door on 2026-09-17,
        under a parent still on 85) joins the suspects. Persisted with the
        generation record, so the census after a restart still has it."""
        if generation != self._keys.get("highest") or self._keys.get("census_at") is None:
            return
        suspects = self._keys.setdefault("suspects", [])
        if any(s.get("addr") == who for s in suspects):
            return
        entry = self._origin(who, row, generation, frame, ts, first=False)
        if entry is None:
            return
        suspects.append(entry)
        # Update the incident's candidate list without creating a second
        # network advance or duplicating the packet history.
        for record in reversed(self.journal.records):
            evidence = record.get("evidence", {})
            if evidence.get("event") == "key_sequence_advanced" and evidence.get("sequence") == generation:
                evidence["suspects"] = [dict(s) for s in suspects]
                self.journal.dirty = True
                break
        self._save_keys()

    @staticmethod
    def _suspect_sentence(suspect: dict) -> str:
        """The rotation note's verdict on its first sender."""
        label = suspect.get("name") or suspect.get("addr")
        if suspect.get("evidence") == "ahead of its parent":
            heard = suspect.get("parent_heard_s")
            return (f"{label} was observed ahead of its last known parent sequence: {suspect.get('parent')} on "
                    f"{suspect.get('parent_generation')}"
                    + (f", heard {heard} s earlier" if heard is not None else "")
                    + "; an origin candidate, not proof: missed traffic, an attachment or a stale parent mapping "
                      "can explain it")
        if suspect.get("role") == "router":
            return (f"{label} is a router, so it may have relayed a frame the sniffer missed: suspected, "
                    "not proven")
        if suspect.get("parent") is None:
            return f"whether {label} started it or relayed it is not known: its parent is not known"
        if suspect.get("parent_generation") is not None:
            return (f"{label}'s parent {suspect.get('parent')} was already observed on generation "
                    f"{suspect['parent_generation']}; origin unconfirmed")
        return (f"whether {label} started it or relayed it is not known: its parent {suspect.get('parent')} had "
                "no fresh generation reading")

    def _generation(self, row: dict, now: float) -> tuple[int | None, float | None]:
        """The newest key generation a device's authenticated frames were
        accepted under within [keys] fresh_s, MAC or MLE, and when: (None,
        None) when nothing fresh says. A reading older than that is not
        judged either way."""
        seq, ts = newest_generation(row)
        if seq is None or now - ts > self.cfg.key_fresh_s:
            return None, None
        return seq, ts

    def _key_lags(self, now: float, dominant: int | None) -> list[dict]:
        """Every device on our PAN judged against its reference generation:
        a child against its live parent's, a router against the mesh's
        (decryptor.key_sequence, and only once two routers are fresh on
        it, so one straggler frame cannot raise the bar for everyone).
        lag is None when nothing fresh says: a device or parent unheard for
        [keys] fresh_s, no key generation on record, no role known."""
        mesh = self.decryptor.key_sequence
        holders = router_holders(self.seen.table)
        gens: dict[str, tuple] = {}
        for addr, row in self.seen.table.items():
            if row.get("rotated_to"):
                continue
            pan = row.get("pan")
            if dominant is not None and pan is not None and pan != dominant:
                continue
            gens[addr] = self._generation(row, now)
        on_mesh = sum(1 for addr, (seq, _ts) in gens.items() if seq is not None and seq == mesh
                      and (rloc16_role(self.seen.table[addr].get("rloc16")) or {}).get("role") == "router")
        out = []
        for addr, (seq, ts) in gens.items():
            row = self.seen.table[addr]
            live = rloc16_role(row.get("rloc16")) or {}
            parent = parent_address(row, holders)
            entry = {"addr": addr, "name": self.names.name(addr), "role": live.get("role"),
                     "generation": seq, "generation_ts": ts, "parent_addr": parent,
                     "parent": (self.names.name(parent) or parent) if parent else None,
                     "parent_generation": None, "mesh_generation": mesh, "lag": None}
            if parent is not None and parent in gens:
                entry["parent_generation"] = gens[parent][0]
            if seq is None:
                out.append(entry)
                continue
            if entry["role"] == "child":
                if entry["parent_generation"] is not None:
                    entry["lag"] = entry["parent_generation"] - seq
            elif entry["role"] == "router" and mesh is not None and on_mesh >= 2:
                entry["lag"] = mesh - seq
            out.append(entry)
        return out

    KEYLAG_KEYS = ("keylag_since", "keylag_confirm_at", "keylag_parent", "keylag_role", "keylag_gens",
                   "keylag_sent")

    def _check_key_lag(self, now: float, dominant: int | None) -> None:
        """The key_lag episodes, once per periodic pass. A device two or
        more generations below its reference opens an episode on its row
        (silently), and is paged at the first pass after [keys] confirm_s
        in which it has sent a frame past that mark and is still that far
        behind: evidence, not a timer. A fresh frame within
        one generation closes it, with key_lag_cleared only if the page
        went out. A child whose parent changed closes its episode and is
        judged against the new parent."""
        for entry in self._key_lags(now, dominant):
            addr = entry["addr"]
            row = self.seen.table[addr]
            is_open = row.get("keylag_since") is not None
            if is_open and (row.get("keylag_role"), row.get("keylag_parent")) != (entry["role"], entry["parent_addr"]):
                self._close_key_lag(addr, row, now, entry, "its parent changed")
                is_open = False
            lag = entry["lag"]
            if lag is None:
                continue
            if lag <= 1:
                if is_open:
                    self._close_key_lag(addr, row, now, entry)
                continue
            if not is_open:
                row["keylag_since"] = now
                row["keylag_confirm_at"] = now + self.cfg.key_confirm_s
                row["keylag_parent"] = entry["parent_addr"]
                row["keylag_role"] = entry["role"]
                row["keylag_gens"] = [entry["generation"], entry["parent_generation"] if entry["role"] == "child"
                                      else entry["mesh_generation"]]
                self.seen._dirty = True
                if self.cfg.key_confirm_s > 0:
                    continue
                # confirm_s = 0: page at once, on the frame that opened it.
            if row.get("keylag_sent"):
                continue
            mark = row.get("keylag_confirm_at", now)
            if now >= mark and (self.cfg.key_confirm_s == 0 or entry["generation_ts"] >= mark):
                self._page_key_lag(addr, row, entry, now)

    def _page_key_lag(self, addr: str, row: dict, entry: dict, now: float) -> None:
        since = row["keylag_since"]
        closed = row.get("keylag_closed")
        gap = since - closed if closed is not None else None
        flapping = gap is not None and self.cfg.key_rearm_s > 0 and gap < self.cfg.key_rearm_s
        episode = ((row.get("keylag_episodes") or 0) + 1) if flapping else 1
        router = entry["role"] == "router"
        severity = "notice" if flapping else ("critical" if router else "warning")
        row["keylag_episodes"] = episode
        row["keylag_sent"] = severity
        row.pop("keylag_confirm_at", None)
        self.seen._dirty = True
        self.seen.save()          # rare, and the flag is what stops a restart paging it again
        generation, lag = entry["generation"], entry["lag"]
        reference = entry["mesh_generation"] if router else entry["parent_generation"]
        rssi = row.get("rssi")
        what = (f"the mesh is on {reference}" if router
                else f"its parent {entry['parent']} is on {reference}")
        note = (f"still transmitting under key generation {generation} while {what}: {lag} generations behind, "
                "so every frame it sends is dropped (OpenThread accepts frames only within one generation of its "
                "own) while the radio still acknowledges its polls, so it looks alive and neither device_quiet "
                f"nor poll_starvation will follow; held {round((now - since) / 60)} min with fresh frames before "
                "this record. A battery pull or power cycle forces a rejoin, which fetches the current key")
        if router:
            note += "; a router this far behind cuts off every child that follows it"
        if flapping:
            note += (f". Episode {episode} since the last page, {gap / 60:.0f} min after the previous one "
                     "closed: logged, not paged, until it has stayed within a generation for "
                     f"{self.cfg.key_rearm_s / 60:.0f} min")
        self._emit("key_lag", severity, now, addr=addr, name=entry["name"], role=entry["role"],
                   generation=generation, parent=entry["parent"], parent_addr=entry["parent_addr"],
                   **({"mesh_generation": reference} if router else {"parent_generation": reference}),
                   lag=lag, since=since, lagged_for_s=round(now - since), rssi_dbm=rssi,
                   reception=reception(rssi, self.cfg.quiet_min_rssi_dbm), polls_acked=bool(row.get("polls_acked")),
                   episode=episode, since_previous_s=round(gap) if gap is not None else None, note=note)

    def _close_key_lag(self, addr: str, row: dict, now: float, entry: dict, reason: str | None = None) -> None:
        sent = row.get("keylag_sent")
        since = row.get("keylag_since")
        rejoin = row.get("rejoin_ts")
        rejoined = isinstance(rejoin, (int, float)) and since is not None and rejoin >= since
        router = row.get("keylag_role") == "router"
        for key in self.KEYLAG_KEYS:
            row.pop(key, None)
        if sent:
            row["keylag_closed"] = now
        self.seen._dirty = True
        if not sent:
            return
        generation = entry["generation"]
        reference = entry["mesh_generation"] if router else entry["parent_generation"]
        if reason:
            note = f"the episode is closed: {reason}"
        elif generation is None:
            note = "the episode is closed"
        else:
            note = (f"heard again under key generation {generation}, within one of "
                    + (f"the mesh's {reference}" if router else f"its parent's {reference}"))
        if rejoined:
            note += f"; it rejoined at {time.strftime('%H:%M:%S', time.localtime(rejoin))}"
        self._emit("key_lag_cleared", "info", now, addr=addr, name=entry["name"], role=entry["role"],
                   generation=generation, parent=entry["parent"], parent_addr=entry["parent_addr"],
                   **({"mesh_generation": reference} if router else {"parent_generation": reference}),
                   since=since, lagged_for_s=round(now - since) if since is not None else None,
                   rejoined=rejoined, rejoin_ts=rejoin if rejoined else None, note=note)

    def _maybe_census(self, now: float, dominant: int | None) -> None:
        """key_lag_census, [keys] census_delay_s after a rotation: how many
        devices are on each generation, who is one behind (normal, and
        never paged), who is two or more behind (cut off), which routers
        trail the mesh, and who could not be judged."""
        due = self._keys.get("census_at")
        if due is None or now < due:
            return
        self._keys["census_at"] = None
        self._save_keys()
        counts: dict[str, int] = {}
        behind_1, behind_2plus, routers_behind, unknown = [], [], [], []
        for e in self._key_lags(now, dominant):
            label = e["name"] or e["addr"]
            if e["generation"] is None:
                unknown.append(label)
                continue
            counts[str(e["generation"])] = counts.get(str(e["generation"]), 0) + 1
            if e["lag"] is None or e["lag"] < 1:
                continue
            item = {"name": e["name"], "addr": e["addr"], "generation": e["generation"], "lag": e["lag"]}
            if e["role"] == "child":
                item.update(parent=e["parent"], parent_generation=e["parent_generation"])
                (behind_1 if e["lag"] == 1 else behind_2plus).append(item)
            else:
                item["mesh_generation"] = e["mesh_generation"]
                routers_behind.append(item)
        for group in (behind_1, behind_2plus, routers_behind):
            group.sort(key=lambda i: (i["name"] or i["addr"]).lower())
        unknown.sort(key=str.lower)
        highest = self._keys.get("highest")
        tally = ", ".join(f"{n} on {g}" for g, n in sorted(counts.items(), key=lambda kv: -int(kv[0])))
        names = lambda group: ", ".join(i["name"] or i["addr"] for i in group)
        parts = [f"generation {highest}: {tally or 'nobody judged'}"]
        parts.append(f"one behind: {names(behind_1)}" if behind_1 else "nobody one behind")
        parts.append(f"cut off (2+ behind): {names(behind_2plus)}" if behind_2plus else "nobody cut off")
        if routers_behind:
            parts.append(f"routers behind the mesh: {names(routers_behind)}")
        if unknown:
            parts.append(f"{len(unknown)} not judged (no fresh frame)")
        suspects = list(self._keys.get("suspects") or [])
        parts.append("origin candidates: "
                     + ", ".join(self._suspect_label(s) for s in suspects) if suspects else "trigger unknown")
        self._emit("key_lag_census", "info", now, sequence=highest, mesh_generation=self.decryptor.key_sequence,
                   counts=counts, behind_parent_1=behind_1, behind_parent_2plus=behind_2plus,
                   routers_behind=routers_behind, unknown=unknown, suspects=suspects,
                   note=f"census {self.cfg.key_census_delay_s / 60:.0f} min after the advance; "
                   + "; ".join(parts))
        self._key_snapshot(now, "census")

    @staticmethod
    def _suspect_label(suspect: dict) -> str:
        """One suspect for a note: the name and why."""
        label = suspect.get("name") or suspect.get("addr")
        if suspect.get("evidence") == "ahead of its parent":
            return (f"{label} (ahead of last known parent sequence: {suspect.get('parent')} "
                    f"on {suspect.get('parent_generation')})")
        return f"{label} (first on air)"

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

    # What the radio has to say before a claimed rotation retires the old
    # address. A rebooting router asks the leader for the router id it had
    # and usually gets it back, so an unchanged rloc16 under a new extended
    # address is the rotation's own signature, and nothing off the mesh can
    # forge it. Failing that, the two weaker signs together -- circumstantial,
    # not proof, so both are bounded tightly enough that unrelated traffic
    # does not wander into them:
    #
    # the handover, which is a reboot and so is quick. The two addresses may
    # interleave by ROTATION_OVERLAP_S (the last frames of one crossing the
    # first of the other) and the new address must speak within
    # ROTATION_HANDOVER_S of the old one's last frame. Without that second
    # bound the test reads "the new address turned up at some point after
    # the old one stopped", which any device that joined the mesh a day
    # later also satisfies;
    #
    # the level, which a hub that has not moved keeps (ROTATION_RSSI_DB,
    # wider than the link detector's default drop so a rotation is not
    # judged by it). A row's level is an average, and an address heard two
    # or three times has no average worth comparing, so both rows need
    # ROTATION_MIN_FRAMES behind theirs before the comparison counts.
    ROTATION_OVERLAP_S = 120.0
    ROTATION_HANDOVER_S = 15 * 60.0
    ROTATION_RSSI_DB = 10.0
    ROTATION_MIN_FRAMES = 20
    # An address heard once carries neither an rloc16 nor a settled level,
    # so the browse that first reports a rotation often cannot corroborate
    # one that is real. Each later browse looks again while the claim is
    # this young; past it the claim keeps the name it was given and stays
    # unretired, because evidence that has not arrived in six hours of
    # capture is not coming.
    ROTATION_RECHECK_S = 6 * 3600

    def _rotation_evidence(self, prev: str, ext: str) -> tuple[bool, list[str], list[str], bool]:
        """What the radio says about a claimed rotation ``prev`` -> ``ext``:
        (corroborated, what held, what did not, whether it contradicts).

        The last of those separates a claim the traffic argues against from
        one it has nothing to say about yet. A rotation is bound to its new
        address by that address's first frame, which carries no router id and
        no average worth the name, so the first look at a real rotation is
        almost always ignorant rather than doubtful. Reporting the two the
        same way would put a notice on every reboot.

        Hearing an address on air proves the device exists. It does not
        prove that an unauthenticated hostname advertising it belongs to
        the device the inventory gives that hostname to, and the addresses
        an mDNS responder needs for the claim are in the clear in every
        802.15.4 header. What a responder off the mesh cannot arrange is
        the traffic itself: that the old address kept its router id, or
        that it fell silent exactly as the new one started talking, at the
        level the sniffer used to hear it at.
        """
        old_row, new_row = self.seen.table.get(prev), self.seen.table.get(ext)
        if old_row is None or new_row is None:
            # An address with no row has not been heard in this run: there is
            # no traffic to judge either way.
            return False, [], ["one of the addresses is not in the last-seen table"], False
        held: list[str] = []
        missing: list[str] = []
        against = False

        old_id, new_id = old_row.get("rloc16"), new_row.get("rloc16")
        same_id = bool(old_id) and old_id == new_id
        if same_id:
            held.append(f"kept router id {new_id}")
        elif old_id and new_id:
            missing.append(f"router id changed, {old_id} to {new_id}")
            against = True
        else:
            missing.append("no router id seen for both addresses")

        # A negative overlap is a gap: the new address started that long
        # after the old one was last heard. Positive is the old one still
        # talking once the new one had begun, which is two devices, not one
        # rebooting.
        started = max(new_row.get("first_seen", 0.0), new_row.get("resumed_ts", 0.0))
        overlap = old_row.get("last_seen", 0.0) - started
        handover = -self.ROTATION_HANDOVER_S <= overlap <= self.ROTATION_OVERLAP_S
        if handover:
            held.append("the old address stopped as the new one started")
        elif overlap > self.ROTATION_OVERLAP_S:
            missing.append(f"both addresses were on air together for {round(overlap)} s")
            against = True
        else:
            missing.append(f"the new address first spoke {round(-overlap)} s after the old one stopped")
            against = True

        old_level = old_row.get("rssi_ref")
        if old_level is None:
            old_level = old_row.get("rssi")
        new_level = new_row.get("rssi")
        heard = min(old_row.get("frames", 0), new_row.get("frames", 0))
        close = False
        if old_level is None or new_level is None:
            missing.append("no signal level for both addresses")
        elif heard < self.ROTATION_MIN_FRAMES:
            missing.append(f"only {heard} frames behind a signal level, too few to compare")
        else:
            gap = abs(new_level - old_level)
            close = gap <= self.ROTATION_RSSI_DB
            if close:
                held.append(f"heard within {gap:.0f} dB of the old address")
            else:
                missing.append(f"heard {gap:.0f} dB from the old address")
                against = True
        return same_id or (handover and close), held, missing, against

    def _settle_rotation(self, prev: str, ext: str, name: str | None, host: str,
                         r: dict, now: float, new: dict, late: bool = False) -> None:
        """Retire ``prev`` for ``ext`` if the radio corroborates the browse's
        claim, else record the claim as unverified and leave the old address
        judged. ``late`` is a second look at a claim already reported.
        """
        trusted = self.cfg.border_router_rotation == "trusted"
        old_row = self.seen.table.get(prev)
        if old_row is None:
            # Nothing to retire, so nothing to hold back: the address the hub
            # rotated away from is not in the table (evicted under the track
            # cap, or pruned before a restart), and no quiet check is looking
            # at it. Believing the claim suppresses nothing.
            ok, held, missing, against = True, ["the old address is no longer tracked"], [], False
        else:
            ok, held, missing, against = self._rotation_evidence(prev, ext)
        # The window binds whatever turns up after it, corroboration included:
        # evidence that arrives half a day late is a coincidence the mesh
        # happened to supply, not the rotation being witnessed.
        expired = late and now - new.get("unverified_since", now) > self.ROTATION_RECHECK_S
        who = name or r.get("instance") or host
        if expired or not (ok or trusted):
            if not late:
                new["unverified_previous"], new["unverified_since"] = prev, now
            # Said once per claim: as soon as the traffic argues against it,
            # whether that is the look that reported the claim or a later one
            # (the old address talking on is exactly the contradiction that
            # takes a second look to see), and when the window runs out with
            # nothing having corroborated it, which is worth hearing before
            # the old address's silences are all the operator has to go on.
            if against or expired:
                if not new.get("unverified_reported"):
                    new["unverified_reported"] = True
                    fix = (f'threadwatch name {ext} "{name}"' if name
                           else f'threadwatch name {ext} "<name>"')
                    self._emit("border_router_rotation_unverified", "notice", now, addr=ext, name=name,
                               previous=prev, hostname=host, evidence="; ".join(held) or None,
                               missing="; ".join(missing),
                               note=(f"{who} advertises {ext}, was {prev}, but the radio does not "
                                     f"corroborate it: {'; '.join(missing)}. mDNS is unauthenticated, so "
                                     f"{prev} keeps its name and stays judged: expect it to report quiet. "
                                     f"If the hub really did rotate, confirm it with: {fix} (then restart "
                                     "the recorder)."))
            if expired:
                for key in ("unverified_previous", "unverified_since", "unverified_reported"):
                    new.pop(key, None)
            return
        for key in ("unverified_previous", "unverified_since", "unverified_reported"):
            new.pop(key, None)
        if old_row is not None:
            old_row["rotated_to"] = ext
            old_row.pop("quiet_reported_ts", None)
            was_quiet = old_row.pop("quiet_reported", None) or prev in self.quiet_reported
            self.quiet_reported.discard(prev)
            self.seen._dirty = True
            if was_quiet:
                # The silence announced for the old address is over: the
                # device is back under the new one. A retired row is never
                # judged again, so nothing else could close the episode, and
                # every day page would carry it open.
                self._emit("device_returned", "notice", now, addr=prev, name=name,
                           note=f"back under a new address, {ext}")
        why = ("; ".join(held) if ok else
               'the advertisement alone ([border_routers] rotation = "trusted")')
        seen_late = ", corroborated by a later browse" if late else ""
        note = (f"{who} now answers to {ext}, was {prev}: an Apple hub takes a new Thread address on "
                f"every reboot. Retired on {why}{seen_late}, so {prev} is not reported quiet. "
                + ("Named from its entry; nothing to edit." if name
                   else "Not in devices.json: see the devices page."))
        self._border_router_changed = (now, name or host)
        self._emit("border_router_address_changed", "notice", now, addr=ext, name=name,
                   previous=prev, hostname=host, evidence=why, note=note)

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
            if not changed and rec.get("unverified_previous"):
                # A rotation an earlier browse reported but could not
                # corroborate, carried forward: the look below is at the
                # same claim, and border-routers.json keeps it over a
                # restart, so a recorder that came back does not start the
                # six hours again.
                new["unverified_previous"] = rec["unverified_previous"]
                new["unverified_since"] = rec.get("unverified_since", now)
                if rec.get("unverified_reported"):
                    new["unverified_reported"] = True
            if changed:
                # One entry per address, newest last, and never the live
                # one: an A -> B -> A rotation would otherwise leave two
                # entries for A and B and grow by one on every hop.
                retired = {prev, ext}
                new["previous"] = [e for e in new["previous"]
                                   if not (isinstance(e, dict) and (e.get("addr") or "").lower() in retired)]
                new["previous"].append({"addr": prev, "until": now})
                new["previous"] = new["previous"][-self.ROUTER_PREVIOUS_MAX:]
            # Naming and retiring are separate acts, and only one of them is
            # dangerous. Naming writes an in-memory index that decides what
            # the pages call an address; got wrong, it mislabels a row, and
            # the label is there to be seen and corrected. Retiring sets
            # rotated_to, which takes the old address out of the quiet
            # checks, out of the link and starvation checks, and out of the
            # summary's judged set: got wrong, it is a device that can never
            # page again, and nothing says so. So the hostname's claim is
            # enough to carry the name across, and only the radio retires.
            if entry is not None:
                self.names.learn(ext, entry)
            if changed:
                # The address it rotated to is live by definition, even if
                # it was itself retired once (an A -> B -> A sequence).
                if self.seen.table[ext].pop("rotated_to", None):
                    self.seen._dirty = True
                self._settle_rotation(prev, ext, name, host, r, now, new)
            elif new.get("unverified_previous"):
                self._settle_rotation(new["unverified_previous"], ext, name, host, r, now, new, late=True)
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

    # An address not in the inventory heard for less than this before its
    # silence is a visit, not a failure. Phones and tablets with a Thread
    # radio join the mesh for seconds to reach a HomeKit accessory: on
    # 2026-09-14 one attached, opened a session with a lock, and left 17 s
    # later, and its silence paged a warning half an hour on.
    BRIEF_VISIT_S = 5 * 60
    # The addresses visits.json remembers. Household phones keep theirs,
    # but every guest's phone or tablet adds one for good; past this the
    # longest-gone are forgotten, and their next visit is first seen again.
    VISITS_MAX = 256

    def _brief_visit(self, addr: str, row: dict) -> float | None:
        """How long a visitor was heard, or None for a device. A visitor is
        an address nobody named, heard for under BRIEF_VISIT_S in its
        latest stretch of presence (heard_since; first_seen for a row from
        before stretches were marked), that was a child: a router that
        appeared and died within minutes is a device missing from the
        inventory, and its silence is still a silence."""
        first = row.get("heard_since", row.get("first_seen"))
        if first is None or self.names.name(addr) is not None:
            return None
        heard_for = row["last_seen"] - first
        if heard_for >= self.BRIEF_VISIT_S:
            return None
        if (rloc16_role(row.get("rloc16")) or {}).get("role") == "router":
            return None
        return heard_for

    def _mark_stretch_from_log(self, addr: str, row: dict) -> None:
        """A row saved before heard_since existed: its latest stretch began
        at its last device_returned on record, if the log has one after
        first_seen. Only rows the visitor check could take are worth the
        read (unnamed children heard over the limit since first_seen); the
        day files are read newest first and the search stops at the first
        return found."""
        first, last = row.get("first_seen"), row.get("last_seen")
        events_dir = getattr(self.events, "dir", None)
        if events_dir is None or first is None or last is None or last - first < self.BRIEF_VISIT_S:
            return
        if self.names.name(addr) is not None or (rloc16_role(row.get("rloc16")) or {}).get("role") == "router":
            return
        day, stop = day_of(last), day_of(first)
        while True:
            returns = [r["ts"] for r in read_day(events_dir, day)
                       if r.get("event") == "device_returned" and r.get("addr") == addr
                       and isinstance(r.get("ts"), (int, float)) and first < r["ts"] <= last]
            if returns:
                row["heard_since"] = max(returns)
                self.seen._dirty = True
                return
            if day <= stop:
                return
            day = day_of(time.mktime(time.strptime(day, "%Y-%m-%d")) - 43200)   # the day before

    def _file_visit(self, addr: str, row: dict, now: float, persist: bool = True) -> None:
        """A visitor left: log the visit, with everything the row knew about
        it, and drop the row. Nothing about a visit is current once it is
        over, so nothing stays for the pages to show as quiet or unnamed, and
        an address that visits under a new address each time does not grow
        the device table. The record keeps the evidence a later visit can
        be compared against: which key generation it sent under and how
        far its MLE counter had run."""
        since = row.get("heard_since", row["first_seen"])
        heard_for = row["last_seen"] - since
        known = dict(self._visits.get(addr) or {})
        visit = int(known.get("visits") or 0) + 1
        known.update(visits=visit, last_visit=row["last_seen"], last_heard_for_s=round(heard_for),
                     first_visit=min(since, known.get("first_visit") or since))
        self._visits[addr] = known
        if len(self._visits) > self.VISITS_MAX:
            oldest = sorted(self._visits, key=lambda a: _seconds(self._visits[a].get("last_visit")))
            for a in oldest[:len(self._visits) - self.VISITS_MAX]:
                del self._visits[a]
        self._save_visits()
        parent, parent_addr = self._last_parent(row)
        generations = []
        for seq in sorted({*self._mle_counter.get(addr, {}), *self._mac_counter.get(addr, {})},
                          key=lambda x: (x is not None, x or 0)):
            mle = self._mle_counter.get(addr, {}).get(seq)
            mac = self._mac_counter.get(addr, {}).get(seq)
            generations.append({"sequence": seq, "mle_counter": mle[0] if mle else None,
                                "counter": mac[0] if mac else None})
        self._emit("visitor_left", "info", now, addr=addr, name=self.visitor_names.name(addr), visit=visit,
                   first_seen=since, last_seen=row["last_seen"],
                   heard_for_s=round(heard_for), silent_for_s=round(now - row["last_seen"]),
                   frames=row.get("frames"), rloc16=row.get("rloc16"),
                   parent=parent, parent_addr=parent_addr, rssi_dbm=row.get("rssi"),
                   generations=generations,
                   note=(f"an address not in the inventory, heard for {round(heard_for)} s and then no "
                         "more: a visitor (a phone or tablet joining the mesh briefly to reach a HomeKit "
                         "accessory), not a device that failed"))
        self._forget(addr)
        if persist:
            self.seen.save()

    def _last_parent(self, row: dict) -> tuple[str | None, str | None]:
        """The parent a row last sat under, by name where it has one, and
        its address: from the router holding the row's short address."""
        parent_addr = parent_address(row, router_holders(self.seen.table))
        live = rloc16_role(row.get("rloc16")) or {}
        parent = ((self.names.name(parent_addr) or parent_addr) if parent_addr
                  else (f"router {live['router_id']}" if live else None))
        return parent, parent_addr

    def _forget_unnamed(self, now: float) -> None:
        """Drop the rows of addresses nobody named that have been silent for
        [quiet] forget_unnamed_s. Only a visit's row went before, so any
        other unnamed address stayed quiet and unknown for good: on
        2026-09-18 a sensor that lost its fabric rejoined under a new
        address, was reset under another the next morning, and the one in
        between was listed in every daily summary after. An address that
        was a router stays, as a device missing from the inventory; so do
        a hub's retired address and a labelled visitor's."""
        keep_s = self.cfg.quiet_forget_unnamed_s
        if keep_s <= 0:
            return
        gone = [(addr, row) for addr, row in self.seen.table.items()
                if now - row["last_seen"] >= keep_s and not row.get("rotated_to")
                and self.names.name(addr) is None and self.visitor_names.name(addr) is None
                and (rloc16_role(row.get("rloc16")) or {}).get("role") != "router"]
        for addr, row in gone:
            parent, parent_addr = self._last_parent(row)
            silent = round(now - row["last_seen"])
            self._emit("address_forgotten", "info", now, addr=addr, first_seen=row.get("first_seen"),
                       last_seen=row["last_seen"], silent_for_s=silent, frames=row.get("frames"),
                       rloc16=row.get("rloc16"), parent=parent, parent_addr=parent_addr,
                       rssi_dbm=row.get("rssi"), pan=row.get("pan"),
                       observed_names=dict(self.observed_names.get(addr) or {}),
                       note=(f"an address not in the inventory, silent for {silent / 86400:.1f} days: "
                             "dropped from the device table so it is no longer listed quiet or "
                             "unknown. A device that took a new address (a reset, a lost fabric) "
                             "leaves its old one behind like this; it comes back as a new "
                             "device_first_seen if it is ever heard again."))
            self._forget(addr)
        if gone:
            self.seen.save()

    def _report_quiet(self, addr: str, row: dict, now: float, persist: bool = True) -> None:
        """Emit device_quiet once and remember, in memory and in the row
        (persisted with last-seen.json), that it has been announced.

        Persist at once, as a return does: the flag is what stops a restart
        announcing this silence a second time, and waiting for the next 30 s
        save leaves a window where the outage that follows costs the flag but
        not the silence. Quiets are rare, saves are cheap. The startup pass
        passes persist=False and saves once for the batch it announces.

        An address that was only ever a brief visitor is not quiet, it has
        left: its visit is filed instead and its row goes."""
        if self._brief_visit(addr, row) is not None:
            self._file_visit(addr, row, now, persist)
            return
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
        unheard_s = self.silence_s(row, now)
        blind = max(0.0, wall - unheard_s)
        # A device the sniffer barely hears goes "quiet" whenever the link
        # fades; log it, but do not page for it.
        rssi = row.get("rssi")
        marginal = reception(rssi, self.cfg.quiet_min_rssi_dbm) == "marginal"
        # A device only a radio now down was hearing is out of earshot,
        # which the recorder cannot tell from silent: logged, not paged,
        # as a marginal device is.
        unheard = self._unheard_radio(row)
        if unheard:
            note = (f"the only radio that heard this device lately ({unheard}) is down: its silence here is "
                    "the recorder's loss of that radio until another hears it, not evidence about the device")
        elif marginal:
            note = ("sniffer hears this device at the edge of its range; "
                    "silence is more likely reception than failure")
        else:
            note = ("no frames heard; if no mle_rejoin_attempt follows, "
                    "suspect device-internal failure rather than RF")
        # What the rest of the recorder already knows about this device
        # outranks the reception hedge: the leader the mesh lost, or Home
        # Assistant having marked it unavailable, is a device that failed,
        # however faintly the sniffer heard it.
        corroborated = []
        lost = self.lost_leader_for(addr)
        if lost and abs(row["last_seen"] - lost["ts"]) <= 600:
            corroborated.append(
                f"it was the mesh leader: it stopped leading at "
                f"{time.strftime('%H:%M:%S', time.localtime(lost['ts']))} and the routers re-elected "
                f"{lost.get('successor') or 'another router'}")
        ha_since = self._ha_unavailable_since(addr)
        if ha_since is not None:
            corroborated.append(f"Home Assistant has had it unavailable since "
                                f"{time.strftime('%H:%M:%S', time.localtime(ha_since))}")
        if corroborated:
            note = "; ".join(corroborated) + ": the device failed, whatever the signal here. " + note
        if blind >= 60:
            note += (f" (the recorder itself was not listening for {round(blind / 60)} min of the "
                     f"{round(wall / 60)} min: a restart, a stalled dongle or a clock step)")
        # Proof of life the recorder did not hear itself (_vouch): the
        # report waited for it to age out, and says so. A radio that went
        # on acknowledging for a minute after the device's last frame is
        # a hung stack with a live radio; a parent that kept answering for
        # an hour is reception, and the recorder's chair to blame.
        vouched, how = row.get("vouched_ts"), row.get("vouched_by")
        proxy = {}
        if vouched is not None and vouched > row["last_seen"]:
            proxy = {"vouched_ts": vouched, "vouched_by": how}
            what = {"parent": "its parent answered its keep-alive",
                    "ack": "its radio acknowledged a frame"}.get(how, "something answered for it")
            note += (f"; {what} {round((now - vouched) / 60)} min ago, "
                     f"{round((vouched - row['last_seen']) / 60)} min after its last frame heard here, "
                     "so it was alive then, out of the recorder's earshot")
        # The inventory's mute is applied in _emit (MUTED_EVENTS).
        soft = (marginal or unheard) and not corroborated
        self._emit(
            "device_quiet", "notice" if soft else "warning", now, addr=addr,
            name=self.names.name(addr), silent_for_s=round(wall), unheard_s=round(unheard_s),
            blind_s=round(blind), last_seen=row["last_seen"], hold_s=self.quiet_threshold_s(addr),
            rssi_dbm=rssi, reception="unheard" if unheard else "marginal" if marginal else "good",
            radio_down=unheard, was_leader=bool(lost and abs(row["last_seen"] - lost["ts"]) <= 600),
            ha_unavailable_since=ha_since, note=note, **proxy)


class CredentialsError(RuntimeError):
    """No usable network key: the recorder cannot do its job without one."""


def credentials_path(cfg) -> Path:
    return Path(cfg.credentials_path) if getattr(cfg, "credentials_path", None) \
        else cfg.config_dir / "credentials.toml"


def parse_network_key(raw: dict) -> bytes | None:
    """The 16-byte network key from a parsed credentials.toml, or None.
    bytes.fromhex skips whitespace between bytes, so a key grouped with
    spaces or with a trailing one loads; doctor judges it by this too."""
    try:
        key = bytes.fromhex(str(raw.get("credentials", {}).get("network_key", "")))
    except ValueError:
        return None
    return key if len(key) == 16 else None


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
    key = parse_network_key(raw)
    if key is None:
        raise CredentialsError(f"{cred_path}: network_key must be 32 hex digits ({how})")
    try:
        from .crypto import Decryptor
    except ModuleNotFoundError as exc:
        raise CredentialsError(f"decryption needs the 'cryptography' package ({exc}); "
                               "pip install cryptography, or apt install python3-cryptography "
                               "into the interpreter bin/threadwatch uses") from exc
    return Decryptor(network_key=key)
