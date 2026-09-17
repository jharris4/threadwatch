"""`threadwatch device <device>`: reconstruct one device's story from the ring.

Walks the ring pcaps (or a given file) and produces a per-hour narrative for
one device: cadence, RSSI trend, ACK health, MLE activity (with credentials),
silences — the questions you ask when something went offline. The packets
last a week; the event log lasts a year by default ([events] keep_days),
so the device's episodes from it (quiet spells, rejoins, bad links)
follow, newest first, to answer "has this happened before?".
"""

from __future__ import annotations

import sys
from pathlib import Path

from .config import Config
from .events import NullEventLog
from .merge import merge_readers
from .pcap import PcapStreamReader, is_poll
from .pipeline import Pipeline, load_decryptor
from .review import coverage, devices_history, episode_blind_s, fmt_duration, fmt_episode
from .ring import HOUR_FORMAT, group_files, parse_ring_name
from .snapshot import saved_at

HISTORY_ROWS = 20


def resolve_target(cfg: Config, target: str) -> tuple[list[str], str]:
    """Resolve a name or address into the set of extended addresses to track
    (every address of a rotating device belongs to the story)."""
    try:
        from .names import load_names
        return load_names(cfg).resolve(target)
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


def _hour_start(path: Path) -> float | None:
    """When a ring-named file's local hour starts (any radio's series),
    None for a name that is not a ring file's."""
    import time as _t
    parsed = parse_ring_name(path.name)
    if parsed is None:
        return None
    try:
        return _t.mktime(_t.strptime(parsed[0], HOUR_FORMAT))
    except ValueError:
        return None


def select_recent(files: list[Path], hours: float | None, now: float | None = None) -> list[Path]:
    """The ring files that cover any of the last ``hours``: a file is named
    for the local hour it starts, so it is kept when that hour ends after
    the window opens. ``hours`` None keeps everything. A name that does not
    parse is kept: better to read too much than to skip evidence."""
    if hours is None:
        return list(files)
    import time as _t
    cutoff = (now or _t.time()) - hours * 3600
    keep = []
    for path in files:
        start = _hour_start(path)
        if start is None or start + 3600 > cutoff:
            keep.append(path)
    return keep


event_history = devices_history   # every address of a rotating device, newest first


def newest_hour_end(files: list[Path]) -> float | None:
    """When the newest ring-named file's hour ends: what "the last N
    hours" of a saved snapshot counts back from, since its files stop
    where the snapshot was taken, not now."""
    ends = [start + 3600 for path in files if (start := _hour_start(path)) is not None]
    return max(ends) if ends else None


def blind_during(events_dir: Path, a: float, b: float) -> float:
    """How much of the span a..b the recorder was not listening for, from
    the log's coverage (docs/REVIEW.md): a silence the recorder slept
    through is not the device's."""
    import time as _t

    from .events import day_of, next_day
    total, day, last = 0.0, day_of(a), day_of(b)
    now = max(b, _t.time())
    while day <= last:
        total += episode_blind_s({"start": a, "end": b}, coverage(events_dir, day, now), now)
        day = next_day(day)
    return total


def print_history(events_dir: Path, addrs: list[str], now: float | None = None) -> None:
    episodes = event_history(events_dir, addrs, now)
    if not episodes:
        print("\nevent log: nothing recorded for this device.")
        return
    shown = episodes[:HISTORY_ROWS]
    # Local days, as every other day count here is: // 86400 buckets by the
    # UTC calendar, so two evening episodes on one local day west of
    # Greenwich report as two.
    from .events import day_of
    days = len({day_of(e["start"]) for e in episodes})
    print(f"\nevent log ({len(episodes)} episode(s) across {days} day(s), newest first"
          + (f", latest {len(shown)}" if len(shown) < len(episodes) else "") + "):")
    for ep in shown:
        print("  " + fmt_episode(ep, "%Y-%m-%d %H:%M"))
    if len(shown) < len(episodes):
        print(f"  ... {len(episodes) - len(shown)} more: threadwatch serve, /device/{addrs[0]}")


def run_device(cfg: Config, target: str, pcap_file: Path | None = None,
            hours: float | None = None, snapshot_dir: Path | None = None) -> int:
    """Print the device's story. Returns 0, or 1 when some of the files
    could not be read (the report then covers the rest); exits with a
    message when none could. With ``snapshot_dir`` the story is the saved
    snapshot's: its pcaps, and (cfg.for_snapshot) its inventory and event
    log, so the names and the history are the ones current when it was
    saved."""
    # A snapshot is read on its own terms: months later, "the last 90
    # days" measured from today holds none of the history saved with it,
    # and an episode still open when it was saved would stretch its
    # duration to now. Everything the bundle knows stops at the moment it
    # was taken, so that is the moment its history is read against; the
    # last frame analyzed stands in when the manifest cannot be read.
    reference = None
    if snapshot_dir is not None:
        cfg = cfg.for_snapshot(snapshot_dir)
        reference = saved_at(snapshot_dir)
    addrs, display = resolve_target(cfg, target)
    addr_set = set(addrs)
    decryptor = load_decryptor(cfg)
    print("[threadwatch] credentials: loaded", file=sys.stderr, flush=True)
    # With credentials, frames sent from a short address (everything a
    # sleepy end device sends once attached, polls included) are attributed
    # by the same MIC search the live pipeline uses.
    pipe = Pipeline(cfg, NullEventLog(), decryptor, ephemeral=True)
    pipe.extra_candidates = addrs      # the device asked about need not be in devices.json

    if pcap_file:
        files = [pcap_file]
    elif snapshot_dir is not None:
        ring = sorted(snapshot_dir.glob("*.pcap"))
        if not ring:
            raise SystemExit(f"no pcap files in snapshot {snapshot_dir.name}")
        files = select_recent(ring, hours, now=newest_hour_end(ring))
        if not files:
            raise SystemExit(f"no files in the snapshot's last {hours:g} h (it spans "
                             f"{ring[0].name[12:23]} to {ring[-1].name[12:23]})")
    else:
        ring = sorted(cfg.ring_dir.glob("threadwatch-*.pcap"))
        if not ring:
            raise SystemExit("no ring files; is the recorder running?")
        files = select_recent(ring, hours)
        if not files:
            raise SystemExit(f"no ring files in the last {hours:g} h (the ring spans "
                             f"{ring[0].name[12:23]} to {ring[-1].name[12:23]})")

    from collections import defaultdict
    per_hour = defaultdict(lambda: {"frames": 0, "polls": 0, "rssi": [], "acked": 0,
                                 "tx": 0, "mle": {}, "rssi_by": defaultdict(list)})
    heard_by: dict = defaultdict(int)     # frames of this device per named radio
    last_ts = None
    first_ts = None
    gaps = []
    prev_frame = None
    mle_events = []
    generations: dict = {}     # key generation -> [first frame ts, last frame ts, frames], vouched frames only

    import time as _t

    def hour_of(ts):
        # The local wall-clock hour as (year, month, day, hour): sorts in
        # time order across a year boundary, where the printed label does
        # not ("01-01 00h" < "12-31 23h").
        return tuple(_t.localtime(ts)[:4])

    def inspect(f, h):
        """MLE visibility for one of our data frames, as the pipeline just
        read it (Pipeline.last_mle).

        Never a second decode of the same bytes. Parsing the frame again
        here called parse_mle with its default bind_short, which applies
        the short address the message asserts without the counter check
        the pipeline makes first - so a replayed message moved an address
        the pipeline had refused to move, in the very decryptor the
        pipeline goes on using, and the report disagreed with replay and
        the recorder over one capture. A stale message is still traffic
        and still counted as the message it is; only a fresh authenticated
        one is an attach attempt the device actually made."""
        got = pipe.last_mle
        if got is None:
            return
        info, fresh = got
        h["mle"][info.command_name] = h["mle"].get(info.command_name, 0) + 1
        if fresh and info.command_name in ("Parent Request", "Child ID Request", "Announce"):
            mle_events.append((f.ts, info.command_name))

    # An MLE payload the pipeline could not parse: its own count, since
    # the report no longer decodes anything itself.
    parse_failed_before = decryptor.stats.get("parse_failed", 0)
    refused = 0                # frames bearing the address that did not vouch for it
    skipped_bytes = skipped_files = tail_bytes = 0
    unreadable: list[tuple[Path, Exception]] = []
    from contextlib import ExitStack
    # An hour recorded by several radios is several files read together,
    # merged as the recorder merged them (merge.py); one radio's file
    # unreadable costs that radio's copies of the hour, not the hour.
    for group in group_files(files):
        with ExitStack() as stack:
            readers = {}
            for label, path in group.items():
                try:
                    readers[label] = PcapStreamReader(stack.enter_context(open(path, "rb")))
                except Exception as exc:
                    print(f"(skipping {path}: {exc})", file=sys.stderr, flush=True)
                    unreadable.append((path, exc))
            if not readers:
                continue
            try:
                for f in merge_readers(readers, primary=None if None in readers else next(iter(readers))):
                    # Every frame goes through the pipeline, ours or not:
                    # another device's MLE advertisement carries the key
                    # sequence the target's short-source frames are
                    # secured under, and without it those frames resolve
                    # to nobody and the device reads as unheard. The
                    # pipeline's answer is the attribution used here, so
                    # no frame is identified twice.
                    is_ours = pipe.ingest(f) in addr_set
                    # Attribution is not a sighting. An extended address is
                    # 64 bits the sender asserts, and the pipeline counts a
                    # frame as the device's own only when its MIC and its
                    # frame counter vouch for it. The traffic table below
                    # is everything that carried the address - a beacon
                    # request during a join scan is unsecured and worth
                    # seeing - but when the device was last really heard,
                    # and the silences that follow from it, are the
                    # vouched-for frames alone, as the recorder judged them.
                    vouched = is_ours and pipe.last_sighting in addr_set
                    # ACK for our previous unicast transmission
                    if (prev_frame is not None and f.ftype == 2
                            and f.seq == prev_frame.seq and 0.0 <= f.ts - prev_frame.ts < 0.05):
                        per_hour[hour_of(prev_frame.ts)]["acked"] += 1
                    prev_frame = f if is_ours and f.dst not in (None, "ffff") else None
                    if not is_ours:
                        continue
                    h = per_hour[hour_of(f.ts)]
                    h["frames"] += 1
                    if f.ftype in (1, 3) and f.dst not in (None, "ffff"):   # unicast only: broadcasts are never ACKed
                        h["tx"] += 1
                    if is_poll(f):
                        h["polls"] += 1
                    if f.rssi is not None:
                        h["rssi"].append(f.rssi)
                    for label, copy in (f.heard or {}).items():
                        if label is not None:
                            heard_by[label] += 1
                            if copy.rssi is not None:
                                h["rssi_by"][label].append(copy.rssi)
                    if vouched:
                        if first_ts is None:
                            first_ts = f.ts
                        if last_ts is not None and f.ts - last_ts > cfg.quiet_s:
                            gaps.append((last_ts, f.ts))
                        last_ts = f.ts
                        # The key generation the pipeline accepted this
                        # frame under, as it judged it: which generations
                        # the device has sent under and when, so a device
                        # left behind by a rotation shows it here.
                        gen = pipe.last_generation
                        if gen is not None:
                            span = generations.setdefault(gen, [f.ts, f.ts, 0])
                            span[1] = f.ts
                            span[2] += 1
                    else:
                        refused += 1
                    if f.ftype == 1:
                        inspect(f, h)
            except Exception as exc:
                # A file that is not a pcap past its header, or damaged in
                # a way the reader cannot step over: said on stderr, not
                # woven into the report. With none readable there is no
                # report to give: "no frames from this device" would be a
                # verdict on zero packets, delivered with exit 0 to whatever
                # script asked, in the middle of the outage it was asked about.
                for path in group.values():
                    print(f"(skipping {path}: {exc})", file=sys.stderr, flush=True)
                    unreadable.append((path, exc))
            else:
                for reader in readers.values():
                    if reader.skipped_bytes:
                        skipped_bytes += reader.skipped_bytes
                        skipped_files += 1
                    tail_bytes += reader.tail_bytes
    if unreadable and len(unreadable) == len(files):
        path, exc = unreadable[0]
        raise SystemExit(f"threadwatch device: could not read {path}: {exc}" if len(files) == 1 else
                         f"threadwatch device: none of the {len(files)} ring files could be read "
                         f"(first: {path}: {exc})")
    undecodable = decryptor.stats.get("parse_failed", 0) - parse_failed_before
    if undecodable:
        print(f"({undecodable} frames with undecodable payloads skipped)")
    if refused:
        print(f"({refused} frame(s) carrying this address did not vouch for it - unsecured, a replay, or "
              "a forgery - and count as traffic below but not as sightings of the device)")
    if skipped_bytes:
        print(f"({skipped_bytes} bytes in {skipped_files} ring file(s) are not readable records and were skipped)")
    if tail_bytes:
        print(f"({tail_bytes} bytes at the end of the capture(s) hold no readable record and were not read; "
              "a file cut short by a crash ends this way, and so does one damaged past recovery)")

    print(f"=== {display} ({', '.join(addrs)}) ===")
    if unreadable:
        print(f"WARNING: {len(unreadable)} of {len(files)} ring file(s) could not be read (see stderr); "
              "what follows covers the rest only")
    if not pcap_file:
        window = f"last {hours:g} h: " if hours is not None else ""
        source = f"snapshot {snapshot_dir.name}: " if snapshot_dir is not None else ""
        hours_on_disk = sorted({parsed[0] for f in files if (parsed := parse_ring_name(f.name))})
        radios = sorted({parsed[1] for f in files if (parsed := parse_ring_name(f.name)) and parsed[1]})
        count = (f"{len(hours_on_disk)} hour(s) in {len(files)} ring file(s) from {len(radios) + 1} radios"
                 if radios else f"{len(files)} ring file(s)")
        span = f", {hours_on_disk[0]} to {hours_on_disk[-1]}" if hours_on_disk else ""
        print(f"analyzed {source}{window}{count}{span}")
    if not per_hour:
        print("No frames from this device in the analyzed window.")
        print("Interpretation: either out of range of the dongle, silent (dead "
              "battery / crashed radio), or transmitting under an unknown "
              "rotated address — check `threadwatch devices` for unknowns.")
        print_history(cfg.events_dir, addrs, reference)
        return 1 if unreadable else 0
    if first_ts is None:
        print("Not heard: frames carrying this address are in the window, but none of them vouched for "
              "the sender, so none is a sighting. The traffic is below; the device itself was not heard.")
    else:
        print(f"first seen: {_t.strftime('%Y-%m-%d %H:%M:%S', _t.localtime(first_ts))}")
        print(f"last seen:  {_t.strftime('%Y-%m-%d %H:%M:%S', _t.localtime(last_ts))}"
              f"  ({round((_t.time() - last_ts) / 60, 1)} min ago)")
    # The year is shown only when the table spans more than one.
    years = {k[0] for k in per_hour}
    labels = {k: (f"{k[0]}-" if len(years) > 1 else "") + f"{k[1]:02d}-{k[2]:02d} {k[3]:02d}h" for k in per_hour}
    width = max([12, *(len(v) for v in labels.values())])
    # With named radios, the median each radio heard beside the best ear's.
    radio_labels = sorted(heard_by)
    radio_heads = "".join(f" {('rssi ' + lab)[:9]:>9s}" for lab in radio_labels)
    print(f"\n{'hour':{width}s} {'frames':>6s} {'polls':>6s} {'tx':>5s} {'acked':>6s} {'rssi med':>9s}"
          f"{radio_heads}  mle")

    def median(values):
        ordered = sorted(values)
        return f"{ordered[len(ordered) // 2]:.0f}" if ordered else "-"

    for hkey in sorted(per_hour):
        h = per_hour[hkey]
        if h["frames"] == 0 and h["acked"] == 0:
            continue
        med = median(h["rssi"])
        by_radio = "".join(f" {median(h['rssi_by'].get(lab, [])):>9s}" for lab in radio_labels)
        mle = ", ".join(f"{k}x{v}" for k, v in h["mle"].items()) if h["mle"] else ""
        print(f"{labels[hkey]:{width}s} {h['frames']:6d} {h['polls']:6d} {h['tx']:5d} {h['acked']:6d} {med:>9s}"
              f"{by_radio}  {mle}")
    if radio_labels:
        total_frames = sum(h["frames"] for h in per_hour.values())
        parts = []
        for lab in radio_labels:
            levels = [v for h in per_hour.values() for v in h["rssi_by"].get(lab, [])]
            parts.append(f"{lab} {100 * heard_by[lab] / total_frames:.0f}% ({heard_by[lab]:,} frames"
                         + (f", {median(levels)} dBm median)" if levels else ")"))
        print("\nheard by: " + ", ".join(parts))
    # The pipeline's own per-device figures, over the same frames. The
    # hour table above counts an ACK on a sequence match alone; the
    # pipeline additionally requires the ACK to answer the transmission
    # it has pending, so ack_rate here is the stricter number and the one
    # the recorder judges a link by. Nothing else in the tool reads
    # DeviceStats.as_dict.
    # One block per address that has any, rather than the first address in
    # inventory order. A device that rotated keeps a DeviceStats per address,
    # and taking one of them described an old - possibly retired - address's
    # link while the hour table above counted every address's frames: the two
    # halves of one report disagreeing about what they covered. They are not
    # merged: an RSSI average and a poll cadence belong to the address they
    # were measured on, and a rotation is exactly where that matters.
    measured = [(a, pipe.devices[a]) for a in addrs if a in pipe.devices]
    for a, live in measured:
        d = live.as_dict()
        rssi = "-" if d["rssi_ewma"] is None else (
            f"{d['rssi_ewma']} dBm (min {d['rssi_min']:.0f}, max {d['rssi_max']:.0f})")
        acks = "-" if d["ack_rate"] is None else f"{d['ack_rate'] * 100:.0f}% of {d['tx']} unicast"
        poll = "-" if d["median_poll_interval_s"] is None else (
            f"{d['polls']} every {fmt_duration(d['median_poll_interval_s'])} (median)")
        head = f"\n{a}:" if len(measured) > 1 else ""
        print(f"{head}\nrssi:  {rssi}\nacked: {acks}\npolls: {poll}")

    if generations:
        # A device that keeps sending under a generation the mesh has left
        # behind is the key-lag story (docs/ALERTING.md): the last frame
        # under each generation says when it last did.
        print("\nkey generations (first -> last frame accepted under each):")
        for gen in sorted(generations):
            a, b, n = generations[gen]
            print(f"  {gen}: {_t.strftime('%m-%d %H:%M', _t.localtime(a))} -> "
                  f"{_t.strftime('%m-%d %H:%M', _t.localtime(b))}  ({n} frame{'s' if n != 1 else ''})")
    if gaps:
        print(f"\nsilences (>{fmt_duration(cfg.quiet_s)}, the configured [quiet] silence_s):")
        for a, b in gaps[-10:]:
            # A silence the recorder was not there for is not the device's.
            blind = blind_during(cfg.events_dir, a, b)
            deaf = f"  (recorder not listening for {fmt_duration(blind)} of it)" if blind >= 60 else ""
            print(f"  {_t.strftime('%m-%d %H:%M', _t.localtime(a))} -> "
                  f"{_t.strftime('%m-%d %H:%M', _t.localtime(b))}  ({round((b-a)/60)} min){deaf}")
    if mle_events:
        print("\nrejoin-related MLE (attach attempts):")
        for ts, cmd in mle_events[-10:]:
            print(f"  {_t.strftime('%m-%d %H:%M:%S', _t.localtime(ts))}  {cmd}")
    else:
        print("\nno rejoin-related MLE seen from this device in the window.")
    print_history(cfg.events_dir, addrs, reference if reference is not None
                  else (last_ts if snapshot_dir is not None else None))
    return 1 if unreadable else 0
