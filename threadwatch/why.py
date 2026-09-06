"""`threadwatch why <device>`: reconstruct one device's story from the ring.

Walks the ring pcaps (or a given file) and produces a per-hour narrative for
one device: cadence, RSSI trend, ACK health, MLE activity (with credentials),
silences — the questions you ask when something went offline. The packets
last a week; the event log is kept forever, so the device's episodes from
it (quiet spells, rejoins, bad links) follow, newest first, to answer
"has this happened before?".
"""

from __future__ import annotations

import sys
from pathlib import Path

from .config import Config
from .events import NullEventLog
from .names import DeviceNames
from .pcap import PcapStreamReader, is_poll
from .pipeline import Pipeline, load_decryptor
from .review import coverage, devices_history, episode_blind_s, fmt_duration, fmt_episode

HISTORY_ROWS = 20


def resolve_target(cfg: Config, target: str) -> tuple[list[str], str]:
    """Resolve a name or address into the set of extended addresses to track
    (every address of a rotating device belongs to the story)."""
    try:
        from .names import load_names
        return load_names(cfg).resolve(target)
    except ValueError as exc:
        raise SystemExit(str(exc))


RING_NAME = "threadwatch-%Y%m%d-%H.pcap"


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
        try:
            start = _t.mktime(_t.strptime(path.name, RING_NAME))
        except ValueError:
            keep.append(path)
            continue
        if start + 3600 > cutoff:
            keep.append(path)
    return keep


event_history = devices_history   # every address of a rotating device, newest first


def newest_hour_end(files: list[Path]) -> float | None:
    """When the newest ring-named file's hour ends: what "the last N
    hours" of a frozen incident counts back from, since its files stop
    where the freeze was, not now."""
    import time as _t
    ends = []
    for path in files:
        try:
            ends.append(_t.mktime(_t.strptime(path.name, RING_NAME)) + 3600)
        except ValueError:
            continue
    return max(ends) if ends else None


def blind_during(events_dir: Path, a: float, b: float) -> float:
    """How much of the span a..b the recorder was not listening for, from
    the log's coverage (docs/REVIEW.md): a silence the recorder slept
    through is not the device's."""
    from .events import day_of, next_day
    import time as _t
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
        print(f"  ... {len(episodes) - len(shown)} more: threadwatch web, /device/{addrs[0]}")


def run_why(cfg: Config, target: str, pcap_file: Path | None = None,
            hours: float | None = None, incident_dir: Path | None = None) -> int:
    """Print the device's story. Returns 0, or 1 when some of the files
    could not be read (the report then covers the rest); exits with a
    message when none could. With ``incident_dir`` the story is the frozen
    incident's: its pcaps, and (cfg.for_incident) its inventory and event
    log, so the names and the history are the ones current when it was
    frozen."""
    if incident_dir is not None:
        cfg = cfg.for_incident(incident_dir)
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
    elif incident_dir is not None:
        ring = sorted(incident_dir.glob("*.pcap"))
        if not ring:
            raise SystemExit(f"no pcap files in incident {incident_dir.name}")
        files = select_recent(ring, hours, now=newest_hour_end(ring))
        if not files:
            raise SystemExit(f"no files in the incident's last {hours:g} h (it spans "
                             f"{ring[0].name[12:23]} to {ring[-1].name[12:23]})")
    else:
        ring = sorted(cfg.ring_dir.glob("threadwatch-*.pcap"))
        if not ring:
            raise SystemExit("no ring files; is the capture daemon running?")
        files = select_recent(ring, hours)
        if not files:
            raise SystemExit(f"no ring files in the last {hours:g} h (the ring spans "
                             f"{ring[0].name[12:23]} to {ring[-1].name[12:23]})")

    from collections import defaultdict
    per_hour = defaultdict(lambda: {"frames": 0, "polls": 0, "rssi": [], "acked": 0,
                                 "tx": 0, "mle": {}})
    last_ts = None
    first_ts = None
    gaps = []
    prev_frame = None
    mle_events = []

    import time as _t

    def hour_of(ts):
        # The local wall-clock hour as (year, month, day, hour): sorts in
        # time order across a year boundary, where the printed label does
        # not ("01-01 00h" < "12-31 23h").
        return tuple(_t.localtime(ts)[:4])

    def inspect(f, h):
        """MLE visibility for one of our data frames (credentials only)."""
        from .crypto import Decryptor, MLE_UDP_PORT
        ext = f.src if len(f.src) == 16 else None
        plain = decryptor.decrypt_frame(f.psdu, ext, f.src if len(f.src) == 4 else None)
        if not plain:
            return
        r = Decryptor.udp_ports(plain, mac_src_ext=ext,
                                mac_dst_ext=f.dst if f.dst and len(f.dst) == 16 else None,
                                mac_dst_short=f.dst if f.dst and len(f.dst) == 4 else None)
        if r and MLE_UDP_PORT in (r[0], r[1]):
            info = decryptor.parse_mle(r[2], ext or decryptor.short_to_ext.get(f.src), r[3], r[4])
            if info:
                h["mle"][info.command_name] = h["mle"].get(info.command_name, 0) + 1
                if info.secured and info.command_name in ("Parent Request", "Child ID Request", "Announce"):
                    mle_events.append((f.ts, info.command_name))

    undecodable = 0
    skipped_bytes = skipped_files = 0
    unreadable: list[tuple[Path, Exception]] = []
    for path in files:
        try:
            with open(path, "rb") as fh:
                reader = PcapStreamReader(fh)
                for f in reader:
                    # Every frame goes through the pipeline, ours or not:
                    # another device's MLE advertisement carries the key
                    # sequence the target's short-source frames are
                    # secured under, and without it those frames resolve
                    # to nobody and the device reads as unheard. The
                    # pipeline's answer is the attribution used here, so
                    # no frame is identified twice.
                    is_ours = pipe.ingest(f) in addr_set
                    # ACK for our previous unicast transmission
                    if (prev_frame is not None and f.ftype == 2
                            and f.seq == prev_frame.seq and f.ts - prev_frame.ts < 0.05):
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
                    if first_ts is None:
                        first_ts = f.ts
                    if last_ts is not None and f.ts - last_ts > cfg.quiet_s:
                        gaps.append((last_ts, f.ts))
                    last_ts = f.ts
                    if f.ftype == 1:
                        try:
                            inspect(f, h)
                        except Exception:   # one malformed unsecured payload; keep going
                            undecodable += 1
        except Exception as exc:
            # A file that cannot be opened or is not a pcap: said on stderr,
            # not woven into the report. With none readable there is no
            # report to give: "no frames from this device" would be a
            # verdict on zero packets, delivered with exit 0 to whatever
            # script asked, in the middle of the outage it was asked about.
            print(f"(skipping {path}: {exc})", file=sys.stderr, flush=True)
            unreadable.append((path, exc))
        else:
            if reader.skipped_bytes:
                skipped_bytes += reader.skipped_bytes
                skipped_files += 1
    if unreadable and len(unreadable) == len(files):
        path, exc = unreadable[0]
        raise SystemExit(f"threadwatch why: could not read {path}: {exc}" if len(files) == 1 else
                         f"threadwatch why: none of the {len(files)} ring files could be read "
                         f"(first: {path}: {exc})")
    if undecodable:
        print(f"({undecodable} frames with undecodable payloads skipped)")
    if skipped_bytes:
        print(f"({skipped_bytes} bytes in {skipped_files} ring file(s) are not readable records and were skipped)")

    print(f"=== {display} ({', '.join(addrs)}) ===")
    if unreadable:
        print(f"WARNING: {len(unreadable)} of {len(files)} ring file(s) could not be read (see stderr); "
              "what follows covers the rest only")
    if not pcap_file:
        window = f"last {hours:g} h: " if hours is not None else ""
        source = f"incident {incident_dir.name}: " if incident_dir is not None else ""
        print(f"analyzed {source}{window}{len(files)} ring file(s), {files[0].name[12:23]} to {files[-1].name[12:23]}")
    if first_ts is None:
        print("No frames from this device in the analyzed window.")
        print("Interpretation: either out of range of the dongle, silent (dead "
              "battery / crashed radio), or transmitting under an unknown "
              "rotated address — check `threadwatch report` for unknowns.")
        print_history(cfg.events_dir, addrs)
        return 1 if unreadable else 0
    print(f"first seen: {_t.strftime('%Y-%m-%d %H:%M:%S', _t.localtime(first_ts))}")
    print(f"last seen:  {_t.strftime('%Y-%m-%d %H:%M:%S', _t.localtime(last_ts))}"
          f"  ({round((_t.time() - last_ts) / 60, 1)} min ago)")
    # The year is shown only when the table spans more than one.
    years = {k[0] for k in per_hour}
    labels = {k: (f"{k[0]}-" if len(years) > 1 else "") + f"{k[1]:02d}-{k[2]:02d} {k[3]:02d}h" for k in per_hour}
    width = max([12, *(len(v) for v in labels.values())])
    print(f"\n{'hour':{width}s} {'frames':>6s} {'polls':>6s} {'tx':>5s} {'acked':>6s} {'rssi med':>9s}  mle")
    for hkey in sorted(per_hour):
        h = per_hour[hkey]
        if h["frames"] == 0 and h["acked"] == 0:
            continue
        rssi = sorted(h["rssi"])
        med = f"{rssi[len(rssi)//2]:.0f}" if rssi else "-"
        mle = ", ".join(f"{k}x{v}" for k, v in h["mle"].items()) if h["mle"] else ""
        print(f"{labels[hkey]:{width}s} {h['frames']:6d} {h['polls']:6d} {h['tx']:5d} {h['acked']:6d} {med:>9s}  {mle}")
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
    print_history(cfg.events_dir, addrs)
    return 1 if unreadable else 0
