"""`threadwatch why <device>`: reconstruct one device's story from the ring.

Walks the ring pcaps (or a given file) and produces a per-hour narrative for
one device: cadence, RSSI trend, ACK health, MLE activity (with credentials),
silences — the questions you ask when something went offline. The packets
last a week; the event log is kept forever, so the device's episodes from
it (quiet spells, rejoins, bad links) follow, newest first, to answer
"has this happened before?".
"""

from __future__ import annotations

from pathlib import Path

from .config import Config
from .events import NullEventLog
from .names import DeviceNames
from .pcap import PcapStreamReader
from .pipeline import Pipeline, load_decryptor
from .review import devices_history, fmt_episode

HISTORY_ROWS = 20


def resolve_target(cfg: Config, target: str) -> tuple[list[str], str]:
    """Resolve a name or address into the set of extended addresses to track
    (every address of a rotating device belongs to the story)."""
    try:
        return DeviceNames(cfg.devices_path).resolve(target)
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


def print_history(events_dir: Path, addrs: list[str], now: float | None = None) -> None:
    episodes = event_history(events_dir, addrs, now)
    if not episodes:
        print("\nevent log: nothing recorded for this device.")
        return
    shown = episodes[:HISTORY_ROWS]
    days = len({e["start"] // 86400 for e in episodes})
    print(f"\nevent log ({len(episodes)} episode(s) across {days} day(s), newest first"
          + (f", latest {len(shown)}" if len(shown) < len(episodes) else "") + "):")
    for ep in shown:
        print("  " + fmt_episode(ep, "%Y-%m-%d %H:%M"))
    if len(shown) < len(episodes):
        print(f"  ... {len(episodes) - len(shown)} more: threadwatch web, /device/{addrs[0]}")


def run_why(cfg: Config, target: str, pcap_file: Path | None = None,
            hours: float | None = None) -> None:
    addrs, display = resolve_target(cfg, target)
    addr_set = set(addrs)
    decryptor = load_decryptor(cfg)
    # With credentials, frames sent from a short address (everything a
    # sleepy end device sends once attached, polls included) are attributed
    # by the same MIC search the live pipeline uses.
    pipe = Pipeline(cfg, NullEventLog(), decryptor, ephemeral=True)
    pipe.extra_candidates = addrs      # the device asked about need not be in devices.json
    ident = pipe.identity

    if pcap_file:
        files = [pcap_file]
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
        return _t.strftime("%m-%d %Hh", _t.localtime(ts))

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
                if info.command_name in ("Parent Request", "Child ID Request", "Announce"):
                    mle_events.append((f.ts, info.command_name))

    undecodable = 0
    for path in files:
        try:
            with open(path, "rb") as fh:
                for f in PcapStreamReader(fh):
                    is_ours = ident(f) in addr_set
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
                    if f.ftype == 3:
                        h["polls"] += 1
                    if f.rssi is not None:
                        h["rssi"].append(f.rssi)
                    if first_ts is None:
                        first_ts = f.ts
                    if last_ts is not None and f.ts - last_ts > 1800:
                        gaps.append((last_ts, f.ts))
                    last_ts = f.ts
                    if f.ftype == 1:
                        try:
                            inspect(f, h)
                        except Exception:   # one malformed unsecured payload; keep going
                            undecodable += 1
        except Exception as exc:
            print(f"(skipping {path}: {exc})")
    if undecodable:
        print(f"({undecodable} frames with undecodable payloads skipped)")

    print(f"=== {display} ({', '.join(addrs)}) ===")
    if not pcap_file:
        window = f"last {hours:g} h: " if hours is not None else ""
        print(f"analyzed {window}{len(files)} ring file(s), {files[0].name[12:23]} to {files[-1].name[12:23]}")
    if first_ts is None:
        print("No frames from this device in the analyzed window.")
        print("Interpretation: either out of range of the dongle, silent (dead "
              "battery / crashed radio), or transmitting under an unknown "
              "rotated address — check `threadwatch report` for unknowns.")
        print_history(cfg.events_dir, addrs)
        return
    print(f"first seen: {_t.strftime('%Y-%m-%d %H:%M:%S', _t.localtime(first_ts))}")
    print(f"last seen:  {_t.strftime('%Y-%m-%d %H:%M:%S', _t.localtime(last_ts))}"
          f"  ({round((_t.time() - last_ts) / 60, 1)} min ago)")
    print(f"\n{'hour':12s} {'frames':>6s} {'polls':>6s} {'tx':>5s} {'acked':>6s} {'rssi med':>9s}  mle")
    for hkey in sorted(per_hour):
        h = per_hour[hkey]
        if h["frames"] == 0 and h["acked"] == 0:
            continue
        rssi = sorted(h["rssi"])
        med = f"{rssi[len(rssi)//2]:.0f}" if rssi else "-"
        mle = ", ".join(f"{k}x{v}" for k, v in h["mle"].items()) if h["mle"] else ""
        print(f"{hkey:12s} {h['frames']:6d} {h['polls']:6d} {h['tx']:5d} {h['acked']:6d} {med:>9s}  {mle}")
    if gaps:
        print("\nsilences (>30 min):")
        for a, b in gaps[-10:]:
            print(f"  {_t.strftime('%m-%d %H:%M', _t.localtime(a))} -> "
                  f"{_t.strftime('%m-%d %H:%M', _t.localtime(b))}  ({round((b-a)/60)} min)")
    if mle_events:
        print("\nrejoin-related MLE (attach attempts):")
        for ts, cmd in mle_events[-10:]:
            print(f"  {_t.strftime('%m-%d %H:%M:%S', _t.localtime(ts))}  {cmd}")
    else:
        print("\nno rejoin-related MLE seen from this device in the window.")
    print_history(cfg.events_dir, addrs)
