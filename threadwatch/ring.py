"""Ring file names: one pcap per local hour, per radio.

The recorder writes ``threadwatch-YYYYMMDD-HH.pcap`` for its primary radio,
as it always has, and ``threadwatch-YYYYMMDD-HH-<label>.pcap`` for every
other radio in ``[record] radios``: one series of files per radio, each a
plain pcap of what that radio heard, with its own reception in the TAP
header. A single-dongle install writes only the unlabelled series and
nothing about its files changes.

A label suffix sorts before ``.pcap`` (``-`` is 0x2d, ``.`` is 0x2e), so a
sorted listing keeps an hour's files together, but never in a fixed order
inside the hour: everything that reads the ring groups by the hour these
helpers parse out of the name, not by position in the listing.
"""

from __future__ import annotations

import re
from pathlib import Path

LABEL_RE = re.compile(r"^[a-z0-9_]{1,16}$")
RING_RE = re.compile(r"^threadwatch-(\d{8}-\d{2})(?:-([a-z0-9_]{1,16}))?\.pcap$")
HOUR_FORMAT = "%Y%m%d-%H"


def ring_name(hour: str, label: str | None = None) -> str:
    """The file for a local hour (``YYYYMMDD-HH``), for one radio's series."""
    return f"threadwatch-{hour}.pcap" if label is None else f"threadwatch-{hour}-{label}.pcap"


def parse_ring_name(name: str) -> tuple[str, str | None] | None:
    """(hour, label) of a ring file name, None for a name that is not one.
    The label is None for the primary series."""
    m = RING_RE.match(name)
    return (m.group(1), m.group(2)) if m else None


def ring_files(ring_dir: Path, label: str | None = None) -> list[Path]:
    """One radio's series, sorted by hour. Only names of that series: the
    primary's glob must not take another radio's hours for its own, or
    the count cap prunes them as if they were."""
    if not ring_dir.exists():
        return []
    out = []
    for p in ring_dir.iterdir():
        parsed = parse_ring_name(p.name)
        if parsed and parsed[1] == label:
            out.append((parsed[0], p))
    return [p for _, p in sorted(out)]


def ring_hours(ring_dir: Path) -> list[tuple[str, dict[str | None, Path]]]:
    """Every hour on disk with the file each radio wrote for it, oldest
    first: ``[(hour, {label: path, ...}), ...]``. An hour one radio did not
    write (it was down, or not yet plugged in) has no entry for it."""
    hours: dict[str, dict[str | None, Path]] = {}
    if ring_dir.exists():
        for p in ring_dir.iterdir():
            parsed = parse_ring_name(p.name)
            if parsed:
                hours.setdefault(parsed[0], {})[parsed[1]] = p
    return sorted(hours.items())


def ring_labels(ring_dir: Path) -> list[str | None]:
    """The series present on disk, the primary (None) first."""
    seen = {label for _, files in ring_hours(ring_dir) for label in files}
    return sorted(seen, key=lambda label: (label is not None, label or ""))


def group_files(paths: list[Path]) -> list[dict[str | None, Path]]:
    """Given files (a ring, a snapshot, or files named by hand), the hour
    groups to read together, in order: ring-named files grouped by hour and
    series, and any other file as a group of its own in the order given,
    so a capture from elsewhere reads exactly as it did."""
    groups: list[tuple[tuple, dict[str | None, Path]]] = []
    by_hour: dict[str, dict[str | None, Path]] = {}
    for i, p in enumerate(paths):
        parsed = parse_ring_name(p.name)
        if parsed is None:
            groups.append(((1, i), {None: p}))
            continue
        hour, label = parsed
        if hour not in by_hour:
            by_hour[hour] = {}
            groups.append(((0, hour), by_hour[hour]))
        by_hour[hour][label] = p
    # Ring-named files sort by hour among themselves and keep their place
    # relative to the plain files only when every file is ring-named;
    # a mixed list (rare: a snapshot plus a stray capture) reads the
    # ring hours first, then the others as given.
    return [files for _, files in sorted(groups, key=lambda g: g[0])]
