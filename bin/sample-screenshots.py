#!/usr/bin/env python3
"""The README's screenshots of the review pages, from a made-up household.

    .venv/bin/python bin/sample-screenshots.py

Writes fake state files to a temporary directory, renders the real pages with
web.Site, and photographs the HTML with headless Chrome into docs/images. The
pages publish a household's device inventory, so screenshots of a live server
do not belong in a public repository; these come from nothing on this machine.
The day, the clock, the time zone and the random seed are all fixed, so a
second run differs only where the pages themselves have changed.

Before writing an image the rendered pages are compared with the local
config/ (when there is one), and any real name, address, model, channel or
PAN found in them stops the run. The colours follow the system's light or
dark setting, which is the one thing here that is not fixed.
"""

import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from threadwatch.config import Config  # noqa: E402
from threadwatch.web import Site  # noqa: E402

DAY = "2026-11-03"
PAN, FOREIGN_PAN, CHANNEL = 0x7c3e, 0x51d9, 20
GEN = 42
OUT = REPO / "docs" / "images"
PAGES = {"today": "/", "devices": "/devices"}
rng = random.Random(20261103)

# The pages print local times, and a run must not depend on (or show) where it ran.
os.environ["TZ"] = "UTC"
time.tzset()


def at(hhmm: str, day_offset: int = 0) -> float:
    base = time.mktime(time.strptime(f"{DAY} {hhmm}", "%Y-%m-%d %H:%M"))
    return base + day_offset * 86400


NOW = at("17:42") + 18
time.time = lambda: NOW     # every page asks time.time(); it is always this moment


def addr() -> str:
    return f"{rng.getrandbits(64):016x}"


def rloc(router: int, child: int = 0) -> str:
    return f"{(router << 10) | child:04x}"


# name, model, router id, generation, rssi, frames a day
ROUTERS = [
    ("Loft Hub", "Streaming Box", 8, GEN, -48, 412_000),
    ("Study Hub", "Border Router", 21, GEN, -55, 388_000),
    ("Attic Air Monitor", "Air Monitor", 5, GEN, -71, 96_400),
    ("Sunroom Air Monitor", "Air Monitor", 12, GEN, -63, 104_800),
    ("Library Plug", "Smart Plug", 33, GEN, -58, 151_200),
    ("Pantry Plug", "Smart Plug", 47, GEN, -66, 132_900),
    ("Workshop Plug", "Smart Plug", 56, GEN, -79, 88_300),
]
# name, model, parent's router id, child id, generation, rssi, frames a day
CHILDREN = [
    ("Side Gate Lock", "Door Lock", 56, 1, GEN, -77, 18_400),
    ("Library Smoke Alarm", "Smoke Alarm", 33, 2, GEN, -69, 6_120),
    ("Guest Room Climate", "Climate Sensor", 5, 3, GEN - 2, -74, 9_310),
    ("Hall Remote", "Remote", 21, 4, GEN - 1, -64, 3_250),
    ("Loft Thermostat", "Thermostat", 8, 5, GEN, -52, 21_700),
    ("Pantry Leak Sensor", "Leak Sensor", 47, 6, GEN, -72, 4_480),
    ("Terrace Motion Sensor", "Motion Sensor", 56, 7, GEN, -85, 7_940),
    ("Shed Door Sensor", "Door Sensor", 56, 8, GEN, -88, 2_210),
    ("Study Window Sensor", "Door Sensor", 21, 9, GEN, -60, 3_870),
    ("Sunroom Blind", "Blind", 12, 10, GEN, -67, 5_560),
]
DEVICES = ROUTERS + CHILDREN

ADDR = {row[0]: addr() for row in DEVICES}
VISITOR, UNKNOWN, NEIGHBOUR = addr(), addr(), addr()
TRACKED_DAYS = 19


def table_row(frames: int, rssi: int, last_seen: float, generation: int = GEN, **extra) -> dict:
    return {"first_seen": NOW - TRACKED_DAYS * 86400 - rng.randint(0, 40000), "last_seen": last_seen,
            "frames": frames, "types": {"1": frames}, "rssi": rssi, "pan": PAN,
            "counter_seq": generation, "counter_ts": last_seen,
            "rloc16_ts": last_seen - rng.randint(0, 40), **extra}


def last_seen_table() -> dict:
    """One radio, the default install: a second adds a "heard by" column that
    triples the height of every row. A row's frames are cumulative."""
    table = {}
    for name, _model, router, gen, rssi, frames in ROUTERS:
        table[ADDR[name]] = table_row(frames * TRACKED_DAYS, rssi, NOW - rng.randint(1, 25), gen, rloc16=rloc(router))
    for name, _model, router, child, gen, rssi, frames in CHILDREN:
        table[ADDR[name]] = table_row(frames * TRACKED_DAYS, rssi, NOW - rng.randint(5, 280), gen,
                                      rloc16=rloc(router, child))
    # Where the day's events (day_events) have left things.
    table[ADDR["Guest Room Climate"]]["keylag_since"] = at("09:06")
    table[ADDR["Workshop Plug"]].update(rssi_degraded=True, rssi_ref=-66)
    table[ADDR["Shed Door Sensor"]].update(quiet_reported=True, last_seen=at("15:58"), counter_ts=at("15:58"),
                                           rloc16_ts=at("15:58"))
    table[VISITOR] = table_row(14_380, -61, NOW - 42, rloc16=rloc(12, 11), heard_since=at("16:02"))
    table[VISITOR]["first_seen"] = at("16:02")
    table[UNKNOWN] = table_row(212, -83, NOW - 610, rloc16=rloc(47, 12))
    table[UNKNOWN]["first_seen"] = at("15:31")
    table[NEIGHBOUR] = table_row(1_904, -91, NOW - 95, pan=FOREIGN_PAN)
    del table[NEIGHBOUR]["counter_seq"], table[NEIGHBOUR]["counter_ts"]
    return table


def named(name: str) -> dict:
    return {"addr": ADDR[name], "name": name}


def day_events() -> list[tuple]:
    """The sample day, with the severities and wording the recorder uses. The
    key change comes after the 08:00 summary, which therefore cannot know of it."""
    guest, hall, shed, terrace, gate = ("Guest Room Climate", "Hall Remote", "Shed Door Sensor",
                                        "Terrace Motion Sensor", "Side Gate Lock")
    last_visit = at("19:20", -9)
    origin = {**named("Sunroom Blind"), "evidence": "ahead of its parent"}
    return [
        ("parent_check", "info", at("02:17"), {
            **named("Sunroom Blind"), "margins": {"Sunroom Air Monitor": 31, "Pantry Plug": 18},
            "note": "Sunroom Blind looked for a better parent and stayed."}),
        ("device_quiet", "notice", at("03:41"), {**named(terrace), "reception": "marginal", "last_seen": at("03:11")}),
        ("device_returned", "notice", at("03:58"), named(terrace)),
        ("device_rebooted", "info", at("06:12"), {
            **named("Loft Thermostat"), "node_id": 14, "reason_name": "software update completed"}),
        ("daily_summary", "info", at("08:00"), {}),     # the note needs the records: write_events
        ("key_sequence_advanced", "info", at("08:52"), {
            "sequence": GEN, "previous": GEN - 1, "first_sender": ADDR["Sunroom Blind"], **named("Sunroom Blind"),
            "frame": "mac_poll", "since_previous_s": 28 * 86400 + 2 * 3600,
            "suspects": [{**origin, "parent": "Sunroom Air Monitor", "parent_generation": GEN - 1}]}),
        ("key_lag", "warning", at("09:06"), {
            **named(guest), "role": "child", "generation": GEN - 2, "parent": "Attic Air Monitor",
            "parent_addr": ADDR["Attic Air Monitor"], "parent_generation": GEN, "lag": 2, "since": at("09:06")}),
        ("key_lag_census", "info", at("09:07"), {
            "sequence": GEN, "counts": {str(GEN): 15, str(GEN - 1): 1, str(GEN - 2): 1},
            "behind_parent_1": [named(hall)], "behind_parent_2plus": [named(guest)], "suspects": [origin]}),
        ("recorder_started", "info", at("10:14") + 5, {
            "cause": "stopped", "gap_s": 185, "last_frame_ts": at("10:11"), "stopped_ts": at("10:11") + 2,
            "note": "not listening for 3 min since the last frame at 10:11; the recorder was stopped"}),
        ("rssi_degradation", "notice", at("11:26"), {
            **named("Workshop Plug"), "drop_db": 13, "rssi_dbm": -79, "reference_dbm": -66, "since": at("11:26")}),
        ("poll_starvation", "warning", at("12:39"), {
            **named(hall), "unanswered_polls": 24, "acked_polls": 1180, "since": at("12:39")}),
        ("poll_answered", "notice", at("12:51"), {**named(hall), "note": "its polls are acknowledged again"}),
        ("srp_refused", "warning", at("13:08"), {
            **named(gate), "refusals": 6, "rcode_name": "SERVFAIL", "refused_for_s": 620, "since": at("12:58")}),
        ("srp_accepted", "info", at("13:44"), {**named(gate), "refusals": 6, "refused_for_s": 2760,
                                               "since": at("12:58")}),
        ("device_first_seen", "info", at("15:31"), {"addr": UNKNOWN, "name": None}),
        ("visitor_returned", "info", at("16:02"), {
            "addr": VISITOR, "name": "Guest Phone", "visit": 6, "last_visit": last_visit,
            "note": "an address that has visited 5 times before, last "
                    + time.strftime("%Y-%m-%d %H:%M", time.localtime(last_visit))}),
        ("device_quiet", "notice", at("16:28"), {**named(shed), "reception": "marginal", "last_seen": at("15:58")}),
        ("ha_unavailable", "warning", at("16:31"), {
            **named(shed), "ha_device_id": "ha-shed", "cause": "silent", "since": at("16:31")}),
    ]


def earlier_day_events(offset: int) -> list[tuple]:
    """Enough closed episodes for the strip of days to look lived in."""
    out = []
    names = [row[0] for row in CHILDREN]
    for _ in range(rng.randint(3, 11)):
        ts = at(f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}", offset)
        name = rng.choice(names)
        out.append(("parent_check", "info", ts, {**named(name),
                                                 "note": f"{name} looked for a better parent and stayed."}))
    for _ in range(rng.choice((0, 0, 1, 1, 2, 4))):
        ts = at(f"{rng.randint(1, 21):02d}:{rng.randint(0, 59):02d}", offset)
        name = rng.choice(names)
        out.append(("device_quiet", "warning", ts, {**named(name), "last_seen": ts - 1800}))
        out.append(("device_returned", "notice", ts + rng.randint(300, 4000), named(name)))
    return out


def write_events(events_dir: Path) -> None:
    events_dir.mkdir(parents=True)
    days = {offset: earlier_day_events(offset) for offset in range(-20, 0)}
    days[-20].append(("recorder_started", "info", at("00:00", -20), {"cause": "first_start", "note": "first run"}))
    days[0] = day_events()
    summary = next(r for r in days[0] if r[0] == "daily_summary")
    counts = {"warning": 0, "notice": 0}
    for _event, severity, ts, _fields in days[-1] + days[0]:
        if summary[2] - 86400 <= ts < summary[2] and severity in counts:
            counts[severity] += 1
    summary[3]["note"] = ("last 24 h: 1,512,880 frames from 17 of 17 devices; nothing quiet; 2 heard marginally; "
                          f"keys: 16 on {GEN - 1}, 1 on {GEN - 2}; 1 one behind their parent; events: "
                          + ", ".join(f"{n} {severity}" for severity, n in counts.items() if n))
    for offset, records in days.items():
        lines = [json.dumps({"ts": ts, "event": event, "severity": severity, **fields, "id": f"s{offset}-{i}"})
                 for i, (event, severity, ts, fields) in enumerate(sorted(records, key=lambda r: r[2]))]
        day = time.strftime("%Y-%m-%d", time.localtime(at("12:00", offset)))
        (events_dir / f"{day}.jsonl").write_text("\n".join(lines) + "\n")


def write_fixture(root: Path) -> Config:
    state, conf, ring = root / "data" / "state", root / "config", root / "data" / "ring"
    for directory in (state, conf, ring, root / "data" / "snapshots"):
        directory.mkdir(parents=True)
    stamp = DAY.replace("-", "")
    for hour in range(18):
        (ring / f"threadwatch-{stamp}-{hour:02d}0000.pcap").touch()

    (conf / "devices.json").write_text(json.dumps(
        [{"name": row[0], "extendedAddress": ADDR[row[0]].upper(), "model": row[1]} for row in DEVICES]))
    (conf / "visitors.json").write_text(json.dumps([{"name": "Guest Phone", "extendedAddress": VISITOR.upper()}]))
    (state / "last-seen.json").write_text(json.dumps(last_seen_table()))
    (state / "visits.json").write_text(json.dumps({VISITOR: {
        "visits": 5, "first_visit": at("18:00", -17), "last_visit": at("19:20", -9), "last_heard_for_s": 7400}}))
    # This run's frames: 7.5 h of the 1.5 M a day the summary reports.
    (state / "status.json").write_text(json.dumps({
        "updated": NOW - 12, "last_frame_age_s": 0.4, "channel": CHANNEL, "dominant_pan": PAN,
        "frames_total": 468_219, "devices_tracked": 20, "uptime_s": 7 * 3600 + 28 * 60,
        "crypto": {"mac_decrypted": 452_806, "key_sequence": GEN},
        "partition": {"leader_router": 8, "partition": 118_204_337}}))
    (state / "border-routers.json").write_text(json.dumps({
        f"{name.split()[0].lower()}-hub.local": {"addr": ADDR[name], "name": name, "instance": name,
                                                 "vendor": "Acme", "model": "BorderRouter"}
        for name in ("Loft Hub", "Study Hub")}))
    (state / "ha-map.json").write_text(json.dumps({
        "ha-shed" if row[0] == "Shed Door Sensor" else f"ha-{i}":
            {"addr": ADDR[row[0]], "name": row[0], "entities": ["sensor.sample"]}
        for i, row in enumerate(DEVICES)}))
    (state / "ha-availability.json").write_text(json.dumps({
        "episodes": {"ha-shed": {"since": at("16:31"), "paged": True, "burst_id": None}}}))
    write_events(state / "events")
    return Config(data_dir=root / "data", devices_path=conf / "devices.json", visitors_path=conf / "visitors.json",
                  config_dir=conf, ha_availability_enabled=True)


def real_identifiers() -> dict[str, set[str]]:
    """What must not appear in a screenshot: this machine's own inventory."""
    found: dict[str, set[str]] = {"name": set(), "address": set(), "model": set()}
    for file in ("devices.json", "visitors.json"):
        try:
            entries = json.loads((REPO / "config" / file).read_text())
        except FileNotFoundError:
            continue
        for entry in entries:
            found["name"].add(entry["name"].lower())
            if entry.get("model"):
                found["model"].add(entry["model"].lower())
            for a in [entry.get("extendedAddress"), *(entry.get("extendedAddresses") or [])]:
                if a:
                    found["address"].add(a.lower().replace(":", ""))
    return found


def leaks(pages: dict[str, bytes]) -> list[str]:
    """The real identifiers found in the rendered pages; a sample name that
    is part of a real one counts too, since it would still describe that device."""
    real = real_identifiers()
    # The stylesheet is the same on every install, and full of short words.
    text = {name: re.sub(r"<style>.*?</style>", "", body.decode(), flags=re.S).lower() for name, body in pages.items()}
    out = [f"{name}: a real {kind}: {value if kind != 'address' else value[:4] + '...'}"
           for name, body in text.items() for kind, values in real.items() for value in values if value in body]
    samples = [row[0].lower() for row in DEVICES] + ["guest phone"]
    out += [f"sample name {sample!r} is part of a real name" for sample in samples
            if any(sample in value for value in real["name"])]
    out += [f"{name}: the home directory" for name, body in text.items() if str(Path.home()).lower() in body]
    try:
        network = tomllib.loads((REPO / "config" / "config.toml").read_text()).get("network") or {}
    except FileNotFoundError:
        network = {}
    for key, sample in (("channel", CHANNEL), ("pan_id", PAN)):
        value = network.get(key)
        if (int(value, 16) if isinstance(value, str) else value) == sample:
            out.append(f"the sample {key} is the real one")
    return out


def find_chrome() -> str:
    candidates = [os.environ.get("CHROME"), "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                  *map(shutil.which, ("google-chrome", "chromium", "chromium-browser"))]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    sys.exit("no Chrome or Chromium found: set CHROME to its path")


def main() -> None:
    browser = find_chrome()
    with tempfile.TemporaryDirectory(prefix="threadwatch-samples-") as tmp:
        root = Path(tmp)
        site = Site(write_fixture(root / "fixture"))

        def chrome(*args: str) -> str:
            return subprocess.run([browser, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--no-first-run",
                                   f"--user-data-dir={root / 'chrome'}", *args],
                                  check=True, capture_output=True, text=True, timeout=60).stdout

        pages = {}
        for name, path in PAGES.items():
            status, _ctype, pages[name] = site.respond(path)
            if status != 200:
                sys.exit(f"{path}: HTTP {status}")
        problems = leaks(pages)
        if problems:
            sys.exit("not writing screenshots, the sample pages show real details:\n  " + "\n  ".join(problems))

        OUT.mkdir(parents=True, exist_ok=True)
        for name, body in pages.items():
            page = root / f"{name}.html"
            page.write_bytes(body)
            # Chrome has no full-page flag: ask the page how tall it is first.
            probe = root / f"{name}-probe.html"
            probe.write_bytes(body + b"<script>document.body.dataset.h=document.documentElement.scrollHeight</script>")
            height = re.search(r'data-h="(\d+)"', chrome("--window-size=1280,600", "--dump-dom", probe.as_uri()))[1]
            image = OUT / f"threadwatch-{name}.png"
            chrome("--force-device-scale-factor=2", f"--window-size=1280,{height}", f"--screenshot={image}",
                   page.as_uri())
            print(image.relative_to(REPO))


if __name__ == "__main__":
    main()
