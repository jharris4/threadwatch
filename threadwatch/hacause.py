"""Why Home Assistant lost a Thread device, from the recorder's radio
evidence: one pure function, so the reasoning is tested on its own and
the availability poller only asks.

Home Assistant's "unavailable" is the outage a person notices; the
recorder holds what explains it. A last-seen row carries the device's
key generation (counter_seq, judged against its parent's), whether its
polls are unanswered (starved), when it was last heard and whether that
silence was announced (quiet_reported), and how well the sniffer hears
it. First match wins, in the order of the table in docs/ALERTING.md.
"""

from __future__ import annotations

import time

from .names import newest_generation, reception

# A frame within this long counts as the radio being fine right now.
RADIO_OK_S = 5 * 60
# A last frame this long before HA lost the device is the radio going
# first: the device died, lost power or left the mesh.
SILENT_BEFORE_S = 120.0

# frame_counter_mismatch is said again once an hour while the device keeps
# sending below its advertisement; a stamp older than this is a past episode.
MISMATCH_FRESH_S = 2 * 3600.0

SENTENCES = {
    "key_lag": ("Cut off by a key change: radio alive on generation {generation}, parent on {parent}. "
                "A battery pull or power cycle forces a rejoin."),
    "counter_mismatch": "Advertised a frame counter above the ones it sends with: its parent "
                        "drops everything it sends as stale (frame_counter_mismatch).",
    "dropped_polls": "Its polls are acknowledged with data pending and nothing follows: the "
                     "parent's stack is dropping them (poll_unserved).",
    "lost_parent": "Still polling its parent with no answer: parent gone or link broken.",
    "silent": "Radio went silent at {when}: device died, lost power or left the mesh.",
    "radio_ok": "Radio and key look fine: likely the Matter, IP or HA side. Check the Matter Server log.",
    "unheard": "The sniffer cannot hear this device; cause unknown from here.",
}


def classify(row: dict | None, parent_row: dict | None, episode_since: float, now: float, *,
             fresh_s: float = 30 * 60, min_rssi_dbm: float = -82.0) -> tuple[str, str]:
    """(cause, sentence) for a device HA marked unavailable at
    ``episode_since``, from its last-seen row and its parent's. A device
    with an open key-lag episode (the recorder's own judgement) is
    key_lag before anything else; otherwise a fresh generation reading
    two or more below the parent's says the same. Then starvation, then
    a silence that began before HA lost the device, then a radio heard
    in the last five minutes, and finally: the sniffer cannot say."""
    if not row:
        return "unheard", SENTENCES["unheard"]
    gens = row.get("keylag_gens")
    if row.get("keylag_since") is not None and isinstance(gens, list) and len(gens) == 2:
        return "key_lag", SENTENCES["key_lag"].format(generation=gens[0], parent=gens[1])
    generation, gen_ts = newest_generation(row)
    parent_gen, parent_ts = newest_generation(parent_row) if parent_row else (None, None)
    if (generation is not None and gen_ts is not None and now - gen_ts <= fresh_s
            and parent_ts is not None and 0 <= now - parent_ts <= fresh_s
            and parent_gen is not None and parent_gen >= generation + 2):
        return "key_lag", SENTENCES["key_lag"].format(generation=generation, parent=parent_gen)
    mismatch = row.get("counter_mismatch_ts")
    if (isinstance(mismatch, (int, float)) and not isinstance(mismatch, bool)
            and 0 <= now - mismatch <= MISMATCH_FRESH_S):
        return "counter_mismatch", SENTENCES["counter_mismatch"]
    if row.get("unserved"):
        return "dropped_polls", SENTENCES["dropped_polls"]
    if row.get("starved"):
        return "lost_parent", SENTENCES["lost_parent"]
    last = row.get("last_seen")
    heard = isinstance(last, (int, float)) and not isinstance(last, bool)
    if heard and last < episode_since - SILENT_BEFORE_S and row.get("quiet_reported"):
        return "silent", SENTENCES["silent"].format(when=time.strftime("%H:%M", time.localtime(last)))
    if heard and now - last <= RADIO_OK_S:
        return "radio_ok", SENTENCES["radio_ok"]
    marginal = reception(row.get("rssi"), min_rssi_dbm) == "marginal"
    if not heard or marginal:
        return "unheard", SENTENCES["unheard"]
    # Heard, but not in the last five minutes and not announced quiet:
    # a silence too young to judge. The sniffer cannot say yet.
    return "unheard", SENTENCES["unheard"]
