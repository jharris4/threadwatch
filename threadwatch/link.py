"""Slow link degradation: a device the sniffer hears steadily weaker.

The quiet detector fires when a device stops being heard; this one fires
before that, while it is still talking but its signal at the sniffer has
sunk well below what is normal for it. That is what a moved or obstructed
device, a failing antenna, or new interference near it looks like from the
recorder's chair, and it is the "slow link degradation" case that ends in a
silence with no rejoin attempt.

Each last-seen row already carries an RSSI average (names.LastSeen.touch,
a per-frame EWMA). This module keeps a daily *reference* level beside it
and judges the average against the reference:

  rssi_ref, rssi_ref_ts   the reference and when it was taken; refreshed
                          once a day so a slow drift (sniffer moved, a
                          door now kept shut) becomes the new normal;
  rssi_low_since          when the average first sat more than drop_db
                          below the reference (cleared once it climbs back
                          within half that, so a flicker at the threshold
                          does not restart the clock);
  rssi_degraded           set once the drop has held hold_s and been
                          announced, cleared by the recovery event or by
                          the daily refresh (a drop that persists a day is
                          the new normal, and further drops measure from
                          there). Either way the clearing is reported as a
                          recovery, so an announced drop is always closed.

The reference is only taken once a device has been heard enough for its
average to have settled.
"""

from __future__ import annotations

from typing import Optional

DAY_S = 86400.0
WARMUP_FRAMES = 200


def assess(row: dict, now: float, drop_db: float, hold_s: float) -> Optional[str]:
    """Update one last-seen row's link bookkeeping. Returns "degraded" the
    moment a drop has held long enough to announce, "recovered" when an
    announced drop has ended (the signal came back, or the daily refresh
    made the lower level the new reference), else None. A drop_db of zero
    disables it."""
    rssi = row.get("rssi")
    if rssi is None or drop_db <= 0 or row.get("frames", 0) < WARMUP_FRAMES:
        return None
    ref = row.get("rssi_ref")
    if ref is None:
        row["rssi_ref"], row["rssi_ref_ts"] = rssi, now
        return None
    result = None
    if rssi <= ref - drop_db:
        row.setdefault("rssi_low_since", now)
        if not row.get("rssi_degraded") and now - row["rssi_low_since"] >= hold_s:
            row["rssi_degraded"] = True
            result = "degraded"
    elif rssi >= ref - drop_db / 2:
        row.pop("rssi_low_since", None)
        if row.pop("rssi_degraded", None):
            result = "recovered"
    # Between the two thresholds: nothing changes; the clock keeps running.
    low_since = row.get("rssi_low_since")
    if now - row.get("rssi_ref_ts", now) >= DAY_S and (low_since is None or now - low_since >= DAY_S):
        row["rssi_ref"], row["rssi_ref_ts"] = rssi, now
        row.pop("rssi_low_since", None)
        if row.pop("rssi_degraded", None):
            # The announced drop is now the normal level. Report it closed,
            # or the review would carry it as "still down" forever while
            # the device page says the device is fine.
            result = "recovered"
    return result
