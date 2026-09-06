"""Storm detection: traffic-flood windows and phase-lock periodicity.

Tuned from the 2026-09-01 incident: calm mesh ~250 frames/10 s, storm
floods 1,200-2,000 frames/10 s recurring every ~80.5 s. Detection is
relative to a rolling baseline so it adapts to mesh size.
"""

from __future__ import annotations

import statistics
from collections import deque
from dataclasses import dataclass, field


@dataclass
class DetectorConfig:
    window_seconds: int = 10
    baseline_windows: int = 90        # ~15 min of history for the baseline
    flood_multiplier: float = 3.0     # window is a flood at N x baseline...
    flood_min_frames: int = 400       # ...but never below this absolute floor
    period_min_s: float = 40.0        # phase-lock signature bounds
    period_max_s: float = 180.0
    period_onsets: int = 3            # consecutive periodic onsets to alert
    alert_cooldown_s: float = 1800.0


@dataclass
class Detector:
    cfg: DetectorConfig
    counts: deque = field(default_factory=lambda: deque(maxlen=360))
    calm: deque = field(default_factory=lambda: deque(maxlen=360))   # windows outside storms: the baseline
    last_flood: float = 0.0
    window_start: float = 0.0
    window_count: int = 0
    in_flood: bool = False
    onsets: deque = field(default_factory=lambda: deque(maxlen=32))
    last_alert: float | None = None      # frame time of the last counted alert
    alerts_sent: int = 0
    storm_active: bool = False
    # The storm as last measured (period, onsets): refreshed at every
    # periodic onset, cooldown or not, so whoever reports the storm
    # describes the one running and never an earlier one.
    storm_details: dict = field(default_factory=dict)

    def add_frame(self, ts: float) -> None:
        w = self.cfg.window_seconds
        if self.window_start == 0.0:
            self.window_start = ts
        if self.window_start - ts >= w:
            # Time went backwards by a window or more: the clock was stepped
            # back, or the record before this one carried a corrupt future
            # stamp and the window clock followed it. Left there, every
            # frame from now on would land "before" the open window and no
            # window would ever close again. Start the window clock over at
            # this frame; the frames counted so far in a window that spans
            # a discontinuity are not worth judging.
            #
            # The storm state goes with it. The only way out of a storm is
            # window_start - last_flood > 3 * period_max_s, which stays
            # negative for the whole length of the step while last_flood
            # sits on the pre-step clock: the storm could never end, and
            # _close_window stopped feeding calm, so the flood baseline
            # froze too. The onsets and the alert stamp are on the old
            # clock as well, and none of that history is comparable with
            # what follows.
            self.window_start, self.window_count = ts, 0
            self.last_flood, self.in_flood, self.storm_active = 0.0, False, False
            self.storm_details = {}
            self.onsets.clear()
            self.last_alert = None
        if ts - self.window_start >= w:
            self._close_window()                  # the window that had the frames
            self.window_start += w
            # Every window from here to ts is empty, and once the history is
            # full of empty ones another changes nothing: skip straight to
            # the last history's worth of them. A replayed file with a
            # corrupt timestamp, or a host clock stepped from 1970 to now,
            # is otherwise a step per ten seconds, minutes of spinning.
            empties = int((ts - self.window_start) // w)
            if empties > self.counts.maxlen:
                self.window_start += (empties - self.counts.maxlen) * w
            while ts - self.window_start >= w:
                self._close_window()
                self.window_start += w
        self.window_count += 1

    def _baseline(self) -> float:
        # Windows seen during a storm are left out: a storm whose bursts
        # merge into a continuous flood would otherwise become the new
        # normal within the baseline span and stop looking like a flood.
        history = [c for c in self.calm][-self.cfg.baseline_windows:]
        calm = sorted(history)[: max(1, len(history) * 3 // 4)]  # ignore top quartile (floods)
        return statistics.median(calm) if calm else 0.0

    def _close_window(self) -> None:
        count = self.window_count
        self.window_count = 0
        base = self._baseline()
        threshold = max(self.cfg.flood_min_frames, base * self.cfg.flood_multiplier)
        flood = count >= threshold and len(self.counts) >= 6
        if flood and not self.in_flood:
            self.onsets.append(self.window_start)
            self._check_periodicity()
        if flood:
            self.last_flood = self.window_start
        # A storm is over once flooding has stopped for 3 periods.
        if self.storm_active and self.window_start - self.last_flood > 3 * self.cfg.period_max_s:
            self.storm_active = False
        self.in_flood = flood
        self.counts.append(count)
        if not self.storm_active:
            self.calm.append(count)

    def _check_periodicity(self) -> None:
        need = max(2, self.cfg.period_onsets)   # a period needs two onsets to measure
        if len(self.onsets) < need:
            return
        recent = list(self.onsets)[-need:]
        gaps = [b - a for a, b in zip(recent, recent[1:], strict=False)]
        if all(self.cfg.period_min_s <= g <= self.cfg.period_max_s for g in gaps):
            mean = sum(gaps) / len(gaps)
            spread = max(gaps) - min(gaps)
            if spread <= 0.25 * mean:
                self.storm_active = True
                self.storm_details = {"period": mean, "onsets": [round(t, 1) for t in recent]}
                self._alert(self.window_start)
        # An off-period onset (an unrelated burst during a storm) does not
        # end the storm; _close_window clears it after three missed periods.

    def _alert(self, now: float) -> None:
        # Bookkeeping only. Notification is the Pipeline's job: it emits a
        # `phase_locked_storm` event, and the EventLog owns webhook dispatch.
        # (Printing or webhooking here would double-alert and pollute the
        # stdout of `threadwatch replay`.) The cooldown runs on the frame
        # clock, as the Pipeline's does: on the wall clock a replayed day
        # is one alert, and the two would count different storms.
        if self.last_alert is not None and now - self.last_alert < self.cfg.alert_cooldown_s:
            return
        self.last_alert = now
        self.alerts_sent += 1

    def snapshot(self) -> dict:
        # Called from the status thread while the capture thread appends:
        # a deque copy can raise 'mutated during iteration'; try again.
        for _attempt in range(3):
            try:
                return {
                    "baseline_frames_per_window": round(self._baseline(), 1),
                    "recent_windows": list(self.counts)[-6:],
                    "storm_active": self.storm_active,
                    "flood_onsets_recent": [round(t, 1) for t in list(self.onsets)[-5:]],
                    "alerts_sent": self.alerts_sent,
                }
            except RuntimeError:
                continue
        return {"storm_active": self.storm_active, "alerts_sent": self.alerts_sent}
