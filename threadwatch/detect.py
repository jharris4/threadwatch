"""Storm detection: traffic-flood windows and phase-lock periodicity.

Tuned from the 2026-09-01 incident: calm mesh ~250 frames/10 s, storm
floods 1,200-2,000 frames/10 s recurring every ~80.5 s. Detection is
relative to a rolling baseline so it adapts to mesh size.
"""

from __future__ import annotations

import json
import statistics
import time
import urllib.request
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
    webhook_url: str = ""


@dataclass
class Detector:
    cfg: DetectorConfig
    counts: deque = field(default_factory=lambda: deque(maxlen=360))
    window_start: float = 0.0
    window_count: int = 0
    in_flood: bool = False
    onsets: deque = field(default_factory=lambda: deque(maxlen=32))
    last_alert: float = 0.0
    alerts_sent: int = 0
    storm_active: bool = False

    def add_frame(self, ts: float) -> None:
        if self.window_start == 0.0:
            self.window_start = ts
        while ts - self.window_start >= self.cfg.window_seconds:
            self._close_window()
            self.window_start += self.cfg.window_seconds
        self.window_count += 1

    def _baseline(self) -> float:
        history = [c for c in self.counts][-self.cfg.baseline_windows:]
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
        self.in_flood = flood
        self.counts.append(count)

    def _check_periodicity(self) -> None:
        need = self.cfg.period_onsets
        if len(self.onsets) < need:
            return
        recent = list(self.onsets)[-need:]
        gaps = [b - a for a, b in zip(recent, recent[1:])]
        if all(self.cfg.period_min_s <= g <= self.cfg.period_max_s for g in gaps):
            mean = sum(gaps) / len(gaps)
            spread = max(gaps) - min(gaps)
            if spread <= 0.25 * mean:
                self.storm_active = True
                self._alert(period=mean, onsets=[round(t, 1) for t in recent])
        else:
            self.storm_active = False

    def _alert(self, **details) -> None:
        now = time.time()
        if now - self.last_alert < self.cfg.alert_cooldown_s:
            return
        self.last_alert = now
        self.alerts_sent += 1
        payload = {
            "event": "thread_storm_detected",
            "message": "Phase-locked Thread traffic storm signature detected "
                       f"(periodic floods every ~{details.get('period', 0):.0f}s). "
                       "Known cure: power-cycle the active HomeKit hub Apple TV.",
            **details,
        }
        print(f"[threadwatch] ALERT: {json.dumps(payload)}", flush=True)
        if self.cfg.webhook_url:
            try:
                req = urllib.request.Request(
                    self.cfg.webhook_url,
                    data=json.dumps(payload).encode(),
                    headers={"Content-Type": "application/json"},
                )
                urllib.request.urlopen(req, timeout=10).read()
            except Exception as exc:  # alerting must never kill capture
                print(f"[threadwatch] webhook failed: {exc}", flush=True)

    def snapshot(self) -> dict:
        recent = list(self.counts)[-6:]
        return {
            "baseline_frames_per_window": round(self._baseline(), 1),
            "recent_windows": recent,
            "storm_active": self.storm_active,
            "flood_onsets_recent": [round(t, 1) for t in list(self.onsets)[-5:]],
            "alerts_sent": self.alerts_sent,
        }
