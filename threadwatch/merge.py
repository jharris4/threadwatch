"""One stream from several radios: alignment and deduplication.

Every radio delivers its own copy of what it heard, stamped by its own
clock. The pipeline judges on-air events, so a frame two radios both heard
has to reach it once, with both receptions attached, while a MAC retry of
the same bytes has to reach it twice: it is the retransmission detector's
evidence. Time is what tells the two apart. Two copies of one frame differ
by the radios' clock offset and a few tens of microseconds of jitter; a
retry starts no sooner than the ACK wait, a backoff and a CCA after the
original, 2.4 ms at the least on the mesh this was measured on and never
under 1.5 ms by the standard's constants. So a duplicate is the same psdu
from another radio within a window well under a millisecond *after the
clocks are aligned*, and alignment is the work of this module.

Measured 2026-09-17, one hour, two nRF52840 dongles: offset drift 79 ppm
and stable to under 1 ppm; residual after a linear fit p99 58 us; closest
same-radio repeat of a psdu 2.44 ms. The constants below come from that.

Clocks. Each radio's stamps are linear in its own crystal (the vendored
driver's correct_time keeps the intervals exactly). An Aligner per
non-primary radio tracks that radio's stamp offset against the primary as
d(t) = a + b * (t - t0) in the primary's stamp domain, fed by every pair
of copies it accepts. Locked, it maps the radio's stamps into the
primary's domain to within the jitter, and the recorder then runs the
primary's RadioClock over that one domain, so both ring series share one
epoch mapping. Unlocked (start, or after the radio's stream restarted and
its stamps have a new base), the radio's copies are placed by the epoch
estimate the recorder supplies for it, merged only when the pairing is
unambiguous (one identical psdu, nothing else like it nearby from either
radio), and each such pair is a sample toward a lock.

Release. Copies wait in per-radio queues until every radio still
delivering has delivered past them (plus the window, or the search span
when unlocked), or they have waited hold_s. The oldest is released, the
other radios' queues are searched for its duplicates, and the merged
frame goes out with every copy under ``heard``. Offline (replay, device),
there is no hold: a reader that has ended is not waited for, and stamps
on disk are already aligned.
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import replace
from typing import Callable, Iterator

from .pcap import Frame

W_MIN = 200e-6          # s: duplicate window at best; 3x the measured p99 jitter
W_MAX = 1e-3            # s: and at most; under half the measured retry floor
BUDGET_PPM = 3.0        # window growth per second without a pair, once the rate is measured (~1 ppm)
YOUNG_BUDGET_PPM = 100.0  # ...and until it is: a fresh lock knows the offset, not yet the drift
RATE_BASELINE_S = 30.0  # the offset's slope over at least this long is the rate
RATE_HISTORY_S = 120.0  # ...and at most this long
MISSES_TO_RELOCK = 10   # locked, with a same-psdu copy near but outside the window this often in a row: start over
GAIN = 0.2              # offset correction per pair (the rate term takes the drift)
RATE_CLAMP = 1e-3       # |b| <= 1000 ppm: nothing plausible drifts faster
LOCK_SAMPLES = 3        # unambiguous pairs that must agree before the model is trusted
LOCK_AGREE_S = 1e-3     # ...to within this
SEARCH_S = 0.050        # s: how far an unlocked radio's copy may sit from the primary's
UNLOCK_AFTER_S = 300.0  # s at W_MAX without a pair before the model is dropped
HOLD_S = 0.25           # s: the longest a live copy waits for the other radios
CLAMP_S = 0.5           # s: a backwards step smaller than this is a correction, not a restart


class Aligner:
    """One radio's stamps against the primary's: d(t) = a + b * (t - t0),
    t in the primary's domain, d = other - primary."""

    def __init__(self):
        self.reset()

    def reset(self) -> None:
        self.locked = False
        self.a = self.b = 0.0
        self.t0: float | None = None
        self.t_last: float | None = None      # primary stamp of the last accepted pair
        self.sigma = W_MIN / 3                # running mean |innovation|
        self.rate_known = False
        self.misses = 0
        self.pairs = getattr(self, "pairs", 0)
        self.locks = getattr(self, "locks", 0)
        self._samples: list[tuple[float, float]] = []
        self._hist: deque = deque()           # (t_primary, a) every few seconds, for the rate

    def predict(self, t_primary: float) -> float:
        return self.a + self.b * (t_primary - (self.t0 or t_primary))

    def window(self, t_primary: float) -> float:
        """How far a copy may sit from the prediction and still be the same
        frame: W_MIN or 3 sigma, widened by the rate's uncertainty for the
        time since the last pair, never past W_MAX. SEARCH_S unlocked."""
        if not self.locked:
            return SEARCH_S
        idle = max(0.0, t_primary - (self.t_last if self.t_last is not None else t_primary))
        budget = BUDGET_PPM if self.rate_known else YOUNG_BUDGET_PPM
        return min(W_MAX, max(W_MIN, 3 * self.sigma) + budget * 1e-6 * idle)

    def stale(self, t_primary: float) -> bool:
        """Locked for so long without a pair that the model should go."""
        return (self.locked and self.t_last is not None
                and t_primary - self.t_last > UNLOCK_AFTER_S + (W_MAX - W_MIN) / (BUDGET_PPM * 1e-6))

    def to_primary(self, t_other: float) -> float:
        """The primary-domain stamp of a copy this radio stamped t_other
        (exact inverse of predict, not the first-order one: at 80 ppm and
        a 0.3 s offset the first-order error is 24 us, half the jitter)."""
        t0 = self.t0 if self.t0 is not None else t_other
        return (t_other - self.a + self.b * t0) / (1.0 + self.b)

    def observe(self, t_primary: float, t_other: float) -> None:
        """Take a pair of copies of one frame."""
        d = t_other - t_primary
        self.pairs += 1
        if not self.locked:
            self._samples.append((t_primary, d))
            self._samples = self._samples[-LOCK_SAMPLES:]
            if len(self._samples) == LOCK_SAMPLES and max(s[1] for s in self._samples) - \
                    min(s[1] for s in self._samples) <= LOCK_AGREE_S:
                last = self._samples[-1]
                self.t0, self.a = last[0], last[1]
                self.b = 0.0                  # the rate comes from the offset's slope, below
                self.t_last = last[0]
                self.locked = True
                self.locks += 1
                self._samples = []
                self._hist.append((self.t0, self.a))
            return
        e = d - self.predict(t_primary)
        self.a = self.predict(t_primary) + GAIN * e
        self.t0 = t_primary
        self.sigma = 0.95 * self.sigma + 0.05 * abs(e)
        self.t_last = t_primary
        self.misses = 0
        # The rate: the slope of the tracked offset over a baseline of
        # RATE_BASELINE_S to RATE_HISTORY_S. The offset follows the drift
        # through its own gain whatever b says; b only has to predict
        # across the gaps between pairs, and a 60 s baseline gave it to
        # under a ppm on the bench.
        if t_primary - self._hist[-1][0] >= 5.0:
            self._hist.append((t_primary, self.a))
            while len(self._hist) > 1 and t_primary - self._hist[0][0] > RATE_HISTORY_S:
                self._hist.popleft()
            t_old, a_old = self._hist[0]
            if t_primary - t_old >= RATE_BASELINE_S:
                self.b = max(-RATE_CLAMP, min(RATE_CLAMP, (self.a - a_old) / (t_primary - t_old)))
                self.rate_known = True

    def missed(self) -> None:
        """A same-psdu copy sat near but outside the window: once is a
        retry, MISSES_TO_RELOCK in a row is a model that no longer fits
        (a radio's stream restarted without a backwards stamp, say)."""
        self.misses += 1
        if self.misses >= MISSES_TO_RELOCK:
            self.reset()

    def status(self) -> dict:
        return {"locked": self.locked, "offset_ms": round(self.a * 1e3, 3) if self.locked else None,
                "ppm": round(self.b * 1e6, 2) if self.locked and self.rate_known else None,
                "sigma_us": round(self.sigma * 1e6, 1) if self.locked else None,
                "pairs": self.pairs, "locks": self.locks}


class _Pending:
    __slots__ = ("label", "frame", "order", "mono", "seq")

    def __init__(self, label, frame, order, mono, seq):
        self.label, self.frame, self.order, self.mono, self.seq = label, frame, order, mono, seq


class Merger:
    """Copies in, merged frames out, in time order.

    ``epoch(label, raw)`` places an unlocked radio's copies for ordering
    (the recorder passes its RadioClock's current offset; identity offline,
    where stamps are epochs already). ``stamp(label, raw)`` makes the final
    epoch stamp of a released frame in that radio's domain (the RadioClock;
    identity offline). Both default to identity."""

    def __init__(self, primary: str | None, labels: list[str | None], hold_s: float = HOLD_S,
                 epoch: Callable[[str | None, float], float] | None = None,
                 stamp: Callable[[str | None, float], float] | None = None, offline: bool = False):
        self.primary = primary
        self.labels = list(labels)
        self.hold_s = hold_s
        self.offline = offline
        self._epoch = epoch or (lambda label, raw: raw)
        self._stamp = stamp or (lambda label, raw: raw)
        self.aligners: dict[str | None, Aligner] = {label: Aligner() for label in self.labels if label != primary}
        self._queues: dict[str | None, deque] = {label: deque() for label in self.labels}
        self._by_psdu: dict[str | None, dict[bytes, list]] = {label: {} for label in self.labels}
        self._last_ts: dict[str | None, float] = {}       # newest stamp pushed, per radio
        # What each radio released lately, (order, psdu): a copy released
        # alone because its twin was ambiguous must keep the twin from
        # pairing with the next radio's copy as if it were alone.
        self._recent: dict[str | None, deque] = {label: deque() for label in self.labels}
        self._ended: set = set()
        self._seq = 0
        self._last_out: float | None = None    # last released primary-domain stamp (monotone clamp)
        self.merged = 0                        # frames released
        self.duplicates = 0                    # copies folded into another

    # ------------------------------------------------------------ input

    def push(self, label: str | None, frame: Frame, mono: float = 0.0) -> None:
        """One copy from one radio. Copies from a radio arrive in its own
        time order; a stamp that goes backwards is the radio's stream
        restarting on a new base, and its alignment starts over."""
        last = self._last_ts.get(label)
        if last is not None and frame.ts < last - 1.0:
            self.reset(label)
        self._last_ts[label] = frame.ts
        q = self._queues[label]
        self._seq += 1
        p = _Pending(label, frame, self._order(label, frame.ts), mono, self._seq)
        q.append(p)
        self._by_psdu[label].setdefault(frame.psdu, []).append(p)
        self._ended.discard(label)

    def end(self, label: str | None) -> None:
        """This radio's stream has ended (offline: EOF; live: the radio went
        down): nothing more is waited for from it."""
        self._ended.add(label)

    def reset(self, label: str | None) -> None:
        """The radio's stamps have a new base: forget its alignment."""
        if label in self.aligners:
            self.aligners[label].reset()

    # ------------------------------------------------------------ domains

    def _order(self, label: str | None, raw: float) -> float:
        """Where a copy sits for ordering: the primary's domain when it
        can be mapped there, else the recorder's epoch estimate for it."""
        if label == self.primary:
            return self._epoch(label, raw) if not self.offline else raw
        al = self.aligners[label]
        if al.locked:
            mapped = al.to_primary(raw)
            return self._epoch(self.primary, mapped) if not self.offline else mapped
        return self._epoch(label, raw) if not self.offline else raw

    def _active(self, label: str | None) -> bool:
        """Whether a radio's copies are still waited for: until its stream
        is declared ended (a reader at EOF, a radio detached). Not "has
        delivered lately": a radio that heard nothing for a quarter
        second is listening to a quiet channel, and the copy it is about
        to deliver belongs with the other radio's. What bounds the wait
        is each copy's own age (hold_s), not the other radio's silence."""
        return label not in self._ended

    # ------------------------------------------------------------ output

    def release(self, mono: float = 0.0, flush: bool = False) -> list[Frame]:
        """Every merged frame that is ready, in order. ``flush`` releases
        everything (the end of a replay, or a shutdown)."""
        out: list[Frame] = []
        while True:
            head = None
            for q in self._queues.values():
                if q and (head is None or (q[0].order, q[0].seq) < (head.order, head.seq)):
                    head = q[0]
            if head is None:
                break
            if not flush and not self._ready(head, mono):
                break
            out.append(self._release(head))
        return out

    def _ready(self, p: _Pending, mono: float) -> bool:
        if not self.offline and mono - p.mono >= self.hold_s:
            return True
        for label, q in self._queues.items():
            if label == p.label or not self._active(label):
                continue
            al = self.aligners.get(label) or self.aligners.get(p.label)
            margin = W_MAX if (al is None or al.locked) else SEARCH_S
            # Ordered within itself: the other radio has delivered past
            # the window once its newest copy is beyond it.
            newest = q[-1].order if q else None
            if newest is None or newest < p.order + margin:
                return False
        return True

    def _release(self, p: _Pending) -> Frame:
        # Matched before it is taken: once taken it is among its radio's
        # recent releases, where the ambiguity test would find it.
        copies: dict[str | None, _Pending] = {p.label: p}
        for label, q in self._queues.items():
            if label == p.label or not q:
                continue
            match = self._match(p, label)
            if match is not None:
                copies[label] = match
        for c in copies.values():
            self._take(c)
        self.duplicates += len(copies) - 1
        self._learn(copies)
        return self._build(copies)

    def _take(self, p: _Pending) -> None:
        self._queues[p.label].remove(p)
        lst = self._by_psdu[p.label][p.frame.psdu]
        lst.remove(p)
        if not lst:
            del self._by_psdu[p.label][p.frame.psdu]
        recent = self._recent[p.label]
        recent.append((p.order, p.frame.psdu))
        while recent and recent[0][0] < p.order - 2 * SEARCH_S:
            recent.popleft()

    def _alike_nearby(self, label: str | None, p: _Pending, exclude=None) -> int:
        """How many copies of p's psdu radio ``label`` has pending or lately
        released within the search span of p, other than ``exclude``."""
        pending = self._by_psdu[label].get(p.frame.psdu, [])
        n = sum(1 for c in pending if c is not exclude and abs(c.order - p.order) <= SEARCH_S)
        n += sum(1 for order, psdu in self._recent[label] if psdu == p.frame.psdu and abs(order - p.order) <= SEARCH_S)
        return n

    def _match(self, p: _Pending, label: str | None) -> _Pending | None:
        """The copy of p's frame in radio ``label``'s queue, if there is one:
        the identical psdu nearest the aligned prediction, inside the
        window; unlocked, the one identical psdu inside the search span,
        provided nothing else identical sits there from either side."""
        cands = self._by_psdu[label].get(p.frame.psdu)
        if not cands:
            return None
        al = self._aligner_between(p.label, label)
        if al is not None and al.locked:
            pt, other_is = self._primary_side(p, label)
            best, best_err, near = None, None, False
            for c in cands:
                t_primary, t_other = (pt, c.frame.ts) if other_is else (c.frame.ts, pt)
                err = abs((t_other - t_primary) - al.predict(t_primary))
                if err <= al.window(t_primary) and (best is None or err < best_err):
                    best, best_err = c, err
                elif err <= SEARCH_S:
                    near = True
            if best is None and near:
                al.missed()
            return best
        # Unlocked, or no aligner between these two: unambiguous only. One
        # identical psdu on their side, none other on mine, and neither
        # side has just released one like it (a retry burst straddling the
        # release is otherwise paired one copy at a time, wrongly).
        near = [c for c in cands if abs(c.order - p.order) <= SEARCH_S]
        if len(near) != 1 or self._alike_nearby(label, p, exclude=near[0]) or self._alike_nearby(p.label, p, exclude=p):
            return None
        return near[0]

    def _aligner_between(self, a: str | None, b: str | None) -> Aligner | None:
        if a == self.primary:
            return self.aligners.get(b)
        if b == self.primary:
            return self.aligners.get(a)
        return None

    def _primary_side(self, p: _Pending, label: str | None) -> tuple[float, bool]:
        """p's stamp as the primary sees it, and whether ``label`` is the
        other (non-primary) side of the aligner."""
        if p.label == self.primary:
            return p.frame.ts, True
        return p.frame.ts, False     # p is the other side; the candidates are primary copies

    def _learn(self, copies: dict) -> None:
        if self.primary not in copies:
            return
        pt = copies[self.primary].frame.ts
        for label, c in copies.items():
            if label != self.primary and label in self.aligners:
                self.aligners[label].observe(pt, c.frame.ts)

    def _build(self, copies: dict) -> Frame:
        """The merged frame: the best ear's copy, every copy under heard,
        each stamped in one epoch."""
        # The canonical stamp: the primary's copy when it heard the frame,
        # else the copy of a locked radio mapped into the primary's domain,
        # else the first copy in its own domain.
        if self.primary in copies:
            domain, raw = self.primary, copies[self.primary].frame.ts
        else:
            first = min(copies.values(), key=lambda c: (c.order, c.seq))
            al = self.aligners.get(first.label)
            if al is not None and al.locked:
                domain, raw = self.primary, al.to_primary(first.frame.ts)
            else:
                domain, raw = first.label, first.frame.ts
        if domain == self.primary:
            # A relock correction can put a mapped copy a little before the
            # last frame out; held to it, so the RadioClock does not read a
            # radio restart into it. A real restart is a bigger step and
            # passes, for the clock to re-anchor on.
            if self._last_out is not None and 0 < self._last_out - raw < CLAMP_S:
                raw = self._last_out
            self._last_out = raw
        ts = self._stamp(domain, raw)
        heard: dict[str | None, Frame] = {}
        for label, c in copies.items():
            if label == domain:
                own = ts
            else:
                al = self.aligners.get(label)
                if domain == self.primary and al is not None and al.locked:
                    own = ts + (al.to_primary(c.frame.ts) - raw)     # a microsecond delta, no clock call
                else:
                    own = ts                                          # placed with the frame it is a copy of
            heard[label] = replace(c.frame, ts=own, radio=label, heard=None)
        best = max(heard.items(), key=lambda kv: (-math.inf if kv[1].rssi is None else kv[1].rssi,
                                                   kv[0] == self.primary))
        self.merged += 1
        return replace(best[1], ts=ts, radio=best[0], heard=heard)

    # ------------------------------------------------------------ status

    def pending(self) -> int:
        return sum(len(q) for q in self._queues.values())

    def status(self) -> dict:
        return {"merged": self.merged, "duplicates": self.duplicates, "pending": self.pending(),
                "radios": {label or "radio": al.status() for label, al in self.aligners.items()}}


def merge_readers(readers: dict, primary: str | None = None) -> Iterator[Frame]:
    """Merged frames from several readers of one hour (one per radio),
    offline: each reader's next frame is pushed in stamp order and what is
    ready comes out; a reader at its end is not waited for."""
    labels = list(readers)
    if primary not in labels:
        primary = labels[0]
    merger = Merger(primary, labels, offline=True)
    iters = {label: iter(r) for label, r in readers.items()}
    heads: dict = {}
    for label, it in iters.items():
        nxt = next(it, None)
        if nxt is None:
            merger.end(label)
        else:
            heads[label] = nxt
    while heads:
        label = min(heads, key=lambda lb: heads[lb].ts)
        merger.push(label, heads[label])
        nxt = next(iters[label], None)
        if nxt is None:
            del heads[label]
            merger.end(label)
        else:
            heads[label] = nxt
        yield from merger.release()
    yield from merger.release(flush=True)
