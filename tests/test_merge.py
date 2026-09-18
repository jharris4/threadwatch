"""Two radios' copies become one frame; a retry stays two."""

import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from threadwatch import merge
from threadwatch.merge import Aligner, Merger, merge_readers
from threadwatch.pcap import Frame

T0 = 1_789_000_000.0


def frame(ts, psdu=b"\x41\x88\x01", rssi=-60.0, lqi=100):
    return Frame(ts=ts, raw=b"\x00\x00\x08\x00" + psdu, psdu=psdu, rssi=rssi, channel=25, lqi=lqi)


def secured(i: int) -> bytes:
    """A distinct 40-byte psdu per i, as a secured data frame would be."""
    return b"\x61\x98" + bytes([i & 0xff]) + i.to_bytes(4, "little") + bytes(33)


class AlignerTest(unittest.TestCase):
    def _locked(self, offset=0.010, ppm=79.0):
        al = Aligner()
        for i in range(3):
            t = T0 + i * 2
            al.observe(t, t + offset + ppm * 1e-6 * (t - T0))
        self.assertTrue(al.locked)
        return al

    def test_three_agreeing_pairs_lock_and_the_model_predicts_the_drift(self):
        al = Aligner()
        al.observe(T0, T0 + 0.010)
        al.observe(T0 + 1, T0 + 1 + 0.030)        # 20 ms apart: not the same frame twice
        al.observe(T0 + 2, T0 + 2 + 0.0101)
        self.assertFalse(al.locked)
        al.observe(T0 + 3, T0 + 3 + 0.0102)
        self.assertFalse(al.locked)               # the stray one is still among the last three
        al.observe(T0 + 4, T0 + 4 + 0.0103)       # now the last three agree within 1 ms
        self.assertTrue(al.locked)
        al = self._locked(offset=0.010, ppm=79.0)
        t = T0 + 3600
        # Fed pairs for an hour at 79 ppm, the prediction stays within the window.
        for i in range(3600):
            tp = T0 + 4 + i
            al.observe(tp, tp + 0.010 + 79e-6 * (tp - T0) + random.uniform(-30e-6, 30e-6))
        self.assertAlmostEqual(al.b * 1e6, 79.0, delta=2.0)
        self.assertLess(abs(al.predict(t) - (0.010 + 79e-6 * 3600)), 150e-6)
        self.assertLessEqual(al.window(t), merge.W_MAX)
        self.assertGreaterEqual(al.window(t), merge.W_MIN)
        st = al.status()
        self.assertTrue(st["locked"])
        self.assertAlmostEqual(st["ppm"], 79.0, delta=2.0)

    def test_the_window_grows_with_silence_to_the_ceiling_and_the_model_then_ages_out(self):
        al = self._locked()
        last = al.t_last
        self.assertAlmostEqual(al.window(last), merge.W_MIN, delta=1e-9)
        # A fresh lock knows the offset, not the drift: the window grows fast...
        self.assertAlmostEqual(al.window(last + 5), merge.W_MIN + 100e-6 * 5, delta=1e-9)
        al.rate_known = True
        # ...and slowly once the rate is measured.
        self.assertAlmostEqual(al.window(last + 100), merge.W_MIN + 3e-6 * 100, delta=1e-9)
        self.assertEqual(al.window(last + 10_000), merge.W_MAX)
        self.assertFalse(al.stale(last + 300))
        self.assertTrue(al.stale(last + 10_000))
        al.reset()
        self.assertFalse(al.locked)
        self.assertEqual(al.window(last), merge.SEARCH_S)

    def test_the_mapping_into_the_primary_domain_is_the_exact_inverse(self):
        al = self._locked(offset=0.3, ppm=79.0)
        for tp in (T0, T0 + 1800, T0 + 3599):
            t_other = tp + al.predict(tp)
            self.assertAlmostEqual(al.to_primary(t_other), tp, delta=1e-7)


class TwoRadiosTest(unittest.TestCase):
    """Live merging: the copies of A (primary) and B, B's clock 10 ms ahead."""

    OFFSET = 0.010

    def _merger(self):
        return Merger("hub", ["hub", "annex"])

    def _lock(self, m, mono=0.0):
        """Three distinct frames both radios heard: the lock."""
        out = []
        for i in range(3):
            t = T0 + i
            m.push("hub", frame(t, secured(i), rssi=-70), mono)
            m.push("annex", frame(t + self.OFFSET, secured(i), rssi=-60), mono)
        for i in range(3):       # a later frame from each moves the watermarks past them
            t = T0 + 3 + i
            m.push("hub", frame(t, secured(10 + i)), mono)
            m.push("annex", frame(t + self.OFFSET, secured(10 + i)), mono)
        # Once locked, both final watermarks agree. Let the hold expire
        # instead of relying on the old unaligned 10 ms ordering skew.
        out.extend(m.release(mono + merge.HOLD_S))
        self.assertTrue(m.aligners["annex"].locked)
        return out

    def test_a_frame_both_heard_is_one_frame_with_two_receptions_and_the_best_ear_on_top(self):
        m = self._merger()
        out = self._lock(m)
        self.assertEqual(len(out), 6)                 # the three locking frames and the three after them
        f = out[0]
        self.assertEqual(f.psdu, secured(0))
        self.assertEqual(f.radio, "annex")            # -60 beats -70
        self.assertEqual(f.rssi, -60.0)
        self.assertEqual(sorted(f.heard), ["annex", "hub"])
        self.assertEqual(f.ts, T0)                    # the primary's stamp
        self.assertEqual(f.heard["hub"].rssi, -70.0)
        self.assertEqual(f.heard["hub"].radio, "hub")
        self.assertIsNone(f.heard["hub"].heard)
        # The annex copy is stamped in the primary's domain, within the jitter of it.
        self.assertLess(abs(f.heard["annex"].ts - T0), 1e-3)
        self.assertEqual(m.duplicates, 6)

    def test_after_the_lock_a_retry_is_two_frames_and_a_duplicate_is_one(self):
        m = self._merger()
        self._lock(m)
        t = T0 + 10
        # One frame, both heard, then its MAC retry 2.5 ms later, both heard.
        m.push("hub", frame(t, secured(50), rssi=-70))
        m.push("annex", frame(t + self.OFFSET + 40e-6, secured(50), rssi=-65))
        m.push("hub", frame(t + 0.0025, secured(50), rssi=-70))
        m.push("annex", frame(t + 0.0025 + self.OFFSET - 30e-6, secured(50), rssi=-65))
        m.push("hub", frame(t + 1, secured(51)))
        m.push("annex", frame(t + 1 + self.OFFSET, secured(51)))
        out = m.release()
        got = [(f.psdu == secured(50), round(f.ts - t, 4), sorted(f.heard)) for f in out if f.psdu == secured(50)]
        self.assertEqual(got, [(True, 0.0, ["annex", "hub"]), (True, 0.0025, ["annex", "hub"])])

    def test_identical_acks_close_together_are_not_confused(self):
        m = self._merger()
        self._lock(m)
        t = T0 + 10
        ack = b"\x02\x00\x07"
        # A hears an ACK; B hears the same bytes 1.5 ms later (the standard's
        # floor for a repeat: the window never reaches it, whatever the lock's age).
        m.push("hub", frame(t, ack))
        m.push("annex", frame(t + self.OFFSET + 1.5e-3, ack))
        m.push("hub", frame(t + 1, secured(60)))
        m.push("annex", frame(t + 1 + self.OFFSET, secured(60)))
        out = [f for f in m.release() if f.psdu == ack]
        self.assertEqual([sorted(f.heard) for f in out], [["hub"], ["annex"]])

    def test_a_frame_only_one_radio_heard_waits_for_the_other_then_goes_alone(self):
        m = self._merger()
        self._lock(m, mono=100.0)
        t = T0 + 10
        m.push("hub", frame(t, secured(70)), mono=100.0)
        self.assertEqual(m.release(mono=100.0), [])                       # annex may still deliver a copy
        m.push("annex", frame(t + self.OFFSET + 0.5, secured(71)), mono=100.1)   # annex is past it: no copy
        out = m.release(mono=100.1)
        self.assertEqual([(f.psdu, sorted(f.heard)) for f in out], [(secured(70), ["hub"])])
        m.push("hub", frame(t + 2, secured(72)), mono=100.2)             # hub is past annex's frame...
        self.assertEqual([f.psdu for f in m.release(mono=100.2)], [secured(71)])
        # ...and its own waits for annex only as long as hold_s.
        self.assertEqual(m.release(mono=100.2 + merge.HOLD_S / 2), [])
        self.assertEqual([f.psdu for f in m.release(mono=100.2 + merge.HOLD_S)], [secured(72)])

    def test_output_is_in_time_order_across_radios_and_a_relock_never_steps_backwards(self):
        m = self._merger()
        self._lock(m)
        t = T0 + 10
        for i in range(20):
            m.push("hub", frame(t + i * 0.1, secured(100 + i)))
            m.push("annex", frame(t + i * 0.1 + 0.05 + self.OFFSET, secured(200 + i)))
        out = m.release(flush=True)
        stamps = [f.ts for f in out]
        self.assertEqual(stamps, sorted(stamps))
        self.assertEqual(len(out), 40)
        # The annex stream restarts on a new base: alignment starts over, order holds.
        m.push("annex", frame(1000.0, secured(300)))
        self.assertFalse(m.aligners["annex"].locked)
        m.push("hub", frame(t + 5, secured(301)))
        out = m.release(flush=True)
        self.assertEqual(sorted(f.ts for f in out), [f.ts for f in out])

    def test_a_single_radio_passes_straight_through(self):
        m = Merger(None, [None])
        m.push(None, frame(T0, secured(1)), mono=5.0)
        out = m.release(mono=5.0)
        self.assertEqual([(f.psdu, f.radio, list(f.heard)) for f in out], [(secured(1), None, [None])])
        self.assertEqual(m.pending(), 0)

    def test_primary_restart_drains_old_copies_and_relearns_every_secondary(self):
        offsets = {"hub": 0.0, "annex": 0.0}
        m = Merger("hub", ["hub", "annex"], epoch=lambda label, raw: raw + offsets[label])
        self._lock(m)
        old = T0 + 10
        m.push("hub", frame(old, secured(80)))
        m.push("annex", frame(old + self.OFFSET, secured(80)))
        m.reset("hub")
        self.assertFalse(m.aligners["annex"].locked)
        # The old pair survives, with its old timestamp and both receptions.
        drained = m.release()
        self.assertEqual([(f.ts, len(f.heard)) for f in drained], [(old, 2)])
        offsets["hub"] = -0.2  # the restarted primary is now 200 ms ahead
        for i in range(20):
            t = T0 + 20 + i
            m.push("hub", frame(t + 0.2, secured(100 + i)))
            m.push("annex", frame(t + self.OFFSET, secured(100 + i)))
        out = m.release(flush=True)
        self.assertEqual(len(out), 20)
        self.assertTrue(all(len(f.heard) == 2 for f in out))
        self.assertTrue(m.aligners["annex"].locked)
        self.assertAlmostEqual(m.aligners["annex"].a, self.OFFSET - 0.2, places=6)

    def test_primary_backwards_stamp_invalidates_all_secondary_models(self):
        m = Merger("hub", ["hub", "annex", "shed"])
        for al in m.aligners.values():
            for i in range(3):
                al.observe(T0 + i, T0 + i + 0.01)
        m.push("hub", frame(T0 + 10, secured(1)))
        m.push("hub", frame(T0, secured(2)))
        self.assertTrue(all(not al.locked for al in m.aligners.values()))
        self.assertEqual([f.psdu for f in m.release(flush=True)], [secured(1), secured(2)])

    def test_either_radio_expires_a_model_without_shared_frames(self):
        for label in ("hub", "annex"):
            with self.subTest(label=label):
                m = self._merger()
                self._lock(m)
                m.push(label, frame(T0 + 1000, secured(500)))
                self.assertFalse(m.aligners["annex"].locked)
                self.assertEqual(len(m.release(flush=True)), 1)

    def test_expiration_rebases_pending_copies_without_losing_them(self):
        offsets = {"hub": 0.0, "annex": -0.04}
        m = Merger("hub", ["hub", "annex"], epoch=lambda label, raw: raw + offsets[label])
        self._lock(m)
        m.push("annex", frame(T0 + 300.01, secured(500)))
        before = m._queues["annex"][0].order
        m.push("hub", frame(T0 + 1000, secured(501)))
        self.assertFalse(m.aligners["annex"].locked)
        self.assertNotEqual(m._queues["annex"][0].order, before)
        self.assertAlmostEqual(m._queues["annex"][0].order, T0 + 299.97, places=6)
        self.assertEqual([f.psdu for f in m.release(flush=True)], [secured(500), secured(501)])

    def test_live_epoch_clocks_recover_after_drift_beyond_the_search_span(self):
        from threadwatch.record import RadioClock
        now = [T0]
        clocks = {lb: RadioClock(wall=lambda: now[0], mono=lambda: now[0] - T0)
                  for lb in ("hub", "annex")}
        m = Merger("hub", ["hub", "annex"],
                   epoch=lambda label, raw: raw + (clocks[label].offset or 0.0),
                   stamp=lambda label, raw: clocks[label].stamp(raw))
        for i in range(3):
            now[0] = T0 + i
            m.push("hub", frame(now[0], secured(i)), mono=i)
            m.push("annex", frame(now[0] + 0.01 + i * 79e-6, secured(i)), mono=i)
            m.release(mono=i + 1)
        self.assertTrue(m.aligners["annex"].locked)
        # For a thousand seconds the radios hear disjoint traffic.
        for i in range(3, 1000):
            now[0] = T0 + i
            m.push("hub", frame(now[0], secured(1000 + i)), mono=i)
            m.push("annex", frame(now[0] + 0.01 + i * 79e-6, secured(3000 + i)), mono=i)
            m.release(mono=i + 1)
        self.assertFalse(m.aligners["annex"].locked)
        # Their raw offset now exceeds SEARCH_S, but independent epoch
        # estimates allow shared traffic to train a new lock.
        out = []
        for i in range(1000, 1020):
            now[0] = T0 + i
            m.push("hub", frame(now[0], secured(i)), mono=i)
            m.push("annex", frame(now[0] + 0.01 + i * 79e-6, secured(i)), mono=i)
            out.extend(m.release(mono=i + 1))
        self.assertTrue(m.aligners["annex"].locked)
        self.assertEqual(len(out), 20)
        self.assertTrue(all(len(f.heard) == 2 for f in out))

    def test_before_the_lock_only_an_unambiguous_pair_merges(self):
        m = self._merger()
        t = T0
        # Two identical psdus close together on hub (a retry burst) and one on annex: ambiguous.
        m.push("hub", frame(t, secured(5)))
        m.push("hub", frame(t + 0.003, secured(5)))
        m.push("annex", frame(t + self.OFFSET, secured(5)))
        m.push("hub", frame(t + 1, secured(6)))
        m.push("annex", frame(t + 1 + self.OFFSET, secured(6)))
        out = m.release(flush=True)
        self.assertEqual([sorted(f.heard) for f in out if f.psdu == secured(5)], [["hub"], ["hub"], ["annex"]])
        self.assertEqual([sorted(f.heard) for f in out if f.psdu == secured(6)], [["annex", "hub"]])


class OfflineTest(unittest.TestCase):
    def test_an_hour_starting_with_only_retries_merges_without_training(self):
        psdu = secured(99)
        hub = [frame(T0 + i * 0.0025, psdu) for i in range(4)]
        annex = [frame(f.ts + 40e-6, psdu) for f in hub]
        shed = [frame(f.ts + 60e-6, psdu) for f in hub]
        out = list(merge_readers({None: hub, "annex": annex, "shed": shed}))
        self.assertEqual(len(out), 4)
        self.assertEqual([f.ts for f in out], [f.ts for f in hub])
        self.assertTrue(all(len(f.heard) == 3 for f in out))
        self.assertEqual([f.heard["annex"].ts for f in out], [f.ts for f in annex])

    def test_identical_transmissions_heard_by_different_radios_are_not_clock_offsets(self):
        ack = b"\x02\x00\x07"
        hub = [frame(T0 + i, ack) for i in range(5)]
        annex = [frame(f.ts + 0.0015, ack) for f in hub]
        out = list(merge_readers({None: hub, "annex": annex}))
        self.assertEqual(len(out), 10)
        self.assertTrue(all(len(f.heard) == 1 for f in out))
        self.assertEqual([f.ts for f in out], sorted(f.ts for f in hub + annex))

    def test_two_series_of_one_hour_merge_into_the_stream_the_recorder_saw(self):
        offset = 20e-6                     # stamps on disk are aligned already
        hub = [frame(T0 + i, secured(i), rssi=-70) for i in range(50)]
        annex = [frame(T0 + i + offset, secured(i), rssi=-60) for i in range(50) if i % 5]   # annex missed every fifth
        annex.append(frame(T0 + 20.5, secured(999), rssi=-80))                         # and heard one hub did not
        out = list(merge_readers({"hub": iter(hub), "annex": iter(sorted(annex, key=lambda f: f.ts))}, "hub"))
        self.assertEqual(len(out), 51)
        self.assertEqual([f.ts for f in out], sorted(f.ts for f in out))
        both = [f for f in out if len(f.heard) == 2]
        self.assertEqual(len(both), 40)
        self.assertEqual({f.radio for f in both}, {"annex"})
        only_hub = [f for f in out if list(f.heard) == ["hub"]]
        self.assertEqual([f.psdu for f in only_hub], [secured(i) for i in range(0, 50, 5)])
        self.assertEqual([f.psdu for f in out if list(f.heard) == ["annex"]], [secured(999)])

    def test_one_series_reads_as_it_always_did(self):
        frames = [frame(T0 + i, secured(i)) for i in range(5)]
        out = list(merge_readers({None: iter(frames)}))
        self.assertEqual([f.psdu for f in out], [f.psdu for f in frames])
        self.assertEqual([f.radio for f in out], [None] * 5)


if __name__ == "__main__":
    unittest.main()


class SoakTest(unittest.TestCase):
    def test_ten_simulated_minutes_at_the_measured_drift_merge_exactly(self):
        """Every on-air event heard by any radio comes out once, with
        exactly the radios that heard it; a retry is its own event."""
        rng = random.Random(7)
        events = []                       # (t, psdu, heard_by)
        t = T0
        n = 0
        while t < T0 + 600:
            # ~25 frames/s, and never two inside one frame's airtime: two
            # copies 50 us apart can only be one frame, which is the premise.
            t += 0.0005 + rng.expovariate(25.0)
            psdu = secured(n); n += 1
            heard = {r for r in ("hub", "annex") if rng.random() < 0.9}
            if heard:
                events.append((t, psdu, heard))
            if rng.random() < 0.05:       # a retry of the same bytes, 2.5-8 ms on
                t2 = t + rng.uniform(0.0025, 0.008)
                heard2 = {r for r in ("hub", "annex") if rng.random() < 0.9}
                if heard2:
                    events.append((t2, psdu, heard2))
                t = t2
        copies = []                       # (arrival order key, radio, frame)
        for t, psdu, heard in events:
            if "hub" in heard:
                copies.append((t, "hub", frame(t, psdu, rssi=-70)))
            if "annex" in heard:
                tb = (t - T0) * (1 + 79e-6) + T0 + 0.010 + rng.uniform(-30e-6, 30e-6)
                copies.append((tb, "annex", frame(tb, psdu, rssi=-60)))
        m = Merger("hub", ["hub", "annex"])
        out = []
        for key, label, f in sorted(copies, key=lambda c: c[0]):
            m.push(label, f, mono=key - T0)
            out.extend(m.release(mono=key - T0))
        out.extend(m.release(flush=True))
        want = [(round(t, 6), psdu, tuple(sorted(heard))) for t, psdu, heard in events]
        got = [(round(f.ts, 6), f.psdu, tuple(sorted(f.heard))) for f in out]
        # Before the lock (the first few pairs) an annex-only copy is placed by its
        # own stamp; compare on psdu and radios, and stamps once locked.
        self.assertEqual(len(got), len(want))
        self.assertEqual([(p, h) for _, p, h in got], [(p, h) for _, p, h in want])
        locked_from = next(i for i, f in enumerate(out) if m.aligners["annex"].locks and "hub" in f.heard)
        for (t, _p, _h), f in list(zip(want, out, strict=True))[locked_from + 50:]:
            if "hub" in f.heard:
                self.assertAlmostEqual(f.ts, t, places=6)
            else:
                self.assertLess(abs(f.ts - t), 200e-6)      # a mapped annex-only copy
        self.assertTrue(m.aligners["annex"].locked)
        self.assertAlmostEqual(m.aligners["annex"].b * 1e6, 79.0, delta=3.0)
