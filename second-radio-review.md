# Review of `second-radio`

Review completed on 2026-09-18 against `main...second-radio`, branch tip `5ef8c19`. **Six findings: three P1 (high priority) and three P2 (normal priority). All six are now fixed in separate commits on `second-radio`.**

The original review used an isolated archive under `/private/tmp/threadwatch-review` and made no source changes or commits. The fixes below were subsequently implemented and committed on `second-radio`, as requested. Finding descriptions and source line numbers describe the original reviewed commit, not the corrected code.

## Findings

### P1 — Primary restart leaves secondary clock models locked to the old timebase

**Fixed in `c0d0063`** — reset dependent models, drain queued copies under the old clocks, and apply attachment clock changes in the capture loop. Validation: 58 merger/recorder tests and 6 subtests passed; Ruff passed.

- Location: `threadwatch/merge.py:226–229` (`Merger.reset`).
- Resetting the primary does nothing because only secondary labels occur in `aligners`. Both reconnect paths call this function, so reconnecting the primary leaves every secondary mapped against its old clock. A new sniffer instance anchors its timestamps afresh; the previous crystal drift/offset need not survive the restart. Copies outside the old window are counted separately and secondary-only traffic is stamped against the wrong base. Offsets beyond `SEARCH_S` never trigger the near-miss recovery either.
- Reproduction: after three matching pairs establish a lock, call `reset("hub")`; the secondary remains locked. Advance the primary base by 200 ms and supply 20 shared transmissions: the merger emits **40 frames** and remains locked.
- Fix: reset all dependent aligners when the primary restarts, and reconcile pending entries from the old domain.

### P2 — Configuring radios abandons the existing primary ring series

**Fixed in `7fc3c4d`** — preserve the unlabelled primary series and its retention. Validation: 5 ring/recorder tests passed, including an existing primary hour being pruned after enabling named radios; Ruff passed.

- Location: `threadwatch/record.py:902`.
- Every writer receives `label=r.label`, including the first configured radio. Configuring `hub` therefore writes `threadwatch-YYYYMMDD-HH-hub.pcap`, despite the documented guarantee that the primary keeps the unlabelled filenames. Existing unlabelled files are no longer considered by any writer's per-series pruning, so enabling the feature on an existing installation leaves those files outside both retention limits indefinitely. Offline readers also lose their explicit `None` primary and select a series by listing order.
- Reproduction: running the existing two-radio recorder fixture creates `threadwatch-20260918-09-annex.pcap` and `threadwatch-20260918-09-hub.pcap`; neither is the plain primary filename. The existing test only checks that the second filename does not end in `-annex.pcap`, so it misses this.
- Fix: give the primary writer `label=None` while retaining the configured label for live radio identity.

### P1 — Relay backoff stops draining capture instead of dropping disconnected traffic

**Fixed in `8e2c401`** — drain capture independently of connection attempts and sends, drop/count outage records, bound queued traffic and its age, and interrupt retry backoff at EOF. Validation: 8 relay tests and 5 subtests passed; Ruff passed.

- Location: `threadwatch/relay.py:107–127`.
- Connection attempts and `sleep(delay)` run in the same loop that reads the FIFO. During each 2–30 second backoff (and up to 10 seconds connecting), no capture records are consumed. The FIFO fills, its writer blocks, and the vendored serial-reader process continues buffering records in its multiprocessing queue. Reconnection then forwards old traffic as fresh arrivals; only one record per failed attempt is counted as dropped. This defeats the stated drop-while-disconnected behavior, can grow memory throughout an outage, and prevents those late copies from merging with the primary's already released frames.
- Reproduction: inject three capture records into the stream during the first failed connection's backoff. On reconnect, the relay sends all three and reports `sent=3, dropped=1`; the three outage records were retained, not dropped.
- Fix: keep draining capture while disconnected and perform retries independently, discarding/counting all records until the connection is usable.

### P2 — Replay relearns alignment for timestamps that are already aligned

**Fixed in `8d60ff1`** — compare offline timestamps directly within the duplicate window, without clock fitting; preserve each reception timestamp. Validation: 93 merger/device/ring/recorder tests and 6 subtests passed; Ruff passed.

- Location: `threadwatch/merge.py:329–349`, `merge_readers` at lines 422–450.
- Each hour's offline merger begins unlocked and uses the 50 ms ambiguity search until it learns three unique pairs. However, the recorder already aligned the timestamps written to the ring. A retry burst at the start of an hour (or a short snapshot with only repeated traffic) consequently produces both radios' copies separately, changing frame counts and retry evidence relative to live capture.
- Reproduction: two readers each contain four copies of the same PSDU at 2.5 ms intervals, with the second reader's timestamps 40 microseconds later. `list(merge_readers({None: a, 'annex': b}))` returns **8 frames**, each with one reception; the correct result is **4 transmissions**, each with two receptions.
- Fix: provide an offline path that uses the already-shared epoch and the narrow duplicate tolerance without requiring a fresh clock lock for every hour.

### P1 — Failure to attach a later radio leaves earlier sniffers running outside cleanup

**Fixed in `011df8f`** — bind listeners before starting USB workers; close listeners, wake and stop vendor consumers, and remove owned FIFOs after startup failures. Validation: 45 recorder tests and 6 subtests passed, including a non-daemon worker blocked on FIFO open; Ruff passed.

- Location: `threadwatch/record.py:715–730`.
- The startup loop starts the first USB sniffer before it binds a later TCP listener. If that listener's port is occupied or its configured LAN address is unavailable, `_listen()` raises. The surrounding handler closes only the event log; it never stops already-started sniffers or closes their FIFOs/listeners, and execution never reaches the recorder's normal cleanup/watchdog. The real vendor sniffer owns a non-daemon thread, so this can leave a process hanging after its startup traceback, holding capture resources without recording and preventing a normal supervisor restart.
- Reproduction: use `TwoRadiosRunTest`'s fake first USB radio, change the second radio to TCP, and make `Radio._listen` raise `OSError('Address already in use')`. After `run_record` raises, the sniffer call log contains only `('start', '/dev/fake-hub')`, with **no stop call**.
- Fix: validate/bind listeners before starting capture and unwind every previously attached radio if any startup step fails; account for the vendor thread's shutdown requirements.

### P2 — Expired clock models are never invalidated by the merger

**Fixed in `76a8114`** — expire stale models before mapping/matching, refresh queued and recent ordering when alignment changes, and use independent epoch estimates to regain a lock. Validation: 244 focused tests and 14 subtests passed; the full suite and Ruff also passed (see below).

- Location: `threadwatch/merge.py:100–104`, `Merger.push` at lines 206–219 and locked matching at lines 329–342.
- `Aligner.stale()` is implemented and unit-tested, but nothing calls it. A secondary that stops sharing frames with the primary remains locked indefinitely, even while it continues delivering its own frames. A fresh lock has no measured drift; at the branch's measured 79 ppm, 1,000 seconds without a pair adds about 79 ms of error. When overlap resumes, that exceeds both the 1 ms matching ceiling and the 50 ms near-miss search, so neither successful pairing nor the ten-miss reset repairs it. Frames continue to be doubled and secondary-only timestamps continue using the expired model.
- Reproduction: learn three pairs, advance to `T0 + 1000`, and release a secondary frame. `aligner.stale(T0 + 1000)` is **True**, but `aligner.locked` remains **True** after release.
- Fix: apply the staleness check before using a model for mapping or matching, with appropriate reinitialization of queued ordering and unlocked epoch estimates.


## Coverage and validation

- Inspected all changed production modules and the associated documentation/tests: configuration, discovery, per-radio capture and supervision, TCP relay, alignment/deduplication, ring retention and readers, snapshot metadata, pipeline reception tracking, and status/UI changes.
- Ran the branch's complete test suite using the repository's existing virtual environment: **902 passed, 428 subtests passed in 37.14 seconds**. Command: `/Users/jonharris/Source/threadwatch/.venv/bin/python -m pytest -q` from the isolated branch copy.
- The initial sandboxed run could not bind local test sockets (110 failures, 792 passes). The complete rerun with loopback access passed; those sandbox failures are not reported as branch defects.
- Ran additional deterministic probes for primary reset, offline retry merging, unused stale-model expiration, startup cleanup, relay backoff, and actual ring filenames. Their observed results are recorded with the findings above. Temporary probe code and test logs were kept outside the repository.
- No physical dongles or remote relay hosts were used. Hardware capture, long-running USB reattachment, and real network outage behavior were assessed from the implementation and simulated inputs, not a hardware soak test.


## Fix validation

All fixes were completed one at a time, with a separate source/test commit for each:

| Finding | Fix commit |
| --- | --- |
| Primary restart invalidation | `c0d0063` |
| Primary ring naming and retention | `7fc3c4d` |
| Relay outage buffering | `8e2c401` |
| Already-aligned offline replay | `8d60ff1` |
| Startup resource cleanup | `011df8f` |
| Expired clock models | `76a8114` |

Final validation on the combined changes:

- `.venv/bin/python -m pytest -q`: **914 passed, 430 subtests passed in 39.45 seconds**, with local socket access enabled for integration tests.
- `.venv/bin/ruff check .`: **all checks passed**.
- `git diff --check`: passed before committing.
- Additional live-clock simulation confirmed that a primary reconnect with a 200 ms timebase change regains its lock; the final ten shared frames each retain both receptions. The first unaligned pair is conservatively released separately while its epoch estimate is initialized.
- Physical dongles and remote hosts were not available; hardware operation remains unverified.

This report is committed separately from the six fixes so it can record every final fix hash.
