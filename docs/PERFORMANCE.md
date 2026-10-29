# Performance

## Detection pipeline

Scope: `parse -> FeatureExtractor -> 4 detectors -> fusion -> ThreatAssessment`
(`IDSPipeline.process_tick`). **Nothing here was measured on a Raspberry Pi.** All numbers are from the
development host (Windows 10, CPython 3.14, numpy/scikit-learn as installed in `C:\afvenv`); treat the
**relative** gains as the result and the absolute microseconds as host-specific.

### Rule: only speed / memory may change

Results must be bit-identical. `scripts/make_golden.py` + `tests/unit/test_golden_equivalence.py` +
`tests/golden/golden.json` (generated from the pre-optimisation code) hash, per decision, every field of the
`ThreatAssessment` (floats via `repr`, only the wall-clock `wall_time` / `latency_ms` excluded), every field of the
`FeatureFrame`, and every field of the four `DetectorResult`s; live-style cases also hash the parsed envelopes and the
parser statistics. 137 tests: 131 cases (76 with ML off, 55 with ML on) plus self-checks (the guard is shown to fail on
a changed constant, a changed threshold and a one-ulp float change). Cases: every attack mode of
`benchmark.extended.MODES` x 2 seeds, benign, 4 composites, 2 benign link-stress runs, and 14 synthetic pymavlink
streams (EKF_STATUS_REPORT gating, GPS_RAW_INT / GPS_STATUS receiver signature, mission upload + MISSION_CURRENT,
SET_MODE / COMMAND_LONG from unexpected sources, sequence gaps / duplicates / reorder, floods, GPS and heartbeat
dropouts, garbage / truncated / unknown-id / bad-CRC datagrams, signed frames with a verifying parser, cross-end
summaries from sysid 1 / comp 191 with and without a key, management frames from comp 191 / 192), each with the
ArduCopter profile (auto rate baseline on) and the default config. ML cases are skipped if `models/isoforest.joblib`
is missing or is not the model the fixture was built with. Also: `aegis benchmark` (ML on) reproduces
TP/FP/TN/FN = 6535 / 4 / 16826 / 65 and all 378 non-timing cells of `artifacts/benchmarks/results.csv`.

### Before / after (host, `python scripts/perf_bench.py`)

Workload: 6 SIM sessions (benign + 5 attack classes, 60 s) and 5 synthetic live streams (70 s); 3 repeats. Per
operation, microseconds (p50 / mean). `before` = `artifacts/perf/before.json`, `after` = `artifacts/perf/after.json`.

| operation | ML off before | ML off after | ML on before | ML on after |
|---|---:|---:|---:|---:|
| parse, per datagram | 10.0 / 10.6 | 10.0 / 10.3 | 10.1 / 10.5 | 10.1 / 10.5 |
| `extractor.update`, per message | 1.8 / 2.2 | 1.8 / 2.2 | 2.2 / 3.3 | 1.9 / 2.5 |
| `extract`, per decision | 84.4 / 87.8 | 26.7 / 30.2 | 108.7 / 111.4 | 30.0 / 33.7 |
| protocol detector | 5.0 / 29.1 | 4.9 / 5.4 | 8.0 / 35.6 | 5.5 / 6.0 |
| physics detector | 5.0 / 5.2 | 4.7 / 4.8 | 7.5 / 8.0 | 5.0 / 5.2 |
| anomaly detector (ML) | 1.0 / 1.1 | 1.0 / 1.0 | **12313 / 11687** | **168 / 163** |
| integrity detector | 2.2 / 2.3 | 2.3 / 2.4 | 4.1 / 4.5 | 2.8 / 2.9 |
| fusion + telemetry dict | 12.0 / 12.8 | 12.1 / 12.6 | 22.0 / 23.3 | 15.1 / 16.2 |
| `process_tick`, decision ticks | 124 / 150 | 61.5 / 68.4 | **12479 / 11874** | **242 / 242** |
| `process_tick`, all ticks (mean) | 77 | 36 | 5940 | 124 |
| throughput, ticks/s | 12964 | 27506 | 168 | 8082 |
| peak Python heap (tracemalloc) | 91 KiB | 83 KiB | 4472 KiB | 4419 KiB |
| process RSS | 107 MiB | 107 MiB | 229 MiB | 230 MiB |

(p95 / max per operation are in the JSON files. The protocol detector's old mean was dominated by a 0.3 ms
`dir(mavlink)` scan per command name; its max fell from 1.8-2.2 ms to a few tens of microseconds.)

Relative gain: whole decision tick **~50x with ML** (12.5 ms -> 0.24 ms) and **~2x without ML**; the ML-on
`aegis benchmark` wall time fell from about 9 minutes to 26 seconds on this host.

### What changed

* **ML anomaly detector (99.9 % of the ML-on time).** `IsolationForest.score_samples` on one row spent ~12 ms in joblib
  dispatch, per-tree validation and warning contexts. `AnomalyDetector` now walks the same fitted trees itself:
  same float32 cast, same `<=` threshold test, the per-leaf terms taken from the fitted model and added left to right
  in tree order, the same numpy `divide` / `2 **` finish, and one standardisation instead of two. It is verified
  bit-for-bit against sklearn on 13 probe rows when the model is first loaded (once per process and model file) and
  silently falls back to the original sklearn code on any mismatch, an unexpected model layout, or non-finite input.
  Also checked on 3000 random rows outside the guard: 0 differences.
* **`FeatureExtractor.extract`.** The receive-time window no longer scans (and twice sorts) a 2000-entry deque: while
  the deque is non-decreasing (tracked exactly) the window is a suffix found by walking back from the newest entry;
  an out-of-order arrival switches to the original scan until it has left the deque. Residual sums run over parallel
  float deques (`sum` over the same values in the same order, so the compensated-summation result is unchanged).
* `ProtocolDetector`: the static MAV_CMD id -> name lookup is memoised.
* `__slots__` on `MessageEnvelope`, `TelemetrySnapshot`, `CommandEvent`, `FeatureFrame` (smaller, quicker to build).

### Not changed, and why

* `MavlinkFrameParser.parse` (10 us per datagram): ~80 % is pymavlink's own `decode` + `to_dict`; replacing it
  could not be shown bit-identical for every field type, so it was left alone.
* Detectors and fusion (5-15 us each): already small; remaining gains are micro-optimisations below the 10 % bar.
* RSS (~230 MiB with ML) is dominated by importing scikit-learn / scipy to unpickle the model; avoiding it would need a
  different model format (an ML change, out of scope).
* Typed `array` storage for the forest tables would save ~2 MB but made the walk ~30 % slower; plain lists kept.

## Forwarding path

Scope: the inline (Raspberry-Pi-side) forwarding path: serial stream framer, CRC, `split_frames`, `FrameContext`,
`InlinePolicy.up/down`, bridge `_handle`, management emission. **Host numbers only (Windows, CPython 3.14, one run
each, about +-10 % run-to-run noise); nothing was measured on a Raspberry Pi.** Per-call numbers include one
`perf_counter_ns` pair (about 0.1-0.2 us). Reproduce with `python scripts/perf_bench_forwarding.py` (`--profile` for
cProfile); raw results in `artifacts/perf/forwarding_before.json` / `forwarding_after1.json`.

Rule: zero behaviour change. `tests/unit/test_forwarding_equivalence.py` replays a deterministic corpus (25 bridge
scenarios x 3 postures, 260 framer cases, `split_frames`, CRC) against `tests/golden_forwarding/golden.json`, which was
generated from the code before any change: forwarded bytes to FC and GCS, management frames, tap contents and every
bridge / policy / sanitizer / management counter are compared bit for bit. No buffering or batching was added; no
frame is held longer than before.

| Operation | before p50 / mean (us) | after p50 / mean (us) |
|---|---|---|
| X.25 CRC, 30 B | 2.6 / 2.63 | 0.5 / 0.50 |
| X.25 CRC, 263 B | 17.7 / 17.8 | 1.1 / 1.06 |
| Stream framer, per 256 B read (about 8 frames) | 29.0 / 28.5 | 15.7 / 15.7 |
| Stream framer throughput (4096 B reads) | 9.2 MB/s | 16.7 MB/s |
| Stream framer, one frame per read | 3.8 / 3.98 | 2.5 / 2.50 |
| `split_frames`, 1 frame | 1.3 / 1.28 | 1.0 / 1.03 |
| `split_frames`, 3 frames | 3.4 / 3.47 | 2.8 / 2.85 |
| `policy.up` active-ips, GCS heartbeat / command mix | 3.4 / 3.99 | 2.8 / 3.39 |
| `policy.down`, telemetry (passive / active) | 0.3 / 0.49, 0.4 / 0.53 | unchanged (0.3 / 0.51, 0.4 / 0.56) |
| bridge `_handle` down, 1 frame (passive / active) | 4.2 / 4.40, 4.3 / 4.48 | 3.9 / 4.20, 4.0 / 4.24 |
| bridge `_handle` up, active-ips | 8.1 / 9.25 | 7.8 / 9.15 |
| management STATUSTEXT emit | 8.8 / 9.14 | unchanged (9.5 / 9.7, noise) |
| management status emit | 41.7 / 42.9 | unchanged (43.8 / 44.4, noise) |

Peak Python heap while forwarding 3300 frames (tracemalloc, bridge built beforehand): passive 114 KB, active-ips
122 KB, unchanged (it is dominated by the 20000-sample latency deque, kept as is); framer over 4096 B reads: 18 KB
peak, under 1 KB retained, unchanged.

What changed, and why only that:

* **CRC** (`mavlink/signing.py`, re-used by `mitigation/actuator.py` and `sources/mavlink_serial.py`): the Python
  per-byte loop is replaced by `binascii.crc_hqx` over bit-reversed bytes with reversed init / result (a reflected CRC
  is the plain CRC of reversed input). Standard library, bit-identical (checked against an independent bit-level
  reference for all lengths 0-299 and random inits, and by the guard).
* **Framer** `_accept`: the `crc_extra` lookup is a dict built once per framer instead of a `getattr` per frame; all
  counters (including `crc_bytes_checked`) are unchanged.
* **`split_frames`**: `_Frame` is a `NamedTuple` instead of a frozen dataclass (immutable, same field names, private
  type), and a datagram that is exactly one frame is not copied.
* **Bridge `_handle`**: direction branches and bound methods hoisted out of the per-frame loop, `FrameContext` built
  positionally (about 0.3 us cheaper than keywords). Order of side effects is unchanged.
* **`InlinePolicy._observe_dual`**: loop instead of a generator and no zero-padded payload copy for the CRC-32 (CRC-32
  chains over the padding, identical value).

Skipped: changing `FrameContext` to a `NamedTuple` (public hook type; equality / indexing semantics would change for
about 0.5 us); bypassing `FrameContext` for the passive policy (would not honour a replaced / subclassed hook); an
array-based latency ring (saves memory but makes every `append` a Python-level call, i.e. slower); management
emission (dominated by pymavlink encoding and HMAC, off the per-frame path); inlining the framer scan loop (under 10 %
for a harder-to-read loop). Management-channel files, `status_server.py` and `hooks.py` were not changed.
