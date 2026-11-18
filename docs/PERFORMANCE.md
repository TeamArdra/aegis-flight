# Performance

## Detection pipeline

Scope: `parse -> FeatureExtractor -> 4 detectors -> fusion -> ThreatAssessment`
(`IDSPipeline.process_tick`). **Nothing in this subsection was measured on a Raspberry Pi** (the Pi 3B+ figures are in the Raspberry Pi section below). All numbers are from the
development host (Windows 10, CPython 3.14, numpy/scikit-learn as installed in `C:\afvenv`); treat the
**relative** gains as the result and the absolute microseconds as host-specific.

### Rule: only speed / memory may change

Results must not change. `scripts/make_golden.py` + `tests/unit/test_golden_equivalence.py` +
`tests/golden/golden.json` hash, per decision, every field of the
`ThreatAssessment` (floats via `repr`, only the wall-clock `wall_time` / `latency_ms` excluded), every field of the
`FeatureFrame`, and every field of the four `DetectorResult`s; live-style cases also hash the parsed envelopes and the
parser statistics. The fixture is a snapshot of the current code, not of the pre-optimisation code: it was added with
the speed-ups (`15c3aaf`, generated, per that commit, from the pre-optimisation code), regenerated after them (`7ff7ab2`,
new `FeatureFrame` fields and the live-profile detection changes), extended with rounded layers (`14e629e`), and its
ML-on section was regenerated from the canonical team model (every ML digest other than 3 host-dependent `frame`
digests came out unchanged). That the speed-ups changed no result was shown separately, by running `make_golden.py`
on the old and the new code on one Windows host (PR #39 audit), not by this fixture.

What the guard enforces by default, on every host (CI included): parsed messages, parser statistics and decision
summaries (decisions, threats, alerts, attack types) exactly; with ML off also the full `ThreatAssessment` hashes
exactly; and the feature and detector layers with floats rounded to 9 significant digits (`frame_r` / `detectors_r`).
The exact feature and detector hashes are host-dependent in the last bit (see the Raspberry Pi section below; Linux
x86-64 CI differs in the exact `frame` and `detectors` hashes of every ML-off case; a second Windows CPython 3.13 host
differs in the exact `frame` hash of 4 ML-off cases with numpy 2.5.3, 2.5.4 and 2.5.5), so comparing every hash bit for
bit is **opt-in**: `AEGIS_GOLDEN_STRICT=1`, meant for the host that records the fixture (`recorded_env` in the fixture);
elsewhere a strict failure confined to `frame` / `detectors` is a host difference. The test reports which mode ran as a
skip reason (`pytest -r s`). A plain `python scripts/make_golden.py` refuses to overwrite an existing fixture; `--ml-only`
rewrites only the ML-on section, `--rewrite-all` everything.

140 tests: 131 cases (76 with ML off, 55 with ML on) plus self-checks (the guard is shown to fail on a changed constant, a
changed threshold and a one-ulp float change; the fast Isolation Forest scorer is checked bitwise against scikit-learn on a
model trained in the test and, when present, on `models/isoforest.joblib`). Cases: every attack mode of
`benchmark.extended.MODES` x 2 seeds, benign, 4 composites, 2 benign link-stress runs, and 14 synthetic pymavlink
streams (EKF_STATUS_REPORT gating, GPS_RAW_INT / GPS_STATUS receiver signature, mission upload + MISSION_CURRENT,
SET_MODE / COMMAND_LONG from unexpected sources, sequence gaps / duplicates / reorder, floods, GPS and heartbeat
dropouts, garbage / truncated / unknown-id / bad-CRC datagrams, signed frames with a verifying parser, cross-end
summaries from sysid 1 / comp 191 with and without a key, management frames from comp 191 / 192), each with the
ArduCopter profile (auto rate baseline on) and the default config. ML cases need the canonical team model
`models/isoforest.joblib` (sha256 `3fe74cdd...42939c4`, recorded in the fixture as `ml_model_sha256`). It is git-ignored,
and `aegis train` stamps a creation time into the bundle, so a retrain never reproduces it; without it the ML cases skip,
as they do in CI. Also: `aegis benchmark` (ML on) reproduces
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
each, about +-10 % run-to-run noise); the Raspberry Pi 3B+ figures for this path are in the section below.** Per-call numbers include one
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

## Dashboard

Scope: `backend/engine.py`, `backend/app.py`, `frontend/`. Rule: no change in what the operator sees or in any number shown.

Guard (recorded before any change): `tests/integration/test_dashboard_payload_guard.py` drives `LiveEngine._process` on a deterministic SIM run
(attack, mode switch to active-ips, attack cleared; 441 updates) and a REPLAY of a SYNTHETIC tlog (fix loss; 400 updates), canonicalises every
`update` exactly as `ws.send_json` does and checks a sha256 of the sequence plus explicit values. Only wall-clock leaves are masked
(`run_id`, `threat.latency_ms`). `scripts/perf_bench_backend.py` measures per-tick `_process` / `_make_update`, JSON size and time, CPU and peak memory.

Backend (400 ticks, min of 3): `_make_update` about 57-74 us before, 59-60 us after (the cached `SourceSpec.describe()` is within noise); JSON
payload 3.7 kB (SIM) / 4.3 kB (REPLAY) per update, unchanged byte for byte. The per-tick cost is dominated by the pipeline, outside this scope.
Real change: `/ws/telemetry` serialises each broadcast message once and shares the text between all connected clients (was one `json.dumps` of
about 55-80 us per client per message); output identical to `send_json`. Skipped: slimmer "unchanged field" payloads (the frontend replaces
whole sub-objects per message, and the contract must stay identical), caching topology / bridge_remote (age fields are time dependent, the
saving is under 10 us), caching `MitigationAction.to_dict()` (the action is mutated in place by `set_defense_mode`).

Frontend: sub-objects of each update (source, signing, topology, mitigation, link, checks, telemetry, threat) keep their previous reference when
deeply equal (`lib/stable.ts`), history arrays are appended without copying when nothing is added (`grow`, same caps 400 / 240), the heavy
panels are `React.memo`, the track projection is incremental (`projectTrackInc`, element-for-element equal to `projectTrack`) and MapPanel's
path strings are memoised. A differential run of the old and new reducers over 6000 random updates gave identical JSON state; after the first
update `source`, `signing`, `topologyInfo` and `mitigation` changed reference 0 more times (previously every update), so the panels that
depend only on them stop re-rendering. Bundle: JS 235.72 kB (73.69 kB gzip) before, 237.72 kB (74.46 kB gzip) after (helpers + memo wrappers);
CSS unchanged at 26.41 kB. No avoidable weight was found (React and ReactDOM dominate; no new dependencies).

## SITL regression after performance work

The detection and forwarding optimisations above (Isolation Forest scorer, extractor, X.25 CRC, framer, inline policy)
were re-checked against ArduCopter SITL with the maintained harness in `scripts/ardupilot/inline_demo/`, one run per
scenario, current code, same flights and attackers as the earlier evidence in `docs/INLINE_IPS.md` and
`docs/MGMT_CHANNEL.md`. Guards `test_golden_equivalence.py` and `test_forwarding_equivalence.py` pass. No functional
regression was found and no source file was changed.

| Scenario | Earlier numbers | Now | |
|---|---|---|---|
| Unsigned: own-counter forged LAND | 10 dropped, no LAND | 10 dropped (`dropped_provenance`), no LAND | identical |
| Unsigned: replay of captured SET_MODE | 3 dropped | 3 dropped | identical |
| Unsigned: counter-tracking forger | passes (LAND reached FC), contested alarm | passes (LAND), 10 contested events, 1 alarm | identical |
| Unsigned: pilot restart lock-out | 3.4 / 3.5 s, 1 resync | 3.7 s (second command), 1 resync | similar (+0.2 s, 1 s granularity of the pilot script) |
| Unsigned: downlink dropped | 0 | 0 of 24,461 | identical |
| Unsigned: totals | 206/204 forwarded, 15/16 `dropped_provenance` | 206 forwarded, 16 `dropped_provenance` | identical |
| Signing: unsigned / wrong-key / replay dropped | 40 / 10 / 3 | 40 / 10 / 3 | identical |
| Signing: signed pilot, uplink | 70 in, 17 forwarded, 53 dropped; `signed_ok` 16 | 70 / 17 / 53; `signed_ok` 16 | identical |
| Signing: downlink / cross-end | 24,386 and 24,524 fwd, 0 dropped; 168-169 matched, 0 mismatches | 23,852 fwd, 0 dropped; 165 matched, 0 mismatches | identical (counts vary with flight length) |
| Management: alert / blocked-action latency | 0.1-0.2 s / 0.7-0.8 s | 0.2 s / 0.7 s | identical within range |
| Management: status age | 1.1-1.4 s | 1.0 s | identical |
| Management: control (raise, confirm-lower, lock file, 5-frame lockout, rate limit), audit chain | as in MGMT_CHANNEL.md, 20 entries | same results, chain verified, 20 entries (4 posture, 7 accepted, 4 denied, 1 confirm, 3 ignored, 1 lockout) | identical |
| Management: bandwidth, nominal / 18 s flood avg | 24 B/s / 133.5 B/s (peak 204-247) | 24.0 B/s / 141.5 B/s (peak 190) | within 150 B/s |
| GPS glitch ~111 m, active-ips: first detection | +0.7 s | +0.5 s | same order |
| GPS: CRITICAL | +12.7 s | +12.5 s | same |
| GPS: ALT_HOLD | +3.9 s after fault (3.0 s after confirmation) | +3.75 s after fault | same; modes seen 0, 4, 2 only, no forbidden mode |
| GPS: benign flight | no alert in flight (3 on the ground) | 3 alerts before takeoff, none after | identical |
| Ground-side IDS (late-connecting `aegis serve`) | 1 alert (heading rule), 0 `DOS` | 0 events with the repo profile (management run); 1 and 4 heading-rule alerts with the old SITL profile; 0 `DOS` everywhere | no DOS storm |
| Bridge per-frame latency p50 / p95 / max | 16 / 48 / 2,000 us | 42-66 / 176-312 / 4,000-6,400 us | slower, see below |

Latency. `/status` `latency_us` is the time to forward one frame including socket sends, with the 20,000-sample ring. It
is 2.6x to 4x the earlier figures in all three bridge runs. This is not attributed to the code: during these runs the
host was shared with other work (dashboard benchmarking, browsers; a 14-31 % CPU load sample), and the same host ran
`scripts/perf_bench_forwarding.py` about 40 % slower than the table above (bridge `_handle` down 5.5 us against 3.9-4.2
us, management status emit 60 us against 42 us) with the same code. The `/status` figure is wall-clock inside a Python
process competing with SITL, the hub, pilot, attacker and ground IDS processes, so it is sensitive to host load. It
should be re-measured on an idle host before it is quoted.

Harness note: `gps_response.py` predates the signing gate and did not pass `--allow-unsigned` for `active-ips`, so the
bridge refused to start; the flag is now in the script (the gate itself is unchanged and working).

What this does not show: single runs per scenario, a simulated autopilot, loopback with no radio loss or latency, a
pymavlink pilot and attacker, one loaded Windows host, no real hardware and nothing on a Raspberry Pi. It shows
equal counters and outcomes, not equal timing under load.

## Raspberry Pi 3 Model B+ (measured 2026-10-29)

Board: Raspberry Pi 3 Model B+ Rev 1.3 (4 x Cortex-A53 at 1.4 GHz, 905 MB RAM), Debian aarch64, Python 3.13.5, numpy 2.5.4,
scikit-learn 1.9.1 (same versions as the development PC), bridge and detection dependencies only (no dashboard libraries).
The board reported `throttled=0x50000` (under-voltage and throttling occurred at some point since boot), so these numbers
may be slightly pessimistic. This is a Pi 3B+, not a Pi Zero 2 W; nothing was measured on a Zero 2 W or in flight.

**Correctness on ARM Linux.** All 48 simulator cases (10,800 decisions, ML off) give decisions byte-identical to the x86 PC
(threat, severity, attack class, score to the last digit, alert, evidence). About 1% of internal feature values differ in the
last bits (130 of 14,850 ML-feature values on 6 cases, max 4.4e-16 absolute / 2.6e-15 relative), a CPU / libm effect that never
reached a decision. So the exact golden hashes of the feature and detector layers are host-specific. That is not an ARM
effect only: Linux x86-64 CI differs in the exact `frame` and `detectors` hashes of every ML-off case (CI run 43982963893,
at `dd5aa5a`, where `parse` / `stats` / `assess` all matched), and a second Windows x86-64 CPython 3.13 host differs in the
exact `frame` hash of 4 ML-off cases. Bit-exact comparison is therefore opt-in (`AEGIS_GOLDEN_STRICT=1`, on the recording
host). By default, on every host, `tests/unit/test_golden_equivalence.py` compares the parsed messages, parser statistics,
decision summaries, (ML off) the full assessments exactly, and the feature and detector values rounded to 9 significant
digits. Unit tests on the Pi: 1,027 passed, the 8 errors need the dashboard libraries that were deliberately not
installed, the forwarding equivalence guard, the serial framer tests and the Linux-only serial tests all passed (272 in those files).

**Detection pipeline (host = this Pi), microseconds, p50 / p95:**

| Operation | ML off | ML on |
|---|---:|---:|
| whole decision tick | 452 / 949 | 3,401 / 4,200 |
| feature extraction per decision | 196 / 408 | 345 / 512 |
| anomaly detector | 9 / 15 | 2,545 / 3,141 |
| parse per datagram | 96 / 143 | 93 / 121 |

At 5 decisions per second that is about 0.2% (ML off) to 1.7% (ML on) of one core. Process RSS 105 MiB (ML off) and 192 MiB (ML on).

**Forwarding path:** X.25 CRC of a 263-byte frame 7.4 us; the serial framer handles about 1.5 MB/s (a 57,600-baud radio is
about 5.8 kB/s); per-frame inline policy 3.4 us (down) and 27 us (up, the uplink does the control checks), full bridge handling
of one frame 46 us (down) and 72 us (up) p50 in `active-ips`.

**Bridge soak over real Linux serial devices** (`scripts/pi_soak.py`: pseudo-terminal pairs, the synthetic benign stream replayed
in real time, a 1 Hz GCS heartbeat and a trusted DO_SET_MODE every 10 s; the bridge's own CPU and memory, ML off):

| Posture | Downlink | Frames lost | Bridge CPU (of one core) | Peak RSS | Per-frame latency p50 / p95 |
|---|---:|---:|---:|---:|---:|
| passive | 135 frames/s, 60 s | 0 down, 0 up | 28% | 61 MiB | 127 / 441 us |
| active-ips | 135 frames/s, 60 s | 0 down, 0 up | 25% | 62 MiB | 157 / 333 us |
| active-ips | 405 frames/s, 30 s | 1 down, 1 up (end-of-run drain) | 40% | 62 MiB | 144 / 327 us |

No frame was dropped by the bridge and the tap never overflowed. What this does not show: a real UART or radio (pseudo-terminals
have no baud-rate pacing), a flight, the management channel and signing on the Pi, or any Pi other than a 3B+. A first soak
showed apparent uplink drops and "contested sender" alarms; the cause was the test rig sending every frame with sequence
number 0 (pymavlink's `pack()` does not advance the counter), which the bridge correctly treated as a replay. Fixed in the rig.

**Pi 3B+ soak with signing and the management channel on** (`scripts/pi_soak.py --signing --mgmt`; throwaway test keys): 135
frames/s for 60 s in `active-ips`: 0 frames lost either way, bridge CPU 32% of one core, 61 MiB, per-frame latency p50 / p95 / max
183 / 379 / 3,371 us. Signed GCS commands were verified and forwarded (0 signature drops); management traffic on the radio side
averaged 126 B/s including the cross-end summary (30 status messages and 44 alert/action texts in 60 s); 3 signed posture
commands from the ground side were answered (a lowering from `active-ips` correctly asked for its second confirmation; the other
two were accepted). Pseudo-terminals, a Pi 3B+, ML off: not a radio or flight test.

**Later (2026-10-30/31):** the same Pi 3B+ ran the bridge over the real LR900 radio pair with ArduCopter SITL on the laptop (`docs/RADIO_TEST_RESULTS.md`). On 2026-10-31 a Raspberry Pi 5 ran the bridge with a real Pixhawk 6X on USB, disarmed; those results are in `docs/RADIO_TEST_RESULTS.md`, section "Real Pixhawk 6X on a Pi 5, 2026-10-31". Those later figures are not repeated in this file. The Pi 5 bench soak (1,500 s) completed; its result is in `docs/RADIO_TEST_RESULTS.md`.
