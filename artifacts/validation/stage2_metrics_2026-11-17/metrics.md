# Stage 2 metrics

Definitions: `src/aegisflight/metrics/stage2.py; docs/BENCHMARKING.md#stage-2-metrics`. Decision period 0.2 s.

**Claim class: per row, in each source's own words ("not recorded" where the source states none); no figure here is flight-hour, real-flight or real-world validation.** Each row's claim class is its source's own wording (section 0 and the `claim class` column).

**Dated snapshot.** Every figure describes the code that produced its source artifact (per-source commit, config, ML state and date under provenance), not the tree this file was generated on. Later live-source/detector changes (e.g. PR #39, pending) are not reflected: this is a dated snapshot of committed evidence. Recorded source dates: 2026-10-06 to 2026-10-28. No recorded commit: `artifacts/benchmarks_extended`, `artifacts/hardware/serial_ids_com7_001`, `artifacts/hardware/serial_ids_com7_002`, `artifacts/sitl/benign_replay_stage1_default.json`, `artifacts/external/alfa/results.json`. No recorded date: `artifacts/benchmarks_extended`, `artifacts/sitl/benign_replay_stage1_default.json`, `artifacts/external/alfa/results.json`.

**SIM reproducibility.** `artifacts/benchmarks_extended` is a 2026-09-24 snapshot of pre-Stage-2 code (`artifacts/validation/submission_rerun_20261029/README.md`). A decision-level re-run of all 116 sessions on the current tree (2026-11-18; PR #48 re-verification (two independent re-runs); not a committed artifact) found sessions 76, 77, 78, 79 (dos:blackout) do not reproduce their committed decisions; the other 112 of 116 do. The gap predates PR #48: the committed 2026-10-29 re-run (`artifacts/validation/submission_rerun_20261029/extended_rerun`) already differs in session rows 76, 77, 78 (dos:blackout) and in no-grace false positives (470 committed vs 463 re-run); 5 s-grace binary rows identical: True. Note: every SIM figure here is computed from the committed decisions, not from a re-run.

## 0. Provenance per source (as each source's own metadata records it; "not recorded" = absent)

| source | claim class (source's words; field) | commit | dirty tree | config | ML | UTC (field) | note |
|---|---|---|---|---|---|---|---|
| `artifacts/benchmarks_extended` | not recorded (artifacts/benchmarks_extended/results.json: no claim class) | not recorded | not recorded | not recorded | True | not recorded (not recorded) | results.json records python 3.13.11 and the grid only |
| `artifacts/ardupilot/ap_benign_final_noml_001` | none (benign false-alarm / cost reference) (artifacts/ardupilot/ap_benign_final_noml_001/summary.json claim_class) | eae85e6ecae4... | False | configs (Stage-1 default); configs_sha256 f9f7de15a412... | False | 2026-10-10T09:52:31.487224+00:00 (provenance.collected_utc) |  |
| `artifacts/ardupilot/ap_benign_final_noml_002` | none (benign false-alarm / cost reference) (artifacts/ardupilot/ap_benign_final_noml_002/summary.json claim_class) | eae85e6ecae4... | False | configs (Stage-1 default); configs_sha256 f9f7de15a412... | False | 2026-10-10T09:54:43.297286+00:00 (provenance.collected_utc) |  |
| `artifacts/ardupilot/ap_benign_groups_001` | none (benign false-alarm / cost reference) (artifacts/ardupilot/ap_benign_groups_001/summary.json claim_class) | 9a6cd0274cd0... | True | configs (Stage-1 default); configs_sha256 f9f7de15a412... | True | 2026-10-10T06:05:00.124760+00:00 (provenance.collected_utc) |  |
| `artifacts/ardupilot/ap_benign_six_001` | none (benign false-alarm / cost reference) (artifacts/ardupilot/ap_benign_six_001/summary.json claim_class) | 9a6cd0274cd0... | True | configs (Stage-1 default); configs_sha256 f9f7de15a412... | True | 2026-10-10T05:54:21.356098+00:00 (provenance.collected_utc) |  |
| `artifacts/ardupilot/ap_benign_six_002` | none (benign false-alarm / cost reference) (artifacts/ardupilot/ap_benign_six_002/summary.json claim_class) | 9a6cd0274cd0... | True | configs (Stage-1 default); configs_sha256 f9f7de15a412... | True | 2026-10-10T05:57:45.393017+00:00 (provenance.collected_utc) |  |
| `artifacts/ardupilot/ap_benign_six_003` | none (benign false-alarm / cost reference) (artifacts/ardupilot/ap_benign_six_003/summary.json claim_class) | 9a6cd0274cd0... | True | configs (Stage-1 default); configs_sha256 f9f7de15a412... | True | 2026-10-10T06:00:10.178075+00:00 (provenance.collected_utc) |  |
| `artifacts/ardupilot/ap_benign_six_004` | none (benign false-alarm / cost reference) (artifacts/ardupilot/ap_benign_six_004/summary.json claim_class) | 9a6cd0274cd0... | True | configs (Stage-1 default); configs_sha256 f9f7de15a412... | True | 2026-10-10T06:02:35.102014+00:00 (provenance.collected_utc) |  |
| `artifacts/ardupilot/ap_attack_final_drift_001` | link-level detection (SITL); estimator and flight unaffected (artifacts/ardupilot/ap_attack_final_drift_001/evaluation.json claim_class) | eae85e6ecae4... | False | configs (Stage-1 default); configs_sha256 f9f7de15a412... | False | 2026-10-10T09:45:52.136443+00:00 (provenance.collected_utc) |  |
| `artifacts/ardupilot/ap_attack_final_drift_002` | link-level detection (SITL); estimator and flight unaffected (artifacts/ardupilot/ap_attack_final_drift_002/evaluation.json claim_class) | eae85e6ecae4... | False | configs (Stage-1 default); configs_sha256 f9f7de15a412... | False | 2026-10-10T09:48:05.369186+00:00 (provenance.collected_utc) |  |
| `artifacts/ardupilot/ap_attack_final_drift_003` | link-level detection (SITL); estimator and flight unaffected (artifacts/ardupilot/ap_attack_final_drift_003/evaluation.json claim_class) | eae85e6ecae4... | False | configs (Stage-1 default); configs_sha256 f9f7de15a412... | False | 2026-10-10T09:50:18.488602+00:00 (provenance.collected_utc) |  |
| `artifacts/sitl/live_run_002.jsonl` | none (reference / false-alarm measurement) (artifacts/sitl/P1_summary.md header (the summary covers artifacts/sitl/live_run_002.*)) | 5c009484abc5... | True | configs_sha256 f9f7de15a412... | True | 2026-10-06T07:41:05.838925+00:00 (started_utc) |  |
| `artifacts/sitl/p2_final_trial_001.manifest.json` | link-level detection (SITL) (artifacts/sitl/p2_final_trial_001.manifest.json claim_class) | eae85e6ecae4... | False | configs/px4_sitl; configs_sha256 f9f7de15a412... | model_choice px4 | 2026-10-10T09:57:24.101365+00:00 (full_provenance.collected_utc) |  |
| `artifacts/sitl/p2_final_trial_002.manifest.json` | link-level detection (SITL) (artifacts/sitl/p2_final_trial_002.manifest.json claim_class) | eae85e6ecae4... | False | configs/px4_sitl; configs_sha256 f9f7de15a412... | model_choice px4 | 2026-10-10T09:59:20.106927+00:00 (full_provenance.collected_utc) |  |
| `artifacts/sitl/p2_final_trial_003.manifest.json` | link-level detection (SITL) (artifacts/sitl/p2_final_trial_003.manifest.json claim_class) | eae85e6ecae4... | False | configs/px4_sitl; configs_sha256 f9f7de15a412... | model_choice px4 | 2026-10-10T10:01:16.081521+00:00 (full_provenance.collected_utc) |  |
| `artifacts/hardware/serial_ids_com7_001` | none (docs/HARDWARE_BENCH_PIXHAWK6X.md header (summary.json has no claim class)) | not recorded | not recorded | configs (Stage-1 default) | False | 2026-10-14T18:29:45.025829+00:00 (started_utc) | commit not in summary.json; see the BENCH row note |
| `artifacts/hardware/serial_ids_com7_002` | none (docs/HARDWARE_BENCH_PIXHAWK6X.md header (summary.json has no claim class)) | not recorded | not recorded | configs (Stage-1 default) | False | 2026-10-25T17:10:12.043821+00:00 (started_utc) | commit not in summary.json; see the BENCH row note |
| `artifacts/hardware/gps_hw_verify_20261029/live_capture` | none (receiver/estimator reports + false-alarm behaviour on one benign stream; not detection evidence) (artifacts/hardware/gps_hw_verify_20261029/manifest.json claim_class) | a44dd9c2b2e2... | run_serial_ids.py --tlog change and 2 tests uncommitted; src/ and configs/ identical to HEAD | configs (Stage-1 default); configs/detector.yaml sha256 be7876745a26... | False | 2026-10-28T20:04:26.241991+00:00 (started_utc) |  |
| `artifacts/sitl/benign_replay_stage1_default.json` | none (false-alarm reference) (artifacts/sitl/benign_replay_stage1_default.json claim_class) | not recorded | not recorded | not recorded | True | not recorded (not recorded) | model models/isoforest.joblib |
| `artifacts/external/alfa/results.json` | not recorded (artifacts/external/alfa/results.json: no claim class) | not recorded | not recorded | not recorded | not recorded | not recorded (not recorded) | experiment: E2 ALFA real MAVLink telemetry -> full AegisFlight pipeline (production config, ML on); python 3.13.11 |

## 1. False alerts per hour (alert events after cooldown, benign ground truth)

| source | set | claim class | events | exposure h | per h | 95% upper (one-sided Poisson) | decision FPR | artifact |
|---|---|---|---|---|---|---|---|---|
| SIM | benign | not recorded | 4 | 0.3833 | 10.43 | 23.88 | 0.00058 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SIM | link_fifo_benign | not recorded | 217 | 0.1917 | 1132 | 1267 | 0.6128 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SIM | link_reorder_benign | not recorded | 243 | 0.1917 | 1268 | 1410 | 0.9997 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SIM | single_attack_sessions_benign_decisions_grace5 | not recorded | 26 | 1.886 | 13.78 | 19.13 | 0.001031 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SIM | single_attack_sessions_benign_decisions_grace0 | not recorded | 53 | 1.988 | 26.66 | 33.52 | 0.01302 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SIM | combo_attack_sessions_benign_decisions_grace5 | not recorded | 4 | 0.2306 | 17.35 | 39.7 | 0.001205 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SIM | combo_attack_sessions_benign_decisions_grace0 | not recorded | 6 | 0.2426 | 24.74 | 48.82 | 0.01649 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SITL | ap_benign_final_noml_001 in_link_span | none (benign false-alarm / cost reference) | 5 | 0.03578 | 139.8 | 293.8 | 0.08851 | `artifacts/ardupilot/ap_benign_final_noml_001/decisions.jsonl` |
| SITL | ap_benign_final_noml_001 from_arm_phase | none (benign false-alarm / cost reference) | 0 | 0.03289 | 0 | 91.09 | 0.0152 | `artifacts/ardupilot/ap_benign_final_noml_001/decisions.jsonl` |
| SITL | ap_benign_final_noml_002 in_link_span | none (benign false-alarm / cost reference) | 5 | 0.03578 | 139.8 | 293.8 | 0.08851 | `artifacts/ardupilot/ap_benign_final_noml_002/decisions.jsonl` |
| SITL | ap_benign_final_noml_002 from_arm_phase | none (benign false-alarm / cost reference) | 0 | 0.03289 | 0 | 91.09 | 0.0152 | `artifacts/ardupilot/ap_benign_final_noml_002/decisions.jsonl` |
| SITL | ap_benign_groups_001 in_link_span | none (benign false-alarm / cost reference) | 38 | 0.039 | 974.4 | 1277 | 0.9957 | `artifacts/ardupilot/ap_benign_groups_001/decisions.jsonl` |
| SITL | ap_benign_groups_001 from_arm_phase | none (benign false-alarm / cost reference) | 32 | 0.03611 | 886.2 | 1190 | 1 | `artifacts/ardupilot/ap_benign_groups_001/decisions.jsonl` |
| SITL | ap_benign_six_001 in_link_span | none (benign false-alarm / cost reference) | 41 | 0.03872 | 1059 | 1374 | 0.8164 | `artifacts/ardupilot/ap_benign_six_001/decisions.jsonl` |
| SITL | ap_benign_six_001 from_arm_phase | none (benign false-alarm / cost reference) | 35 | 0.03572 | 979.8 | 1299 | 0.8056 | `artifacts/ardupilot/ap_benign_six_001/decisions.jsonl` |
| SITL | ap_benign_six_002 in_link_span | none (benign false-alarm / cost reference) | 41 | 0.039 | 1051 | 1364 | 0.8704 | `artifacts/ardupilot/ap_benign_six_002/decisions.jsonl` |
| SITL | ap_benign_six_002 from_arm_phase | none (benign false-alarm / cost reference) | 35 | 0.03583 | 976.7 | 1295 | 0.8636 | `artifacts/ardupilot/ap_benign_six_002/decisions.jsonl` |
| SITL | ap_benign_six_003 in_link_span | none (benign false-alarm / cost reference) | 41 | 0.039 | 1051 | 1364 | 0.886 | `artifacts/ardupilot/ap_benign_six_003/decisions.jsonl` |
| SITL | ap_benign_six_003 from_arm_phase | none (benign false-alarm / cost reference) | 35 | 0.03589 | 975.2 | 1293 | 0.8808 | `artifacts/ardupilot/ap_benign_six_003/decisions.jsonl` |
| SITL | ap_benign_six_004 in_link_span | none (benign false-alarm / cost reference) | 40 | 0.039 | 1026 | 1335 | 0.8846 | `artifacts/ardupilot/ap_benign_six_004/decisions.jsonl` |
| SITL | ap_benign_six_004 from_arm_phase | none (benign false-alarm / cost reference) | 34 | 0.036 | 944.4 | 1257 | 0.8796 | `artifacts/ardupilot/ap_benign_six_004/decisions.jsonl` |
| SITL | pooled ml_off@eae85e6 (2 runs) in_link_span | none (benign false-alarm / cost reference) | 10 | 0.07156 | 139.8 | 237 | 0.08851 | `artifacts/ardupilot/{ap_benign_final_noml_001,ap_benign_final_noml_002}/decisions.jsonl` |
| SITL | pooled ml_off@eae85e6 (2 runs) from_arm_phase | none (benign false-alarm / cost reference) | 0 | 0.06578 | 0 | 45.54 | 0.0152 | `artifacts/ardupilot/{ap_benign_final_noml_001,ap_benign_final_noml_002}/decisions.jsonl` |
| SITL | pooled ml_on@9a6cd02 (5 runs) in_link_span | none (benign false-alarm / cost reference) | 201 | 0.1947 | 1032 | 1160 | 0.8907 | `artifacts/ardupilot/{ap_benign_groups_001,ap_benign_six_001,ap_benign_six_002,ap_benign_six_003,ap_benign_six_004}/decisions.jsonl` |
| SITL | pooled ml_on@9a6cd02 (5 runs) from_arm_phase | none (benign false-alarm / cost reference) | 171 | 0.1796 | 952.4 | 1081 | 0.8861 | `artifacts/ardupilot/{ap_benign_groups_001,ap_benign_six_001,ap_benign_six_002,ap_benign_six_003,ap_benign_six_004}/decisions.jsonl` |
| SITL | pooled all_runs_mixed (7 runs) in_link_span | none (benign false-alarm / cost reference) | 211 | 0.2663 | 792.4 | 888.2 | 0.6752 | `artifacts/ardupilot/{ap_benign_final_noml_001,ap_benign_final_noml_002,ap_benign_groups_001,ap_benign_six_001,ap_benign_six_002,ap_benign_six_003,ap_benign_six_004}/decisions.jsonl` |
| SITL | pooled all_runs_mixed (7 runs) from_arm_phase | none (benign false-alarm / cost reference) | 171 | 0.2453 | 697 | 791.3 | 0.6526 | `artifacts/ardupilot/{ap_benign_final_noml_001,ap_benign_final_noml_002,ap_benign_groups_001,ap_benign_six_001,ap_benign_six_002,ap_benign_six_003,ap_benign_six_004}/decisions.jsonl` |
| SITL-PX4 | live_run_002 | none (reference / false-alarm measurement) | 39 | 0.03889 | 1003 | 1310 | 1 | `artifacts/sitl/live_run_002.jsonl` |
| BENCH | serial_ids_com7_001 | none | 16 | 0.01667 | 960 | 1458 | 0.9867 | `artifacts/hardware/serial_ids_com7_001/summary.json` |
| BENCH | serial_ids_com7_002 | none | 0 | 0.01667 | 0 | 179.7 | 0 | `artifacts/hardware/serial_ids_com7_002/summary.json` |
| BENCH | gps_hw_verify_20261029/live_capture | none (receiver/estimator reports + false-alarm behaviour on one benign stream; not detection evidence) | 0 | 0.025 | 0 | 119.8 | 0 | `artifacts/hardware/gps_hw_verify_20261029/live_capture/summary.json` |

SITL ArduPilot pools (runs grouped by recorded ML state and commit, see section 0):

- ml_off@eae85e6: ap_benign_final_noml_001, ap_benign_final_noml_002; stream configs six.
- ml_on@9a6cd02: ap_benign_groups_001, ap_benign_six_001, ap_benign_six_002, ap_benign_six_003, ap_benign_six_004; stream configs groups, six.
- all_runs_mixed: ap_benign_final_noml_001, ap_benign_final_noml_002, ap_benign_groups_001, ap_benign_six_001, ap_benign_six_002, ap_benign_six_003, ap_benign_six_004; stream configs groups, six. WARNING: pools ML-on and ML-off runs recorded at different commits; it describes no single detector configuration. Use the per-group pools.

SITL ArduPilot phase sets: `in_link_span` = every phase inside the link span (post_link excluded, as in summary.json); `from_arm_phase` = arm, takeoff, square, rtl, landed: excludes boot / await_gps and post_link; includes the on-ground arm phase, so it is not an in-flight figure.

BENCH runs (environment; claim class; source of that statement):

- serial_ids_com7_001: BENCH; none (`docs/HARDWARE_BENCH_PIXHAWK6X.md header (summary.json has no claim class)`). Events: summary.json alert_decisions (engine is_alert count, not re-derived); exposure = wall_s. Note: not comparable with serial_ids_com7_002: run 2026-10-14 on 6b21d1f plus uncommitted src/aegisflight/{detectors/protocol.py, features/extractor.py, sources/mavlink_serial.py} changes, on an indoor desk with no GPS fix (docs/HARDWARE_BENCH_PIXHAWK6X.md section 6.8). Of its 16 alerts, 1 (never-received streams at t = 0) would not be raised after the 2026-10-15 policy P1 (section 6.8 alert #1, section 6.5); the other 15 are the no-fix rule ("GNSS fix lost"), whose score, DOS vote and timing that policy left unchanged (section 6.5, P3.4). The GNSS state during serial_ids_com7_002 is not recorded (section 6.10), so the difference between the two runs is not attributable to the policy.
- serial_ids_com7_002: BENCH; none (`docs/HARDWARE_BENCH_PIXHAWK6X.md header (summary.json has no claim class)`). Events: summary.json alert_decisions (engine is_alert count, not re-derived); exposure = wall_s. Note: run 2026-10-25 (started_utc), after the 2026-10-15 policy date; its code commit and its GNSS state are not recorded (docs/HARDWARE_BENCH_PIXHAWK6X.md section 6.10).
- gps_hw_verify_20261029/live_capture: BENCH-class (physical ArduPilot-family quadrotor, disarmed and stationary per telemetry; props/airframe state not confirmed); none (receiver/estimator reports + false-alarm behaviour on one benign stream; not detection evidence) (`artifacts/hardware/gps_hw_verify_20261029/manifest.json claim_class`). Events: summary.json alert_decisions (engine is_alert count, not re-derived); exposure = wall_s.

REPLAY (decision level only, no alert flags logged):

- benign_001.tlog: decision FPR 1 (519/519), claim class none (false-alarm reference), `artifacts/sitl/benign_replay_stage1_default.json`
- benign_002.tlog: decision FPR 1 (537/537), claim class none (false-alarm reference), `artifacts/sitl/benign_replay_stage1_default.json`
- benign_003.tlog: decision FPR 1 (662/662), claim class none (false-alarm reference), `artifacts/sitl/benign_replay_stage1_default.json`
- benign_004.tlog: decision FPR 1 (449/449), claim class none (false-alarm reference), `artifacts/sitl/benign_replay_stage1_default.json`
- benign_005.tlog: decision FPR 1 (593/593), claim class none (false-alarm reference), `artifacts/sitl/benign_replay_stage1_default.json`

## 2. Grace (with vs without)

Grace excludes benign decisions in the 5 s after an attack stops: the recovery tail, where the detector state (residual windows, rate counters) still reflects the attack, so a threat there is late attribution of a real attack, not a false alarm on benign traffic. Both are shown; grace0 is the conservative figure.

- single grace5: 26 events / 1.886 h (13.78/h, one-sided 95% upper 19.13), decision FPR 0.001031 (`artifacts/benchmarks_extended/decisions.csv.gz`)
- single grace0: 53 events / 1.988 h (26.66/h, one-sided 95% upper 33.52), decision FPR 0.01302 (`artifacts/benchmarks_extended/decisions.csv.gz`)
- combo grace5: 4 events / 0.2306 h (17.35/h, one-sided 95% upper 39.7), decision FPR 0.001205 (`artifacts/benchmarks_extended/decisions.csv.gz`)
- combo grace0: 6 events / 0.2426 h (24.74/h, one-sided 95% upper 48.82), decision FPR 0.01649 (`artifacts/benchmarks_extended/decisions.csv.gz`)

Recomputed benign row vs `artifacts/benchmarks_extended/results.json` (benign + single sessions): {'grace5': {'recomputed': [40852, 39], 'results_json': [40852, 39], 'match': True}, 'grace0': {'recomputed': [42679, 470], 'results_json': [42679, 470], 'match': True}}.

## 3. Session-level detection (two-sided Wilson 95%) and onset latency

Claim class (`artifacts/benchmarks_extended`): not recorded. Percentiles: nearest rank, no interpolation: the median is the lower middle value for even n, and with n < 20 the nearest-rank p95 is the maximum. Detection rule: first threat decision (any type) among the decisions labelled with the attack; onset = the first labelled decision (benchmark ttd_s; sessions.csv).

| class | detected/n | rate | two-sided 95% Wilson CI | latency n | median s (nearest rank) | p95 s (nearest rank) |
|---|---|---|---|---|---|---|
| combo:dos+telemetry_manipulation | 3/3 | 1 | 0.4385-1 | 3 | 0 | max 0 (n=3) |
| combo:gps_spoofing+command_injection | 3/3 | 1 | 0.4385-1 | 3 | 1 | max 1.4 (n=3) |
| combo:gps_spoofing+mavlink_anomaly | 3/3 | 1 | 0.4385-1 | 3 | 0 | max 0 (n=3) |
| combo:telemetry_manipulation+firmware_integrity | 3/3 | 1 | 0.4385-1 | 3 | 0 | max 0 (n=3) |
| command_injection | 12/16 | 0.75 | 0.505-0.8982 | 12 | 0.2 | max 0.4 (n=12) |
| dos | 16/16 | 1 | 0.8064-1 | 16 | 0 | max 0.8 (n=16) |
| firmware_integrity | 4/4 | 1 | 0.5101-1 | 4 | 0.4 | max 0.8 (n=4) |
| gps_spoofing | 12/12 | 1 | 0.7575-1 | 12 | 0.4 | max 1.2 (n=12) |
| mavlink_anomaly | 16/16 | 1 | 0.8064-1 | 16 | 0 | max 0.4 (n=16) |
| telemetry_manipulation | 16/16 | 1 | 0.8064-1 | 16 | 0 | max 18.8 (n=16) |

Source: `artifacts/benchmarks_extended/sessions.csv`. Recomputed latency vs `ttd_s`: {'sessions_compared': 76, 'max_abs_diff_s': 0.0}.

Benign session FPR:

- benign/any_threat_decision: 4/12, two-sided Wilson 95% CI 0.1381-0.6094 (`artifacts/benchmarks_extended/sessions.csv`)
- benign/any_alert_event: 4/12, two-sided Wilson 95% CI 0.1381-0.6094 (`artifacts/benchmarks_extended/decisions.csv.gz`)
- link_fifo_benign/any_threat_decision: 6/6, two-sided Wilson 95% CI 0.6097-1 (`artifacts/benchmarks_extended/sessions.csv`)
- link_fifo_benign/any_alert_event: 6/6, two-sided Wilson 95% CI 0.6097-1 (`artifacts/benchmarks_extended/decisions.csv.gz`)
- link_reorder_benign/any_threat_decision: 6/6, two-sided Wilson 95% CI 0.6097-1 (`artifacts/benchmarks_extended/sessions.csv`)
- link_reorder_benign/any_alert_event: 6/6, two-sided Wilson 95% CI 0.6097-1 (`artifacts/benchmarks_extended/decisions.csv.gz`)

## 4. Drift latency (from onset and from release)

- sitl_ardupilot: from onset n 3 of 3, median 2.692 s, p95 max 2.694 (n=3) s; from release n 3 of 3, median -22.31 s, p95 max -22.31 (n=3) s. Detection rule: first is_alert decision (any type) in [window onset, window end + post_window_grace_s]; onset and release = evaluation.json window_decision_time onset_t_s / end_t_s (scripts/ardupilot/evaluate_ap_attack.py).
  - `artifacts/ardupilot/ap_attack_final_drift_001/evaluation.json`: onset 2.691 s, release -22.31 s; claim class link-level detection (SITL); estimator and flight unaffected
  - `artifacts/ardupilot/ap_attack_final_drift_002/evaluation.json`: onset 2.692 s, release -22.31 s; claim class link-level detection (SITL); estimator and flight unaffected
  - `artifacts/ardupilot/ap_attack_final_drift_003/evaluation.json`: onset 2.694 s, release -22.31 s; claim class link-level detection (SITL); estimator and flight unaffected
- sitl_px4: from onset n 3 of 3, median 22.49 s, p95 max 24.97 (n=3) s; from release n 3 of 3, median 1.04 s, p95 max 1.07 (n=3) s. Detection rule: first GPS_SPOOFING threat decision at or after the window end (onset_s + duration_s); onset = manifest onset_s (scripts/sitl/make_p2_summary.py load_trial; preregistered P2 rule).
  - `artifacts/sitl/p2_final_trial_001.manifest.json`: onset 16.3 s, release 0.9 s; claim class link-level detection (SITL)
  - `artifacts/sitl/p2_final_trial_002.manifest.json`: onset 24.97 s, release 1.04 s; claim class link-level detection (SITL)
  - `artifacts/sitl/p2_final_trial_003.manifest.json`: onset 22.49 s, release 1.07 s; claim class link-level detection (SITL)

## 5. Per-class precision / recall / F1 (extended benchmark)

Claim class (`artifacts/benchmarks_extended`): not recorded.

### grace5 (`artifacts/benchmarks_extended/results.json#confusion_grace5`)

| class | P | R | F1 | support |
|---|---|---|---|---|
| BENIGN | 0.973 | 0.999 | 0.9858 | 40852 |
| COMMAND_INJECTION | 1 | 0.7254 | 0.8409 | 1832 |
| DOS | 0.6122 | 0.7094 | 0.6572 | 1858 |
| FIRMWARE_INTEGRITY | 1 | 0.9941 | 0.997 | 1699 |
| GPS_SPOOFING | 0.8736 | 0.6598 | 0.7518 | 1320 |
| MAVLINK_ANOMALY | 0.6711 | 0.4937 | 0.5689 | 1752 |
| TELEMETRY_MANIPULATION | 0.9659 | 0.9165 | 0.9405 | 1760 |

Macro-F1, attack classes only (the class set of `metrics/scoring.py` `Evaluation.macro()`): 0.7927. Macro-F1 including BENIGN: 0.8203. Which one is the headline needs definition sign-off (#28 AC4).

Confusion (rows true, columns predicted):

| true \ pred | BENIGN | GPS_SPOOFING | MAVLINK_ANOMALY | COMMAND_INJECTION | TELEMETRY_MANIPULATION | DOS | FIRMWARE_INTEGRITY |
|---|---|---|---|---|---|---|---|
| BENIGN | 40813 | 0 | 0 | 0 | 39 | 0 | 0 |
| GPS_SPOOFING | 449 | 871 | 0 | 0 | 0 | 0 | 0 |
| MAVLINK_ANOMALY | 5 | 30 | 865 | 0 | 17 | 835 | 0 |
| COMMAND_INJECTION | 503 | 0 | 0 | 1329 | 0 | 0 | 0 |
| TELEMETRY_MANIPULATION | 147 | 0 | 0 | 0 | 1613 | 0 | 0 |
| DOS | 19 | 96 | 424 | 0 | 1 | 1318 | 0 |
| FIRMWARE_INTEGRITY | 10 | 0 | 0 | 0 | 0 | 0 | 1689 |

### grace0 (`artifacts/benchmarks_extended/results.json#confusion_grace0`)

| class | P | R | F1 | support |
|---|---|---|---|---|
| BENIGN | 0.9739 | 0.989 | 0.9814 | 42679 |
| COMMAND_INJECTION | 0.9287 | 0.7254 | 0.8146 | 1832 |
| DOS | 0.586 | 0.7094 | 0.6418 | 1858 |
| FIRMWARE_INTEGRITY | 1 | 0.9941 | 0.997 | 1699 |
| GPS_SPOOFING | 0.7216 | 0.6598 | 0.6894 | 1320 |
| MAVLINK_ANOMALY | 0.6674 | 0.4937 | 0.5676 | 1752 |
| TELEMETRY_MANIPULATION | 0.9567 | 0.9165 | 0.9362 | 1760 |

Macro-F1, attack classes only (the class set of `metrics/scoring.py` `Evaluation.macro()`): 0.7744. Macro-F1 including BENIGN: 0.804. Which one is the headline needs definition sign-off (#28 AC4).

Confusion (rows true, columns predicted):

| true \ pred | BENIGN | GPS_SPOOFING | MAVLINK_ANOMALY | COMMAND_INJECTION | TELEMETRY_MANIPULATION | DOS | FIRMWARE_INTEGRITY |
|---|---|---|---|---|---|---|---|
| BENIGN | 42209 | 210 | 7 | 102 | 55 | 96 | 0 |
| GPS_SPOOFING | 449 | 871 | 0 | 0 | 0 | 0 | 0 |
| MAVLINK_ANOMALY | 5 | 30 | 865 | 0 | 17 | 835 | 0 |
| COMMAND_INJECTION | 503 | 0 | 0 | 1329 | 0 | 0 | 0 |
| TELEMETRY_MANIPULATION | 147 | 0 | 0 | 0 | 1613 | 0 | 0 |
| DOS | 19 | 96 | 424 | 0 | 1 | 1318 | 0 |
| FIRMWARE_INTEGRITY | 10 | 0 | 0 | 0 | 0 | 0 | 1689 |

## 6. Accuracy (last; dominated by the benign majority)

- grace5: binary accuracy (attack = positive, as `docs/BENCHMARKING.md` defines accuracy) 0.9771 (equals `artifacts/benchmarks_extended/results.json` `binary_grace5.accuracy`: True); multiclass (attribution) accuracy 0.9496 (`artifacts/benchmarks_extended/results.json#confusion_grace5`)
- grace0: binary accuracy (attack = positive, as `docs/BENCHMARKING.md` defines accuracy) 0.9697 (equals `artifacts/benchmarks_extended/results.json` `binary_grace0.accuracy`: True); multiclass (attribution) accuracy 0.9432 (`artifacts/benchmarks_extended/results.json#confusion_grace0`)

## Missing inputs

- REPLAY data/sitl/raw/benign_00*.tlog: missing the tlogs are not committed (only their .json metadata) -> replay alert events cannot be re-derived; replay figure stays decision level
- REPLAY ALFA raw tlogs: missing external dataset not in the repository -> ALFA alert events cannot be re-derived
- REPLAY artifacts/sitl/benign_replay_stage1_default.json: missing per-decision alert flags -> decision-level FPR only
- REPLAY artifacts/external/alfa/results.json: missing per-decision alert flags -> decision-level only
- BENCH: missing any airborne exposure -> bench rate is per wall hour on a disarmed FC
- REAL flight: missing everything -> no real-flight figure exists; none is claimed

## Excluded sources (in no row or pool above)

- `artifacts/sitl/live_run_001.jsonl`: excluded from every row and pool. Reason, quoted: "An earlier run (`live_run_001`) was contaminated by an aliased 255/190 driver and is superseded." (`docs/PX4_SITL_INTEGRATION.md:85`); "the contaminated `live_run_001` (255/190 aliasing) is superseded by a clean `live_run_002` with the driver on 254/191." (`docs/STAGE2_PROGRESS.md:49`)
