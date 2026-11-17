# Stage 2 metrics

Definitions: `src/aegisflight/metrics/stage2.py; docs/BENCHMARKING.md#stage-2-metrics`. Decision period 0.2 s.

**Claim class (every SIM / SITL / REPLAY figure): link-level detection (false-alarm reference); not flight-hour or real-world validation.** BENCH: link-level detection on a disarmed, props-off bench FC; exposure is wall time, not flight time. No figure here is real-flight evidence.

## 1. False alerts per hour (alert events after cooldown, benign ground truth)

| source | set | events | exposure h | per h | 95% upper | decision FPR | artifact |
|---|---|---|---|---|---|---|---|
| SIM | benign | 4 | 0.3833 | 10.43 | 23.88 | 0.00058 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SIM | link_fifo_benign | 217 | 0.1917 | 1132 | 1267 | 0.6128 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SIM | link_reorder_benign | 243 | 0.1917 | 1268 | 1410 | 0.9997 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SIM | single_attack_sessions_benign_decisions_grace5 | 26 | 1.886 | 13.78 | 19.13 | 0.001031 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SIM | single_attack_sessions_benign_decisions_grace0 | 54 | 1.988 | 27.17 | 34.08 | 0.01302 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SIM | combo_attack_sessions_benign_decisions_grace5 | 4 | 0.2306 | 17.35 | 39.7 | 0.001205 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SIM | combo_attack_sessions_benign_decisions_grace0 | 6 | 0.2426 | 24.74 | 48.82 | 0.01649 | `artifacts/benchmarks_extended/decisions.csv.gz` |
| SITL | ap_benign_final_noml_001 all | 5 | 0.03578 | 139.8 | 293.8 | 0.08851 | `artifacts/ardupilot/ap_benign_final_noml_001/decisions.jsonl` |
| SITL | ap_benign_final_noml_001 armed | 0 | 0.03289 | 0 | 91.09 | 0.0152 | `artifacts/ardupilot/ap_benign_final_noml_001/decisions.jsonl` |
| SITL | ap_benign_final_noml_002 all | 5 | 0.03578 | 139.8 | 293.8 | 0.08851 | `artifacts/ardupilot/ap_benign_final_noml_002/decisions.jsonl` |
| SITL | ap_benign_final_noml_002 armed | 0 | 0.03289 | 0 | 91.09 | 0.0152 | `artifacts/ardupilot/ap_benign_final_noml_002/decisions.jsonl` |
| SITL | ap_benign_groups_001 all | 38 | 0.039 | 974.4 | 1277 | 0.9957 | `artifacts/ardupilot/ap_benign_groups_001/decisions.jsonl` |
| SITL | ap_benign_groups_001 armed | 32 | 0.03611 | 886.2 | 1190 | 1 | `artifacts/ardupilot/ap_benign_groups_001/decisions.jsonl` |
| SITL | ap_benign_six_001 all | 41 | 0.03872 | 1059 | 1374 | 0.8164 | `artifacts/ardupilot/ap_benign_six_001/decisions.jsonl` |
| SITL | ap_benign_six_001 armed | 35 | 0.03572 | 979.8 | 1299 | 0.8056 | `artifacts/ardupilot/ap_benign_six_001/decisions.jsonl` |
| SITL | ap_benign_six_002 all | 41 | 0.039 | 1051 | 1364 | 0.8704 | `artifacts/ardupilot/ap_benign_six_002/decisions.jsonl` |
| SITL | ap_benign_six_002 armed | 35 | 0.03583 | 976.7 | 1295 | 0.8636 | `artifacts/ardupilot/ap_benign_six_002/decisions.jsonl` |
| SITL | ap_benign_six_003 all | 41 | 0.039 | 1051 | 1364 | 0.886 | `artifacts/ardupilot/ap_benign_six_003/decisions.jsonl` |
| SITL | ap_benign_six_003 armed | 35 | 0.03589 | 975.2 | 1293 | 0.8808 | `artifacts/ardupilot/ap_benign_six_003/decisions.jsonl` |
| SITL | ap_benign_six_004 all | 40 | 0.039 | 1026 | 1335 | 0.8846 | `artifacts/ardupilot/ap_benign_six_004/decisions.jsonl` |
| SITL | ap_benign_six_004 armed | 34 | 0.036 | 944.4 | 1257 | 0.8796 | `artifacts/ardupilot/ap_benign_six_004/decisions.jsonl` |
| SITL | pooled all_phases | 211 | 0.2663 | 792.4 | 888.2 | 0.6752 | `artifacts/ardupilot/{ap_benign_final_noml_001,ap_benign_final_noml_002,ap_benign_groups_001,ap_benign_six_001,ap_benign_six_002,ap_benign_six_003,ap_benign_six_004}/decisions.jsonl` |
| SITL | pooled armed_phases | 171 | 0.2453 | 697 | 791.3 | 0.6526 | `artifacts/ardupilot/{ap_benign_final_noml_001,ap_benign_final_noml_002,ap_benign_groups_001,ap_benign_six_001,ap_benign_six_002,ap_benign_six_003,ap_benign_six_004}/decisions.jsonl` |
| SITL-PX4 | live_run_001 | 35 | 0.0375 | 933.3 | 1237 | 1 | `artifacts/sitl/live_run_001.jsonl` |
| SITL-PX4 | live_run_002 | 39 | 0.03889 | 1003 | 1310 | 1 | `artifacts/sitl/live_run_002.jsonl` |
| BENCH | serial_ids_com7_001 | 16 | 0.01667 | 960 | 1458 | 0.9867 | `artifacts/hardware/serial_ids_com7_001/summary.json` |
| BENCH | serial_ids_com7_002 | 0 | 0.01667 | 0 | 179.7 | 0 | `artifacts/hardware/serial_ids_com7_002/summary.json` |

REPLAY (decision level only, no alert flags logged):

- benign_001.tlog: decision FPR 1 (519/519), `artifacts/sitl/benign_replay_stage1_default.json`
- benign_002.tlog: decision FPR 1 (537/537), `artifacts/sitl/benign_replay_stage1_default.json`
- benign_003.tlog: decision FPR 1 (662/662), `artifacts/sitl/benign_replay_stage1_default.json`
- benign_004.tlog: decision FPR 1 (449/449), `artifacts/sitl/benign_replay_stage1_default.json`
- benign_005.tlog: decision FPR 1 (593/593), `artifacts/sitl/benign_replay_stage1_default.json`

## 2. Grace (with vs without)

Grace excludes benign decisions in the 5 s after an attack stops: the recovery tail, where the detector state (residual windows, rate counters) still reflects the attack, so a threat there is late attribution of a real attack, not a false alarm on benign traffic. Both are shown; grace0 is the conservative figure.

- single grace5: 26 events / 1.886 h (13.78/h, upper 19.13), decision FPR 0.001031
- single grace0: 54 events / 1.988 h (27.17/h, upper 34.08), decision FPR 0.01302
- combo grace5: 4 events / 0.2306 h (17.35/h, upper 39.7), decision FPR 0.001205
- combo grace0: 6 events / 0.2426 h (24.74/h, upper 48.82), decision FPR 0.01649

Recomputed benign row vs `artifacts/benchmarks_extended/results.json` (benign + single sessions): {'grace5': {'recomputed': [40852, 39], 'results_json': [40852, 39], 'match': True}, 'grace0': {'recomputed': [42679, 470], 'results_json': [42679, 470], 'match': True}}.

## 3. Session-level detection (Wilson 95%) and onset latency

| class | detected/n | rate | 95% CI | latency n | median s | p95 s |
|---|---|---|---|---|---|---|
| combo:dos+telemetry_manipulation | 3/3 | 1 | 0.4385-1 | 3 | 0 | 0 |
| combo:gps_spoofing+command_injection | 3/3 | 1 | 0.4385-1 | 3 | 1 | 1.4 |
| combo:gps_spoofing+mavlink_anomaly | 3/3 | 1 | 0.4385-1 | 3 | 0 | 0 |
| combo:telemetry_manipulation+firmware_integrity | 3/3 | 1 | 0.4385-1 | 3 | 0 | 0 |
| command_injection | 12/16 | 0.75 | 0.505-0.8982 | 12 | 0.2 | 0.4 |
| dos | 16/16 | 1 | 0.8064-1 | 16 | 0 | 0.8 |
| firmware_integrity | 4/4 | 1 | 0.5101-1 | 4 | 0.4 | 0.8 |
| gps_spoofing | 12/12 | 1 | 0.7575-1 | 12 | 0.4 | 1.2 |
| mavlink_anomaly | 16/16 | 1 | 0.8064-1 | 16 | 0 | 0.4 |
| telemetry_manipulation | 16/16 | 1 | 0.8064-1 | 16 | 0 | 18.8 |

Source: `artifacts/benchmarks_extended/sessions.csv`. Recomputed latency vs `ttd_s`: {'sessions_compared': 76, 'max_abs_diff_s': 0.0}.

Benign session FPR:

- benign/any_threat_decision: 4/12, CI 0.1381-0.6094 (`artifacts/benchmarks_extended/sessions.csv`)
- benign/any_alert_event: 4/12, CI 0.1381-0.6094 (`artifacts/benchmarks_extended/decisions.csv.gz`)
- link_fifo_benign/any_threat_decision: 6/6, CI 0.6097-1 (`artifacts/benchmarks_extended/sessions.csv`)
- link_fifo_benign/any_alert_event: 6/6, CI 0.6097-1 (`artifacts/benchmarks_extended/decisions.csv.gz`)
- link_reorder_benign/any_threat_decision: 6/6, CI 0.6097-1 (`artifacts/benchmarks_extended/sessions.csv`)
- link_reorder_benign/any_alert_event: 6/6, CI 0.6097-1 (`artifacts/benchmarks_extended/decisions.csv.gz`)

## 4. Drift latency (from onset and from release)

- sitl_ardupilot: from onset {'n': 3, 'of': 3, 'median': 2.692, 'p95': 2.694}, from release {'n': 3, 'of': 3, 'median': -22.308, 'p95': -22.306}
  - `artifacts/ardupilot/ap_attack_final_drift_001/evaluation.json`: onset 2.691 s, release -22.31 s
  - `artifacts/ardupilot/ap_attack_final_drift_002/evaluation.json`: onset 2.692 s, release -22.31 s
  - `artifacts/ardupilot/ap_attack_final_drift_003/evaluation.json`: onset 2.694 s, release -22.31 s
- sitl_px4: from onset {'n': 3, 'of': 3, 'median': 22.49, 'p95': 24.97}, from release {'n': 3, 'of': 3, 'median': 1.04, 'p95': 1.07}
  - `artifacts/sitl/p2_final_trial_001.manifest.json`: onset 16.3 s, release 0.9 s
  - `artifacts/sitl/p2_final_trial_002.manifest.json`: onset 24.97 s, release 1.04 s
  - `artifacts/sitl/p2_final_trial_003.manifest.json`: onset 22.49 s, release 1.07 s

## 5. Per-class precision / recall / F1 (extended benchmark)

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

Macro-F1 0.8203.

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

Macro-F1 0.804.

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

- grace5: 0.9496 (`artifacts/benchmarks_extended/results.json#confusion_grace5`)
- grace0: 0.9432 (`artifacts/benchmarks_extended/results.json#confusion_grace0`)

## Missing inputs

- REPLAY data/sitl/raw/benign_00*.tlog: missing the tlogs are not committed (only their .json metadata) -> replay alert events cannot be re-derived; replay figure stays decision level
- REPLAY ALFA raw tlogs: missing external dataset not in the repository -> ALFA alert events cannot be re-derived
- REPLAY artifacts/sitl/benign_replay_stage1_default.json: missing per-decision alert flags -> decision-level FPR only
- REPLAY artifacts/external/alfa/results.json: missing per-decision alert flags -> decision-level only
- BENCH: missing any airborne exposure -> bench rate is per wall hour on a disarmed FC
- REAL flight: missing everything -> no real-flight figure exists; none is claimed
