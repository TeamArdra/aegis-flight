# AegisFlight — Extended synthetic benchmark v2 (generated)

_116 sessions, model used: False, wall 38.2 s. Every session has its own trajectory seed, route, speed, altitude and noise scale; every implemented attack mode is exercised with randomised onset/duration. Production thresholds and model — nothing tuned on these results._

## Binary detection (decision level, benign + single-attack sessions)

| Scoring policy | Decisions | TP / FP / TN / FN | Accuracy | Precision | Recall | FPR | F1 |
|---|---|---|---|---|---|---|---|
| **Baseline benchmark** (artifacts/benchmarks, 5 s grace) | 23430 | 6535 / 4 / 16826 / 65 | 0.9971 | 0.9994 | 0.9902 | 0.0002 | 0.9947 |
| v2, 5 s grace (baseline policy) | 51073 | 8025 / 3 / 40849 / 2196 | 0.9569 | 0.9996 | 0.7851 | 0.0001 | 0.8795 |
| v2, **no grace** | 52900 | 8025 / 355 / 42324 / 2196 | 0.9518 | 0.9576 | 0.7851 | 0.0083 | 0.8629 |
| v2, 5 s grace, excl. firmware | 48773 | 6336 / 3 / 40248 / 2186 | 0.9551 | 0.9995 | 0.7435 | 0.0001 | 0.8527 |
| v2, no grace, excl. firmware | 50600 | 6336 / 355 / 41723 / 2186 | 0.9498 | 0.9469 | 0.7435 | 0.0084 | 0.8330 |
| v2, 5 s grace, excl. known-gap mode | 48870 | 8025 / 3 / 39137 / 1705 | 0.9651 | 0.9996 | 0.8248 | 0.0001 | 0.9038 |

## Per attack mode (5 s grace)

| Mode | Sessions detected | Decision recall | Median / max time-to-detect (s) | Median post-attack alarm tail (s) | Attribution accuracy |
|---|---|---|---|---|---|
| `command_injection:arm_disarm_burst` | 4/4 | 98.82 % | 0.30 / 0.40 | 1.70 | 100.00 % |
| `command_injection:gcs_replay` ⚠ known gap | 0/4 | 0.00 % | — / — | 0.00 | — |
| `command_injection:mode_flip` | 4/4 | 99.57 % | 0.10 / 0.20 | 1.80 | 100.00 % |
| `command_injection:rogue_command` | 4/4 | 98.88 % | 0.20 / 0.40 | 1.60 | 100.00 % |
| `dos:blackout` | 4/4 | 74.95 % | 3.50 / 4.20 | 1.10 | 87.77 % |
| `dos:flood` | 4/4 | 99.58 % | 0.10 / 0.20 | 1.00 | 100.00 % |
| `dos:gnss_jamming` | 4/4 | 96.61 % | 0.80 / 0.80 | 0.00 | 100.00 % |
| `dos:latency` | 0/4 | 0.00 % | — / — | 0.00 | — |
| `firmware_integrity:default` | 4/4 | 99.41 % | 0.50 / 0.80 | 0.00 | 100.00 % |
| `gps_spoofing:gradual_drift` | 4/4 | 89.28 % | 2.30 / 2.40 | 3.00 | 100.00 % |
| `gps_spoofing:replay_freeze` | 4/4 | 93.99 % | 1.20 / 1.60 | 3.00 | 100.00 % |
| `gps_spoofing:sudden_offset` | 4/4 | 12.00 % | 0.20 / 0.20 | 3.00 | 100.00 % |
| `mavlink_anomaly:packet_loss` | 4/4 | 14.23 % | 9.00 / 20.80 | 0.60 | 0.00 % |
| `mavlink_anomaly:rate_spike` | 4/4 | 97.98 % | 0.40 / 0.40 | 0.60 | 0.00 % |
| `mavlink_anomaly:rogue_sysid` | 4/4 | 100.00 % | 0.00 / 0.00 | 0.20 | 100.00 % |
| `mavlink_anomaly:seq_scramble` | 4/4 | 96.67 % | 0.00 / 0.00 | 0.00 | 100.00 % |
| `telemetry_manipulation:altitude_bias` | 4/4 | 99.10 % | 0.20 / 0.20 | 0.00 | 100.00 % |
| `telemetry_manipulation:battery_jump` | 4/4 | 98.31 % | 0.40 / 0.40 | 0.80 | 100.00 % |
| `telemetry_manipulation:frozen_attitude` | 4/4 | 66.01 % | 5.20 / 19.60 | 0.00 | 100.00 % |
| `telemetry_manipulation:speed_mismatch` | 4/4 | 99.10 % | 0.20 / 0.20 | 0.00 | 100.00 % |

## Benign sessions (false alarms)

| Condition | Sessions | Decisions | FP decisions | FPR | Sessions with ≥1 FP | FP classes |
|---|---|---|---|---|---|---|
| `benign` | 12 | 6900 | 0 | 0.00 % | 0 | `{}` |
| `link_fifo_benign` | 6 | 3450 | 1 | 0.03 % | 1 | `{"TELEMETRY_MANIPULATION": 1}` |
| `link_reorder_benign` | 6 | 3450 | 0 | 0.00 % | 0 | `{}` |

_Link stress conditions: `{"link_fifo_benign": {"mean_delay_ms": 25.0, "loss_prob": 0.02, "fifo": true}, "link_reorder_benign": {"mean_delay_ms": 25.0, "loss_prob": 0.02, "fifo": false}}`_

## Simultaneous attacks (multi-label ground truth)

| Combination | Sessions | In-window decisions | Binary recall | Primary ∈ truth | All active classes reported (both active) |
|---|---|---|---|---|---|
| `gps_spoofing+mavlink_anomaly` | 3 | 341 | 100.00 % | 100.00 % | 96.48 % |
| `gps_spoofing+command_injection` | 3 | 409 | 92.18 % | 90.22 % | 99.61 % |
| `dos+telemetry_manipulation` | 3 | 441 | 99.77 % | 99.77 % | 100.00 % |
| `telemetry_manipulation+firmware_integrity` | 3 | 1343 | 99.78 % | 99.78 % | 95.10 % |

_Prediction set for a decision = fused primary class ∪ `secondary_indicators`. The fusion emits one primary label; secondary indicators are ≥25 % of the primary vote._

Compute: mean 1.11 ms/decision (mean of session means), worst session p95 7.28 ms.
