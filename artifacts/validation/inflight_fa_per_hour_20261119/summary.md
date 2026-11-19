# In-Flight False Alerts Per Hour on Real-Rate SITL Links (Issue #49)

- **Environment tag:** `SITL` (ArduCopter 4.7.1 SITL & PX4 `v1.18.0-rc1` + Gazebo Harmonic `gz_x500` SITL)
- **Claim class:** link-level detection (false-alarm reference on benign SITL streams and link-level drift detection; not flight-hour or real-vehicle validation)
- **Command:** `python scripts/evaluate_inflight_fa_per_hour.py`
- **Held-out lock:** `artifacts/ardupilot/calibration/heldout_lock.json` (`held_out_burned: False`)

## 1. Before vs. After Per-Hour False-Alert Table (with Per-Detector Attribution)

| Stack & Condition | Phase Window | Events | Exposure (h) | FA / h | 95% Poisson Upper (/h) | Decision FPR | Per-Detector Attribution (events) | Source Artifact |
|---|---|---:|---:|---:|---:|---:|---|---|
| **ArduPilot SITL — Before** (Stage-1 config, ML on, 5 runs) | `in_link_span` (all) | 201 | 0.19472 | 1032.24 | 1160.28 | 0.89073 | `{'protocol_rule': 5, 'physics_consistency': 5, 'ml_anomaly+protocol_rule': 10, 'ml_anomaly+physics_consistency': 10, 'ml_anomaly': 171}` | `artifacts/ardupilot/{ap_benign_six_001,ap_benign_six_002,ap_benign_six_003,ap_benign_six_004,ap_benign_groups_001}/decisions.jsonl` |
| **ArduPilot SITL — Before** (Stage-1 config, ML on, 5 runs) | `from_arm_phase` (post-boot) | 171 | 0.17956 | 952.35 | 1081.14 | 0.88614 | `{'ml_anomaly': 171}` | `artifacts/ardupilot/{ap_benign_six_001,ap_benign_six_002,ap_benign_six_003,ap_benign_six_004,ap_benign_groups_001}/decisions.jsonl` |
| **ArduPilot SITL — Before** (Stage-1 config, ML on, 5 runs) | `airborne_only` (`takeoff/square/rtl`) | 120 | 0.12228 | 981.37 | 1142.02 | 0.91595 | `{'ml_anomaly': 120}` | `artifacts/ardupilot/{ap_benign_six_001,ap_benign_six_002,ap_benign_six_003,ap_benign_six_004,ap_benign_groups_001}/decisions.jsonl` |
| **ArduPilot SITL — Before** (Stage-1 config, ML off, 2 runs) | `in_link_span` (all) | 10 | 0.07156 | 139.75 | 237.05 | 0.08851 | `{'protocol_rule': 6, 'physics_consistency+protocol_rule': 2, 'physics_consistency': 2}` | `artifacts/ardupilot/{ap_benign_final_noml_001,ap_benign_final_noml_002}/decisions.jsonl` |
| **ArduPilot SITL — Before** (Stage-1 config, ML off, 2 runs) | `from_arm_phase` (post-boot) | 0 | 0.06578 | 0.0 | 45.54 | 0.0152 | `{}` | `artifacts/ardupilot/{ap_benign_final_noml_001,ap_benign_final_noml_002}/decisions.jsonl` |
| **ArduPilot SITL — Before** (Stage-1 config, ML off, 2 runs) | `airborne_only` (`takeoff/square/rtl`) | 0 | 0.04444 | 0.0 | 67.4 | 0.0 | `{}` | `artifacts/ardupilot/{ap_benign_final_noml_001,ap_benign_final_noml_002}/decisions.jsonl` |
| **ArduPilot SITL — After** (`configs/ardupilot_copter`, Calib 3 runs) | `in_link_span` (all) | 14 | 0.1135 | 123.35 | 192.83 | 0.07734 | `{'physics_consistency': 7, 'protocol_rule': 6, 'physics_consistency+protocol_rule': 1}` | `artifacts/ardupilot/calibration/evaluation_calib.json` |
| **ArduPilot SITL — After** (`configs/ardupilot_copter`, Calib 3 runs) | `from_arm_phase` (post-boot) | **0** | 0.10444 | **0.0** | **28.68** | 0.01649 | `{}` | `artifacts/ardupilot/calibration/evaluation_calib.json` |
| **ArduPilot SITL — After** (`configs/ardupilot_copter`, Calib 3 runs) | `airborne_only` (`takeoff/square/rtl`) | **0** | 0.0705 | **0.0** | **42.49** | 0.0 | `{}` | `artifacts/ardupilot/calibration/evaluation_calib.json` |
| **ArduPilot SITL — After** (`configs/ardupilot_copter`, **Held-out 4 runs**) | `in_link_span` (all) | 19 | 0.15278 | 124.36 | 182.48 | 0.07673 | `{'physics_consistency': 10, 'protocol_rule': 8, 'physics_consistency+protocol_rule': 1}` | `artifacts/ardupilot/calibration/evaluation_heldout.json` |
| **ArduPilot SITL — After** (`configs/ardupilot_copter`, **Held-out 4 runs**) | `from_arm_phase` (post-boot) | **0** | 0.14089 | **0.0** | **21.26** | 0.01814 | `{}` | `artifacts/ardupilot/calibration/evaluation_heldout.json` |
| **ArduPilot SITL — After** (`configs/ardupilot_copter`, **Held-out 4 runs**) | `airborne_only` (`takeoff/square/rtl`) | **0** | 0.09622 | **0.0** | **31.13** | 0.0 | `{}` | `artifacts/ardupilot/calibration/evaluation_heldout.json` |
| **ArduPilot SITL — After** (`configs/ardupilot_copter`, Pooled 7 runs) | `from_arm_phase` (post-boot) | **0** | 0.24533 | **0.0** | **12.21** | 0.01744 | `{}` | `artifacts/ardupilot/{ap_benign_six_001,ap_benign_six_002,ap_benign_six_003,ap_benign_six_004,ap_benign_groups_001,ap_benign_final_noml_001,ap_benign_final_noml_002}/decisions.jsonl` |
| **ArduPilot SITL — After** (`configs/ardupilot_copter`, Pooled 7 runs) | `airborne_only` (`takeoff/square/rtl`) | **0** | 0.16672 | **0.0** | **17.97** | 0.0 | `{}` | `artifacts/ardupilot/{ap_benign_six_001,ap_benign_six_002,ap_benign_six_003,ap_benign_six_004,ap_benign_groups_001,ap_benign_final_noml_001,ap_benign_final_noml_002}/decisions.jsonl` |
| **ArduPilot SITL — After** (Forced Stage-1 ML + `ml_require_corroboration: true`, 5 runs) | `from_arm_phase` / `airborne_only` | **0 / 0** | 0.17956 / 0.12228 | **0.0 / 0.0** | **16.68 / 24.5** | 0.0 | `{}` | `artifacts/ardupilot/{ap_benign_six_001,ap_benign_six_002,ap_benign_six_003,ap_benign_six_004,ap_benign_groups_001}/decisions.jsonl` |
| **PX4 SITL — Before** (Cond A: Stage-1 config + Stage-1 ML, Calib 5 flights) | `all_phases` | 132 | 0.15333 | 860.87 | 994.7 | 1.0 | `{'protocol_rule': 95, 'ml_anomaly+protocol_rule': 2530, 'ml_anomaly+physics_consistency+protocol_rule': 135}` | `artifacts/sitl/calibration/evaluation_calib.json` |
| **PX4 SITL — Before** (Cond A: Stage-1 config + Stage-1 ML, Held-out 5 flights) | `all_phases` | 133 | 0.15583 | 853.48 | 985.62 | 1.0 | `{'protocol_rule': 95, 'ml_anomaly+protocol_rule': 2572, 'ml_anomaly+physics_consistency+protocol_rule': 138}` | `artifacts/sitl/calibration/evaluation_heldout.json` |
| **PX4 SITL — After** (Cond B: `configs/px4_sitl`, ML off, Calib 5 flights) | `all_phases` / `airborne_only` | 2 / **2** | 0.15333 / 0.12078 | 13.04 / **16.56** | 41.06 / **52.13** | 0.00072 / 0.00092 | `{'protocol_rule': 2}` | `artifacts/sitl/calibration/evaluation_calib.json` |
| **PX4 SITL — After** (Cond B: `configs/px4_sitl`, ML off, **Held-out 5 flights**) | `all_phases` / `airborne_only` | **1 / 0** | 0.15583 / 0.12317 | **6.42 / 0.0** | **30.44 / 24.32** | 0.00036 / 0.0 | `{'protocol_rule': 1}` | `artifacts/sitl/calibration/evaluation_heldout.json` |
| **PX4 SITL — After** (Cond C: `configs/px4_sitl` + PX4 ML, Calib 5 flights) | `all_phases` / `airborne_only` | 2 / **2** | 0.15333 / 0.12078 | 13.04 / **16.56** | 41.06 / **52.13** | 0.00072 / 0.00092 | `{'ml_anomaly+protocol_rule': 2}` | `artifacts/sitl/calibration/evaluation_calib.json` |
| **PX4 SITL — After** (Cond C: `configs/px4_sitl` + PX4 ML, **Held-out 5 flights**) | `all_phases` / `airborne_only` | **1 / 0** | 0.15583 / 0.12317 | **6.42 / 0.0** | **30.44 / 24.32** | 0.00036 / 0.0 | `{'ml_anomaly+protocol_rule': 1}` | `artifacts/sitl/calibration/evaluation_heldout.json` |

## 2. Root-Cause Diagnosis Confirmed by Step 1

- Across all 5 ML-on ArduPilot SITL benign runs (`ap_benign_six_001..004`, `ap_benign_groups_001`), **171 of 171 (`100.0 %`) post-boot (`from_arm_phase`) alert events and 120 of 120 (`100.0 %`) airborne (`takeoff`/`square`/`rtl`) alert events** had `detector_scores = {"protocol_rule": 0.0, "physics_consistency": 0.0, "ml_anomaly": 0.96..1.00, "firmware_integrity": 0.0}`.
- The Stage-1 Isolation Forest (`AnomalyDetector`, trained on zero-delay in-process simulator trajectories) scores normal SITL pipe/socket scheduling jitter (`interarrival_jitter_ms`, `z = +7..+15`) above `0.95625`, crossing `fusion.threat_threshold = 0.45` (`w_ml = 0.16 / 0.34 = 0.4706`) with **zero corroboration** from protocol, physics, or integrity detectors.
- Under `configs/ardupilot_copter` (`anomaly.enabled: false` + `fusion.ml_require_corroboration: true`), in-flight (`from_arm_phase` and `airborne_only`) false alerts drop to **0 events (`0.0 / h`)** on both the calibration set and the frozen held-out set, while Stage-1 defaults (`configs/detector.yaml`) remain untouched (`6535 / 4 / 16826 / 65`).

## 3. ArduPilot Position-Drift Attack Regression Check (`configs/ardupilot_copter`)

| Trial | Window (s) | Baseline Detected | Baseline Onset Latency (s) | Profile Detected | Profile Onset Latency (s) | Latency Delta (s) | Pre-Onset In-Flight FAs |
|---|---|---|---:|---|---:|---:|---:|
| `ap_attack_final_drift_001` | `56.7..91.7` | `True` | `2.69` | **`True`** | **`2.69`** | **`+0.00`** | **`0`** |
| `ap_attack_final_drift_002` | `56.7..91.7` | `True` | `2.69` | **`True`** | **`2.69`** | **`+0.00`** | **`0`** |
| `ap_attack_final_drift_003` | `56.7..91.7` | `True` | `2.69` | **`True`** | **`2.69`** | **`+0.00`** | **`0`** |
| `ap_attack_drift_001` | `61.2..96.2` | `True` | `2.81` | **`True`** | **`2.81`** | **`+0.00`** | **`0`** |
| `ap_attack_drift_002` | `61.1..96.1` | `True` | `2.87` | **`True`** | **`2.87`** | **`+0.00`** | **`1`** |
| `ap_attack_drift_003` | `61.1..96.1` | `True` | `2.72` | **`True`** | **`2.72`** | **`+0.00`** | **`0`** |
