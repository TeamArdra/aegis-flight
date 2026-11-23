# AegisFlight — Configuration

All tunables live in `configs/*.yaml` and are deep-merged over built-in defaults
by `config.py` (`load_config()`), so the package works even with no YAML present.
Flow: `configs/*.yaml` → `AegisConfig` (`simulation`, `message_rates`,
`detector`, `attacks`) → consumed by simulator / encoder / detectors / fusion.

## `configs/simulation.yaml`
| Key | Default | Unit | Effect | Safe range |
|---|---|---|---|---|
| `seed` | 42 | — | determinism | any int |
| `sample_rate_hz` | 10 | Hz | simulator tick rate | 5–50 |
| `duration_s` | 120 | s | session length | 30–600 |
| `home.{lat,lon,alt_msl}` | IIT-B | deg/m | takeoff point | any valid |
| `cruise_alt_m` | 60 | m | target altitude | 20–120 |
| `cruise_speed_ms` | 12 | m/s | nominal speed | 5–20 |
| `route` | survey_box | — | survey_box\|out_and_back\|perimeter | — |
| `noise.*` | see file | m,m/s,rad | sensor noise σ | keep small |
| `message_rates.*` | see file | ticks | per-message decimation | ≥1 |

**Danger:** changing `noise.*`, `cruise_*`, or `sample_rate_hz` shifts the
feature distribution → **retrain the ML model** (`aegis train`) and re-benchmark.

## `configs/detector.yaml`
- `decision_rate_hz` (5) — fusion cadence. Compute budget per decision =
  1000/rate ms (200 ms at 5 Hz); we run ≪ that.
- `features.reorder_window` (16, range `0..127`) — per-source MAVLink 8-bit sequence
  reorder tolerance behind the high-water mark. Late frames within `1..R` steps
  increment `FeatureFrame.reorder_count` instead of recording a `256 - k` gap.
  Security note: replays within `R` frames are counted as reorder; MAVLink-2 signing
  and command-cadence checks still apply. `configs/universal_flight` sets 24 as a **candidate (24); not validated until a fresh
  SITL rerun**. The only evidence, `artifacts/sitl/px4_netem_reorder_window/README.md`, was computed at 48 and is
  superseded pending that rerun (PX4 SITL under 40 +/- 20 ms jitter: 195 and 112 benign alerts at 16, 0 and 0 at 48;
  simulator `seq_scramble` recall 0.966 -> 0.911 at 48); nothing was measured at 24.
- `protocol.*` — expected sysids/compids, `max_msg_rate_hz` (400),
  `nominal_msg_rate_hz` (28), `msg_rate_spike_factor` (3), `max_seq_gap` (30),
  `heartbeat_timeout_s` (3), `gps_dropout_s` (2), sensitive commands, burst
  limits, `require_signing`, `signing_settle_s` (default `0.0` — immediate enforcement
  with no unauthenticated blind settle window; opt-in `> 0` only if needed),
  `unsigned_allowed` (default `[]` — no source exempt unless explicitly pinned),
  `gnss_never_acquired_policy`
  (`coverage` | `dos`; default `coverage` for D4 never-acquired GNSS policy), `startup_grace_s`
  (0; optional - ignore the "no heartbeat/GPS seen yet" sentinel for the first N seconds).
- `physics.*` — `gps_pos_residual_m` (12) + hard (30), `gps_speed_consistency_ms`
  (5), `alt_consistency_m` (8), `alt_jump_ms` (25), `max_accel_ms2` (20),
  `battery_rise_v` (0.4), `battery_drop_rate_v_s` (2), `hysteresis_ticks` (2),
  `yaw_course_deg` (25; optional key - previously a hard-coded constant),
  `estimator_gate` (true; optional key, 2026-10-25, v2 2026-10-26). It is inert only while no
  `EKF_STATUS_REPORT` is received; the report is unauthenticated, so an injected one can activate
  it (it needs ≥ 2 s of sustained no-solution reports). A fix is gated when a fresh report says no
  horizontal solution and the reports have said so continuously for ≥ 2 s. At gated fixes the
  position residual is degraded navigation, not spoofing; velocity-implied movement the position
  does not show uses the residual thresholds, and one residual increment |Δp − v·dt| ≥ the hard
  threshold (a step the velocity does not account for) alerts.
  Other fixes use the Stage-1 rule. No new threshold. It needs reports at least every 2 s; slower
  links never gate. `false` = the Stage-1 rule
  (`docs/DETECTION.md`, "Estimator-aware position residual").
- `anomaly.*` — `model_path`, `score_threshold` (0.62), `contamination` (0.02),
  `n_estimators` (200), `warmup_ticks` (20).
- `fusion.*` — `weights` (protocol 0.30 / physics 0.34 / ml 0.16 / firmware
  0.20), `threat_threshold` (0.45), `severity_bands`, `alert_threshold_severity`
  (SUSPICIOUS), `cooldown_s` (4), `clear_ticks` (4).

**Danger — detector thresholds are the accuracy/FPR trade-off.** Lowering
`gps_pos_residual_m`, `alt_consistency_m`, etc. raises recall but risks false
positives; raising `msg_rate_spike_factor` or `max_seq_gap` reduces DoS
sensitivity. Fusion `weights` are max-normalised (relative trust); `n_estimators`
must match the trained model's metadata.

## `configs/px4_sitl/detector.yaml` (per-vehicle profile, overrides only)
A **separate, generated** profile for PX4 SITL (`load_config("configs/px4_sitl")`); Stage-1
`configs/detector.yaml` is the reference condition and is never edited for it. Every override
is derived from the benign calibration flights and commented with its evidence; see
`docs/CALIBRATION_PX4.md`. It reduces benign false alarms on that stack only - it is not
attack detection and not valid for the simulator or other vehicles.

## `configs/attacks.yaml`
Per-scenario `mode`, `start_s`, `duration_s`, and mode-specific magnitudes (e.g.
GPS `drift_rate_ms`, telemetry `altitude_bias_m`, DoS `flood_multiplier`,
firmware `tamper_component`). These drive the benchmark's ground-truth windows
and the simulated attack strength; they do **not** affect the live dashboard's
runtime-injected attacks (those activate from "now").

## `configs/firmware_allowlist.yaml`
Pinned `AUTOPILOT_VERSION` allowlist entries (`sysid`, `compid`, `flight_sw_version`,
`flight_custom_version`, `board_version`, `vendor_id`, `product_id`, `uid`) checked
against live/replay links (`integrity/allowlist.py`). Supports optional `hmac_sha256`
signing verified against `AEGIS_ALLOWLIST_KEY` (fail closed on mismatch or missing key;
unsigned files load with a warning). **Note (unsigned in this PoC):** the shipped
`configs/firmware_allowlist.yaml` is an **unsigned, empty (`vehicles: []`) PoC template**;
on unsigned MAVLink links, `AUTOPILOT_VERSION` remains unauthenticated telemetry until
hardware IDs are pinned and HMAC signing (`AEGIS_ALLOWLIST_KEY`) is enabled.

## Notes
- Config is **not** hot-reloaded: restart the process / re-run after edits.
- Built-in defaults in `config.py` mirror the YAML exactly, so deleting a YAML
  file falls back to the documented default rather than breaking.
- `configs/universal_flight/detector.yaml` enables hardware-agnostic online ground baro bias calibration,
  Control Semantics (*ConstDet*), GNSS clock-skew detection, airborne semantic firewall detection,
  and `yaw_course_auto` while leaving base `configs/detector.yaml` untouched for Stage-1 equivalence.
