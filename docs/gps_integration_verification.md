# GPS integration verification (local, 2026-10-30)

Overall status: **PARTIAL**. Offline/synthetic/replay verification is done and the suite is green. No new
physical-hardware capture was taken this session, and the healthy-estimator branch has never been observed on hardware.
Nothing here was committed, pushed, fetched or switched; no remote was contacted.

## 1. Executive summary
- Fix, GPS health and estimator health are three different signals. The runtime already used the EKF horizontal-solution
  state inside the detector (estimator gate). The **dashboard/API did not expose vehicle-reported GPS health or estimator state at
  all**, and labelled a receiver report "valid fix: yes" next to a vehicle that says its GPS is unhealthy. Fixed (additive).
- MAVLink `satellites_visible = 255` means "unknown" but was stored as 255 satellites (looks like a perfect fix and would
  mask GNSS-loss evidence). Fixed; unknown count is now `None`, and a no-fix report still alerts.
- A flaky test (`test_tlog_tees_the_clean_downlink_and_stays_receive_only`, failed ~3/8 runs) was a harness race, not a product bug:
  pyserial's `socket://` `open()` ends with `reset_input_buffer()`, discarding a first frame sent before open returns
  (measured: 224 vs 245 bytes received at the transport). Fixed in the test device. Real serial ports are unaffected.
- Detector thresholds and detector behaviour for any previously-working input were **not** changed.

## 2. Repository state and files changed
Branch `agent/local-gps-test-20261029`, HEAD `e31caf8cd7dc` (unchanged). Working tree was clean at start. Uncommitted changes:

| File | Change |
|---|---|
| `src/aegisflight/backend/engine.py` | `LinkMonitor`: SYS_STATUS GPS-health bit, EKF horizontal-solution state + ages, 255 -> unknown, `valid_fix` is `None` when the count is unknown |
| `src/aegisflight/features/extractor.py` | `satellites_visible == 255` -> `snapshot.satellites = None` |
| `src/aegisflight/detectors/protocol.py` | GNSS-loss rule judges fix type alone when satellites are unknown (previously the rule was skipped) |
| `frontend/src/{types/index.ts,lib/source.ts,components/Header.tsx}`, `frontend/tests/source.test.ts` | separate "receiver report", "vehicle GPS health", "estimator" display; unknown shown as unknown; degraded wording is explicitly not a spoofing verdict |
| `tests/unit/test_gps_health_reporting.py` (new), `tests/integration/test_app_live_source.py`, `tests/unit/test_run_serial_ids.py` | regression tests / race fix |
| `docs/API.md`, this report | docs |

## 3. GPS integration architecture (as read from code)
`SerialMavlinkTransport` (read-only reader thread) -> optional `TapTransport` (tlog tee) -> `LiveMavlinkSource` ->
`FeatureExtractor` (`GPS_RAW_INT` -> fix/sats/hdop; `GLOBAL_POSITION_INT` -> position/velocity residuals; `EKF_STATUS_REPORT` -> `ekf_flags`, debounced
`nav_gated`) -> `PhysicsDetector` (residual rule, estimator-aware) / `ProtocolDetector` (GNSS fix loss, GPS dropout) -> fusion -> hash-chained store -> FastAPI `/api/status`
-> React header. Backend `LinkMonitor` is a separate, display-only view of the same messages. Raw receiver (`GPS_RAW_INT`) and the
autopilot's filtered estimate (`GLOBAL_POSITION_INT`) are separate inputs; the gate keys on `EKF_STATUS_REPORT`.

## 4. Parsing results (findings)
| Item | Result |
|---|---|
| 3D fix is not trusted by itself | Confirmed. Committed bench capture (`artifacts/hardware/gps_hw_verify_20261029/`, 180 reports): fix 3D, 6 to 7 sats, HDOP ~8.1, SYS_STATUS GPS present+enabled but **healthy 0/180**, EKF flags `0xa7` (CONST_POS_MODE, no horizontal position) 180/180 |
| Cause of Mission Planner "3D fix" vs unhealthy | **Not MAVLink version, not parsing**: that link was MAVLink 1 (`0xFE` 5130/5130 frames) and SYS_STATUS/EKF fields were received and decoded; the vehicle really reported those bits. *Why* the vehicle judges the GPS unhealthy is **undetermined** (hypothesis: poor geometry/HDOP ~8 or indoor reception; not proven) |
| MAVLink 1 limits | Extension fields (e.g. `h_acc`) are absent and reported null, not zero (`gnss_summary.json: h_acc_m null`); nothing in the detector reads them |
| `satellites_visible == 255` | **Defect, fixed**: now unknown (`None`) |
| Missing health / EKF messages | Now `null` ("unknown") in the API and the UI, never healthy by default; sensor not present/enabled -> unknown |
| Stale telemetry | Ages reported (`health_age_s`, `estimator.age_s`); detector side already ignores EKF reports older than 2 s (`_LINK_GAP_S`) |
| Not fixed (noted) | `GPS_RAW_INT` missing-field defaults (`.get(..., 0)`) remain in the extractor/LinkMonitor; real pymavlink decodes always carry the fields, so this only affects hand-built messages. `eph = 65535` (unknown) becomes hdop 655.35; hdop is not used by any detector |

## 5. Spoofing detection test matrix (SYNTHETIC / REPLAY; existing tests plus new)
Existing `tests/unit/test_gps_scenarios_fused.py`, `test_missing_telemetry*.py` cover the matrix; all pass in this run. New tests are marked (N).

| # | Scenario | Test evidence | Outcome |
|---|---|---|---|
| 1 | healthy, consistent GPS + estimator | `test_healthy_movement_*` | quiet |
| 2 | position jump vs velocity | `test_position_jump_alerts_gps_spoofing_at_onset` | GPS_SPOOFING at onset |
| 3 | implausible/fast drift | `test_fast_lat_lon_drift_with_truthful_velocity_*` | alert; slow or velocity-consistent drift **not detected** (documented limitation) |
| 4 | stale/missing GPS | `test_missing_telemetry*` | DOS "GPS dropout"; never-received is a coverage line, no alert |
| 5 | fix loss | `test_gnss_fix_lost_*` | DOS 0.7 after `gnss_loss_ticks` |
| 6 | low sats / degraded | `test_gnss_near_miss_*`; (N) `test_no_fix_is_still_flagged_when_the_satellite_count_is_unknown` | flagged; (N) unknown count with 3D fix is not loss evidence |
| 7 | GPS vs estimator disagreement | `test_contradictory_status_claiming_a_solution_does_not_hide_wander` | wander still alerts |
| 8 | unhealthy estimator | `test_stationary_large_wander_with_const_pos_estimator_is_degraded_navigation_not_spoofing`; (N) `test_3d_fix_with_unhealthy_gps_bit_and_no_horizontal_solution_is_not_called_healthy` | no spoofing alert; navigation note instead |
| 9 | MAVLink-version missing fields | (N) health/estimator unknown tests; `h_acc` null in capture | unknown, not healthy |
| 10 | normal movement | `test_healthy_movement_with_a_healthy_estimator_is_quiet` | quiet |
| 11 | invalid/incomplete | (N) 255 satellites tests | unknown, not fabricated |
| 12 | recovery | `test_recovery_from_an_offset_*`, `test_temporary_discontinuity_*` | alerts on the return jump, then clears |

Latency: not re-measured here; see `docs/VALIDATION_EVIDENCE.md` (live proxy drift detected at release only, not during the drift).
API/UI visibility of events: covered by existing `tests/integration/test_app_live_source.py`; the dashboard display of the new fields is covered by the Node test below.

## 6. Estimator-gate behaviour
Gate on (`detector.yaml: estimator_gate: true`): with a debounced (>= 2 s) "no horizontal solution", the position-vs-velocity residual is *not* used as
spoofing evidence; a degraded-navigation note is emitted, and a hard discontinuity or velocity-implied movement the position does not show still alerts.
Gate off restores the Stage-1 rule. On the committed bench capture (REPLAY): gate on 0 alerts, gate off 4 `GPS_SPOOFING` while stationary (receiver wander up to 34 m).
**Caveat:** the gate removing those alerts is not evidence that the detector is accurate; those 4 are receiver wander on a poor fix, and the gate's *un-gated*
(healthy EKF) branch has no hardware evidence. Suppressed decisions remain visible as the navigation note and in `pos_residual_m` signals.
This session did not change gate behaviour.

## 7. Hardware verification
**No new capture this session.** A flight controller is attached (two ArduPilot ports enumerated) but `MissionPlanner.exe` is running and may own the port;
I did not open any port or touch that process. Source audit of the runner (`scripts/hardware/run_serial_ids.py`): the only write path is `SerialMavlinkTransport.send`, which is
never called in the runner; `bytes_sent`/`write_errors` are asserted zero (exit 3 otherwise); defence mode is report-only; `--gcs-notify` is off by default and loopback-only.
The prior (2026-10-29) capture is the only hardware evidence: 90 s, 5130 frames, 0 loss/CRC errors, `bytes_sent` 0 (that is the software counter on the serial write path, not an independent
wire-level measurement). Claim class: BENCH, receiver reports only.

## 8. Test commands and exact results
| Command | Result |
|---|---|
| baseline `pytest -q` (before edits) | 1 failed (the flaky tlog test, 3 of 8 runs), rest passed |
| `.venv/Scripts/python.exe -m pytest -o addopts="" -q` (after) | **884 passed, 11 skipped, 0 failed** (11 skips = git-ignored tlogs/PTY; Windows) |
| `ruff check src tests scripts backend` | All checks passed |
| `pytest tests/unit/test_gps_health_reporting.py` | 9 passed (new) |
| `tests/unit/test_run_serial_ids.py` x6 repeats | 12/12 passed each (was ~3/8 failing) |
| `npm test` (frontend) | 9/9 pass |
| `npm run build` (frontend) | **BLOCKED**: `node_modules` absent (`tsc` not found); installing needs the network. `Header.tsx` is therefore **not type-checked** |

## 9. Confirmed fixes
1. Link block now reports vehicle GPS health and estimator state separately from the receiver report (additive API fields; UI wording; unknown stays unknown).
2. 255 satellites = unknown (extractor, link monitor), with the GNSS-loss rule still catching a no-fix report.
3. Harness race in the tlog test.

## 10. Outstanding blockers and limitations
- Frontend production build/typecheck not run (no `node_modules`; network needed).
- No healthy-estimator hardware capture; no open-sky test; no physical spoofing (never attempted, by design).
- Slow or velocity-consistent drift is undetected by design (see matrix #3).
- Bench evidence is one capture; the vehicle's reason for GPS-unhealthy is unexplained.
- Pre-existing: `/api/defense/mode active-ips` transmit risk on non-SIM sources is recorded in `docs/GPS_WORKSTREAM_PROGRESS.md`; not touched here.
- The IDS still raises no *alert* for "3D fix but vehicle GPS unhealthy"; it is now a visible health warning in the API/UI only (deliberate: a health condition is not an attack).

## 11. Steps for final physical validation
1. Close Mission Planner (or use a second telemetry port); confirm the port is free.
2. Receive-only: `python scripts/hardware/run_serial_ids.py --port <COM> --baud <rate> --out-dir <new dir> --seconds 120 --defense-mode passive --no-reconnect --tlog data/hardware/raw/<new>.tlog`
3. Keep the vehicle disarmed, under open sky until `/api/status` shows `gps.health_ok: true` and `estimator.horizontal_position_ok: true`.
4. Replay that tlog with gate on and off; confirm no alerts on a stationary healthy fix and that the un-gated branch ran.
5. Spoofing only via `aegis simulate`, the replay proxy, or isolated SITL, never the physical link.

## 12. Verdict
Verified (offline/synthetic/replay): parsing of fix/sats/health/EKF fields, unknown-vs-healthy handling, gate semantics, API/UI wording, test suite green.
Verified on hardware: receive-only operation and message flow, one 90 s capture on 2026-10-29 only.
**Not verified:** healthy-estimator operation on hardware, physical spoofing detection, frontend production build, root cause of the vehicle's GPS-unhealthy state.
