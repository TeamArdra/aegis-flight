# GPS verification session: changes made and difficulties faced (2026-10-30)

Branch `agent/local-gps-test-20261029`, HEAD `e31caf8` (unchanged). All changes are uncommitted and local.
Full findings and the test matrix are in `docs/gps_integration_verification.md`.

## Changes made

| File | Change | Why |
|---|---|---|
| `src/aegisflight/backend/engine.py` | `LinkMonitor` now tracks the SYS_STATUS GPS-health bit and the EKF horizontal-solution state, with ages. Adds `gps.health_ok`, `gps.health_age_s` and an `estimator{horizontal_position_ok, flags, age_s}` block. `satellites_visible == 255` becomes unknown. `valid_fix` is `None` when the count is unknown and still `False` when there is no fix. | The API showed only the receiver's fix as "valid fix", so a 3D fix looked healthy even when the vehicle reported GPS unhealthy and no horizontal EKF solution. |
| `src/aegisflight/features/extractor.py` | `satellites_visible == 255` is stored as `None`, not 255. | MAVLink uses 255 for "unknown". Storing it as 255 satellites looked like a perfect fix. |
| `src/aegisflight/detectors/protocol.py` | The GNSS-loss rule judges fix type alone when the satellite count is unknown. | Otherwise the rule would skip a no-fix report whose count is 255. Behaviour for all previously valid inputs is unchanged. |
| `frontend/src/types/index.ts` | Optional `health_ok`, `health_age_s` and `estimator` types. | Matches the new API fields. |
| `frontend/src/lib/source.ts` | New `gpsHealthText()` helper. | Unreported health shows "unknown", never "ok". |
| `frontend/src/components/Header.tsx` | The header shows "GPS receiver report", "meets fix thresholds", "vehicle GPS health" and "estimator" separately. Degraded navigation is worded as a health warning, not a spoofing verdict. | Section 11 requirement: no implication of spoofing from health alone. |
| `frontend/tests/source.test.ts` | One new test for the health text. | Regression cover. |
| `tests/unit/test_gps_health_reporting.py` (new) | 9 tests: unhealthy bit with no horizontal solution, healthy case, unknown until received, sensor not present, ages, 255 satellites (extractor, link monitor, detector). | Regression tests for each fix. |
| `tests/integration/test_app_live_source.py` | Asserts the new API keys exist. | API contract. |
| `tests/unit/test_run_serial_ids.py` | The fake serial device waits 0.3 s after accept before sending. | Fixes a flaky test (see below). |
| `docs/API.md` | Documents the new fields and their meaning. | Docs sync. |
| `docs/gps_integration_verification.md` (new) | Verification report. | Requested deliverable. |

No detector thresholds, the estimator-gate logic, event schema, hash chain or `ML_FEATURES` were changed.

## Difficulties faced

1. **Flaky baseline test.** `test_tlog_tees_the_clean_downlink_and_stays_receive_only` failed in about 3 of 8 runs, so the baseline was not clean.
   - I first suspected frame loss in the transport or tap. A byte count showed the transport received 224 bytes against 245 sent, a missing 21-byte first heartbeat, so the loss happened before the transport.
   - Cause: pyserial's `socket://` `open()` ends with `reset_input_buffer()`, discarding data that arrives before it returns. It is a test-harness artifact; real serial ports are not affected.
   - Fix: delay the fake device's first send. It then passed 6 of 6 repeats and in the full suite.
2. **Missing pytest summary line.** `addopts = "-q"` in `pyproject.toml` suppressed the totals, so I re-ran with `-o addopts=""` to get exact counts (875 passed, 11 skipped before changes; 884 passed, 11 skipped after).
3. **Hardware capture not possible safely.** Two ArduPilot ports are enumerated, but `MissionPlanner.exe` is running and may own the port. The rules forbid opening a port another application owns or killing it, so no capture was taken. The only hardware evidence remains the 2026-10-29 capture, and its "bytes sent = 0" is a software counter, not a wire-level measurement.
4. **Frontend build blocked.** `node_modules` is absent (`tsc` not found) and installing needs the network, which was not allowed. `npm test` passes (9 of 9), but the production build and the type check of `Header.tsx` were not run.
5. **Mission Planner discrepancy only partly explained.** Committed evidence rules out MAVLink version and parsing: that link was MAVLink 1 and the health and EKF fields decoded correctly. Why the vehicle judges its GPS unhealthy (HDOP about 8, 6 to 7 satellites) is undetermined; poor geometry or indoor reception is only a hypothesis.
6. **Tooling slips.** Two shell heredoc attempts to patch the frontend silently did nothing. I caught it with `git diff --stat` and re-ran the edit from a script file.
7. **Scope judgement on the "IDS is silent" gap.** A 3D fix with an unhealthy vehicle GPS still raises no alert. I made it a visible health warning only, because a health condition is not an attack and an alert would blur health with spoofing.

## Not done or not verified

- Frontend production build and type check of the new header code.
- Any new hardware capture, any healthy-estimator hardware data, any open-sky test.
- Detection latency was not re-measured.
- Known, untouched: `GPS_RAW_INT` missing-field defaults of 0 in the extractor (only reachable with hand-built messages), and the `active-ips` transmit risk on non-SIM sources noted in `docs/GPS_WORKSTREAM_PROGRESS.md`.

## Git safety

No commits, pushes, pulls, fetches, `gh` commands, merges, resets or branch switches were run. `.git` and the remote configuration were not touched, no attribution lines were added, and no remote was contacted.
