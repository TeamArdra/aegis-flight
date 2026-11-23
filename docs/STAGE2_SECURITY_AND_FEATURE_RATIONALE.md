# Stage-2 & Universal Flight-Hardening Review Guide: Feature Preservation & Security Verification

This document is a technical walkthrough for **human maintainers** and **automated PR reviewers (Claude reviewer)** covering the four-PR Stage-2 integration stack (**PR #79 → PR #80 → PR #81 → PR #82**, branched cleanly from `main` at `389fc02`).

Every feature added across the Stage-2 issues (`#10`, `#11`, `#14`, `#15`, `#19`, `#20`, `#21`, `#22`, `#24`, `#32`, `#35`, `#49`, `#58`, `#59`, `#60`) and Universal Flight Hardening (**W1–W13**) is **preserved in full**. Rather than dropping features to satisfy audit findings (`#65`–`#74`), each reported security or integration weakness was fixed at its root cause and pinned by regression tests.

---

## 1. Stack Overview & Reviewer Reading Map

| PR | Branch | Base | Scope & Reviewer Focus |
|---|---|---|---|
| **#79 (1/4)** | `feat/stage2-1-detectors-integrity-claims` | `main` (`389fc02`) | Model/firmware integrity, sequence reorder window, link attribution, startup GNSS/physics guards, ArduCopter in-flight FA calibration, MAVLink-2 signing defaults, external hash-chain anchors & actions chain, golden ML SHA lock (`3fe74cdd`), CI claims guard, and docs truth pass. |
| **#80 (2/4)** | `feat/stage2-2-ips-modes-onboard-proxy` | PR #79 | Armed-only/budgeted IPS interlocks, strict 3-mode separation + passive compid-191 boundary, unified onboard companion runtime + bounded SQLite rotation continuity, SITL proxy hooks, and trial allowlist loading. |
| **#81 (3/4)** | `feat/stage2-3-universal-flight-core` | PR #80 | Hardware-agnostic universal flight hardening backend/core (`W1–W12`): multi-dialect codec/actuator, ground baro bias, `yaw_course_auto`, *ConstDet* control semantics, GNSS clock-skew check, inline semantic firewall, zero-TX `SideTapRunner` & passive autobaud, asymmetric failsafe/watchdog, HMAC API command security, forensic export, and `aegis field-drill`. |
| **#82 (4/4)** | `feat/stage2-4-dual-mode-ui` | PR #81 | Demo vs Flight Ops dual-mode & command-secured React operator console (`frontend/`), plus this guide. |

---

## 2. Preserved Features & Security-Criteria Satisfaction

### 2.1 Mode Separation & Component-191 Boundary (PR #80, `#58` / `#68`)
- **Feature preserved:** Strict three-posture separation across `InlineIpsBridge` (`PASSIVE`, `ADVISORY`, `ACTIVE_IPS`) and opt-in `--mgmt-enable` / `mgmt_enable=True` for lab/bench management telemetry while keeping `PASSIVE` strictly 0-byte unsolicited TX.
- **Security fix applied:** Earlier integration left uplink component-191 (`MAV_CMD_USER_1`) frames unconsumed when `PASSIVE` had `mgmt_enable=False`, forwarding them to the flight controller (`fc.sent`). `InlineIpsBridge._handle()` (`src/aegisflight/hal/inline_ips.py`) now **always consumes uplink component-191 management commands at the bridge boundary** (`commands_consumed += 1`, archived via `archive.consumed(...)`, never forwarded to `fc`), while keeping unsolicited management TX (`emit_crossend`, `_send_alarms`, `mgmt.service`, `_announce_actions`) gated by `_mgmt_active()` (`mode != PASSIVE or mgmt_enable`).
- **Serial receive-only boundary:** `may_reach_vehicle()` (`src/aegisflight/sources/mavlink_serial.py`) enforces receive-only behavior on physical serial devices in all postures.
- **Verified by:** `tests/unit/test_mode_separation.py`, `tests/unit/test_mgmt_channel.py`, `tests/unit/test_crossend.py`.

### 2.2 MAVLink-2 Signing Enforcement (PR #79, `#19` / `#69`)
- **Feature preserved:** Configurable per-stream bootstrap settle tolerance (`protocol.signing_settle_s`) and per-source unsigned allowlist (`protocol.unsigned_allowed`) in `ProtocolDetector` (`src/aegisflight/detectors/protocol.py`) for specialized hardware deployments that explicitly opt in.
- **Security fix applied:** Removed the insecure default `2.0 s` unauthenticated blind window (`signing_settle_s: 0.0` default in `configs/detector.yaml`, `src/aegisflight/config.py`, and `ProtocolDetector`) and cleared the default `sysid: 51, msg: RADIO_STATUS` exemption (`unsigned_allowed: []` default). When `require_signing: true`, invalid signatures and unexpected unsigned `RADIO_STATUS` frames raise immediate alerts from `t=0`.
- **Verified by:** `tests/unit/test_signing_bootstrap_and_allowlist.py`.

### 2.3 Armed-Only IPS Interlocks & Recovery Starvation Fix (PR #80, `#60` / `#67`)
- **Feature preserved:** Armed-only gating (`frame.snapshot.armed is True`), one-shot `SAFE_HOLD` `ALT_HOLD`, and per-episode / per-minute counter-command rate budgets in `MitigationController` (`src/aegisflight/mitigation/controller.py`).
- **Security & safety fixes applied:**
  1. `_can_send_command()` logs rate-limited `CMD_BUDGET_REFUSED` audit entries (`_log_cmd_refusal`) whenever `episode_cap` or `minute_cap` blocks a command.
  2. Clean recovery (`EKF_SWITCH_PRIMARY`) uses `bypass_budget=True` (cooldown still enforced) so an attack episode exhausting `max_counter_cmds_per_episode` can never strand a vehicle on the secondary EKF after clean telemetry resumes.
  3. `scripts/verify_stage2.py` suite 5 sets `armed=True` on its in-flight mode-flip test snapshots rather than bypassing the armed-only interlock.
- **Verified by:** `tests/unit/test_ips_safety_interlocks.py`, `scripts/verify_stage2.py`.

### 2.4 Unified Onboard Runtime, Side-Tap Default & Rotation Hash Continuity (PR #80 & PR #81, `#59` / `#71`)
- **Feature preserved:** Single-command companion supervisor (`aegis onboard --config`), size-bounded SQLite/JSONL rotation (`rotate_sqlite_store`, `rotate_file_series`, `prune_rotated_files`), disk-budget enforcement, and clean `SIGTERM` shutdown.
- **Security & reliability fixes applied:**
  1. Safe default switched to RX-only passive observation: `configs/onboard_default.yaml` and `OnboardConfig.topology` default to `"side-tap"` (`defense_mode: passive`) once `SideTapRunner` lands in PR #81; active `inline` bridge remains explicit opt-in and serial links still refuse `active-ips`.
  2. `rotate_sqlite_store()` (`src/aegisflight/logging/rotation.py`) captures `_segment_heads()` (`last_event_hash`, `last_action_hash`, event/action counts) before closing the segment, embeds `"prev_segment"` into the new segment's `runs.meta`, and appends a hash-chained `ROTATION_LINK` action row so forensic continuity holds across segments.
  3. Disk-cap pruning records deleted filenames and emits explicit `PRUNE_ROTATED` actions in `store.log_action()` (`src/aegisflight/onboard.py`) plus `archive.record_pruned()` (`src/aegisflight/hal/run_archive.py`), preventing silent log loss.
  4. `_replace_with_retry()` handles transient Windows handle-release `PermissionError` during rotation tests.
- **Verified by:** `tests/unit/test_onboard_runtime.py`, `tests/unit/test_onboard_watchdog_and_wal.py`, `tests/unit/test_side_tap_and_auto_port.py`.

### 2.5 Restricted-Visibility Proxy Scenarios & Firmware Allowlist Disclaimers (PR #79 & PR #80, `#20` / `#24` / `#65` / `#72`)
- **Features preserved:** All live SITL downlink manipulation hooks (`AltitudeBiasAttack`, `SpeedMismatchAttack`, `BatteryJumpAttack`, `FrozenAttitudeAttack`, `FirmwareIdentityAttack`), uplink restricted-visibility scenarios (`rogue_force_disarm`, `gcs_forgery_own_counter`, `gcs_forgery_track_identity`, `benign_pilot_control`), and `AUTOPILOT_VERSION` allowlist checking (`src/aegisflight/integrity/allowlist.py`).
- **Security fixes applied:**
  1. `RogueForceDisarmAttack.__init__` and `build_restricted_visibility_hook` (`src/aegisflight/proxy/attacks_live_telemetry.py`) default `auto_arm_if_disarmed: bool = False`, eliminating unsolicited auto-arming by default unless explicitly opted in.
  2. `scripts/sitl/run_p2_telemetry_trial.py` loads `configs/firmware_allowlist.yaml` (`--firmware-allowlist` / `default_allowlist_path()`), wires it into `IDSPipeline`, and records `firmware_allowlist_sha256` via `collect_run_provenance()`.
  3. `configs/firmware_allowlist.yaml` and `docs/CONFIGURATION.md` carry explicit disclaimers stating the shipped template is unsigned (`vehicles: []`) in this PoC and requires `AEGIS_ALLOWLIST_KEY` HMAC signing plus populated vehicle entries before trusting operational checks.
- **Verified by:** `tests/unit/test_proxy_telemetry_and_firmware.py`, `tests/unit/test_firmware_allowlist.py`, `tests/unit/test_run_provenance.py`.

### 2.6 Golden ML Guard, Claims Hygiene & Documentation Truth Pass (PR #79, `#10` / `#35` / `#70` / `#73`)
- **Features preserved:** Full equivalence fixture coverage (`76` ML-off + `55` ML-on cases) and CI claims-guard workflow job.
- **Integrity fixes applied:**
  1. `tests/golden/golden.json` restores canonical `ml_model_sha256` (`3fe74cddf3689e169610ffd783b109b6539cc6c03629bd1e4bb8b1d3842939c4` matching `models/MODELS.sha256`), replacing PR #76's non-canonical `bafad273...` digest.
  2. `tests/unit/test_golden_equivalence.py` fails loudly (`test_golden_ml_sha_matches_canonical_manifest`) if `golden.json` drifts from `models/MODELS.sha256` or if a present `models/isoforest.joblib` mismatches canonical `3fe74cdd...`, and adds `test_seeded_ml_exercises_all_55_golden_cases` to verify ML-on execution across all 55 scenarios deterministically (`seed=100`) on hosts where the git-ignored canonical binary is absent.
  3. `frontend/src/components/evalPanels.tsx` labels `evaluation_heldout.json` accurately as `false-alarm only (no attacks)` and ALFA replay as `physical faults only (no cyber attacks)`.
  4. `README.md` accurately states `ACTIVE_IPS` counter-commands transmit only on live UDP / `socket://` SITL links while physical serial links stay receive-only.

### 2.7 Universal Flight Hardening Core & Dual-Mode Secured Console (PR #81 & PR #82, W1–W13)
- **Backend/Core security criteria satisfied (PR #81):**
  - Multi-dialect encode/decode (`src/aegisflight/mavlink/codec.py`, `src/aegisflight/mitigation/actuator.py`) enforces dialect-matched encoding with zero fallback guesses.
  - Inline Semantic Firewall (`src/aegisflight/mitigation/semantic_firewall.py`, `src/aegisflight/mitigation/inline_policy.py`) rejects unauthenticated/unsafe in-flight `PARAM_SET`, `FENCE_POINT`, `MISSION_CLEAR_ALL`, `MISSION_ITEM`, and force-disarm commands fail-closed when configured (`fail_closed_uplink_commands: true`).
  - Zero-TX serial probing (`src/aegisflight/hal/auto_port.py`) and RX-only `SideTapRunner` (`src/aegisflight/hal/side_tap.py`) are verified never to invoke `serial.write()` / `transport.send()`.
  - Privileged operator/bench/override backend routes (`src/aegisflight/backend/app.py`, `src/aegisflight/backend/security.py`) bind to loopback by default, validate `Origin` / `Host`, require authentication by an HMAC-SHA256 canonical signature (`X-Aegis-Key-Id`, `X-Aegis-Timestamp`, single-use `X-Aegis-Nonce`; legacy `X-Aegis-Token` only under `AEGIS_REQUIRE_SIGNED_API=0`). Replayed nonces are rejected within a 60 s window on a loopback or TLS link; the scheme does not encrypt traffic, and lock bench setup routes whenever armed telemetry is active.
  - Pre-flight verification (`aegis field-drill`, `src/aegisflight/testing/field_drill.py`) tests spoof rejection, GPS escalation, semantic firewall blocking, and clock-skew detection in-process with `zero_real_fc_tx=True`.
- **Frontend security criteria satisfied (PR #82):**
  - `deriveConsoleMode()` (`frontend/src/lib/consoleMode.ts`) forces non-SIM environments (`BENCH`, `SITL`, `REPLAY`, live serial) into restricted **Flight Ops** mode; `computeCapabilities()` locks simulation-only attack injection and armed/remote bench configuration routes.
  - Sensitive posture switches and bench actions require deliberate operator hold-to-confirm (`HoldConfirmButton.tsx`) and are signed in-memory via `signCanonicalRequest()` (`frontend/src/lib/requestAuth.ts`) without placing tokens in URLs or `localStorage`.

---

## 3. Non-Negotiable Constraints Check

- **Stage-1 frozen contracts (`ML_FEATURES`, `FlightState`, `MessageEnvelope`, hash-chain canonicalization, benchmark scoring):** Unchanged across all 4 PRs (`FeatureFrame` extended only with defaulted optional fields; Stage-1 `results.csv` non-timing cells and `6535 / 4 / 16826 / 65` confusion matrix preserved).
- **Physical vehicle serial receive-only safety:** `may_reach_vehicle()` blocks `active-ips` and TX on every serial port in `aegis serve`, `aegis ips-bridge`, `aegis onboard`, `SideTapRunner`, and `auto_port`.
- **Supported evidence boundary:** No real-flight hardware or outdoor vehicle validation is claimed in docs, UI labels, or PR summaries; canonical `models/isoforest.joblib` (`3fe74cdd...`) remains out-of-repo (git-ignored) and requires a maintainer host holding the canonical file only when regenerating `--ml-only` digests after the `FeatureFrame` schema additions.

---

## 4. Independent Audit Remediations Applied Across PRs #79–#82

Following the independent Stage-2 audit, the following confirmed security, correctness, and cross-platform fixes were applied across the stack:

- **Pre-deserialization model integrity (PR #79):** `AnomalyDetector.__init__` (`src/aegisflight/detectors/anomaly.py`) verifies `check_model(path)` **before** calling `joblib.load(path)`, refusing tampered (`mismatch`) and `unlisted` files without unpickling unless `allow_unverified=True` is explicitly passed through `IDSPipeline`, `run_session`, `run_benchmark`, or the CLI (`--allow-unverified-model`).
- **Event-log anchor chain continuity (PR #79):** `src/aegisflight/logging/anchors.py` chains every anchor with monotonic `seq`, `prev_anchor_hash` (from `GENESIS_ANCHOR_HASH`), and `anchor_hash` covered by HMAC-SHA256. `verify_anchors(..., expected_min_anchors=...)` detects middle deletion, head deletion, tail truncation, reordering, sequence gaps, modified records, and invalid signatures while preserving legacy read-only DB compatibility.
- **Explicit per-profile GNSS & ML corroboration policies (PR #79, PR #81):** SIM default `gnss_never_acquired_policy` is restored to `dos` (`configs/detector.yaml`, `src/aegisflight/config.py`, `src/aegisflight/detectors/protocol.py`), while live/SITL profiles (`configs/px4_sitl/detector.yaml`, `configs/ardupilot_copter/detector.yaml`, `configs/universal_flight/detector.yaml`) explicitly declare `gnss_never_acquired_policy: coverage`. `configs/px4_sitl/detector.yaml` explicitly enables `fusion.ml_require_corroboration: true`.
- **Strict-JSON metrics serialization (PR #79):** `src/aegisflight/metrics/scoring.py` emits `None` instead of `float("nan")` for empty latency/macro/hierarchical-link summaries so `json.dumps(..., allow_nan=False)` succeeds deterministically.
- **Removal of force-ARM primitive (PR #80):** `RogueForceDisarmAttack` and `auto_arm_if_disarmed` were removed completely from `src/aegisflight/proxy/attacks_live_telemetry.py` so no proxy attack helper can construct `COMMAND_LONG(400, param1=1.0, param2=21196.0)`.
- **Windows test portability (PR #80, PR #81):** `tests/unit/test_onboard_runtime.py` uses `os.pathsep` for `PYTHONPATH`, and `tests/unit/test_onboard_watchdog_and_wal.py` guards `socket.AF_UNIX` with `@pytest.mark.skipif(not hasattr(socket, "AF_UNIX"), ...)`.
