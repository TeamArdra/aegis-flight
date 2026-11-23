# Stage 2 final codebase audit

**Audited commits:**
- main `2bae45a`;
- the Stage-2 stack: #81 `9a15d08` (#80 + #140 + D4) and #82 `1c3c776`.

**Baseline:** the requirement matrix `docs/STAGE2_REQUIREMENT_TRACEABILITY.md` (`3000790`, 2026-11-20). The rows that changed since
then were re-checked. The report was checked against the 11-06 build in report-repo draft PR #1.

**Finding classes:** BLOCKER (submission cannot go without it), CORRECTION (a claim or record must change), SATISFIED, LIMITATION
(document it, no work), POST (after submission).

## 1. Detection (§5–§6, 30 marks)

| Deliverable | Implemented in | Verified by | Evidence (tag) | Class |
|---|---|---|---|---|
| GPS spoofing | `detectors/physics.py` | unit tests; Stage-1 | SIM 12/12; SITL PX4 10/10, ArduPilot 3/3 | SATISFIED. LIMITATION: slow, velocity-consistent drift is missed |
| MAVLink anomalies | `detectors/protocol.py` | unit tests | SIM 16/16; SITL indirect only | SATISFIED (SIM). LIMITATION: no live harness |
| Command injection | protocol identity, cadence and signature | unit tests; SITL | SIM 12/16 (`gcs_replay` 0/4); SITL rogue 10/10, informed forger 0/10, signed forgery rejected 10/10 | SATISFIED. LIMITATION: an unsigned expected-GCS forgery is undetectable; signing is the mitigation |
| Telemetry manipulation | physics consistency rules | unit tests | SIM 16/16 | SATISFIED (SIM only) |
| Denial of service | liveness, rate and GNSS rules | unit tests; SITL | SIM 16/16; SITL drop 10/10, delay 9/10, GNSS 10/10 | SATISFIED |
| Firmware integrity | `integrity/`, `detectors/integrity.py` | unit tests | SIM 4/4 | SATISFIED. LIMITATION: unsigned manifest |
| Detectors never read labels | `FeatureFrame` boundary | `test_label_independence.py` | SIM | SATISFIED |
| Stage-1 regression | whole pipeline | `aegis benchmark --no-figures` | **6535 / 4 / 16826 / 65**, reproduced on every head gated on 2026-11-22/23 (#140, #150, #151, #91, #154) | SATISFIED |

## 2. False alarms and alerting (§7, 8 marks)

| Deliverable | State | Class |
|---|---|---|
| Benign exposure on actual flights | none: there is no own flight data. Public-log replay only (ALFA, PX4) | LIMITATION. Only a flight fixes it (human, #29 is receive-only, ground) |
| False-alarm rate with an upper bound | not established | LIMITATION. State "not established" |
| Tamper-evident log | `logging/store.py` hash chain; `aegis verify-log` | SATISFIED. LIMITATION: deleting the newest rows goes undetected until #21's anchoring lands (it is in the stack) |
| Alerting cannot interfere with flight | serial links are receive-only (`may_reach_vehicle()`); PASSIVE sends 0 bytes (#58 tests) | SATISFIED in software. LIMITATION: never flown; TX-line isolation not measured |
| IPS actuation safety | SAFE_HOLD gate #140; D4 dialect gate (heartbeat-bound, fail-closed); armed-only, one-shot, budgeted (#60) | SATISFIED. D12 (no counter-command on a genuine emergency stop) and D13 (ML-only cannot act in ACTIVE_IPS) are implemented in #114 and #115 (fix-ups #162 and #165 merged). D10 (#112): mode commands and flood actions identical to main. LIMITATION: restore paths have no armed check |
| Safe failure | passive tap is safe; inline bridge has no hardware bypass | LIMITATION: do not fly the bridge (documented) |

## 3. Validation and reproducibility (§8, 14 marks)

| Finding | Detail | Class |
|---|---|---|
| Test suite | main CI green; stack heads 2590 passed (Windows); Linux CI green | SATISFIED. Re-run on the freeze tag |
| **SITL manifest model hash** | All **122** manifests with `model_choice: px4` record `full_provenance.model_sha256 = 3fe74cdd…` (the Stage-1 model). Cause: `scripts/sitl/p2_trial_common.provenance_block()` calls `collect(**extra)` without the resolved model, so `collect()` hashes its default `models/isoforest.joblib`. Also, `resolve_model()` returns `model_choice="px4"` even when the PX4 file is missing and ML silently ran off. | **CORRECTION + BLOCKER for #26.** Fix the writer before the campaign (plan A11). Committed manifests are not hand-edited; the report states an erratum |
| ML on in PX4 SITL | the manifests and ML-anomaly evidence show ML was **on** (`px4` choice) in the PX4 SITL batches; the report says ML is off on live sources | CORRECTION in the report (#31 item 13) |
| Extended benchmark in report | the report has pre-#14 values (9088 / 39 / 40813 / 1133, recall 0.889, "99.97 % reordered"). Post-#14 artifact `artifacts/validation/seq_reorder_20261118`: 9072 / 39 / 40813 / 1149, recall 0.8876, 97.65 % | CORRECTION (#31) |
| Inline-IPS raw logs | `artifacts/` holds no inline-bridge raw frame logs; the results exist only as prose in `docs/RADIO_TEST_RESULTS.md` | LIMITATION: label those results "prose, raw logs not archived" |
| Result files reproduce numbers | Stage-1 378/378 cells (matrix); report traceability: 655 of 819 numbers MATCH, 25 DIFFER, 53 UNSOURCED, 86 need the freeze run | CORRECTION for the 25 and the 53 (#31) |
| Model loading | hash then re-read TOCTOU (#144); two scripts unpickle unverified (#155) | fixes ready: #154, #160 (drafts, green) |

## 4. Compute and integration (§9, 8 marks)

| Deliverable | State | Class |
|---|---|---|
| Resource use on the target (Pi) | none measured | BLOCKER for full marks; human (#30) |
| Tap point, protocols, autopilots | MAVLink 1 on the bench (passive); v2 and signing in SITL; ArduPilot and PX4 SITL | SATISFIED with tags |
| Dashboard | FastAPI + React; console HMAC in #82; D9 signed-only pending (#93) | SATISFIED. D9 is to implement |
| Install guide | `docs/installation.md`; clean-clone run 2026-10-31 | SATISFIED; re-time on the freeze tag |
| **Demo video** | none | **BLOCKER**, human (#33). Checklist in #157 |
| Kit cost, power, mass; operator alert-read time | none | LIMITATION or human input (#32) |

## 5. Package and integrity (§10–§11, 12 marks)

| Item | State | Class |
|---|---|---|
| Archive | `git archive` at the freeze; verifier in #157 | human assembly (#34) |
| Licences | `THIRD_PARTY_NOTICES.md`: ALFA licence not re-checked at the source; Rust crates and Tauri icons declared only | CORRECTION: a human checks ALFA; describe the Rust/Tauri prototypes or exclude them |
| Risk register | `docs/RISK_REGISTER.md` still names the Pi Zero 2W as the design | CORRECTION once the kit is fixed (human) |
| AI declaration, integrity signature | not done | human |

## 6. Evidence-tier and compliance finding (maintainer attention)

`docs/RADIO_TEST_RESULTS.md` on main (merged in #39) records **randomised attack campaigns on a real Pixhawk 6X** on 2026-11-02:
- batches 1–3 of 6;
- conditions: disarmed, propellers removed, bench; ArduCopter 4.7.1;
- forged frames were sent over the LR900 radio;
- in passive posture, forged RTL and LAND frames changed the board's flight mode.

Three problems follow:
1. This is **BENCH** evidence, not SITL, HITL or flight, and the report must label it so.
2. The 11-06 report says "no attack on real hardware" and "bridge SITL only". That contradicts this record. CORRECTION (#31).
3. It conflicts with AGENTS.md §5 (attack tooling targets only local SITL; no real RF or real vehicles) and with the standing rule "no scripted attack
   experiments on real flight hardware". No further such runs are part of this plan. Whether these BENCH results are used in the
   submission, and how they are disclosed, is a maintainer decision.

## 7. Post-submission (no action now)

- #158/#159 script `--help` safety;
- restore-path armed check;
- `make_golden_forwarding` write guard;
- #117 PX4 LAND fallback;
- #13 repository settings;
- a fuzz campaign.
