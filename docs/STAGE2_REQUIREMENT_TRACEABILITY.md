# Stage 2 requirement traceability

**Official sources found.** The only official Stage 2 document used is the PUSHPAK Stage 2 report template PDF
(25 pages, sha256 `e9f35838574b72a7…`). That PDF is **not in this repository** (decision D2, see #31): the committed file
`docs/Stage 2_Security of Drones, Objective 2_Report Template.pdf` is a 23 KB text placeholder with a different hash. Page
numbers below refer to the official PDF. It contains the report structure, the marks, the rubric (p. 23-24) and the evaluation
philosophy (p. 25).

**Not found anywhere in the repository:**
- a separate official Stage 2 problem statement;
- a separate scoring sheet;
- separate submission instructions, a deadline or a format;
- separate demonstration-day requirements.

Everything about the demonstration below therefore comes from the template's only demonstration requirement: "Demonstration
video (screen recording of a real run)" (p. 19) and "real run, not slides" (p. 20). **If the team holds an organiser email or
brief that is not in the repository, check this matrix against it.** The internal brief `AEGISFLIGHT_STAGE2_ENGINEERING_BRIEF.md`
is the team's own plan, not an official source.

**Status values** are the ones requested. Each row uses the strongest status the evidence supports. `Physical-tested` always means
receive-only on a stationary, disarmed bench board, never flight. Evidence paths are expanded in `docs/STAGE2_EVIDENCE_INDEX.md`.

## 1. Attack coverage and detection (template §5, 18 marks; §6, 12 marks)

| Requirement | Official source/page | Existing implementation | Evidence available | Status | Gap | Next action |
|---|---|---|---|---|---|---|
| Detect GPS spoofing | p. 6, p. 10 | `detectors/physics.py` residual, jump, speed, altitude and receiver-signature rules; estimator gate | `SIM` 12/12 sessions; `SITL` PX4 10/10 at release only, ArduPilot 3/3 | Simulation-tested | No real-vehicle attack. Slow and velocity-consistent drift are missed | State the floor. Do not tune to the test |
| Detect MAVLink anomalies | p. 6, p. 10 | `detectors/protocol.py` rate, sequence, identity; ML on `SIM` only | `SIM` 16/16; `SITL` indirect only (replay, impersonation) | Simulation-tested | No live harness for rogue sysid, rate spike, scramble | Say "not run on SITL" |
| Detect command injection | p. 6, p. 10 | protocol source identity, cadence, signature | `SIM` 12/16 (`gcs_replay` 0/4); `SITL` rogue 10/10; informed forger 0/10; signed forgery rejected 10/10 | Simulation-tested | Unsigned expected-GCS forgery is undetectable | Report the miss. Signing is the only answer |
| Detect telemetry manipulation | p. 6, p. 10 | physics consistency rules; cross-end check | `SIM` 16/16 | Simulation-tested | No live harness | Report as `SIM` only |
| Detect denial of service | p. 6, p. 10 | liveness, rate and GNSS-fix rules | `SIM` 16/16; `SITL` drop 10/10, delay 9/10, GNSS 10/10 | Simulation-tested | Real RF jamming not tested | -- |
| Detect firmware integrity faults | p. 6, p. 10 | `integrity/`, `detectors/integrity.py` SHA-256 manifest | `SIM` 4/4; unit tests | Simulation-tested | Manifest unsigned. Dashboard on bench shows "UNKNOWN (no verifier)" | Report the limit |
| Include subtle attacks near the noise level | p. 9 | residual window; drift sweep | `SIM` drift sweep, ML off and on | Simulation-tested | GPS drift only | No sweep exists for the other five classes |
| Detectors must not read labels or attack flags | p. 9, p. 23 | `FeatureFrame` boundary; ground truth is benchmark-only | `tests/unit/test_label_independence.py` (8 tests, `SIM`, five classes) | Unit-tested | Firmware class excluded by design | -- |
| Per-class results with counts and confidence intervals on untuned data | p. 10-11 | `scripts/make_submission_stats.py`, `make_session_ci_sitl_replay.py` | Wilson intervals, `SIM` sessions, `SITL` trials | Simulation-tested | Simulator, attacks and detector are all the team's, so no data is truly independent | State it |
| Detection latency distribution, median and p95 | p. 11 | `metrics/`; figure from `sessions.csv` | per-class min/median/max; dot plot | Simulation-tested | No class has 20 detected sessions, so no p95 per class | Keep it blank, as now |
| Baseline comparison | p. 9, p. 11 | `scripts/baseline_comparison.py` | simple threshold baseline, `SIM` | Simulation-tested | No comparison with the autopilot's own checks | Requires attacked sessions with failsafe output |
| Every missed attack explained | p. 11 | -- | report §5.3 | Implemented | -- | -- |
| Malformed or truncated input handled safely | p. 12, p. 24 | CRC, resync, bounded queues in `sources/mavlink_serial.py` | `tests/unit/test_mavlink_serial.py`, `test_serial_raw_tap.py` | Unit-tested | No fuzz campaign | Do not claim fuzzing |
| Every alert traces to its telemetry | p. 13, p. 24 | evidence strings stored per alert in the event store | §6.3 samples; alert evidence figure; `/api/events/forensic` | Replay-tested | Figure is on the SIMULATED GPS fixture | Label it |

## 2. False alarms and alerting (template §7, 8 marks)

| Requirement | Official source/page | Existing implementation | Evidence available | Status | Gap | Next action |
|---|---|---|---|---|---|---|
| Benign exposure of meaningful length on actual flights | p. 13-14, p. 24 | replay adapters, serial runner | 0 h own flights; bench captures; ALFA and PX4 public logs | **Missing** for own flights; Replay-tested for public logs | **No own flight data exists** | A flight is the only fix. Not possible indoors |
| False-alarm rate per hour with an upper bound | p. 14 | -- | none that can support a rate | **Missing** | Exposure too small | State "not established" |
| Benign-condition matrix | p. 14 | -- | partly: cruise and link loss in `REPLAY`; wind not tested | Partial | Wind, take-off and landing not assessed | Report as is |
| Tamper-evident alerts and logs | p. 7, p. 15 | `logging/store.py` SHA-256 chain; `aegis verify-log` | `tests/unit/test_integrity_and_logging.py`; `chain_truncation_check.txt` in the bundle | Integration-tested | **Deleting the newest rows or a whole run is not detected.** Unsigned: a host-level attacker can rewrite it all | State the limit. A fix needs an external head anchor, which touches the frozen event schema |
| Alert policy cannot interfere with flight | p. 24 | `run_serial_ids.py` and `aegis serve` never transmit on a serial device; `aegis ips-bridge` refuses `active-ips` there but relays the operator's frames when passive; `may_reach_vehicle()` | `tests/unit/test_defense_safety.py`; `bytes_sent` 0 (software counter) on every physical capture | Partial | **Never flown.** DTR/RTS at port open and TX-line isolation unmeasured; a `socket://` URL is trusted as non-physical without checking the host | Leave TX unconnected on the Pi harness |
| Behaviour if the IDS fails is safe | p. 15, p. 24 | passive tap keeps the link unaffected; bridge has no hardware bypass | documented; loopback tests | Partial | Inline bridge cuts the link if the process dies | Do not fly the bridge without a bypass |

## 3. Validation and reproducibility (template §8, 14 marks)

| Requirement | Official source/page | Existing implementation | Evidence available | Status | Gap | Next action |
|---|---|---|---|---|---|---|
| Test suite in the archive that passes on a clean machine | p. 15, p. 24 | `tests/`, `frontend/tests/` | fresh host run today; clean-clone run 2026-10-31 | Integration-tested | Re-run on the frozen commit | Run after the freeze |
| Result files reproduce reported numbers | p. 15, p. 24 | `artifacts/`, scripts | Stage-1: 378 of 378 cells equal today | Simulation-tested | SITL batches not re-run since 2026-10-10; inline IPS raw logs absent | Recover the logs or mark as prose |
| Flight logs and datasets in the archive, or with checksums | p. 2, p. 16 | manifests with SHA-256 | `data/external/manifests/` | Partial | Raw bench captures and the model are git-ignored | Team decision |
| Attack-generation method disclosed | p. 16 | `attacks/`, `proxy/` | report §8.1 | Implemented | -- | -- |
| Claims traceability | p. 17 | report §8.3; evidence index | `docs/STAGE2_EVIDENCE_INDEX.md` | Implemented | -- | -- |

## 4. Compute and integration (template §9, 8 marks)

| Requirement | Official source/page | Existing implementation | Evidence available | Status | Gap | Next action |
|---|---|---|---|---|---|---|
| Resource use on the target hardware | p. 18, p. 24 | `scripts/ardupilot/measure_replay_cost.py` | host only | **Missing** on target; Physical-tested on host | **No Raspberry Pi measurement exists** | Teammate runs the command in the runbook on the Pi |
| Tap point and method | p. 18 | passive serial tap | captures 007-009, 2026-10-28 | Physical-tested | -- | -- |
| Protocol support | p. 18 | MAVLink 1 and 2, signature check | `BENCH` MAVLink 1; `SITL` both | Physical-tested (v1); Simulation-tested (v2, signing) | Signing not run against a real autopilot | -- |
| Autopilot support | p. 18 | ArduPilot, PX4 | `SITL` both; `BENCH` ArduPilot family | Physical-tested (ArduPilot, passive); Simulation-tested (PX4) | Firmware version of the board is **not known** | Reading it needs a ground station, which transmits. Your decision |
| Ground station and dashboard | p. 18 | FastAPI, WebSocket, React | serial session 2026-10-25; replay and loopback today | Physical-tested | Tauri shell outside the tested path | -- |
| Installation guide | p. 18, p. 20 | `docs/installation.md` | clean-clone run | Integration-tested | Install time not measured | Time it once |
| Demonstration video | p. 19, p. 20 | runbook | **none** | **Missing** | **No video exists** | Record it, P0 |
| Total kit cost, power, added mass | p. 18-19 | -- | none | **Missing** | No kit specified | Leave blank or list once the Pi kit is fixed |
| Time for an operator to read an alert | p. 19 | dashboard | none | **Missing** | No usability trial | Time one |

## 5. Package and integrity (template §10-11, 12 marks)

| Requirement | Official source/page | Existing implementation | Evidence available | Status | Gap | Next action |
|---|---|---|---|---|---|---|
| Source, guides, tests, injection scripts, results, configs | p. 20 | repository | `git ls-files` | Implemented | Build the archive from Git, not a zip of the tree | `git archive` at the freeze |
| Dependency list and licences | p. 20, p. 22 | `THIRD_PARTY_NOTICES.md` | partial audit | Partial | Rust crates declared only; ALFA licence conflict (CC BY 4.0 vs CC0); Tauri icons | Team to resolve |
| Risk register | p. 20 | `docs/RISK_REGISTER.md` | corrected, unsigned | Implemented | Still describes a Pi Zero 2W target as the design | Update once the kit is fixed |
| AI tools declared and verified | p. 22, p. 24 | §11.1 | team statement pending | Partial | Team must state what it verified | Human |
| Integrity declaration signed | p. 22 | §11.3 | typed name only | Partial | Must be read and signed after the freeze | Human |

## 6. Rubric reading (p. 25)

The rubric is explicit that "evidence from actual flight operation carries full weight", that simulated results "carry limited
weight", that "anything that is not demonstrated is treated as design", and that "a smaller IDS with traceable results and defensible
claims is preferred over a larger one with unproven claims". The largest scoring exposure is therefore §7 and §8, where the team has **no
flight data**. No amount of software work closes that. The honest report is the best available position short of a flight, and even
a short receive-only flight log, if the team can legally and safely obtain one, would add more than any further simulation.
