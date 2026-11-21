# AegisFlight Hardware & Real-Flight Readiness Playbook

This guide outlines the exact validation sequence for taking AegisFlight from a software-only workstation (zero flight hardware) to props-off bench testing, passive real-world flight logging, and controlled inline IPS qualification.

> **Evidence boundary:** Automated tests and `SIM`/`SITL` benches do not claim real outdoor flight validation. Real-flight claims require recorded hardware captures (`.tlog`/`.ulog`) replayed through AegisFlight with `0` unacknowledged physical risks.

---

## 1. Zero-Hardware Preparation (Software + Resource-Capped Bench)

Before touching physical hardware, run all four layers below on your development host:

### A. Pre-flight drills & RF-impaired extreme-flood soak (Local Python)
```bash
python -m aegisflight.cli.main field-drill
python scripts/hardware/hw_readiness_soak.py --cycles 5 --flood-frames 5000
```
Verifies:
- `4/4` shadow drills (`zero_real_fc_tx=True`).
- `0` false alerts during harsh RF flight (4% loss, reordering, corrupt UART bytes, yaw sweeps).
- `0` crashes / bounded state tables under 5,000+ spoofed-ID flood frames + IEEE-754 `NaN`/`Inf` frames.
- Fail-closed uplink blocking (`dropped_unsigned`, `dropped_semantic_param`, `dropped_untrusted_control`) under signed `ACTIVE_IPS`.
- Validated SHA-256 `events` + `actions` chains and HMAC-signed `anchors.jsonl`.

### B. Companion-Computer Resource Bench (Docker, SIM only)
Runs the field drill and the soak above inside a resource-capped container (`2 vCPU / 512 MiB RAM`). Export
`AEGIS_API_TOKEN` and `AEGIS_ANCHOR_KEY` first (the compose file has no default secrets):
```bash
docker compose -f deploy/bench/docker-compose.yml run --rm aegis-companion
```
The compose command also applies a `tc netem` qdisc to the container's `eth0` (`apply_netem.sh`, defaults `40ms ± 20ms`
jitter, `3%` loss, `4%` reordering, `0.2%` corruption). **That impairment does not reach the drill or the soak**, which use
in-memory transports and open no socket, so no result from this step is evidence about behaviour on an impaired radio link.
The `sitl` profile only starts an ArduCopter SITL container (image pinned by digest) on the same network; the default
command does not connect to it and does not start the dashboard:
```bash
docker compose -f deploy/bench/docker-compose.yml --profile sitl up --build
```

### C. Interactive Operator Drill (Gazebo + PX4/ArduPilot SITL + QGroundControl)
1. Start Gazebo Harmonic + SITL (`scripts/sitl/start_px4_sitl.sh start` on Linux/WSL, or ArduPilot SITL with `SIM_WIND_SPD=12`, `SIM_WIND_TURB=4`, `SIM_GPS_NOISE=0.8`).
2. Start AegisFlight loopback dashboard with token + anchor HMAC keys:
   ```bash
   export AEGIS_API_TOKEN="<operator-secret>"
   export AEGIS_ANCHOR_KEY="<anchor-hmac-secret>"
   aegis serve --source udp --udp-port 14550 --config-dir configs/universal_flight
   ```
3. Practice full operator incident response (`PASSIVE` -> `ADVISORY` -> `ACTIVE IPS`, `HoldConfirmButton`, `SAFE_HOLD` / `ACK_TAKEOVER`, and `/api/forensic/report`).

---

## 2. Props-Off Physical Hardware Bench (Receive-Only `PASSIVE`)

Once you have a real Pixhawk and companion computer (**props removed, bench power only**):

1. **Zero-TX Port Discovery:**
   ```bash
   aegis onboard --preflight --run-dir <writable-dir> --config configs/onboard_default.yaml
   ```
   Confirm `0` bytes transmitted during probe (`discover_mavlink_ports`) and verify serial receive-only safety (`may_reach_vehicle()` blocks `ACTIVE_IPS` on OS serial devices).
2. **Firmware Manifest Enrollment:**
   While disarmed, passively capture the Pixhawk `AUTOPILOT_VERSION` (0 B TX) with `aegis onboard --enroll-firmware OUT_YAML`
   (optionally HMAC-signed with `AEGIS_ALLOWLIST_KEY`) and use `OUT_YAML` as the firmware allowlist
   (e.g. `configs/firmware_allowlist.yaml`). `aegis fw-manifest DIR` is a different tool: it hashes `*.bin` files.
3. **RX-Only Cable Check:**
   Physically disconnect the UART TX pin between the companion computer and Pixhawk TELEM port while testing `PASSIVE` monitoring, confirming QGroundControl and autopilot behavior are completely unaffected.

---

## 3. Staged Progression to Real Outdoor Flying & Inline IPS

Never jump directly to free-flight `ACTIVE_IPS`. Follow all 5 gates in order:

| Stage | Environment | Posture | Mandatory Hardware Safeguard | Exit Gate |
| :--- | :--- | :--- | :--- | :--- |
| 1 | SITL + Gazebo + `tc netem` + Docker cap | `ACTIVE_IPS` (signed) | Loopback only | `0` false counter-commands over 10+ hr soak |
| 2 | Props-off Pixhawk HITL bench | `ACTIVE_IPS` (signed) | Normally-closed (NC) UART bypass relay | Power-yank fails over in `< 10 ms`; clean EKF switch |
| 3 | Outdoor free flight | `PASSIVE` (RX-only) | UART TX disconnected | Replay real `.tlog`/`.ulog` logs; verify low `FA/hr` |
| 4 | Netted / tethered hover | `--vehicle-filter` (signed) | Direct RC safety pilot + NC bypass relay + `--filter-override-file` | Legitimate signed GCS passes `< 5 ms`; forged uplink dropped |
| 5 | Open range qualification | `ACTIVE_IPS` (signed) | Direct RC safety pilot + NC bypass relay + override switch | Verified `ALT_HOLD` / pilot RC takeover recovery |

---

## 4. Measured Evidence Added After Stage-2.4 (2026-11-21)

Every row names its environment. None is a physical-vehicle or outdoor-flight result.

| Env | Claim class | Result | How to re-run |
| :--- | :--- | :--- | :--- |
| REPLAY (PX4-VTOL-SITL tlog over virtual serial; **not** an outdoor flight) | link-level detection | 8 s unplug (`--drop-at 20 --drop-for 8`): before the fix 2 alerts (`MAVLINK_ANOMALY` + `DOS`, `heartbeat stale 8.9s`, `sequence gap 218`) right after reconnect; after the fix `alert_decisions=0`, hash chain OK, 251 decisions in 50 s | `virtual_serial_replay.py <tlog> --speed 1 --drop-at 20 --drop-for 8`, then `run_serial_ids.py --port socket://127.0.0.1:<p> --allow-url --config-dir configs/universal_flight --seconds 50` (tlog: local `Normal/2020-08-02 15-30-00.tlog`, not committed) |
| REPLAY (same tlog, first 120 capture s, 8x) | compute budget | `configs/universal_flight`, ML off: 601 decisions, compute p50/p95/max 1.88/3.00/3.67 ms, 0 dropped, identical to unpaced. Dev laptop, not a companion board | `paced_replay.py <tlog> --factor 8 --ml off --config-dir configs/universal_flight --max-capture-s 120` |
| SIM (SIGKILL of a writer process) | tamper-evidence | WAL store + anchors reopened after kill at 0.15/0.4/0.8 s: `integrity_check ok`, chains OK, a torn final anchor line is flagged as invalid JSON, store stays writable. A process kill, not a real power cut | `pytest tests/unit/test_power_loss_recovery.py` |
| SIM (unit) | watchdog contract | `HardwareWatchdog` toggles at 4 ms, stops pulsing when workers are unhealthy, drives the pin low on stop. The `< 10 ms` relay release also depends on the external detector and is **unverified on hardware** | `pytest tests/unit/test_hw_watchdog.py` |

Behaviour change: after a local port outage the extractor reports a transport fault until a fresh `HEARTBEAT`
arrives (bounded at 5 s, so jamming after reconnect still alerts) and resets sequence state.

### Opt-in hardware watchdog

Disabled unless `AEGIS_HW_WATCHDOG_PATH` is set (a GPIO `value` file); `AEGIS_HW_WATCHDOG_PERIOD_MS` accepts 1-5 (default 4).
Drive the relay coil through a retriggerable monostable that releases after about 8 ms without an edge.
`aegis onboard` starts the pulse after READY and stops it (pin low) on exit; it is suppressed if bridge workers die.

### Live SITL + `tc netem` bench results (2026-11-21, tag `SITL`, link-level only)

Setup: `deploy/bench` containers (`radarku/ardupilot-sitl` ArduCopter, companion 2 vCPU / 512 MiB), `tc netem` on both egress sides (rate 115200 bit, delay 40 +/- 20 ms, loss 3%, reorder 4%, corrupt 0.2%), wind 12 m/s, turbulence 4, GPS noise 0.8, battery sag. Artifacts are container-local (`/h/run_*`), not committed; harness scripts are not in the repo.

- **Benign soak 1 (30 min, untuned universal profile):** 96,816 frames down, 11 alerts (10 heading/yaw > 10 deg, 1 ConstDet 44.4 m/s2 spike). Bridge latency p50 21.5 us, p95 124.7 us; RSS <= 78 MB; CPU mean 7.4%, max 9.0%.
- **Tuning (`configs/universal_flight/detector.yaml` only; Stage-1 `configs/detector.yaml` untouched):** `control_accel_residual_ms2` 8.0 (benign wind residual p99 6.15, max 6.43) and `heading_yaw_tolerance_deg` 20.0. Regression tests: `tests/unit/test_universal_constdet_wind.py`. Cost: heading/yaw offsets below 20 deg are no longer flagged on the universal profile.
- **Benign soak 2 (20 min, tuned profile):** heading/yaw false alarms gone; 8 ConstDet alerts (about 24/h extrapolated; spikes 8.2-57 m/s2, attributed to netem loss/reorder/corruption on velocity deltas, not fixed). Event chain OK, 245 signed anchors OK, `PRAGMA integrity_check` ok, RSS <= 77.8 MB, CPU mean 6.9%, max 8.0%.
- **Compound attack under signed ACTIVE_IPS (15 min flight, attack t=300-390 s):** 5,000 msg/s flood from an unauthorised sysid, rogue/spoofed unsigned COMMAND_LONG, unsigned and signed PARAM_SET, GPS drift. Zero tracebacks, 0 analyser errors, bridge stayed up. 409,580 uplink frames dropped (409,400 by the dynamic rule, 180 unsigned control frames); 23 `DOS` alerts and 1 `MAVLINK_ANOMALY` during the flood; RSS <= 81.2 MB; CPU mean 12.8%, max 61.8% (flood). Event chain OK, 186 signed anchors OK, integrity_check ok.
- **Limitations found in that run:**
  - The legitimately signed in-flight `PARAM_SET` (FS_GCS_ENABLE) was forwarded (`semantic_firewall.dropped_param` = 0). Treat as an open gap for armed flight.
  - The IDS reacted to the GPS drift late (ALT_HOLD at t=456 s) and no `GPS_SPOOFING` event for the drift was found in the event table (STATUSTEXT messages only); the vehicle disarmed at t=579 s for a cause not established. RC takeover/recovery was not exercised.
  - An earlier attack run was discarded: the harness sent unsigned frames (import-order bug), so it measured nothing about recovery.

### Stage-1 regression and readiness soak on the final head (2026-11-21)

- `aegis benchmark --out <scratch> --no-figures` with the hash-verified `models/isoforest.joblib` (`scripts/fetch_models.py`): `TP / FP / TN / FN = 6535 / 4 / 16826 / 65` (tag `SIM`). Unchanged from the Stage-1 baseline.
- `python scripts/hardware/hw_readiness_soak.py --cycles 5 --flood-frames 5000`: `ok=True benign_alerts=0 attack_alerts=1 forwarded=5702 dropped_up=3 dropped_unsigned=2 dropped_semantic_param=1 analyser_errors=0 p95_us=5.3`, event/actions chains and anchors verified (tag `SIM`).
- **ML-on golden audit (SIM / REPLAY, 16 cases, audited per case).** With the model present, the ML-on section of `tests/golden/golden.json` (recorded on `origin/main` 6ef7600) no longer matched the Stage-2 stack: 16 of the 55 ML-on cases change their alert summary (the rest change only digests through additive `FeatureFrame` fields). The section was regenerated with `scripts/make_golden.py --ml-only` (model sha256 `3fe74cdd...2939c4`; ML-off section byte-identical, so the ML-off numbers did not move). `scripts/hardware/golden_ml_audit.py --base-tree <6ef7600 checkout>` traces every case on both trees and re-runs this tree with each suspected cause reverted: `rw0` = `features.reorder_window: 0` (issue #14 off), `ml_uncorr` = `anomaly.enabled: true` and `fusion.ml_require_corroboration: false` (issue #49 off, `configs/ardupilot_copter` only). A case is *explained* only when a variant reproduces the base tree's alert count, alert types and threat-decision count exactly. All 16 are explained; none is unexplained.

| case | base alerts / types | head alerts / types | first alert at/after onset (base -> head) | explained by |
|---|---|---|---|---|
| `sim/mavlink_anomaly:rate_spike/s3` | 5 ['DOS', 'MAVLINK_ANOMALY'] | 4 ['DOS'] | 17.0s MAVLINK_ANOMALY -> 17.0s DOS | rw0, rw0+ml_uncorr |
| `sim/dos:latency/s3` | 6 ['DOS', 'MAVLINK_ANOMALY'] | 6 ['DOS', 'GPS_SPOOFING'] | 17.0s MAVLINK_ANOMALY -> 17.0s DOS | rw0, rw0+ml_uncorr |
| `sim/link_reorder_benign/s7` | 15 ['DOS', 'MAVLINK_ANOMALY'] | 11 ['DOS'] | 0.0s MAVLINK_ANOMALY -> 3.8s DOS | rw0, rw0+ml_uncorr |
| `live/ekf_gate/profile` | 10 ['GPS_SPOOFING'] | 9 ['GPS_SPOOFING'] | 25.0s GPS_SPOOFING -> 25.2s GPS_SPOOFING | ml_uncorr, rw0+ml_uncorr |
| `live/mission/profile` | 10 ['GPS_SPOOFING'] | 5 ['GPS_SPOOFING'] | 32.0s GPS_SPOOFING -> 50.8s GPS_SPOOFING | ml_uncorr, rw0+ml_uncorr |
| `live/seq/profile` | 4 ['DOS', 'MAVLINK_ANOMALY'] | 1 ['MAVLINK_ANOMALY'] | 20.2s DOS -> 40.2s MAVLINK_ANOMALY | rw0+ml_uncorr |
| `live/seq/default` | 4 ['DOS', 'MAVLINK_ANOMALY'] | 3 ['DOS', 'MAVLINK_ANOMALY'] | 20.2s DOS -> 20.2s DOS | rw0, rw0+ml_uncorr |
| `live/flood/profile` | 4 ['DOS', 'TELEMETRY_MANIPULATION'] | 4 ['DOS', 'TELEMETRY_MANIPULATION'] | 25.0s TELEMETRY_MANIPULATION -> 25.2s TELEMETRY_MANIPULATION | ml_uncorr, rw0+ml_uncorr |
| `live/crossend/profile` | 11 ['DOS', 'GPS_SPOOFING', 'TELEMETRY_MANIPULATION'] | 3 ['GPS_SPOOFING', 'TELEMETRY_MANIPULATION'] | 30.0s GPS_SPOOFING -> 30.0s GPS_SPOOFING | ml_uncorr, rw0+ml_uncorr |
| `live/crossend_keyed/profile` | 44 ['DOS', 'GPS_SPOOFING', 'MAVLINK_ANOMALY'] | 2 ['GPS_SPOOFING'] | 5.0s MAVLINK_ANOMALY -> 30.0s GPS_SPOOFING | ml_uncorr, rw0+ml_uncorr |
| `live/mgmt/profile` | 7 ['DOS'] | 0 [] | 30.0s DOS -> none | ml_uncorr, rw0+ml_uncorr |
| `live/garbage/profile` | 54 ['DOS', 'MAVLINK_ANOMALY'] | 50 ['MAVLINK_ANOMALY'] | 0.8s MAVLINK_ANOMALY -> 0.8s MAVLINK_ANOMALY | ml_uncorr, rw0+ml_uncorr |
| `live/signed/profile` | 35 ['DOS', 'MAVLINK_ANOMALY'] | 17 ['MAVLINK_ANOMALY'] | 0.6s MAVLINK_ANOMALY -> 1.6s MAVLINK_ANOMALY | rw0+ml_uncorr |
| `live/signed/default` | 35 ['DOS', 'MAVLINK_ANOMALY'] | 33 ['DOS', 'MAVLINK_ANOMALY'] | 0.6s MAVLINK_ANOMALY -> 1.6s MAVLINK_ANOMALY | rw0, rw0+ml_uncorr |
| `live/spoof_drift/profile` | 1 ['GPS_SPOOFING'] | 1 ['GPS_SPOOFING'] | 50.0s GPS_SPOOFING -> 50.2s GPS_SPOOFING | ml_uncorr, rw0+ml_uncorr |
| `live/dropout/profile` | 5 ['DOS'] | 4 ['DOS'] | 30.2s DOS -> 34.0s DOS | ml_uncorr, rw0+ml_uncorr |

  Reading the table (alert counts are per 0.2 s decision, one ML-on run per case, model `isoforest.joblib`):

  - **False-positive reduction, no injected fault:** `live/mgmt/profile` 7 -> 0, `live/crossend/profile` 11 -> 3, `live/crossend_keyed/profile` 44 -> 2 and `sim/link_reorder_benign/s7` 15 -> 11 (reordered-link benign stream). Every removed alert came from `ml_anomaly` triggering alone (profile cases) or from a reordered frame counted as a sequence gap (`reorder_window`). The 3 and 2 alerts left on the two `crossend` profile cases also appear in the ML-off section and are unchanged by this audit. **Open observation:** `sim/link_reorder_benign/s7` still raises 11 ML-on alerts (ML-off: 0) in the default Stage-1 config, where `ml_anomaly` alone can alert. This is the pre-existing Stage-1 behaviour (15 before), the Stage-1 benchmark does not include it, and the live profiles guard against it with `ml_require_corroboration`. It is reported, not tuned away, because changing it would move the frozen benchmark.
  - **Same fault, same detector, same type** (first alert within one decision of the base tree): `live/ekf_gate/profile`, `live/flood/profile`, `live/spoof_drift/profile`, `live/garbage/profile`, `live/seq/default`, `live/crossend/profile`.
  - **Label change only, fault still alerts at onset:** `sim/mavlink_anomaly:rate_spike/s3` and `sim/dos:latency/s3` (first alert at 17.0 s as `DOS`; the ML-off golden already says `DOS`) and `live/signed/*` (first alert 0.6 s -> 1.6 s; the injected invalid-signature frames still raise `MAVLINK_ANOMALY`). The extra `GPS_SPOOFING` label on `sim/dos:latency/s3` is carried by two `ml_anomaly`-only decisions, as on the base tree.
  - **Sensitivity cost, needs reviewer sign-off:** `live/mission/profile` first `GPS_SPOOFING` alert 32.0 s -> 50.8 s (injected drift starts at 30 s; the base tree alerted through `ml_anomaly` plus physics, the head through physics alone); `live/seq/profile` first alert 20.2 s (30 dropped frames) -> 40.2 s (scrambled sequence numbers), so a pure sequence gap no longer alerts without the ML vote; `live/dropout/profile` 30.2 s -> 34.0 s. All three come from #49 disabling the Stage-1 simulator-trained Isolation Forest in the ArduCopter profile because it does not transfer to SITL rate and timing distributions. No case has an alert before its fault onset on either tree, and the shipped profile still detects every injected fault in this set, later in three of them. Whether an earlier but uncalibrated ML vote is worth its false positives is the maintainer's call (decision D2 on #79); this document does not claim it is approved.
  - **Stage-1 is not affected:** the default config is untouched, and `aegis benchmark --out <scratch> --no-figures` still reports TP/FP/TN/FN 6535 / 4 / 16826 / 65.

### Unit-level safety evidence: branch coverage, mutation testing, fuzz, acceptance specs (2026-11-21, tag `SIM`, unit-level only)

These numbers show how well the safety-critical modules are pinned by tests. They are not flight evidence and make no detection claim.

- **Line + branch coverage.** `python -m pytest tests/unit tests/acceptance --cov=src/aegisflight --cov-branch --cov-report=term-missing:skip-covered` (use the path form: `--cov=aegisflight.<module>` double-imports numpy under pytest-cov). Branch coverage on the safety modules: `mitigation/inline_policy.py` 99% (564 stmts, 0 missed, 3 partial branches), `mitigation/semantic_firewall.py` 98%, `sources/mavlink_serial.py` 97%, `mavlink/signing.py` 100%, `logging/store.py` 100%. `may_reach_vehicle()` is 100% line and branch and has an exact truth-table test (`tests/unit/test_may_reach_vehicle_exact.py`). The whole package is 85%, so the 90% target is met for the safety modules, not for the repository.
- **Mutation testing** (`mutmut` 3.8.1, `also_copy = [src, scripts]`, one run per module; the killed/total counts are the tool's own):

| module | killed / total | score | surviving mutants |
|---|---|---|---|
| `mitigation/semantic_firewall.py` | 383 / 393 | 97.5% | 10, all equivalent (default offsets, unused args) |
| `mavlink/signing.py` | 471 / 492 | 95.7% | reviewed; killing tests added afterwards (`test_signing_exact.py`), **not re-run** |
| `logging/store.py` | 506 / 587 | 86.2% | ~79 equivalent (SQL/PRAGMA case, `Row` keys, encoding aliases); 2 real gaps found and closed afterwards, **not re-run** |
| `mitigation/inline_policy.py` | 1245 / 1279 | 97.3% | 34, reviewed one by one; nearly all equivalent. Two were worth a test (observed-replay accounting, relearn after signing lapse) and have one now, **not re-run** |
| `sources/mavlink_serial.py::may_reach_vehicle` | 24 / 24 | 100% | mutmut could not drive this module, so these are 24 **hand-written** mutants, each killed by the truth-table test |

  Equivalent-mutant classes: SQL keyword/PRAGMA case, `sqlite3.Row` key spelling, codec alias names, default offsets that equal the parsed value, arguments that are never read. Every security-boundary mutant (signature check, replay drop, uplink drop, serial transmit gate, hash-chain link) was killed. Scores were produced on a loaded host, so a latency-sensitive mutant could have been mis-classified as a timeout; none of the survivors is one.
- **Bug found by this work.** `InlinePolicy._load_state` crashed startup when the state file held valid JSON of the wrong shape (for example a list). It now ignores any such file and starts with empty state (`AttributeError` added to the suppressed set). Regression test: `tests/unit/test_inline_policy_state_exact.py`.
- **Hostile-input fuzz:** `tests/unit/test_fuzz_hostile_inputs.py` (hypothesis, 500 examples per property, 24 properties) over `may_reach_vehicle` / `_check_port`, the frame parser and `split_frames`, the sanitizer, the pipeline and detectors on poisoned input, the semantic-firewall extractors and verdicts, `InlinePolicy` (unsigned and forged-signature control frames, sensitive commands, untrusted sysids and armed protected-parameter writes are never forwarded; the fail-open path is not reached on arbitrary input) and the hash chain (verifies for any event sequence, detects any single-field tamper or row deletion).
- **Acceptance specs** (`pytest-bdd`, `tests/acceptance/`): active IPS, receive-only serial, forensic chain.

### Not run in this pass

- **Multi-hour live SITL soak:** not run. The SITL runs below are 20-30 min flights, so every per-hour figure is a short-run extrapolation.
- **Real outdoor replay `FA/hr`:** not measured. The only tlogs on the dev host are PX4-VTOL-SITL captures.
- `aegis onboard --preflight` on a laptop fails only `run_root_writable` (default `/var/lib/aegisflight`); pass `--run-dir`.

### Go / No-Go checklist for physical bench day 1

- [ ] `aegis onboard --preflight --run-dir <dir>`: all checks `ok`, `0` bytes transmitted.
- [ ] `aegis fw-manifest <dir>` baseline stored with the firmware images.
- [ ] `aegis field-drill`: `4/4 passed (zero_real_fc_tx=True)`.
- [ ] Props off, TX pin disconnected, `PASSIVE` only; 30 min benign bench with `0` alerts.
- [ ] USB unplug/replug during the run produces no `DOS` / `MAVLINK_ANOMALY`.
- [ ] `kill -9` of `aegis onboard`, restart: `aegis verify-log <db> --anchors <file>` OK.
- [ ] NC relay: scope the pulse pin and measure release time after `kill -9` (`< 10 ms` required) before any `ACTIVE_IPS`.
- No-Go on any of: serial TX observed, unexplained alert on a benign bench, chain verification failure, relay release `>= 10 ms`.
