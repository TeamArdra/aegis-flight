# Stage 2 GPS-degraded demonstration plan

Two separate paths. **Path A is real hardware and receive-only. Path B is synthetic and is never presented as measured.** They use
different commands, different databases and different output folders, and the dashboard's badge differs (`BENCH` vs `REPLAY`).
Exact commands and the narration are in `docs/STAGE2_DEMO_RUNBOOK.md`.

Every result quoted here was produced today on `main` `f9945a7` with no hardware: `REPLAY` of earlier `BENCH` captures, or the
synthetic fixture. Files are in `artifacts/validation/stage2_readiness_20261103/`. **No serial port was opened for this plan.**

## 1. What the hardware will probably show

The OS device list on 2026-11-03 (read with `Get-PnpDevice`, which does not open a port) shows:

| Device | Port | Meaning |
|---|---|---|
| ArduPilot MAVLink | **COM5** | The board's own USB (`VID_1209&PID_5740`) |
| ArduPilot SLCAN | COM4 | CAN interface. **Never open it** |
| CP210x telemetry radio | **not present** | Earlier captures with GPS data came through this radio, then on COM7 |

Port numbers can change, so re-check on the day. **The choice of link decides what the demo can show:**

| Link | What arrives (from earlier captures) | Can the dashboard show GNSS state? |
|---|---|---|
| USB, fresh boot, no ground station has connected | HEARTBEAT + TIMESYNC only (`pixhawk6x_passive_probe_001.json`: 198 frames, 1 of the 6 messages) | **No.** Fix state stays unknown. Coverage line only, 0 alerts |
| Telemetry radio on TELEM1 | All six messages + `EKF_STATUS_REPORT` once `SR1_*` are set (captures 007-009, 2026-10-28) | **Yes** |
| USB after Mission Planner connected on this boot | Probably streams: a GCS stream request is held in RAM until reboot, per ArduPilot source read at `Copter-4.6.3` (`docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.1 S2); the board's own firmware is unknown. Not verified on USB | Possibly. **Not part of this plan: a ground station transmits to the controller, which the hard rules exclude. It needs your explicit decision, and disclosure on camera** |

**Recommendation: connect the telemetry radio and use its port for the demo.** USB-only gives an honest but nearly empty demo. Do not
change `SR0_*` or any other parameter to fix that: parameter changes are out of scope.

## 2. Path A: real hardware, degraded GNSS, receive-only

**Tag:** `BENCH`, claim class none. **Purpose:** real telemetry reception, real GNSS state, correct handling of missing position data.
**Not a purpose:** detecting any attack. Nothing is injected.

### 2.1 Facts to re-check rather than assume

| Historical note | What the repository actually says |
|---|---|
| ArduCopter 4.6.3 | **Not established.** The board's firmware version was never read. 4.6.3 is the *source tag* the team read. The board has a pre-4.7 parameter layout (`SRn_*`). Reading the version needs a ground station, which transmits, so leave it "not determined" unless you decide otherwise |
| COM7 at 115200 | COM7 was the CP210x on earlier dates. It is absent today. 115200 was empirically right on that radio (0 CRC rejects); 57600 gave garbage. USB-CDC ignores baud |
| Capture 007: 1,620 frames, `fix_type` 0, 0 satellites | Confirmed. It means **no receiver reported**, not "no fix indoors" |
| GPS module attachment not established | **Superseded.** Captures 008, 009 and 2026-10-28 show a receiver reporting 3D fix, 6-7 satellites, while the autopilot reports GPS unhealthy and no horizontal solution. Attachment today must be checked by eye |

### 2.2 What the IDS does in each case (`REPLAY` of real captures, ML off)

This table is the expected-output reference for the day.

| Likely indoor condition | Nearest real capture | Default profile: threat / alerts / decisions | Indoor profile: threat / alerts | What the dashboard says |
|---|---|---|---|---|
| Heartbeat only (USB) | 005 | 0 / 0 / 296 | 0 / 0 | GPS line absent, "position unknown" coverage |
| Position messages, **no receiver or no fix** | 007 | **295 / 15 `DOS` / 300** | 0 / 0 | "NO_GPS · 0 sats · usable fix no"; default also shows `SUSPICIOUS / DOS` |
| Fix degrading during the run | 008 | 138 / 8 (7 `DOS`, 1 `TELEMETRY_MANIPULATION`) / 313 | 5 / 2 (1 `GPS_SPOOFING`, 1 `TELEMETRY_MANIPULATION`) | see §2.3 |
| 3D fix held, unhealthy estimator | 009 | 0 / 0 / 300 | 0 / 0 | "usable fix yes" **and** "no horizontal position solution" |
| 3D fix, 6-7 satellites, wander to 34 m | 2026-10-28 | 0 / 0 / 450 | 0 / 0 | same, with the health note |

### 2.3 The decision you must take before the demo

**With the default configuration, a no-fix link raises `DOS` alerts.** No indoor no-fix was captured on this exact setup: capture 007 reported no receiver at all, while 009 and 2026-10-28 reported a 3D fix, so which case you get is not known in advance. The rule text says "GNSS fix never acquired … (no valid fix
since monitoring began)", but the alert class is `DOS` and the threat card reads `SUSPICIOUS`. Replay of capture 007 gives 15 alerts in
60 s. That conflicts with the requirement not to treat indoor no-fix as an attack. `docs/HARDWARE_BENCH_PIXHAWK6X.md` §6.9 already records
this as "open, user decision".

| Option | What it does | Honest cost |
|---|---|---|
| **A. Default profile, narrated** | Show it as it is. Say aloud: "the rule cannot tell a no-fix from denial, so it raises a `DOS` whose text says no fix was ever acquired; this is a false alarm, not an attack finding" | The screen reads `SUSPICIOUS / DOS` (score 0.6176, the same as a real fix loss) during the segment you are using to show no false claim |
| **B. Indoor profile (recommended for the live segment)** | `--config-dir demo/indoor_bench_profile` raises only `gnss_loss_ticks`, so this one rule cannot fire. "usable fix no" stays on screen; capture 007 gives 0 alerts, threat 0 | Real GNSS loss is not flagged in that run. **Say so on camera.** Quote no detection or false-alarm number from this profile as the default's |
| C. Change the detector to score never-acquired as coverage | The cleanest long-term answer | A detector policy change: not made in this task. Needs your approval, a benchmark re-run and a test update (`tests/unit/test_missing_telemetry*.py` pin today's behaviour) |

**Recommendation: B for the live segment, and state the default behaviour in one sentence, showing
`demo/screenshots/dashboard_REPLAY_capture007_nofix_default_profile.png`.** That is more honest than either hiding the alert or pretending
it is correct. The report (§7.1) states the default behaviour as a known limitation either way.

**A remaining false label.** If the fix degrades during the run (capture 008), even the indoor profile raises one `GPS_SPOOFING` alert:
"GPS_RAW_INT velocity differs from EKF velocity by 3.1 m/s > 3 m/s". On a stationary board that is receiver noise, not an attack.
If it appears, say so. Do not edit it out.

### 2.4 Safety boundary

`run_serial_ids.py` has no transmitting mode (`--defense-mode` accepts only `passive`, `advisory`). `aegis serve` refuses `active-ips` on
a serial device, and the dashboard's API answers an error if the button is pressed (`tests/unit/test_defense_safety.py`). The transmit
counter must stay 0. **Opening the port still asserts DTR/RTS (unmeasured), so `bytes_sent` 0 is a software counter, not a wire
measurement.**

Forbidden throughout: parameter changes, arming, mode or mission commands, corrective commands, injected spoofing or jamming, receiver
reconfiguration, writing coordinates to the controller.

### 2.5 What to capture

Run outputs go to new folders under `artifacts/hardware/`. Raw `.tlog`, `.rawbin` and `.sqlite` stay git-ignored because they hold the
real position. **The dashboard shows a local-frame track and no coordinates, but do not open the tlog on camera.**

## 3. Path B: synthetic GPS replay, clearly labelled

**Tag:** `SIM`-class synthetic fixture, replayed. Claim class none. **Purpose:** show the dashboard and the pipeline responding to GPS
anomalies, which an indoor bench cannot provide.

**Why a new fixture.** The existing `SIM` console has drift, jump and jamming modes, but not one repeatable timeline with recovery, and its
ML is on. Existing replay captures contain no GPS anomaly. So one small file was added, and nothing else: no new source, no new
pipeline, no detector change.

| Item | Value |
|---|---|
| Generator | `scripts/demo/make_synthetic_gps_tlog.py generate --out demo/fixtures` |
| Fixture | `demo/fixtures/SIMULATED_GPS_not_measured_v1.tlog`, 175,560 bytes, 4,340 frames, sha256 `21960b073417…`. The file name is on the dashboard's source bar |
| Ground truth | `SIMULATED_GPS_not_measured_v1.groundtruth.json`. Scoring reads it after each decision; detectors never see it |
| Input fields | HEARTBEAT, SYS_STATUS, GPS_RAW_INT, EKF_STATUS_REPORT, GLOBAL_POSITION_INT, ATTITUDE, VFR_HUD, unsigned MAVLink 2 |
| Determinism | Fixed seed and fixed start time; identical bytes on every build (pinned by a test) |
| Tests | `tests/unit/test_synthetic_gps_demo.py` (11) |
| Limits | No sensor model, no wind, straight constant-speed track. Attacks are **separable by construction**, so the template gives this little weight. It proves the pipeline runs end to end, not that spoofing is detected |

### 3.1 Timeline, expected response and actual result (default profile, ML off)

| Time (s) | Phase | Input | Expected | Actual: threat / alerts / decisions | First alert |
|---|---|---|---|---|---|
| 0-30 | NOMINAL | true track, 3D fix, 10 satellites | quiet | 0 / 0 / 150 | -- |
| 30-50 | SLOW_DRIFT | 1 m/s north, velocity truthful | **no alert** (documented floor) | 0 / 0 / 100 | -- |
| 50-70 | FAST_DRIFT | 6 m/s north | `GPS_SPOOFING` | 88 / 5 / 100 | 52.4 s |
| 70-85 | SUDDEN_JUMP | +200 m east, then held | `GPS_SPOOFING` at the jump; held offset forgotten | 16 / 1 / 75 | 72.4 s |
| 85-105 | GNSS_LOSS | offset removed; fix 1, 3 satellites | return-jump `GPS_SPOOFING`, then `DOS` "GNSS fix lost" | 98 / 6 (1 + 5) / 100 | 85.4 s |
| 105-140 | RECOVERY | nominal | alerts stop, threat clears | 1 / 0 / 176 | -- |

The 72.4 s first alert in the jump phase is the 4 s per-class alert cooldown after the 68.4 s alert, not detection time. Through the real
backend (`aegis serve --source replay`, 10x speed): 12 persisted events (7 `GPS_SPOOFING`, 5 `DOS`), `aegis verify-log` chain OK,
matching the offline evaluation. Figures: `figures/alert_timeline_SIMULATED_GPS.png`, `figures/alert_evidence_SIMULATED_GPS.png`.
Screenshots: `demo/screenshots/dashboard_REPLAY_SIMULATED_GPS_*.png`.

### 3.2 CUSUM: exists, disabled, not exercised, not recommended

`CusumDriftIntegrator` and a CUSUM rule are in `detectors/physics.py`, and the feature `cusum_drift_m` is computed in `features/extractor.py`.
**`cusum_enabled` defaults to false and no config sets it**, so this demo does not exercise it. Measured with it switched on in a scratch
copy of the config, not committed:

| Data | CUSUM off | CUSUM on |
|---|---|---|
| Fixture, SLOW_DRIFT phase | 0 alerts | 5 `GPS_SPOOFING`, first at 33.4 s |
| Fixture, NOMINAL phase | 0 threat | 0 threat |
| Real stationary capture 009 | 0 threat, 0 alerts | **149 threat, 8 false `GPS_SPOOFING`** |
| Real stationary capture 2026-10-28 | 0 threat, 0 alerts | **405 threat, 22 false `GPS_SPOOFING`** |
| Real capture 008 | 0 `GPS_SPOOFING` | 11 `GPS_SPOOFING` |

So on a synthetic track it finds what the rules miss, and on real indoor streams it fires on receiver wander. **Do not turn it on for the
demo and do not present it as a working detector.** Its effect on the Stage-1 benchmark was not measured.

## 4. What this plan cannot show

Real RF spoofing or jamming; detection on a real vehicle; flight; a healthy hardware estimator; the Raspberry Pi; any false-alarm rate.
Say these out loud at the end of the demonstration (`docs/STAGE2_DEMO_RUNBOOK.md` Segment 8).
