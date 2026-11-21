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

### B. Companion-Computer Resource & `tc netem` Bench (Docker)
Simulates a resource-capped companion (`2 vCPU / 512 MiB RAM`) and Linux kernel `tc netem` telemetry-radio impairments (`40ms ± 20ms` jitter, `3%` burst loss, `4%` reordering, `0.2%` corruption):
```bash
docker compose -f deploy/bench/docker-compose.yml run --rm aegis-companion
```
To launch with containerized ArduPilot Copter SITL + `tc netem`:
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
   Capture known-good Pixhawk firmware hashes (`aegis fw-manifest <dir>` (writes an unsigned `manifest.json`; keep it with the images)) and save an HMAC-signed `configs/firmware_allowlist.yaml`.
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
