# AegisFlight — Stage 2 Demonstration Runbook

For demonstrating the Stage 2 UAV Intrusion Detection System (passive demo; the defense layer is shown as a **simulation model**; the inline bridge was verified on ArduCopter SITL and on a bench with a real Pixhawk 6X, disarmed, over a real radio pair
(`docs/RADIO_TEST_RESULTS.md`), not in flight, and no prevention is demonstrated on a flying vehicle) for **PUSHPAK Grand Challenge 2026-27 (IIT Bombay Techfest) — Security of Drones, Objective 2**.
A teammate can run this without the original author.
**For recording the submission video use `docs/DEMO_SCRIPT_SOFTWARE_ONLY.md`** (a narrated, step-by-step plan with environment labels
and a limitation segment); this file is the longer feature tour.

> **What this demo is (2026-10-29).** Segments 1–7 run on the **SIM** source: the dashboard drives a simulator and a cyber-physical
> *twin*. Detection times, "detour" and "vehicle remains airborne" are what that model shows; they are **not measurements** of a
> vehicle, and no prevention metric exists (`docs/VALIDATION_EVIDENCE.md`). The map panel is a local-frame track (no tiles, no
> internet). On a serial-device source `active-ips` is refused (receive-only); on replay nothing is sent (no transport); on a
> UDP or `socket://` (SITL) link `active-ips` does send counter-commands.
>
> **Real-data segment (REPLAY of BENCH data, receive-only, nothing is sent anywhere)** — the 2026-10-28 capture of the powered-on vehicle:
> ```bash
> aegis serve --source replay --tlog data/hardware/raw/gps_hw_verify_20261029.tlog --replay-speed 1.0 --db <scratch>/replay.sqlite
> ```
> Checked through the API at 10× speed on 2026-10-29 (saved, coordinate-free, in
> `artifacts/hardware/gps_hw_verify_20261029/replay/navigation_health_api/`): `environment` REPLAY, 5,130 frames, `link.gps` shows `3D_FIX`,
> 7 satellites, `valid_fix` true **and** `horizontal_solution` false, `gps_healthy` false, `quality_flags` both set; `/api/events` count 0.
> The header is intended to show the vehicle's own "no horizontal position solution / GPS sensor unhealthy" note beside "valid fix"
> (wording unit-tested; not screenshotted). Say what it shows: a vehicle stated stationary and disarmed whose own telemetry reports no
> horizontal solution and an unhealthy GPS sensor (cause not determined), and an IDS that stays quiet while stating that. It is not an
> attack demonstration. The tlog is local and git-ignored.

## Pre-demo checklist
```bash
pip install -e ".[dev]"                       # deps installed
aegis train                                   # models/isoforest.joblib exists
npm --prefix frontend install && npm --prefix frontend run build   # frontend/dist exists
python scripts/verify_stage2.py               # 8/8 automated verification suites passing
pytest tests/unit/test_mitigation.py tests/unit/test_hal.py -q   # 34 tests passing
```
- Close other apps using port 8000.
- Have `aegis verify-log` ready in a second terminal.

## Startup
```bash
aegis serve                                   # http://127.0.0.1:8000 (SIM source, passive posture)
```
Then switch the posture to **ACTIVE IPS** in the dashboard to show the SIM defense twin. On the SIM source there is no
transport, so nothing is sent anywhere. Do not start a live (UDP / `socket://`) source in `active-ips` for this demo.
Or launch the native desktop GCS:
```bash
cd frontend && cargo tauri dev
```
The GCS displays:
- **● ACTIVE IPS** (after the posture switch; SIM model only)
- **● Connected** (10 Hz WebSocket telemetry)
- **Topology: SIM (modelled inline twin)**
- **Live Vehicle Head Pill**: `[COPTER_MODE_GUIDED · 12.0 m/s · 60.0 m]`
- **44px Vertical Altitude Profile Strip**: showing real-time 0–100 m elevation track.

## Segment 1 — Benign Flight Baseline (~20 s)
- Point out the nominal survey pattern on the local-frame track panel (there is no satellite map; the dashboard needs no network).
- Altitude strip holds flat at 60 m cruise; speed is 12 m/s.
- Threat score sparkline remains flat at 0.0 (below 0.45 threshold); 0 false alarms.

## Segment 2 — GPS Spoofing & Synthetic Navigation Recovery
- Click **GPS Spoofing**.
- **Detection** (SIM; the on-screen latency is not an artifact-backed figure — quote `artifacts/benchmarks/summary.md`: mean 0.361 s, p95 1.40 s): Physics + Anomaly detectors trigger (`HIGH / GPS_SPOOFING`).
- **Autonomous Mitigation**:
  - In **Topology B** (Inline): `aegis ips-bridge` (`docs/INLINE_IPS.md`) drops hostile uplink frames before the autopilot and corrects spoofed position on the downlink; the dashboard's SIM twin shows the effect as a model (no measured detour). Verified on ArduCopter SITL / loopback and on a bench with a real Pixhawk 6X, disarmed (`docs/RADIO_TEST_RESULTS.md`); not in flight.
  - In **Topology A** (Sidecar): the controller encodes counter-commands (EKF source switch only with a declared secondary source, otherwise ALT_HOLD; mode restore for command injection) and sends them in ACTIVE_IPS only, and only on a UDP or `socket://` (SITL) link; the dashboard shows the command it would send. In the one ArduCopter SITL sidecar run the vehicle was not recovered from an injected LAND (`docs/INLINE_IPS.md`).
- Notice the vehicle track continues smoothly along the planned trajectory without jumping or diverging.

## Segment 3 — Command Injection & Failsafe Veto
- Click **Command Injection** (e.g., unauthorized land or forced disarm).
- **Flagged, not blocked**: the mitigation controller detects the cadence/provenance violation and records a `VETO_DISARM` action ("Flagged motor arm/disarm command burst in flight (not blocked)", `src/aegisflight/mitigation/controller.py`). The command is not rejected and no veto banner is sent.
- In the SIM twin the vehicle remains airborne and continues the mission (a model of what a veto would do; nothing was vetoed on a vehicle).

## Segment 4 — Denial of Service & High-Rate Flood
- Click **Denial of Service**.
- Threat state escalates to `CRITICAL / DOS`.
- `MitigationController` (`src/aegisflight/mitigation/controller.py`) records a `RATE_LIMIT` action for `DOS_FLOOD` / `MAV_RATE_SPIKE` and sets the
  sanitizer's rate-limit flag after 3 consecutive DoS ticks; `FrameSanitizer` then drops every msgid except HEARTBEAT, ATTITUDE,
  GLOBAL_POSITION_INT and COMMAND_LONG and caps those at 120 frames/s (`mitigation/sanitizer.py`). Frames are dropped only on the
  inline bridge; on the SIM source this is the model's view. A blackout (`DOS_BLACKOUT`) records `LINK_WATCHDOG`.

## Segment 5 — Hardware Abstraction Layer & Topology Detection
- In the **Defense HUD**, read the **detected topology** (no selector): `A` sidecar, `A+B` inline bridge, or SIM/REPLAY. It lists what it can do (block frames, send counter-commands) from the live link and posture.
- Point out the status card following the posture and link state.

## Segment 6 — Tamper-Evident Hash Chain Forensics
- In the second terminal:
  ```bash
  aegis verify-log artifacts/aegisflight_live.sqlite
  ```
- Terminal prints `events: <N>  chain: OK  ...` (`_cmd_verify_log` in `src/aegisflight/cli/main.py`).
- Explains the SHA-256 hash chain over alerts (`aegis verify-log`); no airworthiness compliance is claimed.

## Segment 7 — Automated Verification Benchmarks
- Run the full automated verification audit:
  ```bash
  python scripts/verify_stage2.py
  ```
- 8/8 suites pass in about 2 s (1,949.9 ms measured 2026-10-29; hand-built `SIM` inputs, not validation evidence):
  1. GoldenState dead-reckoning test
  2. FrameSanitizer coordinate clamping test
  3. Killswitch disarm & land veto test
  4. Command cadence guard test
  5. Micro-drift CUSUM test
  6. HAL discovery & topology test
  7. InlineBridge watchdog test
  8. GCS alert dispatch test

## Shutdown
`Ctrl-C` the server. Clean shutdown leaves SQLite ledger verified.
