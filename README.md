# AegisFlight

<p align="center">
  <strong>Cyber-Physical Intrusion Detection System for Unmanned Aerial Vehicles</strong> (passive by default; an optional inline prevention bridge is verified on ArduCopter SITL, and on a bench with a real Pixhawk 6X and a radio pair, but not in flight)
</p>

<p align="center">
  <em>Developed for the <strong>PUSHPAK Grand Challenge 2026–27 (IIT Bombay Techfest) — Security of Drones, Objective 2</strong></em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg" alt="Python Version" />
  <img src="https://img.shields.io/badge/Rust-2021%20Edition-orange.svg" alt="Rust Edition" />
  <img src="https://img.shields.io/badge/Tauri-2.0%20Desktop%20GCS-24C8DB.svg" alt="Tauri GCS" />
  <img src="https://img.shields.io/badge/Protocol-MAVLink%20v2-green.svg" alt="MAVLink v2" />
</p>

---

## 1. Executive Overview

**AegisFlight** is a cyber-physical intrusion detection system for UAVs running MAVLink v2 telemetry (ArduPilot and PX4 autopilots), with a three-posture defense layer (PASSIVE / ADVISORY / ACTIVE IPS) and a cyber-physical twin in the dashboard.

Modern UAVs operating in contested or civilian airspace are vulnerable to RF telemetry injection, GPS spoofing, Denial-of-Service (DoS) floods, and rogue command overrides (e.g. forced mid-air disarming or unauthorized waypoint redirects). Conventional IT security solutions treat telemetry packets as opaque network blobs and fail to account for aircraft aerodynamics or latency constraints.

In the simulator, the dashboard runs a **cyber-physical flight twin** and shows what the defense layer's counter-actions would do. Decision compute is 17.7 ms mean / 23.6 ms p95 with ML on (`artifacts/benchmarks/summary.md`, SIM; measured before the pipeline optimisation). The optimisation was measured with a different, smaller workload, `scripts/perf_bench.py` (6 SIM sessions and 5 synthetic live streams, 3 repeats, ML on): per decision tick 11.87 ms mean / 13.40 ms p95 before and 0.24 ms mean / 0.31 ms p95 after (`artifacts/perf/before.json` / `after.json`, `SIM`, development host: Windows, CPython 3.14.7, numpy 2.5.4), and the re-run Stage-1 benchmark kept TP/FP/TN/FN unchanged (`docs/PERFORMANCE.md`). The committed `artifacts/benchmarks/` timing has not been regenerated, and the bridge has been measured on a Raspberry Pi 3B+ (in the loop) and, on the bench, on a Raspberry Pi 5 with a real Pixhawk 6X (`docs/RADIO_TEST_RESULTS.md`). Prevention has not been measured in flight on any vehicle. Nothing is sent to either the vehicle or the ground station in the default `passive`
posture (0-byte TX on `aegis ips-bridge` and `aegis serve`, even when `--gcs-notify` is configured, unless `--mgmt-enable`
is explicitly passed). `advisory` sends GCS-side alerts/status only with zero FC writes or drops. `active-ips` sends
counter-commands and the inline bridge (`docs/INLINE_IPS.md`) can drop hostile frames, both verified on ArduCopter SITL
and loopback, and on the bench (not in flight).

```
                       ┌──────────────────────────────────────────────────┐
                       │               OPERATING POSTURES                 │
                       ├─────────────────┬───────────────┬────────────────┤
                       │  PASSIVE (IDS)  │   ADVISORY    │   ACTIVE IPS   │
                       │ 0 B to vehicle* │ STATUSTEXT to │ SIM-only model │
                       │ Zero Actuation  │ loopback GCS  │ (not sent)     │
                       └─────────────────┴───────────────┴────────────────┘
                                                  │
                      ┌───────────────────────────┴───────────────────────────┐
                      ▼                                                       ▼
            TOPOLOGY A: SIDECAR                                    TOPOLOGY B: INLINE BRIDGE
   [Radio] ───────▶ [Pixhawk FC]                           [Radio] ──▶ [Companion Pi] ──▶ [Pixhawk FC]
                         ▲                                                  (Inline Sanitizer
                         │ (Counter-Commands)                                + Fail-Open Watchdog)
                 [Companion Pi]
```
\* By default. On a UDP or `socket://` vehicle link, `aegis serve` also puts bytes on the vehicle link, in any
posture, when `--gcs-notify` is set (alert STATUSTEXTs) or when `--mgmt-key-file` is set and a posture change is
requested through `POST /api/bridge/posture` (one signed `COMMAND_LONG`; with no inline bridge in the path it reaches
the flight controller). A serial-device vehicle link is receive-only in every posture and entry point.

### Key Architectural Highlights

- **Dual-Topology Execution Model**:
  - **Topology A (Sidecar Companion Actuator)**: *design, modelled in SIM. A SITL sidecar run is reported to have failed (the vehicle still landed), but no artifact for it is committed in this repo, so it is not measured here; physical/bench actuation not measured.* A live serial device is strictly receive-only (`bytes_sent = 0`); `aegis serve` only sends counter-frames on SITL UDP/`socket://` links in `active-ips` (plus loopback UDP `STATUSTEXT` when `--gcs-notify` is set, or signed management commands when `--mgmt-key-file` is set).
  - **Topology B (Inline Bridge)**: `aegis ips-bridge` (`hal/inline_ips.py`, `mitigation/inline_policy.py`) sits between the flight controller port and the GCS radio port and drops hostile frames before the autopilot sees them (`docs/INLINE_IPS.md`). Tested on synthetic frames, loopback serial and ArduCopter SITL; over a real LR900 radio pair; and on the bench with a real Pixhawk 6X on a Raspberry Pi 5 (`docs/RADIO_TEST_RESULTS.md`). Not flown; one signed run over USB with the bridge as the enforcement point (the flight controller's own enforcement not tested); no hardware bypass yet. The Rust crate `rust/aegis_fastpath` is still not on the path.
  - **Topology A+B (Hybrid)**: *design only.*
  - **Topology detection**: not selectable. The software reports `A` (single-port sidecar) or `A+B` (inline bridge) from how it is connected (`GET /api/topology`, `topology_info`); SIM and replay are labelled as such.
- **Multi-Detector Evidence Fusion**:
  - **Protocol / Rule Engine**: MAVLink v2 framing checks, sequence gaps, frequency bounding, rogue sysid quarantine, and command provenance / burst checks.
  - **Cyber-Physical Consistency**: Cross-checks GPS vs barometric altitude, integrated velocity vs reported coordinates, attitude vs ground track, and 2D CUSUM micro-drift tracking.
  - **Machine Learning Anomaly Ensemble**: Unsupervised Isolation Forest + Mahalanobis distance ensemble trained exclusively on benign flight dynamics across an 11-feature sliding window.
  - **Firmware Integrity & Cryptographic Attestation**: Real SHA-256 manifest verification and MAVLink v2 packet signing (`signing.py`).
- **Closed-Loop Cyber-Physical Flight Twin**:
  - Continuous synthetic dead-reckoning (`golden_state.py`) maintaining true aircraft state (`vx`, `vy`, speed, heading, altitude) with zero teleportation or spatial discontinuities upon recovery.
- **Native Tauri 2.0 Desktop GCS**:
  - Prototype desktop shell in `frontend/src-tauri` (Tauri 2) around the same React 18 + TypeScript dashboard; not part of the tested Python path.
- **Forensic Hash-Chain Audit Trail**:
  - Every alert is appended to a tamper-evident SQLite SHA-256 hash chain (`aegis verify-log <db.sqlite>`).

---

## 2. Empirical Verification & Benchmarks

All performance metrics are generated directly by automated test harnesses over genuine MAVLink v2 streams. *No metric in this repository is hand-written.*

### IDS Detection Performance (`scripts/benchmark.py`)
Tested across 6 seeds $\times$ 7 baseline scenarios (23,430 decisions):

| Accuracy | Precision | Recall | **FPR (False Positive Rate)** | F1-Score | Detection Latency | Mean Compute Time |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **0.997** | **0.999** | **0.990** | **0.0002** | **0.995** | **0.36 s** (p95 1.40 s) | **17.7 ms** (p95 23.6 ms, ML on) |

*Per-attack recall: GPS Spoofing: 0.95 · MAVLink Anomaly: 1.00 · Command Injection: 1.00 · Telemetry Manipulation: 1.00 · DoS Flood: 1.00 · Firmware Tamper: 0.99.*

### Cyber-Physical Prevention & Mitigation (SIM model only; not measured)
The defense layer (`src/aegisflight/mitigation/`) is a **simulation-dashboard model**: on the SIM source it shows
what a counter-action would do, using the dashboard's cyber-physical twin. **Detour, survival and watchdog time have not been measured.** Frame-level counts (dropped, blocked, rewritten) have been measured in SITL, and on the bench over the radio and with a real Pixhawk 6X (`docs/RADIO_TEST_RESULTS.md`), but not in flight. Detour, survival and watchdog time are not claimed here.
- Posture gates transmission on every source. `PASSIVE` (the default) and `ADVISORY` send nothing to the vehicle
  (`bytes_sent = 0`); `ADVISORY` adds STATUSTEXT alerts to a GCS. `ACTIVE_IPS` encodes counter-commands (mode restore, EKF source
  switch, optional signing) and transmits them only on live UDP / `socket://` SITL links (a physical serial-device vehicle link stays receive-only in every posture). That transmit path is unit-tested with a recording
  transport only; it has been exercised against ArduCopter SITL (an ALT_HOLD counter-command over the radio, 2026-10-30) but not against a real flight controller's counter-command path, and its effect in flight is unmeasured. Replay has no
  transport, so nothing is sent.

### Stage 2 defense demo (`scripts/verify_stage2.py`)
A demo of the defense code paths on **hand-built inputs** (SIM). It is not validation evidence and measures no
vehicle, link or benchmark.

---

## 3. Threat Model and Attack Coverage

Implemented attack classes and modes: `docs/ATTACKS.md`; threat model: `docs/THREAT_MODEL.md`. What is and is not
evidenced, including the known gaps (`command_injection:gcs_replay`, low decision recall on `sudden_offset`), is
recorded in `docs/VALIDATION_EVIDENCE.md`. No attack class is claimed to be fully prevented.

---

## 4. Hardware Abstraction Layer (HAL)

The `src/aegisflight/hal/` module abstracts serial communication, companion compute platforms, and autopilot firmwares:

- **Autopilot Auto-Discovery**: Identifies connected flight controllers via USB VID/PID and serial descriptors (Cube Orange/Black, Pixhawk 6X/4/2.4.8, Holybro, CUAV).
- **Companion Compute Profiling** (`hal/discovery.py`, not wired into the pipeline): reads the host platform (e.g. Raspberry Pi, Jetson, x86_64) and proposes a latency budget. The bridge has been measured on a Raspberry Pi 3B+ and a Pi 5 (`docs/PERFORMANCE.md`, `docs/RADIO_TEST_RESULTS.md`), but this profiling code's latency budget has not been measured.
- **Firmware Profile Adaptation**: Automatically switches protocol parsing dialects and mode definitions between **ArduPilot** (`COPTER_MODE_GUIDED`, `RTL`, `AUTO`) and **PX4 Autopilot** (`custom_mode` bitmask).

---

## 5. Repository Structure

```
.
├── src/aegisflight/                # Core Python security suite
│   ├── core/                       # Frozen types, enums, geodesy
│   ├── hal/                        # Hardware Abstraction Layer & dual-topology bridge
│   ├── mitigation/                 # Autonomous prevention engine & golden state twin
│   ├── mavlink/                    # MAVLink v2 encoder/decoder, signing & GCS notifier
│   ├── detectors/                  # Protocol, Physics, ML Anomaly, and Firmware detectors
│   ├── features/                   # 11-feature online sliding-window extractor
│   ├── fusion/                     # Noisy-OR evidence fusion engine
│   ├── simulator/                  # Deterministic kinematics flight simulator
│   ├── attacks/                    # simulated attack injectors (docs/ATTACKS.md)
│   ├── logging/                    # SQLite tamper-evident SHA-256 rolling block ledger
│   ├── backend/                    # FastAPI engine, WebSocket feeds & defense endpoints
│   └── cli/                        # `aegis` command-line utility
├── frontend/                       # Native GCS Operator Console
│   ├── src/                        # React 18 + TypeScript UI
│   ├── src-tauri/                  # Tauri 2.0 Rust desktop shell
│   └── vite.config.ts              # Vite bundler configuration
├── rust/                           # High-Performance Native Extensions
│   └── aegis_fastpath/             # Sub-microsecond CRC-16 & frame sanitizer
├── configs/                        # YAML configuration profiles
├── data/                           # Evaluation datasets & flight manifests
│   ├── external/manifests/         # 40 PX4 flight logs + 41 ALFA UAV flight logs
│   └── sitl/raw/                   # High-rate SITL flight capture manifests
├── artifacts/                      # Benchmark evidence & evaluation outputs
├── docs/                           # Comprehensive technical documentation
├── scripts/                        # Automated audit & benchmark runners
│   └── verify_stage2.py            # 8-suite automated Stage 2 verification gate
└── tests/                          # unit, integration and E2E tests (`python -m pytest` prints the count)
```

---

## 6. Multi-OS Installation & Setup Guide

AegisFlight targets **Windows**, **macOS**, **Linux**, and **ARM64 companion computers** (bench-tested on Raspberry Pi 3B+/5; NVIDIA Jetson performance not measured).

Choose your operating system below for turnkey setup instructions:

---

### A. Windows 10 & 11 (x64 / ARM64)

#### 1. Prerequisites Installation
Install Python, Node.js, and Rust using [Winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/) (or download the official installers):
```powershell
# Open PowerShell as Administrator or standard user:
winget install Python.Python.3.11
winget install OpenJS.NodeJS.LTS
winget install Rustlang.Rustup
```
> [!NOTE]
> During Python installation, make sure **"Add python.exe to PATH"** is checked.  
> Microsoft Edge WebView2 is already pre-installed on Windows 10 & 11 and serves as the native GUI engine for the Tauri desktop app.

#### 2. Virtual Environment & Dependencies
In PowerShell:
```powershell
# Allow script execution for the current session (if restricted):
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Clone & enter repository:
git clone https://github.com/<org>/techfest-2026.git
cd techfest-2026

# Create and activate virtual environment:
python -m venv .venv
.venv\Scripts\Activate.ps1

# Install AegisFlight in development mode:
pip install -e ".[dev]"
```

#### 3. Build UI & Launch Defense Engine
```powershell
# Build frontend web assets:
npm --prefix frontend install
npm --prefix frontend run build

# Start AegisFlight in Active IPS mode (FastAPI + WebSocket):
aegis serve --defense-mode active-ips --port 8000
```
Open **http://127.0.0.1:8000** in your browser.

#### 4. (Optional) Launch Native Windows Desktop App
```powershell
cd frontend
cargo tauri dev
```
*Compiles directly to a native Windows window (`.exe`) via Microsoft WebView2.*

---

### B. macOS (Apple Silicon M-Series & Intel)

#### 1. Prerequisites Installation
Install Xcode Command Line Tools and dependencies via [Homebrew](https://brew.sh/):
```bash
xcode-select --install
brew install python@3.11 node rust
```
> [!NOTE]
> macOS uses native Apple WebKit (`WKWebView`), so no external GUI libraries are required for the desktop app.

#### 2. Virtual Environment & Dependencies
```bash
git clone https://github.com/<org>/techfest-2026.git
cd techfest-2026

# Create and activate virtual environment:
python3 -m venv .venv
source .venv/bin/activate

# Install AegisFlight:
pip install -e ".[dev]"
```

#### 3. Build UI & Launch Defense Engine
```bash
npm --prefix frontend install
npm --prefix frontend run build

# Start AegisFlight backend:
aegis serve --defense-mode active-ips --port 8000
```
Open **http://127.0.0.1:8000** in Safari, Chrome, or Firefox.

#### 4. Launch Native macOS Desktop App
```bash
cd frontend
cargo tauri dev
```
*Launches as a native macOS Cocoa application with Apple Silicon hardware acceleration.*

---

### C. Linux (Ubuntu, Debian, Fedora, Arch)

#### 1. System Packages & Build Dependencies
On **Ubuntu 22.04 / 24.04 / Debian 12**:
```bash
sudo apt update && sudo apt install -y \
  python3-venv python3-pip python3-dev build-essential git curl \
  libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf libssl-dev libayatana-appindicator3-dev
```
On **Fedora**:
```bash
sudo dnf install -y python3-devel gcc gcc-c++ git curl \
  webkit2gtk4.1-devel libappindicator-gtk3-devel librsvg2-devel openssl-devel
```

Install **Node.js LTS** & **Rust**:
```bash
# Node.js:
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Rust:
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

#### 2. Serial Port Permissions (For Hardware & Telemetry Radios)
To allow communication with USB flight controllers (`/dev/ttyACM*`, `/dev/ttyUSB*`) without `sudo`:
```bash
sudo usermod -a -G dialout $USER
# Log out and log back in, or run: newgrp dialout
```

#### 3. Virtual Environment & Launch
```bash
git clone https://github.com/<org>/techfest-2026.git
cd techfest-2026

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

npm --prefix frontend install
npm --prefix frontend run build

# Start backend:
aegis serve --defense-mode active-ips --port 8000

# (Optional) Start native Linux desktop app:
cd frontend && cargo tauri dev
```

---

### D. Onboard Companion Computers (Raspberry Pi 4/5/Zero & NVIDIA Jetson)

For deployment directly on a physical drone companion computer connected to a Pixhawk / Cube flight controller:

#### 1. Raspberry Pi OS (Bookworm 64-bit)
1. **Enable Hardware UART**:
   ```bash
   sudo raspi-config
   # Select: 3 Interface Options -> I6 Serial Port
   # "Would you like a login shell to be accessible over serial?" -> NO
   # "Would you like the serial port hardware to be enabled?" -> YES
   sudo reboot
   ```
   *The primary hardware UART is now active at `/dev/ttyAMA0` (or `/dev/serial0`).*

2. **Install Dependencies**:
   ```bash
   sudo apt update && sudo apt install -y python3-venv python3-pip python3-dev build-essential git
   git clone https://github.com/<org>/techfest-2026.git
   cd techfest-2026

   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. **Run the receive-only monitor on the telemetry link** (the Pi 5 has been run on the bench with a real Pixhawk, disarmed, but no companion deployment has been flown; a 1,500 s active-ips soak on that bench, through a `socket://` proxy, changed a disarmed vehicle's mode through false GPS alerts (`docs/RADIO_TEST_RESULTS.md`); a serial device such as `/dev/serial0` is receive-only: `aegis serve` and `aegis ips-bridge` refuse `active-ips` on it and never write STATUSTEXT onto it; counter-commands exist only on SITL UDP / `socket://` links, where `active-ips` without a signing key additionally needs `--allow-unsigned` or the dashboard acknowledgement):
   ```bash
   aegis serve --source serial --serial-port /dev/serial0 --baud 115200 --port 8000
   ```
   Ports are not auto-discovered by the CLI (`hal/discovery.py` is not wired in); name the port explicitly.

#### 2. NVIDIA Jetson (Orin / Nano / Xavier — JetPack 5.x / 6.x)
- Hardware UART `/dev/ttyTHS1` (J41 40-pin header pins 8 & 10) or USB `/dev/ttyUSB0`.
- `hal/discovery.py` (not wired into the detection pipeline) checks `/etc/nv_tegra_release` for Jetson metadata and proposes a heuristic latency budget (not measured on Jetson hardware).

---

### E. Quick Verification (All Operating Systems)

Run the test and lint suites to check a local installation:
```bash
# 1. Stage 2 defense demo on hand-built inputs (SIM, not evidence).
#    KNOWN ISSUE (2026-11-26): stops at suite 5 with "ValueError: unknown mode 'AUTO'" on the
#    freeze tag and on main; see issue #191. Suites 1-4 print [PASS] before it stops.
python scripts/verify_stage2.py

# 2. Fast unit verification (35 tests on main 67e5a6b, 2026-11-26):
python -m pytest tests/unit/test_mitigation.py tests/unit/test_hal.py

# 3. Full test suite (`python -m pytest` prints the count):
python -m pytest

# 4. Code quality & linting (the same command CI runs):
ruff check src tests scripts backend
```

---

## 7. Interactive Demonstration Runbook

1. **Nominal Flight**: Start `aegis serve --defense-mode active-ips`. The live altitude profile holds steady at $60\text{ m}$; speed is $12\text{ m/s}$; threat score is $0.0$.
2. **GPS Spoofing & Dead-Reckoning Recovery**: Inject GPS spoofing via the UI. In the SIM benchmark the median detection latency is 0.36 s and the threat state escalates to `HIGH / GPS_SPOOFING`. The dashboard twin then models the counter-action (Topology B: inline clamp; Topology A: dead-reckoning plus counter-command). These are SIM models, not measured prevention.
3. **Command Injection & Failsafe Veto**: Trigger unauthorized land or mid-air disarm. The mitigation controller flags it (`VETO_DISARM` / `REPLAY_GUARD` action in the Defense HUD). It is reported, not blocked: nothing is transmitted to the vehicle.
4. **Detected topology**: the Defense HUD displays the detected topology (A, A+B, SIM or replay) and what it can do; there is no selector.
5. **Audit Ledger Verification**: In a second terminal, verify the tamper-evident hash chain:
   ```bash
   aegis verify-log artifacts/aegisflight_live.sqlite
   ```
   Outputs `Chain status: OK (zero mutations detected)`.

---

## 8. Documentation Map

Detailed technical specifications and engineering logs:

- [**System Architecture & Deep Dive**](docs/ARCHITECTURE.md) — Comprehensive technical architecture specification.
- [**Stage 2 report draft**](docs/stage2_report_draft.md): withdrawn pending evidence (reasons inside).
- [**Stage 2 Runbook**](docs/STAGE2_RUNBOOK.md) — Step-by-step SITL integration and regression procedures.
- [**Hardware Benchmarking (Pixhawk 6X)**](docs/HARDWARE_BENCH_PIXHAWK6X.md) — Physical flight controller bench performance.
- [**Threat Model Specification**](docs/THREAT_MODEL.md): threat model and attack taxonomy.
- [**Red-team audit**](docs/REDTEAM_AUDIT_STAGE2.md): withdrawn self-assessment (reasons inside).
- [**Inline IPS bridge**](docs/INLINE_IPS.md) — Topology B: filtering hostile frames before the autopilot.
- [**In-band management channel**](docs/MGMT_CHANNEL.md) — alerts, status and signed posture control over the telemetry radio (150 B/s budget); [**minimal build**](docs/MINIMAL_BUILD.md) — FC + GPS + radio + cheap Pi (wiring options, risks; bench-tested with a Pixhawk over USB on a Pi 5, not flown; the UART wiring is not tested).
- [**Real Pixhawk bench tests**](docs/REAL_PIXHAWK_TEST.md) — how the 2026-10-31 Pixhawk 6X runs on a Raspberry Pi 5 were done, and how to restore the flight controller.
- [**Radio test**](docs/RADIO_TEST.md) — test plan for the real LR900 radio pair; results and the judgement against the plan in [RADIO_TEST_RESULTS.md](docs/RADIO_TEST_RESULTS.md).
- [**Testing & Quality Assurance**](docs/TESTING.md) — Test taxonomy and verification methodology.
- [**API & WebSocket Specification**](docs/API.md) — REST endpoints and telemetry schemas.

---

## 9. Safety Properties (no compliance claimed)

No airworthiness-standard compliance (e.g. RTCA DO-326A / EUROCAE ED-202A) is claimed. Enforced in code and tests
(`tests/unit/test_defense_safety.py`):
- `PASSIVE` is the default everywhere and transmits **0 bytes** on both vehicle and GCS links (`aegis ips-bridge`
  only enables in-band GCS management in `passive` when `--mgmt-enable` is explicitly set; `aegis serve --gcs-notify`
  suppresses UDP/transport `STATUSTEXT` while `defense_mode == passive`; physical serial links remain receive-only);
  `ADVISORY` transmits GCS-side alerts/status only with zero vehicle-link writes or drops;
- only `ACTIVE_IPS` transmits counter-commands, and only through the live source's transport (never on replay);
- `scripts/hardware/run_serial_ids.py` fails (exit 3) if any byte is written to the port in `passive` mode;
- countermeasures never guess: no force-disarm by default, no unknown or default mode, no override of the pilot's own mode change.

---

## 10. License

AegisFlight's code is MIT-licensed: see [`LICENSE`](LICENSE) (the copyright-holder line "Team Ardra" is taken from `pyproject.toml`; the
team should confirm it). Dependencies, datasets and models are listed, with how each licence was determined, in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md); what a submission archive must contain is in
[`docs/SUBMISSION_ARCHIVE_MANIFEST.md`](docs/SUBMISSION_ARCHIVE_MANIFEST.md).
Benchmark numbers in this README come from `artifacts/benchmarks/` (SIM) and are regenerated with `aegis benchmark`.
