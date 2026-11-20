# AegisFlight — Multi-OS Installation & Configuration Reference

This guide provides OS-specific installation instructions. What has actually been run: Windows 11 x64 (development host),
Ubuntu 24.04 with Python 3.13 (CI, `.github/workflows/ci.yml`), and the bridge on a Raspberry Pi 3B+ and a Raspberry Pi 5
(`docs/PERFORMANCE.md`, `docs/RADIO_TEST_RESULTS.md`). macOS, Windows ARM64, Fedora/Arch, Pi 4 / Zero and NVIDIA Jetson are
**not tested**; those instructions have no recorded run.

---

## 1. System Requirements

- **Python**: $\ge 3.11$ (`pyproject.toml`; CI runs 3.13, development hosts 3.13 / 3.14; 3.11 and 3.12 not tested in CI)
- **Node.js**: $\ge 18$ + npm (required for the GCS dashboard)
- **Rust**: $\ge 1.80$ + Cargo (required for the native Tauri desktop GCS and zero-allocation frame sanitizer)
- **Operating Systems**:
  - **Windows 10 / 11** (x64; ARM64 not tested)
  - **macOS 12+** (not tested)
  - **Linux** (CI: Ubuntu 24.04; others not tested)
  - **Single-Board Computers** (Raspberry Pi 3B+ / Pi 5 bench runs; JetPack not tested)
- **Hardware Resources**: no GPU required. Minimum RAM not measured (the Pi 3B+ used has 905 MB, `docs/PERFORMANCE.md`).

---

## 2. Installation by Operating System

### A. Windows 10 & 11 (PowerShell)

1. **Install Prerequisites**:
   ```powershell
   winget install Python.Python.3.11
   winget install OpenJS.NodeJS.LTS
   winget install Rustlang.Rustup
   ```
   *(Ensure "Add python.exe to PATH" is checked during Python installation.)*

2. **Virtual Environment & Package**:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   pip install -e ".[dev]"
   ```

3. **Frontend & Backend Launch**:
   ```powershell
   npm --prefix frontend install
   npm --prefix frontend run build
   aegis serve --port 8000   # 127.0.0.1; SIM source and passive posture by default
   ```

4. **(Optional) Native Desktop Application**:
   ```powershell
   cd frontend
   cargo tauri dev
   ```

---

### B. macOS (Apple Silicon & Intel)

1. **Install Prerequisites**:
   ```bash
   xcode-select --install
   brew install python@3.11 node rust
   ```

2. **Virtual Environment & Package**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

3. **Frontend & Backend Launch**:
   ```bash
   npm --prefix frontend install
   npm --prefix frontend run build
   aegis serve --port 8000   # 127.0.0.1; SIM source and passive posture by default
   ```

4. **Native Desktop Application**:
   ```bash
   cd frontend
   cargo tauri dev
   ```

---

### C. Linux (Ubuntu / Debian / Fedora)

1. **Install System Dependencies & Build Tools**:
   ```bash
   # Ubuntu / Debian:
   sudo apt update && sudo apt install -y \
     python3-venv python3-pip python3-dev build-essential git curl \
     libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf libssl-dev libayatana-appindicator3-dev

   # Node.js LTS:
   curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
   sudo apt install -y nodejs

   # Rust:
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
   source "$HOME/.cargo/env"
   ```

2. **Grant Serial Port Permissions** (for USB telemetry radios & flight controllers):
   ```bash
   sudo usermod -a -G dialout $USER
   # Log out and back in for changes to take effect
   ```

3. **Virtual Environment & Package**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

4. **Frontend & Backend Launch**:
   ```bash
   npm --prefix frontend install
   npm --prefix frontend run build
   aegis serve --port 8000   # 127.0.0.1; SIM source and passive posture by default
   ```

---

### D. Onboard Companion SBCs (Raspberry Pi; NVIDIA Jetson not tested)

1. **Raspberry Pi OS (Bookworm 64-bit)**:
   ```bash
   # Enable hardware UART on GPIO pins (Pins 8 & 10):
   sudo raspi-config
   # Select: Interface Options -> Serial Port
   # Console shell: NO, Hardware enable: YES
   sudo reboot

   # Install & start the receive-only monitor (a serial device is receive-only; active-ips is refused on it):
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   aegis serve --source serial --serial-port /dev/serial0 --baud 115200 --port 8000
   ```

2. **NVIDIA Jetson (JetPack 5.x / 6.x)**:
   - Connect via hardware UART `/dev/ttyTHS1` (J41 header) or USB adapter `/dev/ttyUSB0`.
   - `hal/discovery.py` recognises a Jetson by `/etc/nv_tegra_release` and assigns a fixed 18 ms latency-budget constant (a static
     heuristic, not a measurement; not wired into the pipeline). No run on any Jetson is recorded.

---

## 3. Verification & Validation Commands

Confirm installation integrity across any platform:

```bash
# 1. Demo of the 8 defense code paths on hand-built SIM inputs (not validation evidence):
python scripts/verify_stage2.py

# 2. Focused Stage-2 unit tests (34 tests):
pytest tests/unit/test_mitigation.py tests/unit/test_hal.py -q

# 3. Full test suite (`pytest -q` prints the count):
pytest

# 4. Code quality & linting:
ruff check src tests scripts backend
```
