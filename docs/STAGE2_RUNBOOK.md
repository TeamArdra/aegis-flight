# Stage-2 development runbook

Local, reproducible commands for the Stage-2 live-integration work. Numbers and
findings live in `docs/STAGE2_PROGRESS.md` and `artifacts/sitl/` (never here).

**Topology.** Windows 11 hosts this repo, the IDS, the dashboard and (later) the
attack proxy. WSL2 `Ubuntu-24.04` hosts PX4 SITL + Gazebo Harmonic. MAVLink goes
over UDP across the WSL2 NAT network. The repo is **not** in WSL; PX4 sources and
build are **not** modified.

## 0. Rules of the road
- Always address the distro: `wsl -d Ubuntu-24.04 -- ...` (the default distro is a different one).
- The WSL IP changes across reboots. Never hard-code it: `wsl -d Ubuntu-24.04 -- hostname -I`
  (the recorder discovers it automatically).
- **Attack proxy upstream is loopback-only by default.** Every `scripts/sitl/run_p2_*_trial.py` / `run_p4_signing_trial.py`
  builds its relay through `make_udp_relay`, which refuses a non-loopback `--px4-host` before opening any socket. To reach PX4 in
  WSL2 over its NAT address, opt in explicitly: pass `--allow-private-upstream` (or set `AEGIS_ALLOW_PRIVATE_UPSTREAM=1`). Even then
  the address must lie in the subnet of a **virtual host-only/NAT adapter** of this host: Windows `vEthernet (WSL...)` /
  `vEthernet (Default Switch)`, Linux `docker0` / `br-*` / `virbr*` / `veth*` / `lxcbr*` / `vboxnet*`, VirtualBox/VMware host-only,
  macOS `bridge1xx` (allowlist: `VIRTUAL_INTERFACE_PATTERNS` in `proxy/transport.py`). An address in the subnet of a physical-looking
  interface (`Wi-Fi`, `Ethernet*`, `en*`, `eth*`, `wlan*`, `wl*`, a Hyper-V External switch, `utun`) is refused even with the opt-in,
  naming the interface; the virtual network must be no wider than /16 (IPv4) / /64 (IPv6), so a /8 or /0 docker/custom network is
  refused; a scoped address (anything containing `%`, e.g. `fe80::2%eth0`) is always refused; any other LAN or public address, and any hostname, is refused. `AEGIS_SITL_INTERFACE=<name>` may further pin
  one adapter but can never admit a non-allowlisted one. The opt-in (incl. the interface name) is recorded as `private_upstream_ack`
  in the run manifest. Limitation: this trusts interface names, so a virtual network the user has bridged onto a real LAN (bridged VM
  network, macvlan, a renamed external switch) is not detected: keep the vehicle's radio/bridge off a host running attack tooling.
  (Live verification of this path has not been run.)
- After any WSL session, from **PowerShell**:
  `wsl -d Ubuntu-24.04 --cd /home/astryx/PX4-Autopilot -- git status --porcelain --untracked-files=no` must print nothing.
- Raw captures (`data/sitl/raw/*.tlog`) are local evidence and are git-ignored; manifests and
  generated results under `artifacts/sitl/` are committed.

## 1. Start / stop an isolated PX4 SITL
```bash
wsl -d Ubuntu-24.04 -- bash /mnt/d/Ardra/techfest-2026/aegisflight/scripts/sitl/start_px4_sitl.sh start
wsl -d Ubuntu-24.04 -- bash /mnt/d/Ardra/techfest-2026/aegisflight/scripts/sitl/start_px4_sitl.sh status
wsl -d Ubuntu-24.04 -- bash /mnt/d/Ardra/techfest-2026/aegisflight/scripts/sitl/start_px4_sitl.sh stop
```
The script runs the *built* PX4 binary with env vars only: headless Gazebo (`HEADLESS=1`),
PX4 **instance 2** (GCS link UDP `18572`, offboard `14582`->`14542`), its own Gazebo transport
partition (`GZ_PARTITION=aegis2`), and a working directory outside the PX4 tree
(`~/aegis_sitl/i2`). It never touches another SITL the user may be running (instance 0, port `18570`).
Allow ~30 s for boot (`~/aegis_sitl/i2/px4.log`).

### Why a fresh boot per recording
PX4's UDP GCS link **locks onto the first datagram sender (IP *and* source port)** and never
re-learns it (`mavlink_receiver.cpp`: `set_client_source_initialized`). Any earlier probe
therefore consumes the link; restart SITL before each recording / experiment.

## 2. Observe / record a benign flight
```bash
.venv/Scripts/python.exe scripts/sitl/record_flight.py --out data/sitl/raw/benign_001            # arm, takeoff 20 m, 40 m square, land
.venv/Scripts/python.exe scripts/sitl/record_flight.py --out data/sitl/raw/obs --hover-only 30    # observe only, no flight
.venv/Scripts/python.exe scripts/sitl/tlog_stats.py data/sitl/raw/benign_001.tlog --json artifacts/sitl/benign_001_stream_stats.json
```
The recorder is a normal GCS (sysid 255 / compid 190, 1 Hz heartbeat) and writes the raw
tlog (`>Q` microsecond receive time + raw frame) plus a JSON manifest (PX4 `git describe`,
Gazebo version, link, vehicle ids, flight events, `attack_status: NONE`, `environment: SITL`).

## 3. Replay a capture through the unchanged Stage-1 pipeline
```bash
.venv/Scripts/python.exe -W ignore scripts/sitl/replay_benign.py data/sitl/raw/benign_001.tlog --out artifacts/sitl/benign_001_replay.json
```
Environment `SITL (replayed tlog)`; benign capture, so every `threat=True` is a false alarm.

## 3b. Serial transport (software-only; no hardware has been connected)
`SerialMavlinkTransport` (`pip install -e ".[serial]"`) is unit-tested on virtual ports only.
Usage, counters, timestamp semantics and limits: `docs/SERIAL_TRANSPORT.md`. Tests:
`.venv/Scripts/python.exe -m pytest tests/unit/test_mavlink_serial.py` (PTY tests skip on Windows).

## 4. Stage-1 regression gate (run before calling any milestone done)
```bash
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/ruff.exe check src tests scripts backend
.venv/Scripts/aegis.exe benchmark --out "$SCRATCH/bench" --no-figures   # ~9 min; TP/FP/TN/FN must equal 6535/4/16826/65
```
`--no-figures` is mandatory for regression runs (figures otherwise overwrite committed ones).
