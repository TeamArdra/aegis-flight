# AegisFlight Hardware & Real-Flight Readiness Playbook

This guide outlines the validation sequence for taking AegisFlight from a software-only workstation (zero flight hardware) to props-off bench testing and passive (receive-only) flight logging. Inline IPS on a real vehicle is **not** part of the approved sequence (section 3).

Evidence tiers used in this document, from weakest to strongest. A result at one tier is never evidence for a later one:

| Tier | Meaning | Status for AegisFlight |
| :--- | :--- | :--- |
| `SIM` | Pure software: in-memory or loopback transports, the Stage-1 simulator, unit tests | Done where stated |
| `SITL` | ArduPilot/PX4 software-in-the-loop (no flight hardware) | Done on ArduCopter only |
| `BENCH` | Real board on a desk, props off, **passive** capture only | Partial (Pixhawk 6X passive probe) |
| `HITL` | Real flight controller driven by a simulated environment with the IDS in the loop | **Not performed** |
| `FLIGHT-QUAL` | Maintainer-approved qualification on a vehicle in flight | **Not performed; not approved** |

> **Evidence boundary:** Automated tests and `SIM`/`SITL` benches are not `BENCH`, `HITL` or `FLIGHT-QUAL` evidence and do not claim real outdoor flight validation. Real-flight claims require recorded hardware captures (`.tlog`/`.ulog`) replayed through AegisFlight, and a maintainer-approved `FLIGHT-QUAL` plan with every physical risk acknowledged; none exists yet.

---

## 1. Zero-Hardware Preparation (Software + Resource-Capped Bench)

Before touching physical hardware, run the three layers below on your development host (A and B are `SIM`; C is `SITL`):

### A. Pre-flight drills & RF-impaired extreme-flood soak (Local Python)
```bash
python -m aegisflight.cli.main field-drill
python scripts/hardware/hw_readiness_soak.py --cycles 5 --flood-frames 5000
```
What this checks (SIM / link-level only: in-memory virtual transports, no serial device is opened, no vehicle and no
radio are involved; none of it is flight or hardware evidence):
- `4/4` shadow drills on in-memory shadow transports.
- `0` false alerts over one scripted benign flight with 4% random frame loss, injected garbage UART bytes and yaw sweeps
  (frame reordering is **not** injected).
- `analyser_errors == 0` and live bridge threads after a flood of spoofed-ID `ATTITUDE` frames (default 3,000; set with
  `--flood-frames`) and **one** `VFR_HUD` frame carrying an IEEE-754 `NaN`. `Inf` frames are not sent, and the size of
  state tables or memory growth is **not** measured or asserted.
- Under signed `ACTIVE_IPS` on the in-memory bridge: `dropped_unsigned > 0` and `dropped_semantic_param > 0` are asserted,
  and a forged disarm and a `PARAM_SET` must not reach the shadow FC transport. `dropped_untrusted_control` is reported,
  not asserted.
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

### C. Interactive Operator Drill (`SITL`: Gazebo + PX4/ArduPilot SITL + QGroundControl)
1. Start Gazebo Harmonic + SITL (`scripts/sitl/start_px4_sitl.sh start` on Linux/WSL, or ArduPilot SITL with `SIM_WIND_SPD=12`, `SIM_WIND_TURB=4`, `SIM_GPS_NOISE=0.8`).
2. Start AegisFlight loopback dashboard with token + anchor HMAC keys:
   ```bash
   export AEGIS_API_TOKEN="<operator-secret>"
   export AEGIS_ANCHOR_KEY="<anchor-hmac-secret>"
   aegis serve --source udp --udp-port 14550 --config-dir configs/universal_flight
   ```
3. Practice operator incident response against the simulated vehicle (`PASSIVE` -> `ADVISORY` -> `ACTIVE IPS`, `HoldConfirmButton`, `SAFE_HOLD` / `ACK_TAKEOVER`, and `/api/forensic/report`). `ACTIVE IPS` is exercised here against `SITL` only; it is a procedure drill, not a qualification of `ACTIVE_IPS` on a vehicle.

---

## 2. Props-Off Physical Hardware Bench (`BENCH`, Receive-Only `PASSIVE`)

Once you have a real Pixhawk and companion computer (**props removed, bench power only**). These are `BENCH` checks (passive monitoring on a desk); they are not `HITL` and not flight evidence:

1. **Zero-TX Port Discovery:**
   ```bash
   aegis onboard --preflight --config configs/onboard_default.yaml
   ```
   Confirm `0` bytes transmitted during probe (`discover_mavlink_ports`) and verify serial receive-only safety (`may_reach_vehicle()` blocks `ACTIVE_IPS` on OS serial devices; this refusal is a software guard covered by `SIM` tests, and the bench step only checks that it behaves the same on the real port).
2. **Firmware Manifest Enrollment:**
   While disarmed, passively capture the Pixhawk `AUTOPILOT_VERSION` (0 B TX) with `aegis onboard --enroll-firmware OUT_YAML`
   (optionally HMAC-signed with `AEGIS_ALLOWLIST_KEY`) and use `OUT_YAML` as the firmware allowlist
   (e.g. `configs/firmware_allowlist.yaml`). `aegis fw-manifest DIR` is a different tool: it hashes `*.bin` files.
3. **RX-Only Cable Check:**
   Physically disconnect the UART TX pin between the companion computer and Pixhawk TELEM port while testing `PASSIVE` monitoring, and record whether QGroundControl and autopilot behavior are unaffected (a `BENCH` observation, not a guarantee for flight).

---

## 3. Staged Progression: Passive Flight Logging Only (Inline IPS Not Approved)

**Active prevention is SIM / local-SITL only.** `ACTIVE_IPS` and `--vehicle-uplink-filter` may only be used against a
simulator or a local SITL link (`socket://` or UDP). The code refuses `--defense-mode active-ips` on any OS serial device
(`may_reach_vehicle()`), and the bridge has been verified on ArduCopter SITL only. They stay SIM/local-SITL only until a
separate, maintainer-approved hardware qualification exists. Stages marked **not supported / future** below are not
instructions: do not attempt them, and do not treat the listed hardware safeguards as sufficient approval.

Never jump directly to free-flight `ACTIVE_IPS`. Only stages 1 and 3 are supported (in that order); stages 2, 4 and 5 are not supported and are listed to show what a future, separately approved qualification would still have to cover. Tier of each stage: 1 is `SITL`/`SIM`; 3 is passive `FLIGHT` logging (receive-only, no IPS claim, still needs the owner's flight approval); 2, 4 and 5 would be `BENCH`/`HITL`/`FLIGHT-QUAL` and have not been performed:

| Stage | Environment | Posture | Mandatory Hardware Safeguard | Exit Gate |
| :--- | :--- | :--- | :--- | :--- |
| 1 | SITL + Gazebo + `tc netem` + Docker cap (SIM / local SITL only) | `ACTIVE_IPS` (signed) | Loopback only | Target: `0` false counter-commands over a 10+ hr soak (not yet run) |
| 2 | Props-off Pixhawk bench | **Not supported / future.** `ACTIVE_IPS` is refused on a serial FC link; requires separate maintainer-approved hardware qualification. Until then use `PASSIVE` (RX-only) only (section 2). | n/a | n/a |
| 3 | Outdoor free flight (passive logging only, not `FLIGHT-QUAL`) | `PASSIVE` (RX-only) | UART TX disconnected | Replay real `.tlog`/`.ulog` logs; verify low `FA/hr` (no real-flight false-alarm rate has been measured yet) |
| 4 | Netted / tethered hover | **Not supported / future.** `--vehicle-uplink-filter` is SIM/local-SITL only; requires separate maintainer-approved hardware qualification. | n/a | n/a |
| 5 | Open range qualification | **Not supported / future.** `ACTIVE_IPS` on a real vehicle is not qualified; requires separate maintainer-approved hardware qualification. | n/a | n/a |

Hardware safeguards that a future qualification would be expected to define (normally-closed UART bypass relay, direct RC
safety pilot, `--filter-override-file`) are design intent only. None of them has been built or tested here.
