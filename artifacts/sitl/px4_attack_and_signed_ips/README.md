# PX4 SITL: attack trials and signed ACTIVE_IPS runs

Environment tag: **SITL** (PX4 v1.16.2, Gazebo 8.15.0, `gz_x500`, Docker on aarch64, one host, one airframe).
Nothing here is HITL, FIELD or real-vehicle evidence.

Everything below was produced by the commands listed in each section. Numbers come from the generated
summaries and the per-run JSON in this directory; nothing is hand-edited.

## Provenance

| item | value |
|---|---|
| PX4 | `v1.16.2` (SITL, instance 0 for the bridge runs, instance 2 for the P2/P4 trial batch) |
| Gazebo | 8.15.0 |
| AegisFlight tree, `p2_attacks/` and `signed_ips/sig_*`, `gnss_active` | local merge `2b9eab3` (this branch + #111 reorder window 48); local commit, not on a remote |
| AegisFlight tree, `gnss_fix_active`, `gnss_mc_*` | local `375b2ab` = `2b9eab3` + the sub-mode classifier fix (branch `fix/px4-gnss-loss-submode`) |
| Detector profile | `configs/px4_sitl` (trial batch), `configs/universal_flight` (bridge runs) |
| ML model | none in the bridge (`aegis onboard` has no model option); trial batch used the PX4 profile |

## 1. Attack trials against PX4 (link-level detection, `p2_attacks/`)

Rig: `scripts/sitl/run_p2_*.py` and `scripts/sitl/run_p4_signing_trial.py` through the SITL MITM relay, a fresh PX4
boot per trial. Summaries were generated with `scripts/sitl/make_p2*_summary.py` and `make_p4_summary.py` over the
`*.manifest.json` files in `p2_attacks/` (the summaries are `p2_attacks/P*_summary.md`).

| attack | trials | result (claim class: link-level detection unless noted) |
|---|---|---|
| gradual `GLOBAL_POSITION_INT` drift (downlink only) | 5 | `GPS_SPOOFING` raised in 5/5, 0 false alarms in 953 pre-onset decisions. PX4 never sees the modified frames. |
| GNSS fix loss (`fix_type 0`, 2 sats, downlink only) | 3 | detected 3/3, 0/480 pre-onset false alarms, median latency 1.35 s |
| GPS dropout (frames dropped) | 3 | detected 3/3, 0/599 pre-onset false alarms, median latency 2.30 s |
| downlink delay | 3 | detected 3/3, 0/575 pre-onset false alarms, median latency 9.33 s (as `DOS` message-rate evidence) |
| replay of a legitimate unsigned force-disarm | 3 | PX4 accepted original and replay 3/3 (command-path effect); IDS sequence-gap detection 3/3 |
| informed expected-GCS impersonation (forged force-disarm) | 3 | **PX4 accepted the forged command 3/3; the IDS raised no threat decision 0/3** |
| telemetry (altitude bias, speed mismatch, battery jump, frozen attitude, firmware identity) | 2 each | threat decisions: altitude bias 1, battery jump 8, speed mismatch 0, frozen attitude 0, firmware identity 0 (no per-scenario scoring window; counts only) |
| MAVLink-2 signing batch (`sign_*`) | 2 | **not scored**: both trials failed the integrity gate; forged unsigned command was not rejected by PX4 (PX4 has no signing key here) |

Read the last four rows as detection gaps on PX4, not as passes.

## 2. Signed inline bridge in front of PX4 (`signed_ips/`)

Topology: `PX4 UDP <-> udp_tcp_shim.py <-> aegis onboard (inline) <-> signed pilot`. The bridge enforces MAVLink-2
signing; **PX4 itself does not verify signatures here** (no key provisioned), so the unsigned forgeries below are
stopped by the bridge only. Runs: `scripts/sitl/px4_signed_ips/run_px4_ips.sh <label> <signing|gps> <passive|active-ips>`.
Hash chains and HMAC anchors were checked with `scripts/sitl/px4_signed_ips/verify_run.py` (`verify.txt` per run).

### 2a. Forged uplink (`sig_passive` control, `sig_active`)

Command: `./run_px4_ips.sh sig_passive signing passive`, `./run_px4_ips.sh sig_active signing active-ips`.

| stage | passive (PX4 mode after forgery) | active-ips (PX4 mode, bridge counter) |
|---|---|---|
| unsigned, sysid 66 `DO_SET_MODE(AUTO_LAND)` | `AUTO_LAND` | unchanged, `dropped_unsigned` +9 |
| unsigned, sysid 255 (plus RTL) | `AUTO_RTL` | unchanged, `dropped_unsigned` +12 |
| wrong-key signed, sysid 255 | `AUTO_LAND` | unchanged, `dropped_bad_signature` +9 |
| replay of a captured signed `DO_SET_MODE(AUTO_RTL)` | `AUTO_RTL` | unchanged, `dropped_replay` +3 |
| flood (2000 Hz, 8 s) | unchanged | unchanged, `dropped_dynamic` +15460 |

Chains: `sig_passive` events OK (3), actions OK (0), 141 anchors checked, 141 signed; `sig_active` events OK (3),
actions OK (15493), 40 anchors checked, 40 signed (`verify.txt`). The passive control proves the forgeries really work against this PX4.

### 2b. GNSS fix loss and the GPS response ladder (`gnss_*`)

The relay rewrites `GPS_RAW_INT` on the downlink (fix 0, 2 satellites) from 90 s for 40 s. This is a link-level fault
the bridge sees; PX4's estimator is untouched (Gazebo SITL cannot fail the GPS: `failure gps off` is not implemented).
Command: `ATTACK=gnss ./run_px4_ips.sh <label> gps active-ips`, with `MC=1` for the manual-control source.

| run | tree | `counter_frames_sent` | PX4 mode timeline | note |
|---|---|---|---|---|
| `gnss_active` | `2b9eab3` (no fix) | 0 | never leaves `AUTO_LOITER` | bug: PX4 streams about 370 msg/s, so the classifier called the GNSS loss a `DOS:FLOOD` and the GPS ladder never ran |
| `gnss_fix_active` | `375b2ab` (fix) | 2 (statustext to GCS, `DO_SET_MODE ALTCTL` to FC) | never leaves `AUTO_LOITER` | PX4 acked the command and then refused it: "Switching to Altitude is currently not available" |
| `gnss_mc_active` | `375b2ab` + `MANUAL_CONTROL` | 2 | `AUTO_LOITER` -> **`ALTCTL`** at pilot t=119.5 s | IPS counter-command took effect on PX4 |
| `gnss_mc_passive` (control) | `375b2ab` + `MANUAL_CONTROL` | 0 | stays `AUTO_LOITER` | same 10 alerts, no actuation |

`AUTO_LAND` at about 144 s in every run is the pilot's own landing command at the end of the run, not an IPS action.
In `gnss_mc_active` the ALTCTL change arrives about 30 s after the `AEGIS: GPS unreliable` statustext (89.7 s).
That lag is the ladder's confirm/escalate timing as observed, not tuned.

`altctl_probe_manual_control_0.txt` / `_1.txt` isolate the PX4 side with a plain unsigned GCS and no bridge: without a
manual-control stream PX4 rejects `DO_SET_MODE ALTCTL` and `SET_MODE` (result 1); with a `MANUAL_CONTROL` stream it
accepts both (`HB main=2 sub=0`). So the bridge's ALTCTL command is correct, and `ALTCTL` is only reachable on a PX4
vehicle that has a manual-control source.

## Limits

- Single runs for sections 2a and 2b; no repeats, no confidence intervals. Trial batches in section 1 are n=2 to 5.
- The bridge runs with ML off, so in-flight position drift was not detected through the bridge (the drift runs in
  section 1 are link-level only, with the relay in front of the IDS tap).
- Signed ACTIVE_IPS was tested against PX4 only at the bridge. PX4-side signing was not provisioned.
- No real GNSS fault, no real RF, no estimator effect, no physical-deviation claim.
- The committed scripts were reformatted with `ruff format` for CI after the runs; behaviour is unchanged.
- Not committed by design: tlogs, SQLite event stores, key files, frame captures.
