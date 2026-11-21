> **UNSUPPORTED: not reproducible, not validated evidence. Read [`UNSUPPORTED.md`](UNSUPPORTED.md) before using any number below; it may not be cited for any detection, false-positive-rate or reproducibility claim.**
> **Environment:** SITL (PX4 SITL behind the loopback attack proxy). **Claim class:** link-level only (no estimator, physical or real-world claim).
> **Status: DRY RUN. Not a detection result.** 8 of 9 scenarios had 0 threats (only `rogue_force_disarm` flagged, 10 of 75 decisions); no detection-rate or false-positive figure may be quoted from this table.
> **Generating command (from each manifest's `command_line`):** `python scripts/sitl/run_p2_telemetry_trial.py --scenario <scenario> --px4-host 127.0.0.1 --px4-port 14580 --relay-listen-port <1868x> --seed 1001 --trial-index 0 --seconds 15 --warmup-s 0 --onset-s 3 --expected-sysid 1 --px4-git-describe bce8453e-dirty --out <dir>/p2t_<scenario>_001` (the run used the author's local path as `--out`; see the provenance notes in the PR that added this label).
> Labelling added after the run; the manifests and the table below are unchanged.

# SITL Proxy Telemetry / Firmware / Restricted-Visibility Trial Summary

| Trial | Scenario | Seed | Frames Seen | Modified | Injected | Signed Skipped | Decisions | Threats |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `p2t_altitude_bias_001.manifest.json` | `altitude_bias` | 1001 | 6530 | 667 | 0 | 0 | 75 | 0 |
| `p2t_battery_jump_001.manifest.json` | `battery_jump` | 1001 | 6646 | 59 | 0 | 0 | 75 | 0 |
| `p2t_benign_pilot_control_001.manifest.json` | `benign_pilot_control` | 1001 | 6372 | 0 | 0 | 0 | 75 | 0 |
| `p2t_firmware_identity_001.manifest.json` | `firmware_identity` | 1001 | 6653 | 0 | 0 | 0 | 75 | 0 |
| `p2t_frozen_attitude_001.manifest.json` | `frozen_attitude` | 1001 | 6629 | 1096 | 0 | 0 | 75 | 0 |
| `p2t_gcs_forgery_own_counter_001.manifest.json` | `gcs_forgery_own_counter` | 1001 | 6416 | 0 | 1 | 0 | 75 | 0 |
| `p2t_gcs_forgery_track_identity_001.manifest.json` | `gcs_forgery_track_identity` | 1001 | 6358 | 0 | 1 | 0 | 75 | 0 |
| `p2t_rogue_force_disarm_001.manifest.json` | `rogue_force_disarm` | 1001 | 6672 | 0 | 1 | 0 | 75 | 10 |
| `p2t_speed_mismatch_001.manifest.json` | `speed_mismatch` | 1001 | 6648 | 114 | 0 | 0 | 75 | 0 |
