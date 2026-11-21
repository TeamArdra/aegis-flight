# P2 summary - first live attack trials on PX4 SITL (generated; do not edit)

Environment: **SITL**. Attack: downlink `GLOBAL_POSITION_INT` gradual drift (`docs/ATTACK_PROXY.md` Sec3). Claim class: **link-level detection (SITL) only** -- PX4 never receives a modified frame; this is not GPS spoofing of the vehicle and says nothing about signing.
Regenerate: `.venv/Scripts/python.exe scripts/sitl/make_p2_summary.py /out3/drift_001.manifest.json /out3/drift_002.manifest.json /out3/drift_003.manifest.json /out3/drift_004.manifest.json /out3/drift_005.manifest.json`.

**5/5 trials**: a `GPS_SPOOFING` decision fired at or after the attack window closed, with **0 false alarms** in any trial's pre-onset (benign) portion (953 pre-onset decisions pooled).
Time-to-detection from attack end: n=5, mean=0.44s, median=0.37s, min=0.22s, max=0.66s

| trial | onset s | dur s | rate m/s | bearing | expected m | actual m | frames mod | pre-onset FA | detected | ttd-from-end s | other threat types |
|---|---|---|---|---|---|---|---|---|---|---|---|
| drift_001 | 40.73 | 33.01 | 3.13 | 258.1 | 103.34 | 103.3 | 1650 | 0 | yes | 0.66 | - |
| drift_002 | 40.53 | 18.91 | 7.071 | 3.7 | 133.71 | 133.71 | 942 | 0 | yes | 0.36 | - |
| drift_003 | 48.17 | 23.46 | 9.443 | 73.9 | 221.48 | 221.3 | 1171 | 0 | yes | 0.37 | - |
| drift_004 | 27.35 | 37.23 | 5.848 | 230.5 | 217.72 | 217.7 | 1859 | 0 | yes | 0.22 | - |
| drift_005 | 33.59 | 32.64 | 2.651 | 300.7 | 86.52 | 86.5 | 1632 | 0 | yes | 0.57 | - |

## Limitations
- n reflects however many trials have completed when this was last regenerated; a small n (as called for by the design, >=10) is not a statistically powerful sample -- report counts, not a rate with confidence bounds.
- All trials share one scripted benign-flight-free attack window on one airframe/world/host; this is not independent of host load (see `docs/PX4_SITL_INTEGRATION.md` Sec2 on RTF variability).
- `pos_residual_m` is a running sum (see module docstring); time-to-detection-from-end conflates drift duration with detector latency less than time-to-detection-from-onset does, but neither is a clean 'alarm latency' figure independent of this attack's own duration parameter.
- No claim about PX4's own trajectory/estimator: the relay's uplink stays passthrough by construction.
- No comparison yet against the Stage-1 *simulated* `gps_spoofing` attack class recall (different injection point).
