# Link-stress sweep (SIM, benign sessions)

Sessions per cell: 6 (seeds 70000..70005); session length: simulator default (120 s); link: {"mean_delay_ms": 25.0} + loss/ordering per row.

**Definitions.** *Decision*: one fusion decision (5 Hz); only scored decisions count (t >= 5 s warm-up). *Alarm decision*:
scored decision with `threat == True`; every session is benign, so each is a false positive. *Decision FPR*: alarm
decisions / scored decisions. *Alert event*: a maximal run of consecutive alarm decisions inside one session (a scored
non-alarm decision or the session end closes it). *Events/h*: alert events / (scored decisions x decision period / 3600).
*Dominant evidence*: most frequent normalised evidence string over the cell's alarm decisions (once per decision, digits
collapsed to `#`, `coverage...` notes ignored); the per-decision raw strings are in `decisions.csv.gz`.

| profile | order | loss % | ML | decision FPR | alarm/scored | events/h | events | dominant evidence (count) |
|---|---|---:|---|---:|---:|---:|---:|---|
| stage1 | fifo | 0 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| stage1 | fifo | 0 | on | 0.6455 | 2227/3450 | 2389.6 | 458 | ML anomaly score # ≥ # (driver: interarrival_jitter_ms, z=#) (1824) |
| stage1 | fifo | 1 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| stage1 | fifo | 1 | on | 0.6313 | 2178/3450 | 2493.9 | 478 | ML anomaly score # ≥ # (driver: interarrival_jitter_ms, z=#) (1744) |
| stage1 | fifo | 2 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| stage1 | fifo | 2 | on | 0.6336 | 2186/3450 | 2441.7 | 468 | ML anomaly score # ≥ # (driver: interarrival_jitter_ms, z=#) (1678) |
| stage1 | fifo | 5 | off | 0.0003 | 1/3450 | 5.2 | 1 | implausible acceleration # m/s² (1) |
| stage1 | fifo | 5 | on | 0.6186 | 2134/3450 | 2619.1 | 502 | ML anomaly score # ≥ # (driver: interarrival_jitter_ms, z=#) (1393) |
| stage1 | fifo | 10 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| stage1 | fifo | 10 | on | 0.6699 | 2311/3450 | 2655.7 | 509 | ML anomaly score # ≥ # (driver: interarrival_jitter_ms, z=+#) (1293) |
| stage1 | reorder | 0 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| stage1 | reorder | 0 | on | 0.9881 | 3409/3450 | 156.5 | 30 | ML anomaly score # ≥ # (driver: interarrival_jitter_ms, z=#) (3407) |
| stage1 | reorder | 1 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| stage1 | reorder | 1 | on | 0.9855 | 3400/3450 | 156.5 | 30 | ML anomaly score # ≥ # (driver: interarrival_jitter_ms, z=#) (3398) |
| stage1 | reorder | 2 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| stage1 | reorder | 2 | on | 0.9768 | 3370/3450 | 250.4 | 48 | ML anomaly score # ≥ # (driver: interarrival_jitter_ms, z=#) (3363) |
| stage1 | reorder | 5 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| stage1 | reorder | 5 | on | 0.9510 | 3281/3450 | 464.3 | 89 | ML anomaly score # ≥ # (driver: interarrival_jitter_ms, z=#) (3265) |
| stage1 | reorder | 10 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| stage1 | reorder | 10 | on | 0.9032 | 3116/3450 | 866.1 | 166 | ML anomaly score # ≥ # (driver: interarrival_jitter_ms, z=#) (2930) |
| px4 | fifo | 0 | off | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | fifo | 0 | on | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | fifo | 1 | off | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | fifo | 1 | on | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | fifo | 2 | off | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | fifo | 2 | on | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | fifo | 5 | off | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | fifo | 5 | on | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | fifo | 10 | off | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | fifo | 10 | on | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | reorder | 0 | off | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | reorder | 0 | on | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | reorder | 1 | off | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | reorder | 1 | on | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | reorder | 2 | off | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | reorder | 2 | on | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | reorder | 5 | off | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | reorder | 5 | on | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | reorder | 10 | off | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| px4 | reorder | 10 | on | n/a | n/a | n/a | n/a | n/a: the px4_sitl profile is calibrated for PX4 SITL traffic (sysid 3, ~378 msg/s); the simulator emits sysid 1 at ~28 msg/s, so 'rogue telemetry source' fires on every decision and the cell measures the mismatch, not the profile. Measure this profile on PX4 SITL replays (#27 items 3-4). |
| ardupilot | fifo | 0 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| ardupilot | fifo | 0 | on | n/a | n/a | n/a | n/a | n/a: no ArduPilot-benign ML model exists; the Stage-1 model is documented not to transfer to ArduPilot (docs/ARDUPILOT_SITL.md) - pass --model-ardupilot to force a model |
| ardupilot | fifo | 1 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| ardupilot | fifo | 1 | on | n/a | n/a | n/a | n/a | n/a: no ArduPilot-benign ML model exists; the Stage-1 model is documented not to transfer to ArduPilot (docs/ARDUPILOT_SITL.md) - pass --model-ardupilot to force a model |
| ardupilot | fifo | 2 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| ardupilot | fifo | 2 | on | n/a | n/a | n/a | n/a | n/a: no ArduPilot-benign ML model exists; the Stage-1 model is documented not to transfer to ArduPilot (docs/ARDUPILOT_SITL.md) - pass --model-ardupilot to force a model |
| ardupilot | fifo | 5 | off | 0.0003 | 1/3450 | 5.2 | 1 | implausible acceleration # m/s² (1) |
| ardupilot | fifo | 5 | on | n/a | n/a | n/a | n/a | n/a: no ArduPilot-benign ML model exists; the Stage-1 model is documented not to transfer to ArduPilot (docs/ARDUPILOT_SITL.md) - pass --model-ardupilot to force a model |
| ardupilot | fifo | 10 | off | 0.0003 | 1/3450 | 5.2 | 1 | implausible acceleration # m/s² (1) |
| ardupilot | fifo | 10 | on | n/a | n/a | n/a | n/a | n/a: no ArduPilot-benign ML model exists; the Stage-1 model is documented not to transfer to ArduPilot (docs/ARDUPILOT_SITL.md) - pass --model-ardupilot to force a model |
| ardupilot | reorder | 0 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| ardupilot | reorder | 0 | on | n/a | n/a | n/a | n/a | n/a: no ArduPilot-benign ML model exists; the Stage-1 model is documented not to transfer to ArduPilot (docs/ARDUPILOT_SITL.md) - pass --model-ardupilot to force a model |
| ardupilot | reorder | 1 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| ardupilot | reorder | 1 | on | n/a | n/a | n/a | n/a | n/a: no ArduPilot-benign ML model exists; the Stage-1 model is documented not to transfer to ArduPilot (docs/ARDUPILOT_SITL.md) - pass --model-ardupilot to force a model |
| ardupilot | reorder | 2 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| ardupilot | reorder | 2 | on | n/a | n/a | n/a | n/a | n/a: no ArduPilot-benign ML model exists; the Stage-1 model is documented not to transfer to ArduPilot (docs/ARDUPILOT_SITL.md) - pass --model-ardupilot to force a model |
| ardupilot | reorder | 5 | off | 0.0000 | 0/3450 | 0.0 | 0 | - (0) |
| ardupilot | reorder | 5 | on | n/a | n/a | n/a | n/a | n/a: no ArduPilot-benign ML model exists; the Stage-1 model is documented not to transfer to ArduPilot (docs/ARDUPILOT_SITL.md) - pass --model-ardupilot to force a model |
| ardupilot | reorder | 10 | off | 0.0003 | 1/3450 | 5.2 | 1 | implausible acceleration # m/s² (1) |
| ardupilot | reorder | 10 | on | n/a | n/a | n/a | n/a | n/a: no ArduPilot-benign ML model exists; the Stage-1 model is documented not to transfer to ArduPilot (docs/ARDUPILOT_SITL.md) - pass --model-ardupilot to force a model |
