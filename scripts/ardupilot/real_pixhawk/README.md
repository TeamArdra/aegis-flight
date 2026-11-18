# Real flight-controller bench tests (Pixhawk 6X running ArduCopter)

> **Attack tooling removed (AGENTS.md section 5).** The real-hardware attack and injection drivers (`px_attack.py`,
> `px_signed_attack.py`, `px_track_forger.py`, `px_campaign.py`, `run_px_campaign.sh`, `px_fc_proxy.py`, `px_proxy_ctl.py`,
> `px_altbias_probe.py`, and `scripts/radio_test/attacks.py`) are no longer in the tree: attack tooling targets only local
> SITL. They remain in git history at `c9816ff` as the record behind the BENCH results. Attack testing is done in SITL,
> simulation or offline replay (e.g. `signed_downlink_replay.py` below, which needs no hardware).

Drivers used for the real-hardware runs in `docs/RADIO_TEST_RESULTS.md`: a real Pixhawk on the Pi's USB port, the Pi's
`ips-bridge` in front of it, an LR900 radio pair to the laptop. **Every one of them assumes a DISARMED vehicle with the
propellers removed.** Nothing here arms, takes off or sends a motor command. Some change the flight mode (and `px_legit.py` writes one scratch parameter, restored, and may upload and
clear a two-item mission on an empty vehicle): afterwards run `px_restore_mode.py` on the Pi (bridge stopped).

| script | where | what |
|---|---|---|
| `px_listen.py`, `px_decode.py` | laptop or Pi | read-only: decode what a serial port carries (`px_decode.py` uses the full ArduPilot dialect and accounts for every byte) |
| `px_gcs.py` | laptop (radio port) | benign ground station: heartbeat + low-rate stream request |
| `px_legit.py`, `px_params.py` | laptop (hub 5801) | legitimate-traffic suite through the bridge: streams, parameter read/write/restore, commands, mode changes, RC override, mission download, full parameter download with retries |
| `px_soak.py` | laptop (hub 5801) | long benign soak: heartbeat gaps, frames per minute, AEGIS texts |
| `px_fwwatch.py` | laptop (hub 5802) | prints the AEGIS announcements (firmware-tamper test) |
| `px_gpslog.py`, `gps_replay.py` | Pi / laptop | capture the real GPS / EKF messages and replay them through the repo's extractor and physics detector |
| `px_restore_mode.py` | Pi | put a disarmed vehicle back into STABILIZE |
| `px_snapshot.py`, `px_restore.py`, `px_common.py` | Pi (bridge stopped) | read-only snapshot of all listed parameters + mission; dry-run diff and `--apply` restore |
| `px_signing.py` | Pi (bridge stopped) | MAVLink-2 signing on / off / check (zero key switches it off); the USB link is exempt on ArduPilot, so this cannot show enforcement at the vehicle |

## Things that cost time (read before writing a driver)

* **pymavlink's `msg.pack(mav)` does not advance `mav.seq`; `mav.send()` does.** Hand-built frames with `pack()` all carry
  sequence 0, which the bridge then (correctly) reads as replays (identical bytes) and as "two senders on one sysid" (same
  seq, different payload). Advance the counter yourself, one per sender.
* Never `pkill -f 'ips-bridge'` inside the same SSH command that starts the bridge: the command line matches itself.
* The LR900 ground unit adds ~50 B/s of `0x00` idle fill on its serial port; MAVLink parsers skip it.
* Stream rates persist on the flight controller until it reboots, and the first open of an idle port returns ~100 buffered frames.
* Over the radio (vendor rate setting 2.1 KB/s; measured clean throughput about 1 KB/s) a full parameter download loses roughly a quarter of the frames; re-request the missing indexes.

## Returning the vehicle to its original state

1. `px_snapshot.py PORT DIR` (read-only) before any change: all listed parameters, the mission, firmware version, mode.
2. `px_restore.py PORT DIR` is a dry run that prints the differences; `--apply` puts parameters, mission and mode back and re-checks.
3. Signing is not a parameter: `px_signing.py PORT off KEYFILE` sends a zero key signed with the key in force, then proves an UNSIGNED read is answered again.
   Keep the key file; without it signing cannot be removed over MAVLink.
4. **Limit:** a snapshot covers only the parameters the vehicle lists (1098 on the bench unit). Parameters that answer by name but are not in the
   list (the scripting scratch parameters `SCR_USER1..6`) are NOT covered; a test that touches one must restore it by name. This was found when a
   deliberate change to two of them was invisible to the diff (they were put back by hand), and proven with a listed parameter (`NTF_BUZZ_VOLUME`,
   100 -> 50 -> restored, confirmed by a direct read).

## Software replay of the signed-link detection gap

`signed_downlink_replay.py ARM N OUT.json` (`ARM`: `unsigned`, `signed-fixed` or `signed-before`) needs no hardware. It drives the real `InlineIpsBridge` with a synthetic unsigned ArduPilot-style downlink and applies a +40 m altitude bias, as `px_fc_proxy.py alt_bias 40` does. Result with n = 10: unsigned 10/10 detected, signed with the fix 10/10, signed without it 0/10 (details: `docs/REAL_PIXHAWK_TEST.md`, section 11).
