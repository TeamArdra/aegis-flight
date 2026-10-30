# Real flight-controller bench tests (Pixhawk 6X running ArduCopter)

Drivers used for the real-hardware runs in `docs/RADIO_TEST_RESULTS.md`: a real Pixhawk on the Pi's USB port, the Pi's
`ips-bridge` in front of it, an LR900 radio pair to the laptop. **Every one of them assumes a DISARMED vehicle with the
propellers removed.** `px_attack.py` aborts if the vehicle ever reports armed; nothing here arms, takes off or sends a
motor command. They change the flight mode (and `px_legit.py` writes one scratch parameter, restored, and may upload and
clear a two-item mission on an empty vehicle): afterwards run `px_restore_mode.py` on the Pi (bridge stopped).

| script | where | what |
|---|---|---|
| `px_listen.py`, `px_decode.py` | laptop or Pi | read-only: decode what a serial port carries (`px_decode.py` uses the full ArduPilot dialect and accounts for every byte) |
| `px_gcs.py` | laptop (radio port) | benign ground station: heartbeat + low-rate stream request |
| `px_attack.py` | laptop (radio port) | unsigned-link attack sequence: forged LAND / RTL (spoofing sysid 255) / force-disarm / set-mode, replay, flood; per-event table |
| `px_track_forger.py` | laptop | forger that copies the pilot's own sequence counter |
| `px_legit.py`, `px_params.py` | laptop (hub 5801) | legitimate-traffic suite through the bridge: streams, parameter read/write/restore, commands, mode changes, RC override, mission download, full parameter download with retries |
| `px_soak.py` | laptop (hub 5801) | long benign soak: heartbeat gaps, frames per minute, AEGIS texts |
| `px_fwwatch.py` | laptop (hub 5802) | prints the AEGIS announcements (firmware-tamper test) |
| `px_gpslog.py`, `gps_replay.py` | Pi / laptop | capture the real GPS / EKF messages and replay them through the repo's extractor and physics detector |
| `px_restore_mode.py` | Pi | put a disarmed vehicle back into STABILIZE |

## Things that cost time (read before writing a driver)

* **pymavlink's `msg.pack(mav)` does not advance `mav.seq`; `mav.send()` does.** Hand-built frames with `pack()` all carry
  sequence 0, which the bridge then (correctly) reads as replays (identical bytes) and as "two senders on one sysid" (same
  seq, different payload). Advance the counter yourself, one per sender.
* Never `pkill -f 'ips-bridge'` inside the same SSH command that starts the bridge: the command line matches itself.
* The LR900 ground unit adds ~50 B/s of `0x00` idle fill on its serial port; MAVLink parsers skip it.
* Stream rates persist on the flight controller until it reboots, and the first open of an idle port returns ~100 buffered frames.
* Over the radio (about 2 KB/s) a full parameter download loses roughly a quarter of the frames; re-request the missing indexes.

## Returning the vehicle to its original state

1. `px_snapshot.py PORT DIR` (read-only) before any change: all listed parameters, the mission, firmware version, mode.
2. `px_restore.py PORT DIR` is a dry run that prints the differences; `--apply` puts parameters, mission and mode back and re-checks.
3. Signing is not a parameter: `px_signing.py PORT off KEYFILE` sends a zero key signed with the key in force, then proves an UNSIGNED read is answered again.
   Keep the key file; without it signing cannot be removed over MAVLink.
4. **Limit:** a snapshot covers only the parameters the vehicle lists (1098 on the bench unit). Parameters that answer by name but are not in the
   list (the scripting scratch parameters `SCR_USER1..6`) are NOT covered; a test that touches one must restore it by name. This was found when a
   deliberate change to two of them was invisible to the diff (they were put back by hand), and proven with a listed parameter (`NTF_BUZZ_VOLUME`,
   100 -> 50 -> restored, confirmed by a direct read).
