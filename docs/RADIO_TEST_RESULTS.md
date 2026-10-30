# Real-radio test results log

> **No phase has passed on the real radio.** The Bench log below (2026-10-30) holds the first measured bench observations.
> They are not phase results.
> The phase tables below are empty templates. Do not enter an expected, estimated or simulated number. Each row is one measured run
> of the procedure in `docs/RADIO_TEST.md`, copied from that run's `<phase>.json` / `report.md`. A failed or aborted run gets a row
> too, marked FAIL or ABORTED with the reason. A phase that was not run stays empty.

## Bench log, 2026-10-30 (measured)

Measured on the bench on 2026-10-30. These are observations of the rig, not results of the phases in `docs/RADIO_TEST.md`.
No phase was run to completion, and nothing below is a pass.

**Laptop**

* Silicon Labs CP210x USB driver 11.6.0.420, signed. Device on COM3, status OK.

**Raspberry Pi**

* Kernel 6.18.50. `cp210x` kernel module loaded.
* Radio at `/dev/ttyUSB0`. By-id alias: `/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0`.
* User `ardra` is in group `dialout`.
* Python 3.13.5. Venv `~/aegis_test/venv` with pyserial 3.5.

**Pi power**

* `vcgencmd get_throttled` = `0x50005`. Under-voltage and throttling are active now (bits 0 and 2), and both have occurred
  since boot (bits 16 and 18).
* The kernel log shows repeated `Undervoltage detected`.
* Consequence: Pi timing and CPU figures taken on this supply are worst-case and not valid for the plan until the supply is
  fixed (5 V, 2.5 A or more, short thick cable).

**First link attempt**

* Pi: `pi_relay.py --mode echo`. Laptop: `link_baseline.py` on COM3. Both at 57,600 baud, then both at 115,200 baud.
* Warm-up: 0 of 10 echoes at each baud.
* Pi relay counters: 0 bytes received from the radio.
* Result: no data crossed the air link in this attempt.
* Laptop SiK command-mode query (`+++`, then `ATI`) on COM3 at 57,600, 115,200, 38,400, 9,600, 19,200 and 230,400 baud:
  no `OK` reply at any baud.

**Interpretation (hypotheses, not conclusions)**

These have not been tested. Each would explain the symptoms above.

1. The radio may not be a SiK-type, AT-command-capable unit.
2. The radio may be using a UART baud that was not tried.
3. The air side may be unpowered.
4. The two radios may not be paired: different net id or air rate.

**Not yet checked:** radio LEDs and power on both units; the net id, air rate and serial speed of each unit read with the
vendor tool; the USB latency timer on the Pi.

## How to fill a row

* **Date**: local date and time of the run (ISO format).
* **Config**: the rig for that run in short form, for example `57600 baud, Pi passive, SITL GUIDED, unsigned` or
  `115200, active-ips, signed, mgmt on`. Include the baud, posture, signing on/off, `--signing-max-age-s`, and anything unusual
  (a different radio placement, a changed SiK air rate).
* **Commit**: `git rev-parse --short HEAD` of the repo that was run on the laptop and on the Pi (the same commit on both; if they
  differed, say so in Notes). Add `+dirty` if there were uncommitted changes.
* **Key numbers**: the figures that decide the phase (the checks' `value` fields), with units.
* **Result**: PASS, FAIL or ABORTED, as written by the tool's `passed` flag, not changed by hand.
* **Notes**: Pi `vcgencmd get_throttled` before and after, Wi-Fi RTT, anything that may bias the figures, link to the run
  directory name. Never paste keys, tokens or passwords.

## Rig record (fill once per campaign)

| Item | Value |
|---|---|
| Campaign date | |
| Commit (laptop / Pi) | |
| Radio serial baud (from phase 0) | |
| SiK settings (serial speed, air speed, net id, TX power, band) | |
| Pi Python / aegis version | |
| Pi `get_throttled` at start | |
| Laptop IP / Pi IP / Wi-Fi RTT | |
| USB latency timer on the Pi (set to 1 ms? file present?) | |
| Run directory | |

## Phase 0: preflight and probe

| Date | Config | Commit | Best baud / frames / B/s | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 1: link baseline without the bridge

| Date | Config (echo / pass) | Commit | Throughput B/s, frame loss %, RTT p50 / p95 ms, largest heartbeat gap s | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 2: bridge passive forwarding

| Date | Config | Commit | Frames down / up, dropped, hook_errors, extra RTT vs phase 1 p95, bridge CPU %, RSS MiB | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 3: normal pilot operation

| Date | Config (advisory / active-ips) | Commit | Commands sent / acked, legitimate dropped, alerts (class, count), ACK latency p50 / p95 ms | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 4: detection

| Date | Config | Commit | Per attack: alerted (y/n), time to STATUSTEXT at the laptop s | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 5: prevention in ACTIVE_IPS

| Date | Config | Commit | Hostile frames sent / dropped / reaching FC, forced disarm passed, GPS ladder: confirm to ALT_HOLD s, override honoured, legitimate dropped | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 6: MAVLink-2 signing

| Date | Config (max-age s) | Commit | Signed ok / acked, dropped_unsigned, dropped_bad_signature, dropped_replay, stale dropped, future frame outcome, gate exit code | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 7: management channel over the radio

| Date | Config | Commit | Alert latency s, status age s, posture ACK latency s, mgmt B/s nominal / flood (peak 1 s), cross-end B/s, bad-frame ACKs (expect 0) | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Phase 8: failure and recovery

| Date | Failure case | Commit | Outage s (last ACK to first ACK after), manual steps needed, replay after restart dropped (y/n), CRC-invalid frames | Result | Notes |
|---|---|---|---|---|---|
| | Pi radio replug | | | | |
| | Laptop radio replug | | | | |
| | Bridge kill and restart | | | | |
| | SITL drop and restart | | | | |
| | Pi reboot | | | | |

## Phase 9: soak

| Date | Config | Commit | Duration min, legitimate dropped, hook_errors, RSS start / end MiB, CPU %, loss first / last 10 min, new throttle bits | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Combined flight session (phases 3-6)

| Date | Config | Commit | Stages run, per-stage result, anything left unreliable by an earlier stage | Result | Notes |
|---|---|---|---|---|---|
| | | | | | |

## Findings and what was not shown

Fill after the runs: bugs found (with the fix commit and regression test), documented limits that were confirmed or contradicted,
and the list of phases not run or failed. Keep claims to what the rows above show.

| Finding | Phase | Evidence (run directory, file) | Status |
|---|---|---|---|
| | | | |
