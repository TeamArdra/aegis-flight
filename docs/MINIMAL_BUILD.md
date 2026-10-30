# Minimal build: flight controller + GPS + telemetry radio + cheap onboard computer

The target is a cheap drone whose only link to the ground is the telemetry radio. Nothing below has been measured on real
hardware: the Pi's CPU/latency headroom is **not measured**, and the software has only run on a PC (synthetic frames,
loopback sockets, ArduCopter SITL).

## Two wirings

### 1. Pi inline (recommended): FC TELEM <-> Pi <-> radio

```
FC TELEM port <--UART--> [ Raspberry Pi: aegis ips-bridge ] <--USB-serial adapter--> telemetry radio
```

Needs TWO serial ports on the computer: the Pi's UART for the FC and a USB-serial adapter for the radio. The bridge sees
both directions, can drop hostile uplink frames (active-ips), and reaches the ground in-band
(`docs/MGMT_CHANNEL.md`): alert and action STATUSTEXTs, a compact status vector and a few signed posture controls, all
within a budget of 150 B/s by default.

Can: detect, report, block hostile uplink frames and send counter-commands (active-ips), receive signed posture changes.
Cannot: run without the Pi (it is in the data path), survive the Pi dying (below), configure itself remotely.

### 2. Pi only on TELEM2 as a companion

```
FC TELEM1 <--> radio          FC TELEM2 <--> Pi (companion, passive listener)
```

The Pi sees only what the FC sends on that port; it cannot block frames. Its alerts reach the ground only if the FC forwards
companion-computer messages to the radio, which depends on firmware and parameters (for example MAVLink routing /
forwarding settings) and is **UNVERIFIED here**: treat this wiring as **detection-only** (local log, local dashboard) until
the forwarding is proven on the actual FC. The in-band control channel and `active-ips` blocking are not available this way.

## No hardware bypass: the risk

In wiring 1 both ports end at the Pi: a crash, a power loss or a stalled bridge cuts the radio link to the FC. There is no
hardware bypass (relay or splitter) in this repo. Mitigations, in order of strength:

* A hardware bypass: a latching relay or a serial splitter that connects FC <-> radio directly when the Pi is down or its
  heartbeat stops (optional, not provided).
* A software watchdog: run the bridge under systemd with automatic restart, e.g.

```
[Unit]
Description=AegisFlight inline bridge
[Service]
ExecStart=/opt/aegis/bin/aegis ips-bridge --fc-port /dev/ttyAMA0 --fc-baud 921600 --gcs-port /dev/ttyUSB0 \
  --gcs-baud 57600 --defense-mode advisory --signing-key-file /etc/aegis/flight.key \
  --mgmt-key-file /etc/aegis/mgmt.key --mgmt-state /var/lib/aegis/mgmt.json --audit-log /var/lib/aegis/audit.jsonl \
  --lock-posture-file /boot/aegis-lock
Restart=always
RestartSec=1
WatchdogSec=10
[Install]
WantedBy=multi-user.target
```

  The restart gap is a link outage; the bridge itself fails open per frame and its policy rules lapse if the analyser stalls,
  but a dead process forwards nothing. Measured on a Pi 3B+ on 2026-10-30 (Pi-in-the-loop, no radio): a hard kill
  (`kill -9`) followed by a manual restart gave a telemetry outage of 13.0 s (11 s dead, about 2 s start-up). The systemd
  `Restart=always` path above was not measured.

  Optional firmware check (code commit e8d08d3): add `--firmware-dir /etc/aegis/firmware --firmware-recheck-s 30` to
  `ExecStart`, with the manifest made by `aegis fw-manifest /etc/aegis/firmware`. The manifest is not signed: a rewriter of
  both the binary and the manifest defeats it. Without `--firmware-dir` the firmware verdict stays UNKNOWN.

## Provisioning (all at the bench)

Everything is provisioned before flight: the flight signing key (shared with the GCS and the FC's signing setup), a SEPARATE
management key for remote control, the detector profile, the state/audit paths and the lock-posture file location. Nothing can
be provisioned, rotated or reconfigured over the radio (`docs/MGMT_CHANNEL.md`, "What it cannot do"). Keep key files readable by
the service user only.

## What each wiring can and cannot do

| | 1. Pi inline | 2. Pi on TELEM2 |
|---|---|---|
| Detect attacks on the radio link | both directions | only what the FC emits on that port |
| Alerts to the ground over the radio | yes (in-band, budgeted) | only if the FC forwards companion messages (unverified) |
| Drop hostile uplink frames | yes, in active-ips | no |
| Counter-commands to the FC | yes, in active-ips | yes (to the FC on that port), unverified end to end |
| Signed posture control from the ground | yes | no |
| Survives a Pi failure | no, without a bypass | yes (the radio is wired to the FC directly) |
| Needs | UART + USB-serial adapter | one spare FC serial port |
