# Raspberry Pi test scripts (SITL on the laptop, bridge on a Raspberry Pi)

Bench scripts used for docs/RADIO_TEST_RESULTS.md. Everything runs from `C:/afsitl` on a Windows laptop (see `../README.md`)
and needs `PI_KEY` (ssh private key path), optionally `PI_HOST` (default the link-local address used on the bench) and, for
`run_radio_pi.sh`, `REPO` (this repository's root). The Pi needs `~/aegis_test` with `src/`, `configs/`, a venv, and
`scripts/radio_test/pi_bridge.sh` copied to `~/aegis_test/pi_bridge.sh` (`scripts/radio_test/laptop_ctl.py deploy`).

| script | what it runs |
|---|---|
| `run_pi_case.sh` | flight + forged LAND, bridge on the Pi through ssh -R tunnels |
| `run_signing_pi.sh` | signed link: unsigned / wrong-key / replay attacks |
| `run_fault_pi.sh`, `run_fault2_pi.sh` | bridge kill + restart, link loss without a manual restart |
| `run_attacks_pi.sh` | flood, telemetry manipulation (`inject_proxy.py`), firmware tamper |
| `run_soak_pi.sh` | 30-minute soak with `pi_monitor.py` |
| `run_radio_signing_pi.sh`, `run_radio_gps_pi.sh`, `run_radio_long_pi.sh` | signing, GPS glitch, and bridge kill + restart over the REAL radio pair |
| `run_radio_unplug_pi.sh` | flight with a radio unplug and replug during the run (a person pulls the Pi radio cable) |
| `run_radio_reboot_pi.sh` | a person reboots the Pi during the flight; the bridge must come back by itself (`scripts/radio_test/pi_autostart.sh` via cron @reboot or `aegis-bridge.service`) |
| `run_radio_pi.sh` | the REAL radio pair: laptop COM3 hub -> LR900 ground/air -> Pi bridge (low stream rates) |
