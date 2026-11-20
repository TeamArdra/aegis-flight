# Pre-recording checklist (issue #33)

Work through this on the recording day, before pressing record. Write the answers down: they go into the tracker
with the video's file name, length, format and SHA-256. Script: `DEMO_SCRIPT.md`. PowerShell, repository root.

## 1. Freeze build and software

- [ ] The recording is on the **freeze build**, after #23 merged (#23 is closed; its change is `389fc02` on `main`).
      `git status` is clean; `git rev-parse HEAD` is written down and goes on the title and end cards.
- [ ] Every command in `DEMO_SCRIPT.md` re-checked with `--help` on the freeze build. The commands were verified on
      `main` at `389fc02`; open PRs (for example #76, #79) change the CLI, so a later freeze build may differ.
- [ ] `.venv\Scripts\python.exe -m pytest -p no:cacheprovider` run; write down the pass/skip counts actually
      obtained (they go on the end card; do not copy a number from a document).
- [ ] `.venv\Scripts\ruff.exe check src tests scripts backend` clean.
- [ ] `npm --prefix frontend ci` then `npm --prefix frontend run build`: the server serves `frontend/dist`.
- [ ] `models\isoforest.joblib` (SIM) and `models\isoforest_px4.joblib` (SITL trials) exist. Both are git-ignored;
      `run_p2_trial.py` stops with "requested model ... does not exist" without the second one.
- [ ] A scratch folder outside the repository exists (`<scratch>`, e.g. `$env:TEMP\aegis_demo`) and the `--out`
      and `--db` names used in the script are not already present there (the trial scripts refuse to overwrite).
- [ ] Nothing in the run writes into `artifacts/`; the default database `artifacts/aegisflight_live.sqlite` is not
      used (always pass `--db <scratch>\...`).

## 2. Bench hardware safety (operator, by eye; do not infer from software)

- [ ] Board: Pixhawk 6X (ArduPilot, per `docs/HARDWARE_BENCH_PIXHAWK6X.md`). **Disarmed. Propellers off.** Restrained.
- [ ] Power source written down.
- [ ] **No ground station connected on any port** (Mission Planner, QGroundControl closed). A ground station
      transmits to the board, and a serial port has one owner. If one was connected since power-up, write that down.
- [ ] Nobody touches the RC transmitter. No arming, no mode change, no parameter write, no calibration on camera.
- [ ] Stop rule: if the board arms, changes mode or behaves unexpectedly, unplug the laptop-side radio or USB.

## 3. Serial port: find it without opening it

```powershell
Get-PnpDevice -Class Ports -PresentOnly | Format-Table Status,FriendlyName,InstanceId -AutoSize
```

- [ ] Port identified (the laptop-side telemetry radio at 115200 was the working link in
      `docs/HARDWARE_BENCH_PIXHAWK6X.md` §6). If absent or ambiguous, stop: do not sweep baud rates or reconfigure
      the radio. Never open an SLCAN port.

## 4. PX4 SITL (WSL)

- [ ] PX4 version written down (record it; PX4 is a release candidate):
      ```powershell
      wsl -d Ubuntu-24.04 --cd /home/astryx/PX4-Autopilot -- git describe --tags --always
      ```
      Same command as the trial scripts use (`scripts/sitl/p2_trial_common.py:41-42`); every trial manifest also
      records it under `provenance.px4_git_describe`.
- [ ] Always name the distro (`wsl -d Ubuntu-24.04`); a bare `wsl` reaches a different default distro.
- [ ] Fresh SITL boot before **each** trial (`start_px4_sitl.sh stop`, then `start`, wait ~30 s, `status`).
- [ ] After the session, from PowerShell, this prints nothing (PX4 tree untouched):
      ```powershell
      wsl -d Ubuntu-24.04 --cd /home/astryx/PX4-Autopilot -- git status --porcelain --untracked-files=no
      ```

## 5. Receive-only and local-only boundaries confirmed

- [ ] Bench server started with `--source serial` and **without** `--defense-mode`, `--gcs-notify` or
      `--mgmt-key-file`. Posture shows `PASSIVE` (default, `src/aegisflight/cli/main.py:459`).
- [ ] Code boundary understood: on an OS serial device the backend never transmits
      (`transmit_allowed` is false: `src/aegisflight/backend/sources.py:100-104`,
      `src/aegisflight/sources/mavlink_serial.py:337-342`; `_transmit` returns early:
      `src/aegisflight/backend/engine.py:491-500`).
- [ ] Rehearsal of `/api/status ... bytes_sent` done once before recording (no hardware needed, see the fallback
      in `DEMO_SCRIPT.md`).
- [ ] Bind addresses are local: dashboard `--host` default `127.0.0.1` (`src/aegisflight/cli/main.py:437`); never
      pass `--host 0.0.0.0`. The relay's client side binds loopback only (`src/aegisflight/proxy/transport.py:24`,
      `:212`). `virtual_serial_replay.py` binds 127.0.0.1. The relay's upstream leg goes only to the WSL SITL
      address on the WSL virtual network.
- [ ] Attack tooling targets only the local SITL link. No real RF, no real vehicle, no third-party network.
- [ ] `AEGIS_API_TOKEN` not printed on screen if set (`src/aegisflight/backend/app.py:99`).

## 6. Screen and terminal

- [ ] Resolution at least 1920x1080, browser zoom 100 %, terminal font at least 16 pt.
- [ ] Each terminal carries its environment tag in the prompt and window title, e.g.:
      ```powershell
      function prompt { "[SITL] PS> " }; $Host.UI.RawUI.WindowTitle = "SITL - local link only"
      ```
      (`[BENCH]`, `[SITL]`, `[BENCH db]`, `[SIM db]`).
- [ ] Clean terminals (`Clear-Host`), no history with paths, tokens or keys; no file explorer.
- [ ] No coordinates on screen: do not open or print any `.tlog`, `frames.jsonl` or `telemetry` field; the
      decision lines shown in the script (`t, type, score, evidence`) carry none.
- [ ] No `.claude/`, no private paths beyond the repository root, no notifications (focus mode on).
- [ ] Dashboard header badge and footer visible in every dashboard shot.

## 7. After recording

- [ ] Video saved outside Git. Record file name, length, format and SHA-256
      (`Get-FileHash -Algorithm SHA256 <file>`) in the tracker; check the size against the organisers' limit.
- [ ] Captured evidence (see `EVIDENCE_AND_LIMITATIONS.md` §2) saved with the commit and PX4 version.
- [ ] PX4 tree clean check (§4) run and empty.
