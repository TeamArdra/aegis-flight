"""Hostile-traffic injector for the real-radio test of the AegisFlight inline IPS bridge.

Connects to the ground hub's GCS port (read/write) as an untrusted sysid alongside a continuous legit
trusted-sysid heartbeat/command stream, injects one scenario's hostile frames, and watches the hub's
observer port (read-only downlink) for the effect: the vehicle's HEARTBEAT ``custom_mode`` / armed bit,
and ``AEGIS:`` STATUSTEXT alerts (IDS alerts in passive, ``AEGIS: blocked ...`` drop summaries in active,
see ``docs/MGMT_CHANNEL.md``). Writes ``<out>/<scenario>.json`` via ``PhaseResult`` and a manifest JSON
with the exact counts of hostile frames injected per drop-reason class, so they can be diffed against the
bridge's own ``policy`` counters (``status()["policy"]``, see ``src/aegisflight/mitigation/inline_policy.py``).

    python attacks.py --hub 127.0.0.1:5801 --scenario forged_land --out radio_test_out
    python attacks.py --hub 127.0.0.1:5801 --scenario wrong_key --key-file sign.key \
        --wrong-key-file wrong.key --out radio_test_out --expect active

Scenarios: forged_land, forged_disarm, forged_mode, forged_rtl, flood, replay, unsigned_when_signed,
wrong_key, signed_replay, stale_timestamp, future_timestamp, gps_glitch.

Every scenario injects as ``--untrusted-sysid`` (default 77), EXCEPT the three that must share the
already-signing trusted stream's (link, sysid, compid) identity to exercise the timestamp rule in
isolation rather than the sysid/MAC check (a fresh identity's first signed frame always passes the
monotonicity check trivially): ``signed_replay`` (byte-identical replay of a captured trusted-sysid
frame) and ``stale_timestamp`` / ``future_timestamp`` (freshly built frames signed with the real key but
a bad clock), which impersonate ``--trusted-sysid`` (default 255). This models an attacker who has
obtained the signing key or a GCS with a wrong clock, not a MITM without the key.

``--expect`` sets what "passed" means: ``active`` (default) expects the hostile effect blocked;
``passive``/IDS expects the effect allowed through and an alert raised (``active-ips`` forwards nothing
to enforcement; see ``docs/INLINE_IPS.md``). ``future_timestamp`` is expected to show the hostile effect
even under ``--expect active``: the verifier has no upper bound on a signed timestamp, only strict
monotonicity, so a frame signed with a far-future timestamp is accepted and may then lock out the real
sender's next, correctly-timestamped frame (checked via the post-scenario legit probe). This is a known
gap (see docs/INLINE_IPS.md "Not covered"), not a tool bug.

Exit codes: 0 all checks passed, 1 a check failed, 2 the hub is unreachable or a scenario precondition
(usually a missing key file) was not met.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pymavlink.dialects.v20 import common as mav2

sys.path.insert(0, str(Path(__file__).resolve().parent))
from com_probe import Frame, FrameScanner  # noqa: E402
from results import PhaseResult  # noqa: E402

from aegisflight.mavlink.signing import MAVLINK_EPOCH_UNIX_S, sign_mavlink2_frame  # noqa: E402

UNTRUSTED_SYSID = 77
TRUSTED_SYSID = 255
VEHICLE_SYSID = 1
COMPID = 190
LINK_ID = 0

MAV_CMD_DO_SET_MODE = 176
MAV_CMD_NAV_RETURN_TO_LAUNCH = 20
MAV_CMD_COMPONENT_ARM_DISARM = 400
FORCE_MAGIC = 21196.0

# ArduCopter custom_mode numbers used by the scenarios below (distinct per scenario so effects don't alias).
MODE_GUIDED = 4
MODE_LOITER = 5
MODE_RTL = 6
MODE_CIRCLE = 7
MODE_LAND = 9

HEARTBEAT_ID = 0
STATUSTEXT_ID = 253

SCENARIOS = (
    "forged_land", "forged_disarm", "forged_mode", "forged_rtl", "flood", "replay",
    "unsigned_when_signed", "wrong_key", "signed_replay", "stale_timestamp", "future_timestamp", "gps_glitch",
)


# --------------------------------------------------------------------------- #
# frame construction
# --------------------------------------------------------------------------- #


def load_signing_key(path: str | Path) -> bytes:
    """32 raw bytes, or 64 hex characters, as accepted by ``aegis ips-bridge --signing-key-file``."""
    raw = Path(path).read_bytes().strip()
    if len(raw) == 64:
        with contextlib.suppress(ValueError):
            return bytes.fromhex(raw.decode("ascii"))
    if len(raw) == 32:
        return raw
    raise ValueError(f"{path}: expected 32 raw bytes or 64 hex characters, got {len(raw)}")


def now_10us() -> int:
    """Current time in the signature's 10 us ticks since the MAVLink 2 signing epoch."""
    return int(max(1.0, time.time() - MAVLINK_EPOCH_UNIX_S) * 100_000)


def sign(raw: bytes, key: bytes, timestamp_10us: int | None = None) -> bytes:
    return sign_mavlink2_frame(raw, key, link_id=LINK_ID, timestamp_10us=timestamp_10us)


class FrameBuilder:
    """Builds standalone MAVLink v2 frames for one claimed (sysid, compid); keeps its own seq counter."""

    def __init__(self, sysid: int, compid: int = COMPID) -> None:
        self.sysid, self.compid = sysid, compid
        self._mav = mav2.MAVLink(None, srcSystem=sysid, srcComponent=compid)

    def _raw(self, msg: mav2.MAVLink_message) -> bytes:
        raw = bytes(msg.pack(self._mav))
        self._mav.seq = (self._mav.seq + 1) % 256
        return raw

    def heartbeat(self, custom_mode: int = 0) -> bytes:
        return self._raw(self._mav.heartbeat_encode(mav2.MAV_TYPE_GCS, mav2.MAV_AUTOPILOT_INVALID, 0, custom_mode, 0))

    def command_long(self, command: int, p1: float = 0.0, p2: float = 0.0, p3: float = 0.0, p4: float = 0.0,
                      p5: float = 0.0, p6: float = 0.0, p7: float = 0.0, target_system: int = VEHICLE_SYSID,
                      target_component: int = 1) -> bytes:
        return self._raw(self._mav.command_long_encode(target_system, target_component, command, 0,
                                                        p1, p2, p3, p4, p5, p6, p7))

    def set_mode(self, custom_mode: int, target_system: int = VEHICLE_SYSID) -> bytes:
        return self._raw(self._mav.set_mode_encode(target_system, mav2.MAV_MODE_FLAG_CUSTOM_MODE_ENABLED, custom_mode))

    def param_set(self, param_id: str, value: float, param_type: int = mav2.MAV_PARAM_TYPE_REAL32,
                  target_system: int = VEHICLE_SYSID, target_component: int = 1) -> bytes:
        return self._raw(self._mav.param_set_encode(target_system, target_component, param_id.encode(), value,
                                                     param_type))


# --------------------------------------------------------------------------- #
# downlink effect watcher
# --------------------------------------------------------------------------- #


class DownlinkWatcher:
    """Reads the hub's read-only observer port; tracks the vehicle's HEARTBEAT and ``AEGIS:`` STATUSTEXTs."""

    def __init__(self, sock: socket.socket, vehicle_sysid: int = VEHICLE_SYSID) -> None:
        self._sock = sock
        self._vehicle_sysid = vehicle_sysid
        self._scanner = FrameScanner()
        self._lock = threading.Lock()
        self._heartbeats: list[tuple[float, int, bool]] = []  # (t, custom_mode, armed)
        self._alerts: list[tuple[float, str]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="downlink-watcher")

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._sock.shutdown(socket.SHUT_RDWR)
        with contextlib.suppress(OSError):
            self._sock.close()
        self._thread.join(timeout=2)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data = self._sock.recv(4096)
            except OSError:
                return
            if not data:
                return
            now = time.time()
            for fr in self._scanner.feed(data):
                self._on_frame(now, fr)

    def _on_frame(self, now: float, fr: Frame) -> None:
        if fr.sysid != self._vehicle_sysid:
            return
        if fr.msgid == HEARTBEAT_ID and len(fr.payload) >= 7:
            custom_mode = struct.unpack_from("<I", fr.payload, 0)[0]
            armed = bool(fr.payload[6] & 0x80)
            with self._lock:
                self._heartbeats.append((now, custom_mode, armed))
        elif fr.msgid == STATUSTEXT_ID and fr.payload:
            text = fr.payload[1:51].split(b"\0", 1)[0].decode("ascii", "replace")
            with self._lock:
                self._alerts.append((now, text))

    def modes_since(self, t0: float) -> list[int]:
        with self._lock:
            return [m for t, m, _a in self._heartbeats if t >= t0]

    def heartbeats_since(self, t0: float) -> list[tuple[float, int, bool]]:
        with self._lock:
            return [h for h in self._heartbeats if h[0] >= t0]

    def alerts_since(self, t0: float) -> list[str]:
        with self._lock:
            return [a for t, a in self._alerts if t >= t0]

    def vehicle_alive_since(self, t0: float) -> bool:
        return bool(self.heartbeats_since(t0))


# --------------------------------------------------------------------------- #
# legit trusted-sysid stream
# --------------------------------------------------------------------------- #


class LegitPilot:
    """Trusted-sysid stream: a background heartbeat plus on-demand commands; signs them if given a key."""

    def __init__(self, hub_host: str, hub_port: int, key: bytes | None, trusted_sysid: int = TRUSTED_SYSID) -> None:
        self.key = key
        self.builder = FrameBuilder(trusted_sysid)
        self.sock = socket.create_connection((hub_host, hub_port), timeout=5)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="legit-pilot")
        self.sent_control = 0

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        with contextlib.suppress(OSError):
            self.sock.close()

    def _run(self) -> None:
        last_hb = 0.0
        while not self._stop.is_set():
            now = time.time()
            if now - last_hb >= 0.5:
                with contextlib.suppress(OSError):
                    self.sock.sendall(self.builder.heartbeat())
                last_hb = now
            self._stop.wait(0.05)

    def _send_control(self, raw: bytes) -> bytes:
        if self.key is not None:
            raw = sign(raw, self.key)
        self.sock.sendall(raw)
        self.sent_control += 1
        return raw

    def command_long(self, command: int, p1: float = 0.0, p2: float = 0.0) -> bytes:
        """Send one (signed-if-keyed) sensitive command; returns the exact raw bytes sent."""
        return self._send_control(self.builder.command_long(command, p1, p2))

    def set_mode(self, custom_mode: int) -> bytes:
        return self._send_control(self.builder.set_mode(custom_mode))


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #


@dataclass
class RunCtx:
    out: Path
    key: bytes | None
    wrong_key: bytes | None
    iterations: int
    untrusted_sysid: int
    trusted_sysid: int
    gps_param: str
    gps_value: float
    attacker_sock: socket.socket
    attacker: FrameBuilder
    legit: LegitPilot


@dataclass
class ScenarioOutcome:
    """What was injected, and what a *successful* (unblocked) attack would look like on the downlink."""

    injected: dict[str, int]
    hostile_mode: int | None = None
    hostile_disarm: bool = False
    hostile_alert_substr: str | None = None
    note: str = ""


def _need(cond: bool, msg: str) -> None:
    if not cond:
        raise SystemExit(msg)


def scenario_forged_land(ctx: RunCtx) -> ScenarioOutcome:
    for _ in range(ctx.iterations):
        ctx.attacker_sock.sendall(ctx.attacker.command_long(MAV_CMD_DO_SET_MODE, 1, MODE_LAND))
        ctx.attacker_sock.sendall(ctx.attacker.set_mode(MODE_LAND))
        time.sleep(0.1)
    return ScenarioOutcome({"dropped_untrusted_control": ctx.iterations * 2}, hostile_mode=MODE_LAND,
                           note="DO_SET_MODE + SET_MODE to LAND from an untrusted sysid")


def scenario_forged_disarm(ctx: RunCtx) -> ScenarioOutcome:
    for _ in range(ctx.iterations):
        ctx.attacker_sock.sendall(ctx.attacker.command_long(MAV_CMD_COMPONENT_ARM_DISARM, 0.0, 0.0))
        ctx.attacker_sock.sendall(ctx.attacker.command_long(MAV_CMD_COMPONENT_ARM_DISARM, 0.0, FORCE_MAGIC))
        time.sleep(0.1)
    return ScenarioOutcome({"dropped_untrusted_control": ctx.iterations * 2}, hostile_disarm=True,
                           note="plain and forced (magic 21196) COMPONENT_ARM_DISARM from an untrusted sysid")


def scenario_forged_mode(ctx: RunCtx) -> ScenarioOutcome:
    for _ in range(ctx.iterations):
        ctx.attacker_sock.sendall(ctx.attacker.command_long(MAV_CMD_DO_SET_MODE, 1, MODE_CIRCLE))
        ctx.attacker_sock.sendall(ctx.attacker.set_mode(MODE_CIRCLE))
        time.sleep(0.1)
    return ScenarioOutcome({"dropped_untrusted_control": ctx.iterations * 2}, hostile_mode=MODE_CIRCLE,
                           note="DO_SET_MODE + SET_MODE to CIRCLE from an untrusted sysid")


def scenario_forged_rtl(ctx: RunCtx) -> ScenarioOutcome:
    for _ in range(ctx.iterations):
        ctx.attacker_sock.sendall(ctx.attacker.command_long(MAV_CMD_NAV_RETURN_TO_LAUNCH))
        ctx.attacker_sock.sendall(ctx.attacker.set_mode(MODE_RTL))
        time.sleep(0.1)
    return ScenarioOutcome({"dropped_untrusted_control": ctx.iterations * 2}, hostile_mode=MODE_RTL,
                           note="NAV_RETURN_TO_LAUNCH + SET_MODE to RTL from an untrusted sysid")


def scenario_flood(ctx: RunCtx) -> ScenarioOutcome:
    n = max(ctx.iterations * 10, 50)
    for _ in range(n):
        ctx.attacker_sock.sendall(ctx.attacker.command_long(MAV_CMD_DO_SET_MODE, 1, MODE_LAND))
        time.sleep(0.01)  # well under the 50 ms burst-rule cadence (cadence_s, inline_policy.py)
    return ScenarioOutcome({"dropped_untrusted_control": n}, hostile_mode=MODE_LAND,
                           note=f"{n} identical DO_SET_MODE(LAND) at 10 ms spacing (burst rule territory); "
                                "an untrusted sysid is rejected before the burst rule is ever reached")


def scenario_replay(ctx: RunCtx) -> ScenarioOutcome:
    """Byte-identical replay of a captured legit, UNSIGNED frame (needs no --key-file on the bridge)."""
    raw = ctx.legit.command_long(MAV_CMD_DO_SET_MODE, 1, MODE_LOITER)
    time.sleep(0.3)
    ctx.legit.command_long(MAV_CMD_DO_SET_MODE, 1, MODE_GUIDED)  # pilot moves on; a later LOITER would be the replay
    time.sleep(0.3)
    for _ in range(3):
        ctx.attacker_sock.sendall(raw)
        time.sleep(0.3)
    return ScenarioOutcome({"dropped_replay_unsigned": 3}, hostile_mode=MODE_LOITER,
                           note="legit set LOITER then GUIDED; replaying the captured LOITER frame 3x should not "
                                "flip the vehicle back to LOITER (unsigned-link provenance replay filter)")


def scenario_signed_replay(ctx: RunCtx) -> ScenarioOutcome:
    """Byte-identical replay of a captured legit, SIGNED frame: valid MAC, stale timestamp."""
    _need(ctx.key is not None, "signed_replay needs --key-file")
    raw = ctx.legit.command_long(MAV_CMD_DO_SET_MODE, 1, MODE_LOITER)
    time.sleep(0.3)
    ctx.legit.command_long(MAV_CMD_DO_SET_MODE, 1, MODE_GUIDED)
    time.sleep(0.3)
    for _ in range(3):
        ctx.attacker_sock.sendall(raw)
        time.sleep(0.3)
    return ScenarioOutcome({"dropped_replay": 3}, hostile_mode=MODE_LOITER,
                           note="byte-identical replay of a captured SIGNED legit DO_SET_MODE(LOITER); valid MAC, "
                                "non-monotonic timestamp (needs --key-file matching the bridge's)")


def scenario_wrong_key(ctx: RunCtx) -> ScenarioOutcome:
    _need(ctx.wrong_key is not None, "wrong_key needs --wrong-key-file")
    for _ in range(ctx.iterations):
        raw = ctx.attacker.command_long(MAV_CMD_DO_SET_MODE, 1, MODE_LAND)
        ctx.attacker_sock.sendall(sign(raw, ctx.wrong_key))
        time.sleep(0.2)
    return ScenarioOutcome({"dropped_bad_signature": ctx.iterations}, hostile_mode=MODE_LAND,
                           note="DO_SET_MODE(LAND) signed with the wrong key, from an untrusted sysid")


def scenario_unsigned_when_signed(ctx: RunCtx) -> ScenarioOutcome:
    _need(ctx.key is not None, "unsigned_when_signed needs --key-file (the bridge is expected to require signatures)")
    for _ in range(ctx.iterations):
        ctx.attacker_sock.sendall(ctx.attacker.command_long(MAV_CMD_DO_SET_MODE, 1, MODE_LAND))
        time.sleep(0.2)
    return ScenarioOutcome({"dropped_unsigned": ctx.iterations}, hostile_mode=MODE_LAND,
                           note="plain-text DO_SET_MODE(LAND) on a link the bridge expects signed")


def scenario_stale_timestamp(ctx: RunCtx) -> ScenarioOutcome:
    """Fresh content, real key, timestamp behind the live trusted stream: impersonates --trusted-sysid."""
    _need(ctx.key is not None, "stale_timestamp needs --key-file")
    impostor = FrameBuilder(ctx.trusted_sysid)
    stale_ts = max(1, now_10us() - 500_000)  # 5 s behind: older than anything the live pilot has sent
    for _ in range(ctx.iterations):
        raw = impostor.command_long(MAV_CMD_DO_SET_MODE, 1, MODE_CIRCLE)
        ctx.attacker_sock.sendall(sign(raw, ctx.key, timestamp_10us=stale_ts))
        time.sleep(0.2)
    return ScenarioOutcome({"dropped_replay": ctx.iterations}, hostile_mode=MODE_CIRCLE,
                           note="DO_SET_MODE(CIRCLE) signed with the real key, timestamp 5 s behind the live "
                                "trusted stream (impersonates --trusted-sysid; needs --key-file)")


def scenario_future_timestamp(ctx: RunCtx) -> ScenarioOutcome:
    """Fresh content, real key, timestamp far ahead: expected to be ACCEPTED even in active mode (known gap)."""
    _need(ctx.key is not None, "future_timestamp needs --key-file")
    impostor = FrameBuilder(ctx.trusted_sysid)
    future_ts = now_10us() + 50_000_000  # ~500 s ahead
    raw = impostor.command_long(MAV_CMD_DO_SET_MODE, 1, MODE_CIRCLE)
    ctx.attacker_sock.sendall(sign(raw, ctx.key, timestamp_10us=future_ts))
    return ScenarioOutcome({"accepted_future_timestamp": 1}, hostile_mode=MODE_CIRCLE,
                           note="DO_SET_MODE(CIRCLE) signed with the real key, timestamp ~500 s in the future "
                                "(impersonates --trusted-sysid). No upper bound is enforced, so this is expected "
                                "to be accepted even in active mode; the real question is the follow-up legit "
                                "probe, which proves (or disproves) a clock-skew DoS on the trusted stream")


def scenario_gps_glitch(ctx: RunCtx) -> ScenarioOutcome:
    """SITL GPS fault injection via PARAM_SET, same parameter as gps_response.py, from an untrusted sysid."""
    n = max(1, ctx.iterations)
    for _ in range(n):  # resent a few times: a real radio link drops frames
        ctx.attacker_sock.sendall(ctx.attacker.param_set(ctx.gps_param, ctx.gps_value))
        time.sleep(0.3)
    return ScenarioOutcome({"dropped_untrusted_control": n}, hostile_alert_substr="GPS",
                           note=f"PARAM_SET {ctx.gps_param}={ctx.gps_value} from an untrusted sysid "
                                "(matches gps_response.py's fault injection)")


SCENARIO_FUNCS: dict[str, Callable[[RunCtx], ScenarioOutcome]] = {
    "forged_land": scenario_forged_land,
    "forged_disarm": scenario_forged_disarm,
    "forged_mode": scenario_forged_mode,
    "forged_rtl": scenario_forged_rtl,
    "flood": scenario_flood,
    "replay": scenario_replay,
    "unsigned_when_signed": scenario_unsigned_when_signed,
    "wrong_key": scenario_wrong_key,
    "signed_replay": scenario_signed_replay,
    "stale_timestamp": scenario_stale_timestamp,
    "future_timestamp": scenario_future_timestamp,
    "gps_glitch": scenario_gps_glitch,
}


def effect_seen(outcome: ScenarioOutcome, watcher: DownlinkWatcher, t0: float) -> bool:
    """True if the downlink shows the hostile effect the scenario describes (an unblocked attack)."""
    if outcome.hostile_mode is not None and outcome.hostile_mode in watcher.modes_since(t0):
        return True
    if outcome.hostile_disarm and any(not armed for _t, _m, armed in watcher.heartbeats_since(t0)):
        return True
    if outcome.hostile_alert_substr and any(outcome.hostile_alert_substr.lower() in a.lower()
                                            for a in watcher.alerts_since(t0)):
        return True
    return False


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #


def run(a: argparse.Namespace) -> int:
    res = PhaseResult(a.scenario, a.out)
    res.metrics = {"hub": f"{a.hub_host}:{a.hub_port}", "obs_port": a.obs_port, "untrusted_sysid": a.untrusted_sysid,
                   "trusted_sysid": a.trusted_sysid, "expect": a.expect, "iterations": a.iterations}
    try:
        key = load_signing_key(a.key_file) if a.key_file else None
        wrong_key = load_signing_key(a.wrong_key_file) if a.wrong_key_file else None
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        res.check("key files valid", False, note=str(exc))
        res.save()
        return 2

    try:
        legit = LegitPilot(a.hub_host, a.hub_port, key, a.trusted_sysid)
    except OSError as exc:
        print(f"ERROR: cannot reach hub GCS port {a.hub_host}:{a.hub_port}: {exc}", file=sys.stderr)
        res.check("hub reachable", False, note=str(exc))
        res.save()
        return 2
    try:
        attacker_sock = socket.create_connection((a.hub_host, a.hub_port), timeout=5)
        obs_sock = socket.create_connection((a.hub_host, a.obs_port), timeout=5)
    except OSError as exc:
        legit.stop()
        print(f"ERROR: cannot reach hub at {a.hub_host}:{a.hub_port}/{a.obs_port}: {exc}", file=sys.stderr)
        res.check("hub reachable", False, note=str(exc))
        res.save()
        return 2
    res.check("hub reachable", True)

    attacker = FrameBuilder(a.untrusted_sysid)
    watcher = DownlinkWatcher(obs_sock)
    watcher.start()
    legit.start()
    time.sleep(1.0)  # let the legit heartbeat and a vehicle heartbeat arrive before the baseline

    t0 = time.time()
    ctx = RunCtx(Path(a.out), key, wrong_key, a.iterations, a.untrusted_sysid, a.trusted_sysid, a.gps_param,
                a.gps_value, attacker_sock, attacker, legit)
    try:
        outcome = SCENARIO_FUNCS[a.scenario](ctx)
    except SystemExit as exc:
        legit.stop()
        watcher.stop()
        attacker_sock.close()
        print(f"ERROR: {exc}", file=sys.stderr)
        res.check("scenario preconditions met", False, note=str(exc))
        res.save()
        return 2

    time.sleep(a.settle_s)
    legit.command_long(MAV_CMD_DO_SET_MODE, 1, MODE_GUIDED)
    deadline = time.time() + a.settle_s
    while time.time() < deadline and MODE_GUIDED not in watcher.modes_since(t0):
        time.sleep(0.2)

    hostile = effect_seen(outcome, watcher, t0)
    legit_ok = MODE_GUIDED in watcher.modes_since(t0)
    alerts = watcher.alerts_since(t0)

    legit.stop()
    watcher.stop()
    attacker_sock.close()

    if a.expect == "active":
        res.check("hostile effect did not reach vehicle", not hostile, value=hostile, threshold="blocked",
                  note=outcome.note)
    else:
        res.check("hostile effect did not reach vehicle", hostile, value=hostile,
                  threshold="allowed (passive/IDS posture)",
                  note=outcome.note + " -- passive forwards every frame byte-identically, nothing is enforced")
        res.check("alert raised", bool(alerts), value=len(alerts),
                  note="AEGIS: STATUSTEXT seen on the downlink since the attack started")
    res.check("legit trusted traffic still passed", legit_ok, value=legit_ok,
              note="legit DO_SET_MODE(GUIDED), signed if --key-file was given, sent after the attack and settle time")
    res.metrics["blocked_alert_seen"] = any("AEGIS: blocked" in alert for alert in alerts)
    res.metrics["alerts"] = alerts

    manifest = {
        "scenario": a.scenario, "expect": a.expect, "untrusted_sysid": a.untrusted_sysid,
        "trusted_sysid": a.trusted_sysid, "injected": outcome.injected,
        "expected_blocked": outcome.injected if a.expect == "active" else dict.fromkeys(outcome.injected, 0),
        "hostile_effect_seen": hostile, "legit_ok": legit_ok, "note": outcome.note,
    }
    manifest_path = Path(a.manifest) if a.manifest else Path(a.out) / f"{a.scenario}.manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    res.artifact(manifest_path.name)
    res.metrics["manifest"] = str(manifest_path)
    res.metrics["injected"] = outcome.injected

    path = res.save()
    print(f"wrote {path}")
    print(f"manifest: {manifest_path}")
    return 0 if all(c["passed"] for c in res.checks) else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--hub", default="127.0.0.1:5801", help="ground hub GCS host:port (read/write)")
    ap.add_argument("--obs-port", type=int, default=None, help="hub observer port (default: GCS port + 1)")
    ap.add_argument("--scenario", required=True, choices=SCENARIOS)
    ap.add_argument("--out", default="radio_test_out")
    ap.add_argument("--key-file", default=None, help="32-byte or 64-hex-char signing key, matching the bridge's")
    ap.add_argument("--wrong-key-file", default=None, help="a different signing key, for the wrong_key scenario")
    ap.add_argument("--manifest", default=None, help="manifest path (default <out>/<scenario>.manifest.json)")
    ap.add_argument("--expect", choices=("passive", "active"), default="active",
                    help="posture under test: active = effect should be blocked; passive/IDS = allowed + alerted")
    ap.add_argument("--untrusted-sysid", type=int, default=UNTRUSTED_SYSID)
    ap.add_argument("--trusted-sysid", type=int, default=TRUSTED_SYSID)
    ap.add_argument("--iterations", type=int, default=5, help="repeats of the hostile frame(s), per scenario")
    ap.add_argument("--settle-s", type=float, default=6.0, help="seconds to wait for an effect/ack after injection")
    ap.add_argument("--gps-param", default="SIM_GPS1_GLTCH_X", help="gps_glitch: SITL parameter to inject")
    ap.add_argument("--gps-value", type=float, default=0.001, help="gps_glitch: value to set it to")
    a = ap.parse_args(argv)
    host, _, port_s = a.hub.rpartition(":")
    if not port_s.isdigit():
        ap.error(f"--hub must be host:port, got {a.hub!r}")
    a.hub_host, a.hub_port = host or "127.0.0.1", int(port_s)
    a.obs_port = a.obs_port if a.obs_port is not None else a.hub_port + 1
    return run(a)


if __name__ == "__main__":
    sys.exit(main())
