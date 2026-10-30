"""Inline IPS bridge (Topology B): a real bump-in-the-wire between a flight controller and its GCS link.

::

    FC  <--fc transport-->  [ InlineIpsBridge ]  <--gcs transport-->  GCS / radio
                              |  forwarder thread: frame -> InlinePolicy -> other side
                              |  tap (copy of every ORIGINAL frame, both directions)
                              v
                           analyser thread: LiveMavlinkSource -> IDSPipeline -> MitigationController
                              |  controller state -> InlinePolicy (quarantine / rewrite / QoS)
                              |  ACTIVE_IPS counter-frames -> FC transport

Design rules
------------
* The forwarding path never waits on the analyser: detection can be slow or stall without delaying a
  frame. The policy's dynamic rules lapse on their own when the analyser stops touching them
  (``InlinePolicy.dynamic_ttl_s``), so a stalled analyser means transparent forwarding.
* The detectors see the ORIGINAL frames (before any drop or rewrite), so an attack is still detected
  while it is being filtered.
* ``PASSIVE`` / ``ADVISORY`` forward every frame byte-identically; only ``ACTIVE_IPS`` enforces. Neither ever
  sends anything to the vehicle: the controller's counter-frames (including its own STATUSTEXT) are sent only in
  ``ACTIVE_IPS``. In EVERY posture the bridge does send, to the GCS side only, the cross-end summary and the in-band
  management traffic (alert / action STATUSTEXTs, a compact status MEMORY_VECT, COMMAND_ACKs; ``hal/mgmt_channel.py``),
  and it CONSUMES the signed management control frames (COMMAND_LONG MAV_CMD_USER_1 to component 191) coming from the
  GCS instead of forwarding them to the vehicle: the only uplink frames it ever withholds in PASSIVE / ADVISORY.
* Unframeable bytes are dropped by the transports (counted there); no valid frame is altered unless a rule fires.
* A hook exception forwards the original frame (fail-open, counted in ``policy.hook_errors``).

What this does NOT give you: a process or power failure of the companion cuts the link, because both ports
terminate here. A real installation needs a hardware bypass (relay or splitter) for that; the software
watchdog above only covers a stalled analyser. Latency is measured per frame (``status()['latency_us']``)
on the host it runs on; nothing here has been measured on a companion computer or a flight controller.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Any, Protocol

from pymavlink.dialects.v20 import common as mav2

from ..config import AegisConfig, load_config
from ..detectors.crossend import (
    GPI_MSGID,
    MARKER_ADDRESS,
    MARKER_TYPE,
    MARKER_VER,
    gpi_from_frame,
    pack_summary,
)
from ..mitigation.actuator import MavlinkActuator
from ..mitigation.controller import MitigationController
from ..mitigation.inline_policy import InlinePolicy
from ..mitigation.types import DefenseMode
from ..pipeline import IDSPipeline
from ..proxy.hooks import FrameContext
from ..proxy.transport import split_frames
from ..sources.mavlink_live import LiveMavlinkSource
from .mgmt_channel import FrameSender, MgmtChannel, drop_label, is_mgmt_command


class BridgeTransport(Protocol):
    """A frame transport that can also write (``SerialMavlinkTransport`` satisfies it)."""

    def poll(self) -> list[tuple[int, bytes]]: ...

    def send(self, data: bytes) -> bool: ...

    def close(self) -> None: ...


class TapTransport:
    """``FrameTransport`` fed by the bridge: the analyser reads the original frames from here."""

    def __init__(self, maxlen: int = 65536) -> None:
        self._q: deque[tuple[int, bytes]] = deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self.dropped_overflow = 0

    def push(self, stamp_ns: int, data: bytes) -> None:
        with self._lock:
            if len(self._q) == self._q.maxlen:
                self.dropped_overflow += 1
            self._q.append((stamp_ns, data))

    def poll(self) -> list[tuple[int, bytes]]:
        with self._lock:
            out = list(self._q)
            self._q.clear()
        return out

    def close(self) -> None:
        return None



def _is_statustext(frame: bytes) -> bool:
    """True for a MAVLink STATUSTEXT (msgid 253), v1 or v2 framing."""
    if len(frame) >= 10 and frame[0] == 0xFD:
        return int.from_bytes(frame[7:10], "little") == mav2.MAVLINK_MSG_ID_STATUSTEXT
    if len(frame) >= 6 and frame[0] == 0xFE:
        return frame[5] == mav2.MAVLINK_MSG_ID_STATUSTEXT
    return False


class InlineIpsBridge:
    def __init__(
        self,
        fc: BridgeTransport,
        gcs: BridgeTransport,
        *,
        cfg: AegisConfig | None = None,
        config_dir: str | None = None,
        mode: DefenseMode | str = DefenseMode.PASSIVE,
        trusted_sysids: tuple[int, ...] | None = None,
        vehicle_sysids: tuple[int, ...] | None = None,
        sample_rate_hz: float = 10.0,
        store: Any | None = None,
        run_id: str = "ips-bridge",
        secret_key: bytes | None = None,
        allow_unsigned_from_trusted: bool = False,
        signing_max_age_s: float | None = None,
        signing_state_path: str | None = None,
        idle_sleep_s: float = 0.0005,
        ekf_secondary: bool | None = None,
        clock_ns: Callable[[], int] = time.monotonic_ns,
        crossend_interval_s: float = 1.0,
        firmware_dir: str | None = None,
        firmware_recheck_s: float = 30.0,
        contested_policy: str = "alert",
        replay_memory: int = 4096,
        on_alarm: Callable[[str], None] | None = None,
        gcs_alerts: bool = True,
        alert_min_interval_s: float = 2.0,
        mgmt_status_interval_s: float = 2.0,
        mgmt_max_bytes_per_s: float = 150.0,
        mgmt_key: bytes | None = None,
        mgmt_state_path: str | None = None,
        lock_posture_file: str | None = None,
        audit_log_path: str | None = None,
        unsigned_acknowledged: bool = False,
        mgmt_clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.fc, self.gcs = fc, gcs
        self._secret_key = secret_key
        self.cfg = cfg or load_config(config_dir)
        proto = self.cfg.detector.get("protocol", {})
        if proto.get("auto_rate_baseline") is None:  # unset = auto: on for a live link
            proto["auto_rate_baseline"] = True
        # ML is simulation-only. A real firmware directory (files + manifest from `aegis fw-manifest`) is re-hashed every
        # firmware_recheck_s; without one the integrity verdict stays UNKNOWN (nothing is checked)
        recheck = max(1, int(firmware_recheck_s * float(self.cfg.detector.get("decision_rate_hz", 5.0))))
        self.pipeline = IDSPipeline(self.cfg, model_path=None, firmware_dir=firmware_dir, firmware_real=firmware_dir is not None,
                                    firmware_recheck_every=recheck)
        self.controller = MitigationController(mode=DefenseMode(mode), secret_key=secret_key)
        self.controller.set_capabilities(ekf_secondary=ekf_secondary)
        self.policy = InlinePolicy(
            self.controller.sanitizer,
            trusted_sysids=trusted_sysids if trusted_sysids is not None else tuple(proto.get("expected_gcs_sysids", (255, 254))),
            vehicle_sysids=vehicle_sysids if vehicle_sysids is not None else tuple(proto.get("expected_sysids", (1,))),
            signing_key=secret_key, allow_unsigned_from_trusted=allow_unsigned_from_trusted,
            max_age_s=signing_max_age_s, state_path=signing_state_path,
            contested_policy=contested_policy, replay_memory=replay_memory,
        )
        # the bridge's own signed commands (counter-commands to the FC) are stamped from the signed traffic it has seen, not from
        # its wall clock: a companion computer without RTC / internet has an arbitrary clock and the FC rejects stale timestamps
        self.controller.actuator.set_timestamp_source(self.policy.next_signing_timestamp)
        self.on_alarm = on_alarm
        self._alarm_enc = MavlinkActuator(sysid=1, compid=192, secret_key=secret_key)
        self.alarms_sent = 0
        self.policy.set_enforce(self.controller.mode == DefenseMode.ACTIVE_IPS)
        self.tap = TapTransport()
        self.rate_hz = sample_rate_hz
        self.store = store
        self.run_id = run_id
        self._clock_ns = clock_ns
        self._idle = idle_sleep_s
        self._quiet_until_ns: int | None = None
        # cross-end summary (see detectors/crossend.py): the forward path only stores a reference to the last
        # forwarded GLOBAL_POSITION_INT; the analyser thread builds and sends the summary to the GCS side
        self.crossend_interval_s = float(crossend_interval_s)
        self._last_gpi: bytes | None = None
        self._last_gpi_sent: bytes | None = None
        self._crossend_next_ns = 0
        # ONE encoder / sequence counter / signer for the whole sysid 1 compid 191 stream (cross-end + management)
        self._sender = FrameSender(secret_key)
        self.crossend_sent = 0
        self.unsigned_acknowledged = bool(unsigned_acknowledged)
        self._last_analyse_wall: float | None = None
        self._seen_action: dict[str, Any] | None = None
        vsys = vehicle_sysids if vehicle_sysids is not None else tuple(proto.get("expected_sysids", (1,)))
        self.mgmt = MgmtChannel(
            self.gcs.send, self._sender, self, alerts_enabled=gcs_alerts, alert_min_interval_s=alert_min_interval_s,
            status_interval_s=mgmt_status_interval_s, max_bytes_per_s=mgmt_max_bytes_per_s, mgmt_key=mgmt_key,
            flight_signing=secret_key is not None, vehicle_sysid=vsys[0],
            state_path=mgmt_state_path, audit_path=audit_log_path, lock_posture_file=lock_posture_file,
            clock=mgmt_clock)
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._source: LiveMavlinkSource | None = None
        self._lat_us: deque[float] = deque(maxlen=20000)
        # counters
        self.frames_down = 0
        self.frames_up = 0
        self.forwarded_down = 0
        self.forwarded_up = 0
        self.dropped_down = 0
        self.dropped_up = 0
        self.send_failures = 0
        self.counter_frames_sent = 0
        self.decisions = 0
        self.alerts = 0
        self.analyser_errors = 0
        self.last_error: str | None = None
        self.last_summary: str = ""

    # -- lifecycle ----------------------------------------------------------- #

    def start(self) -> InlineIpsBridge:
        for name, target in (("ips-forward", self._forward_loop), ("ips-analyse", self._analyse_loop)):
            th = threading.Thread(target=target, name=name, daemon=True)
            th.start()
            self._threads.append(th)
        return self

    def close(self) -> None:
        self._stop.set()
        if self._source is not None:
            self._source.stop()
        for th in self._threads:
            if th is not threading.current_thread():
                th.join(timeout=2.0)
        self.policy.flush()
        for tr in (self.fc, self.gcs):
            with contextlib.suppress(Exception):
                tr.close()

    def __enter__(self) -> InlineIpsBridge:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()

    def set_mode(self, mode: DefenseMode | str, origin: str = "local") -> None:
        """Operator posture change. Leaving ACTIVE_IPS clears every enforcement state at once."""
        before = self.controller.mode
        self.controller.set_mode(mode)
        self.policy.set_enforce(self.controller.mode == DefenseMode.ACTIVE_IPS)
        if self.controller.mode != DefenseMode.ACTIVE_IPS:
            self.unsigned_acknowledged = False
        if self.controller.mode != before:
            self.mgmt.posture_changed(self.controller.mode.value, origin)

    # -- management channel host interface (hal/mgmt_channel.py) -------------- #

    def mgmt_snapshot(self) -> dict[str, Any]:
        def link_up(tr: Any, seen: int) -> bool:
            c = getattr(tr, "connected", None)
            return c if isinstance(c, bool) else seen > 0

        st = self.policy.stats()
        stalled = self._last_analyse_wall is not None and time.monotonic() - self._last_analyse_wall > 5.0
        return {
            "posture": self.controller.mode.value, "topology": "A+B", "state": self.controller.state.value,
            "flags": {"signing": self._secret_key is not None,
                      "analyser_ok": self.analyser_errors == 0 and not stalled,
                      "fc_link": link_up(self.fc, self.frames_down), "gcs_link": link_up(self.gcs, self.frames_up),
                      "contested": bool(st.get("contested_sources")), "unsigned_ack": self.unsigned_acknowledged},
            "forwarded": self.forwarded_down + self.forwarded_up, "dropped_up": self.dropped_up,
            "alerts": self.alerts, "counter_frames": self.counter_frames_sent, "hook_errors": self.policy.hook_errors}

    def mgmt_set_posture(self, mode: str, allow_unsigned: bool) -> None:
        self.set_mode(mode, origin="remote")
        if DefenseMode(mode) == DefenseMode.ACTIVE_IPS and self._secret_key is None and allow_unsigned:
            self.unsigned_acknowledged = True

    def mgmt_ack_alarms(self) -> None:
        pol = self.policy
        with pol._lock:
            pol._contested_until.clear()
            pol._alarms.clear()

    # -- forwarding ---------------------------------------------------------- #

    def pump_once(self) -> int:
        """One non-blocking forwarding cycle (also driven directly by tests). Returns frames handled."""
        n = 0
        for stamp, data in self.fc.poll():
            n += self._handle(stamp, data, "down")
        for stamp, data in self.gcs.poll():
            n += self._handle(stamp, data, "up")
        self._send_alarms()
        self.mgmt.service()
        return n

    def _send_alarms(self) -> None:
        """Contested-source alarm: STATUSTEXT (warning) to the GCS side only, signed when a key is configured."""
        for sysid in self.policy.take_alarms():
            text = f"AEGIS: two senders using sysid {sysid} on the uplink"
            if self.gcs.send(self._alarm_enc.encode_statustext(text, severity=4)):
                self.alarms_sent += 1
            else:
                self.send_failures += 1
            if self.on_alarm is not None:
                self.on_alarm(text)

    def _handle(self, stamp: int, data: bytes, direction: str) -> int:
        frames, _bad = split_frames(data)
        if not frames:
            return 0
        n = 0
        down = direction == "down"
        policy = self.policy
        hook = policy.down if down else policy.up
        send = (self.gcs if down else self.fc).send
        tap_push = self.tap.push
        lat_append = self._lat_us.append
        perf_ns = time.perf_counter_ns
        for fr in frames:
            if not down and fr.msgid == 76 and (req := is_mgmt_command(fr.raw)) is not None:
                self.mgmt.handle_command(fr.raw, req)  # consumed: never forwarded to the FC, never tapped
                n += 1
                continue
            t0 = perf_ns()
            tap_push(stamp, fr.raw)  # the detectors always see the original
            ctx = FrameContext(direction, fr.raw, stamp, fr.sysid, fr.compid, fr.seq, fr.msgid, fr.signed)  # type: ignore[arg-type]
            try:
                out = hook(ctx)
            except Exception:  # noqa: BLE001 - never stop forwarding
                policy.hook_errors += 1
                out = [fr.raw]
            if down:
                self.frames_down += 1
            else:
                self.frames_up += 1
            if not out:
                if down:
                    self.dropped_down += 1
                else:
                    self.dropped_up += 1
                with contextlib.suppress(Exception):
                    self.mgmt.note_drop(drop_label(fr.raw, fr.sysid, fr.msgid, direction))
            if policy._observed_pending:
                with contextlib.suppress(Exception):
                    for verdict, oraw, osys, omsg in policy.take_observed():
                        self.mgmt.note_observed(drop_label(oraw, osys, omsg, direction), verdict)
            for raw in out:
                if send(raw):
                    if down:
                        self.forwarded_down += 1
                        if fr.msgid == GPI_MSGID:
                            self._last_gpi = raw
                    else:
                        self.forwarded_up += 1
                else:
                    self.send_failures += 1
            lat_append((perf_ns() - t0) / 1000.0)
            n += 1
        return n

    def _forward_loop(self) -> None:
        while not self._stop.is_set():
            try:
                busy = self.pump_once()
            except Exception as exc:  # noqa: BLE001 - the loop outlives any single bad cycle
                self.last_error = repr(exc)
                busy = 0
            if not busy:
                self._stop.wait(self._idle)

    # -- analysis ------------------------------------------------------------ #

    # Ground start-up: GPS fix acquisition (the position jumps from nothing to the home point) and the first stream requests
    # look like spoofing / flooding for a few seconds. They are still detected, logged and acted on; they are just not
    # announced to the pilot's GCS before the vehicle is armed, so a power-on never opens with a false CRITICAL warning.
    BOOT_QUIET_S = 20.0
    _BOOT_NOISE = frozenset({"GPS_SPOOFING", "DOS"})
    _BOOT_NOISE_ACTIONS = frozenset({"RATE_LIMIT", "SANITIZE_GPS", "ANTI_JAM_DR", "GPS_RECOVERED"})
    _BOOT_FOLLOW_ACTIONS = frozenset({"DETECTED", "RECOVERED"})  # only the tail of a held start-up alert

    def _boot_quiet(self) -> bool:
        now = self._clock_ns()
        if self._quiet_until_ns is None:
            self._quiet_until_ns = now + int(self.BOOT_QUIET_S * 1e9)
        return now < self._quiet_until_ns and not self.policy.armed

    _boot_held = False

    def analyse_tick(self, tick: Any) -> None:
        """Process one tick: detect, run the controller, push its state into the policy, send counter-frames."""
        self._last_analyse_wall = time.monotonic()
        self.emit_crossend()
        assessment = self.pipeline.process_tick(tick)
        if assessment is None or self.pipeline.last_frame is None:
            return
        self.decisions += 1
        act = self.controller.step(self.pipeline.last_frame, assessment)
        self.last_summary = act.summary
        self.policy.touch()
        self._announce_actions()
        if assessment.is_alert:
            self.alerts += 1
            rogue = getattr(getattr(act, "params", None), "rogue_sysids", ())
            if assessment.attack_type.value in self._BOOT_NOISE and self._boot_quiet():
                self._boot_held = True
            else:
                with contextlib.suppress(Exception):
                    self.mgmt.alert(assessment.attack_type.value, assessment.severity.value, rogue[0] if rogue else None)
            if self.store is not None:
                with contextlib.suppress(Exception):
                    self.store.log_event(assessment, self.run_id)
        if self.controller.mode == DefenseMode.ACTIVE_IPS:
            for frame in act.counter_frames:
                # corrective commands go to the flight controller; a STATUSTEXT warning is for the pilot's GCS
                # (the FC does not relay a STATUSTEXT it receives), so it goes to the GCS side only
                link = self.gcs if _is_statustext(frame) else self.fc
                if link.send(frame):
                    self.counter_frames_sent += 1
                else:
                    self.send_failures += 1

    def _announce_actions(self) -> None:
        """One short STATUSTEXT per NEW controller action (the history is capped: new entries are found by identity)."""
        hist = getattr(self.controller, "action_history", None) or []
        start = 0
        if self._seen_action is not None:
            for i in range(len(hist) - 1, -1, -1):
                if hist[i] is self._seen_action:
                    start = i + 1
                    break
        quiet = self._boot_quiet()
        for entry in hist[start:]:
            tag = str(entry.get("tag", "")).upper()
            if quiet and (tag in self._BOOT_NOISE_ACTIONS or (self._boot_held and tag in self._BOOT_FOLLOW_ACTIONS)):
                continue
            with contextlib.suppress(Exception):
                self.mgmt.action(str(entry.get("tag", "")), str(entry.get("detail", "")))
        if hist:
            self._seen_action = hist[-1]

    def emit_crossend(self) -> bool:
        """Send ONE summary of the latest forwarded GLOBAL_POSITION_INT to the GCS transport (never the FC, never the
        tap), at most once per interval and only when a new frame was forwarded. Analyser thread only."""
        if self.crossend_interval_s <= 0:
            return False
        now = self._clock_ns()
        raw = self._last_gpi
        if now < self._crossend_next_ns or raw is None or raw is self._last_gpi_sent:
            return False
        self._crossend_next_ns = now + int(self.crossend_interval_s * 1e9)
        vals = gpi_from_frame(raw)
        if vals is None:
            return False
        self._last_gpi_sent = raw
        with self._sender.lock:
            frame = self._sender.build(lambda e: e.memory_vect_encode(
                MARKER_ADDRESS, MARKER_VER, MARKER_TYPE, pack_summary(vals, self._secret_key)))
            if self.gcs.send(frame):
                self._sender.commit()
                self.crossend_sent += 1
                return True
        self.send_failures += 1
        return False

    def _analyse_loop(self) -> None:
        self._source = LiveMavlinkSource(self.tap, sample_rate_hz=self.rate_hz, origin="start",
                                         secret_key=self._secret_key)
        try:
            for tick in self._source.stream():
                if self._stop.is_set():
                    return
                try:
                    self.analyse_tick(tick)
                except Exception as exc:  # noqa: BLE001 - a detector bug must not stop the link
                    self.analyser_errors += 1
                    self.last_error = repr(exc)
        except Exception as exc:  # noqa: BLE001
            self.last_error = repr(exc)

    # -- observability ------------------------------------------------------- #

    def status(self) -> dict[str, Any]:
        lat = sorted(self._lat_us)

        def pct(q: float) -> float | None:
            return round(lat[min(len(lat) - 1, int(q * len(lat)))], 1) if lat else None

        return {
            "mode": self.controller.mode.value, "state": self.controller.state.value,
            "frames": {"down": self.frames_down, "up": self.frames_up,
                       "forwarded_down": self.forwarded_down, "forwarded_up": self.forwarded_up,
                       "dropped_down": self.dropped_down, "dropped_up": self.dropped_up,
                       "send_failures": self.send_failures, "tap_overflow": self.tap.dropped_overflow},
            "latency_us": {"p50": pct(0.50), "p95": pct(0.95), "max": round(lat[-1], 1) if lat else None,
                           "samples": len(lat)},
            "policy": self.policy.stats(),
            "signing_observed": self.policy.observed_stats(),
            "analyser": {"decisions": self.decisions, "alerts": self.alerts, "errors": self.analyser_errors,
                         "counter_frames_sent": self.counter_frames_sent, "alarms_sent": self.alarms_sent, "crossend_sent": self.crossend_sent, "summary": self.last_summary,
                         "ekf_secondary": self.controller.ekf_secondary_available},
            "last_error": self.last_error,
            "mgmt": self.mgmt.stats(),
            "topology": self.topology_info(),
        }

    def topology_info(self) -> dict[str, Any]:
        from .topology_status import bridge_topology

        def name(tr: Any) -> str | None:
            n = getattr(tr, "name", None)
            return n if isinstance(n, str) else None

        return bridge_topology(self.controller.mode, fc_connected=getattr(self.fc, "connected", None),
                               gcs_connected=getattr(self.gcs, "connected", None), gcs_frames_seen=self.frames_up,
                               fc_name=name(self.fc), gcs_name=name(self.gcs))
