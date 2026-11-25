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
import logging
import os
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
from ..mitigation.inline_policy import _COMMAND_MSGIDS, CONTROL_MSGIDS, InlinePolicy
from ..mitigation.types import DefenseMode
from ..model_integrity import MISSING as _MODEL_MISSING
from ..model_integrity import OK as _MODEL_OK
from ..model_integrity import check_model as _check_model
from ..pipeline import IDSPipeline
from ..proxy.hooks import FrameContext
from ..proxy.transport import split_frames
from ..sources.mavlink_live import GcsSideDatagram, LiveMavlinkSource
from ..sources.mavlink_serial import may_reach_vehicle
from .mgmt_channel import MAX_CMD_AGE_S, FrameSender, MgmtChannel, drop_label, is_mgmt_command

UPLINK_FAIL_CLOSED_MSGIDS = CONTROL_MSGIDS | _COMMAND_MSGIDS
log = logging.getLogger(__name__)


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
        archive: Any | None = None,
        gcs_alerts: bool = True,
        alert_min_interval_s: float = 2.0,
        mgmt_status_interval_s: float = 2.0,
        mgmt_max_bytes_per_s: float = 150.0,
        mgmt_key: bytes | None = None,
        mgmt_state_path: str | None = None,
        lock_posture_file: str | None = None,
        audit_log_path: str | None = None,
        unsigned_acknowledged: bool = False,
        vehicle_filter: bool = False,
        filter_override_file: str | None = None,
        filter_lockout_failopen_s: float | None = None,
        mgmt_clock: Callable[[], float] = time.monotonic,
        mgmt_max_cmd_age_s: float | None = MAX_CMD_AGE_S,
        mgmt_enable: bool = False,
        firmware_allowlist: Any | None = None,
        anchor_writer: Any | None = None,
        fail_closed_uplink_commands: bool = True,
        semantic_firewall_enabled: bool = True,
        actuator_ts_state_path: str | None = None,
        model_path: str | None = None,
        allow_unverified_model: bool = False,
    ) -> None:
        self.fc, self.gcs = fc, gcs
        self._mgmt_in_passive = bool(mgmt_enable)
        self._refuse_active_on_device(mode)
        # receive-only-compatible filtering of the uplink (docs/VEHICLE_UPLINK_FILTER.md): fixed at construction, never a
        # posture, and nothing at run time (status API, management channel) can switch it on or off
        if vehicle_filter and secret_key is None:
            raise ValueError("vehicle_filter needs a signing key: without one the uplink filter cannot tell the pilot from a forger")
        if vehicle_filter and DefenseMode(mode) == DefenseMode.ACTIVE_IPS:
            raise ValueError("vehicle_filter is the alternative to active-ips on a vehicle link; use passive or advisory with it")
        self._vehicle_filter = bool(vehicle_filter)
        if (filter_override_file is not None or filter_lockout_failopen_s is not None) and not vehicle_filter:
            raise ValueError("filter_override_file / filter_lockout_failopen_s only apply with vehicle_filter")
        if filter_lockout_failopen_s is not None and filter_lockout_failopen_s <= 0:
            raise ValueError("filter_lockout_failopen_s must be > 0")
        self._override_file = filter_override_file
        self._override_interval_s = 0.5
        self._override_next = 0.0
        self._secret_key = secret_key
        # Persistent verifier for downlink COMMAND_ACK replay protection (separate from policy's uplink verifier).
        # Fail-safe note: after an FC reboot, PX4 signing timestamps may restart lower; ACKs fail safe (no LAND
        # fallback) until the bridge or _ack_verifier is reset.
        from aegisflight.mavlink.signing import MavlinkSignatureVerifier

        self._ack_verifier: MavlinkSignatureVerifier | None = (
            MavlinkSignatureVerifier(secret_key) if secret_key is not None else None
        )
        self.cfg = cfg or load_config(config_dir)
        proto = self.cfg.detector.get("protocol", {})
        if proto.get("auto_rate_baseline") is None:  # unset = auto: on for a live link
            proto["auto_rate_baseline"] = True
        if model_path is not None:
            chk = _check_model(model_path)
            if chk.status == _MODEL_MISSING or (chk.status != _MODEL_OK and not allow_unverified_model):
                raise ValueError(f"ML model check failed ({chk.status}): {chk.message()}")
        recheck = max(1, int(firmware_recheck_s * float(self.cfg.detector.get("decision_rate_hz", 5.0))))
        self.pipeline = IDSPipeline(
            self.cfg,
            model_path=model_path,
            firmware_dir=firmware_dir,
            firmware_real=firmware_dir is not None,
            firmware_recheck_every=recheck,
            firmware_allowlist=firmware_allowlist,
            allow_unverified_model=allow_unverified_model,
        )
        if model_path is not None and self.pipeline.anomaly.bundle is None:
            raise ValueError(
                f"ML model failed to load: {self.pipeline.anomaly.load_error or 'unknown error'}"
            )
        self.firmware_allowlist = firmware_allowlist
        self.anchor_writer = anchor_writer
        self.fail_closed_uplink_commands = bool(fail_closed_uplink_commands)
        ts_state = actuator_ts_state_path or (f"{signing_state_path}.tx_ts" if signing_state_path else None)
        self.controller = MitigationController(mode=DefenseMode(mode), secret_key=secret_key, ts_state_path=ts_state)
        self.controller.set_capabilities(ekf_secondary=ekf_secondary)
        self.policy = InlinePolicy(
            self.controller.sanitizer,
            trusted_sysids=trusted_sysids if trusted_sysids is not None else tuple(proto.get("expected_gcs_sysids", (255, 254))),
            vehicle_sysids=vehicle_sysids if vehicle_sysids is not None else tuple(proto.get("expected_sysids", (1,))),
            signing_key=secret_key, allow_unsigned_from_trusted=allow_unsigned_from_trusted,
            max_age_s=signing_max_age_s, state_path=signing_state_path,
            contested_policy=contested_policy, replay_memory=replay_memory,
            semantic_firewall_enabled=semantic_firewall_enabled,
        )
        # the bridge's own signed commands (counter-commands to the FC) are stamped from the signed traffic it has seen, not from
        # its wall clock: a companion computer without RTC / internet has an arbitrary clock and the FC rejects stale timestamps
        self.controller.actuator.set_timestamp_source(self.policy.next_signing_timestamp)
        self.on_alarm = on_alarm
        self.archive = archive  # hal.run_archive.BridgeRunArchive: raw frames/decisions/actions (issue #25)
        self._alarm_enc = MavlinkActuator(sysid=1, compid=192, secret_key=secret_key)
        self.alarms_sent = 0
        self._apply_enforcement()
        self.policy.lockout_failopen_s = filter_lockout_failopen_s
        self.tap = TapTransport()
        self.rate_hz = sample_rate_hz
        self.store = store
        self._store_lock = threading.RLock()
        # audit rows that arrived while a rotation held the store lock; flushed (in order) once it is free
        self._action_backlog: deque[tuple[float, str, str, str, str]] = deque(maxlen=20_000)
        self.store_rows_lost = 0
        self.rotation_failures = 0
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
        mgmt_send = self.gcs.send
        if archive is not None:  # evidence run: the management stream to the GCS is archived like every other output
            def mgmt_send(frame: bytes) -> bool:
                t = self._clock_ns()
                ok = self.gcs.send(frame)
                archive.action(t, "mgmt", "gcs", frame, sent=bool(ok))  # the row records whether it left the bridge
                return ok
        self.mgmt = MgmtChannel(
            mgmt_send, self._sender, self, alerts_enabled=gcs_alerts, alert_min_interval_s=alert_min_interval_s,
            status_interval_s=mgmt_status_interval_s, max_bytes_per_s=mgmt_max_bytes_per_s, mgmt_key=mgmt_key,
            flight_signing=secret_key is not None, vehicle_sysid=vsys[0],
            state_path=mgmt_state_path, audit_path=audit_log_path, lock_posture_file=lock_posture_file,
            max_cmd_age_s=mgmt_max_cmd_age_s, clock=mgmt_clock)
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
        self.uplink_fail_closed_drops = 0
        self.send_failures = 0
        # signed link: unsigned frames claiming a vehicle sysid that arrived from the GCS side (report-only; see _handle)
        self.forged_vehicle_up = 0
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

    def threads_healthy(self) -> bool:
        """Return True iff every launched worker thread is still alive."""
        return bool(self._threads) and all(th.is_alive() for th in self._threads)

    def close(self) -> None:
        self._stop.set()
        if self._source is not None:
            self._source.stop()
        for th in self._threads:
            if th is not threading.current_thread():
                th.join(timeout=2.0)
        self.policy.flush()
        self.controller.actuator.flush_state()
        if self.anchor_writer is not None and self.store is not None:
            with self._store_lock, contextlib.suppress(Exception):
                self.anchor_writer.write_now(self.run_id, force=True)
        if self.archive is not None:
            with contextlib.suppress(Exception):  # an archive error must never keep the links open
                self.archive.close()
        for tr in (self.fc, self.gcs):
            with contextlib.suppress(Exception):
                tr.close()

    def _write_action_locked(self, t: float, actor: str, action: str, target: str, detail: str) -> None:
        """Append one action row. Caller holds ``_store_lock``. A failure is counted and logged, never raised."""
        if self.store is None:
            return
        try:
            self.store.log_action(self.run_id, t, actor, action, target, detail)
            if self.anchor_writer is not None:
                self.anchor_writer.maybe_write(self.run_id)
        except Exception:  # noqa: BLE001 - the audit row is lost: count it, say so, keep forwarding
            self.store_rows_lost += 1
            if self.store_rows_lost == 1 or self.store_rows_lost % 1000 == 0:
                log.error("action-log write failed (%d rows lost so far)", self.store_rows_lost, exc_info=True)

    def _flush_action_backlog_locked(self) -> None:
        while self._action_backlog:
            self._write_action_locked(*self._action_backlog.popleft())

    def _log_action(self, t: float, actor: str, action: str, target: str, detail: str = "") -> None:
        """Thread-safe action row. Never blocks the forwarding path: if a rotation holds the store lock the row is
        queued and written, in order, as soon as the lock is free (a full queue is counted in ``store_rows_lost``)."""
        if self.store is None:
            return
        if not self._store_lock.acquire(blocking=False):
            if len(self._action_backlog) == self._action_backlog.maxlen:
                self.store_rows_lost += 1  # deque(maxlen) drops the oldest row on append
            self._action_backlog.append((t, actor, action, target, detail))
            return
        try:
            self._flush_action_backlog_locked()
            self._write_action_locked(t, actor, action, target, detail)
        finally:
            self._store_lock.release()

    def rotate_store(self, *, max_bytes: int, max_rotations: int = 5, run_id_prefix: str = "ips") -> bool:
        """Safely rotate the attached EventStore when its active file reaches ``max_bytes``.

        Never raises: a failed rotation is logged (``rotation_failures``), the store is kept or reopened so the
        IDS keeps logging on an unbroken chain, and ``False`` is returned.
        """
        if self.store is None or max_bytes <= 0:
            return False
        from ..logging.rotation import RotationLinkError, rotate_sqlite_store  # noqa: PLC0415

        with self._store_lock:
            if self.store is None:
                return False
            if self.anchor_writer is not None:
                with contextlib.suppress(Exception):
                    self.anchor_writer.write_now(self.run_id, force=True)
            new_run_id = time.strftime(f"{run_id_prefix}-%Y%m%d-%H%M%S")
            old = self.store
            try:
                fresh, rotated = rotate_sqlite_store(
                    old,
                    max_bytes=max_bytes,
                    max_rotations=max_rotations,
                    run_id=new_run_id,
                    label="ips-bridge",
                )
            except RotationLinkError as exc:
                # Renamed but the link row could not be written: the reopened store carries a ROTATION_FAILED row.
                self.rotation_failures += 1
                log.error("store rotated but ROTATION_LINK not written; ROTATION_FAILED recorded", exc_info=True)
                fresh, rotated = exc.store, exc.started
            except Exception:  # noqa: BLE001 - the IDS must outlive a rotation fault
                self.rotation_failures += 1
                log.error("store rotation failed; recovering a usable store", exc_info=True)
                fresh, rotated = self._recover_store(old), False
            if fresh is not old:
                self.store = fresh  # rotate_sqlite_store closed the old handle whenever it returns a new one
                if self.anchor_writer is not None:
                    self.anchor_writer.store = fresh  # anchors must follow the store, rotated or reopened
            if rotated:
                self.run_id = new_run_id
            self._flush_action_backlog_locked()
            return rotated

    @staticmethod
    def _recover_store(old: Any) -> Any:
        """After an unexpected rotation error: keep ``old`` if its connection still works, else reopen its file."""
        try:
            old.conn.execute("SELECT 1")
            return old
        except Exception:  # noqa: BLE001 - closed connection
            from ..logging.store import EventStore  # noqa: PLC0415

            return EventStore(old.db_path)

    def __enter__(self) -> InlineIpsBridge:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _refuse_active_on_device(self, mode: DefenseMode | str) -> None:
        """Receive-only boundary: ACTIVE_IPS (dropping and counter-commanding) is refused when the FC side is a
        serial device, which may be a physical flight controller. SITL runs over socket:// links."""
        if DefenseMode(mode) == DefenseMode.ACTIVE_IPS and may_reach_vehicle(getattr(self.fc, "port", None)):
            raise ValueError(f"active-ips is refused on FC port {self.fc.port!r}: a serial device may be a physical "
                             "flight controller (receive-only); use a socket:// SITL link")

    def _apply_enforcement(self) -> None:
        """ACTIVE_IPS = full enforcement. vehicle_filter = the uplink rules only (no downlink change, no counter-commands: those are
        gated on the controller being in ACTIVE_IPS). Neither = byte-identical forwarding."""
        active = self.controller.mode == DefenseMode.ACTIVE_IPS
        self.policy.set_uplink_filter_only(self._vehicle_filter and not active)
        self.policy.set_enforce(active or self._vehicle_filter)

    def set_mode(self, mode: DefenseMode | str, origin: str = "local") -> None:
        """Operator posture change. Leaving ACTIVE_IPS clears every enforcement state at once."""
        self._refuse_active_on_device(mode)
        before = self.controller.mode
        self.controller.set_mode(mode)
        self._apply_enforcement()
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

    def _mgmt_active(self) -> bool:
        """True when management/cross-end GCS TX & compid-191 RX are permitted.

        Pure PASSIVE posture transmits 0 bytes on both FC and GCS links unless
        explicitly opted in via ``mgmt_enable=True`` (``--mgmt-enable``).
        """
        return self.controller.mode != DefenseMode.PASSIVE or self._mgmt_in_passive

    def pump_once(self) -> int:
        """One non-blocking forwarding cycle (also driven directly by tests). Returns frames handled."""
        n = 0
        self._poll_override()
        for stamp, data in self.fc.poll():
            n += self._handle(stamp, data, "down")
        for stamp, data in self.gcs.poll():
            n += self._handle(stamp, data, "up")
        self._announce_filter()
        if self._mgmt_active():
            self._send_alarms()
            self.mgmt.service()
        return n

    def _poll_override(self) -> None:
        """Operator's LOCAL off switch for the vehicle uplink filter: while the file exists the filter only reports. Read from the
        bridge's own disk at most every 0.5 s; nothing on the radio or the status API can create or remove it."""
        if self._override_file is None:
            return
        now = time.monotonic()
        if now < self._override_next:
            return
        self._override_next = now + self._override_interval_s
        self.policy.filter_override = os.path.exists(self._override_file)

    def _announce_filter(self) -> None:
        """Every change of the filter's state is told to the pilot's GCS (when mgmt active) and to the console."""
        if not self._vehicle_filter:
            return
        for state, detail in self.policy.take_filter_events():
            if self._mgmt_active():
                with contextlib.suppress(Exception):
                    self.mgmt.action(f"FILTER_{state.upper()}", "")
            if self.on_alarm is not None:
                with contextlib.suppress(Exception):
                    self.on_alarm(f"vehicle uplink filter {state}: {detail}")

    def _send_alarms(self) -> None:
        """Contested-source alarm: STATUSTEXT (warning) to the GCS side only, signed when a key is configured."""
        for sysid in self.policy.take_alarms():
            text = f"AEGIS: two senders using sysid {sysid} on the uplink"
            alarm = self._alarm_enc.encode_statustext(text, severity=4)
            t = self._clock_ns()
            ok = self.gcs.send(alarm)
            if self.archive is not None:
                self.archive.action(t, "alarm", "gcs", alarm, text=text, sent=bool(ok))
            if ok:
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
                if self._mgmt_active():
                    self.mgmt.handle_command(fr.raw, req)  # consumed: never forwarded to the FC, never tapped
                else:
                    # Maintain the compid-191 boundary even in PASSIVE (never forward to FC)
                    # while preserving strict 0-byte TX when mgmt_enable=False.
                    self.mgmt.commands_consumed += 1
                if self.archive is not None:  # every received frame is archived, a consumed command too (#25)
                    self.archive.consumed(direction, stamp, fr.raw)
                n += 1
                continue
            t0 = perf_ns()
            if not down and fr.sysid in policy.vehicle_sysids:
                # the vehicle never transmits from the GCS / radio side: a frame claiming its sysid there (signed or not, a
                # replayed recording included, key or not) is tagged so the analyser never gives it the unsigned-vehicle
                # exemption and never lets it change the vehicle's signing state; otherwise it is verified and ingested
                # normally (the detectors keep their evidence). Always counted; announced (aggregated) on a keyed bridge
                tap_push(stamp, GcsSideDatagram(fr.raw))
                self.forged_vehicle_up += 1
                if self._secret_key is not None and self._mgmt_active():
                    with contextlib.suppress(Exception):
                        self.mgmt.note_forged_vehicle_up(fr.sysid)
            else:
                tap_push(stamp, fr.raw)  # the detectors always see the original
            ctx = FrameContext(direction, fr.raw, stamp, fr.sysid, fr.compid, fr.seq, fr.msgid, fr.signed)  # type: ignore[arg-type]
            fail_closed_exc: Exception | None = None
            try:
                out = hook(ctx)
            except Exception as exc:  # noqa: BLE001 - asymmetric fail-safe: fail-open down / fail-closed control up
                policy.hook_errors += 1
                if (not down and self.controller.mode == DefenseMode.ACTIVE_IPS
                        and self.fail_closed_uplink_commands and fr.msgid in UPLINK_FAIL_CLOSED_MSGIDS):
                    out = []
                    fail_closed_exc = exc
                else:
                    out = [fr.raw]
            if down:
                self.frames_down += 1
                if fr.msgid == 77 and out and fr.sysid in policy.vehicle_sysids:
                    with contextlib.suppress(Exception):
                        sig_ok = True
                        if self._ack_verifier is not None:
                            if fr.signed:
                                sig_ok = self._ack_verifier.verify_frame(fr.raw).valid
                            else:
                                # Unsigned FC downlink ACK is allowed when the FC is not a signing source
                                # (mirroring LiveMavlinkSource unsigned_allowed_sysids / policy._down_forged).
                                sig_ok = not policy.is_downlink_signed_source(fr.sysid, fr.compid, stamp)
                        if sig_ok:
                            hdr = 10 if fr.raw[:1] == b"\xfd" else 6
                            plen = fr.raw[1] if len(fr.raw) > 1 else 0
                            if plen >= 3 and len(fr.raw) >= hdr + 3:
                                cmd = int.from_bytes(fr.raw[hdr : hdr + 2], "little")
                                res = fr.raw[hdr + 2]
                                tgt_sys = fr.raw[hdr + 8] if (fr.raw[:1] == b"\xfd" and plen >= 9 and len(fr.raw) >= hdr + 9) else None
                                self.controller.record_command_ack(cmd, res, t=stamp / 1e9, target_sysid=tgt_sys)
            else:
                self.frames_up += 1
            if not out:
                if down:
                    self.dropped_down += 1
                else:
                    self.dropped_up += 1
                if fail_closed_exc is not None:
                    self.uplink_fail_closed_drops += 1
                    lbl = f"fail_closed:msgid={fr.msgid}:{type(fail_closed_exc).__name__}"
                    action_name = "fail_closed_drop"
                else:
                    lbl = drop_label(fr.raw, fr.sysid, fr.msgid, direction)
                    action_name = "drop_frame"
                if self._mgmt_active():
                    with contextlib.suppress(Exception):
                        self.mgmt.note_drop(lbl)
                self._log_action(stamp / 1e9, "inline_ips", action_name, direction, lbl)
            if policy._observed_pending:
                with contextlib.suppress(Exception):
                    for verdict, oraw, osys, omsg in policy.take_observed():
                        self.mgmt.note_observed(drop_label(oraw, osys, omsg, direction), verdict)
            failed = 0
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
                    failed += 1
            if self.archive is not None:  # after the send: the row says whether the verdict actually reached the wire
                self.archive.frame(direction, stamp, fr.raw, list(out), send_failed=failed)
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

    def _hold_at_boot(self, assessment: Any) -> bool:
        """Start-up noise only: a GPS_SPOOFING / DOS alert while disarmed in the first BOOT_QUIET_S, at any severity (a
        converging GPS on the bench raises CRITICAL GPS_SPOOFING at power-on). Every other class is always announced."""
        return assessment.attack_type.value in self._BOOT_NOISE and self._boot_quiet()

    def analyse_tick(self, tick: Any) -> None:
        """Process one tick: detect, run the controller, push its state into the policy, send counter-frames."""
        self._last_analyse_wall = time.monotonic()
        if self._mgmt_active():
            self.emit_crossend()
        assessment = self.pipeline.process_tick(tick)
        if assessment is None or self.pipeline.last_frame is None:
            return
        self.decisions += 1
        act = self.controller.step(self.pipeline.last_frame, assessment)
        self.last_summary = act.summary
        if self.archive is not None:
            now = self._clock_ns()
            self.archive.decision(now, assessment, self.controller.mode.value, self.controller.state.value, act.summary)
            self.archive.summary_changed(now, act.summary, self.controller.mode.value, self.controller.state.value)
        self.policy.touch()
        if self._mgmt_active():
            self._announce_actions()
        if assessment.is_alert:
            self.alerts += 1
            rogue = getattr(getattr(act, "params", None), "rogue_sysids", ())
            if self._hold_at_boot(assessment):
                self._boot_held = True
            elif self._mgmt_active():
                with contextlib.suppress(Exception):
                    self.mgmt.alert(assessment.attack_type.value, assessment.severity.value, rogue[0] if rogue else None)
            if self.store is not None:
                with self._store_lock:
                    self._flush_action_backlog_locked()
                    try:
                        if self.store is not None:
                            self.store.log_event(assessment, self.run_id)
                            if self.anchor_writer is not None:
                                self.anchor_writer.maybe_write(self.run_id)
                    except Exception:  # noqa: BLE001 - counted and logged; the analyser keeps running
                        self.store_rows_lost += 1
                        log.error("event-log write failed (%d rows lost so far)", self.store_rows_lost, exc_info=True)
        mode = self.controller.mode
        if mode == DefenseMode.ACTIVE_IPS:  # PASSIVE / ADVISORY never write counter-frames (ADVISORY alerts go via mgmt.alert())
            for frame in act.counter_frames:
                is_txt = _is_statustext(frame)
                # corrective commands go to the flight controller; a STATUSTEXT warning is for the pilot's GCS
                # (the FC does not relay a STATUSTEXT it receives), so it goes to the GCS side only
                link = self.gcs if is_txt else self.fc
                target_link = "gcs" if link is self.gcs else "fc"
                t = self._clock_ns()
                ok = link.send(frame)
                if self.archive is not None:
                    self.archive.action(t, "counter_frame", target_link, frame, sent=bool(ok))
                self._log_action(t / 1e9, "inline_ips", "counter_frame", target_link,
                                 f"bytes={len(frame)} sent={bool(ok)}")
                if ok:
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
        if not self._mgmt_active() or self.crossend_interval_s <= 0:
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
            ok = self.gcs.send(frame)
            if self.archive is not None:
                self.archive.action(now, "crossend", "gcs", frame, sent=bool(ok))
            if ok:
                self._sender.commit()
                self.crossend_sent += 1
                return True
        self.send_failures += 1
        return False

    def _analyse_loop(self) -> None:
        # the vehicle's own downlink may legitimately be unsigned (ArduPilot over USB, or FC-side signing off): without
        # this the PX4 id allowlist drops all its telemetry once a key is set and the detectors go blind. Forged
        # ground-station frames (any other sysid) stay dropped; signed frames are still verified. Frames that came from
        # the GCS side are tapped as GcsSideDatagram, which never gets the exemption (see _handle).
        self._source = LiveMavlinkSource(self.tap, sample_rate_hz=self.rate_hz, origin="start",
                                         secret_key=self._secret_key,
                                         unsigned_allowed_sysids=frozenset(self.policy.vehicle_sysids))
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
        try:
            lat_snap = list(self._lat_us)
        except RuntimeError:
            lat_snap = []
        lat = sorted(lat_snap)

        def pct(q: float) -> float | None:
            return round(lat[min(len(lat) - 1, int(q * len(lat)))], 1) if lat else None

        return {
            "mode": self.controller.mode.value, "state": self.controller.state.value, "vehicle_filter": self._vehicle_filter,
            "vehicle_filter_state": self.policy.filter_state,
            "frames": {"down": self.frames_down, "up": self.frames_up,
                       "forwarded_down": self.forwarded_down, "forwarded_up": self.forwarded_up,
                       "dropped_down": self.dropped_down, "dropped_up": self.dropped_up,
                       "uplink_fail_closed_drops": self.uplink_fail_closed_drops,
                       "send_failures": self.send_failures, "tap_overflow": self.tap.dropped_overflow,
                       "forged_vehicle_up": self.forged_vehicle_up},
            "latency_us": {"p50": pct(0.50), "p95": pct(0.95), "max": round(lat[-1], 1) if lat else None,
                           "samples": len(lat)},
            "policy": self.policy.stats(),
            "semantic_firewall": self.policy.semantic_stats(),
            "signing_observed": self.policy.observed_stats(),
            "analyser": {"decisions": self.decisions, "alerts": self.alerts, "errors": self.analyser_errors,
                         "counter_frames_sent": self.counter_frames_sent, "alarms_sent": self.alarms_sent, "crossend_sent": self.crossend_sent, "summary": self.last_summary,
                         "ekf_secondary": self.controller.ekf_secondary_available},
            "firmware_allowlist_sha256": getattr(self.firmware_allowlist, "sha256", None),
            "anchors": self.anchor_writer.snapshot() if self.anchor_writer is not None else None,
            "last_error": self.last_error,
            "mgmt_active": self._mgmt_active(),
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
