"""Single-port receive-only TELEM2 side-tap onboard runner (W5).

Used when ``topology: side-tap`` is selected on ``aegis onboard``: the telemetry
radio stays plugged directly into the flight controller (e.g. TELEM1), while the
onboard companion listens **passively** on a secondary UART (e.g. TELEM2) with
zero bytes ever transmitted to the FC link.
"""

from __future__ import annotations

import contextlib
import logging
import threading
import time
from typing import Any

from ..config import AegisConfig, load_config
from ..logging.anchors import AnchorWriter
from ..mitigation.controller import MitigationController
from ..mitigation.types import DefenseMode
from ..pipeline import IDSPipeline
from ..sources.mavlink_live import LiveMavlinkSource

log = logging.getLogger(__name__)


class SideTapRunner:
    """Receive-only passive observer compatible with ``BridgeStatusServer`` & ``run_onboard``."""

    def __init__(
        self,
        fc: Any,
        *,
        cfg: AegisConfig | None = None,
        config_dir: str | None = None,
        sample_rate_hz: float = 10.0,
        store: Any | None = None,
        run_id: str = "onboard-sidetap",
        secret_key: bytes | None = None,
        firmware_dir: str | None = None,
        firmware_recheck_s: float = 30.0,
        firmware_allowlist: Any | None = None,
        anchor_writer: AnchorWriter | None = None,
        ekf_secondary: bool | None = None,
        archive: Any | None = None,
        on_alarm: Any | None = None,
    ) -> None:
        self.fc = fc
        self.cfg = cfg or load_config(config_dir)
        proto = self.cfg.detector.get("protocol", {})
        if proto.get("auto_rate_baseline") is None:
            proto["auto_rate_baseline"] = True
        recheck = max(1, int(firmware_recheck_s * float(self.cfg.detector.get("decision_rate_hz", 5.0))))
        self.pipeline = IDSPipeline(
            self.cfg,
            model_path=None,
            firmware_dir=firmware_dir,
            firmware_real=firmware_dir is not None,
            firmware_recheck_every=recheck,
            firmware_allowlist=firmware_allowlist,
        )
        self.controller = MitigationController(mode=DefenseMode.PASSIVE, secret_key=None)
        self.controller.set_capabilities(ekf_secondary=ekf_secondary)
        self.firmware_allowlist = firmware_allowlist
        self.anchor_writer = anchor_writer
        self.store = store
        self._store_lock = threading.RLock()
        self.run_id = run_id
        self.rate_hz = sample_rate_hz
        self.archive = archive
        self.on_alarm = on_alarm
        self._secret_key = secret_key

        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._source: LiveMavlinkSource | None = None
        self.decisions = 0
        self.alerts = 0
        self.analyser_errors = 0
        self.rotation_failures = 0
        self.last_error: str | None = None
        self.last_summary: str = "Side-tap passive monitoring (0 B TX)"

    def start(self) -> SideTapRunner:
        th = threading.Thread(target=self._run_loop, name="sidetap-analyse", daemon=True)
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
        if self.anchor_writer is not None and self.store is not None:
            with self._store_lock, contextlib.suppress(Exception):
                self.anchor_writer.write_now(self.run_id, force=True)
        if self.archive is not None:
            with contextlib.suppress(Exception):
                self.archive.close()
        with contextlib.suppress(Exception):
            self.fc.close()

    def set_mode(self, mode: DefenseMode | str, origin: str = "local") -> None:
        if DefenseMode(mode) != DefenseMode.PASSIVE:
            raise ValueError("side-tap topology is strictly receive-only (PASSIVE mode only)")

    def threads_healthy(self) -> bool:
        """Return True iff the side-tap worker thread is still alive."""
        return bool(self._threads) and all(th.is_alive() for th in self._threads)

    def rotate_store(self, *, max_bytes: int, max_rotations: int = 5, run_id_prefix: str = "onboard") -> bool:
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
                    label="onboard-sidetap",
                )
            except RotationLinkError as exc:
                # Renamed but the link row could not be written: adopt the reopened store (has ROTATION_FAILED).
                self.rotation_failures += 1
                log.error("store rotated but ROTATION_LINK not written; ROTATION_FAILED recorded", exc_info=True)
                fresh, rotated = exc.store, exc.started
            except Exception:  # noqa: BLE001 - the observer must outlive a rotation fault
                self.rotation_failures += 1
                log.error("store rotation failed; recovering a usable store", exc_info=True)
                fresh, rotated = self._recover_store(old), False
            if fresh is not old:
                self.store = fresh  # rotate_sqlite_store closed the old handle whenever it returns a new one
                if self.anchor_writer is not None:
                    self.anchor_writer.store = fresh
            if rotated:
                self.run_id = new_run_id
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

    def _run_loop(self) -> None:
        self._source = LiveMavlinkSource(
            self.fc,
            sample_rate_hz=self.rate_hz,
            origin="start",
            secret_key=self._secret_key,
        )
        try:
            for tick in self._source.stream():
                if self._stop.is_set():
                    return
                try:
                    assessment = self.pipeline.process_tick(tick)
                    if assessment is None or self.pipeline.last_frame is None:
                        continue
                    self.decisions += 1
                    act = self.controller.step(self.pipeline.last_frame, assessment)
                    self.last_summary = act.summary
                    if assessment.is_alert:
                        self.alerts += 1
                        if self.on_alarm is not None:
                            with contextlib.suppress(Exception):
                                self.on_alarm(f"{assessment.attack_type.value} ({assessment.severity.value})")
                        if self.store is not None:
                            with self._store_lock, contextlib.suppress(Exception):
                                self.store.log_event(assessment, self.run_id)
                                if self.anchor_writer is not None:
                                    self.anchor_writer.maybe_write(self.run_id)
                except Exception as exc:  # noqa: BLE001
                    self.analyser_errors += 1
                    self.last_error = repr(exc)
        except Exception as exc:  # noqa: BLE001
            self.last_error = repr(exc)

    def status(self) -> dict[str, Any]:
        frames_rx = int(getattr(self.fc, "datagrams_received", 0))
        return {
            "mode": "passive",
            "topology_mode": "side-tap",
            "state": self.controller.state.value,
            "frames": {
                "down": frames_rx,
                "up": 0,
                "forwarded_down": 0,
                "forwarded_up": 0,
                "dropped_down": 0,
                "dropped_up": 0,
                "uplink_fail_closed_drops": 0,
                "send_failures": 0,
            },
            "analyser": {
                "decisions": self.decisions,
                "alerts": self.alerts,
                "errors": self.analyser_errors,
                "counter_frames_sent": 0,
                "summary": self.last_summary,
            },
            "firmware_allowlist_sha256": getattr(self.firmware_allowlist, "sha256", None),
            "anchors": self.anchor_writer.snapshot() if self.anchor_writer is not None else None,
            "last_error": self.last_error,
            "mgmt_active": False,
            "topology": {
                "mode": "side-tap",
                "fc_connected": getattr(self.fc, "connected", None),
                "gcs_connected": False,
                "receive_only": True,
            },
        }
