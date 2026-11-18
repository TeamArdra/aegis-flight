"""Raw-log archive for an inline-IPS bridge run (issue #25).

Writes into one run directory, so a bridge run can be audited and replayed after the fact:

* ``frames_down.jsonl`` -- FC -> GCS: every ORIGINAL frame the bridge received, with what it did with it;
* ``frames_up.jsonl``   -- GCS -> FC: the same for the other direction;
* ``decisions.jsonl``   -- one row per analyser decision (threat flag, type, score, evidence, controller state);
* ``actions.jsonl``     -- everything the bridge itself emitted (counter-frames to the FC, STATUSTEXT alarms and
  cross-end summaries to the GCS) plus each change of the controller's action summary.

A frame row is ``{"t_ns", "raw", "verdict"}`` with ``raw`` hex of the original bytes and ``verdict`` one of
``forwarded`` (byte-identical), ``dropped``, ``rewritten`` (then ``out`` lists the hex of what was sent) or
``consumed`` (a management command the bridge handled itself; never forwarded).

The forwarding path only appends to an in-memory queue; a writer thread does the file I/O, so archiving can never
delay a frame. If the queue overflows (``max_queue``) rows are dropped and counted in ``stats()['dropped_rows']``;
the manifest records the count, so an incomplete archive is visible rather than silent. A row the writer could not
write (a disk error) is counted in ``write_errors`` with the first error in ``writer_error``; the writer keeps going and
``close()`` never raises, so the bridge can still close its links and the manifest is still written.
"""

from __future__ import annotations

import json
import threading
from collections import deque
from pathlib import Path
from typing import Any

FILES = ("frames_down.jsonl", "frames_up.jsonl", "decisions.jsonl", "actions.jsonl")


class BridgeRunArchive:
    def __init__(self, run_dir: str | Path, *, max_queue: int = 500_000, flush_interval_s: float = 0.25) -> None:
        self.dir = Path(run_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        stale = [n for n in FILES if (self.dir / n).exists()]
        if stale:  # evidence is never appended to or overwritten silently
            raise FileExistsError(f"{self.dir} already holds a previous run ({', '.join(stale)}); use a fresh run dir")
        self._files = {n: open(self.dir / n, "w", encoding="utf-8") for n in FILES}  # noqa: SIM115 - closed in close()
        self._q: deque[tuple[str, dict[str, Any]]] = deque()
        self._max = max_queue
        self._lock = threading.Lock()
        self._flush = flush_interval_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._writer, name="ips-archive", daemon=True)
        self.rows = dict.fromkeys(FILES, 0)
        self.dropped_rows = 0
        self.write_errors = 0
        self.writer_error: str | None = None
        self._last_summary = ""
        self._closed = False
        self._thread.start()

    # -- producers (cheap, non-blocking) ------------------------------------- #

    def _put(self, name: str, row: dict[str, Any]) -> None:
        with self._lock:
            # after close() nothing is written any more: count it (complete -> false) instead of queueing it silently
            if self._closed or len(self._q) >= self._max:
                self.dropped_rows += 1
                return
            self._q.append((name, row))

    def frame(self, direction: str, t_ns: int, raw: bytes, out: list[bytes], send_failed: int = 0) -> None:
        """One received frame and what the bridge did with it (``direction`` is ``down`` or ``up``). ``verdict`` is the
        policy's decision; ``send_failed`` (only when > 0) counts output frames the far link did not accept, so a
        ``forwarded`` frame that never reached the wire is not mistaken for a delivered one."""
        row: dict[str, Any] = {"t_ns": t_ns, "raw": raw.hex()}
        if send_failed:
            row["send_failed"] = int(send_failed)
        if not out:
            row["verdict"] = "dropped"
        elif len(out) == 1 and out[0] == raw:
            row["verdict"] = "forwarded"
        else:
            row["verdict"] = "rewritten"
            row["out"] = [o.hex() for o in out]
        self._put("frames_down.jsonl" if direction == "down" else "frames_up.jsonl", row)

    def consumed(self, direction: str, t_ns: int, raw: bytes) -> None:
        """A received frame the bridge consumed itself (a management command): archived, never forwarded."""
        self._put("frames_down.jsonl" if direction == "down" else "frames_up.jsonl",
                  {"t_ns": t_ns, "raw": raw.hex(), "verdict": "consumed"})

    def decision(self, t_ns: int, assessment: Any, mode: str, state: str, summary: str) -> None:
        self._put("decisions.jsonl", {
            "t_ns": t_ns, "t": round(float(assessment.t), 3), "threat": bool(assessment.threat),
            "alert": bool(assessment.is_alert), "type": assessment.attack_type.value,
            "score": round(float(assessment.threat_score), 4), "evidence": list(assessment.evidence),
            "mode": mode, "state": state, "summary": summary})

    def action(self, t_ns: int, kind: str, to: str, raw: bytes | None = None, **extra: Any) -> None:
        """``kind``: counter_frame | alarm | crossend | summary. ``to``: fc | gcs | controller."""
        row: dict[str, Any] = {"t_ns": t_ns, "kind": kind, "to": to, **extra}
        if raw is not None:
            row["raw"] = raw.hex()
        self._put("actions.jsonl", row)

    def summary_changed(self, t_ns: int, summary: str, mode: str, state: str) -> None:
        if summary != self._last_summary:
            self._last_summary = summary
            self.action(t_ns, "summary", "controller", summary=summary, mode=mode, state=state)

    # -- writer -------------------------------------------------------------- #

    def _error(self, exc: BaseException) -> None:
        self.write_errors += 1
        if self.writer_error is None:
            self.writer_error = f"{type(exc).__name__}: {exc}"

    def _drain(self) -> None:
        with self._lock:
            batch, self._q = list(self._q), deque()
        for name, row in batch:
            try:
                self._files[name].write(json.dumps(row, default=str) + "\n")
            except Exception as exc:  # noqa: BLE001 - a lost row is counted, never fatal to the writer
                self._error(exc)
                continue
            self.rows[name] += 1
        for f in self._files.values():
            try:
                f.flush()
            except Exception as exc:  # noqa: BLE001 - buffered rows may be lost: the archive is incomplete
                self._error(exc)

    def _writer(self) -> None:
        while not self._stop.wait(self._flush):
            self._drain()

    def stats(self) -> dict[str, Any]:
        return {"dir": str(self.dir), "rows": dict(self.rows), "dropped_rows": self.dropped_rows,
                "write_errors": self.write_errors, "writer_error": self.writer_error,
                "complete": self.dropped_rows == 0 and self.write_errors == 0}

    def close(self) -> dict[str, Any]:
        """Stop the writer, write what is queued and close the files. Never raises: errors are counted in ``stats()``."""
        with self._lock:
            first, self._closed = not self._closed, True
        if first:
            self._stop.set()
            self._thread.join(timeout=5.0)
            self._drain()
            for f in self._files.values():
                try:
                    f.close()
                except Exception as exc:  # noqa: BLE001
                    self._error(exc)
        return self.stats()
