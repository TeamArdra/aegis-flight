"""Size-bounded log/SQLite rotation and disk-budget enforcement (#59).

Keeps onboard companion storage bounded without corrupting active append-only
SQLite hash chains: each rotated SQLite segment is cleanly closed before
renaming, leaving ``events.sqlite``, ``events.1.sqlite``, ... independently
verifiable with ``aegis verify-log``.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .store import EventStore

log = logging.getLogger(__name__)

_ROTATED_RE = re.compile(r"\.([1-9][0-9]*)\.(?:jsonl|sqlite)$")


def _rotated_path(active: Path, index: int) -> Path:
    return active.with_name(f"{active.stem}.{index}{active.suffix}")


def _replace_with_retry(src: Path, dst: Path, attempts: int = 5) -> None:
    """``os.replace`` with brief retry for transient Windows file-lock lag."""
    for idx in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if idx + 1 >= attempts:
                raise
            time.sleep(0.02 * (idx + 1))


def rotate_file_series(active: Path, *, max_bytes: int, max_rotations: int = 5) -> bool:
    """Rotate ``active`` -> ``<stem>.1<suffix>`` when ``size >= max_bytes``.

    Shifts existing rotated segments up to ``max_rotations`` and unlinks older
    ones. Returns ``True`` if a rotation happened.
    """
    if max_bytes <= 0 or not active.exists():
        return False
    try:
        size = active.stat().st_size
    except OSError:
        return False
    if size < max_bytes:
        return False

    keep = max(0, int(max_rotations))
    if keep == 0:
        active.unlink(missing_ok=True)
        return True

    oldest = _rotated_path(active, keep)
    oldest.unlink(missing_ok=True)
    for idx in range(keep - 1, 0, -1):
        src = _rotated_path(active, idx)
        if src.exists():
            _replace_with_retry(src, _rotated_path(active, idx + 1))
    _replace_with_retry(active, _rotated_path(active, 1))
    return True


def _segment_heads(store: EventStore) -> dict[str, object]:
    """Capture terminal event/action hashes from ``store`` before rotation."""
    ev_row = store.conn.execute("SELECT hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
    ev_cnt = store.conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()
    act_row = store.conn.execute("SELECT hash FROM actions ORDER BY id DESC LIMIT 1").fetchone()
    act_cnt = store.conn.execute("SELECT COUNT(*) AS c FROM actions").fetchone()
    return {
        "last_event_hash": ev_row["hash"] if ev_row else None,
        "event_count": int(ev_cnt["c"]) if ev_cnt else 0,
        "last_action_hash": act_row["hash"] if act_row else None,
        "action_count": int(act_cnt["c"]) if act_cnt else 0,
    }


def rotate_sqlite_store(
    store: EventStore,
    *,
    max_bytes: int,
    max_rotations: int = 5,
    run_id: str,
    label: str = "ips-bridge",
    meta: dict | None = None,
) -> tuple[EventStore, bool]:
    """Close and rotate ``store`` if its primary SQLite file reaches ``max_bytes``.

    Opens and returns a fresh ``EventStore`` at the same ``db_path`` with ``start_run``
    initialized for ``run_id``. Note: callers must hold any store lock so no concurrent
    ``log_event`` uses the closed connection.
    """
    from .store import EventStore as _EventStore  # noqa: PLC0415

    db_path = Path(store.db_path)
    if max_bytes <= 0 or not db_path.exists():
        return store, False
    try:
        size = db_path.stat().st_size
    except OSError:
        return store, False
    if size < max_bytes:
        return store, False

    # Capture the closing heads of this segment BEFORE closing it. If that fails the chain link would
    # carry null heads, so rotation is skipped (the store stays open and usable) and the failure is logged.
    lock = getattr(store, "_lock", None)
    try:
        with lock if lock is not None else contextlib.nullcontext():
            prev_heads = _segment_heads(store)
            try:
                store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                store.conn.commit()
            except Exception:  # noqa: BLE001 - a failed checkpoint only leaves a -wal file; rows are safe
                log.warning("rotation: wal_checkpoint failed for %s", db_path, exc_info=True)
    except Exception:  # noqa: BLE001
        log.error("rotation SKIPPED for %s: could not capture segment head hashes; store kept open",
                  db_path, exc_info=True)
        return store, False

    store.close()
    failure: Exception | None = None
    rotated = False
    try:
        for sidecar in ("-wal", "-shm"):
            Path(f"{db_path}{sidecar}").unlink(missing_ok=True)
        rotated = rotate_file_series(db_path, max_bytes=max_bytes, max_rotations=max_rotations)
    except OSError as exc:
        failure = exc
        log.error("rotation FAILED for %s: %s; reopening the active store (chain continues unbroken)",
                  db_path, exc, exc_info=True)

    if not rotated:
        # Nothing moved (failure, or the file shrank below the threshold): reopen the same file. The run
        # chain resumes from its stored last hash, so no link row is written and continuity is intact.
        reopened = _EventStore(db_path)
        if failure is not None:
            with contextlib.suppress(Exception):
                reopened.log_action(run_id, time.time(), "rotation", "ROTATION_FAILED", db_path.name,
                                    f"{type(failure).__name__}: {failure}")
        return reopened, False

    keep_segment = int(max_rotations) > 0
    prev_segment = {
        "rotated_path": str(_rotated_path(db_path, 1)) if keep_segment else None,
        **prev_heads,
    }
    fresh_meta = {**(meta or {}), "prev_segment": prev_segment}
    fresh = _EventStore(db_path)
    fresh.start_run(run_id, label=label, meta=fresh_meta)
    fresh.log_action(
        run_id,
        time.time(),
        "rotation",
        # With max_rotations == 0 the old segment was deleted: there is nothing to link to, so say so.
        "ROTATION_LINK" if keep_segment else "ROTATION_DISCARDED",
        db_path.name,
        json.dumps(prev_segment, sort_keys=True),
    )
    return fresh, True


def prune_rotated_files(
    root: Path,
    *,
    max_total_bytes: int,
    active_names: set[str] | None = None,
    deleted_paths: list[str] | None = None,
) -> int:
    """Delete oldest rotated segments under ``root`` until total bytes <= ``max_total_bytes``.

    Active (non-rotated) files are never deleted so the running session never loses
    its open handle or chain head. Returns number of deleted files.
    """
    if max_total_bytes <= 0 or not root.exists():
        return 0
    protected = set(active_names or ())

    def _dir_usage() -> tuple[int, list[tuple[float, int, Path]]]:
        total = 0
        candidates: list[tuple[float, int, Path]] = []
        for entry in root.iterdir():
            if not entry.is_file():
                continue
            try:
                st = entry.stat()
            except OSError:
                continue
            total += st.st_size
            if entry.name in protected:
                continue
            m = _ROTATED_RE.search(entry.name)
            if m:
                # Higher index is older; break ties with older mtime.
                candidates.append((st.st_mtime, -int(m.group(1)), entry))
        return total, candidates

    total, candidates = _dir_usage()
    if total <= max_total_bytes or not candidates:
        return 0

    candidates.sort(key=lambda item: (item[0], item[1]))
    deleted = 0
    for _mtime, _neg_idx, victim in candidates:
        if total <= max_total_bytes:
            break
        try:
            sz = victim.stat().st_size
            victim.unlink(missing_ok=True)
        except OSError:
            continue
        total = max(0, total - sz)
        deleted += 1
        if deleted_paths is not None:
            deleted_paths.append(victim.name)
    return deleted
