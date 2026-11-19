"""Size-bounded log/SQLite rotation and disk-budget enforcement (#59).

Keeps onboard companion storage bounded without corrupting active append-only
SQLite hash chains: each rotated SQLite segment is cleanly closed before
renaming, leaving ``events.sqlite``, ``events.1.sqlite``, ... independently
verifiable with ``aegis verify-log``.
"""

from __future__ import annotations

import contextlib
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .store import EventStore

_ROTATED_RE = re.compile(r"\.([1-9][0-9]*)\.(?:jsonl|sqlite)$")


def _rotated_path(active: Path, index: int) -> Path:
    return active.with_name(f"{active.stem}.{index}{active.suffix}")


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
            os.replace(src, _rotated_path(active, idx + 1))
    os.replace(active, _rotated_path(active, 1))
    return True


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

    with contextlib.suppress(Exception):
        lock = getattr(store, "_lock", None)
        if lock is not None:
            with lock:
                store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
                store.conn.commit()
        else:
            store.conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            store.conn.commit()
    store.close()
    for sidecar in ("-wal", "-shm"):
        Path(f"{db_path}{sidecar}").unlink(missing_ok=True)
    rotated = rotate_file_series(db_path, max_bytes=max_bytes, max_rotations=max_rotations)
    fresh = _EventStore(db_path)
    fresh.start_run(run_id, label=label, meta=meta)
    return fresh, rotated


def prune_rotated_files(
    root: Path,
    *,
    max_total_bytes: int,
    active_names: set[str] | None = None,
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
    return deleted
