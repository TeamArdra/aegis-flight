"""Tamper-evident event logging (SQLite + SHA-256 hash chain)."""

from .rotation import prune_rotated_files, rotate_file_series, rotate_sqlite_store
from .store import ChainStatus, EventStore

__all__ = [
    "EventStore",
    "ChainStatus",
    "rotate_file_series",
    "rotate_sqlite_store",
    "prune_rotated_files",
]
