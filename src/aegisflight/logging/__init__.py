"""Tamper-evident event and action logging (SQLite + SHA-256 hash chain + anchors)."""

from .anchors import (
    ANCHOR_KEY_ENV,
    AnchorVerification,
    AnchorWriter,
    append_anchor,
    build_anchor_record,
    compute_anchor_hmac,
    default_anchors_path,
    verify_anchors,
)
from .store import ChainStatus, EventStore

__all__ = [
    "ANCHOR_KEY_ENV",
    "AnchorVerification",
    "AnchorWriter",
    "ChainStatus",
    "EventStore",
    "append_anchor",
    "build_anchor_record",
    "compute_anchor_hmac",
    "default_anchors_path",
    "verify_anchors",
]
