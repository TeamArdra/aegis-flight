"""External chain-head anchoring for SQLite ``EventStore`` truncation detection (#21)."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .store import GENESIS_HASH, EventStore

ANCHOR_KEY_ENV = "AEGIS_ANCHOR_KEY"
DEFAULT_ANCHOR_INTERVAL_S = 5.0


def default_anchors_path(db_path: str | Path) -> Path:
    """Sidecar anchor log path ``<db>.anchors.jsonl``."""
    return Path(f"{db_path}.anchors.jsonl")


def _coerce_key(key: bytes | str | None) -> bytes | None:
    if key is None:
        env = os.environ.get(ANCHOR_KEY_ENV)
        if not env:
            return None
        key = env
    raw = key.encode("utf-8") if isinstance(key, str) else bytes(key)
    return raw if raw else None


def canonical_anchor_bytes(record: dict[str, Any]) -> bytes:
    """Canonical JSON bytes over anchor fields ``{run_id, last_id, row_count, head_hash, wall_time}``."""
    core = {
        "run_id": str(record["run_id"]),
        "last_id": int(record["last_id"]),
        "row_count": int(record["row_count"]),
        "head_hash": str(record["head_hash"]),
        "wall_time": float(record["wall_time"]),
    }
    return json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def compute_anchor_hmac(record: dict[str, Any], key: bytes | str) -> str:
    """Compute hex HMAC-SHA256 over :func:`canonical_anchor_bytes`."""
    raw_key = _coerce_key(key)
    if raw_key is None:
        raise ValueError("AEGIS_ANCHOR_KEY must not be empty")
    return hmac.new(raw_key, canonical_anchor_bytes(record), hashlib.sha256).hexdigest()


def build_anchor_record(
    store: EventStore,
    run_id: str,
    *,
    key: bytes | str | None = None,
    warn_unsigned: bool = True,
) -> dict[str, Any]:
    """Snapshot ``run_id``'s current head into an anchor record."""
    row = store.conn.execute(
        "SELECT id, hash FROM events WHERE run_id=? ORDER BY id DESC LIMIT 1",
        (run_id,),
    ).fetchone()
    cnt_row = store.conn.execute(
        "SELECT COUNT(*) c FROM events WHERE run_id=?",
        (run_id,),
    ).fetchone()
    row_count = int(cnt_row["c"]) if cnt_row else 0
    last_id = int(row["id"]) if row is not None else 0
    head_hash = str(row["hash"]) if row is not None else GENESIS_HASH
    rec: dict[str, Any] = {
        "run_id": run_id,
        "last_id": last_id,
        "row_count": row_count,
        "head_hash": head_hash,
        "wall_time": time.time(),
    }
    raw_key = _coerce_key(key)
    if raw_key is not None:
        rec["hmac_sha256"] = compute_anchor_hmac(rec, raw_key)
        rec["signed"] = True
    else:
        rec["signed"] = False
        if warn_unsigned:
            warnings.warn(
                f"Writing unsigned event-log anchor for run {run_id!r} (set {ANCHOR_KEY_ENV} to HMAC-sign anchors)",
                UserWarning,
                stacklevel=2,
            )
    return rec


def append_anchor(anchor_path: str | Path, record: dict[str, Any]) -> Path:
    """Atomically append one JSONL anchor line with flush + ``os.fsync``."""
    p = Path(anchor_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    line = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)
    return p


@dataclass
class AnchorVerification:
    ok: bool
    anchors_checked: int = 0
    signed_anchors: int = 0
    unsigned_anchors: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    latest_by_run: dict[str, dict[str, Any]] = field(default_factory=dict)


def verify_anchors(
    store: EventStore,
    anchor_path: str | Path,
    *,
    key: bytes | str | None = None,
) -> AnchorVerification:
    """Verify anchor signatures and check ``store`` for truncation or deleted runs."""
    p = Path(anchor_path)
    if not p.is_file():
        return AnchorVerification(ok=False, errors=[f"anchor file not found: {p}"])

    raw_key = _coerce_key(key)
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    warns: list[str] = []
    signed_n = 0
    unsigned_n = 0

    for lineno, raw_line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
        s = raw_line.strip()
        if not s:
            continue
        try:
            rec = json.loads(s)
        except json.JSONDecodeError as exc:
            errors.append(f"anchor line {lineno}: invalid JSON ({exc})")
            continue
        if not isinstance(rec, dict):
            errors.append(f"anchor line {lineno}: expected JSON object")
            continue
        sig = rec.get("hmac_sha256")
        if sig is not None:
            signed_n += 1
            if raw_key is None:
                errors.append(f"anchor line {lineno}: signed anchor cannot be verified without {ANCHOR_KEY_ENV}")
                continue
            if rec.get("signed") is False:
                errors.append(f"anchor line {lineno}: anchor carries hmac_sha256 with signed=false")
                continue
            try:
                expect = compute_anchor_hmac(rec, raw_key)
            except (KeyError, TypeError, ValueError) as exc:
                errors.append(f"anchor line {lineno}: malformed anchor fields ({exc})")
                continue
            if not hmac.compare_digest(expect.lower(), str(sig).strip().lower()):
                errors.append(f"anchor line {lineno} (run {rec.get('run_id')}): HMAC-SHA256 verification failed")
                continue
        else:
            unsigned_n += 1
            if raw_key is not None or signed_n > 0 or rec.get("signed") is True:
                errors.append(
                    f"anchor line {lineno} (run {rec.get('run_id')}): "
                    "unsigned anchor rejected when HMAC key is configured or after signed anchors"
                )
                continue
        records.append(rec)

    if unsigned_n and raw_key is None:
        warns.append(f"{unsigned_n} unsigned anchor(s) in {p.name} ({ANCHOR_KEY_ENV} unset)")

    latest: dict[str, dict[str, Any]] = {}
    for rec in records:
        rid = str(rec["run_id"])
        prev = latest.get(rid)
        if prev is None or (int(rec["row_count"]), int(rec["last_id"])) >= (
            int(prev["row_count"]),
            int(prev["last_id"]),
        ):
            latest[rid] = rec

    for rid, rec in sorted(latest.items()):
        expected_rows = int(rec["row_count"])
        expected_last_id = int(rec["last_id"])
        expected_hash = str(rec["head_hash"])

        cnt_row = store.conn.execute(
            "SELECT COUNT(*) c FROM events WHERE run_id=?", (rid,)
        ).fetchone()
        actual_rows = int(cnt_row["c"]) if cnt_row else 0
        run_exists = store.conn.execute("SELECT 1 FROM runs WHERE run_id=?", (rid,)).fetchone() is not None

        if actual_rows == 0 and expected_rows > 0:
            errors.append(
                f"run {rid}: anchored run missing from database "
                f"(expected >= {expected_rows} row(s), run metadata {'present' if run_exists else 'absent'})"
            )
            continue
        if actual_rows < expected_rows:
            errors.append(
                f"run {rid}: event log truncated ({actual_rows} rows present < anchored {expected_rows}, "
                f"missing {expected_rows - actual_rows} tail row(s))"
            )
            continue
        if expected_rows > 0:
            head_row = store.conn.execute(
                "SELECT hash FROM events WHERE run_id=? AND id=?",
                (rid, expected_last_id),
            ).fetchone()
            if head_row is None:
                errors.append(
                    f"run {rid}: anchored head id={expected_last_id} missing from database"
                )
            elif str(head_row["hash"]) != expected_hash:
                errors.append(
                    f"run {rid}: hash mismatch at anchored head id={expected_last_id}"
                )

    return AnchorVerification(
        ok=not errors,
        anchors_checked=len(records),
        signed_anchors=signed_n,
        unsigned_anchors=unsigned_n,
        errors=errors,
        warnings=warns,
        latest_by_run=latest,
    )


class AnchorWriter:
    """Periodic + shutdown external anchor helper for long-running stores."""

    def __init__(
        self,
        store: EventStore,
        anchor_path: str | Path | None = None,
        *,
        interval_s: float = DEFAULT_ANCHOR_INTERVAL_S,
        key: bytes | str | None = None,
    ) -> None:
        self.store = store
        self.anchor_path = Path(anchor_path) if anchor_path else default_anchors_path(store.db_path)
        self.interval_s = max(0.2, float(interval_s))
        self.key = key
        self._last_write_mono: float = 0.0
        self._last_anchored_count: dict[str, int] = {}
        self.latest_anchor: dict[str, Any] | None = None
        self.last_anchor_mono: float | None = None
        self._warned_unsigned = False

    def write_now(self, run_id: str, *, force: bool = False) -> dict[str, Any] | None:
        """Write an anchor record for ``run_id`` now (unless unchanged and not forced)."""
        warn = not self._warned_unsigned
        rec = build_anchor_record(self.store, run_id, key=self.key, warn_unsigned=warn)
        if not rec["signed"]:
            self._warned_unsigned = True
        if not force and self._last_anchored_count.get(run_id) == rec["row_count"] and self.latest_anchor is not None:
            return None
        append_anchor(self.anchor_path, rec)
        now_mono = time.monotonic()
        self._last_write_mono = now_mono
        self.last_anchor_mono = now_mono
        self._last_anchored_count[run_id] = int(rec["row_count"])
        self.latest_anchor = rec
        return rec

    def maybe_write(self, run_id: str) -> dict[str, Any] | None:
        """Write an anchor if ``interval_s`` has elapsed since the previous write."""
        if (time.monotonic() - self._last_write_mono) < self.interval_s:
            return None
        return self.write_now(run_id, force=True)

    def snapshot(self) -> dict[str, Any] | None:
        if self.latest_anchor is None:
            return None
        age_s = None if self.last_anchor_mono is None else round(max(0.0, time.monotonic() - self.last_anchor_mono), 2)
        return {
            "head_hash": self.latest_anchor["head_hash"],
            "row_count": self.latest_anchor["row_count"],
            "last_id": self.latest_anchor["last_id"],
            "signed": self.latest_anchor["signed"],
            "age_s": age_s,
            "path": self.anchor_path.name,
        }
