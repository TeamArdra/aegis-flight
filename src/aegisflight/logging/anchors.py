"""External chain-head anchoring for SQLite ``EventStore`` truncation detection (#21)."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .store import GENESIS_HASH, EventStore

log = logging.getLogger(__name__)

ANCHOR_KEY_ENV = "AEGIS_ANCHOR_KEY"
DEFAULT_ANCHOR_INTERVAL_S = 5.0
GENESIS_ANCHOR_HASH = "0" * 64


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
    """Canonical JSON bytes over anchor fields including chain linkage ``seq`` and ``prev_anchor_hash``."""
    core: dict[str, Any] = {
        "run_id": str(record["run_id"]),
        "last_id": int(record["last_id"]),
        "row_count": int(record["row_count"]),
        "head_hash": str(record["head_hash"]),
        "wall_time": float(record["wall_time"]),
    }
    if "seq" in record:
        core["seq"] = int(record["seq"])
    if "prev_anchor_hash" in record:
        core["prev_anchor_hash"] = str(record["prev_anchor_hash"])
    return json.dumps(core, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def anchor_record_hash(record: dict[str, Any]) -> str:
    """Compute SHA-256 hex digest of :func:`canonical_anchor_bytes`."""
    return hashlib.sha256(canonical_anchor_bytes(record)).hexdigest()


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
    seq: int = 0,
    prev_anchor_hash: str = GENESIS_ANCHOR_HASH,
) -> dict[str, Any]:
    """Snapshot ``run_id``'s current head into a hash-chained anchor record."""
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
        "seq": int(seq),
        "prev_anchor_hash": str(prev_anchor_hash),
        "run_id": run_id,
        "last_id": last_id,
        "row_count": row_count,
        "head_hash": head_hash,
        "wall_time": time.time(),
    }
    rec["anchor_hash"] = anchor_record_hash(rec)
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
    expected_min_anchors: int | None = None,
) -> AnchorVerification:
    """Verify anchor signatures, anchor-chain continuity (``seq`` & ``prev_anchor_hash``),
    and check ``store`` for truncation or deleted runs."""
    p = Path(anchor_path)
    if not p.is_file():
        return AnchorVerification(ok=False, errors=[f"anchor file not found: {p}"])

    raw_key = _coerce_key(key)
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    warns: list[str] = []
    signed_n = 0
    unsigned_n = 0
    expected_seq = 0
    expected_prev_hash = GENESIS_ANCHOR_HASH

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

        # Enforce sequence and prev_anchor_hash continuity across the anchor log (#21 / D6)
        if "seq" not in rec or "prev_anchor_hash" not in rec:
            errors.append(f"anchor line {lineno}: missing chain-continuity fields (seq / prev_anchor_hash)")
            continue
        try:
            rec_seq = int(rec["seq"])
        except (TypeError, ValueError):
            errors.append(f"anchor line {lineno}: invalid seq {rec.get('seq')!r}")
            continue
        rec_prev = str(rec["prev_anchor_hash"])
        if rec_seq != expected_seq:
            errors.append(
                f"anchor line {lineno}: sequence discontinuity (got seq={rec_seq}, expected {expected_seq})"
            )
        if rec_prev != expected_prev_hash:
            errors.append(
                f"anchor line {lineno}: prev_anchor_hash mismatch (broken anchor chain / deletion or reordering)"
            )

        try:
            computed_hash = anchor_record_hash(rec)
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(f"anchor line {lineno}: malformed anchor fields ({exc})")
            continue
        if "anchor_hash" in rec and str(rec["anchor_hash"]).lower() != computed_hash.lower():
            errors.append(f"anchor line {lineno}: anchor_hash mismatch (record modified)")

        sig = rec.get("hmac_sha256")
        if sig is not None:
            signed_n += 1
            if raw_key is None:
                errors.append(f"anchor line {lineno}: signed anchor cannot be verified without {ANCHOR_KEY_ENV}")
                expected_seq = rec_seq + 1
                expected_prev_hash = computed_hash
                continue
            if rec.get("signed") is False:
                errors.append(f"anchor line {lineno}: anchor carries hmac_sha256 with signed=false")
                expected_seq = rec_seq + 1
                expected_prev_hash = computed_hash
                continue
            try:
                expect = compute_anchor_hmac(rec, raw_key)
            except (KeyError, TypeError, ValueError) as exc:
                errors.append(f"anchor line {lineno}: malformed anchor fields ({exc})")
                expected_seq = rec_seq + 1
                expected_prev_hash = computed_hash
                continue
            if not hmac.compare_digest(expect.lower(), str(sig).strip().lower()):
                errors.append(f"anchor line {lineno} (run {rec.get('run_id')}): HMAC-SHA256 verification failed")
                expected_seq = rec_seq + 1
                expected_prev_hash = computed_hash
                continue
        else:
            unsigned_n += 1
            if raw_key is not None or signed_n > 0 or rec.get("signed") is True:
                errors.append(
                    f"anchor line {lineno} (run {rec.get('run_id')}): "
                    "unsigned anchor rejected when HMAC key is configured or after signed anchors"
                )
                expected_seq = rec_seq + 1
                expected_prev_hash = computed_hash
                continue

        expected_seq = rec_seq + 1
        expected_prev_hash = computed_hash
        records.append(rec)

    if expected_min_anchors is not None and len(records) < int(expected_min_anchors):
        errors.append(
            f"anchor log truncated: found {len(records)} anchor(s), expected >= {int(expected_min_anchors)}"
        )

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
        self._seq: int = 0
        self._prev_anchor_hash: str = GENESIS_ANCHOR_HASH
        self._resume_chain_state()

    def _resume_chain_state(self) -> None:
        """Continue the chain from the last anchor line; never silently fork it.

        If the file exists but its last line cannot be parsed as an anchor record (truncated write,
        corruption, tampering), restarting at seq=0/GENESIS in the same file would splice a second genesis
        onto the old chain. The damaged file is left untouched and new anchors go to a clearly named sibling
        file instead; an error is logged. The anchor record format and hashing are unchanged.
        """
        if not self.anchor_path.is_file():
            return
        try:
            lines = [ln.strip() for ln in self.anchor_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        except (OSError, UnicodeDecodeError) as exc:
            self._divert_corrupt_tail(f"unreadable ({type(exc).__name__}: {exc})")
            return
        if not lines:
            return
        try:
            last = json.loads(lines[-1])
            if not isinstance(last, dict) or "seq" not in last:
                raise ValueError("last line is not an anchor record with a seq")
            seq = int(last["seq"]) + 1
            prev = str(last.get("anchor_hash") or anchor_record_hash(last))
        except (ValueError, TypeError, KeyError) as exc:  # JSONDecodeError is a ValueError
            self._divert_corrupt_tail(f"last line is not a valid anchor record ({type(exc).__name__}: {exc})")
            return
        self._seq = seq
        self._prev_anchor_hash = prev

    def _divert_corrupt_tail(self, reason: str) -> None:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        original = self.anchor_path
        self.anchor_path = original.with_name(f"{original.stem}.resumed-after-corrupt-{stamp}{original.suffix}")
        log.error(
            "anchor file %s has a corrupt tail (%s); NOT appending a new genesis to it. New anchors go to %s "
            "(the original file is left unchanged for investigation; `aegis verify-log` on it will report the damage)",
            original, reason, self.anchor_path,
        )

    def write_now(self, run_id: str, *, force: bool = False) -> dict[str, Any] | None:
        """Write an anchor record for ``run_id`` now (unless unchanged and not forced)."""
        warn = not self._warned_unsigned
        rec = build_anchor_record(
            self.store,
            run_id,
            key=self.key,
            warn_unsigned=warn,
            seq=self._seq,
            prev_anchor_hash=self._prev_anchor_hash,
        )
        if not rec["signed"]:
            self._warned_unsigned = True
        if not force and self._last_anchored_count.get(run_id) == rec["row_count"] and self.latest_anchor is not None:
            return None
        append_anchor(self.anchor_path, rec)
        self._seq += 1
        self._prev_anchor_hash = str(rec["anchor_hash"])
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
