"""Firmware identity allowlist for live MAVLink links (``AUTOPILOT_VERSION``).

Physical flight controllers do not expose on-board firmware files to a ground or
companion monitor, so file-manifest hashing (:class:`FirmwareVerifier`) only
applies to simulated or companion-local files. On real vehicles and SITL links,
this module checks observed ``AUTOPILOT_VERSION`` telemetry against a pinned
YAML allowlist (`configs/firmware_allowlist.yaml`).

Integrity of the allowlist itself can be protected with an HMAC-SHA256 signature
stored in top-level ``hmac_sha256`` using a key from ``AEGIS_ALLOWLIST_KEY``.
- Signed allowlist with a valid key and matching HMAC -> verified & loaded.
- Signed allowlist with a missing key or mismatched HMAC -> fail-closed
  (:class:`AllowlistError`).
- Unsigned allowlist -> loads with a warning (explicitly flagged).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..core.enums import IntegrityStatus
from .verifier import IntegrityReport

ALLOWLIST_KEY_ENV = "AEGIS_ALLOWLIST_KEY"
DEFAULT_ALLOWLIST_NAME = "firmware_allowlist.yaml"


class AllowlistError(ValueError):
    """Raised when a firmware allowlist is malformed or fails HMAC verification."""


def canonical_allowlist_bytes(data: dict[str, Any]) -> bytes:
    """Return canonical UTF-8 JSON bytes of the allowlist excluding ``hmac_sha256``."""
    payload = {k: v for k, v in data.items() if k != "hmac_sha256"}
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    except TypeError as exc:
        raise AllowlistError(f"Firmware allowlist contains non-JSON-serializable YAML types: {exc}") from exc


def _coerce_key(key: bytes | str) -> bytes:
    if isinstance(key, bytes):
        out = key
    elif isinstance(key, str):
        out = key.encode("utf-8")
    else:
        raise AllowlistError("AEGIS_ALLOWLIST_KEY must be bytes or str")
    if not out:
        raise AllowlistError("AEGIS_ALLOWLIST_KEY must not be empty")
    return out


def compute_allowlist_hmac(data: dict[str, Any], key: bytes | str) -> str:
    """Compute hex HMAC-SHA256 over :func:`canonical_allowlist_bytes`."""
    return hmac.new(_coerce_key(key), canonical_allowlist_bytes(data), hashlib.sha256).hexdigest()


def _norm_sw_version(val: int | str) -> tuple[str, Any]:
    if isinstance(val, int) and not isinstance(val, bool):
        return ("int", int(val))
    if isinstance(val, str):
        s = val.strip().lstrip("vV")
        parts = s.split(".")
        if len(parts) == 3 and all(p.isdigit() for p in parts):
            return ("semver", tuple(int(p) for p in parts))
        if len(parts) == 4 and all(p.isdigit() for p in parts):
            maj, min_, pat, fw = (int(p) for p in parts)
            return ("int", ((maj & 0xFF) << 24) | ((min_ & 0xFF) << 16) | ((pat & 0xFF) << 8) | (fw & 0xFF))
        if s.isdigit():
            return ("int", int(s))
    raise AllowlistError(f"Unsupported flight_sw_version format: {val!r}")


def _decode_sw_semver(raw: int) -> tuple[int, int, int]:
    return ((raw >> 24) & 0xFF, (raw >> 16) & 0xFF, (raw >> 8) & 0xFF)


def _norm_custom_version(val: str | bytes | bytearray | list[int] | tuple[int, ...]) -> bytes:
    """Normalise an 8-byte MAVLink ``flight_custom_version`` field to 8 raw bytes."""
    if isinstance(val, (bytes, bytearray)):
        raw = bytes(val)
    elif isinstance(val, (list, tuple)):
        try:
            raw = bytes(int(b) & 0xFF for b in val)
        except (TypeError, ValueError) as exc:
            raise AllowlistError(f"Invalid flight_custom_version byte list: {val!r}") from exc
    elif isinstance(val, str):
        s = val.strip()
        if s.startswith(("0x", "0X")):
            s = s[2:]
        if len(s) == 16 and all(c in "0123456789abcdefABCDEF" for c in s):
            raw = bytes.fromhex(s)
        else:
            raw = s.encode("utf-8")
    else:
        raise AllowlistError(f"Unsupported flight_custom_version type: {type(val).__name__}")
    if len(raw) > 8:
        raw = raw[:8]
    return raw.ljust(8, b"\x00")


def _format_custom_version(raw: bytes) -> str:
    return raw.hex()


@dataclass(frozen=True)
class FirmwareEntry:
    """Pinned expected ``AUTOPILOT_VERSION`` fields for a vehicle endpoint."""

    name: str
    sysid: int | None = 1
    compid: int | None = 1
    flight_sw_version: int | str | None = None
    flight_custom_version: str | bytes | list[int] | None = None
    board_version: int | None = None
    vendor_id: int | None = None
    product_id: int | None = None
    uid: int | None = None


@dataclass
class FirmwareAllowlist:
    """Loaded firmware identity allowlist and verification logic."""

    entries: list[FirmwareEntry] = field(default_factory=list)
    sha256: str = ""
    signed: bool = False
    unsigned_warning: str | None = None
    path: str | None = None

    def match_entry(self, sysid: int, compid: int = 1) -> FirmwareEntry | None:
        """Find the most specific matching entry for ``(sysid, compid)``."""
        exact: FirmwareEntry | None = None
        sys_only: FirmwareEntry | None = None
        wildcard: FirmwareEntry | None = None
        for entry in self.entries:
            s_ok = entry.sysid is None or entry.sysid == sysid
            c_ok = entry.compid is None or entry.compid == compid
            if not (s_ok and c_ok):
                continue
            if entry.sysid == sysid and entry.compid == compid:
                exact = entry
                break
            if entry.sysid == sysid and entry.compid is None and sys_only is None:
                sys_only = entry
            elif entry.sysid is None and entry.compid is None and wildcard is None:
                wildcard = entry
        return exact or sys_only or wildcard

    def verify_autopilot_version(
        self,
        fields: dict[str, Any],
        *,
        sysid: int = 1,
        compid: int = 1,
    ) -> IntegrityReport:
        """Compare observed ``AUTOPILOT_VERSION`` fields against the pinned entry."""
        entry = self.match_entry(sysid, compid)
        if entry is None:
            return IntegrityReport(
                status=IntegrityStatus.UNKNOWN,
                checked=0,
                evidence=[f"coverage: no pinned firmware allowlist entry for sysid={sysid} compid={compid}"],
            )

        checked = 0
        mismatches: list[str] = []

        if entry.flight_sw_version is not None:
            checked += 1
            raw_sw = fields.get("flight_sw_version")
            if raw_sw is None:
                mismatches.append("firmware mismatch: flight_sw_version missing in AUTOPILOT_VERSION")
            else:
                kind, expected_sw = _norm_sw_version(entry.flight_sw_version)
                actual_sw_int = int(raw_sw)
                if kind == "semver":
                    actual_cmp = _decode_sw_semver(actual_sw_int)
                    if actual_cmp != expected_sw:
                        mismatches.append(
                            f"firmware mismatch: flight_sw_version expected "
                            f"{'.'.join(map(str, expected_sw))} got {'.'.join(map(str, actual_cmp))}"
                        )
                elif actual_sw_int != expected_sw:
                    mismatches.append(
                        f"firmware mismatch: flight_sw_version expected {expected_sw} got {actual_sw_int}"
                    )

        if entry.flight_custom_version is not None:
            checked += 1
            raw_custom = fields.get("flight_custom_version")
            if raw_custom is None:
                mismatches.append("firmware mismatch: flight_custom_version missing in AUTOPILOT_VERSION")
            else:
                exp_bytes = _norm_custom_version(entry.flight_custom_version)
                act_bytes = _norm_custom_version(raw_custom)
                if act_bytes != exp_bytes:
                    mismatches.append(
                        f"firmware mismatch: flight_custom_version expected "
                        f"{_format_custom_version(exp_bytes)} got {_format_custom_version(act_bytes)}"
                    )

        for int_field in ("board_version", "vendor_id", "product_id"):
            expected_val = getattr(entry, int_field)
            if expected_val is None:
                continue
            checked += 1
            actual_val = fields.get(int_field)
            if actual_val is None or int(actual_val) != int(expected_val):
                mismatches.append(
                    f"firmware mismatch: {int_field} expected {expected_val} got {actual_val}"
                )

        if entry.uid is not None:
            actual_uid = fields.get("uid")
            if actual_uid is not None and int(actual_uid) != 0:
                checked += 1
                if int(actual_uid) != int(entry.uid):
                    mismatches.append(
                        f"firmware mismatch: uid expected {entry.uid} got {actual_uid}"
                    )
            else:
                checked += 1
                mismatches.append(
                    f"firmware mismatch: uid expected {entry.uid} got {actual_uid}"
                )

        if mismatches:
            return IntegrityReport(
                status=IntegrityStatus.INVALID,
                checked=checked,
                tampered=mismatches,
                evidence=mismatches,
            )
        return IntegrityReport(
            status=IntegrityStatus.VALID,
            checked=checked,
            evidence=[f"AUTOPILOT_VERSION matches pinned entry {entry.name!r}"],
        )


def _parse_entry(raw: dict[str, Any], idx: int) -> FirmwareEntry:
    if not isinstance(raw, dict):
        raise AllowlistError(f"Allowlist entry #{idx} must be a mapping")
    name = str(raw.get("name") or raw.get("vehicle") or f"vehicle-{idx}")
    sysid = None if raw.get("sysid") is None else int(raw["sysid"])
    compid = None if raw.get("compid") is None else int(raw["compid"])
    sw = raw.get("flight_sw_version")
    custom = raw.get("flight_custom_version")
    if custom is not None:
        _norm_custom_version(custom)
    if sw is not None:
        _norm_sw_version(sw)
    return FirmwareEntry(
        name=name,
        sysid=sysid,
        compid=compid,
        flight_sw_version=sw,
        flight_custom_version=custom,
        board_version=None if raw.get("board_version") is None else int(raw["board_version"]),
        vendor_id=None if raw.get("vendor_id") is None else int(raw["vendor_id"]),
        product_id=None if raw.get("product_id") is None else int(raw["product_id"]),
        uid=None if raw.get("uid") is None else int(raw["uid"]),
    )


def load_firmware_allowlist(
    path: str | Path,
    *,
    key: bytes | str | None = None,
    env_var: str = ALLOWLIST_KEY_ENV,
) -> FirmwareAllowlist:
    """Load and optionally verify HMAC-SHA256 on a YAML firmware allowlist.

    Raises :class:`AllowlistError` on malformed YAML or failed signature
    verification (fail closed). Unsigned files load with a ``UserWarning``.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Firmware allowlist not found: {p}")
    raw_bytes = p.read_bytes()
    digest = hashlib.sha256(raw_bytes).hexdigest()
    try:
        data = yaml.safe_load(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise AllowlistError(f"Malformed firmware allowlist YAML {p}: {exc}") from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        raise AllowlistError(f"Firmware allowlist {p} must be a YAML mapping at top level")

    sig = data.get("hmac_sha256")
    resolved_key: bytes | str | None = key if key is not None else os.environ.get(env_var)
    signed = False
    unsigned_warning: str | None = None
    if sig is not None:
        if not isinstance(sig, str) or not sig.strip():
            raise AllowlistError(f"Firmware allowlist {p} has empty/non-string hmac_sha256")
        if not resolved_key:
            raise AllowlistError(
                f"Signed firmware allowlist {p} cannot be verified: set {env_var}"
            )
        expected = compute_allowlist_hmac(data, resolved_key)
        if not hmac.compare_digest(expected.lower(), sig.strip().lower()):
            raise AllowlistError(
                f"Firmware allowlist {p} HMAC-SHA256 verification failed (fail-closed)"
            )
        signed = True
    else:
        if resolved_key:
            raise AllowlistError(
                f"Unsigned firmware allowlist {p} rejected when {env_var} is set (fail-closed)"
            )
        unsigned_warning = (
            f"Firmware allowlist {p} is unsigned (missing hmac_sha256); loading without HMAC verification"
        )
        warnings.warn(unsigned_warning, UserWarning, stacklevel=2)

    vehicles_raw = data.get("vehicles") or []
    if not isinstance(vehicles_raw, list):
        raise AllowlistError(f"Firmware allowlist {p} field 'vehicles' must be a list")
    entries = [_parse_entry(item, i) for i, item in enumerate(vehicles_raw)]
    return FirmwareAllowlist(
        entries=entries,
        sha256=digest,
        signed=signed,
        unsigned_warning=unsigned_warning,
        path=str(p),
    )


def default_allowlist_path(config_dir: str | Path | None = None) -> Path | None:
    """Locate ``firmware_allowlist.yaml`` under ``config_dir`` or built-in ``configs/``."""
    from ..config import CONFIG_DIR

    if config_dir:
        candidate = Path(config_dir) / DEFAULT_ALLOWLIST_NAME
        if candidate.is_file():
            return candidate
    builtin = CONFIG_DIR / DEFAULT_ALLOWLIST_NAME
    return builtin if builtin.is_file() else None
