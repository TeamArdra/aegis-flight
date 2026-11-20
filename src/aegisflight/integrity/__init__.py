"""Firmware-integrity verification (SHA-256 manifests and AUTOPILOT_VERSION allowlists)."""

from .allowlist import (
    ALLOWLIST_KEY_ENV,
    AllowlistError,
    FirmwareAllowlist,
    FirmwareEntry,
    compute_allowlist_hmac,
    default_allowlist_path,
    load_firmware_allowlist,
)
from .verifier import FirmwareVerifier, IntegrityReport, sha256_file

__all__ = [
    "ALLOWLIST_KEY_ENV",
    "AllowlistError",
    "FirmwareAllowlist",
    "FirmwareEntry",
    "FirmwareVerifier",
    "IntegrityReport",
    "compute_allowlist_hmac",
    "default_allowlist_path",
    "load_firmware_allowlist",
    "sha256_file",
]
