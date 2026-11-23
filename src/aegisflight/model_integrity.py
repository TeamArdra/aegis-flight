"""Integrity check for the trained ML models (issue #11).

``models/*.joblib`` is git-ignored, so a clean clone has no model and ``aegis train`` produces a
different file from the one the committed evidence used. ``models/MODELS.sha256`` (``sha256sum``
format) lists the SHA-256 of the exact models; ``scripts/fetch_models.py`` downloads and verifies
them. This module only reads that manifest and hashes files; it never downloads anything.

A model's manifest is the ``MODELS.sha256`` next to it, so the check does not depend on the cwd.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

MANIFEST_NAME = "MODELS.sha256"
FETCH_COMMAND = "python scripts/fetch_models.py"

OK = "ok"  # file present and its SHA-256 matches the manifest
MISSING = "missing"  # file does not exist
MISMATCH = "mismatch"  # present, but the SHA-256 differs from the manifest
UNLISTED = "unlisted"  # present, but no manifest entry for this file name (custom model)


@dataclass(frozen=True)
class ModelCheck:
    path: Path
    status: str
    sha256: str | None  # of the file on disk, ``None`` if missing
    expected: str | None  # from the manifest, ``None`` if unlisted

    @property
    def usable(self) -> bool:
        return self.status == OK  # fail closed: an unlisted model needs an explicit --allow-unverified-model

    def message(self) -> str:
        if self.status == MISSING:
            return (f"model file not found: {self.path}. Get the exact model with `{FETCH_COMMAND}` "
                    "(or pass --no-model for an explicit ML-off run).")
        if self.status == MISMATCH:
            return (f"model SHA-256 mismatch for {self.path}: file {self.sha256}, expected "
                    f"{self.expected} (models/{MANIFEST_NAME}). It is corrupt or a different training "
                    f"run (`aegis train` does not reproduce the shipped model). Run `{FETCH_COMMAND}`, "
                    "or pass --allow-unverified-model to use it anyway (recorded in the output).")
        if self.status == UNLISTED:
            return (f"{self.path} has no entry in {MANIFEST_NAME}, so its integrity cannot be checked and it is "
                    "refused before deserialization. Add its SHA-256 to the manifest, or pass "
                    "--allow-unverified-model to use it anyway (recorded in the output).")
        return f"{self.path}: {self.status}"


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_manifest(path: str | Path) -> dict[str, str]:
    """``{file name: sha256}`` from a ``sha256sum``-format file; ``#`` lines and blanks are ignored."""
    out: dict[str, str] = {}
    p = Path(path)
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        digest, _, name = line.partition(" ")
        name = name.strip().lstrip("*").strip()
        if len(digest) == 64 and name:
            out[name] = digest.lower()
    return out


def read_and_check_model(path: str | Path, manifest: str | Path | None = None) -> tuple[ModelCheck, bytes | None]:
    """Read the model file ONCE and verify exactly those bytes against the manifest (issue #144).

    Returns ``(check, data)``. ``check.sha256`` is the SHA-256 of ``data``, so a caller that deserialises
    ``data`` (``joblib.load(io.BytesIO(data))``) loads precisely the bytes that were verified; re-opening
    the path after the check would let a file swapped in between be unpickled unverified (TOCTOU).
    ``data`` is ``None`` only when the file is missing.
    """
    p = Path(path)
    if not p.is_file():
        return ModelCheck(p, MISSING, None, None), None
    try:
        data = p.read_bytes()
    except FileNotFoundError:  # removed between is_file() and open(): same fail-closed status
        return ModelCheck(p, MISSING, None, None), None
    actual = hashlib.sha256(data).hexdigest()
    expected = parse_manifest(manifest if manifest is not None else p.parent / MANIFEST_NAME).get(p.name)
    if expected is None:
        return ModelCheck(p, UNLISTED, actual, None), data
    return ModelCheck(p, OK if actual == expected else MISMATCH, actual, expected), data


def check_model(path: str | Path, manifest: str | Path | None = None) -> ModelCheck:
    """Status of the model file on disk. Callers that go on to load it must use :func:`read_and_check_model`."""
    return read_and_check_model(path, manifest)[0]


def model_sha256_or_none(path: str | Path | None) -> str:
    """The value recorded in benchmark headers: the file's SHA-256, or ``none`` when ML is off/absent."""
    if not path or not Path(path).is_file():
        return "none"
    return sha256_file(path)


def resolve_model_or_exit(model: str | Path, *, no_model: bool = False, allow_unverified: bool = False,
                          err=None) -> str | None:
    """Model path for a CLI run that asked for ML, or ``None`` for the explicit ``--no-model`` opt-out.

    Fails closed, consistent with ``AnomalyDetector``: exits with status 2 (message names the fetch command)
    when the model is missing, or is not verified OK (hash mismatch, or no ``MODELS.sha256`` entry for a custom
    ``--model`` path) unless ``allow_unverified`` is set, which prints a warning and is recorded in the output.
    """
    import sys

    err = err or sys.stderr
    if no_model:
        return None
    chk = check_model(model)
    if chk.status == MISSING or (chk.status != OK and not allow_unverified):
        print(f"error: {chk.message()}", file=err)
        raise SystemExit(2)
    if chk.status != OK:
        print(f"warning: using an UNVERIFIED model ({chk.message()})", file=err)
    return str(model)
