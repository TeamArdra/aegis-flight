#!/usr/bin/env python
"""Download the exact trained models and verify their SHA-256 (issue #11).

    python scripts/fetch_models.py                    # fetch what is missing or wrong, then verify
    python scripts/fetch_models.py --verify-only      # no network: report ok / missing / mismatch
    python scripts/fetch_models.py --base-url <url>   # a mirror or a local file:// directory

``models/MODELS.sha256`` (committed) is the source of truth for the hashes; ``aegis train`` does NOT
reproduce these files. A download is written to a temporary file, hashed, and only moved into
``models/`` when it matches; a mismatch deletes it and exits non-zero. Nothing is overwritten unless it
is missing or already fails verification.

The default ``--base-url`` points at a GitHub Release. That release is published only after the model
distribution decision (D3) is approved; until then use ``--base-url`` (e.g. a ``file://`` directory) or
copy the files into ``models/`` and run ``--verify-only``. See ``docs/MODEL_DISTRIBUTION.md``.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from aegisflight.model_integrity import (  # noqa: E402
    MANIFEST_NAME,
    MISMATCH,
    MISSING,
    OK,
    check_model,
    parse_manifest,
    sha256_file,
)

DEFAULT_BASE_URL = "https://github.com/TeamArdra/techfest-2026/releases/download/models-v1"


def fetch_one(name: str, expected: str, dest_dir: Path, base_url: str, opener=urllib.request.urlopen) -> str:
    """Download ``name``, verify, and move into place. Returns "" on success, else an error message."""
    url = f"{base_url.rstrip('/')}/{name}"
    dest_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=name + ".", suffix=".part", dir=dest_dir)
    try:
        with os.fdopen(fd, "wb") as out, opener(url, timeout=60) as resp:
            while chunk := resp.read(1 << 20):
                out.write(chunk)
        got = sha256_file(tmp)
        if got != expected:
            return f"{name}: downloaded file has SHA-256 {got}, expected {expected}; discarded"
        os.replace(tmp, dest_dir / name)
        return ""
    except (urllib.error.URLError, OSError) as exc:
        return f"{name}: download from {url} failed: {exc}"
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main(argv: list[str] | None = None, opener=urllib.request.urlopen) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models-dir", default=str(REPO / "models"))
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL)
    ap.add_argument("--verify-only", action="store_true", help="no download; exit non-zero unless all verify")
    a = ap.parse_args(argv)

    mdir = Path(a.models_dir)
    manifest = mdir / MANIFEST_NAME
    entries = parse_manifest(manifest)
    if not entries:
        print(f"error: no entries in {manifest}", file=sys.stderr)
        return 2
    failures: list[str] = []
    for name, expected in sorted(entries.items()):
        chk = check_model(mdir / name, manifest)
        if chk.status == OK:
            print(f"ok       {name}  {expected}")
            continue
        if a.verify_only:
            print(f"{chk.status:8} {name}")
            failures.append(chk.message())
            continue
        verb = "fetching" if chk.status == MISSING else "refetch" if chk.status == MISMATCH else chk.status
        print(f"{verb:8} {name} <- {a.base_url}")
        err = fetch_one(name, expected, mdir, a.base_url, opener)
        if err:
            failures.append(err)
        else:
            print(f"ok       {name}  {expected}")
    for f in failures:
        print(f"error: {f}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
