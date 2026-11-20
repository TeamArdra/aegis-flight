"""Run provenance for evidence-producing entry points (issue #25).

Every script that writes evidence either runs on a clean, committed tree with a complete
manifest, or loudly labels its output ``NOT-REPRODUCIBLE``. The scripts import this through
``scripts/sitl/provenance.py`` (``from provenance import require_clean_tree, ...``); the
``aegis ips-bridge`` CLI imports it directly.

Typical use::

    prov = begin_run(allow_dirty=a.allow_dirty, profile_dir=a.profile, model_path=model,
                     ml_enabled=model is not None, px4_git_describe=px4_describe())
    ... run ...
    finish_run(prov)
    write_manifest(run_dir, prov)          # <run_dir>/run_manifest.json (+ NOT-REPRODUCIBLE marker)

Stem-style outputs (``--out artifacts/sitl/trial_001`` -> ``trial_001.*``) embed ``prov`` in
their own manifest and call ``stamp_stem(stem, prov)`` instead.

Schema ``aegisflight.run_manifest/1`` is documented in ``docs/VALIDATION_EVIDENCE.md``.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as md
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_ID = "aegisflight.run_manifest/1"
MANIFEST_NAME = "run_manifest.json"
NOT_REPRODUCIBLE = "NOT-REPRODUCIBLE"
REPRODUCIBLE = "REPRODUCIBLE"
PACKAGES = ("aegisflight", "pymavlink", "numpy", "scikit-learn", "joblib", "scipy", "pyyaml", "fastapi", "pyserial")

#: Every key a manifest from :func:`collect_run_provenance` carries (the schema test pins this).
MANIFEST_FIELDS = (
    "schema", "status", "reproducible", "commit", "working_tree_dirty", "dirty_paths",
    "detector_profile_dir", "detector_profile_sha256", "firmware_allowlist_sha256",
    "model_path", "model_sha256", "ml_enabled",
    "px4_git_describe", "ardupilot_version", "python", "packages", "command_line", "started_utc", "ended_utc",
    "not_reproducible_reason",
)

#: Untracked files only count as dirt under these roots (a fresh output directory must not
#: make the tree dirty); tracked modifications count anywhere.
_CODE_ROOTS = ("src", "scripts", "configs", "backend", "models", "pyproject.toml")


class DirtyTreeError(SystemExit):
    """Raised by :func:`require_clean_tree`; exits the script with status 2. The message is ``str(exc)``;
    :func:`require_clean_tree` prints it to stderr before raising (``SystemExit(2)`` itself prints nothing)."""

    def __init__(self, paths: list[str]) -> None:
        self.paths = paths
        shown = "\n".join(f"  {p}" for p in paths[:20]) + ("\n  ..." if len(paths) > 20 else "")
        self.message = (
            f"ERROR: working tree is dirty ({len(paths)} path(s)); evidence must come from a clean commit.\n{shown}\n"
            "Commit the changes, or pass --allow-dirty to proceed (output is then stamped NOT-REPRODUCIBLE)."
        )
        super().__init__(2)

    def __str__(self) -> str:
        return self.message


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_dir(path: str | Path) -> str | None:
    """SHA-256 over every ``*.yaml`` in the profile directory (name + bytes, sorted); ``None`` if absent."""
    p = Path(path)
    if not p.is_dir():
        return None
    h = hashlib.sha256()
    for f in sorted(p.glob("*.yaml")):
        h.update(f.name.encode() + b"\0" + f.read_bytes())
    return h.hexdigest()


_STAMP_KEYS = frozenset({"reproducible", "status", "not_reproducible_reason", "working_tree_dirty", "commit"})


def _git(*args: str, repo: str | Path | None = None) -> str | None:
    try:
        r = subprocess.run(["git", *args], capture_output=True, text=True, timeout=30,
                           cwd=str(repo) if repo else None)
    except Exception:  # noqa: BLE001 - provenance must never crash a run
        return None
    return r.stdout.rstrip("\r\n") if r.returncode == 0 else None


def code_repo() -> Path | None:
    """The git checkout the running ``aegisflight`` package was loaded from, or ``None`` when the package is not
    running from one (an installed wheel, a venv inside some other repo). Never the current working directory: a run
    started from inside another clean repository must not borrow that repository's commit."""
    pkg = Path(__file__).resolve().parent  # <repo>/src/aegisflight
    candidate = pkg.parents[1]
    top = _git("rev-parse", "--show-toplevel", repo=pkg)
    if not (top and os.path.normcase(str(Path(top).resolve())) == os.path.normcase(str(candidate))):
        return None
    # the entry script must come from the same checkout: a script run from worktree A while the package is imported from
    # checkout B (e.g. a shared editable venv) would otherwise be stamped with B's commit and clean state. Entry points
    # inside an installed environment (pytest, the aegis console script) are not a checkout's code and are not judged.
    main = getattr(sys.modules.get("__main__"), "__file__", None)
    if main and "site-packages" not in Path(main).parts:
        mtop = _git("rev-parse", "--show-toplevel", repo=Path(main).resolve().parent)
        if mtop and os.path.normcase(str(Path(mtop).resolve())) != os.path.normcase(str(candidate)):
            return None
    return candidate


def tree_state(repo: str | Path | None = None) -> dict[str, Any]:
    """``{"commit", "dirty", "dirty_paths"}`` for the repo at ``repo`` (default: :func:`code_repo`, the checkout of
    the running code, never the cwd). Not running from a checkout counts as dirty (it cannot be proved clean)."""
    if repo is None:
        repo = code_repo()
        if repo is None:
            return {"commit": "unknown", "dirty": True,
                    "dirty_paths": ["<aegisflight is not running from a git checkout>"]}
    commit = (_git("rev-parse", "HEAD", repo=repo) or "unknown").strip()
    tracked = _git("status", "--porcelain", "--untracked-files=no", repo=repo)
    untracked = _git("status", "--porcelain", "--untracked-files=all", "--", *_CODE_ROOTS, repo=repo)
    paths: list[str] = []
    for blob in (tracked, untracked):
        for ln in (blob or "").splitlines():
            if ln.strip() and ln[3:] not in paths:
                paths.append(ln[3:])
    if tracked is None:  # not a git checkout: cannot prove clean
        paths = ["<git status unavailable>"]
    return {"commit": commit, "dirty": bool(paths), "dirty_paths": sorted(paths)}


def require_clean_tree(allow_dirty: bool = False, repo: str | Path | None = None) -> dict[str, Any]:
    """Refuse (``DirtyTreeError``, exit status 2, message on stderr) on a dirty tree unless ``allow_dirty``.
    Returns the tree state; pass it to :func:`collect_run_provenance` as ``start_state`` when the manifest is
    built after the run."""
    state = tree_state(repo)
    if state["dirty"] and not allow_dirty:
        err = DirtyTreeError(state["dirty_paths"])
        print(err, file=sys.stderr)
        raise err
    return state


def _drift_reasons(start: dict[str, Any], end: dict[str, Any]) -> list[str]:
    """Why a run whose tree was ``start`` at the beginning and ``end`` now is not reproducible (``[]`` if it is)."""
    reasons = []
    if start["dirty"]:
        reasons.append("working tree was dirty at run start")
    if end["commit"] != start["commit"]:
        reasons.append(f"commit changed during the run ({start['commit']} -> {end['commit']})")
    if end["dirty"] != start["dirty"]:
        reasons.append(f"working tree became {'dirty' if end['dirty'] else 'clean'} during the run")
    return reasons


def _apply_drift(manifest: dict[str, Any], start: dict[str, Any], end: dict[str, Any]) -> None:
    """Fold a start/end tree comparison into ``manifest``; ``commit`` stays the START commit (the code that ran)."""
    prev = manifest.get("not_reproducible_reason")
    reasons = [r for r in _drift_reasons(start, end) if r not in (prev or "")]
    if not reasons:
        return
    manifest["not_reproducible_reason"] = "; ".join([prev, *reasons] if prev else reasons)
    manifest["reproducible"] = False
    manifest["status"] = NOT_REPRODUCIBLE
    manifest["working_tree_dirty"] = bool(manifest.get("working_tree_dirty")) or start["dirty"] or end["dirty"]
    manifest["dirty_paths"] = sorted(set(manifest.get("dirty_paths") or ()) | set(start["dirty_paths"])
                                     | set(end["dirty_paths"]))


def add_provenance_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--allow-dirty", action="store_true",
                    help="run on a dirty tree; output and manifest are stamped NOT-REPRODUCIBLE")


def _package_versions() -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for name in PACKAGES:
        try:
            out[name] = md.version(name)
        except md.PackageNotFoundError:
            out[name] = None
    return out


def collect_run_provenance(
    *, allow_dirty: bool = False, profile_dir: str | Path | None = None, model_path: str | Path | None = None,
    ml_enabled: bool | None = None, px4_git_describe: str | None = None, ardupilot_version: str | None = None,
    command_line: str | None = None, started_utc: str | None = None, repo: str | Path | None = None,
    extra: dict[str, Any] | None = None, start_state: dict[str, Any] | None = None,
    allowlist_path: str | Path | None = None,
) -> dict[str, Any]:
    """Manifest dict (schema ``aegisflight.run_manifest/1``). Raises ``DirtyTreeError`` on a dirty tree
    unless ``allow_dirty``. ``profile_dir`` ``None``/empty means the built-in ``configs/`` profile.
    ``ml_enabled`` defaults to ``model_path is not None``. ``ended_utc`` is ``None`` until :func:`finish_run`.

    ``start_state`` (from :func:`require_clean_tree` at the start of the run) is for a manifest built AFTER the run:
    the clean-tree check already happened, ``commit`` is the start commit, and a run that started dirty or whose
    commit / dirty state changed since is stamped NOT-REPRODUCIBLE with ``not_reproducible_reason``."""
    if start_state is not None:
        state, end = start_state, tree_state(repo)
    else:
        state = end = require_clean_tree(allow_dirty, repo)
    profile = Path(profile_dir) if profile_dir else Path("configs")
    allowlist = Path(allowlist_path) if allowlist_path else (profile / "firmware_allowlist.yaml")
    if not allowlist.is_file():
        fallback_al = Path("configs") / "firmware_allowlist.yaml"
        allowlist = fallback_al if fallback_al.is_file() else allowlist
    has_model = bool(model_path) and str(model_path).lower() != "none"
    model = Path(model_path) if has_model else None
    reproducible = True  # _apply_drift below clears it for a dirty or changed tree, with the reason
    manifest: dict[str, Any] = {
        "schema": SCHEMA_ID,
        "status": REPRODUCIBLE if reproducible else NOT_REPRODUCIBLE,
        "reproducible": reproducible,
        "commit": state["commit"],
        "working_tree_dirty": state["dirty"],
        "dirty_paths": state["dirty_paths"],
        "detector_profile_dir": str(profile).replace("\\", "/"),
        "detector_profile_sha256": sha256_dir(profile),
        "firmware_allowlist_sha256": sha256_file(allowlist) if allowlist.is_file() else None,
        "model_path": str(model).replace("\\", "/") if model else "none",
        "model_sha256": sha256_file(model) if model and model.exists() else None,
        "ml_enabled": has_model if ml_enabled is None else bool(ml_enabled),
        "px4_git_describe": px4_git_describe,
        "ardupilot_version": ardupilot_version,
        "python": sys.version.split()[0],
        "packages": _package_versions(),
        "command_line": command_line if command_line is not None else " ".join(sys.argv),
        "started_utc": started_utc or datetime.now(UTC).isoformat(),
        "ended_utc": None,
        "not_reproducible_reason": None,
    }
    if extra:  # before the drift check: extra fields can never overwrite the reproducibility stamp
        manifest.update({k: v for k, v in extra.items() if k not in _STAMP_KEYS})
    _apply_drift(manifest, state, end)
    return manifest


begin_run = collect_run_provenance


def finish_run(manifest: dict[str, Any], repo: str | Path | None = None) -> dict[str, Any]:
    """Stamp ``ended_utc`` (UTC now) on a manifest from :func:`collect_run_provenance` and re-check the tree: a
    commit or dirty-state change since the manifest was taken makes it NOT-REPRODUCIBLE (reason recorded).
    ``repo`` must be the one the manifest was collected with (default: the running code's checkout)."""
    manifest["ended_utc"] = datetime.now(UTC).isoformat()
    start = {"commit": manifest.get("commit"), "dirty": bool(manifest.get("working_tree_dirty")),
             "dirty_paths": list(manifest.get("dirty_paths") or ())}
    _apply_drift(manifest, start, tree_state(repo))
    return manifest


def stamp_run_dir(run_dir: str | Path, reproducible: bool) -> Path | None:
    """Mark a run directory: writes a ``NOT-REPRODUCIBLE`` marker file when not reproducible, and removes a
    stale one when it is. Returns the marker path (or ``None`` when reproducible)."""
    d = Path(run_dir)
    d.mkdir(parents=True, exist_ok=True)
    marker = d / NOT_REPRODUCIBLE
    if reproducible:
        marker.unlink(missing_ok=True)
        return None
    marker.write_text("This run is not reproducible (dirty or changed working tree); see run_manifest.json "
                      "not_reproducible_reason and dirty_paths.\n", encoding="utf-8")
    return marker


def stamp_stem(stem: str | Path, manifest: dict[str, Any]) -> Path | None:
    """Stem-style outputs (``<stem>.*``): ``<stem>.NOT-REPRODUCIBLE`` marker when the run was not reproducible."""
    marker = Path(f"{stem}.{NOT_REPRODUCIBLE}")
    if manifest.get("reproducible", True):
        return None
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("This run is not reproducible (dirty or changed working tree); see the manifest "
                      "not_reproducible_reason and dirty_paths.\n", encoding="utf-8")
    return marker


def write_manifest(run_dir: str | Path, manifest: dict[str, Any], name: str = MANIFEST_NAME) -> Path:
    """Write ``<run_dir>/run_manifest.json`` and stamp the directory per ``manifest['reproducible']``."""
    d = Path(run_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / name
    path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
    stamp_run_dir(d, bool(manifest.get("reproducible", False)))
    return path
