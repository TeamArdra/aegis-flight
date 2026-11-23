"""Issue #25: dirty-tree refusal, NOT-REPRODUCIBLE stamping, manifest schema. Uses throwaway git repos."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "sitl"))

import provenance as prov  # noqa: E402


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=repo, check=True,
                   capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    (r / "configs").mkdir(parents=True)
    (r / "src").mkdir()
    (r / "configs" / "detector.yaml").write_text("a: 1\n")
    (r / "src" / "m.py").write_text("x = 1\n")
    _git(r, "init", "-q")
    _git(r, "add", ".")
    _git(r, "commit", "-q", "-m", "init")
    return r


def test_clean_tree_passes(repo: Path) -> None:
    st = prov.require_clean_tree(False, repo)
    assert st["dirty"] is False and st["dirty_paths"] == [] and len(st["commit"]) == 40


def test_dirty_tracked_file_refused(repo: Path) -> None:
    (repo / "src" / "m.py").write_text("x = 2\n")
    with pytest.raises(prov.DirtyTreeError) as ei:
        prov.require_clean_tree(False, repo)
    assert ei.value.code == 2 and "src/m.py" in str(ei.value) and "--allow-dirty" in str(ei.value)
    assert ei.value.paths == ["src/m.py"]


def test_untracked_code_file_refused_but_untracked_output_dir_is_not_dirt(repo: Path) -> None:
    (repo / "artifacts" / "run1").mkdir(parents=True)
    (repo / "artifacts" / "run1" / "frames.jsonl").write_text("{}\n")
    assert prov.require_clean_tree(False, repo)["dirty"] is False
    (repo / "scripts").mkdir()
    (repo / "scripts" / "new.py").write_text("")
    with pytest.raises(prov.DirtyTreeError):
        prov.require_clean_tree(False, repo)


def test_allow_dirty_stamps_dir_and_manifest(repo: Path, tmp_path: Path) -> None:
    (repo / "src" / "m.py").write_text("x = 2\n")
    m = prov.collect_run_provenance(allow_dirty=True, profile_dir=repo / "configs", repo=repo)
    assert m["status"] == "NOT-REPRODUCIBLE" and m["reproducible"] is False
    assert m["working_tree_dirty"] is True and m["dirty_paths"] == ["src/m.py"]
    out = tmp_path / "run"
    path = prov.write_manifest(out, prov.finish_run(m, repo))
    assert path == out / "run_manifest.json"
    assert (out / "NOT-REPRODUCIBLE").is_file()
    assert json.loads(path.read_text())["status"] == "NOT-REPRODUCIBLE"
    stem = tmp_path / "trial_001"
    assert prov.stamp_stem(stem, m) == Path(f"{stem}.NOT-REPRODUCIBLE") and Path(f"{stem}.NOT-REPRODUCIBLE").is_file()


def test_clean_run_not_stamped_and_stale_marker_removed(repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "run"
    prov.stamp_run_dir(out, reproducible=False)
    assert (out / "NOT-REPRODUCIBLE").exists()
    m = prov.collect_run_provenance(profile_dir=repo / "configs", repo=repo)
    prov.write_manifest(out, m)
    assert not (out / "NOT-REPRODUCIBLE").exists() and m["status"] == "REPRODUCIBLE"
    assert prov.stamp_stem(tmp_path / "t", m) is None


def test_manifest_schema_every_field(repo: Path, tmp_path: Path) -> None:
    model = tmp_path / "m.joblib"
    model.write_bytes(b"model-bytes")
    m = prov.finish_run(prov.collect_run_provenance(
        profile_dir=repo / "configs", model_path=model, px4_git_describe="v1.15.0-12-gabc",
        ardupilot_version="ArduCopter V4.5.7", command_line="run.py --x", repo=repo), repo)
    assert set(m) == set(prov.MANIFEST_FIELDS)
    assert m["schema"] == "aegisflight.run_manifest/1" == prov.SCHEMA_ID
    assert len(m["commit"]) == 40 and m["working_tree_dirty"] is False and m["dirty_paths"] == []
    assert m["detector_profile_dir"].endswith("configs") and len(m["detector_profile_sha256"]) == 64
    assert m["model_path"].endswith("m.joblib") and m["model_sha256"] == prov.sha256_file(model)
    assert m["firmware_allowlist_sha256"] is None or len(m["firmware_allowlist_sha256"]) == 64
    assert m["ml_enabled"] is True
    assert m["px4_git_describe"] == "v1.15.0-12-gabc" and m["ardupilot_version"] == "ArduCopter V4.5.7"
    assert m["python"].count(".") == 2 and "numpy" in m["packages"] and "pymavlink" in m["packages"]
    assert m["command_line"] == "run.py --x"
    assert m["started_utc"].endswith("+00:00") and m["ended_utc"].endswith("+00:00")
    assert m["started_utc"] <= m["ended_utc"]
    json.dumps(m)


def test_no_model_is_recorded_as_none(repo: Path) -> None:
    for arg in (None, "none"):
        m = prov.collect_run_provenance(profile_dir=repo / "configs", model_path=arg, repo=repo)
        assert m["model_path"] == "none" and m["model_sha256"] is None and m["ml_enabled"] is False
        assert m["ended_utc"] is None


def test_profile_hash_changes_with_content(repo: Path) -> None:
    a = prov.sha256_dir(repo / "configs")
    (repo / "configs" / "detector.yaml").write_text("a: 2\n")
    assert prov.sha256_dir(repo / "configs") != a
    assert prov.sha256_dir(repo / "nope") is None


def test_add_provenance_args_defines_allow_dirty() -> None:
    ap = argparse.ArgumentParser()
    prov.add_provenance_args(ap)
    assert ap.parse_args([]).allow_dirty is False and ap.parse_args(["--allow-dirty"]).allow_dirty is True


def test_legacy_collect_still_works() -> None:
    d = prov.collect()
    assert {"aegisflight_commit", "working_tree_dirty", "python", "configs_sha256"} <= set(d)


# -- PR #50 security review: tree state is taken at the START and re-checked at the end ----------------------- #


def test_run_started_dirty_then_cleaned_is_not_reproducible(repo: Path) -> None:
    (repo / "src" / "m.py").write_text("x = 2\n")
    start = prov.require_clean_tree(True, repo)
    _git(repo, "checkout", "--", "src/m.py")  # cleaned before the run ends
    m = prov.finish_run(prov.collect_run_provenance(allow_dirty=True, profile_dir=repo / "configs", repo=repo,
                                                    start_state=start), repo)
    assert m["status"] == "NOT-REPRODUCIBLE" and m["reproducible"] is False
    assert "dirty at run start" in m["not_reproducible_reason"] and m["dirty_paths"] == ["src/m.py"]


def test_commit_made_during_the_run_is_not_reproducible_and_keeps_start_commit(repo: Path) -> None:
    start = prov.require_clean_tree(False, repo)
    (repo / "src" / "m.py").write_text("x = 3\n")
    _git(repo, "commit", "-q", "-am", "mid-run")
    m = prov.collect_run_provenance(profile_dir=repo / "configs", repo=repo, start_state=start)
    assert m["status"] == "NOT-REPRODUCIBLE" and m["commit"] == start["commit"]
    assert "commit changed during the run" in m["not_reproducible_reason"]


def test_finish_run_rechecks_a_manifest_taken_at_start(repo: Path) -> None:
    m = prov.begin_run(profile_dir=repo / "configs", repo=repo)
    assert m["status"] == "REPRODUCIBLE" and m["not_reproducible_reason"] is None
    (repo / "src" / "m.py").write_text("x = 4\n")
    prov.finish_run(m, repo)
    assert m["status"] == "NOT-REPRODUCIBLE" and "became dirty during the run" in m["not_reproducible_reason"]


def test_clean_unchanged_run_stays_reproducible(repo: Path) -> None:
    start = prov.require_clean_tree(False, repo)
    m = prov.finish_run(prov.collect_run_provenance(profile_dir=repo / "configs", repo=repo, start_state=start), repo)
    assert m["status"] == "REPRODUCIBLE" and m["not_reproducible_reason"] is None


def test_tree_state_ignores_cwd_and_uses_the_running_code(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    foreign = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
    monkeypatch.chdir(repo)  # a clean one-commit repo that is NOT the code's checkout
    st = prov.tree_state()
    assert st["commit"] != foreign
    assert prov.collect_run_provenance(allow_dirty=True)["commit"] != foreign


def test_not_running_from_a_checkout_is_never_reproducible(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisflight import run_provenance as rp

    fake = tmp_path / "site-packages" / "aegisflight" / "run_provenance.py"
    fake.parent.mkdir(parents=True)
    monkeypatch.setattr(rp, "__file__", str(fake))
    assert rp.code_repo() is None
    st = rp.tree_state()
    assert st["dirty"] is True and st["commit"] == "unknown"


def test_dirty_tree_exits_with_status_2_and_prints_the_reason(repo: Path, capsys: pytest.CaptureFixture) -> None:
    (repo / "src" / "m.py").write_text("x = 2\n")
    with pytest.raises(SystemExit) as ei:
        prov.require_clean_tree(False, repo)
    assert ei.value.code == 2
    assert "src/m.py" in capsys.readouterr().err


# ---- re-review F1 / F3 (PR #50) -------------------------------------------------------------------------------- #

def _not_in_git_checkout() -> bool:
    from aegisflight import run_provenance as rp

    return rp.code_repo() is None


needs_git_checkout = pytest.mark.skipif(
    _not_in_git_checkout(),
    reason="needs the test session to run from a git checkout; an extracted archive is not one",
)


@needs_git_checkout
def test_entry_script_from_another_checkout_is_not_judged_by_the_package_checkout(tmp_path: Path, monkeypatch) -> None:
    """A script run from checkout A while ``aegisflight`` is imported from checkout B must not get B's commit."""
    import types

    from aegisflight import run_provenance as rp

    other = tmp_path / "other"
    other.mkdir()
    subprocess.run(["git", "init", "-q", str(other)], check=True)
    script = other / "trial.py"
    script.write_text("x = 1\n")
    assert rp.code_repo() is not None  # this test session runs from a checkout
    monkeypatch.setitem(sys.modules, "__main__", types.SimpleNamespace(__file__=str(script)))
    assert rp.code_repo() is None
    assert rp.tree_state()["dirty"] is True  # cannot be proved clean -> never REPRODUCIBLE


@needs_git_checkout
def test_entry_script_inside_the_package_checkout_is_accepted(monkeypatch) -> None:
    import types

    from aegisflight import run_provenance as rp

    repo = rp.code_repo()
    assert repo is not None
    monkeypatch.setitem(sys.modules, "__main__", types.SimpleNamespace(__file__=str(repo / "scripts" / "x.py")))
    assert rp.code_repo() == repo


def test_extra_fields_cannot_overwrite_the_reproducibility_stamp(monkeypatch) -> None:
    from aegisflight import run_provenance as rp

    dirty = {"commit": "abc", "dirty": True, "dirty_paths": ["src/x.py"]}
    monkeypatch.setattr(rp, "tree_state", lambda repo=None: dirty)
    m = rp.collect_run_provenance(allow_dirty=True, start_state=dirty,
                                  extra={"reproducible": True, "status": "REPRODUCIBLE", "note": "kept"})
    assert m["reproducible"] is False and m["status"] != "REPRODUCIBLE" and m["note"] == "kept"
