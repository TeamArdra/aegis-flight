"""Issue #25: campaign runner -- fixed seeds, n per scenario, resume, failures reported. Uses a stub driver, no SITL."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "sitl"))

import run_campaign as rc  # noqa: E402

from aegisflight import run_provenance  # noqa: E402

STUB = '''
import json, sys
a = sys.argv[1:]
get = lambda k: a[a.index(k) + 1]
out = get("--out")
if "--fail-index" in a and int(get("--trial-index")) == int(get("--fail-index")):
    sys.exit(3)
open(out + ".manifest.json", "w").write(json.dumps({"seed": int(get("--seed")), "index": int(get("--trial-index")),
                                                    "allow_dirty": "--allow-dirty" in a}))
'''


@pytest.fixture
def stub(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    drv = tmp_path / "stub_driver.py"
    drv.write_text(STUB)
    monkeypatch.setattr(run_provenance, "tree_state",
                        lambda repo=None: {"commit": "a" * 40, "dirty": False, "dirty_paths": []})
    scen = tmp_path / "scen.json"

    def write(*extra_args: str) -> str:
        scen.write_text(json.dumps([
            {"name": "s_one", "kind": "command", "seed": 11, "cmd": [sys.executable, str(drv), "--seed", "{seed}",
             "--trial-index", "{index}", "--out", "{out}", *extra_args]},
            {"name": "s_two", "kind": "command", "seed": 22, "cmd": [sys.executable, str(drv), "--seed", "{seed}",
             "--trial-index", "{index}", "--out", "{out}"]}]))
        return str(scen)
    return write


def _only(extra: str, root: Path, *more: str) -> list[str]:
    return ["--out-root", str(root), "--scenarios-file", extra, "--only", "s_one", "--only", "s_two", "--no-sitl-restart", *more]


def test_fixed_seeds_n_per_scenario_and_manifest(tmp_path, stub):
    root = tmp_path / "c"
    assert rc.main(_only(stub(), root, "--n", "3")) == 0
    for name, seed in (("s_one", 11), ("s_two", 22)):
        ms = [json.loads((root / name / f"trial_{i:03d}.manifest.json").read_text()) for i in (1, 2, 3)]
        assert [m["seed"] for m in ms] == [seed] * 3 and [m["index"] for m in ms] == [0, 1, 2]
    cm = json.loads((root / "campaign_manifest.json").read_text())
    assert cm["schema"] == "aegisflight.run_manifest/1" and cm["ended_utc"] and cm["commit"] == "a" * 40
    summ = json.loads((root / "campaign_summary.json").read_text())
    assert summ["complete"] is True and all(r["n_completed"] == 3 for r in summ["scenarios"])


def test_resume_skips_done_and_reruns_failed_and_quarantines_partials(tmp_path, stub):
    root = tmp_path / "c"
    flaky = stub("--fail-index", "1")
    assert rc.main(_only(flaky, root, "--n", "3")) == 1  # trial 2 of s_one fails: reported, not dropped
    summ = json.loads((root / "campaign_summary.json").read_text())
    one = next(r for r in summ["scenarios"] if r["scenario"] == "s_one")
    assert one["n_completed"] == 2 and one["failed"][0]["index"] == 1 and summ["complete"] is False
    assert "driver exited 3" in (root / "campaign_summary.md").read_text()
    (root / "s_one" / "trial_002.frames.jsonl").write_text("{}\n")  # an interrupted attempt's leftover
    before = (root / "s_one" / "trial_001.manifest.json").stat().st_mtime_ns
    assert rc.main(_only(stub(), root, "--n", "3", "--resume")) == 0  # stub no longer fails
    assert (root / "s_one" / "trial_001.manifest.json").stat().st_mtime_ns == before  # untouched: skipped
    assert (root / "s_one" / "trial_002.manifest.json").exists()
    assert list((root / "s_one" / "_incomplete").rglob("trial_002.frames.jsonl"))  # moved, not deleted
    assert json.loads((root / "campaign_summary.json").read_text())["complete"] is True


def test_existing_campaign_needs_resume_and_commit_must_match(tmp_path, stub, monkeypatch, capsys):
    root = tmp_path / "c"
    assert rc.main(_only(stub(), root, "--n", "1")) == 0
    assert rc.main(_only(stub(), root, "--n", "1")) == 2 and "--resume" in capsys.readouterr().err
    monkeypatch.setattr(run_provenance, "tree_state",
                        lambda repo=None: {"commit": "b" * 40, "dirty": False, "dirty_paths": []})
    assert rc.main(_only(stub(), root, "--n", "1", "--resume")) == 2
    assert "two commits" in capsys.readouterr().err


def test_dirty_tree_refused_then_stamped_and_forwarded_to_children(tmp_path, stub, monkeypatch):
    monkeypatch.setattr(run_provenance, "tree_state",
                        lambda repo=None: {"commit": "a" * 40, "dirty": True, "dirty_paths": ["src/x.py"]})
    with pytest.raises(run_provenance.DirtyTreeError):
        rc.main(_only(stub(), tmp_path / "a", "--n", "1"))
    assert not (tmp_path / "a").exists()
    root = tmp_path / "b"
    assert rc.main(_only(stub(), root, "--n", "1", "--allow-dirty")) == 0
    assert (root / "NOT-REPRODUCIBLE").is_file()
    assert json.loads((root / "campaign_manifest.json").read_text())["status"] == "NOT-REPRODUCIBLE"
    assert json.loads((root / "s_one" / "trial_001.manifest.json").read_text())["allow_dirty"] is True


def test_builtin_scenarios_use_existing_drivers_and_fixed_seeds(capsys):
    assert rc.main(["--out-root", "x", "--n", "2", "--list"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2 * len(rc.BUILTIN)
    assert "--seed 1001 --trial-index 0 --out" in lines[0] and "--trial-index 1" in lines[1]
    for sc in rc.BUILTIN:
        assert (rc.REPO / sc.script).is_file(), sc.script
    assert len({s.name for s in rc.BUILTIN}) == len(rc.BUILTIN)


def test_resume_cannot_launder_a_dirty_campaign_into_reproducible(tmp_path, stub, monkeypatch, capsys):
    """R2: same HEAD, dirty at start, clean at resume -> refused; the NOT-REPRODUCIBLE stamp stays."""
    root = tmp_path / "c"
    dirty = {"commit": "a" * 40, "dirty": True, "dirty_paths": ["src/x.py"]}
    monkeypatch.setattr(run_provenance, "tree_state", lambda repo=None: dirty)
    assert rc.main(_only(stub(), root, "--n", "1", "--allow-dirty")) == 0
    assert json.loads((root / "campaign_state.json").read_text())["reproducible"] is False
    monkeypatch.setattr(run_provenance, "tree_state",
                        lambda repo=None: {"commit": "a" * 40, "dirty": False, "dirty_paths": []})
    assert rc.main(_only(stub(), root, "--n", "2", "--resume")) == 2
    assert "NOT-REPRODUCIBLE" in capsys.readouterr().err
    assert (root / "NOT-REPRODUCIBLE").is_file()
    assert json.loads((root / "campaign_manifest.json").read_text())["status"] == "NOT-REPRODUCIBLE"
    assert not (root / "s_one" / "trial_002.manifest.json").exists()  # nothing was run
    monkeypatch.setattr(run_provenance, "tree_state", lambda repo=None: dirty)
    assert rc.main(_only(stub(), root, "--n", "2", "--resume", "--allow-dirty")) == 0  # dirty resume stays stamped
    assert (root / "NOT-REPRODUCIBLE").is_file()
