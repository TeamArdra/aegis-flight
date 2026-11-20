"""scripts/sweep_link_stress.py (issue #27 tooling): grid expansion, alert events, dominant evidence, manifest, determinism."""

from __future__ import annotations

import csv
import gzip
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import sweep_link_stress as sw  # noqa: E402
from aegisflight import run_provenance  # noqa: E402

TINY = ["--loss", "0", "--ordering", "fifo", "--ml", "off", "--profiles", "stage1", "--sessions", "1",
        "--duration-s", "12", "--allow-dirty"]


def _run(out: Path, *extra: str) -> int:
    return sw.main([*TINY, *extra, "--out", str(out)])


def _summary(out: Path) -> list[dict]:
    with open(out / "cell_summary.csv", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def test_full_grid_defaults_match_issue_27() -> None:
    cells = sw.expand_grid(sw.DEFAULT_LOSS, sw.ORDERINGS, sw.ML_MODES, list(sw.PROFILES))
    assert len(cells) == 5 * 2 * 2 * 3 == 60
    assert len({c.cid for c in cells}) == 60
    assert sw.DEFAULT_LOSS == (0.0, 1.0, 2.0, 5.0, 10.0)
    assert sw.build_parser().parse_args([]).sessions == 6


def test_grid_order_is_independent_of_argv_order_and_deduplicated() -> None:
    a = sw.expand_grid([5, 0, 5], ["reorder", "fifo"], ["on", "off"], ["px4", "stage1"])
    b = sw.expand_grid([0, 5], ["fifo", "reorder"], ["off", "on"], ["stage1", "px4"])
    assert a == b and len(a) == 16
    assert a[0].cid == "stage1/fifo/loss0/ml_off"


def test_ml_on_without_a_model_is_na_with_a_reason() -> None:
    models = {"stage1": "s.joblib", "px4": "p.joblib", "ardupilot": None}
    assert sw.resolve_model(sw.Cell("ardupilot", "fifo", 0.0, "on"), models) == (None, sw.NA_NO_MODEL)
    assert sw.resolve_model(sw.Cell("ardupilot", "fifo", 0.0, "off"), models) == (None, None)
    assert sw.resolve_model(sw.Cell("px4", "fifo", 0.0, "on"), models) == ("p.joblib", None)
    assert sw.resolve_model(sw.Cell("stage1", "fifo", 0.0, "on"), models) == ("s.joblib", None)
    assert sw.DEFAULT_MODELS["px4"] == "models/isoforest_px4.joblib"  # never the Stage-1 model (B2 cross-pairing)


def test_alert_events_are_maximal_runs() -> None:
    f, t = False, True
    assert sw.count_alert_events([]) == 0
    assert sw.count_alert_events([f, f]) == 0
    assert sw.count_alert_events([t]) == 1
    assert sw.count_alert_events([t, t, t]) == 1
    assert sw.count_alert_events([t, f, t]) == 2
    assert sw.count_alert_events([f, t, t, f, f, t, f, t, t, t]) == 3


def test_summary_runs_do_not_span_sessions_and_unscored_rows_are_ignored() -> None:
    def row(alarm: bool, scored: bool = True, key: str = "") -> dict:
        return {"scored": scored, "alarm": alarm, "evidence_key": key, "detectors": "protocol_rule" if alarm else ""}

    s1 = {"rows": [row(True, False, "warm"), row(True, key="k1"), row(False), row(True, key="k1 | k2")],
          "decision_period_s": 0.2}
    s2 = {"rows": [row(True, key="k2"), row(True, key="k2")], "decision_period_s": 0.2}
    r = sw.summarise_cell(sw.Cell("stage1", "fifo", 2.0, "off"), None, [s1, s2])
    assert (r["scored_decisions"], r["alarm_decisions"], r["alert_events"]) == (5, 4, 3)  # s1's end run, s2's run: distinct
    assert r["sessions_with_alarm"] == 2
    assert r["decision_fpr"] == "0.8000"
    assert r["observed_hours"] == f"{5 * 0.2 / 3600:.4f}"
    assert float(r["alert_events_per_hour"]) == pytest.approx(3 / (5 * 0.2 / 3600), abs=0.1)
    assert (r["dominant_evidence"], r["dominant_evidence_count"]) == ("k2", 3)
    assert r["dominant_detector"] == "protocol_rule" and r["model"] == "none"


def test_dominant_evidence_selection_and_normalisation() -> None:
    assert sw.dominant_evidence([]) == ("-", 0)
    assert sw.dominant_evidence([["b", "b"], ["a"]]) == ("a", 1)  # counted once per decision; tie -> alphabetical
    assert sw.dominant_evidence([["b", "b"], ["a"], ["a", "b"]]) == ("a", 2)
    assert sw.dominant_evidence([["x"], ["y"], ["y"]]) == ("y", 2)
    keys = sw.evidence_keys(["sequence gap 12 > 3", "coverage: no ATTITUDE seen",
                             "ML anomaly score 0.91 ≥ 0.62 (driver: a, z=-3.2)"])
    assert keys == ["sequence gap # > #", "ML anomaly score # ≥ # (driver: a, z=#)"]


def test_session_params_are_stable_and_paired_across_cells() -> None:
    assert sw.session_params(70_000, 3) == sw.session_params(70_000, 3)
    assert sw.session_params(70_000, 0)["seed"] == 70_000 and sw.session_params(70_000, 4)["seed"] == 70_004
    assert sw.session_params(70_000, 1) != sw.session_params(70_000, 2)
    p = sw.session_params(1, 0)
    assert 8 <= p["speed"] <= 16 and 35 <= p["alt"] <= 90 and 0.7 <= p["noise_scale"] <= 1.6


def test_tiny_run_outputs_manifest_and_decisions(tmp_path: Path) -> None:
    out = tmp_path / "o"
    assert _run(out) == 0
    rows = _summary(out)
    assert len(rows) == 1 and rows[0]["status"] == "ok" and rows[0]["sessions"] == "1" and rows[0]["ml"] == "off"
    with gzip.open(out / "decisions.csv.gz", "rt", encoding="utf-8", newline="") as f:
        dec = list(csv.DictReader(f))
    assert list(dec[0]) == sw.DECISION_FIELDS and len(dec) > 20
    assert {d["scored"] for d in dec} == {"True", "False"}  # warm-up decisions are present but unscored
    assert (out / "sweep_table.md").read_text(encoding="utf-8").count("Alert event") == 1

    m = json.loads((out / run_provenance.MANIFEST_NAME).read_text(encoding="utf-8"))
    for k in run_provenance.MANIFEST_FIELDS:
        assert k in m, k
    assert m["environment"] == "SIM" and m["schema"] == run_provenance.SCHEMA_ID
    assert m["seeds"] == [sw.SEED0] and m["sessions_per_cell"] == 1 and m["grid"] == ["stage1/fifo/loss0/ml_off"]
    assert m["cli_args"]["allow_dirty"] is True and "--out" in m["command_line"]
    assert m["commit"] and isinstance(m["working_tree_dirty"], bool) and m["python"] and m["packages"]["numpy"]
    assert m["profiles"]["stage1"]["sha256"] and m["models"] == {} and m["ml_enabled"] is False
    assert "alert_event" in m["definitions"]


def test_manifest_records_model_sha256_for_ml_on(tmp_path: Path) -> None:
    model = ROOT / "models" / "isoforest.joblib"
    if not model.exists():
        pytest.skip("models/isoforest.joblib is gitignored and absent")
    out = tmp_path / "o"
    assert sw.main(["--loss", "0", "--ordering", "fifo", "--ml", "on", "--profiles", "stage1", "ardupilot",
                    "--sessions", "1", "--duration-s", "12", "--allow-dirty", "--out", str(out)]) == 0
    m = json.loads((out / "run_manifest.json").read_text(encoding="utf-8"))
    assert m["models"]["stage1"]["sha256"] == run_provenance.sha256_file(model) and m["ml_enabled"] is True
    assert list(m["na_cells"]) == ["ardupilot/fifo/loss0/ml_on"]
    by = {(r["profile"], r["ml"]): r for r in _summary(out)}
    assert by[("ardupilot", "on")]["status"] == "n/a" and by[("stage1", "on")]["status"] == "ok"


def test_same_seed_gives_identical_outputs_and_different_seed_differs(tmp_path: Path) -> None:
    a, b, c = tmp_path / "a", tmp_path / "b", tmp_path / "c"
    args = ["--loss", "5", "--ordering", "reorder", "--ml", "off", "--profiles", "stage1", "--sessions", "2",
            "--duration-s", "15", "--allow-dirty", "--seed", "4242"]
    assert sw.main([*args, "--out", str(a)]) == 0 and sw.main([*args, "--out", str(b)]) == 0
    for name in ("decisions.csv.gz", "cell_summary.csv", "sweep_table.md"):
        assert (a / name).read_bytes() == (b / name).read_bytes(), name
    assert sw.main([*args[:-1], "4343", "--out", str(c)]) == 0
    assert (a / "decisions.csv.gz").read_bytes() != (c / "decisions.csv.gz").read_bytes()


def test_cli_subset_selection_and_loss_ordering_are_applied(tmp_path: Path) -> None:
    out = tmp_path / "o"
    assert sw.main(["--loss", "0", "10", "--ordering", "reorder", "--ml", "off", "--profiles", "stage1", "--sessions", "1",
                    "--duration-s", "12", "--allow-dirty", "--out", str(out)]) == 0
    rows = _summary(out)
    assert [(r["ordering"], r["loss_pct"], r["ml"]) for r in rows] == [("reorder", "0", "off"), ("reorder", "10", "off")]
    # reorder fires the protocol sequence-gap rule even without loss (the 2026-11-17 audit probe's finding, ML off)
    assert int(rows[0]["alarm_decisions"]) > 0 and "sequence gap" in rows[0]["dominant_evidence"]


def test_refuses_dirty_tree_without_flag_and_does_not_overwrite(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(run_provenance, "tree_state",
                        lambda repo=None: {"commit": "c" * 40, "dirty": True, "dirty_paths": ["src/x.py"]})
    out = tmp_path / "o"
    with pytest.raises(run_provenance.DirtyTreeError):
        sw.main([*[a for a in TINY if a != "--allow-dirty"], "--out", str(out)])
    assert not out.exists()
    assert _run(out) == 0
    assert (out / "NOT-REPRODUCIBLE").exists()
    assert _run(out) == 2  # existing output is never silently overwritten


def test_missing_model_for_ml_on_is_an_error_not_a_silent_ml_off(tmp_path: Path) -> None:
    rc = sw.main(["--loss", "0", "--ordering", "fifo", "--ml", "on", "--profiles", "stage1", "--sessions", "1",
                  "--allow-dirty", "--model-stage1", str(tmp_path / "nope.joblib"), "--out", str(tmp_path / "o")])
    assert rc == 2
