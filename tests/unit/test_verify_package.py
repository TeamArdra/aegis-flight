"""Tests for scripts/submission/verify_package.py (issues #34, #33): one passing package and one case per failure kind.

Every package is built in ``tmp_path``; nothing here touches the repository's artifacts, and the verifier is offline.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = REPO_ROOT / "scripts" / "submission" / "verify_package.py"
_spec = importlib.util.spec_from_file_location("verify_package", _SCRIPT)
vp = importlib.util.module_from_spec(_spec)
sys.modules["verify_package"] = vp
_spec.loader.exec_module(vp)

JUNIT_OK = '<testsuites><testsuite name="pytest" tests="3" failures="0" errors="0" skipped="1"/></testsuites>'
REPORT_OK = """# Report

## Results

The benchmark reached accuracy 0.9971 on SIM (`artifacts/benchmarks_extended/summary.md`), a recall of 99.7%
and 10/10 drift detections (artifacts/sitl/final_x/px4_drift/trial_001.json). See Section 5.3 and Figure 4;
PX4 v1.18.0-rc1 was used on 2026-11-27, issue #34.

| Metric | Value | Source |
|---|---|---|
| Total decisions | 23,430 | artifacts/benchmarks_extended/summary.md |

```
aegis benchmark --seed 123456
```
"""
FILES = {
    "README.md": "# AegisFlight submission\n",
    "INSTALL.md": "# Install\n",
    "REPRODUCE.md": "\n".join(
        [f"# Reproduce\n\n## {t}\n\n```\ncommand for {t}\n```\n" for t in
         ("Walk test", "Pi run", "Link-stress sweep", "Restricted-visibility injection",
          "Telemetry SITL", "Firmware SITL")]),
    "report/report.pdf": "%PDF-1.4 stand-in\n",
    "report/report.md": REPORT_OK,
    "video/demo.mp4": "not a real video\n",
    "models/MODELS.sha256": f"{'ab' * 32}  isoforest.joblib\n",
    "results/validation/junit.xml": JUNIT_OK,
    "artifacts/sitl/final_x/px4_drift/trial_001.json": '{"detected": "10/10", "recall": 0.997}\n',
    "artifacts/sitl/final_x/bridge/frames_down.jsonl": '{"n": 1}\n',
    "artifacts/validation/final_x/link_stress/sweep_table.md": "| cell |\n",
    "artifacts/benchmarks_extended/summary.md": "accuracy 0.9971\ndecisions 23430\n",
    "artifacts/validation/stage2_metrics_t/metrics.json": "{}\n",
    "artifacts/hardware/companion_pi_x/paced.json": "{}\n",
    "artifacts/hardware/walk_x/captures.sha256": f"{'cd' * 32}  walk_001.tlog\n",
}


def write(root: Path, rel: str, text: str | bytes) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, str):
        p.write_text(text, encoding="utf-8", newline="\n")
    else:
        p.write_bytes(text)
    return p


def write_manifest(root: Path) -> None:
    lines = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_file() and rel not in vp.MANIFEST_NAMES:
            lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {rel}")
    (root / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


@pytest.fixture
def pkg(tmp_path: Path) -> Path:
    root = tmp_path / "package"
    for rel, text in FILES.items():
        write(root, rel, text)
    write_manifest(root)
    return root


def run(root: Path, **kw):
    return vp.verify(root, **kw)


def messages(res, check: str, kind: str = "failures") -> list[str]:
    return getattr(res, kind).get(check, [])


# --- the passing case ------------------------------------------------------------------------------------------

def test_clean_package_passes(pkg, capsys):
    res = run(pkg)
    assert res.failures == {}
    assert res.warnings == {}
    assert vp.main([str(pkg)]) == 0
    out = capsys.readouterr().out
    assert "-> OK" in out and "FAIL" not in out.replace("0 failure(s)", "")


def test_not_a_directory_is_usage_error(tmp_path, capsys):
    assert vp.main([str(tmp_path / "missing")]) == 2
    assert "not a directory" in capsys.readouterr().err


# --- required files --------------------------------------------------------------------------------------------

@pytest.mark.parametrize("rel,ident", [
    ("README.md", "readme"), ("INSTALL.md", "install"), ("REPRODUCE.md", "reproduce"),
    ("report/report.pdf", "report"), ("video/demo.mp4", "video"), ("models/MODELS.sha256", "model-hashes"),
    ("results/validation/junit.xml", "junit"), ("artifacts/sitl/final_x/bridge/frames_down.jsonl", "bridge-raw-logs"),
    ("artifacts/hardware/walk_x/captures.sha256", "capture-hashes"),
    ("artifacts/hardware/companion_pi_x/paced.json", "pi-run"),
    ("artifacts/validation/stage2_metrics_t/metrics.json", "stage2-metrics"),
])
def test_missing_required_file(pkg, rel, ident):
    (pkg / rel).unlink()
    write_manifest(pkg)
    found = messages(run(pkg), "required")
    assert any(f"[{ident}]" in m for m in found), found


def test_video_link_satisfies_video(pkg):
    (pkg / "video/demo.mp4").unlink()
    write(pkg, "video/VIDEO_LINK.txt", "https://example.invalid/video\n")
    write_manifest(pkg)
    assert messages(run(pkg), "required") == []


def test_checksums_name_from_issue_is_accepted(pkg):
    (pkg / "MANIFEST.sha256").rename(pkg / "CHECKSUMS.sha256")
    assert run(pkg).failures == {}


# --- manifest --------------------------------------------------------------------------------------------------

def test_manifest_hash_mismatch(pkg):
    (pkg / "report/report.pdf").write_text("tampered\n", encoding="utf-8")
    found = messages(run(pkg), "manifest")
    assert any("SHA-256 mismatch: report/report.pdf" in m for m in found), found


def test_sha256sum_output_style_with_dot_slash_and_binary_marker(pkg):
    lines = []
    for p in sorted(pkg.rglob("*")):
        rel = p.relative_to(pkg).as_posix()
        if p.is_file() and rel != "MANIFEST.sha256":
            lines.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()} *./{rel}")
    (pkg / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    res = run(pkg)
    assert res.failures == {} and res.warnings == {}


def test_manifest_lists_missing_file(pkg):
    with (pkg / "MANIFEST.sha256").open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{'0' * 64}  results/gone.json\n")
    found = messages(run(pkg), "manifest")
    assert any("listed file is missing: results/gone.json" in m for m in found), found


def test_manifest_malformed_line(pkg):
    with (pkg / "MANIFEST.sha256").open("a", encoding="utf-8", newline="\n") as fh:
        fh.write("not a checksum line\n")
    assert any("not sha256sum format" in m for m in messages(run(pkg), "manifest"))


def test_manifest_path_escape_is_refused(pkg):
    outside = pkg.parent / "outside.txt"
    outside.write_text("secret\n", encoding="utf-8")
    digest = hashlib.sha256(outside.read_bytes()).hexdigest()
    with (pkg / "MANIFEST.sha256").open("a", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{digest}  ../outside.txt\n")
    assert any("escapes the package" in m for m in messages(run(pkg), "manifest"))


def test_missing_manifest(pkg):
    (pkg / "MANIFEST.sha256").unlink()
    found = messages(run(pkg), "manifest")
    assert any("no MANIFEST.sha256" in m for m in found)
    assert any("[manifest]" in m for m in messages(run(pkg), "required"))


def test_unlisted_file_warns_and_strict_fails(pkg, capsys):
    write(pkg, "extra.txt", "new\n")
    res = run(pkg)
    assert res.failures == {}
    assert any("not covered" in m and "extra.txt" in m for m in messages(res, "manifest", "warnings"))
    assert vp.main([str(pkg)]) == 0
    assert vp.main([str(pkg), "--strict"]) == 1
    assert "FAILED" in capsys.readouterr().out


def test_models_checksum_file_verified_when_model_present(pkg):
    write(pkg, "models/isoforest.joblib", b"model bytes")
    found = messages(run(pkg, allow=["models/*.joblib"]), "manifest")
    assert any("SHA-256 mismatch: isoforest.joblib" in m for m in found), found


# --- forbidden files -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("rel,why", [
    ("models/isoforest.joblib", "forbidden file"),
    ("artifacts/x/events.sqlite", "forbidden file"),
    ("data/hardware/raw/capture.tlog", "forbidden file"),
    ("data/capture.rawbin", "forbidden file"),
    ("keys/signing.key", "forbidden file"),
    (".env", "forbidden file"),
    (".claude/settings.local.json", "forbidden directory"),
    ("node_modules/pkg/index.js", "forbidden directory"),
    ("frontend/dist/index.html", "forbidden directory"),
    ("LOCAL_AEGISFLIGHT_END_TO_END.md", "forbidden file"),
])
def test_forbidden_files(pkg, rel, why):
    write(pkg, rel, "x\n")
    found = messages(run(pkg), "forbidden")
    assert any(why in m for m in found), found


def test_env_example_is_not_forbidden(pkg):
    write(pkg, ".env.example", "AEGIS_API_TOKEN=\n")
    assert messages(run(pkg), "forbidden") == []


def test_allow_pattern_lets_a_file_through(pkg):
    write(pkg, "models/isoforest.joblib", "x\n")
    assert messages(run(pkg, allow=["models/*.joblib"]), "forbidden") == []


def test_secret_content_is_found_and_never_printed(pkg, capsys):
    token = "ghp_" + "a1B2" * 9
    write(pkg, "notes/log.txt", f"line one\nuse {token} here\n")
    write_manifest(pkg)
    found = messages(run(pkg), "forbidden")
    assert any("notes/log.txt:2" in m and "GitHub token" in m for m in found), found
    assert vp.main([str(pkg)]) == 1
    assert token not in capsys.readouterr().out


def test_private_key_block_and_key_assignment(pkg):
    write(pkg, "a.txt", "-----BEGIN " + "OPENSSH PRIVATE KEY-----\nabc\n")
    write(pkg, "b.txt", "AEGIS_SIGNING_KEY=" + "Zm9vYmFyYmF6cXV4MTIzNDU2\n")
    found = messages(run(pkg), "forbidden")
    assert any("a.txt" in m and "private key" in m for m in found), found
    assert any("b.txt" in m and "assignment" in m for m in found), found


def test_symlink_is_forbidden(pkg):
    try:
        os.symlink(pkg / "README.md", pkg / "link.md")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available")
    assert any("symlink" in m for m in messages(run(pkg), "forbidden"))


# --- placeholders ----------------------------------------------------------------------------------------------

@pytest.mark.parametrize("word", ["AWAITING", "TODO", "TBD"])
def test_placeholders_in_readme_report_and_configs(pkg, word):
    write(pkg, "README.md", f"Team leader: {word}\n")
    write(pkg, "report/notes.md", f"{word} later\n")
    write(pkg, "configs/detector.yaml", f"# {word}\nkey: 1\n")
    found = messages(run(pkg), "placeholders")
    assert any(m.startswith("README.md:1") for m in found)
    assert any(m.startswith("report/notes.md:1") for m in found)
    assert any(m.startswith("configs/detector.yaml:1") for m in found)


def test_placeholders_elsewhere_are_not_scanned(pkg):
    write(pkg, "docs/notes.md", "TBD\n")
    write(pkg, "src/x.py", "# TODO\n")
    assert messages(run(pkg), "placeholders") == []
    assert messages(run(pkg, extra_scan=["docs/*"]), "placeholders") != []


# --- JUnit -----------------------------------------------------------------------------------------------------

def test_junit_failures_fail(pkg):
    write(pkg, "results/validation/junit.xml",
          '<testsuites><testsuite tests="3" failures="1" errors="0"/></testsuites>')
    assert any("1 failure(s)/error(s) of 3" in m for m in messages(run(pkg), "junit"))


def test_junit_errors_zero_tests_and_bare_testsuite(pkg):
    write(pkg, "results/validation/junit.xml", '<testsuite tests="2" failures="0" errors="2"/>')
    assert any("error" in m for m in messages(run(pkg), "junit"))
    write(pkg, "results/validation/junit.xml", '<testsuite tests="0" failures="0" errors="0"/>')
    assert any("0 tests" in m for m in messages(run(pkg), "junit"))
    write(pkg, "results/validation/junit.xml", '<testsuite tests="2" failures="0" errors="0"/>')
    assert messages(run(pkg), "junit") == []


def test_junit_invalid_and_dtd_refused(pkg):
    write(pkg, "results/validation/junit.xml", "<testsuites><oops")
    assert any("not valid XML" in m for m in messages(run(pkg), "junit"))
    write(pkg, "results/validation/junit.xml", '<!DOCTYPE x [<!ENTITY a "b">]><testsuite tests="1"/>')
    assert any("DTD" in m for m in messages(run(pkg), "junit"))
    write(pkg, "results/validation/junit.xml", "<html/>")
    assert any("not JUnit" in m for m in messages(run(pkg), "junit"))


# --- REPRODUCE.md ----------------------------------------------------------------------------------------------

def test_reproduce_missing_topic(pkg):
    text = FILES["REPRODUCE.md"].replace("## Firmware SITL", "## Something else")
    write(pkg, "REPRODUCE.md", text)
    assert any("firmware SITL" in m for m in messages(run(pkg), "reproduce"))


def test_reproduce_topic_without_command(pkg):
    text = FILES["REPRODUCE.md"].replace("```\ncommand for Pi run\n```", "see the report")
    write(pkg, "REPRODUCE.md", text)
    found = messages(run(pkg), "reproduce")
    assert any("Pi run" in m and "no code block" in m for m in found), found


def test_reproduce_not_run_statement_is_accepted(pkg):
    text = FILES["REPRODUCE.md"].replace("```\ncommand for Restricted-visibility injection\n```",
                                         "Descoped on 18 Nov; not run.")
    write(pkg, "REPRODUCE.md", text)
    assert messages(run(pkg), "reproduce") == []


# --- report numbers --------------------------------------------------------------------------------------------

def set_report(pkg: Path, text: str) -> None:
    write(pkg, "report/report.md", text)


def test_number_not_in_cited_artifact_fails(pkg):
    set_report(pkg, "Accuracy was 0.9999 (artifacts/benchmarks_extended/summary.md).\n")
    found = messages(run(pkg), "numbers")
    assert any("0.9999" in m and "not found" in m for m in found), found


def test_longer_number_does_not_match_a_prefix(pkg):
    # the artifact holds 0.9971; a report quoting 0.997 must not match it silently
    set_report(pkg, "Accuracy was 0.997 (artifacts/benchmarks_extended/summary.md).\n")
    assert any("0.997 not found" in m for m in messages(run(pkg), "numbers"))


def test_percent_matches_ratio_that_rounds_to_it(pkg):
    set_report(pkg, "Recall was 99.7% (artifacts/sitl/final_x/px4_drift/trial_001.json).\n")
    assert messages(run(pkg), "numbers") == []
    set_report(pkg, "Recall was 99.8% (artifacts/sitl/final_x/px4_drift/trial_001.json).\n")
    assert any("99.8%" in m for m in messages(run(pkg), "numbers"))


def test_thousands_separator_and_fraction(pkg):
    set_report(pkg, "There were 23,430 decisions (artifacts/benchmarks_extended/summary.md) "
                    "and 10/10 detections (artifacts/sitl/final_x/px4_drift/trial_001.json).\n")
    assert messages(run(pkg), "numbers") == []


def test_cited_artifact_missing_fails(pkg):
    set_report(pkg, "See artifacts/validation/does_not_exist/summary.md for details.\n")
    found = messages(run(pkg), "numbers")
    assert any("does not exist" in m and "does_not_exist" in m for m in found), found


def test_artifact_path_with_placeholder_fails(pkg):
    set_report(pkg, "Outputs are in artifacts/sitl/final_<tag>/ on the freeze commit.\n")
    assert any("unfilled placeholder" in m for m in messages(run(pkg), "numbers"))


def test_artifact_path_with_dotdot_is_not_followed(pkg):
    set_report(pkg, "Data: artifacts/../README.md\n")
    assert any("does not exist" in m for m in messages(run(pkg), "numbers"))


def test_glob_reference_and_directory_reference(pkg):
    set_report(pkg, "Accuracy 0.9971 (artifacts/benchmarks_*/summary.md); decisions 23430 (artifacts/benchmarks_extended).\n")
    assert messages(run(pkg), "numbers") == []


def test_unsourced_number_warns_but_does_not_fail(pkg):
    set_report(pkg, "The latency was 12.5 ms on the Pi.\n")
    res = run(pkg)
    assert messages(res, "numbers") == []
    assert any("unsourced number 12.5" in m for m in messages(res, "numbers", "warnings"))
    assert vp.main([str(pkg), "--strict"]) == 1


def test_table_row_without_source_inherits_the_tables(pkg):
    set_report(pkg, "| Metric | Value |\n|---|---|\n| Decisions | 23,430 |\n"
                    "| Source | artifacts/benchmarks_extended/summary.md |\n")
    res = run(pkg)
    assert messages(res, "numbers") == [] and messages(res, "numbers", "warnings") == []


def test_ignored_tokens_are_not_flagged(pkg):
    set_report(pkg, "# 5.3 Heading with 0.12345\n\nSection 5.3, Figure 4.2, Table 7, v1.18.0-rc1, 2026-11-27, "
                    "12:30, #34, https://example.invalid/a/1234.5 and the year 2026 and n = 10.\n\n"
                    "```\nresult 0.31337\n```\n")
    res = run(pkg)
    assert messages(res, "numbers") == [] and messages(res, "numbers", "warnings") == []


def test_allow_numbers_file(pkg, tmp_path):
    set_report(pkg, "Accuracy was 0.9999 (artifacts/benchmarks_extended/summary.md).\n")
    allow = tmp_path / "allowed.txt"
    allow.write_text("# accepted by the team lead\n0.9999\n", encoding="utf-8")
    assert messages(run(pkg, allow_numbers=allow), "numbers") == []


def test_no_text_report_is_skipped_not_passed(pkg, capsys):
    (pkg / "report/report.md").unlink()
    write_manifest(pkg)
    res = run(pkg)
    assert any("SKIPPED" in m for m in messages(res, "numbers", "warnings"))
    assert vp.main([str(pkg)]) == 0
    assert "WARN  numbers" in capsys.readouterr().out
    assert vp.main([str(pkg), "--strict"]) == 1


def test_explicit_report_that_does_not_exist(pkg):
    assert any("does not exist" in m for m in messages(run(pkg, reports=["report/nope.md"]), "numbers"))


# --- CLI output and boundaries ---------------------------------------------------------------------------------

def test_cli_lists_every_failure_and_exits_nonzero(pkg, capsys):
    (pkg / "video/demo.mp4").unlink()
    write(pkg, "events.sqlite", "x")
    code = vp.main([str(pkg)])
    out = capsys.readouterr().out
    assert code == 1
    assert "FAIL  required" in out and "FAIL  forbidden" in out and "-> FAILED" in out
    assert re.search(r"verify_package: \d+ failure\(s\), \d+ warning\(s\) -> FAILED", out)


def test_verifier_does_not_import_network_or_process_modules():
    src = _SCRIPT.read_text(encoding="utf-8")
    imported = set(re.findall(r"^\s*(?:import|from)\s+([A-Za-z_][\w.]*)", src, re.MULTILINE))
    banned = {"socket", "urllib", "http", "requests", "subprocess", "ftplib", "smtplib", "ssl", "asyncio"}
    assert not {m.split(".")[0] for m in imported} & banned
