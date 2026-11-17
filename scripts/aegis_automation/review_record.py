"""The trusted review record: one JSON document per reviewed head commit.

Written by the `claude-review` job of `.github/workflows/claude-review.yml` (this module is
extracted from the PR's BASE branch, never from the PR head) and uploaded as the run
artifact `aegis-review-record`. The merge gate trusts a record only after verifying, from
GitHub's own run metadata, that the run executed that exact workflow path for a
`pull_request` event on the PR's current head SHA (see merge_gate.find_trusted_review).

The verdict is computed here deterministically from the model's structured findings. The
model's own verdict word is recorded but never trusted on its own:

    ERROR        the review run failed, was cancelled, or produced no structured output
    INCOMPLETE   the output is malformed or inconsistent, or the model said it could not finish
    BLOCKING     at least one P0/P1 finding
    NON_BLOCKING no P0/P1, at least one P2 (needs a fix or a documented waiver)
    READY        no P0-P2 findings (P3 suggestions allowed)

Usage inside the workflow (all inputs via environment variables, never interpolated):
    python3 -m aegis_automation.review_record schema          # JSON schema for --json-schema
    python3 -m aegis_automation.review_record build --out DIR # writes the record + outputs
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA_ID = "aegis.review-record/v1"
VERDICTS = ("READY", "NON_BLOCKING", "BLOCKING", "INCOMPLETE", "ERROR")
MODEL_VERDICTS = ("READY", "NON_BLOCKING", "BLOCKING", "INCOMPLETE")
SEVERITIES = ("P0", "P1", "P2", "P3")
FINDING_ID = re.compile(r"^R[0-9]{1,4}$")
SHA = re.compile(r"^[0-9a-f]{40}$")

# JSON schema handed to Claude (`--json-schema`). Keep it free of single quotes: the
# workflow passes it inside a single-quoted CLI argument.
OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": list(MODEL_VERDICTS)},
        "linked_issue": {"type": "integer", "minimum": 0},
        "findings": {
            "type": "array",
            "maxItems": 50,
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "pattern": "^R[0-9]{1,4}$"},
                    "severity": {"type": "string", "enum": list(SEVERITIES)},
                    "confidence": {"type": "string", "enum": ["Confirmed", "Plausible"]},
                    "path": {"type": "string", "maxLength": 300},
                    "line": {"type": "integer", "minimum": 0},
                    "title": {"type": "string", "maxLength": 200},
                },
                "required": ["id", "severity", "confidence", "path", "line", "title"],
                "additionalProperties": False,
            },
        },
        "previous_findings": {
            "type": "array",
            "maxItems": 100,
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "pattern": "^R[0-9]{1,4}$"},
                    "status": {"type": "string", "enum": ["fixed", "still_present", "superseded"]},
                },
                "required": ["id", "status"],
                "additionalProperties": False,
            },
        },
        "acceptance_criteria": {
            "type": "array",
            "maxItems": 40,
            "items": {
                "type": "object",
                "properties": {
                    "criterion": {"type": "string", "maxLength": 300},
                    "status": {"type": "string", "enum": ["met", "not_met", "cannot_verify"]},
                },
                "required": ["criterion", "status"],
                "additionalProperties": False,
            },
        },
        "escalate": {"type": "boolean"},
        "escalation_reason": {"type": "string", "maxLength": 300},
        "p0": {"type": "integer", "minimum": 0},
        "p1": {"type": "integer", "minimum": 0},
        "p2": {"type": "integer", "minimum": 0},
        "p3": {"type": "integer", "minimum": 0},
    },
    "required": ["verdict", "linked_issue", "findings", "previous_findings",
                 "acceptance_criteria", "escalate", "p0", "p1", "p2", "p3"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def safe_text(value: Any, limit: int = 200) -> str:
    """Neutralise model- or user-authored text before it is rendered in a GitHub comment.

    Removes control characters and newlines, breaks @-mentions, HTML comments/tags and
    markdown table pipes, and truncates. Output is display-only; decisions never use it.
    """
    text = _CONTROL.sub(" ", str(value)).replace("\n", " ").replace("\r", " ")
    text = text.replace("<", "&lt;").replace(">", "&gt;").replace("|", "\\|")
    text = text.replace("@", "@​").replace("`", "'")
    return text[:limit]


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def counts_from_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {s.lower(): 0 for s in SEVERITIES}
    for f in findings:
        counts[f["severity"].lower()] += 1
    return counts


def _validate_output(data: Any) -> list[str]:
    """Structural validation of the model's structured output (subset of JSON schema)."""
    errs: list[str] = []
    if not isinstance(data, dict):
        return ["structured output is not a JSON object"]
    allowed = set(OUTPUT_SCHEMA["properties"])
    extra = set(data) - allowed
    if extra:
        errs.append(f"unexpected keys: {sorted(extra)}")
    for key in OUTPUT_SCHEMA["required"]:
        if key not in data:
            errs.append(f"missing key: {key}")
    if errs:
        return errs
    if data["verdict"] not in MODEL_VERDICTS:
        errs.append("invalid verdict")
    if _int(data["linked_issue"]) is None:
        errs.append("invalid linked_issue")
    if not isinstance(data["escalate"], bool):
        errs.append("invalid escalate flag")
    for sev in ("p0", "p1", "p2", "p3"):
        if _int(data[sev]) is None:
            errs.append(f"invalid count {sev}")
    findings = data["findings"]
    if not isinstance(findings, list):
        return [*errs, "findings is not a list"]
    seen: set[str] = set()
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            errs.append(f"finding {i} is not an object")
            continue
        fid = f.get("id")
        if not isinstance(fid, str) or not FINDING_ID.match(fid):
            errs.append(f"finding {i} has an invalid id")
        elif fid in seen:
            errs.append(f"duplicate finding id {fid}")
        else:
            seen.add(fid)
        if f.get("severity") not in SEVERITIES:
            errs.append(f"finding {i} has an invalid severity")
        if f.get("confidence") not in ("Confirmed", "Plausible"):
            errs.append(f"finding {i} has an invalid confidence")
        if not isinstance(f.get("path"), str) or _int(f.get("line")) is None:
            errs.append(f"finding {i} has an invalid location")
        if not isinstance(f.get("title"), str):
            errs.append(f"finding {i} has an invalid title")
    for key, enum in (("previous_findings", ("fixed", "still_present", "superseded")),
                      ("acceptance_criteria", ("met", "not_met", "cannot_verify"))):
        items = data[key]
        if not isinstance(items, list):
            errs.append(f"{key} is not a list")
            continue
        for i, item in enumerate(items):
            if not isinstance(item, dict) or item.get("status") not in enum:
                errs.append(f"{key}[{i}] is invalid")
            elif key == "previous_findings" and not FINDING_ID.match(str(item.get("id", ""))):
                errs.append(f"{key}[{i}] has an invalid id")
            elif key == "acceptance_criteria" and not isinstance(item.get("criterion"), str):
                errs.append(f"{key}[{i}] has an invalid criterion")
    return errs


def compute_verdict(outcome: str, output: Any) -> tuple[str, list[str]]:
    """Return (verdict, problems). Pure function; the core of the trust model."""
    if outcome != "success":
        return "ERROR", [f"review step outcome was {outcome!r}"]
    if output is None:
        # The run itself succeeded, so this is not an infrastructure error.
        return "INCOMPLETE", ["no structured output"]
    problems = _validate_output(output)
    if problems:
        return "INCOMPLETE", problems
    counts = counts_from_findings(output["findings"])
    declared = {k: output[k] for k in ("p0", "p1", "p2", "p3")}
    if counts != declared:
        return "INCOMPLETE", [f"declared counts {declared} do not match findings {counts}"]
    if output["verdict"] == "INCOMPLETE":
        return "INCOMPLETE", ["the reviewer reported that it could not finish"]
    if counts["p0"] + counts["p1"] > 0:
        verdict = "BLOCKING"
    elif counts["p2"] > 0:
        verdict = "NON_BLOCKING"
    else:
        verdict = "READY"
    notes: list[str] = []
    order = {"READY": 0, "NON_BLOCKING": 1, "BLOCKING": 2}
    if output["verdict"] != verdict:
        if order[output["verdict"]] > order[verdict]:
            # The model is stricter than its own findings: inconsistent, fail closed.
            return "INCOMPLETE", [f"model verdict {output['verdict']} is stricter than its findings ({verdict})"]
        notes.append(f"model verdict {output['verdict']} overridden by findings ({verdict})")
    return verdict, notes


def status_for(verdict: str, counts: dict[str, int]) -> tuple[str, str]:
    """Advisory commit-status (state, description). Format is a contract with
    claude-remediate.yml's gate, which parses `P0:a P1:b P2:c P3:d`."""
    if verdict in ("ERROR", "INCOMPLETE"):
        return "error", "Review did not complete; see the run log"
    desc = f"P0:{counts['p0']} P1:{counts['p1']} P2:{counts['p2']} P3:{counts['p3']}"
    if verdict == "BLOCKING":
        return "failure", f"{desc} (blocking findings; advisory)"
    return "success", desc


def build_record(*, output_text: str | None, outcome: str, meta: dict[str, Any]) -> dict[str, Any]:
    output: Any = None
    parse_problem: list[str] = []
    if output_text:
        try:
            output = json.loads(output_text)
        except ValueError:
            parse_problem = ["structured output is not valid JSON"]
    verdict, problems = compute_verdict(outcome, output)
    problems = parse_problem + problems
    valid = verdict not in ("ERROR", "INCOMPLETE")
    findings = []
    previous: list[dict[str, str]] = []
    acceptance: list[dict[str, str]] = []
    counts = {"p0": 0, "p1": 0, "p2": 0, "p3": 0}
    escalate = False
    reason = ""
    linked = None
    model_verdict = None
    if isinstance(output, dict) and not _validate_output(output):
        findings = [
            {
                "id": f["id"],
                "severity": f["severity"],
                "confidence": f["confidence"],
                "path": safe_text(f["path"], 300),
                "line": f["line"],
                "title": safe_text(f["title"], 200),
            }
            for f in output["findings"]
        ]
        previous = [{"id": p["id"], "status": p["status"]} for p in output["previous_findings"]]
        acceptance = [{"criterion": safe_text(a["criterion"], 300), "status": a["status"]}
                      for a in output["acceptance_criteria"]]
        counts = counts_from_findings(output["findings"])
        escalate = bool(output["escalate"])
        reason = safe_text(output.get("escalation_reason", ""), 300)
        linked = output["linked_issue"] or None
        model_verdict = output["verdict"]
    return {
        "schema": SCHEMA_ID,
        "repository": meta["repository"],
        "pr_number": int(meta["pr_number"]),
        "head_sha": meta["head_sha"],
        "base_sha": meta.get("base_sha", ""),
        "base_ref": meta.get("base_ref", ""),
        "reviewer": {
            "identity": meta.get("reviewer_identity", "claude[bot]"),
            "workflow": meta.get("workflow_path", ".github/workflows/claude-review.yml"),
            "run_id": int(meta.get("run_id", 0) or 0),
            "run_attempt": int(meta.get("run_attempt", 1) or 1),
        },
        "model": meta.get("model", ""),
        "mode": meta.get("mode", "full"),
        "previous_reviewed_sha": meta.get("previous_sha") or None,
        "deep": bool(meta.get("deep", False)),
        "created_at": meta.get("created_at") or now_utc(),
        "policy_sha256": meta.get("policy_sha256", ""),
        "outcome": outcome,
        "verdict": verdict,
        "valid": valid,
        "model_verdict": model_verdict,
        "problems": [safe_text(p, 300) for p in problems],
        "counts": counts,
        "findings": findings,
        "previous_findings": previous,
        "acceptance_criteria": acceptance,
        "linked_issue": linked,
        "escalate": escalate,
        "escalation_reason": reason,
        "ci_snapshot": meta.get("ci_snapshot", []),
    }


def validate_record(record: Any) -> list[str]:
    """Validate a record downloaded by the merge gate. Empty list = structurally valid."""
    if not isinstance(record, dict):
        return ["record is not an object"]
    errs: list[str] = []
    if record.get("schema") != SCHEMA_ID:
        errs.append(f"unknown record schema {record.get('schema')!r}")
    if not isinstance(record.get("head_sha"), str) or not SHA.match(record["head_sha"]):
        errs.append("record head_sha is not a full SHA")
    if not isinstance(record.get("pr_number"), int):
        errs.append("record pr_number missing")
    if record.get("verdict") not in VERDICTS:
        errs.append("record verdict invalid")
    counts = record.get("counts")
    findings = record.get("findings")
    if not isinstance(findings, list) or not isinstance(counts, dict):
        errs.append("record findings/counts missing")
    else:
        try:
            if counts_from_findings(findings) != {k: counts.get(k) for k in ("p0", "p1", "p2", "p3")}:
                errs.append("record counts do not match its findings")
        except (KeyError, AttributeError, TypeError):
            errs.append("record findings malformed")
    for key in ("previous_findings", "acceptance_criteria"):
        if not isinstance(record.get(key), list):
            errs.append(f"record {key} missing")
    if not isinstance(record.get("escalate"), bool):
        errs.append("record escalate flag missing")
    return errs


# ---------------------------------------------------------------------------------------
# CLI (runs inside the review workflow)
# ---------------------------------------------------------------------------------------
def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


def _write_outputs(values: dict[str, str]) -> None:
    path = _env("GITHUB_OUTPUT")
    if not path:
        for k, v in values.items():
            print(f"{k}={v}")
        return
    with open(path, "a", encoding="utf-8") as fh:
        for k, v in values.items():
            if "\n" in v:
                raise ValueError(f"output {k} must be single-line")
            fh.write(f"{k}={v}\n")


def _summary(record: dict[str, Any]) -> str:
    c = record["counts"]
    lines = [
        f"### Review record for `{record['head_sha'][:7]}`",
        f"- Verdict: **{record['verdict']}** · model `{safe_text(record['model'], 60)}` · "
        f"mode {record['mode']} · P0:{c['p0']} P1:{c['p1']} P2:{c['p2']} P3:{c['p3']}",
    ]
    if record["escalate"]:
        lines.append(f"- Escalation recommended: {record['escalation_reason']}")
    for p in record["problems"]:
        lines.append(f"- Note: {p}")
    return "\n".join(lines) + "\n"


def cmd_build(out_dir: Path) -> int:
    meta = {
        "repository": _env("GITHUB_REPOSITORY"),
        "pr_number": _env("PR_NUMBER", "0"),
        "head_sha": _env("HEAD_SHA"),
        "base_sha": _env("BASE_SHA"),
        "base_ref": _env("BASE_REF"),
        "run_id": _env("GITHUB_RUN_ID", "0"),
        "run_attempt": _env("GITHUB_RUN_ATTEMPT", "1"),
        "model": _env("MODEL"),
        "mode": _env("MODE", "full"),
        "previous_sha": _env("PREV"),
        "deep": _env("DEEP") == "true",
        "policy_sha256": _env("POLICY_SHA256"),
    }
    snapshot_file = _env("CI_SNAPSHOT_FILE")
    if snapshot_file and Path(snapshot_file).is_file():
        try:
            meta["ci_snapshot"] = json.loads(Path(snapshot_file).read_text(encoding="utf-8"))[:50]
        except ValueError:
            meta["ci_snapshot"] = []
    if not SHA.match(meta["head_sha"]):
        print("::error::HEAD_SHA is not a full commit SHA", file=sys.stderr)
        return 2
    record = build_record(output_text=_env("RESULT") or None, outcome=_env("OUTCOME", "failure"),
                          meta=meta)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "review-record.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n",
                                                encoding="utf-8")
    state, desc = status_for(record["verdict"], record["counts"])
    _write_outputs({
        "state": state,
        "description": desc,
        "verdict": record["verdict"],
        "escalate": "true" if record["escalate"] else "false",
    })
    summary = _env("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(_summary(record))
    print(f"review record: verdict={record['verdict']} state={state} desc={desc!r}")
    return 0


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis_automation.review_record")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("schema", help="print the structured-output JSON schema")
    b = sub.add_parser("build", help="build the review record from env vars")
    b.add_argument("--out", required=True, type=Path)
    h = sub.add_parser("hash", help="sha256 of a file")
    h.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    if args.cmd == "schema":
        print(json.dumps(OUTPUT_SCHEMA, separators=(",", ":")))
        return 0
    if args.cmd == "hash":
        print(sha256_file(args.path))
        return 0
    return cmd_build(args.out)


if __name__ == "__main__":
    raise SystemExit(main())
