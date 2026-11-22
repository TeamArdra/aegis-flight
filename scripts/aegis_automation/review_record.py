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
    READY        no P0-P2 findings (P3 and INFO allowed)

Every finding also carries a category (review-policy.md section 5). The categories make the
reviewer say WHAT is wrong, so that "this is new" or "this changes existing behaviour" can
never be a finding on its own. These classification rules are enforced here, fail-closed
(a violation makes the record INCOMPLETE, which routes the PR to a human):

    INFO severity           only for category IMPROVEMENT (optional, never blocking)
    IMPROVEMENT category    only INFO or P3 (a suggestion can never block a merge)
    Plausible confidence    never P0/P1 (a speculative risk is not a confirmed defect)
    CONTRACT_VIOLATION      only P0/P1 (needs the project owner's approval to proceed)

Any P0, SAFETY or CONTRACT_VIOLATION finding forces `escalate` to true, whatever the model
said, so such a PR always goes to a human and never to automatic remediation.

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

SCHEMA_ID = "aegis.review-record/v2"
# v1 records (no categories, no INFO) stay readable so a PR reviewed before this change is
# judged on its existing record instead of being silently re-classified.
ACCEPTED_SCHEMAS = ("aegis.review-record/v1", SCHEMA_ID)
VERDICTS = ("READY", "NON_BLOCKING", "BLOCKING", "INCOMPLETE", "ERROR")
MODEL_VERDICTS = ("READY", "NON_BLOCKING", "BLOCKING", "INCOMPLETE")
# Counted severities: `counts{p0..p3}` and the `P0:a P1:b P2:c P3:d` status are contracts
# with merge_gate.py and claude-remediate.yml. INFO is recorded but never counted there.
SEVERITIES = ("P0", "P1", "P2", "P3")
FINDING_SEVERITIES = (*SEVERITIES, "INFO")
CATEGORIES = (
    "SAFETY",              # flight safety, vehicle control, receive-only / command boundaries
    "SECURITY",            # exploitable vulnerability, auth/integrity bypass, unsafe input
    "DEFECT",              # logic error, wrong state transition, leak, race, missing recovery
    "REGRESSION",          # previously working behaviour, test or metric broken
    "CONTRACT_VIOLATION",  # frozen contract or explicitly approved decision contradicted
    "EVIDENCE_GAP",        # missing test, unsupported claim, unreproducible evidence
    "IMPROVEMENT",         # optional suggestion or feature observation (INFO/P3 only)
)
ESCALATING_CATEGORIES = ("SAFETY", "CONTRACT_VIOLATION")
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
                    "severity": {"type": "string", "enum": list(FINDING_SEVERITIES)},
                    "category": {"type": "string", "enum": list(CATEGORIES)},
                    "confidence": {"type": "string", "enum": ["Confirmed", "Plausible"]},
                    "path": {"type": "string", "maxLength": 300},
                    "line": {"type": "integer", "minimum": 0},
                    "title": {"type": "string", "maxLength": 200},
                },
                "required": ["id", "severity", "category", "confidence", "path", "line", "title"],
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
        "info": {"type": "integer", "minimum": 0},
    },
    "required": ["verdict", "linked_issue", "findings", "previous_findings",
                 "acceptance_criteria", "escalate", "p0", "p1", "p2", "p3", "info"],
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
    """P0-P3 counts (the merge-gate contract). INFO findings are not counted here."""
    counts = {s.lower(): 0 for s in SEVERITIES}
    for f in findings:
        if f["severity"] != "INFO":
            counts[f["severity"].lower()] += 1
    return counts


def info_count(findings: list[dict[str, Any]]) -> int:
    return sum(1 for f in findings if f.get("severity") == "INFO")


def classification_problems(findings: list[dict[str, Any]]) -> list[str]:
    """Consistency rules between severity, category and confidence (module docstring).

    A violation means the reviewer mislabelled something: either a speculative or optional
    item was made blocking, or a blocking item was hidden as optional. Both fail closed.
    """
    errs: list[str] = []
    for f in findings:
        fid, sev, cat, conf = f["id"], f["severity"], f["category"], f["confidence"]
        if sev == "INFO" and cat != "IMPROVEMENT":
            errs.append(f"{fid}: INFO severity is only for IMPROVEMENT findings, not {cat}")
        if cat == "IMPROVEMENT" and sev not in ("INFO", "P3"):
            errs.append(f"{fid}: an IMPROVEMENT is optional and must be INFO or P3, not {sev}")
        if conf == "Plausible" and sev in ("P0", "P1"):
            errs.append(f"{fid}: a Plausible (unconfirmed) finding cannot be {sev}")
        if cat == "CONTRACT_VIOLATION" and sev not in ("P0", "P1"):
            errs.append(f"{fid}: a CONTRACT_VIOLATION needs owner approval and must be P0/P1, not {sev}")
    return errs


def forced_escalation(findings: list[dict[str, Any]]) -> list[str]:
    """Finding ids that must route the PR to a human regardless of the model's flag."""
    return [f["id"] for f in findings
            if f.get("severity") == "P0" or f.get("category") in ESCALATING_CATEGORIES]


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
    for sev in ("p0", "p1", "p2", "p3", "info"):
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
        if f.get("severity") not in FINDING_SEVERITIES:
            errs.append(f"finding {i} has an invalid severity")
        if f.get("category") not in CATEGORIES:
            errs.append(f"finding {i} has an invalid category")
        extra_f = set(f) - set(OUTPUT_SCHEMA["properties"]["findings"]["items"]["properties"])
        if extra_f:
            errs.append(f"finding {i} has unexpected keys: {sorted(extra_f)}")
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
    if output["info"] != info_count(output["findings"]):
        return "INCOMPLETE", [f"declared info count {output['info']} does not match findings"]
    mislabelled = classification_problems(output["findings"])
    if mislabelled:
        return "INCOMPLETE", mislabelled
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
                "category": f["category"],
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
        forced = forced_escalation(output["findings"])
        if forced:
            # Never weaker than the findings: P0, SAFETY and CONTRACT_VIOLATION go to a human.
            if not escalate:
                reason = safe_text(f"forced by safety/contract/P0 findings {', '.join(forced)}. "
                                   + reason, 300)
            escalate = True
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
        "info_count": info_count(findings),
        "findings": findings,
        "previous_findings": previous,
        "acceptance_criteria": acceptance,
        "linked_issue": linked,
        "escalate": escalate,
        "escalation_reason": reason,
        "ci_snapshot": meta.get("ci_snapshot", []),
    }


V1_SCHEMA_ID = "aegis.review-record/v1"
# Exact finding shapes written by each builder version. A v1 record never had `category`,
# `INFO` or `info_count`; their presence in a record that calls itself v1 means it was not
# written by the v1 builder (a downgrade to dodge the v2 checks), so it is rejected.
_V1_FINDING_KEYS = frozenset({"id", "severity", "confidence", "path", "line", "title"})
_V2_FINDING_KEYS = _V1_FINDING_KEYS | {"category"}
# Verdicts derived from findings; ERROR/INCOMPLETE records are never valid (G09 fails them).
_COUNTED_VERDICTS = ("READY", "NON_BLOCKING", "BLOCKING")


def _verdict_for_counts(counts: dict[str, int]) -> str:
    if counts["p0"] + counts["p1"] > 0:
        return "BLOCKING"
    return "NON_BLOCKING" if counts["p2"] > 0 else "READY"


def legacy_forced_escalation(findings: list[dict[str, Any]]) -> list[str]:
    """v1 findings have no category, so a SAFETY or CONTRACT_VIOLATION finding cannot be told
    apart from any other P0/P1. Conservatively, every v1 P0/P1 must have been escalated."""
    return [f["id"] for f in findings if f.get("severity") in ("P0", "P1")]


def _finding_problems(findings: list[Any], schema: str) -> list[str]:
    keys = _V2_FINDING_KEYS if schema == SCHEMA_ID else _V1_FINDING_KEYS
    severities = FINDING_SEVERITIES if schema == SCHEMA_ID else SEVERITIES
    errs: list[str] = []
    seen: set[str] = set()
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            errs.append(f"record finding {i} is not an object")
            continue
        if set(f) != keys:
            extra, missing = sorted(set(f) - keys), sorted(keys - set(f))
            hint = " (v2 fields in a v1 record: schema downgrade)" if schema != SCHEMA_ID and (
                "category" in extra) else ""
            errs.append(f"record finding {i} keys invalid for {schema}: "
                        f"extra={extra} missing={missing}{hint}")
            continue
        if not isinstance(f["id"], str) or not FINDING_ID.match(f["id"]) or f["id"] in seen:
            errs.append(f"record finding {i} id invalid or duplicated")
        else:
            seen.add(f["id"])
        if f["severity"] not in severities:
            errs.append(f"record finding {i} severity {f['severity']!r} not allowed in {schema}")
        if f["confidence"] not in ("Confirmed", "Plausible"):
            errs.append(f"record finding {i} confidence invalid")
        if schema == SCHEMA_ID and f["category"] not in CATEGORIES:
            errs.append(f"record finding {i} category invalid")
        if not isinstance(f["path"], str) or not isinstance(f["title"], str) or _int(f["line"]) is None:
            errs.append(f"record finding {i} location malformed")
    return errs


def validate_record(record: Any) -> list[str]:
    """Validate a record downloaded by the merge gate. Empty list = valid.

    Stored records are re-checked in full, never trusted as written: the gate applies the
    same invariants the builder enforced (counts, INFO count, classification rules, verdict
    derivation, forced escalation), so an edited record is rejected rather than obeyed.
    Rejection fails closed: the gate treats the PR as having no valid review (G09).
    """
    if not isinstance(record, dict):
        return ["record is not an object"]
    errs: list[str] = []
    schema = record.get("schema")
    if schema not in ACCEPTED_SCHEMAS:
        errs.append(f"unknown record schema {schema!r}")
    if not isinstance(record.get("head_sha"), str) or not SHA.match(record["head_sha"]):
        errs.append("record head_sha is not a full SHA")
    if not isinstance(record.get("pr_number"), int):
        errs.append("record pr_number missing")
    verdict = record.get("verdict")
    if verdict not in VERDICTS:
        errs.append("record verdict invalid")
    if not isinstance(record.get("valid"), bool) or record["valid"] != (verdict in _COUNTED_VERDICTS):
        errs.append("record valid flag inconsistent with its verdict")
    for key in ("previous_findings", "acceptance_criteria"):
        if not isinstance(record.get(key), list):
            errs.append(f"record {key} missing")
    escalate = record.get("escalate")
    if not isinstance(escalate, bool):
        errs.append("record escalate flag missing")
    counts = record.get("counts")
    findings = record.get("findings")
    if not isinstance(findings, list) or not isinstance(counts, dict):
        return [*errs, "record findings/counts missing"]
    if schema not in ACCEPTED_SCHEMAS:
        return errs
    shape = _finding_problems(findings, schema)
    if shape:
        return errs + shape
    # From here every finding has exactly the keys and enum values its schema allows.
    real = counts_from_findings(findings)
    if set(counts) != set(real) or any(counts[k] != real[k] for k in real):
        errs.append("record counts do not match its findings")
    if schema == SCHEMA_ID:
        if record.get("info_count") != info_count(findings):
            errs.append("record info_count does not match its findings")
        if verdict in _COUNTED_VERDICTS:
            # INCOMPLETE records may hold the mislabelled findings that made them incomplete.
            errs.extend(f"record classification: {p}" for p in classification_problems(findings))
        forced = forced_escalation(findings)
        if forced and escalate is not True:
            errs.append(f"record has safety/contract/P0 findings {forced} but is not escalated")
    else:
        if "info_count" in record:
            errs.append("record declares v1 but carries the v2 field info_count (schema downgrade)")
        forced = legacy_forced_escalation(findings)
        if forced and escalate is not True:
            errs.append(f"legacy v1 record has P0/P1 findings {forced} but is not escalated "
                        "(categories unknown, so they may be safety or contract findings)")
    if verdict in _COUNTED_VERDICTS and verdict != _verdict_for_counts(real):
        errs.append(f"record verdict {verdict} does not follow from its findings "
                    f"({_verdict_for_counts(real)})")
    return errs


# ---------------------------------------------------------------------------------------
# Run diagnosis (issue #119): WHY a review produced no structured output.
# Explanatory only: it never changes the verdict, the status or the record's validity.
# ---------------------------------------------------------------------------------------
# Credential-looking strings: Anthropic keys/OAuth tokens, bearer values, long opaque runs.
_TOKENISH = re.compile(r"sk-ant-[A-Za-z0-9_\-]+|(?i:bearer)\s+\S+|[A-Za-z0-9_\-+/=]{32,}")


def _redact(text: str) -> str:
    return _TOKENISH.sub("[redacted]", text)


def diagnose_execution(events: Any) -> tuple[str, str]:
    """Classify the claude-code-action execution log (a list of SDK messages).

    Returns (kind, detail) with kind one of: ok, api_error (the CLI failed before any model
    call, e.g. a usage limit or a rejected credential), max_turns, run_error,
    no_structured_output, no_result, unreadable. The CLI's own error text is echoed only for
    api_error, where no model ran, so model-authored text never reaches the log.
    """
    if not isinstance(events, list):
        return "unreadable", "the execution log is not a list of messages"
    results = [e for e in events if isinstance(e, dict) and e.get("type") == "result"]
    if not results:
        return "no_result", "the CLI emitted no result message"
    r = results[-1]
    if r.get("structured_output") is not None:
        return "ok", ""
    turns = _int(r.get("num_turns"))
    turns_text = f"{turns} turns" if turns is not None else "an unknown number of turns"
    if str(r.get("subtype", "")).startswith("error_max_turns"):
        return "max_turns", f"the review stopped at the turn limit after {turns_text}"
    cost = r.get("total_cost_usd")
    model_ran = bool(r.get("modelUsage")) or (isinstance(cost, (int, float)) and cost > 0)
    if r.get("is_error") is True and not model_ran:
        cli_text = safe_text(_redact(str(r.get("result") or "")), 160).strip()
        detail = "the Claude CLI failed before any model call (no tokens used)"
        return "api_error", f"{detail}: {cli_text}" if cli_text else detail
    if r.get("is_error") is True:
        return "run_error", f"the Claude CLI reported an error after {turns_text}"
    return "no_structured_output", f"the model ran {turns_text} but returned no structured output"


def diagnose_file(path: Path) -> tuple[str, str]:
    """diagnose_execution() on a JSON-array or JSON-lines execution log; never raises."""
    # ValueError covers UnicodeDecodeError and JSON errors; RecursionError a pathologically
    # nested log. The build step must still write its (fail-closed) record.
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return "unreadable", "no execution log"
    except ValueError:
        return "unreadable", "the execution log is not UTF-8 text"
    try:
        return diagnose_execution(json.loads(text))
    except (ValueError, RecursionError):
        pass
    try:
        return diagnose_execution([json.loads(line) for line in text.splitlines() if line.strip()])
    except (ValueError, RecursionError):
        return "unreadable", "the execution log is not valid JSON"


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
    diagnosis = ""
    if record["verdict"] in ("ERROR", "INCOMPLETE"):
        exe = _env("EXECUTION_FILE")
        try:
            kind, detail = (diagnose_file(Path(exe)) if exe else
                            ("unreadable", "no execution log; the review step was cancelled or skipped"))
        except Exception as exc:  # explanatory only: never block writing the record
            kind, detail = "unreadable", f"diagnosis failed ({type(exc).__name__})"
        if kind != "ok":
            diagnosis = safe_text(f"run diagnosis: {kind}" + (f" ({detail})" if detail else ""), 300)
            record["problems"].append(diagnosis)
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
    if diagnosis:
        # safe_text removed newlines/control chars, so this is one workflow-command line.
        print(f"::error::Automated review did not run to completion: {diagnosis}")
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
