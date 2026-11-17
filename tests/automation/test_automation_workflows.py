"""Static security and contract checks of the GitHub Actions workflows.

These complement actionlint / shellcheck / zizmor (run separately, see
docs/AUTONOMOUS_PIPELINE.md "Validation") with repository-specific invariants.
"""

from __future__ import annotations

import re

import pytest
import yaml
from automation_fakes import REPO_ROOT, policy

WF_DIR = REPO_ROOT / ".github" / "workflows"
WORKFLOWS = sorted(WF_DIR.glob("*.yml"))
PINNED = re.compile(r"^[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}$")
# Event fields an outsider (or any PR author) controls. Never inline them in shell.
UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.event\.(comment\.body|issue\.title|issue\.body|pull_request\.title|"
    r"pull_request\.body|pull_request\.head\.ref|review\.body|head_commit\.message|"
    r"workflow_run\.head_branch|workflow_run\.display_title)|\$\{\{\s*github\.head_ref"
)


def load(path):
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    # PyYAML parses the key `on` as boolean True.
    data["on"] = data.pop(True, data.get("on"))
    return data


def steps(wf):
    for job in wf["jobs"].values():
        yield from job.get("steps", [])


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_third_party_actions_are_pinned_to_full_shas(path):
    for step in steps(load(path)):
        uses = step.get("uses")
        if uses and not uses.startswith("./"):
            assert PINNED.match(uses), f"{path.name}: {uses} is not pinned to a commit SHA"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_no_pull_request_target_and_least_privilege(path):
    wf = load(path)
    assert "pull_request_target" not in (wf["on"] or {}), path.name
    assert wf.get("permissions") in ({}, {"contents": "read"}), f"{path.name}: workflow-level permissions"
    for name, job in wf["jobs"].items():
        perms = job.get("permissions", {})
        assert perms != "write-all", f"{path.name}:{name}"
        assert perms.get("contents", "read") == "read", f"{path.name}:{name} must not hold contents: write"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_untrusted_event_text_never_reaches_shell(path):
    for step in steps(load(path)):
        assert not UNTRUSTED.search(step.get("run", "")), f"{path.name}: {step.get('name')}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_checkouts_do_not_persist_credentials(path):
    for step in steps(load(path)):
        if str(step.get("uses", "")).startswith("actions/checkout@"):
            assert step.get("with", {}).get("persist-credentials") is False, path.name


def test_orchestrator_runs_trusted_code_only():
    wf = load(WF_DIR / "aegis-orchestrator.yml")
    triggers = wf["on"]
    assert set(triggers) == {"workflow_run", "issue_comment", "workflow_dispatch"}
    names = {load(WF_DIR / "claude-review.yml")["name"], load(WF_DIR / "ci.yml")["name"]}
    assert set(triggers["workflow_run"]["workflows"]) == names
    job = wf["jobs"]["orchestrate"]
    assert job["environment"] == "automerge"
    assert "refs/heads/{0}" in job["if"] and "default_branch" in job["if"]
    assert "workflow_run.event == 'pull_request'" in job["if"]
    assert "comment.user.type == 'User'" in job["if"]
    checkout = job["steps"][0]
    assert checkout["with"]["ref"] == "${{ github.event.repository.default_branch }}"
    assert wf["concurrency"]["cancel-in-progress"] is False
    app = next(s for s in job["steps"] if "create-github-app-token" in s.get("uses", ""))
    assert app["with"]["client-id"] == "${{ vars.AEGIS_MERGE_APP_CLIENT_ID }}"
    run = job["steps"][-1]
    assert run["env"]["READ_TOKEN"] == "${{ github.token }}"
    assert run["run"].strip() == "PYTHONPATH=scripts python3 -m aegis_automation.orchestrator"


def test_review_workflow_publishes_the_trusted_record_from_base_tooling():
    wf = load(WF_DIR / "claude-review.yml")
    job = wf["jobs"]["review"]
    by_name = {s.get("name"): s for s in job["steps"]}
    load_step = by_name["Load review-record tooling from the base branch"]["run"]
    assert 'git archive "origin/${BASE_REF}" scripts/aegis_automation' in load_step
    build = by_name["Build the review record"]
    assert build["env"]["RESULT"] == "${{ steps.review.outputs.structured_output }}"
    assert "always()" in build["if"]
    upload = by_name["Upload the trusted review record"]
    assert upload["with"]["name"] == policy().review_record_artifact
    assert upload["with"]["path"].endswith("/" + policy().review_record_file)
    assert upload["with"]["overwrite"] is True  # re-run attempts must not create a duplicate
    review = by_name["Claude review"]
    assert "--json-schema '${{ steps.automation.outputs.schema }}'" in review["with"]["claude_args"]
    assert review["with"]["allowed_bots"] == "claude"
    disallowed = review["with"]["claude_args"]
    for tool in ("Bash(gh pr review:*)", "Bash(gh pr merge:*)", "Bash(gh api:*)", "Bash(git push:*)"):
        assert tool in disallowed
    assert job["concurrency"]["cancel-in-progress"] is True
    assert wf["jobs"]["review"]["if"].count("head.repo.full_name == github.repository") == 1


def test_remediation_cannot_touch_automation_and_verifies_bot_requests():
    wf = load(WF_DIR / "claude-remediate.yml")
    job = wf["jobs"]["remediate"]
    gate = job["steps"][0]["run"]
    assert "performed_via_github_app.id" in gate
    assert "aegis-auto-remediation sha=$head_sha " in gate
    assert "vars.AEGIS_AUTOREMEDIATE == 'on'" in job["if"]
    action = next(s for s in job["steps"] if "claude-code-action" in s.get("uses", ""))
    args = action["with"]["claude_args"]
    for path in (".github/**", "scripts/aegis_automation/**", "tests/automation/**", "AGENTS.md"):
        assert f"Edit({path})" in args and f"Write({path})" in args
    for tool in ("Bash(gh pr merge:*)", "Bash(gh pr review:*)", "Bash(git push --force:*)"):
        assert tool in args
    assert action["with"]["allowed_bots"] == "${{ vars.AEGIS_MERGE_APP_SLUG }}"


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_subprocess_scrubbing_is_provisioned_and_never_disabled(path):
    """Claude Code with CLAUDE_CODE_SUBPROCESS_ENV_SCRUB=1 refuses to start without bubblewrap
    (remediation run 44033857812). claude-code-action only installs it when
    allowed_non_write_users is set, so the job must provision and verify it itself."""
    text = path.read_text(encoding="utf-8")
    assert not re.search(r"CLAUDE_CODE_SUBPROCESS_ENV_SCRUB:\s*[\"']?0", text), "isolation disabled"
    for name, job in load(path)["jobs"].items():
        job_steps = job.get("steps", [])
        for i, step in enumerate(job_steps):
            if str((step.get("env") or {}).get("CLAUDE_CODE_SUBPROCESS_ENV_SCRUB")) != "1":
                continue
            before = " ".join(s.get("run", "") for s in job_steps[:i])
            assert "apt-get install" in before and "bubblewrap" in before, f"{path.name}:{name}"
            assert "bwrap --ro-bind / /" in before and "--unshare-all" in before, f"{path.name}:{name}"
            assert "exit 1" in before, f"{path.name}:{name}: must fail closed"


def test_remediation_provisions_isolation_only_after_the_gate():
    job = load(WF_DIR / "claude-remediate.yml")["jobs"]["remediate"]
    step = next(s for s in job["steps"] if s.get("name") == "Provision subprocess isolation (bubblewrap)")
    assert step["if"] == "steps.gate.outputs.proceed == 'true'"


def test_remediation_marker_and_cycle_marker_are_consistent_with_policy():
    text = (WF_DIR / "claude-remediate.yml").read_text(encoding="utf-8")
    assert policy().cycle_marker in text
    assert policy().auto_request_marker in text


def test_ci_job_names_match_policy_required_jobs():
    ci = load(WF_DIR / "ci.yml")
    names = {job.get("name", key) for key, job in ci["jobs"].items()}
    assert set(policy().required_ci_jobs) <= names
