"""Load and validate `.github/automation/policy.toml`.

The policy is only ever read from the default branch (see the header of the TOML file).
Validation is strict: an unknown schema version, a missing table or a malformed regex
raises `PolicyError`, and every caller treats that as "not eligible" (fail closed).
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_POLICY_PATH = Path(".github/automation/policy.toml")
SEVERITIES = ("P0", "P1", "P2", "P3")


class PolicyError(ValueError):
    """The policy file is missing or invalid."""


@dataclass(frozen=True)
class EscalationCategory:
    name: str
    description: str
    paths: tuple[str, ...]
    content_globs: tuple[str, ...] = ()
    added_line_patterns: tuple[re.Pattern[str], ...] = ()


@dataclass(frozen=True)
class Policy:
    raw: dict[str, Any]
    categories: tuple[EscalationCategory, ...] = field(default_factory=tuple)

    # --- repository -------------------------------------------------------------------
    @property
    def default_branch(self) -> str:
        return str(self.raw["repository"]["default_branch"])

    @property
    def review_workflow_path(self) -> str:
        return str(self.raw["repository"]["review_workflow_path"])

    @property
    def ci_workflow_path(self) -> str:
        return str(self.raw["repository"]["ci_workflow_path"])

    @property
    def review_record_artifact(self) -> str:
        return str(self.raw["repository"]["review_record_artifact"])

    @property
    def review_record_file(self) -> str:
        return str(self.raw["repository"]["review_record_file"])

    @property
    def reviewer_login(self) -> str:
        return str(self.raw["repository"]["reviewer_login"])

    @property
    def status_writer_login(self) -> str:
        return str(self.raw["repository"]["status_writer_login"])

    # --- ci ---------------------------------------------------------------------------
    @property
    def required_ci_jobs(self) -> tuple[str, ...]:
        return tuple(self.raw["ci"]["required_jobs"])

    @property
    def advisory_contexts(self) -> tuple[str, ...]:
        return tuple(self.raw["ci"].get("advisory_contexts", ()))

    # --- authors ----------------------------------------------------------------------
    @property
    def minimum_permission(self) -> str:
        return str(self.raw["authors"]["minimum_permission"])

    @property
    def trusted_agent_identities(self) -> tuple[str, ...]:
        return tuple(self.raw["authors"].get("trusted_agent_identities", ()))

    @property
    def branch_pattern(self) -> re.Pattern[str]:
        return re.compile(self.raw["authors"]["branch_pattern"])

    @property
    def require_issue_number_in_branch(self) -> bool:
        return bool(self.raw["authors"].get("require_issue_number_in_branch", True))

    # --- issue ------------------------------------------------------------------------
    @property
    def acceptance_heading(self) -> str:
        return str(self.raw["issue"]["acceptance_heading"]).lower()

    @property
    def escalation_labels(self) -> tuple[str, ...]:
        return tuple(self.raw["issue"].get("escalation_labels", ()))

    # --- review -----------------------------------------------------------------------
    @property
    def blocking_severities(self) -> tuple[str, ...]:
        return tuple(self.raw["review"]["blocking_severities"])

    @property
    def allow_p2_waivers(self) -> bool:
        return bool(self.raw["review"].get("allow_p2_waivers", False))

    @property
    def waiver_requires_non_author(self) -> bool:
        return bool(self.raw["review"].get("waiver_requires_non_author", True))

    @property
    def min_waiver_sha_prefix(self) -> int:
        return max(7, int(self.raw["review"].get("min_waiver_sha_prefix", 7)))

    @property
    def require_all_acceptance_met(self) -> bool:
        return bool(self.raw["review"].get("require_all_acceptance_met", True))

    @property
    def max_review_attempts(self) -> int:
        return max(1, int(self.raw["review"].get("max_review_attempts", 1)))

    # --- remediation ------------------------------------------------------------------
    @property
    def max_remediation_cycles(self) -> int:
        return int(self.raw["remediation"]["max_cycles"])

    @property
    def auto_remediation_severities(self) -> tuple[str, ...]:
        return tuple(self.raw["remediation"]["auto_severities"])

    @property
    def cycle_marker(self) -> str:
        return str(self.raw["remediation"]["cycle_marker"])

    @property
    def auto_request_marker(self) -> str:
        return str(self.raw["remediation"]["auto_request_marker"])

    @property
    def max_auto_requests_per_head(self) -> int:
        return max(1, int(self.raw["remediation"].get("max_auto_requests_per_head", 1)))

    # --- merge / limits ---------------------------------------------------------------
    @property
    def merge_method(self) -> str:
        return str(self.raw["merge"]["method"])

    @property
    def resolve_fixed_reviewer_threads(self) -> bool:
        return bool(self.raw["merge"].get("resolve_fixed_reviewer_threads", False))

    @property
    def max_changed_files(self) -> int:
        return int(self.raw["limits"]["max_changed_files"])

    @property
    def max_changed_lines(self) -> int:
        return int(self.raw["limits"]["max_changed_lines"])


_REQUIRED_TABLES = ("repository", "ci", "authors", "issue", "review", "remediation", "merge",
                    "limits", "escalation")


def parse_policy(raw: dict[str, Any]) -> Policy:
    """Validate a parsed TOML document and build a `Policy`."""
    if raw.get("schema") != 1:
        raise PolicyError(f"unsupported policy schema {raw.get('schema')!r} (expected 1)")
    missing = [t for t in _REQUIRED_TABLES if not isinstance(raw.get(t), dict)]
    if missing:
        raise PolicyError(f"policy is missing table(s): {', '.join(missing)}")

    categories: list[EscalationCategory] = []
    for name, spec in raw["escalation"].items():
        if not isinstance(spec, dict) or not isinstance(spec.get("paths", []), list):
            raise PolicyError(f"escalation.{name} must be a table with a 'paths' list")
        try:
            patterns = tuple(re.compile(p) for p in spec.get("added_line_patterns", []))
        except re.error as exc:  # a broken regex must not silently disable a category
            raise PolicyError(f"escalation.{name}: invalid regex: {exc}") from exc
        categories.append(
            EscalationCategory(
                name=name,
                description=str(spec.get("description", name)),
                paths=tuple(spec.get("paths", [])),
                content_globs=tuple(spec.get("content_globs", [])),
                added_line_patterns=patterns,
            )
        )
    if not categories:
        raise PolicyError("policy defines no escalation categories")

    policy = Policy(raw=raw, categories=tuple(categories))
    # Touch every property once so a missing key fails here, not mid-merge.
    for attr in dir(Policy):
        if isinstance(getattr(Policy, attr, None), property):
            try:
                getattr(policy, attr)
            except (KeyError, TypeError, ValueError, re.error) as exc:
                raise PolicyError(f"policy value for {attr!r} is missing or invalid: {exc}") from exc
    if policy.merge_method != "squash":
        raise PolicyError("only merge.method = 'squash' is supported (ruleset allows squash only)")
    if "P0" not in policy.blocking_severities or "P1" not in policy.blocking_severities:
        raise PolicyError("review.blocking_severities must include P0 and P1")
    if policy.max_remediation_cycles < 0:
        raise PolicyError("remediation.max_cycles must be >= 0")
    return policy


def load_policy(path: Path | str = DEFAULT_POLICY_PATH) -> Policy:
    path = Path(path)
    try:
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
    except FileNotFoundError as exc:
        raise PolicyError(f"policy file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"policy file is not valid TOML: {exc}") from exc
    return parse_policy(raw)
