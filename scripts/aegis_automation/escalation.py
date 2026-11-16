"""Deterministic human-escalation classifier.

The merge gate never relies on the model alone to decide whether a change is
security-sensitive. This module classifies a PR from GitHub's own file list (paths,
renames, added lines, sizes) and from labels, using the categories in policy.toml.
Any match means: review normally, but never approve or merge automatically.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any

from .policy import Policy


@dataclass(frozen=True)
class Escalation:
    category: str
    reason: str
    evidence: tuple[str, ...] = ()

    def render(self) -> str:
        ev = ", ".join(f"`{e}`" for e in self.evidence[:6])
        more = f" (+{len(self.evidence) - 6} more)" if len(self.evidence) > 6 else ""
        return f"**{self.category}**: {self.reason}" + (f" ({ev}{more})" if ev else "")


def _matches(path: str, globs: Iterable[str]) -> bool:
    return any(fnmatchcase(path, g) for g in globs)


def added_lines(patch: str | None) -> list[str]:
    if not patch:
        return []
    return [ln[1:] for ln in patch.splitlines() if ln.startswith("+") and not ln.startswith("+++")]


def classify(files: list[dict[str, Any]], labels: Iterable[str], policy: Policy) -> list[Escalation]:
    """Return every escalation that applies. Empty list = routine change."""
    found: list[Escalation] = []
    label_hits = sorted(set(labels) & set(policy.escalation_labels))
    if label_hits:
        found.append(Escalation("labels", "PR or linked issue carries an escalation label",
                                tuple(label_hits)))

    for cat in policy.categories:
        path_hits: list[str] = []
        content_hits: list[str] = []
        for f in files:
            names = [f.get("filename", "")]
            if f.get("previous_filename"):
                names.append(f["previous_filename"])
            if any(_matches(n, cat.paths) for n in names if n):
                path_hits.append(names[0])
                continue
            if cat.added_line_patterns and _matches(names[0], cat.content_globs or ("*",)):
                for line in added_lines(f.get("patch")):
                    if any(p.search(line) for p in cat.added_line_patterns):
                        content_hits.append(names[0])
                        break
        if path_hits:
            found.append(Escalation(cat.name, cat.description, tuple(path_hits)))
        if content_hits:
            found.append(Escalation(cat.name, f"{cat.description} (added content)",
                                    tuple(content_hits)))

    total_lines = sum(int(f.get("additions", 0)) + int(f.get("deletions", 0)) for f in files)
    if len(files) > policy.max_changed_files:
        found.append(Escalation("size", f"{len(files)} files changed (limit "
                                        f"{policy.max_changed_files})"))
    if total_lines > policy.max_changed_lines:
        found.append(Escalation("size", f"{total_lines} lines changed (limit "
                                        f"{policy.max_changed_lines})"))

    unverifiable = [
        f.get("filename", "?")
        for f in files
        if f.get("status") != "removed" and int(f.get("changes", 0)) > 0 and not f.get("patch")
    ]
    if unverifiable:
        found.append(Escalation("unverifiable", "binary or oversized diff the reviewer cannot "
                                                "read in full", tuple(unverifiable)))
    return found
