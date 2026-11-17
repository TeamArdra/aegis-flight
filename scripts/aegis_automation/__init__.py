"""AegisFlight GitHub automation: trusted review records, merge gate, orchestration.

Standard library only. These modules run inside privileged GitHub Actions jobs (the merge
orchestrator holds the merge App's token), so they must not import project code or install
third-party packages. Documentation: docs/AUTONOMOUS_PIPELINE.md.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "1.0.0"
