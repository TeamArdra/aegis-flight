"""Shared result format for the real-radio test tools.

Every phase tool writes ``<out>/<phase>.json`` through ``PhaseResult`` so ``report.py`` can assemble one report:

    {"phase": "p2_passive", "started": <epoch>, "ended": <epoch>, "passed": bool,
     "checks": [{"name", "passed", "value", "threshold", "note"}], "metrics": {...}, "artifacts": ["raw.log", ...]}
"""

from __future__ import annotations

import json
import time
from pathlib import Path


class PhaseResult:
    def __init__(self, phase: str, out_dir: str | Path):
        self.phase = phase
        self.out = Path(out_dir)
        self.out.mkdir(parents=True, exist_ok=True)
        self.started = time.time()
        self.checks: list[dict] = []
        self.metrics: dict = {}
        self.artifacts: list[str] = []

    def check(self, name: str, passed: bool, value=None, threshold=None, note: str = "") -> bool:
        self.checks.append({"name": name, "passed": bool(passed), "value": value, "threshold": threshold, "note": note})
        return bool(passed)

    def artifact(self, filename: str) -> None:
        self.artifacts.append(filename)

    def save(self) -> Path:
        doc = {"phase": self.phase, "started": self.started, "ended": time.time(),
               "passed": all(c["passed"] for c in self.checks) if self.checks else False,
               "checks": self.checks, "metrics": self.metrics, "artifacts": self.artifacts}
        path = self.out / f"{self.phase}.json"
        path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
        return path
