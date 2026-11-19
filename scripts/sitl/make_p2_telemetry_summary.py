"""Summarize one or more P2 telemetry / firmware / restricted-visibility trial manifests (#24)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def build_summary(manifests: list[Path]) -> str:
    lines = [
        "# SITL Proxy Telemetry / Firmware / Restricted-Visibility Trial Summary",
        "",
        "| Trial | Scenario | Seed | Frames Seen | Modified | Injected | Signed Skipped | Decisions | Threats |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for path in sorted(manifests):
        d = json.loads(path.read_text(encoding="utf-8"))
        lines.append(
            f"| `{path.name}` | `{d.get('scenario')}` | {d.get('seed')} | "
            f"{d.get('frames_seen', 0)} | {d.get('frames_modified', 0)} | "
            f"{d.get('frames_injected', 0)} | {d.get('frames_skipped_signed', 0)} | "
            f"{d.get('n_decisions', 0)} | {d.get('n_threats', 0)} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("manifests", nargs="+", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build_summary(args.manifests), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
