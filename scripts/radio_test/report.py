#!/usr/bin/env python3
"""Assemble ``report.md`` from a radio-test run directory.

    python scripts/radio_test/report.py RUN_DIR [--out report.md] [--expect p1_link,p2_passive] [--docs-section]

Reads every ``PhaseResult`` JSON (``results.py``) and every ``pi_monitor*_summary.json`` in RUN_DIR. Missing or
unreadable files are noted, never fatal. ``--docs-section`` also prints (and saves as ``docs_section.md``) a section for
docs/INLINE_IPS.md. Exit code 0 only when at least one phase ran and every phase passed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

DOCS_TITLE = "Real radio test (Raspberry Pi 3B+ + SiK radios)"


def load_run(run_dir: Path) -> tuple[list[dict[str, Any]], list[tuple[str, dict[str, Any]]], list[str]]:
    """(phases sorted by name, [(file name, monitor summary)], warnings) from a run directory."""
    phases: list[dict[str, Any]] = []
    monitors: list[tuple[str, dict[str, Any]]] = []
    warnings: list[str] = []
    for path in sorted(run_dir.glob("*.json")):
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            warnings.append(f"{path.name}: unreadable ({exc.__class__.__name__})")
            continue
        if not isinstance(doc, dict):
            continue
        if path.name.startswith("pi_monitor") and "summary" in path.name:
            monitors.append((path.name, doc))
        elif "phase" in doc and isinstance(doc.get("checks"), list):
            doc.setdefault("metrics", {})
            phases.append(doc)
    phases.sort(key=lambda p: str(p["phase"]))
    return phases, monitors, warnings


def fmt(v: Any) -> str:
    """Compact, table-safe rendering of a value."""
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, float):
        return f"{v:.4g}"
    if isinstance(v, (dict, list)):
        v = json.dumps(v, default=str)
    return str(v).replace("|", "/").replace("\n", " ")


def flat_metrics(metrics: dict[str, Any], prefix: str = "", depth: int = 2) -> list[tuple[str, Any]]:
    """Scalar leaves of a metrics dict, nested keys joined with dots (up to ``depth`` levels)."""
    out: list[tuple[str, Any]] = []
    for k, v in metrics.items():
        name = f"{prefix}{k}"
        if isinstance(v, dict) and depth > 1:
            out += flat_metrics(v, name + ".", depth - 1)
        elif not isinstance(v, (dict, list)):
            out.append((name, v))
    return out


def key_metrics(phase: dict[str, Any], n: int = 4) -> str:
    items = flat_metrics(phase.get("metrics") or {})[:n]
    return ", ".join(f"{k}={fmt(v)}" for k, v in items) or "-"


def duration(phase: dict[str, Any]) -> str:
    try:
        return f"{float(phase['ended']) - float(phase['started']):.0f}s"
    except (KeyError, TypeError, ValueError):
        return "-"


def phase_ok(phase: dict[str, Any]) -> bool:
    return bool(phase.get("passed")) and all(c.get("passed") for c in phase.get("checks", []))


def failed_checks(phases: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    return [(str(p["phase"]), c) for p in phases for c in p.get("checks", []) if not c.get("passed")]


def monitor_lines(name: str, m: dict[str, Any]) -> tuple[list[str], list[str]]:
    """(facts, warnings) for one pi_monitor summary."""
    facts: list[str] = []
    warns: list[str] = []
    if not m.get("samples"):
        return [f"{name}: no samples"], [f"{name}: monitor recorded no samples"]
    facts.append(f"{m['samples']} samples over {fmt(m.get('duration_s'))} s")
    cpu, rss, temp, thr = m.get("cpu_percent"), m.get("rss_mib"), m.get("temp_c"), m.get("throttling") or {}
    if cpu:
        facts.append(f"bridge CPU mean {fmt(cpu['mean'])}% / peak {fmt(cpu['peak'])}% of one core")
    if rss:
        facts.append(f"RSS mean {fmt(rss['mean'])} / peak {fmt(rss['peak'])} MiB, slope {fmt(rss.get('slope_mib_per_min'))} MiB/min")
        if rss.get("memory_growth_flag"):
            warns.append(f"memory growth flagged (slope {fmt(rss.get('slope_mib_per_min'))} MiB/min)")
    if temp:
        facts.append(f"SoC temperature mean {fmt(temp['mean'])} / peak {fmt(temp['peak'])} C")
    if thr.get("readable"):
        if thr.get("seen_now"):
            warns.append("throttling seen during the run: " + ", ".join(thr.get("flags_seen_now", [])))
        since = thr.get("flags_since_boot") or []
        facts.append(f"throttled at end {thr.get('final_raw')}" + (f" (since boot: {', '.join(since)})" if since else ""))
    else:
        warns.append("vcgencmd get_throttled unreadable: throttling unknown")
    if m.get("process_lost_samples"):
        warns.append(f"bridge process absent in {m['process_lost_samples']} samples")
    if m.get("status_errors"):
        warns.append(f"status API failed in {m['status_errors']} samples")
    delta = (m.get("counters") or {}).get("delta")
    if delta:
        facts.append("counter deltas: " + ", ".join(f"{k}={v}" for k, v in delta.items()))
        if (m.get("counters") or {}).get("counter_resets"):
            warns.append("bridge counters went backwards (bridge restarted during the run)")
    return facts, warns


def build_report(run_dir: Path, phases: list[dict[str, Any]], monitors: list[tuple[str, dict[str, Any]]],
                 warnings: list[str], expect: list[str] | None = None) -> str:
    names = {str(p["phase"]) for p in phases}
    missing = [e for e in (expect or []) if e not in names]
    bad = failed_checks(phases)
    all_ok = bool(phases) and all(phase_ok(p) for p in phases) and not missing
    verdict = "PASS" if all_ok else ("NO DATA" if not phases else "FAIL")
    lines = [f"# Radio test report: {run_dir.name}", "",
             f"Generated {time.strftime('%Y-%m-%d %H:%M:%S')}. Overall: **{verdict}** "
             f"({sum(phase_ok(p) for p in phases)}/{len(phases)} phases passed, {len(bad)} failed checks"
             + (f", {len(missing)} expected phases missing" if missing else "") + ").", ""]
    if bad:
        lines += ["## Failed checks", "", "| Phase | Check | Value | Threshold | Note |", "|---|---|---|---|---|"]
        lines += [f"| {ph} | {fmt(c.get('name'))} | {fmt(c.get('value'))} | {fmt(c.get('threshold'))} | {fmt(c.get('note'))} |"
                  for ph, c in bad]
        lines.append("")
    lines += ["## Phases", "", "| Phase | Result | Checks | Time | Key metrics |", "|---|---|---|---|---|"]
    ordered = sorted(phases, key=lambda p: (phase_ok(p), str(p["phase"])))  # failed phases first
    for p in ordered:
        cs = p.get("checks", [])
        lines.append(f"| {p['phase']} | {'PASS' if phase_ok(p) else 'FAIL'} | {sum(bool(c.get('passed')) for c in cs)}/{len(cs)} "
                     f"| {duration(p)} | {key_metrics(p)} |")
    lines += [f"| {m} | NOT RUN | - | - | no result file |" for m in missing]
    if not phases:
        lines.append("| (none) | - | - | - | no PhaseResult JSON found |")
    lines.append("")
    passed_rows = [(str(p["phase"]), c) for p in phases for c in p.get("checks", []) if c.get("passed")]
    if passed_rows:
        lines += ["## Passed checks", "", "| Phase | Check | Value | Threshold |", "|---|---|---|---|"]
        lines += [f"| {ph} | {fmt(c.get('name'))} | {fmt(c.get('value'))} | {fmt(c.get('threshold'))} |" for ph, c in passed_rows]
        lines.append("")
    lines += ["## Raspberry Pi health", ""]
    if not monitors:
        lines += ["No pi_monitor summary found (monitor not run or not pulled).", ""]
    for name, m in monitors:
        facts, warns = monitor_lines(name, m)
        lines += [f"**{name}**", ""] + [f"- {f}" for f in facts] + [f"- WARNING: {w}" for w in warns] + [""]
    if warnings:
        lines += ["## Read problems", ""] + [f"- {w}" for w in warnings] + [""]
    lines += ["## Appendix: raw metrics", ""]
    for p in phases:
        lines += [f"### {p['phase']}", "", "```json", json.dumps(p.get("metrics", {}), indent=2, default=str), "```", ""]
        if p.get("artifacts"):
            lines += ["Artifacts: " + ", ".join(str(a) for a in p["artifacts"]), ""]
    for name, m in monitors:
        lines += [f"### {name}", "", "```json", json.dumps(m, indent=2, default=str), "```", ""]
    return "\n".join(lines).rstrip() + "\n"


def build_docs_section(phases: list[dict[str, Any]], monitors: list[tuple[str, dict[str, Any]]]) -> str:
    """Markdown section for docs/INLINE_IPS.md; states only what the run files show."""
    lines = [f"## {DOCS_TITLE}", ""]
    if not phases:
        return "\n".join(lines + ["No phase results were recorded; nothing to report.", ""])
    stamp = time.strftime("%Y-%m-%d", time.localtime(min(float(p.get("started") or time.time()) for p in phases)))
    lines += [f"Run of {stamp}: `aegis ips-bridge` on a Raspberry Pi 3B+ with a SiK telemetry radio on the GCS side and the "
              "flight-controller side fed over TCP from a laptop simulator. Phases run by `scripts/radio_test/`; "
              "raw results are in the run directory.", "",
              "| Phase | Result | Checks | Key metrics |", "|---|---|---|---|"]
    for p in phases:
        cs = p.get("checks", [])
        lines.append(f"| {p['phase']} | {'pass' if phase_ok(p) else 'FAIL'} | {sum(bool(c.get('passed')) for c in cs)}/{len(cs)} "
                     f"| {key_metrics(p)} |")
    bad = failed_checks(phases)
    lines.append("")
    if bad:
        lines += ["Failed checks: " + "; ".join(f"{ph}: {c.get('name')} (value {fmt(c.get('value'))}, threshold "
                                                  f"{fmt(c.get('threshold'))})" for ph, c in bad) + ".", ""]
    for name, m in monitors:
        facts, warns = monitor_lines(name, m)
        lines += [f"Pi resources ({name}): " + "; ".join(facts) + ".", ""]
        if warns:
            lines += ["Pi warnings: " + "; ".join(warns) + ".", ""]
    lines += ["What this does not show: a flight, a real autopilot (the flight controller side is a simulator over TCP), "
              "more than the runs listed, or any Pi other than a 3B+. Numbers are from single runs.", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("run_dir")
    ap.add_argument("--out", default=None, help="report path (default: RUN_DIR/report.md)")
    ap.add_argument("--expect", default="", help="comma-separated phase names that must be present")
    ap.add_argument("--docs-section", action="store_true", help=f"also print the '{DOCS_TITLE}' docs section")
    a = ap.parse_args(argv)
    run_dir = Path(a.run_dir)
    if not run_dir.is_dir():
        print(f"report: {run_dir} is not a directory", file=sys.stderr)
        return 2
    phases, monitors, warnings = load_run(run_dir)
    expect = [e.strip() for e in a.expect.split(",") if e.strip()]
    out = Path(a.out) if a.out else run_dir / "report.md"
    out.write_text(build_report(run_dir, phases, monitors, warnings, expect), encoding="utf-8")
    print(f"wrote {out} ({len(phases)} phases, {len(monitors)} monitor summaries)")
    if a.docs_section:
        section = build_docs_section(phases, monitors)
        (run_dir / "docs_section.md").write_text(section, encoding="utf-8")
        print(section)
    names = {str(p["phase"]) for p in phases}
    return 0 if phases and all(phase_ok(p) for p in phases) and all(e in names for e in expect) else 1


if __name__ == "__main__":
    sys.exit(main())
