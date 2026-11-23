"""Write bisect_470_vs_463/ (report + per-commit summary.md + per-pair session diffs) from the scratch re-runs."""
import gzip
import hashlib
import subprocess
import sys
from pathlib import Path

import os
S = Path(os.environ["SCRATCH"])  # scratch dir holding bisect_out/
OUT = Path(sys.argv[1])
OUT.mkdir(parents=True, exist_ok=True)
REPO = Path.cwd()
TOOLS = REPO / "artifacts/validation/final_stage2-freeze-2026-11-27/benchmarks/tools"

steps = [  # (label, dir, git subject)
    ("committed artifacts/benchmarks_extended (41311fa)", REPO / "artifacts/benchmarks_extended", "committed artifact"),
    ("41311fa", S / "bisect_out/41311fa", "feat: add real-data validation and extended attack benchmarks"),
    ("444f385 (= eae85e6^)", S / "bisect_out/444f385", "docs: Stage-2 ArduPilot/Pixhawk reports ..."),
    ("eae85e6", S / "bisect_out/eae85e6", "fix: skip position-residual and yaw/course checks across a >2 s link gap"),
    ("8605cea", S / "bisect_out/8605cea", "fix(hardware): paced replay feeder ... (#30) (#86)"),
    ("3a10573", S / "bisect_out/3a10573", "feat(stage2 1/4): detectors, integrity allowlist, ... (#79)"),
    ("03e4de9", S / "bisect_out/03e4de9", "feat(stage2 2/4): IPS safety interlocks ... (#80)"),
    ("63241a1", S / "bisect_out/63241a1", "feat(stage2 3/4): universal flight hardening core ... (#81)"),
    ("b6d2ab7", S / "bisect_out/b6d2ab7", "fix(ips): classify named GNSS fix loss ... (#112)"),
    ("8e58003 = freeze tag (extended_ml_on)", REPO / "artifacts/validation/final_stage2-freeze-2026-11-27/benchmarks/extended_ml_on", "feat(stage2 4/4): dual-mode operator console ... (#82)"),
]


def md5_dec(d):
    with gzip.open(Path(d) / "decisions.csv.gz", "rt", encoding="utf-8", newline="") as fh:
        return hashlib.md5(fh.read().encode()).hexdigest()


def line(d, needle):
    for ln in (Path(d) / "summary.md").read_text(encoding="utf-8").splitlines():
        if needle in ln:
            return ln
    return "?"


rep = ["# Extended benchmark, ML on (models/isoforest.joblib 3fe74cdd...), no-grace FP drift: bisect\n",
       "Environment: SIM. Each row is a full extended-benchmark run (`scripts/benchmark_extended.py --model models/isoforest.joblib`, 116 sessions) "
       "of that commit in a scratch worktree (read-only: no commit was made from them), same machine, same shipped model. "
       "`decisions md5` is the md5 of the decompressed decisions.csv (69,600 per-decision rows).\n",
       "| code | decisions md5 | v2 no-grace TP / FP / TN / FN | v2 5 s grace TP / FP / TN / FN |", "|---|---|---|---|"]
for lab, d, _ in steps:
    ng = line(d, "no grace**").split("|")[3].strip()
    g5 = line(d, "5 s grace (baseline policy)").split("|")[3].strip()
    rep.append(f"| {lab} | `{md5_dec(d)[:12]}` | {ng} | {g5} |")
rep.append("")
rep.append("Pairwise per-session diffs (rows that differ between consecutive steps; see `diff_*.txt`):\n")
pairs = [(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7), (7, 8), (8, 9)]
for i, j in pairs:
    a, b = steps[i], steps[j]
    r = subprocess.run([sys.executable, str(TOOLS / "cmp_sessions.py"), str(a[1]), str(b[1])], capture_output=True, text=True,
                       encoding="utf-8")
    name = f"diff_{a[0].split()[0]}__{b[0].split()[0]}.txt".replace("/", "_")
    (OUT / name).write_text(f"# {a[0]}  vs  {b[0]}\n" + r.stdout, encoding="utf-8")
    tot = [x for x in r.stdout.splitlines() if x.startswith("total differing rows")][0]
    rep.append(f"- {a[0]} -> {b[0]}: {tot} (`{name}`)")
(OUT / "bisect_report.md").write_text("\n".join(rep) + "\n", encoding="utf-8")
for lab, d, _ in steps[1:9]:
    c = lab.split()[0]
    (OUT / f"summary_{c}.md").write_text((Path(d) / "summary.md").read_text(encoding="utf-8"), encoding="utf-8")
print("\n".join(rep))
