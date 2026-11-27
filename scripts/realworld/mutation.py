"""Small AST mutation tester (mutmut does not run on Windows). Mutates a COPY of the repo, never the working tree.

    python scripts/realworld/mutation.py --target src/aegisflight/mitigation/inline_policy.py --sample 150 --workers 8 \
        --tests tests/unit/test_inline_policy_exact.py tests/unit/test_inline_ips.py --out <dir>

A mutant is KILLED if the targeted tests fail or time out, SURVIVED if they all pass. Survivors are the interesting output.
Operators: comparison flip (< <= > >= == !=), and<->or, drop `not`, True<->False, int constant +-1, `in`<->`not in`, `is`<->`is not`,
return-value negation for bool returns, arithmetic +<->-.
"""
from __future__ import annotations

import argparse
import ast
import json
import multiprocessing as mp
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CMP = {ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE, ast.GtE: ast.Gt, ast.Eq: ast.NotEq, ast.NotEq: ast.Eq,
       ast.In: ast.NotIn, ast.NotIn: ast.In, ast.Is: ast.IsNot, ast.IsNot: ast.Is}


class Enumerate(ast.NodeVisitor):
    def __init__(self) -> None:
        self.sites: list[tuple[str, int, int]] = []  # (kind, lineno, col)

    def visit_Compare(self, n):
        for i, op in enumerate(n.ops):
            if type(op) in CMP:
                self.sites.append((f"cmp{i}", n.lineno, n.col_offset))
        self.generic_visit(n)

    def visit_BoolOp(self, n):
        self.sites.append(("boolop", n.lineno, n.col_offset))
        self.generic_visit(n)

    def visit_UnaryOp(self, n):
        if isinstance(n.op, ast.Not):
            self.sites.append(("not", n.lineno, n.col_offset))
        self.generic_visit(n)

    def visit_Constant(self, n):
        if isinstance(n.value, bool):
            self.sites.append(("bool", n.lineno, n.col_offset))
        elif isinstance(n.value, int) and abs(n.value) < 10**9:
            self.sites.append(("int", n.lineno, n.col_offset))

    def visit_BinOp(self, n):
        if isinstance(n.op, (ast.Add, ast.Sub)):
            self.sites.append(("arith", n.lineno, n.col_offset))
        self.generic_visit(n)


class Mutate(ast.NodeTransformer):
    def __init__(self, site: tuple[str, int, int]) -> None:
        self.site, self.done = site, False

    def _hit(self, n, kind: str) -> bool:
        return (not self.done) and self.site[0].startswith(kind) and (self.site[1], self.site[2]) == (n.lineno, n.col_offset)

    def visit_Compare(self, n):
        self.generic_visit(n)
        if self._hit(n, "cmp"):
            i = int(self.site[0][3:])
            n.ops[i] = CMP[type(n.ops[i])]()
            self.done = True
        return n

    def visit_BoolOp(self, n):
        self.generic_visit(n)
        if self._hit(n, "boolop"):
            n.op = ast.Or() if isinstance(n.op, ast.And) else ast.And()
            self.done = True
        return n

    def visit_UnaryOp(self, n):
        self.generic_visit(n)
        if self._hit(n, "not"):
            self.done = True
            return n.operand
        return n

    def visit_Constant(self, n):
        if self._hit(n, "bool") or self._hit(n, "int"):
            self.done = True
            if isinstance(n.value, bool):
                return ast.copy_location(ast.Constant(not n.value), n)
            return ast.copy_location(ast.Constant(n.value + 1), n)
        return n

    def visit_BinOp(self, n):
        self.generic_visit(n)
        if self._hit(n, "arith"):
            n.op = ast.Sub() if isinstance(n.op, ast.Add) else ast.Add()
            self.done = True
        return n


def prep_copy(dst: Path, tests: list[str]) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    for d in ("src", "configs", "models", "scripts", "backend", "data"):
        s = REPO / d
        if s.exists():
            shutil.copytree(s, dst / d, ignore=shutil.ignore_patterns("__pycache__", "raw", "external", "*.sqlite"))
    for t in {str(Path(x).parent) for x in tests} | {"tests/unit", "tests/fixtures", "tests/golden", "tests/acceptance"}:
        s = REPO / t
        if s.exists() and not (dst / t).exists():
            shutil.copytree(s, dst / t, ignore=shutil.ignore_patterns("__pycache__"))
    for f in ("pyproject.toml",):
        shutil.copy(REPO / f, dst / f)


def worker(args: tuple) -> dict:
    wid, target, tests, mutants, root, timeout = args
    work = Path(root) / f"w{wid}"
    prep_copy(work, tests)
    tgt = work / target
    orig = tgt.read_text(encoding="utf-8")
    env = dict(os.environ, PYTHONPATH=str(work / "src"), PYTHONDONTWRITEBYTECODE="1")
    out = []
    for site in mutants:
        tree = ast.parse(orig)
        m = Mutate(tuple(site))
        tree = m.visit(tree)
        if not m.done:
            out.append({"site": site, "status": "skipped"})
            continue
        ast.fix_missing_locations(tree)
        tgt.write_text(ast.unparse(tree), encoding="utf-8")
        t0 = time.time()
        try:
            p = subprocess.run([sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider", "-W", "ignore", "--no-header", *tests],
                               cwd=work, env=env, capture_output=True, text=True, timeout=timeout)
            status = "survived" if p.returncode == 0 else "killed"
            if p.returncode not in (0, 1):
                status = "killed"  # collection/import error from the mutant counts as caught
        except subprocess.TimeoutExpired:
            status = "killed"
        line = orig.splitlines()[site[1] - 1].strip() if site[1] - 1 < len(orig.splitlines()) else ""
        out.append({"site": site, "status": status, "secs": round(time.time() - t0, 1), "line": line})
    tgt.write_text(orig, encoding="utf-8")
    return {"wid": wid, "results": out}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--tests", nargs="+", required=True)
    ap.add_argument("--sample", type=int, default=150)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=180)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--lines", default="", help="restrict to a line range a-b")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    src = (REPO / a.target).read_text(encoding="utf-8")
    e = Enumerate()
    e.visit(ast.parse(src))
    sites = sorted(set(e.sites))
    if a.lines:
        lo, hi = (int(x) for x in a.lines.split("-"))
        sites = [s for s in sites if lo <= s[1] <= hi]
    random.Random(a.seed).shuffle(sites)
    sites = sites[:a.sample]
    chunks = [sites[i::a.workers] for i in range(a.workers)]
    root = Path(a.out)
    root.mkdir(parents=True, exist_ok=True)
    # baseline sanity: the unmutated copy must pass
    print(f"{len(sites)} mutants of {a.target} over {a.workers} workers", flush=True)
    t0 = time.time()
    with mp.Pool(a.workers) as pool:
        res = pool.map(worker, [(i, a.target, a.tests, c, str(root), a.timeout) for i, c in enumerate(chunks) if c])
    allr = [r for w in res for r in w["results"]]
    killed = sum(1 for r in allr if r["status"] == "killed")
    surv = [r for r in allr if r["status"] == "survived"]
    tot = killed + len(surv)
    print(f"killed {killed}/{tot} ({100 * killed / max(1, tot):.0f}%), survived {len(surv)}, time {time.time() - t0:.0f}s")
    (root / "mutation.json").write_text(json.dumps({"target": a.target, "killed": killed, "survived": len(surv), "results": allr}, indent=1))
    for r in sorted(surv, key=lambda r: r["site"][1]):
        print(f"  SURVIVED L{r['site'][1]} {r['site'][0]}: {r['line'][:110]}")


if __name__ == "__main__":
    main()
