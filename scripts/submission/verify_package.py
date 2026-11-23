#!/usr/bin/env python
"""Verify a Stage-2 submission package directory (issue #34; the demo video is #33).

The human team assembles the package (layout: ``docs/SUBMISSION.md``). This script only *checks* it and exits
non-zero with a list of every problem. It is standard library only, reads files under the package directory, and
never downloads or sends anything. Nothing is repaired: an unmatched number or a hash mismatch is reported and a
human decides what to do.

    python scripts/submission/verify_package.py <package_dir> [--report report/report.md] [--strict]

Exit status: 0 = every check passed; 1 = at least one failure (with ``--strict``, warnings count as failures);
2 = usage error (not a directory).

Checks (each prints PASS / FAIL / WARN and its findings):

``required``     every item of ``REQUIRED`` below exists (the list is the #34 checklist turned into globs; edit it
                 here if the maintainers change the layout).
``manifest``     ``MANIFEST.sha256`` (or ``CHECKSUMS.sha256``, the name #34 uses) is ``sha256sum`` format; every
                 listed file exists inside the package and its SHA-256 matches. Files not listed are WARN.
                 ``models/MODELS.sha256`` must be well formed; the model files it names are checked if present
                 (under decision D3 they normally are not bundled).
``forbidden``    no ``*.joblib``, ``*.sqlite``, captures (``*.tlog``, ``*.rawbin``, ``*.ulg``, ``*.pcap``),
                 secret-looking file names or contents, ``.claude/``, ``.git/``, ``.venv/``, ``node_modules/``,
                 symlinks. ``--allow PATTERN`` (fnmatch on the package-relative path) lets a human-approved file
                 through; contents are still scanned for secrets. Matched secret text is never printed.
``placeholders`` no ``AWAITING``, ``TODO`` or ``TBD`` in README*, INSTALL*, REPRODUCE*, top-level text files,
                 ``report/`` and ``configs/`` (#34). A PDF cannot be scanned here: see the human checklist.
``junit``        every ``results/validation/*.xml`` parses (DTDs are refused), has tests, and 0 failures/errors.
``reproduce``    REPRODUCE.md has a section (heading) with a code block, or an explicit "not run"/"descoped"
                 statement, for each topic of ``REPRODUCE_TOPICS``. This proves the topic is addressed, not that the
                 command is right: run them.
``numbers``      the report-number heuristic, below.

Report-number heuristic (deliberately simple; it reports, it never decides). Text reports are the ``--report``
files (default ``report/**/*.md`` and ``REPORT.md``). Fenced code blocks and headings are skipped. In each paragraph
(or table row; a table row without its own reference inherits the table's) it finds:

* artifact references: ``artifacts/...`` paths. A path that does not exist in the package (globs allowed, ``..``
  and unfilled ``<placeholder>`` rejected) is a FAIL.
* result numbers: percentages (``99.7%``), decimals (``0.9971``), fractions (``10/10``), and integers of four digits
  or more (years excluded; section/figure/table numbers, versions, dates, URLs and issue numbers removed first).
  Integers below 1,000 are ignored on purpose: they are too ambiguous for a text heuristic.

A result number in a paragraph that cites artifacts must appear verbatim (not as a longer number) in at least one
cited text artifact (``.md .json .jsonl .csv .tsv .txt .yaml .yml``; a directory means every such file under it).
A percentage also matches an artifact ratio that rounds to it (``0.997`` for ``99.7%``). Otherwise FAIL "not found".
A result number in a paragraph that cites no artifact is WARN "unsourced" (it may come from elsewhere). If no text
report exists the whole check is reported as SKIPPED (WARN): a PDF-only package cannot be number-checked here.
``--allow-numbers FILE`` lists numbers (one per line, as printed, ``#`` comments) that a human accepted.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

# --- configuration: the #34 checklist as data -----------------------------------------------------------------

# (id, issue, description, alternative glob patterns relative to the package; matching FILES, any one is enough)
REQUIRED: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("readme", "#34", "README.md", ("README.md",)),
    ("install", "#34", "INSTALL.md", ("INSTALL.md",)),
    ("reproduce", "#34", "REPRODUCE.md", ("REPRODUCE.md",)),
    ("manifest", "#34", "MANIFEST.sha256 (or CHECKSUMS.sha256)", ("MANIFEST.sha256", "CHECKSUMS.sha256")),
    ("report", "#31/#34", "final report PDF", ("report/*.pdf",)),
    ("video", "#33", "demonstration video, or VIDEO_LINK.txt if the organisers require a link",
     ("video/*.mp4", "video/*.mkv", "video/*.mov", "video/*.webm", "video/VIDEO_LINK.txt")),
    ("model-hashes", "#11/#34 (D3)", "models/MODELS.sha256", ("models/MODELS.sha256",)),
    ("junit", "#12/#34", "clean-install JUnit XML", ("results/validation/*.xml",)),
    ("sitl-campaign", "#26", "SITL campaign outputs", ("artifacts/sitl/final_*/**/*",)),
    ("bridge-raw-logs", "#26", "inline-bridge raw logs (hal/run_archive.py file names)",
     ("artifacts/sitl/final_*/**/frames_down.jsonl",)),
    ("link-stress", "#27", "link-stress sweep outputs", ("artifacts/validation/final_*/link_stress/**/*",)),
    ("benchmark-extended", "#27", "regenerated extended benchmark", ("artifacts/benchmarks_extended/summary.md",)),
    ("stage2-metrics", "#28", "Stage-2 metrics outputs", ("artifacts/validation/stage2_metrics_*/metrics.json",)),
    ("capture-hashes", "#29/#30", "SHA-256 manifest of the new captures",
     ("artifacts/hardware/**/*.sha256", "artifacts/hardware/**/*sha256*.txt")),
    ("pi-run", "#30", "companion-computer paced-replay output", ("artifacts/hardware/companion_*/**/*.json",)),
)

# (label, regex for the heading text) : each needs a REPRODUCE.md section with a command (#34)
REPRODUCE_TOPICS: tuple[tuple[str, str], ...] = (
    ("walk test", r"walk"),
    ("Pi run", r"\bpi\b|raspberry"),
    ("link-stress sweep", r"link[- ]?stress"),
    ("restricted-visibility injection", r"restricted[- ]?visibility"),
    ("telemetry SITL", r"telemetry"),
    ("firmware SITL", r"firmware"),
)
NOT_RUN = re.compile(r"\b(not run|descoped|de-scoped|not applicable)\b", re.IGNORECASE)

FORBIDDEN_DIRS = (".claude", ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
                  ".ruff_cache", ".mypy_cache")
FORBIDDEN_DIR_PATHS = ("frontend/dist",)
FORBIDDEN_SUFFIXES: tuple[tuple[str, str], ...] = (
    (".joblib", "trained model (git-ignored; ship its SHA-256, see docs/MODEL_DISTRIBUTION.md)"),
    (".sqlite", "event database"), (".sqlite3", "event database"),
    (".sqlite-wal", "event database"), (".sqlite-shm", "event database"),
    (".tlog", "raw capture"), (".rawbin", "raw capture"), (".ulg", "raw capture"), (".ulog", "raw capture"),
    (".pcap", "raw capture"), (".pcapng", "raw capture"),
    (".pem", "secret"), (".key", "secret"), (".p12", "secret"), (".pfx", "secret"), (".keystore", "secret"),
    (".secret", "secret"), (".pyc", "bytecode"),
)
FORBIDDEN_NAMES = ("AEGISFLIGHT_STAGE2_ENGINEERING_BRIEF.md", "LOCAL_AEGISFLIGHT_END_TO_END.md", ".env", ".netrc")
FORBIDDEN_NAME_GLOBS = (".env.*", "id_rsa*", "id_ed25519*", "credentials*.json")
NAME_EXEMPT = (".env.example",)

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("private key block", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("GitHub token", re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("AWS access key id", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("Anthropic API key", re.compile(rb"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("Slack token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("key/token assignment",
     re.compile(rb"(?i)\b(?:AEGIS_[A-Z_]*(?:KEY|TOKEN)|SIGNING_KEY|API_TOKEN|SECRET_KEY)\s*[=:]\s*['\"]?[A-Za-z0-9+/=_-]{16,}")),
)

TEXT_SUFFIXES = (".md", ".txt", ".rst", ".yaml", ".yml", ".json", ".toml")
SEARCH_SUFFIXES = (".md", ".json", ".jsonl", ".csv", ".tsv", ".txt", ".yaml", ".yml")
PLACEHOLDER = re.compile(r"\b(AWAITING|TODO|TBD)\b")
SCAN_BYTES = 16 * 1024 * 1024          # secret scan: first 16 MiB of each file
SEARCH_FILE_BYTES = 8 * 1024 * 1024    # number search: first 8 MiB of each artifact file
SEARCH_FILES_PER_REF = 500
CACHE_BYTES = 1024 * 1024
JUNIT_MAX_BYTES = 20 * 1024 * 1024
MANIFEST_NAMES = ("MANIFEST.sha256", "CHECKSUMS.sha256")
SHA_LINE = re.compile(r"^\\?([0-9a-fA-F]{64}) [ *](.+)$")


@dataclass
class Result:
    order: list[str] = field(default_factory=list)
    failures: dict[str, list[str]] = field(default_factory=dict)
    warnings: dict[str, list[str]] = field(default_factory=dict)

    def start(self, check: str) -> None:
        self.order.append(check)

    def fail(self, check: str, msg: str) -> None:
        self.failures.setdefault(check, []).append(msg)

    def warn(self, check: str, msg: str) -> None:
        self.warnings.setdefault(check, []).append(msg)


# --- helpers ---------------------------------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def glob_files(root: Path, pattern: str) -> list[str]:
    """Package-relative POSIX paths of regular files (not symlinks) matching ``pattern``."""
    out = []
    for p in root.glob(pattern):
        if p.is_file() and not p.is_symlink():
            out.append(p.relative_to(root).as_posix())
    return sorted(out)


def scan_tree(root: Path, allow: list[str]) -> tuple[list[str], list[str]]:
    """Return (kept file paths, forbidden-item findings). Forbidden directories are not descended into."""
    files: list[str] = []
    problems: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = PurePosixPath(Path(dirpath).relative_to(root).as_posix())
        keep = []
        for d in sorted(dirnames):
            rel = str(rel_dir / d)
            if Path(dirpath, d).is_symlink():
                problems.append(f"{rel}: symlink (a package must not point outside itself)")
            elif d in FORBIDDEN_DIRS or rel in FORBIDDEN_DIR_PATHS:
                problems.append(f"{rel}/: forbidden directory")
            else:
                keep.append(d)
        dirnames[:] = keep
        for name in sorted(filenames):
            rel = str(rel_dir / name)
            if Path(dirpath, name).is_symlink():
                problems.append(f"{rel}: symlink (a package must not point outside itself)")
                continue
            files.append(rel)
            reason = forbidden_reason(rel, name)
            if reason and not any(fnmatch.fnmatchcase(rel, pat) for pat in allow):
                problems.append(f"{rel}: forbidden file ({reason})")
    return files, problems


def forbidden_reason(rel: str, name: str) -> str | None:
    low = name.lower()
    if name in NAME_EXEMPT:
        return None
    for suffix, why in FORBIDDEN_SUFFIXES:
        if low.endswith(suffix):
            return why
    if name in FORBIDDEN_NAMES:
        return "local or secret file"
    if any(fnmatch.fnmatchcase(low, g) for g in FORBIDDEN_NAME_GLOBS):
        return "secret"
    return None


def read_text(path: Path, limit: int = SEARCH_FILE_BYTES) -> str:
    with path.open("rb") as fh:
        return fh.read(limit).decode("utf-8", errors="replace")


def parse_sha_file(path: Path) -> tuple[list[tuple[str, str, int]], list[str]]:
    entries, errors = [], []
    for n, line in enumerate(read_text(path).splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = SHA_LINE.match(line.rstrip("\r"))
        if not m:
            errors.append(f"{path.name}:{n}: not sha256sum format ('<64 hex>  <path>')")
        else:
            entries.append((m.group(1).lower(), m.group(2), n))
    return entries, errors


# --- checks ----------------------------------------------------------------------------------------------------

def check_required(root: Path, res: Result) -> None:
    res.start("required")
    for ident, issue, desc, patterns in REQUIRED:
        if not any(glob_files(root, p) for p in patterns):
            res.fail("required", f"[{ident}] missing ({issue}): {desc}; looked for {', '.join(patterns)}")


def find_manifest(root: Path) -> Path | None:
    for name in MANIFEST_NAMES:
        if (root / name).is_file():
            return root / name
    return None


def _hash_entries(base: Path, entries: list[tuple[str, str, int]], label: str, res: Result,
                  *, must_exist: bool) -> set[str]:
    listed: set[str] = set()
    base_res = base.resolve()
    for digest, name, n in entries:
        target = (base / name)
        try:
            inside = target.resolve().is_relative_to(base_res)
        except OSError:
            inside = False
        if not inside or PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts:
            res.fail("manifest", f"{label}:{n}: path escapes the package: {name}")
            continue
        listed.add(PurePosixPath(name).as_posix())
        if target.is_symlink() or not target.is_file():
            if must_exist:
                res.fail("manifest", f"{label}:{n}: listed file is missing: {name}")
        elif sha256_file(target) != digest:
            res.fail("manifest", f"{label}:{n}: SHA-256 mismatch: {name}")
    return listed


def check_manifest(root: Path, files: list[str], res: Result) -> None:
    res.start("manifest")
    manifest = find_manifest(root)
    if manifest is None:
        res.fail("manifest", "no MANIFEST.sha256 or CHECKSUMS.sha256 in the package root")
    else:
        entries, errors = parse_sha_file(manifest)
        for e in errors:
            res.fail("manifest", e)
        if not entries and not errors:
            res.fail("manifest", f"{manifest.name} lists no files")
        listed = _hash_entries(root, entries, manifest.name, res, must_exist=True)
        for rel in files:
            if rel not in listed and rel not in MANIFEST_NAMES:
                res.warn("manifest", f"not covered by {manifest.name}: {rel}")
    models = root / "models" / "MODELS.sha256"
    if models.is_file():
        entries, errors = parse_sha_file(models)
        for e in errors:
            res.fail("manifest", f"models/{e}")
        if not entries and not errors:
            res.fail("manifest", "models/MODELS.sha256 lists no files")
        _hash_entries(root / "models", entries, "models/MODELS.sha256", res, must_exist=False)


def check_forbidden(root: Path, files: list[str], problems: list[str], res: Result) -> None:
    res.start("forbidden")
    for p in problems:
        res.fail("forbidden", p)
    for rel in files:
        try:
            with (root / rel).open("rb") as fh:
                data = fh.read(SCAN_BYTES)
        except OSError as exc:
            res.fail("forbidden", f"{rel}: unreadable ({exc.strerror})")
            continue
        if b"\0" in data[:4096]:
            continue
        for label, pat in SECRET_PATTERNS:
            m = pat.search(data)
            if m:
                line = data.count(b"\n", 0, m.start()) + 1
                res.fail("forbidden", f"{rel}:{line}: looks like a {label} (text not shown)")


def check_placeholders(root: Path, files: list[str], extra: list[str], res: Result) -> None:
    res.start("placeholders")
    for rel in files:
        name = PurePosixPath(rel).name.upper()
        top = "/" not in rel
        scoped = (name.startswith(("README", "INSTALL", "REPRODUCE")) or rel.startswith(("report/", "configs/"))
                  or top or any(fnmatch.fnmatchcase(rel, g) for g in extra))
        if not scoped or not rel.lower().endswith(TEXT_SUFFIXES):
            continue
        for n, line in enumerate(read_text(root / rel, SCAN_BYTES).splitlines(), 1):
            m = PLACEHOLDER.search(line)
            if m:
                res.fail("placeholders", f"{rel}:{n}: {m.group(1)}")


def check_junit(root: Path, res: Result) -> None:
    res.start("junit")
    for rel in glob_files(root, "results/validation/*.xml"):
        path = root / rel
        if path.stat().st_size > JUNIT_MAX_BYTES:
            res.fail("junit", f"{rel}: larger than {JUNIT_MAX_BYTES} bytes")
            continue
        raw = path.read_bytes()
        if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
            res.fail("junit", f"{rel}: contains a DTD/entity declaration (refused)")
            continue
        try:
            tree = ET.fromstring(raw)
        except ET.ParseError as exc:
            res.fail("junit", f"{rel}: not valid XML ({exc})")
            continue
        suites = [tree] if tree.tag == "testsuite" else [s for s in tree if s.tag == "testsuite"]
        if not suites:
            res.fail("junit", f"{rel}: no <testsuite> element (not JUnit XML)")
            continue
        try:
            tests = sum(int(s.get("tests", "0")) for s in suites)
            bad = sum(int(s.get("failures", "0")) + int(s.get("errors", "0")) for s in suites)
        except ValueError:
            res.fail("junit", f"{rel}: non-numeric tests/failures/errors attribute")
            continue
        if tests == 0:
            res.fail("junit", f"{rel}: 0 tests recorded")
        if bad:
            res.fail("junit", f"{rel}: {bad} failure(s)/error(s) of {tests} tests (#34 requires 0)")


def check_reproduce(root: Path, res: Result) -> None:
    res.start("reproduce")
    path = root / "REPRODUCE.md"
    if not path.is_file():
        return                                    # already a 'required' failure
    sections: list[tuple[str, str]] = []          # (heading text, body)
    head, body = "", []
    for line in read_text(path).splitlines():
        if re.match(r"^#{1,6}\s", line):
            sections.append((head, "\n".join(body)))
            head, body = line.lstrip("# ").strip(), []
        else:
            body.append(line)
    sections.append((head, "\n".join(body)))
    for label, pattern in REPRODUCE_TOPICS:
        hit = [(h, b) for h, b in sections if h and re.search(pattern, h, re.IGNORECASE)]
        if not hit:
            res.fail("reproduce", f"no section heading for: {label}")
        elif not any("```" in b or NOT_RUN.search(b) for _, b in hit):
            res.fail("reproduce", f"section for '{label}' has no code block and no 'not run'/'descoped' statement")


# --- report-number heuristic -----------------------------------------------------------------------------------

ARTIFACT_REF = re.compile(r"artifacts/[A-Za-z0-9_./*\-]+")
_NOISE = re.compile(
    r"(?:§|\bSec(?:tion)?\.?|\bFig(?:ure)?\.?|\bTable|\bAppendix|\bEq\.?|\bv|#)\s?[A-Z]?\d+(?:\.\d+)*"
    r"|\b\d+\.\d+\.\d+[\w.\-]*|\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}:\d{2}(?::\d{2})?\b|https?://\S+|\]\([^)]*\)")
_NUM = re.compile(
    r"(?<![\w.,/])(?P<pct>\d+(?:\.\d+)?)\s?%"
    r"|(?<![\w.,/])(?P<frac>\d+/\d+)(?![\w/])"
    r"|(?<![\w.,/])(?P<dec>\d+\.\d+)(?!\w|\.\d)"
    r"|(?<![\w.,/])(?P<int>\d{1,3}(?:,\d{3})+|\d{4,})(?!\w|[.,]\d)")
_DEC = re.compile(r"(?<![\d.])\d+\.\d+(?!\d)")


def _literal(value: str, text: str) -> bool:
    return re.search(r"(?<![\d.])" + re.escape(value) + r"(?!\d)", text) is not None


def _ratio_rounds_to(pct: str, text: str) -> bool:
    places = len(pct.split(".")[1]) if "." in pct else 0
    for m in _DEC.finditer(text):
        if f"{float(m.group()) * 100:.{places}f}" == pct:
            return True
    return False


def number_in(kind: str, value: str, text: str) -> bool:
    if kind == "frac":
        a, b = value.split("/")
        return _literal(value, text) or re.search(rf"\b{a} of {b}\b", text) is not None
    if kind == "int":
        return _literal(value, text) or _literal(value.replace(",", ""), text) or _literal(f"{int(value.replace(',', '')):,}", text)
    if kind == "pct":
        return _literal(value, text) or _ratio_rounds_to(value, text)
    return _literal(value, text)


def report_blocks(text: str) -> list[tuple[str, list[tuple[int, str]]]]:
    """Split markdown into ('para'|'table', [(lineno, line)]) blocks; code fences and headings are dropped."""
    blocks: list[tuple[str, list[tuple[int, str]]]] = []
    cur: list[tuple[int, str]] = []
    kind = "para"
    fence = False

    def flush() -> None:
        nonlocal cur
        if cur:
            blocks.append((kind, cur))
        cur = []

    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith(("```", "~~~")):
            fence = not fence
            flush()
            continue
        if fence or re.match(r"^#{1,6}\s", s):
            flush()
            continue
        if not s:
            flush()
            continue
        k = "table" if s.startswith("|") else "para"
        if k != kind:
            flush()
            kind = k
        cur.append((n, line))
    flush()
    return blocks


class ArtifactIndex:
    """Resolves ``artifacts/...`` references inside the package and caches small file texts."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._resolved: dict[str, tuple[bool, list[Path], bool]] = {}
        self._cache: dict[Path, str] = {}

    def resolve(self, ref: str) -> tuple[bool, list[Path], bool]:
        """(exists, searchable text files, truncated)."""
        if ref in self._resolved:
            return self._resolved[ref]
        found: list[Path] = []
        if ".." in PurePosixPath(ref).parts:
            out = (False, [], False)
        else:
            matches = list(self.root.glob(ref)) if "*" in ref else [self.root / ref]
            matches = [m for m in matches if m.exists() and m.resolve().is_relative_to(self.root.resolve())]
            truncated = False
            for m in matches:
                cands = [m] if m.is_file() else sorted(x for x in m.rglob("*") if x.is_file())
                for c in cands:
                    if c.suffix.lower() in SEARCH_SUFFIXES and not c.is_symlink():
                        if len(found) >= SEARCH_FILES_PER_REF:
                            truncated = True
                            break
                        found.append(c)
            out = (bool(matches), found, truncated)
        self._resolved[ref] = out
        return out

    def text(self, path: Path) -> str:
        if path in self._cache:
            return self._cache[path]
        txt = read_text(path)
        if len(txt) <= CACHE_BYTES:
            self._cache[path] = txt
        return txt


def load_allowed_numbers(path: Path | None) -> set[str]:
    if path is None:
        return set()
    out = set()
    for line in read_text(path).splitlines():
        s = line.split("#", 1)[0].strip()
        if s:
            out.add(s)
    return out


def check_numbers(root: Path, reports: list[str], allowed: set[str], res: Result) -> None:
    res.start("numbers")
    if not reports:
        res.warn("numbers", "SKIPPED: no text report found (report/**/*.md or REPORT.md); a PDF-only package "
                            "cannot be number-checked. Pass --report <file> to check a text source.")
        return
    index = ArtifactIndex(root)
    reported_refs: set[tuple[str, str]] = set()
    for rel in reports:
        path = root / rel
        if not path.is_file():
            res.fail("numbers", f"{rel}: --report file does not exist in the package")
            continue
        for kind, lines in report_blocks(read_text(path, SCAN_BYTES)):
            block_refs = _refs("\n".join(line for _, line in lines), rel, lines[0][0], index, reported_refs, None)
            for n, line in lines:
                own = _refs(line, rel, n, index, reported_refs, res)
                refs = (own or block_refs) if kind == "table" else block_refs
                _check_line(rel, n, line, refs, index, allowed, res)


def _refs(text: str, rel: str, lineno: int, index: ArtifactIndex, seen: set[tuple[str, str]],
          res: Result | None) -> list[str]:
    """Artifact paths cited in ``text``; with ``res`` given, also report missing or placeholder paths."""
    refs = []
    for m in ARTIFACT_REF.finditer(text):
        ref = m.group().rstrip(".,;:)")
        nxt = text[m.end():m.end() + 1]
        if nxt in ("<", "{"):
            if res is not None and (rel, ref) not in seen:
                seen.add((rel, ref))
                res.fail("numbers", f"{rel}:{lineno}: artifact path has an unfilled placeholder: {ref}{nxt}...")
            continue
        refs.append(ref)
        exists, _, _ = index.resolve(ref)
        if res is not None and not exists and (rel, ref) not in seen:
            seen.add((rel, ref))
            res.fail("numbers", f"{rel}:{lineno}: cited artifact does not exist in the package: {ref}")
    return refs


def _check_line(rel: str, n: int, line: str, refs: list[str], index: ArtifactIndex, allowed: set[str],
                res: Result) -> None:
    scrub = _NOISE.sub(" ", ARTIFACT_REF.sub(" ", line))
    for m in _NUM.finditer(scrub):
        kind = m.lastgroup or ""
        value = m.group(kind)
        token = m.group().strip()
        if token in allowed or value in allowed:
            continue
        if kind == "int" and "," not in value and 1900 <= int(value) <= 2100:
            continue
        if not refs:
            res.warn("numbers", f"{rel}:{n}: unsourced number {token} (no artifact cited in this paragraph)")
            continue
        texts, searchable = [], False
        for ref in refs:
            exists, files, truncated = index.resolve(ref)
            if truncated:
                res.warn("numbers", f"{rel}:{n}: search of {ref} truncated at {SEARCH_FILES_PER_REF} files")
            searchable = searchable or bool(files)
            texts.extend(files)
        if not searchable:
            res.warn("numbers", f"{rel}:{n}: number {token} cites only artifacts that are not text (cannot check)")
        elif not any(number_in(kind, value, index.text(f)) for f in texts):
            res.fail("numbers", f"{rel}:{n}: number {token} not found in cited artifacts: {', '.join(refs)}")


# --- driver ----------------------------------------------------------------------------------------------------

def verify(root: Path, *, reports: list[str] | None = None, allow: list[str] | None = None,
           allow_numbers: Path | None = None, extra_scan: list[str] | None = None) -> Result:
    res = Result()
    files, problems = scan_tree(root, allow or [])
    check_required(root, res)
    check_manifest(root, files, res)
    check_forbidden(root, files, problems, res)
    check_placeholders(root, files, extra_scan or [], res)
    check_junit(root, res)
    check_reproduce(root, res)
    if reports is None:
        reports = sorted(set(glob_files(root, "report/**/*.md") + glob_files(root, "REPORT.md")))
    check_numbers(root, reports, load_allowed_numbers(allow_numbers), res)
    return res


def render(res: Result, *, strict: bool, max_list: int) -> tuple[list[str], int]:
    lines: list[str] = []
    n_fail = n_warn = 0
    for check in res.order:
        fails, warns = res.failures.get(check, []), res.warnings.get(check, [])
        n_fail += len(fails)
        n_warn += len(warns)
        bad = fails or (strict and warns)
        status = "FAIL" if bad else ("WARN" if warns else "PASS")
        lines.append(f"{status}  {check}" + (f" ({len(fails)} failure(s), {len(warns)} warning(s))" if fails or warns else ""))
        for tag, items in (("FAIL", fails), ("WARN", warns)):
            for item in items[:max_list]:
                lines.append(f"        {tag} {item}")
            if len(items) > max_list:
                lines.append(f"        ... and {len(items) - max_list} more {tag}")
    failed = n_fail > 0 or (strict and n_warn > 0)
    lines.append(f"verify_package: {n_fail} failure(s), {n_warn} warning(s)"
                 + (" (warnings count: --strict)" if strict else "") + (" -> FAILED" if failed else " -> OK"))
    return lines, 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    ap = argparse.ArgumentParser(description="Verify a Stage-2 submission package directory (offline, read-only).")
    ap.add_argument("package", type=Path, help="the package directory the team assembled")
    ap.add_argument("--report", action="append", metavar="REL", help="text report file, relative to the package "
                    "(repeatable; default: report/**/*.md and REPORT.md)")
    ap.add_argument("--allow", action="append", default=[], metavar="PATTERN",
                    help="fnmatch pattern of a human-approved file that would otherwise be forbidden (repeatable)")
    ap.add_argument("--allow-numbers", type=Path, metavar="FILE", help="numbers a human accepted, one per line")
    ap.add_argument("--scan-extra", action="append", default=[], metavar="GLOB",
                    help="more files for the AWAITING/TODO/TBD scan (package-relative fnmatch, repeatable)")
    ap.add_argument("--strict", action="store_true", help="treat warnings as failures")
    ap.add_argument("--max-list", type=int, default=40, help="findings printed per check and severity (default 40)")
    args = ap.parse_args(argv)
    if not args.package.is_dir():
        print(f"verify_package: not a directory: {args.package}", file=sys.stderr)
        return 2
    root = args.package.resolve()
    res = verify(root, reports=args.report, allow=args.allow, allow_numbers=args.allow_numbers,
                 extra_scan=args.scan_extra)
    lines, code = render(res, strict=args.strict, max_list=args.max_list)
    print(f"verify_package: {root}")
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    sys.exit(main())
