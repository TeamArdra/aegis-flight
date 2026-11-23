#!/usr/bin/env python
"""Verify the downloaded public datasets against the committed manifests (issue #27 item 3).

    python artifacts/validation/final_stage2-freeze-2026-11-27/replays/verify_data.py --out <dir>

Run from the repository root. Reads (never executes, never unpickles) the raw files under ``data/external/raw/``:

* every file listed in ``data/external/manifests/{alfa,px4_review_v1,px4_review_v2}.json`` is checked for existence,
  byte size and SHA-256 against the manifest;
* every extracted ALFA ``flight.tlog`` is compared byte-for-byte (SHA-256) with the matching member of the verified
  ``telemetry.zip``, so the extracted logs the replay reads are the manifest-verified bytes;
* the SHA-256 of every ALFA tlog and every PX4 ULog is written to ``data_sha256.csv``.

Writes ``data_verification.json`` and ``data_sha256.csv`` into ``--out``. Exit status 1 if any check fails.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import zipfile
from pathlib import Path

MAN = Path("data/external/manifests")
ALFA_ROOT = Path("data/external/raw/alfa")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    report: dict = {"manifests": {}, "alfa_extracted_vs_zip": {}}
    rows: list[dict] = []
    ok_all = True
    hashes: dict[str, str] = {}
    for name in ("alfa", "px4_review_v1", "px4_review_v2"):
        man = json.loads((MAN / f"{name}.json").read_text(encoding="utf-8"))
        res = {"manifest_sha256": sha256_file(MAN / f"{name}.json"), "n_files": len(man["files"]), "ok": 0,
               "missing": [], "size_mismatch": [], "hash_mismatch": []}
        for f in man["files"]:
            p = Path(f["path"])
            if not p.exists():
                res["missing"].append(f["path"])
                continue
            if p.stat().st_size != f["bytes"]:
                res["size_mismatch"].append(f["path"])
                continue
            if f["path"] in hashes:
                h = hashes[f["path"]]
            else:
                h = hashes[f["path"]] = sha256_file(p)
            if h != f["sha256"]:
                res["hash_mismatch"].append(f["path"])
                continue
            res["ok"] += 1
            if p.suffix == ".ulg":
                rows.append({"dataset": name, "file": p.name, "bytes": f["bytes"], "sha256": h,
                             "manifest_sha256": f["sha256"], "match": True})
        res["all_ok"] = res["ok"] == res["n_files"]
        ok_all &= res["all_ok"]
        report["manifests"][name] = res

    z = ALFA_ROOT / "telemetry.zip"
    cmp: dict = {"zip": z.as_posix(), "members_compared": 0, "mismatch": [], "extracted_not_in_zip": [], "n_extracted": 0}
    with zipfile.ZipFile(z) as zf:
        members = {Path(i.filename).as_posix(): i for i in zf.infolist() if i.filename.endswith(".tlog")}
        extracted = sorted((ALFA_ROOT / "telemetry").rglob("*.tlog"))
        cmp["n_extracted"] = len(extracted)
        cmp["n_zip_tlog_members"] = len(members)
        for p in extracted:
            rel = p.relative_to(ALFA_ROOT / "telemetry").as_posix()
            info = members.get(rel)
            h = sha256_file(p)
            if info is None:
                cmp["extracted_not_in_zip"].append(rel)
                continue
            zh = hashlib.sha256()
            with zf.open(info) as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    zh.update(chunk)
            cmp["members_compared"] += 1
            match = zh.hexdigest() == h
            if not match:
                cmp["mismatch"].append(rel)
            rows.append({"dataset": "alfa", "file": rel, "bytes": p.stat().st_size, "sha256": h,
                         "manifest_sha256": f"zip-member:{zh.hexdigest()}", "match": match})
    cmp["all_ok"] = not cmp["mismatch"] and not cmp["extracted_not_in_zip"] and cmp["members_compared"] > 0
    ok_all &= cmp["all_ok"]
    report["alfa_extracted_vs_zip"] = cmp
    report["all_ok"] = ok_all
    (a.out / "data_verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8", newline="\n")
    with open(a.out / "data_sha256.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["dataset", "file", "bytes", "sha256", "manifest_sha256", "match"],
                           lineterminator="\n")
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r["dataset"], r["file"])))
    print(json.dumps({k: (v if k != "manifests" else {n: {kk: vv for kk, vv in m.items() if kk in
                      ("n_files", "ok", "all_ok")} for n, m in v.items()}) for k, v in report.items()
                      if k != "alfa_extracted_vs_zip"}, indent=2))
    print({k: v for k, v in cmp.items() if k != "zip"})
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
