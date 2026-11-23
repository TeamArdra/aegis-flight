"""Cryptographic forensic flight security report generator (W9).

Reads an :class:`~aegisflight.logging.store.EventStore` SQLite database in read-only mode,
verifies both the ``events`` and ``actions`` SHA-256 hash chains plus optional external
``.anchors.jsonl`` records, and produces a standalone JSON or self-contained HTML report.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from pathlib import Path
from typing import Any

from ..logging.anchors import default_anchors_path, verify_anchors
from ..logging.store import EventStore


def build_forensic_report(
    db_path: str | Path,
    *,
    run_id: str | None = None,
    anchors_path: str | Path | None = None,
    anchor_key: bytes | str | None = None,
    verify_actions: bool = True,
    limit: int = 500,
) -> dict[str, Any]:
    """Build a structured, verified forensic report dictionary from ``db_path``."""
    p = Path(db_path)
    if not p.exists():
        raise FileNotFoundError(f"event database not found: {p}")

    store = EventStore(p, read_only=True)
    try:
        runs = [
            {
                "run_id": str(r["run_id"]),
                "started": r["started"],
                "label": r["label"],
                "meta": json.loads(r["meta"]) if r["meta"] else {},
            }
            for r in store.conn.execute("SELECT run_id, started, label, meta FROM runs ORDER BY started DESC").fetchall()
        ]
        ev_chain = store.verify_chain(run_id)
        act_chain = store.verify_actions_chain(run_id) if verify_actions else None
        events = store.get_events(run_id=run_id, limit=limit)
        actions = store.get_actions(run_id=run_id, limit=limit)

        anchor_p = Path(anchors_path) if anchors_path else default_anchors_path(p)
        anchor_ver = None
        if anchor_p.is_file():
            av = verify_anchors(store, anchor_p, key=anchor_key)
            anchor_ver = {
                "path": str(anchor_p),
                "ok": av.ok,
                "anchors_checked": av.anchors_checked,
                "signed_anchors": av.signed_anchors,
                "unsigned_anchors": av.unsigned_anchors,
                "errors": av.errors,
                "warnings": av.warnings,
            }
    finally:
        store.close()

    by_attack = Counter(e.get("attack_type", "UNKNOWN") for e in events)
    by_severity = Counter(e.get("severity", "UNKNOWN") for e in events)
    by_action = Counter(a.get("action", "UNKNOWN") for a in actions)

    chain_ok = bool(ev_chain.ok and (act_chain is None or act_chain.ok))
    anchors_ok = True if anchor_ver is None else bool(anchor_ver["ok"])

    return {
        "schema": "aegisflight.forensic_report/1",
        "db_path": str(p),
        "run_id": run_id,
        "verified": bool(chain_ok and anchors_ok),
        "events_chain": {
            "ok": ev_chain.ok,
            "length": ev_chain.length,
            "broken_at": ev_chain.broken_at,
            "detail": ev_chain.detail,
        },
        "actions_chain": None
        if act_chain is None
        else {
            "ok": act_chain.ok,
            "length": act_chain.length,
            "broken_at": act_chain.broken_at,
            "detail": act_chain.detail,
        },
        "anchors": anchor_ver,
        "runs": runs,
        "summary": {
            "total_events_included": len(events),
            "total_actions_included": len(actions),
            "by_attack_type": dict(by_attack),
            "by_severity": dict(by_severity),
            "by_action_type": dict(by_action),
        },
        "events": events,
        "actions": actions,
    }


def render_forensic_html(report: dict[str, Any]) -> str:
    """Render a self-contained static HTML report (XSS-escaped, zero external assets)."""
    esc = html.escape
    status_badge = "VERIFIED" if report.get("verified") else "VERIFICATION FAILED"
    ev_c = report.get("events_chain") or {}
    act_c = report.get("actions_chain") or {}
    summary = report.get("summary") or {}

    rows = []
    for e in (report.get("events") or [])[:200]:
        ev_text = "; ".join(str(x) for x in (e.get("evidence") or [])[:3])
        rows.append(
            "<tr>"
            f"<td>{esc(str(e.get('id', '')))}</td>"
            f"<td>{esc(str(e.get('t', '')))}</td>"
            f"<td>{esc(str(e.get('severity', '')))}</td>"
            f"<td>{esc(str(e.get('attack_type', '')))}</td>"
            f"<td>{esc(str(e.get('threat_score', '')))}</td>"
            f"<td>{esc(ev_text)}</td>"
            "</tr>"
        )

    act_rows = []
    for a in (report.get("actions") or [])[:200]:
        act_rows.append(
            "<tr>"
            f"<td>{esc(str(a.get('id', '')))}</td>"
            f"<td>{esc(str(a.get('t', '')))}</td>"
            f"<td>{esc(str(a.get('actor', '')))}</td>"
            f"<td>{esc(str(a.get('action', '')))}</td>"
            f"<td>{esc(str(a.get('target', '')))}</td>"
            f"<td>{esc(str(a.get('detail', '')))}</td>"
            "</tr>"
        )

    return "\n".join([
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<title>AegisFlight Forensic Flight Security Report</title>",
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;background:#0b1220;color:#e2e8f0;}"
        "h1,h2{color:#38bdf8} .card{background:#111c30;padding:1rem;border-radius:8px;margin-bottom:1rem;}"
        "table{width:100%;border-collapse:collapse;font-size:0.9rem} th,td{border:1px solid #243554;padding:6px;text-align:left}"
        ".ok{color:#4ade80;font-weight:bold}.fail{color:#f87171;font-weight:bold}</style></head><body>",
        "<h1>AegisFlight Cryptographic Forensic Report</h1>",
        f"<div class='card'>Status: <span class='{'ok' if report.get('verified') else 'fail'}'>{esc(status_badge)}</span>"
        f" | DB: <code>{esc(str(report.get('db_path', '')))}</code></div>",
        "<div class='card'><h2>Hash Chain Verification</h2><ul>",
        f"<li>Events Chain: ok={esc(str(ev_c.get('ok')))} len={esc(str(ev_c.get('length')))} ({esc(str(ev_c.get('detail', '')))})</li>",
        f"<li>Actions Chain: ok={esc(str(act_c.get('ok')))} len={esc(str(act_c.get('length')))} ({esc(str(act_c.get('detail', '')))})</li>",
        f"<li>By Attack: <code>{esc(json.dumps(summary.get('by_attack_type', {})))}</code></li>",
        "</ul></div>",
        "<div class='card'><h2>Security Events</h2><table><thead><tr><th>ID</th><th>t (s)</th><th>Severity</th><th>Attack</th><th>Score</th><th>Evidence</th></tr></thead><tbody>",
        "\n".join(rows) or "<tr><td colspan='6'>No events recorded.</td></tr>",
        "</tbody></table></div>",
        "<div class='card'><h2>Defense &amp; Command Audit Actions</h2><table><thead><tr><th>ID</th><th>t (s)</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th></tr></thead><tbody>",
        "\n".join(act_rows) or "<tr><td colspan='6'>No actions recorded.</td></tr>",
        "</tbody></table></div></body></html>",
    ])
