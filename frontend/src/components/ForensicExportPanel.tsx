import { useState } from "react";
import { api, backendBase } from "../services/api";

export function ForensicExportPanel() {
  const [report, setReport] = useState<Record<string, unknown> | null>(null);
  const [drill, setDrill] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const loadForensic = async () => {
    setBusy(true);
    setErr(null);
    try {
      const rep = await api.forensicReportJson();
      setReport(rep);
    } catch {
      setErr("Failed to verify forensic log chains.");
    } finally {
      setBusy(false);
    }
  };

  const runDrill = async () => {
    setBusy(true);
    setErr(null);
    try {
      const res = await api.runDrill("all");
      setDrill(res);
    } catch {
      setErr("Shadow field drill execution failed.");
    } finally {
      setBusy(false);
    }
  };

  const downloadJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aegis-forensic-report-${String(report.run_id || "flight")}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="forensics-grid" data-testid="forensic-export-panel">
      <div className="panel">
        <header>
          <span className="panel-title">Post-Flight Forensic Verification &amp; Export</span>
          <span className="panel-note">SHA-256 Events Chain · Actions Chain · External Anchors</span>
        </header>
        <div className="wizard-body">
          <div className="wizard-actions">
            <button type="button" disabled={busy} onClick={() => void loadForensic()}>
              Verify Hash Chains &amp; Build Report
            </button>
            {report && (
              <button type="button" onClick={downloadJson}>
                Download Verified JSON
              </button>
            )}
            <a
              className="btn-link"
              href={`${backendBase()}/api/forensic/report?format=html`}
              target="_blank"
              rel="noopener noreferrer"
            >
              Open Standalone HTML Report
            </a>
          </div>
          {err && <div className="alert-banner crit">{err}</div>}
          {report && (
            <pre className="yaml-box">
              {JSON.stringify(
                {
                  verified: report.verified,
                  run_id: report.run_id,
                  events_chain: report.events_chain,
                  actions_chain: report.actions_chain,
                  anchors: report.anchors,
                  summary: report.summary,
                },
                null,
                2,
              )}
            </pre>
          )}
        </div>
      </div>

      <div className="panel">
        <header>
          <span className="panel-title">Shadow Field Drills (0 B FC TX)</span>
          <span className="panel-note">Verifies active IPS &amp; detector rules without transmitting to drone</span>
        </header>
        <div className="wizard-body">
          <div className="wizard-actions">
            <button type="button" disabled={busy} onClick={() => void runDrill()}>
              Execute All Shadow Drills
            </button>
          </div>
          {drill && <pre className="yaml-box">{JSON.stringify(drill, null, 2)}</pre>}
        </div>
      </div>
    </div>
  );
}
