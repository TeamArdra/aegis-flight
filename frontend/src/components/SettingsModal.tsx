import { useEffect, useRef, useState } from "react";
import { BACKEND_KEY, BRIDGE_KEY, backendBase, getBridgeToken, getUrlSetting, saveBridgeToken, saveUrlSetting } from "../services/api";
import { getApiToken, saveApiToken } from "../lib/requestAuth";

// Backend URL (REST + WebSocket) and optional inline-IPS bridge status URL;
// auth tokens are stored strictly in sessionStorage + memory (never localStorage).
export function SettingsModal({ onClose }: { onClose: () => void }) {
  const dlgRef = useRef<HTMLDialogElement | null>(null);
  const [backend, setBackend] = useState(getUrlSetting(BACKEND_KEY));
  const [bridge, setBridge] = useState(getUrlSetting(BRIDGE_KEY));
  const [apiToken, setApiToken] = useState(getApiToken());
  const [token, setToken] = useState(getBridgeToken());
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const dlg = dlgRef.current;
    if (dlg && !dlg.open) dlg.showModal();
  }, []);

  const save = () => {
    const e1 = saveUrlSetting(BACKEND_KEY, backend);
    const e2 = saveUrlSetting(BRIDGE_KEY, bridge);
    if (e1 || e2) {
      setErr(`${e1 ? "Backend: " + e1 : ""} ${e2 ? "Bridge: " + e2 : ""}`.trim());
      return;
    }
    saveApiToken(apiToken);
    saveBridgeToken(token);
    window.location.reload();
  };

  const clear = () => {
    setBackend("");
    setBridge("");
    saveUrlSetting(BACKEND_KEY, "");
    saveUrlSetting(BRIDGE_KEY, "");
    saveApiToken("");
    saveBridgeToken("");
    window.location.reload();
  };

  const field = { width: "100%", boxSizing: "border-box", padding: "8px", marginTop: 4 } as const;

  return (
    <dialog
      ref={dlgRef}
      aria-labelledby="settings-modal-title"
      data-testid="settings-modal"
      className="aegis-modal"
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
      onClick={(e) => {
        if (e.target === dlgRef.current) onClose();
      }}
    >
      <div className="panel" style={{ width: 480, maxWidth: "92vw", padding: 18 }}>
        <h2 id="settings-modal-title" className="panel-title" style={{ marginTop: 0, marginBottom: 10 }}>
          Connection &amp; Session Security Settings
        </h2>
        <label>
          Backend URL <span className="panel-note">(active: {backendBase() || "same-origin"})</span>
          <input
            autoFocus
            style={field}
            value={backend}
            placeholder="http://127.0.0.1:8000"
            onChange={(e) => setBackend(e.target.value)}
          />
        </label>
        <label style={{ display: "block", marginTop: 10 }}>
          Backend Control Token <span className="panel-note">(HMAC-signed session token; cleared on tab close)</span>
          <input
            style={field}
            type="password"
            autoComplete="off"
            value={apiToken}
            placeholder="AEGIS_API_TOKEN (session memory only)"
            onChange={(e) => setApiToken(e.target.value)}
          />
        </label>
        <label style={{ display: "block", marginTop: 10 }}>
          Inline IPS Bridge Status URL <span className="panel-note">(optional)</span>
          <input style={field} value={bridge} placeholder="http://127.0.0.1:8765" onChange={(e) => setBridge(e.target.value)} />
        </label>
        <label style={{ display: "block", marginTop: 10 }}>
          Bridge Control Token <span className="panel-note">(session memory only; Authorization header)</span>
          <input
            style={field}
            type="password"
            autoComplete="off"
            value={token}
            placeholder="token from --control-token-file"
            onChange={(e) => setToken(e.target.value)}
          />
        </label>
        {err && <div role="alert" style={{ color: "var(--crit)", marginTop: 8 }}>{err}</div>}
        <div style={{ display: "flex", gap: 8, marginTop: 16, justifyContent: "flex-end" }}>
          <button type="button" onClick={clear}>Clear</button>
          <button type="button" onClick={onClose}>Cancel</button>
          <button type="button" onClick={save}>Save &amp; reload</button>
        </div>
      </div>
    </dialog>
  );
}
