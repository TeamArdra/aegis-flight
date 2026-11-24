import { useEffect, useState, memo } from "react";
import { api } from "../services/api";
import { describe, selectTopology } from "../lib/topology";
import { ActiveIpsDialog } from "./ActiveIpsDialog";
import { HoldConfirmButton } from "./HoldConfirmButton";
import { needsActiveIpsDialog, signingText, type SigningInfo } from "../lib/posture";
import {
  ACTION_TIMELINE_CAPTION,
  CONTROLLER_SUMMARY_CAPTION,
  DECISION_COMPUTE_LABEL,
  DEFENSE_LIMITS,
  MODE_OPTIONS,
  controllerSummaryLabel,
  emptyTimelineText,
  internalStateCaption,
  internalStateTitle,
  ladderStates as getLadderStates,
  mitigationPresentation,
  overrideFallback,
  postureBanner,
  summaryFallback,
  transmissionText,
} from "../lib/wording";
import type { DefenseMode, Environment, MitigationActionItem, MitigationInfo, Telemetry, Threat, TopologyInfo } from "../types";

interface Props {
  mode: DefenseMode;
  mitigation: MitigationInfo | null;
  threat: Threat | null;
  telemetry: Telemetry | null;
  topologyInfo?: TopologyInfo | null;
  bridgeTopology?: TopologyInfo | null;
  environment?: Environment | null;
  signing?: SigningInfo | null;
}

function fmtNum(val: number | null | undefined, digits = 1, fallback = "0.0"): string {
  if (typeof val !== "number" || isNaN(val)) return fallback;
  return val.toFixed(digits);
}

function getPilotAdvisory(subMode: string): string {
  if (subMode.startsWith("gps_spoofing")) {
    return "Ignore primary GPS guidance; cross-check baro & switch to ALT_HOLD";
  }
  if (subMode.startsWith("command_injection")) {
    return "Hostile command injected on link; verify GCS link ID and lock controls";
  }
  if (subMode.startsWith("telemetry_manipulation")) {
    return "Sensor bias detected; verify airspeed sensor and baro before altitude changes";
  }
  if (subMode.startsWith("dos")) {
    return "RF link under contention / flood; prepare for Return-To-Launch (RTL)";
  }
  if (subMode.startsWith("mavlink_anomaly")) {
    return "MAVLink sequence or CRC anomaly detected; verify RF telemetry modem";
  }
  if (subMode.startsWith("firmware_integrity")) {
    return "CRITICAL: Firmware signature mismatch; land vehicle immediately";
  }
  return "Monitor flight parameters; standby for pilot action";
}

function DefensePanelImpl({ mode, mitigation, threat, telemetry, topologyInfo, bridgeTopology, environment, signing }: Props) {
  const [dialog, setDialog] = useState(false);
  const [dialogErr, setDialogErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [overrideMsg, setOverrideMsg] = useState<string | null>(null);
  const [optimisticMode, setOptimisticMode] = useState<DefenseMode | null>(null);

  const activeMode = optimisticMode ?? mode ?? "passive";

  useEffect(() => {
    if (optimisticMode && mode === optimisticMode) {
      setOptimisticMode(null);
    }
  }, [mode, optimisticMode]);

  const stateId = mitigation?.state || "NOMINAL";
  const subMode = mitigation?.sub_mode || "NONE";
  const cleanStreak = mitigation?.clean_streak ?? 0;
  const targetTicks = mitigation?.recovery_target_ticks ?? 25;
  const recoveryPct = Math.min(100, Math.round((cleanStreak / Math.max(1, targetTicks)) * 100));

  // Null-safe accessors across flat and nested schemas
  const inputs = mitigation?.inputs;
  const outputs = mitigation?.outputs;
  const params = mitigation?.params;
  const actions: MitigationActionItem[] = mitigation?.actions ?? [];

  const quarantined: number[] = Array.isArray(outputs?.quarantined_sysids)
    ? outputs!.quarantined_sysids
    : Array.isArray(mitigation?.quarantined_sysids)
    ? mitigation!.quarantined_sysids
    : [];

  const rogueSysids: number[] = Array.isArray(outputs?.rogue_sysids)
    ? outputs!.rogue_sysids
    : Array.isArray(params?.rogue_sysids)
    ? params!.rogue_sysids
    : [];

  const northOffset = outputs?.north_offset_m ?? params?.north_offset_m ?? 0;
  const eastOffset = outputs?.east_offset_m ?? params?.east_offset_m ?? 0;
  const driftRate = outputs?.drift_rate_ms ?? params?.drift_rate_ms ?? 0;
  const altBias = outputs?.alt_bias_m ?? params?.alt_bias_m ?? 0;
  const speedBias = outputs?.speed_bias_ms ?? params?.speed_bias_ms ?? 0;
  const batteryBias = outputs?.battery_bias_v ?? params?.battery_bias_v ?? 0;
  const latOffsetDeg = params?.lat_offset_deg ?? 0;
  const targetRestoreMode = outputs?.target_restore_mode ?? params?.target_restore_mode ?? null;
  // Controller decisions, not confirmed effects: absent stays null ("not reported"), never 0/false.
  // counter_frames_sent counts frames the controller encoded/queued, not frames transmitted.
  const queuedFrames: number | null = outputs?.counter_frames_sent ?? mitigation?.counter_frames_sent ?? null;

  const ekfSwitched: boolean | null = outputs?.ekf_switched ?? mitigation?.ekf_switched ?? null;
  const sanitizeGps: boolean | null = outputs?.sanitize_gps ?? mitigation?.sanitize_gps ?? null;
  const sanitizeAlt: boolean | null = outputs?.sanitize_alt ?? mitigation?.sanitize_alt ?? null;
  const lastCommand = outputs?.last_command_sent ?? mitigation?.last_command_sent ?? null;

  const trustedLat = inputs?.trusted_lat ?? params?.trusted_lat;
  const trustedLon = inputs?.trusted_lon ?? params?.trusted_lon;
  const trustedMode = inputs?.trusted_mode ?? params?.trusted_mode;

  // Posture statement: factual, evidence-bounded (lib/wording.ts)
  const isAttackActive = Boolean(threat?.threat);
  const { cls: resClass, title: resTitle, desc: resDesc, badge: resBadge } = postureBanner(activeMode, isAttackActive, threat?.attack_type, environment);
  const mitigationRows = mitigationPresentation({ mode: activeMode, state: mitigation?.state ?? null, environment, threat, queuedFrames });
  const transmission = transmissionText(activeMode, environment, queuedFrames, Boolean(mitigation?.state));

  const applyMode = async (newMode: DefenseMode, allowUnsigned?: boolean) => {
    setOptimisticMode(newMode);
    setBusy(true);
    setOverrideMsg(null);
    setDialogErr(null);
    try {
      const res = await api.setDefenseMode(newMode, allowUnsigned);
      if (res && res.ok === false) {
        setOptimisticMode(null);
        const msg = res.message || res.error || "mode change refused";
        if (res.error === "signing_required") { setDialogErr(msg); setDialog(true); } else { setOverrideMsg(`Failed to switch mode: ${msg}`); }
      } else {
        setDialog(false);
      }
    } catch (err) {
      setOptimisticMode(null);
      setOverrideMsg(`Failed to switch mode: ${err}`);
    } finally {
      setBusy(false);
    }
  };

  const handleModeChange = async (newMode: DefenseMode) => {
    if (newMode === activeMode || busy) return;
    if (needsActiveIpsDialog(environment, activeMode, newMode)) { setDialogErr(null); setDialog(true); return; }
    await applyMode(newMode);
  };

  const handleOverride = async (action: "safe_hold" | "reset_quarantine" | "ack_takeover") => {
    if (busy) return;
    setBusy(true);
    setOverrideMsg(null);
    try {
      const res = await api.defenseOverride(action);
      setOverrideMsg(res.mitigation?.summary || overrideFallback(action));
    } catch (err) {
      setOverrideMsg(`Override failed: ${err}`);
    } finally {
      setBusy(false);
    }
  };

  const isMitigating = stateId !== "NOMINAL";
  const ladderStates = getLadderStates(activeMode);

  // Recovery monitor title
  const recoveryTitle =
    activeMode === "passive"
      ? "IDS THREAT CLEARANCE MONITOR"
      : activeMode === "advisory"
      ? "ADVISORY CLEARANCE MONITOR"
      : "QUARANTINE & IPS RECOVERY MONITOR";

  return (
    <section className="panel def-panel" data-testid="defense-panel">
      {dialog && (
        <ActiveIpsDialog signing={signing ?? null} busy={busy} error={dialogErr}
          onCancel={() => { setDialog(false); setDialogErr(null); }}
          onConfirm={(u) => { void applyMode("active-ips", u); }} />
      )}
      <div className="panel-head">
        <div className="title-row">
          <h3>DEFENSE POSTURE & RESPONSE</h3>
          <span className={`pill def-mode-pill def-pill-${activeMode}`}>
            {activeMode.toUpperCase()}
          </span>
        </div>
        <div className="panel-sub">
          {activeMode === "passive"
            ? "Passive intrusion detection (IDS) · nothing sent to the flight controller"
            : activeMode === "advisory"
            ? "Pilot-in-the-loop advisory alerting · nothing sent to the flight controller"
            : "Intrusion prevention (IPS) · verified in ArduCopter SITL only, not flight-validated"}
        </div>
      </div>

      {/* 0. Real-time Resistance Monitor Banner */}
      <div className={`resistance-banner ${resClass}`}>
        <div className="res-header">
          <div>
            <div className="res-title" data-testid="defense-title">{resTitle}</div>
            <div className="res-desc" data-testid="defense-desc">{resDesc}</div>
          </div>
        </div>
        <div className="res-badge" data-testid="defense-badge">{resBadge}</div>
      </div>
      <div className="topo-card" data-testid="mitigation-presentation">
        <div className="topo-rows">
          {mitigationRows.map((r) => (
            <div key={r.id} className="topo-row" data-testid={`mitigation-row-${r.id}`}>
              <span>{r.label}</span>
              <b className="topo-muted">{r.value}</b>
            </div>
          ))}
        </div>
      </div>
      <ul className="topo-reasons" data-testid="defense-limits">
        {DEFENSE_LIMITS.map((l) => <li key={l}>{l}</li>)}
      </ul>

      {/* 0.1 Read-only topology status (detected by the software, never operator-selected) */}
      <TopologyCard backend={topologyInfo} bridge={bridgeTopology} />

      {/* 1. Operational Mode Switcher */}
      <div className="def-section">
        <div className="def-section-title">OPERATIONAL POSTURE SELECTOR</div>
        {environment && environment !== "SIM" && (
          <div className="topo-note" data-testid="signing-indicator" style={{ fontWeight: 700, color: signing?.configured ? "var(--ok)" : "var(--warn)" }}>{signingText(signing)}</div>
        )}
        <div className="topo-note">Posture is your choice; the Topology capability rows depend on it.</div>
        <div className="mode-toggle-group" role="radiogroup" aria-label="Defense Mode Selector">
          {MODE_OPTIONS.map((m) => {
            const isSelected = activeMode === m.id;
            return (
              <button
                key={m.id}
                type="button"
                className={`mode-btn ${isSelected ? "active" : ""}`}
                onClick={() => handleModeChange(m.id)}
                disabled={busy}
                aria-checked={isSelected}
                role="radio"
              >
                <div className="mode-label">{m.label}</div>
                <div className="mode-desc">{m.desc}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* 2. 4-State Escalation Ladder (Mode-Adaptive) */}
      <div className="def-section">
        <div className="def-section-title" data-testid="internal-state-title">{internalStateTitle(activeMode)}</div>
        <div className="topo-note" data-testid="internal-state-caption">{internalStateCaption(activeMode)}</div>
        <div className="fsm-ladder">
          {ladderStates.map((s, idx) => {
            const isCurrent = stateId === s.id;
            return (
              <div
                key={s.id}
                className={`fsm-step ${isCurrent ? "current" : ""}`}
                style={{ borderColor: isCurrent ? s.color : undefined }}
              >
                <div className="step-num">{idx + 1}</div>
                <div className="step-body">
                  <div className="step-name" style={{ color: isCurrent ? s.color : undefined }}>
                    {s.label}
                  </div>
                  <div className="step-desc">{s.desc}</div>
                </div>
                {isCurrent && <span className="step-indicator" style={{ backgroundColor: s.color }} />}
              </div>
            );
          })}
        </div>
      </div>

      {/* 3. Recovery Monitor Progress (During active mitigation / clearance) */}
      {isMitigating && (
        <div className="def-section recovery-box">
          <div className="recovery-head">
            <span className="recovery-title">{recoveryTitle}</span>
            <span className="recovery-val mono">
              {cleanStreak} / {targetTicks} ticks ({(cleanStreak * 0.2).toFixed(1)}s / 5.0s clean)
            </span>
          </div>
          <div className="recovery-bar-bg">
            <div className="recovery-bar-fill" style={{ width: `${recoveryPct}%` }} />
          </div>
        </div>
      )}

      {/* 4. Forensics Matrix: Side-by-Side Inputs vs Outputs (Strictly Mode-Segregated) */}
      <div className="def-section">
        <div className="def-section-title">DEFENSE FORENSICS MATRIX</div>
        <div className="forensics-grid">
          {/* Left Column: Attack Inputs & Perturbations (Shared Across All Modes) */}
          <div className="forensics-col input-col">
            <div className="col-header">
              <span className="col-tag">INPUTS</span>
              <span className="col-title">Detected Cyber-Physical Vectors</span>
            </div>
            <div className="forensics-data">
              <div className="data-row">
                <span className="lbl">Active Threat</span>
                <span className="val highlight" style={{ color: threat?.threat ? "var(--crit)" : "var(--ok)" }}>
                  {threat?.threat ? threat.attack_type : "BENIGN"}
                </span>
              </div>
              <div className="data-row">
                <span className="lbl">Tactical Sub-Mode</span>
                <span className="val mono">{subMode}</span>
              </div>
              <div className="data-row">
                <span className="lbl">GPS Pos Divergence</span>
                <span className="val mono">
                  {`N: ${fmtNum(northOffset)}m · E: ${fmtNum(eastOffset)}m`}
                  {driftRate > 0.05 && ` · ${fmtNum(driftRate, 2)}m/s`}
                </span>
              </div>
              <div className="data-row">
                <span className="lbl">Sensor Biases</span>
                <span className="val mono">
                  {altBias !== 0 ? `Alt: ${fmtNum(altBias)}m` : "Alt: 0.0m"}
                  {speedBias !== 0 && ` · Spd: ${fmtNum(speedBias)}m/s`}
                  {batteryBias !== 0 && ` · Bat: ${fmtNum(batteryBias, 2)}V`}
                </span>
              </div>
              <div className="data-row">
                <span className="lbl">Rogue System IDs</span>
                <span className="val mono">
                  {rogueSysids.length > 0 ? `[${rogueSysids.join(", ")}]` : "None"}
                </span>
              </div>
              <div className="data-row">
                <span className="lbl">Packet / Link Guard</span>
                <span
                  className="val mono"
                  style={{
                    color: threat?.integrity_status === "INVALID" ? "var(--crit)" : "var(--ok)",
                  }}
                >
                  {threat?.integrity_status === "INVALID"
                    ? "⚠️ CRC / INTEGRITY VIOLATION"
                    : subMode === "command_injection:gcs_replay"
                    ? "⚠️ REPLAY CADENCE SPIKE"
                    : "X.25 VALID + CADENCE ARMED"}
                </span>
              </div>
            </div>
          </div>

          {/* Right Column: Outputs (Strictly Mode-Dependent) */}
          {activeMode === "passive" ? (
            /* PASSIVE MODE: Zero-Emission IDS Audit */
            <div className="forensics-col output-col">
              <div className="col-header">
                <span className="col-tag">IDS POSTURE</span>
                <span className="col-title">Audit & Zero-Emission Posture</span>
              </div>
              <div className="forensics-data">
                <div className="data-row">
                  <span className="lbl">Transmission Policy</span>
                  <span className="val mono" style={{ color: "var(--ok)", fontWeight: 700 }} data-testid="transmission-policy">
                    {transmission}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Wire Tap Posture</span>
                  <span className="val mono">READ-ONLY (Pass-Through Tap)</span>
                </div>
                <div className="data-row">
                  <span className="lbl">Control Actuation</span>
                  <span className="val mono" style={{ color: "var(--muted)" }}>
                    DISABLED (Passive Audit)
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Frame Sanitizer</span>
                  <span className="val mono" style={{ color: "var(--muted)" }}>
                    BYPASSED (Unmodified Stream)
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Baseline Flight Mode</span>
                  <span className="val mono">{trustedMode || telemetry?.flight_mode || "AUTO"}</span>
                </div>
                <div className="data-row">
                  <span className="lbl" title="Compute cost of one fused decision, not attack-onset detection latency.">{DECISION_COMPUTE_LABEL}</span>
                  <span className="val mono">{fmtNum(threat?.latency_ms, 2)} ms</span>
                </div>
              </div>
            </div>
          ) : activeMode === "advisory" ? (
            /* ADVISORY MODE: HUD STATUSTEXT & Pilot Guidance */
            <div className="forensics-col output-col">
              <div className="col-header">
                <span className="col-tag">HUD ADVISORY</span>
                <span className="col-title">MAVLink STATUSTEXT & Guidance</span>
              </div>
              <div className="forensics-data">
                <div className="data-row">
                  <span className="lbl">HUD Alert Channel</span>
                  <span className="val mono">
                    MAVLink STATUSTEXT (prepared by the controller; delivery not reported)
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Alert Frames Queued</span>
                  <span className="val mono">
                    {queuedFrames === null ? "Not reported" : `${queuedFrames} queued by the controller, not transmitted by the mitigation path`}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Last Advisory Prepared</span>
                  <span className="val mono">{lastCommand || "Standby"}</span>
                </div>
                <div className="data-row">
                  <span className="lbl">Transmission</span>
                  <span className="val mono" style={{ color: "var(--muted)", fontSize: "11px" }} data-testid="transmission-advisory">
                    {transmission}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Control Surfaces</span>
                  <span className="val mono" style={{ color: "var(--muted)" }}>
                    UN-ACTUATED (Pilot in Command)
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Recommended Action</span>
                  <span className="val mono" style={{ color: "var(--warn)", fontSize: "11px" }}>
                    {getPilotAdvisory(subMode)}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Baseline Reference</span>
                  <span className="val mono">
                    {trustedLat != null && trustedLon != null
                      ? `${fmtNum(trustedLat, 4)}, ${fmtNum(trustedLon, 4)}`
                      : "Acquiring..."}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            /* ACTIVE IPS MODE: Full Closed-Loop Counter-Actuation & Sanitization */
            <div className="forensics-col output-col">
              <div className="col-header">
                <span className="col-tag">OUTPUTS</span>
                <span className="col-title">Controller Decisions (Counter-Actuation & Sanitization)</span>
              </div>
              <div className="forensics-data">
                <div className="data-row">
                  <span className="lbl">EKF Source Request (controller)</span>
                  <span className="val mono" style={{ color: ekfSwitched ? "var(--warn)" : undefined }}>
                    {ekfSwitched === null
                      ? "Not reported"
                      : ekfSwitched
                      ? "SOURCE 2 (OptFlow / Non-GPS DR) requested"
                      : "No switch requested (SOURCE 1, Primary GPS)"}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Sanitizer Flag (controller)</span>
                  <span className="val mono" style={{ color: sanitizeGps || sanitizeAlt ? "var(--warn)" : undefined }}>
                    {sanitizeGps
                      ? `FLAGGED (Δlat=${fmtNum(latOffsetDeg, 5)}°), not confirmed applied`
                      : sanitizeAlt
                      ? `FLAGGED (Alt -${fmtNum(altBias)}m), not confirmed applied`
                      : sanitizeGps === null && sanitizeAlt === null
                      ? "Not reported"
                      : "Not flagged"}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Quarantined SysIDs (controller)</span>
                  <span className="val mono" style={{ color: quarantined.length > 0 ? "var(--crit)" : undefined }}>
                    {quarantined.length > 0 ? `[${quarantined.join(", ")}] (drop requested by the controller)` : "None"}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Target Restore Mode</span>
                  <span className="val mono" style={{ color: targetRestoreMode ? "var(--ok)" : undefined }}>
                    {targetRestoreMode || trustedMode || "AUTO"}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Last Counter Command (controller)</span>
                  <span className="val mono">
                    {lastCommand || "None"}
                    {queuedFrames !== null && queuedFrames > 0 && ` (${queuedFrames} queued)`}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Transmission confirmed</span>
                  <span className="val mono" style={{ color: "var(--muted)" }} data-testid="transmission-confirmed">
                    {transmission}
                  </span>
                </div>
                <div className="data-row">
                  <span className="lbl">Sanitized Golden Anchor</span>
                  <span className="val mono">
                    {trustedLat != null && trustedLon != null
                      ? `${fmtNum(trustedLat, 5)}, ${fmtNum(trustedLon, 5)}`
                      : "Acquiring..."}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 5. Real-time Tactical Action Timeline */}
      <div className="def-section">
        <div className="def-section-title">
          {activeMode === "passive"
            ? "IDS AUDIT LOG TIMELINE"
            : activeMode === "advisory"
            ? "ADVISORY ALERT TIMELINE"
            : "MITIGATION CONTROLLER DECISION LOG"}
        </div>
        <div className="topo-note" data-testid="timeline-caption">{ACTION_TIMELINE_CAPTION}</div>
        <div className="action-timeline">
          {actions.length === 0 ? (
            <div className="empty-timeline">{emptyTimelineText(activeMode)}</div>
          ) : (
            actions.slice().reverse().map((act, i) => (
              <div key={actions.length - 1 - i} className="timeline-item">
                <span className="tl-time mono">{act.t.toFixed(1)}s</span>
                <span className={`tl-tag tl-tag-${act.tag.toLowerCase()}`}>{act.tag}</span>
                <span className="tl-detail">{act.detail}</span>
              </div>
            ))
          )}
        </div>
      </div>

      {/* 6. Summary Banner */}
      <div className="def-summary-bar">
        <span className="summary-lbl" title={CONTROLLER_SUMMARY_CAPTION}>{controllerSummaryLabel(activeMode)}</span>
        <span className="summary-txt" title={CONTROLLER_SUMMARY_CAPTION}>
          {mitigation?.summary || summaryFallback(activeMode)}
        </span>
      </div>

      {/* 7. Tactical Pilot Overrides (Strictly Mode-Gated) */}
      <div className="def-section overrides-section">
        <div className="def-section-title">
          {activeMode === "passive"
            ? "OPERATOR IDS CONTROLS"
            : activeMode === "advisory"
            ? "PILOT ADVISORY CONTROLS"
            : "PILOT TACTICAL OVERRIDES"}
        </div>

        {activeMode === "passive" ? (
          <div className="passive-overrides-container">
            <div className="passive-notice-card">
              <span className="notice-badge">PASSIVE IDS ONLY</span>
              <span className="notice-text">
                No counter-command, frame drop or quarantine: nothing is sent to the flight controller. Only <b>ACTIVE IPS</b> enforces, and it is refused on a serial (physical) flight-controller link.
              </span>
            </div>
            {isMitigating && (
              <button
                type="button"
                className="override-btn info-btn"
                onClick={() => handleOverride("ack_takeover")}
                disabled={busy}
                style={{ marginTop: "8px" }}
              >
                RESET IDS ALERT LATCH
              </button>
            )}
          </div>
        ) : activeMode === "advisory" ? (
          <div className="override-actions">
            <button
              type="button"
              className="override-btn warn-btn"
              onClick={() => handleOverride("ack_takeover")}
              disabled={busy}
            >
              ACKNOWLEDGE HUD ADVISORY (CLEAR ALERT)
            </button>
          </div>
        ) : (
          <div className="override-actions">
            {environment !== "SIM" ? (
              <HoldConfirmButton
                label="ENGAGE SAFE HOLD (ALT_HOLD)"
                className="override-btn warn-btn"
                disabled={busy}
                onConfirm={() => handleOverride("safe_hold")}
              />
            ) : (
              <button
                type="button"
                className="override-btn warn-btn"
                onClick={() => handleOverride("safe_hold")}
                disabled={busy}
              >
                ENGAGE SAFE HOLD (ALT_HOLD)
              </button>
            )}
            <button
              type="button"
              className="override-btn info-btn"
              onClick={() => handleOverride("reset_quarantine")}
              disabled={busy}
            >
              FLUSH QUARANTINED SYSIDS
            </button>
            <button
              type="button"
              className="override-btn success-btn"
              onClick={() => handleOverride("ack_takeover")}
              disabled={busy}
            >
              ACKNOWLEDGE TAKEOVER (RESET NOMINAL)
            </button>
          </div>
        )}

        {overrideMsg && <div className="override-feedback">{overrideMsg}</div>}
      </div>
    </section>
  );
}

function TopologyCard({ backend, bridge }: { backend?: TopologyInfo | null; bridge?: TopologyInfo | null }) {
  const sel = selectTopology(backend, bridge);
  if (!sel) {
    return (
      <div className="topo-card" data-testid="topology-card">
        <span className="topo-title">TOPOLOGY</span> <span className="topo-muted">Topology not reported</span>
      </div>
    );
  }
  const v = describe(sel);
  return (
    <div className="topo-card" data-testid="topology-card">
      <div className="topo-head">
        <span className="topo-title">TOPOLOGY</span>
        <span className={`topo-badge topo-${v.kind === "A+B" ? "ab" : v.kind.toLowerCase()}`} data-testid="topology-badge">{v.badge}</span>
        <span className={`topo-src topo-src-${v.source}`} data-testid="topology-source">{v.sourceText}</span>
        <span className="topo-muted">{v.originText}</span>
      </div>
      <div className="topo-rows">
        {v.caps.map((c) => (
          <div key={c.id} className="topo-row" data-testid={`topo-${c.id}`}>
            <span>{c.label}</span>
            <b className={c.text === "yes" ? "topo-yes" : c.text === "no" ? "topo-no" : "topo-muted"}>{c.text.toUpperCase()}</b>
          </div>
        ))}
        {v.links.map((l) => (
          <div key={l.id} className="topo-row" data-testid={`topo-link-${l.id}`}>
            <span>{l.label}{l.name ? ` (${l.name})` : ""}</span>
            <b className={l.state === "connected" ? "topo-yes" : l.state === "disconnected" ? "topo-no" : "topo-muted"}>{l.state}</b>
          </div>
        ))}
      </div>
      {v.reasons.length > 0 && (
        <ul className="topo-reasons">{v.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
      )}
    </div>
  );
}

// memoised: the dashboard state changes at 10 Hz, these panels re-render only when their own props change
export const DefensePanel = memo(DefensePanelImpl);
