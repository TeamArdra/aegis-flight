import { useEffect, useState } from "react";
import { setBridgePostureViaRadio } from "../services/api";
import {
  CONTROL_HINT, canSend, commandView, confirmDeadline, confirmOpen, confirmRemainingS, feedAge, fmtAgo, freshness, isLowering,
  isPending, orderFeed,
} from "../lib/bridgeRemote";
import { ActiveIpsDialog } from "./ActiveIpsDialog";
import type { BridgeRemote, DefenseMode } from "../types";

const TONE: Record<string, string | undefined> = { ok: "var(--ok)", warn: "var(--warn, #d9a400)", crit: "var(--crit)", info: undefined };
const MODES: DefenseMode[] = ["passive", "advisory", "active-ips"];

// Bridge panel fed by the in-band report the backend decodes from the telemetry radio.
export function InbandBridgePanel({ remote }: { remote: BridgeRemote }) {
  const [now, setNow] = useState(Date.now());
  const [sending, setSending] = useState(false);
  const [target, setTarget] = useState<DefenseMode | null>(null); // lowering target awaiting the second confirmation
  const [deadline, setDeadline] = useState<number | null>(null);
  const [dialog, setDialog] = useState(false);
  const [dialogErr, setDialogErr] = useState<string | null>(null);
  const [ctlErr, setCtlErr] = useState<string | null>(null);
  const lc = remote.last_command;
  const result = lc?.result ?? null;
  useEffect(() => { const id = window.setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(id); }, []);
  // the 10 s window starts when the bridge first asks for confirmation
  useEffect(() => {
    if (result === "confirm_required" && target) setDeadline((d) => d ?? confirmDeadline(lc, Date.now()));
    else setDeadline(null);
  }, [result, target]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (result === "accepted" || result === "denied" || result === "timeout" || result === "failed") setTarget(null);
  }, [result]);

  const fresh = freshness(remote.age_s);
  const cmd = commandView(lc);
  const pending = isPending(sending, lc);
  const flags = remote.flags;
  const c = remote.counters;
  const confirming = confirmOpen(target, lc, deadline, now);
  const left = confirmRemainingS(deadline, now);

  const send = async (mode: DefenseMode, allowUnsigned?: boolean, confirm?: boolean) => {
    if (sending) return; // never double-send
    setSending(true); setCtlErr(null); setDialogErr(null);
    const r = await setBridgePostureViaRadio(mode, allowUnsigned, confirm);
    setSending(false);
    if (r.kind === "pending") { setDialog(false); if (confirm) { setTarget(null); setDeadline(null); } }
    else if (r.kind === "signing_required") { setDialogErr(r.message); setDialog(true); }
    else { setDialog(false); setCtlErr(r.message); }
  };
  const pick = (mode: DefenseMode) => {
    if (pending || mode === remote.posture) return;
    if (mode === "active-ips") { setDialogErr(null); setDialog(true); return; }
    setTarget(isLowering(remote.posture, mode) ? mode : null);
    void send(mode);
  };
  const feed = orderFeed(remote.recent);
  return (
    <div className="panel" data-testid="bridge-panel">
      <header><span className="panel-title">Inline IPS bridge</span><span className="panel-note">in-band over the radio</span></header>
      <div className="source-bar" style={{ flexWrap: "wrap" }}>
        <span data-testid="bridge-fresh" style={fresh === "fresh" ? undefined : { color: "var(--crit)", fontWeight: 700 }}>
          {fresh === "lost" ? "bridge status LOST" : fresh === "stale" ? "status STALE" : "status live"} · last status {fmtAgo(remote.age_s)}
        </span>
        <span>posture <b>{remote.posture ?? "—"}</b> · topology <b>{remote.topology ?? "—"}</b> · state <b>{remote.state ?? "—"}</b></span>
        <span>signing <b>{flags.signing ? "on" : "off"}</b> · analyser <b>{flags.analyser_ok ? "ok" : "fault"}</b> · FC link <b>{flags.fc_link ? "up" : "down"}</b> · GCS link <b>{flags.gcs_link ? "up" : "down"}</b></span>
        <span style={flags.contested ? { color: "var(--crit)", fontWeight: 700 } : undefined}>contested <b>{flags.contested ? "yes" : "no"}</b> · unsigned acknowledged <b>{flags.unsigned_ack ? "yes" : "no"}</b></span>
        <span>forwarded <b>{c.forwarded}</b> · dropped up <b>{c.dropped_up}</b> · alerts <b>{c.alerts}</b> · counter-frames <b>{c.counter_frames}</b> · hook errors <b style={c.hook_errors > 0 ? { color: "var(--crit)" } : undefined}>{c.hook_errors}</b></span>
        <span>last alert <b>{remote.last_alert ?? "none"}</b></span>
        <span>last action <b>{remote.last_action ?? "none"}</b></span>
      </div>
      <div className="source-bar" style={{ flexWrap: "wrap", gap: 8 }}>
        {remote.control_available && MODES.map((m) => (
          <button key={m} type="button" disabled={!canSend(remote, sending)} aria-pressed={remote.posture === m}
            style={remote.posture === m ? { fontWeight: 700 } : undefined} onClick={() => pick(m)}>{m.toUpperCase()}</button>
        ))}
        {!remote.control_available && <span className="panel-note" data-testid="bridge-control-hint">{CONTROL_HINT}</span>}
        <span data-testid="bridge-command" role="status" style={{ color: TONE[cmd.tone] }}>command: {cmd.text}</span>
        {ctlErr && <span role="alert" data-testid="bridge-control-error" style={{ color: "var(--crit)" }}>{ctlErr}</span>}
      </div>
      {confirming && target && (
        <div className="source-bar" role="alertdialog" aria-label="Confirm posture change" data-testid="bridge-confirm" style={{ flexWrap: "wrap", gap: 8 }}>
          <span>Confirm switching the bridge to <b>{target}</b>? The bridge asked for a second confirmation. <b data-testid="bridge-countdown">{left} s</b> left.</span>
          <button type="button" disabled={sending} onClick={() => void send(target, undefined, true)}>Confirm</button>
          <button type="button" onClick={() => { setTarget(null); setDeadline(null); }}>Cancel</button>
        </div>
      )}
      {result === "confirm_required" && target && !confirming && (
        <div className="source-bar"><span data-testid="bridge-confirm-expired">Confirmation window expired; nothing was changed.</span></div>
      )}
      <ul data-testid="bridge-feed" aria-label="Bridge alert feed" style={{ listStyle: "none", margin: 0, padding: "4px 12px", maxHeight: 180, overflowY: "auto" }}>
        {feed.length === 0 && <li className="panel-note">no bridge messages yet</li>}
        {feed.map((e, i) => {
          const a = feedAge(e.t, now / 1000);
          return <li key={`${e.t}-${i}`}><span className="panel-note">{a == null ? `t=${e.t}` : fmtAgo(a)}</span> {e.text}</li>;
        })}
      </ul>
      {dialog && (
        <ActiveIpsDialog signing={{ configured: flags.signing, unsigned_acknowledged: flags.unsigned_ack }} busy={sending} error={dialogErr}
          onCancel={() => { setDialog(false); setDialogErr(null); }}
          onConfirm={(u) => { void send("active-ips", u); }} />
      )}
    </div>
  );
}
