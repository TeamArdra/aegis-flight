import { useState } from "react";
import { api, type DiscoveredPort } from "../services/api";
import type { ModeCapabilities } from "../lib/consoleMode";

interface Props {
  caps: ModeCapabilities;
}

export function BenchSetupWizard({ caps }: Props) {
  const [step, setStep] = useState<number>(1);
  const [topology, setTopology] = useState<"inline" | "side-tap">("inline");
  const [fcPort, setFcPort] = useState("auto");
  const [fcBaud, setFcBaud] = useState("auto");
  const [fcRtscts, setFcRtscts] = useState(false);
  const [gcsPort, setGcsPort] = useState("auto");
  const [gcsBaud, setGcsBaud] = useState("auto");
  const [configDir, setConfigDir] = useState("configs/universal_flight");
  const [defenseMode, setDefenseMode] = useState<"passive" | "advisory" | "active-ips">("passive");
  const [semanticFirewall, setSemanticFirewall] = useState(true);
  const [failClosedUplink, setFailClosedUplink] = useState(true);

  const [ports, setPorts] = useState<DiscoveredPort[]>([]);
  const [discoverBusy, setDiscoverBusy] = useState(false);
  const [discoverMsg, setDiscoverMsg] = useState<string | null>(null);

  const [enrollBusy, setEnrollBusy] = useState(false);
  const [enrollResult, setEnrollResult] = useState<Record<string, unknown> | null>(null);
  const [enrollErr, setEnrollErr] = useState<string | null>(null);

  const [yamlOut, setYamlOut] = useState<string>("");
  const [preflightOut, setPreflightOut] = useState<Record<string, unknown> | null>(null);
  const [drillOut, setDrillOut] = useState<Record<string, unknown> | null>(null);
  const [stepErr, setStepErr] = useState<string | null>(null);

  const locked = !caps.benchSetupAllowed;

  const discoverPorts = async () => {
    setDiscoverBusy(true);
    setStepErr(null);
    setDiscoverMsg("Passively listening (0 B TX) on serial ports…");
    try {
      const res = await api.discoverPorts();
      if (!res.ok) {
        setDiscoverMsg(null);
        setStepErr(res.error || "Port discovery refused.");
      } else {
        setPorts(res.ports || []);
        setDiscoverMsg(`Found ${res.ports?.length ?? 0} MAVLink port(s) with 0 B transmitted.`);
        const fcCand = (res.ports || []).find((p) => p.role === "fc") || (res.ports || [])[0];
        const gcsCand = (res.ports || []).find((p) => p.role === "gcs_radio" && p.device !== fcCand?.device);
        if (fcCand) {
          setFcPort(fcCand.device);
          setFcBaud(String(fcCand.baudrate));
        }
        if (gcsCand && topology === "inline") {
          setGcsPort(gcsCand.device);
          setGcsBaud(String(gcsCand.baudrate));
        }
      }
    } catch {
      setDiscoverMsg(null);
      setStepErr("Port discovery failed (backend unreachable or locked).");
    } finally {
      setDiscoverBusy(false);
    }
  };

  const runEnroll = async () => {
    setEnrollBusy(true);
    setEnrollErr(null);
    setEnrollResult(null);
    try {
      const baudNum = fcBaud === "auto" ? 921600 : Number(fcBaud) || 921600;
      const res = await api.enrollFirmware(fcPort, baudNum);
      if (!res.ok) setEnrollErr(res.error || "Firmware enrollment failed.");
      else setEnrollResult(res.entry ?? null);
    } catch {
      setEnrollErr("Firmware enrollment request failed.");
    } finally {
      setEnrollBusy(false);
    }
  };

  const buildConfigPayload = () => ({
    topology,
    fc_port: fcPort.trim() || "auto",
    fc_baud: fcBaud === "auto" ? "auto" : Number(fcBaud) || 921600,
    fc_rtscts: fcRtscts,
    ...(topology === "inline"
      ? { gcs_port: gcsPort.trim() || "auto", gcs_baud: gcsBaud === "auto" ? "auto" : Number(gcsBaud) || 57600 }
      : {}),
    defense_mode: topology === "side-tap" ? "passive" : defenseMode,
    config_dir: configDir || null,
    semantic_firewall_enabled: semanticFirewall,
    fail_closed_uplink_commands: failClosedUplink,
    anchors_enabled: true,
  });

  const generateAndPreflight = async () => {
    setStepErr(null);
    const payload = buildConfigPayload();
    try {
      const [gen, pre] = await Promise.all([api.generateConfig(payload), api.runPreflight(payload)]);
      if (!gen.ok) setStepErr(gen.error || "Configuration validation failed.");
      else setYamlOut(gen.yaml || "");
      setPreflightOut(pre);
    } catch {
      setStepErr("Failed to generate configuration or run preflight.");
    }
  };

  const runDrill = async () => {
    setStepErr(null);
    try {
      const res = await api.runDrill("all");
      setDrillOut(res);
    } catch {
      setStepErr("Shadow field drill failed.");
    }
  };

  return (
    <div className="bench-wizard" data-testid="bench-setup-wizard">
      <div className="panel">
        <header>
          <span className="panel-title">On-Vehicle Bench Setup Wizard</span>
          <span className="panel-note">Initial companion installation · 0 B FC TX checks</span>
        </header>

        <div className="setup-split-note">
          <div>
            <b>Over-the-Air via GCS Radio (Active in Flight):</b> Posture switching (<code>PASSIVE / ADVISORY / ACTIVE IPS</code>),
            Safe-Hold / Quarantine overrides, cross-end health &amp; forensic verification.
          </div>
          <div>
            <b>Initial Companion Setup on Bench (Requires USB/SSH Loopback &amp; Disarmed Airframe):</b>{" "}
            Wiring topology selection (<i>Radio -&gt; Companion -&gt; FC</i> inline or single RX Y-tap), UART autobaud discovery,
            MAVLink-2 signing key pairing, <code>AUTOPILOT_VERSION</code> pinning &amp; <code>systemd</code> install.
          </div>
        </div>

        {locked && (
          <div className="alert-banner crit" role="alert">
            {caps.benchBlockedReason}
          </div>
        )}

        <div className="wizard-steps" role="tablist" aria-label="Setup steps">
          {[
            { id: 1, label: "1. Wiring Topology" },
            { id: 2, label: "2. Port & Autobaud" },
            { id: 3, label: "3. Firmware & Signing" },
            { id: 4, label: "4. YAML & Preflight" },
            { id: 5, label: "5. Shadow Drill" },
          ].map((s) => (
            <button
              key={s.id}
              type="button"
              role="tab"
              aria-selected={step === s.id}
              className={step === s.id ? "wiz-step active" : "wiz-step"}
              onClick={() => setStep(s.id)}
            >
              {s.label}
            </button>
          ))}
        </div>

        {stepErr && <div className="alert-banner crit" role="alert">{stepErr}</div>}

        {step === 1 && (
          <div className="wizard-body">
            <h3>Select Physical Companion Wiring</h3>
            <p className="panel-note">
              Telemetry radios can either wire through the companion computer (<code>inline</code>, enabling uplink IPS &amp; semantic firewall)
              or Y-tap passively onto the UART line (<code>side-tap</code>, zero transmit risk).
            </p>
            <div className="topo-cards">
              <label className={topology === "inline" ? "topo-card selected" : "topo-card"}>
                <input
                  type="radio"
                  name="topology"
                  value="inline"
                  checked={topology === "inline"}
                  onChange={() => setTopology("inline")}
                />
                <strong>Inline Companion Bridge (Recommended)</strong>
                <pre className="wiring-ascii">Radio Telemetry &lt;-&gt; Companion (Aegis) &lt;-&gt; Flight Controller</pre>
                <span>Enables Semantic Firewall, MAVLink-2 Uplink Guard, Safe-Hold &amp; In-Band Radio GCS posture control.</span>
              </label>

              <label className={topology === "side-tap" ? "topo-card selected" : "topo-card"}>
                <input
                  type="radio"
                  name="topology"
                  value="side-tap"
                  checked={topology === "side-tap"}
                  onChange={() => {
                    setTopology("side-tap");
                    setDefenseMode("passive");
                  }}
                />
                <strong>Single-Port Passive Side-Tap (RX-Only Y-Split)</strong>
                <pre className="wiring-ascii">Radio Telemetry &lt;-&gt; FC UART  |  Companion RX Pin ---&gt; Observe Only (0 B TX)</pre>
                <span>Zero modification to existing drone wiring; strictly passive monitoring &amp; cryptographic black-box logging.</span>
              </label>
            </div>
            <div className="wizard-actions">
              <button type="button" onClick={() => setStep(2)}>Next: Port Discovery -&gt;</button>
            </div>
          </div>
        )}

        {step === 2 && (
          <div className="wizard-body">
            <h3>Zero-TX Serial Port &amp; Autobaud Discovery</h3>
            <p className="panel-note">
              Probes connected UART / USB adapters in strict read-only mode (0 bytes transmitted) across 57600–921600 baud.
            </p>
            <div className="form-grid">
              <label>
                FC Port (<code>auto</code> or device path)
                <input value={fcPort} onChange={(e) => setFcPort(e.target.value)} placeholder="auto" />
              </label>
              <label>
                FC Baud (<code>auto</code> or rate)
                <input value={fcBaud} onChange={(e) => setFcBaud(e.target.value)} placeholder="auto" />
              </label>
              {topology === "inline" && (
                <>
                  <label>
                    Radio GCS Port
                    <input value={gcsPort} onChange={(e) => setGcsPort(e.target.value)} placeholder="auto" />
                  </label>
                  <label>
                    Radio GCS Baud
                    <input value={gcsBaud} onChange={(e) => setGcsBaud(e.target.value)} placeholder="auto" />
                  </label>
                </>
              )}
              <label className="chk">
                <input type="checkbox" checked={fcRtscts} onChange={(e) => setFcRtscts(e.target.checked)} />
                Hardware UART flow control (RTS/CTS)
              </label>
            </div>
            <div className="wizard-actions">
              <button type="button" disabled={locked || discoverBusy} onClick={() => void discoverPorts()}>
                {discoverBusy ? "Scanning (0 B TX)…" : "Auto-Detect Connected Ports (0 B TX)"}
              </button>
              <button type="button" onClick={() => setStep(3)}>Next: Firmware &amp; Signing -&gt;</button>
            </div>
            {discoverMsg && <p className="panel-note">{discoverMsg}</p>}
            {ports.length > 0 && (
              <ul className="port-list">
                {ports.map((p) => (
                  <li key={p.device} className="mono">
                    {p.device} @ {p.baudrate} ({p.role.toUpperCase()}) — sysids={p.sysids.join(",")} autopilot={p.autopilot_id ?? "?"} ({p.frames_valid} frames)
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}

        {step === 3 && (
          <div className="wizard-body">
            <h3>Firmware Pinning &amp; MAVLink-2 Signing Checklist</h3>
            <p className="panel-note">
              Enroll your flight controller&apos;s genuine <code>AUTOPILOT_VERSION</code> passively before flight.
              Signing keys are never entered in or transmitted through the web UI — provision your 32-byte key on disk via CLI or SSH.
            </p>
            <div className="cli-callout mono">
              <div># Generate &amp; store MAVLink-2 key outside repo (mode 0600):</div>
              <div>python -c &quot;import os,pathlib; p=pathlib.Path(&apos;/etc/aegisflight/signing.key&apos;); p.write_bytes(os.urandom(32)); p.chmod(0o600)&quot;</div>
              <div># Pin firmware with optional HMAC allowlist key:</div>
              <div>AEGIS_ALLOWLIST_KEY=&quot;...&quot; aegis onboard --enroll-firmware /etc/aegisflight/firmware_allowlist.yaml</div>
            </div>
            <div className="wizard-actions">
              <button type="button" disabled={locked || enrollBusy || fcPort === "auto"} onClick={() => void runEnroll()}>
                {enrollBusy ? "Listening for AUTOPILOT_VERSION…" : "Passively Capture AUTOPILOT_VERSION (0 B TX)"}
              </button>
              <button type="button" onClick={() => setStep(4)}>Next: YAML &amp; Preflight -&gt;</button>
            </div>
            {enrollErr && <div className="alert-banner warn">{enrollErr}</div>}
            {enrollResult && (
              <pre className="yaml-box">{JSON.stringify(enrollResult, null, 2)}</pre>
            )}
          </div>
        )}

        {step === 4 && (
          <div className="wizard-body">
            <h3>Generate Validated Companion Configuration &amp; Preflight</h3>
            <div className="form-grid">
              <label>
                Detector Profile
                <select value={configDir} onChange={(e) => setConfigDir(e.target.value)}>
                  <option value="configs/universal_flight">Universal Flight (Auto-dialect + ConstDet + Bias Learn)</option>
                  <option value="configs/ardupilot_copter">ArduCopter Profile</option>
                  <option value="configs/px4_sitl">PX4 Profile</option>
                </select>
              </label>
              <label>
                Boot Defense Posture
                <select
                  value={topology === "side-tap" ? "passive" : defenseMode}
                  disabled={topology === "side-tap"}
                  onChange={(e) => setDefenseMode(e.target.value as "passive" | "advisory" | "active-ips")}
                >
                  <option value="passive">passive (recommended initial)</option>
                  <option value="advisory">advisory (GCS alerts)</option>
                  <option value="active-ips">active-ips (SITL / socket:// only)</option>
                </select>
              </label>
              <label className="chk">
                <input type="checkbox" checked={semanticFirewall} onChange={(e) => setSemanticFirewall(e.target.checked)} />
                Airborne Semantic Firewall (PARAM_SET / geofence block while armed)
              </label>
              <label className="chk">
                <input type="checkbox" checked={failClosedUplink} onChange={(e) => setFailClosedUplink(e.target.checked)} />
                Asymmetric Fail-Safe Bridge (fail-closed uplink control commands)
              </label>
            </div>
            <div className="wizard-actions">
              <button type="button" disabled={locked} onClick={() => void generateAndPreflight()}>
                Validate YAML &amp; Run 0-TX Preflight
              </button>
              <button type="button" onClick={() => setStep(5)}>Next: Shadow Drill -&gt;</button>
            </div>
            {yamlOut && <pre className="yaml-box">{yamlOut}</pre>}
            {preflightOut && <pre className="yaml-box">{JSON.stringify(preflightOut, null, 2)}</pre>}
          </div>
        )}

        {step === 5 && (
          <div className="wizard-body">
            <h3>Zero-TX Pre-Flight Shadow Verification Drill</h3>
            <p className="panel-note">
              Exercises signed command rejection, armed semantic firewall drops, GPS spoofing detection, and clock-skew detection in memory (0 bytes transmitted to the airframe).
            </p>
            <div className="wizard-actions">
              <button type="button" onClick={() => void runDrill()}>
                Run All Pre-Flight Shadow Drills (0 B FC TX)
              </button>
            </div>
            {drillOut && <pre className="yaml-box">{JSON.stringify(drillOut, null, 2)}</pre>}
          </div>
        )}
      </div>
    </div>
  );
}
