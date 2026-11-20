import type { ConsoleMode, FlightOpsTab, ModeCapabilities } from "../lib/consoleMode";
import type { Environment } from "../types";

interface Props {
  env: Environment | null;
  mode: ConsoleMode;
  caps: ModeCapabilities;
  activeTab: FlightOpsTab;
  onModeChange: (next: ConsoleMode) => void;
  onTabChange: (tab: FlightOpsTab) => void;
}

export function ModeBanner({ env, mode, caps, activeTab, onModeChange, onTabChange }: Props) {
  const liveLocked = env != null && env !== "SIM";
  return (
    <div className="mode-banner" data-testid="mode-banner">
      <div className="mode-banner-left">
        <span className={`mode-pill ${mode === "flight-ops" ? "mode-pill-ops" : "mode-pill-demo"}`}>
          {mode === "flight-ops" ? "FLIGHT OPS MODE" : "DEMO / LAB MODE"}
        </span>
        <span className="mode-desc">
          {mode === "flight-ops"
            ? "Over-the-air GCS controls & live telemetry active · simulation attack injection disabled"
            : "In-process flight simulator · attack injection & scenario lab active"}
        </span>
      </div>

      <div className="mode-banner-controls">
        <div className="mode-seg" role="group" aria-label="Console operating mode">
          <button
            type="button"
            disabled={liveLocked}
            className={mode === "demo" ? "seg-btn active" : "seg-btn"}
            onClick={() => onModeChange("demo")}
            title={liveLocked ? "Disabled when monitoring a live/replay vehicle stream" : "Switch to Demo / Lab console"}
          >
            Demo / Lab
          </button>
          <button
            type="button"
            className={mode === "flight-ops" ? "seg-btn active" : "seg-btn"}
            onClick={() => onModeChange("flight-ops")}
          >
            Flight Ops
          </button>
        </div>

        <nav className="mode-tabs" aria-label="Operations sections">
          <button
            type="button"
            className={activeTab === "monitor" ? "tab-btn active" : "tab-btn"}
            onClick={() => onTabChange("monitor")}
          >
            GCS Monitor &amp; Defense
          </button>
          <button
            type="button"
            className={activeTab === "bench-setup" ? "tab-btn active" : "tab-btn"}
            onClick={() => onTabChange("bench-setup")}
            title={caps.benchBlockedReason ?? "Pre-flight companion setup & field drills"}
          >
            Bench Setup Wizard {!caps.benchSetupAllowed ? " (Locked)" : ""}
          </button>
          <button
            type="button"
            className={activeTab === "forensics" ? "tab-btn active" : "tab-btn"}
            onClick={() => onTabChange("forensics")}
          >
            Forensics &amp; Drills
          </button>
        </nav>
      </div>
    </div>
  );
}
