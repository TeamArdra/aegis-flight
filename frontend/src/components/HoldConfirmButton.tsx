import { useEffect, useRef, useState } from "react";

interface HoldConfirmButtonProps {
  label: string;
  holdingLabel?: string;
  holdMs?: number;
  disabled?: boolean;
  className?: string;
  onConfirm: () => void | Promise<void>;
}

/** Press-and-hold safety trigger preventing accidental single-click actuation in Flight Ops mode. */
export function HoldConfirmButton({
  label,
  holdingLabel = "Keep holding to confirm…",
  holdMs = 1400,
  disabled = false,
  className = "btn danger",
  onConfirm,
}: HoldConfirmButtonProps) {
  const [holding, setHolding] = useState(false);
  const [pct, setPct] = useState(0);
  const timerRef = useRef<number | null>(null);
  const startRef = useRef<number>(0);

  const stop = () => {
    setHolding(false);
    setPct(0);
    if (timerRef.current != null) {
      window.clearInterval(timerRef.current);
      timerRef.current = null;
    }
  };

  useEffect(() => () => {
    if (timerRef.current != null) window.clearInterval(timerRef.current);
  }, []);

  const begin = () => {
    if (disabled || holding) return;
    setHolding(true);
    startRef.current = performance.now();
    timerRef.current = window.setInterval(() => {
      const elapsed = performance.now() - startRef.current;
      const next = Math.min(100, Math.round((elapsed / holdMs) * 100));
      setPct(next);
      if (elapsed >= holdMs) {
        stop();
        void onConfirm();
      }
    }, 40);
  };

  return (
    <button
      type="button"
      className={className}
      disabled={disabled}
      onPointerDown={begin}
      onPointerUp={stop}
      onPointerLeave={stop}
      onPointerCancel={stop}
      onKeyDown={(e) => { if (e.key === " " || e.key === "Enter") begin(); }}
      onKeyUp={stop}
      style={{ position: "relative", overflow: "hidden", minHeight: 44 }}
      aria-label={`${label} (press and hold ${Math.round(holdMs / 100) / 10} seconds to confirm)`}
    >
      <span
        style={{
          position: "absolute",
          inset: 0,
          width: `${pct}%`,
          background: "rgba(255,255,255,0.22)",
          pointerEvents: "none",
          transition: holding ? "none" : "width 120ms ease-out",
        }}
      />
      <span style={{ position: "relative", zIndex: 1 }}>
        {holding ? `${holdingLabel} (${pct}%)` : `${label} (Hold)`}
      </span>
    </button>
  );
}
