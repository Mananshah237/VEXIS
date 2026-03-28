"use client";

import { useEffect, useState } from "react";

const PHASES = [
  { key: "parsing", label: "Parsing" },
  { key: "taint_analysis", label: "Taint Analysis" },
  { key: "reasoning", label: "AI Reasoning" },
  { key: "complete", label: "Complete" },
] as const;

type PhaseKey = (typeof PHASES)[number]["key"] | "queued" | "failed";

const PHASE_ORDER: Record<string, number> = {
  queued: -1,
  parsing: 0,
  taint_analysis: 1,
  reasoning: 2,
  complete: 3,
  failed: -1,
};

interface WsMessage {
  phase: string;
  progress: number;
  message: string;
}

interface Props {
  scanId: string;
  initialStatus: string;
}

export function ScanProgress({ scanId, initialStatus }: Props) {
  const [phase, setPhase] = useState<string>(initialStatus);
  const [progress, setProgress] = useState(0);
  const [message, setMessage] = useState("Connecting...");
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const wsBase = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000";
    const ws = new WebSocket(`${wsBase}/ws/scan/${scanId}`);

    ws.onopen = () => {
      setConnected(true);
      setMessage("Connected — waiting for scan updates...");
    };

    ws.onmessage = (evt) => {
      try {
        const data: WsMessage = JSON.parse(evt.data);
        setPhase(data.phase);
        setProgress(data.progress);
        setMessage(data.message);
      } catch {
        // ignore malformed messages
      }
    };

    ws.onerror = () => {
      setConnected(false);
      setMessage("WebSocket unavailable — polling for status");
    };

    ws.onclose = () => setConnected(false);

    return () => ws.close();
  }, [scanId]);

  const currentIdx = PHASE_ORDER[phase] ?? -1;
  const isFailed = phase === "failed";

  return (
    <div className="space-y-5">
      {/* Phase indicator row */}
      <div className="flex items-center gap-0">
        {PHASES.map((p, i) => {
          const pIdx = PHASE_ORDER[p.key];
          const isDone = currentIdx > pIdx;
          const isActive = currentIdx === pIdx;
          const isLast = i === PHASES.length - 1;

          return (
            <div key={p.key} className="flex items-center flex-1">
              <div className="flex flex-col items-center flex-1">
                <div
                  className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold border-2 transition-all duration-500 ${
                    isFailed
                      ? "border-severity-critical text-severity-critical"
                      : isDone
                      ? "border-severity-safe bg-severity-safe text-bg-primary"
                      : isActive
                      ? "border-accent-primary text-accent-primary animate-pulse"
                      : "border-border text-text-muted"
                  }`}
                >
                  {isDone ? "✓" : i + 1}
                </div>
                <span
                  className={`text-xs mt-1.5 font-code ${
                    isActive ? "text-accent-primary" : isDone ? "text-severity-safe" : "text-text-muted"
                  }`}
                >
                  {p.label}
                </span>
              </div>
              {!isLast && (
                <div
                  className={`h-0.5 w-full mx-1 mb-5 transition-all duration-700 ${
                    isDone ? "bg-severity-safe" : "bg-border"
                  }`}
                />
              )}
            </div>
          );
        })}
      </div>

      {/* Progress bar */}
      <div className="h-1.5 bg-bg-elevated rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{
            width: `${Math.round(progress * 100)}%`,
            backgroundColor: isFailed
              ? "var(--tw-color-severity-critical, #FF1744)"
              : phase === "complete"
              ? "#00E676"
              : "#00E5FF",
          }}
        />
      </div>

      {/* Status message */}
      <div className="flex items-center justify-between text-xs">
        <span className={`font-code ${isFailed ? "text-severity-critical" : "text-text-secondary"}`}>
          {message}
        </span>
        <span className="text-text-muted">{Math.round(progress * 100)}%</span>
      </div>

      {!connected && phase !== "complete" && phase !== "failed" && (
        <p className="text-xs text-text-muted italic">
          Page will refresh automatically when scan completes.
        </p>
      )}
    </div>
  );
}
