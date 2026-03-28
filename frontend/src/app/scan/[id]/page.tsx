"use client";

import { useParams, useRouter } from "next/navigation";
import useSWR from "swr";
import Link from "next/link";
import { ScanProgress } from "@/components/ScanProgress";

const fetcher = (url: string) => fetch(url).then((r) => r.json());

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const SEV_COLORS: Record<string, string> = {
  critical: "text-severity-critical",
  high: "text-severity-high",
  medium: "text-severity-medium",
  low: "text-severity-low",
  info: "text-severity-info",
};
const SEV_BAR_COLORS: Record<string, string> = {
  critical: "bg-severity-critical",
  high: "bg-severity-high",
  medium: "bg-severity-medium",
  low: "bg-severity-low",
  info: "bg-severity-info",
};

function formatSource(scan: any): string {
  if (scan.source_type === "github_url") return scan.source_ref.replace("https://github.com/", "");
  if (scan.source_type === "raw_code") return "Raw code snippet";
  return scan.source_ref;
}

function duration(scan: any): string {
  if (!scan.completed_at || !scan.created_at) return "";
  const secs = Math.round(
    (new Date(scan.completed_at).getTime() - new Date(scan.created_at).getTime()) / 1000
  );
  return secs < 60 ? `${secs}s` : `${Math.floor(secs / 60)}m ${secs % 60}s`;
}

export default function ScanResultsPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const apiBase = process.env.NEXT_PUBLIC_API_URL;

  const { data: scan, mutate: mutateScan } = useSWR(
    `${apiBase}/api/v1/scan/${id}`,
    fetcher,
    { refreshInterval: (data) => (data?.status === "complete" || data?.status === "failed" ? 0 : 2000) }
  );
  const { data: findingsData } = useSWR(
    scan?.status === "complete" ? `${apiBase}/api/v1/scan/${id}/findings` : null,
    fetcher
  );

  const isRunning = scan && !["complete", "failed"].includes(scan.status);
  const findings: any[] = findingsData?.findings ?? [];
  const hasTaintOnlyFindings = findings.some(
    (f) => f.llm_reasoning && f.llm_reasoning.includes("budget exhausted")
  );

  // Sort by severity
  const sortedFindings = [...findings].sort(
    (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity)
  );

  // Severity counts for breakdown bar
  const sevCounts = SEV_ORDER.reduce((acc, s) => {
    acc[s] = findings.filter((f) => f.severity === s).length;
    return acc;
  }, {} as Record<string, number>);
  const totalFindings = findings.length;

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-2 mb-1">
          <Link href="/dashboard" className="text-text-muted text-sm hover:text-accent-primary">
            Dashboard
          </Link>
          <span className="text-text-muted text-sm">→</span>
          <span className="text-text-secondary text-sm truncate max-w-xs">
            {scan ? formatSource(scan) : id}
          </span>
        </div>
        <h1 className="text-2xl font-display font-bold mb-6">Scan Results</h1>

        {/* Scan metadata */}
        {scan && (
          <div className="bg-bg-secondary border border-border rounded-xl p-5 mb-6">
            <div className="grid grid-cols-4 gap-4">
              <div>
                <p className="text-text-muted text-xs uppercase tracking-wider mb-1">Source</p>
                <p className="font-code text-sm text-text-primary truncate">{formatSource(scan)}</p>
              </div>
              <div>
                <p className="text-text-muted text-xs uppercase tracking-wider mb-1">Status</p>
                <p
                  className={`font-bold text-sm capitalize ${
                    scan.status === "complete"
                      ? "text-severity-safe"
                      : scan.status === "failed"
                      ? "text-severity-critical"
                      : "text-accent-primary"
                  }`}
                >
                  {scan.status}
                </p>
              </div>
              <div>
                <p className="text-text-muted text-xs uppercase tracking-wider mb-1">Files</p>
                <p className="font-code text-sm">{scan.stats?.files_parsed ?? 0} parsed</p>
              </div>
              <div>
                <p className="text-text-muted text-xs uppercase tracking-wider mb-1">Duration</p>
                <p className="font-code text-sm">{duration(scan) || "—"}</p>
              </div>
            </div>

            {/* Progress while running */}
            {isRunning && (
              <div className="mt-5 pt-5 border-t border-border">
                <ScanProgress scanId={id} initialStatus={scan.status} />
              </div>
            )}
          </div>
        )}

        {/* Taint-only budget banner */}
        {!isRunning && hasTaintOnlyFindings && (
          <div className="bg-bg-secondary border border-severity-medium/40 rounded-xl p-4 mb-4 flex items-start gap-3">
            <span className="text-severity-medium text-lg leading-none mt-0.5">⚠</span>
            <div>
              <p className="text-severity-medium font-semibold text-sm">Some findings scored without AI reasoning</p>
              <p className="text-text-muted text-xs mt-0.5">
                The scan&apos;s LLM call budget was reached. Affected findings were scored on taint analysis alone —
                they may have higher false-positive rates. Review them manually or re-run with a higher budget limit.
              </p>
            </div>
          </div>
        )}

        {/* Severity breakdown bar */}
        {!isRunning && totalFindings > 0 && (
          <div className="bg-bg-secondary border border-border rounded-xl p-5 mb-6">
            <div className="flex items-center justify-between mb-3">
              <p className="text-text-muted text-xs uppercase tracking-wider">Severity Breakdown</p>
              <p className="font-code text-sm text-text-secondary">{totalFindings} finding{totalFindings !== 1 ? "s" : ""}</p>
            </div>
            <div className="flex h-2.5 rounded-full overflow-hidden gap-0.5">
              {SEV_ORDER.map((sev) => {
                const count = sevCounts[sev];
                if (!count) return null;
                const pct = (count / totalFindings) * 100;
                return (
                  <div
                    key={sev}
                    className={`${SEV_BAR_COLORS[sev]} rounded-sm`}
                    style={{ width: `${pct}%` }}
                    title={`${sev}: ${count}`}
                  />
                );
              })}
            </div>
            <div className="flex gap-4 mt-2">
              {SEV_ORDER.map((sev) => {
                const count = sevCounts[sev];
                if (!count) return null;
                return (
                  <div key={sev} className="flex items-center gap-1.5 text-xs text-text-muted">
                    <span className={`w-2 h-2 rounded-full ${SEV_BAR_COLORS[sev]}`} />
                    <span className="capitalize">{sev}</span>
                    <span className={`font-bold ${SEV_COLORS[sev]}`}>{count}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Clean result */}
        {!isRunning && scan?.status === "complete" && totalFindings === 0 && (
          <div className="bg-bg-secondary border border-severity-safe/30 rounded-xl p-8 text-center mb-6">
            <p className="text-5xl mb-3">✓</p>
            <p className="text-severity-safe font-bold text-lg">No vulnerabilities found</p>
            <p className="text-text-muted text-sm mt-1">
              {scan.stats?.taint_paths ?? 0} taint paths analyzed — all cleared.
            </p>
          </div>
        )}

        {/* Actions: PDF download + Re-scan */}
        {!isRunning && scan?.status === "complete" && (
          <div className="flex items-center justify-between mb-4">
            <button
              onClick={async () => {
                try {
                  const resp = await fetch(`${apiBase}/api/v1/scan`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                      source_type: scan.source_type,
                      source: scan.source_ref,
                      config: { incremental: true },
                    }),
                  });
                  const data = await resp.json();
                  if (data.id) router.push(`/scan/${data.id}`);
                } catch {
                  // ignore — user can navigate manually
                }
              }}
              className="inline-flex items-center gap-2 px-4 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-secondary hover:border-accent-primary hover:text-accent-primary transition-colors"
            >
              ↺ Re-scan (incremental)
            </button>
            <a
              href={`${apiBase}/api/v1/report/${id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-4 py-2 bg-bg-secondary border border-border rounded-lg text-sm text-text-secondary hover:border-accent-primary hover:text-accent-primary transition-colors"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Download PDF Report
            </a>
          </div>
        )}

        {/* Findings list */}
        {sortedFindings.length > 0 && (
          <div className="space-y-2">
            {sortedFindings.map((f: any) => (
              <Link
                key={f.id}
                href={`/scan/${id}/finding/${f.id}`}
                className="flex items-start justify-between p-4 bg-bg-secondary border border-border rounded-xl hover:border-accent-primary transition-colors group"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-3 mb-1">
                    <span className={`font-bold uppercase text-xs ${SEV_COLORS[f.severity] ?? ""}`}>
                      {f.severity}
                    </span>
                    <span className="font-code text-xs text-text-muted">{f.cwe_id}</span>
                    <span className="font-code text-xs text-text-muted">
                      {Math.round((f.confidence ?? 0) * 100)}% confidence
                    </span>
                  </div>
                  <p className="font-semibold text-sm text-text-primary">{f.title}</p>
                  <p className="text-xs text-text-muted mt-1 font-code">
                    {f.source_file?.split("/").pop()}:{f.source_line}
                    <span className="mx-1.5 text-text-muted">→</span>
                    {f.sink_file?.split("/").pop()}:{f.sink_line}
                  </p>
                </div>
                <span className="text-text-muted text-sm ml-4 group-hover:text-accent-primary flex-shrink-0">
                  →
                </span>
              </Link>
            ))}
          </div>
        )}

        {/* Waiting for results */}
        {isRunning && (
          <div className="text-center py-8 text-text-muted">
            <p className="text-sm">Findings will appear here when the scan completes.</p>
          </div>
        )}
      </div>
    </div>
  );
}
