"use client";

import { useParams, useRouter } from "next/navigation";
import { useState } from "react";
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
  const [activeTab, setActiveTab] = useState<"findings" | "semgrep">("findings");
  const [expandedExploits, setExpandedExploits] = useState<Set<string>>(new Set());
  const [copiedExploit, setCopiedExploit] = useState<string | null>(null);

  function toggleExploit(id: string, e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    setExpandedExploits((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  async function copyExploit(id: string, script: string, e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    await navigator.clipboard.writeText(script);
    setCopiedExploit(id);
    setTimeout(() => setCopiedExploit(null), 2000);
  }

  const { data: scan, mutate: mutateScan } = useSWR(
    `${apiBase}/api/v1/scan/${id}`,
    fetcher,
    { refreshInterval: (data) => (data?.status === "complete" || data?.status === "failed" ? 0 : 2000) }
  );
  const { data: findingsData } = useSWR(
    scan?.status === "complete" ? `${apiBase}/api/v1/scan/${id}/findings` : null,
    fetcher
  );
  const { data: diffData, isLoading: diffLoading } = useSWR(
    activeTab === "semgrep" && scan?.status === "complete"
      ? `${apiBase}/api/v1/scan/${id}/differential`
      : null,
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

        {/* Tabs */}
        {!isRunning && scan?.status === "complete" && (
          <div className="flex gap-1 mb-4 border-b border-border">
            <button
              onClick={() => setActiveTab("findings")}
              className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px ${
                activeTab === "findings"
                  ? "border-accent-primary text-accent-primary"
                  : "border-transparent text-text-muted hover:text-text-secondary"
              }`}
            >
              Findings{totalFindings > 0 ? ` (${totalFindings})` : ""}
            </button>
            <button
              onClick={() => setActiveTab("semgrep")}
              className={`px-4 py-2 text-sm font-medium transition-colors border-b-2 -mb-px flex items-center gap-1.5 ${
                activeTab === "semgrep"
                  ? "border-accent-primary text-accent-primary"
                  : "border-transparent text-text-muted hover:text-text-secondary"
              }`}
            >
              <span>VEXIS vs Semgrep</span>
              {scan.stats?.semgrep_summary && (
                <span className="text-xs bg-accent-primary/15 text-accent-primary px-1.5 py-0.5 rounded-full">
                  {scan.stats.semgrep_summary.vexis_only}↑
                </span>
              )}
            </button>
          </div>
        )}

        {/* Findings list */}
        {activeTab === "findings" && sortedFindings.length > 0 && (
          <div className="space-y-2">
            {sortedFindings.map((f: any) => {
              const isDiscovery = f.taint_path?.type === "business_logic_discovery";
              const hasExploit = !!f.exploit_script;
              const exploitExpanded = expandedExploits.has(f.id);
              return (
                <div
                  key={f.id}
                  className={`bg-bg-secondary border rounded-xl transition-colors ${
                    isDiscovery ? "border-[#7C4DFF]/30" : "border-border"
                  } ${exploitExpanded ? "" : "hover:border-accent-primary"}`}
                >
                  {/* Main clickable row */}
                  <Link
                    href={`/scan/${id}/finding/${f.id}`}
                    className="flex items-start justify-between p-4 group"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-3 mb-1 flex-wrap">
                        <span className={`font-bold uppercase text-xs ${SEV_COLORS[f.severity] ?? ""}`}>
                          {f.severity}
                        </span>
                        <span className="font-code text-xs text-text-muted">{f.cwe_id}</span>
                        <span className="font-code text-xs text-text-muted">
                          {Math.round((f.confidence ?? 0) * 100)}% confidence
                        </span>
                        {isDiscovery && (
                          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-xs font-semibold bg-[#7C4DFF]/15 text-[#7C4DFF] border border-[#7C4DFF]/30">
                            ✦ Discovered by AI
                          </span>
                        )}
                        {hasExploit && (
                          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-xs font-semibold bg-severity-critical/10 text-severity-critical border border-severity-critical/25">
                            ⚡ Exploit
                          </span>
                        )}
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

                  {/* Exploit script section */}
                  {hasExploit && (
                    <div className="border-t border-border">
                      <button
                        onClick={(e) => toggleExploit(f.id, e)}
                        className="w-full flex items-center justify-between px-4 py-2 text-xs text-text-muted hover:text-severity-critical transition-colors"
                      >
                        <span className="flex items-center gap-1.5">
                          <span>⚡</span>
                          <span className="font-semibold">Exploit Script</span>
                          <span className="text-text-muted/60">— runnable PoC</span>
                        </span>
                        <span className="font-code">{exploitExpanded ? "▴ hide" : "▾ show"}</span>
                      </button>

                      {exploitExpanded && (
                        <div className="px-4 pb-4">
                          <div className="relative rounded-lg bg-[#0d0d0d] border border-border overflow-hidden">
                            {/* Toolbar */}
                            <div className="flex items-center justify-between px-3 py-1.5 border-b border-border/60 bg-bg-primary/40">
                              <span className="font-code text-xs text-text-muted">exploit_{f.id.slice(0, 8)}.py</span>
                              <div className="flex items-center gap-2">
                                <button
                                  onClick={(e) => copyExploit(f.id, f.exploit_script, e)}
                                  className="text-xs text-text-muted hover:text-text-primary transition-colors px-2 py-0.5 rounded border border-border/50 hover:border-border"
                                >
                                  {copiedExploit === f.id ? "✓ Copied" : "Copy"}
                                </button>
                                <a
                                  href={`${apiBase}/api/v1/finding/${f.id}/exploit`}
                                  download={`exploit_${f.id.slice(0, 8)}.py`}
                                  onClick={(e) => e.stopPropagation()}
                                  className="text-xs text-text-muted hover:text-text-primary transition-colors px-2 py-0.5 rounded border border-border/50 hover:border-border"
                                >
                                  Download
                                </a>
                              </div>
                            </div>
                            {/* Code */}
                            <pre className="font-code text-xs text-text-secondary p-4 overflow-x-auto max-h-72 leading-relaxed whitespace-pre">
                              {f.exploit_script}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* Semgrep differential tab */}
        {activeTab === "semgrep" && (
          <div>
            {diffLoading && (
              <div className="text-center py-8 text-text-muted text-sm">Running Semgrep analysis...</div>
            )}
            {diffData && !diffLoading && (
              <div className="space-y-4">
                {!diffData.semgrep_available && (
                  <div className="bg-bg-secondary border border-severity-medium/30 rounded-xl p-4 text-sm text-severity-medium">
                    {diffData.semgrep_error ?? "Semgrep is not available for this scan."}
                  </div>
                )}
                {/* Summary bar */}
                {diffData.summary && (
                  <div className="grid grid-cols-3 gap-3">
                    {[
                      { label: "VEXIS Only", value: diffData.summary.vexis_only, color: "text-accent-primary", desc: "Found by VEXIS, missed by Semgrep" },
                      { label: "Overlap", value: diffData.summary.overlap, color: "text-severity-safe", desc: "Both tools found these" },
                      { label: "Semgrep Only", value: diffData.summary.semgrep_only, color: "text-severity-medium", desc: "Found by Semgrep, missed by VEXIS" },
                    ].map(({ label, value, color, desc }) => (
                      <div key={label} className="bg-bg-secondary border border-border rounded-xl p-4 text-center">
                        <p className={`text-3xl font-bold font-code ${color}`}>{value}</p>
                        <p className="text-text-secondary font-semibold text-sm mt-1">{label}</p>
                        <p className="text-text-muted text-xs mt-0.5">{desc}</p>
                      </div>
                    ))}
                  </div>
                )}

                {/* VEXIS-only findings */}
                {diffData.vexis_only?.length > 0 && (
                  <div>
                    <h3 className="text-sm font-semibold text-text-secondary mb-2 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-accent-primary inline-block" />
                      VEXIS-Only Findings
                      <span className="text-text-muted font-normal">({diffData.vexis_only.length}) — deeper taint analysis found these</span>
                    </h3>
                    <div className="space-y-2">
                      {diffData.vexis_only.map((f: any, i: number) => (
                        <div key={i} className="bg-bg-secondary border border-accent-primary/20 rounded-lg p-3 text-sm">
                          <div className="flex items-center gap-2 mb-1">
                            <span className={`font-bold uppercase text-xs ${SEV_COLORS[f.severity] ?? ""}`}>{f.severity}</span>
                            <span className="font-code text-xs text-text-muted">{f.vuln_class}</span>
                          </div>
                          <p className="font-semibold text-text-primary">{f.title}</p>
                          <p className="font-code text-xs text-text-muted mt-1">
                            {f.file?.split("/").pop()}:{f.line}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Semgrep-only findings */}
                {diffData.semgrep_only?.length > 0 && (
                  <div>
                    <h3 className="text-sm font-semibold text-text-secondary mb-2 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-severity-medium inline-block" />
                      Semgrep-Only Findings
                      <span className="text-text-muted font-normal">({diffData.semgrep_only.length}) — consider adding taint sources/sinks</span>
                    </h3>
                    <div className="space-y-2">
                      {diffData.semgrep_only.map((f: any, i: number) => (
                        <div key={i} className="bg-bg-secondary border border-severity-medium/20 rounded-lg p-3 text-sm">
                          <div className="flex items-center gap-2 mb-1">
                            <span className={`font-bold uppercase text-xs ${SEV_COLORS[f.severity] ?? SEV_COLORS.medium}`}>{f.severity}</span>
                            <span className="font-code text-xs text-text-muted">{f.rule_id?.split(".").pop()}</span>
                            {f.cwe && <span className="font-code text-xs text-text-muted">{f.cwe}</span>}
                          </div>
                          <p className="text-text-secondary">{f.message}</p>
                          <p className="font-code text-xs text-text-muted mt-1">
                            {f.file?.split("/").pop()}:{f.line}
                          </p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Overlap */}
                {diffData.overlap?.length > 0 && (
                  <div>
                    <h3 className="text-sm font-semibold text-text-secondary mb-2 flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-severity-safe inline-block" />
                      Confirmed by Both Tools
                      <span className="text-text-muted font-normal">({diffData.overlap.length})</span>
                    </h3>
                    <div className="space-y-2">
                      {diffData.overlap.map((o: any, i: number) => (
                        <div key={i} className="bg-bg-secondary border border-severity-safe/20 rounded-lg p-3 text-sm">
                          <div className="flex items-center justify-between gap-4">
                            <div>
                              <p className="font-semibold text-text-primary">{o.vexis?.title}</p>
                              <p className="font-code text-xs text-text-muted mt-0.5">
                                VEXIS: {o.vexis?.file?.split("/").pop()}:{o.vexis?.line}
                              </p>
                            </div>
                            <div className="text-right">
                              <p className="font-code text-xs text-severity-medium">{o.semgrep?.rule_id?.split(".").pop()}</p>
                              <p className="font-code text-xs text-text-muted">
                                Semgrep: {o.semgrep?.file?.split("/").pop()}:{o.semgrep?.line}
                              </p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {diffData.summary?.vexis_total === 0 && diffData.summary?.semgrep_total === 0 && (
                  <div className="text-center py-8 text-text-muted text-sm">
                    No findings from either tool to compare.
                  </div>
                )}
              </div>
            )}
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
