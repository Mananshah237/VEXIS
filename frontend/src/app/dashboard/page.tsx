"use client";

import Link from "next/link";
import { useState } from "react";
import useSWR from "swr";

const fetcher = (url: string) => fetch(url).then((r) => r.json());

const SEV_COLORS: Record<string, string> = {
  critical: "text-severity-critical",
  high: "text-severity-high",
  medium: "text-severity-medium",
  low: "text-severity-low",
};

const STATUS_COLORS: Record<string, string> = {
  complete: "text-severity-safe",
  failed: "text-severity-critical",
  reasoning: "text-accent-primary",
  taint_analysis: "text-accent-primary",
  parsing: "text-accent-primary",
  queued: "text-text-muted",
};

const SEV_DOT: Record<string, string> = {
  critical: "bg-severity-critical",
  high: "bg-severity-high",
  medium: "bg-severity-medium",
  low: "bg-severity-low",
};

function relativeTime(isoStr: string) {
  const diff = Date.now() - new Date(isoStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

const PAGE_SIZE = 15;

export default function DashboardPage() {
  const apiBase = process.env.NEXT_PUBLIC_API_URL;

  const [page, setPage] = useState(1);
  const [statusFilter, setStatusFilter] = useState("");
  const [sevFilter, setSevFilter] = useState("");

  const { data: stats } = useSWR(`${apiBase}/api/v1/stats`, fetcher, { refreshInterval: 5000 });

  const params = new URLSearchParams({
    limit: String(PAGE_SIZE),
    page: String(page),
    ...(statusFilter ? { status: statusFilter } : {}),
    ...(sevFilter ? { min_severity: sevFilter } : {}),
  });
  const { data: history } = useSWR(
    `${apiBase}/api/v1/scans/recent?${params}`,
    fetcher,
    { refreshInterval: (data) => (data?.scans?.some((s: any) => !["complete", "failed"].includes(s.status)) ? 3000 : 0) }
  );

  const statCards = [
    { label: "Total Scans", value: stats?.total_scans ?? "—" },
    { label: "Total Findings", value: stats?.total_findings ?? "—" },
    { label: "Critical", value: stats?.by_severity?.critical ?? "—", color: "text-severity-critical" },
    { label: "High", value: stats?.by_severity?.high ?? "—", color: "text-severity-high" },
  ];

  const totalPages = history?.pages ?? 1;

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-display font-bold">Dashboard</h1>
            <p className="text-text-muted text-sm mt-1">Vulnerability discovery overview</p>
          </div>
          <Link
            href="/scan/new"
            className="px-5 py-2.5 bg-accent-primary text-bg-primary font-bold rounded-lg hover:opacity-90 transition-opacity text-sm"
          >
            + New Scan
          </Link>
        </div>

        {/* Stat cards */}
        <div className="grid grid-cols-4 gap-4 mb-8">
          {statCards.map(({ label, value, color }) => (
            <div key={label} className="bg-bg-secondary border border-border rounded-xl p-5">
              <p className="text-text-muted text-xs uppercase tracking-wider mb-2">{label}</p>
              <p className={`text-3xl font-bold font-code ${color ?? "text-text-primary"}`}>{value}</p>
            </div>
          ))}
        </div>

        {/* Severity breakdown */}
        {stats && (
          <div className="bg-bg-secondary border border-border rounded-xl p-5 mb-6">
            <p className="text-text-muted text-xs uppercase tracking-wider mb-3">Severity Breakdown</p>
            <div className="flex h-3 rounded-full overflow-hidden gap-0.5">
              {(["critical", "high", "medium", "low"] as const).map((sev) => {
                const count = stats.by_severity?.[sev] ?? 0;
                const total = stats.total_findings || 1;
                const pct = (count / total) * 100;
                const bgColors: Record<string, string> = {
                  critical: "bg-severity-critical",
                  high: "bg-severity-high",
                  medium: "bg-severity-medium",
                  low: "bg-severity-low",
                };
                return count > 0 ? (
                  <div key={sev} className={`${bgColors[sev]} rounded-sm`} style={{ width: `${pct}%` }} title={`${sev}: ${count}`} />
                ) : null;
              })}
              {stats.total_findings === 0 && <div className="bg-border w-full rounded-full" />}
            </div>
            <div className="flex gap-4 mt-2">
              {(["critical", "high", "medium", "low"] as const).map((sev) => {
                const count = stats.by_severity?.[sev] ?? 0;
                return (
                  <div key={sev} className="flex items-center gap-1.5 text-xs text-text-muted">
                    <span className={`w-2 h-2 rounded-full ${SEV_DOT[sev]}`} />
                    <span className="capitalize">{sev}</span>
                    <span className={`font-bold ${SEV_COLORS[sev]}`}>{count}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Scan history */}
        <div className="bg-bg-secondary border border-border rounded-xl p-6">
          {/* Header + filters */}
          <div className="flex items-center justify-between mb-4 gap-4 flex-wrap">
            <h2 className="font-display font-semibold">Scan History</h2>
            <div className="flex items-center gap-2">
              <select
                value={statusFilter}
                onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
                className="bg-bg-elevated border border-border rounded-lg px-3 py-1.5 text-xs text-text-secondary focus:outline-none focus:border-accent-primary"
              >
                <option value="">All statuses</option>
                <option value="complete">Complete</option>
                <option value="failed">Failed</option>
                <option value="queued">Queued</option>
              </select>
              <select
                value={sevFilter}
                onChange={(e) => { setSevFilter(e.target.value); setPage(1); }}
                className="bg-bg-elevated border border-border rounded-lg px-3 py-1.5 text-xs text-text-secondary focus:outline-none focus:border-accent-primary"
              >
                <option value="">All severities</option>
                <option value="critical">Critical+</option>
                <option value="high">High+</option>
                <option value="medium">Medium+</option>
                <option value="low">Low+</option>
              </select>
            </div>
          </div>

          {!history?.scans?.length ? (
            <div className="text-center py-12 text-text-muted">
              <p className="text-4xl mb-3">⬡</p>
              <p>{statusFilter || sevFilter ? "No scans match the current filters." : "No scans yet."}</p>
              {!statusFilter && !sevFilter && (
                <Link href="/scan/new" className="text-accent-primary text-sm hover:underline mt-2 inline-block">
                  Start your first scan →
                </Link>
              )}
            </div>
          ) : (
            <>
              <div className="space-y-2">
                {history.scans.map((scan: any) => (
                  <Link
                    key={scan.id}
                    href={`/scan/${scan.id}`}
                    className="flex items-center justify-between p-4 bg-bg-elevated border border-border rounded-lg hover:border-accent-primary transition-colors group"
                  >
                    <div className="flex items-center gap-4 min-w-0">
                      <div
                        className={`w-2 h-2 rounded-full flex-shrink-0 ${
                          scan.status === "complete"
                            ? "bg-severity-safe"
                            : scan.status === "failed"
                            ? "bg-severity-critical"
                            : "bg-accent-primary animate-pulse"
                        }`}
                      />
                      <div className="min-w-0">
                        <p className="font-code text-sm text-text-primary truncate">
                          {scan.source_type === "github_url"
                            ? scan.source_ref.replace("https://github.com/", "")
                            : scan.source_type === "raw_code"
                            ? "Raw code snippet"
                            : scan.source_ref}
                        </p>
                        <p className="text-xs text-text-muted mt-0.5">
                          {scan.stats?.files_parsed ?? 0} files · {relativeTime(scan.created_at)}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center gap-4 flex-shrink-0">
                      {scan.max_severity && (
                        <span className={`w-2 h-2 rounded-full ${SEV_DOT[scan.max_severity] ?? ""}`} title={`Max severity: ${scan.max_severity}`} />
                      )}
                      {scan.finding_count > 0 && (
                        <span className={`font-bold font-code text-sm ${SEV_COLORS[scan.max_severity] ?? "text-text-primary"}`}>
                          {scan.finding_count} finding{scan.finding_count !== 1 ? "s" : ""}
                        </span>
                      )}
                      <span className={`text-xs font-medium capitalize ${STATUS_COLORS[scan.status] ?? "text-text-muted"}`}>
                        {scan.status}
                      </span>
                      <span className="text-text-muted text-xs group-hover:text-accent-primary">→</span>
                    </div>
                  </Link>
                ))}
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <div className="flex items-center justify-between mt-4 pt-4 border-t border-border">
                  <span className="text-xs text-text-muted">
                    Page {page} of {totalPages} · {history.total} total
                  </span>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setPage((p) => Math.max(1, p - 1))}
                      disabled={page === 1}
                      className="px-3 py-1.5 text-xs bg-bg-elevated border border-border rounded-lg disabled:opacity-40 hover:border-accent-primary transition-colors"
                    >
                      ← Prev
                    </button>
                    <button
                      onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                      disabled={page === totalPages}
                      className="px-3 py-1.5 text-xs bg-bg-elevated border border-border rounded-lg disabled:opacity-40 hover:border-accent-primary transition-colors"
                    >
                      Next →
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
