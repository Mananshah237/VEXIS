"use client";

import { useParams } from "next/navigation";
import { useState } from "react";
import useSWR, { mutate as globalMutate } from "swr";
import Link from "next/link";
import { AttackFlowGraph } from "@/components/AttackFlowGraph";
import { useSession } from "next-auth/react";

const fetcher = (url: string) => fetch(url).then((r) => r.json());

export default function FindingDetailPage() {
  const { id, fid } = useParams<{ id: string; fid: string }>();
  const apiBase = process.env.NEXT_PUBLIC_API_URL;
  const { data: session } = useSession();
  const [generatingExploit, setGeneratingExploit] = useState(false);
  const [exploitCopied, setExploitCopied] = useState(false);

  const { data: finding, mutate: mutateFinding } = useSWR(
    `${apiBase}/api/v1/finding/${fid}`,
    fetcher
  );

  if (!finding) {
    return <div className="min-h-screen flex items-center justify-center text-text-muted">Loading...</div>;
  }

  const isDiscoveryFinding = finding.taint_path?.type === "business_logic_discovery";

  const handleGenerateExploit = async () => {
    setGeneratingExploit(true);
    try {
      await fetch(`${apiBase}/api/v1/finding/${fid}/exploit/generate`, { method: "POST" });
      await mutateFinding();
    } catch {
      // ignore
    } finally {
      setGeneratingExploit(false);
    }
  };

  const handleCopyExploit = async () => {
    if (!finding.exploit_script) return;
    await navigator.clipboard.writeText(finding.exploit_script);
    setExploitCopied(true);
    setTimeout(() => setExploitCopied(false), 2000);
  };

  const attackNodes = finding.attack_flow?.nodes ?? [];
  const attackEdges = finding.attack_flow?.edges ?? [];

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-5xl mx-auto space-y-6">
        <div className="flex items-start justify-between">
          <div>
            <Link href={`/scan/${id}`} className="text-text-muted text-sm hover:text-accent-primary">
              ← Back to scan
            </Link>
            <div className="flex items-center gap-3 mt-2">
              <h1 className="text-2xl font-display font-bold">{finding.title}</h1>
              {isDiscoveryFinding && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-[#7C4DFF]/15 text-[#7C4DFF] border border-[#7C4DFF]/30 flex-shrink-0">
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
                  </svg>
                  Discovered by AI
                </span>
              )}
            </div>
            <p className="text-text-muted mt-1">{finding.description}</p>
          </div>
        </div>

        <div className="grid grid-cols-4 gap-4">
          {[
            ["Severity", finding.severity?.toUpperCase(), null],
            ["CWE", finding.vuln_class === "chain" ? "CHAIN" : finding.cwe_id, (finding.vuln_class !== "chain" && finding.cwe_id) ? `https://cwe.mitre.org/data/definitions/${finding.cwe_id.replace("CWE-", "")}.html` : null],
            ["OWASP", finding.owasp_category ?? "—", null],
            ["Confidence", `${Math.round((finding.confidence ?? 0) * 100)}%`, null],
          ].map(([label, value, href]) => (
            <div key={label} className="bg-bg-secondary border border-border rounded-lg p-4">
              <p className="text-text-muted text-xs uppercase tracking-wider">{label}</p>
              {href ? (
                <a
                  href={href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-bold mt-1 font-code text-sm text-accent-primary hover:underline block"
                >
                  {value}
                </a>
              ) : (
                <p className="font-bold mt-1 font-code text-sm">{value}</p>
              )}
            </div>
          ))}
        </div>

        {attackNodes.length > 0 && (
          <div>
            <h2 className="font-display font-semibold mb-3">
              Attack Flow
              <span className="ml-2 text-text-muted text-sm font-normal">
                {attackNodes.length} nodes · {attackEdges.length} edges
              </span>
            </h2>
            <AttackFlowGraph nodes={attackNodes} edges={attackEdges} />
            <div className="flex gap-4 mt-2 text-xs text-text-muted">
              <span><span className="inline-block w-2 h-2 rounded-full bg-[#FF1744] mr-1" />source</span>
              <span><span className="inline-block w-2 h-2 rounded-full bg-[#FF6D00] mr-1" />sink</span>
              <span><span className="inline-block w-2 h-2 rounded-full bg-[#00E676] mr-1" />sanitizer</span>
              <span><span className="inline-block w-2 h-2 rounded-full bg-[#448AFF] mr-1" />transform</span>
            </div>
          </div>
        )}

        <div className="grid grid-cols-2 gap-4">
          <div className="bg-bg-secondary border border-border rounded-lg p-4">
            <p className="text-text-muted text-xs uppercase tracking-wider mb-2">Source</p>
            <p className="font-code text-sm">{finding.source_file}:{finding.source_line}</p>
            {finding.source_code && (
              <pre className="mt-2 text-xs bg-bg-elevated p-2 rounded overflow-x-auto text-severity-critical">
                {finding.source_code}
              </pre>
            )}
          </div>
          <div className="bg-bg-secondary border border-border rounded-lg p-4">
            <p className="text-text-muted text-xs uppercase tracking-wider mb-2">Sink</p>
            <p className="font-code text-sm">{finding.sink_file}:{finding.sink_line}</p>
            {finding.sink_code && (
              <pre className="mt-2 text-xs bg-bg-elevated p-2 rounded overflow-x-auto text-severity-high">
                {finding.sink_code}
              </pre>
            )}
          </div>
        </div>

        {finding.poc && (
          <div className="bg-bg-secondary border border-border rounded-lg p-6">
            <h2 className="font-display font-semibold mb-4">Proof of Concept</h2>
            <div className="space-y-3 text-sm">
              <div>
                <span className="text-text-muted">Attack Vector: </span>
                <span>{finding.poc.attack_vector}</span>
              </div>
              <div>
                <span className="text-text-muted">Payload: </span>
                <code className="font-code bg-bg-elevated px-2 py-0.5 rounded text-severity-critical">
                  {finding.poc.payload}
                </code>
              </div>
              {finding.poc.steps?.length > 0 && (
                <div>
                  <p className="text-text-muted mb-2">Steps:</p>
                  <ol className="space-y-1 list-decimal list-inside">
                    {finding.poc.steps.map((step: any, i: number) => (
                      <li key={i} className="text-text-secondary">{step.action}: {step.explanation}</li>
                    ))}
                  </ol>
                </div>
              )}
              <div>
                <span className="text-text-muted">Expected Outcome: </span>
                <span>{finding.poc.expected_outcome}</span>
              </div>
            </div>
          </div>
        )}

        {finding.llm_reasoning && (
          <div className="bg-bg-secondary border border-border rounded-lg p-6">
            <h2 className="font-display font-semibold mb-4">AI Reasoning</h2>
            <p className="text-text-secondary text-sm whitespace-pre-wrap font-code leading-relaxed">
              {finding.llm_reasoning}
            </p>
          </div>
        )}

        {finding.vuln_class === "chain" && finding.poc && (
          <div className="bg-bg-secondary border border-[#7C4DFF]/40 rounded-lg p-6">
            <h2 className="font-display font-semibold mb-1 text-[#7C4DFF]">Chain Analysis</h2>
            <p className="text-text-muted text-xs mb-4">{finding.poc.chain_description}</p>
            {finding.poc.attack_steps?.length > 0 && (
              <div className="mb-4">
                <p className="text-text-muted text-xs uppercase tracking-wider mb-2">Attack Steps</p>
                <ol className="space-y-1.5">
                  {finding.poc.attack_steps.map((step: any, i: number) => (
                    <li key={i} className="flex gap-3 text-sm">
                      <span className="text-[#7C4DFF] font-bold font-code w-5 flex-shrink-0">{step.order}.</span>
                      <span className="text-text-secondary">
                        <span className="font-semibold">{step.action}</span>
                        {step.target && <span className="text-text-muted font-code text-xs ml-2">{step.target}</span>}
                      </span>
                    </li>
                  ))}
                </ol>
              </div>
            )}
            {finding.poc.payload_sequence?.length > 0 && (
              <div>
                <p className="text-text-muted text-xs uppercase tracking-wider mb-2">Payload Sequence</p>
                <div className="space-y-2">
                  {finding.poc.payload_sequence.map((ps: any, i: number) => (
                    <div key={i} className="bg-bg-elevated rounded p-3">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[#7C4DFF] font-code text-xs font-bold">Step {ps.step}</span>
                        <span className="font-code text-xs text-severity-medium">{ps.method} {ps.path}</span>
                      </div>
                      <code className="font-code text-xs text-severity-critical">{ps.payload}</code>
                      {ps.purpose && <p className="text-text-muted text-xs mt-1">{ps.purpose}</p>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {finding.remediation && (
          <div className="bg-bg-secondary border border-border rounded-lg p-6">
            <h2 className="font-display font-semibold mb-4">Remediation</h2>
            <p className="text-text-secondary text-sm">{finding.remediation.summary}</p>
            {finding.remediation.code_fix && (
              <pre className="mt-3 text-xs bg-bg-elevated p-3 rounded overflow-x-auto text-severity-safe font-code">
                {finding.remediation.code_fix}
              </pre>
            )}
          </div>
        )}

        {/* Exploit Script */}
        {finding.vuln_class !== "chain" && finding.taint_path?.type !== "business_logic_discovery" && (
          <div className="bg-bg-secondary border border-severity-medium/30 rounded-lg p-6">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <h2 className="font-display font-semibold">Exploit Script</h2>
                <span className="text-xs text-severity-medium bg-severity-medium/10 px-2 py-0.5 rounded font-semibold">
                  ⚠ Authorized use only
                </span>
              </div>
              {finding.exploit_script ? (
                <div className="flex items-center gap-2">
                  <button
                    onClick={handleCopyExploit}
                    className="text-xs px-3 py-1.5 border border-border rounded-lg text-text-secondary hover:border-accent-primary hover:text-accent-primary transition-colors"
                  >
                    {exploitCopied ? "Copied!" : "Copy"}
                  </button>
                  <a
                    href={`${apiBase}/api/v1/finding/${fid}/exploit${(session as any)?.accessToken ? `?token=${(session as any).accessToken}` : ""}`}
                    download={`exploit_${fid.slice(0, 8)}.py`}
                    className="text-xs px-3 py-1.5 border border-border rounded-lg text-text-secondary hover:border-accent-primary hover:text-accent-primary transition-colors"
                  >
                    Download .py
                  </a>
                </div>
              ) : (
                <button
                  onClick={handleGenerateExploit}
                  disabled={generatingExploit}
                  className="text-xs px-3 py-1.5 border border-accent-primary/50 rounded-lg text-accent-primary hover:bg-accent-primary/10 transition-colors disabled:opacity-50"
                >
                  {generatingExploit ? "Generating..." : "Generate Exploit Script"}
                </button>
              )}
            </div>
            {finding.exploit_script ? (
              <pre className="text-xs bg-bg-elevated p-4 rounded-lg overflow-x-auto text-[#A8FF78] font-code leading-relaxed max-h-96 overflow-y-auto">
                {finding.exploit_script}
              </pre>
            ) : (
              <p className="text-text-muted text-sm">
                No exploit script generated yet. Click &quot;Generate Exploit Script&quot; to create a runnable PoC.
              </p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
