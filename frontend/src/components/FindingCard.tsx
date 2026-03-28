import Link from "next/link";
import { SeverityBadge } from "./SeverityBadge";

interface Finding {
  id: string;
  scan_id: string;
  title: string;
  severity: string;
  confidence: number;
  vuln_class: string;
  cwe_id: string | null;
  source_file: string;
  source_line: number;
  triage_status: string;
}

interface Props {
  finding: Finding;
}

export function FindingCard({ finding }: Props) {
  return (
    <Link
      href={`/scan/${finding.scan_id}/finding/${finding.id}`}
      className="block bg-bg-secondary border border-border rounded-lg p-4 hover:border-accent-primary transition-colors"
    >
      <div className="flex justify-between items-start gap-4">
        <div className="min-w-0">
          <p className="font-semibold truncate">{finding.title}</p>
          <p className="text-text-muted text-sm mt-1 font-code truncate">
            {finding.source_file}:{finding.source_line}
          </p>
          {finding.cwe_id && (
            <p className="text-text-muted text-xs mt-1">{finding.cwe_id}</p>
          )}
        </div>
        <div className="flex flex-col items-end gap-2 flex-shrink-0">
          <SeverityBadge severity={finding.severity} />
          <span className="text-xs text-text-muted">
            {Math.round(finding.confidence * 100)}% confidence
          </span>
        </div>
      </div>
    </Link>
  );
}
