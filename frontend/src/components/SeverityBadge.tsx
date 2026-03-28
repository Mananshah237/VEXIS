import { clsx } from "clsx";

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-severity-critical/10 text-severity-critical border-severity-critical/30",
  high: "bg-severity-high/10 text-severity-high border-severity-high/30",
  medium: "bg-severity-medium/10 text-severity-medium border-severity-medium/30",
  low: "bg-severity-low/10 text-severity-low border-severity-low/30",
  info: "bg-severity-info/10 text-severity-info border-severity-info/30",
};

interface Props {
  severity: string;
}

export function SeverityBadge({ severity }: Props) {
  return (
    <span
      className={clsx(
        "inline-flex items-center px-2 py-0.5 rounded border text-xs font-bold uppercase tracking-wider",
        SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info
      )}
    >
      {severity}
    </span>
  );
}
