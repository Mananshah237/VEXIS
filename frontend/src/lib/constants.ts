export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITY_ORDER)[number];

export const VULN_CLASS_LABELS: Record<string, string> = {
  sqli: "SQL Injection",
  cmdi: "Command Injection",
  path_traversal: "Path Traversal",
  ssti: "Template Injection",
  ssrf: "SSRF",
  xss: "XSS",
};
