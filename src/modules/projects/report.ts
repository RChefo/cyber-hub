import type { Finding, Severity } from "@/lib/types";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.updatedAt.localeCompare(a.updatedAt),
  );
}

export function countBySeverity(findings: Finding[], onlyActive = false): Record<Severity, number> {
  const out: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (onlyActive && (f.status === "resolved" || f.status === "false_positive")) continue;
    out[f.severity]++;
  }
  return out;
}

// The Markdown assessment report is generated in Rust (commands/projects.rs `markdown_report`),
// shared by Projects → Export report and the MCP `cyberhub_generate_report` tool.
