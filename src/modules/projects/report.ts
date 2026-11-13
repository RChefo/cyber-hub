// SPDX-License-Identifier: Apache-2.0
import { isOpenFinding } from "@/lib/findings";
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
    if (onlyActive && !isOpenFinding(f.status)) continue;
    out[f.severity]++;
  }
  return out;
}

// The Markdown assessment report is generated in Rust (commands/projects.rs `markdown_report`),
// shared by Projects → Export report and the MCP `cyberhub_generate_report` tool.

/** Tags from a comma-separated text: trimmed, deduplicated, at most 20 of up to 40 characters. */
export function parseTags(text: string): string[] {
  const out: string[] = [];
  for (const t of text.split(",").map((x) => x.trim()).filter(Boolean)) if (!out.includes(t) && t.length <= 40) out.push(t);
  return out.slice(0, 20);
}

export function tagsOf(findings: Finding[]): string[] {
  return [...new Set(findings.flatMap((f) => f.tags))].sort((a, b) => a.localeCompare(b));
}

export function filterFindings(findings: Finding[], f: { severity: string; status: string; query: string; tag: string }): Finding[] {
  const q = f.query.trim().toLowerCase();
  return findings.filter(
    (x) =>
      (f.severity === "all" || x.severity === f.severity) &&
      (f.status === "all" || x.status === f.status) &&
      (f.tag === "all" || x.tags.includes(f.tag)) &&
      (!q || [x.title, x.affectedTarget, x.cve, x.category, x.assignee, x.description].some((v) => v.toLowerCase().includes(q))),
  );
}
