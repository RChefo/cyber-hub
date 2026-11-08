import type { Evidence, FindingTemplate, FindingTemplateInput, Severity } from "@/lib/types";

export const SEVERITY_CHOICES: { id: Severity; label: string }[] = [
  { id: "critical", label: "Critical" },
  { id: "high", label: "High" },
  { id: "medium", label: "Medium" },
  { id: "low", label: "Low" },
  { id: "info", label: "Info" },
];

/** Formats an import rule can name (the scan importer's formats). */
export const RULE_FORMATS = ["nmap", "nuclei", "nessus", "burp", "zap", "sarif"] as const;

/** Non-empty, trimmed lines of a text area. */
export function lines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
}

/** Why an import rule line is not valid, or null. Mirrors the backend's check. */
export function ruleProblem(rule: string): string | null {
  const i = rule.indexOf(":");
  if (i <= 0) return `“${rule}” is not format:rule`;
  const format = rule.slice(0, i).trim().toLowerCase();
  const id = rule.slice(i + 1).trim();
  if (!(RULE_FORMATS as readonly string[]).includes(format)) return `“${format}” is not an import format`;
  if (!id || /\s/.test(id) || id.length > 200) return `The rule in “${rule}” must be 1–200 characters without spaces`;
  return null;
}

/** Case-insensitive search over the fields people remember a template by. */
export function matchesTemplate(t: FindingTemplate, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [t.title, t.category, t.description, ...t.tags, ...t.rules].some((f) => f.toLowerCase().includes(q));
}

export const EMPTY_TEMPLATE: FindingTemplateInput = { title: "", severity: "medium", category: "", description: "", remediation: "", references: [], tags: [], rules: [] };

/** The editable part of a template. */
export function templateInput(t: FindingTemplate): FindingTemplateInput {
  return { id: t.id, title: t.title, severity: t.severity, category: t.category, description: t.description, remediation: t.remediation, references: [...t.references], tags: [...t.tags], rules: [...t.rules] };
}

interface FindingFields {
  title: string;
  severity: Severity;
  category: string;
  description: string;
  remediation: string;
  evidence: Evidence[];
  tags: string[];
}

/** A new template from a finding's write-up. References become URLs only; the instance details stay with the finding. */
export function templateFromFinding(f: FindingFields): FindingTemplateInput {
  const references = f.evidence.map((e) => e.reference.trim()).filter((r) => /^https?:\/\//i.test(r));
  return { title: f.title.trim(), severity: f.severity, category: f.category, description: f.description, remediation: f.remediation, references: [...new Set(references)].slice(0, 30), tags: f.tags.slice(0, 20), rules: [] };
}

/**
 * Fills a finding from a template. Fields the template leaves empty keep what the finding has;
 * references are added once each and tags merged.
 */
export function applyTemplate<T extends FindingFields>(f: T, t: FindingTemplate): T {
  const evidence = [...f.evidence];
  for (const r of t.references) {
    if (!evidence.some((e) => e.reference === r) && evidence.length < 50) evidence.push({ label: "Reference", reference: r });
  }
  return {
    ...f,
    title: t.title,
    severity: t.severity,
    category: t.category || f.category,
    description: t.description || f.description,
    remediation: t.remediation || f.remediation,
    evidence,
    tags: [...new Set([...f.tags, ...t.tags])].slice(0, 20),
  };
}
