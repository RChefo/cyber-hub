import type { ChecklistItem, ChecklistStatus, WstgCategory, WstgTest } from "@/lib/types";
import type { FindingDraft } from "./FindingsTab";

export const CHECKLIST_STATUS_OPTIONS: { id: ChecklistStatus; label: string }[] = [
  { id: "not_started", label: "Not started" },
  { id: "in_progress", label: "In progress" },
  { id: "passed", label: "Passed" },
  { id: "failed", label: "Failed" },
  { id: "not_applicable", label: "Not applicable" },
];

export interface CoverageSummary {
  total: number;
  done: number;
  passed: number;
  failed: number;
  notApplicable: number;
  inProgress: number;
}

/** Counts per status over the catalog (tests without a record count as not started). */
export function coverageOf(categories: WstgCategory[], byTest: Map<string, ChecklistItem>): CoverageSummary {
  const c: CoverageSummary = { total: 0, done: 0, passed: 0, failed: 0, notApplicable: 0, inProgress: 0 };
  for (const cat of categories) {
    for (const t of cat.tests) {
      c.total++;
      const s = byTest.get(t.id)?.status;
      if (s === "passed") c.passed++;
      else if (s === "failed") c.failed++;
      else if (s === "not_applicable") c.notApplicable++;
      else if (s === "in_progress") c.inProgress++;
    }
  }
  c.done = c.passed + c.failed + c.notApplicable;
  return c;
}

/** Categories with the tests that match the search (ID, name, objectives) and status; empty categories are dropped. */
export function filterCatalog(categories: WstgCategory[], byTest: Map<string, ChecklistItem>, query: string, status: string): WstgCategory[] {
  const q = query.trim().toLowerCase();
  return categories
    .map((c) => ({
      ...c,
      tests: c.tests.filter((t) => {
        const s = byTest.get(t.id)?.status ?? "not_started";
        if (status !== "all" && s !== status) return false;
        return !q || [t.id, t.name, c.name, ...t.objectives, byTest.get(t.id)?.note ?? ""].some((f) => f.toLowerCase().includes(q));
      }),
    }))
    .filter((c) => c.tests.length > 0);
}

/** A finding draft for a failed test: its name and objectives, with the test ID as a tag. */
export function findingDraftFor(t: WstgTest, category: string, note: string): FindingDraft {
  const objectives = t.objectives.length ? `\n\nTest objectives (${t.id}):\n${t.objectives.map((o) => `- ${o}`).join("\n")}` : "";
  return {
    title: t.name,
    severity: "medium",
    status: "new",
    category,
    confidence: "medium",
    description: `${note}${objectives}`.trim(),
    affectedTarget: "",
    cve: "",
    evidence: [{ label: "OWASP WSTG", reference: t.reference }],
    reproduction: "",
    technicalDetails: "",
    remediation: "",
    tags: ["wstg", t.id.toLowerCase()],
    assignee: "",
    dueDate: null,
    cvssVector: "",
    cvssScore: null,
  };
}
