import type { AsvsItem, AsvsStatus, AsvsSummary } from "@/lib/types";

/** Status labels and tones; "compliant" is only ever the analyst's call. */
export const ASVS_STATUS: Record<AsvsStatus, { label: string; tone: "default" | "success" | "danger" | "warning" | "accent" }> = {
  not_assessed: { label: "Not assessed", tone: "default" },
  compliant: { label: "Compliant", tone: "success" },
  non_compliant: { label: "Non-compliant", tone: "danger" },
  needs_review: { label: "Needs review", tone: "warning" },
  not_applicable: { label: "Not applicable", tone: "accent" },
};

/** Frameworks an analyst can map a requirement to (`asvs_mappings.framework`). */
export const ASVS_FRAMEWORKS = [
  { id: "wstg", label: "OWASP WSTG" },
  { id: "api_top10", label: "OWASP API Top 10" },
  { id: "cwe", label: "CWE" },
  { id: "attack", label: "MITRE ATT&CK" },
  { id: "nist_800_53", label: "NIST SP 800-53" },
  { id: "other", label: "Other" },
];

/** Assessed share, in percent, of the requirements of the level. */
export function progress(s: Pick<AsvsSummary, "counts">): number {
  return s.counts.total ? Math.round((100 * (s.counts.total - s.counts.notAssessed)) / s.counts.total) : 0;
}

/** Requirements matching the search text (id, text or note), the status and the level filter. */
export function filterItems(items: AsvsItem[], f: { text: string; status: string; beyond: boolean }): AsvsItem[] {
  const q = f.text.trim().toLowerCase();
  return items.filter(
    (i) =>
      (f.beyond || i.inLevel) &&
      (f.status === "all" || i.status === f.status) &&
      (!q || i.requirement.id.toLowerCase().includes(q) || i.requirement.text.toLowerCase().includes(q) || i.note.toLowerCase().includes(q)),
  );
}
