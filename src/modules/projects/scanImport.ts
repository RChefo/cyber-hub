// SPDX-License-Identifier: Apache-2.0
import type { Tone } from "@/components/ui/Badges";
import type { CsvInfo, CsvMapping, ScanImportOptions, ScanImportOutcome, ScanImportPreview } from "@/lib/types";

export const OUTCOME_META: Record<ScanImportOutcome, { label: string; tone: Tone }> = {
  new: { label: "New", tone: "accent" },
  seen_again: { label: "Already recorded", tone: "default" },
  recurring: { label: "Resolved, reported again", tone: "warning" },
  dismissed: { label: "Dismissed earlier", tone: "default" },
  out_of_scope: { label: "Outside the scope", tone: "danger" },
  info: { label: "Informational", tone: "default" },
};

/** How many findings an import would create with these options. */
export function importCount(p: ScanImportPreview, o: ScanImportOptions): number {
  return p.counts.new + (o.includeInfo ? p.counts.info : 0);
}

/** Findings of the file that are already in the project (in any state). */
export function knownCount(p: ScanImportPreview): number {
  return p.counts.seenAgain + p.counts.recurring + p.counts.dismissed;
}

/** True when importing would change nothing: no new findings, no sightings, no assets, nothing no longer reported. */
export function nothingToImport(p: ScanImportPreview, o: ScanImportOptions): boolean {
  return importCount(p, o) === 0 && knownCount(p) === 0 && p.assets === 0 && p.notReportedCount === 0;
}

/** Fields of a CSV import, in the order the mapping step shows them. */
export const CSV_FIELDS: { key: keyof CsvMapping; label: string }[] = [
  { key: "title", label: "Title" },
  { key: "severity", label: "Severity" },
  { key: "target", label: "Target (host, IP or URL)" },
  { key: "port", label: "Port" },
  { key: "description", label: "Description" },
  { key: "remediation", label: "Remediation" },
  { key: "cve", label: "CVE" },
  { key: "cvss", label: "CVSS vector or score" },
  { key: "ruleId", label: "Rule or plugin ID" },
  { key: "references", label: "References" },
  { key: "details", label: "Technical details" },
];

/** Select options for a CSV field: "not used" and every column with its first value. */
export function columnOptions(info: CsvInfo): { id: string; label: string }[] {
  return [
    { id: "none", label: "Not used" },
    ...info.headers.map((h, i) => {
      const sample = info.sample.find((row) => (row[i] ?? "").trim() !== "")?.[i]?.trim() ?? "";
      const name = h.trim() || `Column ${i + 1}`;
      return { id: String(i), label: sample ? `${name} (${sample.length > 40 ? `${sample.slice(0, 40)}…` : sample})` : name };
    }),
  ];
}

/** The mapping with one field set to a column (or not used). */
export function withColumn(m: CsvMapping, key: keyof CsvMapping, id: string): CsvMapping {
  return { ...m, [key]: id === "none" ? null : Number(id) };
}

/** How the severity column was read, in words. */
export function severityScaleText(scale: CsvInfo["severityScale"]): string | null {
  switch (scale) {
    case "levels":
      return "Severity is read as levels 1 to 5, as Qualys uses them: 5 is critical, 1 informational.";
    case "scores":
      return "Severity is read as CVSS scores: 9.0 and above is critical, 7.0 high, 4.0 medium, above 0 low.";
    case "words":
      return "Severity is read as words (critical, high, medium, low, info and common synonyms).";
    default:
      return null;
  }
}

/** The outcome shown for one item: an informational item becomes new once informational findings are included. */
export function shownOutcome(outcome: ScanImportOutcome, o: ScanImportOptions): ScanImportOutcome {
  return outcome === "info" && o.includeInfo ? "new" : outcome;
}
