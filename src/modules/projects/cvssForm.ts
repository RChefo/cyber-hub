import type { Severity } from "@/lib/types";

export type CvssVersion = "4.0" | "3.1";

export interface MetricDef {
  key: string;
  label: string;
  values: { id: string; label: string }[];
}

const CIA = [
  { id: "H", label: "High" },
  { id: "L", label: "Low" },
  { id: "N", label: "None" },
];

/** Base metrics shown in the calculator (plus Exploit Maturity for v4.0); other metrics can be typed into the vector. */
export const METRICS: Record<CvssVersion, MetricDef[]> = {
  "4.0": [
    { key: "AV", label: "Attack vector", values: [{ id: "N", label: "Network" }, { id: "A", label: "Adjacent" }, { id: "L", label: "Local" }, { id: "P", label: "Physical" }] },
    { key: "AC", label: "Attack complexity", values: [{ id: "L", label: "Low" }, { id: "H", label: "High" }] },
    { key: "AT", label: "Attack requirements", values: [{ id: "N", label: "None" }, { id: "P", label: "Present" }] },
    { key: "PR", label: "Privileges required", values: [{ id: "N", label: "None" }, { id: "L", label: "Low" }, { id: "H", label: "High" }] },
    { key: "UI", label: "User interaction", values: [{ id: "N", label: "None" }, { id: "P", label: "Passive" }, { id: "A", label: "Active" }] },
    { key: "VC", label: "Confidentiality (vulnerable system)", values: CIA },
    { key: "VI", label: "Integrity (vulnerable system)", values: CIA },
    { key: "VA", label: "Availability (vulnerable system)", values: CIA },
    { key: "SC", label: "Confidentiality (subsequent systems)", values: CIA },
    { key: "SI", label: "Integrity (subsequent systems)", values: CIA },
    { key: "SA", label: "Availability (subsequent systems)", values: CIA },
    { key: "E", label: "Exploit maturity", values: [{ id: "X", label: "Not defined" }, { id: "A", label: "Attacked" }, { id: "P", label: "Proof of concept" }, { id: "U", label: "Unreported" }] },
  ],
  "3.1": [
    { key: "AV", label: "Attack vector", values: [{ id: "N", label: "Network" }, { id: "A", label: "Adjacent" }, { id: "L", label: "Local" }, { id: "P", label: "Physical" }] },
    { key: "AC", label: "Attack complexity", values: [{ id: "L", label: "Low" }, { id: "H", label: "High" }] },
    { key: "PR", label: "Privileges required", values: [{ id: "N", label: "None" }, { id: "L", label: "Low" }, { id: "H", label: "High" }] },
    { key: "UI", label: "User interaction", values: [{ id: "N", label: "None" }, { id: "R", label: "Required" }] },
    { key: "S", label: "Scope", values: [{ id: "U", label: "Unchanged" }, { id: "C", label: "Changed" }] },
    { key: "C", label: "Confidentiality", values: CIA },
    { key: "I", label: "Integrity", values: CIA },
    { key: "A", label: "Availability", values: CIA },
  ],
};

/** The version of a vector by its prefix (3.0 is edited as 3.1). */
export function versionOf(vector: string): CvssVersion | null {
  const v = vector.trim();
  if (v.startsWith("CVSS:4.0/")) return "4.0";
  if (v.startsWith("CVSS:3.1/") || v.startsWith("CVSS:3.0/")) return "3.1";
  return null;
}

/** Metric → value of a vector (no validation; the backend validates). */
export function vectorParts(vector: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of vector.trim().split("/").slice(1)) {
    const i = part.indexOf(":");
    if (i > 0) out[part.slice(0, i)] = part.slice(i + 1);
  }
  return out;
}

/**
 * A vector from calculator selections. Metrics the calculator does not show (environmental,
 * supplemental) are kept from `previous` when it has the same version; "X" values are left out.
 */
export function buildVector(version: CvssVersion, selection: Record<string, string>, previous = ""): string {
  const shown = METRICS[version].map((m) => m.key);
  const parts = shown.filter((k) => selection[k] && selection[k] !== "X").map((k) => `${k}:${selection[k]}`);
  if (versionOf(previous) === version) {
    for (const [k, v] of Object.entries(vectorParts(previous))) {
      if (!shown.includes(k) && v !== "X") parts.push(`${k}:${v}`);
    }
  }
  return `CVSS:${version}/${parts.join("/")}`;
}

/** Defaults for a new calculation: the most common network-reachable case without impact chosen yet. */
export function defaultSelection(version: CvssVersion): Record<string, string> {
  return version === "4.0"
    ? { AV: "N", AC: "L", AT: "N", PR: "N", UI: "N", VC: "N", VI: "N", VA: "N", SC: "N", SI: "N", SA: "N", E: "X" }
    : { AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "N", I: "N", A: "N" };
}

/** The finding severity for a CVSS rating ("none" is informational). */
export function ratingSeverity(rating: string): Severity {
  return rating === "critical" || rating === "high" || rating === "medium" || rating === "low" ? rating : "info";
}
