import { severityFromCvss } from "@/components/ui/Badges";
import type { CveRecord, CvssScore, Severity } from "@/lib/types";

const VERSION_RANK: Record<string, number> = { "4.0": 4, "3.1": 3, "3.0": 2, "2.0": 1 };

/** Prefer the newest CVSS version; within a version prefer the Primary (NVD) score, then the highest. */
export function bestCvss(record: Pick<CveRecord, "cvss">): CvssScore | null {
  if (!record.cvss.length) return null;
  return [...record.cvss].sort((a, b) => {
    const v = (VERSION_RANK[b.version] ?? 0) - (VERSION_RANK[a.version] ?? 0);
    if (v) return v;
    const p = Number(b.source.includes("Primary")) - Number(a.source.includes("Primary"));
    if (p) return p;
    return b.score - a.score;
  })[0];
}

export function severityOf(score: CvssScore | null): Severity {
  if (!score) return "info";
  const s = score.severity.toLowerCase();
  if (s === "critical" || s === "high" || s === "medium" || s === "low") return s;
  // CVSS v2 records have no severity string: derive it with the shared thresholds
  return severityFromCvss(score.score);
}

const METRICS_V3: Record<string, { name: string; values: Record<string, string> }> = {
  AV: { name: "Attack vector", values: { N: "Network", A: "Adjacent", L: "Local", P: "Physical" } },
  AC: { name: "Attack complexity", values: { L: "Low", H: "High" } },
  PR: { name: "Privileges required", values: { N: "None", L: "Low", H: "High" } },
  UI: { name: "User interaction", values: { N: "None", R: "Required" } },
  S: { name: "Scope", values: { U: "Unchanged", C: "Changed" } },
  C: { name: "Confidentiality", values: { N: "None", L: "Low", H: "High" } },
  I: { name: "Integrity", values: { N: "None", L: "Low", H: "High" } },
  A: { name: "Availability", values: { N: "None", L: "Low", H: "High" } },
};

const METRICS_V4: Record<string, { name: string; values: Record<string, string> }> = {
  AV: METRICS_V3.AV,
  AC: METRICS_V3.AC,
  AT: { name: "Attack requirements", values: { N: "None", P: "Present" } },
  PR: METRICS_V3.PR,
  UI: { name: "User interaction", values: { N: "None", P: "Passive", A: "Active" } },
  VC: { name: "Vulnerable system confidentiality", values: { N: "None", L: "Low", H: "High" } },
  VI: { name: "Vulnerable system integrity", values: { N: "None", L: "Low", H: "High" } },
  VA: { name: "Vulnerable system availability", values: { N: "None", L: "Low", H: "High" } },
  SC: { name: "Subsequent system confidentiality", values: { N: "None", L: "Low", H: "High" } },
  SI: { name: "Subsequent system integrity", values: { N: "None", L: "Low", H: "High" } },
  SA: { name: "Subsequent system availability", values: { N: "None", L: "Low", H: "High" } },
};

export interface VectorPart {
  key: string;
  name: string;
  value: string;
  label: string;
}

/**
 * Parses CVSS 3.x and 4.0 base vectors into labelled parts. Unknown metrics are kept
 * with their raw value; returns [] for unparseable input (e.g. CVSS 2.0 vectors).
 */
export function parseVector(vector: string): VectorPart[] {
  const parts = vector.trim().split("/");
  const head = parts[0] ?? "";
  let table: typeof METRICS_V3;
  if (/^CVSS:3\.[01]$/.test(head)) table = METRICS_V3;
  else if (head === "CVSS:4.0") table = METRICS_V4;
  else return [];
  const out: VectorPart[] = [];
  for (const p of parts.slice(1)) {
    const [k, v] = p.split(":");
    if (!k || v === undefined) continue;
    const def = table[k];
    if (!def) continue; // threat/environmental/supplemental metrics are not shown in the base breakdown
    out.push({ key: k, name: def.name, value: v, label: def.values[v] ?? v });
  }
  return out;
}

export function nvdUrl(id: string): string {
  return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`;
}

export function isCveId(q: string): boolean {
  return /^CVE-\d{4}-\d{4,}$/i.test(q.trim());
}
