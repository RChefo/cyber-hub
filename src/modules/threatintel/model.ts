import type { TiLevel, TiProviderResult, TiStatus, TiSummary, VtKind } from "@/lib/types";

export type Tone = "default" | "accent" | "success" | "warning" | "danger";

export const LEVEL_META: Record<TiLevel, { tone: Tone; label: string }> = {
  malicious: { tone: "danger", label: "Malicious" },
  suspicious: { tone: "warning", label: "Suspicious" },
  clean: { tone: "success", label: "Benign" },
  info: { tone: "accent", label: "Informational" },
  unknown: { tone: "default", label: "No verdict" },
};

export const STATUS_META: Record<TiStatus, { tone: Tone; label: string }> = {
  found: { tone: "accent", label: "Has data" },
  not_found: { tone: "default", label: "No record" },
  unsupported: { tone: "default", label: "Not applicable" },
  no_key: { tone: "warning", label: "No key" },
  disabled: { tone: "default", label: "Turned off" },
  rate_limited: { tone: "warning", label: "Rate limited" },
  error: { tone: "danger", label: "Failed" },
};

const LEVEL_ORDER: TiLevel[] = ["malicious", "suspicious", "info", "unknown", "clean"];
const STATUS_ORDER: TiStatus[] = ["found", "not_found", "rate_limited", "error", "no_key", "disabled", "unsupported"];

/** Providers with data first (most severe verdict first), then the rest by status. */
export function sortResults(results: TiProviderResult[]): TiProviderResult[] {
  const rank = (r: TiProviderResult) => {
    const s = STATUS_ORDER.indexOf(r.status) * 10;
    const lvl = r.report?.verdict ? LEVEL_ORDER.indexOf(r.report.verdict.level) : 9;
    return r.status === "found" ? lvl : s + 10;
  };
  return [...results].sort((a, b) => rank(a) - rank(b));
}

export interface SummaryPart {
  key: keyof TiSummary;
  label: string;
  tone: Tone;
  providers: string[];
}

/** Which providers said what. A list of names per outcome, never a combined score. */
export function summaryParts(s: TiSummary): SummaryPart[] {
  const parts: SummaryPart[] = [
    { key: "malicious", label: "Malicious", tone: "danger", providers: s.malicious },
    { key: "suspicious", label: "Suspicious", tone: "warning", providers: s.suspicious },
    { key: "informational", label: "Informational", tone: "accent", providers: s.informational },
    { key: "noVerdict", label: "Data, no verdict", tone: "default", providers: s.noVerdict },
    { key: "clean", label: "Benign", tone: "success", providers: s.clean },
    { key: "noRecord", label: "No record", tone: "default", providers: s.noRecord },
    { key: "failed", label: "Failed", tone: "danger", providers: s.failed },
    { key: "skipped", label: "Not run", tone: "default", providers: s.skipped },
  ];
  return parts.filter((p) => p.providers.length > 0);
}

export interface Correlated {
  kind: VtKind;
  value: string;
  sources: { provider: string; relation: string }[];
}

/** Related indicators reported by providers, merged so the same IOC from several sources shows once. */
export function correlate(results: TiProviderResult[], self: string): Correlated[] {
  const map = new Map<string, Correlated>();
  for (const r of results) {
    for (const rel of r.report?.related ?? []) {
      if (rel.value === self) continue;
      const entry = map.get(rel.value) ?? { kind: rel.kind, value: rel.value, sources: [] };
      if (!entry.sources.some((x) => x.provider === r.providerName && x.relation === rel.relation)) {
        entry.sources.push({ provider: r.providerName, relation: rel.relation });
      }
      map.set(rel.value, entry);
    }
  }
  return [...map.values()].sort((a, b) => b.sources.length - a.sources.length || a.value.localeCompare(b.value));
}

export interface CompareRow {
  label: string;
  cells: string[];
}

/** Side-by-side rows for the providers that returned data. Values stay in each provider's terms. */
export function compareRows(results: TiProviderResult[]): { providers: string[]; rows: CompareRow[] } {
  const withData = results.filter((r) => r.status === "found" || r.status === "not_found");
  const cell = (r: TiProviderResult, f: (r: TiProviderResult) => string | null | undefined) => f(r)?.trim() || "—";
  const list = (xs: string[] | undefined) => (xs && xs.length ? xs.slice(0, 6).join(", ") + (xs.length > 6 ? ` +${xs.length - 6}` : "") : null);
  const rows: CompareRow[] = [
    { label: "Status", cells: withData.map((r) => STATUS_META[r.status].label) },
    { label: "Verdict (provider's wording)", cells: withData.map((r) => cell(r, (x) => x.report?.verdict?.label)) },
    { label: "Scores", cells: withData.map((r) => cell(r, (x) => x.report?.scores.map((s) => `${s.label}: ${s.display}`).join("; "))) },
    { label: "Malware families", cells: withData.map((r) => cell(r, (x) => list(x.report?.families))) },
    { label: "Categories", cells: withData.map((r) => cell(r, (x) => list(x.report?.categories))) },
    { label: "Tags", cells: withData.map((r) => cell(r, (x) => list(x.report?.tags))) },
    { label: "First seen", cells: withData.map((r) => cell(r, (x) => x.report?.firstSeen)) },
    { label: "Last seen", cells: withData.map((r) => cell(r, (x) => x.report?.lastSeen)) },
    { label: "Retrieved", cells: withData.map((r) => cell(r, (x) => (x.fetchedAt ? `${x.fetchedAt.replace("T", " ").slice(0, 16)} (${x.source})` : null))) },
  ];
  return { providers: withData.map((r) => r.providerName), rows };
}
