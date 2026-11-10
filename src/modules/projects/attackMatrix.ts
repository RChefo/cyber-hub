import type { AttackCatalog, AttackDomain, AttackEntry, AttackMatrix, AttackTactic, AttackTechnique } from "@/lib/types";

/** What the project says about a technique, strongest statement first. Findings name techniques
 * (leads); only an assessment confirms, suspects or rules one out; a layer is an overlay. */
export type TechniqueState = "confirmed" | "hypothesis" | "ruled_out" | "observed" | "linked" | "none";

export const STATE_STYLE: Record<Exclude<TechniqueState, "none">, { label: string; color: string; hint: string }> = {
  confirmed: { label: "Confirmed", color: "#c62828", hint: "You confirmed adversary activity" },
  hypothesis: { label: "Hypothesis", color: "#f9a825", hint: "You suspect it; not confirmed" },
  ruled_out: { label: "Ruled out", color: "#90a4ae", hint: "You checked and ruled it out" },
  observed: { label: "Named by findings", color: "#ef6c00", hint: "Tool output maps to it: leads, not confirmed activity" },
  linked: { label: "Linked by hand", color: "#64b5f6", hint: "A record is linked to it" },
};

export function stateOf(e: AttackEntry | undefined): TechniqueState {
  if (!e) return "none";
  if (e.assessment) return e.assessment.status;
  if (e.observed.length) return "observed";
  if (e.linked.length) return "linked";
  return "none";
}

/** Whether the project says anything about the technique (an imported layer alone does not count). */
export function hasData(e: AttackEntry | undefined): boolean {
  return stateOf(e) !== "none";
}

export interface MatrixRow {
  tech: AttackTechnique;
  entry?: AttackEntry;
  /** sub-techniques shown under it */
  subs: { tech: AttackTechnique; entry?: AttackEntry }[];
  /** sub-techniques the project says something about */
  subsWithData: number;
}

export interface MatrixColumn {
  tactic: AttackTactic;
  rows: MatrixRow[];
}

/** An overlay: an imported layer, or the detection library's rules. */
export type Overlay = number | "rules" | null;

/** Enabled rules that can run, for a technique. */
export function activeRules(e: AttackEntry | undefined) {
  return (e?.rules ?? []).filter((r) => r.enabled && r.runnable);
}

/** Whether the overlay lists the technique. */
export function inOverlay(e: AttackEntry | undefined, overlay: Overlay): boolean {
  if (overlay == null || !e) return false;
  if (overlay === "rules") return activeRules(e).length > 0;
  return e.layers.some((l) => l.layerId === overlay);
}

/** The matrix as columns of tactics (in ATT&CK's order) with their techniques. With `onlyData`,
 * only techniques the project says something about (or whose sub-techniques it does), or that the
 * overlay lists; sub-techniques are listed under their parent when they have data. */
export function buildColumns(catalog: AttackCatalog, matrix: AttackMatrix, opts: { onlyData: boolean; filter: string; layerId: Overlay }): MatrixColumn[] {
  const entries = new Map(matrix.entries.map((e) => [e.id, e]));
  const inLayer = (id: string) => inOverlay(entries.get(id), opts.layerId);
  const q = opts.filter.trim().toLowerCase();
  const matches = (t: AttackTechnique) => !q || t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q);
  const subsOf = new Map<string, AttackTechnique[]>();
  for (const t of catalog.techniques) {
    if (t.parent) subsOf.set(t.parent, [...(subsOf.get(t.parent) ?? []), t]);
  }
  return catalog.tactics.map((tactic) => {
    const rows: MatrixRow[] = [];
    for (const t of catalog.techniques) {
      if (t.parent || !t.tactics.includes(tactic.shortname)) continue;
      const subs = (subsOf.get(t.id) ?? []).filter((s) => s.tactics.includes(tactic.shortname));
      const subsShown = subs.filter((s) => hasData(entries.get(s.id)) || inLayer(s.id));
      const own = hasData(entries.get(t.id)) || inLayer(t.id);
      if (opts.onlyData && !own && subsShown.length === 0) continue;
      if (q && !matches(t) && !subs.some(matches)) continue;
      rows.push({ tech: t, entry: entries.get(t.id), subs: subsShown.filter((s) => !q || matches(s) || matches(t)).map((s) => ({ tech: s, entry: entries.get(s.id) })), subsWithData: subs.filter((s) => hasData(entries.get(s.id))).length });
    }
    return { tactic, rows };
  });
}

/** Techniques the project names, confirms or suspects that the overlay does not cover (a layer
 * that does not list them or lists them disabled, or no enabled detection rule): the gaps. */
export function gaps(matrix: AttackMatrix, overlay: number | "rules"): AttackEntry[] {
  return matrix.entries.filter((e) => {
    const s = stateOf(e);
    if (s === "none" || s === "ruled_out" || s === "linked" || e.state.state !== "current") return false;
    if (overlay === "rules") return activeRules(e).length === 0;
    return !e.layers.some((l) => l.layerId === overlay && l.enabled);
  });
}

/** Entries the matrix cannot place: IDs revoked or deprecated since, or unknown to ATT&CK. */
export function outside(matrix: AttackMatrix): AttackEntry[] {
  return matrix.entries.filter((e) => e.state.state !== "current" && hasData(e));
}

export function mitreUrl(id: string): string {
  return `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`;
}

/** The ATT&CK matrices Cyber Hub bundles (Mission 6), in the order they are offered. */
export const ATTACK_DOMAINS: { id: AttackDomain; label: string }[] = [
  { id: "enterprise-attack", label: "Enterprise" },
  { id: "mobile-attack", label: "Mobile" },
  { id: "ics-attack", label: "ICS" },
];

export function domainLabel(d: AttackDomain | string): string {
  return ATTACK_DOMAINS.find((x) => x.id === d)?.label ?? "Enterprise";
}
