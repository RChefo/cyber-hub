import type { GraphEdge, GraphNode } from "@/modules/osint/graph";
import type { InvestigationGraph, RecordKind, RecordRef, Relation, RelationOrigin, RelationVerification } from "@/lib/types";

/** Project tabs a record opens in. */
export type RecordTab = "findings" | "surface" | "vulns" | "evidence" | "apis" | "components" | "commands" | "attack" | "osint";

export const KIND_LABEL: Record<RecordKind, string> = {
  finding: "Finding",
  asset: "Asset",
  vulnerability: "Vulnerability",
  evidence: "Evidence",
  osint_entity: "OSINT entity",
  api_endpoint: "API endpoint",
  sbom_component: "Component",
  technique: "ATT&CK technique",
  execution: "Tool run",
  project: "Project",
};

/** Colours of the graph nodes by record kind (the OSINT graph's palette). */
export const KIND_STYLE: Record<RecordKind, { color: string; glyph: string }> = {
  finding: { color: "#e5484d", glyph: "F" },
  asset: { color: "#4c8dff", glyph: "A" },
  vulnerability: { color: "#e0a43a", glyph: "V" },
  evidence: { color: "#3fb68b", glyph: "E" },
  osint_entity: { color: "#a78bfa", glyph: "O" },
  api_endpoint: { color: "#38bdf8", glyph: "/" },
  sbom_component: { color: "#f472b6", glyph: "P" },
  technique: { color: "#fb923c", glyph: "T" },
  execution: { color: "#94a3b8", glyph: "R" },
  project: { color: "#8a93a3", glyph: "P" },
};

export const ORIGIN_LABEL: Record<RelationOrigin, string> = {
  observed: "Observed",
  imported: "Imported",
  derived: "Derived",
  inferred: "Inferred",
  manual: "Analyst",
  suggested: "Suggested by an MCP client",
};

export const VERIFICATION_LABEL: Record<RelationVerification, string> = {
  observed: "observed",
  verified: "confirmed",
  inferred: "unconfirmed",
  disputed: "disputed",
  rejected: "rejected",
};

/** Edge colours by origin: confirmed relationships in the foreground, suggestions muted. */
const ORIGIN_COLOR: Record<RelationOrigin, string> = {
  observed: "#8a93a3",
  imported: "#4c8dff",
  derived: "#3fb68b",
  inferred: "#e0a43a",
  manual: "#e8ebf0",
  suggested: "#a78bfa",
};

export const RELATION_TYPES: { id: string; label: string }[] = [
  { id: "related_to", label: "is related to" },
  { id: "affects", label: "affects" },
  { id: "supported_by", label: "is supported by" },
  { id: "corresponds_to", label: "corresponds to" },
  { id: "maps_to", label: "maps to (ATT&CK)" },
  { id: "possible_duplicate", label: "may duplicate" },
  { id: "associated_with", label: "is associated with" },
];

/** The project tab a record lives in. */
export function tabFor(ref: RecordRef): RecordTab {
  switch (ref.kind) {
    case "finding":
      return "findings";
    case "asset":
      return "surface";
    case "vulnerability":
      return "vulns";
    case "evidence":
      return "evidence";
    case "api_endpoint":
      return "apis";
    case "sbom_component":
      return "components";
    case "execution":
      return "commands";
    case "technique":
      return "attack";
    default:
      return "osint";
  }
}

/** "finding:12" → the reference (the inverse of the backend's key). */
export function parseKey(key: string): RecordRef | null {
  const [kind, a, b] = key.split(":");
  if (!kind) return null;
  if (kind === "technique") return a ? { kind: "technique", id: 0, sub: a } : null;
  const id = Number(a);
  if (!Number.isInteger(id)) return null;
  return { kind: kind as RecordKind, id, sub: b ?? "" };
}

export function refKey(r: RecordRef): string {
  if (r.kind === "technique") return `technique:${r.sub}`;
  return r.sub ? `${r.kind}:${r.id}:${r.sub}` : `${r.kind}:${r.id}`;
}

/** "SQL injection affects https://app.example.com" */
export function sentence(r: Pick<Relation, "a" | "b" | "label">): string {
  return `${r.a.label} ${r.label} ${r.b.label}`;
}

/** What a relationship is, in words: "Derived, unconfirmed · high confidence". */
export function provenance(r: Pick<Relation, "origin" | "verification" | "confidence">): string {
  return `${ORIGIN_LABEL[r.origin]}, ${VERIFICATION_LABEL[r.verification]} · ${r.confidence} confidence`;
}

/** The investigation graph in the OSINT graph engine's model. */
export function toCanvas(g: InvestigationGraph): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = g.nodes.map((n) => ({
    id: n.key,
    label: n.label,
    type: n.ref.kind,
    color: KIND_STYLE[n.ref.kind]?.color ?? "#8a93a3",
    glyph: KIND_STYLE[n.ref.kind]?.glyph ?? "?",
    verification: "observed",
    flagged: n.flagged,
  }));
  const edges: GraphEdge[] = g.edges.map((e) => ({
    id: e.id,
    source: e.source,
    target: e.target,
    type: e.type,
    label: e.label,
    color: ORIGIN_COLOR[e.origin] ?? "#8a93a3",
    directed: e.directed,
    verification: e.verification,
  }));
  return { nodes, edges };
}
