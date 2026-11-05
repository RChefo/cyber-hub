/**
 * Pure helpers of the OSINT workspace: visual encoding of entity types, conversion of stored
 * graph data to the canvas model, persisted workspace state (layout, viewport, filters,
 * groups) and version summaries. No IPC here, so everything is unit-testable.
 */
import type { GraphEdge, GraphGroup, GraphNode, LayoutKind, Point, Positions, Viewport } from "./graph";
import type { LabelMode } from "./graph/render";
import { safeColor } from "./graph/style";
import type { Diff, EntityBrief, GraphData, GraphMeta, GraphNodeState, RelationshipBrief, RelationshipTypeInfo, VersionRow, Verification } from "./types";

/* ───────────────────────── entity types ───────────────────────── */

/** Colour + glyph per entity type. The glyph and the legend keep identity readable without colour. */
export const TYPE_STYLE: Record<string, { color: string; glyph: string }> = {
  domain: { color: "#4c8dff", glyph: "D" },
  ip: { color: "#2fb5c9", glyph: "IP" },
  netblock: { color: "#2a8ca6", glyph: "N" },
  url: { color: "#7b9cff", glyph: "U" },
  email: { color: "#b58cff", glyph: "@" },
  username: { color: "#c77dd8", glyph: "u" },
  profile: { color: "#d77fb3", glyph: "P" },
  organization: { color: "#e0a43a", glyph: "O" },
  person: { color: "#e6c05c", glyph: "Pe" },
  hosting_provider: { color: "#c9874a", glyph: "H" },
  certificate: { color: "#57c08f", glyph: "C" },
  asn: { color: "#3f9f77", glyph: "AS" },
  technology: { color: "#8fa3bf", glyph: "T" },
  repository: { color: "#9b8cff", glyph: "R" },
  location: { color: "#a4b46a", glyph: "L" },
  vulnerability: { color: "#e5484d", glyph: "V" },
  file_hash: { color: "#d4685c", glyph: "#" },
  service: { color: "#5fa8d3", glyph: "S" },
  threat: { color: "#f06a6f", glyph: "!" },
  other: { color: "#8a93a3", glyph: "?" },
};

export function typeStyle(type: string): { color: string; glyph: string } {
  return TYPE_STYLE[type] ?? TYPE_STYLE.other;
}

/** Edge colour by relationship category (identity of the line also comes from its label). */
const CATEGORY_COLOR: Record<string, string> = {
  dns: "#4c8dff",
  infrastructure: "#2fb5c9",
  ownership: "#e0a43a",
  identity: "#b58cff",
  web: "#7b9cff",
  certificate: "#57c08f",
  code: "#9b8cff",
  threat: "#e5484d",
  correlation: "#8a93a3",
};

export function relationshipColor(type: string, registry: Map<string, RelationshipTypeInfo>): string {
  const cat = registry.get(type)?.category ?? "";
  return CATEGORY_COLOR[cat] ?? "#8a93a3";
}

export function relationshipLabel(type: string, registry: Map<string, RelationshipTypeInfo>): string {
  return registry.get(type)?.label ?? type.replace(/_/g, " ").toLowerCase();
}

export const VERIFICATION_META: Record<Verification, { label: string; tone: "default" | "accent" | "success" | "warning" | "danger"; hint: string }> = {
  observed: { label: "Observed", tone: "accent", hint: "Reported by a source; not yet confirmed by an analyst" },
  verified: { label: "Verified", tone: "success", hint: "Confirmed by an analyst" },
  inferred: { label: "Inferred", tone: "warning", hint: "Produced by a correlation rule or proposal; needs review" },
  disputed: { label: "Disputed", tone: "warning", hint: "An analyst doubts it; kept for reference" },
  rejected: { label: "Rejected", tone: "danger", hint: "Judged wrong by an analyst; hidden from analysis" },
};

export const CONFIDENCE_META: Record<string, { label: string; tone: "default" | "accent" | "success" | "warning" }> = {
  high: { label: "High confidence", tone: "success" },
  medium: { label: "Medium confidence", tone: "accent" },
  low: { label: "Low confidence", tone: "default" },
};

/* ───────────────────────── workspace state ───────────────────────── */

export interface WorkspaceFilters {
  hiddenTypes: string[];
  /** verification states whose relationships are hidden */
  hiddenVerifications: Verification[];
  hiddenRelationshipTypes: string[];
  flaggedOnly: boolean;
}

export interface WorkspaceGroup {
  id: string;
  label: string;
  color: string;
}

export interface Workspace {
  version: 1;
  layout: LayoutKind;
  viewport: Viewport | null;
  labels: LabelMode;
  filters: WorkspaceFilters;
  groups: WorkspaceGroup[];
  /** entity ids (strings) shown as the path/focus highlight when the graph was saved */
  focus: string[];
  notes: string;
}

export const DEFAULT_FILTERS: WorkspaceFilters = { hiddenTypes: [], hiddenVerifications: ["rejected"], hiddenRelationshipTypes: [], flaggedOnly: false };

export function defaultWorkspace(): Workspace {
  return { version: 1, layout: "force", viewport: null, labels: "auto", filters: { ...DEFAULT_FILTERS, hiddenVerifications: ["rejected"] }, groups: [], focus: [], notes: "" };
}

const LAYOUTS: LayoutKind[] = ["force", "hierarchical", "radial", "circular", "manual"];
const LABELS: LabelMode[] = ["auto", "always", "never"];
const VERIFICATIONS: Verification[] = ["observed", "verified", "inferred", "disputed", "rejected"];

function strings(v: unknown, max = 200, len = 80): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").slice(0, max).map((s) => s.slice(0, len)) : [];
}

function finite(n: unknown): n is number {
  return typeof n === "number" && Number.isFinite(n);
}

/** Read a stored workspace defensively: unknown or malformed fields fall back to defaults. */
export function parseWorkspace(raw: unknown): Workspace {
  const w = defaultWorkspace();
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return w;
  const r = raw as Record<string, unknown>;
  if (typeof r.layout === "string" && LAYOUTS.includes(r.layout as LayoutKind)) w.layout = r.layout as LayoutKind;
  if (typeof r.labels === "string" && LABELS.includes(r.labels as LabelMode)) w.labels = r.labels as LabelMode;
  const vp = r.viewport as Record<string, unknown> | null | undefined;
  if (vp && finite(vp.x) && finite(vp.y) && finite(vp.zoom) && vp.zoom > 0) w.viewport = { x: vp.x, y: vp.y, zoom: Math.min(Math.max(vp.zoom, 0.05), 4) };
  const f = r.filters as Record<string, unknown> | undefined;
  if (f && typeof f === "object") {
    w.filters = {
      hiddenTypes: strings(f.hiddenTypes, 40, 40),
      hiddenVerifications: strings(f.hiddenVerifications, 5, 20).filter((v): v is Verification => VERIFICATIONS.includes(v as Verification)),
      hiddenRelationshipTypes: strings(f.hiddenRelationshipTypes, 200, 40),
      flaggedOnly: f.flaggedOnly === true,
    };
  }
  if (Array.isArray(r.groups)) {
    w.groups = r.groups
      .filter((g): g is Record<string, unknown> => !!g && typeof g === "object")
      .filter((g) => typeof g.id === "string" && typeof g.label === "string")
      .slice(0, 50)
      .map((g) => ({ id: String(g.id).slice(0, 64), label: String(g.label).slice(0, 80), color: safeColor(typeof g.color === "string" ? g.color : "", "#8a93a3") }));
  }
  w.focus = strings(r.focus, 2000, 24);
  if (typeof r.notes === "string") w.notes = r.notes.slice(0, 20000);
  return w;
}

/* ───────────────────────── editor state from a loaded graph ───────────────────────── */

/** The editor's working copy of an open graph. */
export interface WorkState {
  graphId: number;
  meta: GraphMeta;
  revision: number;
  /** saved-state revision this editor started from (optimistic concurrency) */
  stateRevision: number;
  entities: Map<string, EntityBrief>;
  rels: Map<string, RelationshipBrief>;
  members: string[];
  /** membership as last loaded/saved, to tell local removals from deletions elsewhere */
  serverMembers: Set<string>;
  removed: Set<string>;
  pinned: Set<string>;
  hidden: Set<string>;
  nodeGroup: Map<string, string | null>;
  workspace: Workspace;
  warning: string | null;
}

/** Initial editor state for a graph as loaded from the backend: every saved property (workspace,
 *  membership, pins, hidden nodes, groups) comes from the data, nothing from a previous graph. */
export function initState(data: GraphData): WorkState {
  return {
    graphId: data.graph.id,
    meta: data.graph,
    revision: data.graph.revision,
    stateRevision: data.graph.stateRevision,
    entities: new Map(data.entities.map((e) => [String(e.id), e])),
    rels: new Map(data.relationships.map((r) => [String(r.id), r])),
    members: data.nodes.map((n) => String(n.entityId)),
    serverMembers: new Set(data.nodes.map((n) => String(n.entityId))),
    removed: new Set(),
    pinned: new Set(data.nodes.filter((n) => n.pinned).map((n) => String(n.entityId))),
    hidden: new Set(data.nodes.filter((n) => n.hidden).map((n) => String(n.entityId))),
    nodeGroup: new Map(data.nodes.map((n) => [String(n.entityId), n.group])),
    workspace: parseWorkspace(data.workspace),
    warning: data.warning,
  };
}

/* ───────────────────────── canvas model ───────────────────────── */

export interface CanvasModel {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

/** Stored entities/relationships → canvas nodes/edges (ids as strings). */
export function toCanvas(
  entities: readonly EntityBrief[],
  relationships: readonly RelationshipBrief[],
  registry: Map<string, RelationshipTypeInfo>,
  groupOf: Map<string, string | null> = new Map(),
): CanvasModel {
  const ids = new Set(entities.map((e) => String(e.id)));
  const degree = new Map<string, number>();
  for (const r of relationships) {
    degree.set(String(r.source), (degree.get(String(r.source)) ?? 0) + 1);
    degree.set(String(r.target), (degree.get(String(r.target)) ?? 0) + 1);
  }
  const nodes: GraphNode[] = entities.map((e) => {
    const s = typeStyle(e.type);
    const d = degree.get(String(e.id)) ?? 0;
    return {
      id: String(e.id),
      label: e.displayName || e.value,
      type: e.type,
      color: s.color,
      glyph: s.glyph,
      verification: e.verification,
      flagged: e.flagged,
      size: 1 + Math.min(0.7, Math.log10(1 + d) * 0.45),
      group: groupOf.get(String(e.id)) ?? null,
    };
  });
  const edges: GraphEdge[] = relationships
    .filter((r) => ids.has(String(r.source)) && ids.has(String(r.target)))
    .map((r) => ({
      id: String(r.id),
      source: String(r.source),
      target: String(r.target),
      type: r.type,
      label: relationshipLabel(r.type, registry),
      color: relationshipColor(r.type, registry),
      directed: r.directed,
      verification: r.verification,
    }));
  return { nodes, edges };
}

/** Apply workspace filters and per-node hiding. Edges are kept only between visible nodes. */
export function applyFilters(model: CanvasModel, filters: WorkspaceFilters, hidden: ReadonlySet<string>): CanvasModel {
  const types = new Set(filters.hiddenTypes);
  const vers = new Set<string>(filters.hiddenVerifications);
  const relTypes = new Set(filters.hiddenRelationshipTypes);
  const nodes = model.nodes.filter((n) => !hidden.has(n.id) && !types.has(n.type) && !(vers.has("rejected") && n.verification === "rejected") && (!filters.flaggedOnly || n.flagged));
  const visible = new Set(nodes.map((n) => n.id));
  const edges = model.edges.filter((e) => visible.has(e.source) && visible.has(e.target) && !vers.has(e.verification) && !relTypes.has(e.type));
  return { nodes, edges };
}

export function groupsForCanvas(groups: readonly WorkspaceGroup[], nodeGroup: Map<string, string | null>, visible: ReadonlySet<string>): GraphGroup[] {
  return groups
    .map((g) => ({ id: g.id, label: g.label, color: g.color, nodeIds: [...nodeGroup.entries()].filter(([id, gid]) => gid === g.id && visible.has(id)).map(([id]) => id) }))
    .filter((g) => g.nodeIds.length > 0);
}

/** Current canvas state → node states to save. Positions are rounded to keep files small. */
export function nodeStates(entityIds: readonly string[], positions: Positions, pinned: ReadonlySet<string>, hidden: ReadonlySet<string>, nodeGroup: Map<string, string | null>): GraphNodeState[] {
  return entityIds.map((id) => {
    const p = positions.get(id);
    return {
      entityId: Number(id),
      x: p ? Math.round(p.x * 10) / 10 : null,
      y: p ? Math.round(p.y * 10) / 10 : null,
      pinned: pinned.has(id),
      hidden: hidden.has(id),
      group: nodeGroup.get(id) ?? null,
    };
  });
}

/** Stored node states → positions for the nodes that have them. */
export function positionsFrom(states: readonly GraphNodeState[]): Positions {
  const m: Positions = new Map();
  for (const s of states) if (finite(s.x) && finite(s.y)) m.set(String(s.entityId), { x: s.x, y: s.y } as Point);
  return m;
}

/** Ids of nodes within `depth` steps of `start` over the given edges. */
export function neighborhoodIds(start: string, edges: readonly { source: string; target: string }[], depth = 1): Set<string> {
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    (adj.get(e.source) ?? adj.set(e.source, []).get(e.source)!).push(e.target);
    (adj.get(e.target) ?? adj.set(e.target, []).get(e.target)!).push(e.source);
  }
  const seen = new Set([start]);
  let frontier = [start];
  for (let d = 0; d < depth; d++) {
    const next: string[] = [];
    for (const n of frontier) for (const m of adj.get(n) ?? []) if (!seen.has(m)) (seen.add(m), next.push(m));
    frontier = next;
  }
  return seen;
}

/** Case-insensitive search over labels and types; returns matching node ids. */
export function searchNodes(nodes: readonly GraphNode[], q: string): string[] {
  const s = q.trim().toLowerCase();
  if (!s) return [];
  return nodes.filter((n) => n.label.toLowerCase().includes(s) || n.type === s).map((n) => n.id);
}

/* ───────────────────────── versions ───────────────────────── */

function count(v: unknown): number {
  return Array.isArray(v) ? v.length : typeof v === "number" ? v : 0;
}

/** One line describing what a version changed. */
export function versionSummary(v: Pick<VersionRow, "summary" | "kind">): string {
  const s = (v.summary ?? {}) as Record<string, unknown>;
  const parts: string[] = [];
  const add = (n: number, one: string, many: string) => n > 0 && parts.push(`${n} ${n === 1 ? one : many}`);
  add(count(s.entitiesAdded), "entity added", "entities added");
  add(count(s.entitiesRemoved), "entity removed", "entities removed");
  add(count(s.relationshipsAdded), "relationship added", "relationships added");
  add(count(s.relationshipsRemoved), "relationship removed", "relationships removed");
  add(count(s.verificationChanges), "review decision", "review decisions");
  add(count(s.evidenceChanges), "evidence change", "evidence changes");
  add(count(s.nodesMoved), "node moved", "nodes moved");
  if (s.workspaceChanged === true) parts.push("layout or filters changed");
  return parts.length ? parts.join(", ") : v.kind === "manual" ? "Checkpoint" : "No content changes";
}

export function diffIsEmpty(d: Diff): boolean {
  return (
    d.entitiesAdded.length + d.entitiesRemoved.length + d.relationshipsAdded.length + d.relationshipsRemoved.length + d.verificationChanges.length + d.evidenceChanges.length ===
      0 &&
    d.nodesMoved === 0 &&
    !d.workspaceChanged
  );
}

/* ───────────────────────── misc ───────────────────────── */

export const GROUP_COLORS = ["#4c8dff", "#3fb68b", "#e0a43a", "#b58cff", "#2fb5c9", "#e5484d", "#c9874a", "#8fa3bf"];

export function nextGroupColor(groups: readonly WorkspaceGroup[]): string {
  return GROUP_COLORS[groups.length % GROUP_COLORS.length];
}

export function plural(n: number, one: string, many: string): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

/** Turns a ChangeSummary into a short sentence for notifications. */
export function changeText(s: { newEntities: number[]; updatedEntities: number[]; newRelationships: number[]; inferredRelationships: number[]; rejected: string[] }): string {
  const parts = [
    s.newEntities.length && plural(s.newEntities.length, "new entity", "new entities"),
    s.updatedEntities.length && `${s.updatedEntities.length} updated`,
    s.newRelationships.length && plural(s.newRelationships.length, "new relationship", "new relationships"),
    s.inferredRelationships.length && `${s.inferredRelationships.length} inferred for review`,
    s.rejected.length && `${s.rejected.length} skipped`,
  ].filter(Boolean);
  return parts.length ? parts.join(", ") : "Nothing new";
}

/** "2026-11-05T10:20:30Z" → local "2026-11-05 10:20". */
export function shortTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(0, 16).replace("T", " ");
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** Blob → base64 (no data: prefix) for the image export command. */
export async function blobToBase64(blob: Blob): Promise<string> {
  const buf = new Uint8Array(await blob.arrayBuffer());
  let bin = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < buf.length; i += CHUNK) bin += String.fromCharCode(...buf.subarray(i, i + CHUNK));
  return btoa(bin);
}
