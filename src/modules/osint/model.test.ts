import { describe, expect, it } from "vitest";
import {
  applyFilters,
  changeText,
  diffIsEmpty,
  neighborhoodIds,
  nodeStates,
  parseWorkspace,
  positionsFrom,
  searchNodes,
  toCanvas,
  typeStyle,
  versionSummary,
} from "./model";
import type { EntityBrief, RelationshipBrief, RelationshipTypeInfo } from "./types";

const registry = new Map<string, RelationshipTypeInfo>([
  ["RESOLVES_TO", { id: "RESOLVES_TO", label: "resolves to", category: "infrastructure", directed: true, inferred: false, description: "" }],
]);

const e = (id: number, type: string, value: string, extra: Partial<EntityBrief> = {}): EntityBrief => ({
  id,
  type,
  value,
  displayName: value,
  verification: "observed",
  confidence: "medium",
  flagged: false,
  ...extra,
});
const r = (id: number, source: number, target: number, extra: Partial<RelationshipBrief> = {}): RelationshipBrief => ({
  id,
  source,
  target,
  type: "RESOLVES_TO",
  directed: true,
  origin: "observed",
  verification: "observed",
  confidence: "medium",
  ...extra,
});

describe("workspace parsing", () => {
  it("falls back to defaults for malformed input", () => {
    expect(parseWorkspace(null).layout).toBe("force");
    expect(parseWorkspace([1, 2]).filters.hiddenVerifications).toEqual(["rejected"]);
    const w = parseWorkspace({ layout: "evil", viewport: { x: 1, y: 2, zoom: Infinity }, labels: "always", groups: [{ id: "g", label: "Infra", color: "url(javascript:x)" }] });
    expect(w.layout).toBe("force");
    expect(w.viewport).toBeNull();
    expect(w.labels).toBe("always");
    expect(w.groups[0].color).not.toContain("javascript");
  });

  it("keeps valid state", () => {
    const w = parseWorkspace({ layout: "radial", viewport: { x: 10, y: -5, zoom: 1.5 }, filters: { hiddenTypes: ["ip"], hiddenVerifications: ["inferred", "bogus"], flaggedOnly: true }, focus: ["1", 2] });
    expect(w.layout).toBe("radial");
    expect(w.viewport).toEqual({ x: 10, y: -5, zoom: 1.5 });
    expect(w.filters.hiddenVerifications).toEqual(["inferred"]);
    expect(w.filters.flaggedOnly).toBe(true);
    expect(w.focus).toEqual(["1"]);
  });
});

describe("canvas model", () => {
  const ents = [e(1, "domain", "example.com"), e(2, "ip", "93.184.216.34"), e(3, "ip", "192.0.2.1", { verification: "rejected" }), e(4, "unknown_type", "x", { flagged: true })];
  const rels = [r(10, 1, 2), r(11, 1, 3, { verification: "inferred" }), r(12, 1, 99)];

  it("converts entities and drops dangling relationships", () => {
    const m = toCanvas(ents, rels, registry);
    expect(m.nodes.map((n) => n.id)).toEqual(["1", "2", "3", "4"]);
    expect(m.edges.map((x) => x.id)).toEqual(["10", "11"]);
    expect(m.edges[0].label).toBe("resolves to");
    expect(m.nodes[3].glyph).toBe(typeStyle("other").glyph);
    expect(m.nodes[0].size).toBeGreaterThan(m.nodes[3].size!);
  });

  it("filters by type, verification, flag and hidden nodes", () => {
    const m = toCanvas(ents, rels, registry);
    const base = applyFilters(m, { hiddenTypes: [], hiddenVerifications: ["rejected"], hiddenRelationshipTypes: [], flaggedOnly: false }, new Set());
    expect(base.nodes.map((n) => n.id)).toEqual(["1", "2", "4"]);
    expect(base.edges.map((x) => x.id)).toEqual(["10"]);
    const noIp = applyFilters(m, { hiddenTypes: ["ip"], hiddenVerifications: [], hiddenRelationshipTypes: [], flaggedOnly: false }, new Set());
    expect(noIp.edges).toHaveLength(0);
    const flagged = applyFilters(m, { hiddenTypes: [], hiddenVerifications: [], hiddenRelationshipTypes: [], flaggedOnly: true }, new Set());
    expect(flagged.nodes.map((n) => n.id)).toEqual(["4"]);
    const hidden = applyFilters(m, { hiddenTypes: [], hiddenVerifications: [], hiddenRelationshipTypes: ["RESOLVES_TO"], flaggedOnly: false }, new Set(["4"]));
    expect(hidden.nodes).toHaveLength(3);
    expect(hidden.edges).toHaveLength(0);
  });

  it("round-trips node states and positions", () => {
    const pos = new Map([["1", { x: 1.234, y: -5.678 }]]);
    const states = nodeStates(["1", "2"], pos, new Set(["1"]), new Set(["2"]), new Map([["1", "g1"]]));
    expect(states).toEqual([
      { entityId: 1, x: 1.2, y: -5.7, pinned: true, hidden: false, group: "g1" },
      { entityId: 2, x: null, y: null, pinned: false, hidden: true, group: null },
    ]);
    expect([...positionsFrom(states).keys()]).toEqual(["1"]);
  });

  it("finds neighbourhoods and searches labels", () => {
    const edges = [
      { source: "1", target: "2" },
      { source: "2", target: "3" },
    ];
    expect([...neighborhoodIds("1", edges, 1)].sort()).toEqual(["1", "2"]);
    expect([...neighborhoodIds("1", edges, 2)].sort()).toEqual(["1", "2", "3"]);
    const m = toCanvas(ents, [], registry);
    expect(searchNodes(m.nodes, "EXAMPLE")).toEqual(["1"]);
    expect(searchNodes(m.nodes, "ip")).toEqual(["2", "3"]);
    expect(searchNodes(m.nodes, "  ")).toEqual([]);
  });
});

describe("summaries", () => {
  it("describes versions from diffs and first-version counts", () => {
    expect(versionSummary({ kind: "created", summary: { entitiesAdded: 3, relationshipsAdded: 1 } })).toBe("3 entities added, 1 relationship added");
    expect(versionSummary({ kind: "save", summary: { entitiesAdded: [], nodesMoved: 2, workspaceChanged: true } })).toBe("2 nodes moved, layout or filters changed");
    expect(versionSummary({ kind: "manual", summary: {} })).toBe("Checkpoint");
  });

  it("detects empty diffs and summarizes changes", () => {
    const empty = { entitiesAdded: [], entitiesRemoved: [], relationshipsAdded: [], relationshipsRemoved: [], verificationChanges: [], evidenceChanges: [], nodesMoved: 0, workspaceChanged: false };
    expect(diffIsEmpty(empty)).toBe(true);
    expect(diffIsEmpty({ ...empty, nodesMoved: 1 })).toBe(false);
    expect(changeText({ newEntities: [1, 2], updatedEntities: [], newRelationships: [3], inferredRelationships: [4], rejected: [] })).toBe(
      "2 new entities, 1 new relationship, 1 inferred for review",
    );
    expect(changeText({ newEntities: [], updatedEntities: [], newRelationships: [], inferredRelationships: [], rejected: [] })).toBe("Nothing new");
  });
});
