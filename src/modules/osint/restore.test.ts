import { describe, expect, it } from "vitest";
import { initState, nodeStates, parseWorkspace, positionsFrom, type Workspace } from "./model";
import type { GraphData, GraphMeta, GraphNodeState } from "./types";

const meta = (id: number, extra: Partial<GraphMeta> = {}): GraphMeta => ({
  id,
  investigationId: 1,
  investigationName: "Acme",
  primaryTarget: "example.com",
  name: `Graph ${id}`,
  description: "",
  followNew: true,
  revision: 7,
  createdAt: "2026-11-05T00:00:00Z",
  updatedAt: "2026-11-05T00:00:00Z",
  lastOpenedAt: null,
  entityCount: 3,
  relationshipCount: 1,
  versionCount: 2,
  latestVersion: 2,
  stateRevision: 4,
  ...extra,
});

const customWorkspace: Workspace = {
  version: 1,
  layout: "manual",
  viewport: { x: 12.5, y: -40.25, zoom: 1.75 },
  labels: "always",
  filters: { hiddenTypes: ["organization"], hiddenVerifications: ["rejected", "inferred"], hiddenRelationshipTypes: ["REGISTERED_TO"], flaggedOnly: true },
  groups: [{ id: "g1", label: "Hosts", color: "#4c8dff" }],
  focus: ["1"],
  notes: "notes",
};

const nodes: GraphNodeState[] = [
  { entityId: 1, x: 10, y: -10, pinned: true, hidden: false, group: "g1" },
  { entityId: 2, x: 20, y: -20, pinned: false, hidden: true, group: null },
  { entityId: 3, x: null, y: null, pinned: false, hidden: false, group: null },
];

const data = (id: number, workspace: unknown, n: GraphNodeState[] = nodes): GraphData => ({
  graph: meta(id),
  workspace,
  nodes: n,
  entities: n.map((x) => ({ id: x.entityId, type: "domain", value: `d${x.entityId}.example`, displayName: `d${x.entityId}.example`, verification: "observed", confidence: "medium", flagged: false })),
  relationships: [{ id: 9, source: 1, target: 2, type: "RESOLVES_TO", directed: true, origin: "observed", verification: "observed", confidence: "medium" }],
  warning: null,
});

describe("graph restoration", () => {
  it("restores every saved workspace property and node flag", () => {
    // what the backend returns is what the editor saved (JSON round trip)
    const s = initState(data(5, JSON.parse(JSON.stringify(customWorkspace))));
    expect(s.workspace).toEqual(customWorkspace);
    expect(s.graphId).toBe(5);
    expect(s.stateRevision).toBe(4);
    expect([...s.pinned]).toEqual(["1"]);
    expect([...s.hidden]).toEqual(["2"]);
    expect(s.nodeGroup.get("1")).toBe("g1");
    expect(s.members).toEqual(["1", "2", "3"]);
    const pos = positionsFrom(nodes);
    expect(pos.get("1")).toEqual({ x: 10, y: -10 });
    expect(pos.has("3")).toBe(false);
  });

  it("saving and reopening gives back the same state", () => {
    const s = initState(data(5, customWorkspace));
    const saved = nodeStates(s.members, positionsFrom(nodes), s.pinned, s.hidden, s.nodeGroup);
    const workspace = JSON.parse(JSON.stringify({ ...s.workspace, viewport: { x: 1, y: 2, zoom: 0.5 } }));
    const reopened = initState(data(5, workspace, saved));
    expect(reopened.workspace).toEqual({ ...customWorkspace, viewport: { x: 1, y: 2, zoom: 0.5 } });
    expect([...reopened.pinned]).toEqual([...s.pinned]);
    expect([...reopened.hidden]).toEqual([...s.hidden]);
    expect([...reopened.nodeGroup]).toEqual([...s.nodeGroup]);
    expect(positionsFrom(saved)).toEqual(positionsFrom(nodes));
  });

  it("opening graphs one after another never carries state over", () => {
    const a = initState(data(5, customWorkspace));
    const b = initState(data(6, {}, [{ entityId: 4, x: 1, y: 1, pinned: false, hidden: false, group: null }]));
    const a2 = initState(data(5, customWorkspace));
    expect(b.workspace).toEqual(parseWorkspace({}));
    expect(b.pinned.size + b.hidden.size).toBe(0);
    expect(a2).toEqual(a);
  });

  it("a malformed stored workspace falls back to defaults without losing node flags", () => {
    const s = initState(data(5, "not an object"));
    expect(s.workspace).toEqual(parseWorkspace(null));
    expect([...s.hidden]).toEqual(["2"]);
    expect([...s.pinned]).toEqual(["1"]);
  });
});
