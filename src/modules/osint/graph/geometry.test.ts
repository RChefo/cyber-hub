import { describe, expect, it } from "vitest";
import {
  clampZoom,
  computeEdgeGeom,
  convexHull,
  createEdgeGeom,
  distanceToQuadratic,
  distanceToSegment,
  edgeControlPoint,
  edgeCurvatures,
  hitTestEdge,
  hitTestNode,
  MAX_ZOOM,
  MIN_ZOOM,
  nodesInRect,
  paddedHull,
  screenToWorld,
  worldToScreen,
  zoomAt,
} from "./geometry";
import type { GraphEdge, GraphNode, Positions, Viewport } from "./types";

const mkNode = (id: string, size?: number): GraphNode => ({ id, label: id, type: "t", color: "#4c8dff", glyph: "A", verification: "observed", size });
const mkEdge = (id: string, source: string, target: string, directed = true): GraphEdge => ({
  id,
  source,
  target,
  type: "rel",
  label: "",
  color: "#8a93a3",
  directed,
  verification: "observed",
});

describe("coordinate conversion", () => {
  const vp: Viewport = { x: 100, y: -50, zoom: 2 };
  it("maps the viewport centre to the canvas centre", () => {
    expect(worldToScreen({ x: 100, y: -50 }, vp, 800, 600)).toEqual({ x: 400, y: 300 });
  });
  it("round-trips world ↔ screen", () => {
    const w = { x: 123.5, y: -77.25 };
    const back = screenToWorld(worldToScreen(w, vp, 800, 600), vp, 800, 600);
    expect(back.x).toBeCloseTo(w.x, 9);
    expect(back.y).toBeCloseTo(w.y, 9);
  });
});

describe("zoomAt", () => {
  it("keeps the world point under the cursor fixed", () => {
    const vp: Viewport = { x: 30, y: 40, zoom: 0.8 };
    const cursor = { x: 610, y: 95 };
    const before = screenToWorld(cursor, vp, 1000, 700);
    for (const factor of [1.25, 0.5, 3]) {
      const next = zoomAt(vp, factor, cursor, 1000, 700);
      const after = screenToWorld(cursor, next, 1000, 700);
      expect(after.x).toBeCloseTo(before.x, 9);
      expect(after.y).toBeCloseTo(before.y, 9);
    }
  });
  it("clamps zoom", () => {
    const vp: Viewport = { x: 0, y: 0, zoom: 1 };
    expect(zoomAt(vp, 1000, { x: 10, y: 10 }, 100, 100).zoom).toBe(MAX_ZOOM);
    expect(zoomAt(vp, 1e-6, { x: 10, y: 10 }, 100, 100).zoom).toBe(MIN_ZOOM);
    expect(clampZoom(Number.NaN)).toBe(1);
  });
  it("keeps the cursor fixed even when clamped", () => {
    const vp: Viewport = { x: 5, y: 5, zoom: 3.5 };
    const cursor = { x: 20, y: 70 };
    const before = screenToWorld(cursor, vp, 200, 100);
    const after = screenToWorld(cursor, zoomAt(vp, 10, cursor, 200, 100), 200, 100);
    expect(after.x).toBeCloseTo(before.x, 9);
    expect(after.y).toBeCloseTo(before.y, 9);
  });
});

describe("hitTestNode", () => {
  const nodes = [mkNode("a"), mkNode("b", 2), mkNode("c")];
  const positions: Positions = new Map([
    ["a", { x: 0, y: 0 }],
    ["b", { x: 100, y: 0 }],
    ["c", { x: 10, y: 0 }],
  ]);
  it("finds the node under the point, respecting size", () => {
    expect(hitTestNode(positions, nodes, { x: 100 + 30, y: 0 }, 1)).toBe("b"); // radius 32
    expect(hitTestNode(positions, nodes, { x: 100 + 40, y: 0 }, 1)).toBeNull();
    expect(hitTestNode(positions, nodes, { x: 50, y: 50 }, 1)).toBeNull();
  });
  it("prefers the closest centre when nodes overlap", () => {
    expect(hitTestNode(positions, nodes, { x: -2, y: 0 }, 1)).toBe("a");
    expect(hitTestNode(positions, nodes, { x: 9, y: 0 }, 1)).toBe("c");
  });
  it("adds screen-space slack that grows in world units when zoomed out", () => {
    // radius 16 + 3px slack; at zoom 0.1 the slack is 30 world units.
    expect(hitTestNode(positions, nodes, { x: 0, y: 40 }, 0.1)).toBe("a");
    expect(hitTestNode(positions, nodes, { x: 0, y: 40 }, 1)).toBeNull();
  });
});

describe("hitTestEdge", () => {
  const positions: Positions = new Map([
    ["a", { x: 0, y: 0 }],
    ["b", { x: 200, y: 0 }],
    ["c", { x: 0, y: 300 }],
  ]);
  it("hits a straight edge within the pixel tolerance", () => {
    const edges = [mkEdge("ab", "a", "b"), mkEdge("ac", "a", "c")];
    expect(hitTestEdge(positions, edges, { x: 100, y: 4 }, 1)).toBe("ab");
    expect(hitTestEdge(positions, edges, { x: 100, y: 9 }, 1)).toBeNull();
    expect(hitTestEdge(positions, edges, { x: 100, y: 9 }, 0.5)).toBe("ab"); // 6px = 12 world
    expect(hitTestEdge(positions, edges, { x: 3, y: 150 }, 1)).toBe("ac");
  });
  it("hits parallel edges along their curves", () => {
    const edges = [mkEdge("e1", "a", "b"), mkEdge("e2", "a", "b")];
    const curv = edgeCurvatures(edges);
    expect(curv.get("e1")).toBe(-curv.get("e2")!);
    const c1 = edgeControlPoint(positions.get("a")!, positions.get("b")!, curv.get("e1")!)!;
    // Midpoint of the quadratic is halfway between the chord midpoint and the control point.
    const mid1 = { x: (100 + c1.x) / 2, y: (0 + c1.y) / 2 };
    expect(hitTestEdge(positions, edges, mid1, 1)).toBe("e1");
    expect(hitTestEdge(positions, edges, { x: mid1.x, y: -mid1.y }, 1)).toBe("e2");
    expect(hitTestEdge(positions, edges, { x: 100, y: 0 }, 1)).toBeNull(); // straight chord is empty
  });
  it("bows opposite-direction edges to opposite sides", () => {
    const edges = [mkEdge("ab", "a", "b"), mkEdge("ba", "b", "a")];
    const curv = edgeCurvatures(edges);
    const a = positions.get("a")!;
    const b = positions.get("b")!;
    const c1 = edgeControlPoint(a, b, curv.get("ab")!)!;
    const c2 = edgeControlPoint(b, a, curv.get("ba")!)!;
    expect(Math.sign(c1.y)).toBe(-Math.sign(c2.y));
  });
  it("hits self-loops", () => {
    const edges = [mkEdge("loop", "a", "a")];
    expect(hitTestEdge(positions, edges, { x: 0, y: -16 - 10 * 0.45 - 10 }, 1)).toBe("loop");
  });
});

describe("distance helpers", () => {
  it("measures distance to segments and curves", () => {
    expect(distanceToSegment({ x: 5, y: 5 }, { x: 0, y: 0 }, { x: 10, y: 0 })).toBe(5);
    expect(distanceToSegment({ x: -3, y: 4 }, { x: 0, y: 0 }, { x: 10, y: 0 })).toBe(5);
    expect(distanceToQuadratic({ x: 5, y: 0 }, { x: 0, y: 0 }, { x: 5, y: 0 }, { x: 10, y: 0 })).toBeCloseTo(0, 9);
  });
  it("clips edges to node rims and leaves room for the arrowhead", () => {
    const g = createEdgeGeom();
    expect(computeEdgeGeom(g, 0, 0, 100, 0, 10, 20, 0, 8)).toBe(true);
    expect(g.sx).toBeCloseTo(10, 9);
    expect(g.tipX).toBeCloseTo(80, 9);
    expect(g.ex).toBeCloseTo(80 - 8 * 0.8, 9);
    expect(computeEdgeGeom(g, 0, 0, 20, 0, 10, 10, 0, 0)).toBe(false); // overlapping nodes
  });
});

describe("nodesInRect", () => {
  it("selects nodes whose centres fall inside, regardless of drag direction", () => {
    const nodes = [mkNode("a"), mkNode("b"), mkNode("c")];
    const positions: Positions = new Map([
      ["a", { x: 0, y: 0 }],
      ["b", { x: 50, y: 50 }],
      ["c", { x: 200, y: 0 }],
    ]);
    expect(nodesInRect(positions, nodes, { x: 60, y: 60 }, { x: -10, y: -10 }).sort()).toEqual(["a", "b"]);
    expect(nodesInRect(positions, nodes, { x: 300, y: 300 }, { x: 250, y: 250 })).toEqual([]);
  });
});

describe("hulls", () => {
  it("computes a convex hull without interior points", () => {
    const hull = convexHull([
      { x: 0, y: 0 },
      { x: 10, y: 0 },
      { x: 10, y: 10 },
      { x: 0, y: 10 },
      { x: 5, y: 5 },
      { x: 5, y: 0 },
    ]);
    expect(hull).toHaveLength(4);
    expect(hull).not.toContainEqual({ x: 5, y: 5 });
  });
  it("pads hulls so single points and pairs still get an outline", () => {
    const one = paddedHull([{ x: 0, y: 0 }], 10);
    expect(one.length).toBeGreaterThanOrEqual(8);
    for (const p of one) expect(Math.hypot(p.x, p.y)).toBeCloseTo(10, 6);
    const two = paddedHull(
      [
        { x: 0, y: 0 },
        { x: 100, y: 0 },
      ],
      10,
    );
    expect(Math.max(...two.map((p) => p.x))).toBeCloseTo(110, 6);
    expect(Math.min(...two.map((p) => p.y))).toBeLessThan(-9);
  });
});
