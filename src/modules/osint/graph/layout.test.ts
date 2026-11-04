import { describe, expect, it } from "vitest";
import { worldToScreen } from "./geometry";
import {
  circularLayout,
  computeLayout,
  fitViewport,
  forceLayout,
  hashString,
  hierarchicalLayout,
  mulberry32,
  placeNewNodes,
  radialLayout,
} from "./layout";
import type { LayoutEdge, LayoutNode, Point, Positions } from "./types";

const node = (id: string): LayoutNode => ({ id });
const edge = (source: string, target: string): LayoutEdge => ({ source, target });

/** Random sparse graph with a spanning chain so it is connected. */
function randomGraph(n: number, m: number, seed = 7): { nodes: LayoutNode[]; edges: LayoutEdge[] } {
  const rnd = mulberry32(seed);
  const nodes = Array.from({ length: n }, (_, i) => node(`n${i}`));
  const edges: LayoutEdge[] = [];
  for (let i = 1; i < n; i++) edges.push(edge(`n${Math.floor(rnd() * i)}`, `n${i}`));
  while (edges.length < m) edges.push(edge(`n${Math.floor(rnd() * n)}`, `n${Math.floor(rnd() * n)}`));
  return { nodes, edges };
}

const dist = (a: Point, b: Point) => Math.hypot(a.x - b.x, a.y - b.y);

function allFinite(p: Positions): boolean {
  for (const v of p.values()) if (!Number.isFinite(v.x) || !Number.isFinite(v.y)) return false;
  return true;
}

describe("prng & hash", () => {
  it("are deterministic", () => {
    const a = mulberry32(42);
    const b = mulberry32(42);
    for (let i = 0; i < 5; i++) expect(a()).toBe(b());
    expect(hashString("abc")).toBe(hashString("abc"));
    expect(hashString("abc")).not.toBe(hashString("abd"));
  });
});

describe("forceLayout", () => {
  it("returns nothing for an empty graph and a point for a single node", () => {
    expect(forceLayout([], []).size).toBe(0);
    const one = forceLayout([node("a")], []);
    expect(one.size).toBe(1);
    expect(allFinite(one)).toBe(true);
  });

  it("is deterministic for a given seed and differs across seeds", () => {
    const { nodes, edges } = randomGraph(60, 90);
    const a = forceLayout(nodes, edges, { seed: 3, iterations: 120 });
    const b = forceLayout(nodes, edges, { seed: 3, iterations: 120 });
    const c = forceLayout(nodes, edges, { seed: 4, iterations: 120 });
    expect([...a.entries()]).toEqual([...b.entries()]);
    expect([...a.entries()]).not.toEqual([...c.entries()]);
  });

  it("keeps pinned nodes exactly where they were", () => {
    const { nodes, edges } = randomGraph(80, 120);
    const positions: Positions = new Map([
      ["n0", { x: 500, y: -300 }],
      ["n5", { x: -250, y: 40 }],
    ]);
    const out = forceLayout(nodes, edges, { positions, pinned: new Set(["n0", "n5"]), iterations: 150 });
    expect(out.get("n0")).toEqual({ x: 500, y: -300 });
    expect(out.get("n5")).toEqual({ x: -250, y: 40 });
    expect(out.size).toBe(80);
    expect(allFinite(out)).toBe(true);
  });

  it("pulls connected nodes closer than unconnected ones and avoids overlaps", () => {
    const { nodes, edges } = randomGraph(120, 160, 11);
    const out = forceLayout(nodes, edges, { seed: 1 });
    let linked = 0;
    for (const e of edges) linked += dist(out.get(e.source)!, out.get(e.target)!);
    linked /= edges.length;
    let all = 0;
    let pairs = 0;
    let minD = Infinity;
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const d = dist(out.get(nodes[i].id)!, out.get(nodes[j].id)!);
        all += d;
        pairs++;
        minD = Math.min(minD, d);
      }
    }
    expect(linked).toBeLessThan(all / pairs);
    expect(minD).toBeGreaterThan(16); // no two nodes collapse onto each other
  });

  it("keeps disconnected components together", () => {
    const nodes = Array.from({ length: 40 }, (_, i) => node(`c${i}`));
    const edges: LayoutEdge[] = [];
    // 10 separate 4-cycles.
    for (let k = 0; k < 10; k++) {
      for (let j = 0; j < 4; j++) edges.push(edge(`c${k * 4 + j}`, `c${k * 4 + ((j + 1) % 4)}`));
    }
    const out = forceLayout(nodes, edges, { seed: 2 });
    let maxR = 0;
    for (const p of out.values()) maxR = Math.max(maxR, Math.hypot(p.x, p.y));
    expect(maxR).toBeLessThan(1500);
  });

  it("starts from existing positions", () => {
    const nodes = [node("a"), node("b")];
    const positions: Positions = new Map([
      ["a", { x: 10_000, y: 10_000 }],
      ["b", { x: 10_100, y: 10_000 }],
    ]);
    const out = forceLayout(nodes, [edge("a", "b")], { positions, iterations: 50 });
    // Gravity targets the current centroid, so the pair stays where it already was.
    expect(Math.abs(out.get("a")!.x - 10_000)).toBeLessThan(200);
    expect(Math.abs(out.get("b")!.y - 10_000)).toBeLessThan(200);
  });

  it("handles duplicate, self-loop and dangling edges", () => {
    const out = forceLayout([node("a"), node("b")], [edge("a", "b"), edge("b", "a"), edge("a", "a"), edge("a", "zzz")], { iterations: 30 });
    expect(out.size).toBe(2);
    expect(allFinite(out)).toBe(true);
  });

  it("lays out 1,500 nodes / 3,000 edges in under 3 s", () => {
    const { nodes, edges } = randomGraph(1500, 3000, 5);
    const t0 = performance.now();
    const out = forceLayout(nodes, edges, { seed: 9 });
    const ms = performance.now() - t0;
    expect(out.size).toBe(1500);
    expect(allFinite(out)).toBe(true);
    expect(ms).toBeLessThan(3000);
  });
});

describe("placeNewNodes", () => {
  it("keeps existing positions and places new nodes near their neighbours", () => {
    const nodes = [node("a"), node("b"), node("c"), node("d")];
    const edges = [edge("a", "b"), edge("b", "c"), edge("a", "d")];
    const positions: Positions = new Map([
      ["a", { x: 0, y: 0 }],
      ["b", { x: 400, y: 0 }],
    ]);
    const before = new Map(positions);
    const out = placeNewNodes(nodes, edges, positions);
    expect(out.get("a")).toBe(positions.get("a"));
    expect(out.get("b")).toBe(positions.get("b"));
    expect(positions).toEqual(before); // input untouched
    expect(dist(out.get("c")!, out.get("b")!)).toBeLessThan(250);
    expect(dist(out.get("d")!, out.get("a")!)).toBeLessThan(250);
    expect(dist(out.get("c")!, out.get("a")!)).toBeGreaterThan(dist(out.get("c")!, out.get("b")!));
  });

  it("puts a node bridging two placed nodes between them", () => {
    const out = placeNewNodes([node("a"), node("b"), node("m")], [edge("a", "m"), edge("m", "b")], new Map([
      ["a", { x: 0, y: 0 }],
      ["b", { x: 400, y: 0 }],
    ]));
    expect(out.get("m")).toEqual({ x: 200, y: 0 });
  });

  it("places isolated new nodes outside the existing drawing without overlaps", () => {
    const nodes = [node("a"), node("x"), node("y"), node("z")];
    const out = placeNewNodes(nodes, [], new Map([["a", { x: 0, y: 0 }]]));
    const pts = ["a", "x", "y", "z"].map((id) => out.get(id)!);
    for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) expect(dist(pts[i], pts[j])).toBeGreaterThan(40);
  });

  it("is deterministic", () => {
    const { nodes, edges } = randomGraph(50, 70);
    const a = placeNewNodes(nodes, edges, new Map());
    const b = placeNewNodes(nodes, edges, new Map());
    expect([...a.entries()]).toEqual([...b.entries()]);
    expect(a.size).toBe(50);
  });
});

describe("hierarchicalLayout", () => {
  const nodes = ["r", "a", "b", "a1", "a2", "b1", "b2", "x", "y"].map(node);
  const edges = [edge("r", "a"), edge("r", "b"), edge("b", "b1"), edge("a", "a1"), edge("b", "b2"), edge("a", "a2"), edge("x", "y")];

  it("assigns BFS layers top-down from the root", () => {
    const out = hierarchicalLayout(nodes, edges, { root: "r" });
    const y = (id: string) => out.get(id)!.y;
    expect(y("r")).toBe(0);
    expect(y("a")).toBe(y("b"));
    expect(y("a")).toBeGreaterThan(y("r"));
    expect(y("a1")).toBeGreaterThan(y("a"));
    expect(new Set(["a1", "a2", "b1", "b2"].map(y)).size).toBe(1);
  });

  it("orders children under their parents (no crossings in a tree)", () => {
    const out = hierarchicalLayout(nodes, edges, { root: "r" });
    const x = (id: string) => out.get(id)!.x;
    const [left, right] = x("a") < x("b") ? ["a", "b"] : ["b", "a"];
    expect(Math.max(x(`${left}1`), x(`${left}2`))).toBeLessThan(Math.min(x(`${right}1`), x(`${right}2`)));
  });

  it("places components side by side without overlap", () => {
    const out = hierarchicalLayout(nodes, edges, { root: "r" });
    const main = ["r", "a", "b", "a1", "a2", "b1", "b2"].map((id) => out.get(id)!.x);
    const other = ["x", "y"].map((id) => out.get(id)!.x);
    expect(Math.min(...other)).toBeGreaterThan(Math.max(...main));
    expect(out.size).toBe(nodes.length);
  });

  it("uses barycenters to untangle a crossing", () => {
    // Discovery order puts c before d in layer 2, but c hangs off q (right) and d off p (left).
    const ns = ["r", "p", "q", "c", "d"].map(node);
    const es = [edge("r", "p"), edge("r", "q"), edge("q", "c"), edge("p", "d")];
    const out = hierarchicalLayout(ns, es, { root: "r" });
    const x = (id: string) => out.get(id)!.x;
    expect(Math.sign(x("p") - x("q"))).toBe(Math.sign(x("d") - x("c")));
  });
});

describe("radialLayout", () => {
  it("puts the root at the centre and BFS levels on growing rings", () => {
    const nodes = ["r", "a", "b", "c", "a1", "lonely"].map(node);
    const edges = [edge("r", "a"), edge("r", "b"), edge("r", "c"), edge("a", "a1")];
    const out = radialLayout(nodes, edges, { root: "r" });
    const r = (id: string) => Math.hypot(out.get(id)!.x, out.get(id)!.y);
    expect(r("r")).toBe(0);
    expect(r("a")).toBeCloseTo(r("b"), 6);
    expect(r("a1")).toBeGreaterThan(r("a"));
    expect(r("lonely")).toBeGreaterThan(r("a1"));
  });
});

describe("circularLayout", () => {
  it("places nodes on one circle sized to the node count", () => {
    const small = circularLayout(["a", "b", "c"].map(node));
    const big = circularLayout(Array.from({ length: 100 }, (_, i) => node(`n${i}`)));
    const radius = (p: Positions) => Math.hypot([...p.values()][0].x, [...p.values()][0].y);
    for (const p of small.values()) expect(Math.hypot(p.x, p.y)).toBeCloseTo(radius(small), 6);
    expect(radius(big)).toBeGreaterThan(radius(small));
    expect(circularLayout([node("solo")]).get("solo")).toEqual({ x: 0, y: 0 });
  });
});

describe("computeLayout", () => {
  it("manual keeps existing positions and fills in the rest", () => {
    const positions: Positions = new Map([["a", { x: 5, y: 6 }]]);
    const out = computeLayout("manual", [node("a"), node("b")], [edge("a", "b")], { positions });
    expect(out.get("a")).toEqual({ x: 5, y: 6 });
    expect(out.has("b")).toBe(true);
    expect(out.size).toBe(2);
  });

  it("honours pins for structured layouts", () => {
    const positions: Positions = new Map([["b", { x: 999, y: 999 }]]);
    const out = computeLayout("circular", [node("a"), node("b"), node("c")], [], { positions, pinned: new Set(["b"]) });
    expect(out.get("b")).toEqual({ x: 999, y: 999 });
  });

  it("dispatches every kind", () => {
    const { nodes, edges } = randomGraph(20, 25);
    for (const kind of ["force", "hierarchical", "radial", "circular", "manual"] as const) {
      const out = computeLayout(kind, nodes, edges, { iterations: 40 });
      expect(out.size).toBe(20);
      expect(allFinite(out)).toBe(true);
    }
  });
});

describe("fitViewport", () => {
  it("frames every position inside the canvas with padding", () => {
    const positions: Positions = new Map([
      ["a", { x: -500, y: -200 }],
      ["b", { x: 700, y: 300 }],
      ["c", { x: 0, y: 900 }],
    ]);
    const W = 1200;
    const H = 800;
    const vp = fitViewport(positions, null, W, H, 60);
    expect(vp.zoom).toBeGreaterThanOrEqual(0.05);
    expect(vp.zoom).toBeLessThanOrEqual(4);
    for (const p of positions.values()) {
      const s = worldToScreen(p, vp, W, H);
      expect(s.x).toBeGreaterThanOrEqual(60);
      expect(s.x).toBeLessThanOrEqual(W - 60);
      expect(s.y).toBeGreaterThanOrEqual(60);
      expect(s.y).toBeLessThanOrEqual(H - 60);
    }
  });

  it("fits only the requested ids", () => {
    const positions: Positions = new Map([
      ["a", { x: 0, y: 0 }],
      ["b", { x: 100, y: 0 }],
      ["far", { x: 100_000, y: 100_000 }],
    ]);
    const vp = fitViewport(positions, ["a", "b"], 800, 600);
    expect(vp.x).toBeCloseTo(50, 6);
    expect(vp.zoom).toBeGreaterThan(1);
  });

  it("clamps zoom and handles empty input", () => {
    expect(fitViewport(new Map(), null, 800, 600)).toEqual({ x: 0, y: 0, zoom: 1 });
    const huge: Positions = new Map([
      ["a", { x: -1e7, y: 0 }],
      ["b", { x: 1e7, y: 0 }],
    ]);
    expect(fitViewport(huge, null, 800, 600).zoom).toBe(0.05);
    const single: Positions = new Map([["a", { x: 3, y: 4 }]]);
    const vp = fitViewport(single, null, 800, 600);
    expect(vp.zoom).toBeLessThanOrEqual(4);
    expect(vp.x).toBe(3);
  });
});
