// SPDX-License-Identifier: Apache-2.0
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { forceLayout, mulberry32 } from "./layout";
import { prepareScene, renderToCanvas, sceneBounds, type RenderView } from "./render";
import type { GraphEdge, GraphNode, Positions, Verification } from "./types";

/** Records every method call on a fake 2D context; property writes are accepted silently. */
function mockContext() {
  const calls = new Map<string, number>();
  const texts: string[] = [];
  const state: Record<string | symbol, unknown> = {};
  const ctx = new Proxy(state, {
    get(target, prop) {
      if (prop in target) return target[prop];
      return (...args: unknown[]) => {
        const name = String(prop);
        calls.set(name, (calls.get(name) ?? 0) + 1);
        if (name === "fillText") texts.push(String(args[0]));
      };
    },
    set(target, prop, value) {
      target[prop] = value;
      return true;
    },
  });
  return { ctx: ctx as unknown as CanvasRenderingContext2D, calls, texts };
}

// Path2D is a browser API; the renderer only needs its path-building methods.
class FakePath2D {
  moveTo() {}
  lineTo() {}
  closePath() {}
}
const g = globalThis as { Path2D?: unknown };
let hadPath2D = false;
beforeAll(() => {
  hadPath2D = "Path2D" in g;
  if (!hadPath2D) g.Path2D = FakePath2D;
});
afterAll(() => {
  if (!hadPath2D) delete g.Path2D;
});

const states: Verification[] = ["observed", "verified", "inferred", "disputed", "rejected"];

function sample(n: number, m: number) {
  const rnd = mulberry32(3);
  const nodes: GraphNode[] = Array.from({ length: n }, (_, i) => ({
    id: `n${i}`,
    label: `Entity number ${i} with a fairly long descriptive label`,
    type: "t",
    color: i % 2 ? "#4c8dff" : "#e0a43a",
    glyph: "AB",
    verification: states[i % 5],
    flagged: i % 7 === 0,
    size: i % 11 === 0 ? 1.6 : 1,
  }));
  const edges: GraphEdge[] = [];
  for (let i = 1; i < n; i++) edges.push(mk(`e${i}`, `n${Math.floor(rnd() * i)}`, `n${i}`, i));
  while (edges.length < m) edges.push(mk(`x${edges.length}`, `n${Math.floor(rnd() * n)}`, `n${Math.floor(rnd() * n)}`, edges.length));
  return { nodes, edges };
  function mk(id: string, source: string, target: string, i: number): GraphEdge {
    return { id, source, target, type: "rel", label: i % 3 ? "" : "linked to", color: "#8a93a3", directed: i % 2 === 0, verification: states[i % 5] };
  }
}

describe("renderToCanvas", () => {
  const { nodes, edges } = sample(300, 600);
  const positions: Positions = forceLayout(nodes, edges, { iterations: 80 });
  const scene = prepareScene(nodes, edges, [{ id: "g", label: "Cluster", color: "#3fb68b", nodeIds: ["n1", "n2", "n3"] }]);
  const base: RenderView = { width: 1200, height: 800, pixelRatio: 2, viewport: { x: 0, y: 0, zoom: 0.4 } };

  it("draws every interaction state without throwing", () => {
    const { ctx, calls } = mockContext();
    renderToCanvas(ctx, scene, positions, {
      ...base,
      selection: { nodes: new Set(["n1", "n2"]), edge: "e3" },
      highlight: { nodes: new Set(["n1", "n2", "n3"]), edges: new Set(["e2"]) },
      hovered: { kind: "edge", id: "e4" },
      pinned: new Set(["n1"]),
      showLabels: "always",
      background: "#0b0d10",
      grid: true,
      marquee: { a: { x: 10, y: 10 }, b: { x: 100, y: 80 } },
    });
    expect(calls.get("arc")).toBeGreaterThan(300);
    expect(calls.get("save")).toBe(1);
    expect(calls.get("restore")).toBe(1);
  });

  it("batches edge strokes by style instead of one stroke per edge", () => {
    const view: RenderView = { ...base, viewport: { x: 0, y: 0, zoom: 0.05 } };
    const withEdges = mockContext();
    renderToCanvas(withEdges.ctx, scene, positions, view);
    const nodesOnly = mockContext();
    renderToCanvas(nodesOnly.ctx, prepareScene(nodes, [], scene.groups), positions, view);
    // 600 edges in 5 verification styles cost one stroke per style, not one per edge.
    const edgeStrokes = withEdges.calls.get("stroke")! - nodesOnly.calls.get("stroke")!;
    expect(edgeStrokes).toBe(scene.batches.length);
    expect(scene.batches.length).toBe(5);
  });

  it("culls nodes outside the viewport", () => {
    const wide = mockContext();
    renderToCanvas(wide.ctx, scene, positions, { ...base, viewport: { x: 0, y: 0, zoom: 0.05 } });
    const narrow = mockContext();
    renderToCanvas(narrow.ctx, scene, positions, { ...base, viewport: { x: 0, y: 0, zoom: 4 } });
    expect(narrow.calls.get("arc") ?? 0).toBeLessThan((wide.calls.get("arc") ?? 0) / 4);
  });

  it("applies label thresholds in auto mode", () => {
    const far = mockContext();
    renderToCanvas(far.ctx, scene, positions, { ...base, viewport: { x: 0, y: 0, zoom: 0.5 } });
    expect(far.texts.some((t) => t.startsWith("Entity"))).toBe(false);
    const near = mockContext();
    const p = positions.get("n0")!;
    renderToCanvas(near.ctx, scene, positions, { ...base, viewport: { x: p.x, y: p.y, zoom: 1.2 } });
    expect(near.texts.some((t) => t.startsWith("Entity"))).toBe(true);
    expect(near.texts.every((t) => Array.from(t).length <= 32)).toBe(true); // truncated
    const never = mockContext();
    renderToCanvas(never.ctx, scene, positions, { ...base, viewport: { x: p.x, y: p.y, zoom: 2 }, showLabels: "never" });
    expect(never.texts.some((t) => t.startsWith("Entity") || t === "linked to")).toBe(false);
  });

  it("computes bounds that include labels", () => {
    const b = sceneBounds(scene, positions)!;
    for (const p of positions.values()) {
      expect(p.x).toBeGreaterThan(b.minX);
      expect(p.y).toBeLessThan(b.maxY);
    }
  });
});
