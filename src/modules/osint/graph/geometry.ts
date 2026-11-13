// SPDX-License-Identifier: Apache-2.0
/**
 * Pure geometry helpers: coordinate conversion, hit testing, zooming and hulls.
 * Everything here is DOM-free so it can be unit-tested in node.
 */
import { NODE_RADIUS } from "./style";
import type { Bounds, GraphEdge, GraphNode, Point, Positions, Viewport } from "./types";

export const MIN_ZOOM = 0.05;
export const MAX_ZOOM = 4;

export function clampZoom(zoom: number): number {
  if (!Number.isFinite(zoom)) return 1;
  return Math.min(MAX_ZOOM, Math.max(MIN_ZOOM, zoom));
}

export function worldToScreen(p: Point, vp: Viewport, width: number, height: number): Point {
  return { x: (p.x - vp.x) * vp.zoom + width / 2, y: (p.y - vp.y) * vp.zoom + height / 2 };
}

export function screenToWorld(p: Point, vp: Viewport, width: number, height: number): Point {
  return { x: (p.x - width / 2) / vp.zoom + vp.x, y: (p.y - height / 2) / vp.zoom + vp.y };
}

/**
 * Zoom by `factor`, keeping the world point under `screenPoint` fixed on screen
 * (zoom-at-cursor). The resulting zoom is clamped to [MIN_ZOOM, MAX_ZOOM].
 */
export function zoomAt(vp: Viewport, factor: number, screenPoint: Point, width: number, height: number): Viewport {
  const zoom = clampZoom(vp.zoom * factor);
  const anchor = screenToWorld(screenPoint, vp, width, height);
  return {
    x: anchor.x - (screenPoint.x - width / 2) / zoom,
    y: anchor.y - (screenPoint.y - height / 2) / zoom,
    zoom,
  };
}

export function nodeRadius(node: { size?: number }): number {
  const s = node.size;
  return NODE_RADIUS * (typeof s === "number" && Number.isFinite(s) && s > 0 ? s : 1);
}

export function boundsOf(positions: Positions, ids?: Iterable<string> | null): Bounds | null {
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  const visit = (p: Point | undefined) => {
    if (!p || !Number.isFinite(p.x) || !Number.isFinite(p.y)) return;
    if (p.x < minX) minX = p.x;
    if (p.x > maxX) maxX = p.x;
    if (p.y < minY) minY = p.y;
    if (p.y > maxY) maxY = p.y;
  };
  if (ids) for (const id of ids) visit(positions.get(id));
  else for (const p of positions.values()) visit(p);
  return minX === Infinity ? null : { minX, minY, maxX, maxY };
}

// ---------------------------------------------------------------------------
// Edge geometry
// ---------------------------------------------------------------------------

/** Spacing between parallel edges, as a fraction of the edge length. */
const PARALLEL_STEP = 0.22;

/**
 * Signed curvature per edge. Edges sharing an unordered node pair fan out symmetrically;
 * a lone edge is straight (0). The sign is relative to each edge's own direction, so
 * A→B and B→A between the same pair bow to opposite sides instead of overlapping.
 */
export function edgeCurvatures(edges: readonly GraphEdge[]): Map<string, number> {
  const groups = new Map<string, GraphEdge[]>();
  for (const e of edges) {
    if (e.source === e.target) continue;
    const key = e.source < e.target ? `${e.source}\u0000${e.target}` : `${e.target}\u0000${e.source}`;
    const g = groups.get(key);
    if (g) g.push(e);
    else groups.set(key, [e]);
  }
  const out = new Map<string, number>();
  for (const g of groups.values()) {
    if (g.length === 1) {
      out.set(g[0].id, 0);
      continue;
    }
    const mid = (g.length - 1) / 2;
    g.forEach((e, k) => {
      const c = (k - mid) * PARALLEL_STEP;
      out.set(e.id, e.source < e.target ? c : -c);
    });
  }
  return out;
}

/** Quadratic control point for a curved edge, or null when the edge is straight. */
export function edgeControlPoint(s: Point, t: Point, curvature: number): Point | null {
  if (!curvature) return null;
  // Perpendicular (-dy, dx) scaled by curvature × length = curvature × (-dy, dx).
  return { x: (s.x + t.x) / 2 - (t.y - s.y) * curvature, y: (s.y + t.y) / 2 + (t.x - s.x) * curvature };
}

/** Mutable scratch record so the renderer can compute edge geometry without allocating. */
export interface EdgeGeom {
  sx: number;
  sy: number;
  cx: number;
  cy: number;
  ex: number;
  ey: number;
  curved: boolean;
  /** Arrow tip (on the target node's rim) and the unit direction of travel there. */
  tipX: number;
  tipY: number;
  ux: number;
  uy: number;
}

export function createEdgeGeom(): EdgeGeom {
  return { sx: 0, sy: 0, cx: 0, cy: 0, ex: 0, ey: 0, curved: false, tipX: 0, tipY: 0, ux: 0, uy: 0 };
}

/**
 * Computes a drawable edge clipped to the node rims. When `arrowLen` > 0 the stroke
 * stops short of the tip so a dashed line does not poke through the arrowhead.
 * Returns false when the nodes overlap and there is nothing visible to draw.
 */
export function computeEdgeGeom(
  out: EdgeGeom,
  sx: number,
  sy: number,
  tx: number,
  ty: number,
  rs: number,
  rt: number,
  curvature: number,
  arrowLen: number,
): boolean {
  const dx = tx - sx;
  const dy = ty - sy;
  const len = Math.hypot(dx, dy);
  if (len <= rs + rt + 0.5) return false;
  const curved = curvature !== 0;
  const cx = curved ? (sx + tx) / 2 - dy * curvature : (sx + tx) / 2;
  const cy = curved ? (sy + ty) / 2 + dx * curvature : (sy + ty) / 2;
  // Leave the source along the initial tangent (towards the control point).
  let ax = (curved ? cx : tx) - sx;
  let ay = (curved ? cy : ty) - sy;
  let al = Math.hypot(ax, ay) || 1;
  out.sx = sx + (ax / al) * rs;
  out.sy = sy + (ay / al) * rs;
  // Arrive along the final tangent (from the control point).
  ax = tx - (curved ? cx : sx);
  ay = ty - (curved ? cy : sy);
  al = Math.hypot(ax, ay) || 1;
  const ux = ax / al;
  const uy = ay / al;
  out.ux = ux;
  out.uy = uy;
  out.tipX = tx - ux * rt;
  out.tipY = ty - uy * rt;
  const back = arrowLen > 0 ? arrowLen * 0.8 : 0;
  out.ex = out.tipX - ux * back;
  out.ey = out.tipY - uy * back;
  out.cx = cx;
  out.cy = cy;
  out.curved = curved;
  return true;
}

/** Circle used to draw a self-loop above a node of radius r. */
export function selfLoopCircle(x: number, y: number, r: number): { cx: number; cy: number; r: number } {
  const lr = Math.max(r * 0.62, 7);
  return { cx: x, cy: y - r - lr * 0.45, r: lr };
}

export function quadraticPoint(a: Point, c: Point, b: Point, t: number): Point {
  const u = 1 - t;
  return { x: u * u * a.x + 2 * u * t * c.x + t * t * b.x, y: u * u * a.y + 2 * u * t * c.y + t * t * b.y };
}

export function distanceToSegment(p: Point, a: Point, b: Point): number {
  return segDist(p.x, p.y, a.x, a.y, b.x, b.y);
}

function segDist(px: number, py: number, ax: number, ay: number, bx: number, by: number): number {
  const dx = bx - ax;
  const dy = by - ay;
  const l2 = dx * dx + dy * dy;
  let t = l2 > 0 ? ((px - ax) * dx + (py - ay) * dy) / l2 : 0;
  t = t < 0 ? 0 : t > 1 ? 1 : t;
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
}

/** Distance to a quadratic Bézier, approximated by a polyline (accurate to well under a pixel for gentle curves). */
export function distanceToQuadratic(p: Point, a: Point, c: Point, b: Point, segments = 16): number {
  let best = Infinity;
  let px = a.x;
  let py = a.y;
  for (let i = 1; i <= segments; i++) {
    const t = i / segments;
    const u = 1 - t;
    const x = u * u * a.x + 2 * u * t * c.x + t * t * b.x;
    const y = u * u * a.y + 2 * u * t * c.y + t * t * b.y;
    const d = segDist(p.x, p.y, px, py, x, y);
    if (d < best) best = d;
    px = x;
    py = y;
  }
  return best;
}

// ---------------------------------------------------------------------------
// Hit testing
// ---------------------------------------------------------------------------

/**
 * Topmost node under a world-space point. A few screen pixels of slack make small
 * nodes easy to grab when zoomed out. Later nodes are drawn on top, so they win ties.
 */
export function hitTestNode(
  positions: Positions,
  nodes: readonly GraphNode[],
  point: Point,
  zoom: number,
  tolerancePx = 3,
): string | null {
  const slack = tolerancePx / zoom;
  let best: string | null = null;
  let bestD = Infinity;
  for (let i = nodes.length - 1; i >= 0; i--) {
    const n = nodes[i];
    const p = positions.get(n.id);
    if (!p) continue;
    const r = nodeRadius(n) + slack;
    const dx = point.x - p.x;
    const dy = point.y - p.y;
    if (Math.abs(dx) > r || Math.abs(dy) > r) continue;
    const d = Math.hypot(dx, dy);
    // Prefer the node whose centre is closest (relative to its size) when nodes overlap.
    if (d <= r && d / r < bestD) {
      bestD = d / r;
      best = n.id;
    }
  }
  return best;
}

export interface EdgeHitOptions {
  tolerancePx?: number;
  curvatures?: Map<string, number>;
  /** Node radius lookup (for self-loops); defaults to NODE_RADIUS. */
  radiusOf?: (id: string) => number;
}

/** Nearest edge within `tolerancePx` screen pixels of a world-space point. */
export function hitTestEdge(
  positions: Positions,
  edges: readonly GraphEdge[],
  point: Point,
  zoom: number,
  opts: EdgeHitOptions = {},
): string | null {
  const tol = (opts.tolerancePx ?? 6) / zoom;
  const curv = opts.curvatures ?? edgeCurvatures(edges);
  let best: string | null = null;
  let bestD = tol;
  for (let i = edges.length - 1; i >= 0; i--) {
    const e = edges[i];
    const s = positions.get(e.source);
    const t = positions.get(e.target);
    if (!s || !t) continue;
    let d: number;
    if (e.source === e.target) {
      const loop = selfLoopCircle(s.x, s.y, opts.radiusOf ? opts.radiusOf(e.source) : NODE_RADIUS);
      d = Math.abs(Math.hypot(point.x - loop.cx, point.y - loop.cy) - loop.r);
    } else {
      const c = edgeControlPoint(s, t, curv.get(e.id) ?? 0);
      // Cheap bounding-box rejection before the exact distance.
      const minX = Math.min(s.x, t.x, c ? c.x : s.x) - tol;
      const maxX = Math.max(s.x, t.x, c ? c.x : s.x) + tol;
      const minY = Math.min(s.y, t.y, c ? c.y : s.y) - tol;
      const maxY = Math.max(s.y, t.y, c ? c.y : s.y) + tol;
      if (point.x < minX || point.x > maxX || point.y < minY || point.y > maxY) continue;
      d = c ? distanceToQuadratic(point, s, c, t) : distanceToSegment(point, s, t);
    }
    if (d <= bestD) {
      bestD = d;
      best = e.id;
    }
  }
  return best;
}

/** Ids of nodes whose centres fall inside the rectangle spanned by two world points. */
export function nodesInRect(positions: Positions, nodes: readonly GraphNode[], a: Point, b: Point): string[] {
  const minX = Math.min(a.x, b.x);
  const maxX = Math.max(a.x, b.x);
  const minY = Math.min(a.y, b.y);
  const maxY = Math.max(a.y, b.y);
  const out: string[] = [];
  for (const n of nodes) {
    const p = positions.get(n.id);
    if (p && p.x >= minX && p.x <= maxX && p.y >= minY && p.y <= maxY) out.push(n.id);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Hulls
// ---------------------------------------------------------------------------

/** Convex hull (Andrew's monotone chain), counter-clockwise in a y-up frame, no collinear points. */
export function convexHull(points: readonly Point[]): Point[] {
  const pts = points
    .filter((p) => Number.isFinite(p.x) && Number.isFinite(p.y))
    .slice()
    .sort((a, b) => a.x - b.x || a.y - b.y);
  if (pts.length <= 2) {
    if (pts.length === 2 && pts[0].x === pts[1].x && pts[0].y === pts[1].y) return [pts[0]];
    return pts;
  }
  const cross = (o: Point, a: Point, b: Point) => (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
  const lower: Point[] = [];
  for (const p of pts) {
    while (lower.length >= 2 && cross(lower[lower.length - 2], lower[lower.length - 1], p) <= 0) lower.pop();
    lower.push(p);
  }
  const upper: Point[] = [];
  for (let i = pts.length - 1; i >= 0; i--) {
    const p = pts[i];
    while (upper.length >= 2 && cross(upper[upper.length - 2], upper[upper.length - 1], p) <= 0) upper.pop();
    upper.push(p);
  }
  lower.pop();
  upper.pop();
  const hull = lower.concat(upper);
  return hull.length ? hull : [pts[0]];
}

/**
 * Hull of discs of radius `pad` around each point: a padded, rounded outline that
 * works for 1 point (circle), 2 points (capsule) and collinear members alike.
 */
export function paddedHull(points: readonly Point[], pad: number, segments = 12): Point[] {
  if (points.length === 0) return [];
  const ring: Point[] = [];
  // Only hull vertices can contribute to the padded hull, which keeps big groups cheap.
  const core = points.length > 3 ? convexHull(points) : points;
  for (const p of core) {
    for (let k = 0; k < segments; k++) {
      const a = (k / segments) * Math.PI * 2;
      ring.push({ x: p.x + Math.cos(a) * pad, y: p.y + Math.sin(a) * pad });
    }
  }
  return convexHull(ring);
}
