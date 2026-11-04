/**
 * Canvas 2D renderer shared by the interactive GraphCanvas and the PNG exporter.
 *
 * Performance notes (target: smooth at ~1,500 nodes / 3,000 edges):
 *  - Per-graph work (colour sanitising, label truncation, parallel-edge curvature,
 *    batching edges by stroke style) happens once in `prepareScene`, not per frame.
 *  - Edges are stroked in one path per (colour, verification) batch.
 *  - Everything outside the viewport is culled; glyphs, arrowheads and dashes are
 *    skipped when zoomed far out; labels obey the zoom thresholds.
 *  - Drawing happens in world space under a single transform; line widths are divided
 *    by the zoom so strokes stay a constant number of screen pixels.
 */
import { computeEdgeGeom, createEdgeGeom, edgeCurvatures, nodeRadius, paddedHull, selfLoopCircle } from "./geometry";
import {
  cleanGlyph,
  DIM_EDGE_ALPHA,
  DIM_NODE_ALPHA,
  EDGE_STYLES,
  type EdgeStyle,
  FONT_FAMILY,
  inkFor,
  NODE_RING_STYLES,
  safeColor,
  THEME,
  truncateLabel,
} from "./style";
import type { Bounds, GraphEdge, GraphGroup, GraphNode, Highlight, Point, Positions, Selection, Verification, Viewport } from "./types";

const TAU = Math.PI * 2;
const EMPTY_DASH: number[] = [];

export interface EdgeBatch {
  color: string;
  style: EdgeStyle;
  edges: GraphEdge[];
}

export interface NodeBatch {
  fill: string;
  verification: Verification;
  indices: number[];
}

/** Per-graph derived data. Rebuild when nodes, edges or groups change (not per frame). */
export interface PreparedScene {
  nodes: readonly GraphNode[];
  edges: readonly GraphEdge[];
  groups: readonly GraphGroup[];
  nodeIndex: Map<string, number>;
  edgeById: Map<string, GraphEdge>;
  radius: Float64Array;
  fill: string[];
  ink: string[];
  glyph: string[];
  label: string[];
  edgeLabel: Map<string, string>;
  edgeColor: Map<string, string>;
  curvature: Map<string, number>;
  batches: EdgeBatch[];
  /** Node indices grouped by (fill colour, verification) for batched drawing. */
  nodeBatches: NodeBatch[];
  maxRadius: number;
  /** Group hulls are cached per positions object (recomputed only when positions change). */
  hullCache: { positions: Positions | null; hulls: Map<string, Point[]> };
}

export function prepareScene(nodes: readonly GraphNode[], edges: readonly GraphEdge[], groups: readonly GraphGroup[] = []): PreparedScene {
  const nodeIndex = new Map<string, number>();
  const radius = new Float64Array(nodes.length);
  const fill: string[] = [];
  const ink: string[] = [];
  const glyph: string[] = [];
  const label: string[] = [];
  let maxRadius = 0;
  nodes.forEach((n, i) => {
    if (!nodeIndex.has(n.id)) nodeIndex.set(n.id, i);
    radius[i] = nodeRadius(n);
    if (radius[i] > maxRadius) maxRadius = radius[i];
    const f = safeColor(n.color, THEME.muted);
    fill.push(f);
    ink.push(inkFor(f));
    glyph.push(cleanGlyph(String(n.glyph ?? "")));
    label.push(truncateLabel(String(n.label ?? "")));
  });

  const nodeBatchMap = new Map<string, NodeBatch>();
  nodes.forEach((n, i) => {
    const verification: Verification = n.verification in NODE_RING_STYLES ? n.verification : "observed";
    const key = `${verification}|${fill[i]}`;
    let b = nodeBatchMap.get(key);
    if (!b) {
      b = { fill: fill[i], verification, indices: [] };
      nodeBatchMap.set(key, b);
    }
    b.indices.push(i);
  });

  const edgeById = new Map<string, GraphEdge>();
  const edgeLabel = new Map<string, string>();
  const edgeColor = new Map<string, string>();
  const batchMap = new Map<string, EdgeBatch>();
  for (const e of edges) {
    edgeById.set(e.id, e);
    const style = EDGE_STYLES[e.verification] ?? EDGE_STYLES.observed;
    const color = style.color ?? safeColor(e.color, THEME.muted);
    edgeColor.set(e.id, color);
    if (e.label) edgeLabel.set(e.id, truncateLabel(String(e.label), 32));
    const key = `${e.verification}|${color}`;
    let b = batchMap.get(key);
    if (!b) {
      b = { color, style, edges: [] };
      batchMap.set(key, b);
    }
    b.edges.push(e);
  }
  // Fainter styles first so stronger evidence is drawn on top.
  const batches = [...batchMap.values()].sort((a, b) => a.style.alpha - b.style.alpha);

  return {
    nodes,
    edges,
    groups,
    nodeIndex,
    edgeById,
    radius,
    fill,
    ink,
    glyph,
    label,
    edgeLabel,
    edgeColor,
    curvature: edgeCurvatures(edges),
    batches,
    nodeBatches: [...nodeBatchMap.values()],
    maxRadius: maxRadius || 16,
    hullCache: { positions: null, hulls: new Map() },
  };
}

/** Padded hull outline per group, from member positions (cached per positions object). */
export function groupHulls(scene: PreparedScene, positions: Positions): Map<string, Point[]> {
  if (scene.hullCache.positions === positions) return scene.hullCache.hulls;
  const hulls = new Map<string, Point[]>();
  for (const g of scene.groups) {
    const pts: Point[] = [];
    let pad = 0;
    for (const id of g.nodeIds) {
      const p = positions.get(id);
      if (!p) continue;
      pts.push(p);
      const i = scene.nodeIndex.get(id);
      pad = Math.max(pad, i === undefined ? 16 : scene.radius[i]);
    }
    if (pts.length) hulls.set(g.id, paddedHull(pts, pad + 16));
  }
  scene.hullCache = { positions, hulls };
  return hulls;
}

/** World-space bounds of everything drawn (nodes, rings, labels underneath). */
export function sceneBounds(scene: PreparedScene, positions: Positions, withLabels = true): Bounds | null {
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  scene.nodes.forEach((n, i) => {
    const p = positions.get(n.id);
    if (!p || !Number.isFinite(p.x) || !Number.isFinite(p.y)) return;
    const r = scene.radius[i] + 8;
    // Labels are ~6.4 px per character at 11 px; they hang below the node.
    const half = withLabels ? Math.max(r, scene.label[i].length * 3.2) : r;
    minX = Math.min(minX, p.x - half);
    maxX = Math.max(maxX, p.x + half);
    minY = Math.min(minY, p.y - r);
    maxY = Math.max(maxY, p.y + r + (withLabels && scene.label[i] ? 18 : 0));
  });
  for (const hull of groupHulls(scene, positions).values()) {
    for (const p of hull) {
      minX = Math.min(minX, p.x);
      maxX = Math.max(maxX, p.x);
      minY = Math.min(minY, p.y - 18); // room for the group label above the hull
      maxY = Math.max(maxY, p.y);
    }
  }
  return minX === Infinity ? null : { minX, minY, maxX, maxY };
}

export type HoverTarget = { kind: "node" | "edge"; id: string };
export type LabelMode = "auto" | "always" | "never";

export interface RenderView {
  /** CSS pixel size of the drawing surface. */
  width: number;
  height: number;
  /** Backing-store pixels per CSS pixel (devicePixelRatio, or the export scale). */
  pixelRatio: number;
  viewport: Viewport;
  selection?: Selection | null;
  highlight?: Highlight | null;
  hovered?: HoverTarget | null;
  pinned?: ReadonlySet<string> | null;
  showLabels?: LabelMode;
  /** Opaque fill behind everything; null/undefined leaves the canvas transparent. */
  background?: string | null;
  grid?: boolean;
  /** Selection rectangle in screen (CSS px) coordinates. */
  marquee?: { a: Point; b: Point } | null;
}

/** Below this zoom node labels are hidden in "auto" mode. */
export const NODE_LABEL_MIN_ZOOM = 0.55;
/** Below this zoom edge labels are hidden in "auto" mode. */
export const EDGE_LABEL_MIN_ZOOM = 1.1;
/** Below this zoom glyphs, arrowheads, dashes and pins are skipped. */
const DETAIL_MIN_ZOOM = 0.28;
/** Cap on labels drawn per frame in auto mode (selected/hovered always get theirs). */
const LABEL_BUDGET = 900;

interface FrameInfo {
  px: number;
  zoom: number;
  dpr: number;
  detail: boolean;
  /** Stroke thinning when zoomed out, so the overview reads as structure rather than a hairball. */
  lineScale: number;
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
}

const geom = createEdgeGeom();

export function renderToCanvas(ctx: CanvasRenderingContext2D, scene: PreparedScene, positions: Positions, view: RenderView): void {
  const { width, height, viewport: vp } = view;
  const dpr = view.pixelRatio > 0 ? view.pixelRatio : 1;
  const zoom = vp.zoom > 0 ? vp.zoom : 1;
  const px = 1 / zoom;

  ctx.save();
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.globalAlpha = 1;
  ctx.shadowBlur = 0;
  ctx.setLineDash(EMPTY_DASH);
  ctx.clearRect(0, 0, width * dpr, height * dpr);
  if (view.background) {
    ctx.fillStyle = safeColor(view.background, THEME.background);
    ctx.fillRect(0, 0, width * dpr, height * dpr);
  }
  if (view.grid) drawGrid(ctx, vp, width, height, dpr);

  ctx.setTransform(dpr * zoom, 0, 0, dpr * zoom, dpr * (width / 2 - vp.x * zoom), dpr * (height / 2 - vp.y * zoom));
  const margin = scene.maxRadius + 12 + 40 * px;
  const f: FrameInfo = {
    px,
    zoom,
    dpr,
    detail: zoom >= DETAIL_MIN_ZOOM,
    lineScale: Math.min(1, Math.max(0.5, Math.sqrt(zoom * 1.6))),
    minX: vp.x - (width / 2) * px - margin,
    maxX: vp.x + (width / 2) * px + margin,
    minY: vp.y - (height / 2) * px - margin,
    maxY: vp.y + (height / 2) * px + margin,
  };
  const mode = view.showLabels ?? "auto";
  ctx.lineJoin = "round";
  ctx.textAlign = "center";

  drawGroups(ctx, scene, positions, view, f);
  drawEdges(ctx, scene, positions, view, f);
  if (mode === "always" || (mode === "auto" && zoom >= EDGE_LABEL_MIN_ZOOM)) drawEdgeLabels(ctx, scene, positions, view, f);
  drawNodes(ctx, scene, positions, view, f);
  if (mode === "always" || (mode === "auto" && zoom >= NODE_LABEL_MIN_ZOOM)) drawNodeLabels(ctx, scene, positions, view, f, mode === "auto");

  if (view.marquee) {
    const { a, b } = view.marquee;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.setLineDash(EMPTY_DASH);
    const x = Math.min(a.x, b.x);
    const y = Math.min(a.y, b.y);
    const w = Math.abs(a.x - b.x);
    const h = Math.abs(a.y - b.y);
    ctx.globalAlpha = 0.1;
    ctx.fillStyle = THEME.accent;
    ctx.fillRect(x, y, w, h);
    ctx.globalAlpha = 0.75;
    ctx.strokeStyle = THEME.accent;
    ctx.lineWidth = 1;
    ctx.strokeRect(x + 0.5, y + 0.5, w, h);
  }
  ctx.restore();
}

function drawGrid(ctx: CanvasRenderingContext2D, vp: Viewport, width: number, height: number, dpr: number): void {
  // Spacing is a power-of-two multiple of 40 world units, kept between 18 and 72 px on
  // screen, so dots stay aligned to world space while their density stays comfortable.
  let step = 40 * vp.zoom;
  while (step < 18) step *= 2;
  while (step > 72) step /= 2;
  const ox = (((width / 2 - vp.x * vp.zoom) % step) + step) % step;
  const oy = (((height / 2 - vp.y * vp.zoom) % step) + step) % step;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.globalAlpha = 1;
  ctx.fillStyle = "rgba(255, 255, 255, 0.055)";
  ctx.beginPath();
  const s = 1.4;
  for (let x = ox; x < width; x += step) {
    for (let y = oy; y < height; y += step) ctx.rect(x - s / 2, y - s / 2, s, s);
  }
  ctx.fill();
}

function scaledDash(dash: readonly number[], px: number): number[] {
  return dash.length ? dash.map((d) => d * px) : EMPTY_DASH;
}

/** Traces a smooth closed curve through the midpoints of a polygon's sides. */
function traceSmoothHull(ctx: CanvasRenderingContext2D, hull: readonly Point[]): void {
  const n = hull.length;
  const mid = (i: number) => {
    const a = hull[i % n];
    const b = hull[(i + 1) % n];
    return { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
  };
  const m0 = mid(0);
  ctx.moveTo(m0.x, m0.y);
  for (let i = 1; i <= n; i++) {
    const p = hull[i % n];
    const m = mid(i);
    ctx.quadraticCurveTo(p.x, p.y, m.x, m.y);
  }
  ctx.closePath();
}

function drawHaloText(ctx: CanvasRenderingContext2D, text: string, x: number, y: number, px: number, color: string, alpha: number): void {
  ctx.globalAlpha = alpha;
  ctx.lineWidth = 3 * px;
  ctx.strokeStyle = THEME.halo;
  ctx.strokeText(text, x, y);
  ctx.fillStyle = color;
  ctx.fillText(text, x, y);
}

function drawGroups(ctx: CanvasRenderingContext2D, scene: PreparedScene, positions: Positions, view: RenderView, f: FrameInfo): void {
  if (!scene.groups.length) return;
  const hulls = groupHulls(scene, positions);
  const dimmed = !!view.highlight;
  ctx.setLineDash(EMPTY_DASH);
  for (const g of scene.groups) {
    const hull = hulls.get(g.id);
    if (!hull || hull.length < 3) continue;
    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;
    let top = hull[0];
    for (const p of hull) {
      if (p.x < minX) minX = p.x;
      if (p.x > maxX) maxX = p.x;
      if (p.y > maxY) maxY = p.y;
      if (p.y < minY) {
        minY = p.y;
        top = p;
      }
    }
    if (maxX < f.minX || minX > f.maxX || maxY < f.minY || minY > f.maxY) continue;
    const color = safeColor(g.color, THEME.accent);
    ctx.beginPath();
    traceSmoothHull(ctx, hull);
    ctx.fillStyle = color;
    ctx.globalAlpha = dimmed ? 0.04 : 0.085;
    ctx.fill();
    ctx.strokeStyle = color;
    ctx.globalAlpha = dimmed ? 0.1 : 0.26;
    ctx.lineWidth = f.px;
    ctx.stroke();
    if (g.label && f.zoom >= 0.2) {
      ctx.font = `600 ${11 * f.px}px ${FONT_FAMILY}`;
      ctx.textBaseline = "bottom";
      drawHaloText(ctx, truncateLabel(g.label, 40), top.x, minY - 4 * f.px, f.px, color, dimmed ? 0.35 : 0.95);
    }
  }
}

/** Adds the visible part of an edge to the current path; false if culled or degenerate. */
function traceEdge(ctx: CanvasRenderingContext2D, scene: PreparedScene, positions: Positions, e: GraphEdge, f: FrameInfo, arrowLen: number): boolean {
  const s = positions.get(e.source);
  const t = positions.get(e.target);
  if (!s || !t) return false;
  const si = scene.nodeIndex.get(e.source);
  const ti = scene.nodeIndex.get(e.target);
  if (si === undefined || ti === undefined) return false;
  if (si === ti) {
    const loop = selfLoopCircle(s.x, s.y, scene.radius[si]);
    if (loop.cx + loop.r < f.minX || loop.cx - loop.r > f.maxX || loop.cy + loop.r < f.minY || loop.cy - loop.r > f.maxY) return false;
    ctx.moveTo(loop.cx + loop.r, loop.cy);
    ctx.arc(loop.cx, loop.cy, loop.r, 0, TAU);
    return true;
  }
  const curv = scene.curvature.get(e.id) ?? 0;
  // Cull on the bounding box of endpoints (+ control point for curves).
  let minX = Math.min(s.x, t.x);
  let maxX = Math.max(s.x, t.x);
  let minY = Math.min(s.y, t.y);
  let maxY = Math.max(s.y, t.y);
  if (curv) {
    const cx = (s.x + t.x) / 2 - (t.y - s.y) * curv;
    const cy = (s.y + t.y) / 2 + (t.x - s.x) * curv;
    minX = Math.min(minX, cx);
    maxX = Math.max(maxX, cx);
    minY = Math.min(minY, cy);
    maxY = Math.max(maxY, cy);
  }
  if (maxX < f.minX || minX > f.maxX || maxY < f.minY || minY > f.maxY) return false;
  if (!computeEdgeGeom(geom, s.x, s.y, t.x, t.y, scene.radius[si], scene.radius[ti], curv, e.directed ? arrowLen : 0)) return false;
  ctx.moveTo(geom.sx, geom.sy);
  if (geom.curved) ctx.quadraticCurveTo(geom.cx, geom.cy, geom.ex, geom.ey);
  else ctx.lineTo(geom.ex, geom.ey);
  return true;
}

function traceArrow(path: Path2D, len: number): void {
  const bx = geom.tipX - geom.ux * len;
  const by = geom.tipY - geom.uy * len;
  const hw = len * 0.42;
  path.moveTo(geom.tipX, geom.tipY);
  path.lineTo(bx - geom.uy * hw, by + geom.ux * hw);
  path.lineTo(bx + geom.uy * hw, by - geom.ux * hw);
  path.closePath();
}

function arrowLength(style: EdgeStyle, px: number): number {
  // Constant on screen, but never larger than ~60% of a node at low zoom.
  return Math.min((7 + style.width * 1.5) * px, 11);
}

function drawEdges(ctx: CanvasRenderingContext2D, scene: PreparedScene, positions: Positions, view: RenderView, f: FrameInfo): void {
  const hl = view.highlight;
  const selected = view.selection?.edge ?? null;
  const hovered = view.hovered?.kind === "edge" ? view.hovered.id : null;
  const passes = hl ? [0, 1] : [1];
  ctx.shadowBlur = 0;

  for (const batch of scene.batches) {
    const st = batch.style;
    const len = f.detail ? arrowLength(st, f.px) : 0;
    const dash = f.detail ? scaledDash(st.dash, f.px) : EMPTY_DASH;
    ctx.strokeStyle = batch.color;
    ctx.fillStyle = batch.color;
    ctx.lineWidth = st.width * f.lineScale * f.px;
    ctx.lineCap = st.cap;
    for (const pass of passes) {
      ctx.globalAlpha = pass === 0 ? DIM_EDGE_ALPHA * Math.min(1, st.alpha * 1.6) : st.alpha;
      ctx.setLineDash(dash);
      ctx.beginPath();
      let any = false;
      let arrows: Path2D | null = null;
      for (const e of batch.edges) {
        if (hl && (hl.edges.has(e.id) ? 1 : 0) !== pass) continue;
        if (e.id === selected || e.id === hovered) continue;
        if (!traceEdge(ctx, scene, positions, e, f, len)) continue;
        any = true;
        if (len > 0 && e.directed && e.source !== e.target) traceArrow((arrows ??= new Path2D()), len);
      }
      if (any) ctx.stroke();
      if (arrows) {
        ctx.setLineDash(EMPTY_DASH);
        ctx.fill(arrows);
      }
    }
  }

  // Selected and hovered edges are drawn last, thicker and on top.
  for (const id of [hovered, selected]) {
    if (!id) continue;
    const e = scene.edgeById.get(id);
    if (!e) continue;
    const st = EDGE_STYLES[e.verification] ?? EDGE_STYLES.observed;
    const isSel = id === selected;
    const color = isSel ? THEME.accent : (scene.edgeColor.get(id) ?? THEME.muted);
    const len = arrowLength(st, f.px) + f.px;
    ctx.globalAlpha = hl && !hl.edges.has(id) && !isSel ? 0.4 : 1;
    ctx.strokeStyle = color;
    ctx.fillStyle = color;
    ctx.lineWidth = (st.width + (isSel ? 1.5 : 1)) * f.px;
    ctx.lineCap = st.cap;
    ctx.setLineDash(scaledDash(st.dash, f.px));
    if (isSel) {
      ctx.shadowColor = THEME.accent;
      ctx.shadowBlur = 8 * f.dpr;
    }
    ctx.beginPath();
    if (traceEdge(ctx, scene, positions, e, f, len)) {
      ctx.stroke();
      if (e.directed && e.source !== e.target) {
        const arrow = new Path2D();
        traceArrow(arrow, len);
        ctx.setLineDash(EMPTY_DASH);
        ctx.fill(arrow);
      }
    }
    ctx.shadowBlur = 0;
  }
  ctx.lineCap = "butt";
}

function drawEdgeLabels(ctx: CanvasRenderingContext2D, scene: PreparedScene, positions: Positions, view: RenderView, f: FrameInfo): void {
  if (!scene.edgeLabel.size) return;
  const hl = view.highlight;
  ctx.font = `${10 * f.px}px ${FONT_FAMILY}`;
  ctx.textBaseline = "middle";
  ctx.setLineDash(EMPTY_DASH);
  for (const [id, text] of scene.edgeLabel) {
    if (hl && !hl.edges.has(id)) continue;
    const e = scene.edgeById.get(id)!;
    const s = positions.get(e.source);
    const t = positions.get(e.target);
    if (!s || !t || e.source === e.target) continue;
    const curv = scene.curvature.get(id) ?? 0;
    // Midpoint of the quadratic (t = 0.5) = mid + half the control offset.
    const x = (s.x + t.x) / 2 - ((t.y - s.y) * curv) / 2;
    const y = (s.y + t.y) / 2 + ((t.x - s.x) * curv) / 2;
    if (x < f.minX || x > f.maxX || y < f.minY || y > f.maxY) continue;
    const isSel = view.selection?.edge === id;
    drawHaloText(ctx, text, x, y, f.px, isSel ? THEME.foreground : THEME.muted, isSel ? 1 : 0.9);
  }
}

function drawNodes(ctx: CanvasRenderingContext2D, scene: PreparedScene, positions: Positions, view: RenderView, f: FrameInfo): void {
  const hl = view.highlight;
  const sel = view.selection?.nodes;
  const hovered = view.hovered?.kind === "node" ? view.hovered.id : null;
  const pinned = view.pinned;
  const nodes = scene.nodes;
  ctx.textBaseline = "middle";
  ctx.lineCap = "butt";
  let currentFont = "";
  const setFont = (r: number) => {
    const font = `600 ${Math.round(r * 9) / 10}px ${FONT_FAMILY}`;
    if (font !== currentFont) {
      ctx.font = font;
      currentFont = font;
    }
  };

  // Regular nodes are drawn in batches — one fill and one ring stroke per (fill colour ×
  // verification) — which is what keeps 1,500+ nodes cheap. Pass 0 = dimmed, 1 = normal.
  // Selected nodes are skipped here and drawn individually on top.
  for (let pass = hl ? 0 : 1; pass <= 1; pass++) {
    const alpha = pass === 0 ? DIM_NODE_ALPHA : 1;
    const visible = scratchVisible;
    visible.length = 0;
    for (const batch of scene.nodeBatches) {
      const ring = NODE_RING_STYLES[batch.verification];
      const first = visible.length;
      ctx.beginPath();
      for (const i of batch.indices) {
        const id = nodes[i].id;
        if (sel?.has(id)) continue;
        if (hl && (hl.nodes.has(id) ? 1 : 0) !== pass) continue;
        const p = positions.get(id);
        if (!p) continue;
        const r = scene.radius[i];
        if (p.x + r < f.minX || p.x - r > f.maxX || p.y + r < f.minY || p.y - r > f.maxY) continue;
        ctx.moveTo(p.x + r, p.y);
        ctx.arc(p.x, p.y, r, 0, TAU);
        visible.push(i);
      }
      if (visible.length === first) continue;
      ctx.globalAlpha = alpha * ring.bodyAlpha;
      ctx.fillStyle = batch.fill;
      ctx.fill();
      ctx.globalAlpha = alpha * ring.alpha;
      ctx.strokeStyle = ring.color;
      ctx.lineWidth = ring.width * f.lineScale * f.px;
      ctx.setLineDash(f.detail ? scaledDash(ring.dash, f.px) : EMPTY_DASH);
      ctx.stroke();
    }
    ctx.setLineDash(EMPTY_DASH);

    // Danger rings for flagged nodes: a single stroke for all of them.
    ctx.beginPath();
    let anyFlagged = false;
    for (const i of visible) {
      if (!nodes[i].flagged) continue;
      const p = positions.get(nodes[i].id)!;
      const rr = scene.radius[i] + 5 * f.px;
      ctx.moveTo(p.x + rr, p.y);
      ctx.arc(p.x, p.y, rr, 0, TAU);
      anyFlagged = true;
    }
    if (anyFlagged) {
      ctx.globalAlpha = pass === 0 ? 0.3 : 1;
      ctx.strokeStyle = THEME.danger;
      ctx.lineWidth = 2 * f.lineScale * f.px;
      ctx.stroke();
    }

    if (!f.detail) continue;
    // Glyphs. `visible` is grouped by batch, so the ink colour changes rarely.
    let ink = "";
    for (const i of visible) {
      const r = scene.radius[i];
      const glyph = scene.glyph[i];
      if (!glyph || r * f.zoom < 7) continue;
      const p = positions.get(nodes[i].id)!;
      setFont(r);
      if (scene.ink[i] !== ink) {
        ink = scene.ink[i];
        ctx.fillStyle = ink;
      }
      ctx.globalAlpha = alpha * Math.max(0.55, NODE_RING_STYLES[nodes[i].verification]?.bodyAlpha ?? 1);
      ctx.fillText(glyph, p.x, p.y + r * 0.05);
    }
    if (pinned?.size) {
      for (const i of visible) {
        if (!pinned.has(nodes[i].id)) continue;
        const p = positions.get(nodes[i].id)!;
        const r = scene.radius[i];
        drawPin(ctx, p.x + r * 0.74, p.y - r * 0.74, Math.max(r * 0.24, 2.6 * f.px), f.px, alpha);
      }
    }
  }

  // Hovered (unselected) node: brighten it in place.
  if (hovered && !sel?.has(hovered)) {
    const i = scene.nodeIndex.get(hovered);
    const p = i === undefined ? undefined : positions.get(hovered);
    if (i !== undefined && p) {
      const r = scene.radius[i];
      const ring = NODE_RING_STYLES[nodes[i].verification] ?? NODE_RING_STYLES.observed;
      const dim = !!hl && !hl.nodes.has(hovered);
      ctx.beginPath();
      ctx.arc(p.x, p.y, r, 0, TAU);
      ctx.globalAlpha = dim ? 0.08 : 0.2;
      ctx.fillStyle = "#ffffff";
      ctx.fill();
      ctx.globalAlpha = dim ? 0.4 : Math.min(1, ring.alpha + 0.4);
      ctx.strokeStyle = ring.color;
      ctx.lineWidth = (ring.width + 0.5) * f.px;
      ctx.setLineDash(f.detail ? scaledDash(ring.dash, f.px) : EMPTY_DASH);
      ctx.stroke();
      ctx.setLineDash(EMPTY_DASH);
    }
  }

  // Selected nodes, individually and on top, with an accent ring and glow.
  if (!sel?.size) return;
  for (const id of sel) {
    const i = scene.nodeIndex.get(id);
    const p = i === undefined ? undefined : positions.get(id);
    if (i === undefined || !p) continue;
    const r = scene.radius[i];
    const reach = r + 12 * f.px;
    if (p.x + reach < f.minX || p.x - reach > f.maxX || p.y + reach < f.minY || p.y - reach > f.maxY) continue;
    const n = nodes[i];
    const ring = NODE_RING_STYLES[n.verification] ?? NODE_RING_STYLES.observed;
    ctx.beginPath();
    ctx.arc(p.x, p.y, r, 0, TAU);
    ctx.globalAlpha = ring.bodyAlpha;
    ctx.fillStyle = scene.fill[i];
    ctx.fill();
    if (id === hovered) {
      ctx.globalAlpha = 0.2;
      ctx.fillStyle = "#ffffff";
      ctx.fill();
    }
    ctx.globalAlpha = ring.alpha;
    ctx.strokeStyle = ring.color;
    ctx.lineWidth = ring.width * f.px;
    ctx.setLineDash(f.detail ? scaledDash(ring.dash, f.px) : EMPTY_DASH);
    ctx.stroke();
    ctx.setLineDash(EMPTY_DASH);
    if (n.flagged) {
      ctx.globalAlpha = 1;
      ctx.strokeStyle = THEME.danger;
      ctx.lineWidth = 2 * f.lineScale * f.px;
      ctx.beginPath();
      ctx.arc(p.x, p.y, r + 5 * f.px, 0, TAU);
      ctx.stroke();
    }
    ctx.globalAlpha = 1;
    ctx.strokeStyle = THEME.accent;
    ctx.lineWidth = 3 * f.px;
    ctx.shadowColor = THEME.accent;
    ctx.shadowBlur = 12 * f.dpr;
    ctx.beginPath();
    ctx.arc(p.x, p.y, r + (n.flagged ? 9 : 4.5) * f.px, 0, TAU);
    ctx.stroke();
    ctx.shadowBlur = 0;
    if (scene.glyph[i] && r * f.zoom >= 5) {
      setFont(r);
      ctx.globalAlpha = Math.max(0.55, ring.bodyAlpha);
      ctx.fillStyle = scene.ink[i];
      ctx.fillText(scene.glyph[i], p.x, p.y + r * 0.05);
    }
    if (pinned?.has(id)) drawPin(ctx, p.x + r * 0.74, p.y - r * 0.74, Math.max(r * 0.24, 2.6 * f.px), f.px, 1);
  }
}

/** Reused every frame so collecting visible nodes doesn't allocate. */
const scratchVisible: number[] = [];

function drawPin(ctx: CanvasRenderingContext2D, x: number, y: number, size: number, px: number, alpha: number): void {
  ctx.setLineDash(EMPTY_DASH);
  ctx.globalAlpha = alpha;
  // Needle, then head with a dark outline so it reads on any node colour.
  ctx.strokeStyle = THEME.halo;
  ctx.lineWidth = 2.5 * px;
  ctx.beginPath();
  ctx.moveTo(x, y);
  ctx.lineTo(x - size * 1.2, y + size * 1.2);
  ctx.stroke();
  ctx.strokeStyle = THEME.foreground;
  ctx.lineWidth = 1.2 * px;
  ctx.stroke();
  ctx.beginPath();
  ctx.arc(x, y, size, 0, TAU);
  ctx.fillStyle = THEME.foreground;
  ctx.fill();
  ctx.strokeStyle = THEME.halo;
  ctx.lineWidth = 1.5 * px;
  ctx.stroke();
}

function drawNodeLabels(ctx: CanvasRenderingContext2D, scene: PreparedScene, positions: Positions, view: RenderView, f: FrameInfo, budgeted: boolean): void {
  const hl = view.highlight;
  const sel = view.selection?.nodes;
  const hovered = view.hovered?.kind === "node" ? view.hovered.id : null;
  // 11 px at zoom ≤ 1 growing to 12 px at zoom ≥ 2.
  const sizePx = 11 + Math.min(1, Math.max(0, f.zoom - 1));
  const regular = `${sizePx * f.px}px ${FONT_FAMILY}`;
  const strong = `600 ${sizePx * f.px}px ${FONT_FAMILY}`;
  ctx.setLineDash(EMPTY_DASH);
  ctx.textBaseline = "top";
  let budget = budgeted ? LABEL_BUDGET : Infinity;
  let currentFont = "";
  for (let i = 0; i < scene.nodes.length; i++) {
    const text = scene.label[i];
    if (!text) continue;
    const n = scene.nodes[i];
    const isSel = !!sel && sel.has(n.id);
    const isHover = n.id === hovered;
    if (hl && !hl.nodes.has(n.id) && !isSel && !isHover) continue;
    const p = positions.get(n.id);
    if (!p || p.x < f.minX || p.x > f.maxX || p.y < f.minY || p.y > f.maxY) continue;
    if (!isSel && !isHover) {
      if (budget <= 0) continue;
      budget--;
    }
    const font = isSel || isHover ? strong : regular;
    if (font !== currentFont) {
      ctx.font = font;
      currentFont = font;
    }
    const r = scene.radius[i];
    const below = r + (n.flagged ? 8 : 4) * f.px + (isSel ? 4 * f.px : 0);
    const rejected = n.verification === "rejected";
    drawHaloText(ctx, text, p.x, p.y + below, f.px, isSel ? "#ffffff" : THEME.foreground, rejected ? 0.55 : isSel || isHover ? 1 : 0.88);
  }
}
