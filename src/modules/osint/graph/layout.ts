// SPDX-License-Identifier: Apache-2.0
/**
 * Graph layout algorithms. Pure, deterministic and DOM-free: they run in node tests,
 * on the main thread, or inside layout.worker.ts unchanged.
 */
import { boundsOf, clampZoom, nodeRadius } from "./geometry";
import { NODE_RADIUS } from "./style";
import type { Bounds, LayoutEdge, LayoutKind, LayoutNode, Point, Positions, Viewport } from "./types";

export interface LayoutOptions {
  /** Existing positions: the starting point for force, the source of truth for manual. */
  positions?: Positions;
  /** Nodes that must keep their current position (honoured by every layout kind). */
  pinned?: Set<string>;
  iterations?: number;
  seed?: number;
  /** Root for hierarchical/radial layouts; defaults to the highest-degree node. */
  root?: string;
}

export interface ForceLayoutOptions {
  positions?: Positions;
  pinned?: Set<string>;
  /** Simulation ticks (default 300; cost is O(iterations · n log n)). */
  iterations?: number;
  seed?: number;
  /** Rest length of edge springs in world units (default 110). */
  linkDistance?: number;
  /** Node repulsion strength; more negative = more spread (default -420). */
  charge?: number;
  /** Pull towards the layout centre that keeps components together (default 0.045). */
  gravity?: number;
  /** Starting "temperature" in (0, 1]; lower values refine an existing layout gently. */
  alpha?: number;
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

/** Mulberry32: tiny, fast, good-enough seeded PRNG returning floats in [0, 1). */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** FNV-1a 32-bit hash; used to derive stable per-node angles from ids. */
export function hashString(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));

interface IndexedGraph {
  ids: string[];
  index: Map<string, number>;
  /** Undirected, de-duplicated adjacency without self-loops. */
  adj: number[][];
  /** Unique undirected links as flat [a0, b0, a1, b1, ...]. */
  links: number[];
}

function indexGraph(nodes: readonly LayoutNode[], edges: readonly LayoutEdge[]): IndexedGraph {
  const ids: string[] = [];
  const index = new Map<string, number>();
  for (const n of nodes) {
    if (index.has(n.id)) continue;
    index.set(n.id, ids.length);
    ids.push(n.id);
  }
  const n = ids.length;
  const adj: number[][] = Array.from({ length: n }, () => []);
  const links: number[] = [];
  const seen = new Set<number>();
  for (const e of edges) {
    const a = index.get(e.source);
    const b = index.get(e.target);
    if (a === undefined || b === undefined || a === b) continue;
    const key = a < b ? a * n + b : b * n + a;
    if (seen.has(key)) continue;
    seen.add(key);
    adj[a].push(b);
    adj[b].push(a);
    links.push(a, b);
  }
  return { ids, index, adj, links };
}

/** Connected components, each listed in input order, components ordered by first member. */
function components(g: IndexedGraph): number[][] {
  const n = g.ids.length;
  const comp = new Int32Array(n).fill(-1);
  const out: number[][] = [];
  for (let s = 0; s < n; s++) {
    if (comp[s] !== -1) continue;
    const id = out.length;
    const members: number[] = [];
    const stack = [s];
    comp[s] = id;
    while (stack.length) {
      const v = stack.pop()!;
      members.push(v);
      for (const w of g.adj[v]) {
        if (comp[w] === -1) {
          comp[w] = id;
          stack.push(w);
        }
      }
    }
    members.sort((a, b) => a - b);
    out.push(members);
  }
  return out;
}

function highestDegree(g: IndexedGraph, members: readonly number[]): number {
  let best = members[0];
  for (const v of members) if (g.adj[v].length > g.adj[best].length) best = v;
  return best;
}

/** BFS from root; returns visit order, depth (-1 = unreached) and BFS-tree parent. */
function bfs(g: IndexedGraph, root: number): { order: number[]; depth: Int32Array; parent: Int32Array } {
  const n = g.ids.length;
  const depth = new Int32Array(n).fill(-1);
  const parent = new Int32Array(n).fill(-1);
  const order = [root];
  depth[root] = 0;
  for (let h = 0; h < order.length; h++) {
    const v = order[h];
    for (const w of g.adj[v]) {
      if (depth[w] !== -1) continue;
      depth[w] = depth[v] + 1;
      parent[w] = v;
      order.push(w);
    }
  }
  return { order, depth, parent };
}

/** Uniform-grid spatial hash answering "is any placed point within d?". */
class SpatialHash {
  private cells = new Map<number, Point[]>();
  constructor(private cell: number) {}
  private key(cx: number, cy: number): number {
    return (cx + 0x8000) * 0x10000 + (cy + 0x8000);
  }
  add(p: Point): void {
    const k = this.key(Math.floor(p.x / this.cell), Math.floor(p.y / this.cell));
    const list = this.cells.get(k);
    if (list) list.push(p);
    else this.cells.set(k, [p]);
  }
  anyWithin(x: number, y: number, d: number): boolean {
    const cx = Math.floor(x / this.cell);
    const cy = Math.floor(y / this.cell);
    const span = Math.ceil(d / this.cell);
    const d2 = d * d;
    for (let i = -span; i <= span; i++) {
      for (let j = -span; j <= span; j++) {
        const list = this.cells.get(this.key(cx + i, cy + j));
        if (!list) continue;
        for (const p of list) {
          const dx = p.x - x;
          const dy = p.y - y;
          if (dx * dx + dy * dy < d2) return true;
        }
      }
    }
    return false;
  }
}

// ---------------------------------------------------------------------------
// Incremental placement
// ---------------------------------------------------------------------------

const PLACE_DISTANCE = 96;
const PLACE_MIN_GAP = 52;

/**
 * Gives a position to every node that lacks one, next to its already-placed neighbours,
 * so incremental additions (pivots, imports) never reshuffle the existing picture.
 * Existing entries are returned untouched. Nodes with no placed neighbours start a
 * spiral just outside the current drawing and their own neighbours grow around them.
 * Deterministic: angles derive from node ids, not from randomness.
 */
export function placeNewNodes(nodes: readonly LayoutNode[], edges: readonly LayoutEdge[], positions: Positions): Positions {
  const out: Positions = new Map(positions);
  const g = indexGraph(nodes, edges);
  const n = g.ids.length;
  const placed = new Uint8Array(n);
  const hash = new SpatialHash(PLACE_MIN_GAP);
  let pending = 0;
  for (let i = 0; i < n; i++) {
    const p = out.get(g.ids[i]);
    if (p && Number.isFinite(p.x) && Number.isFinite(p.y)) {
      placed[i] = 1;
      hash.add(p);
    } else pending++;
  }
  if (pending === 0) return out;

  // Spiral seeds go just outside the current drawing so they never land on top of it.
  const b = boundsOf(out, g.ids.filter((_, i) => placed[i]));
  const centre: Point = b ? { x: (b.minX + b.maxX) / 2, y: (b.minY + b.maxY) / 2 } : { x: 0, y: 0 };
  const r0 = b ? Math.hypot(b.maxX - b.minX, b.maxY - b.minY) / 2 + PLACE_DISTANCE * 1.5 : 0;
  let spiral = 0;

  const put = (i: number, p: Point) => {
    out.set(g.ids[i], p);
    placed[i] = 1;
    hash.add(p);
    pending--;
  };

  const placeNear = (i: number) => {
    let sx = 0;
    let sy = 0;
    let k = 0;
    for (const w of g.adj[i]) {
      if (!placed[w]) continue;
      const p = out.get(g.ids[w])!;
      sx += p.x;
      sy += p.y;
      k++;
    }
    const cx = sx / k;
    const cy = sy / k;
    // Bridging nodes (2+ placed neighbours) belong between them; leaves go around their anchor.
    if (k >= 2 && !hash.anyWithin(cx, cy, PLACE_MIN_GAP)) {
      put(i, { x: cx, y: cy });
      return;
    }
    const base = (hashString(g.ids[i]) / 4294967296) * Math.PI * 2;
    let fallback: Point | null = null;
    for (let ring = 1; ring <= 4; ring++) {
      const dist = (k >= 2 ? PLACE_DISTANCE * 0.6 : PLACE_DISTANCE) * (0.8 + ring * 0.35);
      for (let s = 0; s < 14; s++) {
        const a = base + s * GOLDEN_ANGLE;
        const x = cx + Math.cos(a) * dist;
        const y = cy + Math.sin(a) * dist;
        fallback ??= { x, y };
        if (!hash.anyWithin(x, y, PLACE_MIN_GAP)) {
          put(i, { x, y });
          return;
        }
      }
    }
    put(i, fallback!);
  };

  const placeOnSpiral = (i: number) => {
    // Equal-area spiral starting at radius r0 (sunflower packing).
    for (;;) {
      const r = Math.sqrt(r0 * r0 + spiral * PLACE_DISTANCE * PLACE_DISTANCE * 0.9);
      const a = spiral * GOLDEN_ANGLE;
      spiral++;
      const x = centre.x + Math.cos(a) * r;
      const y = centre.y + Math.sin(a) * r;
      if (!hash.anyWithin(x, y, PLACE_MIN_GAP) || spiral > n * 4 + 64) {
        put(i, { x, y });
        return;
      }
    }
  };

  // Breadth-first growth from everything already placed.
  const queue: number[] = [];
  const queued = new Uint8Array(n);
  const enqueueNeighbours = (v: number) => {
    for (const w of g.adj[v]) {
      if (!placed[w] && !queued[w]) {
        queued[w] = 1;
        queue.push(w);
      }
    }
  };
  for (let i = 0; i < n; i++) if (placed[i]) enqueueNeighbours(i);
  let head = 0;
  let nextSeed = 0;
  let compOf: Int32Array | null = null;
  let comps: number[][] = [];
  while (pending > 0) {
    if (head < queue.length) {
      const v = queue[head++];
      if (placed[v]) continue;
      placeNear(v);
      enqueueNeighbours(v);
      continue;
    }
    // No frontier left: seed the next unplaced component, preferring its hub.
    while (placed[nextSeed]) nextSeed++;
    if (!compOf) {
      compOf = new Int32Array(n);
      comps = components(g);
      comps.forEach((c, k) => c.forEach((v) => (compOf![v] = k)));
    }
    const unplaced = comps[compOf[nextSeed]].filter((v) => !placed[v]);
    const seed = highestDegree(g, unplaced);
    placeOnSpiral(seed);
    enqueueNeighbours(seed);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Force-directed layout (Barnes–Hut)
// ---------------------------------------------------------------------------

/**
 * Flat-array quadtree for Barnes–Hut repulsion. Typed arrays (rather than node
 * objects) keep the hot loop allocation-free; children are always allocated after
 * their parent, which lets mass aggregation run as a single reverse sweep.
 */
class BarnesHutTree {
  private cap = 0;
  count = 0;
  x0 = new Float64Array(0);
  y0 = new Float64Array(0);
  size = new Float64Array(0);
  mass = new Float64Array(0);
  mx = new Float64Array(0);
  my = new Float64Array(0);
  child = new Int32Array(0);
  parent = new Int32Array(0);
  point = new Int32Array(0);
  internal = new Uint8Array(0);
  next: Int32Array;
  stack = new Int32Array(0);

  constructor(points: number) {
    this.next = new Int32Array(points);
    this.grow(Math.max(64, points * 2));
  }

  private grow(cap: number): void {
    const copyF = (a: Float64Array) => {
      const b = new Float64Array(cap);
      b.set(a);
      return b;
    };
    const copyI = (a: Int32Array, stride = 1) => {
      const b = new Int32Array(cap * stride);
      b.set(a);
      return b;
    };
    this.x0 = copyF(this.x0);
    this.y0 = copyF(this.y0);
    this.size = copyF(this.size);
    this.mass = copyF(this.mass);
    this.mx = copyF(this.mx);
    this.my = copyF(this.my);
    this.child = copyI(this.child, 4);
    this.parent = copyI(this.parent);
    this.point = copyI(this.point);
    const internal = new Uint8Array(cap);
    internal.set(this.internal);
    this.internal = internal;
    this.stack = new Int32Array(cap);
    this.cap = cap;
  }

  private alloc(x0: number, y0: number, size: number, parent: number): number {
    if (this.count >= this.cap) this.grow(this.cap * 2);
    const i = this.count++;
    this.x0[i] = x0;
    this.y0[i] = y0;
    this.size[i] = size;
    this.parent[i] = parent;
    this.point[i] = -1;
    this.internal[i] = 0;
    this.child[i * 4] = this.child[i * 4 + 1] = this.child[i * 4 + 2] = this.child[i * 4 + 3] = -1;
    return i;
  }

  private childFor(node: number, x: number, y: number): number {
    const half = this.size[node] / 2;
    const right = x >= this.x0[node] + half ? 1 : 0;
    const bottom = y >= this.y0[node] + half ? 1 : 0;
    const q = right | (bottom << 1);
    let c = this.child[node * 4 + q];
    if (c < 0) {
      c = this.alloc(this.x0[node] + right * half, this.y0[node] + bottom * half, half, node);
      this.child[node * 4 + q] = c;
    }
    return c;
  }

  build(xs: Float64Array, ys: Float64Array, n: number): void {
    this.count = 0;
    let minX = Infinity;
    let minY = Infinity;
    let maxX = -Infinity;
    let maxY = -Infinity;
    for (let i = 0; i < n; i++) {
      if (xs[i] < minX) minX = xs[i];
      if (xs[i] > maxX) maxX = xs[i];
      if (ys[i] < minY) minY = ys[i];
      if (ys[i] > maxY) maxY = ys[i];
    }
    const root = this.alloc(minX - 1, minY - 1, Math.max(maxX - minX, maxY - minY) + 2, -1);
    for (let p = 0; p < n; p++) this.insert(root, p, xs, ys);
    this.aggregate(xs, ys);
  }

  private insert(root: number, p: number, xs: Float64Array, ys: Float64Array): void {
    let node = root;
    for (;;) {
      if (this.internal[node]) {
        node = this.childFor(node, xs[p], ys[p]);
        continue;
      }
      const q = this.point[node];
      if (q < 0) {
        this.point[node] = p;
        this.next[p] = -1;
        return;
      }
      // Coincident (or practically coincident) points share a leaf as a linked list
      // instead of subdividing forever.
      if ((xs[q] === xs[p] && ys[q] === ys[p]) || this.size[node] < 1e-3) {
        this.next[p] = q;
        this.point[node] = p;
        return;
      }
      // Split: push the resident list down one level, then retry p at this node.
      this.point[node] = -1;
      this.internal[node] = 1;
      const c = this.childFor(node, xs[q], ys[q]);
      this.point[c] = q;
    }
  }

  private aggregate(xs: Float64Array, ys: Float64Array): void {
    this.mass.fill(0, 0, this.count);
    this.mx.fill(0, 0, this.count);
    this.my.fill(0, 0, this.count);
    for (let i = this.count - 1; i >= 0; i--) {
      if (!this.internal[i]) {
        for (let p = this.point[i]; p >= 0; p = this.next[p]) {
          this.mass[i] += 1;
          this.mx[i] += xs[p];
          this.my[i] += ys[p];
        }
      }
      const m = this.mass[i];
      if (m > 0) {
        // mx/my hold weighted sums until here; children were finalised earlier in the sweep.
        const cx = this.mx[i] / m;
        const cy = this.my[i] / m;
        this.mx[i] = cx;
        this.my[i] = cy;
        const par = this.parent[i];
        if (par >= 0) {
          this.mass[par] += m;
          this.mx[par] += cx * m;
          this.my[par] += cy * m;
        }
      }
    }
  }
}

/**
 * Force-directed layout in the spirit of d3-force: velocity Verlet with spring links,
 * Barnes–Hut many-body repulsion (θ = 0.9), grid-based collision and a weak gravity
 * towards the layout centre so disconnected components stay together.
 * Deterministic for a given seed; pinned nodes never move.
 */
export function forceLayout(nodes: readonly LayoutNode[], edges: readonly LayoutEdge[], opts: ForceLayoutOptions = {}): Positions {
  const g = indexGraph(nodes, edges);
  const n = g.ids.length;
  const out: Positions = new Map();
  if (n === 0) return out;

  const given = opts.positions ?? new Map<string, Point>();
  const rng = mulberry32(opts.seed ?? 1);
  const iterations = Math.max(1, Math.floor(opts.iterations ?? 300));
  const linkDistance = opts.linkDistance ?? 110;
  const charge = opts.charge ?? -420;
  const gravity = opts.gravity ?? 0.045;
  const pinned = opts.pinned;

  const start = placeNewNodes(nodes, edges, given);
  const xs = new Float64Array(n);
  const ys = new Float64Array(n);
  const vx = new Float64Array(n);
  const vy = new Float64Array(n);
  const fixed = new Uint8Array(n);
  const radius = new Float64Array(n);
  const sizeOf = new Map<string, number | undefined>();
  for (const nd of nodes) if (!sizeOf.has(nd.id)) sizeOf.set(nd.id, nd.size);
  let maxRadius = 0;
  let gx = 0;
  let gy = 0;
  for (let i = 0; i < n; i++) {
    const id = g.ids[i];
    const p = start.get(id)!;
    const had = given.has(id);
    // Fresh nodes get a little seeded jitter so different seeds explore different minima.
    xs[i] = p.x + (had ? 0 : (rng() - 0.5) * 12);
    ys[i] = p.y + (had ? 0 : (rng() - 0.5) * 12);
    if (pinned?.has(id)) {
      fixed[i] = 1;
      xs[i] = p.x;
      ys[i] = p.y;
    }
    radius[i] = nodeRadius({ size: sizeOf.get(id) }) + 10;
    if (radius[i] > maxRadius) maxRadius = radius[i];
    gx += xs[i];
    gy += ys[i];
  }
  // Gravity pulls towards where the drawing already is, so a relayout doesn't drift.
  gx /= n;
  gy /= n;

  const m = g.links.length / 2;
  const deg = new Float64Array(n);
  for (let k = 0; k < g.links.length; k++) deg[g.links[k]]++;
  const bias = new Float64Array(m);
  const strength = new Float64Array(m);
  for (let k = 0; k < m; k++) {
    const a = g.links[2 * k];
    const b = g.links[2 * k + 1];
    bias[k] = deg[a] / (deg[a] + deg[b]);
    // Weaker springs on hubs keep high-degree nodes from collapsing their neighbourhood.
    strength[k] = 1 / Math.min(deg[a], deg[b]);
  }

  const tree = new BarnesHutTree(n);
  const theta2 = 0.81;
  const distMin2 = 100;
  const alphaMin = 0.001;
  const alphaDecay = 1 - Math.pow(alphaMin, 1 / iterations);
  const velocityKeep = 0.6;
  let alpha = Math.min(1, Math.max(0.01, opts.alpha ?? 1));

  // Collision grid (reused every tick).
  const cellSize = maxRadius * 2;
  const cellHead = new Map<number, number>();
  const cellNext = new Int32Array(n);

  for (let it = 0; it < iterations; it++) {
    alpha += (0 - alpha) * alphaDecay;

    // Springs.
    for (let k = 0; k < m; k++) {
      const a = g.links[2 * k];
      const b = g.links[2 * k + 1];
      let dx = xs[b] + vx[b] - xs[a] - vx[a];
      let dy = ys[b] + vy[b] - ys[a] - vy[a];
      if (dx === 0 && dy === 0) {
        dx = (rng() - 0.5) * 1e-3;
        dy = (rng() - 0.5) * 1e-3;
      }
      const l = Math.sqrt(dx * dx + dy * dy);
      const f = ((l - linkDistance) / l) * alpha * strength[k];
      dx *= f;
      dy *= f;
      const bb = bias[k];
      vx[b] -= dx * bb;
      vy[b] -= dy * bb;
      vx[a] += dx * (1 - bb);
      vy[a] += dy * (1 - bb);
    }

    // Many-body repulsion via Barnes–Hut.
    tree.build(xs, ys, n);
    const stack = tree.stack;
    for (let p = 0; p < n; p++) {
      if (fixed[p]) continue;
      const px = xs[p];
      const py = ys[p];
      let fx = 0;
      let fy = 0;
      let sp = 0;
      stack[sp++] = 0;
      while (sp > 0) {
        const node = stack[--sp];
        const mass = tree.mass[node];
        if (mass === 0) continue;
        if (tree.internal[node]) {
          const dx = tree.mx[node] - px;
          const dy = tree.my[node] - py;
          let l = dx * dx + dy * dy;
          const w = tree.size[node];
          if ((w * w) / theta2 < l) {
            if (l < distMin2) l = Math.sqrt(distMin2 * l);
            const f = (charge * mass) / l;
            fx += dx * f;
            fy += dy * f;
            continue;
          }
          for (let c = 0; c < 4; c++) {
            const ch = tree.child[node * 4 + c];
            if (ch >= 0) stack[sp++] = ch;
          }
          continue;
        }
        for (let q = tree.point[node]; q >= 0; q = tree.next[q]) {
          if (q === p) continue;
          let dx = xs[q] - px;
          let dy = ys[q] - py;
          if (dx === 0 && dy === 0) {
            dx = (rng() - 0.5) * 1e-3;
            dy = (rng() - 0.5) * 1e-3;
          }
          let l = dx * dx + dy * dy;
          if (l < distMin2) l = Math.sqrt(distMin2 * l);
          const f = charge / l;
          fx += dx * f;
          fy += dy * f;
        }
      }
      vx[p] += fx * alpha;
      vy[p] += fy * alpha;
    }

    // Gravity.
    const gs = gravity * alpha;
    for (let i = 0; i < n; i++) {
      vx[i] += (gx - xs[i]) * gs;
      vy[i] += (gy - ys[i]) * gs;
    }

    // Collision: resolve overlaps of predicted positions using a uniform grid.
    cellHead.clear();
    for (let i = 0; i < n; i++) {
      const key = (Math.floor((xs[i] + vx[i]) / cellSize) + 0x8000) * 0x10000 + (Math.floor((ys[i] + vy[i]) / cellSize) + 0x8000);
      const head = cellHead.get(key);
      cellNext[i] = head === undefined ? -1 : head;
      cellHead.set(key, i);
    }
    for (let i = 0; i < n; i++) {
      const xi = xs[i] + vx[i];
      const yi = ys[i] + vy[i];
      const cx = Math.floor(xi / cellSize);
      const cy = Math.floor(yi / cellSize);
      for (let ox = -1; ox <= 1; ox++) {
        for (let oy = -1; oy <= 1; oy++) {
          let j = cellHead.get((cx + ox + 0x8000) * 0x10000 + (cy + oy + 0x8000));
          for (; j !== undefined && j >= 0; j = cellNext[j]) {
            if (j <= i) continue;
            const rr = radius[i] + radius[j];
            let dx = xi - (xs[j] + vx[j]);
            let dy = yi - (ys[j] + vy[j]);
            let l = dx * dx + dy * dy;
            if (l >= rr * rr) continue;
            if (l === 0) {
              dx = (rng() - 0.5) * 1e-2;
              dy = (rng() - 0.5) * 1e-2;
              l = dx * dx + dy * dy;
            }
            l = Math.sqrt(l);
            const push = ((rr - l) / l) * 0.7;
            dx *= push;
            dy *= push;
            const wi = fixed[i] ? 0 : fixed[j] ? 1 : 0.5;
            const wj = fixed[j] ? 0 : fixed[i] ? 1 : 0.5;
            vx[i] += dx * wi;
            vy[i] += dy * wi;
            vx[j] -= dx * wj;
            vy[j] -= dy * wj;
          }
        }
      }
    }

    // Integrate.
    for (let i = 0; i < n; i++) {
      if (fixed[i]) {
        vx[i] = 0;
        vy[i] = 0;
        continue;
      }
      vx[i] *= velocityKeep;
      vy[i] *= velocityKeep;
      xs[i] += vx[i];
      ys[i] += vy[i];
    }
  }

  for (let i = 0; i < n; i++) {
    const id = g.ids[i];
    if (fixed[i]) {
      const p = start.get(id)!;
      out.set(id, { x: p.x, y: p.y });
    } else if (Number.isFinite(xs[i]) && Number.isFinite(ys[i])) {
      out.set(id, { x: xs[i], y: ys[i] });
    } else {
      // Defensive: never hand NaN to the renderer.
      const p = start.get(id)!;
      out.set(id, { x: p.x, y: p.y });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Hierarchical layout
// ---------------------------------------------------------------------------

export interface HierarchicalOptions {
  root?: string;
  layerGap?: number;
  nodeGap?: number;
  componentGap?: number;
}

/**
 * Layered (top-down) layout: BFS layers from the root (or the highest-degree node of
 * each component), barycenter sweeps to reduce crossings, components side by side.
 */
export function hierarchicalLayout(nodes: readonly LayoutNode[], edges: readonly LayoutEdge[], opts: HierarchicalOptions = {}): Positions {
  const g = indexGraph(nodes, edges);
  const out: Positions = new Map();
  if (g.ids.length === 0) return out;
  const layerGap = opts.layerGap ?? 130;
  const nodeGap = opts.nodeGap ?? 96;
  const componentGap = opts.componentGap ?? 160;
  const requestedRoot = opts.root !== undefined ? g.index.get(opts.root) : undefined;

  const comps = components(g);
  // The component holding the requested root goes first.
  if (requestedRoot !== undefined) {
    const k = comps.findIndex((c) => c.includes(requestedRoot));
    if (k > 0) comps.unshift(...comps.splice(k, 1));
  }

  const order = new Float64Array(g.ids.length);
  const depthOf = new Int32Array(g.ids.length);
  const placedComps: { layers: number[][]; width: number }[] = [];
  for (const members of comps) {
    const root = requestedRoot !== undefined && members.includes(requestedRoot) ? requestedRoot : highestDegree(g, members);
    const { order: visit, depth } = bfs(g, root);
    const layers: number[][] = [];
    for (const v of visit) {
      const d = depth[v];
      depthOf[v] = d;
      (layers[d] ??= []).push(v);
    }
    layers.forEach((layer) => layer.forEach((v, i) => (order[v] = i)));

    // Barycenter heuristic: alternate down and up sweeps, ordering each layer by the
    // mean position of its neighbours in the adjacent (already ordered) layer.
    const sweep = (k: number, ref: number) => {
      const layer = layers[k];
      const bary = new Map<number, number>();
      for (const v of layer) {
        let s = 0;
        let c = 0;
        for (const w of g.adj[v]) {
          if (depthOf[w] === ref) {
            s += order[w];
            c++;
          }
        }
        bary.set(v, c ? s / c : order[v]);
      }
      layer.sort((a, b) => bary.get(a)! - bary.get(b)! || order[a] - order[b]);
      layer.forEach((v, i) => (order[v] = i));
    };
    for (let pass = 0; pass < 4; pass++) {
      for (let k = 1; k < layers.length; k++) sweep(k, k - 1);
      for (let k = layers.length - 2; k >= 1; k--) sweep(k, k + 1);
    }
    const width = Math.max(...layers.map((l) => l.length)) * nodeGap;
    placedComps.push({ layers, width });
  }

  let cursor = 0;
  for (const { layers, width } of placedComps) {
    const cx = cursor + width / 2;
    layers.forEach((layer, k) => {
      layer.forEach((v, i) => {
        out.set(g.ids[v], { x: cx + (i - (layer.length - 1) / 2) * nodeGap, y: k * layerGap });
      });
    });
    cursor += width + componentGap;
  }
  // Centre the drawing horizontally on the origin.
  const shift = (cursor - componentGap) / 2;
  for (const p of out.values()) p.x -= shift;
  return out;
}

// ---------------------------------------------------------------------------
// Radial layout
// ---------------------------------------------------------------------------

export interface RadialOptions {
  root?: string;
  ringGap?: number;
  minSpacing?: number;
}

/**
 * Root at the centre, BFS rings around it. Each subtree gets an angular wedge
 * proportional to its leaf count, so branches stay together without crossing.
 * Nodes not reachable from the root sit on an outer ring.
 */
export function radialLayout(nodes: readonly LayoutNode[], edges: readonly LayoutEdge[], opts: RadialOptions = {}): Positions {
  const g = indexGraph(nodes, edges);
  const n = g.ids.length;
  const out: Positions = new Map();
  if (n === 0) return out;
  const ringGap = opts.ringGap ?? 140;
  const minSpacing = opts.minSpacing ?? 46;
  const all = Array.from({ length: n }, (_, i) => i);
  const requested = opts.root !== undefined ? g.index.get(opts.root) : undefined;
  const root = requested ?? highestDegree(g, all);
  const { order, depth, parent } = bfs(g, root);

  const children: number[][] = Array.from({ length: n }, () => []);
  for (const v of order) if (parent[v] >= 0) children[parent[v]].push(v);
  const weight = new Float64Array(n);
  for (let k = order.length - 1; k >= 0; k--) {
    const v = order[k];
    let w = 0;
    for (const c of children[v]) w += weight[c];
    weight[v] = Math.max(1, w);
  }

  const maxDepth = order.reduce((d, v) => Math.max(d, depth[v]), 0);
  const ringCount = new Int32Array(maxDepth + 2);
  for (const v of order) ringCount[depth[v]]++;
  const ringRadius = new Float64Array(maxDepth + 2);
  for (let k = 1; k <= maxDepth; k++) {
    const fit = (ringCount[k] * minSpacing) / (Math.PI * 2);
    ringRadius[k] = Math.max(k * ringGap, ringRadius[k - 1] + ringGap * 0.75, fit);
  }

  const angle = new Float64Array(n);
  out.set(g.ids[root], { x: 0, y: 0 });
  const assign = (v: number, from: number, span: number) => {
    let a = from;
    for (const c of children[v]) {
      const share = (span * weight[c]) / weight[v];
      angle[c] = a + share / 2;
      const r = ringRadius[depth[c]];
      out.set(g.ids[c], { x: Math.cos(angle[c]) * r, y: Math.sin(angle[c]) * r });
      assign(c, a, share);
      a += share;
    }
  };
  // Iterative traversal would avoid deep recursion, but BFS-tree depth is bounded by the
  // ring count, which stays small for any graph readable as a radial drawing.
  assign(root, -Math.PI / 2, Math.PI * 2);

  const rest = all.filter((v) => depth[v] < 0);
  if (rest.length) {
    const outer = Math.max(ringRadius[maxDepth] + ringGap * 1.2, (rest.length * minSpacing) / (Math.PI * 2));
    rest.forEach((v, i) => {
      const a = -Math.PI / 2 + (i / rest.length) * Math.PI * 2;
      out.set(g.ids[v], { x: Math.cos(a) * outer, y: Math.sin(a) * outer });
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Circular layout
// ---------------------------------------------------------------------------

export function circularLayout(nodes: readonly LayoutNode[], spacing = 58): Positions {
  const out: Positions = new Map();
  const ids = Array.from(new Set(nodes.map((n) => n.id)));
  if (ids.length === 1) out.set(ids[0], { x: 0, y: 0 });
  if (ids.length <= 1) return out;
  const r = Math.max(70, (ids.length * spacing) / (Math.PI * 2));
  ids.forEach((id, i) => {
    const a = -Math.PI / 2 + (i / ids.length) * Math.PI * 2;
    out.set(id, { x: Math.cos(a) * r, y: Math.sin(a) * r });
  });
  return out;
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/**
 * Runs the requested layout and returns positions for exactly the given nodes.
 * Pinned nodes that already have a position keep it for every kind.
 */
export function computeLayout(kind: LayoutKind, nodes: readonly LayoutNode[], edges: readonly LayoutEdge[], opts: LayoutOptions = {}): Positions {
  const positions = opts.positions ?? new Map<string, Point>();
  let result: Positions;
  switch (kind) {
    case "force":
      return forceLayout(nodes, edges, { positions, pinned: opts.pinned, iterations: opts.iterations, seed: opts.seed });
    case "hierarchical":
      result = hierarchicalLayout(nodes, edges, { root: opts.root });
      break;
    case "radial":
      result = radialLayout(nodes, edges, { root: opts.root });
      break;
    case "circular":
      result = circularLayout(nodes);
      break;
    case "manual": {
      const placed = placeNewNodes(nodes, edges, positions);
      result = new Map();
      for (const nd of nodes) result.set(nd.id, placed.get(nd.id)!);
      return result;
    }
  }
  if (opts.pinned) {
    for (const id of opts.pinned) {
      const p = positions.get(id);
      if (p && result.has(id)) result.set(id, { x: p.x, y: p.y });
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// Viewport fitting
// ---------------------------------------------------------------------------

/** Fitting never zooms in beyond this, so a lone node is not blown up to 4×. */
const FIT_MAX_ZOOM = 2;

/** Viewport that shows `bounds` inside a width×height canvas with `padding` px margins. */
export function fitBounds(bounds: Bounds | null, width: number, height: number, padding = 60, maxZoom = FIT_MAX_ZOOM): Viewport {
  if (!bounds) return { x: 0, y: 0, zoom: 1 };
  const x = (bounds.minX + bounds.maxX) / 2;
  const y = (bounds.minY + bounds.maxY) / 2;
  const bw = Math.max(1, bounds.maxX - bounds.minX);
  const bh = Math.max(1, bounds.maxY - bounds.minY);
  const aw = Math.max(1, width - padding * 2);
  const ah = Math.max(1, height - padding * 2);
  const zoom = clampZoom(Math.min(aw / bw, ah / bh, maxZoom));
  return { x, y, zoom };
}

/**
 * Viewport that frames the given node ids (or every position when `ids` is null),
 * allowing for node radius and the label underneath. Zoom is clamped to [0.05, 4]
 * and fitting itself never zooms in past 2×.
 */
export function fitViewport(positions: Positions, ids: Iterable<string> | null, width: number, height: number, padding = 60): Viewport {
  const b = boundsOf(positions, ids);
  if (!b) return { x: 0, y: 0, zoom: 1 };
  const r = NODE_RADIUS * 1.5;
  return fitBounds({ minX: b.minX - r, minY: b.minY - r, maxX: b.maxX + r, maxY: b.maxY + r + 16 }, width, height, padding);
}
