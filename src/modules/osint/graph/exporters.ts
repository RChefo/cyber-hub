// SPDX-License-Identifier: Apache-2.0
/**
 * PNG and SVG export with the same visual encoding as the interactive canvas.
 * Labels, ids and colours are untrusted (they come from investigated data), so the SVG
 * writer escapes every text node and attribute and only emits sanitised colours.
 */
import { computeEdgeGeom, createEdgeGeom, selfLoopCircle } from "./geometry";
import { fitBounds } from "./layout";
import { groupHulls, prepareScene, renderToCanvas, sceneBounds, type PreparedScene } from "./render";
import { DIM_NODE_ALPHA, EDGE_STYLES, FONT_FAMILY, NODE_RING_STYLES, safeColor, THEME, truncateLabel } from "./style";
import type { GraphEdge, GraphGroup, GraphNode, Point, Positions } from "./types";

export { prepareScene, renderToCanvas, sceneBounds } from "./render";
export type { PreparedScene, RenderView, HoverTarget, LabelMode } from "./render";

// ---------------------------------------------------------------------------
// PNG
// ---------------------------------------------------------------------------

export interface PngExportOptions {
  /** Output size in CSS px; defaults to the graph's natural size (max 4096). */
  width?: number;
  height?: number;
  /** Pixel density multiplier (default 2). Reduced automatically to stay within browser canvas limits. */
  scale?: number;
  background: string;
  groups?: GraphGroup[];
  pinned?: ReadonlySet<string>;
  padding?: number;
  showLabels?: boolean;
}

const MAX_CANVAS_SIDE = 16_384;
const MAX_CANVAS_AREA = 120_000_000;

/** Renders the whole graph, fitted, into an offscreen canvas and encodes it as PNG. */
export async function exportPng(nodes: GraphNode[], edges: GraphEdge[], positions: Positions, opts: PngExportOptions): Promise<Blob> {
  const scene = prepareScene(nodes, edges, opts.groups ?? []);
  const showLabels = opts.showLabels ?? true;
  const bounds = sceneBounds(scene, positions, showLabels);
  const padding = opts.padding ?? 40;
  const naturalW = bounds ? bounds.maxX - bounds.minX + padding * 2 : 640;
  const naturalH = bounds ? bounds.maxY - bounds.minY + padding * 2 : 480;
  const width = Math.max(1, Math.round(opts.width ?? Math.min(4096, Math.max(320, naturalW))));
  const height = Math.max(1, Math.round(opts.height ?? Math.min(4096, Math.max(240, naturalH))));
  const scale = Math.max(
    0.1,
    Math.min(opts.scale ?? 2, MAX_CANVAS_SIDE / width, MAX_CANVAS_SIDE / height, Math.sqrt(MAX_CANVAS_AREA / (width * height))),
  );

  const canvas = document.createElement("canvas");
  canvas.width = Math.round(width * scale);
  canvas.height = Math.round(height * scale);
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new Error("Canvas 2D context is unavailable");
  // Wait for IBM Plex so labels don't render in a fallback face.
  if (typeof document.fonts?.ready?.then === "function") await document.fonts.ready;

  renderToCanvas(ctx, scene, positions, {
    width,
    height,
    pixelRatio: canvas.width / width,
    viewport: fitBounds(bounds, width, height, padding, 4),
    background: opts.background,
    grid: false,
    showLabels: showLabels ? "always" : "never",
    pinned: opts.pinned ?? null,
  });

  return new Promise<Blob>((resolve, reject) => {
    canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("PNG encoding failed"))), "image/png");
  });
}

// ---------------------------------------------------------------------------
// SVG
// ---------------------------------------------------------------------------

export interface SvgExportOptions {
  /** Width/height attributes; default to the drawing's natural size. */
  width?: number;
  height?: number;
  padding?: number;
  background?: string | null;
  groups?: GraphGroup[];
  pinned?: ReadonlySet<string>;
  showLabels?: boolean;
  showEdgeLabels?: boolean;
  /** Ids to keep at full opacity; everything else is dimmed (mirrors Highlight). */
  highlight?: { nodes: ReadonlySet<string>; edges: ReadonlySet<string> } | null;
  title?: string;
}

// Characters that are not allowed anywhere in XML 1.0, plus lone surrogates.
const INVALID_XML = /[\u0000-\u0008\u000B\u000C\u000E-\u001F￾￿]|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;

/** Escapes text for use in XML element content and (double- or single-quoted) attributes. */
export function xmlEscape(value: string): string {
  return String(value)
    .replace(INVALID_XML, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/** Compact, locale-independent number formatting for SVG attributes. */
function num(v: number): string {
  if (!Number.isFinite(v)) return "0";
  const r = Math.round(v * 100) / 100;
  return Object.is(r, -0) ? "0" : String(r);
}

function smoothHullPath(hull: readonly Point[]): string {
  const n = hull.length;
  const mid = (i: number) => {
    const a = hull[i % n];
    const b = hull[(i + 1) % n];
    return { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
  };
  const m0 = mid(0);
  let d = `M${num(m0.x)},${num(m0.y)}`;
  for (let i = 1; i <= n; i++) {
    const p = hull[i % n];
    const m = mid(i);
    d += `Q${num(p.x)},${num(p.y)} ${num(m.x)},${num(m.y)}`;
  }
  return `${d}Z`;
}

/** Arrow length in world units (= SVG user units at the drawing's native scale). */
const SVG_ARROW = 9;

/**
 * Produces a standalone SVG document of the full graph. Coordinates are world units, so
 * the drawing is resolution-independent; the viewBox frames everything with padding.
 */
export function exportSvg(nodes: GraphNode[], edges: GraphEdge[], positions: Positions, opts: SvgExportOptions = {}): string {
  const scene: PreparedScene = prepareScene(nodes, edges, opts.groups ?? []);
  const showLabels = opts.showLabels ?? true;
  const showEdgeLabels = opts.showEdgeLabels ?? showLabels;
  const hl = opts.highlight ?? null;
  const padding = opts.padding ?? 40;
  const b = sceneBounds(scene, positions, showLabels) ?? { minX: 0, minY: 0, maxX: 0, maxY: 0 };
  const vbX = b.minX - padding;
  const vbY = b.minY - padding;
  const vbW = Math.max(1, b.maxX - b.minX + padding * 2);
  const vbH = Math.max(1, b.maxY - b.minY + padding * 2);
  const width = Math.max(1, Math.round(opts.width ?? vbW));
  const height = Math.max(1, Math.round(opts.height ?? vbH));
  const font = xmlEscape(FONT_FAMILY);

  const out: string[] = [];
  out.push('<?xml version="1.0" encoding="UTF-8"?>');
  out.push(
    `<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="${width}" height="${height}" viewBox="${num(vbX)} ${num(vbY)} ${num(vbW)} ${num(vbH)}" font-family="${font}">`,
  );
  out.push(`<title>${xmlEscape(opts.title ?? `Graph: ${nodes.length} entities, ${edges.length} relationships`)}</title>`);

  // Arrow markers, one per (colour, opacity) combination actually used by directed edges.
  const markers = new Map<string, string>();
  const markerDefs: string[] = [];
  const markerFor = (color: string, alpha: number): string => {
    const key = `${color}|${alpha}`;
    let id = markers.get(key);
    if (!id) {
      id = `arrow-${markers.size}`;
      markers.set(key, id);
      // The path ends 0.8·len before the tip (see computeEdgeGeom); refX = 2 of 10 puts
      // that point on the path end so the arrow tip lands exactly on the node rim.
      markerDefs.push(
        `<marker id="${id}" viewBox="0 0 10 10" refX="2" refY="5" markerWidth="${SVG_ARROW}" markerHeight="${SVG_ARROW}" markerUnits="userSpaceOnUse" orient="auto"><path d="M0,0.8 L10,5 L0,9.2 Z" fill="${xmlEscape(color)}" fill-opacity="${num(alpha)}"/></marker>`,
      );
    }
    return id;
  };

  const body: string[] = [];
  if (opts.background) {
    body.push(`<rect x="${num(vbX)}" y="${num(vbY)}" width="${num(vbW)}" height="${num(vbH)}" fill="${xmlEscape(safeColor(opts.background, THEME.background))}"/>`);
  }

  // Groups.
  if (scene.groups.length) {
    const hulls = groupHulls(scene, positions);
    body.push('<g class="groups">');
    for (const g of scene.groups) {
      const hull = hulls.get(g.id);
      if (!hull || hull.length < 3) continue;
      const color = xmlEscape(safeColor(g.color, THEME.accent));
      body.push(
        `<path class="group" data-id="${xmlEscape(g.id)}" d="${smoothHullPath(hull)}" fill="${color}" fill-opacity="${hl ? 0.04 : 0.085}" stroke="${color}" stroke-opacity="${hl ? 0.1 : 0.26}" stroke-width="1"/>`,
      );
      if (g.label) {
        let top = hull[0];
        for (const p of hull) if (p.y < top.y) top = p;
        body.push(
          `<text class="group-label" x="${num(top.x)}" y="${num(top.y - 5)}" text-anchor="middle" font-size="11" font-weight="600" fill="${color}" paint-order="stroke" stroke="${THEME.background}" stroke-opacity="0.88" stroke-width="3" stroke-linejoin="round">${xmlEscape(truncateLabel(g.label, 40))}</text>`,
        );
      }
    }
    body.push("</g>");
  }

  // Edges.
  const geom = createEdgeGeom();
  const edgeLabels: string[] = [];
  body.push('<g class="edges" fill="none">');
  for (const e of edges) {
    const s = positions.get(e.source);
    const t = positions.get(e.target);
    const si = scene.nodeIndex.get(e.source);
    const ti = scene.nodeIndex.get(e.target);
    if (!s || !t || si === undefined || ti === undefined) continue;
    const st = EDGE_STYLES[e.verification] ?? EDGE_STYLES.observed;
    const color = scene.edgeColor.get(e.id) ?? THEME.muted;
    const alpha = hl && !hl.edges.has(e.id) ? 0.07 : st.alpha;
    const common =
      `data-id="${xmlEscape(e.id)}" stroke="${xmlEscape(color)}" stroke-width="${num(st.width)}" stroke-opacity="${num(alpha)}"` +
      (st.dash.length ? ` stroke-dasharray="${st.dash.map(num).join(" ")}"` : "") +
      (st.cap !== "butt" ? ` stroke-linecap="${st.cap}"` : "");
    const tooltip = `<title>${xmlEscape(e.label ? `${e.type}: ${e.label}` : e.type)}</title>`;
    if (si === ti) {
      const loop = selfLoopCircle(s.x, s.y, scene.radius[si]);
      body.push(`<circle class="edge edge-loop" cx="${num(loop.cx)}" cy="${num(loop.cy)}" r="${num(loop.r)}" ${common}>${tooltip}</circle>`);
      continue;
    }
    const curv = scene.curvature.get(e.id) ?? 0;
    if (!computeEdgeGeom(geom, s.x, s.y, t.x, t.y, scene.radius[si], scene.radius[ti], curv, e.directed ? SVG_ARROW : 0)) continue;
    const d = geom.curved
      ? `M${num(geom.sx)},${num(geom.sy)} Q${num(geom.cx)},${num(geom.cy)} ${num(geom.ex)},${num(geom.ey)}`
      : `M${num(geom.sx)},${num(geom.sy)} L${num(geom.ex)},${num(geom.ey)}`;
    const marker = e.directed ? ` marker-end="url(#${markerFor(color, alpha)})"` : "";
    body.push(`<path class="edge" d="${d}" ${common}${marker}>${tooltip}</path>`);

    const text = scene.edgeLabel.get(e.id);
    if (showEdgeLabels && text && (!hl || hl.edges.has(e.id))) {
      const mx = (s.x + t.x) / 2 - ((t.y - s.y) * curv) / 2;
      const my = (s.y + t.y) / 2 + ((t.x - s.x) * curv) / 2;
      edgeLabels.push(
        `<text class="edge-label" x="${num(mx)}" y="${num(my + 3.5)}" text-anchor="middle" font-size="10" fill="${THEME.muted}" paint-order="stroke" stroke="${THEME.background}" stroke-opacity="0.88" stroke-width="3" stroke-linejoin="round">${xmlEscape(text)}</text>`,
      );
    }
  }
  body.push("</g>");
  if (edgeLabels.length) body.push('<g class="edge-labels">', ...edgeLabels, "</g>");

  // Nodes.
  const labels: string[] = [];
  body.push('<g class="nodes">');
  scene.nodes.forEach((n, i) => {
    const p = positions.get(n.id);
    if (!p || !Number.isFinite(p.x) || !Number.isFinite(p.y)) return;
    const r = scene.radius[i];
    const ring = NODE_RING_STYLES[n.verification] ?? NODE_RING_STYLES.observed;
    const dim = hl && !hl.nodes.has(n.id);
    const parts: string[] = [];
    parts.push(`<g class="node" data-id="${xmlEscape(n.id)}"${dim ? ` opacity="${DIM_NODE_ALPHA}"` : ""}>`);
    parts.push(`<title>${xmlEscape(n.type ? `${n.label} (${n.type})` : n.label)}</title>`);
    if (n.flagged) {
      parts.push(`<circle class="node-flag" cx="${num(p.x)}" cy="${num(p.y)}" r="${num(r + 5)}" fill="none" stroke="${THEME.danger}" stroke-width="2"/>`);
    }
    parts.push(
      `<circle class="node-body" cx="${num(p.x)}" cy="${num(p.y)}" r="${num(r)}" fill="${xmlEscape(scene.fill[i])}"` +
        (ring.bodyAlpha < 1 ? ` fill-opacity="${num(ring.bodyAlpha)}"` : "") +
        ` stroke="${xmlEscape(ring.color)}" stroke-opacity="${num(ring.alpha)}" stroke-width="${num(ring.width)}"` +
        (ring.dash.length ? ` stroke-dasharray="${ring.dash.map(num).join(" ")}"` : "") +
        "/>",
    );
    const glyph = scene.glyph[i];
    if (glyph) {
      const fs = r * 0.9;
      parts.push(
        `<text class="node-glyph" x="${num(p.x)}" y="${num(p.y + fs * 0.36)}" text-anchor="middle" font-size="${num(fs)}" font-weight="600" fill="${xmlEscape(scene.ink[i])}">${xmlEscape(glyph)}</text>`,
      );
    }
    if (opts.pinned?.has(n.id)) {
      const px = p.x + r * 0.74;
      const py = p.y - r * 0.74;
      const size = Math.max(r * 0.24, 2.6);
      parts.push(
        `<g class="node-pin"><line x1="${num(px)}" y1="${num(py)}" x2="${num(px - size * 1.2)}" y2="${num(py + size * 1.2)}" stroke="${THEME.foreground}" stroke-width="1.2"/><circle cx="${num(px)}" cy="${num(py)}" r="${num(size)}" fill="${THEME.foreground}" stroke="${THEME.background}" stroke-width="1.5"/></g>`,
      );
    }
    parts.push("</g>");
    body.push(parts.join(""));

    const text = scene.label[i];
    if (showLabels && text && !dim) {
      const y = p.y + r + (n.flagged ? 8 : 4) + 9;
      labels.push(
        `<text class="node-label" x="${num(p.x)}" y="${num(y)}" text-anchor="middle" font-size="11" fill="${THEME.foreground}"${n.verification === "rejected" ? ' fill-opacity="0.55"' : ""} paint-order="stroke" stroke="${THEME.background}" stroke-opacity="0.88" stroke-width="3" stroke-linejoin="round">${xmlEscape(text)}</text>`,
      );
    }
  });
  body.push("</g>");
  if (labels.length) body.push('<g class="node-labels">', ...labels, "</g>");

  if (markerDefs.length) out.push("<defs>", ...markerDefs, "</defs>");
  out.push(...body, "</svg>");
  return out.join("\n");
}
