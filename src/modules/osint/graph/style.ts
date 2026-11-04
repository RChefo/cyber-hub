/**
 * Visual encoding shared by the canvas renderer and the SVG exporter, so an export
 * looks exactly like the workspace. All sizes are in screen pixels at zoom 1.
 */
import type { Verification } from "./types";

/** Cyber Hub dark-theme tokens (mirrors src/styles/index.css). */
export const THEME = {
  background: "#0b0d10",
  surface: "#15181f",
  foreground: "#e8ebf0",
  muted: "#8a93a3",
  accent: "#4c8dff",
  success: "#3fb68b",
  warning: "#e0a43a",
  danger: "#e5484d",
  halo: "rgba(11, 13, 16, 0.88)",
} as const;

export const FONT_FAMILY = '"IBM Plex Sans", "Segoe UI", system-ui, sans-serif';

/** Base node radius in world units; GraphNode.size multiplies it. */
export const NODE_RADIUS = 16;
export const LABEL_MAX_CHARS = 28;

export type LineCap = "butt" | "round" | "square";

export interface EdgeStyle {
  width: number;
  dash: readonly number[];
  alpha: number;
  cap: LineCap;
  /** Overrides the edge's own colour (disputed edges use the warning colour). */
  color: string | null;
}

export const EDGE_STYLES: Record<Verification, EdgeStyle> = {
  observed: { width: 1.5, dash: [], alpha: 0.62, cap: "butt", color: null },
  verified: { width: 2, dash: [], alpha: 1, cap: "butt", color: null },
  inferred: { width: 1.5, dash: [6, 4], alpha: 0.62, cap: "butt", color: null },
  // A near-zero dash with round caps renders as dots.
  disputed: { width: 1.75, dash: [0.01, 4.5], alpha: 0.9, cap: "round", color: THEME.warning },
  rejected: { width: 1, dash: [4, 5], alpha: 0.2, cap: "butt", color: null },
};

export interface RingStyle {
  color: string;
  alpha: number;
  dash: readonly number[];
  width: number;
  /** Multiplier applied to the node body opacity. */
  bodyAlpha: number;
}

export const NODE_RING_STYLES: Record<Verification, RingStyle> = {
  observed: { color: "#ffffff", alpha: 0.22, dash: [], width: 2, bodyAlpha: 1 },
  verified: { color: THEME.success, alpha: 1, dash: [], width: 2, bodyAlpha: 1 },
  inferred: { color: THEME.foreground, alpha: 0.7, dash: [3, 3], width: 2, bodyAlpha: 1 },
  disputed: { color: THEME.warning, alpha: 1, dash: [], width: 2, bodyAlpha: 1 },
  rejected: { color: THEME.muted, alpha: 0.6, dash: [2, 3], width: 1.5, bodyAlpha: 0.4 },
};

/** Opacity applied to everything outside an active highlight. */
export const DIM_NODE_ALPHA = 0.16;
export const DIM_EDGE_ALPHA = 0.07;

const COLOR_RE = /^(#[0-9a-f]{3,8}|(?:rgb|rgba|hsl|hsla)\(\s*[-\d.%\s,/deg]+\)|[a-z]{3,20})$/i;

/**
 * Colours come from data (entity types, user-defined groups), so they are treated as
 * untrusted: anything that is not a plain CSS colour literal falls back. This keeps SVG
 * attributes inert and stops the canvas silently keeping the previous fillStyle.
 */
export function safeColor(color: string | null | undefined, fallback: string = THEME.muted): string {
  if (typeof color !== "string") return fallback;
  const c = color.trim();
  return COLOR_RE.test(c) ? c : fallback;
}

/** Truncate by code points (never splits a surrogate pair) and append an ellipsis. */
export function truncateLabel(text: string, max: number = LABEL_MAX_CHARS): string {
  const chars = Array.from(text.replace(/\s+/g, " ").trim());
  if (chars.length <= max) return chars.join("");
  return `${chars.slice(0, max - 1).join("").trimEnd()}…`;
}

/** Parses #rgb / #rrggbb (with optional alpha) to [r, g, b] in 0–255, or null. */
export function parseHex(color: string): [number, number, number] | null {
  const m = /^#([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/i.exec(color.trim());
  if (!m) return null;
  let h = m[1];
  if (h.length <= 4) h = h.slice(0, 3).split("").map((c) => c + c).join("");
  return [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
}

/** Picks dark or light glyph ink for legibility on the given node fill. */
export function inkFor(fill: string): string {
  const rgb = parseHex(fill);
  if (!rgb) return "#ffffff";
  const lin = rgb.map((v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  const luminance = 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2];
  return luminance > 0.42 ? "#0b0d10" : "#ffffff";
}

/** First 1–2 visible characters of a glyph (by code point). */
export function cleanGlyph(glyph: string): string {
  return Array.from(glyph.trim()).slice(0, 2).join("");
}
