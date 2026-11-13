// SPDX-License-Identifier: Apache-2.0
/**
 * Shared data model for the OSINT link-analysis graph engine.
 *
 * Coordinates live in "world" space (layout units). The viewport maps world to screen:
 *   sx = (wx - viewport.x) * viewport.zoom + width / 2
 *   sy = (wy - viewport.y) * viewport.zoom + height / 2
 * i.e. (viewport.x, viewport.y) is the world point shown at the centre of the canvas.
 */

export type Verification = "observed" | "verified" | "inferred" | "disputed" | "rejected";

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  color: string;
  /** 1–2 characters drawn inside the node. */
  glyph: string;
  verification: Verification;
  /** Suspicious/malicious indicator: drawn as a danger-coloured outer ring. */
  flagged?: boolean;
  /** Radius multiplier, default 1. */
  size?: number;
  group?: string | null;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  label: string;
  color: string;
  directed: boolean;
  verification: Verification;
}

export interface Point {
  x: number;
  y: number;
}

export type Positions = Map<string, Point>;

/** (x, y) is the world point at the viewport centre; zoom is screen px per world unit. */
export interface Viewport {
  x: number;
  y: number;
  zoom: number;
}

export interface Selection {
  nodes: Set<string>;
  edge: string | null;
}

/** When present, everything not listed is dimmed. */
export interface Highlight {
  nodes: Set<string>;
  edges: Set<string>;
}

/** Drawn as a soft translucent hull behind its members, with a label. */
export interface GraphGroup {
  id: string;
  label: string;
  color: string;
  nodeIds: string[];
}

export type LayoutKind = "force" | "hierarchical" | "radial" | "circular" | "manual";

/** Minimal node shape the layout algorithms need (GraphNode satisfies it). */
export interface LayoutNode {
  id: string;
  size?: number;
}

/** Minimal edge shape the layout algorithms need (GraphEdge satisfies it). */
export interface LayoutEdge {
  source: string;
  target: string;
}

export interface Bounds {
  minX: number;
  minY: number;
  maxX: number;
  maxY: number;
}
