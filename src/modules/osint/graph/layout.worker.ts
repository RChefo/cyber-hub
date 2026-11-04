/**
 * Module worker that runs layouts off the main thread. Loaded by layoutAsync.ts via
 * `new Worker(new URL("./layout.worker.ts", import.meta.url), { type: "module" })`,
 * which Vite bundles as a same-origin file (compatible with CSP `script-src 'self'`).
 */
import { computeLayout } from "./layout";
import type { LayoutKind, Point } from "./types";

export interface LayoutRequest {
  id: number;
  kind: LayoutKind;
  nodes: { id: string; size?: number }[];
  edges: { source: string; target: string }[];
  positions: [string, number, number][];
  pinned: string[];
  iterations?: number;
  seed?: number;
  root?: string;
}

export type LayoutResponse =
  | { id: number; ok: true; ids: string[]; coords: Float64Array }
  | { id: number; ok: false; error: string };

interface WorkerScope {
  onmessage: ((event: MessageEvent<LayoutRequest>) => void) | null;
  postMessage(message: LayoutResponse, transfer?: Transferable[]): void;
}

const scope = self as unknown as WorkerScope;

scope.onmessage = (event) => {
  const req = event.data;
  try {
    const positions = new Map<string, Point>(req.positions.map(([id, x, y]) => [id, { x, y }]));
    const result = computeLayout(req.kind, req.nodes, req.edges, {
      positions,
      pinned: new Set(req.pinned),
      iterations: req.iterations,
      seed: req.seed,
      root: req.root,
    });
    const ids: string[] = [];
    const coords = new Float64Array(result.size * 2);
    let k = 0;
    for (const [id, p] of result) {
      ids.push(id);
      coords[k++] = p.x;
      coords[k++] = p.y;
    }
    scope.postMessage({ id: req.id, ok: true, ids, coords }, [coords.buffer]);
  } catch (err) {
    scope.postMessage({ id: req.id, ok: false, error: err instanceof Error ? err.message : String(err) });
  }
};
