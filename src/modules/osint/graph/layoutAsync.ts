// SPDX-License-Identifier: Apache-2.0
/**
 * Runs layouts in a module Web Worker so large force layouts don't block the UI.
 * Falls back to the main thread when workers are unavailable (tests, CSP failure,
 * worker crash) or when the graph is small enough that messaging would cost more.
 */
import { computeLayout, type LayoutOptions } from "./layout";
import type { LayoutRequest, LayoutResponse } from "./layout.worker";
import type { LayoutEdge, LayoutKind, LayoutNode, Point, Positions } from "./types";

export interface AsyncLayoutOptions extends LayoutOptions {
  signal?: AbortSignal;
  /** Graphs smaller than this run inline (default 200 nodes). */
  inlineBelow?: number;
}

interface Pending {
  resolve(p: Positions): void;
  reject(e: unknown): void;
  /** Recompute on the main thread (used if the worker dies mid-request). */
  fallback(): void;
}

let worker: Worker | null = null;
let workerBroken = false;
let nextId = 1;
const pending = new Map<number, Pending>();

function abortError(): Error {
  return typeof DOMException === "function" ? new DOMException("Layout aborted", "AbortError") : new Error("Layout aborted");
}

function dropWorker(): void {
  worker?.terminate();
  worker = null;
  // Anything still in flight is recomputed locally rather than lost.
  const stranded = [...pending.values()];
  pending.clear();
  for (const p of stranded) p.fallback();
}

function getWorker(): Worker | null {
  if (workerBroken || typeof Worker === "undefined") return null;
  if (worker) return worker;
  try {
    worker = new Worker(new URL("./layout.worker.ts", import.meta.url), { type: "module", name: "graph-layout" });
  } catch {
    workerBroken = true;
    return null;
  }
  worker.onmessage = (event: MessageEvent<LayoutResponse>) => {
    const msg = event.data;
    const entry = pending.get(msg.id);
    if (!entry) return; // aborted or superseded
    pending.delete(msg.id);
    if (!msg.ok) {
      entry.reject(new Error(msg.error));
      return;
    }
    const out: Positions = new Map();
    msg.ids.forEach((id, i) => out.set(id, { x: msg.coords[i * 2], y: msg.coords[i * 2 + 1] }));
    entry.resolve(out);
  };
  worker.onerror = (event) => {
    event.preventDefault();
    workerBroken = true;
    dropWorker();
  };
  return worker;
}

/**
 * Async counterpart of `computeLayout`. Resolves with positions for exactly the given
 * nodes; rejects with an AbortError if `signal` fires first.
 */
export function computeLayoutAsync(
  kind: LayoutKind,
  nodes: readonly LayoutNode[],
  edges: readonly LayoutEdge[],
  opts: AsyncLayoutOptions = {},
): Promise<Positions> {
  const { signal, inlineBelow = 200, ...layoutOpts } = opts;
  if (signal?.aborted) return Promise.reject(abortError());

  const inline = () => computeLayout(kind, nodes, edges, layoutOpts);
  const w = kind === "manual" || nodes.length < inlineBelow ? null : getWorker();
  if (!w) {
    return new Promise<Positions>((resolve, reject) => {
      // Yield first so callers can paint a "laying out…" state.
      setTimeout(() => {
        if (signal?.aborted) return reject(abortError());
        try {
          resolve(inline());
        } catch (err) {
          reject(err);
        }
      }, 0);
    });
  }

  return new Promise<Positions>((resolve, reject) => {
    const id = nextId++;
    const cleanup = () => signal?.removeEventListener("abort", onAbort);
    const onAbort = () => {
      if (!pending.delete(id)) return;
      cleanup();
      reject(abortError());
      // The worker is busy with a result nobody wants; restart it so the next request
      // doesn't queue behind it (other in-flight requests fall back to the main thread).
      if (worker) dropWorker();
    };
    pending.set(id, {
      resolve: (p) => {
        cleanup();
        resolve(p);
      },
      reject: (e) => {
        cleanup();
        reject(e);
      },
      fallback: () => {
        cleanup();
        try {
          resolve(inline());
        } catch (err) {
          reject(err);
        }
      },
    });
    signal?.addEventListener("abort", onAbort, { once: true });

    const positions: [string, number, number][] = [];
    for (const [nid, p] of layoutOpts.positions ?? new Map<string, Point>()) positions.push([nid, p.x, p.y]);
    const req: LayoutRequest = {
      id,
      kind,
      // Send only what the algorithms read; full node objects would bloat structured cloning.
      nodes: nodes.map((n) => (n.size === undefined ? { id: n.id } : { id: n.id, size: n.size })),
      edges: edges.map((e) => ({ source: e.source, target: e.target })),
      positions,
      pinned: layoutOpts.pinned ? [...layoutOpts.pinned] : [],
      iterations: layoutOpts.iterations,
      seed: layoutOpts.seed,
      root: layoutOpts.root,
    };
    try {
      w.postMessage(req);
    } catch {
      const entry = pending.get(id);
      pending.delete(id);
      entry?.fallback();
    }
  });
}
