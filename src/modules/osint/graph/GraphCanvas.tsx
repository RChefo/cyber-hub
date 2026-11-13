// SPDX-License-Identifier: Apache-2.0
/**
 * Interactive link-analysis canvas.
 *
 * Fully controlled: positions, viewport and selection live in the parent and change
 * only through the callbacks. Rendering is imperative (one <canvas>, Canvas 2D) and
 * happens in a requestAnimationFrame only when something changed — there is no
 * continuous render loop. Pointer and wheel interactions apply optimistically (the
 * canvas shows the new viewport / dragged nodes immediately) while the parent catches
 * up, so pans and drags stay smooth even if the parent re-renders slowly.
 */
import { useEffect, useId, useLayoutEffect, useMemo, useRef, type KeyboardEvent, type MouseEvent, type PointerEvent, type Ref } from "react";
import { cn } from "@/lib/utils";
import { hitTestEdge, hitTestNode, nodesInRect, screenToWorld, zoomAt } from "./geometry";
import { fitViewport } from "./layout";
import { prepareScene, renderToCanvas, type HoverTarget, type LabelMode, type PreparedScene } from "./render";
import { NODE_RADIUS } from "./style";
import type { GraphEdge, GraphGroup, GraphNode, Highlight, Point, Positions, Selection, Viewport } from "./types";

export interface GraphContextTarget {
  kind: "node" | "edge" | "background";
  id?: string;
  /** Pointer position in client (viewport) coordinates, ready for a position:fixed menu. */
  screen: Point;
}

export interface GraphCanvasProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  positions: Positions;
  /** "drag" fires on every move while dragging; "end" once with the final positions. */
  onPositionsChange(updates: Map<string, Point>, phase: "drag" | "end"): void;
  viewport: Viewport;
  onViewportChange(v: Viewport): void;
  selection: Selection;
  onSelectionChange(s: Selection): void;
  highlight?: Highlight | null;
  groups?: GraphGroup[];
  /** Pinned nodes are drawn with a small pin marker. */
  pinned?: Set<string>;
  /** auto: node labels hidden below zoom 0.55, edge labels below 1.1. */
  showLabels?: LabelMode;
  onNodeDoubleClick?(id: string): void;
  onContextMenu?(target: GraphContextTarget): void;
  canvasRef?: Ref<HTMLCanvasElement>;
  className?: string;
}

const EMPTY_GROUPS: GraphGroup[] = [];
const DRAG_THRESHOLD_PX = 4;
const KEY_ZOOM = 1.25;
const KEY_PAN_PX = 60;
const EMPTY_SELECTION = (): Selection => ({ nodes: new Set(), edge: null });

type Gesture =
  | {
      kind: "node";
      pointerId: number;
      nodeId: string;
      start: Point;
      origin: Map<string, Point>;
      additive: boolean;
      moved: boolean;
      last: Map<string, Point> | null;
    }
  | { kind: "pan"; pointerId: number; start: Point; startViewport: Viewport; moved: boolean; edgeId: string | null }
  | { kind: "marquee"; pointerId: number; start: Point; current: Point };

function assignRef<T>(ref: Ref<T> | undefined, value: T | null): void {
  if (!ref) return;
  if (typeof ref === "function") ref(value);
  else (ref as { current: T | null }).current = value;
}

function plural(n: number, one: string, many: string): string {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

export function GraphCanvas(props: GraphCanvasProps) {
  const { nodes, edges, groups = EMPTY_GROUPS, selection, canvasRef, className } = props;
  const scene = useMemo(() => prepareScene(nodes, edges, groups), [nodes, edges, groups]);
  const summaryId = useId();

  const wrapRef = useRef<HTMLDivElement>(null);
  const canvasEl = useRef<HTMLCanvasElement | null>(null);
  const propsRef = useRef(props);
  const sceneRef = useRef<PreparedScene>(scene);
  const sizeRef = useRef({ width: 0, height: 0, dpr: 1 });
  /** Viewport as currently shown: the prop, or a newer value we emitted and the parent hasn't echoed yet. */
  const liveViewport = useRef(props.viewport);
  const emitted = useRef<Viewport[]>([]);
  const hoverRef = useRef<HoverTarget | null>(null);
  const gestureRef = useRef<Gesture | null>(null);
  /** Positions of nodes being dragged, layered over props.positions until the parent catches up. */
  const overridesRef = useRef<{ map: Map<string, Point>; base: Positions; settled: boolean } | null>(null);
  const mergedRef = useRef<{ base: Positions; over: Map<string, Point>; map: Positions } | null>(null);
  const rafRef = useRef(0);

  // Imperative engine. Every function reads state through refs, so creating it once is
  // safe and keeps native listeners (wheel, ResizeObserver) stable.
  const engine = useMemo(() => {
    const effectivePositions = (): Positions => {
      const base = propsRef.current.positions;
      const ov = overridesRef.current;
      if (!ov) return base;
      const cached = mergedRef.current;
      if (cached && cached.base === base && cached.over === ov.map) return cached.map;
      const map = new Map(base);
      for (const [id, p] of ov.map) map.set(id, p);
      mergedRef.current = { base, over: ov.map, map };
      return map;
    };

    const resizeBacking = () => {
      const wrap = wrapRef.current;
      const canvas = canvasEl.current;
      if (!wrap || !canvas) return;
      const rect = wrap.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      sizeRef.current = { width: rect.width, height: rect.height, dpr };
      canvas.width = Math.max(1, Math.round(rect.width * dpr));
      canvas.height = Math.max(1, Math.round(rect.height * dpr));
    };

    const draw = () => {
      const canvas = canvasEl.current;
      if (!canvas) return;
      if ((window.devicePixelRatio || 1) !== sizeRef.current.dpr) resizeBacking();
      const { width, height, dpr } = sizeRef.current;
      if (width <= 0 || height <= 0) return;
      const ctx = canvas.getContext("2d");
      if (!ctx) return;
      const p = propsRef.current;
      const g = gestureRef.current;
      renderToCanvas(ctx, sceneRef.current, effectivePositions(), {
        width,
        height,
        pixelRatio: dpr,
        viewport: liveViewport.current,
        selection: p.selection,
        highlight: p.highlight ?? null,
        hovered: hoverRef.current,
        pinned: p.pinned ?? null,
        showLabels: p.showLabels ?? "auto",
        grid: true,
        marquee: g?.kind === "marquee" ? { a: g.start, b: g.current } : null,
      });
    };

    const requestDraw = () => {
      if (rafRef.current) return;
      rafRef.current = requestAnimationFrame(() => {
        rafRef.current = 0;
        draw();
      });
    };

    const localPoint = (e: { clientX: number; clientY: number }): Point => {
      const rect = canvasEl.current?.getBoundingClientRect();
      return rect ? { x: e.clientX - rect.left, y: e.clientY - rect.top } : { x: 0, y: 0 };
    };

    const toWorld = (sp: Point): Point => screenToWorld(sp, liveViewport.current, sizeRef.current.width, sizeRef.current.height);

    const hitNode = (sp: Point): string | null =>
      hitTestNode(effectivePositions(), sceneRef.current.nodes, toWorld(sp), liveViewport.current.zoom);

    const hitEdge = (sp: Point): string | null => {
      const sc = sceneRef.current;
      return hitTestEdge(effectivePositions(), sc.edges, toWorld(sp), liveViewport.current.zoom, {
        curvatures: sc.curvature,
        radiusOf: (id) => {
          const i = sc.nodeIndex.get(id);
          return i === undefined ? NODE_RADIUS : sc.radius[i];
        },
      });
    };

    const emitViewport = (v: Viewport) => {
      liveViewport.current = v;
      emitted.current.push(v);
      if (emitted.current.length > 32) emitted.current.shift();
      requestDraw();
      propsRef.current.onViewportChange(v);
    };

    const setCursor = () => {
      const canvas = canvasEl.current;
      if (!canvas) return;
      const g = gestureRef.current;
      const cursor = g ? (g.kind === "marquee" ? "crosshair" : "grabbing") : hoverRef.current ? "pointer" : "grab";
      if (canvas.style.cursor !== cursor) canvas.style.cursor = cursor;
    };

    const setHover = (target: HoverTarget | null) => {
      const cur = hoverRef.current;
      if (cur?.kind === target?.kind && cur?.id === target?.id) return;
      hoverRef.current = target;
      requestDraw();
      setCursor();
    };

    const updateHover = (sp: Point) => {
      const { width, height } = sizeRef.current;
      if (sp.x < 0 || sp.y < 0 || sp.x > width || sp.y > height) return setHover(null);
      const node = hitNode(sp);
      if (node) return setHover({ kind: "node", id: node });
      const edge = hitEdge(sp);
      setHover(edge ? { kind: "edge", id: edge } : null);
    };

    return { effectivePositions, resizeBacking, draw, requestDraw, localPoint, toWorld, hitNode, hitEdge, emitViewport, setCursor, setHover, updateHover };
  }, []);

  // Sync props into refs after every render, then schedule a redraw.
  useLayoutEffect(() => {
    propsRef.current = props;
    sceneRef.current = scene;
    const v = props.viewport;
    const idx = emitted.current.indexOf(v);
    if (idx === -1) {
      // External change (fit, programmatic pan…): adopt it.
      liveViewport.current = v;
      emitted.current = [];
    } else {
      // Parent echoed one of ours; anything emitted after it is still in flight.
      emitted.current = emitted.current.slice(idx + 1);
      if (emitted.current.length === 0) liveViewport.current = v;
    }
    const ov = overridesRef.current;
    if (ov && ov.settled && ov.base !== props.positions) overridesRef.current = null;
    engine.requestDraw();
  });

  // Size tracking (ResizeObserver + devicePixelRatio changes) and font loading.
  useEffect(() => {
    const wrap = wrapRef.current;
    if (!wrap) return;
    const apply = () => {
      engine.resizeBacking();
      engine.draw(); // synchronous: resizing the backing store clears it
    };
    apply();
    const ro = new ResizeObserver(apply);
    ro.observe(wrap);

    let mq: MediaQueryList | null = null;
    const onDprChange = () => {
      apply();
      watchDpr();
    };
    const watchDpr = () => {
      mq?.removeEventListener("change", onDprChange);
      mq = window.matchMedia(`(resolution: ${window.devicePixelRatio || 1}dppx)`);
      mq.addEventListener("change", onDprChange);
    };
    watchDpr();

    const fonts = document.fonts;
    const onFonts = () => engine.requestDraw();
    fonts?.addEventListener?.("loadingdone", onFonts);
    void fonts?.ready?.then(onFonts);

    return () => {
      ro.disconnect();
      mq?.removeEventListener("change", onDprChange);
      fonts?.removeEventListener?.("loadingdone", onFonts);
      if (rafRef.current) cancelAnimationFrame(rafRef.current);
      rafRef.current = 0;
    };
  }, [engine]);

  // Wheel must be a non-passive native listener to be able to preventDefault page zoom/scroll.
  useEffect(() => {
    const canvas = canvasEl.current;
    if (!canvas) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const unit = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? sizeRef.current.height : 1;
      // Trackpad pinch arrives as ctrl+wheel with small deltas: amplify it.
      const k = e.ctrlKey ? 0.01 : 0.0015;
      const factor = Math.min(2, Math.max(0.5, Math.exp(-e.deltaY * unit * k)));
      const { width, height } = sizeRef.current;
      engine.emitViewport(zoomAt(liveViewport.current, factor, engine.localPoint(e), width, height));
    };
    canvas.addEventListener("wheel", onWheel, { passive: false });
    return () => canvas.removeEventListener("wheel", onWheel);
  }, [engine]);

  const setCanvas = useMemo(
    () => (el: HTMLCanvasElement | null) => {
      canvasEl.current = el;
      assignRef(canvasRef, el);
    },
    [canvasRef],
  );

  const select = (s: Selection) => propsRef.current.onSelectionChange(s);

  const onPointerDown = (e: PointerEvent<HTMLCanvasElement>) => {
    if (e.button !== 0 && e.button !== 1) return;
    const canvas = e.currentTarget;
    canvas.focus({ preventScroll: true });
    const sp = engine.localPoint(e);
    const p = propsRef.current;

    if (e.button === 1) {
      // Middle button always pans.
      e.preventDefault();
      gestureRef.current = { kind: "pan", pointerId: e.pointerId, start: sp, startViewport: liveViewport.current, moved: true, edgeId: null };
    } else {
      const nodeId = engine.hitNode(sp);
      const additive = e.ctrlKey || e.metaKey || e.shiftKey;
      if (nodeId) {
        const selected = p.selection.nodes;
        const wasSelected = selected.has(nodeId);
        if (!additive && !wasSelected) select({ nodes: new Set([nodeId]), edge: null });
        // Dragging a member of the multi-selection moves the whole selection.
        const dragIds = wasSelected ? selected : [nodeId];
        const pos = engine.effectivePositions();
        const origin = new Map<string, Point>();
        for (const id of dragIds) {
          const q = pos.get(id);
          if (q) origin.set(id, { x: q.x, y: q.y });
        }
        gestureRef.current = { kind: "node", pointerId: e.pointerId, nodeId, start: sp, origin, additive, moved: false, last: null };
      } else if (e.shiftKey) {
        gestureRef.current = { kind: "marquee", pointerId: e.pointerId, start: sp, current: sp };
      } else {
        gestureRef.current = {
          kind: "pan",
          pointerId: e.pointerId,
          start: sp,
          startViewport: liveViewport.current,
          moved: false,
          edgeId: engine.hitEdge(sp),
        };
      }
    }
    canvas.setPointerCapture(e.pointerId);
    engine.setCursor();
  };

  const onPointerMove = (e: PointerEvent<HTMLCanvasElement>) => {
    const sp = engine.localPoint(e);
    const g = gestureRef.current;
    if (!g || g.pointerId !== e.pointerId) {
      engine.updateHover(sp);
      return;
    }
    if (g.kind === "marquee") {
      g.current = sp;
      engine.requestDraw();
      return;
    }
    if (!g.moved && Math.hypot(sp.x - g.start.x, sp.y - g.start.y) < DRAG_THRESHOLD_PX) return;
    g.moved = true;
    if (g.kind === "pan") {
      const v = g.startViewport;
      engine.emitViewport({ x: v.x - (sp.x - g.start.x) / v.zoom, y: v.y - (sp.y - g.start.y) / v.zoom, zoom: v.zoom });
      return;
    }
    const z = liveViewport.current.zoom;
    const dx = (sp.x - g.start.x) / z;
    const dy = (sp.y - g.start.y) / z;
    const updates = new Map<string, Point>();
    for (const [id, o] of g.origin) updates.set(id, { x: o.x + dx, y: o.y + dy });
    g.last = updates;
    overridesRef.current = { map: updates, base: propsRef.current.positions, settled: false };
    engine.requestDraw();
    propsRef.current.onPositionsChange(updates, "drag");
  };

  const finishGesture = (e: PointerEvent<HTMLCanvasElement>, cancelled: boolean) => {
    const g = gestureRef.current;
    if (!g || g.pointerId !== e.pointerId) return;
    gestureRef.current = null;
    if (e.currentTarget.hasPointerCapture(e.pointerId)) e.currentTarget.releasePointerCapture(e.pointerId);
    const p = propsRef.current;
    const sel = p.selection;

    if (g.kind === "node") {
      if (g.moved && g.last) {
        // A cancelled drag still commits: the nodes are visibly where the user left them.
        overridesRef.current = { map: g.last, base: p.positions, settled: true };
        p.onPositionsChange(g.last, "end");
      } else if (!cancelled) {
        if (g.additive) {
          const next = new Set(sel.nodes);
          if (next.has(g.nodeId)) next.delete(g.nodeId);
          else next.add(g.nodeId);
          select({ nodes: next, edge: null });
        } else if (sel.nodes.size !== 1 || !sel.nodes.has(g.nodeId) || sel.edge) {
          select({ nodes: new Set([g.nodeId]), edge: null });
        }
      }
    } else if (g.kind === "pan") {
      if (!g.moved && !cancelled) {
        if (g.edgeId) select({ nodes: new Set(), edge: g.edgeId });
        else if (sel.nodes.size || sel.edge) select(EMPTY_SELECTION());
      }
    } else if (!cancelled) {
      if (Math.abs(g.current.x - g.start.x) > 2 || Math.abs(g.current.y - g.start.y) > 2) {
        const ids = nodesInRect(engine.effectivePositions(), sceneRef.current.nodes, engine.toWorld(g.start), engine.toWorld(g.current));
        // Shift is the additive modifier, so the rectangle adds to the current selection.
        const next = new Set(sel.nodes);
        for (const id of ids) next.add(id);
        select({ nodes: next, edge: null });
      }
    }
    engine.requestDraw();
    engine.updateHover(engine.localPoint(e));
    engine.setCursor();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLCanvasElement>) => {
    const { width, height } = sizeRef.current;
    const centre = { x: width / 2, y: height / 2 };
    const v = liveViewport.current;
    const mod = e.ctrlKey || e.metaKey;
    const pan = (dx: number, dy: number) => {
      const step = (KEY_PAN_PX * (e.shiftKey ? 4 : 1)) / v.zoom;
      engine.emitViewport({ x: v.x + dx * step, y: v.y + dy * step, zoom: v.zoom });
    };
    let handled = true;
    switch (e.key) {
      case "Escape":
        if (gestureRef.current?.kind === "marquee") {
          gestureRef.current = null;
          engine.requestDraw();
        }
        if (propsRef.current.selection.nodes.size || propsRef.current.selection.edge) select(EMPTY_SELECTION());
        break;
      case "+":
      case "=":
        if (mod) handled = false; // leave Ctrl/Cmd + = to the webview
        else engine.emitViewport(zoomAt(v, KEY_ZOOM, centre, width, height));
        break;
      case "-":
      case "_":
        if (mod) handled = false;
        else engine.emitViewport(zoomAt(v, 1 / KEY_ZOOM, centre, width, height));
        break;
      case "0":
        if (mod) handled = false;
        else engine.emitViewport(fitViewport(engine.effectivePositions(), null, width, height));
        break;
      case "ArrowLeft":
        pan(-1, 0);
        break;
      case "ArrowRight":
        pan(1, 0);
        break;
      case "ArrowUp":
        pan(0, -1);
        break;
      case "ArrowDown":
        pan(0, 1);
        break;
      case "a":
      case "A":
        if (mod) select({ nodes: new Set(sceneRef.current.nodes.map((n) => n.id)), edge: null });
        else handled = false;
        break;
      default:
        handled = false;
    }
    if (handled) e.preventDefault();
  };

  const onDoubleClick = (e: MouseEvent<HTMLCanvasElement>) => {
    const id = engine.hitNode(engine.localPoint(e));
    if (id) propsRef.current.onNodeDoubleClick?.(id);
  };

  const onContextMenu = (e: MouseEvent<HTMLCanvasElement>) => {
    const handler = propsRef.current.onContextMenu;
    if (!handler) return;
    e.preventDefault();
    const sp = engine.localPoint(e);
    const screen = { x: e.clientX, y: e.clientY };
    const node = engine.hitNode(sp);
    if (node) return handler({ kind: "node", id: node, screen });
    const edge = engine.hitEdge(sp);
    if (edge) return handler({ kind: "edge", id: edge, screen });
    handler({ kind: "background", screen });
  };

  const selectedCount = selection.nodes.size;
  const summary =
    `Graph with ${plural(nodes.length, "entity", "entities")} and ${plural(edges.length, "relationship", "relationships")}.` +
    (selectedCount ? ` ${plural(selectedCount, "entity", "entities")} selected.` : selection.edge ? " 1 relationship selected." : "");

  return (
    <div ref={wrapRef} className={cn("relative h-full w-full overflow-hidden", className)}>
      <canvas
        ref={setCanvas}
        tabIndex={0}
        role="application"
        aria-roledescription="graph"
        aria-label="Link analysis graph. Drag to pan, scroll to zoom, plus and minus keys zoom, 0 fits the graph, Escape clears the selection."
        aria-describedby={summaryId}
        className="absolute inset-0 block h-full w-full touch-none select-none outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-focus"
        style={{ cursor: "grab" }}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={(e) => finishGesture(e, false)}
        onPointerCancel={(e) => finishGesture(e, true)}
        onLostPointerCapture={(e) => finishGesture(e, true)}
        onPointerLeave={() => {
          if (!gestureRef.current) engine.setHover(null);
        }}
        onDoubleClick={onDoubleClick}
        onContextMenu={onContextMenu}
        onKeyDown={onKeyDown}
      />
      <span id={summaryId} className="sr-only" aria-live="polite">
        {summary}
      </span>
    </div>
  );
}

export default GraphCanvas;
