/**
 * Link-analysis workspace: an interactive, saved graph of an investigation's entities.
 *
 * Intelligence (entities, relationships, evidence, review decisions) is shared by the whole
 * investigation; a graph stores presentation state only: which entities it shows, their
 * positions, pinned/hidden nodes, groups, filters, layout and viewport. Saving records a
 * version when something changed; Save As and Duplicate create independent graphs.
 */
import { Button, Dropdown, Popover, Tooltip } from "@heroui/react";
import {
  ChevronDown,
  Crosshair,
  Download,
  Eye,
  EyeOff,
  FolderOpen,
  Group,
  History,
  Info,
  Maximize2,
  Minimize2,
  Network,
  Pin,
  PinOff,
  Plus,
  Route,
  Save,
  SaveAll,
  ScanSearch,
  SlidersHorizontal,
  Trash2,
  Upload,
  Waypoints,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ToneChip } from "@/components/ui/Badges";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, InlineSpinner, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { api, errorMessage, IpcError } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import { cn } from "@/lib/utils";
import { useOsint } from "./context";
import {
  computeLayoutAsync,
  exportPng,
  exportSvg,
  fitViewport,
  GraphCanvas,
  GRAPH_THEME,
  placeNewNodes,
  type GraphContextTarget,
  type Highlight,
  type LayoutKind,
  type Positions,
  type Selection,
  type Viewport,
} from "./graph";
import type { LabelMode } from "./graph/render";
import { Check, GraphManager, NameDialog, VersionsDialog } from "./GraphModals";
import { ImportGraphModal } from "./ImportGraphModal";
import { TypeGlyph } from "./Inspector";
import {
  applyFilters,
  blobToBase64,
  defaultWorkspace,
  groupsForCanvas,
  neighborhoodIds,
  nextGroupColor,
  nodeStates,
  parseWorkspace,
  plural,
  positionsFrom,
  searchNodes,
  toCanvas,
  typeStyle,
  VERIFICATION_META,
  type Workspace,
} from "./model";
import type { EntityBrief, ExportFormat, GraphData, GraphMeta, RelationshipBrief, Verification } from "./types";

interface WorkState {
  graphId: number;
  meta: GraphMeta;
  revision: number;
  /** saved-state revision this editor started from (optimistic concurrency) */
  stateRevision: number;
  entities: Map<string, EntityBrief>;
  rels: Map<string, RelationshipBrief>;
  members: string[];
  /** membership as last loaded/saved, to tell local removals from deletions elsewhere */
  serverMembers: Set<string>;
  removed: Set<string>;
  pinned: Set<string>;
  hidden: Set<string>;
  nodeGroup: Map<string, string | null>;
  workspace: Workspace;
  warning: string | null;
}

const EMPTY_SELECTION: Selection = { nodes: new Set(), edge: null };
const LAYOUT_LABEL: Record<LayoutKind, string> = { force: "Force-directed", hierarchical: "Hierarchical", radial: "Radial", circular: "Circular", manual: "Manual" };
const LABEL_MODE: Record<LabelMode, string> = { auto: "Labels: automatic", always: "Labels: always", never: "Labels: hidden" };
const MAX_EXPAND = 300;

function initState(data: GraphData): WorkState {
  return {
    graphId: data.graph.id,
    meta: data.graph,
    revision: data.graph.revision,
    stateRevision: data.graph.stateRevision,
    entities: new Map(data.entities.map((e) => [String(e.id), e])),
    rels: new Map(data.relationships.map((r) => [String(r.id), r])),
    members: data.nodes.map((n) => String(n.entityId)),
    serverMembers: new Set(data.nodes.map((n) => String(n.entityId))),
    removed: new Set(),
    pinned: new Set(data.nodes.filter((n) => n.pinned).map((n) => String(n.entityId))),
    hidden: new Set(data.nodes.filter((n) => n.hidden).map((n) => String(n.entityId))),
    nodeGroup: new Map(data.nodes.map((n) => [String(n.entityId), n.group])),
    workspace: parseWorkspace(data.workspace),
    warning: data.warning,
  };
}

export function GraphWorkspace({
  graphId,
  onGraphChange,
  pendingAdd,
  onPendingAddUsed,
}: {
  graphId: number | null;
  onGraphChange: (id: number) => void;
  pendingAdd: number[] | null;
  onPendingAddUsed: () => void;
}) {
  const { investigation, registry, openEntity, openRelationship, collectFor } = useOsint();
  const inv = investigation.id;
  const confirm = useConfirm();

  const graphs = useQuery(["osint"], () => api.osintGraphs(inv), [inv]);
  useEffect(() => {
    if (graphId != null || !graphs.data?.length) return;
    const pick = [...graphs.data].sort((a, b) => (b.lastOpenedAt ?? "").localeCompare(a.lastOpenedAt ?? ""))[0];
    onGraphChange(pick.id);
  }, [graphId, graphs.data, onGraphChange]);

  // the first load of a graph records it as opened; refreshes after data changes do not write
  const touchedRef = useRef<number | null>(null);
  const q = useQuery(
    ["osint"],
    () => {
      const touch = touchedRef.current !== graphId;
      touchedRef.current = graphId;
      return api.osintGraphLoad(graphId as number, touch);
    },
    [graphId],
    graphId != null,
  );
  const [conflict, setConflict] = useState<string | null>(null);

  const [state, setState] = useState<WorkState | null>(null);
  const [positions, setPositions] = useState<Positions>(new Map());
  const [viewport, setViewport] = useState<Viewport>({ x: 0, y: 0, zoom: 1 });
  const [selection, setSelection] = useState<Selection>(EMPTY_SELECTION);
  const [highlight, setHighlight] = useState<{ h: Highlight; label: string } | null>(null);
  const [dirty, setDirty] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [focusMode, setFocusMode] = useState(false);
  const [legend, setLegend] = useState(true);
  const [menu, setMenu] = useState<GraphContextTarget | null>(null);
  const [dialog, setDialog] = useState<"manager" | "versions" | "saveAs" | "group" | "import" | null>(null);
  const [pathStart, setPathStart] = useState<string | null>(null);

  const stateRef = useRef(state);
  stateRef.current = state;
  const posRef = useRef(positions);
  posRef.current = positions;
  const resetRef = useRef(true);
  const fitPending = useRef(false);
  const layoutAbort = useRef<AbortController | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const [size, setSize] = useState({ w: 900, h: 600 });

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setSize({ w: el.clientWidth || 900, h: el.clientHeight || 600 }));
    ro.observe(el);
    return () => ro.disconnect();
  }, [state != null]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    resetRef.current = true;
  }, [graphId]);

  const ws = state?.workspace ?? defaultWorkspace();

  /* ── canvas model ── */
  const model = useMemo(() => {
    if (!state) return { nodes: [], edges: [] };
    const ents = state.members.map((id) => state.entities.get(id)).filter((e): e is EntityBrief => !!e);
    return toCanvas(ents, [...state.rels.values()], registry.relationshipTypes, state.nodeGroup);
  }, [state, registry.relationshipTypes]);
  const visible = useMemo(() => applyFilters(model, ws.filters, state?.hidden ?? new Set()), [model, ws.filters, state?.hidden]);
  const visibleIds = useMemo(() => new Set(visible.nodes.map((n) => n.id)), [visible.nodes]);
  const canvasGroups = useMemo(() => (state ? groupsForCanvas(ws.groups, state.nodeGroup, visibleIds) : []), [state, ws.groups, visibleIds]);

  const fit = useCallback(
    (ids: Iterable<string> | null = null, pos: Positions = posRef.current) => setViewport(fitViewport(pos, ids, size.w, size.h)),
    [size.w, size.h],
  );

  useEffect(() => {
    if (fitPending.current && positions.size > 0) {
      fitPending.current = false;
      fit(null, positions);
    }
  }, [positions, fit]);

  const runLayout = useCallback(
    async (kind: LayoutKind, nodes = visible.nodes, edges = visible.edges, base: Positions = posRef.current, pinned: Set<string> = stateRef.current?.pinned ?? new Set(), markDirty = true) => {
      if (nodes.length === 0) return;
      layoutAbort.current?.abort();
      const ac = new AbortController();
      layoutAbort.current = ac;
      setBusy("Laying out…");
      try {
        const p = await computeLayoutAsync(kind === "manual" ? "force" : kind, nodes, edges, { positions: base, pinned, signal: ac.signal });
        const next = new Map(posRef.current);
        p.forEach((v, k) => next.set(k, v));
        setPositions(next);
        setViewport(fitViewport(next, nodes.map((n) => n.id), size.w, size.h));
        if (markDirty) setDirty(true);
      } catch (e) {
        if ((e as Error)?.name !== "AbortError") notify.error("Layout failed", e);
      } finally {
        if (layoutAbort.current === ac) setBusy(null);
      }
    },
    [visible.nodes, visible.edges, size.w, size.h],
  );

  /* ── load / refresh ── */
  useEffect(() => {
    const data = q.data;
    if (!data || data.graph.id !== graphId) return;
    let alive = true;
    const cur = stateRef.current;
    if (resetRef.current || !cur || cur.graphId !== data.graph.id) {
      resetRef.current = false;
      const s = initState(data);
      setState(s);
      setDirty(false);
      setSelection(EMPTY_SELECTION);
      setHighlight(null);
      setPathStart(null);
      const pos = positionsFrom(data.nodes);
      const m = toCanvas(data.entities, data.relationships, registry.relationshipTypes);
      const missing = s.members.filter((id) => !pos.has(id));
      if (s.workspace.viewport) setViewport(s.workspace.viewport);
      else fitPending.current = true;
      if (missing.length > 0 && missing.length === s.members.length) {
        setPositions(new Map());
        fitPending.current = false;
        void runLayout(s.workspace.layout, m.nodes, m.edges, new Map(), s.pinned, false);
      } else if (missing.length > 0) {
        setPositions(placeNewNodes(m.nodes, m.edges, pos));
      } else {
        setPositions(pos);
      }
      return;
    }
    // refresh: keep local work, merge what changed elsewhere (new entities, deletions, decisions)
    const serverNow = new Set(data.nodes.map((n) => String(n.entityId)));
    const kept = cur.members.filter((id) => serverNow.has(id) || !cur.serverMembers.has(id));
    const added = [...serverNow].filter((id) => !kept.includes(id) && !cur.removed.has(id));
    const members = [...kept, ...added];
    const refresh = members.length <= 5000 ? api.osintEntitiesByIds(inv, members.map(Number)) : Promise.resolve({ entities: data.entities, relationships: data.relationships });
    refresh
      .then((fresh) => {
        if (!alive) return;
        const entities = new Map(fresh.entities.map((e) => [String(e.id), e]));
        const finalMembers = members.filter((id) => entities.has(id));
        const rels = new Map(fresh.relationships.map((r) => [String(r.id), r]));
        setState((s) => {
          if (!s || s.graphId !== data.graph.id) return s;
          // nothing that the canvas shows changed: keep the same state object (no re-render)
          if (
            finalMembers.length === s.members.length &&
            finalMembers.every((id, i) => id === s.members[i]) &&
            sameBriefs(entities, s.entities) &&
            sameBriefs(rels, s.rels) &&
            s.warning === data.warning
          ) {
            return s.revision === data.graph.revision ? s : { ...s, revision: data.graph.revision, serverMembers: serverNow };
          }
          // the loaded state revision is kept: a save elsewhere must still be detected on save
          return { ...s, meta: { ...data.graph, stateRevision: s.stateRevision }, revision: data.graph.revision, entities, rels, members: finalMembers, serverMembers: serverNow, warning: data.warning };
        });
        if (added.length) {
          const m = toCanvas(fresh.entities, fresh.relationships, registry.relationshipTypes);
          setPositions(placeNewNodes(m.nodes, m.edges, posRef.current));
        }
      })
      .catch(() => undefined);
    return () => {
      alive = false;
    };
  }, [q.data]); // eslint-disable-line react-hooks/exhaustive-deps

  /* ── mutations of the working state ── */
  const update = (fn: (s: WorkState) => WorkState, markDirty = true) => {
    setState((s) => (s ? fn(s) : s));
    if (markDirty) setDirty(true);
  };
  const setWorkspace = (patch: Partial<Workspace>) => update((s) => ({ ...s, workspace: { ...s.workspace, ...patch } }));

  const addEntities = useCallback(
    async (ids: number[], select = true) => {
      const s = stateRef.current;
      if (!s || ids.length === 0) return;
      const all = [...new Set([...s.members.map(Number), ...ids])];
      if (all.length > 20000) return notify.warning("The graph is limited to 20,000 entities");
      try {
        const fresh = await api.osintEntitiesByIds(inv, all);
        const entities = new Map(fresh.entities.map((e) => [String(e.id), e]));
        const newIds = ids.map(String).filter((id) => entities.has(id) && !s.members.includes(id));
        const members = [...s.members.filter((id) => entities.has(id)), ...newIds];
        const rels = new Map(fresh.relationships.map((r) => [String(r.id), r]));
        const hidden = new Set([...s.hidden].filter((id) => !ids.map(String).includes(id)));
        const removed = new Set([...s.removed].filter((id) => !newIds.includes(id)));
        setState({ ...s, entities, rels, members, hidden, removed });
        const m = toCanvas(fresh.entities, fresh.relationships, registry.relationshipTypes);
        const pos = placeNewNodes(m.nodes, m.edges, posRef.current);
        setPositions(pos);
        setDirty(true);
        if (select) {
          setSelection({ nodes: new Set(ids.map(String)), edge: null });
          setViewport(fitViewport(pos, ids.map(String), size.w, size.h));
        }
        if (newIds.length) notify.success(`${plural(newIds.length, "entity", "entities")} added to the graph`);
      } catch (e) {
        notify.error("Could not add entities", e);
      }
    },
    [inv, registry.relationshipTypes, size.w, size.h],
  );

  useEffect(() => {
    if (pendingAdd && state) {
      void addEntities(pendingAdd);
      onPendingAddUsed();
    }
  }, [pendingAdd, state != null]); // eslint-disable-line react-hooks/exhaustive-deps

  const expand = async (ids: string[]) => {
    if (!ids.length) return;
    setBusy("Expanding…");
    try {
      const n = await api.osintNeighbors(inv, ids.map(Number), false, MAX_EXPAND);
      const s = stateRef.current;
      if (!s) return;
      const entities = new Map(s.entities);
      n.entities.forEach((e) => entities.set(String(e.id), e));
      const rels = new Map(s.rels);
      n.relationships.forEach((r) => rels.set(String(r.id), r));
      const newIds = n.entities.map((e) => String(e.id)).filter((id) => !s.members.includes(id));
      const members = [...s.members, ...newIds];
      const hidden = new Set([...s.hidden].filter((id) => !newIds.includes(id)));
      setState({ ...s, entities, rels, members, hidden, removed: new Set([...s.removed].filter((id) => !newIds.includes(id))) });
      const m = toCanvas([...entities.values()].filter((e) => members.includes(String(e.id))), [...rels.values()], registry.relationshipTypes);
      setPositions(placeNewNodes(m.nodes, m.edges, posRef.current));
      setDirty(newIds.length > 0 || dirty);
      notify.success(newIds.length ? `${plural(newIds.length, "linked entity", "linked entities")} added` : "No further linked entities", n.entities.length >= MAX_EXPAND ? `Showing the first ${MAX_EXPAND}; expand again to continue.` : undefined);
    } catch (e) {
      notify.error("Could not expand", e);
    } finally {
      setBusy(null);
    }
  };

  const removeFromGraph = (ids: string[]) => {
    update((s) => {
      const set = new Set(ids);
      const removed = new Set(s.removed);
      ids.forEach((id) => s.serverMembers.has(id) && removed.add(id));
      return { ...s, members: s.members.filter((id) => !set.has(id)), removed };
    });
    setSelection(EMPTY_SELECTION);
  };
  const hide = (ids: string[]) => {
    update((s) => ({ ...s, hidden: new Set([...s.hidden, ...ids]) }));
    setSelection(EMPTY_SELECTION);
  };
  const togglePin = (ids: string[]) =>
    update((s) => {
      const pinned = new Set(s.pinned);
      const allPinned = ids.every((id) => pinned.has(id));
      ids.forEach((id) => (allPinned ? pinned.delete(id) : pinned.add(id)));
      return { ...s, pinned };
    });
  const ungroup = (ids: string[]) =>
    update((s) => {
      const nodeGroup = new Map(s.nodeGroup);
      ids.forEach((id) => nodeGroup.set(id, null));
      const used = new Set([...nodeGroup.values()].filter(Boolean));
      return { ...s, nodeGroup, workspace: { ...s.workspace, groups: s.workspace.groups.filter((g) => used.has(g.id)) } };
    });

  const findPath = async (from: string, to: string) => {
    setBusy("Finding a path…");
    try {
      const includeInferred = !ws.filters.hiddenVerifications.includes("inferred");
      const p = await api.osintPath(inv, null, Number(from), Number(to), includeInferred, 8);
      if (!p) {
        notify.info("No path found", `No chain of ${includeInferred ? "" : "reviewed or observed "}relationships within 8 steps connects these entities.`);
        return;
      }
      const missing = p.entities.filter((id) => !stateRef.current?.members.includes(String(id)));
      if (missing.length) await addEntities(missing, false);
      setHighlight({ h: { nodes: new Set(p.entities.map(String)), edges: new Set(p.relationships.map(String)) }, label: `Path: ${plural(p.relationships.length, "step", "steps")}` });
      notify.success("Path found", p.explanation);
    } catch (e) {
      notify.error("Could not find a path", e);
    } finally {
      setBusy(null);
      setPathStart(null);
    }
  };

  /* ── selection → inspector ── */
  const onSelectionChange = (s: Selection) => {
    setSelection(s);
    if (pathStart && s.nodes.size === 1) {
      const [to] = [...s.nodes];
      if (to !== pathStart) void findPath(pathStart, to);
      return;
    }
    if (s.nodes.size === 1 && !s.edge) openEntity(Number([...s.nodes][0]));
    else if (s.edge && s.nodes.size === 0) openRelationship(Number(s.edge));
  };

  /* ── search highlight ── */
  useEffect(() => {
    const ids = searchNodes(visible.nodes, search);
    if (!search.trim()) {
      setHighlight((h) => (h?.label.startsWith("Search") ? null : h));
      return;
    }
    const set = new Set(ids);
    setHighlight({ h: { nodes: set, edges: new Set(visible.edges.filter((e) => set.has(e.source) && set.has(e.target)).map((e) => e.id)) }, label: `Search: ${plural(ids.length, "match", "matches")}` });
  }, [search, visible.nodes, visible.edges]);

  /* ── save ── */
  const save = useCallback(
    async (label?: string, force = false) => {
      const s = stateRef.current;
      if (!s) return false;
      setBusy("Saving…");
      try {
        const nodes = nodeStates(s.members, posRef.current, s.pinned, s.hidden, s.nodeGroup);
        const workspace = { ...s.workspace, viewport };
        const removed = [...s.removed].filter((id) => s.serverMembers.has(id)).map(Number);
        const r = await api.osintGraphSave(s.graphId, {
          baseRevision: s.revision,
          baseStateRevision: s.stateRevision,
          force,
          nodes,
          removed,
          workspace,
          versionLabel: label ?? null,
          manualVersion: false,
        });
        setState((cur) =>
          cur && cur.graphId === s.graphId ? { ...cur, revision: r.revision, stateRevision: r.stateRevision, removed: new Set(), serverMembers: new Set(s.members) } : cur,
        );
        setDirty(false);
        notify.success(r.version ? `Saved as version ${r.version}` : "Saved", r.mergedConcurrentChanges ? "Entities collected while you worked were kept in the graph." : undefined);
        invalidate("osint");
        return true;
      } catch (e) {
        if (e instanceof IpcError && e.kind === "conflict") setConflict(e.message);
        else notify.error("Could not save the graph", e);
        return false;
      } finally {
        setBusy(null);
      }
    },
    [viewport],
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s") {
        e.preventDefault();
        if (stateRef.current) void save();
      }
      if (e.key === "Escape") {
        setMenu(null);
        setPathStart(null);
        if (focusMode && !(e.target instanceof HTMLInputElement)) setFocusMode(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [save, focusMode]);

  const guardUnsaved = async (): Promise<boolean> => {
    if (!dirty) return true;
    return confirm.ask({ title: "Discard unsaved changes?", body: "The open graph has changes that are not saved. Continue without saving them?", confirmLabel: "Discard changes" });
  };
  const openGraph = async (id: number) => {
    if (id === graphId) return setDialog(null);
    if (!(await guardUnsaved())) return;
    setDialog(null);
    setState(null);
    onGraphChange(id);
  };

  /* ── export ── */
  const exportData = async (format: ExportFormat) => {
    const s = stateRef.current;
    if (!s) return;
    if (dirty) {
      const ok = await confirm.ask({ title: "Save before exporting?", body: "Exports are written from the saved graph. Save the current changes first?", confirmLabel: "Save and export", tone: "accent" });
      if (!ok || !(await save())) return;
    }
    try {
      const name = await api.osintExport(s.graphId, format);
      if (name) notify.success(`Exported ${name}`);
    } catch (e) {
      notify.error("Export failed", e);
    }
  };
  const exportImage = async (format: "png" | "svg") => {
    const s = stateRef.current;
    if (!s) return;
    setBusy("Rendering…");
    try {
      const opts = { groups: canvasGroups, pinned: s.pinned, showLabels: ws.labels !== "never" };
      const data =
        format === "png"
          ? await blobToBase64(await exportPng(visible.nodes, visible.edges, positions, { ...opts, background: GRAPH_THEME.background }))
          : exportSvg(visible.nodes, visible.edges, positions, { ...opts, background: GRAPH_THEME.background, title: `${investigation.name} — ${s.meta.name}` });
      const name = await api.osintExportImage(s.graphId, format, data);
      if (name) notify.success(`Exported ${name}`);
    } catch (e) {
      notify.error("Export failed", e);
    } finally {
      setBusy(null);
    }
  };

  /* ── render ── */
  if (graphs.error && !graphs.data) return <ErrorBlock message={graphs.error} onRetry={graphs.reload} />;
  if (graphs.data && graphs.data.length === 0)
    return (
      <EmptyBlock
        icon={Network}
        title="No saved graphs"
        description="Create a graph to map this investigation's entities."
        action={
          <Button variant="primary" onPress={() => setDialog("manager")}>
            <Plus className="size-3.5" />
            New graph
          </Button>
        }
      />
    );
  if (q.error && !q.data) return <ErrorBlock message={q.error} onRetry={q.reload} />;
  if (!state) return <LoadingRows rows={8} />;

  const sel = [...selection.nodes];
  const presentTypes = [...new Set(model.nodes.map((n) => n.type))].sort();
  const presentRelTypes = [...new Set(model.edges.map((e) => e.type))].sort();
  const typeCounts = new Map<string, number>();
  visible.nodes.forEach((n) => typeCounts.set(n.type, (typeCounts.get(n.type) ?? 0) + 1));
  const toggleIn = <T,>(list: T[], v: T, on: boolean) => (on ? list.filter((x) => x !== v) : [...list, v]);
  const groupOfSel = sel.some((id) => state.nodeGroup.get(id));

  const menuTarget = menu?.kind === "node" && menu.id ? (selection.nodes.has(menu.id) ? sel : [menu.id]) : [];

  return (
    <div className={cn("flex flex-col gap-2", focusMode && "fixed inset-0 z-50 bg-background p-3")}>
      {/* toolbar */}
      <div className="flex flex-wrap items-center gap-1.5 rounded-[12px] bg-white/[0.03] p-1.5">
        <Button size="sm" variant="ghost" onPress={() => setDialog("manager")} className="max-w-[260px]">
          <FolderOpen className="size-3.5 shrink-0" />
          <span className="truncate">{state.meta.name}</span>
          {dirty && <span className="size-1.5 shrink-0 rounded-full bg-warning" aria-label="Unsaved changes" />}
        </Button>
        <Tooltip delay={300}>
          <Button size="sm" variant={dirty ? "primary" : "tertiary"} onPress={() => save()} isDisabled={!!busy && busy !== "Laying out…"} aria-label="Save graph">
            <Save className="size-3.5" />
            Save
          </Button>
          <Tooltip.Content>Save layout, membership and filters (Ctrl+S)</Tooltip.Content>
        </Tooltip>
        <Button size="sm" variant="tertiary" onPress={() => setDialog("saveAs")}>
          <SaveAll className="size-3.5" />
          Save as
        </Button>
        <Button size="sm" variant="tertiary" onPress={() => setDialog("versions")}>
          <History className="size-3.5" />
          Versions
        </Button>
        <Dropdown>
          <Button size="sm" variant="tertiary">
            <Download className="size-3.5" />
            Export
            <ChevronDown className="size-3.5" />
          </Button>
          <Dropdown.Popover placement="bottom start">
            <Dropdown.Menu
              aria-label="Export graph"
              onAction={(k) => {
                const key = String(k);
                if (key === "png" || key === "svg") void exportImage(key);
                else void exportData(key as ExportFormat);
              }}
            >
              <Dropdown.Item id="json" textValue="Cyber Hub graph (JSON)">
                <div className="flex flex-col">
                  <span>Cyber Hub graph (JSON)</span>
                  <span className="text-[12px] text-muted">Complete: entities, relationships, evidence, layout. Re-importable.</span>
                </div>
              </Dropdown.Item>
              <Dropdown.Item id="graphml" textValue="GraphML">
                GraphML
              </Dropdown.Item>
              <Dropdown.Item id="csv-entities" textValue="Entities CSV">
                Entities (CSV)
              </Dropdown.Item>
              <Dropdown.Item id="csv-relationships" textValue="Relationships CSV">
                Relationships (CSV)
              </Dropdown.Item>
              <Dropdown.Item id="png" textValue="PNG image">
                Image (PNG)
              </Dropdown.Item>
              <Dropdown.Item id="svg" textValue="SVG image">
                Vector image (SVG)
              </Dropdown.Item>
            </Dropdown.Menu>
          </Dropdown.Popover>
        </Dropdown>
        <Button size="sm" variant="tertiary" onPress={() => setDialog("import")}>
          <Upload className="size-3.5" />
          Import
        </Button>
        <span className="mx-1 h-5 w-px bg-white/[0.06]" aria-hidden />
        <Dropdown>
          <Button size="sm" variant="ghost">
            <Waypoints className="size-3.5" />
            {LAYOUT_LABEL[ws.layout]}
            <ChevronDown className="size-3.5" />
          </Button>
          <Dropdown.Popover placement="bottom start">
            <Dropdown.Menu
              aria-label="Layout"
              onAction={(k) => {
                const kind = String(k) as LayoutKind;
                setWorkspace({ layout: kind });
                if (kind !== "manual") void runLayout(kind);
              }}
            >
              {(Object.keys(LAYOUT_LABEL) as LayoutKind[]).map((k) => (
                <Dropdown.Item key={k} id={k} textValue={LAYOUT_LABEL[k]}>
                  <div className="flex flex-col">
                    <span>{LAYOUT_LABEL[k]}</span>
                    <span className="text-[12px] text-muted">
                      {k === "manual" ? "Keep positions; arrange by dragging" : k === "force" ? "Clusters related entities" : k === "hierarchical" ? "Layers from the most connected entity" : k === "radial" ? "Rings around the most connected entity" : "All entities on a circle"}
                    </span>
                  </div>
                </Dropdown.Item>
              ))}
            </Dropdown.Menu>
          </Dropdown.Popover>
        </Dropdown>
        <Button size="sm" variant="ghost" onPress={() => fit(selection.nodes.size ? sel : visible.nodes.map((n) => n.id))} aria-label="Fit to view">
          <Crosshair className="size-3.5" />
          Fit
        </Button>
        <Dropdown>
          <Button size="sm" variant="ghost">
            {LABEL_MODE[ws.labels]}
            <ChevronDown className="size-3.5" />
          </Button>
          <Dropdown.Popover placement="bottom start">
            <Dropdown.Menu aria-label="Labels" onAction={(k) => setWorkspace({ labels: String(k) as LabelMode })}>
              {(Object.keys(LABEL_MODE) as LabelMode[]).map((k) => (
                <Dropdown.Item key={k} id={k} textValue={LABEL_MODE[k]}>
                  {LABEL_MODE[k]}
                </Dropdown.Item>
              ))}
            </Dropdown.Menu>
          </Dropdown.Popover>
        </Dropdown>
        <Popover>
          <Button size="sm" variant={ws.filters.hiddenTypes.length || ws.filters.hiddenRelationshipTypes.length || ws.filters.flaggedOnly ? "secondary" : "ghost"}>
            <SlidersHorizontal className="size-3.5" />
            Filters
          </Button>
          <Popover.Content placement="bottom start" className="w-[340px] bg-overlay p-0">
            <Popover.Dialog className="flex max-h-[70vh] flex-col gap-4 overflow-y-auto p-4 outline-none">
              <section className="flex flex-col gap-1.5">
                <h3 className="text-[12.5px] font-medium text-muted">Entity types</h3>
                {presentTypes.map((t) => {
                  const on = !ws.filters.hiddenTypes.includes(t);
                  return (
                    <Check
                      key={t}
                      label={
                        <span className="inline-flex items-center gap-1.5">
                          <TypeGlyph type={t} className="size-4 text-[8px]" />
                          {registry.entityTypeLabel(t)}
                        </span>
                      }
                      isSelected={on}
                      onChange={() => setWorkspace({ filters: { ...ws.filters, hiddenTypes: toggleIn(ws.filters.hiddenTypes, t, !on) } })}
                    />
                  );
                })}
              </section>
              <section className="flex flex-col gap-1.5">
                <h3 className="text-[12.5px] font-medium text-muted">Relationships</h3>
                {(["observed", "verified", "inferred", "disputed", "rejected"] as Verification[]).map((v) => {
                  const on = !ws.filters.hiddenVerifications.includes(v);
                  return (
                    <Check
                      key={v}
                      label={VERIFICATION_META[v].label}
                      description={VERIFICATION_META[v].hint}
                      isSelected={on}
                      onChange={() => setWorkspace({ filters: { ...ws.filters, hiddenVerifications: toggleIn(ws.filters.hiddenVerifications, v, !on) } })}
                    />
                  );
                })}
              </section>
              {presentRelTypes.length > 0 && (
                <section className="flex flex-col gap-1.5">
                  <h3 className="text-[12.5px] font-medium text-muted">Relationship types</h3>
                  {presentRelTypes.map((t) => {
                    const on = !ws.filters.hiddenRelationshipTypes.includes(t);
                    return (
                      <Check
                        key={t}
                        label={registry.relationshipTypes.get(t)?.label ?? t}
                        isSelected={on}
                        onChange={() => setWorkspace({ filters: { ...ws.filters, hiddenRelationshipTypes: toggleIn(ws.filters.hiddenRelationshipTypes, t, !on) } })}
                      />
                    );
                  })}
                </section>
              )}
              <Check label="Only entities flagged by threat intelligence" isSelected={ws.filters.flaggedOnly} onChange={(v) => setWorkspace({ filters: { ...ws.filters, flaggedOnly: v } })} />
            </Popover.Dialog>
          </Popover.Content>
        </Popover>
        <AddEntityButton onAdd={(ids) => void addEntities(ids)} />
        <div className="ml-auto flex items-center gap-1.5">
          <SearchInput value={search} onChange={setSearch} placeholder="Search the graph" className="w-[220px]" />
          <Button isIconOnly size="sm" variant={legend ? "secondary" : "ghost"} onPress={() => setLegend((l) => !l)} aria-label={legend ? "Hide legend" : "Show legend"}>
            <Info className="size-3.5" />
          </Button>
          <Button isIconOnly size="sm" variant="ghost" onPress={() => setFocusMode((f) => !f)} aria-label={focusMode ? "Exit full screen" : "Full screen"}>
            {focusMode ? <Minimize2 className="size-3.5" /> : <Maximize2 className="size-3.5" />}
          </Button>
        </div>
      </div>

      {/* selection bar */}
      {(sel.length > 0 || highlight || pathStart || state.hidden.size > 0) && (
        <div className="flex flex-wrap items-center gap-1.5 px-1 text-[12.5px]">
          {sel.length > 0 && (
            <>
              <span className="text-muted">{plural(sel.length, "entity", "entities")} selected</span>
              <Button size="sm" variant="ghost" onPress={() => expand(sel)}>
                <Network className="size-3.5" />
                Expand
              </Button>
              <Button size="sm" variant="ghost" onPress={() => togglePin(sel)}>
                {sel.every((id) => state.pinned.has(id)) ? <PinOff className="size-3.5" /> : <Pin className="size-3.5" />}
                {sel.every((id) => state.pinned.has(id)) ? "Unpin" : "Pin"}
              </Button>
              <Button size="sm" variant="ghost" onPress={() => setDialog("group")}>
                <Group className="size-3.5" />
                Group
              </Button>
              {groupOfSel && (
                <Button size="sm" variant="ghost" onPress={() => ungroup(sel)}>
                  Ungroup
                </Button>
              )}
              <Button size="sm" variant="ghost" onPress={() => hide(sel)}>
                <EyeOff className="size-3.5" />
                Hide
              </Button>
              {sel.length === 1 && (
                <Button
                  size="sm"
                  variant="ghost"
                  onPress={() => {
                    const ids = neighborhoodIds(sel[0], visible.edges, 1);
                    setHighlight({ h: { nodes: ids, edges: new Set(visible.edges.filter((e) => ids.has(e.source) && ids.has(e.target)).map((e) => e.id)) }, label: "Neighbourhood" });
                  }}
                >
                  <ScanSearch className="size-3.5" />
                  Focus
                </Button>
              )}
              {sel.length === 2 && (
                <Button size="sm" variant="ghost" onPress={() => findPath(sel[0], sel[1])}>
                  <Route className="size-3.5" />
                  Find path
                </Button>
              )}
              <Button size="sm" variant="ghost" onPress={() => removeFromGraph(sel)}>
                <Trash2 className="size-3.5" />
                Remove from graph
              </Button>
            </>
          )}
          {pathStart && (
            <ToneChip tone="accent">
              Choose the end of the path · <button type="button" className="underline" onClick={() => setPathStart(null)}>cancel</button>
            </ToneChip>
          )}
          {highlight && (
            <span className="inline-flex items-center gap-1 rounded-full bg-accent-soft px-2 py-0.5 text-accent-soft-foreground">
              {highlight.label}
              <button type="button" aria-label="Clear highlight" onClick={() => (setHighlight(null), setSearch(""))}>
                <X className="size-3" />
              </button>
            </span>
          )}
          {state.hidden.size > 0 && (
            <Button size="sm" variant="ghost" onPress={() => update((s) => ({ ...s, hidden: new Set() }))}>
              <Eye className="size-3.5" />
              Show {plural(state.hidden.size, "hidden entity", "hidden entities")}
            </Button>
          )}
        </div>
      )}

      {state.warning && <p className="rounded-lg bg-warning-soft px-3 py-2 text-[12.5px] text-warning-soft-foreground">{state.warning}</p>}

      {/* canvas */}
      <div ref={wrapRef} className={cn("relative overflow-hidden rounded-[14px] bg-[#0b0d10]", focusMode ? "min-h-0 flex-1" : "h-[calc(100vh-250px)] min-h-[520px]")}>
        {visible.nodes.length === 0 ? (
          <div className="flex h-full items-center justify-center p-6">
            <EmptyBlock
              icon={Network}
              title={model.nodes.length ? "Everything is filtered out" : "This graph is empty"}
              description={model.nodes.length ? "Adjust the filters or show hidden entities." : "Add entities from the search button above, from the inspector, or collect data in Data Sources."}
            />
          </div>
        ) : (
          <GraphCanvas
            nodes={visible.nodes}
            edges={visible.edges}
            positions={positions}
            onPositionsChange={(updates, phase) => {
              setPositions((p) => {
                const next = new Map(p);
                updates.forEach((v, k) => next.set(k, v));
                return next;
              });
              if (phase === "end") {
                setDirty(true);
                if (ws.layout !== "manual") setWorkspace({ layout: "manual" });
              }
            }}
            viewport={viewport}
            onViewportChange={setViewport}
            selection={selection}
            onSelectionChange={onSelectionChange}
            highlight={highlight?.h ?? null}
            groups={canvasGroups}
            pinned={state.pinned}
            showLabels={ws.labels}
            onNodeDoubleClick={(id) => void expand([id])}
            onContextMenu={setMenu}
            className="h-full w-full"
          />
        )}
        {busy && (
          <div className="absolute top-3 left-3 rounded-lg bg-overlay/90 px-3 py-1.5">
            <InlineSpinner label={busy} />
          </div>
        )}
        <div className="pointer-events-none absolute bottom-3 left-3 text-[11.5px] text-muted">
          {plural(visible.nodes.length, "entity", "entities")} · {plural(visible.edges.length, "relationship", "relationships")}
          {model.nodes.length !== visible.nodes.length ? ` (of ${model.nodes.length})` : ""} · double-click expands · right-click for actions
        </div>
        {legend && visible.nodes.length > 0 && (
          <div className="absolute top-3 right-3 max-h-[60%] w-[200px] overflow-y-auto rounded-[12px] bg-overlay/90 p-3 text-[12px]">
            <div className="mb-1.5 font-medium text-muted">Legend</div>
            <ul className="flex flex-col gap-1">
              {[...typeCounts.entries()]
                .sort((a, b) => b[1] - a[1])
                .map(([t, n]) => (
                  <li key={t} className="flex items-center gap-2">
                    <span className="inline-flex size-4 items-center justify-center rounded-full text-[8px] font-semibold text-[#0b0d10]" style={{ backgroundColor: typeStyle(t).color }}>
                      {typeStyle(t).glyph}
                    </span>
                    <span className="flex-1 truncate">{registry.entityTypeLabel(t)}</span>
                    <span className="tabular text-muted">{n}</span>
                  </li>
                ))}
            </ul>
            <div className="mt-3 mb-1.5 font-medium text-muted">Relationships</div>
            <ul className="flex flex-col gap-1 text-muted">
              <li className="flex items-center gap-2">
                <svg width="28" height="6" aria-hidden>
                  <line x1="0" y1="3" x2="28" y2="3" stroke="#e8ebf0" strokeWidth="2" />
                </svg>
                Verified
              </li>
              <li className="flex items-center gap-2">
                <svg width="28" height="6" aria-hidden>
                  <line x1="0" y1="3" x2="28" y2="3" stroke="#e8ebf0" strokeOpacity="0.62" strokeWidth="1.5" />
                </svg>
                Observed
              </li>
              <li className="flex items-center gap-2">
                <svg width="28" height="6" aria-hidden>
                  <line x1="0" y1="3" x2="28" y2="3" stroke="#e8ebf0" strokeOpacity="0.62" strokeWidth="1.5" strokeDasharray="6 4" />
                </svg>
                Inferred (needs review)
              </li>
              <li className="flex items-center gap-2">
                <svg width="28" height="6" aria-hidden>
                  <line x1="1" y1="3" x2="28" y2="3" stroke="#e0a43a" strokeWidth="1.75" strokeDasharray="0.01 4.5" strokeLinecap="round" />
                </svg>
                Disputed
              </li>
              <li className="flex items-center gap-2">
                <span className="inline-block size-3 rounded-full ring-2 ring-[#e5484d]" aria-hidden />
                Flagged entity
              </li>
            </ul>
          </div>
        )}
      </div>

      {/* context menu */}
      {menu && (
        <>
          <div className="fixed inset-0 z-[60]" onClick={() => setMenu(null)} onContextMenu={(e) => (e.preventDefault(), setMenu(null))} aria-hidden />
          <div
            role="menu"
            aria-label="Graph actions"
            className="fixed z-[61] min-w-[200px] rounded-[12px] bg-overlay p-1 text-[13px] shadow-[0_16px_40px_-8px_rgba(0,0,0,0.6)]"
            style={{ left: Math.min(menu.screen.x, window.innerWidth - 220), top: Math.min(menu.screen.y, window.innerHeight - 320) }}
          >
            {(() => {
              const item = (label: string, action: () => void, icon?: React.ReactNode) => (
                <button
                  key={label}
                  type="button"
                  role="menuitem"
                  className="flex w-full items-center gap-2 rounded-lg px-2.5 py-1.5 text-left hover:bg-white/[0.06] focus:bg-white/[0.06] focus:outline-none"
                  onClick={() => {
                    setMenu(null);
                    action();
                  }}
                >
                  {icon}
                  {label}
                </button>
              );
              if (menu.kind === "node" && menu.id) {
                const id = menu.id;
                return [
                  item("Inspect", () => openEntity(Number(id)), <Info className="size-3.5" />),
                  item("Expand linked entities", () => void expand(menuTarget), <Network className="size-3.5" />),
                  item("Collect more about it", () => collectFor(Number(id)), <ScanSearch className="size-3.5" />),
                  item("Find path from here", () => (setPathStart(id), setSelection({ nodes: new Set([id]), edge: null })), <Route className="size-3.5" />),
                  item(menuTarget.every((x) => state.pinned.has(x)) ? "Unpin" : "Pin position", () => togglePin(menuTarget), <Pin className="size-3.5" />),
                  item("Hide", () => hide(menuTarget), <EyeOff className="size-3.5" />),
                  item("Remove from graph", () => removeFromGraph(menuTarget), <Trash2 className="size-3.5" />),
                ];
              }
              if (menu.kind === "edge" && menu.id) {
                const id = menu.id;
                return [
                  item("Inspect relationship", () => openRelationship(Number(id)), <Info className="size-3.5" />),
                  item("Verify", () => void api.osintSetVerification("relationship", Number(id), "verified").then(() => invalidate("osint"), (e) => notify.error("Could not verify", e))),
                  item("Reject", () => void api.osintSetVerification("relationship", Number(id), "rejected").then(() => invalidate("osint"), (e) => notify.error("Could not reject", e))),
                ];
              }
              return [
                item("Fit to view", () => fit(visible.nodes.map((n) => n.id)), <Crosshair className="size-3.5" />),
                item("Re-run layout", () => void runLayout(ws.layout), <Waypoints className="size-3.5" />),
                item("Select all", () => setSelection({ nodes: new Set(visible.nodes.map((n) => n.id)), edge: null })),
              ];
            })()}
          </div>
        </>
      )}

      <GraphManager isOpen={dialog === "manager"} onOpenChange={(o) => !o && setDialog(null)} investigationId={inv} currentId={graphId} onOpen={(id) => void openGraph(id)} />
      <VersionsDialog
        isOpen={dialog === "versions"}
        onOpenChange={(o) => !o && setDialog(null)}
        graph={state.meta}
        dirty={dirty}
        onRestored={() => {
          resetRef.current = true;
          q.reload();
        }}
      />
      <NameDialog
        isOpen={dialog === "saveAs"}
        onOpenChange={(o) => !o && setDialog(null)}
        title="Save as a new graph"
        description="Creates an independent graph with the current layout, membership, filters and groups. The original graph is left as it was last saved."
        initialName={`${state.meta.name} (copy)`}
        showFollow
        initialFollow={false}
        confirmLabel="Save as new graph"
        onConfirm={async (name, _d, follow) => {
          const s = stateRef.current;
          if (!s) return;
          const id = await api.osintGraphSaveAs(s.graphId, name, nodeStates(s.members, posRef.current, s.pinned, s.hidden, s.nodeGroup), { ...s.workspace, viewport }, follow);
          invalidate("osint");
          notify.success(`Saved as “${name}”`);
          setDirty(false);
          setState(null);
          onGraphChange(id);
        }}
      />
      <NameDialog
        isOpen={dialog === "group"}
        onOpenChange={(o) => !o && setDialog(null)}
        title="Group selected entities"
        description="Groups are drawn as a shaded area behind their members and saved with the graph."
        initialName="Group"
        confirmLabel="Create group"
        onConfirm={async (name) => {
          const id = `g${Date.now().toString(36)}`;
          update((s) => {
            const nodeGroup = new Map(s.nodeGroup);
            sel.forEach((n) => nodeGroup.set(n, id));
            return { ...s, nodeGroup, workspace: { ...s.workspace, groups: [...s.workspace.groups, { id, label: name.slice(0, 80), color: nextGroupColor(s.workspace.groups) }] } };
          });
        }}
      />
      <ImportGraphModal
        isOpen={dialog === "import"}
        onOpenChange={(o) => !o && setDialog(null)}
        investigationId={inv}
        onImported={(r) => {
          setDialog(null);
          invalidate("osint");
          if (r.investigationId === inv) void openGraph(r.graphId);
          else notify.info("Imported into a new investigation", "Open it from the investigation list.");
        }}
      />
      <AppModal
        isOpen={conflict !== null}
        onOpenChange={(o) => !o && setConflict(null)}
        title="This graph changed since you opened it"
        description={conflict ?? undefined}
        footer={
          <>
            <Button variant="tertiary" onPress={() => setConflict(null)}>
              Cancel
            </Button>
            <Button
              variant="secondary"
              onPress={() => {
                setConflict(null);
                resetRef.current = true;
                setDirty(false);
                q.reload();
              }}
            >
              Discard mine and reload
            </Button>
            <Button
              variant="secondary"
              onPress={() => {
                setConflict(null);
                setDialog("saveAs");
              }}
            >
              Save mine as a new graph
            </Button>
            <Button
              variant="danger"
              onPress={() => {
                setConflict(null);
                void save(undefined, true);
              }}
            >
              Overwrite
            </Button>
          </>
        }
      >
        <p className="text-[13px] text-muted">
          Your layout, membership and filters were not saved. Entities, relationships and evidence are not affected by any of these choices; overwriting replaces only the other saved
          layout (it stays available in the version history).
        </p>
      </AppModal>
      {confirm.element}
    </div>
  );
}

function sameBriefs<T extends object>(a: Map<string, T>, b: Map<string, T>): boolean {
  if (a.size !== b.size) return false;
  for (const [k, v] of a) {
    const w = b.get(k);
    if (!w || JSON.stringify(v) !== JSON.stringify(w)) return false;
  }
  return true;
}

/** Search the investigation's entities and add the chosen ones to the graph. */
function AddEntityButton({ onAdd }: { onAdd: (ids: number[]) => void }) {
  const { investigation, registry } = useOsint();
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [debounced, setDebounced] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setDebounced(q), 250);
    return () => clearTimeout(t);
  }, [q]);
  const results = useQuery(["osint"], () => api.osintEntities(investigation.id, { q: debounced, limit: 25, sort: "connections" }), [investigation.id, debounced], open);
  return (
    <Popover isOpen={open} onOpenChange={setOpen}>
      <Button size="sm" variant="ghost">
        <Plus className="size-3.5" />
        Add
      </Button>
      <Popover.Content placement="bottom start" className="w-[380px] bg-overlay p-0">
        <Popover.Dialog className="flex flex-col gap-2 p-3 outline-none">
          <SearchInput value={q} onChange={setQ} placeholder="Find an entity of this investigation" autoFocus />
          {results.error ? (
            <p className="text-[12.5px] text-danger">{errorMessage(results.error)}</p>
          ) : !results.data ? (
            <LoadingRows rows={3} />
          ) : results.data.items.length === 0 ? (
            <p className="px-1 py-2 text-[12.5px] text-muted">No entities match.</p>
          ) : (
            <ul className="flex max-h-[320px] flex-col gap-0.5 overflow-y-auto">
              {results.data.items.map((e) => (
                <li key={e.id}>
                  <button
                    type="button"
                    className="flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-[13px] hover:bg-white/[0.06]"
                    onClick={() => {
                      onAdd([e.id]);
                      setOpen(false);
                    }}
                  >
                    <TypeGlyph type={e.type} className="size-5 text-[9px]" />
                    <span className="min-w-0 flex-1 truncate" title={e.value}>
                      {e.displayName}
                    </span>
                    <span className="shrink-0 text-[11.5px] text-muted">
                      {registry.entityTypeLabel(e.type)} · {e.relationships}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
          {results.data && results.data.total > results.data.items.length && (
            <Button
              size="sm"
              variant="tertiary"
              onPress={() => {
                onAdd(results.data!.items.map((e) => e.id));
                setOpen(false);
              }}
            >
              Add these {results.data.items.length}
            </Button>
          )}
        </Popover.Dialog>
      </Popover.Content>
    </Popover>
  );
}
