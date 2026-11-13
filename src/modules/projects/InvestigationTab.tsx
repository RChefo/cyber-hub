import { Button } from "@heroui/react";
import { ArrowRight, Check, Crosshair, Download, GitFork, History, Link2, Network, RotateCcw, Route, Search, Sparkles, Trash2, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useApp } from "@/app/store";
import { SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, InlineSpinner, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput, TextAreaInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery, type Tag } from "@/lib/query";
import type { CorrelationReport, InvestigationGraphFilter, Project, RecordNode, RecordRef, Relation, RelationReview, SearchHit } from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";
import { computeLayoutAsync, exportPng, exportSvg, fitViewport, GraphCanvas, GRAPH_THEME, type Highlight, type Point, type Positions, type Selection, type Viewport } from "@/modules/osint/graph";
import { Segmented } from "@/modules/utilities/tools/shared";
import { AttackMatrixView } from "./AttackMatrixView";
import { DetectionHitsView } from "./DetectionHitsView";
import { KIND_LABEL, RELATION_TYPES, parseKey, provenance, refKey, tabFor, toCanvas } from "./investigation";

const KEYS: Tag[] = ["relations", "findings", "assets", "vulns", "projects"];

/** A record named in a list: kind, label, click to explore it. */
function RecordChip({ node, onOpen }: { node: RecordNode; onOpen: (r: RecordRef) => void }) {
  return (
    <button type="button" onClick={() => onOpen(node.ref)} className="group flex min-w-0 items-center gap-1.5 rounded-md text-left hover:text-accent-soft-foreground" title={`${KIND_LABEL[node.ref.kind]}: ${node.label}`}>
      <ToneChip tone={node.flagged ? "danger" : "default"} dot={false} className="shrink-0 text-[11px]">
        {KIND_LABEL[node.ref.kind]}
      </ToneChip>
      {node.severity && <SeverityBadge severity={node.severity} />}
      <span className="min-w-0 truncate text-[13px] font-medium group-hover:underline">{node.label}</span>
    </button>
  );
}

function Provenance({ r }: { r: Pick<Relation, "origin" | "verification" | "confidence"> }) {
  const tone = r.verification === "verified" ? "success" : r.verification === "rejected" ? "danger" : r.verification === "inferred" ? "warning" : "default";
  return (
    <ToneChip tone={tone} dot={false} className="text-[11px]">
      {provenance(r)}
    </ToneChip>
  );
}

/** Projects → Investigation: correlation, its review, relationships, the graph. */
export function InvestigationTab({
  project,
  record,
  onRecord: setRecord,
  onOpenRecord,
  onTimeline,
}: {
  project: Project;
  /** the record whose related records are open (kept by the project page, so other tabs can open it) */
  record: RecordRef | null;
  onRecord: (r: RecordRef | null) => void;
  onOpenRecord: (r: RecordRef) => void;
  onTimeline: (r: RecordRef, label: string) => void;
}) {
  const { runtime } = useApp();
  const [view, setView] = useState<"queue" | "relations" | "graph" | "attack" | "detections">("queue");
  const [linking, setLinking] = useState<RecordRef | null>(null);
  const [focus, setFocus] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [last, setLast] = useState<CorrelationReport | null>(null);
  const counts = useQuery(KEYS, () => api.relationsList(project.id, { limit: 1 }), [project.id], runtime);
  const rules = useQuery(["relations"], () => api.correlationRules(), [], runtime);
  const archived = project.status === "archived";

  const correlate = async () => {
    setRunning(true);
    try {
      const r = await api.correlateProject(project.id);
      setLast(r);
      invalidate("relations", "projects", "activity");
      notify.success(`${r.stored.new} new suggestion${r.stored.new === 1 ? "" : "s"}`, `${r.stored.updated} updated, ${r.stored.decided} already decided, ${r.stored.linked} already linked · ${r.elapsedMs} ms`);
      setView("queue");
    } catch (e) {
      notify.error("Correlation failed", e);
    } finally {
      setRunning(false);
    }
  };

  const c = counts.data;
  return (
    <div className="flex flex-col gap-4">
      <Panel
        title="Investigation"
        description="Relationships between the records of every module: findings, assets, vulnerabilities, evidence, OSINT entities, API endpoints, SBOM components and ATT&CK techniques. Correlation only suggests: each suggestion says which values matched and stays unconfirmed until you accept it. Nothing is merged."
        actions={
          <Button size="sm" variant="primary" onPress={() => void correlate()} isPending={running} isDisabled={!runtime || archived}>
            <Sparkles className="size-3.5" />
            Correlate
          </Button>
        }
      >
        <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
          {c ? (
            <>
              <ToneChip tone={c.pending ? "warning" : "default"}>{c.pending} to review</ToneChip>
              <ToneChip tone="success">{c.done} decided</ToneChip>
              <ToneChip tone="default">{c.dismissed} dismissed</ToneChip>
            </>
          ) : (
            <InlineSpinner />
          )}
          {archived && <span className="text-muted">The project is archived: relationships can be read, not changed.</span>}
          {last && (
            <span className="text-muted">
              Last run: {Object.entries(last.byRule)
                .map(([rule, n]) => `${rule} ${n}`)
                .join(" · ") || "nothing matched"}
              {last.stored.truncated ? " · the queue is full" : ""}
            </span>
          )}
        </div>
        {rules.data && (
          <details className="mt-2 text-[12.5px]">
            <summary className="cursor-pointer text-muted">How correlation matches ({rules.data.length} rules)</summary>
            <ul className="mt-1.5 flex flex-col gap-1">
              {rules.data.map(([id, what]) => (
                <li key={id}>
                  <span className="font-mono text-[11.5px]">{id}</span> <span className="text-muted">{what}</span>
                </li>
              ))}
            </ul>
          </details>
        )}
      </Panel>
      <Segmented
        value={view}
        onChange={setView}
        ariaLabel="Investigation view"
        options={[
          { id: "queue", label: `Review queue${c ? ` (${c.pending})` : ""}` },
          { id: "relations", label: "Relationships" },
          { id: "graph", label: "Graph" },
          { id: "attack", label: "ATT&CK" },
          { id: "detections", label: "Detections" },
        ]}
      />
      {view === "queue" && <RelationList projectId={project.id} review="pending" archived={archived} onOpen={setRecord} />}
      {view === "relations" && <RelationList projectId={project.id} review="done" archived={archived} onOpen={setRecord} />}
      {view === "graph" && <GraphView project={project} focus={focus} onFocus={setFocus} onOpen={setRecord} />}
      {view === "attack" && <AttackMatrixView project={project} archived={archived} onOpen={setRecord} />}
      {view === "detections" && <DetectionHitsView project={project} archived={archived} onOpen={onOpenRecord} />}
      {record && (
        <RecordPanel
          projectId={project.id}
          record={record}
          archived={archived}
          onClose={() => setRecord(null)}
          onNavigate={setRecord}
          onOpenTab={(r) => {
            setRecord(null);
            onOpenRecord(r);
          }}
          onLink={(r) => setLinking(r)}
          onTimeline={(r, label) => {
            setRecord(null);
            onTimeline(r, label);
          }}
          onGraph={(r) => {
            setRecord(null);
            setFocus(refKey(r));
            setView("graph");
          }}
        />
      )}
      {linking && <LinkModal projectId={project.id} from={linking} onClose={() => setLinking(null)} />}
    </div>
  );
}

/* ───────────────────────── suggestions and relationships ───────────────────────── */

function RelationList({ projectId, review, archived, onOpen }: { projectId: number; review: RelationReview; archived: boolean; onOpen: (r: RecordRef) => void }) {
  const { runtime } = useApp();
  const [verification, setVerification] = useState("all");
  const [minConfidence, setMinConfidence] = useState("low");
  const [page, setPage] = useState(0);
  const size = 25;
  const filter = { review, limit: size, offset: page * size, minConfidence: minConfidence as "low", ...(verification === "all" ? {} : { verification: verification as "verified" }) };
  const q = useQuery(KEYS, () => api.relationsList(projectId, filter), [projectId, review, verification, minConfidence, page], runtime);
  const confirm = useConfirm();
  const [busy, setBusy] = useState<number | null>(null);
  useEffect(() => setPage(0), [review, verification, minConfidence]);

  const act = async (r: Relation, action: "accept" | "reject" | "dismiss" | "reviewed" | "restore" | "unlink") => {
    if (action === "unlink") {
      const ok = await confirm.ask({ title: "Remove this relationship?", body: r.origin === "manual" ? "The link you made is deleted, with the finding link it created." : "It is kept as rejected, so correlation does not suggest it again.", confirmLabel: "Remove" });
      if (!ok) return;
    }
    setBusy(r.id);
    try {
      if (action === "unlink") await api.relationUnlink(r.id);
      else await api.relationReview(r.id, action);
      invalidate(...KEYS, "activity", "projects");
    } catch (e) {
      notify.error("Could not change the relationship", e);
    } finally {
      setBusy(null);
    }
  };

  const items = q.data?.items ?? [];
  const total = q.data?.total ?? 0;
  return (
    <Panel
      title={review === "pending" ? "Suggestions to review" : "Decided relationships"}
      description={
        review === "pending"
          ? "Accept a suggestion to confirm it (a finding's link to an asset, vulnerability, evidence or OSINT entity is then created), reject it if it is wrong (it is not suggested again), dismiss it if it does not matter, or mark it reviewed to keep it unconfirmed."
          : "Relationships you confirmed, rejected, marked reviewed or made by hand. Removing one made by hand deletes it; removing a suggestion keeps it as rejected."
      }
      actions={
        <div className="flex flex-wrap gap-2">
          {review === "done" && (
            <SelectInput
              aria-label="Verification"
              value={verification}
              onChange={setVerification}
              options={[
                { id: "all", label: "All decisions" },
                { id: "verified", label: "Confirmed" },
                { id: "inferred", label: "Reviewed, unconfirmed" },
                { id: "rejected", label: "Rejected" },
              ]}
              className="w-48"
            />
          )}
          <SelectInput
            aria-label="Confidence"
            value={minConfidence}
            onChange={setMinConfidence}
            options={[
              { id: "low", label: "Any confidence" },
              { id: "medium", label: "Medium or high" },
              { id: "high", label: "High" },
            ]}
            className="w-40"
          />
        </div>
      }
    >
      {q.error ? (
        <ErrorBlock message={q.error} onRetry={q.reload} />
      ) : !q.data ? (
        <LoadingRows rows={3} />
      ) : items.length === 0 ? (
        <EmptyBlock compact icon={GitFork} title={review === "pending" ? "Nothing to review" : "No decided relationships yet"} description={review === "pending" ? "Run correlation to look for matches between the project's records." : "Accept or reject suggestions, or link records from a record's panel."} />
      ) : (
        <div className="flex flex-col gap-2">
          <ul className="flex flex-col gap-2">
            {items.map((r) => (
              <li key={r.id} className="panel-inset flex flex-col gap-1.5 px-3 py-2.5">
                <div className="flex min-w-0 flex-wrap items-center gap-2">
                  <RecordChip node={r.a} onOpen={onOpen} />
                  <span className="shrink-0 text-[12.5px] text-muted">{r.label}</span>
                  <RecordChip node={r.b} onOpen={onOpen} />
                </div>
                <p className="text-[12.5px]">{r.reason}</p>
                {r.matched.length > 0 && (
                  <ul className="flex flex-col gap-0.5 font-mono text-[11.5px] text-muted">
                    {r.matched.map((m, i) => (
                      <li key={i} className="break-all">
                        {m.fieldA} = {m.valueA} <span className="text-foreground/70">↔</span> {m.fieldB} = {m.valueB} <span className="text-foreground/70">({m.how})</span>
                      </li>
                    ))}
                  </ul>
                )}
                <div className="flex flex-wrap items-center gap-2">
                  <Provenance r={r} />
                  {r.rules.map((x) => (
                    <ToneChip key={x} tone="default" dot={false} className="font-mono text-[11px]">
                      {x}
                    </ToneChip>
                  ))}
                  <span className="text-[11.5px] text-muted">
                    {r.createdBy === "correlation" ? "found by correlation" : `by ${r.createdBy}`} {formatRelative(r.createdAt)}
                    {r.reviewedAt ? ` · decided ${formatRelative(r.reviewedAt)}` : ""}
                    {r.materialized ? " · finding link created" : ""}
                  </span>
                  {r.note && <span className="text-[11.5px] text-muted">· “{r.note}”</span>}
                  <span className="flex-1" />
                  {!archived &&
                    (review === "pending" ? (
                      <>
                        <Button size="sm" variant="primary" onPress={() => void act(r, "accept")} isPending={busy === r.id} aria-label={`Accept: ${r.a.label} ${r.label} ${r.b.label}`}>
                          <Check className="size-3.5" />
                          Accept
                        </Button>
                        <Button size="sm" variant="tertiary" onPress={() => void act(r, "reject")} isDisabled={busy === r.id}>
                          <X className="size-3.5" />
                          Reject
                        </Button>
                        <Button size="sm" variant="ghost" onPress={() => void act(r, "dismiss")} isDisabled={busy === r.id}>
                          Dismiss
                        </Button>
                        <Button size="sm" variant="ghost" onPress={() => void act(r, "reviewed")} isDisabled={busy === r.id}>
                          Reviewed
                        </Button>
                      </>
                    ) : (
                      <>
                        {r.origin !== "manual" && (
                          <Button size="sm" variant="ghost" onPress={() => void act(r, "restore")} isDisabled={busy === r.id}>
                            <RotateCcw className="size-3.5" />
                            Back to review
                          </Button>
                        )}
                        {r.verification !== "rejected" && (
                          <Button size="sm" variant="ghost" onPress={() => void act(r, "unlink")} isDisabled={busy === r.id} aria-label={`Remove: ${r.a.label} ${r.label} ${r.b.label}`}>
                            <Trash2 className="size-3.5" />
                            Remove
                          </Button>
                        )}
                      </>
                    ))}
                </div>
              </li>
            ))}
          </ul>
          {total > size && (
            <div className="flex items-center gap-2 text-[12.5px] text-muted">
              <Button size="sm" variant="ghost" isDisabled={page === 0} onPress={() => setPage((p) => p - 1)}>
                Previous
              </Button>
              <span>
                {page * size + 1}–{Math.min(total, (page + 1) * size)} of {total}
              </span>
              <Button size="sm" variant="ghost" isDisabled={(page + 1) * size >= total} onPress={() => setPage((p) => p + 1)}>
                Next
              </Button>
            </div>
          )}
        </div>
      )}
      {confirm.element}
    </Panel>
  );
}

/* ───────────────────────── one record ───────────────────────── */

function RecordPanel({
  projectId,
  record,
  archived,
  onClose,
  onNavigate,
  onOpenTab,
  onLink,
  onTimeline,
  onGraph,
}: {
  projectId: number;
  record: RecordRef;
  archived: boolean;
  onClose: () => void;
  onNavigate: (r: RecordRef) => void;
  onOpenTab: (r: RecordRef) => void;
  onLink: (r: RecordRef) => void;
  onTimeline: (r: RecordRef, label: string) => void;
  onGraph: (r: RecordRef) => void;
}) {
  const { runtime } = useApp();
  const [rejected, setRejected] = useState(false);
  const key = refKey(record);
  const q = useQuery(KEYS, () => api.relatedRecords(projectId, record, rejected), [projectId, key, rejected], runtime);
  const v = q.data;
  const groups = useMemo(() => {
    const out = new Map<string, NonNullable<typeof v>["related"]>();
    for (const r of v?.related ?? []) out.set(r.via, [...(out.get(r.via) ?? []), r]);
    return [...out.entries()];
  }, [v]);
  const tab = tabFor(record);
  return (
    <AppModal
      isOpen
      onOpenChange={(o) => !o && onClose()}
      size="lg"
      title={v ? v.node.label : "Record"}
      description={v ? `${KIND_LABEL[record.kind]} · ${v.node.detail}` : KIND_LABEL[record.kind]}
      footer={
        <div className="flex w-full flex-wrap items-center gap-2">
          <SwitchInput label="Show rejected" isSelected={rejected} onChange={setRejected} />
          <span className="flex-1" />
          {["finding", "asset", "evidence", "vulnerability", "execution"].includes(record.kind) && (
            <Button variant="tertiary" onPress={() => onTimeline(record, v?.node.label ?? refKey(record))}>
              <History className="size-3.5" />
              Timeline
            </Button>
          )}
          <Button variant="tertiary" onPress={() => onGraph(record)}>
            <Network className="size-3.5" />
            Show in graph
          </Button>
          {!archived && (
            <Button variant="tertiary" onPress={() => onLink(record)}>
              <Link2 className="size-3.5" />
              Link to…
            </Button>
          )}
          {tab !== "osint" && (
            <Button variant="primary" onPress={() => onOpenTab(record)}>
              Open
              <ArrowRight className="size-3.5" />
            </Button>
          )}
        </div>
      }
    >
      {q.error ? (
        <ErrorBlock message={q.error} onRetry={q.reload} />
      ) : !v ? (
        <LoadingRows rows={4} />
      ) : (
        <div className="flex flex-col gap-4">
          {groups.length === 0 ? (
            <EmptyBlock compact icon={GitFork} title="Nothing related yet" description="Run correlation, or link this record to another one." />
          ) : (
            groups.map(([via, items]) => (
              <section key={via} className="flex flex-col gap-1.5">
                <h3 className="text-[12.5px] font-medium text-muted">
                  {via} ({items.length})
                </h3>
                <ul className="flex flex-col gap-1">
                  {items.map((r) => (
                    <li key={`${r.node.key}-${r.relationId ?? "l"}`} className="tile flex flex-wrap items-center gap-2 px-3 py-1.5">
                      <RecordChip node={r.node} onOpen={onNavigate} />
                      <span className="flex-1" />
                      <Provenance r={{ origin: r.origin, verification: r.verification, confidence: "high" }} />
                    </li>
                  ))}
                </ul>
              </section>
            ))
          )}
          {v.events.length > 0 && (
            <section className="flex flex-col gap-1">
              <h3 className="text-[12.5px] font-medium text-muted">Timeline</h3>
              <ol className="flex flex-col gap-0.5 text-[12.5px]">
                {v.events.slice(0, 20).map((e) => (
                  <li key={e.cursor} className="flex gap-3">
                    <span className="w-32 shrink-0 tabular text-muted">{e.at.slice(0, 16).replace("T", " ")}</span>
                    <span className="min-w-0">
                      {e.title}
                      {e.detail && <span className="text-muted"> · {e.detail}</span>}
                    </span>
                  </li>
                ))}
              </ol>
            </section>
          )}
        </div>
      )}
    </AppModal>
  );
}

function LinkModal({ projectId, from, onClose }: { projectId: number; from: RecordRef; onClose: () => void }) {
  const [text, setText] = useState("");
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [target, setTarget] = useState<SearchHit | null>(null);
  const [relType, setRelType] = useState<string | null>("related_to");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (text.trim().length < 2) {
      setHits([]);
      return;
    }
    let alive = true;
    const t = setTimeout(() => {
      api
        .recordsSearch({ text, projectId, limit: 30 })
        .then((h) => alive && setHits(h.filter((x) => x.node.ref.kind !== "project" && refKey(x.node.ref) !== refKey(from))))
        .catch((e) => alive && setError(String(e)));
    }, 250);
    return () => {
      alive = false;
      clearTimeout(t);
    };
  }, [text, projectId, from]);
  const link = async () => {
    if (!target || !relType) return;
    setBusy(true);
    try {
      await api.relationLink(projectId, from, target.node.ref, relType, note);
      invalidate(...KEYS, "activity");
      notify.success("Linked", `${target.node.label}`);
      onClose();
    } catch (e) {
      notify.error("Could not link the records", e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <AppModal
      isOpen
      onOpenChange={(o) => !o && onClose()}
      title="Link to another record"
      description="A link you make is confirmed (origin: analyst). Between a finding and an asset, vulnerability, evidence record or OSINT entity it also creates the finding link."
      footer={
        <>
          <Button variant="tertiary" onPress={onClose}>
            Cancel
          </Button>
          <Button variant="primary" onPress={() => void link()} isPending={busy} isDisabled={!target || !relType}>
            <Link2 className="size-3.5" />
            Link
          </Button>
        </>
      }
    >
      <SearchInput value={text} onChange={setText} placeholder="Search findings, assets, evidence, CVEs, endpoints, packages, techniques…" autoFocus />
      {error && <ErrorBlock message={error} />}
      <ul className="flex max-h-64 flex-col gap-1 overflow-auto">
        {hits.map((h) => (
          <li key={h.node.key}>
            <button
              type="button"
              onClick={() => setTarget(h)}
              className={cn("flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-[13px] hover:bg-white/[0.04]", target?.node.key === h.node.key && "bg-accent-soft/40")}
              aria-pressed={target?.node.key === h.node.key}
            >
              <ToneChip tone="default" dot={false} className="shrink-0 text-[11px]">
                {KIND_LABEL[h.node.ref.kind]}
              </ToneChip>
              <span className="min-w-0 truncate">{h.node.label}</span>
              <span className="ml-auto shrink-0 text-[11.5px] text-muted">{h.node.detail}</span>
            </button>
          </li>
        ))}
        {text.trim().length >= 2 && hits.length === 0 && <li className="px-2 text-[12.5px] text-muted">No record matches.</li>}
      </ul>
      <SelectInput label="Relationship" value={relType} onChange={setRelType} options={RELATION_TYPES} className="w-64" />
      <TextAreaInput label="Note (optional)" value={note} onChange={setNote} rows={2} />
    </AppModal>
  );
}

/* ───────────────────────── graph ───────────────────────── */

async function blobToBase64(blob: Blob): Promise<string> {
  const buf = new Uint8Array(await blob.arrayBuffer());
  let bin = "";
  for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  return btoa(bin);
}

function useSize<T extends HTMLElement>(): [React.RefObject<T | null>, { w: number; h: number }] {
  const ref = useRef<T | null>(null);
  const [size, setSize] = useState({ w: 800, h: 520 });
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setSize({ w: Math.max(200, e.contentRect.width), h: Math.max(200, e.contentRect.height) }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  return [ref, size];
}

function GraphView({ project, focus, onFocus, onOpen }: { project: Project; focus: string | null; onFocus: (k: string | null) => void; onOpen: (r: RecordRef) => void }) {
  const { runtime } = useApp();
  const [includePending, setIncludePending] = useState(false);
  const [includeRejected, setIncludeRejected] = useState(false);
  const [minConfidence, setMinConfidence] = useState<"low" | "medium" | "high">("low");
  const [depth, setDepth] = useState("2");
  const filter: InvestigationGraphFilter = { includePending, includeRejected, minConfidence, ...(focus ? { focus, depth: Number(depth) } : {}) };
  const q = useQuery(KEYS, () => api.investigationGraph(project.id, filter), [project.id, includePending, includeRejected, minConfidence, focus, depth], runtime);
  const model = useMemo(() => (q.data ? toCanvas(q.data) : { nodes: [], edges: [] }), [q.data]);
  const [positions, setPositions] = useState<Positions>(new Map());
  const [viewport, setViewport] = useState<Viewport>({ x: 0, y: 0, zoom: 1 });
  const [selection, setSelection] = useState<Selection>({ nodes: new Set(), edge: null });
  const [highlight, setHighlight] = useState<Highlight | null>(null);
  const [laying, setLaying] = useState(false);
  const [boxRef, size] = useSize<HTMLDivElement>();

  const layout = useCallback(async () => {
    if (model.nodes.length === 0) return;
    setLaying(true);
    try {
      const p = await computeLayoutAsync("force", model.nodes, model.edges, {});
      setPositions(p);
      setViewport(fitViewport(p, model.nodes.map((n) => n.id), size.w, size.h));
    } catch (e) {
      if ((e as Error)?.name !== "AbortError") notify.error("Layout failed", e);
    } finally {
      setLaying(false);
    }
  }, [model, size.w, size.h]);
  useEffect(() => {
    void layout();
    setHighlight(null);
    // the layout follows the data, not the size
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [model]);

  const selected = [...selection.nodes];
  const path = async () => {
    if (selected.length !== 2) return;
    try {
      const p = await api.investigationPath(project.id, selected[0], selected[1], { includePending, includeRejected, minConfidence });
      if (!p) {
        notify.info("Not connected", "No chain of relationships joins these two records with the current filters.");
        setHighlight(null);
        return;
      }
      const nodes = new Set(p);
      const edges = new Set(model.edges.filter((e) => p.some((k, i) => i > 0 && ((p[i - 1] === e.source && k === e.target) || (p[i - 1] === e.target && k === e.source)))).map((e) => e.id));
      setHighlight({ nodes, edges });
      notify.success(`Path of ${p.length - 1} step${p.length === 2 ? "" : "s"}`, p.map((k) => model.nodes.find((n) => n.id === k)?.label ?? k).join(" → "));
    } catch (e) {
      notify.error("Could not find a path", e);
    }
  };
  const exportAs = async (format: "json" | "svg" | "png") => {
    try {
      let name: string | null;
      if (format === "json") name = await api.investigationGraphExport(project.id, filter);
      else if (format === "svg") name = await api.investigationGraphExportImage(project.id, "svg", exportSvg(model.nodes, model.edges, positions, { background: GRAPH_THEME.background, title: `${project.name}: investigation graph` }));
      else name = await api.investigationGraphExportImage(project.id, "png", await blobToBase64(await exportPng(model.nodes, model.edges, positions, { background: GRAPH_THEME.background })));
      if (name) notify.success("Graph exported", name);
    } catch (e) {
      notify.error("Could not export the graph", e);
    }
  };

  const focusLabel = focus ? (q.data?.nodes.find((n) => n.key === focus)?.label ?? focus) : null;
  return (
    <Panel
      title="Investigation graph"
      description="Confirmed relationships and finding links; suggestions and rejected ones on request. Solid lines are confirmed, dashed ones unconfirmed. Select one record to explore its neighbourhood, two to find the shortest chain between them; double-click opens a record."
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <SwitchInput label="Suggestions" isSelected={includePending} onChange={setIncludePending} />
          <SwitchInput label="Rejected" isSelected={includeRejected} onChange={setIncludeRejected} />
          <SelectInput
            aria-label="Confidence"
            value={minConfidence}
            onChange={(v) => setMinConfidence(v as "low")}
            options={[
              { id: "low", label: "Any confidence" },
              { id: "medium", label: "Medium or high" },
              { id: "high", label: "High" },
            ]}
            className="w-40"
          />
        </div>
      }
    >
      <div className="mb-2 flex flex-wrap items-center gap-2 text-[12.5px]">
        {focusLabel && (
          <>
            <ToneChip tone="accent" dot={false}>
              Neighbourhood of {focusLabel}
            </ToneChip>
            <SelectInput aria-label="Depth" value={depth} onChange={(v) => setDepth(v ?? "2")} options={["1", "2", "3", "4"].map((d) => ({ id: d, label: `${d} step${d === "1" ? "" : "s"}` }))} className="w-28" />
            <Button size="sm" variant="ghost" onPress={() => onFocus(null)}>
              Whole graph
            </Button>
          </>
        )}
        {selected.length === 1 && (
          <>
            <Button size="sm" variant="tertiary" onPress={() => onFocus(selected[0])}>
              <Crosshair className="size-3.5" />
              Neighbourhood
            </Button>
            <Button size="sm" variant="tertiary" onPress={() => { const r = parseKey(selected[0]); if (r) onOpen(r); }}>
              <Search className="size-3.5" />
              Related records
            </Button>
          </>
        )}
        {selected.length === 2 && (
          <Button size="sm" variant="tertiary" onPress={() => void path()}>
            <Route className="size-3.5" />
            Shortest path
          </Button>
        )}
        <span className="flex-1" />
        {(["json", "svg", "png"] as const).map((f) => (
          <Button key={f} size="sm" variant="ghost" onPress={() => void exportAs(f)} isDisabled={model.nodes.length === 0}>
            <Download className="size-3.5" />
            {f.toUpperCase()}
          </Button>
        ))}
      </div>
      {q.error ? (
        <ErrorBlock message={q.error} onRetry={q.reload} />
      ) : !q.data ? (
        <LoadingRows rows={4} />
      ) : model.nodes.length === 0 ? (
        <EmptyBlock compact icon={Network} title="No relationships to draw" description="Accept suggestions, link records by hand or turn on suggestions above." />
      ) : (
        <div ref={boxRef} className="relative h-[560px] w-full overflow-hidden rounded-[10px] bg-background">
          <GraphCanvas
            nodes={model.nodes}
            edges={model.edges}
            positions={positions}
            onPositionsChange={(updates: Map<string, Point>) =>
              setPositions((p) => {
                const next = new Map(p);
                updates.forEach((v, k) => next.set(k, v));
                return next;
              })
            }
            viewport={viewport}
            onViewportChange={setViewport}
            selection={selection}
            onSelectionChange={setSelection}
            highlight={highlight}
            onNodeDoubleClick={(id) => {
              const r = parseKey(id);
              if (r) onOpen(r);
            }}
            className="h-full w-full"
          />
          {laying && (
            <div className="absolute top-3 left-3 rounded-lg bg-overlay/90 px-3 py-1.5">
              <InlineSpinner label="Laying out…" />
            </div>
          )}
          <div className="pointer-events-none absolute bottom-3 left-3 text-[11.5px] text-muted">
            {q.data.nodes.length} records · {q.data.edges.length} relationships{q.data.truncated ? " (limited)" : ""}
          </div>
        </div>
      )}
    </Panel>
  );
}
