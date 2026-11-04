/**
 * OSINT Workspace: investigations, the link-analysis graph, entities, timeline, data sources
 * and reports. Route params: `id` (open investigation), `tab`, `graph`.
 */
import { Button, Tabs } from "@heroui/react";
import { listen } from "@tauri-apps/api/event";
import { ArrowLeft, MonitorX } from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { PageHeader } from "@/components/ui/Panel";
import { api, runtimeAvailable } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import { Ctx, registryMaps, type OsintContext, type OsintTab } from "./context";
import { EntitiesTab } from "./EntitiesTab";
import { GraphWorkspace } from "./GraphWorkspace";
import { InspectorPanel, TypeGlyph, type InspectorTarget } from "./Inspector";
import { INVESTIGATION_STATUS_META, InvestigationsView } from "./InvestigationsView";
import { plural } from "./model";
import { OverviewTab } from "./OverviewTab";
import { ReportsTab } from "./ReportsTab";
import { SourcesTab } from "./SourcesTab";
import { TimelineTab } from "./TimelineTab";

const TABS: { id: OsintTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "graph", label: "Link Analysis" },
  { id: "entities", label: "Entities" },
  { id: "timeline", label: "Timeline" },
  { id: "sources", label: "Data Sources" },
  { id: "reports", label: "Reports" },
];

/** Refresh OSINT data when the backend reports changes (background collections, MCP). */
function useOsintEvents() {
  useEffect(() => {
    if (!runtimeAvailable()) return;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const un = listen("osint-changed", () => {
      if (timer) return;
      timer = setTimeout(() => {
        timer = null;
        invalidate("osint");
      }, 400);
    });
    return () => {
      if (timer) clearTimeout(timer);
      void un.then((f) => f());
    };
  }, []);
}

function InvestigationWorkspace({ id, onClose }: { id: number; onClose: () => void }) {
  const { route, navigate } = useApp();
  const registry = useQuery([], api.osintRegistry, []);
  const touched = useRef(false);
  const inv = useQuery(
    ["osint"],
    () => {
      const touch = !touched.current;
      touched.current = true;
      return api.osintInvestigationGet(id, touch);
    },
    [id],
  );
  const [tab, setTab] = useState<OsintTab>((route.params?.tab as OsintTab) ?? "overview");
  const [graphId, setGraphId] = useState<number | null>(route.params?.graph ? Number(route.params.graph) : null);
  const [inspect, setInspect] = useState<InspectorTarget | null>(null);
  const [prefill, setPrefill] = useState<{ entityId: number; provider?: string } | null>(null);
  const [pendingAdd, setPendingAdd] = useState<number[] | null>(null);

  const maps = useMemo(() => (registry.data ? registryMaps(registry.data) : null), [registry.data]);
  const closeInspector = useCallback(() => setInspect(null), []);

  const ctx: OsintContext | null = useMemo(
    () =>
      inv.data && maps
        ? {
            investigation: inv.data,
            registry: maps,
            openEntity: (eid) => setInspect({ kind: "entity", id: eid }),
            openRelationship: (rid) => setInspect({ kind: "relationship", id: rid }),
            openGraph: (gid) => {
              setGraphId(gid);
              setTab("graph");
            },
            goTab: setTab,
            collectFor: (entityId, provider) => {
              setPrefill({ entityId, provider });
              setTab("sources");
            },
          }
        : null,
    [inv.data, maps],
  );

  if ((inv.error && !inv.data) || (registry.error && !registry.data)) {
    return (
      <div className="flex flex-col gap-3">
        <Button size="sm" variant="ghost" onPress={onClose} className="self-start">
          <ArrowLeft className="size-3.5" />
          Investigations
        </Button>
        <ErrorBlock message={inv.error ?? registry.error ?? ""} onRetry={() => (inv.reload(), registry.reload())} />
      </div>
    );
  }
  if (!ctx) return <LoadingRows rows={8} />;
  const i = ctx.investigation;
  const status = INVESTIGATION_STATUS_META[i.status];

  return (
    <Ctx.Provider value={ctx}>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-3">
          <Button isIconOnly size="sm" variant="ghost" onPress={onClose} aria-label="Back to investigations" className="mt-0.5">
            <ArrowLeft className="size-4" />
          </Button>
          <div className="min-w-0">
            <h1 className="truncate text-[20px] font-semibold tracking-tight">{i.name}</h1>
            <div className="mt-1 flex flex-wrap items-center gap-2 text-[12.5px] text-muted">
              <TypeGlyph type={i.targetType} className="size-5 text-[9px]" />
              <span className="font-mono text-foreground">{i.targetValue}</span>
              <ToneChip tone={status.tone}>{status.label}</ToneChip>
              {i.projectName && <span>Project: {i.projectName}</span>}
              <span>
                {plural(i.counts.entities, "entity", "entities")} · {plural(i.counts.relationships, "relationship", "relationships")} · {plural(i.counts.evidence, "evidence record", "evidence records")}
              </span>
              {i.counts.pendingReview > 0 && <ToneChip tone="warning">{i.counts.pendingReview} awaiting review</ToneChip>}
            </div>
          </div>
        </div>
      </div>
      <Tabs
        selectedKey={tab}
        onSelectionChange={(k) => {
          setTab(k as OsintTab);
          navigate("osint", { id: String(id), tab: String(k), ...(graphId ? { graph: String(graphId) } : {}) });
        }}
      >
        <Tabs.ListContainer className="mb-3">
          <Tabs.List aria-label="Investigation sections">
            {TABS.map((t) => (
              <Tabs.Tab key={t.id} id={t.id} className="px-3 text-[13px]">
                {t.label}
                <Tabs.Indicator />
              </Tabs.Tab>
            ))}
          </Tabs.List>
        </Tabs.ListContainer>
        <Tabs.Panel id="overview">
          <OverviewTab onDeleted={onClose} />
        </Tabs.Panel>
        <Tabs.Panel id="graph">
          <GraphWorkspace graphId={graphId} onGraphChange={setGraphId} pendingAdd={pendingAdd} onPendingAddUsed={() => setPendingAdd(null)} />
        </Tabs.Panel>
        <Tabs.Panel id="entities">
          <EntitiesTab />
        </Tabs.Panel>
        <Tabs.Panel id="timeline">
          <TimelineTab />
        </Tabs.Panel>
        <Tabs.Panel id="sources">
          <SourcesTab prefill={prefill} onPrefillUsed={() => setPrefill(null)} />
        </Tabs.Panel>
        <Tabs.Panel id="reports">
          <ReportsTab />
        </Tabs.Panel>
      </Tabs>
      <InspectorPanel
        target={inspect}
        onClose={closeInspector}
        onAddToGraph={(ids) => {
          setPendingAdd(ids);
          setTab("graph");
        }}
      />
    </Ctx.Provider>
  );
}

export default function OsintPage() {
  const { route, navigate, runtime } = useApp();
  useOsintEvents();
  const id = route.params?.id ? Number(route.params.id) : null;
  if (!runtime) {
    return (
      <>
        <PageHeader title="OSINT Workspace" description="Investigations, evidence-backed relationship mapping and public-source collection." />
        <EmptyBlock icon={MonitorX} title="Desktop runtime required" description="Start Cyber Hub with `npm run tauri dev` to use the OSINT workspace." />
      </>
    );
  }
  if (id && Number.isFinite(id)) return <InvestigationWorkspace key={id} id={id} onClose={() => navigate("osint")} />;
  return <InvestigationsView onOpen={(invId) => navigate("osint", { id: String(invId) })} />;
}
