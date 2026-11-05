import { Button, Dropdown } from "@heroui/react";
import { Archive, ChevronDown, CircleCheck, Copy, Lightbulb, Pencil, RotateCcw, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { ToneChip } from "@/components/ui/Badges";
import { useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, QueryView } from "@/components/ui/Feedback";
import { SwitchInput } from "@/components/ui/Fields";
import { Panel, Stat } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import { formatDateTime } from "@/lib/utils";
import { Fact, OP_STATUS_META, TypeBadge } from "./bits";
import { useOsint } from "./context";
import { InvestigationFormModal } from "./InvestigationFormModal";
import { INVESTIGATION_STATUS_META } from "./InvestigationsView";
import { plural, shortTime } from "./model";
import type { EntityBrief, InvestigationStatus, Suggestion } from "./types";

const SUGGESTION_TONE: Record<Suggestion["kind"], "default" | "accent" | "warning" | "danger"> = {
  review_inferred: "warning",
  resolve_duplicates: "warning",
  corroborate: "accent",
  collect: "accent",
  review_flagged: "danger",
  connect_isolated: "default",
};

const SUGGESTION_LABEL: Record<Suggestion["kind"], string> = {
  review_inferred: "Review",
  resolve_duplicates: "Duplicates",
  corroborate: "Corroborate",
  collect: "Collect",
  review_flagged: "Flagged",
  connect_isolated: "Isolated",
};

function useNames(investigationId: number, ids: number[]) {
  const key = ids.join(",");
  const q = useQuery(["osint"], () => (ids.length ? api.osintEntitiesByIds(investigationId, ids) : Promise.resolve({ entities: [], relationships: [] })), [investigationId, key]);
  return useMemo(() => new Map<number, EntityBrief>((q.data?.entities ?? []).map((e) => [e.id, e])), [q.data]);
}

function SuggestionsPanel() {
  const { investigation: inv, openEntity, openRelationship, collectFor } = useOsint();
  const q = useQuery(["osint"], () => api.osintSuggestions(inv.id), [inv.id]);
  return (
    <Panel title="Next steps" description="Computed from the stored data with fixed rules; each item says why it is listed.">
      <QueryView
        query={q}
        rows={3}
        isEmpty={(d) => d.length === 0}
        empty={<EmptyBlock compact icon={CircleCheck} title="Nothing open" description="No unreviewed links, duplicates or collection gaps were found." />}
      >
        {(list) => (
          <ul className="flex flex-col gap-1.5">
            {list.slice(0, 12).map((s, i) => (
              <li key={i} className="tile flex items-start gap-3 px-3 py-2.5">
                <ToneChip tone={SUGGESTION_TONE[s.kind]} className="mt-0.5 shrink-0">
                  {SUGGESTION_LABEL[s.kind]}
                </ToneChip>
                <div className="min-w-0 flex-1">
                  <div className="text-[13px] break-words text-foreground">{s.title}</div>
                  <div className="mt-0.5 text-[12.5px] text-muted">{s.reason}</div>
                </div>
                <div className="flex shrink-0 gap-1">
                  {s.kind === "collect" && s.entityIds[0] != null && (
                    <Button size="sm" variant="tertiary" onPress={() => collectFor(s.entityIds[0], s.provider ?? undefined)}>
                      Collect
                    </Button>
                  )}
                  {s.kind !== "collect" && s.entityIds[0] != null && (
                    <Button size="sm" variant="ghost" onPress={() => openEntity(s.entityIds[0])}>
                      Open
                    </Button>
                  )}
                  {s.entityIds.length === 0 && s.relationshipIds[0] != null && (
                    <Button size="sm" variant="ghost" onPress={() => openRelationship(s.relationshipIds[0])}>
                      Open first
                    </Button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </QueryView>
    </Panel>
  );
}

function AnalysisPanel() {
  const { investigation: inv, openEntity, registry } = useOsint();
  const [includeInferred, setIncludeInferred] = useState(false);
  const q = useQuery(["osint"], () => api.osintAnalysis(inv.id, null, includeInferred), [inv.id, includeInferred]);
  const ids = useMemo(() => {
    const d = q.data;
    if (!d) return [];
    const set = new Set<number>();
    d.hubs.slice(0, 8).forEach((h) => set.add(h.entity));
    d.sharedInfrastructure.slice(0, 6).forEach((s) => set.add(s.infrastructure));
    return [...set];
  }, [q.data]);
  const names = useNames(inv.id, ids);
  const label = (id: number) => names.get(id)?.displayName ?? `#${id}`;

  return (
    <Panel
      title="Graph analysis"
      description="Structure of the reviewed and observed relationships. Connectivity says nothing about maliciousness."
      actions={<SwitchInput label="Include inferred" isSelected={includeInferred} onChange={setIncludeInferred} />}
    >
      <QueryView query={q} rows={3}>
        {(o) => (
          <div className="flex flex-col gap-4">
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <Stat label="Entities" value={o.entities.toLocaleString()} />
              <Stat label="Relationships counted" value={o.relationships.toLocaleString()} />
              <Stat label="Connected groups" value={o.components.filter((c) => c.entities.length > 1).length} hint={o.components[0] ? `largest: ${o.components[0].entities.length}` : undefined} />
              <Stat label="Without links" value={o.isolated.length} />
            </div>
            {o.hubs.length > 0 && (
              <div>
                <div className="mb-1.5 text-[12.5px] font-medium text-muted">Most connected</div>
                <ul className="flex flex-col gap-1">
                  {o.hubs.slice(0, 8).map((h) => (
                    <li key={h.entity}>
                      <Button variant="ghost" size="sm" className="h-auto w-full justify-between gap-3 px-2 py-1.5 font-normal" onPress={() => openEntity(h.entity)}>
                        <TypeBadge type={names.get(h.entity)?.type ?? "other"} label={label(h.entity)} className="text-foreground" />
                        <span className="tabular shrink-0 text-[12.5px] text-muted">{plural(h.degree, "link", "links")}</span>
                      </Button>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {o.sharedInfrastructure.length > 0 && (
              <div>
                <div className="mb-1.5 text-[12.5px] font-medium text-muted">Shared infrastructure</div>
                <ul className="flex flex-col gap-1.5">
                  {o.sharedInfrastructure.slice(0, 6).map((s) => (
                    <li key={`${s.infrastructure}-${s.via}`} className="tile px-3 py-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <Button variant="ghost" size="sm" className="h-auto px-1 py-0.5 font-normal" onPress={() => openEntity(s.infrastructure)}>
                          <TypeBadge type={names.get(s.infrastructure)?.type ?? "other"} label={label(s.infrastructure)} className="text-foreground" />
                        </Button>
                        <span className="text-[12.5px] text-muted">
                          via {registry.relationshipTypes.get(s.via)?.label ?? s.via} · {plural(s.members.length, "entity", "entities")}
                        </span>
                      </div>
                      <div className="mt-0.5 text-[12px] text-muted">{s.note}</div>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <ul className="flex flex-col gap-1 text-[12px] text-muted">
              {o.explanation.map((x, i) => (
                <li key={i}>{x}</li>
              ))}
            </ul>
          </div>
        )}
      </QueryView>
    </Panel>
  );
}

function DuplicatesPanel() {
  const { investigation: inv, openEntity } = useOsint();
  const q = useQuery(["osint"], () => api.osintDuplicates(inv.id), [inv.id]);
  const confirm = useConfirm();

  const merge = async (keep: EntityBrief, drop: EntityBrief) => {
    const ok = await confirm.ask({
      title: "Merge entities",
      body: `Merge “${drop.value}” into “${keep.value}”? Its relationships and evidence move to “${keep.value}”, and the merge is recorded in the history.`,
      confirmLabel: "Merge",
      tone: "accent",
    });
    if (!ok) return;
    try {
      await api.osintEntityMerge(keep.id, drop.id);
      invalidate("osint");
      notify.success("Entities merged");
    } catch (e) {
      notify.error("Could not merge", e);
    }
  };

  if (!q.data || q.data.length === 0) return null;
  return (
    <Panel title="Possible duplicates" description="Entities that differ only in formatting. They are never merged automatically.">
      {confirm.element}
      <ul className="flex flex-col gap-1.5">
        {q.data.slice(0, 20).map((group, gi) => (
          <li key={gi} className="tile flex flex-wrap items-center gap-2 px-3 py-2">
            {group.map((e) => (
              <div key={e.id} className="flex items-center gap-1">
                <Button variant="ghost" size="sm" className="h-auto px-1.5 py-0.5 font-normal" onPress={() => openEntity(e.id)}>
                  <TypeBadge type={e.type} label={e.value} className="font-mono text-foreground" />
                </Button>
                <Dropdown>
                  <Button size="sm" variant="ghost" isIconOnly aria-label={`Merge ${e.value} into another entity`}>
                    <Copy className="size-3.5" />
                  </Button>
                  <Dropdown.Popover placement="bottom start">
                    <Dropdown.Menu
                      aria-label="Merge into"
                      onAction={(k) => {
                        const keep = group.find((x) => String(x.id) === String(k));
                        if (keep) void merge(keep, e);
                      }}
                    >
                      {group
                        .filter((x) => x.id !== e.id)
                        .map((x) => (
                          <Dropdown.Item key={x.id} id={String(x.id)} textValue={x.value}>
                            Merge into {x.value}
                          </Dropdown.Item>
                        ))}
                    </Dropdown.Menu>
                  </Dropdown.Popover>
                </Dropdown>
              </div>
            ))}
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function OperationsPanel() {
  const { investigation: inv, goTab } = useOsint();
  const q = useQuery(["osint", "osint-ops"], () => api.osintOperations(inv.id), [inv.id]);
  return (
    <Panel
      title="Recent collection"
      actions={
        <Button size="sm" variant="ghost" onPress={() => goTab("sources")}>
          Data sources
        </Button>
      }
    >
      <QueryView
        query={q}
        rows={3}
        isEmpty={(d) => d.length === 0}
        empty={
          <EmptyBlock
            compact
            icon={Lightbulb}
            title="No collection yet"
            description="Query a public source about the target, or import data Cyber Hub already holds."
            action={
              <Button size="sm" variant="primary" onPress={() => goTab("sources")}>
                Collect data
              </Button>
            }
          />
        }
      >
        {(ops) => (
          <ul className="flex flex-col gap-1">
            {ops.slice(0, 8).map((o) => (
              <li key={o.id} className="tile flex items-center gap-3 px-3 py-2 text-[13px]">
                <ToneChip tone={OP_STATUS_META[o.status].tone}>{OP_STATUS_META[o.status].label}</ToneChip>
                <span className="shrink-0 text-foreground">{o.providerName}</span>
                <span className="min-w-0 flex-1 truncate font-mono text-[12px] text-muted">{o.inputValue}</span>
                <span className="tabular shrink-0 text-[12px] text-muted">
                  {o.resultCount} results · {o.importedAt ? `${o.importedCount} imported` : o.status === "completed" ? "awaiting review" : shortTime(o.startedAt)}
                </span>
              </li>
            ))}
          </ul>
        )}
      </QueryView>
    </Panel>
  );
}

export function OverviewTab({ onDeleted }: { onDeleted?: () => void }) {
  const { investigation: inv, registry } = useOsint();
  const [editing, setEditing] = useState(false);
  const meta = INVESTIGATION_STATUS_META[inv.status];
  const c = inv.counts;

  const setStatus = async (s: InvestigationStatus) => {
    try {
      await api.osintInvestigationSetStatus(inv.id, s);
      invalidate("osint");
      notify.success(s === "active" ? "Investigation reactivated" : s === "closed" ? "Investigation closed" : "Investigation archived");
    } catch (e) {
      notify.error("Could not change the status", e);
    }
  };

  const remove = async () => {
    try {
      const deleted = await api.osintInvestigationDelete(inv.id);
      if (deleted) {
        invalidate("osint");
        notify.success("Investigation deleted");
        onDeleted?.();
      }
    } catch (e) {
      notify.error("Could not delete the investigation", e);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <Panel
        title="Investigation"
        actions={
          <>
            <Button size="sm" variant="ghost" onPress={() => setEditing(true)}>
              <Pencil className="size-3.5" />
              Edit
            </Button>
            <Dropdown>
              <Button size="sm" variant="ghost" aria-label="Change status">
                {meta.label}
                <ChevronDown className="size-3.5" />
              </Button>
              <Dropdown.Popover placement="bottom end">
                <Dropdown.Menu
                  aria-label="Investigation status"
                  onAction={(k) => {
                    if (k === "delete") void remove();
                    else void setStatus(k as InvestigationStatus);
                  }}
                >
                  {inv.status !== "active" ? (
                    <Dropdown.Item id="active" textValue="Reactivate">
                      <RotateCcw className="size-3.5" /> Reactivate
                    </Dropdown.Item>
                  ) : null}
                  {inv.status !== "closed" ? (
                    <Dropdown.Item id="closed" textValue="Close">
                      <CircleCheck className="size-3.5" /> Close
                    </Dropdown.Item>
                  ) : null}
                  {inv.status !== "archived" ? (
                    <Dropdown.Item id="archived" textValue="Archive">
                      <Archive className="size-3.5" /> Archive
                    </Dropdown.Item>
                  ) : null}
                  <Dropdown.Item id="delete" textValue="Delete" variant="danger">
                    <Trash2 className="size-3.5" /> Delete…
                  </Dropdown.Item>
                </Dropdown.Menu>
              </Dropdown.Popover>
            </Dropdown>
          </>
        }
      >
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Fact label="Primary target">
            <TypeBadge type={inv.targetType} label={`${registry.entityTypeLabel(inv.targetType)} · ${inv.targetValue}`} className="text-foreground" />
          </Fact>
          <Fact label="Status">
            <ToneChip tone={meta.tone}>{meta.label}</ToneChip>
          </Fact>
          <Fact label="Linked project">{inv.projectName ?? "None"}</Fact>
          <Fact label="Tags">{inv.tags.length ? inv.tags.join(", ") : "—"}</Fact>
          <Fact label="Created">{formatDateTime(inv.createdAt)}</Fact>
          <Fact label="Updated">{formatDateTime(inv.updatedAt)}</Fact>
          <Fact label="Authorization or scope note">{inv.authorization || "—"}</Fact>
        </div>
        {inv.description.trim() && <p className="mt-4 max-w-[80ch] text-[13px] whitespace-pre-wrap text-muted">{inv.description}</p>}
        <div className="mt-5 grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-7">
          <Stat label="Entities" value={c.entities.toLocaleString()} />
          <Stat label="Relationships" value={c.relationships.toLocaleString()} />
          <Stat label="Evidence" value={c.evidence.toLocaleString()} />
          <Stat label="Graphs" value={c.graphs} />
          <Stat label="Operations" value={c.operations} />
          <Stat label="To review" value={c.pendingReview} tone={c.pendingReview ? "warning" : "default"} hint={c.pendingReview ? "inferred links" : undefined} />
          <Stat label="Flagged" value={c.flagged} tone={c.flagged ? "danger" : "default"} hint={c.flagged ? "by threat intel" : undefined} />
        </div>
      </Panel>
      <div className="grid gap-4 xl:grid-cols-2">
        <SuggestionsPanel />
        <AnalysisPanel />
      </div>
      <DuplicatesPanel />
      <OperationsPanel />
      <InvestigationFormModal isOpen={editing} onOpenChange={setEditing} investigation={inv} />
    </div>
  );
}
