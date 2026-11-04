import { Button, Chip } from "@heroui/react";
import { ChevronLeft, ChevronRight, History } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { ToneChip } from "@/components/ui/Badges";
import { EmptyBlock, QueryView } from "@/components/ui/Feedback";
import { SearchInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { api } from "@/lib/ipc";
import { useQuery } from "@/lib/query";
import { cn } from "@/lib/utils";
import { useDebounced } from "./bits";
import { useOsint } from "./context";
import type { TimelineEvent, TimelineQuery } from "./types";

const PAGE = 100;

export const EVENT_KIND_LABEL: Record<string, string> = {
  investigation: "Investigation",
  collection: "Collection",
  entity_discovered: "Entity found",
  relationship_discovered: "Link found",
  relationship_inferred: "Link inferred",
  verification: "Review",
  annotation: "Note",
  entity_merged: "Merge",
  entity_removed: "Entity removed",
  relationship_removed: "Link removed",
  graph: "Graph",
  discovery: "Discovery",
  import: "Import",
  export: "Export",
};

const KIND_TONE: Record<string, "default" | "accent" | "success" | "warning" | "danger"> = {
  entity_discovered: "accent",
  relationship_discovered: "accent",
  relationship_inferred: "warning",
  verification: "success",
  entity_removed: "danger",
  relationship_removed: "danger",
};

function localDay(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(0, 10);
  return d.toLocaleDateString(undefined, { weekday: "short", year: "numeric", month: "short", day: "numeric" });
}

function localTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso.slice(11, 16);
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

/** Group events (newest first) by local day, keeping order. */
export function groupByDay(events: readonly TimelineEvent[]): [string, TimelineEvent[]][] {
  const out: [string, TimelineEvent[]][] = [];
  for (const e of events) {
    const day = localDay(e.at);
    const last = out[out.length - 1];
    if (last && last[0] === day) last[1].push(e);
    else out.push([day, [e]]);
  }
  return out;
}

/** yyyy-mm-dd from a date input → inclusive ISO bounds. */
export function dayBounds(from: string, to: string): { from: string | null; to: string | null } {
  return {
    from: /^\d{4}-\d{2}-\d{2}$/.test(from) ? `${from}T00:00:00` : null,
    to: /^\d{4}-\d{2}-\d{2}$/.test(to) ? `${to}T23:59:59.999` : null,
  };
}

export function TimelineTab() {
  const { investigation: inv, registry, openEntity, openRelationship, openGraph } = useOsint();
  const [kinds, setKinds] = useState<Set<string>>(new Set());
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [source, setSource] = useState("");
  const [text, setText] = useState("");
  const [page, setPage] = useState(0);
  const dText = useDebounced(text);
  const dSource = useDebounced(source);

  useEffect(() => setPage(0), [kinds, from, to, dText, dSource]);

  const query: TimelineQuery = useMemo(() => {
    const b = dayBounds(from, to);
    return { kinds: [...kinds], from: b.from, to: b.to, source: dSource.trim() || null, q: dText.trim() || null, offset: page * PAGE, limit: PAGE };
  }, [kinds, from, to, dSource, dText, page]);
  const data = useQuery(["osint"], () => api.osintTimeline(inv.id, query), [inv.id, query]);
  const total = data.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE));

  const toggle = (k: string) =>
    setKinds((s) => {
      const n = new Set(s);
      if (n.has(k)) n.delete(k);
      else n.add(k);
      return n;
    });

  return (
    <Panel title="Timeline" description="Everything that happened in this investigation: collection, discoveries, review decisions, graph saves, imports and exports.">
      <div className="mb-3 flex flex-col gap-3">
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Event kinds">
          {registry.raw.eventKinds.map((k) => {
            const on = kinds.has(k);
            return (
              <Button
                key={k}
                size="sm"
                variant={on ? "primary" : "ghost"}
                className={cn("h-7 px-2.5 text-[12.5px]", !on && "bg-white/[0.03]")}
                onPress={() => toggle(k)}
                aria-pressed={on}
              >
                {EVENT_KIND_LABEL[k] ?? k}
              </Button>
            );
          })}
          {kinds.size > 0 && (
            <Button size="sm" variant="ghost" className="h-7 px-2.5 text-[12.5px]" onPress={() => setKinds(new Set())}>
              Clear
            </Button>
          )}
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <SearchInput value={text} onChange={setText} placeholder="Search event text" className="max-w-xs" />
          <TextInput aria-label="Source" value={source} onChange={setSource} placeholder="Source (dns, crtsh, analyst…)" className="w-56" />
          <TextInput label="From" type="date" value={from} onChange={setFrom} className="w-40" />
          <TextInput label="To" type="date" value={to} onChange={setTo} className="w-40" />
        </div>
      </div>
      <QueryView
        query={data}
        rows={6}
        isEmpty={(d) => d.items.length === 0}
        empty={<EmptyBlock compact icon={History} title="No events match these filters" />}
      >
        {(d) => (
          <div className="flex flex-col gap-4">
            {groupByDay(d.items).map(([day, events]) => (
              <section key={day}>
                <h3 className="mb-1.5 text-[12.5px] font-medium text-muted">{day}</h3>
                <ol className="flex flex-col gap-1">
                  {events.map((e) => (
                    <li key={e.id} className="tile flex items-start gap-3 px-3 py-2">
                      <span className="tabular mt-0.5 w-12 shrink-0 text-[12px] text-muted">{localTime(e.at)}</span>
                      <ToneChip tone={KIND_TONE[e.kind] ?? "default"} className="mt-px shrink-0">
                        {EVENT_KIND_LABEL[e.kind] ?? e.kind}
                      </ToneChip>
                      <div className="min-w-0 flex-1">
                        <div className="text-[13px] break-words text-foreground">{e.summary}</div>
                        <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[12px] text-muted">
                          {e.source && <Chip size="sm" variant="soft">{e.source}</Chip>}
                          {e.entityId != null && (
                            <Button size="sm" variant="ghost" className="h-6 px-1.5 text-[12px]" onPress={() => openEntity(e.entityId!)}>
                              Entity
                            </Button>
                          )}
                          {e.relationshipId != null && (
                            <Button size="sm" variant="ghost" className="h-6 px-1.5 text-[12px]" onPress={() => openRelationship(e.relationshipId!)}>
                              Relationship
                            </Button>
                          )}
                          {e.graphId != null && (
                            <Button size="sm" variant="ghost" className="h-6 px-1.5 text-[12px]" onPress={() => openGraph(e.graphId!)}>
                              Graph
                            </Button>
                          )}
                        </div>
                      </div>
                    </li>
                  ))}
                </ol>
              </section>
            ))}
            {pages > 1 && (
              <div className="flex items-center justify-end gap-2 text-[12.5px] text-muted">
                <span className="tabular">
                  {d.offset + 1}–{d.offset + d.items.length} of {total.toLocaleString()}
                </span>
                <Button size="sm" variant="ghost" isIconOnly aria-label="Newer events" isDisabled={page === 0} onPress={() => setPage((p) => p - 1)}>
                  <ChevronLeft className="size-4" />
                </Button>
                <Button size="sm" variant="ghost" isIconOnly aria-label="Older events" isDisabled={page + 1 >= pages} onPress={() => setPage((p) => p + 1)}>
                  <ChevronRight className="size-4" />
                </Button>
              </div>
            )}
          </div>
        )}
      </QueryView>
    </Panel>
  );
}
