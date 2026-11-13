// SPDX-License-Identifier: Apache-2.0
import { Button, Checkbox, Label } from "@heroui/react";
import { AlertTriangle, Ban, Database, Eye, Play, Radar } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { ToneChip } from "@/components/ui/Badges";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows, QueryView } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import { cn } from "@/lib/utils";
import { OP_STATUS_META, TypeBadge, useDebounced } from "./bits";
import { useOsint } from "./context";
import { changeText, plural, shortTime } from "./model";
import type { ImportSource, OperationDetail, ResultSelection } from "./types";

type InputMode = "entity" | "value";

const IMPORT_KIND_LABEL: Record<ImportSource["kind"], string> = {
  run: "Tool runs",
  lookup: "Threat-intelligence lookups",
  cve: "Cached CVEs",
  finding: "Project findings",
  scope: "Project scope",
};

/* ───────────────────────── collect ───────────────────────── */

function CollectPanel({ prefill, onPrefillUsed }: { prefill: { entityId: number; provider?: string } | null; onPrefillUsed: () => void }) {
  const { investigation: inv, registry } = useOsint();
  const providers = registry.raw.providers;
  const [providerId, setProviderId] = useState<string>(providers[0]?.id ?? "dns");
  const [mode, setMode] = useState<InputMode>("entity");
  const [search, setSearch] = useState("");
  const [entityId, setEntityId] = useState<string | null>(null);
  const [type, setType] = useState<string | null>(null);
  const [value, setValue] = useState("");
  const [refresh, setRefresh] = useState(false);
  const [autoImport, setAutoImport] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const dSearch = useDebounced(search);
  const provider = registry.providers.get(providerId);

  useEffect(() => {
    if (!prefill) return;
    if (prefill.provider && registry.providers.has(prefill.provider)) setProviderId(prefill.provider);
    setMode("entity");
    setEntityId(String(prefill.entityId));
    setSearch("");
    onPrefillUsed();
  }, [prefill, onPrefillUsed, registry.providers]);

  const candidates = useQuery(["osint"], () => api.osintEntities(inv.id, { q: dSearch.trim() || undefined, limit: 20, sort: "connections" }), [inv.id, dSearch]);
  // the prefilled entity may not be among the first 20 results
  const prefilled = useQuery(["osint"], () => (entityId ? api.osintEntitiesByIds(inv.id, [Number(entityId)]) : Promise.resolve(null)), [inv.id, entityId]);
  const entityOptions = useMemo(() => {
    const accepted = new Set(provider?.inputs ?? []);
    const list = [...(candidates.data?.items ?? [])];
    for (const e of prefilled.data?.entities ?? []) if (!list.some((x) => x.id === e.id)) list.unshift({ ...e, firstSeen: "", lastSeen: "", relationships: 0, evidence: 0, sources: [] });
    return list.filter((e) => accepted.has(e.type)).map((e) => ({ id: String(e.id), label: e.value, description: registry.entityTypeLabel(e.type) }));
  }, [candidates.data, prefilled.data, provider, registry]);

  const typeOptions = (provider?.inputs ?? []).map((t) => ({ id: t, label: registry.entityTypeLabel(t) }));
  useEffect(() => {
    if (provider && (!type || !provider.inputs.includes(type))) setType(provider.inputs[0] ?? null);
  }, [provider, type]);

  const ready = mode === "entity" ? !!entityId && entityOptions.some((o) => o.id === entityId) : !!type && !!value.trim();

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.osintDiscover({
        investigationId: inv.id,
        provider: providerId,
        entityId: mode === "entity" ? Number(entityId) : null,
        entityType: mode === "value" ? type : null,
        value: mode === "value" ? value.trim() : null,
        autoImport,
        refresh,
      });
      invalidate("osint");
      notify.success(`${provider?.name ?? providerId} started`, autoImport ? "Results are imported when it finishes." : "Results wait for your review in the operations list.");
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Panel title="Collect" description="Query a public source about an entity. Private and internal values are never sent.">
      <div className="flex flex-col gap-4">
        <SelectInput
          label="Source"
          value={providerId}
          onChange={setProviderId}
          options={providers.map((p) => ({ id: p.id, label: p.name, description: p.category }))}
        />
        {provider && (
          <div className="panel-inset flex flex-col gap-1.5 px-4 py-3 text-[12.5px] text-muted">
            <div className="text-[13px] text-foreground">{provider.description}</div>
            <div>Accepts: {provider.inputs.map((t) => registry.entityTypeLabel(t)).join(", ")}</div>
            {provider.usesThreatIntel && <div>Uses your configured threat-intelligence keys and their quotas.</div>}
            {provider.contactsTarget && (
              <div className="flex items-start gap-2 text-warning-soft-foreground">
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                Contacts the target directly; requires a linked active project whose authorized scope covers it.
              </div>
            )}
          </div>
        )}
        <SelectInput
          label="Input"
          value={mode}
          onChange={(v) => setMode(v as InputMode)}
          options={[
            { id: "entity", label: "An entity of this investigation" },
            { id: "value", label: "A new value" },
          ]}
        />
        {mode === "entity" ? (
          <div className="grid gap-3 sm:grid-cols-2">
            <SearchInput value={search} onChange={setSearch} placeholder="Find an entity" />
            <SelectInput
              aria-label="Entity"
              value={entityId}
              onChange={setEntityId}
              options={entityOptions}
              placeholder={entityOptions.length ? "Choose an entity" : "No entity of an accepted type"}
            />
          </div>
        ) : (
          <div className="grid gap-3 sm:grid-cols-[200px_1fr]">
            <SelectInput label="Type" value={type} onChange={setType} options={typeOptions} />
            <TextInput label="Value" value={value} onChange={setValue} mono placeholder="example.com" onEnter={() => ready && void start()} />
          </div>
        )}
        <div className="flex flex-col gap-2">
          <SwitchInput label="Ignore cached responses" isSelected={refresh} onChange={setRefresh} description="Query the source again even if a recent response is cached." />
          <SwitchInput
            label="Import results without review"
            isSelected={autoImport}
            onChange={setAutoImport}
            description="Off: results wait in the operations list until you choose what to import."
          />
        </div>
        {error && <ErrorBlock message={error} />}
        <div>
          <Button variant="primary" onPress={start} isDisabled={!ready} isPending={busy}>
            <Play className="size-4" />
            Start collection
          </Button>
        </div>
      </div>
    </Panel>
  );
}

/* ───────────────────────── results review ───────────────────────── */

function key(oi: number, i: number): string {
  return `${oi}:${i}`;
}

function ReviewModal({ operationId, onClose }: { operationId: number | null; onClose: () => void }) {
  const { registry } = useOsint();
  const [detail, setDetail] = useState<OperationDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [ents, setEnts] = useState<Set<string>>(new Set());
  const [rels, setRels] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (operationId == null) return;
    setDetail(null);
    setError(null);
    api
      .osintOperation(operationId)
      .then((d) => {
        setDetail(d);
        setEnts(new Set(d.results.flatMap((o, oi) => o.entities.map((_, i) => key(oi, i)))));
        setRels(new Set(d.results.flatMap((o, oi) => o.relationships.map((_, i) => key(oi, i)))));
      })
      .catch((e) => setError(errorMessage(e)));
  }, [operationId]);

  const imported = !!detail?.importedAt;
  const toggle = (set: Set<string>, setter: (s: Set<string>) => void, k: string) => {
    const n = new Set(set);
    if (n.has(k)) n.delete(k);
    else n.add(k);
    setter(n);
  };

  const run = async (all: boolean) => {
    if (operationId == null) return;
    setBusy(true);
    try {
      const pair = (k: string): [number, number] => k.split(":").map(Number) as [number, number];
      const selection: ResultSelection | null = all ? null : { entities: [...ents].map(pair), relationships: [...rels].map(pair) };
      const s = await api.osintOperationImport(operationId, selection);
      invalidate("osint");
      notify.success("Results imported", changeText(s));
      onClose();
    } catch (e) {
      notify.error("Could not import the results", e);
    } finally {
      setBusy(false);
    }
  };

  const entityCount = detail?.results.reduce((n, o) => n + o.entities.length, 0) ?? 0;
  const relCount = detail?.results.reduce((n, o) => n + o.relationships.length, 0) ?? 0;

  return (
    <AppModal
      isOpen={operationId != null}
      onOpenChange={(o) => !o && onClose()}
      size="lg"
      title={detail ? `${detail.providerName}: ${detail.inputValue}` : "Collected results"}
      description={
        detail
          ? `${plural(detail.results.length, "evidence record", "evidence records")}, ${plural(entityCount, "entity", "entities")}, ${plural(relCount, "relationship", "relationships")} proposed.${detail.truncated ? " The result was cut to its stored size limit." : ""}`
          : undefined
      }
      footer={
        <>
          {imported && (
            <span className="mr-auto self-center text-[12.5px] text-muted">
              Imported {shortTime(detail?.importedAt)} ({detail?.importedCount} new entities). Importing again adds only what is missing.
            </span>
          )}
          <Button variant="tertiary" onPress={() => run(true)} isDisabled={!detail || busy}>
            Import all
          </Button>
          <Button variant="primary" onPress={() => run(false)} isDisabled={!detail || ents.size === 0} isPending={busy}>
            Import selected ({ents.size + rels.size})
          </Button>
        </>
      }
    >
      {error && <ErrorBlock message={error} />}
      {!detail && !error && <LoadingRows rows={4} />}
      {detail?.rateNote && <p className="text-[12.5px] text-muted">{detail.rateNote}</p>}
      {detail && detail.results.length === 0 && <EmptyBlock compact icon={Database} title="Nothing found" description={detail.message ?? "The source returned no data for this input."} />}
      {detail && (
        <div className="flex flex-col gap-3">
          {detail.results.map((o, oi) => (
            <section key={oi} className="panel-inset flex flex-col gap-2 px-4 py-3">
              <div>
                <div className="text-[13px] break-words text-foreground">{o.evidence.summary}</div>
                <div className="mt-0.5 flex flex-wrap gap-x-3 text-[12px] text-muted">
                  <span>{o.evidence.source}</span>
                  <span>{o.evidence.strength}</span>
                  {o.evidence.observedAt && <span>observed {shortTime(o.evidence.observedAt)}</span>}
                </div>
                {o.evidence.reference && <div className="mt-0.5 font-mono text-[11.5px] break-all text-muted select-text">{o.evidence.reference}</div>}
              </div>
              <ul className="flex flex-col gap-0.5">
                {o.entities.map((e, i) => (
                  <li key={`e${i}`}>
                    <Checkbox isSelected={ents.has(key(oi, i))} onChange={() => toggle(ents, setEnts, key(oi, i))}>
                      <Checkbox.Content className="flex items-center gap-2 py-0.5">
                        <Checkbox.Control>
                          <Checkbox.Indicator />
                        </Checkbox.Control>
                        <Label className="flex min-w-0 items-center gap-2 text-[13px] font-normal">
                          <TypeBadge type={e.type} />
                          <span className="truncate font-mono text-[12.5px] text-foreground">{e.value}</span>
                          {e.flagged && <ToneChip tone="danger">Flagged</ToneChip>}
                        </Label>
                      </Checkbox.Content>
                    </Checkbox>
                  </li>
                ))}
                {o.relationships.map((r, i) => {
                  const s = o.entities[r.source]?.value ?? "?";
                  const t = o.entities[r.target]?.value ?? "?";
                  const label = registry.relationshipTypes.get(r.type)?.label ?? r.type;
                  return (
                    <li key={`r${i}`}>
                      <Checkbox isSelected={rels.has(key(oi, i))} onChange={() => toggle(rels, setRels, key(oi, i))}>
                        <Checkbox.Content className="flex items-center gap-2 py-0.5">
                          <Checkbox.Control>
                            <Checkbox.Indicator />
                          </Checkbox.Control>
                          <Label className="min-w-0 text-[12.5px] font-normal break-words text-muted">
                            <span className="font-mono text-foreground">{s}</span> —{label}→ <span className="font-mono text-foreground">{t}</span>
                            <span className="ml-2">
                              {r.strength}
                              {r.origin !== "observed" ? `, ${r.origin}` : ""}
                            </span>
                          </Label>
                        </Checkbox.Content>
                      </Checkbox>
                    </li>
                  );
                })}
              </ul>
            </section>
          ))}
          <p className="text-[12px] text-muted">A relationship is imported only when both of its entities are selected. Collected text is shown as-is and is never executed.</p>
        </div>
      )}
    </AppModal>
  );
}

/* ───────────────────────── operations ───────────────────────── */

function OperationsPanel() {
  const { investigation: inv } = useOsint();
  const q = useQuery(["osint", "osint-ops"], () => api.osintOperations(inv.id), [inv.id]);
  const [review, setReview] = useState<number | null>(null);
  const running = (q.data ?? []).some((o) => o.status === "running");

  useEffect(() => {
    if (!running) return;
    // reload only this list while something runs; when a collection finishes the backend emits
    // "osint-changed" once, which refreshes the rest of the page (graph, counts, timeline)
    const t = setInterval(() => q.reload(), 2000);
    return () => clearInterval(t);
  }, [running]); // eslint-disable-line react-hooks/exhaustive-deps

  const cancel = async (id: number) => {
    try {
      await api.osintOperationCancel(id);
      invalidate("osint");
    } catch (e) {
      notify.error("Could not cancel", e);
    }
  };

  return (
    <Panel title="Operations" description="Collections from public sources and imports of internal data, newest first.">
      <QueryView
        query={q}
        rows={4}
        isEmpty={(d) => d.length === 0}
        empty={<EmptyBlock compact icon={Radar} title="No operations yet" description="Start a collection on the left, or import data ExploitX already holds." />}
      >
        {(ops) => (
          <ul className="flex flex-col gap-1">
            {ops.map((o) => {
              const meta = OP_STATUS_META[o.status];
              const awaiting = o.status === "completed" && !o.importedAt && o.resultCount > 0;
              return (
                <li key={o.id} className={cn("tile flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-[13px]", awaiting && "bg-accent-soft/40")}>
                  <ToneChip tone={meta.tone}>{meta.label}</ToneChip>
                  <span className="shrink-0 text-foreground">{o.providerName}</span>
                  <TypeBadge type={o.inputType} label={o.inputValue} className="min-w-0 flex-1 font-mono" />
                  <span className="tabular shrink-0 text-[12px] text-muted">
                    {o.resultCount} results · {o.importedAt ? `${o.importedCount} new entities imported` : awaiting ? "awaiting review" : shortTime(o.startedAt)}
                  </span>
                  <span className="shrink-0 text-[12px] text-muted">{o.requestedBy}</span>
                  <div className="flex shrink-0 gap-1">
                    {o.status === "running" ? (
                      <Button size="sm" variant="ghost" onPress={() => cancel(o.id)}>
                        <Ban className="size-3.5" />
                        Cancel
                      </Button>
                    ) : o.status === "completed" && o.resultCount > 0 ? (
                      <Button size="sm" variant={awaiting ? "primary" : "ghost"} onPress={() => setReview(o.id)}>
                        <Eye className="size-3.5" />
                        {awaiting ? "Review" : "View"}
                      </Button>
                    ) : null}
                  </div>
                  {o.message && <div className="w-full text-[12px] break-words text-muted">{o.message}</div>}
                </li>
              );
            })}
          </ul>
        )}
      </QueryView>
      <ReviewModal operationId={review} onClose={() => setReview(null)} />
    </Panel>
  );
}

/* ───────────────────────── internal data ───────────────────────── */

function InternalPanel() {
  const { investigation: inv } = useOsint();
  const q = useQuery(["osint", "executions", "ti", "cve", "findings", "projects"], () => api.osintImportSources(inv.projectId), [inv.projectId]);
  const [busy, setBusy] = useState<string | null>(null);
  const [showOther, setShowOther] = useState(false);
  const confirm = useConfirm();

  const run = async (s: ImportSource) => {
    if (s.association === "other") {
      const ok = await confirm.ask({
        title: "Import from another project?",
        body: `${s.label} belongs to the project “${s.projectName ?? `#${s.projectId}`}”, not to the project linked to this investigation. Import it only if you are authorized to combine the two.`,
        confirmLabel: "Import",
        tone: "accent",
      });
      if (!ok) return;
    }
    setBusy(`${s.kind}:${s.id}`);
    try {
      const r = await api.osintImportInternal(inv.id, s.kind, s.id);
      invalidate("osint");
      notify.success(`Imported: ${s.label}`, changeText(r));
    } catch (e) {
      notify.error("Could not import", e);
    } finally {
      setBusy(null);
    }
  };

  return (
    <Panel
      title="ExploitX data"
      description={
        inv.projectId
          ? "Reuse what ExploitX already holds: tool output, threat-intelligence lookups, cached CVEs and the linked project's findings and scope. Nothing is sent anywhere."
          : "Reuse tool output, threat-intelligence lookups and cached CVEs. Link a project to also import its findings and scope. Nothing is sent anywhere."
      }
    >
      <QueryView query={q} rows={4} isEmpty={(d) => d.length === 0} empty={<EmptyBlock compact icon={Database} title="Nothing to import yet" description="Run tools, look up indicators or open CVEs first." />}>
        {(all) => {
          const otherCount = all.filter((s) => s.association === "other").length;
          const list = all.filter((s) => showOther || s.association !== "other");
          const groups = new Map<ImportSource["kind"], ImportSource[]>();
          for (const s of list) groups.set(s.kind, [...(groups.get(s.kind) ?? []), s]);
          return (
            <div className="flex flex-col gap-4">
              {otherCount > 0 && (
                <SwitchInput
                  label={`Show ${otherCount} run${otherCount === 1 ? "" : "s"} from other projects`}
                  isSelected={showOther}
                  onChange={setShowOther}
                  description={inv.projectId ? "Hidden by default: they belong to a different project than the one linked to this investigation." : "This investigation has no linked project; these runs belong to projects."}
                />
              )}
              {[...groups.entries()].map(([kind, items]) => (
                <section key={kind}>
                  <h3 className="mb-1.5 text-[12.5px] font-medium text-muted">{IMPORT_KIND_LABEL[kind] ?? kind}</h3>
                  <ul className="flex flex-col gap-1">
                    {items.slice(0, 15).map((s) => (
                      <li key={s.id} className="tile flex items-center gap-3 px-3 py-2 text-[13px]">
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-foreground">{s.label}</div>
                          <div className="truncate text-[12px] text-muted">
                            {s.detail} · {shortTime(s.at)}
                            {s.kind === "run" && (s.association === "none" ? " · no project" : ` · project: ${s.projectName ?? `#${s.projectId}`}`)}
                          </div>
                        </div>
                        <Button size="sm" variant="ghost" onPress={() => run(s)} isPending={busy === `${s.kind}:${s.id}`} isDisabled={busy !== null && busy !== `${s.kind}:${s.id}`}>
                          Import
                        </Button>
                      </li>
                    ))}
                  </ul>
                </section>
              ))}
            </div>
          );
        }}
      </QueryView>
      {confirm.element}
    </Panel>
  );
}

function SourceReference() {
  const { registry } = useOsint();
  return (
    <Panel title="About the sources" description="Where each source gets its data and the terms that apply. Respect them; ExploitX does not bypass authentication, CAPTCHAs or paywalls.">
      <ul className="flex flex-col gap-1.5">
        {registry.raw.providers.map((p) => (
          <li key={p.id} className="tile px-3 py-2 text-[12.5px]">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-[13px] text-foreground">{p.name}</span>
              <span className="font-mono text-[11.5px] break-all text-muted select-text">{p.sourceUrl}</span>
            </div>
            <div className="mt-0.5 text-muted">
              {p.terms} · at most {p.rate[0]} requests per {p.rate[1]} s{p.cacheHours > 0 ? ` · responses cached ${p.cacheHours} h` : ""}
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export function SourcesTab({ prefill, onPrefillUsed }: { prefill: { entityId: number; provider?: string } | null; onPrefillUsed: () => void }) {
  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-4 xl:grid-cols-[minmax(340px,420px)_1fr]">
        <CollectPanel prefill={prefill} onPrefillUsed={onPrefillUsed} />
        <OperationsPanel />
      </div>
      <InternalPanel />
      <SourceReference />
    </div>
  );
}
