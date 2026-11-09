import { Button } from "@heroui/react";
import { Download, ExternalLink, Layers, ShieldAlert, Trash2, Upload } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput, TextAreaInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify, openExternal } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { AttackCatalog, AttackEntry, AttackMatrix, AttackStatus, AttackTechnique, Project, RecordRef } from "@/lib/types";
import { cn, formatRelative, pluralize } from "@/lib/utils";
import { Segmented } from "@/modules/utilities/tools/shared";
import { buildColumns, gaps, mitreUrl, outside, STATE_STYLE, stateOf, type TechniqueState } from "./attackMatrix";
import { provenance } from "./investigation";

function cellStyle(state: TechniqueState) {
  return state === "none" ? undefined : { backgroundColor: `${STATE_STYLE[state].color}2e` };
}

/** One technique in the matrix: its state as a fill, findings and layer score as small marks. */
function Cell({ tech, entry, layerId, sub, onOpen }: { tech: AttackTechnique; entry?: AttackEntry; layerId: number | null; sub?: boolean; onOpen: (id: string) => void }) {
  const state = stateOf(entry);
  const mark = layerId != null ? entry?.layers.find((l) => l.layerId === layerId) : undefined;
  const gap = layerId != null && (state === "observed" || state === "confirmed" || state === "hypothesis") && !(mark && mark.enabled);
  return (
    <button
      type="button"
      onClick={() => onOpen(tech.id)}
      style={cellStyle(state)}
      title={[`${tech.id} ${tech.name}`, state !== "none" ? STATE_STYLE[state].hint : null, mark ? `In the layer${mark.score != null ? `: score ${mark.score}` : ""}${mark.comment ? ` · ${mark.comment}` : ""}` : null, gap ? "Not in the layer" : null].filter(Boolean).join("\n")}
      className={cn("flex w-full flex-col gap-0.5 rounded-[6px] px-2 py-1.5 text-left hover:brightness-125", state === "none" && "bg-white/[0.03]", sub && "ml-2 w-[calc(100%-0.5rem)]")}
    >
      <span className="flex items-center gap-1 text-[10.5px] text-muted">
        <span className="font-mono">{tech.id}</span>
        {entry && entry.observed.length > 0 && <span title="Findings that name it">· {entry.observed.length}</span>}
        <span className="flex-1" />
        {mark && (
          <span className={cn("rounded px-1 font-mono text-[10px]", mark.enabled ? "bg-success/25 text-success" : "bg-white/10 text-muted")}>{mark.score != null ? mark.score : "✓"}</span>
        )}
        {gap && <span className="rounded bg-danger/20 px-1 text-[10px] text-danger">gap</span>}
      </span>
      <span className={cn("line-clamp-2 text-[12px] leading-snug", state === "ruled_out" ? "text-muted line-through" : "text-foreground")}>{tech.name}</span>
    </button>
  );
}

/** Projects → Investigation → ATT&CK: the matrix of what findings name and what the analyst
 * assessed, with imported layers as an overlay. */
export function AttackMatrixView({ project, archived, onOpen }: { project: Project; archived: boolean; onOpen: (r: RecordRef) => void }) {
  const { runtime } = useApp();
  const confirm = useConfirm();
  const catalog = useQuery(["attack"], () => api.attackCatalog(), [], runtime);
  const matrix = useQuery(["attack", "findings", "relations"], () => api.attackMatrix(project.id), [project.id], runtime);
  const [onlyData, setOnlyData] = useState(true);
  const [filter, setFilter] = useState("");
  const [layerId, setLayerId] = useState<number | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const m = matrix.data;
  const cat = catalog.data;
  const columns = useMemo(() => (cat && m ? buildColumns(cat, m, { onlyData, filter, layerId }) : []), [cat, m, onlyData, filter, layerId]);
  const layer = m?.layers.find((l) => l.id === layerId) ?? null;
  const missing = useMemo(() => (m && layerId != null ? gaps(m, layerId) : []), [m, layerId]);
  const odd = useMemo(() => (m ? outside(m) : []), [m]);

  const act = async (key: string, fn: () => Promise<unknown>) => {
    setBusy(key);
    try {
      await fn();
    } finally {
      setBusy(null);
    }
  };
  const importLayer = () =>
    act("import", async () => {
      try {
        const l = await api.attackLayerImport(project.id);
        if (!l) return;
        invalidate("attack", "findings", "relations");
        setLayerId(l.id);
        notify.success(`Layer imported: ${l.name}`, [`${pluralize(l.techniques, "technique")}`, l.unknown.length ? `${l.unknown.length} unknown left out` : null, Object.keys(l.remapped).length ? `${Object.keys(l.remapped).length} revoked IDs mapped` : null].filter(Boolean).join(" · "));
      } catch (e) {
        notify.error("The layer was not imported", e);
      }
    });
  const exportLayer = () =>
    act("export", async () => {
      try {
        const f = await api.attackLayerExport(project.id);
        if (f) notify.success("Layer saved", f);
      } catch (e) {
        notify.error("The layer was not exported", e);
      }
    });

  if (catalog.error || matrix.error) return <ErrorBlock message={catalog.error ?? matrix.error ?? ""} onRetry={() => matrix.reload()} />;
  if (!cat || !m) return <LoadingRows rows={6} />;
  const empty = m.entries.length === 0;
  return (
    <div className="flex flex-col gap-3">
      <Panel
        title="ATT&CK matrix"
        description={`Techniques that findings name are leads from the tools, not confirmed adversary activity: only your assessment marks a technique as confirmed, a hypothesis or ruled out. Imported layers (for example detection coverage) are an overlay and never count as observed. MITRE ATT&CK Enterprise v${cat.version}, retrieved ${cat.retrieved}.`}
        actions={
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="tertiary" onPress={() => void importLayer()} isPending={busy === "import"} isDisabled={!runtime || archived}>
              <Upload className="size-3.5" />
              Import layer…
            </Button>
            <Button size="sm" variant="tertiary" onPress={() => void exportLayer()} isPending={busy === "export"} isDisabled={!runtime || (m.counts.observed === 0 && m.counts.confirmed + m.counts.hypothesis + m.counts.ruledOut === 0)}>
              <Download className="size-3.5" />
              Export layer
            </Button>
          </div>
        }
      >
        <div className="flex flex-col gap-2.5">
          <div className="flex flex-wrap items-center gap-2 text-[12.5px]">
            {(["observed", "confirmed", "hypothesis", "ruled_out", "linked"] as const).map((s) => {
              const n = s === "observed" ? m.counts.observed : s === "confirmed" ? m.counts.confirmed : s === "hypothesis" ? m.counts.hypothesis : s === "ruled_out" ? m.counts.ruledOut : m.entries.filter((e) => stateOf(e) === "linked").length;
              return (
                <span key={s} title={STATE_STYLE[s].hint} className="flex items-center gap-1.5 rounded-full bg-white/[0.04] px-2.5 py-1">
                  <span className="size-2.5 rounded-full" style={{ backgroundColor: STATE_STYLE[s].color }} />
                  {STATE_STYLE[s].label} <span className="text-muted">{n}</span>
                </span>
              );
            })}
            <span className="text-muted">{pluralize(m.counts.findings, "finding")} name a technique</span>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <SearchInput value={filter} onChange={setFilter} placeholder="Find a technique" className="w-56" />
            <SwitchInput label="Only techniques with data" isSelected={onlyData} onChange={setOnlyData} />
            {m.layers.length > 0 && (
              <SelectInput
                aria-label="Layer shown"
                value={layerId == null ? "none" : String(layerId)}
                onChange={(v) => setLayerId(v === "none" ? null : Number(v))}
                options={[{ id: "none", label: "No layer" }, ...m.layers.map((l) => ({ id: String(l.id), label: `Layer: ${l.name}` }))]}
                className="w-60"
              />
            )}
          </div>
          {layer && (
            <div className="flex flex-col gap-1 rounded-[8px] bg-white/[0.03] px-3 py-2 text-[12.5px]">
              <div className="flex flex-wrap items-center gap-2">
                <Layers className="size-3.5 text-muted" />
                <span className="font-medium">{layer.name}</span>
                <span className="text-muted">
                  {pluralize(layer.techniques, "technique")} · layer format {layer.layerVersion || "?"} · {layer.attackVersion ? `made for ATT&CK v${layer.attackVersion}` : "no ATT&CK version stated"} · imported {formatRelative(layer.importedAt)}
                </span>
                <span className="flex-1" />
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7 px-1.5"
                  aria-label={`Remove the layer ${layer.name}`}
                  isDisabled={archived}
                  onPress={async () => {
                    if (!(await confirm.ask({ title: `Remove the layer “${layer.name}”?`, body: "Its file stays in the evidence vault.", confirmLabel: "Remove", tone: "danger" }))) return;
                    try {
                      await api.attackLayerDelete(layer.id);
                      setLayerId(null);
                      invalidate("attack", "relations");
                    } catch (e) {
                      notify.error("The layer was not removed", e);
                    }
                  }}
                >
                  <Trash2 className="size-3.5" />
                </Button>
              </div>
              {layer.warnings.map((w) => (
                <span key={w} className="text-warning">
                  {w}
                </span>
              ))}
              {Object.keys(layer.remapped).length > 0 && (
                <span className="text-muted">
                  Revoked IDs mapped: {Object.entries(layer.remapped)
                    .map(([a, b]) => `${a} → ${b}`)
                    .join(", ")}
                </span>
              )}
              {layer.unknown.length > 0 && <span className="text-muted">Not in ATT&CK Enterprise v{cat.version}, left out: {layer.unknown.join(", ")}</span>}
              <span className={cn(missing.length ? "text-danger" : "text-success")}>
                {missing.length ? `${pluralize(missing.length, "technique")} that findings name or you confirmed or suspect ${missing.length === 1 ? "is" : "are"} not in this layer (marked “gap”): ${missing.map((e) => e.id).join(", ")}` : "Every technique that findings name or you confirmed or suspect is in this layer."}
              </span>
            </div>
          )}
        </div>
      </Panel>
      {empty && onlyData ? (
        <EmptyBlock
          icon={ShieldAlert}
          title="No technique yet"
          description="Techniques appear when findings name them (file, log, event log, Linux and cloud triage record them as tags such as T1059.001), when you link a record to a technique, or when you import a layer. Turn off “Only techniques with data” to browse and assess the whole matrix."
        />
      ) : (
        <div className="overflow-x-auto pb-2">
          <div className="grid auto-cols-[minmax(168px,1fr)] grid-flow-col gap-2">
            {columns.map((col) => (
              <div key={col.tactic.id} className="flex min-w-0 flex-col gap-1.5">
                <div className="rounded-[6px] bg-white/[0.05] px-2 py-1.5">
                  <div className="truncate text-[12.5px] font-medium" title={`${col.tactic.id} ${col.tactic.name}`}>
                    {col.tactic.name}
                  </div>
                  <div className="text-[10.5px] text-muted">{col.rows.length ? pluralize(col.rows.length, "technique") : "nothing"}</div>
                </div>
                {col.rows.map((r) => (
                  <div key={r.tech.id} className="flex flex-col gap-1">
                    <Cell tech={r.tech} entry={r.entry} layerId={layerId} onOpen={setOpen} />
                    {r.subs.map((s) => (
                      <Cell key={s.tech.id} tech={s.tech} entry={s.entry} layerId={layerId} sub onOpen={setOpen} />
                    ))}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}
      {odd.length > 0 && (
        <Panel title="Outside the matrix" description={`Technique IDs that findings or links name but ATT&CK Enterprise v${cat.version} no longer lists as they are.`}>
          <ul className="flex flex-col gap-1">
            {odd.map((e) => (
              <li key={e.id}>
                <button type="button" onClick={() => setOpen(e.id)} className="text-left text-[12.5px] hover:underline">
                  <span className="font-mono">{e.id}</span> <span className="text-muted">({e.name}) · {pluralize(e.observed.length, "finding")}</span>
                </button>
              </li>
            ))}
          </ul>
        </Panel>
      )}
      {open && <TechniqueModal id={open} project={project} archived={archived} catalog={cat} matrix={m} onClose={() => setOpen(null)} onOpen={onOpen} />}
      {confirm.element}
    </div>
  );
}

/** A technique: what findings name, linked records, the analyst's assessment, imported layers. */
function TechniqueModal({ id, project, archived, catalog, matrix, onClose, onOpen }: { id: string; project: Project; archived: boolean; catalog: AttackCatalog; matrix: AttackMatrix; onClose: () => void; onOpen: (r: RecordRef) => void }) {
  const tech = catalog.techniques.find((t) => t.id === id);
  const entry = matrix.entries.find((e) => e.id === id);
  const [status, setStatus] = useState<AttackStatus | "none">(entry?.assessment?.status ?? "none");
  const [confidence, setConfidence] = useState<string>(entry?.assessment?.confidence ?? "medium");
  const [note, setNote] = useState(entry?.assessment?.note ?? "");
  const [saving, setSaving] = useState(false);
  const tactics = (tech?.tactics ?? entry?.tactics ?? []).map((s) => catalog.tactics.find((t) => t.shortname === s)?.name ?? s);
  const name = tech?.name ?? entry?.name ?? "";
  const changed = status !== (entry?.assessment?.status ?? "none") || (status !== "none" && (confidence !== (entry?.assessment?.confidence ?? "medium") || note.trim() !== (entry?.assessment?.note ?? "")));
  const save = async () => {
    setSaving(true);
    try {
      await api.attackAssess(project.id, id, status === "none" ? null : status, confidence, note);
      invalidate("attack", "relations");
      notify.success(status === "none" ? "Assessment removed" : `${id} marked ${STATE_STYLE[status].label.toLowerCase()}`);
      onClose();
    } catch (e) {
      notify.error("The assessment was not saved", e);
    } finally {
      setSaving(false);
    }
  };
  return (
    <AppModal
      isOpen
      onOpenChange={(o) => !o && onClose()}
      size="lg"
      title={`${id} ${name}`}
      description={[tactics.join(", "), tech?.platforms.length ? tech.platforms.join(", ") : null].filter(Boolean).join(" · ") || undefined}
      footer={
        <div className="flex w-full flex-wrap items-center gap-2">
          {entry?.state.state === "current" || tech ? (
            <Button size="sm" variant="ghost" onPress={() => void openExternal(mitreUrl(id))}>
              <ExternalLink className="size-3.5" />
              On attack.mitre.org
            </Button>
          ) : null}
          {(tech || entry?.state.state === "revoked" || entry?.state.state === "deprecated") && (
            <Button
              size="sm"
              variant="ghost"
              onPress={() => {
                onClose();
                onOpen({ kind: "technique", id: 0, sub: id });
              }}
            >
              Related records
            </Button>
          )}
          <span className="flex-1" />
          <Button size="sm" variant="tertiary" onPress={onClose}>
            Close
          </Button>
          <Button size="sm" variant="primary" onPress={() => void save()} isPending={saving} isDisabled={archived || !changed}>
            Save assessment
          </Button>
        </div>
      }
    >
      <div className="flex flex-col gap-4 text-[12.5px]">
        {entry && entry.state.state !== "current" && (
          <p className="rounded-[8px] bg-warning-soft px-2.5 py-1.5 text-warning-soft-foreground">
            {entry.state.state === "revoked" ? `ATT&CK revoked ${id}; it is now ${entry.state.by}.` : entry.state.state === "deprecated" ? `${id} is deprecated in ATT&CK v${catalog.version}.` : `${id} is not in ATT&CK Enterprise v${catalog.version}.`}
          </p>
        )}
        <section className="flex flex-col gap-1.5">
          <h3 className="text-[13px] font-medium">Named by findings ({entry?.observed.length ?? 0})</h3>
          <p className="text-muted">Tool output that maps to this technique: leads to confirm, not confirmed activity.</p>
          {entry?.observed.length ? (
            <ul className="flex flex-col gap-1">
              {entry.observed.map((o) => (
                <li key={o.findingId}>
                  <button
                    type="button"
                    onClick={() => {
                      onClose();
                      onOpen({ kind: "finding", id: o.findingId, sub: "" });
                    }}
                    className="flex w-full items-center gap-2 rounded-[6px] bg-white/[0.03] px-2 py-1.5 text-left hover:bg-white/[0.06]">
                    <SeverityBadge severity={o.severity} />
                    <span className="min-w-0 flex-1 truncate">{o.title}</span>
                    <span className="text-muted">
                      {o.status.replace("_", " ")} · {pluralize(o.evidence, "evidence record")}
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          ) : (
            <span className="text-muted">None.</span>
          )}
        </section>
        {entry && entry.linked.length > 0 && (
          <section className="flex flex-col gap-1.5">
            <h3 className="text-[13px] font-medium">Linked records ({entry.linked.length})</h3>
            <ul className="flex flex-col gap-1">
              {entry.linked.map((l) => (
                <li key={l.relationId} className="flex items-center gap-2">
                  <span className="min-w-0 flex-1 truncate">{l.label}</span>
                  <ToneChip tone={l.verification === "verified" ? "success" : "warning"} dot={false} className="text-[11px]">
                    {provenance({ origin: l.origin, verification: l.verification, confidence: "high" })}
                  </ToneChip>
                </li>
              ))}
            </ul>
          </section>
        )}
        <section className="flex flex-col gap-2">
          <h3 className="text-[13px] font-medium">Your assessment</h3>
          <Segmented
            value={status}
            onChange={setStatus}
            ariaLabel="Assessment"
            options={[
              { id: "none", label: "Not assessed" },
              { id: "hypothesis", label: "Hypothesis" },
              { id: "confirmed", label: "Confirmed" },
              { id: "ruled_out", label: "Ruled out" },
            ]}
          />
          {status !== "none" && (
            <div className="flex flex-col gap-2">
              <SelectInput
                label="Confidence"
                value={confidence}
                onChange={setConfidence}
                options={[
                  { id: "low", label: "Low" },
                  { id: "medium", label: "Medium" },
                  { id: "high", label: "High" },
                ]}
                className="w-40"
              />
              <TextAreaInput label="Why" value={note} onChange={setNote} rows={3} placeholder="What confirms it, what is suspected, or why it is ruled out" />
            </div>
          )}
          {entry?.assessment && (
            <span className="text-muted">
              {STATE_STYLE[entry.assessment.status].label} with {entry.assessment.confidence} confidence, assessed against ATT&CK v{entry.assessment.attackVersion}, {formatRelative(entry.assessment.updatedAt)}
            </span>
          )}
          {archived && <span className="text-muted">The project is archived: assessments can be read, not changed.</span>}
        </section>
        {entry && entry.layers.length > 0 && (
          <section className="flex flex-col gap-1.5">
            <h3 className="text-[13px] font-medium">In imported layers</h3>
            <ul className="flex flex-col gap-1">
              {entry.layers.map((l) => (
                <li key={l.layerId} className="text-muted">
                  <span className="text-foreground">{matrix.layers.find((x) => x.id === l.layerId)?.name ?? `Layer #${l.layerId}`}</span>
                  {l.score != null ? ` · score ${l.score}` : ""}
                  {l.enabled ? "" : " · disabled"}
                  {l.comment ? ` · ${l.comment}` : ""}
                </li>
              ))}
            </ul>
          </section>
        )}
      </div>
    </AppModal>
  );
}
