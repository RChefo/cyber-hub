// SPDX-License-Identifier: Apache-2.0
import { Button } from "@heroui/react";
import { ClipboardCheck, Download, Plus, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { AsvsItem, AsvsStatus, AsvsSummary, Project, Severity } from "@/lib/types";
import { ASVS_FRAMEWORKS, ASVS_STATUS, filterItems, progress, statusLabel } from "./asvs";
import { cn, formatRelative, pluralize } from "@/lib/utils";
import type { RiskAcceptance } from "@/lib/types";
import { AcceptRiskModal } from "./RiskTab";
import { AsvsGaps } from "./AsvsGaps";
import { coverIndex, coverKey, RISK_STANDING } from "./risk";

/** Projects → ASVS: OWASP ASVS 5.0.0 assessments. */
export function AsvsTab({ project, onOpenFinding, onOpenRisks }: { project: Project; onOpenFinding: (id: number) => void; onOpenRisks?: () => void }) {
  const { runtime } = useApp();
  const confirm = useConfirm();
  const catalog = useQuery(["asvs"], () => api.asvsCatalog(), [], runtime);
  const list = useQuery(["asvs"], () => api.asvsAssessments(project.id), [project.id], runtime);
  const [chosen, setChosen] = useState<number | null>(null);
  const [creating, setCreating] = useState(false);
  const archived = project.status === "archived";
  const current = (list.data ?? []).find((a) => a.id === chosen) ?? list.data?.[0] ?? null;
  const cat = catalog.data;
  const attribution = cat ? `Requirements: OWASP ${cat.name.replace(" Project", "")} ${cat.version}, © OWASP Foundation, ${cat.license}.` : "";

  if (list.error) return <ErrorBlock message={list.error} onRetry={list.reload} />;
  if (!list.data || !cat) return <LoadingRows rows={5} />;
  return (
    <div className="flex flex-col gap-4">
      <Panel
        title={`OWASP ASVS ${cat.version}`}
        description={`Assess the project against the Application Security Verification Standard at a level. A requirement is compliant only when you say so: no finding is not evidence of compliance. ${attribution}`}
        actions={
          <div className="flex flex-wrap gap-2">
            {current && (
              <Button
                size="sm"
                variant="tertiary"
                onPress={async () => {
                  try {
                    const f = await api.asvsReportExport(current.id);
                    if (f) notify.success("Assessment report saved", f);
                  } catch (e) {
                    notify.error("The report was not saved", e);
                  }
                }}
              >
                <Download className="size-3.5" />
                Export report
              </Button>
            )}
            <Button size="sm" variant={current ? "tertiary" : "primary"} onPress={() => setCreating(true)} isDisabled={!runtime || archived}>
              <Plus className="size-3.5" />
              New assessment
            </Button>
          </div>
        }
      >
        {creating && <CreateForm projectId={project.id} onDone={(id) => (setCreating(false), id && setChosen(id))} />}
        {list.data.length === 0 && !creating ? (
          <EmptyBlock compact icon={ClipboardCheck} title="No assessment yet" description={`Start one at level 1 (${cat.requirements.filter((r) => r.level === 1).length} requirements), 2 or 3.`} />
        ) : (
          current && (
            <div className="flex flex-col gap-2.5">
              <div className="flex flex-wrap items-center gap-2">
                {list.data.length > 1 && (
                  <SelectInput aria-label="Assessment" value={String(current.id)} onChange={(v) => setChosen(Number(v))} options={list.data.map((a) => ({ id: String(a.id), label: a.name }))} className="w-56" />
                )}
                <span className="text-[13px] font-medium">{current.name}</span>
                <SelectInput
                  aria-label="Level"
                  value={String(current.level)}
                  isDisabled={archived}
                  onChange={async (v) => {
                    await api.asvsAssessmentUpdate(current.id, { level: Number(v) });
                    invalidate("asvs");
                  }}
                  options={[1, 2, 3].map((l) => ({ id: String(l), label: `Level ${l}` }))}
                  className="w-32"
                />
                <span className="flex-1" />
                <Button
                  size="sm"
                  variant="ghost"
                  aria-label="Delete the assessment"
                  isDisabled={archived}
                  onPress={async () => {
                    if (!(await confirm.ask({ title: `Delete “${current.name}”?`, body: "Its statuses, notes, links, mappings and history go with it. Findings and evidence stay.", confirmLabel: "Delete", tone: "danger" }))) return;
                    await api.asvsAssessmentDelete(current.id);
                    setChosen(null);
                    invalidate("asvs");
                  }}
                >
                  <Trash2 className="size-3.5" />
                </Button>
              </div>
              {current.scope && <span className="text-[12.5px] text-muted">Scope: {current.scope}</span>}
              <div className="h-2 overflow-hidden rounded-full bg-white/[0.06]" aria-label={`${progress(current)}% assessed`}>
                <div className="h-full bg-accent" style={{ width: `${progress(current)}%` }} />
              </div>
              <div className="flex flex-wrap gap-1.5 text-[12px]">
                <span className="text-muted">{progress(current)}% of {current.counts.total} requirements assessed:</span>
                <ToneChip tone="success" dot={false}>{current.counts.compliant} compliant</ToneChip>
                <ToneChip tone="danger" dot={false}>{current.counts.nonCompliant} non-compliant</ToneChip>
                <ToneChip tone="warning" dot={false}>{current.counts.needsReview} needs review</ToneChip>
                <ToneChip tone="accent" dot={false}>{current.counts.notApplicable} not applicable</ToneChip>
                <ToneChip tone="default" dot={false}>{current.counts.notAssessed} not assessed</ToneChip>
              </div>
            </div>
          )
        )}
      </Panel>
      {current && <AsvsGaps key={`gaps-${current.id}`} assessment={current} others={list.data ?? []} />}
      {current && <Requirements key={current.id} assessment={current} project={project} archived={archived} onOpenFinding={onOpenFinding} onOpenRisks={onOpenRisks} />}
      {confirm.element}
    </div>
  );
}

function CreateForm({ projectId, onDone }: { projectId: number; onDone: (id: number | null) => void }) {
  const [name, setName] = useState("Application assessment");
  const [level, setLevel] = useState("1");
  const [scope, setScope] = useState("");
  return (
    <div className="mb-3 flex flex-wrap items-end gap-2 rounded-[8px] bg-white/[0.03] p-3">
      <TextInput label="Name" value={name} onChange={setName} className="min-w-[200px] flex-1" />
      <SelectInput label="Level" value={level} onChange={setLevel} options={[1, 2, 3].map((l) => ({ id: String(l), label: `Level ${l}` }))} className="w-32" />
      <TextInput label="Scope" value={scope} onChange={setScope} placeholder="Application, URL or component" className="min-w-[200px] flex-1" />
      <Button size="sm" variant="tertiary" onPress={() => onDone(null)}>
        Cancel
      </Button>
      <Button
        size="sm"
        variant="primary"
        isDisabled={!name.trim()}
        onPress={async () => {
          try {
            const id = await api.asvsAssessmentCreate(projectId, name.trim(), Number(level), scope.trim() || undefined);
            invalidate("asvs", "projects");
            onDone(id);
          } catch (e) {
            notify.error("The assessment was not created", e);
          }
        }}
      >
        Start
      </Button>
    </div>
  );
}

function Requirements({ assessment, project, archived, onOpenFinding, onOpenRisks }: { assessment: AsvsSummary; project: Project; archived: boolean; onOpenFinding: (id: number) => void; onOpenRisks?: () => void }) {
  const { runtime } = useApp();
  const view = useQuery(["asvs", "findings"], () => api.asvsAssessmentGet(assessment.id), [assessment.id], runtime);
  const catalog = useQuery(["asvs"], () => api.asvsCatalog(), [], runtime);
  const [text, setText] = useState("");
  const [status, setStatus] = useState("all");
  const [beyond, setBeyond] = useState(false);
  const [open, setOpen] = useState<string | null>(null);
  const items = useMemo(() => filterItems(view.data?.items ?? [], { text, status, beyond }), [view.data, text, status, beyond]);
  // exceptions: risk acceptances covering a requirement of this assessment
  const risks = useQuery(["risk"], () => api.riskList(project.id), [project.id], runtime);
  const covers = useMemo(() => coverIndex(risks.data ?? []), [risks.data]);
  if (view.error) return <ErrorBlock message={view.error} onRetry={view.reload} />;
  if (!view.data || !catalog.data) return <LoadingRows rows={6} />;
  return (
    <Panel
      title="Requirements"
      toolbar={
        <div className="flex flex-wrap items-center gap-2 px-4 pb-3">
          <SearchInput value={text} onChange={setText} placeholder="Find a requirement or note" className="min-w-[220px] flex-1" />
          <SelectInput aria-label="Status" value={status} onChange={setStatus} options={[{ id: "all", label: "Any status" }, ...Object.entries(ASVS_STATUS).map(([id, s]) => ({ id, label: s.label }))]} className="w-44" />
          <SwitchInput label="Above the level too" isSelected={beyond} onChange={setBeyond} />
        </div>
      }
    >
      <div className="flex flex-col gap-3">
        {catalog.data.chapters.map((ch) => {
          const rows = items.filter((i) => i.requirement.chapter === ch.id);
          if (rows.length === 0) return null;
          return (
            <section key={ch.id} className="flex flex-col gap-1">
              <h3 className="text-[13px] font-medium">
                {ch.id} {ch.name} <span className="font-normal text-muted">· {pluralize(rows.length, "requirement")}</span>
              </h3>
              {rows.map((i) => (
                <Row key={i.requirement.id} id={assessment.id} item={i} project={project} archived={archived} open={open === i.requirement.id} onToggle={() => setOpen(open === i.requirement.id ? null : i.requirement.id)} onOpenFinding={onOpenFinding} onOpenRisks={onOpenRisks} exception={covers.get(coverKey("asvs", assessment.id, i.requirement.id))} />
              ))}
            </section>
          );
        })}
        {items.length === 0 && <span className="text-[12.5px] text-muted">No requirement matches.</span>}
        {view.data.history.length > 0 && (
          <details className="text-[12.5px]">
            <summary className="cursor-pointer text-muted">Recent changes ({view.data.history.length})</summary>
            <ul className="mt-1.5 flex flex-col gap-0.5">
              {view.data.history.slice(0, 50).map((h, n) => (
                <li key={n}>
                  <span className="font-mono">{h.requirement}</span> {statusLabel(h.fromStatus)} → {statusLabel(h.toStatus)}
                  <span className="text-muted"> · {formatRelative(h.at)}</span>
                </li>
              ))}
            </ul>
          </details>
        )}
      </div>
    </Panel>
  );
}

function Row({ id, item, project, archived, open, onToggle, onOpenFinding, onOpenRisks, exception }: { id: number; item: AsvsItem; project: Project; archived: boolean; open: boolean; onToggle: () => void; onOpenFinding: (id: number) => void; onOpenRisks?: () => void; exception?: RiskAcceptance }) {
  const confirm = useConfirm();
  const r = item.requirement;
  const st = ASVS_STATUS[item.status];
  const setStatus = async (s: AsvsStatus, note?: string) => {
    // an exception covers a non-compliant requirement only: any other status ends it
    if (exception && item.status === "non_compliant" && s !== "non_compliant") {
      const ok = await confirm.ask({
        title: `End the exception for ${r.id}?`,
        body: `Exception #${exception.id} “${exception.title}” covers this requirement only while it is non-compliant. Changing its status ends the exception for this requirement; the acceptance's history keeps the change, and covering it again takes a new exception.`,
        confirmLabel: "Change and end the exception",
      });
      if (!ok) return;
    }
    try {
      await api.asvsSetStatus(id, r.id, s, note);
      invalidate("asvs", "risk");
    } catch (e) {
      notify.error("The status was not saved", e);
    }
  };
  return (
    <div className={cn("rounded-[8px] px-2.5 py-2 text-[12.5px]", item.inLevel ? "bg-white/[0.02]" : "bg-white/[0.01] opacity-70")}>
      <div className="flex items-start gap-2">
        <button type="button" onClick={onToggle} className="flex min-w-0 flex-1 items-start gap-2 text-left">
          <span className="w-16 shrink-0 font-mono text-[11.5px]">{r.id}</span>
          <ToneChip tone="default" dot={false} className="shrink-0 text-[10.5px]">
            L{r.level}
          </ToneChip>
          <span className={cn("min-w-0 flex-1", !open && "line-clamp-2")}>{r.text}</span>
        </button>
        {(item.findings.length > 0 || item.evidence.length > 0) && <span className="shrink-0 text-[11px] text-muted">{item.findings.length + item.evidence.length} linked</span>}
        {exception && (
          <ToneChip tone={exception.standing === "active" ? "accent" : RISK_STANDING[exception.standing].tone} dot={false} className="shrink-0 text-[10.5px]">
            {exception.standing === "expired" ? `exception expired ${exception.expiresAt}` : `exception until ${exception.expiresAt}`}
          </ToneChip>
        )}
        <SelectInput aria-label={`Status of ${r.id}`} value={item.status} isDisabled={archived} onChange={(v) => void setStatus(v as AsvsStatus)} options={Object.entries(ASVS_STATUS).map(([k, s]) => ({ id: k, label: s.label }))} className={cn("w-40 shrink-0", st.tone === "danger" && "text-danger")} />
      </div>
      {open && <Details id={id} item={item} project={project} archived={archived} onSaveNote={(note) => void setStatus(item.status, note)} onOpenFinding={onOpenFinding} onOpenRisks={onOpenRisks} exception={exception} />}
      {confirm.element}
    </div>
  );
}

function Details({ id, item, project, archived, onSaveNote, onOpenFinding, onOpenRisks, exception }: { id: number; item: AsvsItem; project: Project; archived: boolean; onSaveNote: (note: string) => void; onOpenFinding: (id: number) => void; onOpenRisks?: () => void; exception?: RiskAcceptance }) {
  const { runtime } = useApp();
  const [excepting, setExcepting] = useState(false);
  const r = item.requirement;
  const [note, setNote] = useState(item.note);
  const [framework, setFramework] = useState("wstg");
  const [reference, setReference] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const findings = useQuery(["findings"], () => api.findingsList(project.id), [project.id], runtime);
  const evidence = useQuery(["findings"], () => api.evidenceList(project.id), [project.id], runtime);
  const link = async (kind: "finding" | "evidence", refId: number, linked: boolean) => {
    try {
      await api.asvsLink(id, r.id, kind, refId, linked);
      invalidate("asvs");
    } catch (e) {
      notify.error("The link was not changed", e);
    }
  };
  return (
    <div className="mt-2 ml-[4.5rem] flex flex-col gap-2.5">
      <TextAreaInput label="Note (what you checked, how)" value={note} onChange={setNote} rows={2} />
      {note !== item.note && (
        <Button size="sm" variant="tertiary" className="self-start" isDisabled={archived} onPress={() => onSaveNote(note)}>
          Save note
        </Button>
      )}
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-muted">Findings:</span>
        {item.findings.map((f) => (
          <span key={f.id} className="flex items-center gap-1 rounded-full bg-white/[0.05] px-2 py-0.5">
            <button type="button" className="hover:underline" onClick={() => onOpenFinding(f.id)}>
              #{f.id} {f.title}
            </button>
            <span className="text-muted">({f.status.replace("_", " ")})</span>
            {!archived && (
              <button type="button" aria-label={`Unlink finding ${f.id}`} className="text-muted hover:text-foreground" onClick={() => void link("finding", f.id, false)}>
                ×
              </button>
            )}
          </span>
        ))}
        <SelectInput aria-label="Link a finding" value={null} isDisabled={archived} onChange={(v) => void link("finding", Number(v), true)} options={(findings.data ?? []).filter((f) => !item.findings.some((x) => x.id === f.id)).map((f) => ({ id: String(f.id), label: f.title }))} placeholder="Link a finding…" className="w-56" />
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-muted">Evidence:</span>
        {item.evidence.map((e) => (
          <span key={e.id} className="flex items-center gap-1 rounded-full bg-white/[0.05] px-2 py-0.5">
            #{e.id} {e.title}
            {!archived && (
              <button type="button" aria-label={`Unlink evidence ${e.id}`} className="text-muted hover:text-foreground" onClick={() => void link("evidence", e.id, false)}>
                ×
              </button>
            )}
          </span>
        ))}
        <SelectInput aria-label="Link evidence" value={null} isDisabled={archived} onChange={(v) => void link("evidence", Number(v), true)} options={(evidence.data ?? []).filter((e) => !item.evidence.some((x) => x.id === e.id)).map((e) => ({ id: String(e.id), label: e.title }))} placeholder="Link evidence…" className="w-56" />
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-muted">Mappings (yours; ASVS 5.0.0 publishes none):</span>
        {item.mappings.map((m) => (
          <span key={m.id} className="flex items-center gap-1 rounded-full bg-white/[0.05] px-2 py-0.5">
            {ASVS_FRAMEWORKS.find((f) => f.id === m.framework)?.label} {m.reference}
            {!archived && (
              <button
                type="button"
                aria-label={`Remove mapping ${m.reference}`}
                className="text-muted hover:text-foreground"
                onClick={async () => {
                  await api.asvsMappingDelete(m.id);
                  invalidate("asvs");
                }}
              >
                ×
              </button>
            )}
          </span>
        ))}
      </div>
      {!archived && (
        <div className="flex flex-wrap items-center gap-1.5">
          <SelectInput aria-label="Framework" value={framework} onChange={setFramework} options={ASVS_FRAMEWORKS} className="w-48" />
          <TextInput aria-label="Reference" value={reference} onChange={setReference} placeholder="WSTG-INPV-05, API1:2023, CWE-79, T1190, AC-3" className="w-64" />
          <Button
            size="sm"
            variant="tertiary"
            isDisabled={!reference.trim()}
            onPress={async () => {
              try {
                await api.asvsMappingAdd(id, r.id, framework, reference.trim());
                setReference("");
                invalidate("asvs");
              } catch (e) {
                notify.error("The mapping was not added", e);
              }
            }}
          >
            Add mapping
          </Button>
        </div>
      )}
      {!archived && (item.status === "non_compliant" || item.status === "needs_review") && (
        <div className="flex flex-wrap items-center gap-1.5">
          <SelectInput aria-label="Severity" value={severity} onChange={(v) => setSeverity(v as Severity)} options={["critical", "high", "medium", "low", "info"].map((s) => ({ id: s, label: s }))} className="w-32" />
          <Button
            size="sm"
            variant="tertiary"
            onPress={async () => {
              try {
                const fid = await api.asvsRecordFinding(id, r.id, severity);
                invalidate("asvs", "findings", "projects");
                notify.success("Finding recorded and linked", `The requirement stays ${ASVS_STATUS[item.status].label.toLowerCase()} until you change it`);
                onOpenFinding(fid);
              } catch (e) {
                notify.error("The finding was not recorded", e);
              }
            }}
          >
            Record a finding
          </Button>
        </div>
      )}
      {exception ? (
        <p className="text-[12px] text-muted">
          Exception: risk acceptance #{exception.id} “{exception.title}”, owner {exception.owner}, approved by {exception.approver} on {exception.approvedAt}, {exception.standing === "expired" ? "expired on" : "until"} {exception.expiresAt}. It stays non-compliant.{" "}
          {onOpenRisks ? (
            <button type="button" className="text-accent hover:underline" onClick={onOpenRisks}>
              Open in Risks
            </button>
          ) : (
            "The exception is managed on the Risks tab."
          )}
        </p>
      ) : (
        !archived &&
        item.status === "non_compliant" && (
          <div>
            <Button size="sm" variant="tertiary" onPress={() => setExcepting(true)}>
              Record an exception…
            </Button>
          </div>
        )
      )}
      {excepting && (
        <AcceptRiskModal
          projectId={project.id}
          items={[{ kind: "asvs", refId: id, requirement: item.requirement.id }]}
          labels={[`ASVS ${item.requirement.id} · ${item.requirement.text}`]}
          defaultTitle={`Exception to ASVS ${item.requirement.id}`}
          isOpen
          onOpenChange={(o) => !o && setExcepting(false)}
        />
      )}
    </div>
  );
}
