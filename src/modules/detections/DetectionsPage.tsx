// SPDX-License-Identifier: Apache-2.0
import { Button } from "@heroui/react";
import { Download, FileUp, FlaskConical, FolderOutput, Plus, RotateCcw, ScanSearch, Trash2, Upload } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { CorrelationMeta, DetectionImportReport, DetectionRuleDetail, DetectionRuleSummary, DetectionTestOutcome, YaraMeta } from "@/lib/types";
import { cn, formatRelative, pluralize } from "@/lib/utils";
import { formatBytes } from "@/modules/utilities/lib/triage";
import { Segmented } from "@/modules/utilities/tools/shared";
import { correlationSummary, diffLines, explain, LEVEL_TONE, RULE_TEMPLATE, runState, testsLabel, YARA_TEMPLATE } from "./detections";

type Kind = "sigma" | "yara";
/** A rule being written: new (no id) or a new version of a library entry. */
type Draft = { content: string; kind: Kind; id?: number };
const KIND_LABEL: Record<Kind, string> = { sigma: "Sigma", yara: "YARA" };

const KEYS = ["detections"] as const;

function importSummary(r: DetectionImportReport): string {
  const n = (o: string) => r.imported.filter((x) => x.outcome === o).length;
  return [`${n("added")} added`, `${n("updated")} new versions`, `${n("unchanged")} unchanged`, r.failed.length ? `${r.failed.length} not read: ${r.failed.slice(0, 2).map(([f, e]) => `${f}: ${e}`).join("; ")}` : null, ...(r.notes ?? [])].filter(Boolean).join(", ");
}

/** Detections: a library of Sigma and YARA rules with versions, collections, tests on log and
 * file samples with expectations, feedback, and their ATT&CK coverage. */
export default function DetectionsPage() {
  const { runtime } = useApp();
  const [text, setText] = useState("");
  const [level, setLevel] = useState("all");
  const [kind, setKind] = useState("all");
  const [enabled, setEnabled] = useState("all");
  const [collection, setCollection] = useState("all");
  const [selected, setSelected] = useState<number | null>(null);
  const [writing, setWriting] = useState<Draft | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const engine = useQuery([...KEYS], () => api.detectionEngine(), [], runtime);
  const collections = useQuery([...KEYS], () => api.detectionCollections(), [], runtime);
  const samples = useQuery([...KEYS], () => api.detectionSamples(), [], runtime);
  const filter = useMemo(
    () => ({ text: text.trim() || null, kind: kind === "all" ? null : kind, level: level === "all" ? null : level, enabled: enabled === "all" ? null : enabled === "on", collection: collection === "all" ? null : Number(collection), limit: 300 }),
    [text, kind, level, enabled, collection],
  );
  const rules = useQuery([...KEYS], () => api.detectionRulesList(filter), [filter], runtime);

  const act = async (key: string, fn: () => Promise<void>) => {
    setBusy(key);
    try {
      await fn();
    } finally {
      setBusy(null);
    }
  };
  const importRules = () =>
    act("import", async () => {
      try {
        const r = await api.detectionRulesImport();
        if (!r) return;
        invalidate("detections", "attack");
        if (r.imported[0]) setSelected(r.imported[0].id);
        notify.success("Rules imported", importSummary(r));
      } catch (e) {
        notify.error("The rules were not imported", e);
      }
    });
  const addSample = (file: boolean) =>
    act(file ? "file" : "sample", async () => {
      try {
        const s = await api.detectionSampleAdd(file ? "file" : undefined);
        if (!s) return;
        invalidate("detections");
        notify.success(`Sample added: ${s.fileName}`, s.kind === "file" ? `File, ${formatBytes(s.size)}` : `${s.kind.toUpperCase()}, ${pluralize(s.events, "event")}`);
      } catch (e) {
        notify.error("The sample was not added", e);
      }
    });

  return (
    <div>
      <PageHeader
        title="Detections"
        description={`Sigma rules (specification v${engine.data?.spec ?? "2.1.0"}) for logs and YARA rules (${engine.data?.yara.engine ?? "boreal"}) for files, with versions, collections and tests on your own samples. A rule match is a lead: in a project it stays a detection hit until you promote it to a finding. Rules are data; nothing in a rule or a sample is run.`}
        actions={
          <>
            <Button variant="secondary" size="sm" onPress={() => void addSample(false)} isPending={busy === "sample"} isDisabled={!runtime}>
              <FileUp className="size-3.5" />
              Add log sample…
            </Button>
            <Button variant="secondary" size="sm" onPress={() => void addSample(true)} isPending={busy === "file"} isDisabled={!runtime}>
              <FileUp className="size-3.5" />
              Add file sample…
            </Button>
            <Button variant="secondary" size="sm" onPress={() => void importRules()} isPending={busy === "import"} isDisabled={!runtime}>
              <Upload className="size-3.5" />
              Import rules…
            </Button>
            <Button variant="primary" size="sm" onPress={() => setWriting({ content: RULE_TEMPLATE, kind: "sigma" })} isDisabled={!runtime}>
              <Plus className="size-3.5" />
              New rule
            </Button>
          </>
        }
      />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="flex flex-col gap-4 xl:col-span-5">
          <Panel
            title={`Rules${rules.data ? ` (${rules.data.total})` : ""}`}
            toolbar={
              <div className="flex flex-wrap items-center gap-2 px-4 pb-3">
                <SearchInput value={text} onChange={setText} placeholder="Find a rule" className="min-w-[160px] flex-1" />
                <SelectInput aria-label="Kind" value={kind} onChange={setKind} options={[{ id: "all", label: "Sigma and YARA" }, { id: "sigma", label: "Sigma" }, { id: "yara", label: "YARA" }]} className="w-40" />
                <SelectInput aria-label="Level" value={level} onChange={setLevel} options={[{ id: "all", label: "All levels" }, ...["critical", "high", "medium", "low", "informational"].map((l) => ({ id: l, label: l }))]} className="w-36" />
                <SelectInput aria-label="Enabled" value={enabled} onChange={setEnabled} options={[{ id: "all", label: "Any state" }, { id: "on", label: "Enabled" }, { id: "off", label: "Disabled" }]} className="w-32" />
                {(collections.data?.length ?? 0) > 0 && (
                  <SelectInput aria-label="Collection" value={collection} onChange={setCollection} options={[{ id: "all", label: "All collections" }, ...(collections.data ?? []).map((c) => ({ id: String(c.id), label: c.name }))]} className="w-40" />
                )}
              </div>
            }
          >
            {rules.error ? (
              <ErrorBlock message={rules.error} onRetry={rules.reload} />
            ) : !rules.data ? (
              <LoadingRows rows={5} />
            ) : rules.data.items.length === 0 ? (
              <EmptyBlock compact icon={ScanSearch} title={rules.data.total === 0 && !filter.text ? "No rules yet" : "No rule matches"} description="Import Sigma rule files (.yml) or YARA rule files (.yar), or write one. SigmaHQ's and Neo23x0's signature-base repositories publish thousands under the Detection Rule License." />
            ) : (
              <ul className="flex flex-col gap-1">
                {rules.data.items.map((r) => (
                  <RuleRow key={r.id} r={r} active={r.id === selected} onOpen={() => setSelected(r.id)} />
                ))}
              </ul>
            )}
          </Panel>
          <Collections />
          <Panel title={`Samples${samples.data ? ` (${samples.data.length})` : ""}`} description="Kept by content hash in ExploitX's data folder, to test rules again after every change. Files are only read, never opened or run.">
            {(samples.data ?? []).length === 0 ? (
              <span className="text-[12.5px] text-muted">No sample yet: add an EVTX file, a JSON or JSON Lines export or a text log for Sigma rules, or any file for YARA rules.</span>
            ) : (
              <ul className="flex flex-col gap-1 text-[12.5px]">
                {(samples.data ?? []).map((s) => (
                  <li key={s.id} className="flex items-center gap-2">
                    <ToneChip tone="default" dot={false} className="text-[11px]">
                      {s.kind.toUpperCase()}
                    </ToneChip>
                    <span className="min-w-0 flex-1 truncate">{s.fileName}</span>
                    <span className="text-muted">{s.kind === "file" ? formatBytes(s.size) : pluralize(s.events, "event")}</span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
          {engine.data && (
            <details className="text-[12.5px] text-muted">
              <summary className="cursor-pointer">What the Sigma engine supports</summary>
              <p className="mt-1.5">Modifiers: {engine.data.modifiers.join(", ")}.</p>
              <p className="mt-1">Refused with the reason: {engine.data.unsupported.join("; ")}.</p>
              {engine.data.correlation && (
                <p className="mt-1">
                  Correlation rules: {engine.data.correlation.types.join(", ")}, with group-by, aliases, ranges and chains of up to {engine.data.correlation.maxChain} correlations; windows slide (they are not cut at clock boundaries) and last at most {engine.data.correlation.maxTimespan}. The rules a correlation refers to run as part of it, also when disabled.
                </p>
              )}
              <p className="mt-1">Windows log sources mapped to channels and event IDs: {[...engine.data.services, ...engine.data.categories].join(", ")}. Other log sources run against every event, and the result says so.</p>
            </details>
          )}
          {engine.data?.yara && (
            <details className="text-[12.5px] text-muted">
              <summary className="cursor-pointer">What the YARA engine supports</summary>
              <p className="mt-1.5">
                {engine.data.yara.engine}: text, hex and regular-expression strings with their modifiers, conditions, private and global rules, and the modules {engine.data.yara.modules.join(", ")}.
              </p>
              <p className="mt-1">Not available: {engine.data.yara.unsupported.join("; ")}.</p>
              <p className="mt-1">
                Limits: rule files of {engine.data.yara.limits.ruleFileKb / 1024} MB and {engine.data.yara.limits.stringsPerRule.toLocaleString()} strings per rule; files of {engine.data.yara.limits.fileMb} MB; a scan stops after {engine.data.yara.limits.scanSeconds} s. Conditions nesting deeper than 64 levels are refused before they are read.
              </p>
            </details>
          )}
        </div>
        <div className="xl:col-span-7">
          {selected == null ? (
            <Panel>
              <EmptyBlock compact icon={FlaskConical} title="Choose a rule" description="Its metadata, problems, versions, tests and feedback appear here." />
            </Panel>
          ) : (
            <RuleView key={selected} id={selected} onDeleted={() => setSelected(null)} onEdit={setWriting} />
          )}
        </div>
      </div>
      {writing != null && (
        <RuleEditor
          draft={writing}
          onClose={() => setWriting(null)}
          onSaved={(id) => {
            setWriting(null);
            setSelected(id);
          }}
        />
      )}
    </div>
  );
}

function RuleRow({ r, active, onOpen }: { r: DetectionRuleSummary; active: boolean; onOpen: () => void }) {
  const state = runState(r);
  const tests = testsLabel(r);
  return (
    <li>
      <button type="button" onClick={onOpen} className={cn("flex w-full flex-col gap-1 rounded-[8px] px-2.5 py-2 text-left", active ? "bg-accent-soft/40" : "bg-white/[0.02] hover:bg-white/[0.05]")}>
        <span className="flex items-center gap-2">
          <ToneChip tone={LEVEL_TONE[r.level] ?? "default"} dot={false} className="text-[11px]">
            {r.level || "no level"}
          </ToneChip>
          {r.kind === "yara" && (
            <ToneChip tone="accent" dot={false} className="text-[10.5px]">
              YARA
            </ToneChip>
          )}
          <span className="min-w-0 flex-1 truncate text-[13px] font-medium">{r.title}</span>
          <span className="text-[11px] text-muted">v{r.version}</span>
        </span>
        <span className="flex flex-wrap items-center gap-1.5 text-[11.5px] text-muted">
          <span>{r.logsource || "no log source"}</span>
          <ToneChip tone={state.tone} dot={false} className="text-[10.5px]">
            {state.label}
          </ToneChip>
          {tests && (
            <ToneChip tone={tests.tone} dot={false} className="text-[10.5px]">
              {tests.label}
            </ToneChip>
          )}
          {r.falsePositives > 0 && <span>{pluralize(r.falsePositives, "false positive")}</span>}
          {r.techniques.slice(0, 3).map((t) => (
            <span key={t} className="font-mono">
              {t}
            </span>
          ))}
        </span>
      </button>
    </li>
  );
}

function Collections() {
  const { runtime } = useApp();
  const confirm = useConfirm();
  const q = useQuery(["detections"], () => api.detectionCollections(), [], runtime);
  const [name, setName] = useState("");
  return (
    <Panel title="Collections" description="Group rules to run them together on a project, or to export them.">
      <div className="flex flex-col gap-2">
        <div className="flex gap-2">
          <TextInput aria-label="New collection" value={name} onChange={setName} placeholder="New collection name" className="flex-1" />
          <Button
            size="sm"
            variant="tertiary"
            isDisabled={!name.trim()}
            onPress={async () => {
              try {
                await api.detectionCollectionCreate(name.trim());
                setName("");
                invalidate("detections");
              } catch (e) {
                notify.error("The collection was not created", e);
              }
            }}
          >
            Create
          </Button>
        </div>
        <ul className="flex flex-col gap-1 text-[12.5px]">
          {(q.data ?? []).map((c) => (
            <li key={c.id} className="flex items-center gap-2">
              <span className="min-w-0 flex-1 truncate">{c.name}</span>
              <span className="text-muted">{pluralize(c.rules, "rule")}</span>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 px-1.5"
                aria-label={`Export ${c.name}`}
                isDisabled={c.rules === 0}
                onPress={async () => {
                  try {
                    const n = await api.detectionCollectionExport(c.id);
                    if (n != null) notify.success(`${pluralize(n, "rule")} exported`);
                  } catch (e) {
                    notify.error("The collection was not exported", e);
                  }
                }}
              >
                <FolderOutput className="size-3.5" />
              </Button>
              <Button
                size="sm"
                variant="ghost"
                className="h-7 px-1.5"
                aria-label={`Delete ${c.name}`}
                onPress={async () => {
                  if (!(await confirm.ask({ title: `Delete the collection “${c.name}”?`, body: "Its rules stay in the library.", confirmLabel: "Delete", tone: "danger" }))) return;
                  await api.detectionCollectionDelete(c.id);
                  invalidate("detections");
                }}
              >
                <Trash2 className="size-3.5" />
              </Button>
            </li>
          ))}
        </ul>
      </div>
      {confirm.element}
    </Panel>
  );
}

function RuleEditor({ draft, onClose, onSaved }: { draft: Draft; onClose: () => void; onSaved: (id: number) => void }) {
  const [kind, setKind] = useState<Kind>(draft.kind);
  const [text, setText] = useState(draft.content);
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  const [report, setReport] = useState<DetectionImportReport | null>(null);
  const save = async () => {
    setSaving(true);
    try {
      const r = await api.detectionRuleSave(text, note.trim() || undefined, kind, draft.id);
      setReport(r);
      invalidate("detections", "attack");
      if (r.failed.length === 0 && r.imported[0]) {
        // a rule that cannot run is saved, but that is not a clean success (Mission 7)
        (r.imported[0].errors ? notify.warning : notify.success)(
          r.imported[0].outcome === "unchanged" ? "No change" : `Saved as version ${r.imported[0].version}`,
          r.imported[0].errors ? `${pluralize(r.imported[0].errors, "problem")} keep it from running` : undefined,
        );
        onSaved(r.imported[0].id);
      }
    } catch (e) {
      notify.error("The rule was not saved", e);
    } finally {
      setSaving(false);
    }
  };
  return (
    <AppModal
      isOpen
      onOpenChange={(o) => !o && onClose()}
      size="lg"
      title={draft.id != null ? `Edit the ${KIND_LABEL[kind]} rule${kind === "yara" ? "s" : ""}` : kind === "yara" ? "Write YARA rules" : "Write a Sigma rule"}
      description={
        kind === "yara"
          ? draft.id != null
            ? "Saving makes the next version of this rule file. Rules are compiled by boreal when saved; includes are refused."
            : "A new rule file is named after its first rule. Rules are compiled by boreal when saved; includes are refused."
          : "Saved rules are checked against the specification. A rule with the id of a rule in the library becomes its next version."
      }
      footer={
        <div className="flex w-full items-center gap-2">
          <TextInput aria-label="What changed" value={note} onChange={setNote} placeholder="What changed (kept with the version)" className="flex-1" />
          <Button size="sm" variant="tertiary" onPress={onClose}>
            Cancel
          </Button>
          <Button size="sm" variant="primary" onPress={() => void save()} isPending={saving} isDisabled={!text.trim()}>
            Save
          </Button>
        </div>
      }
    >
      {draft.id == null && (
        <Segmented
          value={kind}
          onChange={(k: Kind) => {
            if (text === RULE_TEMPLATE || text === YARA_TEMPLATE || !text.trim()) setText(k === "yara" ? YARA_TEMPLATE : RULE_TEMPLATE);
            setKind(k);
          }}
          ariaLabel="Rule kind"
          options={[
            { id: "sigma", label: "Sigma (logs)" },
            { id: "yara", label: "YARA (files)" },
          ]}
        />
      )}
      <TextAreaInput label={kind === "yara" ? "Rules (YARA)" : "Rule (YAML)"} value={text} onChange={setText} rows={20} mono />
      {report && report.failed.length > 0 && <ErrorBlock message={report.failed.map(([f, e]) => `${f}: ${e}`).join("\n")} />}
    </AppModal>
  );
}

function RuleView({ id, onDeleted, onEdit }: { id: number; onDeleted: () => void; onEdit: (draft: Draft) => void }) {
  const { runtime } = useApp();
  const confirm = useConfirm();
  const q = useQuery(["detections"], () => api.detectionRuleGet(id), [id], runtime);
  const [tab, setTab] = useState<"overview" | "rule" | "versions" | "tests" | "feedback">("overview");
  if (q.error) return <ErrorBlock message={q.error} onRetry={q.reload} />;
  if (!q.data) return <LoadingRows rows={6} />;
  const d = q.data;
  const s = d.summary;
  const state = runState(s);
  return (
    <Panel
      title={s.title}
      description={[`${KIND_LABEL[s.kind]} · version ${s.version}`, s.status && `status ${s.status}`, s.logsource, `updated ${formatRelative(s.updatedAt)}`].filter(Boolean).join(" · ")}
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <SwitchInput
            label={state.label === "cannot run" ? "Cannot run" : "Enabled"}
            isSelected={s.enabled}
            onChange={async (v) => {
              await api.detectionRuleSetEnabled(id, v);
              invalidate("detections", "attack");
            }}
          />
          <Button size="sm" variant="tertiary" onPress={() => onEdit(s.kind === "yara" ? { content: d.content, kind: "yara", id: s.id } : { content: d.content, kind: "sigma" })}>
            Edit
          </Button>
          <Button
            size="sm"
            variant="ghost"
            aria-label="Export the rule"
            onPress={async () => {
              const f = await api.detectionRuleExport(id).catch((e) => (notify.error("The rule was not exported", e), null));
              if (f) notify.success("Rule exported", f);
            }}
          >
            <Download className="size-3.5" />
          </Button>
          <Button
            size="sm"
            variant="ghost"
            aria-label="Delete the rule"
            onPress={async () => {
              if (!(await confirm.ask({ title: `Delete “${s.title}”?`, body: "Its versions, tests and feedback go with it. Detection hits in projects stay, without the rule.", confirmLabel: "Delete", tone: "danger" }))) return;
              await api.detectionRuleDelete(id);
              invalidate("detections", "attack");
              onDeleted();
            }}
          >
            <Trash2 className="size-3.5" />
          </Button>
        </div>
      }
    >
      <div className="flex flex-col gap-3">
        <Segmented
          value={tab}
          onChange={setTab}
          ariaLabel="Rule view"
          options={[
            { id: "overview", label: "Overview" },
            { id: "rule", label: "Rule" },
            { id: "versions", label: `Versions (${d.versions.length})` },
            { id: "tests", label: `Tests (${d.samples.length})` },
            { id: "feedback", label: `Feedback (${d.feedback.length})` },
          ]}
        />
        {tab === "overview" && <Overview d={d} />}
        {tab === "rule" && (
          <pre data-selectable className="panel-inset max-h-[560px] overflow-auto px-3 py-2 font-mono text-[12px] whitespace-pre-wrap">
            {d.content}
          </pre>
        )}
        {tab === "versions" && <Versions d={d} />}
        {tab === "tests" && <Tests d={d} />}
        {tab === "feedback" && <FeedbackView d={d} />}
      </div>
      {confirm.element}
    </Panel>
  );
}

function Overview({ d }: { d: DetectionRuleDetail }) {
  const { runtime } = useApp();
  const collections = useQuery(["detections"], () => api.detectionCollections(), [], runtime);
  const m = d.meta as { description?: string; author?: string; references?: string[]; falsepositives?: string[]; tags?: string[]; tactics?: string[]; techniques?: string[]; correlation?: CorrelationMeta };
  const levelTone: Record<string, "danger" | "warning" | "default"> = { error: "danger", unsupported: "warning", warning: "default" };
  const yara = d.summary.kind === "yara" ? (d.meta as unknown as YaraMeta) : null;
  return (
    <div className="flex flex-col gap-3 text-[12.5px]">
      {m.description && <p>{m.description}</p>}
      {m.correlation && (
        <section className="flex flex-col gap-1">
          <h3 className="text-[13px] font-medium">Correlation rule</h3>
          <p>{correlationSummary(m.correlation)}.</p>
          <p className="text-muted">
            {m.correlation.generate
              ? "generate: true — the rules it refers to also run on their own."
              : "The rules it refers to run as part of it; on their own they run only when enabled."}{" "}
            A match is a lead built from other rules' matches, kept as a detection hit for review.
          </p>
        </section>
      )}
      {yara && yara.rules.length > 0 && (
        <section className="flex flex-col gap-1">
          <h3 className="text-[13px] font-medium">
            {pluralize(yara.rules.length, "rule")}
            {yara.imports.length > 0 && <span className="font-normal text-muted"> · modules {yara.imports.join(", ")}</span>}
          </h3>
          <ul className="flex flex-col gap-0.5">
            {yara.rules.slice(0, 100).map((r) => (
              <li key={r.name} className="flex flex-wrap items-center gap-1.5">
                <span className="font-mono text-[12px]">{r.name}</span>
                {r.private && <span className="text-muted">private (never reported)</span>}
                {r.global && <span className="text-muted">global (applies to every rule of the file)</span>}
                {r.tags.map((t) => (
                  <ToneChip key={t} tone="default" dot={false} className="text-[10.5px]">
                    {t}
                  </ToneChip>
                ))}
              </li>
            ))}
          </ul>
        </section>
      )}
      <div className="flex flex-wrap gap-1.5">
        {(m.techniques ?? []).map((t) => (
          <ToneChip key={t} tone="accent" dot={false} className="text-[11px]">
            ATT&CK {t}
          </ToneChip>
        ))}
        {(yara ? [] : (m.tags ?? [])).filter((t) => !/^attack\.t\d/i.test(t)).map((t) => (
          <ToneChip key={t} tone="default" dot={false} className="text-[11px]">
            {t}
          </ToneChip>
        ))}
      </div>
      {d.issues.length > 0 && (
        <section className="flex flex-col gap-1">
          <h3 className="text-[13px] font-medium">{yara ? "Compiled by boreal" : "Checked against the specification"}</h3>
          {d.issues.map((i, n) => (
            <div key={n} className="flex items-start gap-2">
              <ToneChip tone={levelTone[i.level]} dot={false} className="shrink-0 text-[10.5px]">
                {i.level}
              </ToneChip>
              <span>{i.message}</span>
            </div>
          ))}
        </section>
      )}
      {(m.falsepositives ?? []).length > 0 && <p className="text-muted">Known false positives: {(m.falsepositives ?? []).join("; ")}</p>}
      {m.author && <p className="text-muted">Author: {m.author}</p>}
      {(m.references ?? []).length > 0 && (
        <ul className="flex flex-col gap-0.5 text-muted">
          {(m.references ?? []).slice(0, 10).map((r) => (
            <li key={r} className="truncate font-mono text-[11.5px]">
              {r}
            </li>
          ))}
        </ul>
      )}
      {(collections.data?.length ?? 0) > 0 && (
        <section className="flex flex-wrap items-center gap-3">
          <span className="text-muted">Collections:</span>
          {(collections.data ?? []).map((c) => (
            <SwitchInput
              key={c.id}
              label={c.name}
              isSelected={d.summary.collections.includes(c.id)}
              onChange={async (v) => {
                await api.detectionCollectionMember(c.id, d.summary.id, v);
                invalidate("detections");
              }}
            />
          ))}
        </section>
      )}
      {d.projects.length > 0 && (
        <p className="text-muted">
          Matched in: {d.projects.map((p) => `${p.project} (${pluralize(p.hits, "hit")}${p.findings ? `, ${pluralize(p.findings, "finding")}` : ""})`).join("; ")}
        </p>
      )}
    </div>
  );
}

function Versions({ d }: { d: DetectionRuleDetail }) {
  const [from, setFrom] = useState(String(d.versions[1]?.version ?? d.versions[0]?.version ?? 1));
  const [to, setTo] = useState(String(d.versions[0]?.version ?? 1));
  const { runtime } = useApp();
  const a = useQuery(["detections"], () => api.detectionRuleVersion(d.summary.id, Number(from)), [d.summary.id, from], runtime);
  const b = useQuery(["detections"], () => api.detectionRuleVersion(d.summary.id, Number(to)), [d.summary.id, to], runtime);
  const lines = useMemo(() => (a.data != null && b.data != null ? diffLines(a.data, b.data) : []), [a.data, b.data]);
  const opts = d.versions.map((v) => ({ id: String(v.version), label: `Version ${v.version}` }));
  return (
    <div className="flex flex-col gap-2 text-[12.5px]">
      <ul className="flex flex-col gap-0.5">
        {d.versions.map((v) => (
          <li key={v.version} className="flex gap-2">
            <span className="w-20 font-medium">Version {v.version}</span>
            <span className="text-muted">{formatRelative(v.createdAt)}</span>
            <span className="min-w-0 flex-1 truncate">{v.note}</span>
          </li>
        ))}
      </ul>
      {d.versions.length > 1 && (
        <>
          <div className="flex items-center gap-2">
            <span className="text-muted">Compare</span>
            <SelectInput aria-label="From version" value={from} onChange={setFrom} options={opts} className="w-36" />
            <span className="text-muted">with</span>
            <SelectInput aria-label="To version" value={to} onChange={setTo} options={opts} className="w-36" />
          </div>
          <pre className="panel-inset max-h-[420px] overflow-auto px-3 py-2 font-mono text-[12px]">
            {lines.map((l, i) => (
              <div key={i} className={cn(l.kind === "added" && "bg-success/15 text-success", l.kind === "removed" && "bg-danger/15 text-danger")}>
                {l.kind === "added" ? "+ " : l.kind === "removed" ? "- " : "  "}
                {l.text}
              </div>
            ))}
          </pre>
        </>
      )}
    </div>
  );
}

function Outcome({ o, kind }: { o: DetectionTestOutcome; kind: Kind }) {
  const r = o.result;
  return (
    <div className="flex flex-col gap-1.5 rounded-[8px] bg-white/[0.03] px-3 py-2 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-medium">{o.sample.fileName}</span>
        <span className="text-muted">
          {kind === "yara" ? `${pluralize(r.matched, "rule")} matched the file` : `${pluralize(r.matched, "match", "matches")} in ${pluralize(r.inSource, "event")} of the log source (${r.events} read)`}
        </span>
        {o.test.passed != null && (
          <ToneChip tone={o.test.passed ? "success" : "danger"} dot={false} className="text-[11px]">
            {o.test.passed ? "passed" : "failed"} (expected {o.test.expect === "match" ? "a match" : "no match"})
          </ToneChip>
        )}
        {o.previous && (
          <span className="text-muted">
            before: {pluralize(o.previous.matched, "match", "matches")} with version {o.previous.version}
          </span>
        )}
      </div>
      {r.notes.map((n) => (
        <span key={n} className="text-warning">
          {n}
        </span>
      ))}
      {r.matches.slice(0, 10).map((m) => (
        <details key={m.position} className="text-[12px]">
          <summary className="cursor-pointer">
            <span className="font-mono">{m.position}</span> {m.time && <span className="text-muted">{m.time}</span>} {m.label}
          </summary>
          <ul className="mt-1 ml-3 flex flex-col gap-0.5">
            {explain(m.explanation).map((line) => (
              <li key={line} className="break-all">
                {line}
              </li>
            ))}
          </ul>
        </details>
      ))}
    </div>
  );
}

function Tests({ d }: { d: DetectionRuleDetail }) {
  const { runtime } = useApp();
  const samples = useQuery(["detections"], () => api.detectionSamples(), [], runtime);
  const [outcomes, setOutcomes] = useState<DetectionTestOutcome[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [add, setAdd] = useState<string | null>(null);
  const known = new Set(d.samples.map((s) => s.sampleId));
  const yara = d.summary.kind === "yara";
  const run = async (key: string, fn: () => Promise<DetectionTestOutcome[]>) => {
    setBusy(key);
    try {
      setOutcomes(await fn());
      invalidate("detections", "attack");
    } catch (e) {
      notify.error("The test did not run", e);
    } finally {
      setBusy(null);
    }
  };
  return (
    <div className="flex flex-col gap-3 text-[12.5px]">
      <p className="text-muted">
        {yara ? "Test the rules on samples (any file) " : "Test the rule on log samples "}
        and say what it should do on each: a test passes when the rule matches a sample it should match, and stays silent on one it should not. Re-test after every change.
      </p>
      {d.samples.map((s) => (
        <div key={s.sampleId} className="flex flex-wrap items-center gap-2">
          <span className="min-w-0 flex-1 truncate">{s.fileName}</span>
          <SelectInput
            aria-label={`Expectation for ${s.fileName}`}
            value={s.expect}
            onChange={async (v) => {
              await api.detectionRuleExpect(d.summary.id, s.sampleId, v as "none" | "match" | "no_match");
              invalidate("detections", "attack");
            }}
            options={[
              { id: "none", label: "No expectation" },
              { id: "match", label: "Should match" },
              { id: "no_match", label: "Should not match" },
            ]}
            className="w-44"
          />
          {s.last && (
            <ToneChip tone={s.last.passed == null ? "default" : s.last.passed ? "success" : "danger"} dot={false} className="text-[11px]">
              v{s.last.version}: {pluralize(s.last.matched, "match", "matches")}
              {s.last.passed == null ? "" : s.last.passed ? ", passed" : ", failed"}
            </ToneChip>
          )}
          <Button size="sm" variant="tertiary" isPending={busy === `s${s.sampleId}`} isDisabled={!d.summary.runnable} onPress={() => void run(`s${s.sampleId}`, async () => [await api.detectionRuleTest(d.summary.id, s.sampleId)])}>
            Test
          </Button>
        </div>
      ))}
      <div className="flex flex-wrap items-center gap-2">
        <SelectInput
          aria-label="Sample to test"
          value={add}
          onChange={setAdd}
          options={(samples.data ?? []).filter((s) => !known.has(s.id) && (yara || s.kind !== "file")).map((s) => ({ id: String(s.id), label: s.kind === "file" ? `${s.fileName} (file, ${formatBytes(s.size)})` : `${s.fileName} (${s.kind}, ${s.events} events)` }))}
          placeholder="Test on another sample…"
          className="min-w-[260px] flex-1"
        />
        <Button size="sm" variant="tertiary" isDisabled={!add || !d.summary.runnable} isPending={busy === "add"} onPress={() => void run("add", async () => [await api.detectionRuleTest(d.summary.id, Number(add))])}>
          <FlaskConical className="size-3.5" />
          Test
        </Button>
        {d.samples.length > 0 && (
          <Button size="sm" variant="tertiary" isPending={busy === "all"} isDisabled={!d.summary.runnable} onPress={() => void run("all", () => api.detectionRuleRetest(d.summary.id))}>
            <RotateCcw className="size-3.5" />
            Re-test all samples
          </Button>
        )}
      </div>
      {!d.summary.runnable && <span className="text-danger">The rule cannot run: see the problems in its overview.</span>}
      {outcomes.map((o) => (
        <Outcome key={o.test.id} o={o} kind={d.summary.kind} />
      ))}
    </div>
  );
}

function FeedbackView({ d }: { d: DetectionRuleDetail }) {
  const [verdict, setVerdict] = useState("note");
  const [note, setNote] = useState("");
  const label: Record<string, string> = { false_positive: "False positive", true_positive: "True positive", note: "Note" };
  return (
    <div className="flex flex-col gap-2 text-[12.5px]">
      <div className="flex flex-wrap gap-2">
        <SelectInput
          aria-label="Verdict"
          value={verdict}
          onChange={setVerdict}
          options={[
            { id: "note", label: "Note" },
            { id: "false_positive", label: "False positive" },
            { id: "true_positive", label: "True positive" },
          ]}
          className="w-40"
        />
        <TextInput aria-label="Feedback" value={note} onChange={setNote} placeholder="What you saw (tuning ideas, exclusions)" className="min-w-[220px] flex-1" />
        <Button
          size="sm"
          variant="tertiary"
          isDisabled={!note.trim()}
          onPress={async () => {
            await api.detectionFeedbackAdd(d.summary.id, null, verdict as "note", note);
            setNote("");
            invalidate("detections");
          }}
        >
          Add
        </Button>
      </div>
      {d.feedback.length === 0 ? (
        <span className="text-muted">No feedback yet. False positives marked in projects are recorded here.</span>
      ) : (
        <ul className="flex flex-col gap-1">
          {d.feedback.map((f) => (
            <li key={f.id} className="flex gap-2">
              <ToneChip tone={f.verdict === "false_positive" ? "warning" : f.verdict === "true_positive" ? "success" : "default"} dot={false} className="shrink-0 text-[11px]">
                {label[f.verdict]}
              </ToneChip>
              <span className="min-w-0 flex-1">
                {f.note || <span className="text-muted">(no note)</span>}
                {f.project && <span className="text-muted"> · {f.project}</span>}
              </span>
              <span className="text-muted">{formatRelative(f.createdAt)}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
