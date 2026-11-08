import { Button, Dropdown } from "@heroui/react";
import { ChevronDown, Download, FilePlus2, FileText, History, Link2, NotebookPen, Printer, Save, Trash2, Upload } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SelectInput, SwitchInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { EvidenceRecord, Finding, Project, ReportOptions, Severity, TimelineEventType } from "@/lib/types";
import { useShowMore } from "@/lib/showMore";
import { cn, formatDateTime, formatNumber, formatRelative } from "@/lib/utils";

/* ───────────────────────── scope history and tester ───────────────────────── */

const ACTION_TONE = { added: "success", updated: "accent", removed: "default", blocked: "danger" } as const;

export function ScopeExtras({ project }: { project: Project }) {
  const { runtime } = useApp();
  const history = useQuery(["projects"], () => api.scopeHistory(project.id, 200), [project.id], runtime);
  return (
    <div className="mt-3">
      <Panel title="Scope history" description="Every change to the scope, and every active operation refused because of it.">
        {history.error ? (
          <ErrorBlock message={history.error} onRetry={history.reload} />
        ) : !history.data ? (
          <LoadingRows rows={3} />
        ) : history.data.length === 0 ? (
          <p className="text-[12.5px] text-muted">No changes recorded yet.</p>
        ) : (
          <ol className="flex max-h-[420px] flex-col gap-1 overflow-auto">
            {history.data.map((e) => (
              <li key={e.id} className="flex items-start gap-2 text-[12.5px]">
                <span className="w-28 shrink-0 text-muted">{formatRelative(e.at)}</span>
                <ToneChip tone={ACTION_TONE[e.action]}>{e.action}</ToneChip>
                <span className="min-w-0">
                  <span className="font-mono">{e.value}</span>
                  {e.inScope === false && e.action !== "blocked" && <span className="text-muted"> (exclusion)</span>}
                  {e.note && <span className="text-muted"> · {e.note}</span>}
                  {e.source !== "user" && <span className="text-muted"> · {e.source}</span>}
                </span>
              </li>
            ))}
          </ol>
        )}
      </Panel>
    </div>
  );
}

/* ───────────────────────── evidence vault ───────────────────────── */

const KIND_LABEL: Record<EvidenceRecord["kind"], string> = { file: "File", text: "Text", execution: "Tool run", osint_evidence: "OSINT evidence" };

function formatSize(n: number | null) {
  if (n == null) return "";
  return n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function ShowMoreRow({ hidden, shown, step, noun, onMore }: { hidden: number; shown: number; step: number; noun: string; onMore: () => void }) {
  if (hidden === 0) return null;
  return (
    <li className="flex flex-wrap items-center justify-between gap-2 px-3 pt-1 text-[12.5px] text-muted">
      <span>
        Showing {formatNumber(shown)} of {formatNumber(shown + hidden)} {noun}
      </span>
      <Button size="sm" variant="ghost" onPress={onMore}>
        Show {formatNumber(Math.min(step, hidden))} more
      </Button>
    </li>
  );
}

export function EvidenceVault({ project, findings, onOpenFindings }: { project: Project; findings: Finding[]; onOpenFindings: () => void }) {
  const { runtime } = useApp();
  const confirm = useConfirm();
  const list = useQuery(["findings"], () => api.evidenceList(project.id), [project.id], runtime);
  const runs = useQuery(["executions"], () => api.projectToolHistory(project.id), [project.id], runtime);
  const [note, setNote] = useState<{ title: string; content: string } | null>(null);
  const [view, setView] = useState<EvidenceRecord | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const refs = useMemo(() => findings.flatMap((f) => f.evidence.map((e, i) => ({ key: `${f.id}-${i}`, finding: f, ...e }))), [findings]);
  // thousands of records would block the window; they are rendered in steps
  const records = useShowMore(list.data ?? [], project.id);
  const shownRefs = useShowMore(refs, project.id);

  const act = async (key: string, fn: () => Promise<unknown>, done?: string) => {
    setBusy(key);
    try {
      const r = await fn();
      invalidate("findings");
      if (done && r !== null) notify.success(done);
    } catch (e) {
      notify.error("The evidence action failed", e);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <Panel
        title="Evidence vault"
        description="Files are copied into Cyber Hub's private evidence folder and identified by SHA-256; tool runs and OSINT evidence are referenced, not copied."
        actions={
          <>
            <Button size="sm" variant="tertiary" onPress={() => setNote({ title: "", content: "" })}>
              <NotebookPen className="size-3.5" />
              Add note
            </Button>
            <Dropdown>
              <Button size="sm" variant="tertiary" isDisabled={!runs.data?.length}>
                <Link2 className="size-3.5" />
                Add tool run
                <ChevronDown className="size-3" />
              </Button>
              <Dropdown.Popover placement="bottom end">
                <Dropdown.Menu aria-label="Tool runs" onAction={(k) => void act("run", () => api.evidenceLinkExecution(project.id, Number(k)), "Tool run added to the evidence")}>
                  {(runs.data ?? [])
                    .filter((r) => r.kind === "run")
                    .slice(0, 50)
                    .map((r) => (
                      <Dropdown.Item key={r.id} id={String(r.id)} textValue={`${r.toolId} #${r.id}`}>
                        {r.toolId} #{r.id} · {formatRelative(r.startedAt)}
                      </Dropdown.Item>
                    ))}
                </Dropdown.Menu>
              </Dropdown.Popover>
            </Dropdown>
            <Button size="sm" variant="primary" isPending={busy === "file"} onPress={() => act("file", () => api.evidenceAddFile(project.id), "File added to the evidence")}>
              <Upload className="size-3.5" />
              Add file
            </Button>
          </>
        }
      >
        {list.error ? (
          <ErrorBlock message={list.error} onRetry={list.reload} />
        ) : !list.data ? (
          <LoadingRows rows={3} />
        ) : list.data.length === 0 ? (
          <EmptyBlock compact icon={FileText} title="No evidence yet" description="Add screenshots, request and response files, notes or tool runs. Link evidence to findings from a finding's history and links." />
        ) : (
          <ul className="flex flex-col gap-1">
            {records.visible.map((e) => (
              <li key={e.id} className="panel-inset flex items-center gap-3 px-3 py-2 text-[12.5px]">
                <span className="w-24 shrink-0 text-muted">{KIND_LABEL[e.kind]}</span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-foreground">{e.title}</div>
                  <div className="truncate text-muted">
                    {[e.fileName, formatSize(e.size), e.sha256 ? `SHA-256 ${e.sha256.slice(0, 16)}…` : null, formatRelative(e.createdAt)].filter(Boolean).join(" · ")}
                  </div>
                </div>
                <Dropdown>
                  <Button size="sm" variant="ghost" className="h-7 gap-1 px-1.5" aria-label={`Link ${e.title} to a finding`} isDisabled={findings.length === 0}>
                    <Link2 className="size-3.5" />
                    Link
                  </Button>
                  <Dropdown.Popover placement="bottom end">
                    <Dropdown.Menu aria-label="Findings" onAction={(k) => void act("link", () => api.findingLink(Number(k), "evidence", e.id), "Linked to the finding")}>
                      {findings.slice(0, 100).map((f) => (
                        <Dropdown.Item key={f.id} id={String(f.id)} textValue={f.title}>
                          {f.title}
                        </Dropdown.Item>
                      ))}
                    </Dropdown.Menu>
                  </Dropdown.Popover>
                </Dropdown>
                {e.kind === "text" && (
                  <Button size="sm" variant="ghost" className="h-7 px-1.5" onPress={() => setView(e)}>
                    View
                  </Button>
                )}
                {e.kind === "file" && (
                  <Button isIconOnly size="sm" variant="ghost" aria-label={`Save a copy of ${e.title}`} onPress={() => act(`x${e.id}`, () => api.evidenceExport(e.id), "Saved")}>
                    <Download className="size-3.5" />
                  </Button>
                )}
                <Button
                  isIconOnly
                  size="sm"
                  variant="ghost"
                  aria-label={`Delete ${e.title}`}
                  onPress={async () => {
                    if (!(await confirm.ask({ title: "Delete evidence?", body: `“${e.title}” and its links to findings are removed. A stored file is deleted when no other record uses it.`, confirmLabel: "Delete" }))) return;
                    await act(`d${e.id}`, () => api.evidenceDelete(e.id), "Evidence deleted");
                  }}
                >
                  <Trash2 className="size-3.5" />
                </Button>
              </li>
            ))}
            <ShowMoreRow hidden={records.hidden} shown={records.visible.length} step={records.step} noun="records" onMore={records.more} />
          </ul>
        )}
      </Panel>
      <Panel title="References in findings" description={`${refs.length} free-form references (paths, URLs, ticket ids) recorded with findings`}>
        {refs.length === 0 ? (
          <p className="text-[12.5px] text-muted">
            None.{" "}
            <Button size="sm" variant="ghost" className="h-6 px-1" onPress={onOpenFindings}>
              Go to findings
            </Button>
          </p>
        ) : (
          <ul className="flex flex-col gap-1">
            {shownRefs.visible.map((r) => (
              <li key={r.key} className="tile flex items-center gap-3 px-3 py-2">
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px]">
                    {r.label} <span className="text-muted">· {r.finding.title}</span>
                  </div>
                  <code data-selectable className="block truncate font-mono text-[12px] text-muted">
                    {r.reference}
                  </code>
                </div>
                <CopyButton text={r.reference} label="Copy reference" />
              </li>
            ))}
            <ShowMoreRow hidden={shownRefs.hidden} shown={shownRefs.visible.length} step={shownRefs.step} noun="references" onMore={shownRefs.more} />
          </ul>
        )}
      </Panel>
      <AppModal
        isOpen={!!note}
        onOpenChange={(o) => !o && setNote(null)}
        title="Add a note to the evidence"
        footer={
          <Button
            variant="primary"
            isDisabled={!note?.title.trim() || !note?.content.trim()}
            isPending={busy === "note"}
            onPress={async () => {
              if (!note) return;
              await act("note", () => api.evidenceAddText(project.id, note.title, note.content), "Note added");
              setNote(null);
            }}
          >
            Add note
          </Button>
        }
      >
        {note && (
          <>
            <TextInput label="Title" value={note.title} onChange={(v) => setNote({ ...note, title: v })} autoFocus />
            <TextAreaInput label="Content" value={note.content} onChange={(v) => setNote({ ...note, content: v })} rows={10} mono description="Up to 1 MB of text, for example a request and response pair." />
          </>
        )}
      </AppModal>
      <AppModal isOpen={!!view} onOpenChange={(o) => !o && setView(null)} title={view?.title ?? ""} description={view ? formatDateTime(view.createdAt) : undefined} size="lg">
        <pre data-selectable className="panel-inset max-h-[520px] overflow-auto px-3 py-2 font-mono text-[12px] whitespace-pre-wrap">
          {view?.content}
        </pre>
      </AppModal>
      {confirm.element}
    </div>
  );
}

/* ───────────────────────── timeline ───────────────────────── */

const TYPE_LABEL: Record<TimelineEventType, string> = {
  execution: "Tool runs",
  finding: "Findings",
  vulnerability: "Vulnerabilities",
  scope: "Scope",
  evidence: "Evidence",
  investigation: "OSINT",
  discovery: "Discovery",
  asset: "Assets",
  workflow: "Workflows",
  remediation: "Remediation",
  report: "Reports",
  note: "Notes",
};

export function TimelineTab({ project }: { project: Project }) {
  const { runtime } = useApp();
  const [type, setType] = useState<string>("all");
  const [pages, setPages] = useState<string[]>([]);
  const types = type === "all" ? [] : [type as TimelineEventType];
  const first = useQuery(["projects", "findings", "assets", "vulns", "workflows", "executions"], () => api.projectTimeline(project.id, { types, limit: 100 }), [project.id, type], runtime);
  const [more, setMore] = useState<Awaited<ReturnType<typeof api.projectTimeline>>>([]);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    setMore([]);
    setPages([]);
  }, [type, project.id, first.data]);
  const events = [...(first.data ?? []), ...more];
  const loadMore = async () => {
    const last = events[events.length - 1];
    if (!last || pages.includes(last.at)) return;
    setLoading(true);
    try {
      const next = await api.projectTimeline(project.id, { types, before: last.at, limit: 100 });
      setMore((m) => [...m, ...next]);
      setPages((p) => [...p, last.at]);
    } catch (e) {
      notify.error("Could not load more", e);
    } finally {
      setLoading(false);
    }
  };
  // group by day
  const days = useMemo(() => {
    const out: { day: string; items: typeof events }[] = [];
    for (const e of events) {
      const day = e.at.slice(0, 10);
      if (!out.length || out[out.length - 1].day !== day) out.push({ day, items: [] });
      out[out.length - 1].items.push(e);
    }
    return out;
  }, [events]);
  return (
    <Panel
      title="Timeline"
      description="Everything recorded in this project, newest first: runs, findings, vulnerabilities, scope, evidence, discovery, workflows and reports."
      actions={<SelectInput aria-label="Event type" value={type} onChange={setType} options={[{ id: "all", label: "All events" }, ...Object.entries(TYPE_LABEL).map(([id, label]) => ({ id, label }))]} className="w-44" />}
    >
      {first.error ? (
        <ErrorBlock message={first.error} onRetry={first.reload} />
      ) : !first.data ? (
        <LoadingRows rows={5} />
      ) : events.length === 0 ? (
        <EmptyBlock compact icon={History} title="Nothing recorded yet" />
      ) : (
        <div className="flex flex-col gap-4">
          {days.map((d) => (
            <section key={d.day}>
              <h3 className="mb-1.5 text-[12.5px] font-medium text-muted">{d.day}</h3>
              <ol className="flex flex-col gap-1">
                {d.items.map((e, i) => (
                  <li key={`${e.at}-${i}`} className="flex items-start gap-3 text-[12.5px]">
                    <span className="w-12 shrink-0 tabular text-muted">{e.at.slice(11, 16)}</span>
                    <span className="w-28 shrink-0 text-muted">{TYPE_LABEL[e.type] ?? e.type}</span>
                    <span className="min-w-0">
                      <span className="text-foreground">{e.title}</span>
                      {e.detail && <span className="text-muted"> · {e.detail}</span>}
                    </span>
                  </li>
                ))}
              </ol>
            </section>
          ))}
          {events.length % 100 === 0 && (
            <Button size="sm" variant="tertiary" className="self-start" onPress={loadMore} isPending={loading}>
              Load older events
            </Button>
          )}
        </div>
      )}
    </Panel>
  );
}

/* ───────────────────────── report builder ───────────────────────── */

const SECTIONS: { key: keyof ReportOptions; label: string }[] = [
  { key: "includeScope", label: "Scope and rules of engagement" },
  { key: "includeFindings", label: "Findings" },
  { key: "includeVulnerabilities", label: "Vulnerabilities" },
  { key: "includeAssets", label: "Assets" },
  { key: "includeEvidence", label: "Evidence register" },
  { key: "includeTimeline", label: "Timeline" },
];

const DEFAULT_OPTIONS: ReportOptions = {
  title: "",
  author: "",
  classification: "Confidential",
  summary: "",
  includeScope: true,
  includeFindings: true,
  minSeverity: "info",
  includeClosed: false,
  includeVulnerabilities: true,
  includeAssets: true,
  includeEvidence: true,
  includeTimeline: false,
};

/** Prints an HTML document through the web view's print dialog (choose "Save as PDF"). */
function printHtml(html: string) {
  const frame = document.createElement("iframe");
  frame.setAttribute("aria-hidden", "true");
  // same origin so the app can call print(), but no scripts may run inside (the report has none)
  frame.setAttribute("sandbox", "allow-same-origin allow-modals");
  frame.style.position = "fixed";
  frame.style.width = "0";
  frame.style.height = "0";
  frame.style.border = "0";
  frame.srcdoc = html;
  frame.onload = () => {
    frame.contentWindow?.focus();
    frame.contentWindow?.print();
    setTimeout(() => frame.remove(), 60_000);
  };
  document.body.appendChild(frame);
}

export function ReportTab({ project }: { project: Project }) {
  const { prefs } = useApp();
  const [o, setO] = useState<ReportOptions>(() => ({ ...DEFAULT_OPTIONS, author: typeof prefs["user.displayName"] === "string" ? (prefs["user.displayName"] as string) : "" }));
  const [html, setHtml] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // regenerate the preview shortly after the options change
  useEffect(() => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      api
        .reportHtml(project.id, o)
        .then((h) => {
          setHtml(h);
          setError(null);
        })
        .catch((e) => setError(errorMessage(e)));
    }, 350);
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [project.id, o]);

  const set = <K extends keyof ReportOptions>(k: K, v: ReportOptions[K]) => setO((x) => ({ ...x, [k]: v }));
  const run = async (key: string, fn: () => Promise<unknown>, done: (r: unknown) => string | null) => {
    setBusy(key);
    try {
      const r = await fn();
      const msg = done(r);
      if (msg) notify.success(msg);
      invalidate("findings", "projects");
    } catch (e) {
      notify.error("The report action failed", e);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
      <div className="flex flex-col gap-3 xl:col-span-4">
        <Panel title="Report" description="Choose what the report contains. The preview updates as you change it.">
          <div className="flex flex-col gap-3">
            <TextInput label="Title" value={o.title} onChange={(v) => set("title", v)} placeholder={/assessment/i.test(project.name) ? `${project.name} report` : `${project.name} assessment report`} />
            <div className="grid grid-cols-2 gap-3">
              <TextInput label="Author" value={o.author} onChange={(v) => set("author", v)} />
              <TextInput label="Classification" value={o.classification} onChange={(v) => set("classification", v)} />
            </div>
            <TextAreaInput label="Executive summary" value={o.summary} onChange={(v) => set("summary", v)} rows={5} description="Leave empty to use the project description." />
            <SelectInput
              label="Findings from severity"
              value={o.minSeverity}
              onChange={(v) => set("minSeverity", v as Severity)}
              options={[
                { id: "critical", label: "Critical only" },
                { id: "high", label: "High and above" },
                { id: "medium", label: "Medium and above" },
                { id: "low", label: "Low and above" },
                { id: "info", label: "All severities" },
              ]}
            />
            <SwitchInput label="Include resolved, accepted and false-positive findings" isSelected={o.includeClosed} onChange={(v) => set("includeClosed", v)} />
            {SECTIONS.map((s) => (
              <SwitchInput key={s.key} label={s.label} isSelected={o[s.key] as boolean} onChange={(v) => set(s.key, v as never)} />
            ))}
          </div>
        </Panel>
        <Panel title="Export">
          <div className="flex flex-col gap-2">
            <Button
              variant="primary"
              className="justify-start"
              isDisabled={!html}
              onPress={() => {
                if (!html) return;
                printHtml(html);
                void api.reportPrinted(project.id).then(() => invalidate("projects"));
              }}
            >
              <Printer className="size-4" />
              Print or save as PDF…
            </Button>
            <Button variant="secondary" className="justify-start" isPending={busy === "html"} onPress={() => run("html", () => api.reportExportHtml(project.id, o), (r) => (r ? `Saved ${r as string}` : null))}>
              <Save className="size-4" />
              Save as HTML…
            </Button>
            <Button variant="secondary" className="justify-start" isPending={busy === "evidence"} onPress={() => run("evidence", () => api.reportSaveEvidence(project.id, o), () => "Report saved to the evidence")}>
              <FilePlus2 className="size-4" />
              Keep a copy in the evidence
            </Button>
            <p className="text-[12px] text-muted">In the print dialog, choose a PDF printer (for example “Save as PDF” or “Microsoft Print to PDF”) to create a PDF.</p>
          </div>
        </Panel>
      </div>
      <div className="xl:col-span-8">
        <Panel title="Preview" contentClassName="p-0">
          {error ? (
            <ErrorBlock message={error} />
          ) : !html ? (
            <LoadingRows rows={6} />
          ) : (
            // the report has no scripts; the frame is sandboxed anyway
            <iframe title="Report preview" sandbox="" srcDoc={html} className={cn("h-[calc(100vh-220px)] min-h-[560px] w-full rounded-b-[10px] bg-white")} />
          )}
        </Panel>
      </div>
    </div>
  );
}
