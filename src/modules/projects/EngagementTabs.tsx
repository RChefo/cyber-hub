import { Button, Dropdown } from "@heroui/react";
import { ChevronDown, Download, FileDown, FilePlus2, FileText, History, Link2, NotebookPen, Printer, Save, ShieldCheck, Trash2, Upload } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { EvidenceRecord, Finding, Project, ReportOptions, Severity, TimelineEvent, TimelineEventType, TimelineQuery } from "@/lib/types";
import { useShowMore } from "@/lib/showMore";
import { cn, formatDateTime, formatNumber, formatRelative, pluralize } from "@/lib/utils";

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
                  {e.repeats > 0 && <span className="text-muted"> · {e.repeats + 1} attempts, the last {formatRelative(e.at)}</span>}
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

/** Where a record came from: the module and record, the tool, when the source collected it. */
function provenanceLine(e: EvidenceRecord): string {
  return [
    e.sourceModule && `From ${e.sourceModule.replace(/_/g, " ")}${e.sourceRef ? ` (${e.sourceRef})` : ""}`,
    e.tool && `tool ${e.tool}${e.toolVersion ? ` ${e.toolVersion}` : ""}`,
    e.collectedAt && `collected ${formatDateTime(e.collectedAt)}`,
    e.derivedFrom ? `derived from evidence #${e.derivedFrom}` : null,
  ]
    .filter(Boolean)
    .join(" · ");
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
  // the text of the record being viewed is loaded when it opens (lists leave it out)
  const viewText = useQuery(["findings"], () => (view ? api.evidenceText(view.id) : Promise.resolve("")), [view?.id], runtime);
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
            <Button
              size="sm"
              variant="tertiary"
              isDisabled={!list.data?.length}
              isPending={busy === "verify"}
              onPress={() =>
                void act("verify", async () => {
                  const r = await api.evidenceVerify(project.id);
                  if (r.problems.length === 0)
                    notify.success("Evidence verified", `${pluralize(r.checked, "stored record")} ${r.checked === 1 ? "matches its" : "match their"} SHA-256.`);
                  else
                    notify.warning(
                      `${pluralize(r.problems.length, "record")} ${r.problems.length === 1 ? "does" : "do"} not match`,
                      r.problems
                        .slice(0, 3)
                        .map((p) => `#${p.id} ${p.title}: ${p.problem}`)
                        .join("; "),
                    );
                  return null;
                })
              }
            >
              <ShieldCheck className="size-3.5" />
              Verify
            </Button>
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
                  {provenanceLine(e) && <div className="truncate text-[11.5px] text-muted">{provenanceLine(e)}</div>}
                </div>
                {e.verification !== "unverified" && (
                  <span title={e.verifiedAt ? `Checked ${formatDateTime(e.verifiedAt)}` : undefined}>
                    <ToneChip tone={e.verification === "intact" ? "success" : "danger"} dot={false} className="text-[11px]">
                      {e.verification}
                    </ToneChip>
                  </span>
                )}
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
        {viewText.error ? (
          <ErrorBlock message={viewText.error} />
        ) : viewText.loading ? (
          <LoadingRows rows={4} />
        ) : (
          <pre data-selectable className="panel-inset max-h-[520px] overflow-auto px-3 py-2 font-mono text-[12px] whitespace-pre-wrap">
            {viewText.data}
          </pre>
        )}
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
  utility: "Utilities",
  checklist: "Checklist",
  correlation: "Correlation",
  detection: "Detection",
};

/** A record the timeline is limited to (from the investigation view or a deep link). */
export interface TimelineRecord {
  kind: string;
  id: number;
  label: string;
}

export function TimelineTab({ project, record, onClearRecord, onOpenRecord }: { project: Project; record?: TimelineRecord | null; onClearRecord?: () => void; onOpenRecord?: (kind: string, id: number) => void }) {
  const { runtime } = useApp();
  const [type, setType] = useState<string>("all");
  const [text, setText] = useState("");
  const [search, setSearch] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [pages, setPages] = useState<string[]>([]);
  useEffect(() => {
    const t = setTimeout(() => setSearch(text.trim()), 300);
    return () => clearTimeout(t);
  }, [text]);
  const query: TimelineQuery = {
    ...(type === "all" ? {} : { types: [type as TimelineEventType] }),
    ...(search ? { search } : {}),
    ...(from ? { from } : {}),
    // the "to" date is included: events before the next day
    ...(to ? { to: nextDay(to) } : {}),
    ...(record ? { refKind: record.kind, refId: record.id } : {}),
  };
  const first = useQuery(["projects", "findings", "assets", "vulns", "workflows", "executions", "relations"], () => api.timelineQuery(project.id, { ...query, limit: 100 }), [project.id, type, search, from, to, record?.kind, record?.id], runtime);
  const [more, setMore] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    setMore([]);
    setPages([]);
  }, [type, search, from, to, record?.kind, record?.id, project.id, first.data]);
  const events = [...(first.data ?? []), ...more];
  const loadMore = async () => {
    const last = events[events.length - 1];
    if (!last || pages.includes(last.cursor)) return;
    setLoading(true);
    try {
      const next = await api.timelineQuery(project.id, { ...query, before: last.cursor, limit: 100 });
      setMore((m) => [...m, ...next]);
      setPages((p) => [...p, last.cursor]);
    } catch (e) {
      notify.error("Could not load more", e);
    } finally {
      setLoading(false);
    }
  };
  const exportAs = async (format: "csv" | "json") => {
    try {
      const file = await api.timelineExport(project.id, query, format);
      if (file) notify.success("Timeline exported", file);
    } catch (e) {
      notify.error("Could not export the timeline", e);
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
  const filtered = type !== "all" || !!search || !!from || !!to || !!record;
  return (
    <Panel
      title="Timeline"
      description="Everything recorded in this project, newest first: runs, findings, vulnerabilities, scope, evidence, OSINT, discovery, imports, utilities, correlation decisions, workflows and reports. Times are when Cyber Hub recorded the event; evidence collected earlier also shows when it was collected."
      actions={
        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="ghost" onPress={() => void exportAs("csv")}>
            <FileDown className="size-3.5" />
            CSV
          </Button>
          <Button size="sm" variant="ghost" onPress={() => void exportAs("json")}>
            <FileDown className="size-3.5" />
            JSON
          </Button>
        </div>
      }
      toolbar={
        <div className="flex flex-wrap items-end gap-2 px-4 pb-3">
          <SelectInput aria-label="Event type" value={type} onChange={setType} options={[{ id: "all", label: "All events" }, ...Object.entries(TYPE_LABEL).map(([id, label]) => ({ id, label }))]} className="w-44" />
          <SearchInput value={text} onChange={setText} placeholder="Search titles and details" className="w-64" />
          <TextInput aria-label="From date" value={from} onChange={setFrom} placeholder="From (YYYY-MM-DD)" className="w-40" />
          <TextInput aria-label="To date" value={to} onChange={setTo} placeholder="To (YYYY-MM-DD)" className="w-40" />
          {record && (
            <ToneChip tone="accent" dot={false}>
              Only: {record.label}
            </ToneChip>
          )}
          {filtered && (
            <Button
              size="sm"
              variant="ghost"
              onPress={() => {
                setType("all");
                setText("");
                setFrom("");
                setTo("");
                onClearRecord?.();
              }}
            >
              Clear filters
            </Button>
          )}
        </div>
      }
    >
      {first.error ? (
        <ErrorBlock message={first.error} onRetry={first.reload} />
      ) : !first.data ? (
        <LoadingRows rows={5} />
      ) : events.length === 0 ? (
        <EmptyBlock compact icon={History} title={filtered ? "No event matches" : "Nothing recorded yet"} />
      ) : (
        <div className="flex flex-col gap-4">
          {days.map((d) => (
            <section key={d.day}>
              <h3 className="mb-1.5 text-[12.5px] font-medium text-muted">{d.day}</h3>
              <ol className="flex flex-col gap-1">
                {d.items.map((e) => (
                  <li key={e.cursor} className="flex items-start gap-3 text-[12.5px]">
                    <span className="w-12 shrink-0 tabular text-muted">{e.at.slice(11, 16)}</span>
                    <span className="w-28 shrink-0 text-muted">{TYPE_LABEL[e.type] ?? e.type}</span>
                    <span className="min-w-0">
                      {onOpenRecord && e.refKind && e.refId != null && OPENABLE.includes(e.refKind) ? (
                        <button type="button" className="text-left text-foreground hover:underline" onClick={() => onOpenRecord(e.refKind!, e.refId!)}>
                          {e.title}
                        </button>
                      ) : (
                        <span className="text-foreground">{e.title}</span>
                      )}
                      {e.detail && <span className="text-muted"> · {e.detail}</span>}
                      {e.observedAt && <span className="text-muted"> · collected {e.observedAt.slice(0, 16).replace("T", " ")}</span>}
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

/** Records a timeline event can open in the investigation view. */
const OPENABLE = ["finding", "asset", "evidence", "vulnerability", "execution"];

/** The day after a YYYY-MM-DD date (an inclusive "to" date), or the text unchanged. */
export function nextDay(date: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date.trim());
  if (!m) return date.trim();
  const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]) + 1));
  return d.toISOString().slice(0, 10);
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
