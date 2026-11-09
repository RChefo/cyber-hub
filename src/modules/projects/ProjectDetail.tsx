import { Button, Dropdown, Tabs } from "@heroui/react";
import { ArrowLeft, ChevronDown, ClipboardCopy, FileDown, FileText, Pencil, Play, Save, SquareTerminal, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { SeverityBarChart } from "@/components/charts/SeverityBarChart";
import { EXEC_STATUS_META, PROJECT_STATUS_META, ToneChip } from "@/components/ui/Badges";
import { CodeBlock, CopyButton } from "@/components/ui/Code";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { TextAreaInput } from "@/components/ui/Fields";
import { Panel, Stat } from "@/components/ui/Panel";
import { FeaturedIcon } from "@/components/vendor/untitledui/FeaturedIcon";
import { copyCommand, copyText, notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { Finding, Project, ProjectStatus, RecordRef } from "@/lib/types";
import { formatDate, formatDateTime, formatRelative, pluralize, shellQuote } from "@/lib/utils";
import { AnalysisTab } from "./AnalysisTab";
import { ApiTab } from "./ApiTab";
import { ComponentsTab } from "./ComponentsTab";
import { AssistantTab } from "./AssistantTab";
import { AttackSurfaceTab } from "./AttackSurfaceTab";
import { AutomationTab } from "./AutomationTab";
import { ChecklistTab } from "./ChecklistTab";
import { EvidenceVault, ReportTab, ScopeExtras, TimelineTab, type TimelineRecord } from "./EngagementTabs";
import { FindingsTab } from "./FindingsTab";
import { InvestigationTab } from "./InvestigationTab";
import { parseKey, tabFor } from "./investigation";
import { ENGAGEMENT_TYPES, engagementOf, ProjectFormModal, STATUS_OPTIONS } from "./ProjectFormModal";
import { isOpenFinding } from "@/lib/findings";
import { countBySeverity } from "./report";
import { ScopeTab } from "./ScopeTab";
import { VulnerabilitiesTab } from "./VulnerabilitiesTab";

type TabId = "overview" | "scope" | "surface" | "apis" | "components" | "vulns" | "findings" | "checklist" | "analysis" | "investigation" | "assistant" | "automation" | "timeline" | "evidence" | "report" | "notes" | "commands";

const TAB_IDS: TabId[] = ["overview", "scope", "surface", "apis", "components", "vulns", "findings", "checklist", "analysis", "investigation", "assistant", "automation", "timeline", "evidence", "report", "notes", "commands"];

function NotesTab({ project }: { project: Project }) {
  const [notes, setNotes] = useState(project.notes);
  const [saving, setSaving] = useState(false);
  useEffect(() => setNotes(project.notes), [project.notes]);
  const dirty = notes !== project.notes;

  const save = async () => {
    setSaving(true);
    try {
      await api.projectUpsert({
        id: project.id,
        name: project.name,
        description: project.description,
        status: project.status,
        scopeNotes: project.scopeNotes,
        notes,
        startDate: project.startDate,
        endDate: project.endDate,
        ...engagementOf(project),
      });
      invalidate("projects");
      notify.success("Notes saved");
    } catch (e) {
      notify.error("Could not save notes", e);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Panel
      title="Notes"
      description={dirty ? "Unsaved changes" : `Saved · project updated ${formatRelative(project.updatedAt)}`}
      actions={
        <>
          {dirty && (
            <Button size="sm" variant="ghost" onPress={() => setNotes(project.notes)}>
              Discard
            </Button>
          )}
          <Button size="sm" variant="primary" onPress={save} isDisabled={!dirty} isPending={saving}>
            <Save className="size-3.5" />
            Save notes
          </Button>
        </>
      }
    >
      <TextAreaInput
        aria-label="Project notes"
        value={notes}
        onChange={setNotes}
        rows={22}
        mono
        placeholder="Working notes, observations, hypotheses, credentials references (never store secrets in plain text)…"
      />
    </Panel>
  );
}

function CommandsTab({ projectId }: { projectId: number }) {
  const { runtime, navigate, toolById } = useApp();
  const runs = useQuery(["executions"], () => api.projectToolHistory(projectId), [projectId], runtime);
  const history = useQuery(["history"], () => api.commandHistoryList(500), [], runtime);
  const commands = (history.data ?? []).filter((h) => h.projectId === projectId);

  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
      <Panel title="Tool runs" description="Executions started for this project" actions={<Button size="sm" variant="ghost" onPress={() => navigate("runs")}>All runs</Button>}>
        {runs.error && !runs.data ? (
          <ErrorBlock message={runs.error} onRetry={runs.reload} />
        ) : !runs.data ? (
          <LoadingRows rows={3} />
        ) : runs.data.length === 0 ? (
          <EmptyBlock compact icon={Play} title="No tool runs yet" description="Runs started from the Tools Library with this project selected appear here." />
        ) : (
          <ul className="flex flex-col gap-1">
            {runs.data.map((r) => {
              const meta = EXEC_STATUS_META[r.status];
              const line = [r.toolId, ...r.args.map(shellQuote)].join(" ");
              return (
                <li key={r.id} className="tile flex items-center gap-3 px-3 py-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 text-[13px]">
                      <span className="font-medium">{toolById(r.toolId)?.name ?? r.toolId}</span>
                      <span className="text-[12px] text-muted">
                        {r.kind === "install" ? "install" : "run"} · {formatDateTime(r.startedAt)}
                        {r.exitCode !== null ? ` · exit ${r.exitCode}` : ""}
                      </span>
                    </div>
                    <code data-selectable className="block truncate font-mono text-[12px] text-muted">
                      {line}
                    </code>
                  </div>
                  <ToneChip tone={meta.tone}>{meta.label}</ToneChip>
                  <CopyButton text={line} label="Copy command" onCopy={(t) => copyCommand(t, "execution", r.toolId, projectId)} />
                </li>
              );
            })}
          </ul>
        )}
      </Panel>
      <Panel title="Command history" description="Commands copied or built while this project was selected">
        {history.error && !history.data ? (
          <ErrorBlock message={history.error} onRetry={history.reload} />
        ) : !history.data ? (
          <LoadingRows rows={3} />
        ) : commands.length === 0 ? (
          <EmptyBlock compact icon={SquareTerminal} title="No project commands" description="Commands are linked to a project when it is selected in a command builder or run dialog." />
        ) : (
          <ul className="flex flex-col gap-1">
            {commands.map((h) => (
              <li key={h.id} className="tile flex items-center gap-2 py-1 pr-1 pl-3">
                <code data-selectable className="min-w-0 flex-1 truncate font-mono text-[12px]">
                  {h.command}
                </code>
                <span className="shrink-0 text-[11.5px] text-muted">{formatRelative(h.createdAt)}</span>
                <CopyButton text={h.command} label="Copy command" onCopy={(t) => copyCommand(t, "manual", h.toolId, projectId)} />
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

function OverviewTab({ project, findings, onTab }: { project: Project; findings: Finding[]; onTab: (t: TabId) => void }) {
  const { runtime, toolById } = useApp();
  const runs = useQuery(["executions"], () => api.projectToolHistory(project.id), [project.id], runtime);
  const counts = useMemo(() => countBySeverity(findings, true), [findings]);
  const open = findings.filter((f) => isOpenFinding(f.status)).length;
  const inScope = project.targets.filter((t) => t.inScope).length;

  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
      <div className="flex flex-col gap-3 xl:col-span-8">
        <div className="panel grid grid-cols-2 gap-4 p-4 md:grid-cols-4">
          <Stat label="In-scope entries" value={inScope} hint={`${project.targets.length - inScope} excluded`} />
          <Stat label="Findings" value={findings.length} hint={`${open} open`} tone={open ? "warning" : "default"} />
          <Stat label="Critical & high" value={counts.critical + counts.high} hint="Unresolved" tone={counts.critical + counts.high ? "danger" : "default"} />
          <Stat label="Tool runs" value={runs.data?.length ?? "—"} hint="For this project" />
        </div>
        <Panel title="About this assessment">
          <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-[13px] md:grid-cols-2">
            <div>
              <dt className="text-muted">Description</dt>
              <dd className="mt-0.5 whitespace-pre-wrap">{project.description || <span className="text-muted">No description.</span>}</dd>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <dt className="text-muted">Start</dt>
                <dd className="mt-0.5">{project.startDate ? formatDate(project.startDate) : "Not set"}</dd>
              </div>
              <div>
                <dt className="text-muted">End</dt>
                <dd className="mt-0.5">{project.endDate ? formatDate(project.endDate) : "Not set"}</dd>
              </div>
              <div>
                <dt className="text-muted">Created</dt>
                <dd className="mt-0.5">{formatDate(project.createdAt)}</dd>
              </div>
              <div>
                <dt className="text-muted">Updated</dt>
                <dd className="mt-0.5">{formatRelative(project.updatedAt)}</dd>
              </div>
            </div>
            <div>
              <dt className="text-muted">Client</dt>
              <dd className="mt-0.5">{project.client || <span className="text-muted">Not set</span>}</dd>
            </div>
            <div>
              <dt className="text-muted">Engagement</dt>
              <dd className="mt-0.5">{ENGAGEMENT_TYPES.find((t) => t.id === project.engagementType)?.label ?? project.engagementType}</dd>
            </div>
            <div className="md:col-span-2">
              <dt className="text-muted">Authorization</dt>
              <dd className="mt-0.5">{project.authorizationRef || <span className="text-warning-soft-foreground">No written authorization recorded. Add its reference before testing.</span>}</dd>
            </div>
            <div className="md:col-span-2">
              <dt className="text-muted">Rules of engagement</dt>
              <dd className="mt-0.5 whitespace-pre-wrap">{project.scopeNotes || <span className="text-muted">Not documented. Record testing windows and constraints before testing.</span>}</dd>
            </div>
          </dl>
        </Panel>
        <Panel title="Recent tool runs" actions={<Button size="sm" variant="ghost" onPress={() => onTab("commands")}>View all</Button>}>
          {!runs.data ? (
            runs.error ? <ErrorBlock message={runs.error} onRetry={runs.reload} /> : <LoadingRows rows={2} />
          ) : runs.data.length === 0 ? (
            <EmptyBlock compact icon={Play} title="No tool runs yet" />
          ) : (
            <ul className="flex flex-col gap-1">
              {runs.data.slice(0, 5).map((r) => (
                <li key={r.id} className="tile flex items-center gap-3 px-3 py-2 text-[13px]">
                  <span className="font-medium">{toolById(r.toolId)?.name ?? r.toolId}</span>
                  <code className="min-w-0 flex-1 truncate font-mono text-[12px] text-muted">{r.args.map(shellQuote).join(" ")}</code>
                  <span className="text-[12px] text-muted">{formatRelative(r.startedAt)}</span>
                  <ToneChip tone={EXEC_STATUS_META[r.status].tone}>{EXEC_STATUS_META[r.status].label}</ToneChip>
                </li>
              ))}
            </ul>
          )}
        </Panel>
      </div>
      <div className="flex flex-col gap-3 xl:col-span-4">
        <Panel title="Unresolved findings by severity" actions={<Button size="sm" variant="ghost" onPress={() => onTab("findings")}>Findings</Button>}>
          {findings.length === 0 ? (
            <EmptyBlock compact icon={FileText} title="No findings recorded" />
          ) : (
            <SeverityBarChart counts={counts} height={170} />
          )}
        </Panel>
        {project.status !== "active" && (
          <div className="rounded-xl bg-warning-soft px-4 py-3 text-[13px] text-warning-soft-foreground">
            This project is <strong>{PROJECT_STATUS_META[project.status].label.toLowerCase()}</strong>. Tools that send traffic to targets only run for active projects.
          </div>
        )}
      </div>
    </div>
  );
}

export function ProjectDetail({ id }: { id: number }) {
  const { runtime, navigate, route } = useApp();
  const confirm = useConfirm();
  // a deep link (global search, another page) may name the tab
  const [tab, setTab] = useState<TabId>(() => (TAB_IDS as string[]).includes(route.params?.tab ?? "") ? (route.params!.tab as TabId) : "overview");
  // the record whose related records are shown in the investigation view, the finding to open,
  // and the record the timeline is limited to
  const [panelRecord, setPanelRecord] = useState<RecordRef | null>(() => (route.params?.record ? parseKey(route.params.record) : null));
  const [focusFinding, setFocusFinding] = useState<number | null>(() => (route.params?.finding && /^\d+$/.test(route.params.finding) ? Number(route.params.finding) : null));
  // a deep link to this same project (the global search) applies without remounting the page
  const deepLink = [route.params?.tab, route.params?.finding, route.params?.record, route.params?.at].join("|");
  useEffect(() => {
    const t = route.params?.tab;
    if (t && (TAB_IDS as string[]).includes(t)) setTab(t as TabId);
    const fid = route.params?.finding;
    if (fid && /^\d+$/.test(fid)) setFocusFinding(Number(fid));
    const rec = route.params?.record ? parseKey(route.params.record) : null;
    if (rec) {
      setTab("investigation");
      setPanelRecord(rec);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deepLink]);
  const [timelineRecord, setTimelineRecord] = useState<TimelineRecord | null>(null);
  const openRecordTab = (r: RecordRef) => {
    const t = tabFor(r);
    if (t === "attack") setTab("investigation");
    else if (t !== "osint") setTab(t);
    if (r.kind === "finding") setFocusFinding(r.id);
  };
  const [editOpen, setEditOpen] = useState(false);
  const [report, setReport] = useState<string | null>(null);
  const project = useQuery(["projects"], () => api.projectGet(id), [id], runtime);
  const findings = useQuery(["findings"], () => api.findingsList(id), [id], runtime);

  if (project.error && !project.data) {
    return (
      <div className="flex flex-col gap-3">
        <Button variant="ghost" size="sm" className="self-start" onPress={() => navigate("projects")}>
          <ArrowLeft className="size-3.5" />
          All projects
        </Button>
        <ErrorBlock message={project.error} onRetry={project.reload} />
      </div>
    );
  }
  if (!project.data) return <LoadingRows rows={6} />;
  const p = project.data;
  const f = findings.data ?? [];

  const setStatus = async (status: ProjectStatus) => {
    try {
      await api.projectUpsert({ id: p.id, name: p.name, description: p.description, status, scopeNotes: p.scopeNotes, notes: p.notes, startDate: p.startDate, endDate: p.endDate, ...engagementOf(p) });
      invalidate("projects", "activity");
      notify.success(`Project marked ${PROJECT_STATUS_META[status].label.toLowerCase()}`);
    } catch (e) {
      notify.error("Could not change status", e);
    }
  };

  const remove = async () => {
    const ok = await confirm.ask({
      title: `Delete “${p.name}”?`,
      body: `This permanently deletes the project, its ${pluralize(p.targets.length, "scope entry", "scope entries")}, ${pluralize(f.length, "finding")}, evidence and other records. Tool runs and the activity log are kept but unlinked. A project with a run, workflow or discovery still in progress cannot be deleted.`,
      confirmLabel: "Delete project",
    });
    if (!ok) return;
    try {
      await api.projectDelete(p.id);
      invalidate("projects", "findings", "activity", "tasks");
      notify.success("Project deleted");
      navigate("projects");
    } catch (e) {
      notify.error("Could not delete project", e);
    }
  };

  const exportReport = async () => {
    try {
      const md = await api.projectReport(p.id);
      setReport(md);
      await copyText(md, "Markdown report copied to clipboard");
    } catch (e) {
      notify.error("Could not build the report", e);
    }
  };

  // the backend opens the system save dialog and writes the file; the page never sees the path
  const saveReport = async () => {
    try {
      const name = await api.projectReportExport(p.id);
      if (name) notify.success("Report saved", name);
    } catch (e) {
      notify.error("Could not save the report", e);
    }
  };

  const tabs: { id: TabId; label: string }[] = [
    { id: "overview", label: "Overview" },
    { id: "scope", label: `Scope (${p.targets.length})` },
    { id: "surface", label: "Attack surface" },
    { id: "apis", label: "APIs" },
    { id: "components", label: "Components" },
    { id: "vulns", label: "Vulnerabilities" },
    { id: "findings", label: `Findings (${f.length})` },
    { id: "checklist", label: "Checklist" },
    { id: "analysis", label: "Analysis" },
    { id: "investigation", label: "Investigation" },
    { id: "assistant", label: "Assistant" },
    { id: "automation", label: "Automation" },
    { id: "timeline", label: "Timeline" },
    { id: "evidence", label: "Evidence" },
    { id: "report", label: "Report" },
    { id: "notes", label: "Notes" },
    { id: "commands", label: "Commands & runs" },
  ];

  return (
    <div>
      <Button variant="ghost" size="sm" className="mb-2 -ml-2" onPress={() => navigate("projects")}>
        <ArrowLeft className="size-3.5" />
        All projects
      </Button>
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4">
        <div className="flex min-w-0 items-start gap-3">
          <FeaturedIcon icon={FileText} size="lg" color={p.status === "active" ? "brand" : "gray"} />
          <div className="min-w-0">
            <div className="flex items-center gap-2.5">
              <h1 className="truncate text-[22px] font-semibold tracking-tight">{p.name}</h1>
              <ToneChip tone={PROJECT_STATUS_META[p.status].tone}>{PROJECT_STATUS_META[p.status].label}</ToneChip>
            </div>
            <p className="mt-0.5 max-w-[72ch] truncate text-[13.5px] text-muted">
              {[p.startDate && p.endDate ? `${p.startDate} → ${p.endDate}` : null, pluralize(p.targets.length, "scope entry", "scope entries"), pluralize(f.length, "finding")].filter(Boolean).join(" · ")}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Dropdown>
            <Button size="sm" variant="tertiary" className="gap-1.5">
              Status: {PROJECT_STATUS_META[p.status].label}
              <ChevronDown className="size-3.5" />
            </Button>
            <Dropdown.Popover placement="bottom end">
              <Dropdown.Menu aria-label="Project status" onAction={(k) => k !== p.status && setStatus(k as ProjectStatus)}>
                {STATUS_OPTIONS.map((o) => (
                  <Dropdown.Item key={o.id} id={o.id} textValue={o.label}>
                    <div className="flex flex-col">
                      <span>{o.label}</span>
                      <span className="text-[12px] text-muted">{o.description}</span>
                    </div>
                  </Dropdown.Item>
                ))}
              </Dropdown.Menu>
            </Dropdown.Popover>
          </Dropdown>
          <Button size="sm" variant="tertiary" onPress={exportReport}>
            <FileDown className="size-3.5" />
            Export report (Markdown)
          </Button>
          <Button size="sm" variant="tertiary" onPress={() => setEditOpen(true)}>
            <Pencil className="size-3.5" />
            Edit
          </Button>
          <Button size="sm" variant="ghost" onPress={remove} aria-label="Delete project">
            <Trash2 className="size-3.5" />
            Delete
          </Button>
        </div>
      </div>

      <Tabs selectedKey={tab} onSelectionChange={(k) => setTab(k as TabId)}>
        <Tabs.ListContainer className="mb-3">
          <Tabs.List aria-label="Project sections">
            {tabs.map((t) => (
              <Tabs.Tab key={t.id} id={t.id} className="px-3 text-[13px]">
                {t.label}
                <Tabs.Indicator />
              </Tabs.Tab>
            ))}
          </Tabs.List>
        </Tabs.ListContainer>
        <Tabs.Panel id="overview">
          <OverviewTab project={p} findings={f} onTab={setTab} />
        </Tabs.Panel>
        <Tabs.Panel id="scope">
          <ScopeTab project={p} onChanged={project.reload} />
          <ScopeExtras project={p} />
        </Tabs.Panel>
        <Tabs.Panel id="surface">
          <AttackSurfaceTab project={p} />
        </Tabs.Panel>
        <Tabs.Panel id="apis">
          <ApiTab project={p} onOpenFindings={() => setTab("findings")} />
        </Tabs.Panel>
        <Tabs.Panel id="components">
          <ComponentsTab project={p} onOpenFindings={() => setTab("findings")} />
        </Tabs.Panel>
        <Tabs.Panel id="vulns">
          <VulnerabilitiesTab project={p} />
        </Tabs.Panel>
        <Tabs.Panel id="findings">
          {findings.error && !findings.data ? <ErrorBlock message={findings.error} onRetry={findings.reload} /> : <FindingsTab projectId={p.id} findings={f} focusId={focusFinding} onFocused={() => setFocusFinding(null)} />}
        </Tabs.Panel>
        <Tabs.Panel id="analysis">
          <AnalysisTab project={p} />
        </Tabs.Panel>
        <Tabs.Panel id="investigation">
          <InvestigationTab
            project={p}
            record={panelRecord}
            onRecord={setPanelRecord}
            onOpenRecord={openRecordTab}
            onTimeline={(r, label) => {
              setTimelineRecord({ kind: r.kind, id: r.id, label });
              setTab("timeline");
            }}
          />
        </Tabs.Panel>
        <Tabs.Panel id="assistant">
          <AssistantTab project={p} />
        </Tabs.Panel>
        <Tabs.Panel id="automation">
          <AutomationTab project={p} />
        </Tabs.Panel>
        <Tabs.Panel id="notes">
          <NotesTab project={p} />
        </Tabs.Panel>
        <Tabs.Panel id="commands">
          <CommandsTab projectId={p.id} />
        </Tabs.Panel>
        <Tabs.Panel id="evidence">
          <EvidenceVault project={p} findings={f} onOpenFindings={() => setTab("findings")} />
        </Tabs.Panel>
        <Tabs.Panel id="checklist">
          <ChecklistTab projectId={p.id} />
        </Tabs.Panel>
        <Tabs.Panel id="timeline">
          <TimelineTab
            project={p}
            record={timelineRecord}
            onClearRecord={() => setTimelineRecord(null)}
            onOpenRecord={(kind, refId) => {
              setPanelRecord({ kind: kind as RecordRef["kind"], id: refId, sub: "" });
              setTab("investigation");
            }}
          />
        </Tabs.Panel>
        <Tabs.Panel id="report">
          <ReportTab project={p} />
        </Tabs.Panel>
      </Tabs>

      <ProjectFormModal isOpen={editOpen} onOpenChange={setEditOpen} project={p} />
      <AppModal
        isOpen={report !== null}
        onOpenChange={(o) => !o && setReport(null)}
        title="Markdown report"
        description="Copied to your clipboard. Paste it into a .md file or your reporting tool."
        size="lg"
        footer={
          <>
            <Button variant="tertiary" onPress={() => report && copyText(report, "Markdown report copied to clipboard")}>
              <ClipboardCopy className="size-3.5" />
              Copy again
            </Button>
            <Button variant="tertiary" onPress={saveReport}>
              <FileDown className="size-3.5" />
              Save as file…
            </Button>
            <Button variant="primary" onPress={() => setReport(null)}>
              Done
            </Button>
          </>
        }
      >
        <CodeBlock code={report ?? ""} maxHeight={460} />
      </AppModal>
      {confirm.element}
    </div>
  );
}
