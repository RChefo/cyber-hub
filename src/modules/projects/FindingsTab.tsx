import { Button, Checkbox, Dropdown, Tooltip } from "@heroui/react";
import { ChevronDown, FileDown, FileUp, History, Link2, Pencil, Plus, ShieldAlert, Trash2, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { FINDING_STATUS_META, SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import { useApp } from "@/app/store";
import { canChangeStatus } from "@/lib/findings";
import type { Confidence, Evidence, Finding, FindingLinkKind, FindingStatus, Severity } from "@/lib/types";
import { useShowMore } from "@/lib/showMore";
import { formatDateTime, formatNumber, formatRelative } from "@/lib/utils";
import { filterFindings, parseTags, sortFindings, tagsOf } from "./report";
import { BulkEditModal } from "./BulkEditModal";
import { CvssField } from "./CvssField";
import { ScanImportModal } from "./ScanImportModal";
import { applyTemplate, templateFromFinding } from "@/modules/library/library";
import { TemplateFormModal } from "@/modules/library/TemplateFormModal";
import type { FindingTemplateInput } from "@/lib/types";

export const SEVERITY_OPTIONS: { id: Severity; label: string }[] = [
  { id: "critical", label: "Critical" },
  { id: "high", label: "High" },
  { id: "medium", label: "Medium" },
  { id: "low", label: "Low" },
  { id: "info", label: "Informational" },
];

export const FINDING_STATUS_OPTIONS: { id: FindingStatus; label: string }[] = (Object.keys(FINDING_STATUS_META) as FindingStatus[]).map((id) => ({
  id,
  label: FINDING_STATUS_META[id].label,
}));

const CONFIDENCE_OPTIONS: { id: Confidence; label: string }[] = [
  { id: "high", label: "High confidence" },
  { id: "medium", label: "Medium confidence" },
  { id: "low", label: "Low confidence" },
];

/** Every editable field, so saving never drops data the form does not show. */
export type FindingDraft = Omit<Finding, "id" | "projectId" | "source" | "createdAt" | "updatedAt"> & { id?: number };

const EMPTY: FindingDraft = {
  title: "",
  severity: "medium",
  status: "new",
  category: "",
  confidence: "medium",
  description: "",
  affectedTarget: "",
  cve: "",
  evidence: [],
  reproduction: "",
  technicalDetails: "",
  remediation: "",
  tags: [],
  assignee: "",
  dueDate: null,
  cvssVector: "",
  cvssScore: null,
};

export function draftOf(f: Finding): FindingDraft {
  const { projectId: _p, source: _s, createdAt: _c, updatedAt: _u, ...draft } = f;
  return draft;
}

export function FindingFormModal({
  isOpen,
  onOpenChange,
  projectId,
  initial,
}: {
  isOpen: boolean;
  onOpenChange: (o: boolean) => void;
  projectId: number;
  initial?: FindingDraft | null;
}) {
  const [d, setD] = useState<FindingDraft>(EMPTY);
  const [tagText, setTagText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [templateId, setTemplateId] = useState("");
  const [asTemplate, setAsTemplate] = useState<FindingTemplateInput | null>(null);
  const templates = useQuery(["templates"], api.findingTemplatesList, [], isOpen);

  useEffect(() => {
    if (isOpen) {
      setD(initial ? { ...initial, evidence: initial.evidence.map((e) => ({ ...e })), tags: [...initial.tags] } : EMPTY);
      setTagText((initial?.tags ?? []).join(", "));
      setError(null);
      setTemplateId("");
    }
  }, [isOpen, initial]);

  const useTemplate = (id: string) => {
    setTemplateId(id);
    const t = templates.data?.find((x) => String(x.id) === id);
    if (!t) return;
    const next = applyTemplate({ ...d, tags: parseTags(tagText) }, t);
    setD(next);
    setTagText(next.tags.join(", "));
  };

  const set = <K extends keyof FindingDraft>(k: K, v: FindingDraft[K]) => setD((s) => ({ ...s, [k]: v }));
  const setEvidence = (i: number, patch: Partial<Evidence>) => set("evidence", d.evidence.map((e, j) => (j === i ? { ...e, ...patch } : e)));
  const incompleteEvidence = d.evidence.some((e) => !e.label.trim() || !e.reference.trim());

  const save = async () => {
    if (!d.title.trim() || incompleteEvidence) return;
    setSaving(true);
    setError(null);
    try {
      await api.findingUpsert({ ...d, tags: parseTags(tagText), projectId });
      if (templateId) {
        await api.findingTemplateUsed(Number(templateId)).catch(() => undefined);
        invalidate("templates");
      }
      invalidate("findings", "projects", "activity");
      notify.success(d.id ? "Finding updated" : "Finding recorded");
      onOpenChange(false);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <AppModal
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      title={d.id ? "Edit finding" : "Record finding"}
      description="Record only what you have verified on in-scope assets."
      size="lg"
      footer={
        <>
          <Button variant="tertiary" className="mr-auto" onPress={() => setAsTemplate(templateFromFinding({ ...d, tags: parseTags(tagText) }))} isDisabled={!d.title.trim()}>
            Save as template
          </Button>
          <Button variant="tertiary" onPress={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={save} isPending={saving} isDisabled={!d.title.trim() || incompleteEvidence}>
            {d.id ? "Save changes" : "Record finding"}
          </Button>
        </>
      }
    >
      <TemplateFormModal initial={asTemplate} onClose={() => setAsTemplate(null)} />
      {!d.id && (templates.data?.length ?? 0) > 0 && (
        <SelectInput
          label="Start from a template"
          value={templateId}
          onChange={useTemplate}
          options={[{ id: "", label: "No template" }, ...(templates.data ?? []).map((t) => ({ id: String(t.id), label: t.title, description: [t.severity, t.category].filter(Boolean).join(" · ") }))]}
        />
      )}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <TextInput label="Title" value={d.title} onChange={(v) => set("title", v)} placeholder="Reflected XSS in search parameter" isRequired autoFocus className="md:col-span-2" />
        <SelectInput label="Severity" value={d.severity} onChange={(v) => set("severity", v as Severity)} options={SEVERITY_OPTIONS} />
        <SelectInput label="Status" value={d.status} onChange={(v) => set("status", v as FindingStatus)} options={FINDING_STATUS_OPTIONS} />
        <TextInput label="Category" value={d.category} onChange={(v) => set("category", v)} placeholder="Injection, access control, misconfiguration" />
        <SelectInput label="Confidence" value={d.confidence} onChange={(v) => set("confidence", v as Confidence)} options={CONFIDENCE_OPTIONS} />
        <TextInput label="Affected target" value={d.affectedTarget} onChange={(v) => set("affectedTarget", v)} placeholder="https://app.example.com/search?q=" mono />
        <TextInput label="CVE (optional)" value={d.cve} onChange={(v) => set("cve", v)} placeholder="CVE-2024-12345" mono />
        <CvssField value={d.cvssVector} onChange={(v) => set("cvssVector", v)} severity={d.severity} onSeverity={(v) => set("severity", v)} />
        <TextAreaInput label="Description" value={d.description} onChange={(v) => set("description", v)} rows={5} placeholder="What the issue is and its impact" className="md:col-span-2" />
        <TextAreaInput label="Reproduction steps" value={d.reproduction} onChange={(v) => set("reproduction", v)} rows={4} placeholder="1. Open … 2. Send … 3. Observe …" className="md:col-span-2" />
        <TextAreaInput label="Technical details" value={d.technicalDetails} onChange={(v) => set("technicalDetails", v)} rows={3} placeholder="Requests, parameters, versions" className="md:col-span-2" />
        <TextAreaInput label="Remediation" value={d.remediation} onChange={(v) => set("remediation", v)} rows={3} placeholder="How to fix it and how to verify the fix" className="md:col-span-2" />
        <TextInput label="Tags" value={tagText} onChange={setTagText} placeholder="web, auth, quick-win" description="Separated by commas" className="md:col-span-2" />
        <TextInput label="Assignee" value={d.assignee} onChange={(v) => set("assignee", v)} placeholder="Who follows it up" />
        <TextInput label="Due date" value={d.dueDate ?? ""} onChange={(v) => set("dueDate", v || null)} placeholder="YYYY-MM-DD" mono />
      </div>
      <div>
        <div className="mb-2 flex items-center justify-between">
          <div className="text-[12.5px] font-medium text-muted">Evidence references</div>
          <Button size="sm" variant="tertiary" onPress={() => set("evidence", [...d.evidence, { label: "", reference: "" }])} isDisabled={d.evidence.length >= 50}>
            <Plus className="size-3.5" />
            Add reference
          </Button>
        </div>
        {d.evidence.length === 0 ? (
          <p className="text-[12.5px] text-muted">Point to screenshots, request/response files, tool output or ticket links. Files are referenced, not copied.</p>
        ) : (
          <div className="flex flex-col gap-2">
            {d.evidence.map((e, i) => (
              <div key={i} className="grid grid-cols-[1fr_2fr_auto] items-start gap-2">
                <TextInput aria-label={`Evidence ${i + 1} label`} value={e.label} onChange={(v) => setEvidence(i, { label: v })} placeholder="Screenshot" />
                <TextInput aria-label={`Evidence ${i + 1} reference`} value={e.reference} onChange={(v) => setEvidence(i, { reference: v })} placeholder="C:\\evidence\\xss-01.png or URL" mono />
                <Button isIconOnly variant="ghost" aria-label={`Remove evidence ${i + 1}`} onPress={() => set("evidence", d.evidence.filter((_, j) => j !== i))}>
                  <X className="size-4" />
                </Button>
              </div>
            ))}
            {incompleteEvidence && <p className="text-[12px] text-warning-soft-foreground">Each evidence row needs a label and a reference.</p>}
          </div>
        )}
      </div>
      {error && (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-[13px] text-danger-soft-foreground">
          {error}
        </div>
      )}
    </AppModal>
  );
}

const LINK_LABEL: Record<string, string> = { asset: "Asset", vulnerability: "Vulnerability", osint_entity: "OSINT entity", execution: "Tool run", evidence: "Evidence" };

function FindingDetailModal({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  const { runtime } = useApp();
  const history = useQuery(["findings"], () => (finding ? api.findingHistory(finding.id) : Promise.resolve([])), [finding?.id], runtime && !!finding);
  const links = useQuery(["findings"], () => (finding ? api.findingLinks(finding.id) : Promise.resolve([])), [finding?.id], runtime && !!finding);
  const [note, setNote] = useState("");
  const [saving, setSaving] = useState(false);
  useEffect(() => setNote(""), [finding?.id]);
  if (!finding) return null;
  const addNote = async () => {
    setSaving(true);
    try {
      await api.findingAddNote(finding.id, note);
      setNote("");
      invalidate("findings");
    } catch (e) {
      notify.error("Could not add the note", e);
    } finally {
      setSaving(false);
    }
  };
  const unlink = async (kind: FindingLinkKind, refId: number) => {
    try {
      await api.findingUnlink(finding.id, kind, refId);
      invalidate("findings");
    } catch (e) {
      notify.error("Could not remove the link", e);
    }
  };
  return (
    <AppModal isOpen={!!finding} onOpenChange={(o) => !o && onClose()} title={finding.title} description={`Recorded ${formatDateTime(finding.createdAt)} by ${finding.source}`} size="lg">
      <section>
        <h3 className="mb-1.5 text-[12.5px] font-medium text-muted">Linked records</h3>
        {!links.data ? (
          <LoadingRowsInline />
        ) : links.data.length === 0 ? (
          <p className="text-[12.5px] text-muted">None. Findings created from vulnerabilities or OSINT entities are linked automatically.</p>
        ) : (
          <ul className="flex flex-col gap-1">
            {links.data.map((l) => (
              <li key={`${l.kind}-${l.refId}`} className="panel-inset flex items-center gap-2 px-3 py-1.5 text-[12.5px]">
                <Link2 className="size-3.5 text-muted" />
                <span className="w-28 shrink-0 text-muted">{LINK_LABEL[l.kind] ?? l.kind}</span>
                <span className="min-w-0 flex-1 truncate font-mono">{l.label ?? `#${l.refId} (deleted)`}</span>
                <Button isIconOnly size="sm" variant="ghost" aria-label={`Remove link to ${l.label ?? l.refId}`} onPress={() => unlink(l.kind, l.refId)}>
                  <X className="size-3.5" />
                </Button>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section>
        <h3 className="mb-1.5 text-[12.5px] font-medium text-muted">History</h3>
        {!history.data ? (
          <LoadingRowsInline />
        ) : (
          <ol className="flex flex-col gap-1 text-[12.5px]">
            {history.data.map((e) => (
              <li key={e.id} className="flex gap-3">
                <span className="w-32 shrink-0 text-muted">{formatRelative(e.at)}</span>
                <span className="min-w-0">
                  <span className="text-foreground">
                    {e.kind === "status" || e.kind === "migrated"
                      ? `${FINDING_STATUS_META[e.fromStatus as FindingStatus]?.label ?? e.fromStatus ?? "—"} → ${FINDING_STATUS_META[e.toStatus as FindingStatus]?.label ?? e.toStatus ?? "—"}`
                      : e.kind === "created"
                        ? "Recorded"
                        : e.kind === "note"
                          ? "Note"
                          : e.kind === "updated"
                            ? "Edited"
                            : e.kind === "link"
                              ? "Linked"
                              : "Unlinked"}
                  </span>
                  {e.note && <span className="text-muted"> · {e.note}</span>}
                  {e.source !== "user" && <span className="text-muted"> · {e.source}</span>}
                </span>
              </li>
            ))}
          </ol>
        )}
        <div className="mt-2 flex items-end gap-2">
          <TextInput aria-label="Add a note" value={note} onChange={setNote} placeholder="Add a note to the history" className="flex-1" onEnter={() => note.trim() && addNote()} />
          <Button size="sm" variant="secondary" onPress={addNote} isPending={saving} isDisabled={!note.trim()}>
            Add note
          </Button>
        </div>
      </section>
    </AppModal>
  );
}

function LoadingRowsInline() {
  return <p className="text-[12.5px] text-muted">Loading…</p>;
}

export function FindingsTab({ projectId, findings }: { projectId: number; findings: Finding[] }) {
  const confirm = useConfirm();
  const [editing, setEditing] = useState<FindingDraft | null>(null);
  const [open, setOpen] = useState(false);
  const [sev, setSev] = useState<string>("all");
  const [status, setStatus] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [tag, setTag] = useState("all");
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [detail, setDetail] = useState<number | null>(null);
  const [importing, setImporting] = useState(false);
  const [bulkEditing, setBulkEditing] = useState(false);

  const list = useMemo(() => filterFindings(sortFindings(findings), { severity: sev, status, query, tag }), [findings, sev, status, query, tag]);
  const tags = useMemo(() => tagsOf(findings), [findings]);
  // thousands of rows would block the window; they are rendered in steps
  const shown = useShowMore(list, `${sev}|${status}|${query}|${tag}`);
  const visibleSelected = list.filter((f) => selected.has(f.id));
  const allSelected = shown.visible.length > 0 && shown.visible.every((f) => selected.has(f.id));

  const bulk = async (next: FindingStatus) => {
    try {
      const r = await api.findingsBulkStatus(
        visibleSelected.map((f) => f.id),
        next,
      );
      invalidate("findings", "projects");
      setSelected(new Set());
      notify.success(`${r.changed.length} marked as ${FINDING_STATUS_META[next].label.toLowerCase()}`, r.skipped.length ? `${r.skipped.length} left unchanged (${r.skipped[0][1]})` : undefined);
    } catch (e) {
      notify.error("Could not change the findings", e);
    }
  };

  const exportList = async (format: "csv" | "json") => {
    try {
      const file = await api.findingsExport(projectId, list.map((f) => f.id), format);
      if (file) notify.success(`${list.length} findings exported`, file);
    } catch (e) {
      notify.error("Could not export the findings", e);
    }
  };

  const openNew = () => {
    setEditing(null);
    setOpen(true);
  };
  const openEdit = (f: Finding) => {
    setEditing(draftOf(f));
    setOpen(true);
  };

  const changeStatus = async (f: Finding, next: FindingStatus) => {
    try {
      await api.findingSetStatus(f.id, next);
      invalidate("findings", "projects");
      notify.success(`Marked as ${FINDING_STATUS_META[next].label.toLowerCase()}`);
    } catch (e) {
      notify.error("Could not update finding", e);
    }
  };

  const remove = async (f: Finding) => {
    if (!(await confirm.ask({ title: "Delete finding?", body: `“${f.title}” and its evidence references will be permanently deleted.`, confirmLabel: "Delete finding" }))) return;
    try {
      await api.findingDelete(f.id);
      invalidate("findings", "projects");
      notify.success("Finding deleted");
    } catch (e) {
      notify.error("Could not delete finding", e);
    }
  };

  return (
    <Panel
      title="Findings"
      description={`${findings.length} recorded · sorted by severity`}
      actions={
        <>
          <SearchInput value={query} onChange={setQuery} placeholder="Search findings" className="w-52" />
          {tags.length > 0 && <SelectInput aria-label="Filter by tag" value={tag} onChange={setTag} options={[{ id: "all", label: "All tags" }, ...tags.map((t) => ({ id: t, label: t }))]} className="w-36" />}
          <SelectInput aria-label="Filter by severity" value={sev} onChange={setSev} options={[{ id: "all", label: "All severities" }, ...SEVERITY_OPTIONS]} className="w-40" />
          <SelectInput aria-label="Filter by status" value={status} onChange={setStatus} options={[{ id: "all", label: "All statuses" }, ...FINDING_STATUS_OPTIONS]} className="w-40" />
          <Button variant="secondary" size="sm" onPress={() => setImporting(true)}>
            <FileUp className="size-3.5" />
            Import results
          </Button>
          {list.length > 0 && (
            <Dropdown>
              <Button variant="secondary" size="sm" className="gap-1" aria-label="Export the listed findings">
                <FileDown className="size-3.5" />
                Export
                <ChevronDown className="size-3" />
              </Button>
              <Dropdown.Popover placement="bottom end">
                <Dropdown.Menu aria-label="Export format" onAction={(k) => void exportList(k as "csv" | "json")}>
                  <Dropdown.Item id="csv" textValue="CSV">
                    CSV (spreadsheets)
                  </Dropdown.Item>
                  <Dropdown.Item id="json" textValue="JSON">
                    JSON (other tools)
                  </Dropdown.Item>
                </Dropdown.Menu>
              </Dropdown.Popover>
            </Dropdown>
          )}
          <Button variant="primary" size="sm" onPress={openNew}>
            <Plus className="size-3.5" />
            Record finding
          </Button>
        </>
      }
    >
      <ScanImportModal isOpen={importing} onOpenChange={setImporting} projectId={projectId} />
      <BulkEditModal ids={visibleSelected.map((f) => f.id)} isOpen={bulkEditing} onOpenChange={setBulkEditing} onDone={() => setSelected(new Set())} />
      {findings.length === 0 ? (
        <EmptyBlock
          icon={ShieldAlert}
          title="No findings recorded"
          description="Record verified issues with severity, affected target and evidence references, or import the results of Nmap, Nuclei, Nessus, Greenbone/OpenVAS, Burp Suite, OWASP ZAP or a SARIF tool."
          action={
            <div className="flex gap-2">
              <Button size="sm" variant="secondary" onPress={() => setImporting(true)}>
                <FileUp className="size-3.5" />
                Import results
              </Button>
              <Button size="sm" variant="primary" onPress={openNew}>
                <Plus className="size-3.5" />
                Record finding
              </Button>
            </div>
          }
        />
      ) : list.length === 0 ? (
        <EmptyBlock compact icon={ShieldAlert} title="No findings match these filters" />
      ) : (
        <div className="panel-inset overflow-x-auto px-3 py-1">
          {visibleSelected.length > 0 && (
            <div className="flex items-center gap-2 py-2 text-[12.5px]">
              <span className="text-foreground">{visibleSelected.length} selected</span>
              <Dropdown>
                <Button size="sm" variant="secondary" className="h-7 gap-1">
                  Change status
                  <ChevronDown className="size-3" />
                </Button>
                <Dropdown.Popover placement="bottom start">
                  <Dropdown.Menu aria-label="New status for the selected findings" onAction={(k) => void bulk(k as FindingStatus)}>
                    {FINDING_STATUS_OPTIONS.map((o) => (
                      <Dropdown.Item key={o.id} id={o.id} textValue={o.label}>
                        {o.label}
                      </Dropdown.Item>
                    ))}
                  </Dropdown.Menu>
                </Dropdown.Popover>
              </Dropdown>
              <Button size="sm" variant="secondary" className="h-7" onPress={() => setBulkEditing(true)}>
                Edit tags or assignee
              </Button>
              <Button size="sm" variant="ghost" className="h-7" onPress={() => setSelected(new Set())}>
                Clear selection
              </Button>
            </div>
          )}
          <table className="w-full border-separate border-spacing-y-0.5 text-left text-[13px]">
            <thead>
              <tr className="text-[12px] text-muted">
                <th className="w-8 py-2 pr-2 font-medium">
                  <Checkbox isSelected={allSelected} isIndeterminate={!allSelected && visibleSelected.length > 0} onChange={(v) => setSelected(v ? new Set(shown.visible.map((f) => f.id)) : new Set())} aria-label="Select all shown findings">
                    <Checkbox.Content>
                      <Checkbox.Control>
                        <Checkbox.Indicator />
                      </Checkbox.Control>
                    </Checkbox.Content>
                  </Checkbox>
                </th>
                <th className="py-2 pr-3 font-medium">Severity</th>
                <th className="py-2 pr-3 font-medium">Title</th>
                <th className="py-2 pr-3 font-medium">Affected</th>
                <th className="py-2 pr-3 font-medium">Status</th>
                <th className="py-2 pr-3 font-medium">Updated</th>
                <th className="py-2 font-medium">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {shown.visible.map((f) => (
                <tr key={f.id} className="align-top transition-colors hover:bg-white/[0.025]">
                  <td className="py-2.5 pr-2">
                    <Checkbox
                      isSelected={selected.has(f.id)}
                      onChange={(v) =>
                        setSelected((s) => {
                          const n = new Set(s);
                          if (v) n.add(f.id);
                          else n.delete(f.id);
                          return n;
                        })
                      }
                      aria-label={`Select ${f.title}`}
                    >
                      <Checkbox.Content>
                        <Checkbox.Control>
                          <Checkbox.Indicator />
                        </Checkbox.Control>
                      </Checkbox.Content>
                    </Checkbox>
                  </td>
                  <td className="py-2.5 pr-3">
                    <SeverityBadge severity={f.severity} score={f.cvssScore ?? undefined} />
                  </td>
                  <td className="max-w-[340px] py-2.5 pr-3">
                    <div className="truncate text-foreground">{f.title}</div>
                    <div className="truncate text-[12px] text-muted">
                      {[f.cve, f.evidence.length ? `${f.evidence.length} evidence` : null, f.tags.length ? f.tags.join(", ") : null, f.assignee || null].filter(Boolean).join(" · ") || "No CVE or evidence"}
                    </div>
                  </td>
                  <td className="max-w-[220px] truncate py-2.5 pr-3 font-mono text-[12px] text-muted">{f.affectedTarget || "—"}</td>
                  <td className="py-2.5 pr-3">
                    <Dropdown>
                      <Button size="sm" variant="ghost" className="h-7 gap-1 px-1.5" aria-label={`Change status of ${f.title}`}>
                        <ToneChip tone={FINDING_STATUS_META[f.status].tone}>{FINDING_STATUS_META[f.status].label}</ToneChip>
                        <ChevronDown className="size-3 text-muted" />
                      </Button>
                      <Dropdown.Popover placement="bottom start">
                        <Dropdown.Menu
                          aria-label="Finding status"
                          disabledKeys={FINDING_STATUS_OPTIONS.filter((o) => !canChangeStatus(f.status, o.id)).map((o) => o.id)}
                          onAction={(k) => canChangeStatus(f.status, k as FindingStatus) && changeStatus(f, k as FindingStatus)}
                        >
                          {FINDING_STATUS_OPTIONS.map((o) => (
                            <Dropdown.Item key={o.id} id={o.id} textValue={o.label}>
                              {o.label}
                            </Dropdown.Item>
                          ))}
                        </Dropdown.Menu>
                      </Dropdown.Popover>
                    </Dropdown>
                  </td>
                  <td className="py-2.5 pr-3 whitespace-nowrap text-muted">{formatRelative(f.updatedAt)}</td>
                  <td className="py-2 text-right whitespace-nowrap">
                    <Tooltip delay={400}>
                      <Button isIconOnly size="sm" variant="ghost" aria-label={`History and links of ${f.title}`} onPress={() => setDetail(f.id)}>
                        <History className="size-3.5" />
                      </Button>
                      <Tooltip.Content>History and links</Tooltip.Content>
                    </Tooltip>
                    <Tooltip delay={400}>
                      <Button isIconOnly size="sm" variant="ghost" aria-label={`Edit ${f.title}`} onPress={() => openEdit(f)}>
                        <Pencil className="size-3.5" />
                      </Button>
                      <Tooltip.Content>Edit</Tooltip.Content>
                    </Tooltip>
                    <Tooltip delay={400}>
                      <Button isIconOnly size="sm" variant="ghost" aria-label={`Delete ${f.title}`} onPress={() => remove(f)}>
                        <Trash2 className="size-3.5" />
                      </Button>
                      <Tooltip.Content>Delete</Tooltip.Content>
                    </Tooltip>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {shown.hidden > 0 && (
            <div className="flex flex-wrap items-center justify-between gap-2 px-3 pt-2 text-[12.5px] text-muted">
              <span>
                Showing {formatNumber(shown.visible.length)} of {formatNumber(list.length)} findings. Search or filter to narrow the list.
              </span>
              <Button size="sm" variant="ghost" onPress={shown.more}>
                Show {formatNumber(Math.min(shown.step, shown.hidden))} more
              </Button>
            </div>
          )}
        </div>
      )}
      <FindingFormModal isOpen={open} onOpenChange={setOpen} projectId={projectId} initial={editing} />
      <FindingDetailModal finding={findings.find((f) => f.id === detail) ?? null} onClose={() => setDetail(null)} />
      {confirm.element}
    </Panel>
  );
}
