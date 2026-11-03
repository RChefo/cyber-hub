import { Button, Dropdown, Tooltip } from "@heroui/react";
import { ChevronDown, Pencil, Plus, ShieldAlert, Trash2, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { FINDING_STATUS_META, SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock } from "@/components/ui/Feedback";
import { SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate } from "@/lib/query";
import type { Evidence, Finding, FindingStatus, Severity } from "@/lib/types";
import { formatRelative } from "@/lib/utils";
import { sortFindings } from "./report";

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

export interface FindingDraft {
  id?: number;
  title: string;
  severity: Severity;
  status: FindingStatus;
  description: string;
  affectedTarget: string;
  cve: string;
  evidence: Evidence[];
}

const EMPTY: FindingDraft = { title: "", severity: "medium", status: "open", description: "", affectedTarget: "", cve: "", evidence: [] };

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
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setD(initial ? { ...initial, evidence: initial.evidence.map((e) => ({ ...e })) } : EMPTY);
      setError(null);
    }
  }, [isOpen, initial]);

  const set = <K extends keyof FindingDraft>(k: K, v: FindingDraft[K]) => setD((s) => ({ ...s, [k]: v }));
  const setEvidence = (i: number, patch: Partial<Evidence>) => set("evidence", d.evidence.map((e, j) => (j === i ? { ...e, ...patch } : e)));
  const incompleteEvidence = d.evidence.some((e) => !e.label.trim() || !e.reference.trim());

  const save = async () => {
    if (!d.title.trim() || incompleteEvidence) return;
    setSaving(true);
    setError(null);
    try {
      await api.findingUpsert({ ...d, projectId });
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
          <Button variant="tertiary" onPress={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={save} isPending={saving} isDisabled={!d.title.trim() || incompleteEvidence}>
            {d.id ? "Save changes" : "Record finding"}
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <TextInput label="Title" value={d.title} onChange={(v) => set("title", v)} placeholder="Reflected XSS in search parameter" isRequired autoFocus className="md:col-span-2" />
        <SelectInput label="Severity" value={d.severity} onChange={(v) => set("severity", v as Severity)} options={SEVERITY_OPTIONS} />
        <SelectInput label="Status" value={d.status} onChange={(v) => set("status", v as FindingStatus)} options={FINDING_STATUS_OPTIONS} />
        <TextInput label="Affected target" value={d.affectedTarget} onChange={(v) => set("affectedTarget", v)} placeholder="https://app.example.com/search?q=" mono />
        <TextInput label="CVE (optional)" value={d.cve} onChange={(v) => set("cve", v)} placeholder="CVE-2024-12345" mono />
        <TextAreaInput
          label="Description"
          value={d.description}
          onChange={(v) => set("description", v)}
          rows={6}
          placeholder="Impact, reproduction steps, remediation"
          className="md:col-span-2"
        />
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

export function FindingsTab({ projectId, findings }: { projectId: number; findings: Finding[] }) {
  const confirm = useConfirm();
  const [editing, setEditing] = useState<FindingDraft | null>(null);
  const [open, setOpen] = useState(false);
  const [sev, setSev] = useState<string>("all");
  const [status, setStatus] = useState<string>("all");

  const list = useMemo(
    () => sortFindings(findings).filter((f) => (sev === "all" || f.severity === sev) && (status === "all" || f.status === status)),
    [findings, sev, status],
  );

  const openNew = () => {
    setEditing(null);
    setOpen(true);
  };
  const openEdit = (f: Finding) => {
    setEditing({ id: f.id, title: f.title, severity: f.severity, status: f.status, description: f.description, affectedTarget: f.affectedTarget, cve: f.cve, evidence: f.evidence });
    setOpen(true);
  };

  const changeStatus = async (f: Finding, next: FindingStatus) => {
    try {
      await api.findingUpsert({ id: f.id, projectId, title: f.title, severity: f.severity, status: next, description: f.description, affectedTarget: f.affectedTarget, cve: f.cve, evidence: f.evidence });
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
          <SelectInput aria-label="Filter by severity" value={sev} onChange={setSev} options={[{ id: "all", label: "All severities" }, ...SEVERITY_OPTIONS]} className="w-40" />
          <SelectInput aria-label="Filter by status" value={status} onChange={setStatus} options={[{ id: "all", label: "All statuses" }, ...FINDING_STATUS_OPTIONS]} className="w-40" />
          <Button variant="primary" size="sm" onPress={openNew}>
            <Plus className="size-3.5" />
            Record finding
          </Button>
        </>
      }
    >
      {findings.length === 0 ? (
        <EmptyBlock
          icon={ShieldAlert}
          title="No findings recorded"
          description="Record verified issues with severity, affected target and evidence references."
          action={
            <Button size="sm" variant="primary" onPress={openNew}>
              <Plus className="size-3.5" />
              Record finding
            </Button>
          }
        />
      ) : list.length === 0 ? (
        <EmptyBlock compact icon={ShieldAlert} title="No findings match these filters" />
      ) : (
        <div className="panel-inset overflow-x-auto px-3 py-1">
          <table className="w-full border-separate border-spacing-y-0.5 text-left text-[13px]">
            <thead>
              <tr className="text-[12px] text-muted">
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
              {list.map((f) => (
                <tr key={f.id} className="align-top transition-colors hover:bg-white/[0.025]">
                  <td className="py-2.5 pr-3">
                    <SeverityBadge severity={f.severity} />
                  </td>
                  <td className="max-w-[340px] py-2.5 pr-3">
                    <div className="truncate text-foreground">{f.title}</div>
                    <div className="truncate text-[12px] text-muted">
                      {[f.cve, f.evidence.length ? `${f.evidence.length} evidence` : null].filter(Boolean).join(" · ") || "No CVE or evidence"}
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
                        <Dropdown.Menu aria-label="Finding status" onAction={(k) => k !== f.status && changeStatus(f, k as FindingStatus)}>
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
        </div>
      )}
      <FindingFormModal isOpen={open} onOpenChange={setOpen} projectId={projectId} initial={editing} />
      {confirm.element}
    </Panel>
  );
}
