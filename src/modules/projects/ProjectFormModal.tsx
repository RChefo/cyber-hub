import { Button } from "@heroui/react";
import { useEffect, useState } from "react";
import { AppModal } from "@/components/ui/Dialogs";
import { SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { api, errorMessage, IpcError } from "@/lib/ipc";
import { invalidate } from "@/lib/query";
import type { Engagement, Project, ProjectStatus } from "@/lib/types";

export const STATUS_OPTIONS: { id: ProjectStatus; label: string; description: string }[] = [
  { id: "planning", label: "Planning", description: "Scope is being agreed; tools cannot run yet" },
  { id: "active", label: "Active", description: "Testing window open; tools may run against scope" },
  { id: "paused", label: "Paused", description: "Testing temporarily stopped" },
  { id: "completed", label: "Completed", description: "Testing finished, reporting done" },
  { id: "archived", label: "Archived", description: "Kept for reference" },
];

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

export const ENGAGEMENT_TYPES: { id: string; label: string }[] = [
  { id: "", label: "Not set" },
  { id: "external", label: "External network" },
  { id: "internal", label: "Internal network" },
  { id: "web_application", label: "Web application" },
  { id: "api", label: "API" },
  { id: "cloud", label: "Cloud" },
  { id: "mobile", label: "Mobile" },
  { id: "wireless", label: "Wireless" },
  { id: "red_team", label: "Red team" },
  { id: "osint", label: "OSINT" },
  { id: "other", label: "Other" },
];

const EMPTY_ENGAGEMENT: Engagement = { client: "", engagementType: "", authorizationRef: "", objectives: "", methodology: "", contacts: "" };

export function engagementOf(p: Project | null | undefined): Engagement {
  if (!p) return EMPTY_ENGAGEMENT;
  return { client: p.client, engagementType: p.engagementType, authorizationRef: p.authorizationRef, objectives: p.objectives, methodology: p.methodology, contacts: p.contacts };
}

interface Props {
  isOpen: boolean;
  onOpenChange: (open: boolean) => void;
  /** Existing project to edit; omit to create. */
  project?: Project | null;
  onSaved?: (id: number) => void;
}

export function ProjectFormModal({ isOpen, onOpenChange, project, onSaved }: Props) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [status, setStatus] = useState<ProjectStatus>("planning");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [scopeNotes, setScopeNotes] = useState("");
  const [eng, setEng] = useState<Engagement>(EMPTY_ENGAGEMENT);
  const setE = (k: keyof Engagement, v: string) => setEng((e) => ({ ...e, [k]: v }));
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    setName(project?.name ?? "");
    setDescription(project?.description ?? "");
    setStatus(project?.status ?? "planning");
    setStartDate(project?.startDate ?? "");
    setEndDate(project?.endDate ?? "");
    setScopeNotes(project?.scopeNotes ?? "");
    setEng(engagementOf(project));
    setError(null);
  }, [isOpen, project]);

  const startErr = startDate && !DATE_RE.test(startDate) ? "Use YYYY-MM-DD" : null;
  const endErr = endDate && !DATE_RE.test(endDate) ? "Use YYYY-MM-DD" : startDate && endDate && endDate < startDate ? "End date is before the start date" : null;
  const canSave = name.trim().length > 0 && !startErr && !endErr && !saving;

  const save = async () => {
    if (!canSave) return;
    setSaving(true);
    setError(null);
    try {
      const id = await api.projectUpsert({
        id: project?.id,
        name,
        description,
        status,
        scopeNotes,
        notes: project?.notes ?? "",
        startDate: startDate || null,
        endDate: endDate || null,
        ...eng,
      });
      invalidate("projects", "activity");
      notify.success(project ? "Project updated" : "Project created");
      onOpenChange(false);
      onSaved?.(id);
    } catch (e) {
      // declining the native question about reopening an ended project is a decision, not an
      // error: the form stays open with the analyst's edits (Mission 8)
      if (e instanceof IpcError && e.kind === "cancelled") notify.error("", e);
      else setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <AppModal
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      title={project ? "Edit project" : "New project"}
      description="Projects hold the authorized scope that tool execution is checked against."
      size="lg"
      footer={
        <>
          <Button variant="tertiary" onPress={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={save} isDisabled={!canSave} isPending={saving}>
            {project ? "Save changes" : "Create project"}
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <TextInput label="Project name" value={name} onChange={setName} placeholder="Acme external assessment Q4" isRequired autoFocus className="md:col-span-2" />
        <TextAreaInput label="Description" value={description} onChange={setDescription} rows={2} placeholder="What is being assessed and why" className="md:col-span-2" />
        <TextInput label="Client" value={eng.client} onChange={(v) => setE("client", v)} placeholder="Acme Corp" />
        <SelectInput label="Engagement type" value={eng.engagementType} onChange={(v) => setE("engagementType", v)} options={ENGAGEMENT_TYPES} />
        <TextInput
          label="Authorization reference"
          value={eng.authorizationRef}
          onChange={(v) => setE("authorizationRef", v)}
          placeholder="SOW-2026-117, signed 2026-10-28"
          description="The written authorization this testing relies on"
          className="md:col-span-2"
        />
        <SelectInput label="Status" value={status} onChange={(v) => setStatus(v as ProjectStatus)} options={STATUS_OPTIONS} />
        <div className="grid grid-cols-2 gap-3">
          <TextInput label="Start date" value={startDate} onChange={setStartDate} placeholder="2026-11-01" error={startErr} mono />
          <TextInput label="End date" value={endDate} onChange={setEndDate} placeholder="2026-11-15" error={endErr} mono />
        </div>
        <TextAreaInput
          label="Rules of engagement"
          value={scopeNotes}
          onChange={setScopeNotes}
          rows={4}
          placeholder="Testing windows, excluded techniques, rate limits"
          description="Scope targets (domains, IPs, CIDRs) are managed on the project's Scope tab."
          className="md:col-span-2"
        />
        <TextAreaInput label="Objectives" value={eng.objectives} onChange={(v) => setE("objectives", v)} rows={2} className="md:col-span-2" />
        <TextAreaInput label="Methodology" value={eng.methodology} onChange={(v) => setE("methodology", v)} rows={2} placeholder="OWASP WSTG, PTES, internal checklist" className="md:col-span-2" />
        <TextAreaInput label="Contacts" value={eng.contacts} onChange={(v) => setE("contacts", v)} rows={2} placeholder="Technical and emergency contacts" className="md:col-span-2" />
      </div>
      {error && (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-[13px] text-danger-soft-foreground">
          {error}
        </div>
      )}
    </AppModal>
  );
}
