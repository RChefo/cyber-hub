import { Button } from "@heroui/react";
import { useEffect, useState } from "react";
import { AppModal } from "@/components/ui/Dialogs";
import { SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate } from "@/lib/query";
import type { Project, ProjectStatus } from "@/lib/types";

export const STATUS_OPTIONS: { id: ProjectStatus; label: string; description: string }[] = [
  { id: "planning", label: "Planning", description: "Scope is being agreed; tools cannot run yet" },
  { id: "active", label: "Active", description: "Testing window open; tools may run against scope" },
  { id: "paused", label: "Paused", description: "Testing temporarily stopped" },
  { id: "completed", label: "Completed", description: "Testing finished, reporting done" },
  { id: "archived", label: "Archived", description: "Kept for reference" },
];

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

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
      });
      invalidate("projects", "activity");
      notify.success(project ? "Project updated" : "Project created");
      onOpenChange(false);
      onSaved?.(id);
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
        <TextAreaInput label="Description" value={description} onChange={setDescription} rows={2} placeholder="Objective, client contact, engagement type" className="md:col-span-2" />
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
          placeholder="Authorization reference, testing windows, excluded techniques, emergency contacts"
          description="Scope targets (domains, IPs, CIDRs) are managed on the project's Scope tab."
          className="md:col-span-2"
        />
      </div>
      {error && (
        <div role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-[13px] text-danger-soft-foreground">
          {error}
        </div>
      )}
    </AppModal>
  );
}
