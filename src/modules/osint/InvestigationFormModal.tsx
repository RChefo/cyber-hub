import { Button } from "@heroui/react";
import { useEffect, useMemo, useState } from "react";
import { AppModal } from "@/components/ui/Dialogs";
import { ErrorBlock } from "@/components/ui/Feedback";
import { SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { Investigation, InvestigationInput } from "./types";

const NO_PROJECT = "none";

function emptyInput(): InvestigationInput {
  return { name: "", description: "", targetType: "domain", targetValue: "", tags: [], notes: "", authorization: "", projectId: null };
}

export function InvestigationFormModal({
  isOpen,
  onOpenChange,
  investigation,
  onSaved,
}: {
  isOpen: boolean;
  onOpenChange: (o: boolean) => void;
  investigation?: Investigation | null;
  onSaved?: (inv: Investigation) => void;
}) {
  const editing = !!investigation;
  const registry = useQuery(["osint"], api.osintRegistry, [], isOpen);
  const projects = useQuery(["projects"], api.projectsList, [], isOpen);
  const [input, setInput] = useState<InvestigationInput>(emptyInput);
  const [tags, setTags] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!isOpen) return;
    setError(null);
    if (investigation) {
      setInput({
        name: investigation.name,
        description: investigation.description,
        targetType: investigation.targetType,
        targetValue: investigation.targetValue,
        tags: investigation.tags,
        notes: investigation.notes,
        authorization: investigation.authorization,
        projectId: investigation.projectId,
      });
      setTags(investigation.tags.join(", "));
    } else {
      setInput(emptyInput());
      setTags("");
    }
  }, [isOpen, investigation]);

  const typeOptions = useMemo(
    () => (registry.data?.entityTypes ?? []).filter((t) => t.target || t.id === input.targetType).map((t) => ({ id: t.id, label: t.label })),
    [registry.data, input.targetType],
  );
  const projectOptions = useMemo(
    () => [{ id: NO_PROJECT, label: "No linked project" }, ...(projects.data ?? []).map((p) => ({ id: String(p.id), label: p.name, description: p.status }))],
    [projects.data],
  );

  const set = <K extends keyof InvestigationInput>(k: K, v: InvestigationInput[K]) => setInput((s) => ({ ...s, [k]: v }));
  const valid = input.name.trim().length > 0 && input.targetValue.trim().length > 0;

  const save = async () => {
    setSaving(true);
    setError(null);
    const payload: InvestigationInput = {
      ...input,
      name: input.name.trim(),
      targetValue: input.targetValue.trim(),
      tags: tags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    };
    try {
      const saved = investigation ? await api.osintInvestigationUpdate(investigation.id, payload) : await api.osintInvestigationCreate(payload);
      invalidate("osint");
      notify.success(editing ? "Investigation updated" : "Investigation created", editing ? undefined : `${saved.name} with a main graph for ${saved.targetValue}`);
      onSaved?.(saved);
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
      size="lg"
      title={editing ? "Edit investigation" : "New investigation"}
      description={
        editing
          ? "The primary target cannot change; start a new investigation for a different target."
          : "An investigation collects public information about one primary target, links what it finds with evidence and keeps its graphs."
      }
      footer={
        <>
          <Button variant="tertiary" onPress={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={save} isDisabled={!valid} isPending={saving}>
            {editing ? "Save changes" : "Create investigation"}
          </Button>
        </>
      }
    >
      {error && <ErrorBlock message={error} />}
      <div className="grid gap-4 sm:grid-cols-2">
        <TextInput label="Name" value={input.name} onChange={(v) => set("name", v)} isRequired autoFocus placeholder="Acme external footprint" />
        <TextInput label="Tags" value={tags} onChange={setTags} placeholder="q4, phishing, vendor" description="Comma separated" />
        <SelectInput label="Target type" value={input.targetType} onChange={(v) => set("targetType", v)} options={typeOptions} isDisabled={editing} />
        <TextInput
          label="Target value"
          value={input.targetValue}
          onChange={(v) => set("targetValue", v)}
          isRequired
          isDisabled={editing}
          mono
          placeholder={input.targetType === "domain" ? "example.com" : input.targetType === "ip" ? "93.184.216.34" : "Value"}
        />
        <SelectInput
          label="Linked project"
          value={input.projectId == null ? NO_PROJECT : String(input.projectId)}
          onChange={(v) => set("projectId", v === NO_PROJECT ? null : Number(v))}
          options={projectOptions}
        />
        <TextInput
          label="Authorization or scope note"
          value={input.authorization}
          onChange={(v) => set("authorization", v)}
          placeholder="Engagement letter of 2026-11-01, public footprint only"
        />
      </div>
      <p className="text-[12px] text-muted">
        Sources that contact the target directly (web fingerprint) run only when a linked, active project's scope covers the target. Passive public sources work without a
        project.
      </p>
      <TextAreaInput label="Description" value={input.description} onChange={(v) => set("description", v)} rows={3} placeholder="Purpose and questions to answer" />
      <TextAreaInput label="Notes" value={input.notes} onChange={(v) => set("notes", v)} rows={4} placeholder="Working notes" />
    </AppModal>
  );
}
