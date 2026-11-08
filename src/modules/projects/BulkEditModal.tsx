import { Button } from "@heroui/react";
import { useEffect, useState } from "react";
import { AppModal } from "@/components/ui/Dialogs";
import { ErrorBlock } from "@/components/ui/Feedback";
import { SelectInput, TextInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate } from "@/lib/query";
import { pluralize } from "@/lib/utils";
import { parseTags } from "./report";

type AssigneeMode = "keep" | "set" | "clear";

/** Adds or removes tags and sets or clears the assignee of the selected findings. */
export function BulkEditModal({ ids, isOpen, onOpenChange, onDone }: { ids: number[]; isOpen: boolean; onOpenChange: (o: boolean) => void; onDone: () => void }) {
  const [add, setAdd] = useState("");
  const [remove, setRemove] = useState("");
  const [mode, setMode] = useState<AssigneeMode>("keep");
  const [assignee, setAssignee] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setAdd("");
      setRemove("");
      setMode("keep");
      setAssignee("");
      setError(null);
    }
  }, [isOpen]);

  const empty = !add.trim() && !remove.trim() && mode === "keep";

  const apply = async () => {
    setSaving(true);
    setError(null);
    try {
      const r = await api.findingsBulkEdit(ids, { addTags: parseTags(add), removeTags: parseTags(remove), assignee: mode === "keep" ? null : mode === "clear" ? "" : assignee.trim() });
      invalidate("findings", "projects");
      notify.success(`${pluralize(r.changed.length, "finding")} updated`, r.skipped.length ? `${pluralize(r.skipped.length, "finding")} left unchanged (${r.skipped[0][1]})` : undefined);
      onDone();
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
      title={`Edit ${pluralize(ids.length, "finding")}`}
      description="Each finding is saved on its own, and its history records what changed."
      footer={
        <>
          <Button variant="tertiary" onPress={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={apply} isPending={saving} isDisabled={empty || (mode === "set" && !assignee.trim())}>
            Apply
          </Button>
        </>
      }
    >
      {error && <ErrorBlock message={error} />}
      <TextInput label="Add tags" value={add} onChange={setAdd} placeholder="retest, quick-win" description="Separated by commas" autoFocus />
      <TextInput label="Remove tags" value={remove} onChange={setRemove} placeholder="imported" description="Matched without regard to case" />
      <SelectInput
        label="Assignee"
        value={mode}
        onChange={(v) => setMode(v as AssigneeMode)}
        options={[
          { id: "keep", label: "Keep each finding's assignee" },
          { id: "set", label: "Set the assignee" },
          { id: "clear", label: "Clear the assignee" },
        ]}
      />
      {mode === "set" && <TextInput label="New assignee" value={assignee} onChange={setAssignee} placeholder="Who follows them up" />}
    </AppModal>
  );
}
