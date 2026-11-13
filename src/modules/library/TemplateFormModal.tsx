// SPDX-License-Identifier: Apache-2.0
import { Button } from "@heroui/react";
import { Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { ErrorBlock } from "@/components/ui/Feedback";
import { SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate } from "@/lib/query";
import type { FindingTemplate, FindingTemplateInput, Severity } from "@/lib/types";
import { EMPTY_TEMPLATE, lines, ruleProblem, SEVERITY_CHOICES } from "./library";

/** Creates or edits a template. `initial` null closes the dialog. */
export function TemplateFormModal({ initial, onClose, onSaved }: { initial: FindingTemplateInput | null; onClose: () => void; onSaved?: (t: FindingTemplate) => void }) {
  const confirm = useConfirm();
  const [d, setD] = useState<FindingTemplateInput>(EMPTY_TEMPLATE);
  const [refText, setRefText] = useState("");
  const [tagText, setTagText] = useState("");
  const [ruleText, setRuleText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (initial) {
      setD(initial);
      setRefText(initial.references.join("\n"));
      setTagText(initial.tags.join(", "));
      setRuleText(initial.rules.join("\n"));
      setError(null);
    }
  }, [initial]);

  const set = <K extends keyof FindingTemplateInput>(k: K, v: FindingTemplateInput[K]) => setD((s) => ({ ...s, [k]: v }));
  const ruleErrors = lines(ruleText).map(ruleProblem).filter((p): p is string => p !== null);

  const save = async () => {
    if (!d.title.trim() || ruleErrors.length) return;
    setSaving(true);
    setError(null);
    try {
      const saved = await api.findingTemplateSave({
        ...d,
        references: lines(refText),
        tags: tagText.split(",").map((t) => t.trim()).filter(Boolean),
        rules: lines(ruleText),
      });
      invalidate("templates");
      notify.success(d.id ? "Template saved" : "Template added to the library");
      onSaved?.(saved);
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  const remove = async () => {
    if (!d.id) return;
    if (!(await confirm.ask({ title: "Delete template?", body: `“${d.title}” will be removed from the library. Findings written from it keep their text.`, confirmLabel: "Delete template" }))) return;
    try {
      await api.findingTemplateDelete(d.id);
      invalidate("templates");
      notify.success("Template deleted");
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <>
      <AppModal
        isOpen={initial !== null}
        onOpenChange={(o) => !o && onClose()}
        size="lg"
        title={d.id ? "Edit template" : "New template"}
        description="Write it once, the way you want it in reports. The affected target, reproduction steps and evidence stay with each finding."
        footer={
          <>
            {d.id && (
              <Button variant="danger-soft" className="mr-auto" onPress={() => void remove()}>
                <Trash2 className="size-3.5" />
                Delete
              </Button>
            )}
            <Button variant="tertiary" onPress={onClose}>
              Cancel
            </Button>
            <Button variant="primary" onPress={save} isPending={saving} isDisabled={!d.title.trim() || ruleErrors.length > 0}>
              {d.id ? "Save template" : "Add template"}
            </Button>
          </>
        }
      >
        {error && <ErrorBlock message={error} />}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <TextInput label="Title" value={d.title} onChange={(v) => set("title", v)} placeholder="Reflected cross-site scripting" isRequired autoFocus className="md:col-span-2" />
          <SelectInput label="Severity" value={d.severity} onChange={(v) => set("severity", v as Severity)} options={SEVERITY_CHOICES} />
          <TextInput label="Category" value={d.category} onChange={(v) => set("category", v)} placeholder="Injection, access control, transport security" />
          <TextAreaInput label="Description" value={d.description} onChange={(v) => set("description", v)} rows={6} placeholder="What the issue is, why it matters, and its impact" className="md:col-span-2" />
          <TextAreaInput label="Remediation" value={d.remediation} onChange={(v) => set("remediation", v)} rows={4} placeholder="How to fix it and how to verify the fix" className="md:col-span-2" />
          <TextAreaInput label="References" value={refText} onChange={setRefText} rows={3} placeholder="One URL or citation per line" className="md:col-span-2" />
          <TextInput label="Tags" value={tagText} onChange={setTagText} placeholder="web, owasp-top-10" description="Separated by commas" className="md:col-span-2" />
          <TextAreaInput
            label="Import rules"
            value={ruleText}
            onChange={setRuleText}
            rows={3}
            placeholder={"nessus:57582\nzap:10038\nnuclei:CVE-2021-41773"}
            description={ruleErrors[0] ?? "One format:rule per line (nmap, nuclei, nessus, burp, zap, sarif, openvas, ocsf). A scan import writes matching findings from this template. A rule belongs to one template."}
            className="md:col-span-2"
          />
        </div>
      </AppModal>
      {confirm.element}
    </>
  );
}
