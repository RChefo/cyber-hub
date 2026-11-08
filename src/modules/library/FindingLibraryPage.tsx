import { Button } from "@heroui/react";
import { Download, LibraryBig, Plus, Sparkles, Upload } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { EmptyBlock, QueryView } from "@/components/ui/Feedback";
import { SearchInput, SelectInput } from "@/components/ui/Fields";
import { PageHeader } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { FindingTemplate, FindingTemplateInput } from "@/lib/types";
import { formatRelative, pluralize } from "@/lib/utils";
import { EMPTY_TEMPLATE, matchesTemplate, SEVERITY_CHOICES, templateInput } from "./library";
import { TemplateFormModal } from "./TemplateFormModal";

export default function FindingLibraryPage() {
  const { runtime } = useApp();
  const q = useQuery(["templates"], api.findingTemplatesList, [], runtime);
  const [search, setSearch] = useState("");
  const [sev, setSev] = useState("all");
  const [editing, setEditing] = useState<FindingTemplateInput | null>(null);
  const [busy, setBusy] = useState<"starters" | "import" | "export" | null>(null);

  const list = useMemo(() => (q.data ?? []).filter((t) => (sev === "all" || t.severity === sev) && matchesTemplate(t, search)), [q.data, search, sev]);

  const run = async (kind: "starters" | "import" | "export") => {
    setBusy(kind);
    try {
      if (kind === "starters") {
        const n = await api.findingTemplatesAddStarters();
        notify.success(n > 0 ? `${pluralize(n, "starter template")} added` : "The starter templates are already in the library");
      } else if (kind === "export") {
        const file = await api.findingTemplatesExport();
        if (file) notify.success("Finding library exported", file);
      } else {
        const r = await api.findingTemplatesImport();
        if (r) {
          const notes = [r.skipped.length ? `${pluralize(r.skipped.length, "template")} with an existing title left as they are` : "", r.invalid.length ? `${pluralize(r.invalid.length, "entry", "entries")} not valid: ${r.invalid.slice(0, 3).join("; ")}` : ""].filter(Boolean).join(". ");
          notify.success(`${pluralize(r.created, "template")} imported`, notes || undefined);
        }
      }
      invalidate("templates");
    } catch (e) {
      notify.error(kind === "export" ? "Could not export the library" : kind === "import" ? "Could not import the library" : "Could not add the starter templates", e);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div>
      <PageHeader
        title="Finding Library"
        description="Reusable write-ups for findings you report again and again. Start a finding from a template, save a finding as one, and give templates import rules so scan imports use your text instead of the scanner's."
        actions={
          <>
            <Button variant="secondary" size="sm" onPress={() => void run("import")} isPending={busy === "import"} isDisabled={!runtime}>
              <Upload className="size-3.5" />
              Import
            </Button>
            <Button variant="secondary" size="sm" onPress={() => void run("export")} isPending={busy === "export"} isDisabled={!runtime || !q.data?.length}>
              <Download className="size-3.5" />
              Export
            </Button>
            <Button variant="primary" size="sm" onPress={() => setEditing({ ...EMPTY_TEMPLATE })} isDisabled={!runtime}>
              <Plus className="size-3.5" />
              New template
            </Button>
          </>
        }
      />
      <div className="mb-3 flex flex-wrap gap-2">
        <SearchInput value={search} onChange={setSearch} placeholder="Search titles, categories, tags and rules" className="max-w-sm" />
        <SelectInput aria-label="Filter by severity" value={sev} onChange={setSev} options={[{ id: "all", label: "All severities" }, ...SEVERITY_CHOICES]} className="w-44" />
      </div>
      <QueryView
        query={q}
        rows={4}
        isEmpty={(d) => d.length === 0}
        empty={
          <EmptyBlock
            icon={LibraryBig}
            title="The library is empty"
            description="Write a template for a finding you report often, or start with 14 common web, TLS and network findings. Starter templates come with import rules for OWASP ZAP, Burp Suite and Nessus."
            action={
              <div className="flex gap-2">
                <Button size="sm" variant="secondary" onPress={() => void run("starters")} isPending={busy === "starters"}>
                  <Sparkles className="size-3.5" />
                  Add starter templates
                </Button>
                <Button size="sm" variant="primary" onPress={() => setEditing({ ...EMPTY_TEMPLATE })}>
                  <Plus className="size-3.5" />
                  New template
                </Button>
              </div>
            }
          />
        }
      >
        {() =>
          list.length === 0 ? (
            <EmptyBlock compact icon={LibraryBig} title="No templates match" description="Try a different search or severity." />
          ) : (
            <div className="flex flex-col gap-2">
              {list.map((t) => (
                <TemplateRow key={t.id} t={t} onOpen={() => setEditing(templateInput(t))} />
              ))}
            </div>
          )
        }
      </QueryView>
      <TemplateFormModal initial={editing} onClose={() => setEditing(null)} />
    </div>
  );
}

function TemplateRow({ t, onOpen }: { t: FindingTemplate; onOpen: () => void }) {
  return (
    <Button variant="ghost" onPress={onOpen} className="panel h-auto w-full justify-start gap-4 px-4 py-3 text-left font-normal whitespace-normal hover:bg-surface-hover" aria-label={`Edit template ${t.title}`}>
      <div className="w-16 shrink-0">
        <SeverityBadge severity={t.severity} />
      </div>
      <div className="min-w-0 flex-1">
        <div className="truncate text-[14px] font-medium text-foreground">{t.title}</div>
        <div className="mt-0.5 truncate text-[12.5px] text-muted">{[t.category, t.description].filter(Boolean).join(" — ") || "No description"}</div>
      </div>
      <div className="hidden shrink-0 flex-wrap justify-end gap-1.5 md:flex">
        {t.rules.slice(0, 3).map((r) => (
          <ToneChip key={r} tone="default" dot={false} className="font-mono">
            {r}
          </ToneChip>
        ))}
        {t.rules.length > 3 && <ToneChip tone="default" dot={false}>+{t.rules.length - 3}</ToneChip>}
      </div>
      <div className="hidden w-28 shrink-0 text-right text-[12px] text-muted lg:block">
        {t.useCount > 0 ? `Used ${pluralize(t.useCount, "time")}` : "Not used yet"}
        <div>{formatRelative(t.updatedAt)}</div>
      </div>
    </Button>
  );
}
