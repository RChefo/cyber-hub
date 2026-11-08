import { Button } from "@heroui/react";
import { ExternalLink, ListChecks, ShieldAlert, StickyNote } from "lucide-react";
import { useMemo, useState } from "react";
import { AppModal } from "@/components/ui/Dialogs";
import { EmptyBlock, QueryView } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, TextAreaInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify, openExternal } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { ChecklistItem, ChecklistStatus, WstgTest } from "@/lib/types";
import { formatNumber } from "@/lib/utils";
import { CHECKLIST_STATUS_OPTIONS, coverageOf, filterCatalog, findingDraftFor } from "./checklist";
import { type FindingDraft, FindingFormModal } from "./FindingsTab";

/** Progress through the bundled OWASP WSTG checklist for one project. */
export function ChecklistTab({ projectId }: { projectId: number }) {
  const catalog = useQuery(["checklist"], api.wstgCatalog, []);
  const items = useQuery(["checklist"], () => api.checklistItems(projectId), [projectId]);
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [noteFor, setNoteFor] = useState<{ test: WstgTest; text: string } | null>(null);
  const [findingFor, setFindingFor] = useState<{ test: WstgTest; draft: FindingDraft } | null>(null);

  const byTest = useMemo(() => new Map((items.data ?? []).map((i) => [i.testId, i])), [items.data]);
  const categories = useMemo(() => (catalog.data ? filterCatalog(catalog.data.categories, byTest, query, status) : []), [catalog.data, byTest, query, status]);
  const cov = catalog.data ? coverageOf(catalog.data.categories, byTest) : null;

  const save = async (test: WstgTest, next: ChecklistStatus, note?: string, findingId?: number) => {
    const current = byTest.get(test.id);
    try {
      await api.checklistSet(projectId, test.id, next, note ?? current?.note ?? "", findingId ?? null);
      invalidate("checklist");
    } catch (e) {
      notify.error("Could not update the checklist", e);
    }
  };

  return (
    <Panel
      title="Testing checklist"
      description="Track coverage of the OWASP Web Security Testing Guide for this engagement: what was tested, what passed, what failed, and what does not apply."
      actions={
        <>
          <SearchInput value={query} onChange={setQuery} placeholder="Search tests" className="w-52" />
          <SelectInput aria-label="Filter by status" value={status} onChange={setStatus} options={[{ id: "all", label: "All statuses" }, ...CHECKLIST_STATUS_OPTIONS]} className="w-44" />
        </>
      }
    >
      <QueryView query={catalog} rows={4}>
        {(cat) => (
          <div className="flex flex-col gap-4">
            {cov && (
              <div className="panel-inset flex flex-col gap-2 px-4 py-3">
                <div className="flex flex-wrap items-baseline justify-between gap-2 text-[13px]">
                  <span className="text-foreground">
                    {formatNumber(cov.done)} of {formatNumber(cov.total)} tests have a result ({Math.round((cov.done / cov.total) * 100)} %)
                  </span>
                  <span className="text-muted">
                    {cov.passed} passed · {cov.failed} failed · {cov.notApplicable} not applicable · {cov.inProgress} in progress
                  </span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.06]" role="progressbar" aria-valuemin={0} aria-valuemax={cov.total} aria-valuenow={cov.done} aria-label="Checklist coverage">
                  <div className="h-full rounded-full bg-accent" style={{ width: `${(cov.done / cov.total) * 100}%` }} />
                </div>
              </div>
            )}
            {categories.length === 0 ? (
              <EmptyBlock compact icon={ListChecks} title="No tests match" description="Try a different search or status." />
            ) : (
              categories.map((c) => (
                <section key={c.id} aria-label={c.name} className="flex flex-col gap-1">
                  <h3 className="text-[13.5px] font-medium text-foreground">
                    {c.name} <span className="font-mono text-[12px] text-muted">{c.id}</span>
                  </h3>
                  <ul className="flex flex-col gap-0.5">
                    {c.tests.map((t) => {
                      const it = byTest.get(t.id);
                      const st = (it?.status ?? "not_started") as ChecklistStatus;
                      return (
                        <li key={t.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 rounded-lg px-2 py-1.5 hover:bg-white/[0.025]">
                          <span className="w-28 shrink-0 font-mono text-[12px] text-muted">{t.id}</span>
                          <div className="min-w-0 flex-1">
                            <div className="text-[13px] text-foreground">{t.name}</div>
                            {it?.note && <div className="truncate text-[12px] text-muted">{it.note}</div>}
                          </div>
                          {it?.findingId && <span className="text-[12px] text-muted">Finding #{it.findingId}</span>}
                          <SelectInput aria-label={`Status of ${t.id}`} value={st} onChange={(v) => void save(t, v as ChecklistStatus)} options={CHECKLIST_STATUS_OPTIONS} className="w-40" />
                          <Button size="sm" variant="ghost" isIconOnly className="size-7 min-w-7" aria-label={`Note for ${t.id}`} onPress={() => setNoteFor({ test: t, text: it?.note ?? "" })}>
                            <StickyNote className="size-3.5" />
                          </Button>
                          {st === "failed" && !it?.findingId && (
                            <Button size="sm" variant="ghost" className="h-7" onPress={() => setFindingFor({ test: t, draft: findingDraftFor(t, c.name, it?.note ?? "") })}>
                              <ShieldAlert className="size-3.5" />
                              Record finding
                            </Button>
                          )}
                          <Button size="sm" variant="ghost" isIconOnly className="size-7 min-w-7" aria-label={`Open ${t.id} in the WSTG`} onPress={() => void openExternal(t.reference)}>
                            <ExternalLink className="size-3.5" />
                          </Button>
                        </li>
                      );
                    })}
                  </ul>
                </section>
              ))
            )}
            <p className="text-[11.5px] text-muted">
              Checklist from the{" "}
              <button type="button" className="underline decoration-dotted underline-offset-2" onClick={() => void openExternal(cat.url)}>
                OWASP Web Security Testing Guide
              </button>{" "}
              (commit {cat.commit.slice(0, 7)}, {cat.retrieved}), licensed CC BY-SA 4.0.
            </p>
          </div>
        )}
      </QueryView>

      <AppModal
        isOpen={noteFor !== null}
        onOpenChange={(o) => !o && setNoteFor(null)}
        title={noteFor ? `Note for ${noteFor.test.id}` : ""}
        description={noteFor?.test.name}
        footer={
          <>
            <Button variant="tertiary" onPress={() => setNoteFor(null)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onPress={async () => {
                if (!noteFor) return;
                await save(noteFor.test, (byTest.get(noteFor.test.id)?.status ?? "in_progress") as ChecklistStatus, noteFor.text);
                setNoteFor(null);
              }}
            >
              Save note
            </Button>
          </>
        }
      >
        {noteFor && (
          <>
            {noteFor.test.objectives.length > 0 && (
              <ul className="list-disc pl-5 text-[12.5px] text-muted">
                {noteFor.test.objectives.map((o) => (
                  <li key={o}>{o}</li>
                ))}
              </ul>
            )}
            <TextAreaInput label="Note" value={noteFor.text} onChange={(v) => setNoteFor({ ...noteFor, text: v })} rows={4} placeholder="What was tested, where, and with what result" />
          </>
        )}
      </AppModal>
      <FindingFormModal
        isOpen={findingFor !== null}
        onOpenChange={(o) => !o && setFindingFor(null)}
        projectId={projectId}
        initial={findingFor?.draft ?? null}
        onSaved={(id) => {
          if (findingFor) void save(findingFor.test, "failed", undefined, id);
        }}
      />
    </Panel>
  );
}

export type { ChecklistItem };
