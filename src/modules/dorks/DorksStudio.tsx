import { Button, Checkbox, Label, Tabs, Tooltip } from "@heroui/react";
import { ExternalLink, History, Info, Pencil, Plus, Save, Search, Trash2, Upload, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { CodeBlock, CopyButton } from "@/components/ui/Code";
import { useConfirm, AppModal } from "@/components/ui/Dialogs";
import { EmptyBlock, QueryView } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { DORK_CATEGORY_LABELS, DORK_TEMPLATES } from "@/data/dorkTemplates";
import { copyText, notify, openExternal } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { SavedDork } from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";
import type { DorkCategory, DorkTemplate } from "@/types/catalog";
import {
  applyTemplate,
  buildQuery,
  EMPTY_STATE,
  FILE_TYPES,
  googleUrl,
  isValidDate,
  isValidDomain,
  NEGATABLE,
  OPERATOR_LABELS,
  type DorkState,
  type OperatorKind,
  type OperatorRow,
  type OrInner,
} from "./query";

let rowSeq = 0;
const newRow = (kind: OperatorKind = "inurl"): OperatorRow => ({
  id: `r${++rowSeq}`,
  kind,
  value: kind === "filetype" ? "pdf" : "",
  negate: false,
  inner: kind === "or" ? "term" : undefined,
});

const OPERATOR_OPTIONS = (Object.keys(OPERATOR_LABELS) as OperatorKind[]).map((k) => ({ id: k, label: OPERATOR_LABELS[k] }));
const OR_INNER_OPTIONS: { id: OrInner; label: string }[] = [
  { id: "term", label: "Plain terms" },
  { id: "site", label: "site:" },
  { id: "filetype", label: "filetype:" },
  { id: "inurl", label: "inurl:" },
  { id: "intitle", label: "intitle:" },
  { id: "intext", label: "intext:" },
];
const SAVE_CATEGORIES = [...(Object.keys(DORK_CATEGORY_LABELS) as DorkCategory[]).map((k) => ({ id: k, label: DORK_CATEGORY_LABELS[k] })), { id: "custom", label: "Custom" }];

/** Open a query in the system browser and record it in history. */
async function runQuery(query: string) {
  if (!query.trim()) return;
  await openExternal(googleUrl(query));
  api
    .dorkHistoryAdd(query)
    .then(() => invalidate("dorks", "activity"))
    .catch(() => undefined);
}

function OperatorRowEditor({ row, onChange, onRemove }: { row: OperatorRow; onChange: (r: OperatorRow) => void; onRemove: () => void }) {
  const dateInvalid = (row.kind === "before" || row.kind === "after") && row.value !== "" && !isValidDate(row.value);
  return (
    <div className="tile flex flex-wrap items-start gap-2 p-2.5">
      <SelectInput
        aria-label="Operator"
        className="w-[170px]"
        value={row.kind}
        options={OPERATOR_OPTIONS}
        onChange={(k) => onChange({ ...newRow(k as OperatorKind), id: row.id, value: k === row.kind ? row.value : k === "filetype" ? "pdf" : "" })}
      />
      {row.kind === "or" && (
        <SelectInput aria-label="Apply to each value" className="w-[140px]" value={row.inner ?? "term"} options={OR_INNER_OPTIONS} onChange={(v) => onChange({ ...row, inner: v as OrInner })} />
      )}
      <div className="min-w-[200px] flex-1">
        {row.kind === "filetype" ? (
          <SelectInput aria-label="File type" value={row.value} options={FILE_TYPES.map((f) => ({ id: f, label: f }))} onChange={(v) => onChange({ ...row, value: v })} />
        ) : row.kind === "before" || row.kind === "after" ? (
          <TextInput aria-label={`${row.kind} date`} type="date" value={row.value} onChange={(v) => onChange({ ...row, value: v })} error={dateInvalid ? "Use YYYY-MM-DD" : null} />
        ) : (
          <TextInput
            aria-label="Value"
            mono
            value={row.value}
            onChange={(v) => onChange({ ...row, value: v })}
            placeholder={row.kind === "or" ? "Values separated by commas, e.g. pdf, docx, xlsx" : row.kind === "exclude" ? "Term to exclude" : "Value"}
          />
        )}
      </div>
      {NEGATABLE.has(row.kind) && (
        <Checkbox isSelected={row.negate} onChange={(v) => onChange({ ...row, negate: v })} className="mt-2">
          <Checkbox.Content className="flex items-center gap-1.5">
            <Checkbox.Control>
              <Checkbox.Indicator />
            </Checkbox.Control>
            <Label className="text-[12.5px] font-normal text-muted">Exclude</Label>
          </Checkbox.Content>
        </Checkbox>
      )}
      <Button isIconOnly size="sm" variant="ghost" aria-label="Remove operator" onPress={onRemove} className="mt-0.5">
        <X className="size-3.5" />
      </Button>
    </div>
  );
}

interface SaveDraft {
  id?: number;
  title: string;
  query: string;
  category: string;
  notes: string;
}

function SaveDorkModal({ draft, onClose }: { draft: SaveDraft | null; onClose: () => void }) {
  const [form, setForm] = useState<SaveDraft>({ title: "", query: "", category: "custom", notes: "" });
  const [pending, setPending] = useState(false);
  useEffect(() => {
    if (draft) setForm(draft);
  }, [draft]);
  const save = async () => {
    setPending(true);
    try {
      await api.savedDorkUpsert(form);
      invalidate("dorks", "activity");
      notify.success(form.id ? "Query updated" : "Query saved");
      onClose();
    } catch (e) {
      notify.error("Could not save query", e);
    } finally {
      setPending(false);
    }
  };
  const invalid = !form.title.trim() || !form.query.trim() || form.title.length > 150 || form.query.length > 2000;
  return (
    <AppModal
      isOpen={!!draft}
      onOpenChange={(o) => !o && onClose()}
      title={form.id ? "Edit saved query" : "Save query"}
      footer={
        <>
          <Button variant="tertiary" onPress={onClose}>Cancel</Button>
          <Button variant="primary" isPending={pending} isDisabled={invalid} onPress={save}>
            {form.id ? "Save changes" : "Save query"}
          </Button>
        </>
      }
    >
      <TextInput label="Title" value={form.title} onChange={(v) => setForm({ ...form, title: v })} placeholder="e.g. Exposed PDFs on corp domain" isRequired autoFocus />
      <TextAreaInput label="Query" mono rows={3} value={form.query} onChange={(v) => setForm({ ...form, query: v })} isRequired />
      <SelectInput label="Category" value={form.category} options={SAVE_CATEGORIES} onChange={(v) => setForm({ ...form, category: v })} />
      <TextAreaInput label="Notes" rows={3} value={form.notes} onChange={(v) => setForm({ ...form, notes: v })} placeholder="Why this query matters, what to look for" />
    </AppModal>
  );
}

function TemplatesPanel({ domain, onLoad, initialId }: { domain: string; onLoad: (q: string) => void; initialId?: string }) {
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<string | null>(initialId ?? null);
  const domainOk = isValidDomain(domain);
  const q = search.toLowerCase().trim();
  const filtered = DORK_TEMPLATES.filter((t) => !q || `${t.title} ${t.description} ${t.query}`.toLowerCase().includes(q));
  const groups = (Object.keys(DORK_CATEGORY_LABELS) as DorkCategory[])
    .map((c) => ({ c, items: filtered.filter((t) => t.category === c) }))
    .filter((g) => g.items.length);

  useEffect(() => {
    if (initialId) document.getElementById(`tpl-${initialId}`)?.scrollIntoView({ block: "center" });
  }, [initialId]);

  const renderItem = (t: DorkTemplate) => {
    const expanded = open === t.id;
    const query = applyTemplate(t.query, domain);
    return (
      <li key={t.id} id={`tpl-${t.id}`} className={cn("rounded-lg", expanded && "bg-accent-soft/50")}>
        <Button
          variant="ghost"
          onPress={() => setOpen(expanded ? null : t.id)}
          aria-expanded={expanded}
          className="h-auto w-full flex-col items-start gap-0.5 rounded-lg px-2.5 py-2 text-left font-normal whitespace-normal"
        >
          <span className="text-[13px] text-foreground">{t.title}</span>
          <span className="text-[12px] text-muted">{t.description}</span>
        </Button>
        {expanded && (
          <div className="flex flex-col gap-2 px-2.5 pb-2.5">
            {!domainOk && (
              <div className="flex items-center gap-1.5 text-[12px] text-warning-soft-foreground">
                <Info className="size-3.5" />
                Enter a valid domain in the builder to substitute {"{domain}"}.
              </div>
            )}
            <CodeBlock code={domainOk ? query : t.query} actions={<span />} />
            <div className="flex flex-wrap gap-1.5">
              <Button size="sm" variant="primary" isDisabled={!domainOk} onPress={() => runQuery(query)}>
                <ExternalLink className="size-3.5" />
                Open in Google
              </Button>
              <Button size="sm" variant="tertiary" isDisabled={!domainOk} onPress={() => copyText(query, "Query copied")}>Copy</Button>
              <Button size="sm" variant="ghost" onPress={() => onLoad(domainOk ? query : t.query)}>
                <Upload className="size-3.5" />
                Load into editor
              </Button>
            </div>
          </div>
        )}
      </li>
    );
  };

  return (
    <Panel title="Templates" description={`${DORK_TEMPLATES.length} templates for reviewing your own exposure`} contentClassName="flex flex-col gap-3">
      <SearchInput value={search} onChange={setSearch} placeholder="Search templates" />
      {groups.length === 0 ? (
        <EmptyBlock compact icon={Search} title="No matching templates" />
      ) : (
        <div className="scroll-area -mx-1 max-h-[560px] px-1">
          {groups.map((g) => (
            <div key={g.c} className="mb-3">
              <div className="mb-1 px-1 text-[12px] font-medium text-muted">{DORK_CATEGORY_LABELS[g.c]}</div>
              <ul className="flex flex-col gap-0.5">{g.items.map(renderItem)}</ul>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function SavedAndHistory({ onLoad }: { onLoad: (q: string) => void }) {
  const { runtime } = useApp();
  const [tab, setTab] = useState<"saved" | "history">("saved");
  const saved = useQuery(["dorks"], api.savedDorksList, [], runtime);
  const history = useQuery(["dorks"], () => api.dorkHistoryList(50), [], runtime);
  const [edit, setEdit] = useState<SaveDraft | null>(null);
  const confirm = useConfirm();

  const remove = async (d: SavedDork) => {
    if (!(await confirm.ask({ title: "Delete saved query?", body: `“${d.title}” will be removed. This cannot be undone.`, confirmLabel: "Delete" }))) return;
    try {
      await api.savedDorkDelete(d.id);
      invalidate("dorks");
      notify.success("Query deleted");
    } catch (e) {
      notify.error("Could not delete query", e);
    }
  };
  const clearHistory = async () => {
    if (!(await confirm.ask({ title: "Clear query history?", body: "All recorded Google searches from Dorks Studio will be removed.", confirmLabel: "Clear history" }))) return;
    try {
      await api.dorkHistoryClear();
      invalidate("dorks");
      notify.success("History cleared");
    } catch (e) {
      notify.error("Could not clear history", e);
    }
  };

  return (
    <Panel
      title="Your queries"
      actions={
        tab === "history" && (history.data?.length ?? 0) > 0 ? (
          <Button size="sm" variant="ghost" onPress={clearHistory}>
            <Trash2 className="size-3.5" />
            Clear history
          </Button>
        ) : undefined
      }
    >
      <Tabs selectedKey={tab} onSelectionChange={(k) => setTab(k as "saved" | "history")}>
        <Tabs.ListContainer>
          <Tabs.List aria-label="Saved queries and history" className="h-8">
            <Tabs.Tab id="saved" className="px-2.5 text-[12.5px]">Saved ({saved.data?.length ?? 0})<Tabs.Indicator /></Tabs.Tab>
            <Tabs.Tab id="history" className="px-2.5 text-[12.5px]">History<Tabs.Indicator /></Tabs.Tab>
          </Tabs.List>
        </Tabs.ListContainer>
        <Tabs.Panel id="saved" className="pt-3">
          <QueryView
            query={saved}
            rows={3}
            isEmpty={(d) => d.length === 0}
            empty={<EmptyBlock compact icon={Save} title="No saved queries" description="Build a query and choose Save to keep it here." />}
          >
            {(items) => (
              <ul className="flex flex-col gap-2">
                {items.map((d) => (
                  <li key={d.id} className="tile p-2.5">
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="truncate text-[13px]">{d.title}</div>
                        <div className="text-[11.5px] text-muted">
                          {DORK_CATEGORY_LABELS[d.category as DorkCategory] ?? "Custom"} · updated {formatRelative(d.updatedAt)}
                        </div>
                      </div>
                      <div className="flex shrink-0 gap-0.5">
                        <Tooltip delay={300}>
                          <Button isIconOnly size="sm" variant="ghost" aria-label="Open in Google" onPress={() => runQuery(d.query)}>
                            <ExternalLink className="size-3.5" />
                          </Button>
                          <Tooltip.Content>Open in Google</Tooltip.Content>
                        </Tooltip>
                        <CopyButton text={d.query} label="Copy query" />
                        <Tooltip delay={300}>
                          <Button isIconOnly size="sm" variant="ghost" aria-label="Load into editor" onPress={() => onLoad(d.query)}>
                            <Upload className="size-3.5" />
                          </Button>
                          <Tooltip.Content>Load into editor</Tooltip.Content>
                        </Tooltip>
                        <Tooltip delay={300}>
                          <Button isIconOnly size="sm" variant="ghost" aria-label="Edit" onPress={() => setEdit({ id: d.id, title: d.title, query: d.query, category: d.category, notes: d.notes })}>
                            <Pencil className="size-3.5" />
                          </Button>
                          <Tooltip.Content>Edit</Tooltip.Content>
                        </Tooltip>
                        <Tooltip delay={300}>
                          <Button isIconOnly size="sm" variant="ghost" aria-label="Delete" onPress={() => remove(d)}>
                            <Trash2 className="size-3.5" />
                          </Button>
                          <Tooltip.Content>Delete</Tooltip.Content>
                        </Tooltip>
                      </div>
                    </div>
                    <code data-selectable className="mt-1.5 block font-mono text-[12px] break-all text-foreground">{d.query}</code>
                    {d.notes && <p className="mt-1 text-[12px] text-muted">{d.notes}</p>}
                  </li>
                ))}
              </ul>
            )}
          </QueryView>
        </Tabs.Panel>
        <Tabs.Panel id="history" className="pt-3">
          <QueryView
            query={history}
            rows={3}
            isEmpty={(d) => d.length === 0}
            empty={<EmptyBlock compact icon={History} title="No searches yet" description="Queries you open in Google are recorded here, locally." />}
          >
            {(items) => (
              <ul className="flex flex-col gap-1">
                {items.map((h) => (
                  <li key={h.id} className="tile flex items-center gap-2 py-1 pr-1 pl-2.5">
                    <code data-selectable className="min-w-0 flex-1 truncate font-mono text-[12px]" title={h.query}>{h.query}</code>
                    <span className="shrink-0 text-[11.5px] text-muted">{formatRelative(h.createdAt)}</span>
                    <Tooltip delay={300}>
                      <Button isIconOnly size="sm" variant="ghost" aria-label="Run again" onPress={() => runQuery(h.query)}>
                        <ExternalLink className="size-3.5" />
                      </Button>
                      <Tooltip.Content>Run again</Tooltip.Content>
                    </Tooltip>
                    <CopyButton text={h.query} label="Copy query" />
                    <Tooltip delay={300}>
                      <Button isIconOnly size="sm" variant="ghost" aria-label="Load into editor" onPress={() => onLoad(h.query)}>
                        <Upload className="size-3.5" />
                      </Button>
                      <Tooltip.Content>Load into editor</Tooltip.Content>
                    </Tooltip>
                  </li>
                ))}
              </ul>
            )}
          </QueryView>
        </Tabs.Panel>
      </Tabs>
      <SaveDorkModal draft={edit} onClose={() => setEdit(null)} />
      {confirm.element}
    </Panel>
  );
}

export default function DorksStudio() {
  const { route } = useApp();
  const params = route.params ?? {};
  const [state, setState] = useState<DorkState>(EMPTY_STATE);
  const [mode, setMode] = useState<"visual" | "raw">(params.query ? "raw" : "visual");
  const [raw, setRaw] = useState(params.query ?? "");
  const [saveDraft, setSaveDraft] = useState<SaveDraft | null>(null);

  const built = useMemo(() => buildQuery(state), [state]);
  const query = mode === "raw" ? raw.trim() : built;
  const domainError = state.domain.trim() && !isValidDomain(state.domain) ? "Enter a host name like example.com" : null;

  const loadRaw = (q: string) => {
    setRaw(q);
    setMode("raw");
    document.getElementById("main-scroll")?.scrollTo({ top: 0, behavior: "smooth" });
  };
  const updateRow = (id: string, r: OperatorRow) => setState((s) => ({ ...s, rows: s.rows.map((x) => (x.id === id ? r : x)) }));
  const clear = () => {
    setState(EMPTY_STATE);
    setRaw("");
  };

  return (
    <div>
      <PageHeader
        title="Dorks Studio"
        description="Compose advanced Google search queries to review what search engines have indexed about domains you own or are authorized to assess."
      />
      <div className="panel-inset mb-4 flex items-start gap-2.5 px-3.5 py-2.5 text-[13px] text-muted">
        <Info className="mt-0.5 size-4 shrink-0 text-accent-soft-foreground" />
        <span>
          Dorks only search Google's existing index. They don't scan or probe anything and are not a vulnerability scanner. Results open in your browser, and only the query
          is shared with Google.
        </span>
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
        <div className="flex min-w-0 flex-col gap-3 xl:col-span-7">
          <Panel
            title="Query builder"
            actions={
              <Tabs selectedKey={mode} onSelectionChange={(k) => setMode(k as "visual" | "raw")}>
                <Tabs.ListContainer>
                  <Tabs.List aria-label="Editor mode" className="h-8">
                    <Tabs.Tab id="visual" className="px-2.5 text-[12.5px]">Visual<Tabs.Indicator /></Tabs.Tab>
                    <Tabs.Tab id="raw" className="px-2.5 text-[12.5px]">Raw query<Tabs.Indicator /></Tabs.Tab>
                  </Tabs.List>
                </Tabs.ListContainer>
              </Tabs>
            }
            contentClassName="flex flex-col gap-3"
          >
            {mode === "visual" ? (
              <>
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <TextInput
                    label="Domain"
                    mono
                    value={state.domain}
                    onChange={(v) => setState({ ...state, domain: v })}
                    placeholder="example.com"
                    error={domainError}
                    description="Adds site: and fills {domain} in templates"
                  />
                  <TextInput label="Exact phrase" value={state.phrase} onChange={(v) => setState({ ...state, phrase: v })} placeholder="internal use only" description="Wrapped in quotes" />
                </div>
                <TextInput label="Keywords" value={state.keywords} onChange={(v) => setState({ ...state, keywords: v })} placeholder="annual report" description="Added as-is" />
                <div className="flex flex-col gap-2">
                  <div className="flex items-center justify-between">
                    <span className="text-[12.5px] font-medium text-muted">Operators</span>
                    <Button size="sm" variant="tertiary" onPress={() => setState((s) => ({ ...s, rows: [...s.rows, newRow()] }))}>
                      <Plus className="size-3.5" />
                      Add operator
                    </Button>
                  </div>
                  {state.rows.length === 0 ? (
                    <div className="tile px-3 py-4 text-center text-[12.5px] text-muted">
                      Add site:, filetype:, inurl:, intitle:, intext:, before:, after:, exclusions or OR groups.
                    </div>
                  ) : (
                    state.rows.map((r) => (
                      <OperatorRowEditor key={r.id} row={r} onChange={(nr) => updateRow(r.id, nr)} onRemove={() => setState((s) => ({ ...s, rows: s.rows.filter((x) => x.id !== r.id) }))} />
                    ))
                  )}
                </div>
              </>
            ) : (
              <TextAreaInput
                label="Raw query"
                mono
                rows={5}
                value={raw}
                onChange={setRaw}
                placeholder='site:example.com (filetype:pdf OR filetype:docx) intext:"confidential"'
                description="Edit freely. Switching back to Visual keeps the builder state separate."
              />
            )}
          </Panel>

          <Panel title="Preview" description={query ? `${query.length} characters` : "Your query appears here as you build it"} contentClassName="flex flex-col gap-3">
            <CodeBlock code={query} actions={<CopyButton text={query} label="Copy query" />} />
            <div className="flex flex-wrap gap-2">
              <Button variant="primary" isDisabled={!query} onPress={() => runQuery(query)}>
                <ExternalLink className="size-4" />
                Open in Google
              </Button>
              <Button variant="tertiary" isDisabled={!query} onPress={() => copyText(query, "Query copied")}>Copy query</Button>
              <Button variant="tertiary" isDisabled={!query} onPress={() => setSaveDraft({ title: "", query, category: "custom", notes: "" })}>
                <Save className="size-4" />
                Save
              </Button>
              {mode === "visual" && built && (
                <Button variant="ghost" onPress={() => loadRaw(built)}>Edit as raw</Button>
              )}
              <Button variant="ghost" className="ml-auto" isDisabled={!query && !state.rows.length} onPress={clear}>Clear</Button>
            </div>
          </Panel>

          <SavedAndHistory onLoad={loadRaw} />
        </div>

        <div className="min-w-0 xl:col-span-5">
          <TemplatesPanel domain={state.domain} onLoad={loadRaw} initialId={params.template} />
        </div>
      </div>
      <SaveDorkModal draft={saveDraft} onClose={() => setSaveDraft(null)} />
    </div>
  );
}
