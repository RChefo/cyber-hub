// SPDX-License-Identifier: Apache-2.0
import { Button, Tabs } from "@heroui/react";
import { History, Pencil, Play, Plus, Save, SquareTerminal, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { DETECTION_META, StatusDot, osLabel } from "@/components/ui/Badges";
import { CodeBlock, CopyButton } from "@/components/ui/Code";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, QueryView } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { COMMAND_TEMPLATES, COMMAND_TEMPLATE_CATEGORIES } from "@/data/commandTemplates";
import { copyAndOpenTerminal, copyCommand, notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { SavedCommand } from "@/lib/types";
import { cn, fillPlaceholders, formatRelative, placeholdersIn, shellQuote } from "@/lib/utils";
import { RunDialog } from "@/modules/runs/RunDialog";
import { BUILDERS, defaultValues, type BuilderDef, type Values } from "./builders";

type Tab = "builders" | "templates" | "saved" | "history";

const SAVED_CATEGORIES = [
  { id: "general", label: "General" },
  { id: "network", label: "Network" },
  { id: "web", label: "Web" },
  { id: "recon", label: "Recon" },
  { id: "password", label: "Password auditing" },
  { id: "forensics", label: "Forensics" },
  { id: "system", label: "System" },
];
const OS_OPTIONS = [
  { id: "any", label: "Any OS" },
  { id: "windows", label: "Windows" },
  { id: "macos", label: "macOS" },
  { id: "linux", label: "Linux" },
];

/* ─────────────── save dialog (shared) ─────────────── */

interface SaveDraft {
  id?: number;
  title: string;
  command: string;
  description: string;
  categoryId: string;
  os: SavedCommand["os"];
  tags: string;
}

function SaveCommandDialog({ draft, onClose }: { draft: SaveDraft | null; onClose: () => void }) {
  const [d, setD] = useState<SaveDraft | null>(draft);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  useEffect(() => {
    setD(draft);
    setError(null);
  }, [draft]);
  if (!d) return null;
  const save = async () => {
    setSaving(true);
    try {
      await api.savedCommandUpsert({ ...d, tags: d.tags.split(",").map((t) => t.trim()).filter(Boolean) });
      invalidate("commands", "activity");
      notify.success(d.id ? "Command updated" : "Command saved");
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };
  return (
    <AppModal
      isOpen={!!draft}
      onOpenChange={(o) => !o && onClose()}
      title={d.id ? "Edit saved command" : "Save command"}
      footer={
        <>
          <Button variant="tertiary" onPress={onClose}>Cancel</Button>
          <Button variant="primary" isPending={saving} onPress={save}>
            <Save className="size-3.5" />
            {d.id ? "Save changes" : "Save command"}
          </Button>
        </>
      }
    >
      <TextInput label="Title" value={d.title} onChange={(v) => setD({ ...d, title: v })} placeholder="Full TCP scan of lab network" isRequired autoFocus />
      <TextAreaInput label="Command" value={d.command} onChange={(v) => setD({ ...d, command: v })} rows={3} mono description="Use {{name}} placeholders to fill values when copying." />
      <TextAreaInput label="Description" value={d.description} onChange={(v) => setD({ ...d, description: v })} rows={2} />
      <div className="grid grid-cols-2 gap-3">
        <SelectInput label="Category" value={d.categoryId} onChange={(v) => setD({ ...d, categoryId: v })} options={SAVED_CATEGORIES} />
        <SelectInput label="Operating system" value={d.os} onChange={(v) => setD({ ...d, os: v as SavedCommand["os"] })} options={OS_OPTIONS} />
      </div>
      <TextInput label="Tags" value={d.tags} onChange={(v) => setD({ ...d, tags: v })} placeholder="scan, lab" description="Comma-separated." />
      {error && <div className="text-[13px] text-danger-soft-foreground" role="alert">{error}</div>}
    </AppModal>
  );
}

/* ─────────────── builders ─────────────── */

function BuilderForm({ def, projectId }: { def: BuilderDef; projectId: number | null }) {
  const { detections, os } = useApp();
  const [values, setValues] = useState<Values>(() => defaultValues(def));
  const [runOpen, setRunOpen] = useState(false);
  const [saveDraft, setSaveDraft] = useState<SaveDraft | null>(null);
  useEffect(() => setValues(defaultValues(def)), [def]);

  const result = useMemo(() => def.build(values), [def, values]);
  const preview = [def.toolId, ...result.args.map(shellQuote)].join(" ");
  const det = detections.get(def.toolId);
  const installed = det?.status === "installed" || det?.status === "dependency_missing";
  const meta = DETECTION_META[det?.status ?? "unknown"];
  const valid = result.errors.length === 0;
  const set = (k: string, v: string | boolean) => setValues((prev) => ({ ...prev, [k]: v }));

  return (
    <div className="grid grid-cols-1 items-start gap-3 xl:grid-cols-[minmax(0,1fr)_minmax(380px,0.8fr)]">
      <Panel title={`${def.name} options`} description={def.description}>
        <div className="grid grid-cols-1 gap-x-4 gap-y-3.5 md:grid-cols-2">
          {def.fields
            .filter((f) => f.type !== "switch")
            .map((f) =>
              f.type === "select" ? (
                <SelectInput key={f.name} label={f.label} value={String(values[f.name] ?? "")} onChange={(v) => set(f.name, v)} options={f.options ?? []} />
              ) : (
                <TextInput
                  key={f.name}
                  label={f.label + (f.required ? "" : " (optional)")}
                  value={String(values[f.name] ?? "")}
                  onChange={(v) => set(f.name, v)}
                  placeholder={f.placeholder}
                  description={f.description}
                  mono={f.mono}
                  className={f.target ? "md:col-span-2" : undefined}
                />
              ),
            )}
        </div>
        <div className="mt-4 grid grid-cols-1 gap-2.5 md:grid-cols-2">
          {def.fields
            .filter((f) => f.type === "switch")
            .map((f) => (
              <SwitchInput key={f.name} label={f.label} isSelected={values[f.name] === true} onChange={(v) => set(f.name, v)} />
            ))}
        </div>
      </Panel>

      <Panel
        title="Generated command"
        description="Review before copying or running. Selecting options never executes anything."
        actions={
          <Button size="sm" variant="ghost" onPress={() => setValues(defaultValues(def))}>
            Reset
          </Button>
        }
      >
        <CodeBlock code={preview} actions={<CopyButton text={valid ? preview : ""} label="Copy command" onCopy={(t) => copyCommand(t, "builder", def.toolId, projectId)} />} />
        {result.errors.length > 0 && (
          <ul className="mt-3 flex flex-col gap-1 text-[12.5px] text-warning-soft-foreground" role="alert">
            {result.errors.map((e) => (
              <li key={e}>• {e}</li>
            ))}
          </ul>
        )}
        {result.targets.length > 0 && (
          <div className="mt-3 text-[12.5px] text-muted">
            Targets checked against the project scope when run: <span className="font-mono text-foreground">{result.targets.join(", ")}</span>
          </div>
        )}
        <div className="mt-4 flex flex-wrap gap-2">
          <Button size="sm" variant="primary" isDisabled={!valid || !installed} onPress={() => setRunOpen(true)}>
            <Play className="size-3.5" />
            Run…
          </Button>
          <Button size="sm" variant="tertiary" isDisabled={!valid} onPress={() => copyCommand(preview, "builder", def.toolId, projectId)}>
            Copy
          </Button>
          <Button size="sm" variant="tertiary" isDisabled={!valid} onPress={() => copyAndOpenTerminal(preview, "builder", def.toolId)}>
            <SquareTerminal className="size-3.5" />
            Copy & open terminal
          </Button>
          <Button
            size="sm"
            variant="ghost"
            isDisabled={!valid}
            onPress={() => setSaveDraft({ title: `${def.name} — ${result.targets[0] ?? "command"}`, command: preview, description: "", categoryId: def.id === "nmap" ? "network" : def.id === "subfinder" || def.id === "httpx" ? "recon" : "web", os: "any", tags: def.id })}
          >
            <Save className="size-3.5" />
            Save
          </Button>
        </div>
        <div className="mt-3 flex items-center gap-2 text-[12.5px] text-muted">
          <StatusDot tone={meta.tone} />
          {installed ? `${def.name} ${det?.version ? `v${det.version} ` : ""}found at ${det?.path}` : `${def.name}: ${meta.label.toLowerCase()} on this ${osLabel(os)} system — running is disabled, copying still works.`}
        </div>
      </Panel>

      <RunDialog isOpen={runOpen} onOpenChange={setRunOpen} toolId={def.toolId} initialArgs={result.args} initialTargets={result.targets} initialProjectId={projectId} />
      <SaveCommandDialog draft={saveDraft} onClose={() => setSaveDraft(null)} />
    </div>
  );
}

function BuildersTab({ projectId }: { projectId: number | null }) {
  const { route, navigate } = useApp();
  const id = route.params?.builder ?? "nmap";
  const def = BUILDERS.find((b) => b.id === id) ?? BUILDERS[0];
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap gap-1.5" role="tablist" aria-label="Command builders">
        {BUILDERS.map((b) => (
          <Button
            key={b.id}
            size="sm"
            variant={b.id === def.id ? "primary" : "tertiary"}
            onPress={() => navigate("commands", { ...(route.params ?? {}), tab: "builders", builder: b.id })}
            aria-pressed={b.id === def.id}
          >
            {b.name}
          </Button>
        ))}
      </div>
      <BuilderForm key={def.id} def={def} projectId={projectId} />
    </div>
  );
}

/* ─────────────── templates ─────────────── */

function TemplatesTab() {
  const { os, route } = useApp();
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("all");
  const [onlyMyOs, setOnlyMyOs] = useState(true);
  const [selectedId, setSelectedId] = useState<string>(route.params?.template ?? "");
  const [vars, setVars] = useState<Record<string, string>>({});
  const [saveDraft, setSaveDraft] = useState<SaveDraft | null>(null);

  const list = COMMAND_TEMPLATES.filter((t) => {
    if (category !== "all" && t.category !== category) return false;
    if (onlyMyOs && t.os !== "any" && t.os !== os) return false;
    const q = query.toLowerCase();
    return !q || `${t.title} ${t.template} ${t.description} ${t.tool ?? ""}`.toLowerCase().includes(q);
  });
  const selected = COMMAND_TEMPLATES.find((t) => t.id === selectedId) ?? list[0];

  useEffect(() => {
    if (!selected) return;
    const init: Record<string, string> = {};
    for (const v of selected.variables) init[v.name] = v.default ?? "";
    setVars(init);
  }, [selected?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  const filled = selected ? fillPlaceholders(selected.template, vars) : "";
  const missing = selected ? placeholdersIn(filled) : [];

  return (
    <div className="grid grid-cols-1 gap-3 xl:grid-cols-[minmax(320px,420px)_1fr]">
      <Panel title="Templates" description={`${list.length} of ${COMMAND_TEMPLATES.length}`} contentClassName="px-2 pb-2">
        <div className="flex flex-col gap-2 px-2 pb-2">
          <SearchInput value={query} onChange={setQuery} placeholder="Search templates" />
          <div className="flex items-center gap-2">
            <SelectInput aria-label="Category" value={category} onChange={setCategory} options={[{ id: "all", label: "All categories" }, ...COMMAND_TEMPLATE_CATEGORIES.map((c) => ({ id: c, label: c }))]} className="flex-1" />
          </div>
          <SwitchInput label={`Only ${osLabel(os)} and cross-platform`} isSelected={onlyMyOs} onChange={setOnlyMyOs} />
        </div>
        <ul className="scroll-area flex max-h-[calc(100vh-380px)] flex-col gap-0.5">
          {list.map((t) => (
            <li key={t.id}>
              <button
                type="button"
                onClick={() => setSelectedId(t.id)}
                className={cn(
                  "w-full rounded-lg px-2.5 py-2 text-left outline-none transition-colors focus-visible:ring-2 focus-visible:ring-focus",
                  selected?.id === t.id ? "bg-white/[0.06]" : "hover:bg-white/[0.03]",
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="truncate text-[13.5px]">{t.title}</span>
                  <span className="shrink-0 text-[11.5px] text-muted">{osLabel(t.os)}</span>
                </div>
                <div className="truncate font-mono text-[11.5px] text-muted">{t.template}</div>
              </button>
            </li>
          ))}
          {list.length === 0 && <EmptyBlock compact icon={SquareTerminal} title="No templates match" />}
        </ul>
      </Panel>

      {selected && (
        <Panel title={selected.title} description={`${selected.category} · ${osLabel(selected.os)} — ${selected.description}`}>
          {selected.variables.length > 0 && (
            <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-2">
              {selected.variables.map((v) => (
                <TextInput key={v.name} label={v.label} value={vars[v.name] ?? ""} onChange={(x) => setVars((p) => ({ ...p, [v.name]: x }))} placeholder={v.placeholder} mono />
              ))}
            </div>
          )}
          <CodeBlock code={filled} actions={<CopyButton text={filled} label="Copy command" onCopy={(t) => copyCommand(t, "template", selected.tool)} />} />
          {missing.length > 0 && <div className="mt-2 text-[12.5px] text-warning-soft-foreground">Fill in: {missing.join(", ")}</div>}
          <div className="mt-3 flex flex-wrap gap-2">
            <Button size="sm" variant="tertiary" onPress={() => copyCommand(filled, "template", selected.tool)}>Copy</Button>
            <Button size="sm" variant="tertiary" onPress={() => copyAndOpenTerminal(filled, "template", selected.tool)}>
              <SquareTerminal className="size-3.5" />
              Copy & open terminal
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onPress={() => setSaveDraft({ title: selected.title, command: selected.template, description: selected.description, categoryId: "general", os: selected.os, tags: selected.tool ?? "" })}
            >
              <Save className="size-3.5" />
              Save as my command
            </Button>
          </div>
          <h3 className="mt-5 mb-2 text-[13.5px] font-medium">What each part does</h3>
          <dl className="flex flex-col gap-1.5">
            {selected.explanation.map((e) => (
              <div key={e.part} className="tile grid grid-cols-[minmax(110px,auto)_1fr] gap-3 px-3 py-2 text-[13px]">
                <dt className="font-mono text-[12px] text-accent-soft-foreground">{e.part}</dt>
                <dd className="text-muted">{e.meaning}</dd>
              </div>
            ))}
          </dl>
          <p className="mt-3 text-[12px] text-muted">Templates are copied, not executed: they may use shell features (pipes, redirection) that the execution engine deliberately does not support.</p>
        </Panel>
      )}
      <SaveCommandDialog draft={saveDraft} onClose={() => setSaveDraft(null)} />
    </div>
  );
}

/* ─────────────── saved ─────────────── */

function SavedTab() {
  const { runtime, route } = useApp();
  const q = useQuery(["commands"], api.savedCommandsList, [], runtime);
  const [query, setQuery] = useState("");
  const [draft, setDraft] = useState<SaveDraft | null>(null);
  const [vars, setVars] = useState<Record<number, Record<string, string>>>({});
  const confirm = useConfirm();
  const highlight = route.params?.saved ? Number(route.params.saved) : null;

  return (
    <Panel
      title="Saved commands"
      description="Your own command library, stored locally."
      actions={
        <Button size="sm" variant="primary" onPress={() => setDraft({ title: "", command: "", description: "", categoryId: "general", os: "any", tags: "" })}>
          <Plus className="size-3.5" />
          New command
        </Button>
      }
    >
      <SearchInput value={query} onChange={setQuery} placeholder="Search saved commands" className="mb-3 max-w-[360px]" />
      <QueryView
        query={q}
        isEmpty={(d) => d.length === 0}
        empty={<EmptyBlock icon={Save} title="No saved commands" description="Save commands from builders and templates, or write your own." />}
      >
        {(items) => (
          <ul className="flex flex-col gap-2.5">
            {items
              .filter((c) => !query || `${c.title} ${c.command} ${c.tags.join(" ")}`.toLowerCase().includes(query.toLowerCase()))
              .map((c) => {
                const names = placeholdersIn(c.command);
                const filled = fillPlaceholders(c.command, vars[c.id] ?? {});
                return (
                  <li key={c.id} className={cn("tile flex flex-col gap-2 p-3", highlight === c.id && "bg-accent-soft")}>
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="text-[13.5px] font-medium">{c.title}</div>
                        <div className="text-[12px] text-muted">
                          {SAVED_CATEGORIES.find((x) => x.id === c.categoryId)?.label} · {osLabel(c.os)}
                          {c.tags.length > 0 && ` · ${c.tags.join(", ")}`} · updated {formatRelative(c.updatedAt)}
                        </div>
                      </div>
                      <div className="flex shrink-0 gap-0.5">
                        <Button isIconOnly size="sm" variant="ghost" aria-label="Edit command" onPress={() => setDraft({ id: c.id, title: c.title, command: c.command, description: c.description, categoryId: c.categoryId, os: c.os, tags: c.tags.join(", ") })}>
                          <Pencil className="size-3.5" />
                        </Button>
                        <Button
                          isIconOnly
                          size="sm"
                          variant="ghost"
                          aria-label="Delete command"
                          onPress={async () => {
                            if (await confirm.ask({ title: `Delete “${c.title}”?`, body: "This saved command will be removed.", confirmLabel: "Delete" })) {
                              await api.savedCommandDelete(c.id).catch((e) => notify.error("Could not delete", e));
                              invalidate("commands");
                            }
                          }}
                        >
                          <Trash2 className="size-3.5" />
                        </Button>
                      </div>
                    </div>
                    {c.description && <p className="text-[12.5px] text-muted">{c.description}</p>}
                    {names.length > 0 && (
                      <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
                        {names.map((n) => (
                          <TextInput key={n} aria-label={n} placeholder={n} value={vars[c.id]?.[n] ?? ""} onChange={(v) => setVars((p) => ({ ...p, [c.id]: { ...(p[c.id] ?? {}), [n]: v } }))} mono />
                        ))}
                      </div>
                    )}
                    <CodeBlock code={filled} actions={<CopyButton text={filled} label="Copy command" onCopy={(t) => copyCommand(t, "saved")} />} />
                  </li>
                );
              })}
          </ul>
        )}
      </QueryView>
      <SaveCommandDialog draft={draft} onClose={() => setDraft(null)} />
      {confirm.element}
    </Panel>
  );
}

/* ─────────────── history ─────────────── */

function HistoryTab() {
  const { runtime, toolById } = useApp();
  const q = useQuery(["history"], () => api.commandHistoryList(300), [], runtime);
  const confirm = useConfirm();
  return (
    <Panel
      title="Command history"
      description="Commands you copied, built, saved or executed."
      actions={
        <Button
          size="sm"
          variant="tertiary"
          isDisabled={!q.data?.length}
          onPress={async () => {
            if (await confirm.ask({ title: "Clear command history?", body: "All recorded commands are deleted. Saved commands are kept.", confirmLabel: "Clear history" })) {
              await api.commandHistoryClear().catch((e) => notify.error("Could not clear history", e));
              invalidate("history");
            }
          }}
        >
          <Trash2 className="size-3.5" />
          Clear
        </Button>
      }
    >
      <QueryView query={q} isEmpty={(d) => d.length === 0} empty={<EmptyBlock icon={History} title="No commands yet" description="Copy a command from a builder or template and it will appear here." />}>
        {(items) => (
          <ul className="flex flex-col gap-1.5">
            {items.map((h) => (
              <li key={h.id} className="flex items-center gap-3 rounded-lg bg-background-secondary py-1.5 pr-1.5 pl-3">
                <code data-selectable className="min-w-0 flex-1 truncate font-mono text-[12px]">{h.command}</code>
                <span className="hidden shrink-0 text-[11.5px] text-muted md:inline">
                  {h.source}
                  {h.toolId && ` · ${toolById(h.toolId)?.name ?? h.toolId}`} · {formatRelative(h.createdAt)}
                </span>
                <CopyButton text={h.command} label="Copy command" onCopy={(t) => copyCommand(t, "manual", h.toolId, h.projectId)} />
              </li>
            ))}
          </ul>
        )}
      </QueryView>
      {confirm.element}
    </Panel>
  );
}

/* ─────────────── page ─────────────── */

export default function CommandCenter() {
  const { route, navigate, runtime } = useApp();
  const tab = (route.params?.tab as Tab) ?? (route.params?.template ? "templates" : route.params?.saved ? "saved" : "builders");
  const projects = useQuery(["projects"], api.projectsList, [], runtime);
  const [projectId, setProjectId] = useState<string | null>(null);

  return (
    <div>
      <PageHeader
        title="Command Center"
        description="Build, explain and keep commands. Nothing runs automatically: commands are copied, or executed only after a reviewed and confirmed preview."
        actions={
          <SelectInput
            aria-label="Project context"
            value={projectId}
            onChange={setProjectId}
            placeholder="No project context"
            options={[{ id: "", label: "No project context" }, ...(projects.data ?? []).map((p) => ({ id: String(p.id), label: p.name, description: p.status }))]}
            className="w-[240px]"
          />
        }
      />
      <Tabs selectedKey={tab} onSelectionChange={(k) => navigate("commands", { tab: String(k) })}>
        <Tabs.ListContainer className="mb-4">
          <Tabs.List aria-label="Command Center sections">
            <Tabs.Tab id="builders">Builders<Tabs.Indicator /></Tabs.Tab>
            <Tabs.Tab id="templates">Templates<Tabs.Indicator /></Tabs.Tab>
            <Tabs.Tab id="saved">Saved<Tabs.Indicator /></Tabs.Tab>
            <Tabs.Tab id="history">History<Tabs.Indicator /></Tabs.Tab>
          </Tabs.List>
        </Tabs.ListContainer>
        <Tabs.Panel id="builders"><BuildersTab projectId={projectId ? Number(projectId) : null} /></Tabs.Panel>
        <Tabs.Panel id="templates"><TemplatesTab /></Tabs.Panel>
        <Tabs.Panel id="saved"><SavedTab /></Tabs.Panel>
        <Tabs.Panel id="history"><HistoryTab /></Tabs.Panel>
      </Tabs>
    </div>
  );
}
