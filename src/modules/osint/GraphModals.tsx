/** Graph Manager, Save As, version history and comparison dialogs of the link-analysis workspace. */
import { Button, Checkbox, Label } from "@heroui/react";
import { Copy, FolderOpen, History, Pencil, Plus, RotateCcw, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput, SwitchInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { ToneChip } from "@/components/ui/Badges";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import { cn } from "@/lib/utils";
import { diffIsEmpty, plural, shortTime, versionSummary } from "./model";
import type { Diff, GraphMeta, VersionRow } from "./types";

export function Check({ label, isSelected, onChange, description }: { label: ReactNode; isSelected: boolean; onChange: (v: boolean) => void; description?: string }) {
  return (
    <Checkbox isSelected={isSelected} onChange={onChange}>
      <Checkbox.Content className="flex items-start gap-2">
        <Checkbox.Control className="mt-0.5">
          <Checkbox.Indicator />
        </Checkbox.Control>
        <div className="flex flex-col">
          <Label className="text-[13px] font-normal text-foreground">{label}</Label>
          {description && <span className="text-[12px] text-muted">{description}</span>}
        </div>
      </Checkbox.Content>
    </Checkbox>
  );
}

/* ───────────────────────── name dialog (Save As, New, Rename, Duplicate) ───────────────────────── */

export function NameDialog({
  isOpen,
  onOpenChange,
  title,
  description,
  initialName,
  initialDescription,
  showFollow,
  initialFollow = false,
  confirmLabel,
  onConfirm,
}: {
  isOpen: boolean;
  onOpenChange: (o: boolean) => void;
  title: string;
  description?: string;
  initialName: string;
  initialDescription?: string;
  showFollow?: boolean;
  initialFollow?: boolean;
  confirmLabel: string;
  onConfirm: (name: string, description: string, followNew: boolean) => Promise<void>;
}) {
  const [name, setName] = useState(initialName);
  const [desc, setDesc] = useState(initialDescription ?? "");
  const [follow, setFollow] = useState(initialFollow);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (isOpen) {
      setName(initialName);
      setDesc(initialDescription ?? "");
      setFollow(initialFollow);
      setError(null);
    }
  }, [isOpen, initialName, initialDescription, initialFollow]);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await onConfirm(name.trim(), desc, follow);
      onOpenChange(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <AppModal
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      title={title}
      description={description}
      footer={
        <>
          <Button variant="tertiary" onPress={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={submit} isPending={busy} isDisabled={!name.trim()}>
            {confirmLabel}
          </Button>
        </>
      }
    >
      <TextInput label="Name" value={name} onChange={setName} isRequired autoFocus onEnter={submit} error={error} />
      {initialDescription !== undefined && <TextAreaInput label="Description" value={desc} onChange={setDesc} rows={3} />}
      {showFollow && (
        <SwitchInput
          label="Add newly collected entities automatically"
          isSelected={follow}
          onChange={setFollow}
          description="When off, the graph only changes when you add entities to it."
        />
      )}
    </AppModal>
  );
}

/* ───────────────────────── Graph Manager ───────────────────────── */

export function GraphManager({
  isOpen,
  onOpenChange,
  investigationId,
  currentId,
  onOpen,
}: {
  isOpen: boolean;
  onOpenChange: (o: boolean) => void;
  investigationId: number;
  currentId: number | null;
  onOpen: (id: number) => void;
}) {
  const graphs = useQuery(["osint"], () => api.osintGraphs(investigationId), [investigationId], isOpen);
  const [q, setQ] = useState("");
  const [dialog, setDialog] = useState<{ kind: "new" } | { kind: "rename" | "duplicate"; graph: GraphMeta } | null>(null);
  const list = useMemo(() => {
    const s = q.trim().toLowerCase();
    return (graphs.data ?? []).filter((g) => !s || g.name.toLowerCase().includes(s) || g.description.toLowerCase().includes(s));
  }, [graphs.data, q]);

  const remove = async (g: GraphMeta) => {
    try {
      if (await api.osintGraphDelete(g.id)) {
        invalidate("osint");
        notify.success(`Graph “${g.name}” deleted`);
      }
    } catch (e) {
      notify.error("Could not delete the graph", e);
    }
  };

  return (
    <>
      <AppModal
        isOpen={isOpen && !dialog}
        onOpenChange={onOpenChange}
        size="lg"
        title="Saved graphs"
        description="Each graph keeps its own layout, filters, groups and version history. Entities and evidence belong to the investigation and are shared by its graphs."
        footer={
          <Button variant="secondary" onPress={() => setDialog({ kind: "new" })}>
            <Plus className="size-3.5" />
            New graph
          </Button>
        }
      >
        <SearchInput value={q} onChange={setQ} placeholder="Search graphs" />
        {graphs.error && !graphs.data ? (
          <ErrorBlock message={graphs.error} onRetry={graphs.reload} />
        ) : !graphs.data ? (
          <LoadingRows rows={4} />
        ) : list.length === 0 ? (
          <EmptyBlock icon={FolderOpen} compact title="No graphs match" description="Create a graph, or save the current one under a new name." />
        ) : (
          <ul className="flex flex-col gap-1.5">
            {list.map((g) => (
              <li key={g.id} className={cn("flex items-center gap-3 rounded-lg px-3 py-2.5", g.id === currentId ? "bg-accent-soft" : "bg-white/[0.03]")}>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-[13.5px] font-medium">{g.name}</span>
                    {g.id === currentId && <ToneChip tone="accent">Open</ToneChip>}
                    {g.followNew && (
                      <span className="text-[11.5px] text-muted" title="Newly collected entities are added automatically">
                        follows new data
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 truncate text-[12px] text-muted">
                    {plural(g.entityCount, "entity", "entities")} · {plural(g.relationshipCount, "relationship", "relationships")} · {plural(g.versionCount, "version", "versions")} · updated{" "}
                    {shortTime(g.updatedAt)}
                    {g.lastOpenedAt ? ` · opened ${shortTime(g.lastOpenedAt)}` : ""}
                  </div>
                  {g.description && <div className="mt-0.5 truncate text-[12px] text-muted">{g.description}</div>}
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <Button size="sm" variant={g.id === currentId ? "tertiary" : "primary"} onPress={() => onOpen(g.id)} isDisabled={g.id === currentId}>
                    Open
                  </Button>
                  <Button isIconOnly size="sm" variant="ghost" aria-label={`Rename ${g.name}`} onPress={() => setDialog({ kind: "rename", graph: g })}>
                    <Pencil className="size-3.5" />
                  </Button>
                  <Button isIconOnly size="sm" variant="ghost" aria-label={`Duplicate ${g.name}`} onPress={() => setDialog({ kind: "duplicate", graph: g })}>
                    <Copy className="size-3.5" />
                  </Button>
                  <Button isIconOnly size="sm" variant="ghost" aria-label={`Delete ${g.name}`} onPress={() => remove(g)} isDisabled={g.id === currentId && (graphs.data?.length ?? 0) <= 1}>
                    <Trash2 className="size-3.5" />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </AppModal>
      <NameDialog
        isOpen={dialog?.kind === "new"}
        onOpenChange={(o) => !o && setDialog(null)}
        title="New graph"
        description="Starts empty; add entities from search, the inspector or the Entities tab."
        initialName="Untitled graph"
        initialDescription=""
        showFollow
        confirmLabel="Create graph"
        onConfirm={async (name, description, follow) => {
          const id = await api.osintGraphCreate(investigationId, name, description, follow);
          invalidate("osint");
          setDialog(null);
          onOpen(id);
        }}
      />
      <NameDialog
        isOpen={dialog?.kind === "rename"}
        onOpenChange={(o) => !o && setDialog(null)}
        title="Rename graph"
        initialName={dialog && dialog.kind !== "new" ? dialog.graph.name : ""}
        initialDescription={dialog && dialog.kind !== "new" ? dialog.graph.description : ""}
        showFollow
        initialFollow={dialog && dialog.kind !== "new" ? dialog.graph.followNew : false}
        confirmLabel="Save"
        onConfirm={async (name, description, follow) => {
          if (!dialog || dialog.kind === "new") return;
          await api.osintGraphRename(dialog.graph.id, name, description, follow);
          invalidate("osint");
          notify.success("Graph updated");
        }}
      />
      <NameDialog
        isOpen={dialog?.kind === "duplicate"}
        onOpenChange={(o) => !o && setDialog(null)}
        title="Duplicate graph"
        description="Copies the saved state (layout, filters, groups) into an independent graph with its own history."
        initialName={dialog && dialog.kind !== "new" ? `${dialog.graph.name} (copy)` : ""}
        confirmLabel="Duplicate"
        onConfirm={async (name) => {
          if (!dialog || dialog.kind === "new") return;
          const id = await api.osintGraphDuplicate(dialog.graph.id, name);
          invalidate("osint");
          notify.success("Graph duplicated");
          setDialog(null);
          onOpen(id);
        }}
      />
    </>
  );
}

/* ───────────────────────── versions ───────────────────────── */

function DiffView({ diff }: { diff: Diff }) {
  if (diffIsEmpty(diff)) return <p className="text-[13px] text-muted">No differences.</p>;
  const block = (title: string, items: string[]) =>
    items.length > 0 && (
      <div>
        <div className="text-[12.5px] font-medium text-muted">
          {title} ({items.length})
        </div>
        <ul className="mt-1 flex max-h-40 flex-col gap-0.5 overflow-y-auto text-[12.5px]">
          {items.slice(0, 200).map((t, i) => (
            <li key={i} className="break-words">
              {t}
            </li>
          ))}
        </ul>
      </div>
    );
  return (
    <div className="flex flex-col gap-3">
      {block("Entities added", diff.entitiesAdded.map(([, t, v]) => `${t} ${v}`))}
      {block("Entities removed", diff.entitiesRemoved.map(([, t, v]) => `${t} ${v}`))}
      {block("Relationships added", diff.relationshipsAdded.map(([, l]) => l))}
      {block("Relationships removed", diff.relationshipsRemoved.map(([, l]) => l))}
      {block("Review decisions", diff.verificationChanges.map(([, l, a, b]) => `${l}: ${a} → ${b}`))}
      {block("Evidence changes", diff.evidenceChanges.map(([, l, a, b]) => `${l}: ${a} → ${b} evidence records`))}
      {(diff.nodesMoved > 0 || diff.workspaceChanged) && (
        <p className="text-[12.5px] text-muted">
          {diff.nodesMoved > 0 ? `${plural(diff.nodesMoved, "node", "nodes")} moved. ` : ""}
          {diff.workspaceChanged ? "Layout, filters or groups changed." : ""}
        </p>
      )}
    </div>
  );
}

const KIND_LABEL: Record<VersionRow["kind"], string> = { save: "Save", manual: "Checkpoint", restore: "Restore", import: "Import", created: "Created" };

export function VersionsDialog({
  isOpen,
  onOpenChange,
  graph,
  dirty,
  onRestored,
}: {
  isOpen: boolean;
  onOpenChange: (o: boolean) => void;
  graph: GraphMeta;
  dirty: boolean;
  onRestored: () => void;
}) {
  const versions = useQuery(["osint"], () => api.osintVersions(graph.id), [graph.id], isOpen);
  const confirm = useConfirm();
  const [compare, setCompare] = useState<{ a: VersionRow; b: VersionRow | null; diff: Diff | null; error: string | null } | null>(null);
  const [picked, setPicked] = useState<number[]>([]);
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    if (!isOpen) {
      setCompare(null);
      setPicked([]);
    }
  }, [isOpen]);

  const runCompare = async (a: VersionRow, b: VersionRow | null) => {
    setCompare({ a, b, diff: null, error: null });
    try {
      setCompare({ a, b, diff: await api.osintVersionCompare(a.id, b?.id ?? null), error: null });
    } catch (e) {
      setCompare({ a, b, diff: null, error: e instanceof Error ? e.message : String(e) });
    }
  };
  const checkpoint = async () => {
    setBusy(true);
    try {
      const n = await api.osintVersionCreate(graph.id, label.trim() || "Checkpoint");
      setLabel("");
      invalidate("osint");
      notify.success(n ? `Version ${n} created` : "Checkpoint recorded");
    } catch (e) {
      notify.error("Could not create the checkpoint", e);
    } finally {
      setBusy(false);
    }
  };
  const restore = async (v: VersionRow) => {
    const ok = await confirm.ask({
      title: `Restore version ${v.number}`,
      body: `The graph's layout, filters, groups and membership return to version ${v.number}. This is recorded as a new version, so later versions stay available.${dirty ? " Unsaved changes in the workspace are discarded." : ""} Entities and evidence of the investigation are not changed.`,
      confirmLabel: "Restore",
      tone: "accent",
    });
    if (!ok) return;
    try {
      const r = await api.osintVersionRestore(v.id);
      invalidate("osint");
      notify.success(`Restored as version ${r.version}`, r.missing ? `${plural(r.missing, "entity no longer exists", "entities no longer exist")} and could not be restored.` : undefined);
      onRestored();
      onOpenChange(false);
    } catch (e) {
      notify.error("Could not restore the version", e);
    }
  };
  const togglePick = (id: number) => setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p.slice(-1), id]));

  return (
    <>
      <AppModal
        isOpen={isOpen}
        onOpenChange={onOpenChange}
        size="lg"
        title={`Version history: ${graph.name}`}
        description="Every save that changes the graph creates a version; checkpoints and restores are always kept. Restoring creates a new version and never deletes later ones."
        footer={
          <div className="flex w-full flex-wrap items-end justify-between gap-2">
            <div className="flex min-w-0 flex-1 items-end gap-2">
              <TextInput aria-label="Checkpoint label" value={label} onChange={setLabel} placeholder="Checkpoint label (optional)" className="max-w-xs flex-1" />
              <Button variant="secondary" onPress={checkpoint} isPending={busy} isDisabled={dirty}>
                <History className="size-3.5" />
                Create checkpoint
              </Button>
            </div>
            <Button
              variant="secondary"
              isDisabled={picked.length !== 2}
              onPress={() => {
                const rows = (versions.data ?? []).filter((v) => picked.includes(v.id)).sort((x, y) => x.number - y.number);
                if (rows.length === 2) void runCompare(rows[0], rows[1]);
              }}
            >
              Compare selected
            </Button>
          </div>
        }
      >
        {dirty && <p className="rounded-lg bg-warning-soft px-3 py-2 text-[12.5px] text-warning-soft-foreground">The workspace has unsaved changes. Save first to include them in a version.</p>}
        {compare && (
          <div className="rounded-lg bg-white/[0.03] p-3">
            <div className="mb-2 flex items-center justify-between gap-2">
              <div className="text-[13px] font-medium">
                Version {compare.a.number} → {compare.b ? `version ${compare.b.number}` : "current saved state"}
              </div>
              <Button size="sm" variant="ghost" onPress={() => setCompare(null)}>
                Close comparison
              </Button>
            </div>
            {compare.error ? <ErrorBlock message={compare.error} /> : compare.diff ? <DiffView diff={compare.diff} /> : <LoadingRows rows={2} />}
          </div>
        )}
        {versions.error && !versions.data ? (
          <ErrorBlock message={versions.error} onRetry={versions.reload} />
        ) : !versions.data ? (
          <LoadingRows rows={5} />
        ) : versions.data.length === 0 ? (
          <EmptyBlock icon={History} compact title="No versions yet" description="Save the graph to create its first version." />
        ) : (
          <ul className="flex flex-col gap-1.5">
            {versions.data.map((v) => (
              <li key={v.id} className={cn("flex items-center gap-3 rounded-lg px-3 py-2", picked.includes(v.id) ? "bg-accent-soft" : "bg-white/[0.03]")}>
                <Check label={<span className="sr-only">Select version {v.number} for comparison</span>} isSelected={picked.includes(v.id)} onChange={() => togglePick(v.id)} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 text-[13px]">
                    <span className="tabular font-medium">v{v.number}</span>
                    <ToneChip tone={v.kind === "manual" ? "accent" : v.kind === "restore" ? "warning" : "default"} dot={false}>
                      {KIND_LABEL[v.kind] ?? v.kind}
                    </ToneChip>
                    {v.label && <span className="truncate">{v.label}</span>}
                  </div>
                  <div className="mt-0.5 truncate text-[12px] text-muted">
                    {shortTime(v.createdAt)} · {plural(v.entityCount, "entity", "entities")}, {plural(v.relationshipCount, "relationship", "relationships")} · {versionSummary(v)}
                  </div>
                </div>
                <Button size="sm" variant="ghost" onPress={() => runCompare(v, null)}>
                  Compare with current
                </Button>
                <Button size="sm" variant="tertiary" onPress={() => restore(v)}>
                  <RotateCcw className="size-3.5" />
                  Restore
                </Button>
              </li>
            ))}
          </ul>
        )}
      </AppModal>
      {confirm.element}
    </>
  );
}
