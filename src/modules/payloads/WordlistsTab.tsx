// SPDX-License-Identifier: Apache-2.0
import { Button, Tooltip } from "@heroui/react";
import { AlertTriangle, Copy, Download, FileText, FolderOpen, FolderSearch, Plus, Star, Trash2, X } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { AppModal } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows, QueryView } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { copyText, notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { Wordlist } from "@/lib/types";
import { cn, formatBytes, formatNumber, formatRelative } from "@/lib/utils";

export const WORDLIST_CATEGORIES = ["general", "directories", "subdomains", "passwords", "usernames", "parameters", "fuzzing", "api", "custom"] as const;
const CATEGORY_LABELS: Record<string, string> = {
  general: "General",
  directories: "Directories & files",
  subdomains: "Subdomains",
  passwords: "Passwords",
  usernames: "Usernames",
  parameters: "Parameters",
  fuzzing: "Fuzzing",
  api: "API endpoints",
  custom: "Custom",
};
const CATEGORY_OPTIONS = WORDLIST_CATEGORIES.map((c) => ({ id: c, label: CATEGORY_LABELS[c] }));

/**
 * Choose how files are added, then pick them in the native file dialog. The dialog is opened
 * by the backend, so file paths never come from the web view.
 */
function AddFilesModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const [copy, setCopy] = useState(false);
  const [category, setCategory] = useState("auto");
  const [pending, setPending] = useState(false);
  useEffect(() => {
    if (isOpen) {
      setCopy(false);
      setCategory("auto");
    }
  }, [isOpen]);

  const add = async () => {
    setPending(true);
    try {
      const ids = await api.wordlistsPick(copy, category === "auto" ? null : category);
      if (ids.length === 0) return; // dialog cancelled: keep the choices open
      invalidate("wordlists", "activity");
      notify.success(`Added ${ids.length} ${ids.length === 1 ? "wordlist" : "wordlists"}`);
      onClose();
    } catch (e) {
      notify.error("Could not add wordlists", e);
    } finally {
      setPending(false);
    }
  };

  const choice = (value: boolean, title: string, body: string) => (
    <Button
      variant="ghost"
      onPress={() => setCopy(value)}
      aria-pressed={copy === value}
      className={cn("tile h-auto flex-1 flex-col items-start gap-1 px-3 py-2.5 text-left font-normal whitespace-normal", copy === value && "bg-accent-soft hover:bg-accent-soft")}
    >
      <span className="text-[13.5px] font-medium text-foreground">{title}</span>
      <span className="text-[12px] text-muted">{body}</span>
    </Button>
  );

  return (
    <AppModal
      isOpen={isOpen}
      onOpenChange={(o) => !o && onClose()}
      title="Add wordlist files"
      description="Choose how the files are added, then select them in the file dialog. Line counts are calculated locally for files up to 512 MB."
      footer={
        <>
          <Button variant="tertiary" onPress={onClose}>Cancel</Button>
          <Button variant="primary" isPending={pending} onPress={add}>Choose files…</Button>
        </>
      }
    >
      <div className="flex gap-2">
        {choice(false, "Reference in place", "Recommended for large lists such as SecLists or rockyou. ExploitX indexes the file where it is.")}
        {choice(true, "Copy into ExploitX", "Makes a private copy in the managed directory. Copies can later be deleted from disk.")}
      </div>
      <SelectInput label="Category" value={category} options={[{ id: "auto", label: "Detect from file name" }, ...CATEGORY_OPTIONS]} onChange={setCategory} />
    </AppModal>
  );
}

function RemoveModal({ wordlist, onClose }: { wordlist: Wordlist | null; onClose: () => void }) {
  const [deleteFile, setDeleteFile] = useState(false);
  const [pending, setPending] = useState(false);
  useEffect(() => setDeleteFile(false), [wordlist]);
  const remove = async () => {
    if (!wordlist) return;
    setPending(true);
    try {
      await api.wordlistRemove(wordlist.id, wordlist.managed && deleteFile);
      invalidate("wordlists");
      notify.success(deleteFile ? "Wordlist and file deleted" : "Wordlist removed from index");
      onClose();
    } catch (e) {
      notify.error("Could not remove wordlist", e);
    } finally {
      setPending(false);
    }
  };
  return (
    <AppModal
      isOpen={!!wordlist}
      onOpenChange={(o) => !o && onClose()}
      title="Remove wordlist?"
      size="sm"
      footer={
        <>
          <Button variant="tertiary" onPress={onClose}>Cancel</Button>
          <Button variant="danger" isPending={pending} onPress={remove}>{deleteFile ? "Remove and delete file" : "Remove"}</Button>
        </>
      }
    >
      <p className="text-[13.5px] text-muted">
        “{wordlist?.name}” will be removed from the ExploitX index.
        {wordlist && !wordlist.managed && " The file was indexed by reference and stays on disk."}
      </p>
      {wordlist?.managed && <SwitchInput label="Also delete the copy from the managed directory" isSelected={deleteFile} onChange={setDeleteFile} />}
    </AppModal>
  );
}

function PreviewPanel({ wordlist }: { wordlist: Wordlist | undefined }) {
  const [filter, setFilter] = useState("");
  const [applied, setApplied] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setApplied(filter), 250);
    return () => clearTimeout(t);
  }, [filter]);
  useEffect(() => {
    setFilter("");
    setApplied("");
  }, [wordlist?.id]);
  const preview = useQuery(["wordlists"], () => api.wordlistPreview(wordlist!.id, applied || undefined, 500), [wordlist?.id, applied], !!wordlist && wordlist.exists);

  if (!wordlist) {
    return (
      <Panel title="Preview">
        <EmptyBlock compact icon={FileText} title="Select a wordlist" description="Choose a wordlist to preview its first lines or filter its contents." />
      </Panel>
    );
  }
  return (
    <Panel
      title={wordlist.name}
      description={`${formatBytes(wordlist.sizeBytes)} · ${wordlist.lineCount != null ? `${formatNumber(wordlist.lineCount)} lines` : "line count not calculated (file over 512 MB)"}`}
      contentClassName="flex flex-col gap-3"
    >
      {!wordlist.exists ? (
        <ErrorBlock message={`The file no longer exists at ${wordlist.path}. Remove it from the index or restore the file.`} />
      ) : (
        <>
          <TextInput aria-label="Filter lines" value={filter} onChange={setFilter} placeholder="Filter lines (case-insensitive)" mono />
          <QueryView query={preview} rows={8}>
            {(p) => (
              <>
                <div className="text-[12px] text-muted">
                  {p.lines.length} {applied ? "matching " : ""}lines shown · {formatNumber(p.scannedLines)} lines scanned
                  {p.truncated ? " · limited to the first 500 results" : ""}
                </div>
                {p.lines.length === 0 ? (
                  <EmptyBlock compact icon={FileText} title={applied ? "No matching lines" : "File is empty"} />
                ) : (
                  <div className="panel-inset scroll-area max-h-[460px] py-2 font-mono text-[12px] leading-relaxed" data-selectable>
                    {p.lines.map((line, i) => (
                      <div key={i} className="flex gap-3 px-3">
                        <span className="w-10 shrink-0 text-right text-muted/60 select-none">{i + 1}</span>
                        <span className="min-w-0 break-all whitespace-pre-wrap text-foreground">{line || " "}</span>
                      </div>
                    ))}
                  </div>
                )}
              </>
            )}
          </QueryView>
        </>
      )}
    </Panel>
  );
}

export function WordlistsTab({ preselect }: { preselect?: string }) {
  const { runtime, prefs, isFavorite, toggleFavorite } = useApp();
  const list = useQuery(["wordlists"], api.wordlistsList, [], runtime);
  const managedDir = useQuery([], api.wordlistsDir, [], runtime);
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("all");
  const [selected, setSelected] = useState<number | null>(preselect ? Number(preselect) : null);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<Wordlist | null>(null);
  const [scanning, setScanning] = useState(false);
  const extraDir = typeof prefs["wordlists.directory"] === "string" ? (prefs["wordlists.directory"] as string) : "";

  const pickFiles = () => setAdding(true);

  const pickFolder = async () => {
    try {
      const dir = await api.wordlistsChooseDirectory();
      if (dir) {
        invalidate("prefs");
        notify.success("Wordlist folder set", "Choose Scan folders to index its files.");
      }
    } catch (e) {
      notify.error("Could not set the wordlist folder", e);
    }
  };

  const clearFolder = async () => {
    try {
      await api.wordlistsClearDirectory();
      invalidate("prefs");
    } catch (e) {
      notify.error("Could not clear the wordlist folder", e);
    }
  };

  const scan = async () => {
    setScanning(true);
    try {
      const n = await api.wordlistsScan();
      invalidate("wordlists", "activity");
      notify.success(`Indexed ${n} ${n === 1 ? "file" : "files"}`, extraDir ? "Managed directory and your wordlist folder were scanned." : "The managed directory was scanned.");
    } catch (e) {
      notify.error("Scan failed", e);
    } finally {
      setScanning(false);
    }
  };

  const exportList = async (w: Wordlist) => {
    try {
      const bytes = await api.wordlistExport(w.id);
      if (bytes === null) return; // save dialog cancelled
      notify.success("Wordlist exported", `${formatBytes(bytes)} written`);
    } catch (e) {
      notify.error("Export failed", e);
    }
  };

  const updateCategory = async (w: Wordlist, c: string) => {
    try {
      await api.wordlistUpdate(w.id, w.name, c);
      invalidate("wordlists");
    } catch (e) {
      notify.error("Could not update category", e);
    }
  };

  const q = search.toLowerCase().trim();
  const visible = useMemo(
    () =>
      (list.data ?? []).filter((w) => {
        if (category === "favorites") {
          if (!isFavorite("wordlist", String(w.id))) return false;
        } else if (category !== "all" && w.category !== category) return false;
        return !q || `${w.name} ${w.path}`.toLowerCase().includes(q);
      }),
    [list.data, category, q, isFavorite],
  );
  const selectedList = (list.data ?? []).find((w) => w.id === selected);

  useEffect(() => {
    if (preselect) requestAnimationFrame(() => document.getElementById(`wordlist-${preselect}`)?.scrollIntoView({ block: "center" }));
  }, [preselect, list.data]);

  return (
    <div className="flex flex-col gap-3">
      <div className="panel flex flex-wrap items-center gap-3 px-4 py-3">
        <div className="min-w-0 flex-1">
          <div className="text-[12.5px] text-muted">Managed directory</div>
          <div className="flex items-center gap-1">
            <code className="truncate font-mono text-[12.5px] text-foreground" data-selectable title={managedDir.data}>
              {managedDir.data ?? (runtime ? "Loading…" : "Desktop runtime not connected")}
            </code>
            {managedDir.data && <CopyButton text={managedDir.data} label="Copy path" />}
          </div>
          <div className="mt-1 flex items-center gap-1 text-[12px] text-muted">
            {extraDir ? (
              <>
                <span className="truncate">
                  Also scanning <span className="font-mono" data-selectable>{extraDir}</span>
                </span>
                <Tooltip delay={300}>
                  <Button isIconOnly size="sm" variant="ghost" aria-label="Stop scanning this folder" onPress={clearFolder}>
                    <X className="size-3.5" />
                  </Button>
                  <Tooltip.Content>Stop scanning this folder</Tooltip.Content>
                </Tooltip>
              </>
            ) : (
              "Wordlists are never bundled with ExploitX. Add files or point to a folder such as your SecLists checkout."
            )}
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Button size="sm" variant="primary" isDisabled={!runtime} onPress={pickFiles}>
            <Plus className="size-3.5" />
            Add files
          </Button>
          <Button size="sm" variant="tertiary" isDisabled={!runtime} onPress={pickFolder}>
            <FolderOpen className="size-3.5" />
            {extraDir ? "Change folder" : "Choose folder"}
          </Button>
          <Button size="sm" variant="tertiary" isDisabled={!runtime} isPending={scanning} onPress={scan}>
            <FolderSearch className="size-3.5" />
            Scan folders
          </Button>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
        <div className="flex min-w-0 flex-col gap-3 xl:col-span-7">
          <div className="flex flex-wrap gap-2">
            <SearchInput value={search} onChange={setSearch} placeholder="Search wordlists by name or path" className="min-w-[220px] flex-1" />
            <SelectInput
              aria-label="Filter by category"
              className="w-[200px]"
              value={category}
              options={[{ id: "all", label: "All categories" }, { id: "favorites", label: "Favorites" }, ...CATEGORY_OPTIONS]}
              onChange={setCategory}
            />
          </div>
          {list.error && list.data === undefined ? (
            <ErrorBlock message={list.error} onRetry={list.reload} />
          ) : list.data === undefined ? (
            <LoadingRows rows={5} />
          ) : list.data.length === 0 ? (
            <EmptyBlock
              icon={FileText}
              title="No wordlists indexed"
              description="Add files by reference (recommended for SecLists, rockyou and other large lists) or copy small lists into ExploitX."
              action={
                <Button size="sm" variant="primary" isDisabled={!runtime} onPress={pickFiles}>
                  <Plus className="size-3.5" />
                  Add files
                </Button>
              }
            />
          ) : visible.length === 0 ? (
            <EmptyBlock compact icon={FileText} title="No matching wordlists" />
          ) : (
            <ul className="flex flex-col gap-1.5" aria-label="Wordlists">
              {visible.map((w) => {
                const fav = isFavorite("wordlist", String(w.id));
                const active = w.id === selected;
                return (
                  <li key={w.id} id={`wordlist-${w.id}`} className={cn("tile flex flex-wrap items-center gap-3 px-3 py-2", active && "bg-accent-soft")}>
                    <Button
                      variant="ghost"
                      onPress={() => setSelected(w.id)}
                      aria-pressed={active}
                      className="h-auto min-w-[200px] flex-1 flex-col items-start gap-0.5 bg-transparent p-0 text-left font-normal whitespace-normal hover:bg-transparent"
                    >
                      <span className="flex w-full items-center gap-2">
                        <span className="truncate text-[13.5px] text-foreground">{w.name}</span>
                        {!w.exists && (
                          <span className="flex items-center gap-1 text-[12px] text-warning-soft-foreground">
                            <AlertTriangle className="size-3.5" />
                            Missing
                          </span>
                        )}
                      </span>
                      <span className="w-full truncate font-mono text-[11.5px] text-muted" title={w.path}>{w.path}</span>
                      <span className="text-[11.5px] text-muted">
                        {formatBytes(w.sizeBytes)} · {w.lineCount != null ? `${formatNumber(w.lineCount)} lines` : "lines not counted"} · added {formatRelative(w.addedAt)}
                      </span>
                    </Button>
                    <ToneChip tone={w.managed ? "accent" : "default"} dot={false}>{w.managed ? "Managed copy" : "Referenced"}</ToneChip>
                    <SelectInput aria-label={`Category for ${w.name}`} className="w-[170px]" value={w.category} options={CATEGORY_OPTIONS} onChange={(c) => updateCategory(w, c)} />
                    <div className="flex items-center gap-0.5">
                      <Tooltip delay={300}>
                        <Button isIconOnly size="sm" variant="ghost" aria-pressed={fav} aria-label={fav ? "Remove from favorites" : "Add to favorites"} onPress={() => toggleFavorite("wordlist", String(w.id), w.name)}>
                          <Star className={cn("size-4", fav ? "fill-warning text-warning" : "text-muted")} />
                        </Button>
                        <Tooltip.Content>{fav ? "Remove from favorites" : "Add to favorites"}</Tooltip.Content>
                      </Tooltip>
                      <Tooltip delay={300}>
                        <Button isIconOnly size="sm" variant="ghost" aria-label="Copy path" onPress={() => copyText(w.path, "Path copied")}>
                          <Copy className="size-3.5" />
                        </Button>
                        <Tooltip.Content>Copy path</Tooltip.Content>
                      </Tooltip>
                      <Tooltip delay={300}>
                        <Button isIconOnly size="sm" variant="ghost" aria-label="Export a copy" isDisabled={!w.exists} onPress={() => exportList(w)}>
                          <Download className="size-3.5" />
                        </Button>
                        <Tooltip.Content>Export a copy</Tooltip.Content>
                      </Tooltip>
                      <Tooltip delay={300}>
                        <Button isIconOnly size="sm" variant="ghost" aria-label="Remove" onPress={() => setRemoving(w)}>
                          <Trash2 className="size-3.5" />
                        </Button>
                        <Tooltip.Content>Remove</Tooltip.Content>
                      </Tooltip>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
        <div className="min-w-0 xl:col-span-5">
          <PreviewPanel wordlist={selectedList} />
        </div>
      </div>
      <AddFilesModal isOpen={adding} onClose={() => setAdding(false)} />
      <RemoveModal wordlist={removing} onClose={() => setRemoving(null)} />
    </div>
  );
}
