import { Button, Tabs, Tooltip } from "@heroui/react";
import { BookMarked, ExternalLink, History, Pencil, Plus, Star, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { useConfirm, AppModal } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, QueryView } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { PageHeader, Panel } from "@/components/ui/Panel";
import { RESOURCE_CATEGORY_LABELS, RESOURCES } from "@/data/resources";
import { notify, openResource } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { CustomResource } from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";
import type { ResourceCategory } from "@/types/catalog";

interface CardItem {
  key: string;
  favId: string;
  title: string;
  url: string;
  category: string;
  description: string;
  tags: string[];
  custom?: CustomResource;
}

type Filter = "all" | "favorites" | "custom" | ResourceCategory;

const CATEGORY_OPTIONS = [
  ...(Object.keys(RESOURCE_CATEGORY_LABELS) as ResourceCategory[]).map((k) => ({ id: k, label: RESOURCE_CATEGORY_LABELS[k] })),
  { id: "custom", label: "Custom" },
];

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}

function categoryLabel(c: string): string {
  return RESOURCE_CATEGORY_LABELS[c as ResourceCategory] ?? "Custom";
}

interface Draft {
  id?: number;
  title: string;
  url: string;
  category: string;
  description: string;
}

function validateUrl(url: string): string | null {
  if (!url.trim()) return null;
  try {
    const u = new URL(url.trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return "Only http and https links are allowed";
    if (!u.hostname) return "The URL needs a host";
    return null;
  } catch {
    return "Enter a full URL, e.g. https://example.com";
  }
}

function ResourceModal({ draft, onClose }: { draft: Draft | null; onClose: () => void }) {
  const [form, setForm] = useState<Draft>({ title: "", url: "", category: "custom", description: "" });
  const [pending, setPending] = useState(false);
  useEffect(() => {
    if (draft) setForm(draft);
  }, [draft]);
  const urlError = validateUrl(form.url);
  const invalid = !form.title.trim() || !form.url.trim() || !!urlError || form.title.length > 120 || form.description.length > 500;

  const save = async () => {
    setPending(true);
    try {
      await api.customResourceUpsert({ ...form, url: form.url.trim() });
      invalidate("resources");
      notify.success(form.id ? "Link updated" : "Link added");
      onClose();
    } catch (e) {
      notify.error("Could not save link", e);
    } finally {
      setPending(false);
    }
  };

  return (
    <AppModal
      isOpen={!!draft}
      onOpenChange={(o) => !o && onClose()}
      title={form.id ? "Edit link" : "Add custom link"}
      description="Custom links are stored locally and appear alongside the built-in directory."
      footer={
        <>
          <Button variant="tertiary" onPress={onClose}>Cancel</Button>
          <Button variant="primary" isPending={pending} isDisabled={invalid} onPress={save}>
            {form.id ? "Save changes" : "Add link"}
          </Button>
        </>
      }
    >
      <TextInput label="Title" value={form.title} onChange={(v) => setForm({ ...form, title: v })} placeholder="Internal wiki" isRequired autoFocus />
      <TextInput label="URL" type="url" mono value={form.url} onChange={(v) => setForm({ ...form, url: v })} placeholder="https://" isRequired error={urlError} />
      <SelectInput label="Category" value={form.category} options={CATEGORY_OPTIONS} onChange={(v) => setForm({ ...form, category: v })} />
      <TextAreaInput label="Description" rows={3} value={form.description} onChange={(v) => setForm({ ...form, description: v })} placeholder="What you use it for" />
    </AppModal>
  );
}

function ResourceCard({ item, onEdit, onDelete }: { item: CardItem; onEdit?: () => void; onDelete?: () => void }) {
  const { isFavorite, toggleFavorite } = useApp();
  const fav = isFavorite("resource", item.favId);
  return (
    <article className="panel flex flex-col gap-2 p-3.5">
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <h3 className="truncate text-[14px] font-medium text-foreground">{item.title}</h3>
          <div className="truncate font-mono text-[11.5px] text-muted">{hostOf(item.url)}</div>
        </div>
        <Tooltip delay={300}>
          <Button
            isIconOnly
            size="sm"
            variant="ghost"
            aria-label={fav ? `Remove ${item.title} from favorites` : `Add ${item.title} to favorites`}
            aria-pressed={fav}
            onPress={() => toggleFavorite("resource", item.favId, item.title)}
          >
            <Star className={cn("size-4", fav ? "fill-warning text-warning" : "text-muted")} />
          </Button>
          <Tooltip.Content>{fav ? "Remove from favorites" : "Add to favorites"}</Tooltip.Content>
        </Tooltip>
      </div>
      <p className="line-clamp-3 flex-1 text-[13px] text-muted">{item.description || "No description."}</p>
      <div className="flex flex-wrap gap-1">
        <span className="rounded-md bg-white/[0.05] px-1.5 py-0.5 text-[11.5px] text-muted">{categoryLabel(item.category)}</span>
        {item.tags.slice(0, 3).map((t) => (
          <span key={t} className="rounded-md bg-white/[0.03] px-1.5 py-0.5 text-[11.5px] text-muted">{t}</span>
        ))}
      </div>
      <div className="flex items-center gap-1 pt-1">
        <Button size="sm" variant="tertiary" onPress={() => openResource(item.key, item.title, item.url)}>
          <ExternalLink className="size-3.5" />
          Open
        </Button>
        {onEdit && (
          <Button size="sm" variant="ghost" onPress={onEdit} aria-label={`Edit ${item.title}`}>
            <Pencil className="size-3.5" />
            Edit
          </Button>
        )}
        {onDelete && (
          <Button size="sm" variant="ghost" onPress={onDelete} aria-label={`Delete ${item.title}`} className="ml-auto">
            <Trash2 className="size-3.5" />
          </Button>
        )}
      </div>
    </article>
  );
}

export default function ResourcesPage() {
  const { runtime, isFavorite } = useApp();
  const custom = useQuery(["resources"], api.customResourcesList, [], runtime);
  const recent = useQuery(["resources"], () => api.resourceRecent(8), [], runtime);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [draft, setDraft] = useState<Draft | null>(null);
  const confirm = useConfirm();

  const items = useMemo<CardItem[]>(() => {
    const builtIn: CardItem[] = RESOURCES.map((r) => ({ key: r.id, favId: r.id, title: r.title, url: r.url, category: r.category, description: r.description, tags: r.tags }));
    const own: CardItem[] = (custom.data ?? []).map((c) => ({
      key: `custom:${c.id}`,
      favId: `custom:${c.id}`,
      title: c.title,
      url: c.url,
      category: c.category,
      description: c.description,
      tags: ["custom"],
      custom: c,
    }));
    return [...own, ...builtIn];
  }, [custom.data]);

  const q = search.toLowerCase().trim();
  const visible = items.filter((i) => {
    if (filter === "favorites" && !isFavorite("resource", i.favId)) return false;
    if (filter === "custom" && !i.custom) return false;
    if (filter !== "all" && filter !== "favorites" && filter !== "custom" && i.category !== filter) return false;
    if (!q) return true;
    return `${i.title} ${i.description} ${i.url} ${i.tags.join(" ")}`.toLowerCase().includes(q);
  });

  const tabs: { id: Filter; label: string }[] = [
    { id: "all", label: "All" },
    { id: "favorites", label: "Favorites" },
    ...(Object.keys(RESOURCE_CATEGORY_LABELS) as ResourceCategory[]).map((k) => ({ id: k as Filter, label: RESOURCE_CATEGORY_LABELS[k] })),
    { id: "custom", label: "Custom" },
  ];

  const remove = async (c: CustomResource) => {
    if (!(await confirm.ask({ title: "Delete custom link?", body: `“${c.title}” will be removed from your directory.`, confirmLabel: "Delete" }))) return;
    try {
      await api.customResourceDelete(c.id);
      invalidate("resources");
      notify.success("Link deleted");
    } catch (e) {
      notify.error("Could not delete link", e);
    }
  };

  const emptyText =
    filter === "favorites"
      ? { title: "No favorites yet", description: "Star resources to collect them here and on the dashboard." }
      : filter === "custom"
        ? { title: "No custom links", description: "Add internal wikis, portals or any site you use often." }
        : { title: "No matching resources", description: "Try a different search or category." };

  return (
    <div>
      <PageHeader
        title="Cyber Resources"
        description={`${RESOURCES.length} curated security websites plus your own links. Links open in your default browser.`}
        actions={
          <Button variant="primary" size="sm" isDisabled={!runtime} onPress={() => setDraft({ title: "", url: "", category: "custom", description: "" })}>
            <Plus className="size-3.5" />
            Add link
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-12">
        <div className="min-w-0 xl:col-span-9">
          <div className="mb-3 flex flex-col gap-3">
            <SearchInput value={search} onChange={setSearch} placeholder="Search resources by name, topic or URL" />
            <div className="scroll-area -mx-1 px-1">
              <Tabs selectedKey={filter} onSelectionChange={(k) => setFilter(String(k) as Filter)}>
                <Tabs.ListContainer>
                  <Tabs.List aria-label="Resource category" className="h-8 w-max">
                    {tabs.map((t) => (
                      <Tabs.Tab key={t.id} id={t.id} className="px-2.5 text-[12.5px]">
                        {t.label}
                        <Tabs.Indicator />
                      </Tabs.Tab>
                    ))}
                  </Tabs.List>
                </Tabs.ListContainer>
              </Tabs>
            </div>
          </div>
          {custom.error && runtime && <ErrorBlock className="mb-3" message={custom.error} onRetry={custom.reload} />}
          {visible.length === 0 ? (
            <EmptyBlock
              icon={BookMarked}
              title={emptyText.title}
              description={emptyText.description}
              action={
                filter === "custom" && runtime ? (
                  <Button size="sm" variant="primary" onPress={() => setDraft({ title: "", url: "", category: "custom", description: "" })}>
                    <Plus className="size-3.5" />
                    Add link
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
              {visible.map((i) => (
                <ResourceCard
                  key={i.key}
                  item={i}
                  onEdit={i.custom ? () => setDraft({ id: i.custom!.id, title: i.custom!.title, url: i.custom!.url, category: i.custom!.category, description: i.custom!.description }) : undefined}
                  onDelete={i.custom ? () => remove(i.custom!) : undefined}
                />
              ))}
            </div>
          )}
        </div>

        <div className="min-w-0 xl:col-span-3">
          <Panel title="Recently visited" description="Opened from Cyber Hub">
            <QueryView
              query={recent}
              rows={4}
              isEmpty={(d) => d.length === 0}
              empty={<EmptyBlock compact icon={History} title="Nothing visited yet" description="Resources you open are listed here." />}
            >
              {(visits) => (
                <ul className="flex flex-col">
                  {visits.map((v) => (
                    <li key={v.resourceKey}>
                      <Button
                        variant="ghost"
                        onPress={() => openResource(v.resourceKey, v.title, v.url)}
                        className="h-auto w-full flex-col items-start gap-0 rounded-md px-2 py-1.5 text-left font-normal whitespace-normal"
                      >
                        <span className="w-full truncate text-[13px] text-foreground">{v.title}</span>
                        <span className="text-[11.5px] text-muted">{formatRelative(v.visitedAt)}</span>
                      </Button>
                    </li>
                  ))}
                </ul>
              )}
            </QueryView>
          </Panel>
        </div>
      </div>
      <ResourceModal draft={draft} onClose={() => setDraft(null)} />
      {confirm.element}
    </div>
  );
}
