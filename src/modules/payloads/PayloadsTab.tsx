import { Button, Tabs, Tooltip } from "@heroui/react";
import { Info, Pencil, Plus, Star, Syringe, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { CodeBlock, CopyButton } from "@/components/ui/Code";
import { AppModal, useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { PAYLOAD_CATEGORY_LABELS, PAYLOADS } from "@/data/payloads";
import { copyText, notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { CustomPayload } from "@/lib/types";
import { cn } from "@/lib/utils";
import type { PayloadCategory } from "@/types/catalog";
import { ENCODING_LABELS, encodePayload, type PayloadEncoding } from "./encode";

interface Item {
  key: string; // favorite id: built-in id or custom:<id>
  title: string;
  category: PayloadCategory;
  payload: string;
  description: string;
  context: string;
  tags: string[];
  custom?: CustomPayload;
}

type Filter = "all" | "favorites" | "custom" | PayloadCategory;

const CATEGORY_KEYS = Object.keys(PAYLOAD_CATEGORY_LABELS) as PayloadCategory[];
const CATEGORY_OPTIONS = CATEGORY_KEYS.map((k) => ({ id: k, label: PAYLOAD_CATEGORY_LABELS[k] }));
const ENCODING_OPTIONS = (Object.keys(ENCODING_LABELS) as PayloadEncoding[]).map((k) => ({ id: k, label: ENCODING_LABELS[k] }));

async function copyPayload(item: Item, encoding: PayloadEncoding, runtime: boolean) {
  const text = encodePayload(item.payload, encoding);
  const ok = await copyText(text, encoding === "none" ? "Payload copied" : `Payload copied (${ENCODING_LABELS[encoding]})`);
  if (ok && runtime) {
    api
      .activityLog({ kind: "payload_copy", title: "Copied payload", detail: item.title })
      .then(() => invalidate("activity"))
      .catch(() => undefined);
  }
}

interface Draft {
  id?: number;
  title: string;
  category: string;
  payload: string;
  context: string;
  description: string;
  tags: string;
}

const EMPTY_DRAFT: Draft = { title: "", category: "xss", payload: "", context: "", description: "", tags: "" };

function PayloadModal({ draft, onClose }: { draft: Draft | null; onClose: () => void }) {
  const [form, setForm] = useState<Draft>(EMPTY_DRAFT);
  const [pending, setPending] = useState(false);
  useEffect(() => {
    if (draft) setForm(draft);
  }, [draft]);
  const invalid =
    !form.title.trim() || !form.payload.trim() || form.title.length > 150 || form.payload.length > 20000 || form.description.length > 1000 || form.context.length > 200;

  const save = async () => {
    setPending(true);
    try {
      await api.customPayloadUpsert({
        id: form.id,
        title: form.title,
        category: form.category,
        payload: form.payload,
        context: form.context,
        description: form.description,
        tags: form.tags.split(",").map((t) => t.trim()).filter(Boolean),
      });
      invalidate("payloads");
      notify.success(form.id ? "Payload updated" : "Payload added");
      onClose();
    } catch (e) {
      notify.error("Could not save payload", e);
    } finally {
      setPending(false);
    }
  };

  return (
    <AppModal
      isOpen={!!draft}
      onOpenChange={(o) => !o && onClose()}
      title={form.id ? "Edit payload" : "Add custom payload"}
      description="Custom payloads are stored locally in your Cyber Hub database."
      size="lg"
      footer={
        <>
          <Button variant="tertiary" onPress={onClose}>Cancel</Button>
          <Button variant="primary" isPending={pending} isDisabled={invalid} onPress={save}>
            {form.id ? "Save changes" : "Add payload"}
          </Button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <TextInput label="Title" value={form.title} onChange={(v) => setForm({ ...form, title: v })} isRequired autoFocus />
        <SelectInput label="Category" value={form.category} options={CATEGORY_OPTIONS} onChange={(v) => setForm({ ...form, category: v })} />
      </div>
      <TextAreaInput label="Payload" mono rows={5} value={form.payload} onChange={(v) => setForm({ ...form, payload: v })} isRequired />
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <TextInput label="Context" value={form.context} onChange={(v) => setForm({ ...form, context: v })} placeholder="e.g. URL parameter" />
        <TextInput label="Tags" value={form.tags} onChange={(v) => setForm({ ...form, tags: v })} placeholder="comma, separated" />
      </div>
      <TextAreaInput label="Description" rows={2} value={form.description} onChange={(v) => setForm({ ...form, description: v })} placeholder="What a positive result looks like" />
    </AppModal>
  );
}

function PayloadCard({ item, encoding, highlighted, onEdit, onDelete }: { item: Item; encoding: PayloadEncoding; highlighted: boolean; onEdit?: () => void; onDelete?: () => void }) {
  const { isFavorite, toggleFavorite, runtime } = useApp();
  const fav = isFavorite("payload", item.key);
  const shown = encodePayload(item.payload, encoding);
  return (
    <article id={`payload-${item.key}`} className={cn("panel flex flex-col gap-2.5 p-3.5", highlighted && "bg-accent-soft")}>
      <div className="flex items-start gap-2">
        <div className="min-w-0 flex-1">
          <h3 className="text-[14px] font-medium text-foreground">{item.title}</h3>
          <div className="text-[12px] text-muted">
            {PAYLOAD_CATEGORY_LABELS[item.category]}
            {item.context ? ` · ${item.context}` : ""}
            {item.custom ? " · Custom" : ""}
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-0.5">
          {onEdit && (
            <Tooltip delay={300}>
              <Button isIconOnly size="sm" variant="ghost" aria-label={`Edit ${item.title}`} onPress={onEdit}>
                <Pencil className="size-3.5" />
              </Button>
              <Tooltip.Content>Edit</Tooltip.Content>
            </Tooltip>
          )}
          {onDelete && (
            <Tooltip delay={300}>
              <Button isIconOnly size="sm" variant="ghost" aria-label={`Delete ${item.title}`} onPress={onDelete}>
                <Trash2 className="size-3.5" />
              </Button>
              <Tooltip.Content>Delete</Tooltip.Content>
            </Tooltip>
          )}
          <Tooltip delay={300}>
            <Button
              isIconOnly
              size="sm"
              variant="ghost"
              aria-pressed={fav}
              isDisabled={!runtime}
              aria-label={fav ? `Remove ${item.title} from favorites` : `Add ${item.title} to favorites`}
              onPress={() => toggleFavorite("payload", item.key, item.title)}
            >
              <Star className={cn("size-4", fav ? "fill-warning text-warning" : "text-muted")} />
            </Button>
            <Tooltip.Content>{fav ? "Remove from favorites" : "Add to favorites"}</Tooltip.Content>
          </Tooltip>
        </div>
      </div>
      {item.description && <p className="text-[13px] text-muted">{item.description}</p>}
      <CodeBlock
        code={shown}
        maxHeight={180}
        actions={<CopyButton text={shown} label={encoding === "none" ? "Copy payload" : `Copy (${ENCODING_LABELS[encoding]})`} onCopy={() => copyPayload(item, encoding, runtime)} />}
      />
      {encoding !== "none" && <div className="text-[11.5px] text-muted">Shown and copied as {ENCODING_LABELS[encoding].toLowerCase()}.</div>}
    </article>
  );
}

export function PayloadsTab({ preselect }: { preselect?: string }) {
  const { runtime, isFavorite } = useApp();
  const custom = useQuery(["payloads"], api.customPayloadsList, [], runtime);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const [encoding, setEncoding] = useState<PayloadEncoding>("none");
  const [draft, setDraft] = useState<Draft | null>(null);
  const confirm = useConfirm();

  const items = useMemo<Item[]>(() => {
    const own: Item[] = (custom.data ?? []).map((c) => ({
      key: `custom:${c.id}`,
      title: c.title,
      category: (CATEGORY_KEYS.includes(c.category as PayloadCategory) ? c.category : "input-validation") as PayloadCategory,
      payload: c.payload,
      description: c.description,
      context: c.context,
      tags: c.tags,
      custom: c,
    }));
    return [...own, ...PAYLOADS.map((p) => ({ key: p.id, title: p.title, category: p.category, payload: p.payload, description: p.description, context: p.context, tags: p.tags }))];
  }, [custom.data]);

  useEffect(() => {
    if (!preselect) return;
    const target = items.find((i) => i.key === preselect);
    if (target) {
      setFilter(target.category);
      requestAnimationFrame(() => document.getElementById(`payload-${preselect}`)?.scrollIntoView({ block: "center" }));
    }
  }, [preselect, items]);

  const q = search.toLowerCase().trim();
  const visible = items.filter((i) => {
    if (filter === "favorites" && !isFavorite("payload", i.key)) return false;
    if (filter === "custom" && !i.custom) return false;
    if (filter !== "all" && filter !== "favorites" && filter !== "custom" && i.category !== filter) return false;
    return !q || `${i.title} ${i.description} ${i.context} ${i.payload} ${i.tags.join(" ")}`.toLowerCase().includes(q);
  });

  const remove = async (c: CustomPayload) => {
    if (!(await confirm.ask({ title: "Delete custom payload?", body: `“${c.title}” will be removed. This cannot be undone.`, confirmLabel: "Delete" }))) return;
    try {
      await api.customPayloadDelete(c.id);
      invalidate("payloads");
      notify.success("Payload deleted");
    } catch (e) {
      notify.error("Could not delete payload", e);
    }
  };

  const tabs: { id: Filter; label: string }[] = [
    { id: "all", label: "All" },
    { id: "favorites", label: "Favorites" },
    ...CATEGORY_KEYS.map((k) => ({ id: k as Filter, label: PAYLOAD_CATEGORY_LABELS[k] })),
    { id: "custom", label: "Custom" },
  ];

  return (
    <div className="flex flex-col gap-3">
      <div className="panel-inset flex items-start gap-2.5 px-3.5 py-2.5 text-[13px] text-muted">
        <Info className="mt-0.5 size-4 shrink-0 text-accent-soft-foreground" />
        <span>
          These are well-known detection probes from public testing guides, for applications you are authorized to test. Nothing here is sent anywhere: copy a
          payload and use it in your own tooling.
        </span>
      </div>
      <div className="flex flex-wrap items-end gap-2">
        <SearchInput value={search} onChange={setSearch} placeholder="Search payloads" className="min-w-[240px] flex-1" />
        <SelectInput aria-label="Encode on copy" className="w-[200px]" value={encoding} options={ENCODING_OPTIONS} onChange={(v) => setEncoding(v as PayloadEncoding)} />
        <Button variant="primary" size="sm" className="h-9" isDisabled={!runtime} onPress={() => setDraft(EMPTY_DRAFT)}>
          <Plus className="size-3.5" />
          Add payload
        </Button>
      </div>
      <div className="scroll-area -mx-1 px-1">
        <Tabs selectedKey={filter} onSelectionChange={(k) => setFilter(String(k) as Filter)}>
          <Tabs.ListContainer>
            <Tabs.List aria-label="Payload category" className="h-8 w-max">
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
      {custom.error && runtime && <ErrorBlock message={custom.error} onRetry={custom.reload} />}
      {visible.length === 0 ? (
        <EmptyBlock
          icon={Syringe}
          title={filter === "favorites" ? "No favorite payloads" : filter === "custom" ? "No custom payloads" : "No matching payloads"}
          description={filter === "favorites" ? "Star payloads you use often." : filter === "custom" ? "Add your own test strings to keep them with the library." : "Try another search or category."}
        />
      ) : (
        <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
          {visible.map((i) => (
            <PayloadCard
              key={i.key}
              item={i}
              encoding={encoding}
              highlighted={i.key === preselect}
              onEdit={
                i.custom
                  ? () =>
                      setDraft({
                        id: i.custom!.id,
                        title: i.custom!.title,
                        category: i.custom!.category,
                        payload: i.custom!.payload,
                        context: i.custom!.context,
                        description: i.custom!.description,
                        tags: i.custom!.tags.join(", "),
                      })
                  : undefined
              }
              onDelete={i.custom ? () => remove(i.custom!) : undefined}
            />
          ))}
        </div>
      )}
      <PayloadModal draft={draft} onClose={() => setDraft(null)} />
      {confirm.element}
    </div>
  );
}
