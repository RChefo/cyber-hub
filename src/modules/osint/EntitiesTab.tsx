// SPDX-License-Identifier: Apache-2.0
import { Button } from "@heroui/react";
import { ChevronLeft, ChevronRight, Database, Plus } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { ToneChip } from "@/components/ui/Badges";
import { AppModal } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, QueryView } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput, TextAreaInput, TextInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import { formatRelative } from "@/lib/utils";
import { ConfidenceText, TypeBadge, useDebounced, VerificationChip } from "./bits";
import { useOsint } from "./context";
import { changeText, VERIFICATION_META } from "./model";
import type { EntityQuery, EntityRow, Verification } from "./types";

const PAGE = 50;
const ALL = "all";

function AddEntityModal({ isOpen, onOpenChange }: { isOpen: boolean; onOpenChange: (o: boolean) => void }) {
  const { investigation: inv, registry } = useOsint();
  const [type, setType] = useState("domain");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const [linkSearch, setLinkSearch] = useState("");
  const [linkTo, setLinkTo] = useState<string | null>(null);
  const [linkType, setLinkType] = useState<string | null>(null);
  const [direction, setDirection] = useState<"out" | "in">("out");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const debounced = useDebounced(linkSearch);

  useEffect(() => {
    if (isOpen) {
      setValue("");
      setNote("");
      setLinkSearch("");
      setLinkTo(null);
      setLinkType(null);
      setError(null);
    }
  }, [isOpen]);

  const candidates = useQuery(["osint"], () => api.osintEntities(inv.id, { q: debounced, limit: 20, sort: "connections" }), [inv.id, debounced], isOpen);
  const linkOptions = (candidates.data?.items ?? []).map((e) => ({ id: String(e.id), label: e.displayName || e.value, description: registry.entityTypeLabel(e.type) }));
  const relOptions = [...registry.relationshipTypes.values()].filter((r) => !r.inferred).map((r) => ({ id: r.id, label: r.label, description: r.description }));

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      const s = await api.osintEntityAdd({
        investigationId: inv.id,
        type,
        value: value.trim(),
        note: note.trim(),
        linkTo: linkTo ? Number(linkTo) : null,
        linkType: linkTo ? linkType : null,
        linkOutgoing: direction === "out",
      });
      invalidate("osint");
      notify.success("Entity added", changeText(s));
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
      size="lg"
      title="Add entity"
      description="Manual entries are recorded with you as the source and the note as their evidence. A manual link is stored as verified."
      footer={
        <>
          <Button variant="tertiary" onPress={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="primary" onPress={save} isPending={saving} isDisabled={!value.trim() || (!!linkTo && !linkType)}>
            Add entity
          </Button>
        </>
      }
    >
      {error && <ErrorBlock message={error} />}
      <div className="grid gap-3 sm:grid-cols-[200px_1fr]">
        <SelectInput label="Type" value={type} onChange={setType} options={registry.entityTypes.map((t) => ({ id: t.id, label: t.label }))} />
        <TextInput label="Value" value={value} onChange={setValue} mono isRequired autoFocus placeholder="example.com" />
      </div>
      <TextAreaInput label="Note (evidence)" value={note} onChange={setNote} rows={3} placeholder="Where you found it and why it matters" />
      <div className="panel-inset flex flex-col gap-3 px-4 py-3">
        <div className="text-[13px] font-medium text-foreground">Link to an existing entity (optional)</div>
        <SearchInput value={linkSearch} onChange={setLinkSearch} placeholder="Find an entity" />
        <div className="grid gap-3 sm:grid-cols-3">
          <SelectInput label="Entity" value={linkTo} onChange={setLinkTo} options={linkOptions} placeholder={candidates.loading ? "Searching…" : "Choose"} />
          <SelectInput label="Relationship" value={linkType} onChange={setLinkType} options={relOptions} isDisabled={!linkTo} />
          <SelectInput
            label="Direction"
            value={direction}
            onChange={(v) => setDirection(v as "out" | "in")}
            isDisabled={!linkTo}
            options={[
              { id: "out", label: "New entity → existing" },
              { id: "in", label: "Existing → new entity" },
            ]}
          />
        </div>
      </div>
    </AppModal>
  );
}

function Row({ e, onOpen, typeLabel }: { e: EntityRow; onOpen: () => void; typeLabel: string }) {
  return (
    <tr
      className="cursor-pointer align-top transition-colors hover:bg-white/[0.025] focus-visible:bg-white/[0.04] focus-visible:outline-none"
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(k) => (k.key === "Enter" || k.key === " ") && (k.preventDefault(), onOpen())}
      aria-label={`Open ${e.value}`}
    >
      <td className="py-2 pr-3">
        <TypeBadge type={e.type} label={typeLabel} />
      </td>
      <td className="max-w-[360px] py-2 pr-3">
        <div className="flex items-center gap-2">
          <span className="truncate font-mono text-[12.5px] text-foreground">{e.value}</span>
          {e.flagged && <ToneChip tone="danger">Flagged</ToneChip>}
        </div>
        {e.displayName && e.displayName !== e.value && <div className="truncate text-[12px] text-muted">{e.displayName}</div>}
      </td>
      <td className="py-2 pr-3">
        <VerificationChip value={e.verification} />
      </td>
      <td className="py-2 pr-3">
        <ConfidenceText value={e.confidence} />
      </td>
      <td className="max-w-[180px] truncate py-2 pr-3 text-[12.5px] text-muted">{e.sources.join(", ") || "—"}</td>
      <td className="tabular py-2 pr-3 text-right text-muted">{e.relationships}</td>
      <td className="tabular py-2 pr-3 text-right text-muted">{e.evidence}</td>
      <td className="py-2 text-[12.5px] whitespace-nowrap text-muted">{formatRelative(e.lastSeen)}</td>
    </tr>
  );
}

export function EntitiesTab() {
  const { investigation: inv, registry, openEntity } = useOsint();
  const [search, setSearch] = useState("");
  const [type, setType] = useState(ALL);
  const [verification, setVerification] = useState(ALL);
  const [flagged, setFlagged] = useState(false);
  const [sort, setSort] = useState<NonNullable<EntityQuery["sort"]>>("recent");
  const [page, setPage] = useState(0);
  const [adding, setAdding] = useState(false);
  const q = useDebounced(search);

  useEffect(() => setPage(0), [q, type, verification, flagged, sort]);

  const query: EntityQuery = useMemo(
    () => ({
      q: q.trim() || undefined,
      type: type === ALL ? undefined : type,
      verification: verification === ALL ? undefined : verification,
      flagged: flagged || undefined,
      sort,
      offset: page * PAGE,
      limit: PAGE,
    }),
    [q, type, verification, flagged, sort, page],
  );
  const data = useQuery(["osint"], () => api.osintEntities(inv.id, query), [inv.id, query]);
  const total = data.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE));

  return (
    <Panel
      title="Entities"
      description={data.data ? `${total.toLocaleString()} matching` : undefined}
      actions={
        <Button size="sm" variant="primary" onPress={() => setAdding(true)}>
          <Plus className="size-3.5" />
          Add entity
        </Button>
      }
    >
      <div className="mb-3 flex flex-wrap items-end gap-3">
        <SearchInput value={search} onChange={setSearch} placeholder="Search values, names, aliases" className="max-w-xs" />
        <SelectInput
          aria-label="Type"
          className="w-44"
          value={type}
          onChange={setType}
          options={[{ id: ALL, label: "All types" }, ...registry.entityTypes.map((t) => ({ id: t.id, label: t.label }))]}
        />
        <SelectInput
          aria-label="Verification"
          className="w-40"
          value={verification}
          onChange={setVerification}
          options={[{ id: ALL, label: "Any state" }, ...(Object.keys(VERIFICATION_META) as Verification[]).map((v) => ({ id: v, label: VERIFICATION_META[v].label }))]}
        />
        <SelectInput
          aria-label="Sort"
          className="w-44"
          value={sort}
          onChange={(v) => setSort(v as NonNullable<EntityQuery["sort"]>)}
          options={[
            { id: "recent", label: "Recently seen" },
            { id: "value", label: "Type and value" },
            { id: "connections", label: "Most connected" },
          ]}
        />
        <SwitchInput label="Flagged only" isSelected={flagged} onChange={setFlagged} />
      </div>
      <QueryView
        query={data}
        rows={6}
        isEmpty={(d) => d.items.length === 0}
        empty={
          <EmptyBlock
            compact
            icon={Database}
            title={q || type !== ALL || verification !== ALL || flagged ? "No entity matches these filters" : "No entities yet"}
            description={q || type !== ALL || verification !== ALL || flagged ? undefined : "Collect data in Data sources or add an entity by hand."}
          />
        }
      >
        {(d) => (
          <>
            <div className="panel-inset overflow-x-auto px-3 py-1">
              <table className="w-full border-separate border-spacing-y-0.5 text-left text-[13px]">
                <thead>
                  <tr className="text-[12px] text-muted">
                    <th className="py-2 pr-3 font-medium">Type</th>
                    <th className="py-2 pr-3 font-medium">Value</th>
                    <th className="py-2 pr-3 font-medium">State</th>
                    <th className="py-2 pr-3 font-medium">Confidence</th>
                    <th className="py-2 pr-3 font-medium">Sources</th>
                    <th className="py-2 pr-3 text-right font-medium">Links</th>
                    <th className="py-2 pr-3 text-right font-medium">Evidence</th>
                    <th className="py-2 font-medium">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {d.items.map((e) => (
                    <Row key={e.id} e={e} typeLabel={registry.entityTypeLabel(e.type)} onOpen={() => openEntity(e.id)} />
                  ))}
                </tbody>
              </table>
            </div>
            {pages > 1 && (
              <div className="mt-3 flex items-center justify-end gap-2 text-[12.5px] text-muted">
                <span className="tabular">
                  {d.offset + 1}–{d.offset + d.items.length} of {total.toLocaleString()}
                </span>
                <Button size="sm" variant="ghost" isIconOnly aria-label="Previous page" isDisabled={page === 0} onPress={() => setPage((p) => p - 1)}>
                  <ChevronLeft className="size-4" />
                </Button>
                <Button size="sm" variant="ghost" isIconOnly aria-label="Next page" isDisabled={page + 1 >= pages} onPress={() => setPage((p) => p + 1)}>
                  <ChevronRight className="size-4" />
                </Button>
              </div>
            )}
          </>
        )}
      </QueryView>
      <AddEntityModal isOpen={adding} onOpenChange={setAdding} />
    </Panel>
  );
}
