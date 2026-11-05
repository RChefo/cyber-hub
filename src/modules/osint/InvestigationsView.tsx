import { Button } from "@heroui/react";
import { FileUp, GitCompare, Network, Plus } from "lucide-react";
import { useMemo, useState } from "react";
import { ToneChip } from "@/components/ui/Badges";
import { AppModal } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows, QueryView } from "@/components/ui/Feedback";
import { SearchInput, SelectInput, SwitchInput } from "@/components/ui/Fields";
import { PageHeader } from "@/components/ui/Panel";
import { FeaturedIcon } from "@/components/vendor/untitledui/FeaturedIcon";
import { api, errorMessage } from "@/lib/ipc";
import { useQuery } from "@/lib/query";
import { formatRelative } from "@/lib/utils";
import { TypeBadge } from "./bits";
import { ImportGraphModal } from "./ImportGraphModal";
import { InvestigationFormModal } from "./InvestigationFormModal";
import { plural } from "./model";
import type { Investigation, InvestigationStatus, SharedEntity } from "./types";

export const INVESTIGATION_STATUS_META: Record<InvestigationStatus, { label: string; tone: "default" | "accent" | "success" | "warning" }> = {
  active: { label: "Active", tone: "accent" },
  closed: { label: "Closed", tone: "success" },
  archived: { label: "Archived", tone: "default" },
};

function InvestigationRow({ inv, onOpen }: { inv: Investigation; onOpen: () => void }) {
  const meta = INVESTIGATION_STATUS_META[inv.status];
  const c = inv.counts;
  return (
    <Button
      variant="ghost"
      onPress={onOpen}
      className="panel h-auto w-full justify-start gap-4 px-4 py-3.5 text-left font-normal whitespace-normal hover:bg-surface-hover"
      aria-label={`Open investigation ${inv.name}`}
    >
      <FeaturedIcon icon={Network} size="md" color={inv.status === "active" ? "brand" : "gray"} />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-center gap-2">
          <span className="truncate text-[14.5px] font-medium text-foreground">{inv.name}</span>
          <ToneChip tone={meta.tone}>{meta.label}</ToneChip>
          {c.pendingReview > 0 && <ToneChip tone="warning">{c.pendingReview} to review</ToneChip>}
          {c.flagged > 0 && <ToneChip tone="danger">{c.flagged} flagged</ToneChip>}
        </div>
        <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-[12.5px] text-muted">
          <TypeBadge type={inv.targetType} label={inv.targetValue} className="font-mono" />
          {inv.projectName && <span>Project: {inv.projectName}</span>}
          {inv.tags.length > 0 && <span>{inv.tags.join(", ")}</span>}
        </div>
      </div>
      <div className="hidden shrink-0 text-right text-[12.5px] text-muted md:block">
        <div className="tabular text-foreground">
          {plural(c.entities, "entity", "entities")} · {plural(c.relationships, "link", "links")}
        </div>
        <div>
          {plural(c.graphs, "graph", "graphs")} · {inv.lastOpenedAt ? `opened ${formatRelative(inv.lastOpenedAt)}` : `updated ${formatRelative(inv.updatedAt)}`}
        </div>
      </div>
    </Button>
  );
}

function CompareModal({ isOpen, onOpenChange, investigations }: { isOpen: boolean; onOpenChange: (o: boolean) => void; investigations: Investigation[] }) {
  const [a, setA] = useState<string | null>(null);
  const [b, setB] = useState<string | null>(null);
  const [rows, setRows] = useState<SharedEntity[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const options = investigations.map((i) => ({ id: String(i.id), label: i.name, description: i.targetValue }));
  const name = (id: string | null) => investigations.find((i) => String(i.id) === id)?.name ?? "";

  const run = async () => {
    if (!a || !b) return;
    setBusy(true);
    setError(null);
    try {
      setRows(await api.osintCompare(Number(a), Number(b)));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AppModal
      isOpen={isOpen}
      onOpenChange={onOpenChange}
      size="lg"
      title="Compare investigations"
      description="Entities present in both investigations (same type and normalized value). A shared entity is a lead, not proof of a connection."
      footer={
        <Button variant="primary" onPress={run} isDisabled={!a || !b || a === b} isPending={busy}>
          Compare
        </Button>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2">
        <SelectInput label="First" value={a} onChange={setA} options={options} />
        <SelectInput label="Second" value={b} onChange={setB} options={options.filter((o) => o.id !== a)} />
      </div>
      {error && <ErrorBlock message={error} />}
      {rows && rows.length === 0 && <EmptyBlock compact icon={GitCompare} title="No shared entities" description="The two investigations have no entity in common." />}
      {rows && rows.length > 0 && (
        <div className="panel-inset max-h-[420px] overflow-auto px-3 py-1">
          <table className="w-full border-separate border-spacing-y-0.5 text-left text-[13px]">
            <thead>
              <tr className="text-[12px] text-muted">
                <th className="py-2 pr-3 font-medium">Entity</th>
                <th className="py-2 pr-3 font-medium">Links in {name(a)}</th>
                <th className="py-2 font-medium">Links in {name(b)}</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={`${r.aId}-${r.bId}`}>
                  <td className="max-w-[360px] py-2 pr-3">
                    <TypeBadge type={r.type} label={r.value} className="font-mono text-foreground" />
                  </td>
                  <td className="tabular py-2 pr-3 text-muted">{r.aRelationships}</td>
                  <td className="tabular py-2 text-muted">{r.bRelationships}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </AppModal>
  );
}

export function InvestigationsView({ onOpen }: { onOpen: (id: number, graphId?: number) => void }) {
  const [includeArchived, setIncludeArchived] = useState(false);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState<string>("all");
  const [creating, setCreating] = useState(false);
  const [importing, setImporting] = useState(false);
  const [comparing, setComparing] = useState(false);
  const q = useQuery(["osint"], () => api.osintInvestigations(includeArchived || status === "archived"), [includeArchived, status]);

  const list = useMemo(() => {
    const s = search.trim().toLowerCase();
    return (q.data ?? []).filter(
      (i) =>
        (status === "all" || i.status === status) &&
        (!s || i.name.toLowerCase().includes(s) || i.targetValue.toLowerCase().includes(s) || i.tags.some((t) => t.toLowerCase().includes(s))),
    );
  }, [q.data, search, status]);

  return (
    <div>
      <PageHeader
        title="OSINT Workspace"
        description="Collect public information about a target, connect what you find through evidence-backed relationships and keep the resulting graphs."
        actions={
          <>
            <Button variant="tertiary" onPress={() => setComparing(true)} isDisabled={(q.data?.length ?? 0) < 2}>
              <GitCompare className="size-4" />
              Compare
            </Button>
            <Button variant="tertiary" onPress={() => setImporting(true)}>
              <FileUp className="size-4" />
              Import graph
            </Button>
            <Button variant="primary" onPress={() => setCreating(true)}>
              <Plus className="size-4" />
              New investigation
            </Button>
          </>
        }
      />
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <SearchInput value={search} onChange={setSearch} placeholder="Search by name, target or tag" className="max-w-sm" />
        <SelectInput
          aria-label="Status"
          value={status}
          onChange={setStatus}
          className="w-44"
          options={[
            { id: "all", label: "All statuses" },
            { id: "active", label: "Active" },
            { id: "closed", label: "Closed" },
            { id: "archived", label: "Archived" },
          ]}
        />
        <SwitchInput label="Include archived" isSelected={includeArchived || status === "archived"} onChange={setIncludeArchived} />
      </div>
      {q.loading && q.data === undefined ? (
        <LoadingRows rows={4} />
      ) : (
        <QueryView
          query={q}
          isEmpty={(d) => d.length === 0}
          empty={
            <EmptyBlock
              icon={Network}
              title="Start your first investigation"
              description="An investigation has one primary target (a domain, IP address, organization, email or username). Cyber Hub collects public data about it, extracts entities, links them with evidence and lets you map and save the result."
              action={
                <Button variant="primary" onPress={() => setCreating(true)}>
                  <Plus className="size-4" />
                  New investigation
                </Button>
              }
            />
          }
        >
          {() =>
            list.length === 0 ? (
              <EmptyBlock compact icon={Network} title="No investigation matches these filters" />
            ) : (
              <div className="flex flex-col gap-2">
                {list.map((i) => (
                  <InvestigationRow key={i.id} inv={i} onOpen={() => onOpen(i.id)} />
                ))}
              </div>
            )
          }
        </QueryView>
      )}
      <InvestigationFormModal isOpen={creating} onOpenChange={setCreating} onSaved={(inv) => onOpen(inv.id)} />
      <ImportGraphModal isOpen={importing} onOpenChange={setImporting} investigationId={null} onImported={(r) => onOpen(r.investigationId, r.graphId)} />
      <CompareModal isOpen={comparing} onOpenChange={setComparing} investigations={q.data ?? []} />
    </div>
  );
}
