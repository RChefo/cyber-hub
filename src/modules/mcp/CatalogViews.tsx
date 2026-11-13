// SPDX-License-Identifier: Apache-2.0
import { Button } from "@heroui/react";
import { ChevronDown, FileJson, MessageSquareText, Wrench } from "lucide-react";
import { useMemo, useState } from "react";
import { StatusDot, ToneChip } from "@/components/ui/Badges";
import { CopyButton } from "@/components/ui/Code";
import { EmptyBlock } from "@/components/ui/Feedback";
import { SearchInput, SelectInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import type { McpCatalog, McpCatalogTool, McpParam } from "@/lib/types";
import { cn } from "@/lib/utils";
import { CATEGORY_SHORT, CATEGORY_TONE, gateLabel, groupTools } from "./mcpMeta";

function Params({ params, empty = "No parameters" }: { params: McpParam[]; empty?: string }) {
  if (!params.length) return <p className="text-[12px] text-muted">{empty}</p>;
  return (
    <dl className="grid grid-cols-1 gap-x-4 gap-y-1.5 text-[12.5px] sm:grid-cols-[minmax(120px,auto)_1fr]">
      {params.map((p) => (
        <div key={p.name} className="contents">
          <dt className="font-mono text-[12px]">
            {p.name}
            {p.required ? <span className="text-warning-soft-foreground"> *</span> : <span className="text-muted"> (optional)</span>}
          </dt>
          <dd className="min-w-0 text-muted">
            <span className="text-foreground/80">{p.kind}</span>
            {p.values.length > 0 && <span> · one of {p.values.join(", ")}</span>}
            {p.description && <span> · {p.description}</span>}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function ToolRow({ t }: { t: McpCatalogTool }) {
  const [open, setOpen] = useState(false);
  const gate = gateLabel(t);
  return (
    <li className="rounded-lg px-3 py-2.5 transition-colors hover:bg-white/[0.025]">
      <div className="flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <StatusDot tone={t.available ? "success" : "default"} />
            <span className="text-[13.5px] font-medium">{t.title}</span>
            <code className="text-[12px] text-muted" data-selectable>
              {t.name}
            </code>
          </div>
          <p className="mt-0.5 text-[12.5px] text-muted">{t.description}</p>
          {t.note && <p className={cn("mt-0.5 text-[12px]", t.available ? "text-muted" : "text-warning-soft-foreground")}>{t.note}</p>}
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-1.5 lg:justify-end">
          <ToneChip tone={CATEGORY_TONE[t.category] ?? "default"} dot={false}>
            {CATEGORY_SHORT[t.category] ?? t.category}
          </ToneChip>
          <ToneChip tone={gate.tone}>{gate.label}</ToneChip>
          {t.parameters.length === 0 ? (
            <span className="px-2 text-[12px] text-muted">No parameters</span>
          ) : (
            <Button size="sm" variant="ghost" onPress={() => setOpen((o) => !o)} aria-expanded={open} className="h-7 gap-1 px-2 text-[12px] text-muted">
              {t.parameters.length} parameter{t.parameters.length === 1 ? "" : "s"}
              <ChevronDown className={cn("size-3.5 transition-transform", open && "rotate-180")} />
            </Button>
          )}
        </div>
      </div>
      {open && (
        <div className="mt-2 rounded-md bg-white/[0.02] px-3 py-2.5">
          <Params params={t.parameters} />
        </div>
      )}
    </li>
  );
}

const ALL = "all";

export function ToolsCatalog({ catalog }: { catalog: McpCatalog }) {
  const [q, setQ] = useState("");
  const [category, setCategory] = useState(ALL);
  const [gate, setGate] = useState(ALL);

  const categories = useMemo(() => Array.from(new Set(catalog.tools.map((t) => t.category))), [catalog.tools]);
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return catalog.tools.filter(
      (t) =>
        (category === ALL || t.category === category) &&
        (gate === ALL || (gate === "approval" ? t.requiresApproval : gate === "available" ? t.available : !t.available)) &&
        (!needle || `${t.name} ${t.title} ${t.description}`.toLowerCase().includes(needle)),
    );
  }, [catalog.tools, q, category, gate]);
  const groups = groupTools(catalog.groups, filtered);
  const approvalCount = catalog.tools.filter((t) => t.requiresApproval).length;
  const availableCount = catalog.tools.filter((t) => t.available).length;

  return (
    <Panel
      title={`${catalog.tools.length} tools`}
      description={`What cyberhub-mcp offers to AI clients. ${availableCount} available now, ${approvalCount} ask you first under your current permissions.`}
      toolbar={
        <div className="flex flex-col gap-2 px-4 pb-3 md:flex-row md:flex-wrap md:items-center">
          <SearchInput value={q} onChange={setQ} placeholder="Search tools" className="md:max-w-[320px] md:flex-1" />
          <SelectInput
            aria-label="Permission category"
            value={category}
            onChange={setCategory}
            className="md:w-[200px]"
            options={[{ id: ALL, label: "All categories" }, ...categories.map((c) => ({ id: c, label: CATEGORY_SHORT[c] ?? c }))]}
          />
          <SelectInput
            aria-label="Availability"
            value={gate}
            onChange={setGate}
            className="md:w-[200px]"
            options={[
              { id: ALL, label: "Any availability" },
              { id: "available", label: "Available now" },
              { id: "approval", label: "Asks you first" },
              { id: "unavailable", label: "Unavailable" },
            ]}
          />
        </div>
      }
    >
      {groups.length === 0 ? (
        <EmptyBlock compact icon={Wrench} title="No tools match" description="Clear the search or filters." />
      ) : (
        <div className="flex flex-col gap-5">
          {groups.map((g) => (
            <section key={g.id} aria-label={g.label}>
              <h3 className="mb-1 flex items-baseline gap-2 px-3 text-[13px] font-medium">
                {g.label}
                <span className="tabular text-[12px] font-normal text-muted">{g.tools.length}</span>
              </h3>
              <ul className="flex flex-col">
                {g.tools.map((t) => (
                  <ToolRow key={t.name} t={t} />
                ))}
              </ul>
            </section>
          ))}
        </div>
      )}
    </Panel>
  );
}

export function ResourcesAndPrompts({ catalog }: { catalog: McpCatalog }) {
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      <Panel
        title={
          <span className="flex items-center gap-2">
            <FileJson className="size-4 text-accent" />
            Resources ({catalog.resources.length})
          </span>
        }
        description="Read-only views an AI client can load into its context. Each is served by a read-only tool; no other URI (such as file://) is accepted."
      >
        <ul className="flex flex-col gap-1">
          {catalog.resources.map((r) => (
            <li key={r.uri} className="rounded-lg px-3 py-2.5 hover:bg-white/[0.025]">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <code className="text-[12.5px] text-accent-soft-foreground" data-selectable>
                  {r.uri}
                </code>
                <span className="flex items-center gap-1.5">
                  {r.template && (
                    <ToneChip tone="accent" dot={false}>
                      Template
                    </ToneChip>
                  )}
                  <span className="text-[12px] text-muted">{r.mimeType}</span>
                  <CopyButton text={r.uri} label="Copy URI" />
                </span>
              </div>
              <p className="mt-0.5 text-[12.5px]">{r.description}</p>
              <p className="text-[12px] text-muted">
                Served by <code className="text-[11.5px]">{r.servedBy}</code>
              </p>
              {r.parameters.length > 0 && (
                <div className="mt-1.5">
                  <Params params={r.parameters} />
                </div>
              )}
            </li>
          ))}
        </ul>
      </Panel>
      <Panel
        title={
          <span className="flex items-center gap-2">
            <MessageSquareText className="size-4 text-accent" />
            Prompts ({catalog.prompts.length})
          </span>
        }
        description="Starting points an AI client can offer you. Each one tells the AI to stay inside the project's authorized scope, preview runs and never claim approvals it did not receive."
      >
        <ul className="flex flex-col gap-1">
          {catalog.prompts.map((p) => (
            <li key={p.name} className="rounded-lg px-3 py-2.5 hover:bg-white/[0.025]">
              <div className="flex flex-wrap items-baseline gap-2">
                <span className="text-[13.5px] font-medium">{p.title}</span>
                <code className="text-[12px] text-muted" data-selectable>
                  {p.name}
                </code>
              </div>
              <p className="mt-0.5 text-[12.5px] text-muted">{p.description}</p>
              <div className="mt-1.5">
                <Params params={p.arguments} empty="No arguments" />
              </div>
            </li>
          ))}
        </ul>
      </Panel>
    </div>
  );
}
