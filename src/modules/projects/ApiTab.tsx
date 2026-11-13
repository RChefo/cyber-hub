// SPDX-License-Identifier: Apache-2.0
import { Button } from "@heroui/react";
import { ArrowUpRight, Check, FileCode2, ListChecks, ShieldAlert, Trash2, Upload } from "lucide-react";
import { useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { SeverityBadge, ToneChip } from "@/components/ui/Badges";
import { useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SearchInput, SelectInput } from "@/components/ui/Fields";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { ApiIssue, ApiRecordedIssue, ApiSpecSummary, ApiSpecView, Project } from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";
import { API_FORMAT_LABEL, METHOD_TONE, authLabel, builderParams, compareSummary, filterEndpoints, issueSummary, type EndpointView } from "./apisec";

const ENDPOINTS_SHOWN = 300;

/** Projects → APIs: the endpoint inventory of imported API definitions, and their checks. */
export function ApiTab({ project, onOpenFindings }: { project: Project; onOpenFindings: () => void }) {
  const { runtime } = useApp();
  const specs = useQuery(["apis"], () => api.apiSpecsList(project.id), [project.id], runtime);
  const [selected, setSelected] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const confirm = useConfirm();
  const list = specs.data ?? [];
  const current = list.find((s) => s.id === selected) ?? list[0] ?? null;

  const importFile = async () => {
    setBusy(true);
    try {
      const s = await api.apiSpecImport(project.id);
      if (s) {
        invalidate("apis", "findings", "assets", "activity");
        setSelected(s.id);
        notify.success("Added to the API inventory", `${s.endpoints} endpoints from ${s.name}`);
      }
    } catch (e) {
      notify.error("Could not import the file", e);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (s: ApiSpecSummary) => {
    const ok = await confirm.ask({
      title: `Remove ${s.name}?`,
      body: "The endpoints leave the inventory. The file stays in the evidence vault, and findings recorded from it stay.",
      confirmLabel: "Remove",
    });
    if (!ok) return;
    try {
      await api.apiSpecDelete(s.id);
      invalidate("apis", "activity");
      setSelected(null);
    } catch (e) {
      notify.error("Could not remove the definition", e);
    }
  };

  const importButton = (
    <Button size="sm" variant="primary" onPress={() => void importFile()} isPending={busy} isDisabled={!runtime}>
      <Upload className="size-3.5" />
      Import…
    </Button>
  );

  return (
    <div className="flex flex-col gap-4">
      <Panel
        title="API inventory"
        description="OpenAPI 3.x and Swagger 2.0 definitions (JSON or YAML), Postman collections and HAR captures, read into endpoints and checked against the OWASP API Security Top 10 (2023). Reading a file contacts nothing; only names are kept, never tokens or values."
        actions={importButton}
      >
        {specs.error ? (
          <ErrorBlock message={specs.error} onRetry={specs.reload} />
        ) : !specs.data ? (
          <LoadingRows rows={2} />
        ) : list.length === 0 ? (
          <EmptyBlock compact icon={FileCode2} title="No API definitions yet" description="Import a definition, a Postman collection, or a HAR capture saved from your browser's developer tools or your proxy." />
        ) : (
          <ul className="flex flex-col gap-1.5">
            {list.map((s) => (
              <li key={s.id}>
                <div
                  role="button"
                  tabIndex={0}
                  onClick={() => setSelected(s.id)}
                  onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && setSelected(s.id)}
                  className={cn("tile flex cursor-pointer items-center gap-3 px-3 py-2", current?.id === s.id && "bg-accent-soft/40")}
                >
                  <FileCode2 className="size-4 shrink-0 text-muted" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13.5px]">
                      {s.title || s.name}
                      {s.version && <span className="text-muted"> · {s.version}</span>}
                    </div>
                    <div className="truncate text-[12px] text-muted">
                      {API_FORMAT_LABEL[s.format] ?? s.format} · {s.endpoints} endpoints · {issueSummary(s)} · {s.tests} tests · {s.name} · {formatRelative(s.importedAt)}
                    </div>
                  </div>
                  <Button isIconOnly size="sm" variant="ghost" aria-label={`Remove ${s.name}`} onPress={() => void remove(s)}>
                    <Trash2 className="size-3.5" />
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>
      {list.length >= 2 && <Compare list={list} onOpenFindings={onOpenFindings} />}
      {current && <SpecDetail key={current.id} id={current.id} projectId={project.id} onOpenFindings={onOpenFindings} />}
      {confirm.element}
    </div>
  );
}

function SpecDetail({ id, projectId, onOpenFindings }: { id: number; projectId: number; onOpenFindings: () => void }) {
  const { runtime } = useApp();
  const q = useQuery(["apis", "findings", "projects"], () => api.apiSpecGet(id), [id], runtime);
  if (q.error) return <ErrorBlock message={q.error} onRetry={q.reload} />;
  if (!q.data) return <LoadingRows rows={4} />;
  const v = q.data;
  const issues = v.issues.filter((i) => i.kind === "issue");
  const tests = v.issues.filter((i) => i.kind === "test");
  return (
    <>
      {v.spec.warnings.length > 0 && (
        <ul className="flex flex-col gap-1 rounded-[10px] bg-warning-soft px-3 py-2 text-[12.5px] text-warning-soft-foreground">
          {v.spec.warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
      <Panel title="Security checks" description="Properties of the definition itself. Record one as a finding when it applies to the deployed API.">
        {issues.length === 0 ? (
          <EmptyBlock compact icon={ShieldAlert} title="No issues in this definition" description="The checks look at authentication, transport, secrets in URLs, page sizes and the inventory. Testing can still find flaws a definition cannot show." />
        ) : (
          <ul className="flex flex-col gap-2">
            {issues.map((i) => (
              <IssueRow key={i.id} issue={i} recordWith={() => api.apiIssueRecord(id, i.id)} recorded={v.recorded[i.id]} onOpenFindings={onOpenFindings} />
            ))}
          </ul>
        )}
      </Panel>
      {tests.length > 0 && (
        <Panel title="Test plan" description="Endpoints worth testing for flaws that no definition can show. Record a finding when a test shows one.">
          <ul className="flex flex-col gap-2">
            {tests.map((i) => (
              <IssueRow key={i.id} issue={i} recordWith={() => api.apiIssueRecord(id, i.id)} onOpenFindings={onOpenFindings} />
            ))}
          </ul>
        </Panel>
      )}
      <Endpoints view={v} projectId={projectId} />
    </>
  );
}

/** Two imports of the API compared: the older and the newer one, by default the last two. */
function Compare({ list, onOpenFindings }: { list: ApiSpecSummary[]; onOpenFindings: () => void }) {
  const { runtime } = useApp();
  const options = list.map((s) => ({ id: String(s.id), label: `${s.title || s.name}${s.version ? ` ${s.version}` : ""} · ${formatRelative(s.importedAt)}` }));
  const [older, setOlder] = useState<string | null>(String(list[1].id));
  const [newer, setNewer] = useState<string | null>(String(list[0].id));
  const ready = !!older && !!newer && older !== newer;
  const q = useQuery(["apis", "findings"], () => api.apiSpecCompare(Number(older), Number(newer)), [older, newer], runtime && ready);
  const v = ready ? q.data : undefined;
  const c = v?.comparison;
  return (
    <Panel title="Compare definitions" description="What changed between two imports of the API: endpoints added, removed and changed, and the changes that matter for security. Endpoints match by method and path; renamed path parameters do not count as changes.">
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-end gap-2">
          <SelectInput label="Older" value={older} onChange={setOlder} options={options} className="w-72" />
          <SelectInput label="Newer" value={newer} onChange={setNewer} options={options} className="w-72" />
        </div>
        {!ready ? (
          <p className="text-[12.5px] text-muted">Choose two different definitions.</p>
        ) : q.error ? (
          <ErrorBlock message={q.error} onRetry={q.reload} />
        ) : !c || !v ? (
          <LoadingRows rows={2} />
        ) : (
          <>
            <p className="text-[13px]">
              {compareSummary(c)}
              {c.serversAdded.length > 0 && <span className="text-muted"> · servers added: {c.serversAdded.join(", ")}</span>}
              {c.serversRemoved.length > 0 && <span className="text-muted"> · servers removed: {c.serversRemoved.join(", ")}</span>}
            </p>
            {c.issues.length > 0 && (
              <ul className="flex flex-col gap-2">
                {c.issues.map((i) => (
                  <IssueRow key={i.id} issue={i} recordWith={() => api.apiCompareRecord(v.old.id, v.new.id, i.id)} recorded={v.recorded[i.id]} onOpenFindings={onOpenFindings} />
                ))}
              </ul>
            )}
            {c.changed.length > 0 && (
              <section className="flex flex-col gap-1">
                <h3 className="text-[13.5px] font-medium">Changed endpoints ({c.changed.length})</h3>
                <ul className="flex flex-col gap-1">
                  {c.changed.map((ch) => (
                    <li key={ch.endpoint} className="tile px-3 py-1.5 text-[12.5px]">
                      <span className="font-mono">{ch.endpoint}</span>
                      <span className="text-muted"> · {ch.details.join(" · ")}</span>
                    </li>
                  ))}
                </ul>
              </section>
            )}
            {(
              [
                ["Added endpoints", c.added],
                ["Removed endpoints", c.removed],
              ] as const
            )
              .filter(([, items]) => items.length > 0)
              .map(([title, items]) => (
                <section key={title} className="flex flex-col gap-1">
                  <h3 className="text-[13.5px] font-medium">
                    {title} ({items.length})
                  </h3>
                  <p className="font-mono text-[12px] break-all text-muted">{items.join(" · ")}</p>
                </section>
              ))}
          </>
        )}
      </div>
    </Panel>
  );
}

function IssueRow({ issue, recordWith, recorded, onOpenFindings }: { issue: ApiIssue; recordWith: () => Promise<ApiRecordedIssue>; recorded?: number; onOpenFindings: () => void }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const shown = open ? issue.endpoints : issue.endpoints.slice(0, 5);
  const record = async () => {
    setBusy(true);
    try {
      const r = await recordWith();
      invalidate("findings", "apis", "activity");
      notify.success(r.created ? "Finding recorded" : "Already recorded", `Finding #${r.findingId}: ${issue.title}`);
    } catch (e) {
      notify.error("Could not record the finding", e);
    } finally {
      setBusy(false);
    }
  };
  return (
    <li className="panel-inset flex flex-col gap-1.5 px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        {issue.kind === "issue" ? <SeverityBadge severity={issue.severity} /> : <ListChecks className="size-3.5 text-muted" aria-hidden />}
        <span className="text-[13.5px] font-medium">{issue.title}</span>
        <ToneChip tone="default" dot={false} className="text-[11px]">
          {issue.owasp} {issue.category}
        </ToneChip>
        <span className="flex-1" />
        {issue.kind === "issue" &&
          (recorded ? (
            <Button size="sm" variant="ghost" onPress={onOpenFindings}>
              <Check className="size-3.5" />
              Finding #{recorded}
            </Button>
          ) : (
            <Button size="sm" variant="tertiary" onPress={() => void record()} isPending={busy}>
              Record finding
            </Button>
          ))}
      </div>
      <p className="text-[12.5px] text-muted">{issue.detail}</p>
      {issue.endpoints.length > 0 && (
        <ul className="flex flex-col gap-0.5 font-mono text-[11.5px]">
          {shown.map((e) => (
            <li key={e} className="break-all">
              {e}
            </li>
          ))}
          {issue.endpoints.length > 5 && (
            <li>
              <button type="button" className="text-accent hover:underline" onClick={() => setOpen((o) => !o)}>
                {open ? "Show fewer" : `Show all ${issue.endpoints.length}`}
              </button>
            </li>
          )}
        </ul>
      )}
      <p className="text-[12.5px]">
        <span className="text-muted">Recommendation: </span>
        {issue.recommendation}
      </p>
    </li>
  );
}

function Endpoints({ view, projectId }: { view: ApiSpecView; projectId: number }) {
  const { navigate } = useApp();
  const [text, setText] = useState("");
  const [method, setMethod] = useState("all");
  const [mode, setMode] = useState<EndpointView>("all");
  const { endpoints } = view.spec;
  const methods = useMemo(() => [...new Set(endpoints.map((e) => e.method))], [endpoints]);
  const matched = useMemo(() => filterEndpoints(endpoints, view.scope, { text, method, view: mode }), [endpoints, view.scope, text, method, mode]);
  const capture = view.spec.format === "har";
  return (
    <Panel
      title={`Endpoints (${endpoints.length})`}
      description="The request builder opens on an endpoint that the project's scope authorizes; path parameters stay as {name} until you fill them in."
      toolbar={
        <div className="flex flex-wrap items-end gap-2">
          <SearchInput value={text} onChange={setText} placeholder="Search paths, parameters, tags" className="min-w-[220px] flex-1" />
          <SelectInput aria-label="Method" value={method} onChange={setMethod} options={[{ id: "all", label: "All methods" }, ...methods.map((m) => ({ id: m, label: m }))]} className="w-40" />
          <SelectInput
            aria-label="Show"
            value={mode}
            onChange={(v) => setMode(v as EndpointView)}
            options={[
              { id: "all", label: "All endpoints" },
              { id: "anonymous", label: "Callable without credentials" },
              { id: "outOfScope", label: "Outside the scope" },
              { id: "deprecated", label: "Deprecated" },
            ]}
            className="w-60"
          />
        </div>
      }
    >
      {matched.length === 0 ? (
        <EmptyBlock compact icon={FileCode2} title="No endpoint matches" />
      ) : (
        <ul className="flex flex-col gap-1">
          {matched.slice(0, ENDPOINTS_SHOWN).map((i) => {
            const e = endpoints[i];
            const s = view.scope[i];
            return (
              <li key={`${e.method} ${e.path}`} className="tile flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2">
                <ToneChip tone={METHOD_TONE[e.method] ?? "default"} dot={false} className="w-[68px] justify-center font-mono text-[11px]">
                  {e.method}
                </ToneChip>
                <div className="min-w-0 flex-1">
                  <div className="truncate font-mono text-[12.5px]" title={s?.url}>
                    {e.path}
                    {e.deprecated && <span className="ml-2 font-sans text-[11.5px] text-warning">deprecated</span>}
                  </div>
                  <div className="truncate text-[12px] text-muted">
                    {[e.summary, e.params.length ? `${e.params.length} parameters` : "", e.bodyFields.length ? `body: ${e.bodyFields.slice(0, 6).join(", ")}${e.bodyFields.length > 6 ? "…" : ""}` : "", capture ? `seen ${e.seen}×` : ""]
                      .filter(Boolean)
                      .join(" · ")}
                  </div>
                </div>
                <span className={cn("text-[12px]", e.auth.length === 0 || e.anonymous ? "text-warning" : "text-muted")} title="Authentication">
                  {authLabel(e)}
                </span>
                {s && (
                  <span title={s.inScope ? s.url : s.reason}>
                    <ToneChip tone={s.inScope ? "success" : "default"}>{s.inScope ? "In scope" : "Not in scope"}</ToneChip>
                  </span>
                )}
                <Button
                  size="sm"
                  variant="ghost"
                  isDisabled={!s?.inScope}
                  aria-label={`Open ${e.method} ${e.path} in the request builder`}
                  onPress={() => s && navigate("utilities", builderParams(projectId, e.method, s.url))}
                >
                  <ArrowUpRight className="size-3.5" />
                  Request builder
                </Button>
              </li>
            );
          })}
          {matched.length > ENDPOINTS_SHOWN && <li className="px-1 text-[12px] text-muted">Showing {ENDPOINTS_SHOWN} of {matched.length}. Search to narrow the list.</li>}
        </ul>
      )}
    </Panel>
  );
}
