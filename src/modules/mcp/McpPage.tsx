import { Button, Switch, Tabs } from "@heroui/react";
import { Activity, Bot, ChevronDown, PlugZap, ScrollText, Trash2, Users } from "lucide-react";
import { Fragment, useEffect, useMemo, useState } from "react";
import { useApp } from "@/app/store";
import { StatusDot, ToneChip } from "@/components/ui/Badges";
import { CodeBlock, CopyButton } from "@/components/ui/Code";
import { useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { SelectInput } from "@/components/ui/Fields";
import { PageHeader, Panel, Stat } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { McpAuditFilter, McpAuditResult, McpAuditRow, McpCatalog, McpClientConfigs, McpClientRow, McpPolicy, McpPolicyRow, McpStatus } from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";
import { ApprovalCenter } from "./ApprovalCenter";
import { ResourcesAndPrompts, ToolsCatalog } from "./CatalogViews";
import { approvalLabel, CATEGORY_SHORT, CATEGORY_TONE, type McpTab, POLICY_LABEL, RESULT_META, resultMeta, shortTool, tabFromParams } from "./mcpMeta";

/* ───────────────────────── overview ───────────────────────── */

function StatusStrip({ s, clients }: { s: McpStatus; clients: McpClientRow[] }) {
  const recent = clients.filter((c) => !c.connected).length;
  return (
    <Panel contentClassName="pt-4">
      <div className="grid grid-cols-2 gap-x-6 gap-y-5 md:grid-cols-3 2xl:grid-cols-6">
        <Stat
          label="Server"
          value={
            <span className="flex items-center gap-2">
              <StatusDot tone={s.running ? "success" : "default"} pulse={s.running} />
              {s.running ? "Running" : "Stopped"}
            </span>
          }
          hint={s.running ? `since ${formatRelative(s.startedAt)}` : s.enabled ? "Starting…" : "MCP is off"}
          tone={s.running ? "success" : "default"}
        />
        <Stat label="Transport" value="STDIO" hint="the client starts cyberhub-mcp" />
        <Stat
          label="Local bridge"
          value={s.running ? "Listening" : "Closed"}
          hint={s.running ? `${s.address} · this computer only` : "no port is open"}
          tone={s.running ? "accent" : "default"}
        />
        <Stat label="Clients connected" value={s.connections.length} hint={recent ? `${recent} ${s.connections.length ? "more " : ""}seen before` : "none seen before"} />
        <Stat label="Catalog" value={s.toolCount} hint={`tools · ${s.resourceCount} resources · ${s.promptCount} prompts`} />
        <Stat label="Waiting for approval" value={s.pending} hint={s.pending ? "needs your decision" : "nothing waiting"} tone={s.pending ? "warning" : "default"} />
      </div>
    </Panel>
  );
}

function ActivityList({ rows, compact }: { rows: McpAuditRow[]; compact?: boolean }) {
  return (
    <ul className="flex flex-col">
      {rows.map((r) => {
        const res = resultMeta(r.result);
        return (
          <li key={r.id} className="flex items-center justify-between gap-3 rounded-md px-2 py-1.5 text-[12.5px] odd:bg-white/[0.02]">
            <span className="flex min-w-0 items-center gap-2">
              <StatusDot tone={res.tone} />
              <code className="truncate text-[12px]">{shortTool(r.tool)}</code>
              {!compact && <span className="truncate text-muted">{r.client}</span>}
            </span>
            <span className="flex shrink-0 items-center gap-3 text-muted">
              {r.approval !== "not_required" && <span>{approvalLabel(r.approval)}</span>}
              <span className={cn(res.tone === "danger" && "text-danger-soft-foreground", res.tone === "success" && "text-foreground/80")}>{res.label}</span>
              <span className="w-[72px] text-right">{formatRelative(r.at)}</span>
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function Overview({ s, clients, onTab, toggle, toggling }: { s: McpStatus; clients: McpClientRow[]; onTab: (t: McpTab) => void; toggle: (on: boolean) => void; toggling: boolean }) {
  const audit = useQuery(["mcp"], () => api.mcpAudit(8), []);
  return (
    <div className="flex flex-col gap-4">
      <StatusStrip s={s} clients={clients} />
      {!s.enabled && (
        <EmptyBlock
          icon={PlugZap}
          title="MCP is off"
          description="Turn it on to let AI clients such as Claude Code use Cyber Hub. Cyber Hub then listens on this computer only. Clients never see your API keys, and you approve every sensitive request."
          action={
            <Button variant="primary" onPress={() => toggle(true)} isDisabled={toggling}>
              Turn on MCP
            </Button>
          }
        />
      )}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <Panel
          title="Recent activity"
          actions={
            <Button size="sm" variant="ghost" onPress={() => onTab("activity")}>
              Full log
            </Button>
          }
        >
          {audit.error ? (
            <ErrorBlock message={audit.error} onRetry={audit.reload} />
          ) : !audit.data ? (
            <LoadingRows rows={4} />
          ) : audit.data.length === 0 ? (
            <EmptyBlock compact icon={ScrollText} title="No MCP requests yet" description="Calls from AI clients appear here as they happen." />
          ) : (
            <ActivityList rows={audit.data} />
          )}
        </Panel>
        <Panel
          title="Clients"
          actions={
            <Button size="sm" variant="ghost" onPress={() => onTab("clients")}>
              All clients
            </Button>
          }
        >
          {clients.length === 0 ? (
            <EmptyBlock compact icon={Users} title="No clients yet" description="A client appears once it calls a tool." action={<Button size="sm" variant="tertiary" onPress={() => onTab("connect")}>Connect a client</Button>} />
          ) : (
            <ul className="flex flex-col gap-0.5">
              {clients.slice(0, 6).map((c) => (
                <li key={c.label} className="flex items-center justify-between gap-3 rounded-md px-2 py-1.5 text-[12.5px] odd:bg-white/[0.02]">
                  <span className="flex min-w-0 items-center gap-2">
                    <StatusDot tone={c.connected ? "success" : "default"} />
                    <span className="truncate">{c.name}</span>
                    {c.version && <span className="text-muted">{c.version}</span>}
                  </span>
                  <span className="shrink-0 text-muted">{c.connected ? "Connected" : formatRelative(c.lastActivity)}</span>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 text-[12px] text-muted">Names and versions are reported by each client and are not verified.</p>
        </Panel>
      </div>
    </div>
  );
}

/* ───────────────────────── clients ───────────────────────── */

function ClientsView({ clients, error, reload }: { clients: McpClientRow[] | undefined; error: string | null; reload: () => void }) {
  return (
    <Panel
      title="Clients"
      description="Connected now (from the running bridge) and seen before (from the audit log). Client names and versions are self-reported: any program on this computer that can read the bridge key can claim any name, so they are labels, not identities, and are never used for permissions."
    >
      {error && <ErrorBlock message={error} onRetry={reload} />}
      {!clients && !error && <LoadingRows rows={3} />}
      {clients && clients.length === 0 && <EmptyBlock compact icon={Users} title="No clients yet" description="A client appears here once it connects and calls a tool." />}
      {clients && clients.length > 0 && (
        <div className="scroll-area overflow-x-auto">
          <table className="w-full min-w-[760px] text-left text-[12.5px]">
            <thead className="text-muted">
              <tr>
                {["Client (reported)", "Version (reported)", "Status", "Last activity", "Requests", "Most recent request"].map((h) => (
                  <th key={h} className="px-2.5 pb-2 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {clients.map((c) => {
                const res = resultMeta(c.lastResult);
                return (
                  <tr key={c.label} className="odd:bg-white/[0.02]">
                    <td className="rounded-l-md px-2.5 py-2 font-medium">{c.name}</td>
                    <td className="px-2.5 py-2 text-muted">{c.version || "—"}</td>
                    <td className="px-2.5 py-2">
                      <span className="flex items-center gap-2">
                        <StatusDot tone={c.connected ? "success" : "default"} />
                        {c.connected ? `Connected${c.connections > 1 ? ` (${c.connections} sessions)` : ""}` : "Not connected"}
                      </span>
                      {c.connected && c.connectedSince && <div className="text-[11.5px] text-muted">since {formatRelative(c.connectedSince)}</div>}
                    </td>
                    <td className="px-2.5 py-2 text-muted">{c.lastActivity ? formatRelative(c.lastActivity) : "—"}</td>
                    <td className="tabular px-2.5 py-2">
                      {c.loggedRequests}
                      {c.connected && <span className="text-muted"> · {c.sessionRequests} this session</span>}
                    </td>
                    <td className="rounded-r-md px-2.5 py-2">
                      {c.lastTool ? (
                        <span className="flex flex-wrap items-center gap-2">
                          <code className="text-[12px]">{shortTool(c.lastTool)}</code>
                          <ToneChip tone={res.tone}>{res.label}</ToneChip>
                        </span>
                      ) : (
                        <span className="text-muted">—</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

/* ───────────────────────── permissions ───────────────────────── */

const CATEGORY_HELP: Record<string, string> = {
  read: "Status, projects, scope, the tool catalog, runs, findings, cached lookups and the approval status. Always allowed; nothing leaves this computer.",
  external_lookup: "Sends an indicator or query to VirusTotal, threat-intelligence providers or NVD (CVE tools with live: true). Uses your provider quota.",
  local_write: "Creates findings in a project and saves indicators in Threat Intel.",
  run_tools: "Starts a catalog security tool against targets inside a project's authorized scope. The system confirmation dialog always follows your approval.",
  file_upload: "Uploads a file to VirusTotal, where it becomes available to the security community. You pick the file; the system confirmation follows.",
  export: "Saves a project or threat-intelligence report to a location you choose in the system save dialog.",
};

function PolicyRow({ row, titles }: { row: McpPolicyRow; titles: Map<string, string> }) {
  const [saving, setSaving] = useState(false);
  const set = async (p: McpPolicy) => {
    if (p === row.policy) return;
    setSaving(true);
    try {
      await api.mcpSetPolicy(row.category, p);
      invalidate("mcp");
      notify.success(`${CATEGORY_SHORT[row.category] ?? row.label}: ${POLICY_LABEL[p]}`);
    } catch (e) {
      notify.error("Could not change the permission", e);
    } finally {
      setSaving(false);
    }
  };
  return (
    <li className="grid grid-cols-1 gap-3 rounded-xl bg-white/[0.025] px-4 py-3.5 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center">
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[14px] font-medium">{row.label}</span>
          <ToneChip tone={CATEGORY_TONE[row.category] ?? "default"} dot={false}>
            {row.tools.length} tool{row.tools.length === 1 ? "" : "s"}
          </ToneChip>
        </div>
        <p className="mt-1 max-w-[80ch] text-[12.5px] text-muted">{CATEGORY_HELP[row.category]}</p>
        <p className="mt-1 text-[12px] text-muted/80">{row.tools.map((t) => titles.get(t) ?? shortTool(t)).join(" · ")}</p>
      </div>
      <div className="flex gap-1" role="radiogroup" aria-label={row.label}>
        {row.options.map((o) => (
          <button
            key={o}
            type="button"
            role="radio"
            aria-checked={row.policy === o}
            disabled={saving || row.options.length === 1}
            onClick={() => set(o)}
            className={cn(
              "min-w-[72px] rounded-md px-3 py-1.5 text-[12.5px] outline-none transition-colors focus-visible:ring-2 focus-visible:ring-focus disabled:cursor-default",
              row.policy === o
                ? o === "deny"
                  ? "bg-danger-soft text-danger-soft-foreground"
                  : o === "allow"
                    ? "bg-success-soft text-success-soft-foreground"
                    : "bg-accent-soft text-accent-soft-foreground"
                : "bg-white/[0.04] text-muted hover:bg-white/[0.08]",
            )}
          >
            {POLICY_LABEL[o]}
          </button>
        ))}
      </div>
    </li>
  );
}

function PermissionsView({ s, catalog }: { s: McpStatus; catalog?: McpCatalog }) {
  const titles = useMemo(() => new Map((catalog?.tools ?? []).map((t) => [t.name, t.title])), [catalog]);
  return (
    <Panel
      title="What MCP clients may do"
      description="Applies to every client. “Ask me” shows each request in the Approval Center, where only you can decide. Running tools, uploading files and exporting can never be set to Allow. Scope rules, exclusions and system dialogs apply to MCP requests exactly as they do to your own."
    >
      <ul className="flex flex-col gap-2">
        {s.policy.map((row) => (
          <PolicyRow key={row.category} row={row} titles={titles} />
        ))}
      </ul>
      <p className="mt-3 text-[12px] text-muted">Defaults: reading is allowed; everything else asks you.</p>
    </Panel>
  );
}

/* ───────────────────────── activity ───────────────────────── */

const ALL = "all";

function AuditTable({ rows, projects }: { rows: McpAuditRow[]; projects: Map<number, string> }) {
  const [open, setOpen] = useState<number | null>(null);
  return (
    <div className="scroll-area overflow-x-auto">
      <table className="w-full min-w-[940px] text-left text-[12.5px]">
        <thead className="sticky top-0 bg-surface text-muted">
          <tr>
            {["When", "Client", "Tool", "Category", "Project", "Approval", "Result", "Run", "Duration", ""].map((h, i) => (
              <th key={i} className="whitespace-nowrap px-2.5 pb-2 font-medium" title={h === "Client" ? "Name reported by the client" : undefined}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const res = resultMeta(r.result);
            const expanded = open === r.id;
            return (
              <Fragment key={r.id}>
                <tr className={cn("align-top", expanded ? "bg-white/[0.04]" : "odd:bg-white/[0.02]")}>
                  <td className="whitespace-nowrap rounded-l-md px-2.5 py-1.5 text-muted" title={r.at}>
                    {formatRelative(r.at)}
                  </td>
                  <td className="max-w-[200px] truncate whitespace-nowrap px-2.5 py-1.5" title={r.client}>
                    {r.client}
                  </td>
                  <td className="px-2.5 py-1.5">
                    <code className="text-[12px]">{shortTool(r.tool)}</code>
                  </td>
                  <td className="whitespace-nowrap px-2.5 py-1.5 text-muted">{r.category ? (CATEGORY_SHORT[r.category] ?? r.category) : "—"}</td>
                  <td className="max-w-[180px] truncate whitespace-nowrap px-2.5 py-1.5 text-muted">{r.projectId != null ? (projects.get(r.projectId) ?? `#${r.projectId}`) : "—"}</td>
                  <td className="whitespace-nowrap px-2.5 py-1.5 text-muted">{approvalLabel(r.approval)}</td>
                  <td className="whitespace-nowrap px-2.5 py-1.5">
                    <ToneChip tone={res.tone}>{res.label}</ToneChip>
                  </td>
                  <td className="px-2.5 py-1.5">{r.executionId != null ? `#${r.executionId}` : "—"}</td>
                  <td className="tabular whitespace-nowrap px-2.5 py-1.5 text-muted">{r.durationMs >= 1000 ? `${(r.durationMs / 1000).toFixed(1)} s` : `${r.durationMs} ms`}</td>
                  <td className="rounded-r-md px-1 py-1">
                    <Button size="sm" variant="ghost" isIconOnly aria-label={expanded ? "Hide details" : "Show details"} aria-expanded={expanded} onPress={() => setOpen(expanded ? null : r.id)} className="size-7">
                      <ChevronDown className={cn("size-3.5 transition-transform", expanded && "rotate-180")} />
                    </Button>
                  </td>
                </tr>
                {expanded && (
                  <tr className="bg-white/[0.04]">
                    <td colSpan={10} className="rounded-b-md px-2.5 pt-0 pb-3">
                      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                        <div>
                          <div className="mb-1 text-[12px] text-muted">Arguments (credentials redacted)</div>
                          <CodeBlock code={prettyArgs(r.arguments)} maxHeight={220} />
                        </div>
                        <div className="text-[12.5px]">
                          <div className="mb-1 text-[12px] text-muted">Result summary</div>
                          <p>{r.message || (r.result === "ok" ? "Completed." : res.label)}</p>
                          {r.approvalId && <p className="mt-1 text-muted">Approval {r.approvalId}</p>}
                          <p className="mt-1 text-muted">
                            Connection #{r.connection} · {new Date(r.at).toLocaleString()}
                          </p>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function prettyArgs(s: string): string {
  try {
    return JSON.stringify(JSON.parse(s), null, 2);
  } catch {
    return s;
  }
}

function ActivityView({ clients, policy, projects }: { clients: McpClientRow[]; policy: McpPolicyRow[]; projects: Map<number, string> }) {
  const [client, setClient] = useState(ALL);
  const [category, setCategory] = useState(ALL);
  const [result, setResult] = useState(ALL);
  const confirm = useConfirm();
  const filter: McpAuditFilter = {
    client: client === ALL ? undefined : client,
    category: category === ALL ? undefined : category,
    result: result === ALL ? undefined : (result as McpAuditResult),
  };
  const audit = useQuery(["mcp"], () => api.mcpAudit(200, filter), [client, category, result]);
  const filtered = client !== ALL || category !== ALL || result !== ALL;

  const clear = async () => {
    if (await confirm.ask({ title: "Clear the MCP audit log?", body: "Every recorded MCP call is deleted. Runs, findings and other data are kept.", confirmLabel: "Clear log" })) {
      await api.mcpAuditClear().catch((e) => notify.error("Could not clear the log", e));
      invalidate("mcp");
    }
  };

  return (
    <Panel
      title="Activity and audit"
      description="Every MCP call, including refused ones, from the local audit log (last 1,000). Arguments and messages are stored with credentials redacted; the newest 200 matching entries are shown."
      actions={
        <Button size="sm" variant="ghost" onPress={clear} isDisabled={!audit.data?.length && !filtered}>
          <Trash2 className="size-3.5" />
          Clear log
        </Button>
      }
      toolbar={
        <div className="flex flex-col gap-2 px-4 pb-3 md:flex-row md:flex-wrap md:items-center">
          <SelectInput
            aria-label="Client"
            value={client}
            onChange={setClient}
            className="md:w-[240px]"
            options={[{ id: ALL, label: "All clients" }, ...clients.map((c) => ({ id: c.label, label: c.label }))]}
          />
          <SelectInput
            aria-label="Category"
            value={category}
            onChange={setCategory}
            className="md:w-[200px]"
            options={[{ id: ALL, label: "All categories" }, ...policy.map((p) => ({ id: p.category, label: CATEGORY_SHORT[p.category] ?? p.label }))]}
          />
          <SelectInput
            aria-label="Status"
            value={result}
            onChange={setResult}
            className="md:w-[200px]"
            options={[{ id: ALL, label: "Any status" }, ...Object.entries(RESULT_META).map(([id, m]) => ({ id, label: m.label }))]}
          />
          {filtered && (
            <Button
              size="sm"
              variant="ghost"
              onPress={() => {
                setClient(ALL);
                setCategory(ALL);
                setResult(ALL);
              }}
            >
              Reset filters
            </Button>
          )}
        </div>
      }
    >
      {audit.error && <ErrorBlock message={audit.error} onRetry={audit.reload} />}
      {!audit.data && !audit.error && <LoadingRows rows={5} />}
      {audit.data && audit.data.length === 0 && (
        <EmptyBlock compact icon={Activity} title={filtered ? "No entries match these filters" : "No MCP requests yet"} description={filtered ? "Try another client, category or status." : "Calls from AI clients are recorded here."} />
      )}
      {audit.data && audit.data.length > 0 && <AuditTable rows={audit.data} projects={projects} />}
      {confirm.element}
    </Panel>
  );
}

/* ───────────────────────── connect ───────────────────────── */

const TROUBLESHOOTING: [string, string][] = [
  ["Tools return “Cyber Hub is not running or MCP is turned off”", "Start Cyber Hub and turn on MCP at the top of this page."],
  ["“could not authenticate the Cyber Hub app”", "Restart Cyber Hub (it writes a new key) and make sure cyberhub-mcp comes from the same build as the app."],
  ["A tool returns awaiting_approval", "Decide in the Approval Center; the client can poll cyberhub_get_approval_status."],
  ["“… is turned off for MCP clients”", "That category is set to Block under Permissions."],
  ["“Arguments that refer to local files … are not accepted”", "Pass targets directly, or start file-based runs in Cyber Hub."],
  ["Nothing appears under Activity", "The client did not reach the app: check the first row, then the client's own MCP log."],
];

function ConnectView({ s }: { s: McpStatus }) {
  const [cfg, setCfg] = useState<McpClientConfigs | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!s.serverPath) return;
    api.mcpClientConfigs().then(setCfg).catch((e) => setError(errorMessage(e)));
  }, [s.serverPath]);

  return (
    <div className="grid grid-cols-1 gap-4 2xl:grid-cols-2">
      <Panel title="Server executable" description="MCP clients start this program; it talks to Cyber Hub over the local bridge and holds no credentials." className="2xl:col-span-2">
        {s.serverPath ? (
          <div className="flex min-w-0 items-center gap-2 rounded-lg bg-white/[0.025] px-3 py-2">
            <code className="min-w-0 flex-1 truncate font-mono text-[12.5px]" data-selectable title={s.serverPath}>
              {s.serverPath}
            </code>
            <CopyButton text={s.serverPath} label="Copy path" />
          </div>
        ) : (
          <p className="text-[12.5px] text-warning-soft-foreground">{s.serverPathNote ?? "cyberhub-mcp was not found next to the Cyber Hub executable."} The setup commands appear here once it exists.</p>
        )}
        {s.serverPath && s.serverPathNote && <p className="mt-2 text-[12.5px] text-warning-soft-foreground">{s.serverPathNote}</p>}
        {!s.enabled && <p className="mt-2 text-[12.5px] text-muted">MCP is off. Clients can be configured now, but their calls are refused until you turn it on.</p>}
      </Panel>

      {error && <ErrorBlock message={error} className="2xl:col-span-2" />}
      {s.serverPath && !cfg && !error && <LoadingRows rows={3} />}
      {cfg && (
        <>
          <Panel title="Claude Code" description="Run this once in a terminal. It adds Cyber Hub for your user, in every project.">
            <CodeBlock code={cfg.claudeCodeCommand} actions={<CopyButton text={cfg.claudeCodeCommand} label="Copy command" />} />
            <p className="mt-3 mb-1.5 text-[12.5px] text-muted">
              Or add it to a project's <code>.mcp.json</code>:
            </p>
            <CodeBlock code={cfg.claudeCodeJson} actions={<CopyButton text={cfg.claudeCodeJson} label="Copy JSON" />} />
            <div className="mt-3 text-[12.5px] text-muted">
              <div className="mb-1 font-medium text-foreground">Verify</div>
              Run <code>claude mcp list</code> (cyberhub shows as connected) or type <code>/mcp</code> in Claude Code. Remove it with <code>claude mcp remove cyberhub -s user</code>.
            </div>
          </Panel>
          <Panel title="Claude Desktop" description="Add the entry to Claude Desktop's configuration, then restart Claude Desktop.">
            {cfg.claudeDesktopConfigPath ? (
              <div className="mb-2 text-[12.5px] text-muted">
                Configuration file, merge with any existing <code>mcpServers</code>:
                <div className="mt-1 flex min-w-0 items-center gap-2 rounded-lg bg-white/[0.025] px-3 py-1.5">
                  <code className="min-w-0 flex-1 truncate text-[12px] text-foreground" data-selectable title={cfg.claudeDesktopConfigPath}>
                    {cfg.claudeDesktopConfigPath}
                  </code>
                  <CopyButton text={cfg.claudeDesktopConfigPath} label="Copy file path" />
                </div>
              </div>
            ) : (
              <p className="mb-2 text-[12.5px] text-muted">Claude Desktop is not available for this operating system; the JSON works with other MCP clients that read this format.</p>
            )}
            <CodeBlock code={cfg.claudeDesktopJson} actions={<CopyButton text={cfg.claudeDesktopJson} label="Copy JSON" />} />
            <div className="mt-3 text-[12.5px] text-muted">
              <div className="mb-1 font-medium text-foreground">Verify</div>
              In a new chat, the tools menu lists the cyberhub tools. To remove it, delete the <code>cyberhub</code> entry and restart Claude Desktop.
            </div>
          </Panel>
        </>
      )}

      <Panel title="Troubleshooting" className="2xl:col-span-2" description="The configuration contains only the executable path: no keys, tokens or environment variables.">
        <dl className="grid grid-cols-1 gap-x-6 gap-y-2.5 text-[12.5px] md:grid-cols-[minmax(0,1fr)_minmax(0,1.3fr)]">
          {TROUBLESHOOTING.map(([q, a]) => (
            <div key={q} className="contents">
              <dt className="font-medium">{q}</dt>
              <dd className="text-muted">{a}</dd>
            </div>
          ))}
        </dl>
      </Panel>
    </div>
  );
}

/* ───────────────────────── page ───────────────────────── */

const TAB_LABEL: Record<McpTab, string> = {
  overview: "Overview",
  approvals: "Approvals",
  clients: "Clients",
  tools: "Tools",
  catalog: "Resources & prompts",
  permissions: "Permissions",
  activity: "Activity",
  connect: "Connect",
};

export default function McpPage() {
  const { runtime, route, navigate } = useApp();
  const tab = tabFromParams(route.params);
  const status = useQuery(["mcp"], api.mcpStatus, [], runtime);
  const clients = useQuery(["mcp"], api.mcpClients, [], runtime);
  const catalog = useQuery(["mcp"], api.mcpCatalog, [], runtime);
  const projects = useQuery(["projects"], api.projectsList, [], runtime);
  const [toggling, setToggling] = useState(false);

  // live status: connections, pending requests and the log, while the page is open and visible
  useEffect(() => {
    if (!runtime) return;
    const t = setInterval(() => !document.hidden && invalidate("mcp"), 4000);
    return () => clearInterval(t);
  }, [runtime]);

  const projectNames = useMemo(() => new Map((projects.data ?? []).map((p) => [p.id, p.name])), [projects.data]);
  const s = status.data;
  const setTab = (t: McpTab) => navigate("mcp", { tab: t });

  const toggle = async (on: boolean) => {
    setToggling(true);
    try {
      await api.mcpSetEnabled(on);
      invalidate("mcp");
      notify.success(on ? "MCP is on" : "MCP is off", on ? "AI clients on this computer can now connect." : "Connected clients were disconnected and waiting requests cancelled.");
    } catch (e) {
      notify.error("Could not change MCP", e);
    } finally {
      setToggling(false);
    }
  };

  return (
    <div>
      <PageHeader
        title="MCP"
        description="Let AI clients such as Claude Code and Claude Desktop use Cyber Hub through the Model Context Protocol. They work inside your projects' scope, never see your API keys, and every sensitive request waits for you."
        actions={
          s && (
            <Switch size="sm" isSelected={s.enabled} isDisabled={!runtime || toggling} onChange={toggle} aria-label="Allow MCP clients">
              <Switch.Content className="flex items-center gap-2.5 rounded-lg bg-white/[0.035] px-3 py-2 text-[13px]">
                <Switch.Control>
                  <Switch.Thumb />
                </Switch.Control>
                <span className="flex items-center gap-2">
                  <StatusDot tone={s.running ? "success" : "default"} />
                  {s.running ? "Running" : "Stopped"}
                  <span className="text-muted">· Allow MCP clients</span>
                </span>
              </Switch.Content>
            </Switch>
          )
        }
      />

      {!runtime && <EmptyBlock icon={Bot} title="MCP is managed by the Cyber Hub desktop app" description="Open Cyber Hub itself to manage AI client access." />}
      {runtime && status.error && <ErrorBlock message={status.error} onRetry={status.reload} />}
      {runtime && !s && !status.error && <LoadingRows rows={6} />}

      {s && (
        <>
          <Tabs selectedKey={tab} onSelectionChange={(k) => setTab(String(k) as McpTab)} className="mb-4">
            <Tabs.ListContainer className="scroll-area overflow-x-auto">
              <Tabs.List aria-label="MCP sections" className="h-9">
                {(Object.keys(TAB_LABEL) as McpTab[]).map((id) => (
                  <Tabs.Tab key={id} id={id} className="gap-1.5 whitespace-nowrap px-3 text-[13px]">
                    {TAB_LABEL[id]}
                    {id === "approvals" && s.pending > 0 && <span className="tabular rounded-full bg-warning-soft px-1.5 text-[11px] leading-[18px] text-warning-soft-foreground">{s.pending}</span>}
                    {id === "clients" && s.connections.length > 0 && <span className="tabular text-[11.5px] text-muted">{s.connections.length}</span>}
                    <Tabs.Indicator />
                  </Tabs.Tab>
                ))}
              </Tabs.List>
            </Tabs.ListContainer>
          </Tabs>

          {tab === "overview" && <Overview s={s} clients={clients.data ?? []} onTab={setTab} toggle={toggle} toggling={toggling} />}
          {tab === "approvals" && <ApprovalCenter running={s.running} projects={projects.data ?? []} />}
          {tab === "clients" && <ClientsView clients={clients.data} error={clients.error} reload={clients.reload} />}
          {(tab === "tools" || tab === "catalog") &&
            (catalog.error ? (
              <ErrorBlock message={catalog.error} onRetry={catalog.reload} />
            ) : !catalog.data ? (
              <LoadingRows rows={8} />
            ) : tab === "tools" ? (
              <ToolsCatalog catalog={catalog.data} />
            ) : (
              <ResourcesAndPrompts catalog={catalog.data} />
            ))}
          {tab === "permissions" && <PermissionsView s={s} catalog={catalog.data} />}
          {tab === "activity" && <ActivityView clients={clients.data ?? []} policy={s.policy} projects={projectNames} />}
          {tab === "connect" && <ConnectView s={s} />}
        </>
      )}
    </div>
  );
}
