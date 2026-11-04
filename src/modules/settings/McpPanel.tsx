import { Button, Switch } from "@heroui/react";
import { Bot, Copy, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { useApp } from "@/app/store";
import { StatusDot, ToneChip } from "@/components/ui/Badges";
import { CodeBlock, CopyButton } from "@/components/ui/Code";
import { useConfirm } from "@/components/ui/Dialogs";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api, errorMessage } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { McpClientConfigs, McpPolicy, McpPolicyRow } from "@/lib/types";
import { cn, formatRelative } from "@/lib/utils";

const POLICY_LABEL: Record<McpPolicy, string> = { allow: "Allow", ask: "Ask me", deny: "Block" };

const RESULT_TONE: Record<string, "success" | "warning" | "danger" | "default"> = { ok: "success", awaiting_approval: "warning", refused: "default", error: "danger" };

function PolicyRow({ row }: { row: McpPolicyRow }) {
  const [saving, setSaving] = useState(false);
  const set = async (p: McpPolicy) => {
    setSaving(true);
    try {
      await api.mcpSetPolicy(row.category, p);
      invalidate("mcp");
    } catch (e) {
      notify.error("Could not change the permission", e);
    } finally {
      setSaving(false);
    }
  };
  return (
    <li className="flex flex-wrap items-center justify-between gap-3 rounded-lg bg-white/[0.02] px-3 py-2">
      <div className="min-w-0">
        <div className="text-[13px]">{row.label}</div>
        <div className="truncate text-[11.5px] text-muted" title={row.tools.join(", ")}>
          {row.tools.length} tool{row.tools.length === 1 ? "" : "s"}
          {row.category === "run_tools" && " · the system confirmation dialog always follows"}
          {row.category === "file_upload" && " · you pick the file; the system confirmation follows"}
        </div>
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
              "rounded-md px-2.5 py-1 text-[12px] outline-none transition-colors focus-visible:ring-2 focus-visible:ring-focus",
              row.policy === o ? (o === "deny" ? "bg-danger-soft text-danger-soft-foreground" : o === "allow" ? "bg-success-soft text-success-soft-foreground" : "bg-accent-soft text-accent-soft-foreground") : "bg-white/[0.04] text-muted hover:bg-white/[0.08]",
            )}
          >
            {POLICY_LABEL[o]}
          </button>
        ))}
      </div>
    </li>
  );
}

function Setup({ serverPath }: { serverPath: string | null }) {
  const [cfg, setCfg] = useState<McpClientConfigs | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!serverPath) return;
    api.mcpClientConfigs().then(setCfg).catch((e) => setError(errorMessage(e)));
  }, [serverPath]);
  if (!serverPath) {
    return (
      <p className="text-[12.5px] text-warning-soft-foreground">
        The <code>cyberhub-mcp</code> executable was not found next to Cyber Hub. Build it with <code>cargo build --bin cyberhub-mcp</code> (see docs/MCP.md); the setup commands appear here once it exists.
      </p>
    );
  }
  if (error) return <ErrorBlock message={error} />;
  if (!cfg) return <LoadingRows rows={2} />;
  return (
    <div className="flex flex-col gap-4">
      <div>
        <div className="mb-1.5 text-[13px] font-medium">Claude Code</div>
        <p className="mb-2 text-[12.5px] text-muted">Run this once in a terminal (user scope, available in every project):</p>
        <CodeBlock code={cfg.claudeCodeCommand} actions={<CopyButton text={cfg.claudeCodeCommand} label="Copy command" />} />
        <p className="mt-2 text-[12.5px] text-muted">Or add it to a project's <code>.mcp.json</code>:</p>
        <CodeBlock code={cfg.claudeCodeJson} actions={<CopyButton text={cfg.claudeCodeJson} label="Copy JSON" />} />
        <p className="mt-2 text-[12px] text-muted">
          Check with <code>claude mcp list</code> or <code>/mcp</code> inside Claude Code. Remove with <code>claude mcp remove cyberhub -s user</code>.
        </p>
      </div>
      <div>
        <div className="mb-1.5 text-[13px] font-medium">Claude Desktop</div>
        {cfg.claudeDesktopConfigPath ? (
          <p className="mb-2 text-[12.5px] text-muted">
            Add this to <code data-selectable>{cfg.claudeDesktopConfigPath}</code> (merge with existing <code>mcpServers</code>), then restart Claude Desktop:
          </p>
        ) : (
          <p className="mb-2 text-[12.5px] text-muted">Claude Desktop is not available for this operating system; use the JSON with any MCP client that reads this format.</p>
        )}
        <CodeBlock code={cfg.claudeDesktopJson} actions={<CopyButton text={cfg.claudeDesktopJson} label="Copy JSON" />} />
        <p className="mt-2 text-[12px] text-muted">To remove it, delete the <code>cyberhub</code> entry and restart Claude Desktop.</p>
      </div>
    </div>
  );
}

export function McpPanel() {
  const { runtime } = useApp();
  const status = useQuery(["mcp"], api.mcpStatus, [], runtime);
  const audit = useQuery(["mcp"], () => api.mcpAudit(40), [], runtime);
  const pending = useQuery(["mcp"], api.mcpPending, [], runtime);
  const confirm = useConfirm();
  const [toggling, setToggling] = useState(false);

  // keep connection counts and the request log current while the panel is visible
  useEffect(() => {
    if (!runtime) return;
    const t = setInterval(() => invalidate("mcp"), 4000);
    return () => clearInterval(t);
  }, [runtime]);

  const s = status.data;
  const toggle = async (on: boolean) => {
    setToggling(true);
    try {
      await api.mcpSetEnabled(on);
      invalidate("mcp");
      notify.success(on ? "MCP clients can now connect" : "MCP turned off; connected clients were disconnected");
    } catch (e) {
      notify.error("Could not change MCP", e);
    } finally {
      setToggling(false);
    }
  };

  return (
    <Panel
      title={
        <span className="flex items-center gap-2">
          <Bot className="size-4 text-accent" />
          Integrations · MCP
        </span>
      }
      description="Let AI clients such as Claude Code and Claude Desktop use Cyber Hub through the Model Context Protocol. Sensitive requests wait for your approval here; credentials are never available to them."
      className="xl:col-span-2"
      actions={
        s && (
          <Switch size="sm" isSelected={s.enabled} isDisabled={!runtime || toggling} onChange={toggle} aria-label="Allow MCP clients">
            <Switch.Content className="flex items-center gap-2 text-[13px]">
              <Switch.Control>
                <Switch.Thumb />
              </Switch.Control>
              Allow MCP clients
            </Switch.Content>
          </Switch>
        )
      }
    >
      {status.error && <ErrorBlock message={status.error} onRetry={status.reload} />}
      {!s && !status.error && <LoadingRows rows={3} />}
      {s && (
        <div className="flex flex-col gap-5">
          <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-[12.5px] md:grid-cols-2 xl:grid-cols-4">
            <div>
              <dt className="text-muted">Server</dt>
              <dd className="flex items-center gap-2">
                <StatusDot tone={s.running ? "success" : "default"} />
                {s.running ? `Listening on ${s.address} (this computer only)` : "Off"}
              </dd>
            </div>
            <div>
              <dt className="text-muted">Capabilities</dt>
              <dd>
                {s.toolCount} tools · {s.resourceCount} resources · {s.promptCount} prompts
              </dd>
            </div>
            <div>
              <dt className="text-muted">Connected clients</dt>
              <dd>{s.connections.length ? s.connections.map((c) => `${c.client} (${c.requests} requests)`).join(", ") : "None"}</dd>
            </div>
            <div>
              <dt className="text-muted">Waiting for approval</dt>
              <dd>{s.pending}</dd>
            </div>
            <div className="md:col-span-2 xl:col-span-4">
              <dt className="text-muted">Transport</dt>
              <dd>{s.transport}</dd>
            </div>
            <div className="md:col-span-2 xl:col-span-4">
              <dt className="text-muted">Executable</dt>
              <dd className="flex min-w-0 items-center gap-2">
                <code className="min-w-0 truncate font-mono text-[12px]" data-selectable title={s.serverPath ?? ""}>
                  {s.serverPath ?? "cyberhub-mcp not found next to Cyber Hub"}
                </code>
                {s.serverPath && <CopyButton text={s.serverPath} label="Copy path" />}
              </dd>
            </div>
          </dl>

          {pending.data && pending.data.length > 0 && (
            <div>
              <div className="mb-2 text-[13px] font-medium">Pending approvals</div>
              <ul className="flex flex-col gap-1.5">
                {pending.data.map((p) => (
                  <li key={p.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-warning-soft/40 px-3 py-2 text-[12.5px]">
                    <span className="min-w-0">
                      <span className="font-medium">{p.summary}</span> <span className="text-muted">· {p.client}</span>
                    </span>
                    <span className="flex gap-1">
                      <Button size="sm" variant="tertiary" onPress={() => api.mcpDecide(p.id, false).then(() => invalidate("mcp"))}>
                        Decline
                      </Button>
                      <Button size="sm" variant="primary" onPress={() => api.mcpDecide(p.id, true).then(() => invalidate("mcp"))}>
                        Approve
                      </Button>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div>
            <div className="mb-2 text-[13px] font-medium">What MCP clients may do</div>
            <ul className="grid grid-cols-1 gap-1.5 2xl:grid-cols-2">
              {s.policy.map((row) => (
                <PolicyRow key={row.category} row={row} />
              ))}
            </ul>
            <p className="mt-2 text-[12px] text-muted">
              “Ask me” shows a request in Cyber Hub that only you can approve; requests expire after 3 minutes. Scope rules, exclusions and system confirmation dialogs apply to MCP requests exactly as they do to your own.
            </p>
          </div>

          <div>
            <div className="mb-2 text-[13px] font-medium">Connect a client</div>
            <Setup serverPath={s.serverPath} />
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-[13px] font-medium">Recent requests</span>
              <Button
                size="sm"
                variant="ghost"
                isDisabled={!audit.data?.length}
                onPress={async () => {
                  if (await confirm.ask({ title: "Clear the MCP request log?", body: "The record of MCP tool calls is deleted. Runs, findings and other data are kept.", confirmLabel: "Clear log" })) {
                    await api.mcpAuditClear().catch((e) => notify.error("Could not clear the log", e));
                    invalidate("mcp");
                  }
                }}
              >
                <Trash2 className="size-3.5" />
                Clear
              </Button>
            </div>
            {!audit.data?.length ? (
              <EmptyBlock compact icon={Copy} title="No MCP requests yet" />
            ) : (
              <div className="scroll-area max-h-[320px] overflow-auto rounded-lg bg-white/[0.02]">
                <table className="w-full text-left text-[12px]">
                  <thead className="sticky top-0 bg-surface-secondary text-muted">
                    <tr>
                      {["When", "Client", "Tool", "Approval", "Result", "Run", "Time"].map((h) => (
                        <th key={h} className="px-2.5 py-1.5 font-medium">
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {audit.data.map((r) => (
                      <tr key={r.id} className="align-top odd:bg-white/[0.015]" title={`${r.arguments}${r.message ? `\n${r.message}` : ""}`}>
                        <td className="whitespace-nowrap px-2.5 py-1.5 text-muted">{formatRelative(r.at)}</td>
                        <td className="px-2.5 py-1.5">{r.client}</td>
                        <td className="px-2.5 py-1.5 font-mono">{r.tool.replace(/^cyberhub_/, "")}</td>
                        <td className="px-2.5 py-1.5 text-muted">{r.approval.replace(/_/g, " ")}</td>
                        <td className="px-2.5 py-1.5">
                          <ToneChip tone={RESULT_TONE[r.result] ?? "default"}>{r.result.replace(/_/g, " ")}</ToneChip>
                        </td>
                        <td className="px-2.5 py-1.5">{r.executionId ?? "—"}</td>
                        <td className="whitespace-nowrap px-2.5 py-1.5 text-muted">{r.durationMs} ms</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
      {confirm.element}
    </Panel>
  );
}
