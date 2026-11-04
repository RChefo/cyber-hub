import { Button } from "@heroui/react";
import { CheckCircle2, Clock, Inbox, Info, ShieldAlert } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { ToneChip } from "@/components/ui/Badges";
import { EmptyBlock, ErrorBlock, LoadingRows } from "@/components/ui/Feedback";
import { Panel } from "@/components/ui/Panel";
import { notify } from "@/lib/actions";
import { api } from "@/lib/ipc";
import { invalidate, useQuery } from "@/lib/query";
import type { McpAuditRow, McpPending, ProjectSummary } from "@/lib/types";
import { useArmed } from "@/lib/useArmed";
import { cn, formatRelative } from "@/lib/utils";
import { approvalLabel, CATEGORY_SHORT, CATEGORY_TONE, formatCountdown, requestTarget, resultMeta, secondsLeft, shortTool } from "./mcpMeta";

const AFTER_APPROVAL: Record<string, string> = {
  run_tools: "After you approve, Cyber Hub shows its usual system confirmation for this run. Only approve if you are authorized to test these targets.",
  file_upload: "After you approve, you choose the file in the system file picker, and Cyber Hub asks again before anything is uploaded.",
  export: "After you approve, you choose where to save the file in the system save dialog.",
  external_lookup: "Approving sends the values above to the external service.",
  local_write: "Approving writes this to your local Cyber Hub data.",
};

function RequestItem({
  p,
  left,
  armed,
  projectName,
  onDecide,
  busy,
}: {
  p: McpPending;
  left: number;
  armed: boolean;
  projectName?: string;
  onDecide: (approve: boolean) => void;
  busy: boolean;
}) {
  const expired = left <= 0;
  const target = requestTarget(p);
  const risky = p.category === "run_tools" || p.category === "file_upload";
  const ttlShare = Math.min(1, left / 180);
  return (
    <li className="overflow-hidden rounded-xl bg-white/[0.03]">
      <div className="h-[2px] bg-white/[0.04]" aria-hidden>
        <div className={cn("h-full transition-[width] duration-1000 ease-linear", left < 30 ? "bg-danger" : "bg-warning")} style={{ width: `${ttlShare * 100}%` }} />
      </div>
      <div className="flex flex-col gap-4 p-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <ShieldAlert className="size-4 shrink-0 text-warning-soft-foreground" />
            <span className="text-[15px] font-medium tracking-tight">{p.summary}</span>
            <ToneChip tone={CATEGORY_TONE[p.category] ?? "default"}>{CATEGORY_SHORT[p.category] ?? p.category}</ToneChip>
          </div>
          <div className="mt-1 text-[12.5px] text-muted">
            <span className="text-foreground">{p.client}</span> <span>(name reported by the client, not verified)</span> · <code className="text-[12px]">{shortTool(p.tool)}</code> ·{" "}
            requested {formatRelative(p.createdAt)}
          </div>

          <dl className="mt-3 grid grid-cols-1 gap-x-6 gap-y-1.5 text-[12.5px] sm:grid-cols-[130px_1fr]">
            {p.projectId != null && (
              <>
                <dt className="text-muted">Project</dt>
                <dd>{projectName ? `${projectName} (#${p.projectId})` : `#${p.projectId}`}</dd>
              </>
            )}
            {target && (
              <>
                <dt className="text-muted">Target</dt>
                <dd className="min-w-0 break-words font-mono text-[12px]" data-selectable>
                  {target}
                </dd>
              </>
            )}
            {p.details
              .filter((d) => d.value && d.value !== target && d.label !== "Project")
              .map((d, i) => (
                <div key={i} className="contents">
                  <dt className="text-muted">{d.label}</dt>
                  <dd className={cn("min-w-0 break-words", d.label === "Warning" ? "text-warning-soft-foreground" : "font-mono text-[12px]")} data-selectable>
                    {d.value}
                  </dd>
                </div>
              ))}
          </dl>

          {p.checks.length > 0 && (
            <div className="mt-3">
              <div className="mb-1 text-[12px] font-medium text-muted">Validated by Cyber Hub before reaching you</div>
              <ul className="flex flex-col gap-1 text-[12.5px]">
                {p.checks.map((c) => (
                  <li key={c} className="flex items-start gap-2">
                    <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-success" />
                    <span>{c}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {AFTER_APPROVAL[p.category] && (
            <p className="mt-3 flex items-start gap-2 text-[12px] text-muted">
              <Info className="mt-0.5 size-3.5 shrink-0" />
              {AFTER_APPROVAL[p.category]}
            </p>
          )}
        </div>

        <div className="flex shrink-0 flex-row items-center justify-between gap-3 lg:w-[190px] lg:flex-col lg:items-end">
          <div className={cn("tabular flex items-center gap-1.5 text-[13px]", expired ? "text-danger-soft-foreground" : left < 30 ? "text-warning-soft-foreground" : "text-muted")} aria-live="polite">
            <Clock className="size-3.5" />
            {expired ? "Expired" : `${formatCountdown(left)} left`}
          </div>
          <div className="flex gap-1.5">
            <Button size="sm" variant="tertiary" onPress={() => onDecide(false)} isDisabled={busy || expired}>
              Decline
            </Button>
            <Button size="sm" variant={risky ? "danger" : "primary"} onPress={() => onDecide(true)} isDisabled={busy || expired || !armed} aria-label={`Approve: ${p.summary}`}>
              Approve
            </Button>
          </div>
        </div>
      </div>
    </li>
  );
}

function RecentDecisions({ rows }: { rows: McpAuditRow[] }) {
  if (!rows.length) return <p className="text-[12.5px] text-muted">No decisions recorded yet.</p>;
  return (
    <ul className="flex flex-col">
      {rows.map((r) => {
        const res = resultMeta(r.result);
        return (
          <li key={r.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md px-2 py-1.5 text-[12.5px] odd:bg-white/[0.02]">
            <span className="min-w-0">
              <code className="text-[12px]">{shortTool(r.tool)}</code> <span className="text-muted">· {r.client}</span>
            </span>
            <span className="flex items-center gap-2">
              <span className={cn(r.approval === "approved" ? "text-success-soft-foreground" : "text-muted")}>{approvalLabel(r.approval)}</span>
              <ToneChip tone={res.tone}>{res.label}</ToneChip>
              {r.executionId != null && <span className="text-muted">run #{r.executionId}</span>}
              <span className="w-[80px] text-right text-muted">{formatRelative(r.at)}</span>
            </span>
          </li>
        );
      })}
    </ul>
  );
}

/** Pending MCP requests, decided here by the user through the existing `mcp_decide` command. */
export function ApprovalCenter({ running, projects }: { running: boolean; projects: ProjectSummary[] }) {
  const pending = useQuery(["mcp"], api.mcpPending, []);
  const audit = useQuery(["mcp"], () => api.mcpAudit(200), []);
  const [fetchedAt, setFetchedAt] = useState(Date.now());
  const [now, setNow] = useState(Date.now());
  const [busy, setBusy] = useState<string | null>(null);

  const list = pending.data ?? [];
  // the list changed (new, decided or expired requests): Approve buttons wait a moment again
  const armed = useArmed(list.length ? list.map((p) => p.id).join(",") : undefined);

  useEffect(() => {
    const t = Date.now();
    setFetchedAt(t);
    setNow(t);
  }, [pending.data]);

  useEffect(() => {
    if (!list.length) return;
    const tick = setInterval(() => setNow(Date.now()), 1000);
    const poll = setInterval(() => invalidate("mcp"), 5000);
    return () => {
      clearInterval(tick);
      clearInterval(poll);
    };
  }, [list.length]);

  const names = useMemo(() => new Map(projects.map((p) => [p.id, p.name])), [projects]);
  const decisions = useMemo(() => (audit.data ?? []).filter((r) => r.approvalId && r.approval !== "pending").slice(0, 12), [audit.data]);

  const decide = async (p: McpPending, approve: boolean) => {
    setBusy(p.id);
    try {
      const ok = await api.mcpDecide(p.id, approve);
      if (!ok) notify.info("Request no longer waiting", "It expired or was already decided.");
      else if (!approve) notify.info("Request declined", `${p.client} was told you declined.`);
    } catch (e) {
      notify.error("Could not record the decision", e);
    } finally {
      setBusy(null);
      invalidate("mcp");
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <Panel
        title={`Waiting for you${list.length ? ` (${list.length})` : ""}`}
        description="Requests are validated first; out-of-scope or invalid requests are refused without reaching you. Only you can decide, here in Cyber Hub. Requests expire after 3 minutes and are cancelled if the client disconnects."
      >
        {pending.error && <ErrorBlock message={pending.error} onRetry={pending.reload} />}
        {!pending.data && !pending.error && <LoadingRows rows={2} />}
        {pending.data && list.length === 0 && (
          <EmptyBlock
            compact
            icon={Inbox}
            title="No requests are waiting"
            description={running ? "When an AI client asks for something that needs your approval, it appears here and the taskbar entry flashes." : "MCP is off, so no client can send requests."}
          />
        )}
        {list.length > 0 && (
          <ul className="flex flex-col gap-2.5">
            {list.map((p) => (
              <RequestItem
                key={p.id}
                p={p}
                left={secondsLeft(p, fetchedAt, now)}
                armed={armed}
                busy={busy === p.id}
                projectName={p.projectId != null ? names.get(p.projectId) : undefined}
                onDecide={(a) => decide(p, a)}
              />
            ))}
          </ul>
        )}
      </Panel>
      <Panel title="Recent decisions" description="From the audit log: what you approved or declined, and what happened next.">
        {audit.error ? <ErrorBlock message={audit.error} onRetry={audit.reload} /> : !audit.data ? <LoadingRows rows={3} /> : <RecentDecisions rows={decisions} />}
      </Panel>
    </div>
  );
}
