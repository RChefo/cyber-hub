import { Button } from "@heroui/react";
import { listen } from "@tauri-apps/api/event";
import { Bot, ShieldAlert } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useApp } from "@/app/store";
import { ToneChip } from "@/components/ui/Badges";
import { AppModal } from "@/components/ui/Dialogs";
import { notify } from "@/lib/actions";
import { api, runtimeAvailable } from "@/lib/ipc";
import { invalidate } from "@/lib/query";
import type { McpPending } from "@/lib/types";
import { useArmed } from "@/lib/useArmed";
import { tabFromParams } from "@/modules/mcp/mcpMeta";

const CATEGORY_LABEL: Record<string, string> = {
  external_lookup: "External lookup",
  local_write: "Local change",
  run_tools: "Tool run",
  file_upload: "File upload",
  export: "Export",
};

/**
 * Approval prompt for sensitive MCP requests. It is shown by Cyber Hub itself; MCP clients
 * cannot see or answer it. Runs and uploads are followed by the usual native confirmation.
 * It stays out of the way while the MCP page's Approval Center (which lists the same requests)
 * is on screen, and keeps listening for new requests either way.
 */
export function McpApprovals() {
  const runtime = runtimeAvailable();
  const { route, navigate } = useApp();
  const centerVisible = route.page === "mcp" && tabFromParams(route.params) === "approvals";
  const [pending, setPending] = useState<McpPending[]>([]);
  const [fetchedAt, setFetchedAt] = useState(Date.now());
  const [now, setNow] = useState(Date.now());
  const [busy, setBusy] = useState(false);

  const lastIds = useRef("");
  const refresh = useCallback(async () => {
    try {
      const list = await api.mcpPending();
      setPending(list);
      const t = Date.now();
      setFetchedAt(t);
      setNow(t);
      // other MCP views (sidebar badge, MCP page) refresh only when the waiting list changed
      const ids = list.map((p) => p.id).join(",");
      if (ids !== lastIds.current) {
        lastIds.current = ids;
        invalidate("mcp");
      }
    } catch {
      /* the MCP bridge may be off */
    }
  }, []);

  useEffect(() => {
    if (!runtime) return;
    refresh();
    let un: (() => void) | undefined;
    let disposed = false;
    listen("mcp-approvals", () => refresh())
      .then((fn) => (disposed ? fn() : (un = fn)))
      .catch(() => undefined);
    return () => {
      disposed = true;
      un?.();
    };
  }, [runtime, refresh]);

  // countdown, and a periodic refresh so expired requests disappear
  useEffect(() => {
    if (!pending.length) return;
    const t = setInterval(() => setNow(Date.now()), 1000);
    const r = setInterval(refresh, 5000);
    return () => {
      clearInterval(t);
      clearInterval(r);
    };
  }, [pending.length, refresh]);

  // Approve stays disabled briefly whenever a different request comes to the front, so a click
  // aimed at the previous request cannot approve the next one.
  const armed = useArmed(centerVisible ? undefined : pending[0]?.id);

  const current = pending[0];
  if (!current || centerVisible) return null;
  const left = Math.max(0, current.expiresInSecs - Math.floor((now - fetchedAt) / 1000));

  const decide = async (approve: boolean) => {
    setBusy(true);
    try {
      await api.mcpDecide(current.id, approve);
      if (!approve) notify.info("Request declined", `${current.client} was told you declined.`);
    } catch (e) {
      notify.error("Could not record the decision", e);
    } finally {
      setBusy(false);
      refresh();
    }
  };

  return (
    <AppModal
      isOpen
      isDismissable={false}
      onOpenChange={(open) => !open && decide(false)}
      title={
        <span className="flex items-center gap-2">
          <Bot className="size-4 text-accent" />
          An AI client is asking for permission
        </span>
      }
      description={`${current.client} (name reported by the client) · expires in ${left} s${pending.length > 1 ? ` · ${pending.length - 1} more waiting` : ""}`}
      footer={
        <>
          <Button variant="tertiary" onPress={() => decide(false)} isDisabled={busy}>
            Decline
          </Button>
          <Button variant={current.category === "file_upload" || current.category === "run_tools" ? "danger" : "primary"} onPress={() => decide(true)} isDisabled={busy || !armed}>
            Approve
          </Button>
        </>
      }
    >
      <div className="flex items-start gap-3">
        <ShieldAlert className="mt-0.5 size-5 shrink-0 text-warning-soft-foreground" />
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[15px] font-medium">{current.summary}</span>
            <ToneChip tone={current.category === "external_lookup" ? "accent" : "warning"}>{CATEGORY_LABEL[current.category] ?? current.category}</ToneChip>
          </div>
          <code className="mt-1 block text-[12px] text-muted">{current.tool}</code>
        </div>
      </div>
      {current.details.length > 0 && (
        <dl className="panel-inset grid grid-cols-[140px_1fr] gap-x-4 gap-y-1.5 px-3 py-2.5 text-[12.5px]">
          {current.details.map((d, i) => (
            <div key={i} className="contents">
              <dt className="text-muted">{d.label}</dt>
              <dd className="min-w-0 break-words font-mono text-[12px]" data-selectable>
                {d.value || "—"}
              </dd>
            </div>
          ))}
        </dl>
      )}
      <p className="text-[12.5px] text-muted">
        {current.category === "run_tools"
          ? "Approving lets Cyber Hub continue to its usual system confirmation for this run. Only approve if you are authorized to test these targets."
          : current.category === "file_upload"
            ? "Approving opens the file picker. You choose the file, and Cyber Hub asks again before anything is uploaded."
            : current.category === "external_lookup"
              ? "Approving sends the values above to the external service."
              : "Only approve requests you expect from your AI client."}{" "}
        Waiting requests and what MCP clients may do are also on the{" "}
        <button type="button" className="text-accent-soft-foreground underline-offset-2 outline-none hover:underline focus-visible:underline" onClick={() => navigate("mcp", { tab: "approvals" })}>
          MCP page
        </button>
        .
      </p>
    </AppModal>
  );
}
