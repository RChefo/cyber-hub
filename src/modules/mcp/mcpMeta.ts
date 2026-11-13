// SPDX-License-Identifier: Apache-2.0
import type { McpAuditResult, McpCatalogTool, McpPending, McpPolicy } from "@/lib/types";

export type Tone = "default" | "accent" | "success" | "warning" | "danger";

/** Section tabs of the MCP workspace; the active one lives in the route (`tab` param). */
export const MCP_TABS = ["overview", "approvals", "clients", "tools", "catalog", "permissions", "activity", "connect"] as const;
export type McpTab = (typeof MCP_TABS)[number];

export function tabFromParams(params?: Record<string, string>): McpTab {
  const t = params?.tab;
  return (MCP_TABS as readonly string[]).includes(t ?? "") ? (t as McpTab) : "overview";
}

/** Short names for the permission categories (the backend provides the long labels). */
export const CATEGORY_SHORT: Record<string, string> = {
  read: "Read",
  external_lookup: "External lookup",
  local_write: "Local change",
  run_tools: "Tool run",
  file_upload: "File upload",
  export: "Export",
};

export const CATEGORY_TONE: Record<string, Tone> = {
  read: "default",
  external_lookup: "accent",
  local_write: "warning",
  run_tools: "danger",
  file_upload: "danger",
  export: "warning",
};

export const POLICY_LABEL: Record<McpPolicy, string> = { allow: "Allow", ask: "Ask me", deny: "Block" };

export const RESULT_META: Record<McpAuditResult, { label: string; tone: Tone }> = {
  ok: { label: "Completed", tone: "success" },
  awaiting_approval: { label: "Awaiting approval", tone: "warning" },
  refused: { label: "Refused", tone: "default" },
  error: { label: "Error", tone: "danger" },
};

export function resultMeta(r: string | null | undefined): { label: string; tone: Tone } {
  return RESULT_META[r as McpAuditResult] ?? { label: r ? r.replace(/_/g, " ") : "—", tone: "default" };
}

export const APPROVAL_LABEL: Record<string, string> = {
  not_required: "Not required",
  approved: "Approved",
  denied: "Declined",
  expired: "Expired",
  cancelled: "Cancelled",
  pending: "Pending",
  denied_by_policy: "Blocked by policy",
};

export function approvalLabel(a: string | null | undefined): string {
  return a ? (APPROVAL_LABEL[a] ?? a.replace(/_/g, " ")) : "—";
}

/** `cyberhub_run_tool` → `run_tool`. */
export function shortTool(name: string): string {
  return name.replace(/^cyberhub_/, "");
}

/** Tools grouped in the catalogue's group order; groups without tools are dropped. */
export function groupTools(groups: [string, string][], tools: McpCatalogTool[]): { id: string; label: string; tools: McpCatalogTool[] }[] {
  return groups.map(([id, label]) => ({ id, label, tools: tools.filter((t) => t.group === id) })).filter((g) => g.tools.length > 0);
}

/** How a tool is gated right now, in words. */
export function gateLabel(t: McpCatalogTool): { label: string; tone: Tone } {
  if (t.readOnly) return { label: "No approval (read-only)", tone: "default" };
  if (t.policy === "deny") return { label: "Blocked", tone: "danger" };
  if (t.policy === "allow") return { label: "Allowed without asking", tone: "accent" };
  return { label: t.nativeConfirmation ? "Asks you, then a system dialog" : "Asks you", tone: "warning" };
}

/** Value of a detail row of a pending request (labels come from the backend). */
export function detail(p: McpPending, ...labels: string[]): string | undefined {
  for (const l of labels) {
    const v = p.details.find((d) => d.label.toLowerCase() === l.toLowerCase())?.value;
    if (v) return v;
  }
  return undefined;
}

/** Target(s) a pending request concerns, if any. */
export function requestTarget(p: McpPending): string | undefined {
  return detail(p, "Authorized targets", "Affected target", "Indicator", "indicator", "hash", "cve_id", "query");
}

/** Seconds left before a pending request expires, given when the list was fetched. */
export function secondsLeft(p: McpPending, fetchedAt: number, now: number): number {
  return Math.max(0, p.expiresInSecs - Math.floor((now - fetchedAt) / 1000));
}

export function formatCountdown(secs: number): string {
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${m}:${String(s).padStart(2, "0")}`;
}
