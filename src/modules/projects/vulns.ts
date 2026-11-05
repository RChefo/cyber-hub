import type { Tone } from "@/components/ui/Badges";
import type { Exposure, PriorityLevel, Vulnerability, VulnStatus } from "@/lib/types";

export const VULN_STATUS_META: Record<VulnStatus, { label: string; tone: Tone }> = {
  open: { label: "Open", tone: "danger" },
  triaged: { label: "Triaged", tone: "warning" },
  in_remediation: { label: "In remediation", tone: "accent" },
  mitigated: { label: "Mitigated", tone: "success" },
  resolved: { label: "Resolved", tone: "success" },
  accepted_risk: { label: "Accepted risk", tone: "default" },
  false_positive: { label: "False positive", tone: "default" },
};

export const PRIORITY_META: Record<PriorityLevel, { label: string; tone: Tone; help: string }> = {
  p1: { label: "P1", tone: "danger", help: "Fix first" },
  p2: { label: "P2", tone: "warning", help: "Fix soon" },
  p3: { label: "P3", tone: "accent", help: "Plan a fix" },
  p4: { label: "P4", tone: "default", help: "Low urgency" },
};

export const EXPOSURE_LABEL: Record<Exposure, string> = { internet: "Internet-facing", internal: "Internal only", unknown: "Unknown" };

/** Statuses that still need work; mirrors `vulns::is_open` in the backend. */
export function isOpenVuln(status: VulnStatus): boolean {
  return status === "open" || status === "triaged" || status === "in_remediation";
}

/** A due date before today on a vulnerability that is still open. */
export function isOverdue(v: Pick<Vulnerability, "status" | "remediationDue">, today = new Date().toISOString().slice(0, 10)): boolean {
  return !!v.remediationDue && isOpenVuln(v.status) && v.remediationDue < today;
}

export function formatEpss(v: Pick<Vulnerability, "epss" | "epssPercentile">): string {
  if (v.epss == null) return "—";
  const pct = v.epss * 100;
  return `${pct < 1 ? pct.toFixed(2) : pct.toFixed(1)}%`;
}

export function countByPriority(list: Vulnerability[]): Record<PriorityLevel, number> {
  const out: Record<PriorityLevel, number> = { p1: 0, p2: 0, p3: 0, p4: 0 };
  for (const v of list) if (isOpenVuln(v.status)) out[v.priority]++;
  return out;
}

/** Status changes that need a written reason (mirrors the backend rule). */
export function needsReason(status: VulnStatus): boolean {
  return status === "accepted_risk" || status === "false_positive";
}
