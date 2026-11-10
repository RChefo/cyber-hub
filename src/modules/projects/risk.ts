import type { RiskAcceptance, RiskDraft, RiskItemKind, RiskStanding } from "@/lib/types";

export const RISK_STANDING: Record<RiskStanding, { label: string; tone: "default" | "accent" | "success" | "warning" | "danger" }> = {
  active: { label: "Active", tone: "success" },
  review_due: { label: "Review due", tone: "warning" },
  expired: { label: "Expired", tone: "danger" },
  revoked: { label: "Revoked", tone: "default" },
};

const DATE = /^\d{4}-\d{2}-\d{2}$/;

/** YYYY-MM-DD, `days` from `today`. */
export function addDays(today: string, days: number): string {
  const d = new Date(`${today}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

export function todayUtc(): string {
  return new Date().toISOString().slice(0, 10);
}

/** A new acceptance approved today, expiring in 90 days. */
export function newDraft(today: string, title = ""): RiskDraft {
  return { title, justification: "", compensating: "", owner: "", approver: "", approvedAt: today, expiresAt: addDays(today, 90), reviewAt: null };
}

/** What stops the draft, checked as the backend checks it (the backend has the last word). */
export function draftProblems(d: RiskDraft, today: string): string[] {
  const out: string[] = [];
  if (!d.title.trim()) out.push("a title");
  if (!d.justification.trim()) out.push("the justification");
  if (!d.owner.trim()) out.push("the risk owner");
  if (!d.approver.trim()) out.push("the approver");
  if (!DATE.test(d.approvedAt) || d.approvedAt > today) out.push("an approval date (today or earlier)");
  if (!DATE.test(d.expiresAt) || d.expiresAt <= today) out.push("an expiry date after today");
  else if (DATE.test(d.approvedAt) && d.expiresAt > addDays(d.approvedAt, 3 * 366)) out.push("an expiry within three years of the approval");
  if (d.reviewAt && (!DATE.test(d.reviewAt) || d.reviewAt <= today || d.reviewAt > d.expiresAt)) out.push("a review date between today and the expiry");
  return out;
}

/** Whole days from `today` to `date` (negative when past). */
export function daysUntil(date: string, today: string): number {
  return Math.round((Date.parse(`${date}T00:00:00Z`) - Date.parse(`${today}T00:00:00Z`)) / 86_400_000);
}

export function expiryText(a: Pick<RiskAcceptance, "expiresAt" | "status">, today: string): string {
  if (a.status === "revoked") return `was to expire on ${a.expiresAt}`;
  const n = daysUntil(a.expiresAt, today);
  if (n < 0) return `expired ${-n} day${n === -1 ? "" : "s"} ago (${a.expiresAt})`;
  if (n === 0) return `expires today`;
  return `expires in ${n} day${n === 1 ? "" : "s"} (${a.expiresAt})`;
}

/** The acceptance that currently covers each item, by "kind:refId[:requirement]". */
export function coverIndex(list: RiskAcceptance[]): Map<string, RiskAcceptance> {
  const out = new Map<string, RiskAcceptance>();
  for (const a of list) {
    if (a.status === "revoked") continue;
    for (const i of a.items) {
      if (i.removedAt) continue;
      out.set(coverKey(i.kind, i.refId, i.requirement), a);
    }
  }
  return out;
}

export function coverKey(kind: RiskItemKind, refId: number, requirement = ""): string {
  return requirement ? `${kind}:${refId}:${requirement}` : `${kind}:${refId}`;
}
