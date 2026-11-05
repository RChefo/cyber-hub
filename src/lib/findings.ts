import type { FindingStatus } from "@/lib/types";

/** Statuses that still need attention; mirrors `OPEN_SQL` in src-tauri/src/workspace/findings.rs. */
export const OPEN_FINDING_STATUSES: readonly FindingStatus[] = ["new", "under_review", "confirmed", "in_remediation", "reopened"];
const CLOSED: readonly FindingStatus[] = ["resolved", "false_positive", "accepted_risk"];

export function isOpenFinding(status: FindingStatus): boolean {
  return OPEN_FINDING_STATUSES.includes(status);
}

/** Same rule as `transition_ok` in the backend: only a closed finding can be reopened. */
export function canChangeStatus(from: FindingStatus, to: FindingStatus): boolean {
  if (from === to) return false;
  return to !== "reopened" || CLOSED.includes(from);
}
