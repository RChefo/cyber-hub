// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import type { Vulnerability } from "@/lib/types";
import { countByPriority, formatEpss, isOverdue, needsReason } from "./vulns";

const v = (priority: Vulnerability["priority"], status: Vulnerability["status"], extra: Partial<Vulnerability> = {}) => ({ priority, status, ...extra }) as Vulnerability;

describe("vulnerability helpers", () => {
  it("counts only open vulnerabilities by priority", () => {
    expect(countByPriority([v("p1", "open"), v("p1", "resolved"), v("p3", "in_remediation"), v("p4", "accepted_risk")])).toEqual({ p1: 1, p2: 0, p3: 1, p4: 0 });
  });

  it("flags overdue remediation only while open", () => {
    expect(isOverdue({ status: "in_remediation", remediationDue: "2026-11-01" }, "2026-11-05")).toBe(true);
    expect(isOverdue({ status: "resolved", remediationDue: "2026-11-01" }, "2026-11-05")).toBe(false);
    expect(isOverdue({ status: "open", remediationDue: "2026-11-05" }, "2026-11-05")).toBe(false);
    expect(isOverdue({ status: "open", remediationDue: null }, "2026-11-05")).toBe(false);
  });

  it("formats EPSS as a percentage", () => {
    expect(formatEpss({ epss: 0.94434, epssPercentile: 0.99 })).toBe("94.4%");
    expect(formatEpss({ epss: 0.00043, epssPercentile: 0.08 })).toBe("0.04%");
    expect(formatEpss({ epss: null, epssPercentile: null })).toBe("—");
  });

  it("asks for a reason when accepting or dismissing", () => {
    expect(needsReason("accepted_risk")).toBe(false);
    expect(needsReason("false_positive")).toBe(true);
    expect(needsReason("in_remediation")).toBe(false);
  });
});
