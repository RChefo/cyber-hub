import { describe, expect, it } from "vitest";
import type { Finding } from "@/lib/types";
import { countBySeverity, sortFindings } from "./report";

const f = (id: number, severity: Finding["severity"], status: Finding["status"], updatedAt = "2026-11-02T00:00:00Z"): Finding => ({
  id,
  projectId: 1,
  title: `Finding ${id}`,
  severity,
  status,
  description: id === 2 ? "Line one\nLine two" : "",
  affectedTarget: "app.acme.test",
  cve: id === 2 ? "CVE-2021-44228" : "",
  evidence: id === 2 ? [{ label: "Request", reference: "evidence/req-2.txt" }] : [],
  createdAt: updatedAt,
  updatedAt,
});

describe("findings helpers", () => {
  it("sorts by severity then most recent", () => {
    const sorted = sortFindings([f(1, "low", "open"), f(2, "critical", "open"), f(3, "low", "open", "2026-11-03T00:00:00Z")]);
    expect(sorted.map((x) => x.id)).toEqual([2, 3, 1]);
  });
  it("counts severities, optionally excluding closed findings", () => {
    const list = [f(1, "high", "open"), f(2, "high", "resolved"), f(3, "info", "false_positive")];
    expect(countBySeverity(list).high).toBe(2);
    expect(countBySeverity(list, true)).toEqual({ critical: 0, high: 1, medium: 0, low: 0, info: 0 });
  });
});
