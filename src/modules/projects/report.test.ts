import { describe, expect, it } from "vitest";
import type { Finding } from "@/lib/types";
import { countBySeverity, filterFindings, parseTags, sortFindings, tagsOf } from "./report";

const f = (id: number, severity: Finding["severity"], status: Finding["status"], updatedAt = "2026-11-02T00:00:00Z"): Finding => ({
  id,
  projectId: 1,
  title: `Finding ${id}`,
  severity,
  status,
  description: id === 2 ? "Line one\nLine two" : "",
  affectedTarget: "app.acme.test",
  cvssVector: "",
  cvssScore: null,
  cve: id === 2 ? "CVE-2021-44228" : "",
  evidence: id === 2 ? [{ label: "Request", reference: "evidence/req-2.txt" }] : [],
  category: "",
  confidence: "medium",
  reproduction: "",
  technicalDetails: "",
  remediation: "",
  source: "user",
  tags: [],
  assignee: "",
  dueDate: null,
  createdAt: updatedAt,
  updatedAt,
});

describe("findings helpers", () => {
  it("sorts by severity then most recent", () => {
    const sorted = sortFindings([f(1, "low", "new"), f(2, "critical", "new"), f(3, "low", "new", "2026-11-03T00:00:00Z")]);
    expect(sorted.map((x) => x.id)).toEqual([2, 3, 1]);
  });
  it("counts severities, optionally excluding closed findings", () => {
    const list = [f(1, "high", "new"), f(2, "high", "resolved"), f(3, "info", "false_positive"), f(4, "info", "accepted_risk")];
    expect(countBySeverity(list).high).toBe(2);
    expect(countBySeverity(list, true)).toEqual({ critical: 0, high: 1, medium: 0, low: 0, info: 0 });
  });
});

describe("findings manager helpers", () => {
  it("parses tags from text", () => {
    expect(parseTags(" web, auth ,web,, " + "x".repeat(41))).toEqual(["web", "auth"]);
  });

  it("filters by text, tag, severity and status", () => {
    const a = { ...f(1, "high", "new"), tags: ["web"], title: "Reflected XSS" };
    const b = { ...f(2, "low", "resolved"), tags: ["infra"] };
    expect(tagsOf([a, b])).toEqual(["infra", "web"]);
    expect(filterFindings([a, b], { severity: "all", status: "all", query: "xss", tag: "all" })).toEqual([a]);
    expect(filterFindings([a, b], { severity: "all", status: "all", query: "", tag: "infra" })).toEqual([b]);
    expect(filterFindings([a, b], { severity: "high", status: "resolved", query: "", tag: "all" })).toEqual([]);
    expect(filterFindings([a, b], { severity: "all", status: "all", query: "CVE-2021", tag: "all" })).toEqual([b]);
  });
});

