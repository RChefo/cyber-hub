import { describe, expect, it } from "vitest";
import type { ScanImportPreview } from "@/lib/types";
import { importCount, knownCount, nothingToImport, shownOutcome } from "./scanImport";

const base: ScanImportPreview = {
  format: "nessus",
  formatLabel: "Nessus (.nessus)",
  tool: "Nessus",
  findings: 9,
  bySeverity: { high: 2, info: 7 },
  counts: { new: 2, seenAgain: 1, recurring: 1, dismissed: 1, outOfScope: 1, info: 3 },
  assets: 4,
  assetsNew: 2,
  assetsOutOfScope: 1,
  outOfScopeHosts: ["10.9.9.9"],
  items: [],
  warnings: [],
  merged: 0,
  markedFalsePositive: 0,
  hasScope: true,
  templated: 0,
  notReported: [],
  notReportedCount: 0,
};

describe("scan import preview", () => {
  it("counts informational findings only when they are included", () => {
    expect(importCount(base, { includeInfo: false, reopenResolved: true, useTemplates: true, resolveMissing: false })).toBe(2);
    expect(importCount(base, { includeInfo: true, reopenResolved: true, useTemplates: true, resolveMissing: false })).toBe(5);
    expect(knownCount(base)).toBe(3);
  });

  it("knows when an import would change nothing", () => {
    const empty = { ...base, assets: 0, counts: { new: 0, seenAgain: 0, recurring: 0, dismissed: 0, outOfScope: 4, info: 2 } };
    expect(nothingToImport(empty, { includeInfo: false, reopenResolved: false, useTemplates: true, resolveMissing: false })).toBe(true);
    expect(nothingToImport(empty, { includeInfo: true, reopenResolved: false, useTemplates: true, resolveMissing: false })).toBe(false);
    expect(nothingToImport(base, { includeInfo: false, reopenResolved: false, useTemplates: true, resolveMissing: false })).toBe(false);
    expect(nothingToImport({ ...empty, notReportedCount: 1 }, { includeInfo: false, reopenResolved: false, useTemplates: true, resolveMissing: false })).toBe(false);
  });

  it("shows informational items as new once they are included", () => {
    expect(shownOutcome("info", { includeInfo: true, reopenResolved: false, useTemplates: true, resolveMissing: false })).toBe("new");
    expect(shownOutcome("info", { includeInfo: false, reopenResolved: false, useTemplates: true, resolveMissing: false })).toBe("info");
    expect(shownOutcome("out_of_scope", { includeInfo: true, reopenResolved: false, useTemplates: true, resolveMissing: false })).toBe("out_of_scope");
  });
});
