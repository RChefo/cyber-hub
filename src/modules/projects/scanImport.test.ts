import { describe, expect, it } from "vitest";
import type { CsvInfo, ScanImportPreview } from "@/lib/types";
import { columnOptions, CSV_FIELDS, importCount, knownCount, nothingToImport, severityScaleText, shownOutcome, withColumn } from "./scanImport";

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
  notReportedPassed: 0,
  csv: null,
  cves: 0,
};

describe("scan import preview", () => {
  it("counts informational findings only when they are included", () => {
    expect(importCount(base, { includeInfo: false, reopenResolved: true, useTemplates: true, resolveMissing: false, trackCves: false })).toBe(2);
    expect(importCount(base, { includeInfo: true, reopenResolved: true, useTemplates: true, resolveMissing: false, trackCves: false })).toBe(5);
    expect(knownCount(base)).toBe(3);
  });

  it("knows when an import would change nothing", () => {
    const empty = { ...base, assets: 0, counts: { new: 0, seenAgain: 0, recurring: 0, dismissed: 0, outOfScope: 4, info: 2 } };
    expect(nothingToImport(empty, { includeInfo: false, reopenResolved: false, useTemplates: true, resolveMissing: false, trackCves: false })).toBe(true);
    expect(nothingToImport(empty, { includeInfo: true, reopenResolved: false, useTemplates: true, resolveMissing: false, trackCves: false })).toBe(false);
    expect(nothingToImport(base, { includeInfo: false, reopenResolved: false, useTemplates: true, resolveMissing: false, trackCves: false })).toBe(false);
    expect(nothingToImport({ ...empty, notReportedCount: 1 }, { includeInfo: false, reopenResolved: false, useTemplates: true, resolveMissing: false, trackCves: false })).toBe(false);
  });

  it("shows informational items as new once they are included", () => {
    expect(shownOutcome("info", { includeInfo: true, reopenResolved: false, useTemplates: true, resolveMissing: false, trackCves: false })).toBe("new");
    expect(shownOutcome("info", { includeInfo: false, reopenResolved: false, useTemplates: true, resolveMissing: false, trackCves: false })).toBe("info");
    expect(shownOutcome("out_of_scope", { includeInfo: true, reopenResolved: false, useTemplates: true, resolveMissing: false, trackCves: false })).toBe("out_of_scope");
  });
});

describe("CSV column mapping", () => {
  const info: CsvInfo = {
    headers: ["Name", "Risk", "", "Host"],
    sample: [["", "High", "x", "10.0.0.5"], ["A very long finding title that goes on and on and on", "Low", "", "10.0.0.6"]],
    rows: 2,
    delimiter: ",",
    mapping: { title: 0, severity: 1, target: 3, port: null, description: null, remediation: null, cve: null, cvss: null, ruleId: null, references: null, details: null },
    severityScale: "words",
  };

  it("offers every column with its first value", () => {
    const opts = columnOptions(info);
    expect(opts[0]).toEqual({ id: "none", label: "Not used" });
    expect(opts[1].label).toBe("Name (A very long finding title that goes on a…)");
    expect(opts[2].label).toBe("Risk (High)");
    expect(opts[3].label).toBe("Column 3 (x)");
    expect(opts).toHaveLength(5);
  });

  it("changes one field at a time", () => {
    expect(withColumn(info.mapping, "port", "2").port).toBe(2);
    expect(withColumn(info.mapping, "title", "none").title).toBeNull();
    expect(CSV_FIELDS.map((f) => f.key)).toContain("ruleId");
    expect(severityScaleText("levels")).toContain("5 is critical");
    expect(severityScaleText(null)).toBeNull();
  });
});
