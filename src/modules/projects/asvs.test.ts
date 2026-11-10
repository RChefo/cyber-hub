import { describe, expect, it } from "vitest";
import type { AsvsItem } from "@/lib/types";
import { ASVS_STATUS, filterItems, progress } from "./asvs";

const item = (id: string, level: 1 | 2 | 3, inLevel: boolean, status: AsvsItem["status"], note = ""): AsvsItem => ({
  requirement: { id, chapter: id.split(".").slice(0, 1).join("."), section: id.split(".").slice(0, 2).join("."), text: `Verify that requirement ${id} holds.`, level },
  inLevel,
  status,
  note,
  updatedAt: null,
  findings: [],
  evidence: [],
  mappings: [],
});

describe("ASVS assessments", () => {
  it("counts progress over the requirements of the level", () => {
    expect(progress({ counts: { total: 0, notAssessed: 0, compliant: 0, nonCompliant: 0, notApplicable: 0, needsReview: 0 } })).toBe(0);
    expect(progress({ counts: { total: 70, notAssessed: 70, compliant: 0, nonCompliant: 0, notApplicable: 0, needsReview: 0 } })).toBe(0);
    expect(progress({ counts: { total: 3, notAssessed: 1, compliant: 1, nonCompliant: 1, notApplicable: 0, needsReview: 0 } })).toBe(67);
  });

  it("filters by level, status and text", () => {
    const items = [item("V1.2.1", 1, true, "compliant", "checked the encoder"), item("V1.2.2", 2, false, "not_assessed"), item("V6.1.1", 1, true, "non_compliant")];
    expect(filterItems(items, { text: "", status: "all", beyond: false }).map((i) => i.requirement.id)).toEqual(["V1.2.1", "V6.1.1"]);
    expect(filterItems(items, { text: "", status: "all", beyond: true })).toHaveLength(3);
    expect(filterItems(items, { text: "", status: "non_compliant", beyond: true }).map((i) => i.requirement.id)).toEqual(["V6.1.1"]);
    expect(filterItems(items, { text: "ENCODER", status: "all", beyond: false }).map((i) => i.requirement.id)).toEqual(["V1.2.1"]);
    expect(filterItems(items, { text: "v6.1", status: "all", beyond: false }).map((i) => i.requirement.id)).toEqual(["V6.1.1"]);
  });

  it("labels every status the database accepts", () => {
    expect(Object.keys(ASVS_STATUS).sort()).toEqual(["compliant", "needs_review", "non_compliant", "not_applicable", "not_assessed"]);
  });
});
