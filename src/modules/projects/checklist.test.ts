// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import type { ChecklistItem, WstgCategory } from "@/lib/types";
import { coverageOf, filterCatalog, findingDraftFor } from "./checklist";

const cats: WstgCategory[] = [
  { id: "WSTG-INFO", name: "Information Gathering", tests: [{ id: "WSTG-INFO-01", name: "Search engine recon", reference: "https://wstg.owasp.org/a", objectives: ["Find leaks"] }, { id: "WSTG-INFO-02", name: "Fingerprint web server", reference: "https://wstg.owasp.org/b", objectives: [] }] },
  { id: "WSTG-CLNT", name: "Client-side Testing", tests: [{ id: "WSTG-CLNT-01", name: "DOM-based XSS", reference: "https://wstg.owasp.org/c", objectives: ["Identify DOM sinks"] }] },
];
const item = (testId: string, status: ChecklistItem["status"], note = ""): ChecklistItem => ({ testId, status, note, findingId: null, updatedAt: "" });

describe("checklist helpers", () => {
  const byTest = new Map([["WSTG-INFO-01", item("WSTG-INFO-01", "passed")], ["WSTG-CLNT-01", item("WSTG-CLNT-01", "failed", "sink in hash")]]);

  it("counts coverage over the whole catalog", () => {
    expect(coverageOf(cats, byTest)).toEqual({ total: 3, done: 2, passed: 1, failed: 1, notApplicable: 0, inProgress: 0 });
  });

  it("filters by status and by text, including notes", () => {
    expect(filterCatalog(cats, byTest, "", "not_started").flatMap((c) => c.tests.map((t) => t.id))).toEqual(["WSTG-INFO-02"]);
    expect(filterCatalog(cats, byTest, "sink in", "all").map((c) => c.id)).toEqual(["WSTG-CLNT"]);
    expect(filterCatalog(cats, byTest, "nothing", "all")).toEqual([]);
  });

  it("drafts a finding from a failed test", () => {
    const d = findingDraftFor(cats[1].tests[0], "Client-side Testing", "sink in hash");
    expect(d.title).toBe("DOM-based XSS");
    expect(d.tags).toEqual(["wstg", "wstg-clnt-01"]);
    expect(d.description).toContain("Identify DOM sinks");
    expect(d.evidence[0].reference).toBe("https://wstg.owasp.org/c");
  });
});
