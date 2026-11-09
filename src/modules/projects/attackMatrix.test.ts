import { describe, expect, it } from "vitest";
import type { AttackCatalog, AttackEntry, AttackMatrix } from "@/lib/types";
import { buildColumns, gaps, mitreUrl, outside, stateOf } from "./attackMatrix";

const catalog: AttackCatalog = {
  version: "20.1",
  modified: "",
  retrieved: "",
  url: "",
  notice: "",
  tactics: [
    { id: "TA0002", shortname: "execution", name: "Execution" },
    { id: "TA0005", shortname: "defense-evasion", name: "Defense Evasion" },
  ],
  techniques: [
    { id: "T1059", name: "Command and Scripting Interpreter", tactics: ["execution"], platforms: [] },
    { id: "T1059.001", name: "PowerShell", tactics: ["execution"], platforms: [], parent: "T1059" },
    { id: "T1059.003", name: "Windows Command Shell", tactics: ["execution"], platforms: [], parent: "T1059" },
    { id: "T1055", name: "Process Injection", tactics: ["defense-evasion"], platforms: [] },
    { id: "T1027", name: "Obfuscated Files or Information", tactics: ["defense-evasion"], platforms: [] },
  ],
};

const entry = (id: string, over: Partial<AttackEntry> = {}): AttackEntry => ({ id, name: id, tactics: [], parent: null, state: { state: "current" }, observed: [], linked: [], assessment: null, layers: [], ...over });
const observed = [{ findingId: 1, title: "x", severity: "high" as const, status: "new", confidence: "medium", evidence: 0 }];

const matrix: AttackMatrix = {
  attackVersion: "20.1",
  attackModified: "",
  attackRetrieved: "",
  layers: [],
  counts: { observed: 1, confirmed: 1, hypothesis: 0, ruledOut: 0, findings: 1 },
  entries: [
    entry("T1059.001", { observed, layers: [{ layerId: 7, score: 2, color: "", comment: "", enabled: true }] }),
    entry("T1055", { assessment: { status: "confirmed", confidence: "high", note: "", attackVersion: "20.1", createdBy: "user", updatedAt: "" } }),
    entry("T1027", { layers: [{ layerId: 7, score: 1, color: "", comment: "", enabled: true }] }),
    entry("T1143", { state: { state: "revoked", by: "T1564.003" }, observed }),
  ],
};

describe("ATT&CK matrix", () => {
  it("states: an assessment first, then findings, then links", () => {
    expect(stateOf(matrix.entries[0])).toBe("observed");
    expect(stateOf(matrix.entries[1])).toBe("confirmed");
    expect(stateOf(matrix.entries[2])).toBe("none");
    expect(stateOf(undefined)).toBe("none");
  });

  it("lists techniques with data under their tactics, sub-techniques under their parent", () => {
    const cols = buildColumns(catalog, matrix, { onlyData: true, filter: "", layerId: null });
    expect(cols.map((c) => c.rows.map((r) => r.tech.id))).toEqual([["T1059"], ["T1055"]]);
    expect(cols[0].rows[0].subs.map((s) => s.tech.id)).toEqual(["T1059.001"]);
    expect(cols[0].rows[0].subsWithData).toBe(1);
    // a layer shown as an overlay adds what it lists; the full matrix lists everything
    expect(buildColumns(catalog, matrix, { onlyData: true, filter: "", layerId: 7 })[1].rows.map((r) => r.tech.id)).toEqual(["T1055", "T1027"]);
    expect(buildColumns(catalog, matrix, { onlyData: false, filter: "", layerId: null })[1].rows).toHaveLength(2);
    expect(buildColumns(catalog, matrix, { onlyData: false, filter: "powershell", layerId: null })[0].rows[0].tech.id).toBe("T1059");
  });

  it("gaps are what the project names or confirms that the layer does not cover", () => {
    expect(gaps(matrix, 7).map((e) => e.id)).toEqual(["T1055", "T1143"]);
    expect(outside(matrix).map((e) => e.id)).toEqual(["T1143"]);
    expect(mitreUrl("T1059.001")).toBe("https://attack.mitre.org/techniques/T1059/001/");
  });
});
