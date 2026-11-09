import { describe, expect, it } from "vitest";
import type { SbomComponent, SbomVuln } from "@/lib/types";
import { checkable, componentLabel, filterComponents, vulnRows, vulnSummary } from "./sbom";

const comp = (name: string, extra: Partial<SbomComponent> = {}): SbomComponent => ({
  name,
  group: "",
  version: "1.0",
  purl: `pkg:npm/${name}@1.0`,
  cpe: "",
  kind: "library",
  ecosystem: "npm",
  licenses: ["MIT"],
  licenseRisk: "permissive",
  supplier: "",
  hashes: [],
  direct: false,
  reference: name,
  ...extra,
});

const vuln = (id: string, components: number[], analysis = ""): SbomVuln => ({ id, aliases: [], summary: "", severity: "high", score: null, vector: "", fixed: [], references: [], published: "", components, source: "osv", analysis });

describe("SBOM helpers", () => {
  it("labels components and counts what can be looked up", () => {
    expect(componentLabel({ name: "spring-core", group: "org.springframework", version: "5.3.0" })).toBe("org.springframework/spring-core@5.3.0");
    expect(componentLabel({ name: "x", group: "", version: "" })).toBe("x");
    const list = [comp("a"), comp("b", { version: "", purl: "pkg:npm/b" }), comp("c", { version: "", purl: "pkg:npm/c@2.0" }), comp("d", { purl: "" })];
    expect(checkable(list)).toBe(2);
  });

  it("lists one row per vulnerability and component, without VEX not-affected ones if asked", () => {
    const rows = vulnRows([vuln("CVE-1", [0, 2]), vuln("CVE-2", [1], "not_affected")], false);
    expect(rows.map((r) => r.key)).toEqual(["vuln:CVE-1:0", "vuln:CVE-1:2", "vuln:CVE-2:1"]);
    expect(vulnRows([vuln("CVE-1", [0, 2]), vuln("CVE-2", [1], "not_affected")], true).map((r) => r.key)).toEqual(["vuln:CVE-1:0", "vuln:CVE-1:2"]);
  });

  it("filters components", () => {
    const list = [comp("lodash"), comp("readline", { ecosystem: "deb", licenseRisk: "copyleft", licenses: ["GPL-3.0"] }), comp("mystery", { ecosystem: "", licenseRisk: "unknown", supplier: "Acme" })];
    const f = (o: Partial<{ text: string; ecosystem: string; risk: string; vulnerableOnly: boolean }>) => filterComponents(list, new Set([0]), { text: "", ecosystem: "all", risk: "all", vulnerableOnly: false, ...o });
    expect(f({})).toEqual([0, 1, 2]);
    expect(f({ ecosystem: "deb" })).toEqual([1]);
    expect(f({ ecosystem: "other" })).toEqual([2]);
    expect(f({ risk: "copyleft" })).toEqual([1]);
    expect(f({ vulnerableOnly: true })).toEqual([0]);
    expect(f({ text: "acme" })).toEqual([2]);
    expect(f({ text: "gpl" })).toEqual([1]);
  });

  it("summarizes vulnerability counts", () => {
    expect(vulnSummary({ vulns: [1, 2, 0, 0, 1] })).toBe("1 critical, 2 high, 1 unrated");
    expect(vulnSummary({ vulns: [0, 0, 0, 0, 0] })).toBe("none known");
  });
});
