// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import type { SbomComponent, SbomVuln } from "@/lib/types";
import { checkable, componentFacts, componentLabel, filterComponents, sbomCompareSummary, vulnRows, vulnSummary } from "./sbom";

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
  dev: false,
  resolved: "",
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

describe("SBOM comparison", () => {
  it("summarizes the changes", () => {
    const c = {
      added: ["fresh@0.1.0"],
      removed: [],
      changed: [
        { component: "npm lodash", from: "4.17.20", to: "4.17.21", direction: "upgraded" as const },
        { component: "npm express", from: "4.18.2", to: "4.17.1", direction: "downgraded" as const },
      ],
      unchanged: 40,
    };
    expect(sbomCompareSummary(c)).toBe("1 added · 0 removed · 1 upgraded · 1 downgraded · 40 unchanged");
    expect(sbomCompareSummary({ ...c, changed: [] })).toBe("1 added · 0 removed · 40 unchanged");
  });
});

describe("component facts", () => {
  it("names the origin of dependencies that do not come from a registry", () => {
    const git = comp("forked", { purl: "", ecosystem: "", resolved: "git+ssh://git@github.com/me/forked.git#0123", licenses: [] });
    expect(componentFacts(git, true)).toBe("no package URL · from git+ssh://git@github.com/me/forked.git#0123");
  });
  it("marks development dependencies and leaves out missing licenses for lockfiles", () => {
    const dev = comp("minimist", { dev: true, direct: true, licenses: [], resolved: "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz" });
    expect(componentFacts(dev, true)).toBe("npm · direct · development");
    expect(componentFacts(dev, false)).toBe("npm · direct · development · no license stated");
  });
});
