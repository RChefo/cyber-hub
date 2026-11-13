// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import type { InvestigationGraph } from "@/lib/types";
import { parseKey, provenance, refKey, sentence, tabFor, toCanvas } from "./investigation";

describe("investigation helpers", () => {
  it("round-trips record keys and finds their tabs", () => {
    for (const key of ["finding:12", "api_endpoint:3:5", "sbom_component:7:0", "technique:T1059.001", "osint_entity:4"]) {
      const r = parseKey(key)!;
      expect(refKey(r)).toBe(key);
    }
    expect(parseKey("finding:x")).toBeNull();
    expect(tabFor({ kind: "asset", id: 1, sub: "" })).toBe("surface");
    expect(tabFor({ kind: "technique", id: 0, sub: "T1530" })).toBe("attack");
    expect(tabFor({ kind: "osint_entity", id: 1, sub: "" })).toBe("osint");
  });

  it("says what a relationship is and where it came from", () => {
    const node = (label: string) => ({ ref: { kind: "finding" as const, id: 1, sub: "" }, key: "finding:1", label, detail: "", severity: null, flagged: false });
    expect(sentence({ a: node("SQL injection"), b: node("https://app.example.com"), label: "affects" })).toBe("SQL injection affects https://app.example.com");
    expect(provenance({ origin: "derived", verification: "inferred", confidence: "high" })).toBe("Derived, unconfirmed · high confidence");
    expect(provenance({ origin: "manual", verification: "verified", confidence: "high" })).toBe("Analyst, confirmed · high confidence");
  });

  it("maps the graph onto the OSINT graph engine, keeping each edge's verification", () => {
    const g: InvestigationGraph = {
      nodes: [
        { ref: { kind: "finding", id: 1, sub: "" }, key: "finding:1", label: "XSS", detail: "", severity: "high", flagged: false },
        { ref: { kind: "asset", id: 2, sub: "" }, key: "asset:2", label: "app", detail: "", severity: null, flagged: true },
      ],
      edges: [{ id: "r1", source: "finding:1", target: "asset:2", type: "affects", label: "affects", directed: true, origin: "derived", verification: "inferred", confidence: "high", relationId: 1, updatedAt: "t" }],
      truncated: false,
    };
    const c = toCanvas(g);
    expect(c.nodes.map((n) => [n.id, n.glyph, n.flagged])).toEqual([
      ["finding:1", "F", false],
      ["asset:2", "A", true],
    ]);
    expect(c.edges[0]).toMatchObject({ source: "finding:1", target: "asset:2", directed: true, verification: "inferred" });
  });
});
