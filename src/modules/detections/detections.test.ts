import { describe, expect, it } from "vitest";
import { diffLines, explain, isYara, runState, testsLabel, yaraString } from "./detections";

describe("detections", () => {
  it("diffs rule versions line by line", () => {
    const d = diffLines("title: a\nlevel: low\nstatus: test", "title: a\nlevel: high\nstatus: test");
    expect(d).toEqual([
      { kind: "same", text: "title: a" },
      { kind: "removed", text: "level: low" },
      { kind: "added", text: "level: high" },
      { kind: "same", text: "status: test" },
    ]);
    expect(diffLines("", "x").filter((l) => l.kind === "added")).toHaveLength(1);
  });

  it("states and tests read plainly", () => {
    expect(runState({ runnable: false, errors: 2, enabled: true }).label).toBe("cannot run");
    expect(runState({ runnable: true, errors: 0, enabled: false }).label).toBe("disabled");
    expect(testsLabel({ testsPassed: 0, testsFailed: 0 })).toBeNull();
    expect(testsLabel({ testsPassed: 3, testsFailed: 1 })?.tone).toBe("danger");
    expect(testsLabel({ testsPassed: 1, testsFailed: 0 })?.label).toBe("1 passing test");
  });

  it("explains a match", () => {
    const lines = explain({ condition: "condition 1", selections: [{ name: "selection", matched: true, hits: [{ field: "EventID", condition: "EventID '4625'", value: "4625" }] }, { name: "filter", matched: false, hits: [] }] });
    expect(lines).toEqual(["selection: EventID '4625' — the event has 4625", "filter: did not match"]);
  });

  it("explains a YARA match by its strings", () => {
    const x = {
      kind: "yara" as const,
      rule: "Demo",
      tags: [],
      metas: [] as [string, string][],
      limit: 1000,
      kept: 10,
      strings: [
        { id: "$url", count: 1, matches: [{ offset: 6, length: 26, text: "http://evil.example (UTF-16LE)", hex: "68", xor: null }] },
        { id: "$k", count: 1000, matches: [{ offset: 255, length: 3, text: "KEY", hex: "4b", xor: 32 }] },
      ],
    };
    expect(isYara(x)).toBe(true);
    expect(explain(x)).toEqual(["$url matched once, first at offset 0x6: http://evil.example (UTF-16LE)", "$k matched at least 1,000 times, first at offset 0xff: KEY (xor key 0x20)"]);
    expect(explain({ ...x, strings: [] })[0]).toContain("no string was needed");
    expect(yaraString({ id: "$a", count: 3, matches: [] })).toBe("$a matched 3 times");
    expect(explain(null)).toEqual([]);
    expect(isYara({ condition: "c", selections: [] })).toBe(false);
  });
});
