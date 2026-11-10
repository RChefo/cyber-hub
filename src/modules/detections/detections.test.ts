import { describe, expect, it } from "vitest";
import { correlationSummary, diffLines, explain, isYara, runState, testsLabel, yaraString } from "./detections";

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

describe("correlation rules", () => {
  it("summarizes a correlation section in one sentence", () => {
    expect(correlationSummary({ type: "event_count", rules: ["failed_login"], groupBy: ["User"], timespan: 600, timespanText: "10m", condition: [["gte", 10]], fields: [], aliases: {}, generate: false })).toBe(
      "event count of failed_login by User within 10m: count ≥ 10",
    );
    expect(correlationSummary({ type: "temporal_ordered", rules: ["many", "success"], groupBy: [], timespan: 600, timespanText: "10m", condition: [], fields: [], aliases: {}, generate: false })).toBe(
      "ordered temporal proximity of many, success over all events within 10m: all 2 rules in order",
    );
    expect(correlationSummary({ type: "value_count", rules: ["r"], groupBy: ["Host"], timespan: 60, timespanText: "1m", condition: [["gt", 2], ["lte", 9]], fields: ["User"], aliases: {}, generate: true })).toContain("distinct User > 2 and distinct User ≤ 9");
  });

  it("explains a correlation match with its group, window and events", () => {
    const lines = explain({
      kind: "correlation",
      type: "temporal_ordered",
      rules: [{ ref: "multiple_failed_login", title: "Multiple failed logons" }, { ref: "successful_login", title: "Successful login" }],
      groupBy: [["User", "admin"]],
      timespan: "10m",
      condition: "all 2 rules in order",
      value: 2,
      first: "2026-11-09T10:03:00Z",
      last: "2026-11-09T10:04:00Z",
      events: [
        { rule: "multiple_failed_login", position: "window 2026-11-09T10:00:00Z – 2026-11-09T10:03:00Z · User=admin", time: "2026-11-09T10:03:00Z", source: "dc1.evtx", sourceId: 7 },
        { rule: "successful_login", position: "record 9", time: "2026-11-09T10:04:00Z", source: "dc2.evtx", sourceId: 8 },
      ],
      total: 30,
      kept: 2,
    });
    expect(lines[0]).toBe("For User=admin: all 2 rules in order within 10m (measured 2)");
    expect(lines[2]).toBe("multiple_failed_login: window 2026-11-09T10:00:00Z – 2026-11-09T10:03:00Z · User=admin in dc1.evtx");
    expect(lines[3]).toBe("successful_login: record 9 at 2026-11-09T10:04:00Z in dc2.evtx");
    expect(lines.at(-1)).toBe("28 more events not listed");
  });
});
