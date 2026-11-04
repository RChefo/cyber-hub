import { describe, expect, it } from "vitest";
import { dayBounds, groupByDay } from "./TimelineTab";
import type { TimelineEvent } from "./types";

const ev = (id: number, at: string): TimelineEvent => ({ id, at, kind: "collection", summary: `e${id}`, source: null, entityId: null, relationshipId: null, operationId: null, graphId: null });

describe("timeline helpers", () => {
  it("groups consecutive events of the same local day, keeping order", () => {
    const groups = groupByDay([ev(3, "2026-11-05T15:00:00"), ev(2, "2026-11-05T09:00:00"), ev(1, "2026-11-03T12:00:00")]);
    expect(groups.map(([, list]) => list.map((e) => e.id))).toEqual([[3, 2], [1]]);
  });

  it("turns date inputs into inclusive bounds and ignores invalid values", () => {
    expect(dayBounds("2026-11-01", "2026-11-05")).toEqual({ from: "2026-11-01T00:00:00", to: "2026-11-05T23:59:59.999" });
    expect(dayBounds("", "nope")).toEqual({ from: null, to: null });
  });
});
