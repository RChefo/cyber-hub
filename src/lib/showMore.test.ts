import { describe, expect, it } from "vitest";
import { limitList, SHOW_STEP } from "./showMore";

describe("limitList", () => {
  it("keeps short lists whole", () => {
    expect(limitList([1, 2, 3], SHOW_STEP)).toEqual({ visible: [1, 2, 3], hidden: 0 });
  });

  it("cuts long lists to the limit and counts the rest", () => {
    const items = Array.from({ length: 20_009 }, (_, i) => i);
    const { visible, hidden } = limitList(items, SHOW_STEP);
    expect(visible).toHaveLength(SHOW_STEP);
    expect(visible[0]).toBe(0);
    expect(hidden).toBe(20_009 - SHOW_STEP);
    expect(limitList(items, 20_009).hidden).toBe(0);
  });
});
