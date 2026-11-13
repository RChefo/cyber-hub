// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { COMPACT_SIDEBAR_BELOW, sidebarCollapsed } from "./viewport";

describe("sidebar width", () => {
  it("keeps labels on wide windows unless the user collapsed it", () => {
    expect(sidebarCollapsed(1920, false)).toBe(false);
    expect(sidebarCollapsed(1280, false)).toBe(false); // 1920 × 1080 at 150 %
    expect(sidebarCollapsed(1920, true)).toBe(true);
  });

  it("shows icons only when the window is too narrow for labels", () => {
    expect(sidebarCollapsed(960, false)).toBe(true); // 1920 × 1080 at 200 %
    expect(sidebarCollapsed(800, false)).toBe(true); // the minimum window
    expect(sidebarCollapsed(COMPACT_SIDEBAR_BELOW - 1, false)).toBe(true);
    expect(sidebarCollapsed(COMPACT_SIDEBAR_BELOW, false)).toBe(false);
  });
});
