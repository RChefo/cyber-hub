// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { FINDING_STATUS_META } from "@/components/ui/Badges";
import type { FindingStatus } from "@/lib/types";
import { canChangeStatus, isOpenFinding, OPEN_FINDING_STATUSES } from "./findings";

describe("finding lifecycle", () => {
  it("counts only statuses that still need attention as open", () => {
    const all = Object.keys(FINDING_STATUS_META) as FindingStatus[];
    expect(all).toHaveLength(8);
    expect(all.filter(isOpenFinding).sort()).toEqual([...OPEN_FINDING_STATUSES].sort());
    expect(all.filter((s) => !isOpenFinding(s)).sort()).toEqual(["accepted_risk", "false_positive", "resolved"]);
  });

  it("reopens only closed findings", () => {
    expect(canChangeStatus("resolved", "reopened")).toBe(true);
    expect(canChangeStatus("accepted_risk", "reopened")).toBe(true);
    expect(canChangeStatus("new", "reopened")).toBe(false);
    expect(canChangeStatus("confirmed", "confirmed")).toBe(false);
    expect(canChangeStatus("new", "resolved")).toBe(true);
  });
});
