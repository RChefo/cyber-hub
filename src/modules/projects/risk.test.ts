import { describe, expect, it } from "vitest";
import type { RiskAcceptance } from "@/lib/types";
import { addDays, coverIndex, coverKey, daysUntil, draftProblems, expiryText, newDraft } from "./risk";

const TODAY = "2026-11-10";

function acceptance(over: Partial<RiskAcceptance>): RiskAcceptance {
  return {
    id: 1,
    projectId: 1,
    title: "t",
    justification: "j",
    compensating: "",
    owner: "o",
    approver: "a",
    approvedAt: TODAY,
    expiresAt: "2027-02-08",
    reviewAt: null,
    status: "active",
    standing: "active",
    revokedAt: null,
    revokedReason: "",
    createdAt: "",
    updatedAt: "",
    items: [],
    ...over,
  };
}

describe("risk acceptance helpers", () => {
  it("starts a draft approved today for 90 days and lists what is missing", () => {
    const d = newDraft(TODAY, "Legacy TLS");
    expect([d.approvedAt, d.expiresAt]).toEqual([TODAY, "2027-02-08"]);
    expect(draftProblems(d, TODAY)).toEqual(["the justification", "the risk owner", "the approver"]);
    const full = { ...d, justification: "j", owner: "o", approver: "a" };
    expect(draftProblems(full, TODAY)).toEqual([]);
    expect(draftProblems({ ...full, expiresAt: TODAY }, TODAY)).toEqual(["an expiry date after today"]);
    expect(draftProblems({ ...full, expiresAt: addDays(TODAY, 4 * 365) }, TODAY)).toEqual(["an expiry within three years of the approval"]);
    expect(draftProblems({ ...full, approvedAt: addDays(TODAY, 1) }, TODAY)).toEqual(["an approval date (today or earlier)"]);
    expect(draftProblems({ ...full, reviewAt: addDays(TODAY, 200) }, TODAY)).toEqual(["a review date between today and the expiry"]);
  });

  it("says how long is left", () => {
    expect(daysUntil("2026-11-13", TODAY)).toBe(3);
    expect(expiryText({ expiresAt: "2026-11-11", status: "active" }, TODAY)).toBe("expires in 1 day (2026-11-11)");
    expect(expiryText({ expiresAt: "2026-11-08", status: "active" }, TODAY)).toBe("expired 2 days ago (2026-11-08)");
    expect(expiryText({ expiresAt: TODAY, status: "active" }, TODAY)).toBe("expires today");
  });

  it("indexes what active acceptances cover, ignoring revoked ones and items that left", () => {
    const a = acceptance({
      items: [
        { kind: "finding", refId: 4, requirement: "", label: "", status: "accepted_risk", addedAt: "", removedAt: null, removedReason: "" },
        { kind: "finding", refId: 5, requirement: "", label: "", status: "reopened", addedAt: "", removedAt: "x", removedReason: "reopened" },
        { kind: "asvs", refId: 2, requirement: "V1.2.3", label: "", status: "non_compliant", addedAt: "", removedAt: null, removedReason: "" },
      ],
    });
    const revoked = acceptance({ id: 2, status: "revoked", standing: "revoked", items: [{ kind: "finding", refId: 6, requirement: "", label: "", status: "reopened", addedAt: "", removedAt: null, removedReason: "" }] });
    const idx = coverIndex([a, revoked]);
    expect(idx.get(coverKey("finding", 4))?.id).toBe(1);
    expect(idx.has(coverKey("finding", 5))).toBe(false);
    expect(idx.has(coverKey("finding", 6))).toBe(false);
    expect(idx.get(coverKey("asvs", 2, "V1.2.3"))?.id).toBe(1);
  });
});
