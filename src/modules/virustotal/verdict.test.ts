import { describe, expect, it } from "vitest";
import { reputationTone, shares, verdictOf } from "./verdict";

const s = (malicious = 0, suspicious = 0, harmless = 0, undetected = 0) => ({ malicious, suspicious, harmless, undetected, timeout: 0 });

describe("verdictOf", () => {
  it("prioritizes malicious, then suspicious, then harmless", () => {
    expect(verdictOf(s(3, 1, 50, 20), 74, "file")).toMatchObject({ tone: "danger", title: "Malicious" });
    expect(verdictOf(s(3, 1, 50, 20), 74, "file").summary).toBe("3 of 74 security vendors flagged this file as malicious and 1 as suspicious.");
    expect(verdictOf(s(0, 2, 50), 70, "url")).toMatchObject({ tone: "warning", title: "Suspicious" });
    expect(verdictOf(s(0, 0, 60, 30), 90, "ip")).toMatchObject({ tone: "success", title: "No detections" });
  });

  it("does not call an unanalysed record clean", () => {
    expect(verdictOf(s(0, 0, 0, 70), 70, "domain")).toMatchObject({ tone: "default", title: "No verdicts" });
    expect(verdictOf(s(), 0, "domain").summary).toBe("No vendor has a verdict for this domain yet.");
  });
});

describe("shares", () => {
  it("returns non-zero percentages in a fixed order", () => {
    expect(shares(s(1, 0, 3, 0))).toEqual([
      { key: "malicious", pct: 25 },
      { key: "harmless", pct: 75 },
    ]);
    expect(shares(s())).toEqual([]);
  });
});

describe("reputationTone", () => {
  it("maps the community score", () => {
    expect(reputationTone(-12)).toBe("danger");
    expect(reputationTone(0)).toBe("default");
    expect(reputationTone(40)).toBe("success");
    expect(reputationTone(null)).toBe("default");
  });
});
