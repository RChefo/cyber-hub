import { describe, expect, it } from "vitest";
import { buildVector, defaultSelection, ratingSeverity, vectorParts, versionOf } from "./cvssForm";

describe("CVSS form helpers", () => {
  it("recognizes versions and reads metrics", () => {
    expect(versionOf("CVSS:4.0/AV:N")).toBe("4.0");
    expect(versionOf("CVSS:3.0/AV:N")).toBe("3.1");
    expect(versionOf("AV:N/AC:L")).toBeNull();
    expect(vectorParts("CVSS:3.1/AV:N/AC:L/PR:N")).toEqual({ AV: "N", AC: "L", PR: "N" });
  });

  it("builds a vector from the calculator and keeps metrics it does not show", () => {
    const sel = { ...defaultSelection("4.0"), VC: "H", VI: "H", VA: "H" };
    expect(buildVector("4.0", sel)).toBe("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
    const previous = "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:H/MAV:N/S:X";
    expect(buildVector("4.0", { ...sel, E: "U" }, previous)).toBe("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/CR:H/MAV:N");
    // metrics of another version are not carried over
    expect(buildVector("3.1", defaultSelection("3.1"), previous)).toBe("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
  });

  it("maps ratings to finding severities", () => {
    expect(ratingSeverity("critical")).toBe("critical");
    expect(ratingSeverity("none")).toBe("info");
  });
});
