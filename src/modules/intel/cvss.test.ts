import { describe, expect, it } from "vitest";
import { bestCvss, isCveId, nvdUrl, parseVector, severityOf } from "./cvss";
import { cweUrl } from "./cwe";

const s = (version: string, score: number, severity: string, source = "nvd@nist.gov (Primary)") => ({ version, score, severity, vector: "", source });

describe("bestCvss", () => {
  it("prefers the newest version, then primary, then highest", () => {
    expect(bestCvss({ cvss: [] })).toBeNull();
    expect(bestCvss({ cvss: [s("2.0", 10, "HIGH"), s("3.1", 7.5, "HIGH")] })?.version).toBe("3.1");
    expect(bestCvss({ cvss: [s("3.1", 9.8, "CRITICAL", "x (Secondary)"), s("3.1", 7.5, "HIGH")] })?.score).toBe(7.5);
    expect(bestCvss({ cvss: [s("3.1", 9.8, "CRITICAL"), s("4.0", 8.7, "HIGH")] })?.version).toBe("4.0");
  });
});

describe("severityOf", () => {
  it("uses the reported severity, falling back to score bands", () => {
    expect(severityOf(s("3.1", 9.8, "CRITICAL"))).toBe("critical");
    expect(severityOf(s("2.0", 6.8, ""))).toBe("medium");
    expect(severityOf(s("2.0", 0, ""))).toBe("info");
    expect(severityOf(null)).toBe("info");
  });
});

describe("parseVector", () => {
  it("parses CVSS 3.1 base metrics with labels", () => {
    const parts = parseVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
    expect(parts).toHaveLength(8);
    expect(parts[0]).toEqual({ key: "AV", name: "Attack vector", value: "N", label: "Network" });
    expect(parts.find((p) => p.key === "S")?.label).toBe("Changed");
  });
  it("parses CVSS 4.0 base metrics and skips supplemental ones", () => {
    const parts = parseVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A");
    expect(parts).toHaveLength(11);
    expect(parts.find((p) => p.key === "AT")?.label).toBe("None");
  });
  it("returns nothing for CVSS 2.0 or garbage", () => {
    expect(parseVector("AV:N/AC:L/Au:N/C:P/I:P/A:P")).toEqual([]);
    expect(parseVector("")).toEqual([]);
  });
});

describe("ids and links", () => {
  it("validates CVE ids and builds links", () => {
    expect(isCveId("cve-2021-44228")).toBe(true);
    expect(isCveId("log4j")).toBe(false);
    expect(nvdUrl("CVE-2021-44228")).toBe("https://nvd.nist.gov/vuln/detail/CVE-2021-44228");
    expect(cweUrl("CWE-79")).toBe("https://cwe.mitre.org/data/definitions/79.html");
    expect(cweUrl("NVD-CWE-Other")).toBeNull();
  });
});
