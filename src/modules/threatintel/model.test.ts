import { describe, expect, it } from "vitest";
import type { TiProviderResult, TiReport } from "@/lib/types";
import { availability, compareRows, correlate, sortResults, summaryParts } from "./model";

const report = (over: Partial<TiReport>): TiReport => ({
  verdict: null,
  scores: [],
  categories: [],
  families: [],
  tags: [],
  firstSeen: null,
  lastSeen: null,
  facts: [],
  tables: [],
  related: [],
  permalink: null,
  ...over,
});

const result = (providerName: string, status: TiProviderResult["status"], rep: TiReport | null = null): TiProviderResult => ({
  provider: providerName.toLowerCase(),
  providerName,
  status,
  report: rep,
  message: null,
  source: status === "found" || status === "not_found" ? "live" : null,
  fetchedAt: status === "found" ? "2026-11-03T10:00:00Z" : null,
  freshUntil: null,
  quota: null,
});

describe("sortResults", () => {
  it("puts the most severe provider verdicts first and skipped providers last", () => {
    const sorted = sortResults([
      result("Shodan", "found", report({ verdict: { level: "info", label: "2 open ports" } })),
      result("MalwareBazaar", "unsupported"),
      result("OTX", "not_found"),
      result("URLhaus", "found", report({ verdict: { level: "malicious", label: "Listed malware URL" } })),
      result("AbuseIPDB", "error"),
    ]);
    expect(sorted.map((r) => r.providerName)).toEqual(["URLhaus", "Shodan", "OTX", "AbuseIPDB", "MalwareBazaar"]);
  });
});

describe("summaryParts", () => {
  it("lists provider names per outcome and drops empty outcomes", () => {
    const parts = summaryParts({ malicious: ["VirusTotal"], suspicious: [], clean: [], informational: ["Shodan"], noVerdict: [], noRecord: ["AlienVault OTX"], failed: [], skipped: ["MalwareBazaar"] });
    expect(parts.map((p) => [p.label, p.providers.join(",")])).toEqual([
      ["Malicious", "VirusTotal"],
      ["Informational", "Shodan"],
      ["No record", "AlienVault OTX"],
      ["Not run", "MalwareBazaar"],
    ]);
  });
});

describe("correlate", () => {
  it("merges the same related indicator from several providers", () => {
    const c = correlate(
      [
        result("URLhaus", "found", report({ related: [{ kind: "file", value: "a".repeat(64), relation: "payload served" }, { kind: "domain", value: "evil.xyz", relation: "host" }] })),
        result("ThreatFox", "found", report({ related: [{ kind: "file", value: "a".repeat(64), relation: "IOC linked" }] })),
      ],
      "evil.xyz",
    );
    expect(c).toHaveLength(1);
    expect(c[0].sources.map((s) => s.provider)).toEqual(["URLhaus", "ThreatFox"]);
  });
});

describe("compareRows", () => {
  it("compares only providers that answered, keeping their own wording", () => {
    const { providers, rows } = compareRows([
      result("VirusTotal", "found", report({ verdict: { level: "malicious", label: "3 of 70 engines: malicious" }, families: ["agenttesla"] })),
      result("AlienVault OTX", "not_found"),
      result("Shodan", "unsupported"),
    ]);
    expect(providers).toEqual(["VirusTotal", "AlienVault OTX"]);
    expect(rows.find((r) => r.label.startsWith("Verdict"))!.cells).toEqual(["3 of 70 engines: malicious", "—"]);
    expect(rows.find((r) => r.label === "Retrieved")!.cells[0]).toBe("2026-11-03 10:00 (live)");
  });
});

describe("availability", () => {
  const at = "2026-11-03T10:00:00Z";
  it("never asks the user for credentials", () => {
    const a = availability({ configured: false, enabled: true, health: null });
    expect(a.label).toBe("Not configured");
    expect(a.detail).toMatch(/provisioned by the application owner/);
    expect(a.detail).not.toMatch(/settings|enter|add|key/i);
  });
  it("reports the observed service state", () => {
    expect(availability({ configured: true, enabled: false, health: null }).label).toBe("Turned off");
    expect(availability({ configured: true, enabled: true, health: null }).label).toBe("Available");
    expect(availability({ configured: true, enabled: true, health: { state: "rate_limited", message: "Shodan quota or rate limit reached.", at, quota: null } }).tone).toBe("warning");
    const rejected = availability({ configured: true, enabled: true, health: { state: "rejected", message: "x", at, quota: null } });
    expect(rejected.label).toBe("Credentials rejected");
    expect(rejected.detail).toMatch(/application owner/);
  });
});
