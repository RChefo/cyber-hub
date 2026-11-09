import { describe, expect, it } from "vitest";
import type { BinaryReport } from "@/lib/types";
import { capabilityFinding, hardeningSummary, stringIndicators } from "./binary";

const report = (over: Partial<BinaryReport> = {}): BinaryReport => ({
  format: "PE32+",
  machine: "x64",
  kind: "executable (console)",
  size: 135168,
  md5: "0".repeat(32),
  sha1: "1".repeat(40),
  sha256: "2".repeat(64),
  imphash: "3".repeat(32),
  compiled: "2026-11-09T10:00:00Z",
  interpreter: "",
  entropy: 6.1,
  dotnet: false,
  sections: [],
  libraries: [],
  exports: [],
  hardening: [
    { name: "ASLR", present: true, detail: "" },
    { name: "DEP", present: true, detail: "" },
    { name: "Control Flow Guard", present: false, detail: "" },
  ],
  capabilities: [],
  strings: [],
  stringsTotal: 0,
  overlay: 0,
  warnings: [],
  ...over,
});

describe("file triage helpers", () => {
  it("turn a capability into a finding with hashes and the technique", () => {
    const f = capabilityFinding(3, "loader.exe", report(), { id: "BIN-INJECTION", severity: "high", title: "Can inject code into other processes", detail: "It imports VirtualAllocEx.", technique: "T1055 Process Injection", evidence: ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"] });
    expect(f.title).toBe("Can inject code into other processes (loader.exe)");
    expect(f.description).toContain(`SHA-256: ${"2".repeat(64)}`);
    expect(f.description).toContain("Evidence: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread");
    expect(f.technicalDetails).toContain("MITRE ATT&CK: T1055 Process Injection");
    expect(f.tags).toEqual(["file", "pe32plus", "T1055"]);
  });
  it("summarise hardening and find indicators in strings", () => {
    expect(hardeningSummary(report())).toBe("2 of 3");
    const found = stringIndicators(["GET http://203.0.113.9/stage2.bin HTTP/1.1", "kernel32.dll", "ops@example.com"]);
    expect(found.map((k) => k.kind)).toContain("url");
    expect(found.find((k) => k.kind === "url")?.values).toContain("http://203.0.113.9/stage2.bin");
    expect(found.find((k) => k.kind === "email")?.values).toEqual(["ops@example.com"]);
  });
});
