import { describe, expect, it } from "vitest";
import { captureFinding, captureSpan, formatBytes, logFinding } from "./triage";

describe("triage helpers", () => {
  it("builds findings from capture issues and log detections", () => {
    const f = captureFinding(3, "office.pcapng", { rule: "PCAP-CLEARTEXT-CREDENTIALS", severity: "high", title: "Credentials sent in cleartext (ftp)", detail: "1 login was readable.", remediation: "Use SFTP.", evidence: ["ftp 10.0.0.5 → 10.0.0.9:21 user bob"] });
    expect(f).toMatchObject({ projectId: 3, title: "Credentials sent in cleartext (ftp) (office.pcapng)", severity: "high", affectedTarget: "office.pcapng", tags: ["pcap"] });
    expect(f.description).toContain("- ftp 10.0.0.5 → 10.0.0.9:21 user bob");
    const l = logFinding(3, "access.log", { rule: "WEB-SQLI", severity: "medium", title: "SQL injection attempts", detail: "3 requests.", remediation: "Use parameters.", count: 3, sources: [{ ip: "198.51.100.7", count: 3, examples: ["GET /item?id=1' or '1'='1"] }] });
    expect(l.title).toBe("SQL injection attempts (access.log)");
    expect(l.description).toContain("- 198.51.100.7: 3");
    expect(l.description).toContain("Examples:");
    expect(captureFinding(1, "x".repeat(300), { rule: "R", severity: "low", title: "t", detail: "", remediation: "", evidence: [] }).title.length).toBe(200);
  });

  it("formats sizes and time spans", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatBytes(5 * 1024 * 1024 * 1024)).toBe("5.0 GB");
    expect(captureSpan(1_700_000_000.25, 1_700_000_090.25)).toBe("2023-11-14 22:13:20 UTC, 1 min 30 s");
    expect(captureSpan(null, null)).toBe("no timestamps");
  });
});

describe("Windows event log findings", () => {
  it("carry the ATT&CK technique in the details and as a tag", () => {
    const f = logFinding(5, "Security.evtx", {
      rule: "EVT-LOG-CLEARED",
      severity: "high",
      title: "Event log cleared",
      detail: "An event log was cleared.",
      remediation: "Find out who cleared it.",
      count: 1,
      sources: [{ ip: "user01", count: 1, examples: ["2019-03-19T23:34:25 · WS01 · event 1102 · record 7 · Security log cleared by user01"] }],
      technique: "T1070.001 Indicator Removal: Clear Windows Event Logs",
    });
    expect(f.title).toBe("Event log cleared (Security.evtx)");
    expect(f.technicalDetails).toContain("MITRE ATT&CK: T1070.001 Indicator Removal: Clear Windows Event Logs");
    expect(f.tags).toEqual(["logs", "windows", "T1070.001"]);
  });
});

