import { describe, expect, it } from "vitest";
import type { BackupInfo, RestoreOutcome } from "@/lib/types";
import { restoreNotice, restoreSummary } from "./restore";

const info: BackupInfo = { fileName: "cyberhub-backup.db", size: 2048, modified: null, schema: 17, latest: 17, projects: 1, findings: 12, evidenceReferenced: 0, evidenceAvailable: 0 };

describe("restore summary", () => {
  it("describes the backup and what happens to the current database", () => {
    const lines = restoreSummary(info);
    expect(lines[0]).toBe("cyberhub-backup.db: 2.0 KB.");
    expect(lines[1]).toBe("It holds 1 project and 12 findings.");
    expect(lines.at(-1)).toContain("Nothing is deleted");
    expect(lines.join(" ")).not.toContain("schema");
  });

  it("mentions an upgrade and evidence files that stay missing", () => {
    const lines = restoreSummary({ ...info, schema: 12, evidenceReferenced: 3, evidenceAvailable: 2 }).join(" ");
    expect(lines).toContain("schema 12");
    expect(lines).toContain("upgraded to schema 17");
    expect(lines).toContain("2 of the 3 evidence files it refers to are available");
    expect(restoreSummary({ ...info, evidenceReferenced: 1, evidenceAvailable: 1 }).join(" ")).toContain("The evidence file it refers to is available.");
    expect(restoreSummary({ ...info, evidenceReferenced: 4, evidenceAvailable: 4 }).join(" ")).toContain("All 4 evidence files it refers to are available.");
  });
});

describe("restore notice", () => {
  const ok: RestoreOutcome = { ok: true, source: "b.db", keptIn: "backups/before-restore-20261109T070000Z", evidenceKept: 0, evidenceRestored: 0, mcpTurnedOff: false, retry: false, error: null };
  it("says where the previous database is", () => {
    expect(restoreNotice(ok)).toEqual({ tone: "success", title: "Database restored", description: "b.db is now in use. The previous database is kept in backups/before-restore-20261109T070000Z." });
    expect(restoreNotice({ ...ok, evidenceKept: 2, evidenceRestored: 1 }).description).toBe(
      "b.db is now in use. The previous database is kept in backups/before-restore-20261109T070000Z, with 2 evidence files only it refers to. 1 evidence file came back from the backup's folder.",
    );
  });
  it("reports warnings and failures with the reason", () => {
    expect(restoreNotice({ ...ok, error: "not every evidence file was sorted" }).tone).toBe("warning");
    expect(restoreNotice({ ...ok, ok: false, keptIn: null, error: "damaged" })).toEqual({ tone: "danger", title: "The backup was not restored", description: "damaged" });
    expect(restoreNotice({ ...ok, ok: false, keptIn: null, retry: true, error: "still in use" })).toEqual({ tone: "warning", title: "The backup is not restored yet", description: "still in use" });
  });
  it("says when the MCP bridge was turned off", () => {
    expect(restoreNotice({ ...ok, mcpTurnedOff: true }).description).toContain("The MCP bridge was turned off");
  });
});
