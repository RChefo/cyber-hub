import type { BackupInfo, RestoreOutcome } from "@/lib/types";
import { formatBytes, formatDateTime, pluralize } from "@/lib/utils";

/** What the confirmation says before a backup replaces the current database. */
export function restoreSummary(info: BackupInfo): string[] {
  const lines = [
    `${info.fileName}: ${formatBytes(info.size)}${info.modified ? `, saved ${formatDateTime(info.modified)}` : ""}.`,
    `It holds ${pluralize(info.projects, "project")} and ${pluralize(info.findings, "finding")}.`,
  ];
  if (info.schema < info.latest) {
    lines.push(`It was made by an earlier version (schema ${info.schema}) and is upgraded to schema ${info.latest} when it opens.`);
  }
  if (info.evidenceReferenced > 0) {
    lines.push(
      info.evidenceAvailable === info.evidenceReferenced
        ? info.evidenceReferenced === 1
          ? "The evidence file it refers to is available."
          : `All ${pluralize(info.evidenceReferenced, "evidence file")} it refers to are available.`
        : `${info.evidenceAvailable} of the ${pluralize(info.evidenceReferenced, "evidence file")} it refers to are available. The others were deleted after the backup was made and stay missing.`,
    );
  }
  lines.push("Your current database is kept in the backups folder, with the evidence files only it refers to. Nothing is deleted. Cyber Hub restarts to finish.");
  return lines;
}

/** The notice shown once after the restart. */
export function restoreNotice(o: RestoreOutcome): { tone: "success" | "warning" | "danger"; title: string; description: string } {
  if (o.retry) return { tone: "warning", title: "The backup is not restored yet", description: o.error ?? "It is restored at the next start." };
  if (!o.ok) return { tone: "danger", title: "The backup was not restored", description: o.error ?? "The current database was kept." };
  const mcp = o.mcpTurnedOff ? " The MCP bridge was turned off; turn it on again on the MCP page if you use it." : "";
  if (o.error) return { tone: "warning", title: "Database restored with a warning", description: o.error + mcp };
  const parts = [`${o.source} is now in use. The previous database is kept in ${o.keptIn ?? "the backups folder"}`];
  if (o.evidenceKept > 0) parts[0] += `, with ${pluralize(o.evidenceKept, "evidence file")} only it refers to`;
  parts[0] += ".";
  if (o.evidenceRestored > 0) parts.push(`${pluralize(o.evidenceRestored, "evidence file")} came back from the backup's folder.`);
  return { tone: "success", title: "Database restored", description: parts.join(" ") + mcp };
}
