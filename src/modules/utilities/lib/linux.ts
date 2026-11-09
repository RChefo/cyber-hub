import type { ContainerFileReport, ContainerIssue, FindingInput } from "@/lib/types";

export const LINUX_KIND_LABEL: Record<string, string> = {
  crontab: "Crontab",
  "system-crontab": "System crontab",
  "cron-script": "Cron script",
  systemd: "systemd unit",
  rc: "Boot script",
  "init-script": "Init script",
  motd: "Login message script",
  preload: "Preload list",
  shell: "Shell start-up file",
  environment: "Environment file",
  "authorized-keys": "SSH authorized keys",
  sudoers: "sudoers",
  passwd: "Accounts (passwd)",
  shadow: "Passwords (shadow)",
  pam: "PAM configuration",
  autostart: "Desktop autostart",
  udev: "udev rules",
  unknown: "Not read",
};

/** The ATT&CK technique ID named in a reference ("MITRE ATT&CK T1053.003 …"). */
export function techniqueOf(reference: string): string | null {
  return reference.match(/\bT\d{4}(?:\.\d{3})?\b/)?.[0] ?? null;
}

/** The finding a persistence issue becomes: its title names the file and line (at most 200
 * characters), so it is recorded once; the description keeps the file's SHA-256. */
export function linuxFinding(projectId: number, report: Pick<ContainerFileReport, "file" | "kind" | "sha256">, i: ContainerIssue): FindingInput {
  const technique = techniqueOf(i.reference);
  return {
    projectId,
    title: `${i.title}: ${report.file} (${i.location})`.slice(0, 200),
    severity: i.severity,
    status: "new",
    category: "Persistence",
    confidence: "medium",
    description: `${i.detail}\n\nFile: ${report.file} (${LINUX_KIND_LABEL[report.kind] ?? report.kind}), ${i.location}.${report.sha256 ? `\nSHA-256 of the file as read: ${report.sha256}` : ""}`,
    affectedTarget: report.file,
    technicalDetails: `Rule ${i.rule}. Reference: ${i.reference}. Read from the file system without running anything; the patterns are leads to confirm, not proof of compromise.`,
    remediation: i.remediation,
    tags: ["linux", "persistence", report.kind, ...(technique ? [technique] : [])],
  };
}
