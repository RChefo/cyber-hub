// SPDX-License-Identifier: Apache-2.0
import type { ContainerFileReport, ContainerIssue, FindingInput } from "@/lib/types";

export const KIND_LABEL: Record<string, string> = { dockerfile: "Dockerfile", compose: "Compose file", kubernetes: "Kubernetes manifests", unknown: "Not read" };
const ORDER = ["critical", "high", "medium", "low", "info"] as const;

/** Issue counts per severity, most severe first, without zeros: "1 critical, 3 high". */
export function countSummary(issues: Pick<ContainerIssue, "severity">[]): string {
  const parts = ORDER.map((s) => [s, issues.filter((i) => i.severity === s).length] as const)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`);
  return parts.length ? parts.join(", ") : "no issues";
}

/** A stable key for an issue of a file (used for selection). */
export const issueKey = (file: string, i: Pick<ContainerIssue, "rule" | "location">) => `${file}#${i.rule}@${i.location}`;

/** A long path as its last two parts ("…/k8s/deploy.yaml"). */
export function shortPath(file: string, max = 80): string {
  if (file.length <= max) return file;
  const parts = file.split(/[\\/]/).filter(Boolean);
  return `…/${parts.slice(-2).join("/")}`.slice(-max);
}

/** The finding an issue becomes: its title names the file and place (at most 200 characters,
 * the limit of a finding title), so it is recorded once. */
export function containerFinding(projectId: number, report: Pick<ContainerFileReport, "file" | "kind">, i: ContainerIssue): FindingInput {
  return {
    projectId,
    title: `${i.title}: ${shortPath(report.file)} (${i.location})`.slice(0, 200),
    severity: i.severity,
    status: "new",
    category: "Container configuration",
    confidence: "high",
    description: `${i.detail}\n\nFile: ${report.file} (${KIND_LABEL[report.kind] ?? report.kind}), ${i.location}.`,
    affectedTarget: report.file,
    technicalDetails: `Rule ${i.rule}. Reference: ${i.reference}.`,
    remediation: i.remediation,
    tags: ["container", report.kind],
  };
}
