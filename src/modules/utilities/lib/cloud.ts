// SPDX-License-Identifier: Apache-2.0
import type { ContainerFileReport, ContainerIssue, FindingInput } from "@/lib/types";
import { shortPath } from "./containers";

export const CLOUD_KIND_LABEL: Record<string, string> = {
  terraform: "Terraform",
  "terraform-plan": "Terraform plan",
  cloudformation: "CloudFormation",
  "iam-policy": "IAM policy",
  "iam-account": "IAM account export",
  iam: "IAM policy",
  unknown: "Not read",
};

/** The finding a cloud configuration issue becomes; its title names the file and the resource
 * (at most 200 characters), so it is recorded once. */
export function cloudFinding(projectId: number, report: Pick<ContainerFileReport, "file" | "kind">, i: ContainerIssue): FindingInput {
  return {
    projectId,
    title: `${i.title}: ${shortPath(report.file)} (${i.location})`.slice(0, 200),
    severity: i.severity,
    status: "new",
    category: "Cloud configuration",
    confidence: "high",
    description: `${i.detail}\n\nFile: ${report.file} (${CLOUD_KIND_LABEL[report.kind] ?? report.kind}), ${i.location}.`,
    affectedTarget: report.file,
    technicalDetails: `Rule ${i.rule}. Reference: ${i.reference}. Values written as references, variables or functions are not resolved.`,
    remediation: i.remediation,
    tags: ["cloud", report.kind],
  };
}
