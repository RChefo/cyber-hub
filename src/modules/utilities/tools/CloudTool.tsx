import { Cloud } from "lucide-react";
import { api } from "@/lib/ipc";
import { CLOUD_KIND_LABEL, cloudFinding } from "../lib/cloud";
import { type ConfigCheckConfig, ConfigCheckTool } from "./ConfigCheckTool";

const CLOUD_CHECKS: ConfigCheckConfig = {
  privacy:
    "Reads the text, file or folder on this device; no cloud account is contacted and nothing is deployed. Terraform (HCL, JSON and terraform show -json plans), CloudFormation (JSON, YAML) and AWS IAM policies, including the output of aws iam get-account-authorization-details, are checked against the CIS AWS Foundations Benchmark, AWS guidance and Rhino Security Labs' privilege-escalation methods. References and variables are not resolved.",
  kinds: [
    { id: "auto", label: "Detect" },
    { id: "terraform", label: "Terraform (HCL)" },
    { id: "cloudformation", label: "CloudFormation" },
    { id: "iam", label: "IAM policy" },
  ],
  kindLabel: CLOUD_KIND_LABEL,
  placeholder: '{\n  "Version": "2012-10-17",\n  "Statement": [{ "Effect": "Allow", "Action": ["iam:PassRole", "ec2:RunInstances"], "Resource": "*" }]\n}',
  folderHint: "A folder is searched for .tf, JSON, YAML and .template files; .git, .terraform, node_modules and build folders are skipped.",
  empty: { icon: Cloud, title: "No cloud configuration found", description: "No Terraform, CloudFormation or IAM policy was found." },
  scanText: (text, kind) => api.iacScanText(text, kind),
  scanPick: (folder) => api.iacScanPick(folder),
  finding: cloudFinding,
};

/** Security utility: AWS infrastructure as code and IAM policies, offline. */
export function CloudTool() {
  return <ConfigCheckTool config={CLOUD_CHECKS} />;
}
