import { describe, expect, it } from "vitest";
import { CLOUD_KIND_LABEL, cloudFinding } from "./cloud";

describe("cloud findings", () => {
  it("name the file, the resource and the rule", () => {
    const f = cloudFinding(4, { file: "infra/modules/network/security-groups.tf", kind: "terraform" }, {
      rule: "AWS-SG-ADMIN-OPEN",
      severity: "high",
      title: "Remote administration open to the internet",
      location: "aws_security_group.bastion",
      detail: "Ingress from 0.0.0.0/0 on 22, which includes 22 (SSH).",
      remediation: "Use a VPN or Session Manager.",
      reference: "CIS AWS Foundations Benchmark: no security groups allow ingress from 0.0.0.0/0 to remote server administration ports",
    });
    expect(f.title).toBe("Remote administration open to the internet: infra/modules/network/security-groups.tf (aws_security_group.bastion)");
    expect(f.category).toBe("Cloud configuration");
    expect(f.tags).toEqual(["cloud", "terraform"]);
    expect(f.description).toContain("(Terraform), aws_security_group.bastion");
    expect(f.technicalDetails).toContain("Rule AWS-SG-ADMIN-OPEN");
  });
  it("keep titles within 200 characters", () => {
    const f = cloudFinding(1, { file: "a.json", kind: "iam-account" }, { rule: "IAM-PUBLIC", severity: "critical", title: "Resource open to anyone", location: "x".repeat(300), detail: "", remediation: "", reference: "" });
    expect(f.title.length).toBe(200);
    expect(CLOUD_KIND_LABEL["iam-account"]).toBe("IAM account export");
  });
});
