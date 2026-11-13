// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import type { ContainerIssue } from "@/lib/types";
import { containerFinding, countSummary, issueKey, shortPath } from "./containers";

const issue = (severity: ContainerIssue["severity"], rule = "DF-ROOT"): ContainerIssue => ({
  rule,
  severity,
  title: "The container runs as root",
  location: "line 2",
  detail: "The final stage sets no USER.",
  remediation: "Add USER app.",
  reference: "CIS Docker Benchmark: Ensure that a user for the container has been created",
});

describe("container check helpers", () => {
  it("summarizes severities most severe first", () => {
    expect(countSummary([issue("low"), issue("critical"), issue("high"), issue("high")])).toBe("1 critical, 2 high, 1 low");
    expect(countSummary([])).toBe("no issues");
  });

  it("builds a finding that names the file and the place", () => {
    const f = containerFinding(4, { file: "svc/Dockerfile", kind: "dockerfile" }, issue("high"));
    expect(f).toMatchObject({ projectId: 4, title: "The container runs as root: svc/Dockerfile (line 2)", severity: "high", status: "new", affectedTarget: "svc/Dockerfile", remediation: "Add USER app.", tags: ["container", "dockerfile"] });
    expect(f.technicalDetails).toContain("Rule DF-ROOT. Reference: CIS Docker Benchmark");
    expect(issueKey("svc/Dockerfile", issue("high"))).toBe("svc/Dockerfile#DF-ROOT@line 2");
  });

  it("keeps titles within the 200 characters a finding allows", () => {
    const long = `C:/Users/someone/${"deep/".repeat(40)}k8s/deploy.yaml`;
    const f = containerFinding(1, { file: long, kind: "kubernetes" }, { ...issue("high"), title: "x".repeat(150), location: "Deployment shop/web › container app" });
    expect(f.title.length).toBeLessThanOrEqual(200);
    expect(f.affectedTarget).toBe(long);
    expect(shortPath(long)).toBe("…/k8s/deploy.yaml");
    expect(shortPath("a/b.yaml")).toBe("a/b.yaml");
  });
});
