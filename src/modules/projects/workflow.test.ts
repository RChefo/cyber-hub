// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import type { WorkflowNodeSpec } from "@/lib/types";
import { draftProblems, hasActiveStep, moveStep, newStep, parseTargets } from "./workflow";

const nodes: WorkflowNodeSpec[] = [
  { type: "passive_discovery", label: "Passive discovery", description: "", active: false, retryable: true, defaultTimeout: 900, maxTimeout: 3600, params: [] },
  {
    type: "service_scan",
    label: "Service scan",
    description: "",
    active: true,
    retryable: false,
    defaultTimeout: 3600,
    maxTimeout: 14400,
    params: [
      { key: "targets", label: "Targets", kind: "targets", required: true, help: "", options: [], min: 1, max: 64 },
      { key: "profile", label: "Ports", kind: "select", required: true, help: "", options: [["quick", "Quick"], ["standard", "Standard"]], min: 0, max: 0 },
    ],
  },
];

describe("workflow editor helpers", () => {
  it("creates steps with default selections", () => {
    expect(newStep(nodes[1]).params).toEqual({ profile: "quick" });
  });

  it("moves steps within bounds", () => {
    const a = newStep(nodes[0]);
    const b = newStep(nodes[1]);
    expect(moveStep([a, b], 0, 1)).toEqual([b, a]);
    expect(moveStep([a, b], 0, -1)).toEqual([a, b]);
  });

  it("parses targets and reports problems before saving", () => {
    expect(parseTargets("192.0.2.1\n192.0.2.1, app.example.com ")).toEqual(["192.0.2.1", "app.example.com"]);
    const def = { steps: [newStep(nodes[0]), newStep(nodes[1])] };
    expect(hasActiveStep(def, nodes)).toBe(true);
    const problems = draftProblems("", def, nodes, true);
    expect(problems).toContain("Give the workflow a name.");
    expect(problems.some((p) => p.includes("Targets is required"))).toBe(true);
    expect(problems.some((p) => p.includes("cannot run on a schedule"))).toBe(true);
    expect(draftProblems("Weekly", { steps: [newStep(nodes[0])] }, nodes, true)).toEqual([]);
  });
});
