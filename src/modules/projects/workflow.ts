// SPDX-License-Identifier: Apache-2.0
import type { Tone } from "@/components/ui/Badges";
import type { WorkflowDefinition, WorkflowNodeSpec, WorkflowRunStatus, WorkflowRunStep, WorkflowStep } from "@/lib/types";

export const RUN_STATUS_META: Record<WorkflowRunStatus | WorkflowRunStep["status"], { label: string; tone: Tone }> = {
  running: { label: "Running", tone: "accent" },
  succeeded: { label: "Succeeded", tone: "success" },
  partial: { label: "Partial", tone: "warning" },
  failed: { label: "Failed", tone: "danger" },
  cancelled: { label: "Cancelled", tone: "default" },
  pending: { label: "Pending", tone: "default" },
  skipped: { label: "Skipped", tone: "default" },
};

export function newStep(spec: WorkflowNodeSpec): WorkflowStep {
  const params: Record<string, unknown> = {};
  for (const p of spec.params) if (p.kind === "select" && p.required && p.options.length) params[p.key] = p.options[0][0];
  return { type: spec.type, name: "", params, timeoutSecs: 0, retries: 0, continueOnError: false };
}

/** Moves the step at `from` up (-1) or down (+1); returns a new list. */
export function moveStep(steps: WorkflowStep[], from: number, by: -1 | 1): WorkflowStep[] {
  const to = from + by;
  if (to < 0 || to >= steps.length) return steps;
  const out = [...steps];
  [out[from], out[to]] = [out[to], out[from]];
  return out;
}

export function hasActiveStep(def: WorkflowDefinition, nodes: WorkflowNodeSpec[]): boolean {
  return def.steps.some((s) => nodes.find((n) => n.type === s.type)?.active);
}

/** Targets typed one per line (or separated by spaces/commas) as a list. */
export function parseTargets(text: string): string[] {
  return [...new Set(text.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean))];
}

/** Problems the editor can show before saving (the backend validates everything again). */
export function draftProblems(name: string, def: WorkflowDefinition, nodes: WorkflowNodeSpec[], scheduled: boolean): string[] {
  const out: string[] = [];
  if (!name.trim()) out.push("Give the workflow a name.");
  if (def.steps.length === 0) out.push("Add at least one step.");
  def.steps.forEach((s, i) => {
    const spec = nodes.find((n) => n.type === s.type);
    if (!spec) return;
    for (const p of spec.params) {
      const v = s.params[p.key];
      const empty = v == null || v === "" || (Array.isArray(v) && v.length === 0);
      if (p.required && empty) out.push(`Step ${i + 1}: ${p.label} is required.`);
    }
    if (scheduled && spec.active) out.push(`Step ${i + 1} (${spec.label}) contacts targets, so the workflow cannot run on a schedule.`);
  });
  return out;
}
