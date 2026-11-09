import type { DetectionExplanation, DetectionRuleSummary } from "@/lib/types";

export type Tone = "default" | "accent" | "success" | "warning" | "danger";

/** A new rule to start from: the shape the Sigma specification describes. */
export const RULE_TEMPLATE = `title: Short description of what the rule detects
id: ${"00000000-0000-4000-8000-000000000000"}
status: experimental
description: What the rule looks for and why it matters.
author: ''
date: ${new Date().toISOString().slice(0, 10)}
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: ' -enc '
    condition: selection
falsepositives:
    - Administration scripts
level: medium
`;

export const LEVEL_TONE: Record<string, Tone> = { critical: "danger", high: "danger", medium: "warning", low: "accent", informational: "default" };

/** Whether a rule can run, and if not, why in a word. */
export function runState(r: Pick<DetectionRuleSummary, "runnable" | "errors" | "enabled">): { label: string; tone: Tone } {
  if (!r.runnable) return { label: r.errors ? "cannot run" : "not runnable", tone: "danger" };
  return r.enabled ? { label: "enabled", tone: "success" } : { label: "disabled", tone: "default" };
}

/** The tests summary of a rule: passing and failing samples. */
export function testsLabel(r: Pick<DetectionRuleSummary, "testsPassed" | "testsFailed">): { label: string; tone: Tone } | null {
  if (!r.testsPassed && !r.testsFailed) return null;
  if (r.testsFailed) return { label: `${r.testsFailed} failing test${r.testsFailed === 1 ? "" : "s"}`, tone: "danger" };
  return { label: `${r.testsPassed} passing test${r.testsPassed === 1 ? "" : "s"}`, tone: "success" };
}

export type DiffLine = { kind: "same" | "added" | "removed"; text: string };

/** Line diff (longest common subsequence) of two rule versions; at most 3,000 lines each. */
export function diffLines(before: string, after: string): DiffLine[] {
  const a = before.split("\n").slice(0, 3000);
  const b = after.split("\n").slice(0, 3000);
  const n = a.length;
  const m = b.length;
  const lcs: Uint16Array[] = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ kind: "same", text: a[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) out.push({ kind: "removed", text: a[i++] });
    else out.push({ kind: "added", text: b[j++] });
  }
  while (i < n) out.push({ kind: "removed", text: a[i++] });
  while (j < m) out.push({ kind: "added", text: b[j++] });
  return out;
}

/** Why an event matched, as sentences: the selections that matched with their values, and the
 * ones that did not (filters the condition excludes). */
export function explain(x: DetectionExplanation): string[] {
  const out: string[] = [];
  for (const s of x.selections) {
    if (s.matched) for (const h of s.hits) out.push(`${s.name}: ${h.condition} — the event has ${h.value}`);
    else out.push(`${s.name}: did not match`);
  }
  return out;
}
