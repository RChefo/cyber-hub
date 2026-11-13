// SPDX-License-Identifier: Apache-2.0
/**
 * In-memory buffer of live process output. The Tauri Channel callback keeps firing
 * after the dialog that started a run is closed, so output is collected here and
 * can be followed from the Runs page. Persisted output is stored by the backend
 * when the process exits.
 */
import { useSyncExternalStore } from "react";
import type { ExecEvent, ExecutionStatus } from "@/lib/types";
import { invalidate } from "@/lib/query";

export interface LiveLine {
  stream: "stdout" | "stderr" | "system";
  text: string;
}

export interface LiveRun {
  executionId: number;
  toolId: string;
  kind: "run" | "install";
  program: string;
  args: string[];
  lines: LiveLine[];
  status: ExecutionStatus;
  exitCode: number | null;
  startedAt: number;
}

const MAX_LINES = 20_000;
const runs = new Map<number, LiveRun>();
const listeners = new Set<() => void>();
let version = 0;

function emit() {
  version++;
  listeners.forEach((l) => l());
}

let pendingEmit = false;
function emitSoon() {
  if (pendingEmit) return;
  pendingEmit = true;
  requestAnimationFrame(() => {
    pendingEmit = false;
    emit();
  });
}

/**
 * Returns an event handler for a Channel. Events that arrive before `started`
 * (none in practice) are buffered into a temporary record.
 */
export function createLiveHandler(toolId: string, kind: "run" | "install", onExit?: (status: ExecutionStatus) => void) {
  let id: number | null = null;
  return (e: ExecEvent) => {
    if (e.type === "started") {
      id = e.executionId;
      runs.set(id, {
        executionId: id,
        toolId,
        kind,
        program: e.program,
        args: e.args,
        lines: [{ stream: "system", text: `$ ${[e.program, ...e.args].join(" ")}` }],
        status: "running",
        exitCode: null,
        startedAt: Date.now(),
      });
      invalidate("executions");
      emit();
      return;
    }
    if (id === null) return;
    const run = runs.get(id);
    if (!run) return;
    if (e.type === "stdout" || e.type === "stderr") {
      if (run.lines.length < MAX_LINES) run.lines.push({ stream: e.type, text: e.line });
      else if (run.lines.length === MAX_LINES) run.lines.push({ stream: "system", text: "… live view truncated; full output (up to 2 MB) is saved when the process exits." });
      run.lines = run.lines.slice(); // new identity for React
      emitSoon();
    } else if (e.type === "exit") {
      run.status = e.status;
      run.exitCode = e.code;
      run.lines = [...run.lines, { stream: "system", text: `Process ${e.status}${e.code !== null ? ` (exit code ${e.code})` : ""}` }];
      invalidate("executions", "activity", "history", "detections");
      emit();
      onExit?.(e.status);
    }
  };
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function useLiveRun(id: number | null): LiveRun | undefined {
  useSyncExternalStore(subscribe, () => version);
  return id === null ? undefined : runs.get(id);
}

export function useLiveRuns(): LiveRun[] {
  useSyncExternalStore(subscribe, () => version);
  return [...runs.values()].sort((a, b) => b.startedAt - a.startedAt);
}
