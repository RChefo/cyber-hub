import { describe, expect, it } from "vitest";
import type { ProcessChain } from "@/lib/types";
import { chainFinding, chainLine } from "./triage";

const chain = (technique?: string): ProcessChain => ({
  pattern: "CHAIN-WEB-SERVER-SHELL",
  title: "Web server process started a shell or a discovery command",
  severity: "high",
  technique,
  why: "A web server worker started a command interpreter.",
  hypotheses: "A request ran commands. Rule out document converters.",
  computer: "WEB01.corp.example",
  processes: [
    { role: "ancestor", depth: -1, time: "", record: 0, eventId: 0, pid: "", image: "C:\\Windows\\System32\\inetsrv\\w3wp.exe", commandLine: "", user: "" },
    { role: "flagged", depth: 0, time: "2026-11-09T11:00:00Z", record: 20, eventId: 4688, pid: "420", image: "C:\\Windows\\System32\\cmd.exe", commandLine: 'cmd.exe /c "whoami"', user: "CORP\\iis" },
    { role: "descendant", depth: 1, time: "2026-11-09T11:00:01Z", record: 21, eventId: 4688, pid: "432", image: "C:\\Windows\\System32\\whoami.exe", commandLine: "whoami", user: "CORP\\iis" },
  ],
});

describe("process chains (Mission 6)", () => {
  it("print each process with where the log has it", () => {
    const [parent, flagged, child] = chain().processes.map(chainLine);
    expect(parent).toBe("w3wp.exe (started before the log (known only by name))");
    expect(flagged).toBe('  ▶ cmd.exe (2026-11-09T11:00:00Z · record 20 · event 4688 · PID 420 · CORP\\iis) — cmd.exe /c "whoami"');
    expect(child.startsWith("    whoami.exe (")).toBe(true);
  });

  it("become findings under review that keep facts, signal and hypotheses apart", () => {
    const f = chainFinding(7, "Security.evtx", chain("T1505.003 Server Software Component: Web Shell"));
    expect(f).toMatchObject({ projectId: 7, status: "under_review", confidence: "low", severity: "high", affectedTarget: "WEB01.corp.example" });
    expect(f.title).toBe("Web server process started a shell or a discovery command: w3wp.exe → cmd.exe (Security.evtx)");
    const [observed, why, hypotheses] = f.description!.split("\n\n");
    expect(observed.startsWith("Observed in Security.evtx on WEB01.corp.example:")).toBe(true);
    expect(why).toBe("Why it was flagged (derived): A web server worker started a command interpreter.");
    expect(hypotheses.startsWith("Hypotheses to test:")).toBe(true);
    expect(f.tags).toEqual(["logs", "windows", "process-chain", "T1505.003"]);
  });

  it("claim no technique the chain does not show", () => {
    const f = chainFinding(7, "Security.evtx", chain());
    expect(f.tags).toEqual(["logs", "windows", "process-chain"]);
    expect(f.technicalDetails).toContain("No ATT&CK technique is claimed");
  });
});
