import { describe, expect, it } from "vitest";
import type { McpCatalogTool, McpPending } from "@/lib/types";
import { formatCountdown, gateLabel, groupTools, requestTarget, resultMeta, secondsLeft, shortTool, tabFromParams } from "./mcpMeta";

const tool = (over: Partial<McpCatalogTool>): McpCatalogTool => ({
  name: "cyberhub_x",
  title: "X",
  group: "discovery",
  groupLabel: "Discovery",
  description: "",
  category: "read",
  categoryLabel: "Read local data",
  policy: "allow",
  requiresApproval: false,
  nativeConfirmation: false,
  available: true,
  note: null,
  readOnly: true,
  parameters: [],
  ...over,
});

const pending = (over: Partial<McpPending>): McpPending => ({
  id: "apr_1",
  client: "c",
  connection: 1,
  tool: "cyberhub_run_tool",
  category: "run_tools",
  summary: "Run Nmap",
  details: [],
  checks: [],
  projectId: 1,
  createdAt: "",
  expiresInSecs: 180,
  ...over,
});

describe("MCP workspace helpers", () => {
  it("reads the tab from route params and falls back to the overview", () => {
    expect(tabFromParams({ tab: "approvals" })).toBe("approvals");
    expect(tabFromParams({ tab: "nope" })).toBe("overview");
    expect(tabFromParams()).toBe("overview");
  });

  it("groups tools in catalogue order and drops empty groups", () => {
    const groups: [string, string][] = [
      ["discovery", "Discovery"],
      ["execution", "Execution"],
      ["approvals", "Approvals"],
    ];
    const g = groupTools(groups, [tool({ name: "a", group: "execution" }), tool({ name: "b", group: "discovery" }), tool({ name: "c", group: "execution" })]);
    expect(g.map((x) => x.id)).toEqual(["discovery", "execution"]);
    expect(g[1].tools.map((t) => t.name)).toEqual(["a", "c"]);
  });

  it("describes how a tool is gated", () => {
    expect(gateLabel(tool({})).label).toMatch(/read-only/);
    expect(gateLabel(tool({ readOnly: false, policy: "deny" })).tone).toBe("danger");
    expect(gateLabel(tool({ readOnly: false, policy: "ask", nativeConfirmation: true })).label).toMatch(/system dialog/);
    expect(gateLabel(tool({ readOnly: false, policy: "allow" })).label).toMatch(/without asking/);
  });

  it("finds the target of a pending request", () => {
    expect(requestTarget(pending({ details: [{ label: "Authorized targets", value: "127.0.0.1" }] }))).toBe("127.0.0.1");
    expect(requestTarget(pending({ details: [{ label: "indicator", value: "example.org" }] }))).toBe("example.org");
    expect(requestTarget(pending({ details: [{ label: "Title", value: "x" }] }))).toBeUndefined();
  });

  it("counts down without going negative", () => {
    const p = pending({ expiresInSecs: 100 });
    expect(secondsLeft(p, 0, 30_500)).toBe(70);
    expect(secondsLeft(p, 0, 500_000)).toBe(0);
    expect(formatCountdown(70)).toBe("1:10");
    expect(formatCountdown(5)).toBe("0:05");
  });

  it("labels results and tool names", () => {
    expect(resultMeta("ok").tone).toBe("success");
    expect(resultMeta("weird_value").label).toBe("weird value");
    expect(resultMeta(null).label).toBe("—");
    expect(shortTool("cyberhub_run_tool")).toBe("run_tool");
  });
});
