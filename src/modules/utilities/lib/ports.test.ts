import { describe, expect, it } from "vitest";
import { PORTS, portInfo, searchPorts } from "./ports";

describe("port reference", () => {
  it("has one entry per port with risks and checks", () => {
    expect(new Set(PORTS.map((p) => p.port)).size).toBe(PORTS.length);
    expect(PORTS.every((p) => p.risks.length > 0 && p.checks.length > 0)).toBe(true);
  });

  it("finds ports by number or name", () => {
    expect(portInfo(3389)?.service).toBe("RDP");
    expect(searchPorts("445").map((p) => p.service)).toEqual(["SMB"]);
    expect(searchPorts("redis")[0].port).toBe(6379);
    expect(searchPorts("")).toHaveLength(PORTS.length);
    expect(searchPorts("99999")).toEqual([]);
  });
});
