import { describe, expect, it } from "vitest";
import type { ApiEndpoint, ApiEndpointScope } from "@/lib/types";
import { authLabel, builderParams, filterEndpoints, issueSummary } from "./apisec";

const ep = (method: string, path: string, extra: Partial<ApiEndpoint> = {}): ApiEndpoint => ({
  method,
  path,
  operationId: "",
  summary: "",
  tags: [],
  params: [],
  bodyTypes: [],
  bodyFields: [],
  auth: [["bearerAuth"]],
  anonymous: false,
  deprecated: false,
  servers: ["https://api.example.com"],
  responses: [],
  seen: 0,
  ...extra,
});

const inScope = (ok: boolean): ApiEndpointScope => ({ url: "https://api.example.com/x", inScope: ok, reason: ok ? "" : "outside the authorized URLs" });

describe("API inventory helpers", () => {
  it("describes who may call an endpoint", () => {
    expect(authLabel({ auth: [], anonymous: true })).toBe("None");
    expect(authLabel({ auth: [["bearerAuth"]], anonymous: false })).toBe("bearerAuth");
    expect(authLabel({ auth: [["a"], ["b", "c"]], anonymous: false })).toBe("a or b + c");
    expect(authLabel({ auth: [["bearerAuth"]], anonymous: true })).toBe("Optional (bearerAuth)");
  });

  it("filters endpoints by text, method and view", () => {
    const endpoints = [
      ep("GET", "/users", { tags: ["people"] }),
      ep("POST", "/users", { auth: [], anonymous: true, bodyFields: ["role"] }),
      ep("DELETE", "/users/{id}", { deprecated: true }),
      ep("GET", "/orders", { params: [{ name: "limit", location: "query", required: false, kind: "integer", bounded: false }] }),
    ];
    const scope = [inScope(true), inScope(true), inScope(true), inScope(false)];
    const f = (text: string, method = "all", view: "all" | "anonymous" | "outOfScope" | "deprecated" = "all") => filterEndpoints(endpoints, scope, { text, method, view });
    expect(f("")).toEqual([0, 1, 2, 3]);
    expect(f("people")).toEqual([0]);
    expect(f("ROLE")).toEqual([1]);
    expect(f("limit")).toEqual([3]);
    expect(f("", "GET")).toEqual([0, 3]);
    expect(f("", "all", "anonymous")).toEqual([1]);
    expect(f("", "all", "outOfScope")).toEqual([3]);
    expect(f("", "all", "deprecated")).toEqual([2]);
    expect(f("users", "GET")).toEqual([0]);
  });

  it("builds the request builder's route and the issue summary", () => {
    expect(builderParams(7, "POST", "https://api.example.com/users")).toEqual({ utility: "http-builder", project: "7", method: "POST", url: "https://api.example.com/users" });
    expect(issueSummary({ issues: [0, 2, 3, 0, 1] })).toBe("2 high, 3 medium, 1 info");
    expect(issueSummary({ issues: [0, 0, 0, 0, 0] })).toBe("no issues");
  });
});
