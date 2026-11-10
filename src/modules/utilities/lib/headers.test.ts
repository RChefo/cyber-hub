import { describe, expect, it } from "vitest";
import { analyzeHeaders, weakScriptSources } from "./headers";

const csp = (policy: string) => analyzeHeaders([["content-security-policy", policy]]).find((c) => c.id === "csp")!;

describe("CSP script sources (Mission 6)", () => {
  it("flags wildcard, scheme-only and data: sources of script directives", () => {
    for (const policy of [
      "script-src *",
      "script-src 'self' https:",
      "default-src 'self' http:; object-src 'none'",
      "default-src 'none'; script-src 'self' data:",
      "SCRIPT-SRC 'self' *",
      "script-src-elem https:",
      "script-src-attr *",
      "img-src 'self';script-src *;",
    ]) {
      expect(weakScriptSources(policy), policy).toBe(true);
      expect(csp(policy).detail).toContain("wildcard, scheme-only or data:");
    }
  });

  it("leaves hosts, nonces and other directives alone", () => {
    for (const policy of [
      "script-src 'self' https://cdn.example.com",
      "default-src 'self'; img-src * data:; object-src 'none'",
      "script-src 'nonce-abc' 'strict-dynamic' https://*.example.com",
      "style-src https:",
      "report-uri /csp/script-src-report",
      "",
    ]) {
      expect(weakScriptSources(policy), policy).toBe(false);
    }
  });

  it("reads a hostile policy in linear time", () => {
    // ~400 KB, the most HTTP/1.1 headers a server can send, with no ';' between the names: the
    // regex used before backtracked once per name over the rest of the value (seconds)
    const hostile = "script-src ".repeat(37_000);
    const t0 = performance.now();
    const checks = analyzeHeaders([["content-security-policy", hostile]]);
    expect(performance.now() - t0).toBeLessThan(250);
    expect(checks.find((c) => c.id === "csp")!.level).toBe("warn");
    // the same with a wildcard at the end is one script-src directive that allows any origin
    expect(weakScriptSources(`${"script-src ".repeat(37_000)}*`)).toBe(true);
    expect(weakScriptSources(`script-src ${"'self' ".repeat(50_000)}*`)).toBe(true);
  });
});
