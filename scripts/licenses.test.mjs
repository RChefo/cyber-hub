import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { acceptable, tokenize } from "./licenses.mjs";

// The dependency license policy (Mission 12): SPDX expressions are evaluated, not matched as text.
describe("license policy", () => {
  it("accepts a choice when one side is allowed, and the old Cargo slash form", () => {
    expect(acceptable("MIT OR Apache-2.0")).toBe(true);
    expect(acceptable("MIT/Apache-2.0")).toBe(true);
    expect(acceptable("Apache-2.0 / MIT")).toBe(true);
    expect(acceptable("MIT OR Apache-2.0 OR LGPL-2.1-or-later")).toBe(true);
  });

  it("needs every part of a conjunction", () => {
    expect(acceptable("(MIT OR Apache-2.0) AND Unicode-3.0")).toBe(true);
    expect(acceptable("ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0)")).toBe(true);
    expect(acceptable("MIT AND GPL-2.0-only")).toBe(false);
    expect(acceptable("MIT AND (GPL-3.0-only OR AGPL-3.0-only)")).toBe(false);
  });

  it("treats an exception as extra permission on an allowed license only", () => {
    expect(acceptable("Apache-2.0 WITH LLVM-exception")).toBe(true);
    expect(acceptable("GPL-2.0-only WITH Classpath-exception-2.0")).toBe(false);
  });

  it("refuses strong copyleft, source-available, proprietary and unreadable licenses", () => {
    for (const l of ["GPL-3.0-only", "AGPL-3.0-or-later", "LGPL-2.1-only", "SSPL-1.0", "BUSL-1.1", "LicenseRef-Commons-Clause", "SEE LICENSE IN LICENSE.md"]) {
      let ok;
      try {
        ok = acceptable(l);
      } catch {
        ok = false;
      }
      expect(ok, l).toBe(false);
    }
    expect(() => acceptable("(MIT")).toThrow();
    expect(() => acceptable("MIT OR")).toThrow();
  });

  it("splits parentheses into their own tokens", () => {
    expect(tokenize("(MIT OR Apache-2.0)AND Zlib")).toEqual(["(", "MIT", "OR", "Apache-2.0", ")", "AND", "Zlib"]);
  });

  it("gives every exception a reason", () => {
    const policy = JSON.parse(readFileSync(new URL("./license-policy.json", import.meta.url), "utf8"));
    // the app has no exception since the website (GSAP) moved to its own repository; any future one needs a reason
    expect(Array.isArray(policy.exceptions)).toBe(true);
    for (const e of policy.exceptions) expect(e.reason.length, e.name).toBeGreaterThan(40);
  });
});
