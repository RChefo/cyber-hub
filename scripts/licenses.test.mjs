// SPDX-License-Identifier: Apache-2.0
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { PROJECT_LICENSE, acceptable, declaredLicense, exceptionProblems, expectedLicense, leaves, tokenize, verdictOf } from "./licenses.mjs";

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

// Mission 14: the policy sorts every license into a category; unknown and prohibited licenses fail.
describe("license categories", () => {
  const policy = JSON.parse(readFileSync(new URL("./license-policy.json", import.meta.url), "utf8"));

  it("names each identifier once, an exception together with its license", () => {
    expect(leaves("(MIT OR Apache-2.0) AND Unicode-3.0")).toEqual(["MIT", "Apache-2.0", "Unicode-3.0"]);
    expect(leaves("Apache-2.0 WITH LLVM-exception OR MIT")).toEqual(["Apache-2.0 WITH LLVM-exception", "MIT"]);
    expect(leaves("GPL-2.0+")).toEqual(["GPL-2.0"]);
  });

  it("allows permissive licenses and names the obligations of the others", () => {
    expect(verdictOf("MIT OR Apache-2.0")).toEqual({ status: "allowed", obligations: [] });
    expect(verdictOf("MIT AND Unicode-3.0")).toEqual({ status: "allowed", obligations: ["attribution"] });
    expect(verdictOf("MPL-2.0")).toEqual({ status: "allowed", obligations: ["source obligations"] });
    expect(verdictOf("Apache-2.0 WITH LLVM-exception")).toMatchObject({ status: "allowed" });
  });

  it("allows data-only licenses for data files, and only there", () => {
    expect(verdictOf("CC-BY-SA-4.0", { data: true })).toEqual({ status: "allowed", obligations: ["data only"] });
    expect(verdictOf("LicenseRef-MITRE-ATTACK-Terms", { data: true }).status).toBe("allowed");
    expect(verdictOf("CC-BY-SA-4.0").status).toBe("review");
    expect(verdictOf("LicenseRef-MITRE-ATTACK-Terms").status).not.toBe("allowed");
  });

  it("sends weak copyleft to a review and refuses strong copyleft and non-open licenses", () => {
    expect(verdictOf("LGPL-2.1-or-later").status).toBe("review");
    expect(verdictOf("MIT OR LGPL-3.0-only").status).toBe("allowed");
    for (const l of ["GPL-3.0-only", "AGPL-3.0-or-later", "SSPL-1.0", "BUSL-1.1", "LicenseRef-Commons-Clause", "UNLICENSED", "MIT AND GPL-2.0-only"]) {
      expect(verdictOf(l).status, l).toBe("prohibited");
    }
  });

  it("fails closed on missing, unreadable and unknown licenses", () => {
    // (deprecated identifiers such as GPL-2.0 are not in the policy: unknown, which fails like prohibited)
    for (const l of ["", "   ", undefined, "(MIT", "MIT OR", "SEE LICENSE IN LICENSE.md", "WTFPL", "MIT AND Foo-1.0", "GPL-2.0-only WITH Classpath-exception-2.0 OR Bar", "GPL-2.0+"]) {
      expect(verdictOf(l).status, String(l)).toBe("unknown");
    }
    expect(verdictOf("GPL-2.0-only WITH Classpath-exception-2.0").status).toBe("prohibited");
  });

  it("keeps the categories apart: nothing allowed is also prohibited or needs a review", () => {
    const allowed = [...policy.categories.permissive, ...policy.categories.attribution, ...policy.categories.sourceObligations];
    for (const l of allowed) {
      expect(policy.categories.prohibited, l).not.toContain(l);
      expect(policy.categories.review, l).not.toContain(l);
    }
    for (const l of policy.categories.dataOnly) expect(policy.categories.prohibited, l).not.toContain(l);
    expect(policy.categories.prohibited).toEqual(expect.arrayContaining(["GPL-3.0-only", "AGPL-3.0-only", "SSPL-1.0", "LicenseRef-Commons-Clause"]));
  });

  it("requires an exception to name its license, a reason and review dates that are not past", () => {
    const good = { ecosystem: "npm", name: "x", license: "SEE LICENSE IN x", reason: "Reviewed by hand: the terms allow redistribution in the app.", reviewed: "2026-11-13", reviewBy: "2027-05-13" };
    expect(exceptionProblems(good, "2026-11-13")).toEqual([]);
    expect(exceptionProblems(good, "2027-05-14")).toEqual(["the exception for npm x was due for review on 2027-05-13"]);
    expect(exceptionProblems({ ...good, license: "" }, "2026-11-13")).toHaveLength(1);
    expect(exceptionProblems({ ...good, reason: "ok" }, "2026-11-13")).toHaveLength(1);
    expect(exceptionProblems({ ...good, reviewed: "soon" }, "2026-11-13")).toHaveLength(1);
    expect(exceptionProblems({ ...good, reviewBy: undefined }, "2026-11-13")).toHaveLength(1);
  });
});

// Mission 15: ExploitX is Apache-2.0; every source file says which license it is under.
describe("source file license lines", () => {
  it("reads the identifier from the usual comment forms, after a shebang too", () => {
    expect(declaredLicense("// SPDX-License-Identifier: Apache-2.0\nfn main() {}")).toBe("Apache-2.0");
    expect(declaredLicense("/* SPDX-License-Identifier: Apache-2.0 */\n:root {}")).toBe("Apache-2.0");
    expect(declaredLicense("#!/usr/bin/env bash\n# SPDX-License-Identifier: MIT\nset -e")).toBe("MIT");
    expect(declaredLicense("// Copyright (c) 2023 FIRST.ORG\r\n// SPDX-License-Identifier: BSD-2-Clause\r\n")).toBe("BSD-2-Clause");
    expect(declaredLicense("// a file without one\nexport const x = 1;")).toBeNull();
    expect(declaredLicense(`${"//\n".repeat(10)}// SPDX-License-Identifier: Apache-2.0`)).toBeNull();
  });

  it("expects the project's license, except for copied code and data, which keep theirs", () => {
    expect(PROJECT_LICENSE).toBe("Apache-2.0");
    expect(expectedLicense("src-tauri/src/main.rs")).toBe("Apache-2.0");
    expect(expectedLicense("src/components/vendor/shadcn/chart.tsx")).toBe("MIT");
    expect(expectedLicense("src-tauri/src/cvss/v4_lookup.rs")).toBe("BSD-2-Clause");
    // project assets (icons, brand, favicon) are the project's own, under its license
    expect(expectedLicense("design/brand/build/build.mjs")).toBe("Apache-2.0");
  });
});
