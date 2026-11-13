// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { anchors, links, slug } from "./check-links.mjs";

// The Markdown link check (Mission 12) follows GitHub's heading anchors.
describe("Markdown link check", () => {
  it("makes GitHub's heading anchors", () => {
    expect(slug("Scan import (schema 13)")).toBe("scan-import-schema-13");
    expect(slug("C. CA certificates (Priority A)")).toBe("c-ca-certificates-priority-a");
    expect(slug("`cargo test` and clippy")).toBe("cargo-test-and-clippy");
    expect(slug("Mission 10, continued: the release candidate (2026-11-12)")).toBe("mission-10-continued-the-release-candidate-2026-11-12");
  });

  it("numbers repeated headings and ignores headings in code", () => {
    const a = anchors("# Setup\n\n## Setup\n\n```\n# not a heading\n```\n<a id=\"custom\"></a>\n");
    expect([...a].sort()).toEqual(["custom", "setup", "setup-1"]);
  });

  it("finds links outside code, with titles and reference definitions", () => {
    const l = links('See [a](docs/A.md#x "title") and `[b](no.md)`.\n```\n[c](no.md)\n```\n[ref]: ../B.md\n');
    expect(l.map((x) => x.target)).toEqual(["docs/A.md#x", "../B.md"]);
  });
});
