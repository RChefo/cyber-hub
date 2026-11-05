import { describe, expect, it } from "vitest";
import { parseInline, parseNotes, sections } from "./notes";

describe("release notes", () => {
  it("keeps markup as text and only links https URLs", () => {
    expect(parseInline("<script>alert(1)</script> and [x](javascript:alert(1))")).toEqual([{ t: "text", v: "<script>alert(1)</script> and [x](javascript:alert(1))" }]);
    expect(parseInline("Use `nmap -sV` **now**, see [docs](https://example.com/a)")).toEqual([
      { t: "text", v: "Use " },
      { t: "code", v: "nmap -sV" },
      { t: "text", v: " " },
      { t: "strong", v: "now" },
      { t: "text", v: ", see " },
      { t: "link", v: "docs", href: "https://example.com/a" },
    ]);
  });

  it("groups notes by the author's own headings", () => {
    const s = sections(parseNotes("Intro line\n\n## New features\n- One\n- Two\n\n## Bug fixes\n* Fixed\n\n## Security\nText"));
    expect(s.map((x) => x.title)).toEqual([null, "New features", "Bug fixes", "Security"]);
    expect(s[1].blocks).toEqual([{ t: "list", items: [[{ t: "text", v: "One" }], [{ t: "text", v: "Two" }]] }]);
    expect(sections(parseNotes(""))).toEqual([]);
  });
});
