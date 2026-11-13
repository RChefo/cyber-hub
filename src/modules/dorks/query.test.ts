// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { applyTemplate, buildQuery, buildRow, googleUrl, isValidDate, isValidDomain, quoteValue, type OperatorRow } from "./query";

const row = (kind: OperatorRow["kind"], value: string, extra: Partial<OperatorRow> = {}): OperatorRow => ({ id: "x", kind, value, negate: false, ...extra });

describe("quoteValue", () => {
  it("leaves single words bare", () => expect(quoteValue("admin")).toBe("admin"));
  it("quotes values with spaces and collapses whitespace", () => expect(quoteValue("  index   of ")).toBe('"index of"'));
  it("removes embedded double quotes", () => expect(quoteValue('say "hi" now')).toBe('"say hi now"'));
  it("returns empty for blank or quote-only values", () => {
    expect(quoteValue("   ")).toBe("");
    expect(quoteValue('""')).toBe("");
  });
});

describe("buildRow", () => {
  it("builds simple operators", () => {
    expect(buildRow(row("filetype", "pdf"))).toBe("filetype:pdf");
    expect(buildRow(row("intitle", "index of"))).toBe('intitle:"index of"');
  });
  it("negates supported operators", () => {
    expect(buildRow(row("inurl", "login", { negate: true }))).toBe("-inurl:login");
    expect(buildRow(row("site", "www.example.com", { negate: true }))).toBe("-site:www.example.com");
  });
  it("strips scheme and path from site values", () => expect(buildRow(row("site", "https://a.example.com/path"))).toBe("site:a.example.com"));
  it("validates date operators and ignores negation", () => {
    expect(buildRow(row("after", "2024-01-31"))).toBe("after:2024-01-31");
    expect(buildRow(row("before", "2024-02-30"))).toBe("");
    expect(buildRow(row("before", "2024-02-01", { negate: true }))).toBe("before:2024-02-01");
  });
  it("builds exclude terms", () => {
    expect(buildRow(row("exclude", "test"))).toBe("-test");
    expect(buildRow(row("exclude", "staging server"))).toBe('-"staging server"');
  });
  it("builds OR groups with parentheses", () => {
    expect(buildRow(row("or", "pdf, docx, xlsx", { inner: "filetype" }))).toBe("(filetype:pdf OR filetype:docx OR filetype:xlsx)");
    expect(buildRow(row("or", "login\nsign in", { inner: "term" }))).toBe('(login OR "sign in")');
    expect(buildRow(row("or", "admin", { inner: "inurl" }))).toBe("inurl:admin");
    expect(buildRow(row("or", "a, b", { inner: "intitle", negate: true }))).toBe("-(intitle:a OR intitle:b)");
  });
  it("skips empty rows", () => expect(buildRow(row("intext", "  "))).toBe(""));
});

describe("buildQuery", () => {
  it("combines domain, rows, phrase and keywords", () => {
    const q = buildQuery({
      domain: "example.com",
      keywords: "report  2024",
      phrase: "internal use",
      rows: [row("filetype", "pdf"), row("inurl", "dev", { negate: true })],
    });
    expect(q).toBe('site:example.com filetype:pdf -inurl:dev "internal use" report 2024');
  });
  it("ignores an invalid domain", () => expect(buildQuery({ domain: "not a domain", keywords: "x", phrase: "", rows: [] })).toBe("x"));
  it("quotes single-word phrases", () => expect(buildQuery({ domain: "", keywords: "", phrase: "confidential", rows: [] })).toBe('"confidential"'));
});

describe("helpers", () => {
  it("validates domains", () => {
    expect(isValidDomain("example.com")).toBe(true);
    expect(isValidDomain("*.example.co.uk")).toBe(true);
    expect(isValidDomain("example")).toBe(false);
    expect(isValidDomain("exa mple.com")).toBe(false);
  });
  it("validates dates", () => {
    expect(isValidDate("2024-12-31")).toBe(true);
    expect(isValidDate("2024-13-01")).toBe(false);
  });
  it("substitutes every domain placeholder", () => expect(applyTemplate("site:*.{domain} -site:www.{domain}", "example.com")).toBe("site:*.example.com -site:www.example.com"));
  it("encodes Google URLs", () => expect(googleUrl('site:a.com "x y"')).toBe("https://www.google.com/search?q=site%3Aa.com%20%22x%20y%22"));
});
