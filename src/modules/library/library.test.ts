import { describe, expect, it } from "vitest";
import type { FindingTemplate } from "@/lib/types";
import { applyTemplate, lines, matchesTemplate, ruleProblem, templateFromFinding } from "./library";

const template: FindingTemplate = {
  id: 1,
  title: "SQL injection",
  severity: "high",
  category: "Injection",
  description: "Vetted description",
  remediation: "",
  references: ["https://owasp.org/sqli", "https://cwe.mitre.org/89"],
  tags: ["web"],
  rules: ["zap:40018"],
  useCount: 3,
  createdAt: "",
  updatedAt: "",
};

const finding = {
  title: "sqli in q",
  severity: "medium" as const,
  category: "",
  description: "",
  remediation: "Use parameters",
  evidence: [{ label: "Request", reference: "req.txt" }, { label: "Reference", reference: "https://owasp.org/sqli" }],
  tags: ["quick-win", "web"],
  affectedTarget: "https://app.example.com/search",
};

describe("finding library helpers", () => {
  it("validates import rules like the backend", () => {
    expect(ruleProblem("nessus:57582")).toBeNull();
    expect(ruleProblem("ZAP:10038")).toBeNull();
    expect(ruleProblem("qualys:1")).toContain("not an import format");
    expect(ruleProblem("nessus")).toContain("format:rule");
    expect(ruleProblem("nessus:a b")).toContain("without spaces");
    expect(lines(" a \n\n b\r\n")).toEqual(["a", "b"]);
  });

  it("searches titles, categories, tags and rules", () => {
    expect(matchesTemplate(template, "40018")).toBe(true);
    expect(matchesTemplate(template, "inject")).toBe(true);
    expect(matchesTemplate(template, "xss")).toBe(false);
    expect(matchesTemplate(template, "  ")).toBe(true);
  });

  it("applies a template without losing the finding's own details", () => {
    const f = applyTemplate(finding, template);
    expect(f.title).toBe("SQL injection");
    expect(f.severity).toBe("high");
    expect(f.description).toBe("Vetted description");
    // an empty template field keeps the finding's text
    expect(f.remediation).toBe("Use parameters");
    expect(f.affectedTarget).toBe("https://app.example.com/search");
    expect(f.evidence.map((e) => e.reference)).toEqual(["req.txt", "https://owasp.org/sqli", "https://cwe.mitre.org/89"]);
    expect(f.tags).toEqual(["quick-win", "web"]);
  });

  it("makes a template from a finding with only URL references", () => {
    const t = templateFromFinding(finding);
    expect(t.references).toEqual(["https://owasp.org/sqli"]);
    expect(t.rules).toEqual([]);
    expect(t.title).toBe("sqli in q");
  });
});
