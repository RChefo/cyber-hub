// SPDX-License-Identifier: Apache-2.0
/**
 * Pure query builder for Dorks Studio. No I/O — fully unit tested in query.test.ts.
 */

export type OperatorKind = "site" | "filetype" | "inurl" | "intitle" | "intext" | "before" | "after" | "exclude" | "or";
export type OrInner = "term" | "site" | "filetype" | "inurl" | "intitle" | "intext";

export interface OperatorRow {
  id: string;
  kind: OperatorKind;
  value: string;
  negate: boolean;
  /** only for kind "or": operator applied to every value in the group */
  inner?: OrInner;
}

export interface DorkState {
  domain: string;
  keywords: string;
  phrase: string;
  rows: OperatorRow[];
}

export const EMPTY_STATE: DorkState = { domain: "", keywords: "", phrase: "", rows: [] };

/** Operators Google accepts with a leading minus. */
export const NEGATABLE: ReadonlySet<OperatorKind> = new Set(["site", "filetype", "inurl", "intitle", "intext", "or"]);

export const OPERATOR_LABELS: Record<OperatorKind, string> = {
  site: "site:",
  filetype: "filetype:",
  inurl: "inurl:",
  intitle: "intitle:",
  intext: "intext:",
  before: "before:",
  after: "after:",
  exclude: "Exclude term (-)",
  or: "OR group ( )",
};

export const FILE_TYPES = ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv", "xml", "json", "log", "sql", "env", "conf", "bak"];

const HOST_RE = /^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/i;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

export function isValidDomain(value: string): boolean {
  const v = value.trim().replace(/\.$/, "");
  return v.length > 0 && v.length <= 253 && HOST_RE.test(v);
}

export function isValidDate(value: string): boolean {
  if (!DATE_RE.test(value)) return false;
  const d = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value;
}

/**
 * Quote a value for use after an operator or as a term. Google has no escape for a
 * double quote inside a phrase, so embedded double quotes are removed.
 */
export function quoteValue(raw: string): string {
  const v = raw.replace(/"/g, "").trim().replace(/\s+/g, " ");
  if (!v) return "";
  return /\s/.test(v) ? `"${v}"` : v;
}

function splitGroup(value: string): string[] {
  return value
    .split(/[,\n]/)
    .map((v) => v.trim())
    .filter(Boolean);
}

export function buildRow(row: OperatorRow): string {
  const value = row.value.trim();
  if (!value) return "";
  switch (row.kind) {
    case "before":
    case "after":
      return isValidDate(value) ? `${row.kind}:${value}` : "";
    case "exclude": {
      const q = quoteValue(value);
      return q ? `-${q}` : "";
    }
    case "or": {
      const inner = row.inner ?? "term";
      const parts = splitGroup(value)
        .map((v) => {
          const q = quoteValue(v);
          if (!q) return "";
          return inner === "term" ? q : `${inner}:${q}`;
        })
        .filter(Boolean);
      if (!parts.length) return "";
      const body = parts.length > 1 ? `(${parts.join(" OR ")})` : parts[0];
      return row.negate ? `-${body}` : body;
    }
    default: {
      const q = quoteValue(row.kind === "site" ? value.replace(/^https?:\/\//i, "").replace(/\/.*$/, "") : value);
      if (!q) return "";
      return `${row.negate ? "-" : ""}${row.kind}:${q}`;
    }
  }
}

export function buildQuery(state: DorkState): string {
  const parts: string[] = [];
  const domain = state.domain.trim().replace(/\.$/, "");
  if (domain && isValidDomain(domain)) parts.push(`site:${domain}`);
  for (const row of state.rows) {
    const r = buildRow(row);
    if (r) parts.push(r);
  }
  const phrase = quoteValue(state.phrase);
  if (phrase) parts.push(phrase.startsWith('"') ? phrase : `"${phrase}"`);
  const keywords = state.keywords.trim().replace(/\s+/g, " ");
  if (keywords) parts.push(keywords);
  return parts.join(" ");
}

export function applyTemplate(template: string, domain: string): string {
  return template.split("{domain}").join(domain.trim().replace(/\.$/, ""));
}

export function googleUrl(query: string): string {
  return `https://www.google.com/search?q=${encodeURIComponent(query)}`;
}
