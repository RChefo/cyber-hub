import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${units[i]}`;
}

export function formatNumber(n: number): string {
  return new Intl.NumberFormat().format(n);
}

/** Parses backend RFC3339 timestamps (UTC) and NVD timestamps (no zone, UTC). */
export function parseDate(value: string): Date {
  const hasZone = /[zZ]|[+-]\d\d:\d\d$/.test(value);
  return new Date(hasZone ? value : `${value}Z`);
}

export function formatRelative(value: string | null | undefined): string {
  if (!value) return "never";
  const d = parseDate(value);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < -45) {
    // future times (scheduled runs, due dates)
    const ahead = -diff;
    if (ahead < 3600) return `in ${Math.round(ahead / 60)} min`;
    if (ahead < 86400) return `in ${Math.round(ahead / 3600)} h`;
    if (ahead < 86400 * 7) return `in ${Math.round(ahead / 86400)} d`;
    return d.toLocaleDateString();
  }
  if (diff < 45) return "just now";
  if (diff < 3600) return `${Math.round(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)} h ago`;
  if (diff < 86400 * 7) return `${Math.round(diff / 86400)} d ago`;
  return d.toLocaleDateString();
}

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  return parseDate(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function formatDate(value: string | null | undefined): string {
  if (!value) return "—";
  return parseDate(value).toLocaleDateString(undefined, { dateStyle: "medium" });
}

export function formatDuration(totalSeconds: number): string {
  const d = Math.floor(totalSeconds / 86400);
  const h = Math.floor((totalSeconds % 86400) / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export function pluralize(n: number, one: string, many = `${one}s`): string {
  return `${formatNumber(n)} ${n === 1 ? one : many}`;
}

/** The outcome of clearing the run history, for a notification. */
export function describeRunsCleared(r: { removed: number; kept: number }): string {
  const removed = `${pluralize(r.removed, "finished run")} removed.`;
  return r.kept > 0 ? `${removed} ${pluralize(r.kept, "run")} kept because evidence, findings, OSINT evidence or discovery snapshots refer to ${r.kept === 1 ? "it" : "them"}.` : removed;
}

/** Fills `{name}` (catalog) and `{{name}}` (templates) placeholders. Unfilled ones are kept visible. */
export function fillPlaceholders(template: string, values: Record<string, string>, style: "single" | "double" = "double"): string {
  const re = style === "double" ? /\{\{(\w+)\}\}/g : /\{(\w+)\}/g;
  return template.replace(re, (m, name: string) => {
    const v = values[name];
    return v && v.trim() ? v.trim() : m;
  });
}

export function placeholdersIn(template: string, style: "single" | "double" = "double"): string[] {
  const re = style === "double" ? /\{\{(\w+)\}\}/g : /\{(\w+)\}/g;
  return Array.from(new Set(Array.from(template.matchAll(re), (m) => m[1])));
}

/**
 * Quote an argument for a command line that may be pasted into a shell (Mission 7): POSIX shells
 * and PowerShell both read it back as exactly this word and run nothing else. Plain words (ASCII
 * letters, digits and `_ + = : . / -`) stay as they are; anything else is single-quoted, and a
 * quote inside (`'`, or one of the typographic quotes U+2018–U+201B that PowerShell also reads as
 * `'`) is written as `'"q"'`. The backend quotes history lines the same way (`util::shell_word`).
 */
export function shellQuote(arg: string): string {
  if (/^[A-Za-z0-9_+=:./-]+$/.test(arg)) return arg;
  // a word with a quote and nothing else special in double quotes: POSIX shells and PowerShell
  // both read it back exactly (Mission 8; the same rule as the backend's `shell_word`)
  if (/['\u2018-\u201B]/.test(arg) && !/[$`"\\!\u201C-\u201E]/.test(arg)) return `"${arg}"`;
  return `'${arg.replace(/['\u2018-\u201B]/g, (q) => `'"${q}"'`)}'`;
}

/**
 * Split a command line into argv (supports single/double quotes and backslash escapes
 * inside double quotes). Used only to turn an edited preview into structured args —
 * nothing here is ever passed to a shell.
 */
export function splitArgs(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: '"' | "'" | null = null;
  let has = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote) {
      if (c === quote) quote = null;
      else if (c === "\\" && quote === '"' && (line[i + 1] === '"' || line[i + 1] === "\\")) cur += line[++i];
      else cur += c;
    } else if (c === '"' || c === "'") {
      quote = c;
      has = true;
    } else if (/\s/.test(c)) {
      if (has || cur) out.push(cur);
      cur = "";
      has = false;
    } else {
      cur += c;
      has = true;
    }
  }
  if (quote) throw new Error("Unterminated quote in command");
  if (has || cur) out.push(cur);
  return out;
}

export function debounce<A extends unknown[]>(fn: (...args: A) => void, ms: number) {
  let t: ReturnType<typeof setTimeout> | undefined;
  return (...args: A) => {
    clearTimeout(t);
    t = setTimeout(() => fn(...args), ms);
  };
}

export const isMac = typeof navigator !== "undefined" && /Mac/i.test(navigator.platform || navigator.userAgent);
export const modKey = isMac ? "⌘" : "Ctrl";
