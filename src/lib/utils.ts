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

/** Quote an argument for display in a POSIX-like shell preview. */
export function shellQuote(arg: string): string {
  if (arg === "") return "''";
  if (/^[\w@%+=:,./-]+$/.test(arg)) return arg;
  return `'${arg.replace(/'/g, `'"'"'`)}'`;
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
