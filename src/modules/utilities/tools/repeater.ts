// SPDX-License-Identifier: Apache-2.0
/**
 * Repeater helpers for the HTTP request builder: raw requests, cURL, response comparison and the
 * session history. Pure functions except the history store. Sending stays in the backend
 * (`http_send`), which checks every request against the project's scope.
 */
import { useSyncExternalStore } from "react";
import type { HttpResponseOut } from "@/lib/types";
import { shellQuote } from "@/lib/utils";

export interface RepeaterRequest {
  method: string;
  url: string;
  headers: [string, string][];
  body: string;
}

const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/**
 * Reads a raw HTTP/1.x request as a proxy shows it: request line, headers, a blank line, the body.
 * The URL comes from an absolute request line, otherwise from `target` (scheme://host[:port]) or the
 * Host header (HTTPS unless `target` says otherwise).
 */
export function parseRawRequest(raw: string, target = ""): RepeaterRequest {
  const text = raw.replace(/^﻿/, "").replace(/^\s*\n/, "");
  const split = text.search(/\r?\n\r?\n/);
  const head = split === -1 ? text : text.slice(0, split);
  const body = split === -1 ? "" : text.slice(split).replace(/^\r?\n\r?\n/, "");
  const lines = head.split(/\r?\n/);
  const requestLine = (lines.shift() ?? "").trim();
  const m = requestLine.match(/^(\S+)\s+(\S+)(?:\s+HTTP\/\d(?:\.\d)?)?$/i);
  if (!m) throw new Error("The first line must be a request line, such as GET /path HTTP/1.1");
  const method = m[1].toUpperCase();
  if (!TOKEN.test(method)) throw new Error(`"${m[1]}" is not a method`);
  const headers: [string, string][] = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    const i = line.indexOf(":");
    if (i <= 0) throw new Error(`Not a header: ${line.slice(0, 80)}`);
    const name = line.slice(0, i).trim();
    if (!TOKEN.test(name)) throw new Error(`"${name.slice(0, 40)}" is not a header name`);
    headers.push([name, line.slice(i + 1).trim()]);
  }
  const path = m[2];
  let url: string;
  if (/^https?:\/\//i.test(path)) {
    url = path;
  } else {
    if (!path.startsWith("/")) throw new Error("The request target must be a path (/…) or an absolute URL");
    const base = target.trim().replace(/\/+$/, "");
    const host = headers.find(([k]) => k.toLowerCase() === "host")?.[1];
    if (base) {
      if (!/^https?:\/\/[^/]+$/i.test(base)) throw new Error("The target must be scheme://host[:port], without a path");
      url = base + path;
    } else if (host) {
      url = `https://${host}${path}`;
    } else {
      throw new Error("Give a target (https://host) or a Host header");
    }
  }
  // the client computes these itself
  const kept = headers.filter(([k]) => !["content-length", "transfer-encoding", "connection"].includes(k.toLowerCase()));
  return { method, url, headers: kept, body };
}

/** The request as raw HTTP/1.1 text (origin-form request line and a Host header). */
export function toRawRequest(r: RepeaterRequest): string {
  let u: URL;
  try {
    u = new URL(r.url);
  } catch {
    return `${r.method} ${r.url} HTTP/1.1\n${r.headers.map(([k, v]) => `${k}: ${v}`).join("\n")}\n\n${r.body}`;
  }
  const headers = r.headers.some(([k]) => k.toLowerCase() === "host") ? r.headers : ([["Host", u.host], ...r.headers] as [string, string][]);
  const lines = [`${r.method} ${u.pathname}${u.search} HTTP/1.1`, ...headers.map(([k, v]) => `${k}: ${v}`)];
  return `${lines.join("\n")}\n\n${r.body}`;
}

/** The target of a raw request built from a URL: scheme://host[:port]. */
export function targetOf(url: string): string {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return "";
  }
}

/** A cURL command for the request, quoted for POSIX shells and PowerShell alike (Mission 7). */
export function toCurl(r: RepeaterRequest, insecure = false): string {
  const parts = ["curl", "-sS", "-i"];
  if (insecure) parts.push("-k");
  if (r.method !== "GET" || r.body) parts.push("-X", r.method);
  for (const [k, v] of r.headers) parts.push("-H", shellQuote(`${k}: ${v}`));
  if (r.body) parts.push("--data-raw", shellQuote(r.body));
  parts.push(shellQuote(r.url));
  return parts.join(" ");
}

/* ───────────── comparison ───────────── */

export type DiffOp = { kind: "same" | "added" | "removed"; text: string } | { kind: "skip"; count: number };

/**
 * Line diff of two texts: common lines at the start and end are matched first, the rest by longest
 * common subsequence (at most `limit` lines on each side; beyond that the rest is shown as
 * replaced). Unchanged stretches longer than 2 × `context` lines are shortened.
 */
export function diffLines(a: string, b: string, context = 2, limit = 800): DiffOp[] {
  const x = a.split(/\r?\n/);
  const y = b.split(/\r?\n/);
  let start = 0;
  while (start < x.length && start < y.length && x[start] === y[start]) start++;
  let endX = x.length;
  let endY = y.length;
  while (endX > start && endY > start && x[endX - 1] === y[endY - 1]) {
    endX--;
    endY--;
  }
  const ops: { kind: "same" | "added" | "removed"; text: string }[] = x.slice(0, start).map((t) => ({ kind: "same", text: t }));
  const mx = x.slice(start, endX);
  const my = y.slice(start, endY);
  if (mx.length > limit || my.length > limit) {
    mx.forEach((t) => ops.push({ kind: "removed", text: t }));
    my.forEach((t) => ops.push({ kind: "added", text: t }));
  } else {
    // LCS lengths of suffixes
    const w = my.length + 1;
    const L = new Uint16Array((mx.length + 1) * w);
    for (let i = mx.length - 1; i >= 0; i--) {
      for (let j = my.length - 1; j >= 0; j--) {
        L[i * w + j] = mx[i] === my[j] ? L[(i + 1) * w + j + 1] + 1 : Math.max(L[(i + 1) * w + j], L[i * w + j + 1]);
      }
    }
    let i = 0;
    let j = 0;
    while (i < mx.length && j < my.length) {
      if (mx[i] === my[j]) {
        ops.push({ kind: "same", text: mx[i] });
        i++;
        j++;
      } else if (L[(i + 1) * w + j] >= L[i * w + j + 1]) {
        ops.push({ kind: "removed", text: mx[i++] });
      } else {
        ops.push({ kind: "added", text: my[j++] });
      }
    }
    while (i < mx.length) ops.push({ kind: "removed", text: mx[i++] });
    while (j < my.length) ops.push({ kind: "added", text: my[j++] });
  }
  x.slice(endX).forEach((t) => ops.push({ kind: "same", text: t }));
  // shorten long unchanged stretches
  const out: DiffOp[] = [];
  let k = 0;
  while (k < ops.length) {
    if (ops[k].kind !== "same") {
      out.push(ops[k++]);
      continue;
    }
    let e = k;
    while (e < ops.length && ops[e].kind === "same") e++;
    const run = ops.slice(k, e);
    const keepHead = k === 0 ? 0 : context;
    const keepTail = e === ops.length ? 0 : context;
    if (run.length > keepHead + keepTail + 1) {
      out.push(...run.slice(0, keepHead), { kind: "skip", count: run.length - keepHead - keepTail }, ...run.slice(run.length - keepTail));
    } else {
      out.push(...run);
    }
    k = e;
  }
  return out;
}

export interface HeaderChange {
  name: string;
  before: string | null;
  after: string | null;
}

/** Headers that differ between two responses (names compared without case). */
export function diffHeaders(a: [string, string][], b: [string, string][]): HeaderChange[] {
  const group = (h: [string, string][]) => {
    const m = new Map<string, { name: string; values: string[] }>();
    for (const [k, v] of h) {
      const e = m.get(k.toLowerCase()) ?? { name: k, values: [] };
      e.values.push(v);
      m.set(k.toLowerCase(), e);
    }
    return m;
  };
  const ga = group(a);
  const gb = group(b);
  const out: HeaderChange[] = [];
  for (const key of [...new Set([...ga.keys(), ...gb.keys()])].sort()) {
    const before = ga.get(key)?.values.join(", ") ?? null;
    const after = gb.get(key)?.values.join(", ") ?? null;
    if (before !== after) out.push({ name: (gb.get(key) ?? ga.get(key))!.name, before, after });
  }
  return out;
}

/* ───────────── session history ───────────── */

export interface HistoryEntry {
  id: number;
  at: string;
  projectId: number;
  request: RepeaterRequest;
  insecure: boolean;
  followRedirects: boolean;
  response: HttpResponseOut | null;
  error: string | null;
}

/** Entries kept per session; bodies are cut to keep memory bounded. */
export const HISTORY_LIMIT = 50;
export const HISTORY_BODY_LIMIT = 256 * 1024;

let entries: HistoryEntry[] = [];
let nextId = 1;
const listeners = new Set<() => void>();
const emit = () => listeners.forEach((l) => l());

export const repeaterHistory = {
  add(e: Omit<HistoryEntry, "id" | "at">): HistoryEntry {
    const response = e.response && e.response.body.length > HISTORY_BODY_LIMIT ? { ...e.response, body: e.response.body.slice(0, HISTORY_BODY_LIMIT), truncated: true } : e.response;
    const entry = { ...e, response, id: nextId++, at: new Date().toISOString() };
    entries = [entry, ...entries].slice(0, HISTORY_LIMIT);
    emit();
    return entry;
  },
  clear() {
    entries = [];
    emit();
  },
  list: () => entries,
  subscribe(l: () => void) {
    listeners.add(l);
    return () => listeners.delete(l);
  },
};

/** The session's requests, newest first. Kept in memory only: requests can carry credentials. */
export function useRepeaterHistory(): HistoryEntry[] {
  return useSyncExternalStore(repeaterHistory.subscribe, repeaterHistory.list, repeaterHistory.list);
}
