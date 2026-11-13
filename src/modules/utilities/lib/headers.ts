// SPDX-License-Identifier: Apache-2.0
/** Security header analysis. Pure: input is a list of [name, value] pairs. */

export type CheckLevel = "pass" | "warn" | "fail" | "info";

export interface HeaderCheck {
  id: string;
  title: string;
  level: CheckLevel;
  detail: string;
  value?: string;
}

export type HeaderList = [string, string][];

/** Parse raw header text (optionally starting with an HTTP status line). */
export function parseRawHeaders(raw: string): { status?: string; headers: HeaderList } {
  const lines = raw.replace(/\r/g, "").split("\n");
  let status: string | undefined;
  const headers: HeaderList = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    if (/^HTTP\/[\d.]+\s+\d{3}/i.test(line)) {
      status = line.trim();
      continue;
    }
    if (/^\s/.test(line) && headers.length) {
      headers[headers.length - 1][1] += ` ${line.trim()}`;
      continue;
    }
    const idx = line.indexOf(":");
    if (idx <= 0) continue;
    headers.push([line.slice(0, idx).trim().toLowerCase(), line.slice(idx + 1).trim()]);
  }
  return { status, headers };
}

const get = (h: HeaderList, name: string) => h.filter(([k]) => k.toLowerCase() === name).map(([, v]) => v);

/** Script directives whose sources decide what scripts may run (CSP Level 3). */
const SCRIPT_DIRECTIVES = new Set(["default-src", "script-src", "script-src-elem", "script-src-attr"]);

/**
 * Whether a script directive (or default-src) allows any origin (`*`), a whole scheme (`http:`,
 * `https:`) or `data:` URLs. Each directive is read once, so the time is linear in the policy's
 * length: a regex with a backtracking `[^;]*` took seconds on a long policy a server could send.
 */
export function weakScriptSources(csp: string): boolean {
  for (const directive of csp.split(";")) {
    const [name = "", ...sources] = directive.trim().split(/\s+/);
    if (!SCRIPT_DIRECTIVES.has(name.toLowerCase())) continue;
    for (const src of sources) {
      const s = src.toLowerCase();
      if (s === "*" || s === "http:" || s === "https:" || s.startsWith("data:")) return true;
    }
  }
  return false;
}

export function analyzeHeaders(headers: HeaderList, opts: { https?: boolean } = {}): HeaderCheck[] {
  const checks: HeaderCheck[] = [];
  const one = (n: string) => get(headers, n)[0];

  // HSTS
  const hsts = one("strict-transport-security");
  if (!hsts) {
    checks.push({ id: "hsts", title: "Strict-Transport-Security", level: opts.https === false ? "info" : "fail", detail: "Missing. Browsers may connect over plain HTTP and are exposed to downgrade attacks." });
  } else {
    const maxAge = Number(hsts.match(/max-age\s*=\s*"?(\d+)/i)?.[1] ?? NaN);
    const sub = /includesubdomains/i.test(hsts);
    const preload = /preload/i.test(hsts);
    const level: CheckLevel = !Number.isFinite(maxAge) || maxAge === 0 ? "fail" : maxAge < 15552000 ? "warn" : "pass";
    checks.push({
      id: "hsts",
      title: "Strict-Transport-Security",
      level,
      value: hsts,
      detail: `max-age ${Number.isFinite(maxAge) ? `${Math.round(maxAge / 86400)} days` : "missing"}${maxAge < 15552000 ? " (recommend at least 180 days)" : ""}; includeSubDomains ${sub ? "set" : "not set"}; preload ${preload ? "set" : "not set"}.`,
    });
  }

  // CSP
  const csp = one("content-security-policy");
  const cspRo = one("content-security-policy-report-only");
  if (!csp) {
    checks.push({ id: "csp", title: "Content-Security-Policy", level: cspRo ? "warn" : "fail", value: cspRo, detail: cspRo ? "Only a report-only policy is set; nothing is enforced." : "Missing. No defense-in-depth against XSS and injected content." });
  } else {
    const issues: string[] = [];
    if (/'unsafe-inline'/i.test(csp) && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/i.test(csp)) issues.push("'unsafe-inline' without nonces or hashes");
    if (/'unsafe-eval'/i.test(csp)) issues.push("'unsafe-eval' allows eval()");
    if (weakScriptSources(csp)) issues.push("script sources allow wildcard, scheme-only or data: origins");
    if (!/default-src|script-src/i.test(csp)) issues.push("no default-src or script-src");
    if (!/object-src\s+'none'/i.test(csp) && !/default-src\s+'none'/i.test(csp)) issues.push("object-src is not 'none'");
    checks.push({ id: "csp", title: "Content-Security-Policy", level: issues.length ? "warn" : "pass", value: csp, detail: issues.length ? `Weaknesses: ${issues.join("; ")}.` : "Present with no common weaknesses detected." });
  }

  // X-Content-Type-Options
  const xcto = one("x-content-type-options");
  checks.push({
    id: "xcto",
    title: "X-Content-Type-Options",
    level: xcto?.toLowerCase() === "nosniff" ? "pass" : "fail",
    value: xcto,
    detail: xcto?.toLowerCase() === "nosniff" ? "nosniff prevents MIME-type sniffing." : "Should be 'nosniff' to stop browsers guessing content types.",
  });

  // Framing
  const xfo = one("x-frame-options");
  const fa = csp?.match(/frame-ancestors[^;]*/i)?.[0];
  checks.push({
    id: "framing",
    title: "Clickjacking protection",
    level: fa || /^(deny|sameorigin)$/i.test(xfo ?? "") ? "pass" : "fail",
    value: fa ?? xfo,
    detail: fa ? `CSP ${fa}.` : xfo ? `X-Frame-Options: ${xfo}.` : "Neither X-Frame-Options nor CSP frame-ancestors is set; the page can be framed by any site.",
  });

  // Referrer-Policy
  const rp = one("referrer-policy");
  const weakRp = /unsafe-url|no-referrer-when-downgrade/i.test(rp ?? "");
  checks.push({
    id: "referrer",
    title: "Referrer-Policy",
    level: !rp ? "warn" : weakRp ? "warn" : "pass",
    value: rp,
    detail: !rp ? "Not set; browsers default to strict-origin-when-cross-origin." : weakRp ? "Leaks full URLs to other origins." : "Set to a privacy-preserving value.",
  });

  // Permissions-Policy
  const pp = one("permissions-policy") ?? one("feature-policy");
  checks.push({ id: "permissions", title: "Permissions-Policy", level: pp ? "pass" : "info", value: pp, detail: pp ? "Restricts powerful browser features." : "Not set. Consider disabling unused features (camera, geolocation, …)." });

  // Cross-origin isolation headers
  for (const [id, name, good] of [
    ["coop", "cross-origin-opener-policy", /same-origin/i],
    ["coep", "cross-origin-embedder-policy", /require-corp|credentialless/i],
    ["corp", "cross-origin-resource-policy", /same-origin|same-site/i],
  ] as const) {
    const v = one(name);
    checks.push({
      id,
      title: name.replace(/(^|-)(\w)/g, (_, d: string, c: string) => `${d}${c.toUpperCase()}`),
      level: v && good.test(v) ? "pass" : "info",
      value: v,
      detail: v ? `Set to ${v}.` : "Not set (optional; needed for cross-origin isolation).",
    });
  }

  // Cookies
  for (const cookie of get(headers, "set-cookie")) {
    const name = cookie.split("=")[0].trim();
    const attrs = cookie.toLowerCase();
    const missing: string[] = [];
    if (!/;\s*secure/.test(attrs)) missing.push("Secure");
    if (!/;\s*httponly/.test(attrs)) missing.push("HttpOnly");
    const ss = attrs.match(/;\s*samesite\s*=\s*(\w+)/)?.[1];
    if (!ss) missing.push("SameSite");
    const noneWithoutSecure = ss === "none" && missing.includes("Secure");
    checks.push({
      id: `cookie-${name}`,
      title: `Cookie “${name}”`,
      level: noneWithoutSecure || missing.includes("Secure") ? "fail" : missing.length ? "warn" : "pass",
      value: cookie,
      detail: missing.length ? `Missing ${missing.join(", ")}${noneWithoutSecure ? " (SameSite=None requires Secure)" : ""}.` : `Secure, HttpOnly, SameSite=${ss}.`,
    });
  }

  // Information leakage
  for (const name of ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]) {
    const v = one(name);
    if (v) {
      const versioned = /\d/.test(v);
      checks.push({ id: `leak-${name}`, title: `${name.replace(/(^|-)(\w)/g, (_, d: string, c: string) => `${d}${c.toUpperCase()}`)} disclosure`, level: versioned || name !== "server" ? "warn" : "info", value: v, detail: versioned ? "Reveals software and version, which helps attackers match known vulnerabilities." : "Reveals server software." });
    }
  }

  // CORS
  const acao = one("access-control-allow-origin");
  if (acao) {
    const creds = one("access-control-allow-credentials")?.toLowerCase() === "true";
    checks.push({
      id: "cors",
      title: "CORS",
      level: acao === "*" && creds ? "fail" : acao === "*" ? "warn" : acao === "null" ? "fail" : "pass",
      value: `${acao}${creds ? " (credentials allowed)" : ""}`,
      detail:
        acao === "*" && creds
          ? "Wildcard origin with credentials is invalid and indicates a misconfiguration."
          : acao === "*"
            ? "Any origin may read responses. Acceptable only for truly public resources."
            : acao === "null"
              ? "The null origin can be forged by sandboxed iframes."
              : "Restricted to a specific origin. Verify it is not reflected from the request.",
    });
  }

  return checks;
}
