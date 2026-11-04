/**
 * Declarative command builders. Each builder turns form values into a structured
 * argv (never a shell string) plus the explicit targets that the backend checks
 * against the project scope. The preview string is derived from argv for display/copy.
 */

export type FieldType = "text" | "select" | "switch" | "number";

export interface BuilderField {
  name: string;
  label: string;
  type: FieldType;
  placeholder?: string;
  description?: string;
  options?: { id: string; label: string }[];
  default?: string | boolean;
  required?: boolean;
  mono?: boolean;
  /** this field holds a network target that must be scope-checked */
  target?: boolean;
}

export type Values = Record<string, string | boolean>;

export interface BuildResult {
  args: string[];
  targets: string[];
  errors: string[];
}

export interface BuilderDef {
  id: string;
  toolId: string;
  name: string;
  description: string;
  fields: BuilderField[];
  build: (v: Values) => BuildResult;
}

const s = (v: Values, k: string) => (typeof v[k] === "string" ? (v[k] as string).trim() : "");
const b = (v: Values, k: string) => v[k] === true;

function intIn(v: Values, k: string, label: string, min: number, max: number, errors: string[]): string | null {
  const raw = s(v, k);
  if (!raw) return null;
  if (!/^\d+$/.test(raw) || Number(raw) < min || Number(raw) > max) {
    errors.push(`${label} must be a whole number between ${min} and ${max}`);
    return null;
  }
  return raw;
}

const PORTS_RE = /^(-|(\d{1,5}(-\d{1,5})?)(,(\d{1,5}(-\d{1,5})?))*)$/;
const URL_RE = /^https?:\/\/[^\s]+$/i;
const HOST_RE = /^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,62}$/i;

function requireUrl(v: Values, k: string, errors: string[], mustContainFuzz = false): string {
  const u = s(v, k);
  if (!u) errors.push("A target URL is required");
  else if (!URL_RE.test(u)) errors.push("Target URL must start with http:// or https://");
  else if (mustContainFuzz && !u.includes("FUZZ")) errors.push("The URL must contain the FUZZ keyword where values are injected");
  return u;
}

function requireDomain(v: Values, k: string, errors: string[]): string {
  const d = s(v, k).toLowerCase();
  if (!d) errors.push("A domain is required");
  else if (!HOST_RE.test(d)) errors.push("Enter a valid domain such as example.com");
  return d;
}

function hostOf(url: string): string[] {
  try {
    return [new URL(url.replace("FUZZ", "fuzz")).hostname];
  } catch {
    return [];
  }
}

/* ─────────────── Nmap ─────────────── */

const nmap: BuilderDef = {
  id: "nmap",
  toolId: "nmap",
  name: "Nmap",
  description: "Network discovery and port/service scanning.",
  fields: [
    { name: "target", label: "Targets", type: "text", placeholder: "10.0.0.5 10.0.0.0/24 host.example.com", required: true, mono: true, target: true, description: "Space-separated hosts, IPs or CIDR ranges." },
    {
      name: "scan",
      label: "Scan type",
      type: "select",
      default: "default",
      options: [
        { id: "default", label: "Default (TCP connect/SYN as permitted)" },
        { id: "sn", label: "Host discovery only (-sn)" },
        { id: "sS", label: "TCP SYN scan (-sS, needs privileges)" },
        { id: "sT", label: "TCP connect scan (-sT)" },
        { id: "sU", label: "UDP scan (-sU, needs privileges)" },
      ],
    },
    { name: "ports", label: "Ports", type: "text", placeholder: "22,80,443 or 1-1024 or - for all", mono: true },
    { name: "top", label: "Top ports", type: "number", placeholder: "100", description: "Scan the N most common ports instead of a list." },
    {
      name: "timing",
      label: "Timing",
      type: "select",
      default: "T3",
      options: [
        { id: "T2", label: "T2 polite" },
        { id: "T3", label: "T3 normal" },
        { id: "T4", label: "T4 aggressive" },
      ],
    },
    { name: "sV", label: "Service/version detection (-sV)", type: "switch", default: true },
    { name: "sC", label: "Default safe scripts (-sC)", type: "switch", default: false },
    { name: "O", label: "OS detection (-O, needs privileges)", type: "switch", default: false },
    { name: "Pn", label: "Skip host discovery (-Pn)", type: "switch", default: false },
    { name: "open", label: "Show only open ports (--open)", type: "switch", default: true },
    {
      name: "output",
      label: "Save normal output to",
      type: "text",
      placeholder: "scan.txt",
      mono: true,
      description: "When run in Cyber Hub, a name without a folder is saved in the work folder inside Cyber Hub's app data. The run output is also kept in Runs.",
    },
  ],
  build(v) {
    const errors: string[] = [];
    const args: string[] = [];
    const targets = s(v, "target").split(/\s+/).filter(Boolean);
    if (!targets.length) errors.push("At least one target is required");
    const scan = s(v, "scan") || "default";
    if (scan !== "default") args.push(`-${scan}`);
    const ports = s(v, "ports");
    const top = intIn(v, "top", "Top ports", 1, 65535, errors);
    if (ports && top) errors.push("Use either a port list or top ports, not both");
    if (scan !== "sn") {
      if (ports) {
        if (!PORTS_RE.test(ports)) errors.push("Ports must be like 22,80,443 or 1-1024 or -");
        else args.push(ports === "-" ? "-p-" : "-p", ...(ports === "-" ? [] : [ports]));
      } else if (top) args.push("--top-ports", top);
      if (b(v, "sV")) args.push("-sV");
      if (b(v, "sC")) args.push("-sC");
      if (b(v, "O")) args.push("-O");
      if (b(v, "open")) args.push("--open");
    }
    if (b(v, "Pn")) args.push("-Pn");
    args.push(`-${s(v, "timing") || "T3"}`);
    const out = s(v, "output");
    if (out) args.push("-oN", out);
    args.push(...targets);
    return { args, targets, errors };
  },
};

/* ─────────────── FFUF ─────────────── */

const ffuf: BuilderDef = {
  id: "ffuf",
  toolId: "ffuf",
  name: "FFUF",
  description: "Web fuzzing for content, parameters and virtual hosts.",
  fields: [
    { name: "url", label: "Target URL", type: "text", placeholder: "https://app.example.com/FUZZ", required: true, mono: true, target: true, description: "Place FUZZ where wordlist values are injected." },
    { name: "wordlist", label: "Wordlist", type: "text", placeholder: "/path/to/wordlist.txt", required: true, mono: true },
    { name: "mc", label: "Match status codes", type: "text", default: "200,204,301,302,307,401,403", mono: true },
    { name: "fs", label: "Filter response size", type: "text", placeholder: "e.g. 4242", mono: true },
    { name: "extensions", label: "Extensions", type: "text", placeholder: ".php,.bak", mono: true },
    { name: "threads", label: "Threads", type: "number", default: "40" },
    { name: "rate", label: "Requests per second", type: "number", placeholder: "unlimited", description: "Rate-limit to stay within agreed testing windows." },
    { name: "recursion", label: "Recursion (-recursion)", type: "switch", default: false },
    { name: "output", label: "Save JSON results to", type: "text", placeholder: "ffuf.json", mono: true },
  ],
  build(v) {
    const errors: string[] = [];
    const url = requireUrl(v, "url", errors, true);
    const wl = s(v, "wordlist");
    if (!wl) errors.push("A wordlist is required");
    const args = ["-u", url, "-w", wl];
    const mc = s(v, "mc");
    if (mc) {
      if (!/^(all|\d{3}(,\d{3})*)$/.test(mc)) errors.push("Status codes must look like 200,301,403");
      else args.push("-mc", mc);
    }
    const fs = s(v, "fs");
    if (fs) {
      if (!/^\d+(,\d+)*$/.test(fs)) errors.push("Filter size must be numbers separated by commas");
      else args.push("-fs", fs);
    }
    const ext = s(v, "extensions");
    if (ext) args.push("-e", ext);
    const t = intIn(v, "threads", "Threads", 1, 200, errors);
    if (t) args.push("-t", t);
    const rate = intIn(v, "rate", "Rate", 1, 10000, errors);
    if (rate) args.push("-rate", rate);
    if (b(v, "recursion")) args.push("-recursion");
    const out = s(v, "output");
    if (out) args.push("-o", out, "-of", "json");
    return { args, targets: hostOf(url), errors };
  },
};

/* ─────────────── Gobuster ─────────────── */

const gobuster: BuilderDef = {
  id: "gobuster",
  toolId: "gobuster",
  name: "Gobuster",
  description: "Directory, DNS and virtual-host enumeration.",
  fields: [
    {
      name: "mode",
      label: "Mode",
      type: "select",
      default: "dir",
      options: [
        { id: "dir", label: "dir — files and directories" },
        { id: "dns", label: "dns — subdomains" },
        { id: "vhost", label: "vhost — virtual hosts" },
      ],
    },
    { name: "url", label: "Target URL (dir / vhost)", type: "text", placeholder: "https://app.example.com", mono: true, target: true },
    { name: "domain", label: "Domain (dns)", type: "text", placeholder: "example.com", mono: true, target: true },
    { name: "wordlist", label: "Wordlist", type: "text", placeholder: "/path/to/wordlist.txt", required: true, mono: true },
    { name: "extensions", label: "Extensions (dir)", type: "text", placeholder: "php,txt,bak", mono: true },
    { name: "threads", label: "Threads", type: "number", default: "10" },
    { name: "statusCodes", label: "Show only these status codes (dir)", type: "text", placeholder: "200,204,301,302,307,401,403", mono: true },
    { name: "quiet", label: "Quiet output (-q)", type: "switch", default: false },
    { name: "output", label: "Save results to", type: "text", placeholder: "gobuster.txt", mono: true },
  ],
  build(v) {
    const errors: string[] = [];
    const mode = s(v, "mode") || "dir";
    const args = [mode];
    let targets: string[] = [];
    if (mode === "dns") {
      const d = requireDomain(v, "domain", errors);
      args.push("-d", d);
      targets = d ? [d] : [];
    } else {
      const url = requireUrl(v, "url", errors);
      args.push("-u", url);
      targets = hostOf(url);
      if (mode === "vhost") args.push("--append-domain");
    }
    const wl = s(v, "wordlist");
    if (!wl) errors.push("A wordlist is required");
    args.push("-w", wl);
    const ext = s(v, "extensions");
    if (ext && mode === "dir") args.push("-x", ext);
    const sc = s(v, "statusCodes");
    if (sc && mode === "dir") {
      if (!/^\d{3}(,\d{3})*$/.test(sc)) errors.push("Status codes must look like 200,301,403");
      else args.push("-s", sc, "-b", "");
    }
    const t = intIn(v, "threads", "Threads", 1, 200, errors);
    if (t) args.push("-t", t);
    if (b(v, "quiet")) args.push("-q");
    const out = s(v, "output");
    if (out) args.push("-o", out);
    return { args, targets, errors };
  },
};

/* ─────────────── Nuclei ─────────────── */

const nuclei: BuilderDef = {
  id: "nuclei",
  toolId: "nuclei",
  name: "Nuclei",
  description: "Template-based vulnerability scanning.",
  fields: [
    { name: "url", label: "Target URL", type: "text", placeholder: "https://app.example.com", required: true, mono: true, target: true },
    { name: "severity", label: "Severities", type: "text", default: "critical,high,medium", mono: true },
    { name: "tags", label: "Template tags", type: "text", placeholder: "cve,misconfig", mono: true },
    { name: "exclude", label: "Exclude tags", type: "text", default: "dos,fuzz", mono: true, description: "Denial-of-service and fuzzing templates are excluded by default." },
    { name: "rate", label: "Rate limit (requests/second)", type: "number", default: "50" },
    { name: "concurrency", label: "Template concurrency", type: "number", default: "10" },
    { name: "noUpdate", label: "Skip update check (-duc)", type: "switch", default: true },
    { name: "jsonl", label: "JSON lines output (-jsonl)", type: "switch", default: false },
    { name: "output", label: "Save results to", type: "text", placeholder: "nuclei.txt", mono: true },
  ],
  build(v) {
    const errors: string[] = [];
    const url = requireUrl(v, "url", errors);
    const args = ["-u", url];
    const sev = s(v, "severity");
    if (sev) {
      if (!/^(info|low|medium|high|critical|unknown)(,(info|low|medium|high|critical|unknown))*$/.test(sev)) errors.push("Severities: info, low, medium, high, critical");
      else args.push("-severity", sev);
    }
    const tags = s(v, "tags");
    if (tags) args.push("-tags", tags);
    const ex = s(v, "exclude");
    if (ex) args.push("-etags", ex);
    const rl = intIn(v, "rate", "Rate limit", 1, 1000, errors);
    if (rl) args.push("-rl", rl);
    const c = intIn(v, "concurrency", "Concurrency", 1, 100, errors);
    if (c) args.push("-c", c);
    if (b(v, "noUpdate")) args.push("-duc");
    if (b(v, "jsonl")) args.push("-jsonl");
    const out = s(v, "output");
    if (out) args.push("-o", out);
    return { args, targets: hostOf(url), errors };
  },
};

/* ─────────────── SQLmap ─────────────── */

const sqlmap: BuilderDef = {
  id: "sqlmap",
  toolId: "sqlmap",
  name: "SQLmap",
  description: "SQL injection detection on a single request.",
  fields: [
    { name: "url", label: "Target URL with parameters", type: "text", placeholder: "https://app.example.com/item?id=1", required: true, mono: true, target: true },
    { name: "param", label: "Parameter to test", type: "text", placeholder: "id", mono: true },
    { name: "data", label: "POST body", type: "text", placeholder: "user=a&pass=b", mono: true },
    { name: "cookie", label: "Cookie header", type: "text", placeholder: "session=…", mono: true },
    {
      name: "level",
      label: "Level",
      type: "select",
      default: "1",
      options: ["1", "2", "3", "4", "5"].map((x) => ({ id: x, label: `Level ${x}${x === "1" ? " (default)" : ""}` })),
    },
    {
      name: "risk",
      label: "Risk",
      type: "select",
      default: "1",
      options: [
        { id: "1", label: "Risk 1 (default, safe)" },
        { id: "2", label: "Risk 2 (adds heavy time-based tests)" },
        { id: "3", label: "Risk 3 (may modify data — avoid on production)" },
      ],
    },
    { name: "batch", label: "Non-interactive (--batch)", type: "switch", default: true },
    { name: "banner", label: "Retrieve DBMS banner (--banner)", type: "switch", default: false },
  ],
  build(v) {
    const errors: string[] = [];
    const url = requireUrl(v, "url", errors);
    const args = ["-u", url];
    const p = s(v, "param");
    if (p) {
      if (!/^[\w.[\]-]+(,[\w.[\]-]+)*$/.test(p)) errors.push("Parameter names may contain letters, digits, _ . - [ ]");
      else args.push("-p", p);
    }
    const data = s(v, "data");
    if (data) args.push(`--data=${data}`);
    const cookie = s(v, "cookie");
    if (cookie) args.push(`--cookie=${cookie}`);
    args.push(`--level=${s(v, "level") || "1"}`, `--risk=${s(v, "risk") || "1"}`);
    if (b(v, "batch")) args.push("--batch");
    if (b(v, "banner")) args.push("--banner");
    return { args, targets: hostOf(url), errors };
  },
};

/* ─────────────── Subfinder ─────────────── */

const subfinder: BuilderDef = {
  id: "subfinder",
  toolId: "subfinder",
  name: "Subfinder",
  description: "Passive subdomain discovery from public sources.",
  fields: [
    { name: "domain", label: "Domain", type: "text", placeholder: "example.com", required: true, mono: true, target: true },
    { name: "all", label: "Use all sources (-all)", type: "switch", default: false },
    { name: "recursive", label: "Recursive sources only (-recursive)", type: "switch", default: false },
    { name: "silent", label: "Only print subdomains (-silent)", type: "switch", default: true },
    { name: "noUpdate", label: "Skip update check (-duc)", type: "switch", default: true },
    { name: "output", label: "Save results to", type: "text", placeholder: "subdomains.txt", mono: true },
  ],
  build(v) {
    const errors: string[] = [];
    const d = requireDomain(v, "domain", errors);
    const args = ["-d", d];
    if (b(v, "all")) args.push("-all");
    if (b(v, "recursive")) args.push("-recursive");
    if (b(v, "silent")) args.push("-silent");
    if (b(v, "noUpdate")) args.push("-duc");
    const out = s(v, "output");
    if (out) args.push("-o", out);
    return { args, targets: d ? [d] : [], errors };
  },
};

/* ─────────────── HTTPX ─────────────── */

const httpx: BuilderDef = {
  id: "httpx",
  toolId: "httpx",
  name: "HTTPX",
  description: "Probe hosts for HTTP services and fingerprint them.",
  fields: [
    { name: "target", label: "Targets", type: "text", placeholder: "app.example.com https://api.example.com", required: true, mono: true, target: true, description: "Space-separated hosts or URLs." },
    { name: "sc", label: "Status code (-sc)", type: "switch", default: true },
    { name: "title", label: "Page title (-title)", type: "switch", default: true },
    { name: "tech", label: "Technology detection (-td)", type: "switch", default: true },
    { name: "ip", label: "Resolved IP (-ip)", type: "switch", default: false },
    { name: "follow", label: "Follow redirects (-fr)", type: "switch", default: false },
    { name: "noUpdate", label: "Skip update check (-duc)", type: "switch", default: true },
    { name: "rate", label: "Rate limit (requests/second)", type: "number", default: "50" },
    { name: "output", label: "Save results to", type: "text", placeholder: "httpx.txt", mono: true },
  ],
  build(v) {
    const errors: string[] = [];
    const targets = s(v, "target").split(/\s+/).filter(Boolean);
    if (!targets.length) errors.push("At least one target is required");
    const args = ["-u", targets.join(",")];
    if (b(v, "sc")) args.push("-sc");
    if (b(v, "title")) args.push("-title");
    if (b(v, "tech")) args.push("-td");
    if (b(v, "ip")) args.push("-ip");
    if (b(v, "follow")) args.push("-fr");
    if (b(v, "noUpdate")) args.push("-duc");
    const rl = intIn(v, "rate", "Rate limit", 1, 1000, errors);
    if (rl) args.push("-rl", rl);
    const out = s(v, "output");
    if (out) args.push("-o", out);
    return { args, targets, errors };
  },
};

export const BUILDERS: BuilderDef[] = [nmap, ffuf, gobuster, nuclei, sqlmap, subfinder, httpx];

export function defaultValues(def: BuilderDef): Values {
  const v: Values = {};
  for (const f of def.fields) v[f.name] = f.default ?? (f.type === "switch" ? false : "");
  return v;
}
