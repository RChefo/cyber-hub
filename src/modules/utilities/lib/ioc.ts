// SPDX-License-Identifier: Apache-2.0
/**
 * Indicator-of-compromise extraction, refanging and defanging, entirely local.
 *
 * Refanging follows the conventions handled by common tools (CyberChef "Fang URL", ioc-fanger):
 * `hxxp`, `[.]`, `(.)`, `{.}`, `[dot]`, `[:]`, `[://]`, `[@]`, `[at]`, escaped dots. Defanging
 * writes CyberChef's style: `hxxp`, `[://]`, `[.]`, and `[:]` for IPv6, `[@]` for e-mail.
 */

export type IocKind = "url" | "domain" | "ipv4" | "ipv6" | "email" | "md5" | "sha1" | "sha256" | "sha512" | "cve";

export const IOC_KINDS: { id: IocKind; label: string }[] = [
  { id: "url", label: "URLs" },
  { id: "domain", label: "Domains" },
  { id: "ipv4", label: "IPv4 addresses" },
  { id: "ipv6", label: "IPv6 addresses" },
  { id: "email", label: "E-mail addresses" },
  { id: "md5", label: "MD5" },
  { id: "sha1", label: "SHA-1" },
  { id: "sha256", label: "SHA-256" },
  { id: "sha512", label: "SHA-512" },
  { id: "cve", label: "CVE IDs" },
];

export type IocResult = Record<IocKind, string[]>;

/** Items kept per kind (a pasted log can be huge). */
export const MAX_PER_KIND = 5000;

/**
 * File extensions that look like top-level domains (`report.pdf`, `payload.exe`). Extensions that are
 * also real top-level domains (com, zip, mov, pl, sh, md, rs, py) are not listed: missing a domain
 * is worse than listing a file name.
 */
const FILE_EXTENSIONS = new Set(
  "exe dll sys drv scr bat cmd ps1 psm1 vbs vbe js jse wsf hta msi msp lnk jar class pyc rb bash php asp aspx jsp cgi c h cpp java kt swift txt log csv tsv json xml yaml yml ini cfg conf toml html htm css svg png jpg jpeg gif bmp ico tif tiff webp pdf doc docx docm xls xlsx xlsm ppt pptx pptm rtf odt ods odp rar 7z gz tgz bz2 xz tar iso img dmg apk ipa bin dat tmp bak old db sqlite eml msg pst ost evtx etl pcap pcapng mp3 mp4 avi mkv wav".split(" "),
);

// Patterns shared by extraction and defanging. Every repetition is bounded or anchored by a
// look-behind, so a long run of similar characters is tried once, not at every position (the
// unbounded forms were quadratic: about a second per 40,000 characters).
const URL_RE = /\b(?:https?|ftp):\/\/[^\s<>"'`\]}|]+/gi;
const EMAIL_RE = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,10}[A-Za-z]{2,24}\b/g;
const IPV4_RE = /(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.]*\d)/g;
const IPV6_RE = /(?<![\w:.])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![\w:])/g;
const DOMAIN_RE = /(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,30}[a-z][a-z0-9-]{0,22}[a-z0-9](?![\w-])/gi;
/** One pass for defanging a whole text; the patterns have no capturing groups of their own. */
const DEFANG_RE = new RegExp(`(${URL_RE.source})|(${EMAIL_RE.source})|(${IPV4_RE.source})|(${IPV6_RE.source})|(${DOMAIN_RE.source})`, "gi");

function isFileName(domain: string): boolean {
  return FILE_EXTENSIONS.has(domain.slice(domain.lastIndexOf(".") + 1).toLowerCase());
}

/** Turns defanged indicators back into their usable form. */
export function refang(text: string): string {
  return text
    .replace(/\b[hH][xX]{2}[pP]([sS]?)(?=\s*(?:\[:\/\/\]|\(:\/\/\)|:\/\/|\[:\]\/\/))/g, (_m, s: string) => `http${s.toLowerCase()}`)
    .replace(/\b[hH][xX]{2}[pP]([sS]?)\b/g, (_m, s: string) => `http${s.toLowerCase()}`)
    .replace(/[[({]\s*:\/\/\s*[\])}]/g, "://")
    .replace(/[[({]\s*:\s*[\])}]\/\//g, "://")
    // bounded spaces: an unbounded leading `\s*` is quadratic on long runs of whitespace
    .replace(/[ \t]{0,3}[[({][ \t]{0,3}(?:\.|dot|,)[ \t]{0,3}[\])}][ \t]{0,3}/gi, ".")
    .replace(/[ \t]{0,3}[[({][ \t]{0,3}(?:@|at)[ \t]{0,3}[\])}][ \t]{0,3}/gi, "@")
    .replace(/[[({]:[\])}]/g, ":")
    .replace(/\\\./g, ".");
}

/** The defanged (safe to paste) form of one indicator. */
export function defang(value: string, kind: IocKind): string {
  switch (kind) {
    case "url":
      return value.replace(/^http/i, (m) => (m[0] === "H" ? "HXXP" : "hxxp")).replace("://", "[://]").replace(/\./g, "[.]");
    case "domain":
    case "ipv4":
      return value.replace(/\./g, "[.]");
    case "ipv6":
      return value.replace(/:/g, "[:]");
    case "email":
      return value.replace("@", "[@]").replace(/\./g, "[.]");
    default:
      return value;
  }
}

function push(list: string[], seen: Set<string>, value: string) {
  const key = value.toLowerCase();
  if (!seen.has(key) && list.length < MAX_PER_KIND) {
    seen.add(key);
    list.push(value);
  }
}

/** Trailing characters that end a sentence rather than a URL. */
function trimUrl(u: string): string {
  // linear loops, not regular expressions or repeated counts (those are quadratic on long runs)
  let end = u.length;
  while (end > 0 && ".,;:!?'\"".includes(u[end - 1])) end--;
  let open = 0;
  let close = 0;
  for (let i = 0; i < end; i++) {
    if (u[i] === "(") open++;
    else if (u[i] === ")") close++;
  }
  // a closing parenthesis without an opening one belongs to the text
  while (end > 0 && u[end - 1] === ")" && open < close) {
    end--;
    close--;
  }
  return u.slice(0, end);
}

function isIpv6(candidate: string): boolean {
  if (!candidate.includes("::") && candidate.split(":").length !== 8) return false;
  if ((candidate.match(/::/g)?.length ?? 0) > 1) return false;
  try {
    return new URL(`http://[${candidate}]/`).hostname.length > 2;
  } catch {
    return false;
  }
}

/** Finds indicators in free text (refanged first). Each list keeps the first occurrence order, without duplicates. */
export function extractIocs(input: string): IocResult {
  const text = refang(input);
  const out = Object.fromEntries(IOC_KINDS.map((k) => [k.id, [] as string[]])) as unknown as IocResult;
  const seen = Object.fromEntries(IOC_KINDS.map((k) => [k.id, new Set<string>()])) as unknown as Record<IocKind, Set<string>>;
  const add = (kind: IocKind, v: string) => push(out[kind], seen[kind], v);

  for (const m of text.matchAll(URL_RE)) {
    const u = trimUrl(m[0]);
    if (u.length > 10) add("url", u);
  }
  for (const m of text.matchAll(EMAIL_RE)) add("email", m[0]);
  for (const m of text.matchAll(IPV4_RE)) add("ipv4", m[0]);
  for (const m of text.matchAll(IPV6_RE)) {
    if (isIpv6(m[0])) add("ipv6", m[0].toLowerCase());
  }
  for (const m of text.matchAll(DOMAIN_RE)) {
    const d = m[0].toLowerCase();
    if (!isFileName(d)) add("domain", d);
  }
  // hosts of URLs and e-mail addresses are domains too
  for (const u of out.url) {
    try {
      const h = new URL(u).hostname.toLowerCase();
      if (/[a-z]/.test(h.slice(h.lastIndexOf(".") + 1)) && !h.startsWith("[")) add("domain", h);
    } catch {
      /* not a URL the parser accepts */
    }
  }
  for (const e of out.email) add("domain", e.slice(e.indexOf("@") + 1).toLowerCase());
  for (const [kind, len] of [["md5", 32], ["sha1", 40], ["sha256", 64], ["sha512", 128]] as const) {
    for (const m of text.matchAll(new RegExp(`(?<![A-Fa-f0-9])[A-Fa-f0-9]{${len}}(?![A-Fa-f0-9])`, "g"))) add(kind, m[0].toLowerCase());
  }
  for (const m of text.matchAll(/\bCVE-\d{4}-\d{4,7}\b/gi)) add("cve", m[0].toUpperCase());
  return out;
}

/** Number of indicators found. */
export function iocCount(r: IocResult): number {
  return IOC_KINDS.reduce((n, k) => n + r[k.id].length, 0);
}

/** The text with every URL, e-mail address, IP address and domain in it defanged. */
export function defangText(text: string): string {
  return refang(text).replace(DEFANG_RE, (m: string, url?: string, email?: string, ipv4?: string, ipv6?: string, domain?: string) => {
    if (url) {
      const kept = trimUrl(url);
      return defang(kept, "url") + url.slice(kept.length);
    }
    if (email) return defang(email, "email");
    if (ipv4) return defang(ipv4, "ipv4");
    if (ipv6) return isIpv6(ipv6) ? defang(ipv6, "ipv6") : m;
    if (domain) return isFileName(domain) ? m : defang(domain, "domain");
    return m;
  });
}
