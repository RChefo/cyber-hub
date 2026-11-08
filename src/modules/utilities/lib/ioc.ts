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

/** File extensions that look like top-level domains in `report.pdf`, `payload.exe`, `run.sh`. */
const FILE_EXTENSIONS = new Set(
  "exe dll sys drv scr com bat cmd ps1 psm1 vbs vbe js jse wsf hta msi msp lnk jar class py pyc pl rb sh bash php asp aspx jsp cgi go rs c h cpp cs java kt swift txt log md csv tsv json xml yaml yml ini cfg conf toml html htm css svg png jpg jpeg gif bmp ico tif tiff webp pdf doc docx docm xls xlsx xlsm ppt pptx pptm rtf odt ods odp zip rar 7z gz tgz bz2 xz tar iso img dmg apk ipa bin dat tmp bak old db sqlite eml msg pst ost evtx etl pcap pcapng mp3 mp4 avi mkv mov wav".split(" "),
);

/** Turns defanged indicators back into their usable form. */
export function refang(text: string): string {
  return text
    .replace(/\b[hH][xX]{2}[pP]([sS]?)(?=\s*(?:\[:\/\/\]|\(:\/\/\)|:\/\/|\[:\]\/\/))/g, (_m, s: string) => `http${s.toLowerCase()}`)
    .replace(/\b[hH][xX]{2}[pP]([sS]?)\b/g, (_m, s: string) => `http${s.toLowerCase()}`)
    .replace(/[[({]\s*:\/\/\s*[\])}]/g, "://")
    .replace(/[[({]\s*:\s*[\])}]\/\//g, "://")
    .replace(/\s*[[({]\s*(?:\.|dot|,)\s*[\])}]\s*/gi, ".")
    .replace(/\s*[[({]\s*(?:@|at)\s*[\])}]\s*/gi, "@")
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
  let out = u.replace(/[.,;:!?'"]+$/, "");
  // a closing parenthesis without an opening one belongs to the text
  while (out.endsWith(")") && (out.match(/\(/g)?.length ?? 0) < (out.match(/\)/g)?.length ?? 0)) out = out.slice(0, -1);
  return out;
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

  for (const m of text.matchAll(/\b(?:https?|ftp):\/\/[^\s<>"'`\]}|]+/gi)) {
    const u = trimUrl(m[0]);
    if (u.length > 10) add("url", u);
  }
  for (const m of text.matchAll(/\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b/g)) add("email", m[0]);
  for (const m of text.matchAll(/(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\d.]*\d)/g)) add("ipv4", m[0]);
  for (const m of text.matchAll(/(?<![\w:.])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![\w:])/g)) {
    if (isIpv6(m[0])) add("ipv6", m[0].toLowerCase());
  }
  for (const m of text.matchAll(/(?<![\w@.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,22}[a-z0-9](?![\w-])/gi)) {
    const d = m[0].toLowerCase();
    const tld = d.slice(d.lastIndexOf(".") + 1);
    if (!FILE_EXTENSIONS.has(tld)) add("domain", d);
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

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** The text with every URL, e-mail address, IP address and domain in it defanged. */
export function defangText(text: string): string {
  const r = extractIocs(text);
  let out = refang(text);
  for (const kind of ["url", "email", "ipv6", "ipv4", "domain"] as const) {
    for (const v of [...r[kind]].sort((a, b) => b.length - a.length)) {
      out = out.replace(new RegExp(`(?<![\\w[])${escapeRegExp(v)}(?![\\w\\]])`, "gi"), (m) => defang(m, kind));
    }
  }
  return out;
}
