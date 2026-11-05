// The one release data model of the website. Everything release-related (landing-page changelog
// preview, /changelog, /download recommendations and verification, /download/archive) reads it
// through the shared store in releaseStore.ts, so GitHub is asked once per page load.
//
// Source: GET /repos/<owner>/<repo>/releases (GitHub REST API), the same releases the desktop
// updater reads latest.json from. The API never returns drafts to anonymous visitors, and the
// parser drops them anyway.
import { parseNotes, sections, type Block, type Inline } from "./notes";

export type Os = "windows" | "linux";
export type Arch = "x64";
export type Format = "nsis" | "msi" | "appimage" | "deb" | "rpm";
export type Channel = "stable" | "prerelease";

/** Package name patterns written by `tauri build`. Kept in step with ARTIFACTS in
 *  scripts/updater-manifest.mjs (a test compares both). */
export const ARTIFACT_PATTERNS: { format: Format; os: Os; re: RegExp }[] = [
  { format: "nsis", os: "windows", re: /_x64-setup\.exe$/ },
  { format: "msi", os: "windows", re: /_x64_[A-Za-z-]+\.msi$/ },
  { format: "appimage", os: "linux", re: /_amd64\.AppImage$/ },
  { format: "deb", os: "linux", re: /_amd64\.deb$/ },
  { format: "rpm", os: "linux", re: /\.x86_64\.rpm$/ },
];

export const FORMATS_BY_OS: Record<Os, Format[]> = { windows: ["nsis", "msi"], linux: ["appimage", "deb", "rpm"] };
export const OS_LABEL: Record<Os, string> = { windows: "Windows", linux: "Linux" };

export const FORMAT_LABEL: Record<Format, string> = {
  nsis: "Installer (.exe)",
  msi: "MSI package",
  appimage: "AppImage",
  deb: "Debian / Ubuntu (.deb)",
  rpm: "Fedora / RHEL / openSUSE (.rpm)",
};

/** One line on when to pick each package. */
export const FORMAT_HINT: Record<Format, string> = {
  nsis: "Recommended. Installs for your user account, no administrator rights needed.",
  msi: "Installs for all users of the computer. Needs administrator approval; suits managed deployment.",
  appimage: "A single portable file for most distributions. Runs without installing; needs a writable folder to update itself.",
  deb: "For Debian, Ubuntu and derivatives. Installs dependencies through apt.",
  rpm: "For Fedora, RHEL, openSUSE and derivatives. Installs dependencies through dnf or zypper.",
};

export interface ReleaseAsset {
  name: string;
  os: Os;
  arch: Arch;
  format: Format;
  downloadUrl: string;
  size: number;
  /** lower-case hex SHA-256 from GitHub's asset digest, null when not provided or malformed */
  sha256: string | null;
  /** the asset's `.sig` file (Tauri updater signature), when it was published */
  signatureUrl: string | null;
}

export interface Release {
  version: string;
  tag: string;
  name: string;
  publishedAt: string | null;
  notes: string;
  channel: Channel;
  htmlUrl: string;
  assets: ReleaseAsset[];
  /** SHA256SUMS.txt published with the release */
  checksumsUrl: string | null;
  /** the release carries an update manifest (latest.json) */
  hasUpdateManifest: boolean;
}

interface GhAsset {
  name?: unknown;
  browser_download_url?: unknown;
  size?: unknown;
  state?: unknown;
  digest?: unknown;
}
interface GhRelease {
  tag_name?: unknown;
  name?: unknown;
  body?: unknown;
  published_at?: unknown;
  html_url?: unknown;
  draft?: unknown;
  prerelease?: unknown;
  assets?: unknown;
}

const SEMVER_TAG = /^v?((0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?)$/;

/** `sha256:<64 hex>` (GitHub's format) or a bare 64-hex string → lower-case hex, else null. */
export function parseSha256(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const m = /^(?:sha256:)?([0-9a-fA-F]{64})$/.exec(raw.trim());
  return m ? m[1].toLowerCase() : null;
}

/** Turns one GitHub API release into the model, dropping anything that does not validate. */
export function parseRelease(raw: unknown, repository: string): Release | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as GhRelease;
  if (r.draft === true) return null;
  const tag = typeof r.tag_name === "string" ? r.tag_name : "";
  const m = SEMVER_TAG.exec(tag);
  if (!m) return null;
  const version = m[1];
  const downloadPrefix = `https://github.com/${repository}/releases/download/${encodeURIComponent(tag)}/`;
  const raws = Array.isArray(r.assets) ? (r.assets as GhAsset[]) : [];
  const valid = raws.filter(
    (a): a is GhAsset & { name: string; browser_download_url: string } =>
      typeof a.name === "string" &&
      typeof a.browser_download_url === "string" &&
      a.browser_download_url.startsWith(downloadPrefix) &&
      (a.state === undefined || a.state === "uploaded"),
  );
  const byName = new Map(valid.map((a) => [a.name, a]));
  const assets: ReleaseAsset[] = [];
  for (const a of valid) {
    const kind = ARTIFACT_PATTERNS.find((p) => p.re.test(a.name));
    const size = typeof a.size === "number" && a.size > 0 ? a.size : 0;
    if (!kind || !size || assets.some((x) => x.format === kind.format)) continue;
    const sig = byName.get(`${a.name}.sig`);
    assets.push({
      name: a.name,
      os: kind.os,
      arch: "x64",
      format: kind.format,
      downloadUrl: a.browser_download_url,
      size,
      sha256: parseSha256(a.digest),
      signatureUrl: sig ? sig.browser_download_url : null,
    });
  }
  assets.sort((x, y) => ARTIFACT_PATTERNS.findIndex((p) => p.format === x.format) - ARTIFACT_PATTERNS.findIndex((p) => p.format === y.format));
  const releasePage = `https://github.com/${repository}/releases/tag/${encodeURIComponent(tag)}`;
  return {
    version,
    tag,
    name: typeof r.name === "string" && r.name.trim() ? r.name.trim() : `Cyber Hub ${version}`,
    publishedAt: typeof r.published_at === "string" && !Number.isNaN(Date.parse(r.published_at)) ? r.published_at : null,
    notes: typeof r.body === "string" ? r.body.slice(0, 40000) : "",
    // a semver pre-release tag is a pre-release even if the flag was forgotten
    channel: r.prerelease === true || m[5] !== undefined ? "prerelease" : "stable",
    // only the release's own page on GitHub is linked
    htmlUrl: typeof r.html_url === "string" && r.html_url === releasePage ? r.html_url : releasePage,
    assets,
    checksumsUrl: byName.get("SHA256SUMS.txt")?.browser_download_url ?? null,
    hasUpdateManifest: byName.has("latest.json"),
  };
}

/* ─────────────── versions ─────────────── */

function semverParts(v: string) {
  const [core, pre] = v.split("-", 2);
  return { nums: core.split(".").map(Number), pre: pre ? pre.split(".") : [] };
}

/** Semantic-version precedence: -1, 0 or 1. */
export function compareVersions(a: string, b: string): number {
  const x = semverParts(a);
  const y = semverParts(b);
  for (let i = 0; i < 3; i++) if (x.nums[i] !== y.nums[i]) return x.nums[i] > y.nums[i] ? 1 : -1;
  if (!x.pre.length || !y.pre.length) return x.pre.length === y.pre.length ? 0 : x.pre.length ? -1 : 1;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    const p = x.pre[i];
    const q = y.pre[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    if (p === q) continue;
    const pn = /^\d+$/.test(p);
    const qn = /^\d+$/.test(q);
    if (pn && qn) return Number(p) > Number(q) ? 1 : -1;
    if (pn !== qn) return pn ? -1 : 1;
    return p > q ? 1 : -1;
  }
  return 0;
}

/** Newest first; one entry per version. */
export function sortReleases(list: Release[]): Release[] {
  const seen = new Set<string>();
  return [...list]
    .sort((a, b) => compareVersions(b.version, a.version) || (Date.parse(b.publishedAt ?? "") || 0) - (Date.parse(a.publishedAt ?? "") || 0))
    .filter((r) => (seen.has(r.version) ? false : (seen.add(r.version), true)));
}

/** The newest stable release, as the updater would offer it. */
export function latestStable(list: Release[]): Release | null {
  return sortReleases(list).find((r) => r.channel === "stable") ?? null;
}

/* ─────────────── changelog ─────────────── */

export type Category = "features" | "improvements" | "fixes" | "security" | "other";

export const CATEGORY_LABEL: Record<Category, string> = {
  features: "Features",
  improvements: "Improvements",
  fixes: "Fixes",
  security: "Security",
  other: "Other",
};

/** Maps the release author's own section heading to a category (nothing is guessed from item text). */
export function categoryOf(heading: string | null): Category {
  const h = (heading ?? "").toLowerCase();
  if (/secur|vulnerab|cve/.test(h)) return "security";
  if (/fix|bug/.test(h)) return "fixes";
  if (/feature|new|added|^add/.test(h)) return "features";
  if (/improv|enhanc|change|update|perform/.test(h)) return "improvements";
  return "other";
}

export interface ChangeGroup {
  category: Category;
  title: string | null;
  items: Inline[][];
  blocks: Block[];
}

export interface Changelog {
  summary: Inline[] | null;
  groups: ChangeGroup[];
}

export function changelogOf(release: Release): Changelog {
  const parts = sections(parseNotes(release.notes));
  let summary: Inline[] | null = null;
  const groups: ChangeGroup[] = [];
  for (const p of parts) {
    if (p.title === null) {
      const para = p.blocks.find((b) => b.t === "para");
      if (para && para.t === "para") summary = para.v;
      const list = p.blocks.find((b) => b.t === "list");
      if (list && list.t === "list") groups.push({ category: "other", title: null, items: list.items, blocks: p.blocks });
      continue;
    }
    const items = p.blocks.flatMap((b) => (b.t === "list" ? b.items : []));
    groups.push({ category: categoryOf(p.title), title: p.title, items, blocks: p.blocks });
  }
  return { summary, groups };
}

/** Up to `max` highlights, taken round-robin from security, features, improvements and fixes. */
export function highlights(log: Changelog, max = 5): { category: Category; item: Inline[] }[] {
  const order: Category[] = ["security", "features", "improvements", "fixes", "other"];
  const queues = order.map((c) => log.groups.filter((g) => g.category === c).flatMap((g) => g.items.map((item) => ({ category: c, item }))));
  const out: { category: Category; item: Inline[] }[] = [];
  while (out.length < max && queues.some((q) => q.length)) for (const q of queues) if (q.length && out.length < max) out.push(q.shift()!);
  return out;
}

/* ─────────────── archive ─────────────── */

export interface ArchiveFilter {
  os: Os | "all";
  channel: Channel | "all";
  query: string;
}

export function filterArchive(list: Release[], f: ArchiveFilter): Release[] {
  const q = f.query.trim().replace(/^v/i, "");
  return sortReleases(list).filter(
    (r) => (f.channel === "all" || r.channel === f.channel) && (f.os === "all" || r.assets.some((a) => a.os === f.os)) && (!q || r.version.startsWith(q) || r.version.includes(q)),
  );
}

/* ─────────────── formatting ─────────────── */

export function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

export function formatDate(iso: string | null): string {
  return iso ? new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" }) : "—";
}

export function platformsOf(release: Release): Os[] {
  return (["windows", "linux"] as Os[]).filter((o) => release.assets.some((a) => a.os === o));
}

/* ─────────────── verification ─────────────── */

export type IntegrityState = "checksum" | "checksum-missing" | "unavailable";

export function integrityOf(asset: ReleaseAsset | null): IntegrityState {
  if (!asset) return "unavailable";
  return asset.sha256 ? "checksum" : "checksum-missing";
}

/** Copyable commands that hash the downloaded file locally, with its real name. */
export function verifyCommands(asset: ReleaseAsset): { shell: string; command: string }[] {
  if (asset.os === "windows") return [{ shell: "PowerShell", command: `Get-FileHash .\\${asset.name} -Algorithm SHA256` }];
  return [{ shell: "Terminal", command: `sha256sum ./${asset.name}` }];
}
