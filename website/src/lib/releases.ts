// Release metadata for the download page, read from the GitHub Releases API of the configured
// repository: the same releases the desktop app's updater reads `latest.json` from.
// `releases/latest` only returns a published, non-draft, non-prerelease release, so unpublished
// artifacts are never shown.

export type Os = "windows" | "linux";
export type Format = "nsis" | "msi" | "appimage" | "deb" | "rpm";

/** Package name patterns written by `tauri build`. Kept in step with ARTIFACTS in
 *  scripts/updater-manifest.mjs (a test compares both). */
export const ARTIFACT_PATTERNS: { format: Format; os: Os; re: RegExp }[] = [
  { format: "nsis", os: "windows", re: /_x64-setup\.exe$/ },
  { format: "msi", os: "windows", re: /_x64_[A-Za-z-]+\.msi$/ },
  { format: "appimage", os: "linux", re: /_amd64\.AppImage$/ },
  { format: "deb", os: "linux", re: /_amd64\.deb$/ },
  { format: "rpm", os: "linux", re: /\.x86_64\.rpm$/ },
];

export const FORMAT_LABEL: Record<Format, string> = {
  nsis: "Installer (.exe)",
  msi: "MSI package",
  appimage: "AppImage",
  deb: "Debian / Ubuntu (.deb)",
  rpm: "Fedora / RHEL / openSUSE (.rpm)",
};

export interface Artifact {
  format: Format;
  os: Os;
  name: string;
  url: string;
  size: number;
}

export interface Release {
  version: string;
  tag: string;
  name: string;
  publishedAt: string | null;
  notes: string;
  pageUrl: string;
  artifacts: Artifact[];
  checksumsUrl: string | null;
}

export type ReleaseState =
  | { kind: "not-configured" }
  | { kind: "loading" }
  | { kind: "none" }
  | { kind: "error"; message: string }
  | { kind: "ready"; release: Release };

interface GhAsset {
  name?: unknown;
  browser_download_url?: unknown;
  size?: unknown;
  state?: unknown;
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

const SEMVER_TAG = /^v?(\d+\.\d+\.\d+)$/;

/** Turns a GitHub API release into the page model, dropping anything that does not validate. */
export function parseRelease(raw: unknown, repository: string): Release | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as GhRelease;
  if (r.draft === true || r.prerelease === true) return null;
  const tag = typeof r.tag_name === "string" ? r.tag_name : "";
  const m = SEMVER_TAG.exec(tag);
  if (!m) return null;
  const downloadPrefix = `https://github.com/${repository}/releases/download/${encodeURIComponent(tag)}/`;
  const artifacts: Artifact[] = [];
  let checksumsUrl: string | null = null;
  for (const a of Array.isArray(r.assets) ? (r.assets as GhAsset[]) : []) {
    if (typeof a.name !== "string" || typeof a.browser_download_url !== "string") continue;
    if (a.state !== undefined && a.state !== "uploaded") continue;
    if (!a.browser_download_url.startsWith(downloadPrefix)) continue;
    if (a.name === "SHA256SUMS.txt") {
      checksumsUrl = a.browser_download_url;
      continue;
    }
    const kind = ARTIFACT_PATTERNS.find((p) => p.re.test(a.name as string));
    const size = typeof a.size === "number" && a.size > 0 ? a.size : 0;
    if (!kind || !size) continue;
    if (artifacts.some((x) => x.format === kind.format)) continue;
    artifacts.push({ format: kind.format, os: kind.os, name: a.name, url: a.browser_download_url, size });
  }
  const releasePage = `https://github.com/${repository}/releases/tag/${encodeURIComponent(tag)}`;
  return {
    version: m[1],
    tag,
    name: typeof r.name === "string" && r.name.trim() ? r.name.trim() : `Cyber Hub ${m[1]}`,
    publishedAt: typeof r.published_at === "string" && !Number.isNaN(Date.parse(r.published_at)) ? r.published_at : null,
    notes: typeof r.body === "string" ? r.body.slice(0, 40000) : "",
    pageUrl: typeof r.html_url === "string" && r.html_url === releasePage ? r.html_url : releasePage,
    artifacts,
    checksumsUrl,
  };
}

const CACHE_KEY = "cyberhub.release.v1";
const CACHE_TTL = 15 * 60 * 1000;

interface CacheStore {
  getItem(k: string): string | null;
  setItem(k: string, v: string): void;
}

function store(): CacheStore | null {
  try {
    return typeof sessionStorage !== "undefined" ? sessionStorage : null;
  } catch {
    return null;
  }
}

/** Loads the latest published release (cached for 15 minutes per browser session). */
export async function loadLatestRelease(
  repository: string | null,
  apiBase: string,
  fetcher: typeof fetch = fetch,
  cache: CacheStore | null = store(),
  now = Date.now(),
): Promise<ReleaseState> {
  if (!repository) return { kind: "not-configured" };
  const key = `${CACHE_KEY}:${repository}`;
  const cached = cache?.getItem(key);
  if (cached) {
    try {
      const c = JSON.parse(cached) as { at: number; state: ReleaseState };
      if (now - c.at < CACHE_TTL && (c.state.kind === "ready" || c.state.kind === "none")) return c.state;
    } catch {
      /* ignore a corrupt cache entry */
    }
  }
  let state: ReleaseState;
  try {
    const res = await fetcher(`${apiBase}/repos/${repository}/releases/latest`, { headers: { Accept: "application/vnd.github+json" } });
    if (res.status === 404) state = { kind: "none" };
    else if (res.status === 403 || res.status === 429) state = { kind: "error", message: "GitHub's request limit for this network was reached. Try again in a few minutes, or open the releases page directly." };
    else if (!res.ok) state = { kind: "error", message: `GitHub answered with HTTP ${res.status}.` };
    else {
      const release = parseRelease(await res.json(), repository);
      state = release ? { kind: "ready", release } : { kind: "none" };
    }
  } catch {
    state = { kind: "error", message: "Release information could not be loaded. Check the connection and try again." };
  }
  if (state.kind === "ready" || state.kind === "none") {
    try {
      cache?.setItem(key, JSON.stringify({ at: now, state }));
    } catch {
      /* storage full or blocked */
    }
  }
  return state;
}

export function formatSize(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}
