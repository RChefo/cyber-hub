// Site configuration, read once from build-time environment variables (see docs/WEBSITE.md).
// Nothing here is secret: these values end up in the public bundle.

const REPO = /^[A-Za-z0-9-]{1,39}\/[A-Za-z0-9._-]{1,100}$/;

export interface SiteConfig {
  /** GitHub "owner/repo" that publishes Cyber Hub releases; null until configured */
  repository: string | null;
  /** origin of the GitHub REST API (overridable for local testing only) */
  apiBase: string;
}

export function readConfig(env: Record<string, string | undefined>): SiteConfig {
  const repo = (env.VITE_GITHUB_REPOSITORY ?? "").trim();
  const api = (env.VITE_RELEASES_API_BASE ?? "https://api.github.com").trim().replace(/\/+$/, "");
  return {
    repository: REPO.test(repo) ? repo : null,
    apiBase: /^https:\/\//.test(api) || /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(api) ? api : "https://api.github.com",
  };
}

export const config = readConfig(import.meta.env as Record<string, string | undefined>);

/** Links that exist only when a repository is configured (never guessed). */
export function repoLinks(repository: string | null) {
  if (!repository) return null;
  const base = `https://github.com/${repository}`;
  return {
    repository: base,
    docs: `${base}/tree/HEAD/docs`,
    releases: `${base}/releases`,
  };
}
