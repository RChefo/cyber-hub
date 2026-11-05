// Shared access to the release list. Every component on a page uses the same in-flight request
// (and the same cached answer for 15 minutes per browser session), so GitHub is asked once.
import { useCallback, useEffect, useState } from "react";
import { config } from "./config";
import { latestStable, parseRelease, type Release, sortReleases } from "./releases";

export type ReleasesState =
  | { kind: "not-configured" }
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; releases: Release[]; latest: Release | null };

interface CacheStore {
  getItem(k: string): string | null;
  setItem(k: string, v: string): void;
}

const CACHE_KEY = "cyberhub.releases.v2";
export const CACHE_TTL = 15 * 60 * 1000;
/** one page of the API; enough for the life of the project so far (see docs/WEBSITE.md) */
const PER_PAGE = 100;

function sessionCache(): CacheStore | null {
  try {
    return typeof sessionStorage !== "undefined" ? sessionStorage : null;
  } catch {
    return null;
  }
}

/** Fetches and normalizes the release list. Only stable answers are cached, never errors. */
export async function fetchReleases(
  repository: string | null,
  apiBase: string,
  fetcher: typeof fetch = fetch,
  cache: CacheStore | null = sessionCache(),
  now = Date.now(),
): Promise<ReleasesState> {
  if (!repository) return { kind: "not-configured" };
  const key = `${CACHE_KEY}:${repository}`;
  const cached = cache?.getItem(key);
  if (cached) {
    try {
      const c = JSON.parse(cached) as { at: number; releases: Release[] };
      if (now - c.at < CACHE_TTL && Array.isArray(c.releases)) return ready(c.releases);
    } catch {
      /* a corrupt entry is ignored */
    }
  }
  let res: Response;
  try {
    res = await fetcher(`${apiBase}/repos/${repository}/releases?per_page=${PER_PAGE}`, { headers: { Accept: "application/vnd.github+json" } });
  } catch {
    return { kind: "error", message: "Release information could not be loaded. Check the connection and try again." };
  }
  if (res.status === 404) return ready([]);
  if (res.status === 403 || res.status === 429)
    return { kind: "error", message: "GitHub's request limit for this network was reached. Try again in a few minutes, or open the releases page directly." };
  if (!res.ok) return { kind: "error", message: `GitHub answered with HTTP ${res.status}.` };
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    return { kind: "error", message: "GitHub returned release information that could not be read." };
  }
  if (!Array.isArray(body)) return { kind: "error", message: "GitHub returned release information that could not be read." };
  const releases = sortReleases(body.map((r) => parseRelease(r, repository)).filter((r): r is Release => r !== null));
  try {
    cache?.setItem(key, JSON.stringify({ at: now, releases }));
  } catch {
    /* storage full or blocked */
  }
  return ready(releases);
}

function ready(releases: Release[]): ReleasesState {
  return { kind: "ready", releases, latest: latestStable(releases) };
}

let inflight: Promise<ReleasesState> | null = null;

function load(force = false): Promise<ReleasesState> {
  if (!inflight || force) inflight = fetchReleases(config.repository, config.apiBase);
  return inflight;
}

/** All published releases (newest first) and the latest stable one, shared by every caller. */
export function useReleases(): ReleasesState & { retry: () => void } {
  const [state, setState] = useState<ReleasesState>(config.repository ? { kind: "loading" } : { kind: "not-configured" });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    if (!config.repository) return;
    let live = true;
    load(attempt > 0).then((s) => live && setState(s));
    return () => {
      live = false;
    };
  }, [attempt]);
  const retry = useCallback(() => {
    setState({ kind: "loading" });
    setAttempt((a) => a + 1);
  }, []);
  return { ...state, retry };
}
