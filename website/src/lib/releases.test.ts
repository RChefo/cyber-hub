import { describe, expect, it } from "vitest";
// the updater's release tooling: package patterns must stay identical
import { ARTIFACTS } from "../../../scripts/updater-manifest.mjs";
import { readConfig, repoLinks } from "./config";
import { detectOs } from "./platform";
import { ARTIFACT_PATTERNS, formatSize, loadLatestRelease, parseRelease } from "./releases";

const REPO = "owner/cyber-hub";
const DL = `https://github.com/${REPO}/releases/download/v0.2.0`;
const asset = (name: string, size = 6_000_000, url = `${DL}/${name}`) => ({ name, browser_download_url: url, size, state: "uploaded" });
const gh = (extra: Record<string, unknown> = {}) => ({
  tag_name: "v0.2.0",
  name: "Cyber Hub 0.2.0",
  body: "## New features\n- Signed updates",
  published_at: "2026-11-05T10:00:00Z",
  html_url: `https://github.com/${REPO}/releases/tag/v0.2.0`,
  draft: false,
  prerelease: false,
  assets: [
    asset("Cyber.Hub_0.2.0_x64-setup.exe"),
    asset("Cyber.Hub_0.2.0_x64-setup.exe.sig", 400),
    asset("Cyber.Hub_0.2.0_x64_en-US.msi"),
    asset("Cyber.Hub_0.2.0_amd64.AppImage", 90_000_000),
    asset("Cyber.Hub_0.2.0_amd64.deb"),
    asset("Cyber.Hub-0.2.0-1.x86_64.rpm"),
    asset("latest.json", 3000),
    asset("SHA256SUMS.txt", 700),
  ],
  ...extra,
});

describe("release metadata", () => {
  it("uses the same package patterns as the updater manifest tool", () => {
    const fromScript = Object.fromEntries((ARTIFACTS as { key: string; re: RegExp }[]).map((a) => [a.key.split("-").pop(), a.re.source]));
    const fromSite = Object.fromEntries(ARTIFACT_PATTERNS.map((a) => [a.format, a.re.source]));
    expect(fromSite).toEqual(fromScript);
  });

  it("parses a published release into downloadable packages", () => {
    const r = parseRelease(gh(), REPO)!;
    expect(r.version).toBe("0.2.0");
    expect(r.artifacts.map((a) => a.format).sort()).toEqual(["appimage", "deb", "msi", "nsis", "rpm"]);
    expect(r.checksumsUrl).toBe(`${DL}/SHA256SUMS.txt`);
    expect(r.artifacts.find((a) => a.format === "appimage")!.size).toBe(90_000_000);
  });

  it("never shows drafts, pre-releases, foreign URLs or incomplete uploads", () => {
    expect(parseRelease(gh({ draft: true }), REPO)).toBeNull();
    expect(parseRelease(gh({ prerelease: true }), REPO)).toBeNull();
    expect(parseRelease(gh({ tag_name: "v0.3.0-beta.1" }), REPO)).toBeNull();
    const r = parseRelease(
      gh({
        assets: [
          asset("Cyber.Hub_0.2.0_x64-setup.exe", 6_000_000, "https://evil.example/Cyber.Hub_0.2.0_x64-setup.exe"),
          asset("Cyber.Hub_0.2.0_amd64.deb", 6_000_000, `https://github.com/other/repo/releases/download/v0.2.0/Cyber.Hub_0.2.0_amd64.deb`),
          { ...asset("Cyber.Hub_0.2.0_x64_en-US.msi"), state: "new" },
          asset("Cyber.Hub_0.2.0_amd64.AppImage", 0),
          asset("Cyber.Hub-0.2.0-1.x86_64.rpm"),
        ],
      }),
      REPO,
    )!;
    expect(r.artifacts.map((a) => a.format)).toEqual(["rpm"]);
    expect(r.checksumsUrl).toBeNull();
  });

  it("reports every state and caches only stable answers", async () => {
    const res = (status: number, body: unknown = {}) => async () => new Response(JSON.stringify(body), { status });
    const mem = new Map<string, string>();
    const cache = { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, v: string) => void mem.set(k, v) };
    expect((await loadLatestRelease(null, "https://api.github.com")).kind).toBe("not-configured");
    expect((await loadLatestRelease(REPO, "https://api.github.com", res(404), null)).kind).toBe("none");
    expect((await loadLatestRelease(REPO, "https://api.github.com", res(403), null)).kind).toBe("error");
    expect((await loadLatestRelease(REPO, "https://api.github.com", res(500), null)).kind).toBe("error");
    expect((await loadLatestRelease(REPO, "https://api.github.com", async () => { throw new Error("offline"); }, null)).kind).toBe("error");
    const first = await loadLatestRelease(REPO, "https://api.github.com", res(200, gh()), cache, 1000);
    expect(first.kind).toBe("ready");
    // served from the cache within 15 minutes, refetched after
    let calls = 0;
    const counting = async () => { calls++; return new Response(JSON.stringify(gh()), { status: 200 }); };
    await loadLatestRelease(REPO, "https://api.github.com", counting, cache, 1000 + 60_000);
    expect(calls).toBe(0);
    await loadLatestRelease(REPO, "https://api.github.com", counting, cache, 1000 + 16 * 60_000);
    expect(calls).toBe(1);
    // errors are not cached
    mem.clear();
    await loadLatestRelease(REPO, "https://api.github.com", res(500), cache, 0);
    expect(mem.size).toBe(0);
  });

  it("only accepts a well-formed repository and never guesses links", () => {
    expect(readConfig({}).repository).toBeNull();
    expect(readConfig({ VITE_GITHUB_REPOSITORY: "owner/cyber-hub" }).repository).toBe("owner/cyber-hub");
    expect(readConfig({ VITE_GITHUB_REPOSITORY: "https://github.com/x/y" }).repository).toBeNull();
    expect(readConfig({ VITE_RELEASES_API_BASE: "http://evil.example" }).apiBase).toBe("https://api.github.com");
    expect(readConfig({ VITE_RELEASES_API_BASE: "http://127.0.0.1:8787" }).apiBase).toBe("http://127.0.0.1:8787");
    expect(repoLinks(null)).toBeNull();
    expect(repoLinks("o/r")!.releases).toBe("https://github.com/o/r/releases");
    expect(formatSize(6_291_456)).toBe("6.0 MB");
  });

  it("detects the visitor's OS only as a suggestion", () => {
    expect(detectOs("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")).toBe("windows");
    expect(detectOs("Mozilla/5.0 (X11; Linux x86_64)")).toBe("linux");
    expect(detectOs("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)")).toBe("macos");
    expect(detectOs("Mozilla/5.0 (Linux; Android 15)")).toBeNull();
    expect(detectOs("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)")).toBeNull();
    expect(detectOs("", "Windows")).toBe("windows");
  });
});
