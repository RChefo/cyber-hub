import { describe, expect, it, vi } from "vitest";
// the updater's release tooling: package patterns must stay identical
import { ARTIFACTS } from "../../../scripts/updater-manifest.mjs";
import { copyText } from "./clipboard";
import { readConfig, repoLinks } from "./config";
import { fetchReleases } from "./releaseStore";
import {
  ARTIFACT_PATTERNS,
  categoryOf,
  changelogOf,
  compareVersions,
  filterArchive,
  formatSize,
  highlights,
  integrityOf,
  latestStable,
  parseRelease,
  parseSha256,
  type Release,
  sortReleases,
  verifyCommands,
} from "./releases";

const REPO = "owner/cyber-hub";
const HASH = "a".repeat(64);
const dl = (tag: string, n: string) => `https://github.com/${REPO}/releases/download/${tag}/${n}`;
const asset = (tag: string, name: string, extra: Record<string, unknown> = {}) => ({ name, browser_download_url: dl(tag, name), size: 6_000_000, state: "uploaded", digest: `sha256:${HASH}`, ...extra });
const gh = (version: string, extra: Record<string, unknown> = {}) => {
  const tag = `v${version}`;
  return {
    tag_name: tag,
    name: `Cyber Hub ${version}`,
    body: "A summary line.\n\n## New features\n- Signed updates\n- Archive\n\n## Bug fixes\n- MSI builds\n\n## Security\n- Version-bound signatures",
    published_at: "2026-11-05T10:00:00Z",
    html_url: `https://github.com/${REPO}/releases/tag/${tag}`,
    draft: false,
    prerelease: false,
    assets: [
      asset(tag, `Cyber.Hub_${version}_x64-setup.exe`),
      asset(tag, `Cyber.Hub_${version}_x64-setup.exe.sig`, { size: 400, digest: null }),
      asset(tag, `Cyber.Hub_${version}_x64_en-US.msi`),
      asset(tag, `Cyber.Hub_${version}_amd64.AppImage`, { size: 90_000_000 }),
      asset(tag, `Cyber.Hub_${version}_amd64.deb`),
      asset(tag, `Cyber.Hub-${version}-1.x86_64.rpm`),
      asset(tag, "latest.json", { size: 3000 }),
      asset(tag, "SHA256SUMS.txt", { size: 700 }),
    ],
    ...extra,
  };
};
const parse = (raw: unknown) => parseRelease(raw, REPO)!;

describe("release data", () => {
  it("uses the same package patterns as the updater manifest tool", () => {
    const fromScript = Object.fromEntries((ARTIFACTS as { key: string; re: RegExp }[]).map((a) => [a.key.split("-").pop(), a.re.source]));
    expect(Object.fromEntries(ARTIFACT_PATTERNS.map((a) => [a.format, a.re.source]))).toEqual(fromScript);
  });

  it("normalizes a release: assets, checksums, signatures, manifest", () => {
    const r = parse(gh("0.2.0"));
    expect(r.version).toBe("0.2.0");
    expect(r.channel).toBe("stable");
    expect(r.assets.map((a) => a.format)).toEqual(["nsis", "msi", "appimage", "deb", "rpm"]);
    expect(r.assets.every((a) => a.arch === "x64" && a.sha256 === HASH)).toBe(true);
    expect(r.assets[0].signatureUrl).toBe(dl("v0.2.0", "Cyber.Hub_0.2.0_x64-setup.exe.sig"));
    expect(r.assets[1].signatureUrl).toBeNull();
    expect(r.checksumsUrl).toBe(dl("v0.2.0", "SHA256SUMS.txt"));
    expect(r.hasUpdateManifest).toBe(true);
  });

  it("drops invalid metadata and never shows drafts or foreign files", () => {
    expect(parseRelease(gh("0.2.0", { draft: true }), REPO)).toBeNull();
    expect(parseRelease(gh("0.2.0", { tag_name: "latest" }), REPO)).toBeNull();
    expect(parseRelease(null, REPO)).toBeNull();
    expect(parseRelease("nonsense", REPO)).toBeNull();
    const r = parse(
      gh("0.2.0", {
        assets: [
          asset("v0.2.0", "Cyber.Hub_0.2.0_x64-setup.exe", { browser_download_url: "https://evil.example/Cyber.Hub_0.2.0_x64-setup.exe" }),
          asset("v0.2.0", "Cyber.Hub_0.2.0_amd64.deb", { browser_download_url: "https://github.com/other/repo/releases/download/v0.2.0/x.deb" }),
          asset("v0.2.0", "Cyber.Hub_0.2.0_x64_en-US.msi", { state: "new" }),
          asset("v0.2.0", "Cyber.Hub_0.2.0_amd64.AppImage", { size: 0 }),
          asset("v0.2.0", "Cyber.Hub-0.2.0-1.x86_64.rpm", { digest: "md5:abc" }),
          { name: 42 },
        ],
      }),
    );
    expect(r.assets.map((a) => a.format)).toEqual(["rpm"]);
    expect(r.assets[0].sha256).toBeNull();
    // a release page link that is not the release's own page on GitHub is replaced by it
    expect(parse(gh("0.2.0", { html_url: "https://evil.example/" })).htmlUrl).toBe(`https://github.com/${REPO}/releases/tag/v0.2.0`);
  });

  it("classifies pre-releases by flag or by semver tag, and picks the latest stable", () => {
    const list = [parse(gh("0.1.0")), parse(gh("0.3.0-beta.1")), parse(gh("0.2.0")), parse(gh("0.2.1", { prerelease: true }))];
    expect(list.map((r) => r.channel)).toEqual(["stable", "prerelease", "stable", "prerelease"]);
    expect(sortReleases(list).map((r) => r.version)).toEqual(["0.3.0-beta.1", "0.2.1", "0.2.0", "0.1.0"]);
    expect(latestStable(list)!.version).toBe("0.2.0");
    expect(latestStable([parse(gh("0.3.0-rc.1"))])).toBeNull();
    expect(latestStable([])).toBeNull();
    expect(compareVersions("1.0.0", "1.0.0-rc.2")).toBe(1);
    expect(compareVersions("1.0.0-rc.10", "1.0.0-rc.2")).toBe(1);
    expect(compareVersions("0.10.0", "0.9.9")).toBe(1);
  });

  it("loads the list once, handles every API state and caches only good answers", async () => {
    const res = (status: number, body: unknown = []) => async () => new Response(typeof body === "string" ? body : JSON.stringify(body), { status });
    const mem = new Map<string, string>();
    const cache = { getItem: (k: string) => mem.get(k) ?? null, setItem: (k: string, v: string) => void mem.set(k, v) };
    expect((await fetchReleases(null, "https://api.github.com")).kind).toBe("not-configured");
    expect(await fetchReleases(REPO, "https://api.github.com", res(200, []), null)).toEqual({ kind: "ready", releases: [], latest: null });
    expect((await fetchReleases(REPO, "https://api.github.com", res(404), null)).kind).toBe("ready");
    expect((await fetchReleases(REPO, "https://api.github.com", res(403), null)).kind).toBe("error");
    expect((await fetchReleases(REPO, "https://api.github.com", res(429), null)).kind).toBe("error");
    expect((await fetchReleases(REPO, "https://api.github.com", res(500), null)).kind).toBe("error");
    expect((await fetchReleases(REPO, "https://api.github.com", res(200, "not json"), null)).kind).toBe("error");
    expect((await fetchReleases(REPO, "https://api.github.com", res(200, { message: "x" }), null)).kind).toBe("error");
    expect((await fetchReleases(REPO, "https://api.github.com", async () => { throw new Error("offline"); }, null)).kind).toBe("error");
    // invalid entries are dropped, valid ones kept
    const mixed = await fetchReleases(REPO, "https://api.github.com", res(200, [gh("0.2.0"), { tag_name: "garbage" }, gh("0.1.0", { draft: true })]), null);
    expect(mixed.kind === "ready" && mixed.releases.map((r) => r.version)).toEqual(["0.2.0"]);
    let calls = 0;
    const counting = async () => {
      calls++;
      return new Response(JSON.stringify([gh("0.2.0")]), { status: 200 });
    };
    await fetchReleases(REPO, "https://api.github.com", counting, cache, 1000);
    await fetchReleases(REPO, "https://api.github.com", counting, cache, 1000 + 60_000);
    expect(calls).toBe(1);
    await fetchReleases(REPO, "https://api.github.com", counting, cache, 1000 + 16 * 60_000);
    expect(calls).toBe(2);
    mem.clear();
    await fetchReleases(REPO, "https://api.github.com", res(500), cache, 0);
    expect(mem.size).toBe(0);
  });

  it("only accepts a well-formed repository and never guesses links", () => {
    expect(readConfig({}).repository).toBeNull();
    expect(readConfig({ VITE_GITHUB_REPOSITORY: "owner/cyber-hub" }).repository).toBe("owner/cyber-hub");
    expect(readConfig({ VITE_GITHUB_REPOSITORY: "https://github.com/x/y" }).repository).toBeNull();
    expect(readConfig({ VITE_RELEASES_API_BASE: "http://evil.example" }).apiBase).toBe("https://api.github.com");
    expect(readConfig({ VITE_RELEASES_API_BASE: "http://127.0.0.1:8787" }).apiBase).toBe("http://127.0.0.1:8787");
    expect(repoLinks(null)).toBeNull();
    expect(formatSize(6_291_456)).toBe("6.0 MB");
  });
});

describe("changelog", () => {
  it("groups changes by the author's headings and picks varied highlights", () => {
    const log = changelogOf(parse(gh("0.2.0")));
    expect(log.summary).toEqual([{ t: "text", v: "A summary line." }]);
    expect(log.groups.map((g) => g.category)).toEqual(["features", "fixes", "security"]);
    const h = highlights(log, 5);
    expect(h.map((x) => x.category)).toEqual(["security", "features", "fixes", "features"]);
    expect(highlights(log, 2)).toHaveLength(2);
    expect(categoryOf("Improvements")).toBe("improvements");
    expect(categoryOf("Bug fixes")).toBe("fixes");
    expect(categoryOf("Security")).toBe("security");
    expect(categoryOf("Miscellaneous")).toBe("other");
    expect(changelogOf(parse(gh("0.2.0", { body: "" })))).toEqual({ summary: null, groups: [] });
  });
});

describe("verification", () => {
  it("accepts only real SHA-256 values", () => {
    expect(parseSha256(`sha256:${"AB".repeat(32)}`)).toBe("ab".repeat(32));
    expect(parseSha256("c".repeat(64))).toBe("c".repeat(64));
    expect(parseSha256("sha256:abc")).toBeNull();
    expect(parseSha256(`sha512:${HASH}`)).toBeNull();
    expect(parseSha256("g".repeat(64))).toBeNull();
    expect(parseSha256(undefined)).toBeNull();
  });

  it("reports integrity states without ever claiming a verified file", () => {
    const r = parse(gh("0.2.0"));
    expect(integrityOf(r.assets[0])).toBe("checksum");
    expect(integrityOf({ ...r.assets[0], sha256: null })).toBe("checksum-missing");
    expect(integrityOf(null)).toBe("unavailable");
    // the states describe what is published, not a check the page made
    expect(["checksum", "checksum-missing", "unavailable"]).not.toContain("verified");
  });

  it("builds hashing commands with the real file names", () => {
    const r = parse(gh("0.2.0"));
    expect(verifyCommands(r.assets[0])).toEqual([{ shell: "PowerShell", command: "Get-FileHash .\\Cyber.Hub_0.2.0_x64-setup.exe -Algorithm SHA256" }]);
    expect(verifyCommands(r.assets[2])).toEqual([{ shell: "Terminal", command: "sha256sum ./Cyber.Hub_0.2.0_amd64.AppImage" }]);
  });

  it("copies to the clipboard and reports failure", async () => {
    const writeText = vi.fn(async () => undefined);
    expect(await copyText(HASH, { writeText })).toBe(true);
    expect(writeText).toHaveBeenCalledWith(HASH);
    expect(await copyText(HASH, { writeText: async () => Promise.reject(new Error("denied")) })).toBe(false);
    expect(await copyText(HASH, undefined)).toBe(false);
  });
});

describe("version archive", () => {
  const list: Release[] = [
    parse(gh("0.1.0")),
    parse(gh("0.3.0-beta.1")),
    parse(gh("0.2.0")),
    parse(gh("0.1.5", { assets: [asset("v0.1.5", "Cyber.Hub_0.1.5_amd64.deb")] })),
    parse(gh("0.0.9", { assets: [] })),
  ];

  it("sorts newest first and filters by platform, channel and version", () => {
    const all = { os: "all", channel: "all", query: "" } as const;
    expect(filterArchive(list, all).map((r) => r.version)).toEqual(["0.3.0-beta.1", "0.2.0", "0.1.5", "0.1.0", "0.0.9"]);
    expect(filterArchive(list, { ...all, channel: "stable" }).map((r) => r.version)).toEqual(["0.2.0", "0.1.5", "0.1.0", "0.0.9"]);
    expect(filterArchive(list, { ...all, channel: "prerelease" }).map((r) => r.version)).toEqual(["0.3.0-beta.1"]);
    expect(filterArchive(list, { ...all, os: "windows" }).map((r) => r.version)).toEqual(["0.3.0-beta.1", "0.2.0", "0.1.0"]);
    expect(filterArchive(list, { ...all, os: "linux" }).map((r) => r.version)).toEqual(["0.3.0-beta.1", "0.2.0", "0.1.5", "0.1.0"]);
    expect(filterArchive(list, { ...all, query: "v0.1" }).map((r) => r.version)).toEqual(["0.1.5", "0.1.0"]);
    expect(filterArchive(list, { ...all, query: "9.9" })).toEqual([]);
  });

  it("keeps releases whose packages are gone, with no download actions", () => {
    const gone = list.find((r) => r.version === "0.0.9")!;
    expect(gone.assets).toEqual([]);
    expect(gone.htmlUrl).toBe(`https://github.com/${REPO}/releases/tag/v0.0.9`);
  });
});
