import { describe, expect, it } from "vitest";
import { detectionMessage, detectPlatform, refineArch, resolveSelection } from "./platform";
import { parseRelease, type Release } from "./releases";

const REPO = "o/r";
const release = (names: string[]): Release =>
  parseRelease(
    {
      tag_name: "v0.2.0",
      draft: false,
      prerelease: false,
      assets: names.map((name) => ({ name, size: 100, state: "uploaded", browser_download_url: `https://github.com/${REPO}/releases/download/v0.2.0/${name}` })),
    },
    REPO,
  )!;
const ALL = release(["Cyber.Hub_0.2.0_x64-setup.exe", "Cyber.Hub_0.2.0_x64_en-US.msi", "Cyber.Hub_0.2.0_amd64.AppImage", "Cyber.Hub_0.2.0_amd64.deb", "Cyber.Hub-0.2.0-1.x86_64.rpm"]);

describe("OS detection", () => {
  it("detects Windows and Linux, with architecture only when the browser says it", () => {
    expect(detectPlatform("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")).toEqual({ os: "windows", arch: "x64", distro: null });
    expect(detectPlatform("Mozilla/5.0 (Windows NT 10.0)")).toEqual({ os: "windows", arch: null, distro: null });
    expect(detectPlatform("Mozilla/5.0 (X11; Linux x86_64)")).toEqual({ os: "linux", arch: "x64", distro: null });
    expect(detectPlatform("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:140.0) Gecko Firefox/140.0").distro).toBe("debian");
    expect(detectPlatform("Mozilla/5.0 (X11; Fedora; Linux x86_64)").distro).toBe("fedora");
    expect(detectPlatform("Mozilla/5.0 (X11; Linux aarch64)").arch).toBe("arm");
    expect(detectPlatform("", "Windows").os).toBe("windows");
  });

  it("does not mistake other platforms for supported ones", () => {
    expect(detectPlatform("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)").os).toBe("macos");
    expect(detectPlatform("Mozilla/5.0 (Linux; Android 15) Mobile").os).toBe("mobile");
    expect(detectPlatform("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)").os).toBe("mobile");
    expect(detectPlatform("Mozilla/5.0 (X11; CrOS x86_64 14541.0.0)").os).toBe("mobile");
    expect(detectPlatform("curl/8.0").os).toBeNull();
  });

  it("refines the architecture from client hints, and survives refusal", async () => {
    const base = detectPlatform("Mozilla/5.0 (Windows NT 10.0)");
    const nav = (v: unknown) => ({ userAgentData: { getHighEntropyValues: async () => v } }) as unknown as Navigator;
    expect((await refineArch(base, nav({ architecture: "arm", bitness: "64" }))).arch).toBe("arm");
    expect((await refineArch(base, nav({ architecture: "x86", bitness: "64" }))).arch).toBe("x64");
    expect((await refineArch(base, { userAgentData: { getHighEntropyValues: async () => Promise.reject(new Error("no")) } } as unknown as Navigator)).arch).toBeNull();
    expect((await refineArch(base, {} as Navigator)).arch).toBeNull();
  });
});

describe("recommendation", () => {
  const win = detectPlatform("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");
  const ubuntu = detectPlatform("Mozilla/5.0 (X11; Ubuntu; Linux x86_64)");
  const unknown = detectPlatform("curl/8.0");

  it("recommends the installer on Windows and a matching package on Linux", () => {
    expect(resolveSelection(ALL, win, null, null)).toMatchObject({ os: "windows", format: "nsis", recommended: true });
    expect(resolveSelection(ALL, ubuntu, null, null)).toMatchObject({ os: "linux", format: "deb", recommended: true });
    expect(resolveSelection(ALL, detectPlatform("Mozilla/5.0 (X11; Linux x86_64)"), null, null)).toMatchObject({ os: "linux", format: "appimage" });
  });

  it("falls back to another published package when the preferred one is missing", () => {
    const noNsis = release(["Cyber.Hub_0.2.0_x64_en-US.msi", "Cyber.Hub_0.2.0_amd64.deb"]);
    expect(resolveSelection(noNsis, win, null, null)).toMatchObject({ format: "msi", recommended: true });
    const noWindows = release(["Cyber.Hub_0.2.0_amd64.deb"]);
    expect(resolveSelection(noWindows, win, null, null)).toMatchObject({ os: "windows", asset: null, recommended: false });
  });

  it("always honours a manual choice", () => {
    expect(resolveSelection(ALL, win, "linux", null)).toMatchObject({ os: "linux", recommended: false });
    expect(resolveSelection(ALL, win, null, "msi")).toMatchObject({ format: "msi", recommended: false });
    expect(resolveSelection(ALL, win, "linux", "rpm").asset?.name).toBe("Cyber.Hub-0.2.0-1.x86_64.rpm");
    // a format that does not belong to the chosen platform is ignored
    expect(resolveSelection(ALL, win, "linux", "msi").format).toBe("appimage");
  });

  it("shows a neutral choice when detection fails, without blocking downloads", () => {
    expect(resolveSelection(ALL, unknown, null, null)).toMatchObject({ os: "windows", recommended: false });
    expect(resolveSelection(ALL, unknown, null, null).asset).not.toBeNull();
    expect(detectionMessage(unknown, ALL)).toBe("Choose your platform.");
    expect(resolveSelection(null, win, null, null)).toMatchObject({ asset: null, recommended: false });
  });

  it("explains what was detected without overpromising", () => {
    expect(detectionMessage(win, ALL)).toBe("Windows detected. We recommend the Windows x64 installer.");
    expect(detectionMessage({ ...win, arch: "arm" }, ALL)).toMatch(/x64 only/);
    expect(detectionMessage(detectPlatform("Mozilla/5.0 (Macintosh)"), ALL)).toMatch(/does not support/);
    expect(detectionMessage(win, release(["Cyber.Hub_0.2.0_amd64.deb"]))).toMatch(/no Windows package/);
  });
});
