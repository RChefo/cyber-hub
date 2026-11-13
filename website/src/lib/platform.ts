// Visitor platform detection for the download page. It only ever suggests: the visitor can always
// pick another platform and package, and nothing downloads without a click.
import { FORMATS_BY_OS, type Format, type Os, type Release, type ReleaseAsset } from "./releases";

export type DetectedOs = Os | "macos" | "mobile" | null;

export interface Detection {
  os: DetectedOs;
  /** "x64" when the browser says so, "arm" when it reports an ARM CPU, null when it does not tell */
  arch: "x64" | "arm" | null;
  /** distribution hint from the user agent (Linux browsers rarely send one) */
  distro: "debian" | "fedora" | null;
}

/** Reads the user agent (and the client-hint platform when the browser offers one). */
export function detectPlatform(userAgent: string, platformHint?: string): Detection {
  const p = (platformHint ?? "").toLowerCase();
  const ua = userAgent.toLowerCase();
  let os: DetectedOs = null;
  if (/android|iphone|ipad|ipod|mobile|cros/.test(ua) || p === "android" || p === "ios" || p === "chrome os") os = "mobile";
  else if (p.startsWith("win") || /windows nt/.test(ua)) os = "windows";
  else if (p.startsWith("mac") || /mac os x|macintosh/.test(ua)) os = "macos";
  else if (p.startsWith("linux") || /linux|x11/.test(ua)) os = "linux";
  let arch: Detection["arch"] = null;
  if (/arm64|aarch64|armv\d/.test(ua)) arch = "arm";
  else if (/win64|x64|x86_64|amd64|wow64/.test(ua)) arch = "x64";
  const distro = /ubuntu|debian|mint/.test(ua) ? "debian" : /fedora|red hat|rhel|centos|opensuse|suse/.test(ua) ? "fedora" : null;
  return { os, arch, distro };
}

/** Refines the architecture with User-Agent Client Hints where the browser supports them. */
export async function refineArch(d: Detection, nav: Navigator | undefined = typeof navigator !== "undefined" ? navigator : undefined): Promise<Detection> {
  const data = (nav as Navigator & { userAgentData?: { getHighEntropyValues?: (h: string[]) => Promise<{ architecture?: string; bitness?: string }> } })?.userAgentData;
  if (!data?.getHighEntropyValues) return d;
  try {
    const v = await data.getHighEntropyValues(["architecture", "bitness"]);
    if (v.architecture === "arm") return { ...d, arch: "arm" };
    if (v.architecture === "x86" && v.bitness === "64") return { ...d, arch: "x64" };
  } catch {
    /* hints refused: keep what the user agent said */
  }
  return d;
}

export function currentPlatform(): Detection {
  if (typeof navigator === "undefined") return { os: null, arch: null, distro: null };
  const hint = (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData?.platform;
  return detectPlatform(navigator.userAgent, hint);
}

/** The package suggested for a platform, in order of preference, among those the release has. */
export function preferredFormats(os: Os, d: Detection): Format[] {
  if (os === "windows") return ["nsis", "msi"];
  if (d.os === "linux" && d.distro === "debian") return ["deb", "appimage", "rpm"];
  if (d.os === "linux" && d.distro === "fedora") return ["rpm", "appimage", "deb"];
  return ["appimage", "deb", "rpm"];
}

export interface Selection {
  os: Os;
  format: Format;
  asset: ReleaseAsset | null;
  /** true when this is what detection suggests for the visitor's device */
  recommended: boolean;
}

/**
 * What the download page shows: the visitor's own choice when they made one, otherwise the
 * suggestion for the detected platform (Windows when detection gave nothing usable).
 */
export function resolveSelection(release: Release | null, d: Detection, chosenOs: Os | null, chosenFormat: Format | null): Selection {
  const detectedOs: Os | null = d.os === "windows" || d.os === "linux" ? d.os : null;
  const os = chosenOs ?? detectedOs ?? "windows";
  const has = (f: Format) => release?.assets.find((a) => a.os === os && a.format === f) ?? null;
  const preferred = preferredFormats(os, d).find((f) => has(f)) ?? FORMATS_BY_OS[os][0];
  const format = chosenFormat && FORMATS_BY_OS[os].includes(chosenFormat) ? chosenFormat : preferred;
  return { os, format, asset: has(format), recommended: os === detectedOs && format === preferred && has(format) !== null };
}

/** The one-line explanation above the picker. */
export function detectionMessage(d: Detection, release: Release | null): string {
  const has = (os: Os) => !release || release.assets.some((a) => a.os === os);
  switch (d.os) {
    case "windows":
      if (d.arch === "arm") return "Windows on ARM detected. ExploitX is built for x64 only; it may not run on this device.";
      return has("windows") ? "Windows detected. We recommend the Windows x64 installer." : "Windows detected, but this release has no Windows package.";
    case "linux":
      if (d.arch === "arm") return "Linux on ARM detected. ExploitX packages are x64 only.";
      return has("linux") ? "Linux detected. Pick the package that matches your distribution." : "Linux detected, but this release has no Linux package.";
    case "macos":
      return "You seem to be on macOS, which ExploitX does not support. You can still download for a Windows or Linux computer.";
    case "mobile":
      return "ExploitX is a desktop app for Windows and Linux. You can download it here for another computer.";
    default:
      return "Choose your platform.";
  }
}
