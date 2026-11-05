import type { Os } from "./releases";

/** Best guess of the visitor's OS, used only to preselect a tab. Unknown → null (no preselection). */
export function detectOs(userAgent: string, platformHint?: string): Os | "macos" | null {
  const p = (platformHint ?? "").toLowerCase();
  const ua = userAgent.toLowerCase();
  if (p.startsWith("win") || /windows nt/.test(ua)) return "windows";
  if (p.startsWith("mac") || /mac os x|macintosh/.test(ua)) return /iphone|ipad/.test(ua) ? null : "macos";
  if (/android|iphone|ipad|cros/.test(ua)) return null;
  if (p.startsWith("linux") || /linux|x11/.test(ua)) return "linux";
  return null;
}

export function currentOs(): Os | "macos" | null {
  if (typeof navigator === "undefined") return null;
  const hint = (navigator as Navigator & { userAgentData?: { platform?: string } }).userAgentData?.platform;
  return detectOs(navigator.userAgent, hint);
}
