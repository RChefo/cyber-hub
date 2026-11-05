import type { InstallKind, UpdatePhase, UpdateStatus } from "@/lib/types";

type Tone = "default" | "accent" | "success" | "warning" | "danger";

export const PHASE_META: Record<UpdatePhase, { label: string; tone: Tone }> = {
  idle: { label: "Not checked", tone: "default" },
  checking: { label: "Checking", tone: "accent" },
  upToDate: { label: "Up to date", tone: "success" },
  available: { label: "Update available", tone: "accent" },
  downloading: { label: "Downloading", tone: "accent" },
  verifying: { label: "Verifying", tone: "accent" },
  ready: { label: "Ready to install", tone: "success" },
  installing: { label: "Installing", tone: "accent" },
  restartRequired: { label: "Restart required", tone: "warning" },
  cancelled: { label: "Cancelled", tone: "default" },
  failed: { label: "Failed", tone: "danger" },
};

export const INSTALL_KIND_LABEL: Record<InstallKind, string> = {
  nsis: "Windows installer (NSIS)",
  msi: "Windows installer (MSI)",
  appimage: "AppImage",
  deb: "Debian package (.deb)",
  rpm: "RPM package (.rpm)",
  unknown: "Not installed by an installer",
};

export const FREQUENCY_OPTIONS = [
  { id: "6", label: "Every 6 hours" },
  { id: "12", label: "Every 12 hours" },
  { id: "24", label: "Once a day" },
  { id: "168", label: "Once a week" },
];

const BUSY: UpdatePhase[] = ["checking", "downloading", "verifying", "installing"];

/** Which buttons the Update Center shows for a status. */
export function updateActions(s: UpdateStatus) {
  const busy = BUSY.includes(s.phase);
  const hasRelease = s.available !== null;
  return {
    check: s.configured && !busy && s.phase !== "restartRequired",
    download: s.supported && hasRelease && (s.phase === "available" || s.phase === "cancelled" || s.phase === "failed"),
    cancel: s.phase === "downloading",
    install: s.phase === "ready",
    installBlocked: s.phase === "ready" && s.blockers.length > 0,
    restart: s.phase === "restartRequired",
  };
}

/** Download progress in percent, or null when the size is unknown. */
export function progressPercent(p: UpdateStatus["progress"]): number | null {
  if (!p || !p.total) return null;
  return Math.min(100, Math.round((p.downloaded / p.total) * 100));
}

export function lastResultText(s: UpdateStatus): string {
  switch (s.lastResult) {
    case "upToDate":
      return "up to date";
    case "available":
      return "update found";
    case "failed":
      return "failed";
    default:
      return "";
  }
}

export function platformLabel(s: Pick<UpdateStatus, "os" | "arch">): string {
  const os = s.os === "windows" ? "Windows" : s.os === "linux" ? "Linux" : "macOS";
  return `${os} ${s.arch}`;
}
