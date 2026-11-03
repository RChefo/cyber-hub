import type { VtKind, VtStats } from "@/lib/types";

export type VerdictTone = "danger" | "warning" | "success" | "default";

export interface Verdict {
  tone: VerdictTone;
  title: string;
  summary: string;
}

const NOUN: Record<VtKind, string> = { ip: "IP address", domain: "domain", url: "URL", file: "file" };

/**
 * Overall verdict from VirusTotal's last-analysis statistics. Any malicious vote → danger,
 * otherwise any suspicious vote → warning, otherwise harmless votes → clean. A record with no
 * verdicts at all is "no detections", which is not the same as "clean".
 */
export function verdictOf(stats: VtStats, enginesTotal: number, kind: VtKind): Verdict {
  const noun = NOUN[kind];
  const of = enginesTotal > 0 ? ` of ${enginesTotal}` : "";
  if (stats.malicious > 0) {
    return {
      tone: "danger",
      title: "Malicious",
      summary: `${stats.malicious}${of} security vendors flagged this ${noun} as malicious${stats.suspicious ? ` and ${stats.suspicious} as suspicious` : ""}.`,
    };
  }
  if (stats.suspicious > 0) {
    return { tone: "warning", title: "Suspicious", summary: `${stats.suspicious}${of} security vendors flagged this ${noun} as suspicious.` };
  }
  if (stats.harmless > 0) {
    return { tone: "success", title: "No detections", summary: `No vendor flagged this ${noun}; ${stats.harmless} rated it harmless.` };
  }
  return { tone: "default", title: "No verdicts", summary: `No vendor has a verdict for this ${noun} yet.` };
}

/** Share of each category for the distribution bar (0–100, rounded, sums to ≤ 100). */
export function shares(stats: VtStats): { key: keyof VtStats; pct: number }[] {
  const keys: (keyof VtStats)[] = ["malicious", "suspicious", "harmless", "undetected"];
  const total = keys.reduce((a, k) => a + stats[k], 0);
  if (!total) return [];
  return keys.map((k) => ({ key: k, pct: Math.round((stats[k] / total) * 1000) / 10 })).filter((s) => s.pct > 0);
}

/** Reputation is a community score: negative is bad, positive is good. */
export function reputationTone(rep: number | null): VerdictTone {
  if (rep === null) return "default";
  if (rep < 0) return "danger";
  if (rep > 0) return "success";
  return "default";
}
