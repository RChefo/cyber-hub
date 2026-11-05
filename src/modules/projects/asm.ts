import type { Tone } from "@/components/ui/Badges";
import type { Asset, AssetStatus, AssetType, Certainty, DiscoverySnapshot, Project, SnapshotStatus } from "@/lib/types";

export const ASSET_TYPE_LABEL: Record<AssetType, string> = {
  domain: "Domain",
  subdomain: "Subdomain",
  ip: "IP address",
  dns_record: "DNS record",
  service: "Service",
  http_service: "Web service",
  certificate: "Certificate",
  technology: "Technology",
  endpoint: "Endpoint",
};

export const ASSET_STATUS_META: Record<AssetStatus, { label: string; tone: Tone }> = {
  active: { label: "Active", tone: "success" },
  not_observed: { label: "Not observed", tone: "warning" },
  retired: { label: "Retired", tone: "default" },
};

export const CERTAINTY_META: Record<Certainty, { label: string; tone: Tone; help: string }> = {
  confirmed: { label: "Confirmed", tone: "success", help: "The target itself answered (HTTP response or open port)." },
  observed: { label: "Observed", tone: "accent", help: "Reported by a public source and corroborated by DNS." },
  possible: { label: "Possible", tone: "warning", help: "A single unverified report, such as a certificate name that does not resolve, or an absence after a finished run." },
  incomplete: { label: "Incomplete", tone: "default", help: "The run did not finish, so a missing item says nothing about the asset." },
};

export const SNAPSHOT_STATUS_META: Record<SnapshotStatus, { label: string; tone: Tone }> = {
  running: { label: "Running", tone: "accent" },
  completed: { label: "Completed", tone: "success" },
  partial: { label: "Partial", tone: "warning" },
  failed: { label: "Failed", tone: "danger" },
  cancelled: { label: "Cancelled", tone: "default" },
};

export const SOURCE_LABEL: Record<string, string> = {
  passive: "Passive (certificate logs, DNS)",
  http: "HTTP check",
  nmap: "Service scan",
  manual: "Manual",
};

/** Certainty recorded with an asset's latest discovery; manual assets have none. */
export function certaintyOf(a: Asset): Certainty | null {
  const c = (a.data as { certainty?: unknown } | null)?.certainty;
  return c === "confirmed" || c === "observed" || c === "possible" || c === "incomplete" ? c : null;
}

export interface AssetSummary {
  total: number;
  byStatus: Record<AssetStatus, number>;
  byType: Partial<Record<AssetType, number>>;
}

export function summarize(assets: Asset[]): AssetSummary {
  const out: AssetSummary = { total: assets.length, byStatus: { active: 0, not_observed: 0, retired: 0 }, byType: {} };
  for (const a of assets) {
    out.byStatus[a.status]++;
    out.byType[a.type] = (out.byType[a.type] ?? 0) + 1;
  }
  return out;
}

/** Scan targets suggested from the scope: in-scope IPs, networks and domains (never exclusions). */
export function suggestedScanTargets(project: Project): string[] {
  return project.targets.filter((t) => t.inScope && (t.kind === "ip" || t.kind === "cidr" || t.kind === "domain")).map((t) => t.value);
}

export function matchesFilter(a: Asset, filter: { type: string; status: string; query: string }): boolean {
  if (filter.type !== "all" && a.type !== filter.type) return false;
  if (filter.status !== "all" && a.status !== filter.status) return false;
  const q = filter.query.trim().toLowerCase();
  return !q || a.value.toLowerCase().includes(q);
}

/** The newest snapshot of each source (for "last run" lines). */
export function latestBySource(snapshots: DiscoverySnapshot[]): Partial<Record<string, DiscoverySnapshot>> {
  const out: Partial<Record<string, DiscoverySnapshot>> = {};
  for (const s of snapshots) if (!out[s.source] || out[s.source]!.id < s.id) out[s.source] = s;
  return out;
}

/** One line of what discovery recorded about an asset (shown under its value). */
export function describeAsset(a: Asset): string {
  const d = (a.data ?? {}) as Record<string, unknown>;
  const str = (v: unknown) => (typeof v === "string" && v ? v : null);
  const parts: (string | null)[] = [];
  switch (a.type) {
    case "http_service":
      parts.push(typeof d.status === "number" ? `HTTP ${d.status}` : null, str(d.title), str(d.server), d.tlsTrusted === false ? "certificate not trusted" : null);
      break;
    case "service":
      parts.push(str(d.service), [str(d.product), str(d.version)].filter(Boolean).join(" ") || null);
      break;
    case "ip":
      parts.push(Array.isArray(d.names) && d.names.length ? `${d.names.slice(0, 3).join(", ")}${d.names.length > 3 ? ` +${d.names.length - 3}` : ""}` : null);
      parts.push(d.inScope === false ? "outside the authorized scope" : null, d.nonPublic === true ? "private or reserved address" : null);
      break;
    case "domain":
    case "subdomain":
      parts.push(d.resolves === false ? "does not resolve" : null, Array.isArray(d.sources) ? `from ${d.sources.join(", ")}` : null);
      break;
    case "technology":
      parts.push(Array.isArray(d.versions) && d.versions.length ? d.versions.join(", ") : null, Array.isArray(d.seenOn) ? `on ${d.seenOn.length} service${d.seenOn.length === 1 ? "" : "s"}` : null);
      break;
    default:
      break;
  }
  return parts.filter(Boolean).join(" · ");
}

const COUNT_NOUN: Record<AssetType, [string, string]> = {
  domain: ["domain", "domains"],
  subdomain: ["subdomain", "subdomains"],
  ip: ["IP address", "IP addresses"],
  dns_record: ["DNS record", "DNS records"],
  service: ["service", "services"],
  http_service: ["web service", "web services"],
  certificate: ["certificate", "certificates"],
  technology: ["technology", "technologies"],
  endpoint: ["endpoint", "endpoints"],
};

/** "1 subdomain", "4 subdomains". */
export function countLabel(n: number, type: AssetType): string {
  return `${n} ${COUNT_NOUN[type][n === 1 ? 0 : 1]}`;
}

