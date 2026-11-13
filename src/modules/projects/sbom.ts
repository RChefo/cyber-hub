// SPDX-License-Identifier: Apache-2.0
import type { Tone } from "@/components/ui/Badges";
import type { SbomChange, SbomComparison, SbomComponent, SbomSummary, SbomVuln } from "@/lib/types";

export const SBOM_FORMAT_LABEL: Record<string, string> = {
  "cyclonedx-json": "CycloneDX JSON",
  "cyclonedx-xml": "CycloneDX XML",
  "spdx-json": "SPDX JSON",
  "spdx-tag": "SPDX tag-value",
  "lockfile-npm": "npm lockfile",
  "lockfile-yarn": "Yarn lockfile",
  "lockfile-pnpm": "pnpm lockfile",
  "lockfile-cargo": "Cargo.lock",
  "lockfile-poetry": "poetry.lock",
  "lockfile-uv": "uv.lock",
  "lockfile-pipfile": "Pipfile.lock",
  "lockfile-requirements": "requirements.txt",
  "lockfile-composer": "composer.lock",
  "lockfile-gemfile": "Gemfile.lock",
  "lockfile-gomod": "go.mod",
  "lockfile-nuget": "NuGet lockfile",
  "lockfile-gradle": "Gradle lockfile",
};

export const ISSUE_AREA_LABEL: Record<string, string> = {
  license: "License",
  completeness: "Completeness",
  "supply-chain": "Supply chain",
};

/** The second line of a component row: ecosystem, relationship, origin and licenses. */
export function componentFacts(c: SbomComponent, lockfile: boolean): string {
  const origin = !c.purl && c.resolved ? `from ${c.resolved}` : "";
  const licenses = c.licenses.join(" · ") || (lockfile ? "" : "no license stated");
  return [c.ecosystem || "no package URL", c.direct ? "direct" : "", c.dev ? "development" : "", origin, c.supplier, licenses].filter(Boolean).join(" · ");
}

export const LICENSE_RISK_META: Record<SbomComponent["licenseRisk"], { label: string; tone: Tone }> = {
  permissive: { label: "Permissive", tone: "success" },
  "weak-copyleft": { label: "Weak copyleft", tone: "default" },
  copyleft: { label: "Copyleft", tone: "warning" },
  "network-copyleft": { label: "Network copyleft", tone: "danger" },
  restricted: { label: "Restricted", tone: "danger" },
  unknown: { label: "Unknown", tone: "default" },
};

/** "name@version", with the Maven group. */
export function componentLabel(c: Pick<SbomComponent, "name" | "group" | "version">): string {
  const name = c.group ? `${c.group}/${c.name}` : c.name;
  return c.version ? `${name}@${c.version}` : name;
}

/** Components that can be looked up: a package URL and a version (in it, or the component's). */
export function checkable(components: SbomComponent[]): number {
  return components.filter((c) => c.purl.startsWith("pkg:") && (c.version || /@[^/?#]+/.test(c.purl))).length;
}

/** One row per vulnerability and affected component, with the key used to record it. */
export interface VulnRow {
  key: string;
  vuln: SbomVuln;
  component: number;
}

/** VEX states under which a vulnerability does not apply. */
export const NOT_APPLICABLE = ["not_affected", "false_positive"];

export function vulnRows(vulns: SbomVuln[], hideNotAffected: boolean): VulnRow[] {
  const out: VulnRow[] = [];
  for (const v of vulns) {
    if (hideNotAffected && NOT_APPLICABLE.includes(v.analysis)) continue;
    for (const c of v.components) out.push({ key: `vuln:${v.id}:${c}`, vuln: v, component: c });
  }
  return out;
}

export interface ComponentFilter {
  text: string;
  ecosystem: string;
  risk: string;
  vulnerableOnly: boolean;
}

/** Indices of the components that match; `affected` is the set of vulnerable component indices. */
export function filterComponents(components: SbomComponent[], affected: Set<number>, f: ComponentFilter): number[] {
  const text = f.text.trim().toLowerCase();
  const out: number[] = [];
  components.forEach((c, i) => {
    if (f.ecosystem !== "all" && (c.ecosystem || "other") !== f.ecosystem) return;
    if (f.risk !== "all" && c.licenseRisk !== f.risk) return;
    if (f.vulnerableOnly && !affected.has(i)) return;
    if (text && ![c.name, c.group, c.version, c.purl, c.supplier, ...c.licenses].join(" ").toLowerCase().includes(text)) return;
    out.push(i);
  });
  return out;
}

/** "2 added · 1 removed · 3 upgraded · 1 downgraded · 40 unchanged" (zero counts of upgrades,
 * downgrades and other changes left out). */
export function sbomCompareSummary(c: Pick<SbomComparison, "added" | "removed" | "changed" | "unchanged">): string {
  const n = (d: SbomChange["direction"]) => c.changed.filter((x) => x.direction === d).length;
  return [
    `${c.added.length} added`,
    `${c.removed.length} removed`,
    ...(n("upgraded") ? [`${n("upgraded")} upgraded`] : []),
    ...(n("downgraded") ? [`${n("downgraded")} downgraded`] : []),
    ...(n("changed") ? [`${n("changed")} changed`] : []),
    `${c.unchanged} unchanged`,
  ].join(" · ");
}

/** "1 critical, 2 high" from a summary's counts; "none known" when empty. */
export function vulnSummary(s: Pick<SbomSummary, "vulns">): string {
  const names = ["critical", "high", "medium", "low", "unrated"];
  const parts = s.vulns.map((n, i) => (n > 0 ? `${n} ${names[i]}` : "")).filter(Boolean);
  return parts.length ? parts.join(", ") : "none known";
}
