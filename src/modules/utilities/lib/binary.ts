// SPDX-License-Identifier: Apache-2.0
import type { BinaryCapability, BinaryReport, FindingInput, Severity, YaraTriageMatch } from "@/lib/types";
import { yaraString } from "@/modules/detections/detections";
import { type IocKind, extractIocs } from "./ioc";
import { formatBytes } from "./triage";

/** URLs, addresses, domains and e-mail addresses found in the strings (benign references included). */
export function stringIndicators(strings: string[]): { kind: IocKind; label: string; values: string[] }[] {
  const found = extractIocs(strings.join("\n"));
  const kinds: { kind: IocKind; label: string }[] = [
    { kind: "url", label: "URLs" },
    { kind: "ipv4", label: "IPv4 addresses" },
    { kind: "ipv6", label: "IPv6 addresses" },
    { kind: "domain", label: "Domains" },
    { kind: "email", label: "E-mail addresses" },
  ];
  return kinds.map((k) => ({ ...k, values: found[k.kind] ?? [] })).filter((k) => k.values.length > 0);
}

/** "3 of 5" hardening measures. */
export function hardeningSummary(r: Pick<BinaryReport, "hardening">): string {
  return `${r.hardening.filter((h) => h.present).length} of ${r.hardening.length}`;
}

const YARA_SEVERITY: Record<string, Severity> = { critical: "critical", high: "high", medium: "medium", low: "low" };

/** The finding a YARA match becomes when the analyst records it: under review, with low
 * confidence, since a rule match is a lead; the title names the rule and the file. */
export function yaraFinding(projectId: number, file: string, r: BinaryReport, m: YaraTriageMatch): FindingInput {
  const why = m.strings.length ? m.strings.map((s) => `- ${yaraString(s)}`).join("\n") : "- its condition holds on the file's properties (no string was needed)";
  const description = m.metas.find(([k]) => k.toLowerCase() === "description")?.[1];
  return {
    projectId,
    title: `YARA ${m.rule} (${file})`.slice(0, 200),
    severity: YARA_SEVERITY[m.level] ?? "info",
    status: "under_review",
    category: "Detection",
    confidence: "low",
    description: `The YARA rule ${m.rule} of “${m.title}” (version ${m.version}) matched ${file}.${description ? `\n\nThe rule: ${description}` : ""}\n\nFile: ${file} (${formatBytes(r.size)}), SHA-256 ${r.sha256}, MD5 ${r.md5}.\n\nWhy it matched:\n${why}\n\nA rule match is a lead: confirm it from the file before treating the file as malicious.`,
    affectedTarget: file,
    technicalDetails: `YARA rule file #${m.ruleId} “${m.title}”, version ${m.version}, rule ${m.rule}.${m.techniques.length ? ` MITRE ATT&CK: ${m.techniques.join(", ")}.` : ""} The file was read, not run.`,
    remediation: "Analyse the file in an isolated environment and look up its hashes in threat intelligence before trusting, quarantining or removing it.",
    tags: ["detection", "yara", ...m.techniques],
  };
}

/** The finding a capability becomes; the title names the file, so it is recorded once. */
export function capabilityFinding(projectId: number, file: string, r: BinaryReport, c: BinaryCapability): FindingInput {
  const hashes = [`SHA-256: ${r.sha256}`, `MD5: ${r.md5}`, r.imphash ? `Import hash: ${r.imphash}` : ""].filter(Boolean).join("\n");
  return {
    projectId,
    title: `${c.title} (${file})`.slice(0, 200),
    severity: c.severity,
    status: "new",
    category: "File analysis",
    confidence: "medium",
    description: `${c.detail}\n\nFile: ${file} (${r.format}, ${r.machine}, ${r.kind}, ${formatBytes(r.size)}).\n${hashes}${c.evidence.length ? `\n\nEvidence: ${c.evidence.join(", ")}` : ""}`,
    affectedTarget: file,
    technicalDetails: `Rule ${c.id} (static file triage).${c.technique ? ` MITRE ATT&CK: ${c.technique}.` : ""} Capabilities come from the imported functions and the file's structure; the file was not run.`,
    remediation: "Analyse the file in an isolated environment before trusting it, and look up its hashes in threat intelligence.",
    tags: ["file", r.format.toLowerCase().replace("+", "plus"), ...(c.technique ? [c.technique.split(" ")[0]] : [])],
  };
}
