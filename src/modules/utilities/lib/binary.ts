import type { BinaryCapability, BinaryReport, FindingInput } from "@/lib/types";
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
