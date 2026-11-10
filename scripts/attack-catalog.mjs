// Builds the compact MITRE ATT&CK catalogs bundled with Cyber Hub (src-tauri/catalog/attack-*.json)
// from the official ATT&CK STIX 2.1 bundles (docs/DATA_MODEL.md#attck):
//
//   node scripts/attack-catalog.mjs <bundle.json> <version> <retrieved YYYY-MM-DD> [out.json] [domain]
//
// domain: enterprise-attack (default), mobile-attack or ics-attack. Source:
// https://github.com/mitre-attack/attack-stix-data (<domain>/<domain>-X.Y.json).
// Kept: the tactics in the order of the domain's matrix, and every technique and sub-technique that
// is neither revoked nor deprecated (ID, name, tactics, platforms, parent), plus where revoked IDs
// went and which IDs are deprecated, so older findings and layers can be recognized.
// Mobile and ICS (Mission 6) name their kill chains differently and cite their IDs under their own
// source names; the Enterprise output is byte for byte what the earlier, Enterprise-only script wrote.
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const DOMAINS = {
  "enterprise-attack": { label: "Enterprise", out: "enterprise", killChain: "mitre-attack", sources: ["mitre-attack"] },
  "mobile-attack": { label: "Mobile", out: "mobile", killChain: "mitre-mobile-attack", sources: ["mitre-attack", "mitre-mobile-attack"] },
  "ics-attack": { label: "ICS", out: "ics", killChain: "mitre-ics-attack", sources: ["mitre-attack", "mitre-ics-attack"] },
};
const [file, version, retrieved, outArg, domain = "enterprise-attack"] = process.argv.slice(2);
const d = DOMAINS[domain];
if (!file || !version || !retrieved || !d) {
  console.error("usage: node scripts/attack-catalog.mjs <bundle.json> <version> <retrieved> [out.json] [enterprise-attack|mobile-attack|ics-attack]");
  process.exit(2);
}
const out = outArg || `src-tauri/catalog/attack-${d.out}.json`;
const raw = readFileSync(file);
const bundle = JSON.parse(raw.toString("utf8"));
const objects = bundle.objects ?? [];
const attackId = (o) => (o.external_references ?? []).find((r) => d.sources.includes(r.source_name) && /^T(A)?\d{4}(\.\d{3})?$/.test(r.external_id ?? ""))?.external_id;
const tacticId = (o) => (o.external_references ?? []).find((r) => r.source_name === "mitre-attack")?.external_id;
const byStixId = new Map(objects.map((o) => [o.id, o]));

const matrix = objects.find((o) => o.type === "x-mitre-matrix" && !o.revoked && !o.x_mitre_deprecated);
if (!matrix) throw new Error("no ATT&CK matrix in the bundle");
const tactics = matrix.tactic_refs.map((ref) => {
  const t = byStixId.get(ref);
  return { id: tacticId(t), shortname: t.x_mitre_shortname, name: t.name };
});
const tacticNames = new Set(tactics.map((t) => t.shortname));

const techniques = [];
const deprecated = [];
for (const o of objects) {
  if (o.type !== "attack-pattern") continue;
  const id = attackId(o);
  if (!id) continue;
  if (o.revoked) continue;
  if (o.x_mitre_deprecated) {
    deprecated.push(id);
    continue;
  }
  const phases = (o.kill_chain_phases ?? []).filter((p) => p.kill_chain_name === d.killChain).map((p) => p.phase_name).filter((p) => tacticNames.has(p));
  techniques.push({
    id,
    name: o.name,
    tactics: [...new Set(phases)],
    platforms: o.x_mitre_platforms ?? [],
    ...(o.x_mitre_is_subtechnique ? { parent: id.split(".")[0] } : {}),
  });
}
techniques.sort((a, b) => a.id.localeCompare(b.id, "en", { numeric: true }));
deprecated.sort();

// revoked techniques: where they went
const revoked = {};
for (const r of objects) {
  if (r.type !== "relationship" || r.relationship_type !== "revoked-by") continue;
  const from = byStixId.get(r.source_ref);
  const to = byStixId.get(r.target_ref);
  if (from?.type === "attack-pattern" && to?.type === "attack-pattern" && attackId(from) && attackId(to)) revoked[attackId(from)] = attackId(to);
}

const collection = objects.find((o) => o.type === "x-mitre-collection");
const catalog = {
  source: `MITRE ATT&CK ${d.label}, STIX 2.1 bundle of https://github.com/mitre-attack/attack-stix-data`,
  url: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/${domain}/${domain}-${version}.json`,
  sha256: createHash("sha256").update(raw).digest("hex"),
  version,
  modified: collection?.modified ?? matrix.modified,
  retrieved,
  domain,
  notice: "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.",
  license:
    "MITRE hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy. Adapted by Cyber Hub: only tactic and technique IDs, names, tactics, platforms and parents are kept.",
  tactics,
  techniques,
  revoked,
  deprecated,
};
const noTactic = techniques.filter((t) => t.tactics.length === 0).map((t) => t.id);
const orphans = techniques.filter((t) => t.parent && !techniques.some((p) => p.id === t.parent)).map((t) => t.id);
if (noTactic.length || orphans.length) throw new Error(`incomplete catalog: without tactic ${noTactic.join(", ")}; sub-techniques without parent ${orphans.join(", ")}`);
writeFileSync(out, JSON.stringify(catalog) + "\n");
console.log(`${domain} ${version}: ${tactics.length} tactics, ${techniques.length} techniques (${techniques.filter((t) => t.parent).length} sub-techniques), ${Object.keys(revoked).length} revoked, ${deprecated.length} deprecated → ${out}`);
