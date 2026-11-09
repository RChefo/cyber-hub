// Builds the compact MITRE ATT&CK catalog bundled with Cyber Hub (src-tauri/catalog/attack-enterprise.json)
// from an official Enterprise ATT&CK STIX 2.1 bundle (docs/DATA_MODEL.md#attck):
//
//   node scripts/attack-catalog.mjs <enterprise-attack-X.Y.json> <version> <retrieved YYYY-MM-DD>
//
// Source: https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack-X.Y.json).
// Kept: the tactics in the order of the Enterprise matrix, and every technique and sub-technique that
// is neither revoked nor deprecated (ID, name, tactics, platforms, parent), plus where revoked IDs
// went and which IDs are deprecated, so older findings and layers can be recognized.
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";

const [file, version, retrieved] = process.argv.slice(2);
if (!file || !version || !retrieved) {
  console.error("usage: node scripts/attack-catalog.mjs <enterprise-attack.json> <version> <retrieved>");
  process.exit(2);
}
const raw = readFileSync(file);
const bundle = JSON.parse(raw.toString("utf8"));
const objects = bundle.objects ?? [];
const attackId = (o) => (o.external_references ?? []).find((r) => r.source_name === "mitre-attack")?.external_id;
const byStixId = new Map(objects.map((o) => [o.id, o]));

const matrix = objects.find((o) => o.type === "x-mitre-matrix" && !o.revoked && !o.x_mitre_deprecated);
if (!matrix) throw new Error("no ATT&CK matrix in the bundle");
const tactics = matrix.tactic_refs.map((ref) => {
  const t = byStixId.get(ref);
  return { id: attackId(t), shortname: t.x_mitre_shortname, name: t.name };
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
  const phases = (o.kill_chain_phases ?? []).filter((p) => p.kill_chain_name === "mitre-attack").map((p) => p.phase_name).filter((p) => tacticNames.has(p));
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
  source: "MITRE ATT&CK Enterprise, STIX 2.1 bundle of https://github.com/mitre-attack/attack-stix-data",
  url: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-${version}.json`,
  sha256: createHash("sha256").update(raw).digest("hex"),
  version,
  modified: collection?.modified ?? matrix.modified,
  retrieved,
  domain: "enterprise-attack",
  notice: "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.",
  license:
    "MITRE hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy. Adapted by Cyber Hub: only tactic and technique IDs, names, tactics, platforms and parents are kept.",
  tactics,
  techniques,
  revoked,
  deprecated,
};
writeFileSync(process.argv[5] ?? "src-tauri/catalog/attack-enterprise.json", JSON.stringify(catalog) + "\n");
console.log(`ATT&CK ${version}: ${tactics.length} tactics, ${techniques.length} techniques (${techniques.filter((t) => t.parent).length} sub-techniques), ${Object.keys(revoked).length} revoked, ${deprecated.length} deprecated`);
