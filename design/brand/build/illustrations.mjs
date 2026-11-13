// SPDX-License-Identifier: Apache-2.0
// Feature illustrations: the ExploitX illustration style, as three examples (investigate, detect, report).
// Rules (docs/brand/VISUAL_IDENTITY.md): a night tile, hairline strokes in Bone at low opacity, one
// element in Ultraviolet that carries the idea (the "signal"), the symbol's convergence where it fits,
// no text, no gradients other than the tile's glow. usage: node design/brand/build/illustrations.mjs
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import * as B from "./brand.mjs";
import { tokens } from "./tokens.mjs";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "illustrations");
mkdirSync(dir, { recursive: true });
const UV = tokens.brand.ultraviolet[500], SOFT = tokens.brand.ultraviolet[300], BONE = tokens.brand.bone, SEV = tokens.severity;
const W = 480, H = 320;
const tile = (title, body) => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="${title}"><title>${title}</title>
<defs><radialGradient id="g" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stop-color="${UV}" stop-opacity="0.18"/><stop offset="1" stop-color="${UV}" stop-opacity="0"/></radialGradient></defs>
<rect width="${W}" height="${H}" rx="24" fill="${tokens.neutral.surface}"/><circle cx="${W / 2}" cy="${H / 2}" r="150" fill="url(#g)"/>${body}</svg>\n`;
const sym = (cx, cy, h) => B.symbolGroup(cx - (h * 52) / 96, cy - h / 2, h, UV, BONE);

// 1. Investigate: observations from every side converge on one entity.
const nodes = [[78, 82], [64, 170], [96, 252], [200, 52], [282, 268], [404, 76], [418, 178], [380, 258], [168, 220], [318, 112]];
let inv = "";
for (const [x, y] of nodes) inv += `<line x1="${x}" y1="${y}" x2="240" y2="160" stroke="${BONE}" stroke-opacity="0.22" stroke-width="1.5"/>`;
inv += `<line x1="78" y1="82" x2="200" y2="52" stroke="${BONE}" stroke-opacity="0.12" stroke-width="1.5"/><line x1="404" y1="76" x2="418" y2="178" stroke="${BONE}" stroke-opacity="0.12" stroke-width="1.5"/><line x1="96" y1="252" x2="168" y2="220" stroke="${BONE}" stroke-opacity="0.12" stroke-width="1.5"/>`;
for (const [i, [x, y]] of nodes.entries()) inv += i % 3 === 0 ? `<rect x="${x - 7}" y="${y - 7}" width="14" height="14" rx="3" fill="${tokens.neutral.background}" stroke="${BONE}" stroke-opacity="0.6" stroke-width="1.5"/>` : `<circle cx="${x}" cy="${y}" r="7" fill="${tokens.neutral.background}" stroke="${BONE}" stroke-opacity="0.6" stroke-width="1.5"/>`;
inv += `<circle cx="240" cy="160" r="34" fill="${tokens.neutral.background}" stroke="${UV}" stroke-width="1.5"/>${sym(240, 160, 26)}`;
writeFileSync(join(dir, "investigate.svg"), tile("Investigate: observations converge on one entity", inv));

// 2. Detect: a stream of events passes a rule; one event matches.
let det = "";
const rows = [120, 64, 168, 92, 140, 76, 152, 104];
rows.forEach((len, i) => {
  const y = 58 + i * 28;
  const hit = i === 4;
  det += `<rect x="40" y="${y}" width="${len}" height="8" rx="4" fill="${hit ? UV : BONE}" fill-opacity="${hit ? 1 : 0.18}"/>`;
  det += `<rect x="${52 + len}" y="${y}" width="${36 + ((i * 17) % 40)}" height="8" rx="4" fill="${BONE}" fill-opacity="${hit ? 0.45 : 0.1}"/>`;
});
// the rule: two brackets around the matching field
det += `<path d="M232 44 h-14 v232 h14 M330 44 h14 v232 h-14" fill="none" stroke="${BONE}" stroke-opacity="0.55" stroke-width="1.5"/>`;
det += `<path d="M232 174 H330" stroke="${UV}" stroke-width="1.5" stroke-dasharray="3 5"/>`;
det += `<circle cx="402" cy="174" r="30" fill="${tokens.neutral.background}" stroke="${UV}" stroke-width="1.5"/>${sym(402, 174, 24)}<path d="M344 174 H372" stroke="${UV}" stroke-width="1.5"/>`;
writeFileSync(join(dir, "detect.svg"), tile("Detect: one event in a stream matches a rule", det));

// 3. Report: findings, ordered by severity, become one document.
let rep = "";
const findings = [[SEV.critical, 92], [SEV.high, 126], [SEV.medium, 104], [SEV.low, 80]];
findings.forEach(([c, len], i) => {
  const y = 62 + i * 54;
  rep += `<rect x="40" y="${y}" width="180" height="40" rx="8" fill="${tokens.neutral.background}" fill-opacity="0.7"/><rect x="52" y="${y + 14}" width="6" height="12" rx="2" fill="${c}"/><rect x="68" y="${y + 16}" width="${len}" height="8" rx="4" fill="${BONE}" fill-opacity="0.35"/>`;
  rep += `<path d="M220 ${y + 20} C 262 ${y + 20}, 262 160, 296 160" fill="none" stroke="${BONE}" stroke-opacity="0.18" stroke-width="1.5"/>`;
});
rep += `<rect x="296" y="52" width="148" height="216" rx="10" fill="${tokens.neutral.background}" stroke="${UV}" stroke-width="1.5"/>`;
rep += `<rect x="314" y="74" width="72" height="10" rx="5" fill="${SOFT}"/>`;
for (let i = 0; i < 4; i++) rep += `<rect x="314" y="${100 + i * 18}" width="${[112, 96, 104, 70][i]}" height="6" rx="3" fill="${BONE}" fill-opacity="0.25"/>`;
findings.forEach(([c], i) => (rep += `<rect x="314" y="${182 + i * 16}" width="6" height="8" rx="2" fill="${c}"/><rect x="328" y="${183 + i * 16}" width="${[90, 78, 84, 60][i]}" height="6" rx="3" fill="${BONE}" fill-opacity="0.2"/>`));
writeFileSync(join(dir, "report.svg"), tile("Report: findings ordered by severity become one document", rep));
console.log("illustrations/investigate.svg detect.svg report.svg");
