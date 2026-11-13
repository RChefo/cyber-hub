// Reference data for the CVSS scorer in src-tauri/src/cvss (docs/DATA_MODEL.md#cvss).
//
// Scores CVSS vectors with FIRST's own calculators, so the Rust scorer can be compared with them:
//
//   node scripts/cvss-reference.mjs <cvss-v4-calculator dir> <cvsscalc31.js> <cvsscalc30.js> <out dir>
//
// Sources (not part of this repository):
// * v4.0: https://github.com/FIRSTdotorg/cvss-v4-calculator: metrics.js, max_severity.js,
//   max_composed.js, cvss_lookup.js, cvss_score.js;
// * v3.1 and v3.0: the scripts of https://www.first.org/cvss/calculator/3.1 and /3.0
//   (cvsscalc31.js, cvsscalc30.js).
//
// The calculators are plain arithmetic without I/O. They run in a separate vm context and are
// given nothing but the vectors.
//
// Output, one `vector<TAB>base score<TAB>score` line per vector:
// * <out>/v40.tsv, v31.tsv, v30.tsv: every base vector of the version, plus seeded random vectors
//   with threat or temporal, environmental and supplemental metrics;
// * <out>/fixture.tsv: the subset committed as src-tauri/src/cvss/testdata/first_reference.tsv
//   (one v4.0 vector per macrovector, and v3.0 vectors whose 3.0 and 3.1 scores differ).
//
// "score" is what ExploitX reports: v4.0 the score of the whole vector; v3 the environmental
// score when an environmental metric is set, else the temporal score when a temporal metric is
// set, else the base score.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";

const [v4dir, v31file, v30file, out] = process.argv.slice(2);
if (!out) {
  console.error("usage: node scripts/cvss-reference.mjs <cvss-v4-calculator dir> <cvsscalc31.js> <cvsscalc30.js> <out dir>");
  process.exit(2);
}
const RANDOM = Number(process.env.CVSS_RANDOM ?? 200_000);

function load(files) {
  const ctx = vm.createContext({});
  for (const f of files) vm.runInContext(readFileSync(f, "utf8"), ctx, { filename: f });
  return ctx;
}
const ref4 = load(["metrics.js", "max_severity.js", "max_composed.js", "cvss_lookup.js", "cvss_score.js"].map((f) => join(v4dir, f)));
const ref31 = load([v31file]).CVSS31;
const ref30 = load([v30file]).CVSS;

// mulberry32: a small seeded generator, so the vector sets can be reproduced
function rng(seed) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = (r, values) => values[Math.floor(r() * values.length)];

function* every(spec) {
  const idx = spec.map(() => 0);
  for (;;) {
    yield spec.map(([name, values], i) => `${name}:${values[idx[i]]}`);
    let i = spec.length - 1;
    while (i >= 0 && ++idx[i] === spec[i][1].length) idx[i--] = 0;
    if (i < 0) return;
  }
}
function randomParts(r, base, optional, p) {
  const parts = base.map(([name, values]) => `${name}:${pick(r, values)}`);
  for (const [name, values] of optional) if (r() < p) parts.push(`${name}:${pick(r, values)}`);
  return parts;
}

/* ── v4.0 ── */
const V4_ALL = Object.entries(ref4.expectedMetricOrder);
const V4_BASE = V4_ALL.slice(0, 11);
const V4_OPTIONAL = V4_ALL.slice(11);
function score4(parts) {
  const sel = Object.fromEntries(V4_ALL.map(([name]) => [name, "X"]));
  for (const p of parts) {
    const [k, v] = p.split(":");
    sel[k] = v;
  }
  const mv = ref4.macroVector(sel);
  return { mv, score: ref4.cvss_score(sel, ref4.cvssLookup_global, ref4.maxSeverity, mv).toFixed(1) };
}
function line4(parts) {
  const base = parts.slice(0, 11);
  const all = score4(parts);
  return { mv: all.mv, text: `CVSS:4.0/${parts.join("/")}\t${score4(base).score}\t${all.score}` };
}

/* ── v3.x ── */
const V3_BASE = [["AV", ["N", "A", "L", "P"]], ["AC", ["L", "H"]], ["PR", ["N", "L", "H"]], ["UI", ["N", "R"]], ["S", ["U", "C"]], ["C", ["H", "L", "N"]], ["I", ["H", "L", "N"]], ["A", ["H", "L", "N"]]];
const V3_TEMPORAL = [["E", ["X", "H", "F", "P", "U"]], ["RL", ["X", "U", "W", "T", "O"]], ["RC", ["X", "C", "R", "U"]]];
const V3_ENV = [
  ["CR", ["X", "H", "M", "L"]], ["IR", ["X", "H", "M", "L"]], ["AR", ["X", "H", "M", "L"]],
  ["MAV", ["X", "N", "A", "L", "P"]], ["MAC", ["X", "L", "H"]], ["MPR", ["X", "N", "L", "H"]], ["MUI", ["X", "N", "R"]],
  ["MS", ["X", "U", "C"]], ["MC", ["X", "H", "L", "N"]], ["MI", ["X", "H", "L", "N"]], ["MA", ["X", "H", "L", "N"]],
];
const isSet = (parts, group) => parts.some((p) => {
  const [k, v] = p.split(":");
  return v !== "X" && group.some(([name]) => name === k);
});
function score3(calc, prefix, parts) {
  const r = calc.calculateCVSSFromVector(`${prefix}/${parts.join("/")}`);
  if (!r.success) throw new Error(`${prefix}/${parts.join("/")}: ${JSON.stringify(r)}`);
  const score = isSet(parts, V3_ENV) ? r.environmentalMetricScore : isSet(parts, V3_TEMPORAL) ? r.temporalMetricScore : r.baseMetricScore;
  return { base: r.baseMetricScore, score };
}
const line3 = (calc, prefix, parts) => {
  const s = score3(calc, prefix, parts);
  return `${prefix}/${parts.join("/")}\t${s.base}\t${s.score}`;
};

/* ── generate ── */
mkdirSync(out, { recursive: true });
const fixture = [];

const lines4 = [];
for (const parts of every(V4_BASE)) lines4.push(line4(parts).text);
const r4 = rng(40);
const perMacrovector = new Map();
for (let i = 0; i < RANDOM; i++) {
  const l = line4(randomParts(r4, V4_BASE, V4_OPTIONAL, 0.5));
  lines4.push(l.text);
  if (!perMacrovector.has(l.mv)) perMacrovector.set(l.mv, l.text);
}
writeFileSync(join(out, "v40.tsv"), lines4.join("\n") + "\n");
fixture.push(...[...perMacrovector.entries()].sort().map(([, text]) => text));

const lines31 = [];
for (const parts of every(V3_BASE)) lines31.push(line3(ref31, "CVSS:3.1", parts));
const r31 = rng(31);
for (let i = 0; i < RANDOM; i++) lines31.push(line3(ref31, "CVSS:3.1", randomParts(r31, V3_BASE, [...V3_TEMPORAL, ...V3_ENV], 0.5)));
writeFileSync(join(out, "v31.tsv"), lines31.join("\n") + "\n");
for (let i = 2592; i < lines31.length; i += Math.floor(RANDOM / 120)) fixture.push(lines31[i]);

const lines30 = [];
for (const parts of every(V3_BASE)) lines30.push(line3(ref30, "CVSS:3.0", parts));
const r30 = rng(30);
let differ = 0;
const differing = [];
for (let i = 0; i < RANDOM; i++) {
  const parts = randomParts(r30, V3_BASE, [...V3_TEMPORAL, ...V3_ENV], 0.5);
  const l = line3(ref30, "CVSS:3.0", parts);
  lines30.push(l);
  if (score3(ref30, "CVSS:3.0", parts).score !== score3(ref31, "CVSS:3.1", parts).score) {
    differ++;
    if (differing.length < 60) differing.push(l);
  }
}
writeFileSync(join(out, "v30.tsv"), lines30.join("\n") + "\n");
fixture.push(...differing);
for (let i = 2592; i < lines30.length; i += Math.floor(RANDOM / 40)) fixture.push(lines30[i]);

writeFileSync(join(out, "fixture.tsv"), fixture.join("\n") + "\n");
console.log(`v4.0: ${lines4.length} vectors (${perMacrovector.size} macrovectors reached); v3.1: ${lines31.length}; v3.0: ${lines30.length}, of which ${differ} random vectors score differently under the 3.1 equations; fixture: ${fixture.length}`);
