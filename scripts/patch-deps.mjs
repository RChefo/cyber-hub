// SPDX-License-Identifier: Apache-2.0
// Postinstall patch that keeps Tauri's `freezePrototype` hardening compatible with chart
// dependencies.
//
// With a frozen Object.prototype, assigning a property that an object only *inherits*
// from Object.prototype (`obj.constructor = X`, `obj.toString = f`, `obj.valueOf = f`)
// throws in strict mode — the JavaScript "override mistake". A few dependencies of
// Recharts (shadcn Charts) do exactly that while defining their prototypes:
//
//   decimal.js-light  P.toString = P.valueOf = …;  x.constructor = Decimal;
//   d3-color          prototype.constructor = constructor;
//   d3-format         FormatSpecifier.prototype.toString = function () {…};
//
// Each statement is rewritten to Object.defineProperty with the same resulting property
// (own, writable, enumerable, configurable), which is not affected by the frozen
// prototype. Only exact, known statements are touched; the script fails loudly when an
// expected statement is missing so a dependency update cannot silently break the app.
// Bundled output was scanned for other assignments to Object.prototype names; the rest
// assign to functions or to objects that already own the property, which is safe.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const MARKER = "/* cyber-hub: override-mistake patch */";
const DESC = "writable: true, configurable: true, enumerable: true";

/** Replace an exact statement (must occur exactly once). */
const stmt = (file, from, to) => ({ type: "stmt", file, from, to: `${MARKER} ${to}` });
/** Replace `<head>` … `<end>` where only the head and the closing token change. */
const block = (file, head, newHead, end, newEnd) => ({ type: "block", file, head, newHead: `${MARKER} ${newHead}`, end, newEnd });

const decimalHead = (keys, extra = "") =>
  `(function (fn) { ${JSON.stringify(keys)}.forEach(function (k) { Object.defineProperty(P, k, { value: fn, ${DESC} }); });${extra} })(function () {`;
const CTOR = `Object.defineProperty(x, 'constructor', { value: Decimal, ${DESC} });`;
const D3_CTOR = `Object.defineProperty(prototype, "constructor", { value: constructor, ${DESC} });`;
const D3_FMT = `Object.defineProperty(FormatSpecifier.prototype, "toString", { ${DESC}, value: function() {`;

const PATCHES = [
  // decimal.js-light
  block(
    "node_modules/decimal.js-light/decimal.mjs",
    "P.toString = P.valueOf = P.val = P.toJSON = P[Symbol.for('nodejs.util.inspect.custom')] = function () {",
    decimalHead(["toString", "valueOf", "val", "toJSON"], " P[Symbol.for('nodejs.util.inspect.custom')] = fn;"),
    "\n};",
    "\n});",
  ),
  block("node_modules/decimal.js-light/decimal.js", "P.toString = P.valueOf = P.val = P.toJSON = function () {", decimalHead(["toString", "valueOf", "val", "toJSON"]), "\n  };", "\n  });"),
  stmt("node_modules/decimal.js-light/decimal.mjs", "x.constructor = Decimal;", CTOR),
  stmt("node_modules/decimal.js-light/decimal.js", "x.constructor = Decimal;", CTOR),
  // d3-color
  stmt("node_modules/d3-color/dist/d3-color.js", "prototype.constructor = constructor;", D3_CTOR),
  stmt("node_modules/d3-color/dist/d3-color.mjs", "prototype.constructor = constructor;", D3_CTOR),
  stmt("node_modules/victory-vendor/lib-vendor/d3-color/src/define.js", "prototype.constructor = constructor;", D3_CTOR),
  // d3-format
  block("node_modules/d3-format/dist/d3-format.js", "FormatSpecifier.prototype.toString = function() {", D3_FMT, "\n};", "\n}});"),
  block("node_modules/d3-format/dist/d3-format.mjs", "FormatSpecifier.prototype.toString = function() {", D3_FMT, "\n};", "\n}});"),
  block("node_modules/victory-vendor/lib-vendor/d3-format/src/formatSpecifier.js", "FormatSpecifier.prototype.toString = function () {", D3_FMT, "\n};", "\n}});"),
  // echarts (EvilCharts): mockMethods copies every enumerable prototype key — including the
  // enumerable `constructor` created by the TypeScript __extends helper — onto a plain object.
  stmt("node_modules/echarts/lib/core/Scheduler.js", "target[name_1] = noop;", `Object.defineProperty(target, name_1, { value: noop, ${DESC} });`),
];

let failed = false;
const fail = (msg) => {
  console.error(`[patch-deps] ${msg}`);
  failed = true;
};

for (const p of PATCHES) {
  const file = root + p.file;
  if (!existsSync(file)) {
    fail(`missing ${p.file}`);
    continue;
  }
  let src = readFileSync(file, "utf8");
  if (p.type === "stmt") {
    if (src.includes(p.to)) continue;
    const count = src.split(p.from).length - 1;
    if (count !== 1) {
      fail(`expected exactly one "${p.from}" in ${p.file}, found ${count}`);
      continue;
    }
    writeFileSync(file, src.replace(p.from, p.to));
    console.log(`[patch-deps] patched ${p.file}: ${p.from}`);
    continue;
  }
  // Already patched (by this or an earlier revision of this script): the head is gone and
  // the marker is present. Correctness is proven by the runtime self-test below.
  if (src.includes(p.newHead) || (!src.includes(p.head) && src.includes(MARKER))) continue;
  const start = src.indexOf(p.head);
  const end = start === -1 ? -1 : src.indexOf(p.end, start);
  if (start === -1 || end === -1) {
    fail(`expected code not found in ${p.file}: ${p.head}`);
    continue;
  }
  src = src.slice(0, start) + p.newHead + src.slice(start + p.head.length, end) + p.newEnd + src.slice(end + p.end.length);
  writeFileSync(file, src);
  console.log(`[patch-deps] patched ${p.file}: ${p.head}`);
}

if (failed) process.exit(1);

// Self-test: load every patched module with Object.prototype frozen (as Tauri's
// freezePrototype does) and exercise the patched code paths.
const selfTest = `
'use strict';
Object.freeze(Object.prototype);
const { createRequire } = await import('node:module');
const req = createRequire(${JSON.stringify(root + "package.json")});
const color = await import(${JSON.stringify("file://" + root.replace(/\\/g, "/") + "node_modules/d3-color/dist/d3-color.mjs")});
const fmt = await import(${JSON.stringify("file://" + root.replace(/\\/g, "/") + "node_modules/d3-format/dist/d3-format.mjs")});
const Dec = (await import(${JSON.stringify("file://" + root.replace(/\\/g, "/") + "node_modules/decimal.js-light/decimal.mjs")})).default;
const echarts = await import(${JSON.stringify("file://" + root.replace(/\\/g, "/") + "node_modules/echarts/lib/core/Scheduler.js")});
const checks = [
  typeof echarts.default === 'function',
  color.rgb('#4c8dff').toString() === 'rgb(76, 141, 255)',
  color.hsl('red') instanceof color.hsl && Object.getOwnPropertyDescriptor(color.hsl.prototype, 'constructor').writable === true,
  String(fmt.formatSpecifier('.2f')) === ' >-.2f',
  fmt.format(',.2f')(12345.678) === '12,345.68',
  new Dec('1.1').plus(2).toString() === '3.1',
  +new Dec('2.5') === 2.5,
  req('decimal.js-light').prototype !== undefined && new (req('decimal.js-light'))('4').times(2).valueOf() === '8',
  req(${JSON.stringify(root + 'node_modules/victory-vendor/lib-vendor/d3-color/src/index.js')}).rgb('steelblue').toString() === 'rgb(70, 130, 180)',
  req(${JSON.stringify(root + 'node_modules/victory-vendor/lib-vendor/d3-format/src/index.js')}).format('.1%')(0.123) === '12.3%',
];
if (checks.some((ok) => !ok)) { console.error('[patch-deps] self-test values', checks); process.exit(1); }
`;
const { spawnSync } = await import("node:child_process");
const r = spawnSync(process.execPath, ["--input-type=module", "-e", selfTest], { encoding: "utf8" });
if (r.status !== 0) {
  console.error(`[patch-deps] self-test failed with a frozen Object.prototype:\n${r.stderr || r.stdout}`);
  process.exit(1);
}
console.log("[patch-deps] self-test passed: chart dependencies work with a frozen Object.prototype");
