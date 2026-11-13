#!/usr/bin/env node
// Third-party license inventory and policy check (Mission 12). Only Node built-ins and `cargo`.
//
//   node scripts/licenses.mjs check    every Rust crate (Cargo.lock, all platforms) and npm package
//                                      (package-lock.json, website/package-lock.json) has a license
//                                      the policy in scripts/license-policy.json accepts, or a
//                                      reviewed exception; exits 1 otherwise (CI runs this)
//   node scripts/licenses.mjs report   writes the per-dependency inventories under
//                                      docs/governance/third-party/ (regenerate after dependency
//                                      changes; reviewed in docs/governance/THIRD_PARTY_LICENSE_AUDIT.md)
//
// Licenses are read from package metadata (Cargo `license`, npm lockfile `license`), as published by
// each package's authors. Metadata can be wrong or incomplete: the audit document records what was
// checked by hand (vendored code, assets, native libraries) and what remains open.
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const POLICY = JSON.parse(readFileSync(join(ROOT, "scripts", "license-policy.json"), "utf8"));
const ALLOWED = new Set(POLICY.allowed);
const OUT = join(ROOT, "docs", "governance", "third-party");

/* ───────────── SPDX expressions ───────────── */

/** Tokens of an SPDX expression; the old Cargo form `MIT/Apache-2.0` means `MIT OR Apache-2.0`. */
export function tokenize(expr) {
  return expr
    .replace(/\s*\/\s*/g, " OR ")
    .replace(/\(/g, " ( ")
    .replace(/\)/g, " ) ")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
}

/** Whether `expr` can be satisfied with licenses in `allowed` (OR: either side; AND: both; a
 * `WITH` exception only adds permissions, so `X WITH E` is acceptable when X is). */
export function acceptable(expr, allowed = ALLOWED) {
  const t = tokenize(expr);
  let i = 0;
  const peek = () => t[i];
  const next = () => t[i++];
  const primary = () => {
    const tok = next();
    if (tok === undefined) throw new Error(`incomplete expression "${expr}"`);
    if (tok === "(") {
      const v = orExpr();
      if (next() !== ")") throw new Error(`unbalanced parentheses in "${expr}"`);
      return v;
    }
    if (["AND", "OR", "WITH", ")"].includes(tok.toUpperCase())) throw new Error(`unexpected "${tok}" in "${expr}"`);
    let ok = allowed.has(tok) || allowed.has(tok.replace(/\+$/, ""));
    if ((peek() || "").toUpperCase() === "WITH") {
      next();
      const exception = next();
      ok = ok || allowed.has(`${tok} WITH ${exception}`);
    }
    return ok;
  };
  const andExpr = () => {
    let v = primary();
    while ((peek() || "").toUpperCase() === "AND") {
      next();
      v = primary() && v;
    }
    return v;
  };
  const orExpr = () => {
    let v = andExpr();
    while ((peek() || "").toUpperCase() === "OR") {
      next();
      v = andExpr() || v;
    }
    return v;
  };
  const v = orExpr();
  if (i !== t.length) throw new Error(`trailing tokens in "${expr}"`);
  return v;
}

/* ───────────── Rust ───────────── */

function cargoMetadata(platform) {
  const args = ["metadata", "--locked", "--format-version", "1", "--manifest-path", join(ROOT, "src-tauri", "Cargo.toml")];
  if (platform) args.push("--filter-platform", platform);
  return JSON.parse(execFileSync("cargo", args, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 }));
}

/** For one platform's resolved graph: which packages ship in the binary (reached from the app
 * through normal dependencies, proc-macros excluded), which are build-time only (build scripts,
 * proc-macros and what they use) and which only serve tests. */
function classify(meta) {
  const byId = new Map(meta.packages.map((p) => [p.id, p]));
  const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
  const rootId = meta.resolve.root;
  const isProcMacro = (id) => byId.get(id).targets.some((t) => t.kind.includes("proc-macro"));
  const walk = (starts, kinds) => {
    const seen = new Set();
    const stack = [...starts];
    while (stack.length) {
      const id = stack.pop();
      if (seen.has(id)) continue;
      seen.add(id);
      for (const d of nodes.get(id).deps) if (d.dep_kinds.some((k) => kinds.includes(k.kind))) stack.push(d.pkg);
    }
    return seen;
  };
  const root = nodes.get(rootId);
  const normalFromRoot = root.deps.filter((d) => d.dep_kinds.some((k) => k.kind === null)).map((d) => d.pkg);
  const buildFromRoot = root.deps.filter((d) => d.dep_kinds.some((k) => k.kind === "build")).map((d) => d.pkg);
  // what the app links: normal edges, not through proc-macros (they run in the compiler)
  const ships = new Set();
  const stack = normalFromRoot.filter((id) => !isProcMacro(id));
  while (stack.length) {
    const id = stack.pop();
    if (ships.has(id)) continue;
    ships.add(id);
    for (const d of nodes.get(id).deps) if (d.dep_kinds.some((k) => k.kind === null) && !isProcMacro(d.pkg)) stack.push(d.pkg);
  }
  const build = walk([...normalFromRoot, ...buildFromRoot], [null, "build"]);
  const scope = new Map();
  for (const id of nodes.keys()) {
    if (id === rootId) continue;
    scope.set(id, ships.has(id) ? "ships" : build.has(id) ? "build" : "test");
  }
  const direct = new Map(root.deps.map((d) => [d.pkg, [...new Set(d.dep_kinds.map((k) => k.kind || "normal"))].join(", ")]));
  return { byId, scope, direct, rootId };
}

/* ───────────── npm ───────────── */

function npmPackages(lockfile) {
  const lock = JSON.parse(readFileSync(join(ROOT, lockfile), "utf8"));
  const rootDeps = lock.packages[""] || {};
  const directRuntime = new Set(Object.keys(rootDeps.dependencies || {}));
  const directDev = new Set(Object.keys(rootDeps.devDependencies || {}));
  return Object.entries(lock.packages)
    .filter(([path]) => path)
    .map(([path, p]) => {
      const name = p.name || path.slice(path.lastIndexOf("node_modules/") + "node_modules/".length);
      const direct = !path.slice("node_modules/".length).includes("node_modules/") ? (directRuntime.has(name) ? "runtime" : directDev.has(name) ? "dev" : "") : "";
      return { name, version: p.version, license: p.license || "", dev: !!p.dev, optional: !!p.optional, direct, path };
    });
}

/* ───────────── check ───────────── */

function exceptionFor(ecosystem, name) {
  return POLICY.exceptions.find((e) => e.ecosystem === ecosystem && e.name === name);
}

function check() {
  const problems = [];
  const verdict = (ecosystem, name, version, license) => {
    if (exceptionFor(ecosystem, name)) return;
    if (!license) return problems.push(`${ecosystem} ${name} ${version}: no license in its metadata`);
    let ok;
    try {
      ok = acceptable(license);
    } catch (e) {
      return problems.push(`${ecosystem} ${name} ${version}: unreadable license "${license}" (${e.message})`);
    }
    if (!ok) problems.push(`${ecosystem} ${name} ${version}: "${license}" is not accepted by scripts/license-policy.json`);
  };
  const meta = cargoMetadata(null);
  const roots = new Set(meta.workspace_members);
  let crates = 0;
  for (const p of meta.packages) {
    if (roots.has(p.id)) continue;
    crates++;
    verdict("cargo", p.name, p.version, p.license);
  }
  let npm = 0;
  for (const lockfile of ["package-lock.json", "website/package-lock.json"]) {
    for (const p of npmPackages(lockfile)) {
      npm++;
      verdict(lockfile.startsWith("website") ? "npm-website" : "npm", p.name, p.version, p.license);
    }
  }
  for (const e of POLICY.exceptions) if (!e.reason) problems.push(`the exception for ${e.ecosystem} ${e.name} has no reason`);
  console.log(`checked ${crates} Rust crates and ${npm} npm packages against scripts/license-policy.json (${POLICY.exceptions.length} reviewed exceptions)`);
  if (problems.length) {
    for (const p of problems) console.log(`::error::${p}`);
    console.log("A new license needs a review: see CONTRIBUTING.md, \"Dependencies\".");
    process.exit(1);
  }
  console.log("every dependency has an accepted license");
}

/* ───────────── report ───────────── */

const esc = (s) => String(s ?? "").replace(/\|/g, "\\|");

function report() {
  mkdirSync(OUT, { recursive: true });
  const platforms = { windows: "x86_64-pc-windows-msvc", linux: "x86_64-unknown-linux-gnu" };
  const all = cargoMetadata(null);
  const per = Object.fromEntries(Object.entries(platforms).map(([k, t]) => [k, classify(cargoMetadata(t))]));
  const rootId = all.workspace_members[0];
  const rootNode = all.resolve.nodes.find((n) => n.id === rootId);
  const directKinds = new Map(rootNode.deps.map((d) => [d.pkg, [...new Set(d.dep_kinds.map((k) => k.kind || "normal"))].join(", ")]));
  const where = (id) => {
    const parts = [];
    for (const [k, c] of Object.entries(per)) {
      const s = c.scope.get(id);
      if (s) parts.push(`${k}: ${s}`);
    }
    return parts.length ? parts.join("; ") : "other platforms only";
  };
  const rows = all.packages
    .filter((p) => p.id !== rootId)
    .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version, undefined, { numeric: true }))
    .map((p) => `| ${esc(p.name)} | ${esc(p.version)} | ${esc(p.license || "(none)")} | ${esc(p.repository || `https://crates.io/crates/${p.name}`)} | ${directKinds.has(p.id) ? `direct (${directKinds.get(p.id)})` : "transitive"} | ${where(p.id)} |`);
  const counts = Object.fromEntries(Object.entries(per).map(([k, c]) => [k, [...c.scope.values()].filter((s) => s === "ships").length]));
  writeFileSync(
    join(OUT, "RUST_CRATES.md"),
    `# Rust crates: license inventory

Generated by \`node scripts/licenses.mjs report\` from \`src-tauri/Cargo.lock\` (Cyber Hub ${JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version}). Licenses as declared in each crate's metadata. Reviewed in [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md).

* **${rows.length} crates** in the lock file, for every platform.
* **Ships in the app:** ${counts.windows} on Windows, ${counts.linux} on Linux. These are linked into \`cyber-hub\`, \`cyberhub-mcp\` or \`cyberhub-keys\` through normal dependencies, proc-macros excluded.
* **build:** only build scripts and proc-macros use it. **test:** only tests use it.
* **other platforms only:** macOS, iOS or Android code that the Windows and Linux builds do not compile.

| Crate | Version | License | Source | Dependency of Cyber Hub | Where it is used |
|---|---|---|---|---|---|
${rows.join("\n")}
`,
  );
  const npmTable = (lockfile, title, intro) => {
    const pk = npmPackages(lockfile).sort((a, b) => a.name.localeCompare(b.name) || String(a.version).localeCompare(String(b.version)));
    const body = pk.map((p) => `| ${esc(p.name)} | ${esc(p.version)} | ${esc(p.license || "(none)")} | https://www.npmjs.com/package/${p.name} | ${p.direct ? `direct (${p.direct})` : "transitive"} | ${p.dev ? "development only" : p.optional ? "runtime (optional)" : "runtime"} |`);
    return `# ${title}

Generated by \`node scripts/licenses.mjs report\` from \`${lockfile}\`. Licenses as declared in the lock file (from each package's \`package.json\`). Reviewed in [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md).

${intro}

* **${pk.length} packages:** ${pk.filter((p) => !p.dev).length} runtime, ${pk.filter((p) => p.dev).length} development only.

| Package | Version | License | Source | Dependency | Scope |
|---|---|---|---|---|---|
${body.join("\n")}
`;
  };
  writeFileSync(
    join(OUT, "NPM_PACKAGES.md"),
    npmTable(
      "package-lock.json",
      "npm packages of the desktop app: license inventory",
      "Runtime packages can end up in the app's web assets: Vite bundles what the frontend imports. Development packages (Vite, TypeScript, Vitest, the Tauri CLI and their dependencies) build or test the app and are not part of it.",
    ),
  );
  writeFileSync(
    join(OUT, "WEBSITE_NPM_PACKAGES.md"),
    npmTable("website/package-lock.json", "npm packages of the website: license inventory", "`website/` is the separate marketing site. It is not part of the desktop app or its installers, and it is not deployed."),
  );
  console.log(`wrote ${rows.length} crates and the npm inventories to docs/governance/third-party/`);
}

// run only as a program (the tests import acceptable() and tokenize())
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const cmd = process.argv[2];
  if (cmd === "check") check();
  else if (cmd === "report") report();
  else {
    console.log("usage: node scripts/licenses.mjs check | report");
    process.exit(2);
  }
}
