#!/usr/bin/env node
// Third-party license policy, inventory and notices (Mission 12; categories, assets and notices since
// Mission 14). Only Node built-ins and `cargo`.
//
//   node scripts/licenses.mjs check     every Rust crate (Cargo.lock, all platforms) and npm package
//                                       (package-lock.json) at its locked version, and every file in
//                                       scripts/license-assets.json, has a license the policy in
//                                       scripts/license-policy.json accepts, or a current, reviewed
//                                       exception; the bundled notices file is up to date. Exits 1
//                                       otherwise (CI runs this).
//   node scripts/licenses.mjs notices   writes src-tauri/resources/THIRD_PARTY_LICENSES.txt, bundled
//                                       with every package: what ships, with each license text in full
//   node scripts/licenses.mjs report    writes the inventories under docs/governance/third-party/
//
// Licenses are read from package metadata (Cargo `license`, npm lockfile `license`) and license texts
// from the packages themselves, as published by their authors. Metadata can be wrong: the audit
// documents (docs/governance/) record what was checked by hand and what remains open.
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const POLICY = JSON.parse(readFileSync(join(ROOT, "scripts", "license-policy.json"), "utf8"));
const ASSETS = JSON.parse(readFileSync(join(ROOT, "scripts", "license-assets.json"), "utf8"));
const CAT = Object.fromEntries(Object.entries(POLICY.categories).map(([k, v]) => [k, new Set(v)]));
/** What may be included without a review: permissive, attribution and file-level source obligations. */
const ALLOWED = new Set([...CAT.permissive, ...CAT.attribution, ...CAT.sourceObligations]);
const OUT = join(ROOT, "docs", "governance", "third-party");
export const NOTICES_FILE = join(ROOT, "src-tauri", "resources", "THIRD_PARTY_LICENSES.txt");
const PLATFORMS = { windows: "x86_64-pc-windows-msvc", linux: "x86_64-unknown-linux-gnu" };

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

/** The license identifiers an expression names (`A WITH B` counts as one). */
export function leaves(expr) {
  const t = tokenize(expr);
  const out = [];
  for (let i = 0; i < t.length; i++) {
    if (/^(AND|OR|\(|\))$/i.test(t[i])) continue;
    if ((t[i + 1] || "").toUpperCase() === "WITH") {
      out.push(`${t[i].replace(/\+$/, "")} WITH ${t[i + 2]}`);
      i += 2;
    } else out.push(t[i].replace(/\+$/, ""));
  }
  return out;
}

/**
 * The policy's verdict on an expression, using only the license metadata:
 * * `allowed`: satisfiable with permissive, attribution and source-obligation licenses (`obligations`
 *   names the categories of the licenses it names beyond permissive);
 * * `review`: satisfiable only with a license that needs a review (for example LGPL);
 * * `prohibited`: every license it names is known, and none of the choices is allowed;
 * * `unknown`: missing, unreadable, or naming a license the policy does not know.
 * `data` entries may also use the dataOnly category.
 */
export function verdictOf(expr, { data = false, policy = CAT } = {}) {
  if (!expr || !String(expr).trim()) return { status: "unknown", reason: "no license in its metadata" };
  let names;
  try {
    names = leaves(expr);
    acceptable(expr, new Set());
  } catch (e) {
    return { status: "unknown", reason: `unreadable license "${expr}" (${e.message})` };
  }
  const allowed = new Set([...policy.permissive, ...policy.attribution, ...policy.sourceObligations, ...(data ? policy.dataOnly : [])]);
  const known = new Set([...allowed, ...policy.review, ...policy.prohibited, ...policy.dataOnly]);
  const obligations = [...new Set(names.flatMap((n) => (policy.attribution.has(n) ? ["attribution"] : policy.sourceObligations.has(n) ? ["source obligations"] : policy.dataOnly.has(n) ? ["data only"] : [])))];
  if (acceptable(expr, allowed)) return { status: "allowed", obligations };
  if (acceptable(expr, new Set([...allowed, ...policy.review]))) return { status: "review", reason: `"${expr}" needs a review (see docs/governance/DEPENDENCY_LICENSE_POLICY.md)` };
  const unknown = names.filter((n) => !known.has(n) && !known.has(n.split(" WITH ")[0]));
  if (unknown.length) return { status: "unknown", reason: `"${expr}" names a license the policy does not know (${unknown.join(", ")})` };
  return { status: "prohibited", reason: `"${expr}" is prohibited by the policy` };
}

/** Problems with an exception: it needs the license it covers, a reason, and review dates not in the past. */
export function exceptionProblems(e, today = new Date().toISOString().slice(0, 10)) {
  const p = [];
  const who = `the exception for ${e.ecosystem} ${e.name}`;
  if (!e.license) p.push(`${who} does not name the license it covers`);
  if (!e.reason || e.reason.length < 40) p.push(`${who} has no reason`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(e.reviewed || "")) p.push(`${who} has no review date (reviewed: YYYY-MM-DD)`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(e.reviewBy || "")) p.push(`${who} has no next review date (reviewBy: YYYY-MM-DD)`);
  else if (e.reviewBy < today) p.push(`${who} was due for review on ${e.reviewBy}`);
  return p;
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

/** The crates compiled into the Windows or the Linux build. */
function shippedCrates() {
  const out = new Map();
  for (const target of Object.values(PLATFORMS)) {
    const c = classify(cargoMetadata(target));
    for (const [id, s] of c.scope) if (s === "ships" && c.byId.get(id).source !== null) out.set(id, c.byId.get(id));
  }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version, undefined, { numeric: true }));
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

function exceptionFor(ecosystem, name, license) {
  return POLICY.exceptions.find((e) => e.ecosystem === ecosystem && e.name === name && e.license === license);
}

/** Every tracked file under the covered directories needs an entry; every entry's path must exist. */
function assetProblems() {
  const problems = [];
  const tracked = execFileSync("git", ["ls-files", "--", ...ASSETS.covers], { cwd: ROOT, encoding: "utf8" }).split("\n").filter(Boolean);
  const covered = (f) => ASSETS.entries.some((e) => (e.path.endsWith("/") ? f.startsWith(e.path) : f === e.path));
  for (const f of tracked) if (!covered(f)) problems.push(`${f}: no entry in scripts/license-assets.json (copied code and bundled data need their source and license)`);
  for (const e of ASSETS.entries) {
    if (!existsSync(join(ROOT, e.path))) problems.push(`scripts/license-assets.json: ${e.path} does not exist`);
    if (e.kind === "project") {
      if (e.license !== "LicenseRef-ExploitX") problems.push(`${e.path}: project files are under the project's license (LicenseRef-ExploitX)`);
      continue;
    }
    if (!e.source || !e.copyright) problems.push(`${e.path}: name its source and copyright`);
    const v = verdictOf(e.license, { data: e.kind === "data" });
    if (v.status !== "allowed") problems.push(`${e.path}: ${v.reason}`);
  }
  return problems;
}

function check() {
  const problems = [];
  const counts = { allowed: 0, exception: 0 };
  const verdict = (ecosystem, name, version, license) => {
    const v = verdictOf(license);
    if (v.status === "allowed") return void counts.allowed++;
    if (exceptionFor(ecosystem, name, license)) return void counts.exception++;
    problems.push(`${ecosystem} ${name} ${version}: ${v.reason}`);
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
  for (const p of npmPackages("package-lock.json")) {
    npm++;
    verdict("npm", p.name, p.version, p.license);
  }
  for (const e of POLICY.exceptions) problems.push(...exceptionProblems(e));
  problems.push(...assetProblems());
  // the bundled notices must describe what ships now
  const expected = buildNotices();
  const actual = existsSync(NOTICES_FILE) ? readFileSync(NOTICES_FILE, "utf8") : "";
  if (actual !== expected) problems.push(`${NOTICES_FILE.slice(ROOT.length + 1).replace(/\\/g, "/")} is out of date: run \`node scripts/licenses.mjs notices\` and commit it`);
  console.log(`checked ${crates} Rust crates, ${npm} npm packages and ${ASSETS.entries.length} asset entries against scripts/license-policy.json (${POLICY.exceptions.length} reviewed exceptions, ${counts.exception} in use)`);
  if (problems.length) {
    for (const p of problems) console.log(`::error::${p}`);
    console.log("A new license needs a review: see docs/governance/DEPENDENCY_LICENSE_POLICY.md.");
    process.exit(1);
  }
  console.log("every dependency and asset has an accepted license, and the bundled notices are up to date");
}

/* ───────────── notices ───────────── */

const LICENSE_FILE = /^(licen[cs]e|copying|notice|unlicense|copyright)([-._].*)?$/i;
const normalize = (s) => s.replace(/\r\n?/g, "\n").replace(/\s+$/, "") + "\n";

/** The license and notice files a package ships, verbatim (line endings normalized). */
function licenseFiles(dir) {
  if (!existsSync(dir)) throw new Error(`${dir} is missing: run npm ci (npm) or cargo fetch (Rust) first`);
  return readdirSync(dir)
    .filter((f) => LICENSE_FILE.test(f) && !/\.(rs|toml|js|ts|json|sh|py|yml|yaml|html)$/i.test(f) && statSync(join(dir, f)).isFile())
    .sort()
    .map((f) => ({ file: f, text: normalize(readFileSync(join(dir, f), "utf8")) }));
}

/** For a package without license files: the standard text of the first license its expression allows. */
function standardText(expr, holders) {
  const id = leaves(expr).find((n) => ALLOWED.has(n) && existsSync(join(ROOT, "scripts", "license-texts", `${n}.txt`)));
  if (!id) throw new Error(`no license file and no standard text for "${expr}": add scripts/license-texts/<id>.txt`);
  const text = normalize(readFileSync(join(ROOT, "scripts", "license-texts", `${id}.txt`), "utf8"));
  return { file: `${id} (standard text; the package includes no license file)`, text: `Copyright holders as declared by the package: ${holders || "not declared"}\n\n${text}` };
}

export function buildNotices() {
  const version = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;
  const texts = new Map(); // hash → { text, users: [] }
  const ref = (pkg, files) => {
    const ids = [];
    for (const f of files) {
      const h = createHash("sha256").update(f.text).digest("hex");
      if (!texts.has(h)) texts.set(h, { text: f.text, users: [] });
      texts.get(h).users.push(`${pkg} (${f.file})`);
      ids.push(h);
    }
    return ids;
  };
  const crates = shippedCrates().map((p) => {
    let files = licenseFiles(dirname(p.manifest_path));
    if (!files.some((f) => !/^notice/i.test(f.file))) files = [...files, standardText(p.license, (p.authors || []).join(", "))];
    return { name: p.name, line: `${p.name} ${p.version}`, license: p.license || "(none)", ids: ref(`${p.name} ${p.version}`, files) };
  });
  const mpl = crates.filter((c) => leaves(c.license).includes("MPL-2.0")).map((c) => c.name);
  const npm = npmPackages("package-lock.json")
    .filter((p) => !p.dev)
    .sort((a, b) => a.name.localeCompare(b.name) || String(a.version).localeCompare(String(b.version)))
    .map((p) => {
      const dir = join(ROOT, p.path);
      let files = licenseFiles(dir);
      if (!files.some((f) => !/^notice/i.test(f.file))) {
        const pj = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
        const author = typeof pj.author === "string" ? pj.author : pj.author?.name;
        files = [...files, standardText(p.license, author)];
      }
      return { line: `${p.name} ${p.version}`, license: p.license, ids: ref(`${p.name} ${p.version}`, files) };
    });
  const order = [...texts.keys()].sort((a, b) => texts.get(a).users[0].localeCompare(texts.get(b).users[0]));
  const num = new Map(order.map((h, i) => [h, i + 1]));
  const list = (rows) => rows.map((r) => `  ${r.line}  —  ${r.license}  [text ${r.ids.map((h) => num.get(h)).join(", ")}]`).join("\n");
  const assets = ASSETS.entries.filter((e) => e.kind !== "project").map((e) => `  ${e.path}\n    ${e.source}. ${e.copyright}. License: ${e.license}.`).join("\n");
  const notices = normalize(readFileSync(join(ROOT, "THIRD_PARTY_NOTICES.md"), "utf8"));
  const parts = [
    `ExploitX ${version}: third-party software and data licenses`,
    "=".repeat(60),
    "",
    "ExploitX includes the third-party software and data listed below. Each part is used under its own license;",
    "the license texts are reproduced in full in section 5, as published by each package. ExploitX's own license is",
    "pending selection by its owner (see the project README).",
    "",
    "Source code: every Rust crate in section 1 is published at the version listed on crates.io",
    "(https://crates.io/crates/<name>/<version>) and is compiled unmodified; this includes the files under the",
    `Mozilla Public License 2.0 (${mpl.join(", ") || "none"}). Every JavaScript package in section 2 is`,
    "published at the version listed on the npm registry (https://www.npmjs.com/package/<name>); a few are",
    "patched when installed so that they work with the app's frozen JavaScript prototypes (scripts/patch-deps.mjs",
    "in the ExploitX repository names them).",
    "",
    "Generated by `node scripts/licenses.mjs notices` from src-tauri/Cargo.lock, package-lock.json,",
    "scripts/license-assets.json and THIRD_PARTY_NOTICES.md. Do not edit by hand.",
    "",
    "1. Rust crates compiled into ExploitX (Windows and Linux builds)",
    "",
    list(crates),
    "",
    "2. JavaScript packages bundled into ExploitX's interface (runtime dependencies)",
    "",
    list(npm),
    "",
    "3. Copied code and bundled data",
    "",
    assets,
    "",
    "4. Native libraries",
    "",
    "  Windows installers (NSIS, MSI): no third-party native library is bundled. The Microsoft Edge WebView2",
    "  Runtime is installed by Microsoft's bootstrapper when it is missing; it is not redistributed by ExploitX.",
    "  deb and rpm packages: no third-party native library is bundled; the packages depend on the system's",
    "  WebKitGTK and GTK packages, installed by the package manager under their own licenses.",
    "  AppImage: bundles libraries of the build system (GTK, WebKitGTK and their dependencies). Their list,",
    "  licenses, copyright files and source availability are in usr/share/doc/exploitx-appimage/ inside the",
    "  AppImage (see docs/governance/DISTRIBUTION_LICENSE_COMPLIANCE.md in the project repository).",
    "",
    "5. License texts",
    "",
    ...order.flatMap((h) => {
      const t = texts.get(h);
      return [`----- [text ${num.get(h)}] used by: ${t.users.join("; ")}`, "", t.text];
    }),
    "6. THIRD_PARTY_NOTICES.md (copied components, fonts, icons and data, with their notices)",
    "",
    notices,
  ];
  return parts.join("\n");
}

function notices() {
  mkdirSync(dirname(NOTICES_FILE), { recursive: true });
  const text = buildNotices();
  writeFileSync(NOTICES_FILE, text);
  console.log(`wrote ${NOTICES_FILE.slice(ROOT.length + 1)} (${(text.length / 1024).toFixed(0)} KiB)`);
}

/* ───────────── report ───────────── */

const esc = (s) => String(s ?? "").replace(/\|/g, "\\|");

function report() {
  mkdirSync(OUT, { recursive: true });
  const all = cargoMetadata(null);
  const per = Object.fromEntries(Object.entries(PLATFORMS).map(([k, t]) => [k, classify(cargoMetadata(t))]));
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
  const category = (license) => {
    const v = verdictOf(license);
    return v.status === "allowed" ? (v.obligations.length ? v.obligations.join(", ") : "permissive") : v.status;
  };
  const rows = all.packages
    .filter((p) => p.id !== rootId)
    .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version, undefined, { numeric: true }))
    .map((p) => `| ${esc(p.name)} | ${esc(p.version)} | ${esc(p.license || "(none)")} | ${category(p.license)} | ${esc(p.repository || `https://crates.io/crates/${p.name}`)} | ${directKinds.has(p.id) ? `direct (${directKinds.get(p.id)})` : "transitive"} | ${where(p.id)} |`);
  const counts = Object.fromEntries(Object.entries(per).map(([k, c]) => [k, [...c.scope.values()].filter((s) => s === "ships").length]));
  writeFileSync(
    join(OUT, "RUST_CRATES.md"),
    `# Rust crates: license inventory

Generated by \`node scripts/licenses.mjs report\` from \`src-tauri/Cargo.lock\` (ExploitX ${JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version}). Licenses as declared in each crate's metadata; the policy category from scripts/license-policy.json. Reviewed in [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md).

* **${rows.length} crates** in the lock file, for every platform.
* **Ships in the app:** ${counts.windows} on Windows, ${counts.linux} on Linux. These are linked into \`cyber-hub\`, \`cyberhub-mcp\` or \`cyberhub-keys\` through normal dependencies, proc-macros excluded. Their license texts are bundled with every package (\`THIRD_PARTY_LICENSES.txt\`).
* **build:** only build scripts and proc-macros use it. **test:** only tests use it.
* **other platforms only:** macOS, iOS or Android code that the Windows and Linux builds do not compile.

| Crate | Version | License | Policy category | Source | Dependency of ExploitX | Where it is used |
|---|---|---|---|---|---|---|
${rows.join("\n")}
`,
  );
  const pk = npmPackages("package-lock.json").sort((a, b) => a.name.localeCompare(b.name) || String(a.version).localeCompare(String(b.version)));
  const body = pk.map((p) => `| ${esc(p.name)} | ${esc(p.version)} | ${esc(p.license || "(none)")} | ${category(p.license)} | https://www.npmjs.com/package/${p.name} | ${p.direct ? `direct (${p.direct})` : "transitive"} | ${p.dev ? "development only" : p.optional ? "runtime (optional)" : "runtime"} |`);
  writeFileSync(
    join(OUT, "NPM_PACKAGES.md"),
    `# npm packages of the desktop app: license inventory

Generated by \`node scripts/licenses.mjs report\` from \`package-lock.json\`. Licenses as declared in the lock file (from each package's \`package.json\`); the policy category from scripts/license-policy.json. Reviewed in [THIRD_PARTY_LICENSE_AUDIT.md](../THIRD_PARTY_LICENSE_AUDIT.md).

Runtime packages can end up in the app's web assets: Vite bundles what the frontend imports, and their license texts are bundled with every package (\`THIRD_PARTY_LICENSES.txt\`). Development packages (Vite, TypeScript, Vitest, the Tauri CLI and their dependencies) build or test the app and are not part of it.

* **${pk.length} packages:** ${pk.filter((p) => !p.dev).length} runtime, ${pk.filter((p) => p.dev).length} development only.

| Package | Version | License | Policy category | Source | Dependency | Scope |
|---|---|---|---|---|---|---|
${body.join("\n")}
`,
  );
  console.log(`wrote ${rows.length} crates and the npm inventory to docs/governance/third-party/`);
}

// run only as a program (the tests import the pure functions)
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const cmd = process.argv[2];
  if (cmd === "check") check();
  else if (cmd === "notices") notices();
  else if (cmd === "report") report();
  else {
    console.log("usage: node scripts/licenses.mjs check | notices | report");
    process.exit(2);
  }
}
