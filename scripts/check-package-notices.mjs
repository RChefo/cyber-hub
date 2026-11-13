#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Every release package carries ExploitX's license and the third-party notices (Missions 14 and 15).
// The release workflow runs it on the signed packages of each build, before they are uploaded:
//
//   node scripts/check-package-notices.mjs <dir>
//
// * Windows: the NSIS installer (listed with 7-Zip) and the MSI (its File table, read through the
//   Windows Installer API, nothing installed) contain LICENSE, NOTICE and THIRD_PARTY_LICENSES.txt.
// * Linux: the deb (/usr/share/doc/cyber-hub/), the rpm (/usr/share/licenses/cyber-hub/) and the
//   AppImage contain them. The AppImage also carries the copyright file of every library it bundles and
//   the license texts those files refer to, and the source archive next to it holds, at the shipped
//   versions and with verified checksums, the source package of every GPL/LGPL library
//   (scripts/appimage-licenses.sh --check).
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
export const NOTICES = "THIRD_PARTY_LICENSES.txt";
/** The generated file is about 1 MB; anything much smaller is not the full text. */
export const MIN_SIZE = 500_000;
export const LINUX_PATHS = { deb: "/usr/share/doc/cyber-hub/THIRD_PARTY_LICENSES.txt", rpm: "/usr/share/licenses/cyber-hub/THIRD_PARTY_LICENSES.txt" };
/** Where the deb and rpm also install the license files (Debian's and Fedora's places for them). */
export const LINUX_DIRS = { deb: "/usr/share/doc/cyber-hub/", rpm: "/usr/share/licenses/cyber-hub/" };
/** The files every package must carry, with a size below which the file cannot be the full text. */
export const REQUIRED = [
  { name: NOTICES, min: MIN_SIZE },
  // the official Apache License 2.0 text is 11,358 bytes
  { name: "LICENSE", min: 11_000 },
  { name: "NOTICE", min: 200 },
];

/** `7z l -slt` output: one block of `Key = value` lines per entry. */
export function parse7zSlt(text) {
  const entries = [];
  let cur = null;
  for (const line of text.split(/\r?\n/)) {
    const m = /^(Path|Size) = (.*)$/.exec(line);
    if (!m) continue;
    if (m[1] === "Path") entries.push((cur = { path: m[2], size: null }));
    else if (cur) cur.size = Number(m[2]);
  }
  return entries;
}

/** `dpkg-deb -c` output: `-rw-r--r-- 0/0 1087996 2026-11-13 12:00 usr/share/…` (or `./usr/…`), as absolute paths. */
export function parseDpkgList(text) {
  return text
    .split(/\r?\n/)
    .map((l) => /^\S+\s+\S+\s+(\d+)\s+\S+\s+\S+\s+(?:\.\/|\/)?(.+?)(?: -> .*)?$/.exec(l))
    .filter(Boolean)
    .map((m) => ({ path: `/${m[2]}`, size: Number(m[1]) }));
}

/** `rpm -qlp --dump` output: `path size mtime digest mode owner group …`. */
export function parseRpmDump(text) {
  return text
    .split(/\r?\n/)
    .map((l) => /^(\/\S.*?) (\d+) \d+ /.exec(l))
    .filter(Boolean)
    .map((m) => ({ path: m[1], size: Number(m[2]) }));
}

/** MSI File table rows as `FileName<TAB>FileSize`; FileName is `SHORT~1.TXT|long name.txt` or one name. */
export function parseMsiFiles(text) {
  return text
    .split(/\r?\n/)
    .map((l) => l.split("\t"))
    .filter((c) => c.length >= 2 && /^\d+$/.test(c[1].trim()))
    .map(([name, size]) => ({ path: name.split("|").pop(), size: Number(size) }));
}

/** Problems with the notices among a package's entries (`path` may be the exact path to require). */
export function noticesProblems(pkg, entries, path = null) {
  const hits = entries.filter((e) => (path ? e.path === path : basename(e.path.replace(/\\/g, "/")) === NOTICES));
  if (!hits.length) return [`${pkg} does not contain ${path ?? NOTICES}`];
  if (!hits.some((e) => e.size >= MIN_SIZE)) return [`${pkg}: ${NOTICES} is ${hits.map((e) => e.size).join(", ")} bytes, not the full notices`];
  return [];
}

/** Problems with one required file among a package's entries (`path`: the exact path to require). */
export function fileProblems(pkg, entries, { name, min }, path = null) {
  const hits = entries.filter((e) => (path ? e.path === path : basename(e.path.replace(/\\/g, "/")) === name));
  if (!hits.length) return [`${pkg} does not contain ${path ?? name}`];
  if (!hits.some((e) => e.size >= min)) return [`${pkg}: ${name} is ${hits.map((e) => e.size).join(", ")} bytes, too small to be the full text`];
  return [];
}

/** Problems with all required files; `dir` (deb, rpm) requires them in that directory. */
export function packageProblems(pkg, entries, dir = null) {
  return REQUIRED.flatMap((r) => fileProblems(pkg, entries, r, dir ? dir + r.name : null));
}

const run = (cmd, args, opts = {}) => execFileSync(cmd, args, { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, ...opts });

/** Lists the MSI's File table read-only (database open mode 0); nothing is installed or changed. */
const MSI_FILES = [
  "$ErrorActionPreference = 'Stop'",
  "$installer = New-Object -ComObject WindowsInstaller.Installer",
  "$db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($env:MSI_PATH, 0))",
  "$view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @('SELECT FileName, FileSize FROM File'))",
  "[void]$view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)",
  "while ($row = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)) {",
  "  $name = $row.GetType().InvokeMember('StringData', 'GetProperty', $null, $row, 1)",
  "  $size = $row.GetType().InvokeMember('IntegerData', 'GetProperty', $null, $row, 2)",
  "  $name + [char]9 + $size",
  "}",
  "[void]$view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null)",
].join("\n");

/** The files an MSI installs, with their sizes (Windows only). */
export function msiFiles(path) {
  return parseMsiFiles(run("powershell", ["-NoProfile", "-NonInteractive", "-Command", MSI_FILES], { env: { ...process.env, MSI_PATH: resolve(path) } }));
}

function windows(dir, files) {
  const problems = [];
  const setup = files.filter((f) => f.endsWith("-setup.exe"));
  const msi = files.filter((f) => f.endsWith(".msi"));
  if (!setup.length) problems.push("no NSIS installer (*-setup.exe)");
  if (!msi.length) problems.push("no MSI");
  for (const f of setup) problems.push(...packageProblems(f, parse7zSlt(run("7z", ["l", "-slt", join(dir, f)]))));
  for (const f of msi) problems.push(...packageProblems(f, msiFiles(join(dir, f))));
  return problems;
}

function linux(dir, files) {
  const problems = [];
  const one = (re, what) => {
    const hits = files.filter((f) => re.test(f));
    if (hits.length !== 1) problems.push(`expected one ${what}, found ${hits.length}`);
    return hits[0];
  };
  const deb = one(/\.deb$/, "deb");
  const rpm = one(/\.rpm$/, "rpm");
  const appimage = one(/\.AppImage$/, "AppImage");
  const sources = one(/-sources_.*\.tar$/, "source archive of the AppImage's libraries");
  if (deb) problems.push(...packageProblems(deb, parseDpkgList(run("dpkg-deb", ["-c", join(dir, deb)])), LINUX_DIRS.deb));
  if (rpm) problems.push(...packageProblems(rpm, parseRpmDump(run("rpm", ["-qlp", "--dump", join(dir, rpm)])), LINUX_DIRS.rpm));
  if (appimage) {
    const work = mkdtempSync(join(tmpdir(), "appimage-"));
    try {
      run("cp", [join(dir, appimage), join(work, "app.AppImage")]);
      run("chmod", ["+x", join(work, "app.AppImage")]);
      run(join(work, "app.AppImage"), ["--appimage-extract"], { cwd: work, stdio: ["ignore", "ignore", "inherit"] });
      const root = join(work, "squashfs-root");
      // the app's resources (usr/lib/<product>/), not the libraries' copyright folder
      const found = run("find", [join(root, "usr", "lib"), "-maxdepth", "2", "-type", "f", "(", ...REQUIRED.flatMap((r, i) => (i ? ["-o", "-name", r.name] : ["-name", r.name])), ")"])
        .split("\n")
        .filter(Boolean)
        .map((p) => ({ path: p, size: statSync(p).size }));
      problems.push(...packageProblems(appimage, found));
      try {
        const args = [join(ROOT, "scripts", "appimage-licenses.sh"), "--check", root];
        if (sources) args.push("--sources", join(dir, sources));
        process.stdout.write(run("bash", args));
      } catch (e) {
        problems.push(`${appimage}: ${String(e.stderr || e.message).trim()}`);
      }
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
  return problems;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const dir = process.argv[2];
  if (!dir) {
    console.log("usage: node scripts/check-package-notices.mjs <dir with the release packages>");
    process.exit(2);
  }
  const files = readdirSync(dir).filter((f) => !f.endsWith(".sig"));
  const problems = process.platform === "win32" ? windows(dir, files) : linux(dir, files);
  if (problems.length) {
    for (const p of problems) console.log(`::error::${p}`);
    process.exit(1);
  }
  console.log(`every package in ${dir} carries LICENSE, NOTICE and the third-party notices`);
}
