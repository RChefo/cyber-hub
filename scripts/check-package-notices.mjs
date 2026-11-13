#!/usr/bin/env node
// Every release package carries the third-party notices (Mission 14). The release workflow runs it on
// the signed packages of each build, before they are uploaded:
//
//   node scripts/check-package-notices.mjs <dir>
//
// * Windows: the NSIS installer (listed with 7-Zip) and the MSI (its File table, read through the
//   Windows Installer API, nothing installed) contain THIRD_PARTY_LICENSES.txt at full size.
// * Linux: the deb (/usr/share/doc/cyber-hub/), the rpm (/usr/share/licenses/cyber-hub/) and the
//   AppImage contain it; the AppImage also carries the copyright file of every library it bundles
//   (scripts/appimage-licenses.sh --check), and the source packages of those libraries are next to it.
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
  for (const f of setup) problems.push(...noticesProblems(f, parse7zSlt(run("7z", ["l", "-slt", join(dir, f)]))));
  for (const f of msi) problems.push(...noticesProblems(f, msiFiles(join(dir, f))));
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
  if (deb) problems.push(...noticesProblems(deb, parseDpkgList(run("dpkg-deb", ["-c", join(dir, deb)])), LINUX_PATHS.deb));
  if (rpm) problems.push(...noticesProblems(rpm, parseRpmDump(run("rpm", ["-qlp", "--dump", join(dir, rpm)])), LINUX_PATHS.rpm));
  if (appimage) {
    const work = mkdtempSync(join(tmpdir(), "appimage-"));
    try {
      run("cp", [join(dir, appimage), join(work, "app.AppImage")]);
      run("chmod", ["+x", join(work, "app.AppImage")]);
      run(join(work, "app.AppImage"), ["--appimage-extract"], { cwd: work, stdio: ["ignore", "ignore", "inherit"] });
      const root = join(work, "squashfs-root");
      const found = run("find", [root, "-type", "f", "-name", NOTICES])
        .split("\n")
        .filter(Boolean)
        .map((p) => ({ path: p, size: statSync(p).size }));
      problems.push(...noticesProblems(appimage, found));
      try {
        process.stdout.write(run("bash", [join(ROOT, "scripts", "appimage-licenses.sh"), "--check", root]));
      } catch (e) {
        problems.push(`${appimage}: ${String(e.stderr || e.message).trim()}`);
      }
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
  if (sources) {
    const dsc = run("tar", ["-tf", join(dir, sources)]).split("\n").filter((l) => l.endsWith(".dsc"));
    if (!dsc.length) problems.push(`${sources} contains no Debian source package (.dsc)`);
    else console.log(`${sources}: ${dsc.length} source packages`);
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
  console.log(`every package in ${dir} carries the third-party notices`);
}
