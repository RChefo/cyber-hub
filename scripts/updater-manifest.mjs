#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Builds and validates the static update manifest (`latest.json`) read by the Tauri updater.
//
//   node scripts/updater-manifest.mjs generate --version 0.2.0 --assets <dir> --base-url <https url>
//        --notes-file <file> [--pub-date <RFC 3339>] [--out latest.json] [--normalize-names]
//   node scripts/updater-manifest.mjs validate --manifest latest.json --assets <dir>
//        [--base-url <https url>] [--config src-tauri/tauri.conf.json] [--require <keys>]
//
// `validate` refuses a manifest unless every entry points at a file that exists in <dir>, uses
// HTTPS, and carries a minisign signature that verifies against the public key in tauri.conf.json
// and is bound to the manifest's version (the app enforces the same with `requireSignedVersion`).
// It never reads or needs the private key. `generate` shortens release notes that are longer than
// the app shows (20,000 characters) at a paragraph and links the full notes on the release page.
import { createHash, createPublicKey, verify } from "node:crypto";
import { createReadStream, existsSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;
const SAFE_NAME = /^[A-Za-z0-9._-]+$/;
const MAX_NOTES = 20000;

/** Artifact name patterns produced by `tauri build` with `createUpdaterArtifacts: true`. */
export const ARTIFACTS = [
  { key: "windows-x86_64-nsis", re: /_x64-setup\.exe$/ },
  { key: "windows-x86_64-msi", re: /_x64_[A-Za-z-]+\.msi$/ },
  { key: "linux-x86_64-appimage", re: /_amd64\.AppImage$/ },
  { key: "linux-x86_64-deb", re: /_amd64\.deb$/ },
  { key: "linux-x86_64-rpm", re: /\.x86_64\.rpm$/ },
];
/** `{os}-{arch}` fallbacks, used by copies whose package type is unknown to the updater. */
export const DEFAULTS = { "windows-x86_64": "windows-x86_64-nsis", "linux-x86_64": "linux-x86_64-appimage" };
export const KNOWN_KEYS = new Set([...ARTIFACTS.map((a) => a.key), ...Object.keys(DEFAULTS)]);

/** Tauri names packages `<product>_<version>_…` (NSIS, MSI, AppImage, deb) or `<product>-<version>-1.…` (rpm). */
const namedFor = (name, version) => name.includes(`_${version}_`) || name.includes(`-${version}-`);

/** Key ID as minisign prints it (little-endian). */
const keyIdOf = (raw) => Buffer.from(raw.subarray(2, 10)).reverse().toString("hex");

const fail = (msg) => {
  throw new Error(msg);
};

/* ─────────────── minisign (as written by `tauri signer` / `tauri build`) ─────────────── */

const b64text = (value, what) => {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/=\s]+$/.test(value)) fail(`${what} is not base64 text`);
  return Buffer.from(value, "base64").toString("utf8");
};

/** Parses the `pubkey` value of tauri.conf.json. */
export function parsePublicKey(pubkey) {
  const lines = b64text(pubkey, "The public key").split(/\r?\n/);
  const raw = Buffer.from((lines[1] ?? "").trim(), "base64");
  if (raw.length !== 42 || raw.subarray(0, 2).toString("latin1") !== "Ed") fail("The public key is not a minisign Ed25519 public key");
  const key = createPublicKey({ key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw.subarray(10)]), format: "der", type: "spki" });
  return { keyId: keyIdOf(raw), key };
}

/** Parses a signature as stored in the manifest (the base64 content of the `.sig` file). */
export function parseSignature(signature) {
  const lines = b64text(signature, "The signature").split(/\r?\n/);
  const raw = Buffer.from((lines[1] ?? "").trim(), "base64");
  const trustedLine = lines[2] ?? "";
  const global = Buffer.from((lines[3] ?? "").trim(), "base64");
  if (raw.length !== 74 || !trustedLine.startsWith("trusted comment: ") || global.length !== 64) fail("The signature is not a minisign signature");
  const alg = raw.subarray(0, 2).toString("latin1");
  if (alg !== "ED" && alg !== "Ed") fail(`Unknown signature algorithm ${alg}`);
  const trusted = trustedLine.slice("trusted comment: ".length);
  const fields = Object.fromEntries(trusted.split("\t").map((f) => [f.slice(0, f.indexOf(":")), f.slice(f.indexOf(":") + 1)]));
  return { prehashed: alg === "ED", keyId: keyIdOf(raw), sig: raw.subarray(10), trusted, global, version: fields.version ?? null };
}

async function digest(path) {
  const h = createHash("blake2b512");
  for await (const chunk of createReadStream(path)) h.update(chunk);
  return h.digest();
}

/** Verifies a file against a signature and public key; returns the signed version. */
export async function verifyFile(path, signature, pub) {
  const s = parseSignature(signature);
  if (s.keyId !== pub.keyId) fail(`signed with key ${s.keyId.toUpperCase()}, but the app trusts key ${pub.keyId.toUpperCase()}`);
  const message = s.prehashed ? await digest(path) : readFileSync(path);
  if (!verify(null, message, pub.key, s.sig)) fail("the signature does not match the file");
  if (!verify(null, Buffer.concat([s.sig, Buffer.from(s.trusted, "utf8")]), pub.key, s.global)) fail("the signature's trusted comment was altered");
  return s.version;
}

/* ─────────────── manifest ─────────────── */

/** Renames files so their names survive a GitHub release upload unchanged (no spaces). */
export function normalizeNames(dir) {
  for (const f of readdirSync(dir)) {
    const safe = f.replace(/\s+/g, ".");
    if (safe !== f) renameSync(join(dir, f), join(dir, safe));
  }
}

/**
 * The notes the app shows in its Update Center: at most MAX_NOTES characters. Longer release
 * notes are cut at the last blank line that fits and end with a link to the full release notes
 * on the release page, so the app never shows a text cut off mid-sentence. The release itself
 * keeps the full notes. (Mission 10: 0.1.0's notes, 25,720 characters, stopped the first release
 * run at `validate`.)
 */
export function manifestNotes(notes, baseUrl) {
  const text = (notes ?? "").trim();
  if (text.length <= MAX_NOTES) return text;
  const page = baseUrl.replace(/\/releases\/download\/([^/]+)\/?$/, "/releases/tag/$1");
  const tail = `\n\n…\n\nThe full release notes: ${page}`;
  const room = text.slice(0, MAX_NOTES - tail.length);
  const cut = room.lastIndexOf("\n\n");
  let kept = cut > 0 ? room.slice(0, cut) : room;
  // never end on a heading whose text was cut away
  for (let i = kept.lastIndexOf("\n\n"); i > 0 && /^#{1,6} /.test(kept.slice(i + 2)); i = kept.lastIndexOf("\n\n")) kept = kept.slice(0, i);
  return kept.trimEnd() + tail;
}

export function generate({ version, assets, baseUrl, notes, pubDate }) {
  if (!SEMVER.test(version ?? "")) fail(`"${version}" is not a semantic version (use 1.2.3, without a leading v)`);
  if (!/^https:\/\//.test(baseUrl ?? "")) fail("--base-url must be an https URL");
  const files = readdirSync(assets);
  const platforms = {};
  for (const { key, re } of ARTIFACTS) {
    const matches = files.filter((f) => re.test(f) && namedFor(f, version));
    if (matches.length > 1) fail(`More than one artifact for ${key}: ${matches.join(", ")}`);
    const file = matches[0];
    if (!file) continue;
    if (!SAFE_NAME.test(file)) fail(`Artifact name "${file}" contains characters a release upload would change (run with --normalize-names)`);
    const sigPath = join(assets, `${file}.sig`);
    if (!existsSync(sigPath)) fail(`${file} has no .sig file next to it: the build did not sign it`);
    platforms[key] = { url: `${baseUrl.replace(/\/$/, "")}/${encodeURIComponent(file)}`, signature: readFileSync(sigPath, "utf8").trim() };
  }
  for (const [fallback, target] of Object.entries(DEFAULTS)) if (platforms[target]) platforms[fallback] = { ...platforms[target] };
  if (!Object.keys(platforms).length) fail(`No updater artifacts for version ${version} were found in ${assets}`);
  return { version, notes: manifestNotes(notes, baseUrl), pub_date: pubDate ?? new Date().toISOString().replace(/\.\d+Z$/, "Z"), platforms };
}

/**
 * Checks a manifest before upload. Returns a list of problems (empty when it is valid).
 * `assets` is the folder holding the files the manifest points to.
 */
export async function validate(manifest, { assets, pubkey, baseUrl, require = [], channel = "stable" }) {
  const problems = [];
  const p = (m) => problems.push(m);
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) return ["The manifest is not a JSON object"];
  const { version, notes, pub_date: pubDate, platforms } = manifest;
  if (typeof version !== "string" || !SEMVER.test(version)) p(`version "${version}" is not a semantic version without a leading v`);
  else if (channel === "stable" && version.includes("-")) p(`version ${version} is a pre-release, which the stable channel never offers`);
  if (notes !== undefined && typeof notes !== "string") p("notes must be a string");
  if (typeof notes === "string" && notes.length > MAX_NOTES) p(`notes are longer than ${MAX_NOTES} characters (the app shows the first ${MAX_NOTES})`);
  if (typeof pubDate !== "string" || !RFC3339.test(pubDate) || Number.isNaN(Date.parse(pubDate))) p(`pub_date "${pubDate}" is not an RFC 3339 date`);
  if (!platforms || typeof platforms !== "object" || !Object.keys(platforms).length) {
    p("platforms is missing or empty");
    return problems;
  }
  for (const key of require) if (!platforms[key]) p(`platform ${key} is required but missing`);
  for (const [fallback, target] of Object.entries(DEFAULTS)) {
    if (platforms[target] && !platforms[fallback]) p(`${fallback} is missing (it should repeat ${target})`);
    if (platforms[fallback] && platforms[target] && platforms[fallback].url !== platforms[target].url) p(`${fallback} does not point to the same file as ${target}`);
  }
  let pub = null;
  try {
    pub = parsePublicKey(pubkey);
  } catch (e) {
    p(`public key: ${e.message}`);
  }
  for (const [key, entry] of Object.entries(platforms)) {
    if (!KNOWN_KEYS.has(key)) p(`${key} is not a supported platform key (macOS is not supported)`);
    if (!entry || typeof entry.url !== "string" || typeof entry.signature !== "string") {
      p(`${key}: url and signature must be strings`);
      continue;
    }
    let url;
    try {
      url = new URL(entry.url);
    } catch {
      p(`${key}: "${entry.url}" is not a URL`);
      continue;
    }
    if (url.protocol !== "https:") p(`${key}: ${entry.url} does not use HTTPS`);
    if (baseUrl && !entry.url.startsWith(`${baseUrl.replace(/\/$/, "")}/`)) p(`${key}: ${entry.url} is not under ${baseUrl}`);
    const name = decodeURIComponent(basename(url.pathname));
    if (!SAFE_NAME.test(name)) p(`${key}: file name "${name}" would be changed by a release upload`);
    const file = join(assets, name);
    if (!existsSync(file)) {
      p(`${key}: ${name} does not exist in ${assets}`);
      continue;
    }
    if (!statSync(file).isFile() || statSync(file).size === 0) {
      p(`${key}: ${name} is empty`);
      continue;
    }
    if (typeof version === "string" && !namedFor(name, version)) p(`${key}: ${name} is not named for version ${version}`);
    const artifact = ARTIFACTS.find((a) => a.key === key) ?? ARTIFACTS.find((a) => a.key === DEFAULTS[key]);
    if (artifact && !artifact.re.test(name)) p(`${key}: ${name} is not a ${artifact.key} package`);
    if (!pub) continue;
    try {
      const signed = await verifyFile(file, entry.signature, pub);
      if (signed === null) p(`${key}: the signature does not carry a version (sign with tauri build or --app-version)`);
      else if (signed !== version) p(`${key}: the signature is for version ${signed}, the manifest announces ${version}`);
    } catch (e) {
      p(`${key}: ${e.message}`);
    }
  }
  return problems;
}

/* ─────────────── command line ─────────────── */

function args(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) out._.push(a);
    else if (a === "--normalize-names") out.normalizeNames = true;
    else out[a.slice(2).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = argv[++i];
  }
  return out;
}

async function main() {
  const a = args(process.argv.slice(2));
  const config = JSON.parse(readFileSync(a.config ?? "src-tauri/tauri.conf.json", "utf8"));
  const pubkey = config?.plugins?.updater?.pubkey;
  if (a._[0] === "generate") {
    if (a.normalizeNames) normalizeNames(a.assets);
    const notes = a.notesFile ? readFileSync(a.notesFile, "utf8") : "";
    const manifest = generate({ version: a.version, assets: a.assets, baseUrl: a.baseUrl, notes, pubDate: a.pubDate });
    const problems = await validate(manifest, { assets: a.assets, pubkey, baseUrl: a.baseUrl });
    if (problems.length) fail(`The generated manifest is not valid:\n- ${problems.join("\n- ")}`);
    writeFileSync(a.out ?? "latest.json", `${JSON.stringify(manifest, null, 2)}\n`);
    console.log(`Wrote ${a.out ?? "latest.json"} for ${a.version}: ${Object.keys(manifest.platforms).join(", ")}`);
  } else if (a._[0] === "validate") {
    const manifest = JSON.parse(readFileSync(a.manifest, "utf8"));
    const problems = await validate(manifest, { assets: a.assets, pubkey, baseUrl: a.baseUrl, require: a.require ? a.require.split(",") : [] });
    if (problems.length) fail(`${a.manifest} is not valid:\n- ${problems.join("\n- ")}`);
    console.log(`${a.manifest} is valid: version ${manifest.version}, ${Object.keys(manifest.platforms).length} platform entries, every signature verified.`);
  } else {
    fail("usage: updater-manifest.mjs generate|validate … (see the header of this file)");
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((e) => {
    console.error(`updater-manifest: ${e.message}`);
    process.exit(1);
  });
}
