import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { generate, parsePublicKey, validate } from "./updater-manifest.mjs";

// minisign keys and signatures in the format `tauri signer` writes, made with Node's Ed25519
function keypair() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pk = publicKey.export({ format: "der", type: "spki" }).subarray(12);
  const keyId = randomBytes(8);
  const text = `untrusted comment: minisign public key: ${Buffer.from(keyId).reverse().toString("hex").toUpperCase()}\n${Buffer.concat([Buffer.from("Ed"), keyId, pk]).toString("base64")}\n`;
  return { privateKey, keyId, pubkey: Buffer.from(text).toString("base64") };
}

function signFile(data, kp, trusted) {
  const sig = sign(null, createHash("blake2b512").update(data).digest(), kp.privateKey);
  const global = sign(null, Buffer.concat([sig, Buffer.from(trusted)]), kp.privateKey);
  const text = `untrusted comment: signature from tauri secret key\n${Buffer.concat([Buffer.from("ED"), kp.keyId, sig]).toString("base64")}\ntrusted comment: ${trusted}\n${global.toString("base64")}\n`;
  return Buffer.from(text).toString("base64");
}

const dirs = [];
function release(version, kp, opts = {}) {
  const dir = mkdtempSync(join(tmpdir(), "cyberhub-manifest-"));
  dirs.push(dir);
  const files = {
    nsis: `Cyber.Hub_${version}_x64-setup.exe`,
    msi: `Cyber.Hub_${version}_x64_en-US.msi`,
    appimage: `Cyber.Hub_${version}_amd64.AppImage`,
    deb: `Cyber.Hub_${version}_amd64.deb`,
    rpm: `Cyber.Hub-${version}-1.x86_64.rpm`,
  };
  for (const f of Object.values(files)) {
    const data = randomBytes(4096);
    writeFileSync(join(dir, f), data);
    if (!(opts.unsigned ?? []).includes(f)) writeFileSync(join(dir, `${f}.sig`), signFile(data, kp, `timestamp:1793895691\tfile:${f}\tversion:${opts.signedVersion ?? version}`));
  }
  return { dir, files };
}

const BASE = "https://github.com/owner/cyber-hub/releases/download/v0.2.0";
const kp = keypair();

afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

describe("update manifest", () => {
  it("generates a manifest whose every entry verifies", async () => {
    const { dir } = release("0.2.0", kp);
    const m = generate({ version: "0.2.0", assets: dir, baseUrl: BASE, notes: "Fixes", pubDate: "2026-11-05T10:00:00Z" });
    expect(Object.keys(m.platforms).sort()).toEqual(
      ["linux-x86_64", "linux-x86_64-appimage", "linux-x86_64-deb", "linux-x86_64-rpm", "windows-x86_64", "windows-x86_64-msi", "windows-x86_64-nsis"].sort(),
    );
    expect(m.platforms["windows-x86_64"].url).toBe(`${BASE}/Cyber.Hub_0.2.0_x64-setup.exe`);
    expect(await validate(m, { assets: dir, pubkey: kp.pubkey, baseUrl: BASE, require: ["windows-x86_64-nsis", "linux-x86_64-deb"] })).toEqual([]);
    expect(parsePublicKey(kp.pubkey).keyId).toBe(Buffer.from(kp.keyId).reverse().toString("hex"));
  });

  it("rejects a modified artifact, a wrong key, a missing or broken signature", async () => {
    const { dir, files } = release("0.2.0", kp);
    const m = generate({ version: "0.2.0", assets: dir, baseUrl: BASE, notes: "", pubDate: "2026-11-05T10:00:00Z" });
    // modified artifact
    const deb = join(dir, files.deb);
    const bytes = readFileSync(deb);
    bytes[100] ^= 1;
    writeFileSync(deb, bytes);
    expect((await validate(m, { assets: dir, pubkey: kp.pubkey })).join()).toMatch(/linux-x86_64-deb: the signature does not match the file/);
    // wrong public key
    const other = keypair();
    expect((await validate(m, { assets: dir, pubkey: other.pubkey })).join()).toMatch(/signed with key .* but the app trusts key/);
    // missing and garbage signatures
    const bad = structuredClone(m);
    bad.platforms["windows-x86_64-msi"].signature = "";
    bad.platforms["linux-x86_64-rpm"].signature = Buffer.from("not a signature").toString("base64");
    const problems = (await validate(bad, { assets: dir, pubkey: kp.pubkey })).join("\n");
    expect(problems).toMatch(/windows-x86_64-msi: The signature is not base64 text/);
    expect(problems).toMatch(/linux-x86_64-rpm: The signature is not a minisign signature/);
    // a signature whose trusted comment was edited
    const edited = structuredClone(m);
    const text = Buffer.from(edited.platforms["windows-x86_64-nsis"].signature, "base64").toString().replace("version:0.2.0", "version:0.3.0");
    edited.platforms["windows-x86_64-nsis"].signature = Buffer.from(text).toString("base64");
    expect((await validate(edited, { assets: dir, pubkey: kp.pubkey })).join()).toMatch(/trusted comment was altered/);
  });

  it("refuses unsigned builds and signatures bound to another version", async () => {
    const unsigned = release("0.2.0", kp, { unsigned: ["Cyber.Hub_0.2.0_amd64.deb"] });
    expect(() => generate({ version: "0.2.0", assets: unsigned.dir, baseUrl: BASE })).toThrow(/has no .sig file/);
    const old = release("0.2.0", kp, { signedVersion: "0.1.0" });
    const m = generate({ version: "0.2.0", assets: old.dir, baseUrl: BASE, pubDate: "2026-11-05T10:00:00Z" });
    expect((await validate(m, { assets: old.dir, pubkey: kp.pubkey })).join()).toMatch(/the signature is for version 0.1.0, the manifest announces 0.2.0/);
  });

  it("shortens release notes longer than the app shows, at a paragraph, with a link to the full notes", async () => {
    const { dir } = release("0.2.0", kp);
    const para = "A sentence of the release notes. ".repeat(28).trim();
    const long = Array.from({ length: 30 }, (_, i) => `## Part ${i}\n\n${para}`).join("\n\n");
    expect(long.length).toBeGreaterThan(20000);
    const m = generate({ version: "0.2.0", assets: dir, baseUrl: BASE, notes: long, pubDate: "2026-11-05T10:00:00Z" });
    expect(m.notes.length).toBeLessThanOrEqual(20000);
    expect(m.notes.endsWith("\n\n…\n\nThe full release notes: https://github.com/owner/cyber-hub/releases/tag/v0.2.0")).toBe(true);
    const kept = m.notes.slice(0, m.notes.indexOf("\n\n…"));
    // a prefix of the notes that ends with a whole paragraph
    expect(long.startsWith(kept)).toBe(true);
    expect(kept.endsWith(para)).toBe(true);
    expect(await validate(m, { assets: dir, pubkey: kp.pubkey, baseUrl: BASE })).toEqual([]);
    // notes that fit are kept as they are; a manifest written by hand is still held to the limit
    expect(generate({ version: "0.2.0", assets: dir, baseUrl: BASE, notes: "  Fixes\n", pubDate: "2026-11-05T10:00:00Z" }).notes).toBe("Fixes");
    expect(await validate({ ...m, notes: "x".repeat(20001) }, { assets: dir, pubkey: kp.pubkey })).toContain("notes are longer than 20000 characters (the app shows the first 20000)");
  });

  it("refuses missing files, plain HTTP, unknown platforms and bad metadata", async () => {
    const { dir } = release("0.2.0", kp);
    const m = generate({ version: "0.2.0", assets: dir, baseUrl: BASE, pubDate: "2026-11-05T10:00:00Z" });
    const bad = structuredClone(m);
    bad.version = "v0.2.0";
    bad.pub_date = "yesterday";
    bad.platforms["linux-x86_64-deb"].url = bad.platforms["linux-x86_64-deb"].url.replace("https:", "http:");
    bad.platforms["linux-x86_64-rpm"].url = `${BASE}/Cyber.Hub-0.2.0-1.x86_64.rpm.missing`;
    bad.platforms["darwin-aarch64"] = { ...bad.platforms["linux-x86_64-deb"] };
    delete bad.platforms["windows-x86_64"];
    const problems = (await validate(bad, { assets: dir, pubkey: kp.pubkey, baseUrl: BASE, require: ["windows-x86_64-msi"] })).join("\n");
    expect(problems).toMatch(/version "v0.2.0" is not a semantic version/);
    expect(problems).toMatch(/pub_date "yesterday"/);
    expect(problems).toMatch(/linux-x86_64-deb: .* does not use HTTPS/);
    expect(problems).toMatch(/linux-x86_64-rpm: .* does not exist/);
    expect(problems).toMatch(/darwin-aarch64 is not a supported platform key/);
    expect(problems).toMatch(/windows-x86_64 is missing/);
    expect(await validate({ ...m, version: "0.3.0-beta.1" }, { assets: dir, pubkey: kp.pubkey })).toContain("version 0.3.0-beta.1 is a pre-release, which the stable channel never offers");
    expect(() => generate({ version: "0.2.0", assets: dir, baseUrl: "http://example.com" })).toThrow(/https/);
    expect(() => generate({ version: "0.9.0", assets: dir, baseUrl: BASE })).toThrow(/No updater artifacts for version 0.9.0/);
  });
});
