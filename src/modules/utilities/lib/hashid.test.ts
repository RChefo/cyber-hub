// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { identifyHash } from "./hashid";

const top = (h: string) => identifyHash(h)[0];

describe("identifyHash", () => {
  it("identifies raw hex digests by length", () => {
    expect(top("d41d8cd98f00b204e9800998ecf8427e")).toMatchObject({ name: "MD5", hashcat: 0 });
    expect(identifyHash("d41d8cd98f00b204e9800998ecf8427e").some((c) => c.name === "NTLM" && c.hashcat === 1000)).toBe(true);
    expect(top("da39a3ee5e6b4b0d3255bfef95601890afd80709")).toMatchObject({ name: "SHA-1", hashcat: 100 });
    expect(top("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")).toMatchObject({ name: "SHA-256", hashcat: 1400 });
    expect(top("a".repeat(128))).toMatchObject({ name: "SHA-512", hashcat: 1700 });
    expect(top("a".repeat(96)).name).toBe("SHA-384");
    expect(top("cbf43926").name).toBe("CRC32");
  });

  it("identifies modular crypt formats", () => {
    expect(top("$2b$12$" + "a".repeat(53))).toMatchObject({ name: "bcrypt", hashcat: 3200 });
    expect(top("$6$rounds=5000$salt$abc")).toMatchObject({ hashcat: 1800 });
    expect(top("$5$salt$abc")).toMatchObject({ hashcat: 7400 });
    expect(top("$1$salt$abc")).toMatchObject({ hashcat: 500 });
    expect(top("$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA").name).toMatch(/Argon2/);
    expect(top("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19")).toMatchObject({ hashcat: 300 });
  });

  it("recognizes base64 digests", () => {
    expect(top("1B2M2Y8AsgTpgAmY7PhCfg==").name).toBe("Base64-encoded MD5 digest");
  });

  it("returns nothing for empty or unrecognized input", () => {
    expect(identifyHash("   ")).toEqual([]);
    expect(identifyHash("not a hash!")).toEqual([]);
  });
});
