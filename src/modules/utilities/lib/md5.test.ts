import { describe, expect, it } from "vitest";
import { md5Hex } from "./md5";

describe("md5 (RFC 1321 test suite)", () => {
  const vectors: [string, string][] = [
    ["", "d41d8cd98f00b204e9800998ecf8427e"],
    ["a", "0cc175b9c0f1b6a831c399e269772661"],
    ["abc", "900150983cd24fb0d6963f7d28e17f72"],
    ["message digest", "f96b697d7cb7938d525a2f31aaf161d0"],
    ["abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"],
    ["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"],
    ["12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"],
  ];
  for (const [input, expected] of vectors) {
    it(`md5("${input.slice(0, 20)}${input.length > 20 ? "…" : ""}")`, () => {
      expect(md5Hex(input)).toBe(expected);
    });
  }

  it("hashes UTF-8 encoded text", () => {
    expect(md5Hex("é")).toBe("66ddcd97cfdeabb2f6fb8a999b4bc76f");
  });

  it("handles multi-block input", () => {
    expect(md5Hex("a".repeat(1000))).toBe("cabe45dcc9ae5b66ba86600cca6b8ba8");
  });

  it("handles block-boundary lengths (55, 56, 64 bytes)", () => {
    expect(md5Hex("a".repeat(55))).toBe("ef1772b6dff9a122358552954ad0df65");
    expect(md5Hex("a".repeat(56))).toBe("3b0c8ac703f828b04c6c197006d17218");
    expect(md5Hex("a".repeat(64))).toBe("014842d480b571495a4a0363793f7367");
  });
});
