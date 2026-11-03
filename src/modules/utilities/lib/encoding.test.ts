import { describe, expect, it } from "vitest";
import { base64Decode, base64Encode, binaryDecode, binaryEncode, hexDecode, hexEncode, htmlUnescape, rot13, unicodeEscape, unicodeUnescape, urlDecode } from "./encoding";
import { analyzeHeaders, parseRawHeaders } from "./headers";
import { runRecipe } from "./workbench";

describe("encoding", () => {
  it("round-trips UTF-8 base64 and base64url", () => {
    expect(base64Encode("héllo ✓")).toBe("aMOpbGxvIOKckw==");
    expect(base64Decode("aMOpbGxvIOKckw==")).toBe("héllo ✓");
    expect(base64Encode("??>", true)).toBe("Pz8-");
    expect(base64Decode("Pz8-")).toBe("??>");
    expect(() => base64Decode("!!!")).toThrow();
  });

  it("hex, binary, rot13, html and unicode", () => {
    expect(hexEncode("Hi", ":")).toBe("48:69");
    expect(hexDecode("0x48 0x69")).toBe("Hi");
    expect(binaryDecode(binaryEncode("A"))).toBe("A");
    expect(rot13("Hello")).toBe("Uryyb");
    expect(htmlUnescape("&lt;b&gt; &#65;&#x42;")).toBe("<b> AB");
    expect(unicodeUnescape(unicodeEscape("é😀"))).toBe("é😀");
    expect(() => urlDecode("%E0%A4%A")).toThrow(/percent/);
  });
});

describe("headers", () => {
  it("parses raw headers and analyzes security posture", () => {
    const { status, headers } = parseRawHeaders(
      "HTTP/1.1 200 OK\nServer: Apache/2.4.49\nSet-Cookie: sid=1; Path=/\nAccess-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
    );
    expect(status).toBe("HTTP/1.1 200 OK");
    const checks = analyzeHeaders(headers);
    const by = (id: string) => checks.find((c) => c.id === id)!;
    expect(by("hsts").level).toBe("fail");
    expect(by("csp").level).toBe("fail");
    expect(by("cookie-sid").level).toBe("fail");
    expect(by("leak-server").level).toBe("warn");
    expect(by("cors").level).toBe("fail");
  });

  it("passes a hardened response", () => {
    const checks = analyzeHeaders([
      ["strict-transport-security", "max-age=31536000; includeSubDomains; preload"],
      ["content-security-policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'"],
      ["x-content-type-options", "nosniff"],
      ["referrer-policy", "strict-origin-when-cross-origin"],
    ]);
    for (const id of ["hsts", "csp", "xcto", "framing", "referrer"]) expect(checks.find((c) => c.id === id)!.level).toBe("pass");
  });
});

describe("workbench recipe", () => {
  it("chains steps and reports the failing step", async () => {
    const ok = await runRecipe("hello", [
      { opId: "b64-enc", enabled: true },
      { opId: "upper", enabled: false },
      { opId: "b64-dec", enabled: true },
      { opId: "sha256", enabled: true },
    ]);
    expect(ok.failedAt).toBeNull();
    expect(ok.output).toBe("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    const bad = await runRecipe("not base64!", [{ opId: "b64-dec", enabled: true }, { opId: "upper", enabled: true }]);
    expect(bad.failedAt).toBe(0);
    expect(bad.results[1].output).toBeNull();
  });
});
