// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { base64Encode, doubleUrlEncode, encodePayload, htmlEntityEncode, urlEncode } from "./encode";

describe("payload encoders", () => {
  it("URL-encodes reserved and sub-delimiter characters", () => {
    expect(urlEncode("<a href='x'>(1)!*</a>")).toBe("%3Ca%20href%3D%27x%27%3E%281%29%21%2A%3C%2Fa%3E");
    expect(urlEncode("a-b_c.d~e")).toBe("a-b_c.d~e");
  });
  it("double URL-encodes", () => {
    expect(doubleUrlEncode("../")).toBe("..%252F");
  });
  it("Base64-encodes UTF-8 safely", () => {
    expect(base64Encode("{{7*7}}")).toBe("e3s3Kjd9fQ==");
    expect(base64Encode("é")).toBe("w6k=");
  });
  it("HTML-entity encodes markup and non-ASCII", () => {
    expect(htmlEntityEncode(`<svg onload="a('b')">&`)).toBe("&lt;svg onload=&quot;a(&#39;b&#39;)&quot;&gt;&amp;");
    expect(htmlEntityEncode("ﬀ")).toBe("&#xFB00;");
  });
  it("dispatches by encoding and preserves newlines for none", () => {
    expect(encodePayload("a\nb", "none")).toBe("a\nb");
    expect(encodePayload("a b", "url")).toBe("a%20b");
  });
});
