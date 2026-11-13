// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { base64Encode } from "./encoding";
import { decodeJwt } from "./jwt";

const make = (header: object, payload: object, sig = "c2ln") =>
  `${base64Encode(JSON.stringify(header), true)}.${base64Encode(JSON.stringify(payload), true)}.${sig}`;

describe("decodeJwt", () => {
  it("decodes the jwt.io example token", () => {
    const token =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"; // gitleaks:allow (public jwt.io example token)
    const d = decodeJwt(token);
    expect(d.header).toEqual({ alg: "HS256", typ: "JWT" });
    expect(d.payload).toMatchObject({ sub: "1234567890", name: "John Doe", iat: 1516239022 });
    expect(d.status).toBe("no_expiry");
    expect(d.warnings.some((w) => w.message.includes("No exp"))).toBe(true);
  });

  it("strips a Bearer prefix", () => {
    const d = decodeJwt(`Bearer ${make({ alg: "RS256" }, { exp: 4102444800 })}`);
    expect(d.status).toBe("valid");
  });

  it("detects expiry and nbf", () => {
    const now = new Date("2026-01-01T00:00:00Z");
    expect(decodeJwt(make({ alg: "RS256" }, { exp: 1600000000 }), now).status).toBe("expired");
    expect(decodeJwt(make({ alg: "RS256" }, { nbf: 1900000000, exp: 2000000000 }), now).status).toBe("not_yet_valid");
  });

  it("flags alg none as danger", () => {
    const d = decodeJwt(make({ alg: "none" }, { sub: "x", exp: 1 }, ""));
    expect(d.warnings.find((w) => w.level === "danger")?.message).toMatch(/none/);
  });

  it("rejects malformed tokens", () => {
    expect(() => decodeJwt("abc")).toThrow(/segments/);
    expect(() => decodeJwt("@@@.e30.x")).toThrow(/base64url/);
  });
});
