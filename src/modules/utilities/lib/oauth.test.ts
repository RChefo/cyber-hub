// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { discoveryUrls, issuerOf, oauthFinding, reviewMetadata } from "./oauth";

const legacy = {
  issuer: "https://login.shop.example",
  authorization_endpoint: "https://login.shop.example/authorize",
  token_endpoint: "http://login.shop.example/token",
  userinfo_endpoint: "https://login.shop.example/userinfo",
  jwks_uri: "https://login.shop.example/jwks",
  registration_endpoint: "https://login.shop.example/register",
  response_types_supported: ["code", "token", "id_token token", "code id_token"],
  grant_types_supported: ["authorization_code", "implicit", "password", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["RS256", "HS256", "none"],
  id_token_encryption_alg_values_supported: ["RSA1_5", "RSA-OAEP"],
  token_endpoint_auth_signing_alg_values_supported: ["RS256", "none"],
  code_challenge_methods_supported: ["plain"],
};

const modern = {
  issuer: "https://id.bank.example",
  authorization_endpoint: "https://id.bank.example/authorize",
  token_endpoint: "https://id.bank.example/token",
  pushed_authorization_request_endpoint: "https://id.bank.example/par",
  require_pushed_authorization_requests: true,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["private_key_jwt"],
  dpop_signing_alg_values_supported: ["ES256"],
  authorization_response_iss_parameter_supported: true,
};

describe("OAuth and OpenID Connect metadata", () => {
  it("finds the weaknesses of a legacy provider", () => {
    const r = reviewMetadata(legacy, "https://login.shop.example/.well-known/openid-configuration");
    expect(r.kind).toBe("OpenID Connect");
    const ids = r.checks.map((c) => c.id);
    expect(ids).toEqual(["OAUTH-HTTP", "OAUTH-PASSWORD-GRANT", "OAUTH-ALG-NONE-ID", "OAUTH-ALG-NONE-TOKEN", "OAUTH-IMPLICIT", "OAUTH-PKCE-PLAIN", "OAUTH-ID-TOKEN-HMAC", "OAUTH-RSA1_5", "OAUTH-REQUEST-URI", "OAUTH-REGISTRATION", "OAUTH-DEVICE-CODE"]);
    expect(r.checks.find((c) => c.id === "OAUTH-ALG-NONE-TOKEN")?.severity).toBe("high");
    expect(r.advertised.find((a) => a.label === "PKCE methods")?.values).toEqual(["plain"]);
    expect(r.advertised.find((a) => a.label === "Response modes")).toEqual({ label: "Response modes", values: [], defaults: ["query", "fragment"] });
    expect(r.advertised.find((a) => a.label === "Grant types")?.defaults).toBeUndefined();
    const implicit = r.checks.find((c) => c.id === "OAUTH-IMPLICIT");
    expect(implicit?.detail).toContain("token, id_token token");
    expect(implicit?.detail).not.toContain("code id_token,");
    expect(r.checks.find((c) => c.id === "OAUTH-HTTP")?.detail).toContain("Token (http://login.shop.example/token) uses plain HTTP");
    expect(r.checks.find((c) => c.id === "OAUTH-REQUEST-URI")?.detail).toContain("supported by default");
    expect(r.strengths).toEqual([]);
  });

  it("recognises a hardened provider", () => {
    const r = reviewMetadata(modern, "https://id.bank.example/.well-known/oauth-authorization-server");
    expect(r.kind).toBe("OAuth 2.0");
    expect(r.checks).toEqual([]);
    expect(r.strengths).toEqual(["PKCE with S256", "pushed authorization requests required", "DPoP sender-constrained tokens", "iss in authorization responses (mix-up defence)", "asymmetric client authentication"]);
  });

  it("checks the issuer against the discovery address", () => {
    const r = reviewMetadata({ ...modern, issuer: "https://evil.example" }, "https://id.bank.example/.well-known/openid-configuration");
    expect(r.checks[0].id).toBe("OAUTH-ISSUER-MISMATCH");
    expect(issuerOf("https://id.example/tenant1/.well-known/openid-configuration")).toBe("https://id.example/tenant1");
    expect(issuerOf("https://id.example/.well-known/oauth-authorization-server/tenant1")).toBe("https://id.example/tenant1");
    expect(discoveryUrls("https://id.example/tenant1/")).toEqual(["https://id.example/tenant1/.well-known/openid-configuration", "https://id.example/.well-known/oauth-authorization-server/tenant1"]);
    expect(discoveryUrls("https://id.example")).toEqual(["https://id.example/.well-known/openid-configuration", "https://id.example/.well-known/oauth-authorization-server"]);
    expect(discoveryUrls("https://id.example/.well-known/openid-configuration")).toEqual(["https://id.example/.well-known/openid-configuration"]);
    expect(discoveryUrls("file:///etc/passwd")).toEqual([]);
  });

  it("reports PKCE that is not advertised as something to test, and refuses other documents", () => {
    const { code_challenge_methods_supported: _, ...noPkce } = modern;
    const r = reviewMetadata(noPkce);
    expect(r.checks.map((c) => [c.id, c.kind])).toEqual([["OAUTH-PKCE-UNKNOWN", "test"]]);
    expect(r.checks[0].detail).not.toContain("Public clients");
    expect(reviewMetadata({ ...noPkce, token_endpoint_auth_methods_supported: ["none"] }).checks[0].detail).toContain("Public clients");
    expect(() => reviewMetadata({ name: "x" })).toThrow(/not OAuth or OpenID Connect metadata/);
    expect(() => reviewMetadata([1])).toThrow(/not a JSON object/);
  });

  it("turns a check into a finding", () => {
    const r = reviewMetadata(legacy);
    const f = oauthFinding(2, r, r.checks.find((c) => c.id === "OAUTH-PASSWORD-GRANT")!);
    expect(f.title).toBe("Resource owner password grant enabled (login.shop.example)");
    expect(f.affectedTarget).toBe("https://login.shop.example");
    expect(f.technicalDetails).toContain("RFC 9700, OAuth 2.0 Security Best Current Practice, section 2.4");
    expect(f.tags).toEqual(["oauth", "oidc"]);
  });
});
