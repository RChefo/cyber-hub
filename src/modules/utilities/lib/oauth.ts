import type { FindingInput } from "@/lib/types";

export type OAuthSeverity = "high" | "medium" | "low" | "info";

export interface OAuthCheck {
  id: string;
  severity: OAuthSeverity;
  /** issue: a property of the configuration; test: something to try against the server */
  kind: "issue" | "test";
  title: string;
  detail: string;
  recommendation: string;
  reference: string;
}

export interface OAuthReview {
  kind: "OpenID Connect" | "OAuth 2.0";
  issuer: string;
  endpoints: { name: string; url: string }[];
  /** what the server says it supports; values are empty when the field is absent, and the
   * specifications then give some fields a default */
  advertised: { label: string; values: string[]; defaults?: string[] }[];
  strengths: string[];
  checks: OAuthCheck[];
}

const RFC9700 = "RFC 9700, OAuth 2.0 Security Best Current Practice";
const RFC8725 = "RFC 8725, JSON Web Token Best Current Practices";
const HIDDEN = "PortSwigger Research, Hidden OAuth attack vectors (2021)";
// defaults for absent fields: RFC 8414, section 2, and OpenID Connect Discovery 1.0, section 3
const ADVERTISED: [string, string, string[]?][] = [
  ["grant_types_supported", "Grant types", ["authorization_code", "implicit"]],
  ["response_types_supported", "Response types"],
  ["response_modes_supported", "Response modes", ["query", "fragment"]],
  ["code_challenge_methods_supported", "PKCE methods"],
  ["token_endpoint_auth_methods_supported", "Client authentication", ["client_secret_basic"]],
  ["id_token_signing_alg_values_supported", "ID token signing"],
  ["scopes_supported", "Scopes"],
];
const ENDPOINTS: [string, string][] = [
  ["authorization_endpoint", "Authorization"],
  ["token_endpoint", "Token"],
  ["userinfo_endpoint", "UserInfo"],
  ["jwks_uri", "Keys (JWKS)"],
  ["registration_endpoint", "Client registration"],
  ["revocation_endpoint", "Revocation"],
  ["introspection_endpoint", "Introspection"],
  ["end_session_endpoint", "Logout"],
  ["pushed_authorization_request_endpoint", "Pushed authorization requests"],
  ["device_authorization_endpoint", "Device authorization"],
  ["backchannel_authentication_endpoint", "Back-channel authentication"],
];

const list = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);

function isLoopback(url: string): boolean {
  try {
    const h = new URL(url).hostname;
    return h === "localhost" || h === "127.0.0.1" || h === "[::1]";
  } catch {
    return false;
  }
}

/** The issuer a discovery address belongs to (OpenID Connect Discovery and RFC 8414 forms). */
export function issuerOf(discoveryUrl: string): string {
  try {
    const u = new URL(discoveryUrl);
    let path = u.pathname;
    if (path.endsWith("/.well-known/openid-configuration")) path = path.slice(0, -"/.well-known/openid-configuration".length);
    else if (path.startsWith("/.well-known/oauth-authorization-server")) path = path.slice("/.well-known/oauth-authorization-server".length);
    return `${u.origin}${path}`.replace(/\/$/, "");
  } catch {
    return discoveryUrl;
  }
}

/** Where to fetch the metadata of an issuer: OpenID Connect first, then RFC 8414. A metadata
 * address itself (with /.well-known/) is fetched as it is. */
export function discoveryUrls(issuer: string): string[] {
  const clean = issuer.trim().replace(/\/$/, "");
  try {
    const u = new URL(clean);
    if (u.protocol !== "https:" && u.protocol !== "http:") return [];
    if (u.pathname.includes("/.well-known/")) return [clean];
    const path = u.pathname === "/" ? "" : u.pathname;
    return [`${clean}/.well-known/openid-configuration`, `${u.origin}/.well-known/oauth-authorization-server${path}`];
  } catch {
    return [];
  }
}

/** Reviews authorization server metadata (OpenID Connect Discovery 1.0 or RFC 8414). `fetchedFrom`
 * is the discovery address, when the document was fetched, to check its issuer. Throws for
 * documents that are not metadata. */
export function reviewMetadata(doc: unknown, fetchedFrom?: string): OAuthReview {
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) throw new Error("This is not a JSON object");
  const m = doc as Record<string, unknown>;
  const issuer = typeof m.issuer === "string" ? m.issuer : "";
  if (!issuer && typeof m.authorization_endpoint !== "string" && typeof m.token_endpoint !== "string") {
    throw new Error("This is not OAuth or OpenID Connect metadata: it has no issuer, authorization endpoint or token endpoint");
  }
  const oidc = "id_token_signing_alg_values_supported" in m || "userinfo_endpoint" in m || "subject_types_supported" in m;
  const checks: OAuthCheck[] = [];
  const add = (c: OAuthCheck) => checks.push(c);
  const endpoints = ENDPOINTS.filter(([k]) => typeof m[k] === "string").map(([k, name]) => ({ name, url: m[k] as string }));

  const plain = [...(issuer ? [{ name: "Issuer", url: issuer }] : []), ...endpoints].filter((e) => e.url.startsWith("http://") && !isLoopback(e.url));
  if (plain.length) {
    add({ id: "OAUTH-HTTP", severity: "high", kind: "issue", title: "Endpoints without TLS", detail: `${plain.map((e) => `${e.name} (${e.url})`).join(", ")} ${plain.length === 1 ? "uses" : "use"} plain HTTP: codes, tokens and credentials cross the network unencrypted.`, recommendation: "Serve every endpoint over HTTPS only.", reference: `${RFC9700}, section 2.6` });
  }
  if (fetchedFrom) {
    const expected = issuerOf(fetchedFrom);
    if (issuer && issuer.replace(/\/$/, "") !== expected) {
      add({ id: "OAUTH-ISSUER-MISMATCH", severity: "high", kind: "issue", title: "Issuer differs from where the metadata was fetched", detail: `The document at ${fetchedFrom} names the issuer ${issuer}, not ${expected}. Clients that accept it are open to mix-up and impersonation attacks.`, recommendation: "Publish metadata whose issuer is exactly the issuer URL it is fetched from.", reference: "OpenID Connect Discovery 1.0, section 4.3; RFC 8414, section 3.3" });
    }
  }
  const grants = list(m.grant_types_supported);
  if (grants.includes("password")) {
    add({ id: "OAUTH-PASSWORD-GRANT", severity: "high", kind: "issue", title: "Resource owner password grant enabled", detail: "Clients can send users' passwords to the token endpoint (grant_type=password), which exposes the credentials to the client and cannot use multi-factor authentication. RFC 9700: it MUST NOT be used.", recommendation: "Disable the password grant and move clients to the authorization code grant with PKCE.", reference: `${RFC9700}, section 2.4` });
  }
  const responses = list(m.response_types_supported);
  const frontTokens = responses.filter((r) => r.split(" ").includes("token"));
  if (frontTokens.length) {
    add({ id: "OAUTH-IMPLICIT", severity: "medium", kind: "issue", title: "Access tokens issued in the authorization response", detail: `Response types ${frontTokens.join(", ")} return access tokens through the browser (implicit or hybrid flow), where they leak through history, referrers and logs and can be injected. RFC 9700: clients SHOULD NOT use them.`, recommendation: "Offer only the code response type (with id_token for OpenID Connect hybrid where needed) and use PKCE.", reference: `${RFC9700}, section 2.1.2` });
  }
  const codeFlow = responses.length === 0 || responses.some((r) => r.split(" ").includes("code")) || grants.includes("authorization_code");
  const pkce = list(m.code_challenge_methods_supported);
  const publicClients = list(m.token_endpoint_auth_methods_supported).includes("none");
  if (codeFlow && pkce.length === 0) {
    add({ id: "OAUTH-PKCE-UNKNOWN", severity: "low", kind: "test", title: "PKCE support not advertised", detail: `The metadata has no code_challenge_methods_supported. Authorization servers MUST support PKCE, and publishing it is recommended; without it, clients cannot tell, and support has to be tested.${publicClients ? " Public clients (client authentication none) are offered, and they rely on PKCE alone to protect their codes." : ""}`, recommendation: "Send an authorization request with and without code_challenge (S256) and check that a code issued with a challenge is refused without the right code_verifier.", reference: `${RFC9700}, section 2.1.1` });
  } else if (codeFlow && !pkce.includes("S256")) {
    add({ id: "OAUTH-PKCE-PLAIN", severity: "medium", kind: "issue", title: "PKCE only with the plain method", detail: `The server offers PKCE with ${pkce.join(", ")} only. The plain method sends the verifier itself in the authorization request; S256 is the only method that does not expose it.`, recommendation: "Support S256 and have clients use it.", reference: `${RFC9700}, section 2.1.1` });
  }
  const algs: [string, string][] = [
    ["id_token_signing_alg_values_supported", "ID tokens"],
    ["token_endpoint_auth_signing_alg_values_supported", "client authentication JWTs"],
    ["request_object_signing_alg_values_supported", "request objects"],
    ["userinfo_signing_alg_values_supported", "UserInfo responses"],
    ["authorization_signing_alg_values_supported", "authorization responses"],
  ];
  for (const [key, what] of algs) {
    if (list(m[key]).some((a) => a.toLowerCase() === "none")) {
      // forged ID tokens sign users in, forged client assertions authenticate as any client
      const severe = key.startsWith("id_token") || key.startsWith("token_endpoint");
      add({ id: `OAUTH-ALG-NONE-${key.split("_")[0].toUpperCase()}`, severity: severe ? "high" : "medium", kind: "issue", title: `Unsigned ${what} accepted`, detail: `${key} includes "none": ${what} without a signature are offered, so their contents can be forged unless every party that receives them refuses them.`, recommendation: `Remove "none" from ${key}.`, reference: `${RFC8725}, section 3.2${key.startsWith("token_endpoint") ? '; OpenID Connect Discovery 1.0, section 3 ("The value none MUST NOT be used")' : ""}` });
    }
  }
  const symmetric = list(m.id_token_signing_alg_values_supported).filter((a) => /^HS\d+$/i.test(a));
  if (symmetric.length) {
    add({ id: "OAUTH-ID-TOKEN-HMAC", severity: "low", kind: "issue", title: "ID tokens can be signed with the client secret", detail: `${symmetric.join(", ")} sign ID tokens with each client's secret: anyone who learns a secret can forge tokens for that client, and weak secrets can be guessed offline.`, recommendation: "Prefer asymmetric signatures (RS256, ES256, PS256); where HMAC remains, require long random client secrets.", reference: `${RFC8725}, section 3.5` });
  }
  const rsa15 = ["id_token_encryption_alg_values_supported", "userinfo_encryption_alg_values_supported", "request_object_encryption_alg_values_supported", "authorization_encryption_alg_values_supported"].filter((k) => list(m[k]).includes("RSA1_5"));
  if (rsa15.length) {
    add({ id: "OAUTH-RSA1_5", severity: "low", kind: "issue", title: "RSA PKCS #1 v1.5 encryption offered", detail: `${rsa15.join(", ")} ${rsa15.length === 1 ? "includes" : "include"} RSA1_5, which is open to padding oracle (Bleichenbacher) attacks.`, recommendation: "Offer RSA-OAEP or ECDH-ES key management instead of RSA1_5.", reference: `${RFC8725}, section 3.2` });
  }
  if (oidc && m.request_uri_parameter_supported !== false && m.require_request_uri_registration !== true) {
    add({ id: "OAUTH-REQUEST-URI", severity: "info", kind: "test", title: "Request objects fetched from client-supplied URLs", detail: `request_uri is ${m.request_uri_parameter_supported === undefined ? "supported by default (the field is absent)" : "supported"} and need not be registered: the server fetches the URL a client puts in the authorization request.`, recommendation: "Send an authorization request with request_uri pointing to a server you control and to internal addresses, to check for server-side request forgery.", reference: `OpenID Connect Discovery 1.0, section 3; ${HIDDEN}` });
  }
  if (typeof m.registration_endpoint === "string") {
    add({ id: "OAUTH-REGISTRATION", severity: "info", kind: "test", title: "Dynamic client registration", detail: `Clients can be registered at ${m.registration_endpoint}. If it needs no initial access token, anyone can create clients, and URLs in the registration (logo_uri, jwks_uri, sector_identifier_uri) make the server send requests.`, recommendation: "Register a client without credentials; if that works, check the URLs the server fetches and what the new client can request.", reference: `RFC 7591, OAuth 2.0 Dynamic Client Registration; ${HIDDEN}` });
  }
  if (grants.includes("urn:ietf:params:oauth:grant-type:device_code")) {
    add({ id: "OAUTH-DEVICE-CODE", severity: "info", kind: "test", title: "Device authorization grant enabled", detail: "Users can be asked to enter a code on a page of the real provider, which phishing campaigns use to obtain tokens for an attacker's device.", recommendation: "Limit the device grant to the clients that need it, and watch for device-code sign-ins.", reference: "RFC 8628, section 5.4" });
  }
  const strengths: string[] = [];
  if (pkce.includes("S256")) strengths.push("PKCE with S256");
  if (typeof m.pushed_authorization_request_endpoint === "string") strengths.push(m.require_pushed_authorization_requests === true ? "pushed authorization requests required" : "pushed authorization requests offered");
  if (list(m.dpop_signing_alg_values_supported).length) strengths.push("DPoP sender-constrained tokens");
  if (m.tls_client_certificate_bound_access_tokens === true) strengths.push("mTLS-bound tokens");
  if (m.authorization_response_iss_parameter_supported === true) strengths.push("iss in authorization responses (mix-up defence)");
  if (list(m.token_endpoint_auth_methods_supported).some((x) => x === "private_key_jwt" || x === "tls_client_auth")) strengths.push("asymmetric client authentication");
  const order = ["high", "medium", "low", "info"];
  checks.sort((a, b) => (a.kind === b.kind ? order.indexOf(a.severity) - order.indexOf(b.severity) : a.kind === "issue" ? -1 : 1));
  const advertised = ADVERTISED.map(([k, label, defaults]) => ({ label, values: list(m[k]), ...(defaults && !(k in m) ? { defaults } : {}) }));
  return { kind: oidc ? "OpenID Connect" : "OAuth 2.0", issuer, endpoints, advertised, strengths, checks };
}

/** The finding a check becomes; the title names the issuer, so it is recorded once. */
export function oauthFinding(projectId: number, r: OAuthReview, c: OAuthCheck): FindingInput {
  const host = (() => {
    try {
      return new URL(r.issuer).host;
    } catch {
      return r.issuer || "authorization server";
    }
  })();
  return {
    projectId,
    title: `${c.title} (${host})`.slice(0, 200),
    severity: c.severity,
    status: "new",
    category: "OAuth configuration",
    confidence: c.kind === "issue" ? "high" : "low",
    description: `${c.detail}\n\n${r.kind} provider: ${r.issuer || "(no issuer)"}.`,
    affectedTarget: r.issuer || host,
    technicalDetails: `Rule ${c.id}, from the server's published metadata. Reference: ${c.reference}.`,
    remediation: c.recommendation,
    tags: ["oauth", ...(r.kind === "OpenID Connect" ? ["oidc"] : [])],
  };
}
