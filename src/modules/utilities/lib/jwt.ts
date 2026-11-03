import { base64DecodeBytes, utf8Decode } from "./encoding";

export interface JwtWarning {
  level: "danger" | "warning" | "info";
  message: string;
}

export interface DecodedJwt {
  header: Record<string, unknown>;
  payload: Record<string, unknown> | null;
  /** raw payload text when the payload is not JSON (e.g. JWE or opaque) */
  payloadText: string;
  signature: string;
  parts: number;
  times: { claim: "exp" | "iat" | "nbf"; value: number; date: Date }[];
  status: "valid" | "expired" | "not_yet_valid" | "no_expiry";
  warnings: JwtWarning[];
}

function decodeSegment(seg: string, name: string): string {
  try {
    return utf8Decode(base64DecodeBytes(seg));
  } catch (e) {
    throw new Error(`The ${name} segment is not valid base64url: ${(e as Error).message}`);
  }
}

export function decodeJwt(token: string, now: Date = new Date()): DecodedJwt {
  const t = token.trim().replace(/^Bearer\s+/i, "");
  const parts = t.split(".");
  if (parts.length !== 3 && parts.length !== 5) throw new Error("A JWT has 3 dot-separated segments (JWS) or 5 (JWE)");

  let header: Record<string, unknown>;
  try {
    header = JSON.parse(decodeSegment(parts[0], "header"));
  } catch (e) {
    throw new Error(e instanceof SyntaxError ? "The header is not valid JSON" : (e as Error).message);
  }
  if (!header || typeof header !== "object" || Array.isArray(header)) throw new Error("The header must be a JSON object");

  const warnings: JwtWarning[] = [];
  let payload: Record<string, unknown> | null = null;
  let payloadText = "";

  if (parts.length === 5) {
    warnings.push({ level: "info", message: "This is an encrypted JWE token — the payload cannot be read without the decryption key." });
  } else {
    payloadText = decodeSegment(parts[1], "payload");
    try {
      const p = JSON.parse(payloadText);
      if (p && typeof p === "object" && !Array.isArray(p)) payload = p;
    } catch {
      warnings.push({ level: "info", message: "The payload is not JSON." });
    }
  }

  const alg = String(header.alg ?? "");
  if (!alg || alg.toLowerCase() === "none") warnings.push({ level: "danger", message: 'alg is "none": the token is unsigned. Servers must reject it.' });
  if (/^HS/i.test(alg))
    warnings.push({ level: "warning", message: `${alg} uses a shared secret. Weak secrets can be brute-forced offline — use long random keys.` });
  if (parts.length === 3 && !parts[2] && alg.toLowerCase() !== "none") warnings.push({ level: "danger", message: "The signature segment is empty." });
  if (header.jku || header.x5u) warnings.push({ level: "warning", message: "Header references a remote key (jku/x5u). Servers must restrict allowed key URLs." });
  if (header.kid && /[./\\'"]/.test(String(header.kid))) warnings.push({ level: "warning", message: "kid contains path or quote characters — check for injection in key lookup." });

  const times: DecodedJwt["times"] = [];
  for (const claim of ["iat", "nbf", "exp"] as const) {
    const v = payload?.[claim];
    if (typeof v === "number" && Number.isFinite(v)) times.push({ claim, value: v, date: new Date(v * 1000) });
  }

  let status: DecodedJwt["status"] = "no_expiry";
  const exp = payload?.exp;
  const nbf = payload?.nbf;
  const nowSec = now.getTime() / 1000;
  if (typeof nbf === "number" && nbf > nowSec) status = "not_yet_valid";
  else if (typeof exp === "number") status = exp < nowSec ? "expired" : "valid";
  if (payload && typeof exp !== "number") warnings.push({ level: "warning", message: "No exp claim: the token never expires." });
  if (typeof exp === "number" && typeof payload?.iat === "number" && exp - (payload.iat as number) > 60 * 60 * 24 * 30)
    warnings.push({ level: "info", message: "Lifetime exceeds 30 days." });

  return { header, payload, payloadText, signature: parts.length === 3 ? parts[2] : parts[4], parts: parts.length, times, status, warnings };
}
