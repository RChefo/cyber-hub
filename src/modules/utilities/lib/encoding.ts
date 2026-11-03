/** Pure, UTF-8 safe encoding helpers shared by the individual utilities and the workbench. */

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

export function utf8Encode(s: string): Uint8Array {
  return enc.encode(s);
}

export function utf8Decode(b: Uint8Array): string {
  try {
    return dec.decode(b);
  } catch {
    throw new Error("Decoded bytes are not valid UTF-8 text");
  }
}

function bytesToBinaryString(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return s;
}

export function base64EncodeBytes(bytes: Uint8Array, urlSafe = false): string {
  const b64 = btoa(bytesToBinaryString(bytes));
  return urlSafe ? b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : b64;
}

export function base64DecodeBytes(input: string): Uint8Array {
  let s = input.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new Error("Input contains characters that are not valid Base64");
  const rem = s.length % 4;
  if (rem === 1) throw new Error("Invalid Base64 length");
  if (rem) s += "=".repeat(4 - rem);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const base64Encode = (s: string, urlSafe = false) => base64EncodeBytes(utf8Encode(s), urlSafe);
export const base64Decode = (s: string) => utf8Decode(base64DecodeBytes(s));

export function urlEncode(s: string, mode: "component" | "uri" = "component"): string {
  return mode === "component" ? encodeURIComponent(s) : encodeURI(s);
}

export function urlDecode(s: string, plusAsSpace = false): string {
  try {
    return decodeURIComponent(plusAsSpace ? s.replace(/\+/g, " ") : s);
  } catch {
    throw new Error("Malformed percent-encoding (an incomplete or invalid %XX sequence)");
  }
}

export function hexEncode(s: string, separator = "", uppercase = false): string {
  const parts = Array.from(utf8Encode(s), (b) => b.toString(16).padStart(2, "0"));
  const out = parts.join(separator);
  return uppercase ? out.toUpperCase() : out;
}

export function hexDecodeBytes(input: string): Uint8Array {
  const clean = input.replace(/0x/gi, "").replace(/\\x/gi, "").replace(/[\s:,-]/g, "");
  if (clean.length % 2) throw new Error("Hex input has an odd number of digits");
  if (!/^[0-9a-fA-F]*$/.test(clean)) throw new Error("Input contains non-hex characters");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export const hexDecode = (s: string) => utf8Decode(hexDecodeBytes(s));

const HTML_ESCAPES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const NAMED: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", copy: "©", reg: "®" };

export function htmlEscape(s: string): string {
  return s.replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

export function htmlUnescape(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, body: string) => {
    if (body[0] === "#") {
      const code = body[1].toLowerCase() === "x" ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : m;
    }
    return NAMED[body.toLowerCase()] ?? m;
  });
}

export function rot13(s: string): string {
  return s.replace(/[a-z]/gi, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

export function unicodeEscape(s: string): string {
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0)!;
    if (cp < 0x80 && cp >= 0x20) out += ch;
    else if (cp > 0xffff) {
      const hi = Math.floor((cp - 0x10000) / 0x400) + 0xd800;
      const lo = ((cp - 0x10000) % 0x400) + 0xdc00;
      out += `\\u${hi.toString(16).padStart(4, "0")}\\u${lo.toString(16).padStart(4, "0")}`;
    } else out += `\\u${cp.toString(16).padStart(4, "0")}`;
  }
  return out;
}

export function unicodeUnescape(s: string): string {
  return s
    .replace(/\\u\{([0-9a-f]{1,6})\}/gi, (_, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/\\u([0-9a-f]{4})/gi, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\x([0-9a-f]{2})/gi, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
}

export function binaryEncode(s: string): string {
  return Array.from(utf8Encode(s), (b) => b.toString(2).padStart(8, "0")).join(" ");
}

export function binaryDecode(s: string): string {
  const clean = s.replace(/[\s,]/g, "");
  if (!/^[01]*$/.test(clean)) throw new Error("Binary input may only contain 0 and 1");
  if (clean.length % 8) throw new Error("Binary input length must be a multiple of 8 bits");
  const out = new Uint8Array(clean.length / 8);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 8, 8), 2);
  return utf8Decode(out);
}

export async function digestHex(algorithm: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512", data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? utf8Encode(data) : data;
  const buf = await crypto.subtle.digest(algorithm, bytes as BufferSource);
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}
