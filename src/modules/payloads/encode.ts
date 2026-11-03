/** Encode-on-copy transforms for payloads. Pure functions, unit tested. */

export type PayloadEncoding = "none" | "url" | "double-url" | "base64" | "html";

export const ENCODING_LABELS: Record<PayloadEncoding, string> = {
  none: "No encoding",
  url: "URL-encode",
  "double-url": "Double URL-encode",
  base64: "Base64",
  html: "HTML entities",
};

/** Percent-encodes everything except unreserved characters (RFC 3986), including !'()*. */
export function urlEncode(input: string): string {
  return encodeURIComponent(input).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

export function doubleUrlEncode(input: string): string {
  return urlEncode(urlEncode(input));
}

/** UTF-8 safe Base64. */
export function base64Encode(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

/** Encodes HTML-significant characters and any non-ASCII code point as numeric entities. */
export function htmlEntityEncode(input: string): string {
  const named: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  let out = "";
  for (const ch of input) {
    if (named[ch]) out += named[ch];
    else {
      const cp = ch.codePointAt(0)!;
      out += cp > 0x7e ? `&#x${cp.toString(16).toUpperCase()};` : ch;
    }
  }
  return out;
}

export function encodePayload(input: string, encoding: PayloadEncoding): string {
  switch (encoding) {
    case "url":
      return urlEncode(input);
    case "double-url":
      return doubleUrlEncode(input);
    case "base64":
      return base64Encode(input);
    case "html":
      return htmlEntityEncode(input);
    default:
      return input;
  }
}
