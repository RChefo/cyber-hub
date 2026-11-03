/** Workbench (recipe) operations. Each op maps a string to a string (sync or async). */
import {
  base64Decode,
  base64Encode,
  binaryDecode,
  binaryEncode,
  digestHex,
  hexDecode,
  hexEncode,
  htmlEscape,
  htmlUnescape,
  rot13,
  unicodeEscape,
  unicodeUnescape,
  urlDecode,
  urlEncode,
} from "./encoding";
import { formatJson } from "./format";
import { md5Hex } from "./md5";

export interface Operation {
  id: string;
  name: string;
  group: "Encoding" | "Text" | "Data" | "Hashing";
  run: (input: string) => string | Promise<string>;
}

export const OPERATIONS: Operation[] = [
  { id: "b64-enc", name: "Base64 encode", group: "Encoding", run: (s) => base64Encode(s) },
  { id: "b64-dec", name: "Base64 decode", group: "Encoding", run: (s) => base64Decode(s) },
  { id: "b64url-enc", name: "Base64url encode", group: "Encoding", run: (s) => base64Encode(s, true) },
  { id: "b64url-dec", name: "Base64url decode", group: "Encoding", run: (s) => base64Decode(s) },
  { id: "url-enc", name: "URL encode", group: "Encoding", run: (s) => urlEncode(s) },
  { id: "url-dec", name: "URL decode", group: "Encoding", run: (s) => urlDecode(s) },
  { id: "hex-enc", name: "Hex encode", group: "Encoding", run: (s) => hexEncode(s) },
  { id: "hex-dec", name: "Hex decode", group: "Encoding", run: (s) => hexDecode(s) },
  { id: "html-enc", name: "HTML entity encode", group: "Encoding", run: htmlEscape },
  { id: "html-dec", name: "HTML entity decode", group: "Encoding", run: htmlUnescape },
  { id: "uni-esc", name: "Unicode escape (\\uXXXX)", group: "Encoding", run: unicodeEscape },
  { id: "uni-unesc", name: "Unicode unescape", group: "Encoding", run: unicodeUnescape },
  { id: "bin-enc", name: "To binary", group: "Encoding", run: binaryEncode },
  { id: "bin-dec", name: "From binary", group: "Encoding", run: binaryDecode },
  { id: "rot13", name: "ROT13", group: "Text", run: rot13 },
  { id: "reverse", name: "Reverse", group: "Text", run: (s) => Array.from(s).reverse().join("") },
  { id: "upper", name: "To uppercase", group: "Text", run: (s) => s.toUpperCase() },
  { id: "lower", name: "To lowercase", group: "Text", run: (s) => s.toLowerCase() },
  { id: "trim", name: "Trim", group: "Text", run: (s) => s.trim() },
  { id: "strip-ws", name: "Remove whitespace", group: "Text", run: (s) => s.replace(/\s+/g, "") },
  { id: "count", name: "Count characters and lines", group: "Text", run: (s) => `${Array.from(s).length} characters\n${s ? s.split("\n").length : 0} lines\n${new TextEncoder().encode(s).length} bytes (UTF-8)` },
  { id: "json-pretty", name: "JSON pretty print", group: "Data", run: (s) => formatJson(s, { indent: 2 }) },
  { id: "json-min", name: "JSON minify", group: "Data", run: (s) => formatJson(s, { indent: 0 }) },
  { id: "md5", name: "MD5", group: "Hashing", run: (s) => md5Hex(s) },
  { id: "sha1", name: "SHA-1", group: "Hashing", run: (s) => digestHex("SHA-1", s) },
  { id: "sha256", name: "SHA-256", group: "Hashing", run: (s) => digestHex("SHA-256", s) },
];

export const opById = (id: string) => OPERATIONS.find((o) => o.id === id);

export interface StepResult {
  output: string | null;
  error: string | null;
}

/** Runs an enabled recipe; stops at the first failing step. */
export async function runRecipe(input: string, steps: { opId: string; enabled: boolean }[]): Promise<{ results: StepResult[]; output: string; failedAt: number | null }> {
  let cur = input;
  const results: StepResult[] = [];
  let failedAt: number | null = null;
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    if (failedAt !== null || !step.enabled) {
      results.push({ output: null, error: null });
      continue;
    }
    const op = opById(step.opId);
    if (!op) {
      results.push({ output: null, error: "Unknown operation" });
      failedAt = i;
      continue;
    }
    try {
      cur = await op.run(cur);
      results.push({ output: cur, error: null });
    } catch (e) {
      results.push({ output: null, error: (e as Error).message });
      failedAt = i;
    }
  }
  return { results, output: cur, failedAt };
}
