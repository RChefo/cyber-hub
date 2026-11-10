import { describe, expect, it } from "vitest";
import { shellQuote, splitArgs } from "./utils";

const QUOTES = /['\u2018-\u201B]/;

/** What PowerShell sees outside single-quoted text: plain words, spaces and the `"q"` joins only. */
function powershellSafe(line: string): boolean {
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (QUOTES.test(c)) {
        if (c !== "'") return false; // a typographic quote would end PowerShell's quoted text
        quoted = false;
      }
    } else if (c === "'") {
      quoted = true;
    } else if (c === '"') {
      if (!QUOTES.test(line[i + 1] ?? "") || line[i + 2] !== '"') return false;
      i += 2;
    } else if (!/[A-Za-z0-9_+=:./\- ]/.test(c)) {
      return false;
    }
  }
  return !quoted;
}

describe("shellQuote (Mission 7)", () => {
  const words = [
    "-sV",
    "10.0.0.1",
    "https://app.example.com/a;calc",
    "X: $(curl -s x|sh)",
    "`whoami`",
    "x\u2019;calc;\u2019",
    "it's",
    "\u2018\u201A\u201B",
    "80,443",
    "@splat",
    "--%",
    "~root",
    "a*b?[c]",
    "#c",
    "{x}",
    "a&b|c",
    "<in",
    ">out",
    "",
    "two words",
    "C:\\Program Files\\x.txt",
    "naïve",
    'say "hi"',
  ];

  it("reads back as the same words", () => {
    expect(splitArgs(words.map(shellQuote).join(" "))).toEqual(words);
  });

  it("leaves PowerShell nothing to run", () => {
    for (const w of words) expect(powershellSafe(shellQuote(w)), shellQuote(w)).toBe(true);
  });

  it("keeps plain words plain", () => {
    expect(shellQuote("-sV")).toBe("-sV");
    expect(shellQuote("https://a.example.com/x")).toBe("https://a.example.com/x");
    expect(shellQuote("80,443")).toBe("'80,443'");
    expect(shellQuote("x\u2019;calc")).toBe(`'x'"\u2019"';calc'`);
  });
});
