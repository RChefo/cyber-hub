// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { shellQuote, splitArgs } from "./utils";

const QUOTES = /['\u2018-\u201B]/;

/** Special inside double quotes for PowerShell (`$`, backtick, `"` and its typographic forms) or a POSIX shell (`$`, backtick, `"`, `\`, `!`). */
const DOUBLE_SPECIAL = /[$`"\\!\u201C-\u201E]/;

/** What PowerShell sees outside quoted text: plain words, spaces, the `"q"` joins, and whole words
 * in double quotes with nothing special inside (Mission 8). */
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
      if (QUOTES.test(line[i + 1] ?? "") && line[i + 2] === '"') {
        i += 2;
        continue;
      }
      const end = line.indexOf('"', i + 1);
      if (end < 0 || DOUBLE_SPECIAL.test(line.slice(i + 1, end))) return false;
      if (end + 1 < line.length && line[end + 1] !== " ") return false; // a whole word only
      i = end;
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
    expect(shellQuote("x\u2019;calc")).toBe(`"x\u2019;calc"`);
  });
});

describe("shellQuote (Mission 8): words with a quote", () => {
  const exact = ["it's", "' OR 1=1--", "O\u2019Brien & co", "a'b;c|d", "'"];
  const joined = ["it's $HOME", "'`x`'", 'say "it\'s"', "C:\\it's", "it's!", "\u201Cit's\u201D"];

  it("puts a word with a quote and nothing else special in double quotes, which PowerShell reads whole", () => {
    for (const w of exact) {
      expect(shellQuote(w)).toBe(`"${w}"`);
      expect(powershellSafe(shellQuote(w))).toBe(true);
    }
  });

  it("joins around the quote only when a special character makes double quotes unsafe", () => {
    for (const w of joined) {
      expect(shellQuote(w).startsWith("'"), shellQuote(w)).toBe(true);
      expect(powershellSafe(shellQuote(w)), shellQuote(w)).toBe(true);
    }
  });

  it("reads back as the same words", () => {
    expect(splitArgs([...exact, ...joined].map(shellQuote).join(" "))).toEqual([...exact, ...joined]);
  });

  it("matches the backend's history lines", () => {
    // the same expectations as commands/tools.rs (history_lines_paste_back_as_the_same_words)
    expect(shellQuote("it's $HOME")).toBe(`'it'"'"'s $HOME'`);
    expect(shellQuote("' OR 1=1--")).toBe(`"' OR 1=1--"`);
  });
});
