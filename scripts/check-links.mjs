#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Relative links in the repository's Markdown files (Mission 12): every link to a file in the
// repository must point to a file that exists, and a link to a heading (`file.md#heading` or
// `#heading`) to a heading that exists, using GitHub's anchor rules. External links (http, https,
// mailto) are not fetched: their availability is outside the repository and would make CI flaky.
// Usage: node scripts/check-links.mjs        (exit 1 on a broken link; CI runs it)
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { dirname, join, normalize, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** GitHub's heading anchor: lower case, punctuation removed except '-' and '_', spaces to '-'. */
export function slug(heading) {
  return heading
    .trim()
    .toLowerCase()
    .replace(/<[^>]+>/g, "")
    .replace(/`/g, "")
    .replace(/[^\p{L}\p{N}\s_-]/gu, "")
    .replace(/\s/g, "-");
}

/** The anchors a Markdown file defines: headings (duplicates get -1, -2, …) and explicit ids. */
export function anchors(markdown) {
  const out = new Set();
  const seen = new Map();
  let fence = false;
  for (const line of markdown.split(/\r?\n/)) {
    if (/^\s*(```|~~~)/.test(line)) fence = !fence;
    if (fence) continue;
    const h = /^#{1,6}\s+(.+?)\s*#*\s*$/.exec(line);
    if (h) {
      const base = slug(h[1].replace(/\[([^\]]*)\]\([^)]*\)/g, "$1"));
      const n = seen.get(base) ?? 0;
      seen.set(base, n + 1);
      out.add(n ? `${base}-${n}` : base);
    }
    for (const m of line.matchAll(/<a\s+(?:name|id)="([^"]+)"/g)) out.add(m[1]);
  }
  return out;
}

/** Markdown links outside code: [text](target) and reference definitions [x]: target. */
export function links(markdown) {
  const out = [];
  let fence = false;
  markdown.split(/\r?\n/).forEach((line, i) => {
    if (/^\s*(```|~~~)/.test(line)) fence = !fence;
    if (fence) return;
    const text = line.replace(/`[^`]*`/g, "");
    for (const m of text.matchAll(/\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)/g)) out.push({ target: m[1], line: i + 1 });
    const def = /^\s*\[[^\]]+\]:\s*(\S+)/.exec(text);
    if (def) out.push({ target: def[1], line: i + 1 });
  });
  return out;
}

function main() {
  // tracked files and new ones not yet added (ignored files, such as node_modules, are left out)
  const files = execFileSync("git", ["ls-files", "--cached", "--others", "--exclude-standard", "*.md"], { cwd: ROOT, encoding: "utf8" }).split("\n").filter(Boolean);
  const cache = new Map();
  const anchorsOf = (abs) => {
    if (!cache.has(abs)) cache.set(abs, anchors(readFileSync(abs, "utf8")));
    return cache.get(abs);
  };
  const broken = [];
  let checked = 0;
  for (const file of files) {
    const abs = join(ROOT, file);
    for (const { target, line } of links(readFileSync(abs, "utf8"))) {
      if (/^[a-z][a-z0-9+.-]*:/i.test(target)) continue; // http:, https:, mailto: and other schemes
      checked++;
      const [path, hash] = target.split("#");
      const dest = path ? normalize(join(dirname(abs), decodeURIComponent(path))) : abs;
      if (!dest.startsWith(ROOT)) {
        broken.push(`${file}:${line}: ${target} leaves the repository`);
        continue;
      }
      if (!existsSync(dest)) {
        broken.push(`${file}:${line}: ${target} (no ${relative(ROOT, dest).replace(/\\/g, "/")})`);
        continue;
      }
      if (hash && dest.endsWith(".md") && statSync(dest).isFile() && !anchorsOf(dest).has(decodeURIComponent(hash))) {
        broken.push(`${file}:${line}: ${target} (no heading "#${hash}" in ${relative(ROOT, dest).replace(/\\/g, "/")})`);
      }
    }
  }
  console.log(`checked ${checked} relative links in ${files.length} Markdown files`);
  if (broken.length) {
    for (const b of broken) console.log(`::error::broken link: ${b}`);
    process.exit(1);
  }
  console.log("no broken relative link");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
