// SPDX-License-Identifier: Apache-2.0
// ExploitX brand geometry and SVG builders. No dependencies: the wordmark's letters come from
// wordmark.json (extract-wordmark.mjs); the symbol and the X are defined here.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
export const WORDMARK = JSON.parse(readFileSync(join(here, "wordmark.json"), "utf8"));

/** Brand colours (design/brand/tokens.json is generated from the same values). */
export const C = {
  uv: "#7C6AFF", // Ultraviolet: primary
  uvDeep: "#5B45F0", // Ultraviolet on light backgrounds (text-safe)
  uvBright: "#9A8CFF",
  bone: "#F2F4F7", // the target chevron, text on dark
  ink: "#0B0D12", // text and marks on light
  night: "#0A0B10", // dark backgrounds
  signal: "#C8F03C", // accent, used sparingly
};

/*
 * The symbol, "Convergence": two chevrons that meet at one point. The left one is the operator's
 * input (Ultraviolet), the right one the target (Bone or Ink). 64-unit grid; the mark spans
 * x 6..58 and y 8..56, centred on (32, 32). The tips stop 2 units apart: a hairline that closes
 * at small sizes, where the mark reads as a solid X.
 */
export function symbolPolygons({ gap = 2, arm = 14 } = {}) {
  const tip = 32 - gap / 2;
  const left = [[6, 8], [6 + arm, 8], [tip, 32], [6 + arm, 56], [6, 56], [tip - arm, 32]];
  const right = left.map(([x, y]) => [64 - x, y]);
  return { left, right };
}

const fmt = (n) => (Math.round(n * 10) / 10).toString();
export const poly = (pts) => "M" + pts.map(([x, y]) => `${fmt(x)} ${fmt(y)}`).join("L") + "Z";

/** The wordmark's custom X: the symbol's construction at the letters' stem weight. */
function wordmarkX({ compact = false } = {}) {
  const { capHeight: H, stem, exploitAdvance, xGlyphWidth } = WORDMARK;
  const x0 = exploitAdvance + 14;
  const w = xGlyphWidth;
  const h = stem * (compact ? 1.26 : 1.18); // horizontal thickness of an arm
  const gap = compact ? 0 : stem * 0.2;
  const tip = x0 + w / 2 - gap / 2;
  const left = [[x0, 0], [x0 + h, 0], [tip, H / 2], [x0 + h, H], [x0, H], [tip - h, H / 2]];
  const right = left.map(([x, y]) => [2 * x0 + w - x, y]);
  return { left, right, end: x0 + w };
}

/** Wordmark paths in a box that starts at x = 0 (cap height 0..capHeight, descender below). */
export function wordmarkPaths({ compact = false } = {}) {
  const shift = -WORDMARK.leftBearing;
  const X = wordmarkX({ compact });
  const letters = WORDMARK.letters.map((l) => l.d).join("");
  return {
    d: letters + poly(X.left) + poly(X.right),
    shift,
    width: X.end + shift,
    capHeight: WORDMARK.capHeight,
    descender: WORDMARK.descender,
  };
}

/** Symbol group placed in a box of height `h` (the mark's 48-unit height) at (x, y). */
export function symbolGroup(x, y, h, leftFill, rightFill, opts = {}) {
  const s = h / 48;
  const { left, right } = symbolPolygons(opts);
  return `<g transform="translate(${fmt(x - 6 * s)} ${fmt(y - 8 * s)}) scale(${(s).toFixed(5)})"><path fill="${leftFill}" d="${poly(left)}"/><path fill="${rightFill}" d="${poly(right)}"/></g>`;
}

export const symbolWidth = (h) => (h * 52) / 48;

const svgOpen = (w, h, title, extra = "") =>
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${fmt(w)} ${fmt(h)}" width="${fmt(w)}" height="${fmt(h)}"${extra} role="img" aria-label="${title}"><title>${title}</title>`;

/**
 * Horizontal lockup: symbol, then the wordmark. Units are the wordmark's (cap height 686).
 * The symbol is 1.3 cap heights tall and centred on the caps; the gap is 0.62 cap heights.
 * Clear space: half the symbol's height on every side (included in the viewBox).
 */
export function horizontal({ uv = C.uv, target = C.bone, text = C.bone, compact = false, pad = true } = {}) {
  const wm = wordmarkPaths({ compact });
  const H = wm.capHeight;
  const symH = H * 1.3;
  const symW = symbolWidth(symH);
  const gap = H * (compact ? 0.55 : 0.62);
  const p = pad ? symH / 2 : 0;
  const top = p;
  const capTop = top + (symH - H) / 2;
  const width = p * 2 + symW + gap + wm.width;
  const height = p * 2 + symH;
  const sym = symbolGroup(p, top, symH, uv, target, compact ? { gap: 0 } : {});
  const words = `<path fill="${text}" transform="translate(${fmt(p + symW + gap + wm.shift)} ${fmt(capTop)})" d="${wm.d}"/>`;
  return { body: sym + words, width, height };
}

/** Stacked (primary) lockup: the symbol centred above the wordmark. */
export function stacked({ uv = C.uv, target = C.bone, text = C.bone, pad = true } = {}) {
  const wm = wordmarkPaths();
  const H = wm.capHeight;
  const symH = H * 2.6;
  const symW = symbolWidth(symH);
  const gap = H * 0.8;
  const p = pad ? H * 1.2 : 0;
  const width = p * 2 + Math.max(symW, wm.width);
  const height = p * 2 + symH + gap + H;
  const sym = symbolGroup((width - symW) / 2, p, symH, uv, target);
  const words = `<path fill="${text}" transform="translate(${fmt((width - wm.width) / 2 + wm.shift)} ${fmt(p + symH + gap)})" d="${wm.d}"/>`;
  return { body: sym + words, width, height };
}

export const svg = ({ body, width, height }, title, extra) => `${svgOpen(width, height, title, extra)}${body}</svg>\n`;

/** The symbol alone on the 64-unit square (clear space included). */
export function symbolSvg({ uv = C.uv, target = C.bone, title = "ExploitX symbol", gap = 2 } = {}) {
  const { left, right } = symbolPolygons({ gap });
  return `${svgOpen(64, 64, title)}<path fill="${uv}" d="${poly(left)}"/><path fill="${target}" d="${poly(right)}"/></svg>\n`;
}

/**
 * The application icon: the symbol on a rounded "night" tile, 1024 units.
 * small = true is the optical version for 16–32 px: larger mark, no hairline gap, no glow.
 */
export function appIcon({ small = false } = {}) {
  const S = 1024;
  const inset = small ? 16 : 72;
  const r = small ? 196 : 188;
  const tile = S - inset * 2;
  const symH = small ? tile * 0.6 : tile * 0.5;
  const symW = symbolWidth(symH);
  const x = (S - symW) / 2;
  const y = (S - symH) / 2;
  const defs = `<defs><linearGradient id="t" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#1A1C2A"/><stop offset="1" stop-color="#0C0D14"/></linearGradient>${
    small ? "" : `<radialGradient id="g" cx="0.5" cy="0.5" r="0.5"><stop offset="0" stop-color="${C.uv}" stop-opacity="0.32"/><stop offset="1" stop-color="${C.uv}" stop-opacity="0"/></radialGradient>`
  }</defs>`;
  const glow = small ? "" : `<circle cx="512" cy="512" r="${fmt(tile * 0.42)}" fill="url(#g)"/>`;
  const edge = `<rect x="${inset + 4}" y="${inset + 4}" width="${tile - 8}" height="${tile - 8}" rx="${r - 4}" fill="none" stroke="#FFFFFF" stroke-opacity="0.07" stroke-width="8"/>`;
  return `${svgOpen(S, S, "ExploitX")}${defs}<rect x="${inset}" y="${inset}" width="${tile}" height="${tile}" rx="${r}" fill="url(#t)"/>${glow}${small ? "" : edge}${symbolGroup(x, y, symH, C.uv, C.bone, small ? { gap: 0 } : {})}</svg>\n`;
}
