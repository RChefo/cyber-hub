// One-time extraction of the ExploitX wordmark outlines. The result, wordmark.json, is committed,
// so building the brand assets needs neither the font nor opentype.js.
//
// usage (outside the repository's dependencies):
//   npm install --prefix <tmp> opentype.js@2.0.0
//   NODE_PATH=<tmp>/node_modules node design/brand/build/extract-wordmark.mjs <Archivo-SemiBold.ttf>
//
// The font is Archivo by Omnibus-Type, SIL Open Font License 1.1, weight 600, normal width (a static
// instance, for example from the Google Fonts API). The OFL allows using its outlines in a logo; the
// letters are converted to paths and the X is drawn separately (it is the brand symbol's geometry).
import { createRequire } from "node:module";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const opentype = require("opentype.js");

const fontFile = process.argv[2];
if (!fontFile) throw new Error("usage: extract-wordmark.mjs <Archivo-SemiBold.ttf>");
const font = opentype.parse(readFileSync(fontFile).buffer);

const SIZE = 1000; // units per em of the output
const TRACKING = -0.012; // em, tighter than the font's default for a logotype
const scale = SIZE / font.unitsPerEm;
const capH = Math.round(font.charToGlyph("E").getBoundingBox().y2 * scale);
const stemBox = font.charToGlyph("I").getBoundingBox();
const stem = (stemBox.x2 - stemBox.x1) * scale;

let x = 0;
let prev = null;
const letters = [];
for (const ch of "Exploit") {
  const glyph = font.charToGlyph(ch);
  if (prev) x += font.getKerningValue(prev, glyph) * scale;
  // baseline at y = capH, so the cap height spans y 0..capH (SVG coordinates, y down)
  letters.push({ ch, d: glyph.getPath(x, capH, SIZE).toPathData(1) });
  x += glyph.advanceWidth * scale + TRACKING * SIZE;
  prev = glyph;
}
const xBox = font.charToGlyph("X").getBoundingBox();
const first = font.charToGlyph("E").getBoundingBox();
const out = {
  source: "Archivo SemiBold (600), Omnibus-Type, OFL-1.1; outlines converted to paths",
  unitsPerEm: SIZE,
  capHeight: capH,
  stem: Math.round(stem),
  tracking: TRACKING,
  leftBearing: Math.round(first.x1 * scale),
  exploitAdvance: Math.round(x),
  xGlyphWidth: Math.round((xBox.x2 - xBox.x1) * scale),
  xLeftBearing: Math.round(xBox.x1 * scale),
  descender: Math.round(-font.charToGlyph("p").getBoundingBox().y1 * scale),
  letters,
};
const here = dirname(fileURLToPath(import.meta.url));
writeFileSync(join(here, "wordmark.json"), JSON.stringify(out, null, 2) + "\n");
console.log("wrote wordmark.json", { capH, stem: out.stem, advance: out.exploitAdvance });
