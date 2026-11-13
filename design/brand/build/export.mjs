// Raster exports of the ExploitX identity: PNG logos, application icons (Windows ICO, Linux hicolor,
// Tauri's icon set), favicons. Renders the SVG sources with headless Chrome (set CHROME to its path).
// usage: node design/brand/build/export.mjs [--tauri]   (--tauri also refreshes src-tauri/icons)
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const brand = join(dirname(fileURLToPath(import.meta.url)), "..");
const repo = join(brand, "..", "..");
const CHROME = process.env.CHROME ?? [
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
].find((p) => existsSync(p));
if (!CHROME) throw new Error("set CHROME to a Chrome or Chromium executable");
const work = mkdtempSync(join(tmpdir(), "exploitx-export-"));

/** Renders an SVG file to a PNG of exactly w × h pixels, transparent unless `background` is given. */
export function render(svgFile, outFile, w, h = w, { background = "transparent" } = {}) {
  const html = join(work, "page.html");
  writeFileSync(html, `<!doctype html><html><head><style>html,body{margin:0;background:${background};overflow:hidden}img{display:block;width:${w}px;height:${h}px}</style></head><body><img src="${pathToFileURL(svgFile).href}"></body></html>`);
  mkdirSync(dirname(outFile), { recursive: true });
  execFileSync(CHROME, [
    "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1",
    ...(background === "transparent" ? ["--default-background-color=00000000"] : []),
    `--window-size=${w},${h}`, `--screenshot=${outFile}`, pathToFileURL(html).href,
  ], { stdio: "ignore" });
  return outFile;
}

/** An ICO file holding PNG images (Windows Vista and later read PNG entries). */
export function ico(pngFiles, outFile) {
  const images = pngFiles.map((f) => readFileSync(f));
  const header = Buffer.alloc(6 + 16 * images.length);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(images.length, 4);
  let offset = header.length;
  images.forEach((png, i) => {
    const w = png.readUInt32BE(16), h = png.readUInt32BE(20); // IHDR
    const e = 6 + i * 16;
    header.writeUInt8(w >= 256 ? 0 : w, e);
    header.writeUInt8(h >= 256 ? 0 : h, e + 1);
    header.writeUInt8(0, e + 2);
    header.writeUInt8(0, e + 3);
    header.writeUInt16LE(1, e + 4);
    header.writeUInt16LE(32, e + 6);
    header.writeUInt32LE(png.length, e + 8);
    header.writeUInt32LE(offset, e + 12);
    offset += png.length;
  });
  writeFileSync(outFile, Buffer.concat([header, ...images]));
  return outFile;
}

const svg = (name) => join(brand, name);
/** The small-size master (no hairline gap, larger mark) up to 48 px, the full icon above. */
const iconSource = (size) => (size <= 48 ? svg("app-icon-small.svg") : svg("app-icon.svg"));
const out = [];
const R = (src, rel, w, h, opts) => out.push(render(src, join(brand, rel), w, h, opts));

// application icons
for (const s of [16, 20, 24, 32, 40, 48, 64, 128, 256, 512, 1024]) R(iconSource(s), `png/app-icon-${s}.png`, s);
mkdirSync(join(brand, "icons/windows"), { recursive: true });
out.push(ico([16, 20, 24, 32, 40, 48, 64, 128, 256].map((s) => join(brand, `png/app-icon-${s}.png`)), join(brand, "icons/windows/exploitx.ico")));
for (const s of [16, 24, 32, 48, 64, 128, 256, 512]) {
  const dir = join(brand, `icons/linux/hicolor/${s}x${s}/apps`);
  mkdirSync(dir, { recursive: true });
  copyFileSync(join(brand, `png/app-icon-${s}.png`), join(dir, "exploitx.png"));
}
// favicons
for (const s of [16, 32, 48]) R(svg("favicon.svg"), `icons/favicon/favicon-${s}.png`, s);
out.push(ico([16, 32, 48].map((s) => join(brand, `icons/favicon/favicon-${s}.png`)), join(brand, "icons/favicon/favicon.ico")));
R(svg("app-icon.svg"), "icons/favicon/apple-touch-icon.png", 180, 180, { background: "#0A0B10" });
R(svg("app-icon.svg"), "icons/favicon/icon-192.png", 192);
R(svg("app-icon.svg"), "icons/favicon/icon-512.png", 512);
// logos (transparent), 1x and 2x of a 480 px wide horizontal lockup
const ratio = (file) => {
  const m = readFileSync(svg(file), "utf8").match(/viewBox="0 0 ([\d.]+) ([\d.]+)"/);
  return Number(m[2]) / Number(m[1]);
};
for (const f of ["logo-horizontal", "logo-light", "logo-dark", "logo-compact", "logo-monochrome", "logo-wordmark", "logo-wordmark-light"]) {
  for (const [suffix, w] of [["", 480], ["@2x", 960], ["@4x", 1920]]) R(svg(`${f}.svg`), `png/${f}${suffix}.png`, w, Math.round(w * ratio(`${f}.svg`)));
}
for (const f of ["logo-primary", "logo-primary-light", "logo-monochrome-stacked"]) {
  for (const [suffix, w] of [["", 400], ["@2x", 800]]) R(svg(`${f}.svg`), `png/${f}${suffix}.png`, w, Math.round(w * ratio(`${f}.svg`)));
}
for (const f of ["logo-symbol", "logo-symbol-light", "logo-symbol-monochrome"]) for (const s of [64, 256, 1024]) R(svg(`${f}.svg`), `png/${f}-${s}.png`, s);

if (process.argv.includes("--tauri")) {
  // the files tauri.conf.json lists, plus Tauri's other standard names (same set `tauri icon` writes)
  const icons = join(repo, "src-tauri/icons");
  const map = { "32x32.png": 32, "64x64.png": 64, "128x128.png": 128, "128x128@2x.png": 256, "icon.png": 512,
    "Square30x30Logo.png": 30, "Square44x44Logo.png": 44, "Square71x71Logo.png": 71, "Square89x89Logo.png": 89,
    "Square107x107Logo.png": 107, "Square142x142Logo.png": 142, "Square150x150Logo.png": 150,
    "Square284x284Logo.png": 284, "Square310x310Logo.png": 310, "StoreLogo.png": 50 };
  for (const [name, s] of Object.entries(map)) out.push(render(iconSource(s), join(icons, name), s));
  copyFileSync(join(brand, "icons/windows/exploitx.ico"), join(icons, "icon.ico"));
  out.push(join(icons, "icon.ico"));
}
console.log(`${out.length} files`);
