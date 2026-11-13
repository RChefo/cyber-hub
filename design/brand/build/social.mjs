// SPDX-License-Identifier: Apache-2.0
// Social and marketing images of the ExploitX identity, composed from the vector logo, the brand fonts
// and real screenshots of the app (design/brand/screens). The HTML templates are written to a
// temporary folder and rendered with headless Chrome to design/brand/social/*.png.
// usage: node design/brand/build/social.mjs
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import * as B from "./brand.mjs";
import { tokens } from "./tokens.mjs";

const brand = join(dirname(fileURLToPath(import.meta.url)), "..");
const repo = join(brand, "..", "..");
const tpl = mkdtempSync(join(tmpdir(), "exploitx-social-"));
mkdirSync(join(brand, "social"), { recursive: true });
const CHROME = process.env.CHROME ?? ["C:/Program Files/Google/Chrome/Application/chrome.exe", "/usr/bin/google-chrome", "/usr/bin/chromium"].find((p) => existsSync(p));
const url = (rel) => pathToFileURL(join(repo, rel)).href;
const shot = (name) => url(`design/brand/screens/${name}.webp`);
const UV = tokens.brand.ultraviolet;

const fonts = `
@font-face{font-family:"Archivo";src:url(${url("node_modules/@fontsource-variable/archivo/files/archivo-latin-wdth-normal.woff2")}) format("woff2");font-weight:100 900;font-stretch:62% 125%}
@font-face{font-family:"Plex";src:url(${url("node_modules/@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-400-normal.woff2")}) format("woff2");font-weight:400}
@font-face{font-family:"Plex";src:url(${url("node_modules/@fontsource/ibm-plex-sans/files/ibm-plex-sans-latin-500-normal.woff2")}) format("woff2");font-weight:500}
@font-face{font-family:"Mono";src:url(${url("node_modules/@fontsource-variable/jetbrains-mono/files/jetbrains-mono-latin-wght-normal.woff2")}) format("woff2");font-weight:100 800}`;

const lockup = (capPx, { text = C.bone, uv = UV[500], target = C.bone } = {}) => {
  const L = B.horizontal({ uv, target, text, pad: false });
  const s = capPx / B.WORDMARK.capHeight;
  return `<svg width="${(L.width * s).toFixed(1)}" height="${(L.height * s).toFixed(1)}" viewBox="0 0 ${L.width} ${L.height}" role="img" aria-label="ExploitX">${L.body}</svg>`;
};
const symbol = (h, { uv = UV[500], target = C.bone } = {}) => {
  const { left, right } = B.symbolPolygons();
  return `<svg width="${(h * 52) / 48}" height="${h}" viewBox="6 8 52 48"><path fill="${uv}" d="${B.poly(left)}"/><path fill="${target}" d="${B.poly(right)}"/></svg>`;
};
const { C } = B;

/** The brand's background device: two fans of hairlines that converge on one point, very faint. */
const field = (w, h, fx, fy, opacity = 0.07) => {
  let lines = "";
  for (let i = 0; i <= 16; i++) {
    const y = (h * i) / 16;
    lines += `<line x1="0" y1="${y}" x2="${fx}" y2="${fy}"/><line x1="${w}" y1="${y}" x2="${fx}" y2="${fy}"/>`;
  }
  return `<svg class="field" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><g stroke="#B4A9FF" stroke-opacity="${opacity}" stroke-width="1">${lines}</g></svg>`;
};

const page = (w, h, body, extra = "") => `<!doctype html><html><head><meta charset="utf-8"><style>${fonts}
*{box-sizing:border-box}html,body{margin:0;width:${w}px;height:${h}px;overflow:hidden;background:${tokens.neutral.background};color:${C.bone};font-family:Plex,sans-serif}
.field{position:absolute;inset:0}
.glow{position:absolute;border-radius:50%;background:radial-gradient(closest-side,rgba(124,106,255,.30),rgba(124,106,255,.06) 55%,transparent)}
.display{font-family:Archivo,sans-serif;font-variation-settings:"wdth" 106;font-weight:600;letter-spacing:-.025em;line-height:1.02}
.muted{color:${tokens.neutral.textMuted}}
.frame{position:absolute;border-radius:16px;overflow:hidden;background:${tokens.neutral.surface};box-shadow:0 0 0 1px rgba(255,255,255,.07),0 40px 90px -30px rgba(0,0,0,.85),0 14px 34px -18px rgba(0,0,0,.7)}
.frame img{display:block;width:100%;height:auto}
.uv{color:${UV[300]}}
${extra}</style></head><body>${body}</body></html>`;

const designs = {
  // GitHub repository social preview (Settings → General → Social preview), 1280 × 640
  "github-social-preview": [1280, 640, `
    ${field(1280, 640, 780, 330)}
    <div class="glow" style="left:560px;top:40px;width:900px;height:620px"></div>
    <div style="position:absolute;left:80px;top:96px">${lockup(40)}</div>
    <div class="display" style="position:absolute;left:80px;top:232px;font-size:56px;width:520px">From first signal<br><span class="uv">to final report.</span></div>
    <div class="muted" style="position:absolute;left:80px;top:400px;font-size:22px;line-height:1.45;width:470px">Cybersecurity intelligence and security research platform for Windows and Linux.</div>
    <div class="frame" style="left:640px;top:150px;width:780px"><img src="${shot("osint-graph")}"></div>`],
  // Website Open Graph / Twitter image (public/og.png in RChefo/ExploitX-Web), 1200 × 630
  "website-og": [1200, 630, `
    ${field(1200, 630, 720, 320)}
    <div class="glow" style="left:500px;top:30px;width:860px;height:620px"></div>
    <div style="position:absolute;left:72px;top:92px">${lockup(38)}</div>
    <div class="display" style="position:absolute;left:72px;top:222px;font-size:54px;width:500px">From first signal<br><span class="uv">to final report.</span></div>
    <div class="muted" style="position:absolute;left:72px;top:390px;font-size:21px;line-height:1.45;width:440px">Cybersecurity intelligence and security research platform. Local-first, for Windows and Linux.</div>
    <div class="frame" style="left:600px;top:140px;width:740px"><img src="${shot("dashboard")}"></div>`],
  // Square avatar (GitHub organisation, social profiles); safe inside a circle crop, 1024 × 1024
  "avatar": [1024, 1024, `
    <div class="glow" style="left:112px;top:112px;width:800px;height:800px"></div>
    <div style="position:absolute;left:50%;top:50%;transform:translate(-50%,-50%)">${symbol(420)}</div>`],
  // Wide banner (X/LinkedIn style headers), 1500 × 500; the lower-left corner stays clear for an avatar overlay
  "banner": [1500, 500, `
    ${field(1500, 500, 1040, 250, 0.08)}
    <div class="glow" style="left:760px;top:-120px;width:620px;height:740px"></div>
    <div style="position:absolute;left:560px;top:150px">${lockup(52)}</div>
    <div class="muted" style="position:absolute;left:562px;top:262px;font-size:24px">Cybersecurity intelligence &amp; security research platform</div>
    <div style="position:absolute;left:562px;top:318px;font-family:Mono,monospace;font-size:16px;letter-spacing:.04em;color:${UV[300]}">exploitx.net</div>`],
  // Product announcement (16:9 social post), 1200 × 675
  "announcement": [1200, 675, `
    ${field(1200, 675, 600, 250)}
    <div class="glow" style="left:240px;top:-60px;width:720px;height:560px"></div>
    <div style="position:absolute;left:0;right:0;top:70px;text-align:center;font-size:20px;letter-spacing:.02em" class="muted">Cyber Hub is now</div>
    <div style="position:absolute;left:50%;top:118px;transform:translateX(-50%)">${lockup(64)}</div>
    <div style="position:absolute;left:0;right:0;top:250px;text-align:center;font-size:22px;color:#c9cedb">The same local-first security research platform, with a new name and identity.</div>
    <div class="frame" style="left:150px;top:330px;width:900px"><img src="${shot("dashboard")}"></div>`],
  // Desktop application promotional visual (presentations, website, release posts), 1920 × 1080
  "desktop-promo": [1920, 1080, `
    ${field(1920, 1080, 1180, 560)}
    <div class="glow" style="left:760px;top:60px;width:1300px;height:1000px"></div>
    <div style="position:absolute;left:120px;top:150px">${lockup(44)}</div>
    <div class="display" style="position:absolute;left:120px;top:330px;font-size:76px;width:640px">From first signal<br><span class="uv">to final report.</span></div>
    <div class="muted" style="position:absolute;left:120px;top:560px;font-size:26px;line-height:1.5;width:560px">Security testing, OSINT investigations, threat and vulnerability intelligence, detection engineering and reporting in one desktop platform.</div>
    <div style="position:absolute;left:120px;top:800px;font-family:Mono,monospace;font-size:19px;letter-spacing:.04em;color:${UV[300]}">Windows 10/11 · Linux · x64 · local-first</div>
    <div class="frame" style="left:800px;top:190px;width:1240px"><img src="${shot("osint-graph")}"></div>`],
};

for (const [name, [w, h, body]] of Object.entries(designs)) {
  const file = join(tpl, `${name}.html`);
  writeFileSync(file, page(w, h, body));
  const out = join(brand, "social", `${name}.png`);
  execFileSync(CHROME, ["--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=1", "--allow-file-access-from-files", `--window-size=${w},${h}`, `--screenshot=${out}`, pathToFileURL(file).href], { stdio: "ignore" });
  console.log(`social/${name}.png ${w}x${h}`);
}
