// Layout probe (Mission 7): renders every page of a running development build at the logical
// sizes that common display scalings give, and reports horizontal overflow, content that cannot be
// reached, and dialogs that do not fit. QA only; it changes nothing but the emulated viewport.
//
// Windows, development build only (WebView2 exposes DevTools there):
//   1. npx vite --port 1420
//   2. set CYBERHUB_DATA_DIR to a disposable folder, set
//      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9223, start
//      src-tauri/target/debug/cyber-hub.exe (cargo build --no-default-features)
//   3. node scripts/qa/layout-probe.mjs <label> [WxHxDPR ...]
// Default sizes: 1920x1080 at 100, 125, 150 and 200 % under a 40-48 px taskbar, and the 800x480
// minimum. Screenshots and a JSON result go to scripts/qa/out/<label>/ (git-ignored).
import { writeFileSync, mkdirSync } from "node:fs";

const [label = "run", ...sizeArgs] = process.argv.slice(2);
const SIZES = (sizeArgs.length ? sizeArgs : ["1920x1040x1", "1536x826x1.25", "1280x688x1.5", "960x516x2", "800x480x1"]).map((s) => {
  const [w, h, d] = s.split("x").map(Number);
  return { w, h, d };
});
const OUT = new URL(`./out/${label}/`, import.meta.url);
mkdirSync(OUT, { recursive: true });
const targets = await (await fetch("http://127.0.0.1:9223/json")).json();
const page = targets.find((t) => t.type === "page" && t.url.startsWith("http://localhost:1420"));
const ws = new WebSocket(page.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let seq = 0;
const pending = new Map();
ws.addEventListener("message", (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) {
    pending.get(msg.id)(msg);
    pending.delete(msg.id);
  }
});
const send = (method, params = {}) =>
  new Promise((resolve, reject) => {
    const i = ++seq;
    pending.set(i, (msg) => (msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result)));
    ws.send(JSON.stringify({ id: i, method, params }));
  });
const ev = async (expression) => {
  const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? JSON.stringify(r.exceptionDetails));
  return r.result.value;
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function click(match, { exact = true, scope = "document" } = {}) {
  const pos = await ev(`(() => {
    const want = ${JSON.stringify(match)}, exact = ${exact};
    const root = ${scope === "document" ? "document" : `document.querySelector(${JSON.stringify(scope)})`};
    if (!root) return null;
    const els = [...root.querySelectorAll('button,[role=tab],[role=radio],[role=menuitem],[role=option],a,[role=button]')]
      .filter(e => { const t = (e.innerText || '').trim() || (e.getAttribute('aria-label') || '').trim(); return (exact ? t === want : t.includes(want)) && e.getBoundingClientRect().width > 0; })
      .sort((a, b) => a.innerText.length - b.innerText.length);
    const e = els[0];
    if (!e) return null;
    e.scrollIntoView({ block: 'center', inline: 'center' });
    const r = e.getBoundingClientRect();
    return { x: r.x + r.width / 2, y: r.y + r.height / 2 };
  })()`);
  if (!pos) return false;
  for (const type of ["mousePressed", "mouseReleased"]) await send("Input.dispatchMouseEvent", { type, x: pos.x, y: pos.y, button: "left", clickCount: 1 });
  await sleep(700);
  return true;
}
const PROBE = `(() => {
  const W = innerWidth, H = innerHeight;
  const main = document.getElementById('main-scroll');
  // reachable: inside a horizontally scrolling container that is itself on screen; content cut by
  // a non-scrolling container, or past the window, is not reachable
  const reachable = (el) => { for (let p = el.parentElement; p && p !== document.documentElement; p = p.parentElement) { const ox = getComputedStyle(p).overflowX; if (/(auto|scroll)/.test(ox)) return p.getBoundingClientRect().right <= W + 1; } return false; };
  const bad = [];
  for (const el of document.querySelectorAll('aside *, header *, main *, [role=dialog] *')) {
    if (el.closest('svg') && el.tagName.toLowerCase() !== 'svg') continue;
    const r = el.getBoundingClientRect();
    if (r.width === 0 || r.height === 0 || r.right <= W + 1) continue;
    if (reachable(el)) continue;
    const name = el.tagName.toLowerCase() + (el.getAttribute('aria-label') ? '[' + el.getAttribute('aria-label').slice(0, 30) + ']' : '') + ' "' + (el.innerText || '').trim().slice(0, 30).replace(/\\s+/g, ' ') + '"';
    bad.push(name + ' →' + Math.round(r.right));
  }
  return { W, H, docX: document.documentElement.scrollWidth - W, mainX: main ? main.scrollWidth - main.clientWidth : null, bad: bad.slice(0, 5), badCount: bad.length, title: (document.querySelector('header')?.innerText || '').split('\\n')[0] };
})()`;
const SIDEBAR = ["Dashboard", "Projects", "Finding Library", "Detections", "Runs", "Tools Library", "Command Center", "Payloads & Wordlists", "OSINT Workspace", "Dorks Studio", "Cyber Resources", "Vulnerability Intel", "Threat Intel", "VirusTotal", "Security Utilities", "MCP", "Settings"];
const TABS = ["Overview", "Scope", "Attack surface", "APIs", "Components", "Vulnerabilities", "Findings", "Checklist", "ASVS", "Risks", "Analysis", "Investigation", "Assistant", "Automation", "Timeline", "Evidence", "Report", "Notes", "Commands & runs"];
const results = [];
const note = (size, where, p) => {
  const ok = p.docX <= 1 && (p.mainX === null || p.mainX <= 1) && p.badCount === 0;
  results.push({ size, where, ok, ...p });
  if (!ok) console.log(`  ✗ ${size} ${where}: doc+${p.docX} main+${p.mainX} clipped ${p.badCount} ${p.bad.join(" | ")}`);
};
// the project tabs are probed on the first project, if there is one
const pname = await ev(`window.__TAURI_INTERNALS__.invoke('projects_list').then(l => (l[0] || {}).name || null)`);
for (const s of SIZES) {
  const size = `${s.w}x${s.h}@${s.d}`;
  await send("Emulation.setDeviceMetricsOverride", { width: s.w, height: s.h, deviceScaleFactor: s.d, mobile: false, screenWidth: s.w, screenHeight: s.h });
  await sleep(800);
  console.log(`== ${size}`);
  for (const nav of SIDEBAR) {
    if (!(await click(nav))) {
      console.log(`  ? ${size} no sidebar item ${nav}`);
      continue;
    }
    await sleep(500);
    note(size, nav, await ev(PROBE));
    if (s === SIZES[SIZES.length - 1]) writeFileSync(new URL(`${nav.replace(/\W+/g, "-")}.png`, OUT), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).data, "base64"));
  }
  if (pname) {
    await click("Projects");
    await sleep(600);
    await click(pname, { exact: false });
    await sleep(900);
    for (const t of TABS) {
      if (!(await click(t, { exact: false, scope: "main" }))) continue;
      await sleep(600);
      note(size, `project/${t}`, await ev(PROBE));
      if (s === SIZES[SIZES.length - 1]) writeFileSync(new URL(`project-${t.replace(/\W+/g, "-")}.png`, OUT), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).data, "base64"));
    }
    // a large dialog: the finding form
    await click("Findings", { exact: false, scope: "main" });
    await sleep(500);
    if (await click("Record finding", { scope: "main" })) {
      await sleep(700);
      const d = await ev(`(() => { const d = document.querySelector('[role=dialog]'); if (!d) return null; const r = d.getBoundingClientRect(); const btns = [...d.querySelectorAll('footer button, [data-slot=footer] button')].map(b => { const q = b.getBoundingClientRect(); return { t: b.innerText.trim(), visible: q.bottom <= innerHeight + 1 && q.top >= 0 }; }); return { top: Math.round(r.top), bottom: Math.round(r.bottom), left: Math.round(r.left), right: Math.round(r.right), H: innerHeight, W: innerWidth, buttons: btns }; })()`);
      const fits = d && d.top >= 0 && d.bottom <= d.H + 1 && d.left >= 0 && d.right <= d.W + 1 && d.buttons.every((b) => b.visible);
      results.push({ size, where: "dialog/Record finding", ok: !!fits, dialog: d });
      if (!fits) console.log(`  ✗ ${size} dialog Record finding: ${JSON.stringify(d)}`);
      if (s === SIZES[SIZES.length - 1]) writeFileSync(new URL(`dialog-record-finding.png`, OUT), Buffer.from((await send("Page.captureScreenshot", { format: "png" })).data, "base64"));
      await send("Input.dispatchKeyEvent", { type: "keyDown", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
      await send("Input.dispatchKeyEvent", { type: "keyUp", key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 });
      await sleep(500);
    }
  }
}
await send("Emulation.clearDeviceMetricsOverride");
const bySize = {};
for (const r of results) {
  bySize[r.size] ??= { ok: 0, bad: 0 };
  bySize[r.size][r.ok ? "ok" : "bad"]++;
}
console.log("SUMMARY", JSON.stringify(bySize));
writeFileSync(new URL(`result.json`, OUT), JSON.stringify(results, null, 1));
process.exitCode = results.some((r) => !r.ok) ? 1 : 0;
ws.close();
