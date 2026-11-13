// SPDX-License-Identifier: Apache-2.0
/** Small regex-based User-Agent parser (no dependencies). Order of checks matters. */

export interface ParsedUA {
  browser: { name: string; version: string };
  engine: { name: string; version: string };
  os: { name: string; version: string };
  device: "desktop" | "mobile" | "tablet" | "bot" | "tv" | "console" | "unknown";
  bot: { isBot: boolean; name?: string };
}

const BOTS: [RegExp, string][] = [
  [/googlebot/i, "Googlebot"],
  [/bingbot/i, "Bingbot"],
  [/duckduckbot/i, "DuckDuckBot"],
  [/baiduspider/i, "Baiduspider"],
  [/yandex(bot)?/i, "YandexBot"],
  [/applebot/i, "Applebot"],
  [/facebookexternalhit/i, "Facebook crawler"],
  [/twitterbot/i, "Twitterbot"],
  [/slackbot/i, "Slackbot"],
  [/gptbot/i, "GPTBot"],
  [/claudebot|claude-web/i, "ClaudeBot"],
  [/ahrefsbot/i, "AhrefsBot"],
  [/semrushbot/i, "SemrushBot"],
  [/nuclei/i, "Nuclei scanner"],
  [/sqlmap/i, "sqlmap"],
  [/nikto/i, "Nikto"],
  [/zgrab/i, "ZGrab scanner"],
  [/masscan/i, "Masscan"],
  [/nmap/i, "Nmap scripting engine"],
  [/curl\//i, "curl"],
  [/wget\//i, "Wget"],
  [/python-requests|python-urllib|aiohttp/i, "Python HTTP client"],
  [/go-http-client/i, "Go HTTP client"],
  [/okhttp/i, "OkHttp"],
  [/postmanruntime/i, "Postman"],
  [/headlesschrome/i, "Headless Chrome"],
  [/bot\b|crawler|spider|scraper/i, "Generic bot"],
];

function m(ua: string, re: RegExp, idx = 1): string | null {
  const r = ua.match(re);
  return r ? (r[idx] ?? "") : null;
}

export function parseUserAgent(raw: string): ParsedUA {
  const ua = raw.trim();
  const out: ParsedUA = {
    browser: { name: "Unknown", version: "" },
    engine: { name: "Unknown", version: "" },
    os: { name: "Unknown", version: "" },
    device: "unknown",
    bot: { isBot: false },
  };
  if (!ua) return out;

  const bot = BOTS.find(([re]) => re.test(ua));
  if (bot) out.bot = { isBot: true, name: bot[1] };

  // Browser (most specific first)
  const browsers: [RegExp, string][] = [
    [/Edg(?:e|A|iOS)?\/([\d.]+)/, "Microsoft Edge"],
    [/OPR\/([\d.]+)/, "Opera"],
    [/SamsungBrowser\/([\d.]+)/, "Samsung Internet"],
    [/YaBrowser\/([\d.]+)/, "Yandex Browser"],
    [/Vivaldi\/([\d.]+)/, "Vivaldi"],
    [/Brave\/([\d.]+)/, "Brave"],
    [/FxiOS\/([\d.]+)/, "Firefox for iOS"],
    [/CriOS\/([\d.]+)/, "Chrome for iOS"],
    [/Firefox\/([\d.]+)/, "Firefox"],
    [/HeadlessChrome\/([\d.]+)/, "Headless Chrome"],
    [/Chrome\/([\d.]+)/, "Chrome"],
    [/Version\/([\d.]+).*Safari\//, "Safari"],
    [/MSIE ([\d.]+)/, "Internet Explorer"],
    [/Trident\/.*rv:([\d.]+)/, "Internet Explorer"],
    [/curl\/([\d.]+)/, "curl"],
    [/Wget\/([\d.]+)/, "Wget"],
    [/python-requests\/([\d.]+)/, "python-requests"],
  ];
  for (const [re, name] of browsers) {
    const v = m(ua, re);
    if (v !== null) {
      out.browser = { name, version: v };
      break;
    }
  }

  // Engine
  let v: string | null;
  if ((v = m(ua, /AppleWebKit\/([\d.]+)/)) !== null) {
    out.engine = /Chrome\/|CriOS|Edg|OPR/.test(ua) && !/iPhone|iPad|iPod/.test(ua) ? { name: "Blink", version: m(ua, /Chrome\/([\d.]+)/) ?? v } : { name: "WebKit", version: v };
  } else if (/Gecko\/\d+/.test(ua) && (v = m(ua, /rv:([\d.]+)/)) !== null) out.engine = { name: "Gecko", version: v };
  else if ((v = m(ua, /Trident\/([\d.]+)/)) !== null) out.engine = { name: "Trident", version: v };
  else if ((v = m(ua, /Presto\/([\d.]+)/)) !== null) out.engine = { name: "Presto", version: v };

  // OS
  const winMap: Record<string, string> = { "10.0": "10 / 11", "6.3": "8.1", "6.2": "8", "6.1": "7", "6.0": "Vista", "5.1": "XP" };
  if ((v = m(ua, /Windows NT ([\d.]+)/)) !== null) out.os = { name: "Windows", version: winMap[v] ?? v };
  else if ((v = m(ua, /(?:iPhone|CPU) OS ([\d_]+)/)) !== null) out.os = { name: "iOS", version: v.replace(/_/g, ".") };
  else if ((v = m(ua, /iPad.*OS ([\d_]+)/)) !== null) out.os = { name: "iPadOS", version: v.replace(/_/g, ".") };
  else if ((v = m(ua, /Android ([\d.]+)/)) !== null) out.os = { name: "Android", version: v };
  else if ((v = m(ua, /Mac OS X ([\d_.]+)/)) !== null) out.os = { name: "macOS", version: v.replace(/_/g, ".") };
  else if (/CrOS/.test(ua)) out.os = { name: "ChromeOS", version: m(ua, /CrOS \S+ ([\d.]+)/) ?? "" };
  else if (/Ubuntu/i.test(ua)) out.os = { name: "Ubuntu", version: m(ua, /Ubuntu\/([\d.]+)/) ?? "" };
  else if (/Linux/.test(ua)) out.os = { name: "Linux", version: "" };
  else if (/PlayStation/.test(ua)) out.os = { name: "PlayStation", version: m(ua, /PlayStation \w* ?([\d.]+)/) ?? "" };

  // Device
  if (out.bot.isBot) out.device = "bot";
  else if (/iPad|Tablet|Nexus (7|9|10)|SM-T\d+/i.test(ua) || (/Android/.test(ua) && !/Mobile/.test(ua))) out.device = "tablet";
  else if (/Mobi|iPhone|iPod|Android.*Mobile|Windows Phone/i.test(ua)) out.device = "mobile";
  else if (/SmartTV|SMART-TV|Tizen|WebOS|AppleTV|Roku/i.test(ua)) out.device = "tv";
  else if (/PlayStation|Xbox|Nintendo/i.test(ua)) out.device = "console";
  else if (/Windows NT|Macintosh|X11|CrOS/.test(ua)) out.device = "desktop";

  return out;
}
