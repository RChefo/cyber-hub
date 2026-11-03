import { describe, expect, it } from "vitest";
import { parseUserAgent } from "./ua";

describe("parseUserAgent", () => {
  it("parses desktop Chrome on Windows", () => {
    const r = parseUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36");
    expect(r.browser).toEqual({ name: "Chrome", version: "124.0.0.0" });
    expect(r.engine.name).toBe("Blink");
    expect(r.os).toEqual({ name: "Windows", version: "10 / 11" });
    expect(r.device).toBe("desktop");
    expect(r.bot.isBot).toBe(false);
  });

  it("parses Edge before Chrome", () => {
    const r = parseUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.80");
    expect(r.browser.name).toBe("Microsoft Edge");
  });

  it("parses Safari on iPhone", () => {
    const r = parseUserAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1");
    expect(r.browser).toEqual({ name: "Safari", version: "17.4" });
    expect(r.os).toEqual({ name: "iOS", version: "17.4" });
    expect(r.engine.name).toBe("WebKit");
    expect(r.device).toBe("mobile");
  });

  it("parses Firefox on Linux and Android tablets", () => {
    const ff = parseUserAgent("Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0");
    expect(ff.browser).toEqual({ name: "Firefox", version: "125.0" });
    expect(ff.engine).toEqual({ name: "Gecko", version: "125.0" });
    expect(ff.os.name).toBe("Linux");
    const tab = parseUserAgent("Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36");
    expect(tab.device).toBe("tablet");
    expect(tab.os).toEqual({ name: "Android", version: "13" });
  });

  it("detects bots and tools", () => {
    expect(parseUserAgent("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)").bot).toEqual({ isBot: true, name: "Googlebot" });
    expect(parseUserAgent("curl/8.6.0")).toMatchObject({ device: "bot", browser: { name: "curl", version: "8.6.0" } });
    expect(parseUserAgent("sqlmap/1.8#stable (https://sqlmap.org)").bot.name).toBe("sqlmap");
  });
});
