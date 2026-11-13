// SPDX-License-Identifier: Apache-2.0
import { describe, expect, it } from "vitest";
import { defang, defangText, extractIocs, iocCount, refang } from "./ioc";

describe("defanging a whole text", () => {
  it("defangs every network indicator once and keeps the rest", () => {
    const t = "Seen https://evil.example.com/p?a=1 from 203.0.113.9; mail to ops@evil.example.com about evil.example.com and report.pdf";
    expect(defangText(t)).toBe("Seen hxxps[://]evil[.]example[.]com/p?a=1 from 203[.]0[.]113[.]9; mail to ops[@]evil[.]example[.]com about evil[.]example[.]com and report.pdf");
    expect(refang(defangText(t))).toBe(t);
  });
});

describe("IOC refang and defang", () => {
  it("refangs the common conventions", () => {
    expect(refang("hxxps[://]evil[.]example[.]com/a")).toBe("https://evil.example.com/a");
    expect(refang("hXXp://bad(.)example{.}org")).toBe("http://bad.example.org");
    expect(refang("c2 [dot] example [dot] net")).toBe("c2.example.net");
    expect(refang("user[@]example[.]com and admin(at)example(.)org")).toBe("user@example.com and admin@example.org");
    expect(refang("198[.]51[.]100[.]7 and 2001[:]db8[:][:]1")).toBe("198.51.100.7 and 2001:db8::1");
    expect(refang("evil\\.example\\.com")).toBe("evil.example.com");
  });

  it("defangs each kind and refang reverses it", () => {
    expect(defang("https://evil.example.com/x.php", "url")).toBe("hxxps[://]evil[.]example[.]com/x[.]php");
    expect(defang("198.51.100.7", "ipv4")).toBe("198[.]51[.]100[.]7");
    expect(defang("2001:db8::1", "ipv6")).toBe("2001[:]db8[:][:]1");
    expect(defang("a.b@example.com", "email")).toBe("a[.]b[@]example[.]com");
    for (const [v, k] of [["https://evil.example.com/x.php", "url"], ["198.51.100.7", "ipv4"], ["2001:db8::1", "ipv6"], ["user@example.com", "email"]] as const) {
      expect(refang(defang(v, k))).toBe(v);
    }
  });
});

describe("IOC extraction", () => {
  const sample = `Phishing from hxxps[://]login-micros0ft[.]com/auth?x=1 (see report.pdf).
Beacon to 203.0.113.45:443 and 2001:db8:85a3::8a2e:370:7334, not version 1.2.3.4.5 or 10:30:00.
Dropper payload.exe sha256 9F86D081884C7D659A2FEAE0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08,
md5 5d41402abc4b2a76b9719d911017c592, contact abuse@example.org. Exploits CVE-2021-44228 and cve-2023-4863.
Again: https://login-micros0ft.com/auth?x=1.`;

  it("finds each kind once, in order", () => {
    const r = extractIocs(sample);
    expect(r.url).toEqual(["https://login-micros0ft.com/auth?x=1"]);
    expect(r.ipv4).toEqual(["203.0.113.45"]);
    expect(r.ipv6).toEqual(["2001:db8:85a3::8a2e:370:7334"]);
    expect(r.sha256).toEqual(["9f86d081884c7d659a2feae0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"]);
    expect(r.md5).toEqual(["5d41402abc4b2a76b9719d911017c592"]);
    expect(r.email).toEqual(["abuse@example.org"]);
    expect(r.cve).toEqual(["CVE-2021-44228", "CVE-2023-4863"]);
    expect(r.domain).toContain("login-micros0ft.com");
    expect(r.domain).toContain("example.org");
  });

  it("does not mistake files, versions, times or MAC addresses for indicators", () => {
    const r = extractIocs(sample + " aa:bb:cc:dd:ee:ff config.json run.sh");
    expect(r.domain).not.toContain("report.pdf");
    expect(r.domain).not.toContain("payload.exe");
    expect(r.domain).not.toContain("config.json");
    expect(r.ipv4).not.toContain("1.2.3.4");
    expect(r.ipv6).toHaveLength(1);
    expect(r.sha1).toHaveLength(0);
    expect(iocCount(extractIocs(""))).toBe(0);
    // real top-level domains that are also file extensions are domains
    expect(extractIocs("C2 at evil.com, staging at files.example.zip and allegro.pl").domain).toEqual(["evil.com", "files.example.zip", "allegro.pl"]);
  });
});

describe("IOC handling on hostile input", () => {
  it("stays fast on long runs of similar characters", () => {
    const cases = [" ".repeat(40_000) + "[.]", "http://x.example/" + ".".repeat(40_000), "http://x.example/a" + ")".repeat(40_000), "a.".repeat(20_000), "1.".repeat(20_000), "a".repeat(40_000) + "@"];
    for (const c of cases) {
      const t0 = performance.now();
      extractIocs(c);
      defangText(c);
      expect(performance.now() - t0, c.slice(0, 20)).toBeLessThan(500);
    }
  });

  it("keeps URL trimming and parentheses right", () => {
    expect(extractIocs("see (https://x.example/a(b)c). next").url).toEqual(["https://x.example/a(b)c"]);
    expect(extractIocs("go to https://x.example/path...").url).toEqual(["https://x.example/path"]);
    expect(defangText("(https://x.example/a).")).toBe("(hxxps[://]x[.]example/a).");
  });
});

