import { describe, expect, it } from "vitest";
import type { HttpResponseOut } from "@/lib/types";
import { HISTORY_BODY_LIMIT, HISTORY_LIMIT, diffHeaders, diffLines, parseRawRequest, repeaterHistory, targetOf, toCurl, toRawRequest } from "./repeater";

describe("raw requests", () => {
  it("reads a request as a proxy shows it", () => {
    const raw = "POST /api/login?next=%2Fhome HTTP/1.1\r\nHost: app.example.com\r\nContent-Type: application/json\r\nContent-Length: 27\r\nCookie: s=1\r\n\r\n{\"user\":\"a\",\"pass\":\"b\"}";
    const r = parseRawRequest(raw);
    expect(r.method).toBe("POST");
    expect(r.url).toBe("https://app.example.com/api/login?next=%2Fhome");
    expect(r.headers).toEqual([
      ["Host", "app.example.com"],
      ["Content-Type", "application/json"],
      ["Cookie", "s=1"],
    ]);
    expect(r.body).toBe('{"user":"a","pass":"b"}');
    expect(parseRawRequest(raw, "http://10.0.0.5:8080").url).toBe("http://10.0.0.5:8080/api/login?next=%2Fhome");
    expect(parseRawRequest("get https://x.example.com/a HTTP/2\n\n").url).toBe("https://x.example.com/a");
    expect(parseRawRequest("GET /\nHost: h.example.com").method).toBe("GET");
  });

  it("refuses what it cannot read", () => {
    expect(() => parseRawRequest("hello")).toThrow(/request line/);
    expect(() => parseRawRequest("GET / HTTP/1.1\nno colon here\n\n")).toThrow(/Not a header/);
    expect(() => parseRawRequest("GET / HTTP/1.1\n\n")).toThrow(/target/);
    expect(() => parseRawRequest("GET / HTTP/1.1\n\n", "https://h.example.com/path")).toThrow(/without a path/);
    expect(() => parseRawRequest("GET relative HTTP/1.1\nHost: h\n\n")).toThrow(/path/);
    expect(() => parseRawRequest("G(T / HTTP/1.1\nHost: h\n\n")).toThrow(/method/);
  });

  it("writes requests back as raw text and as cURL", () => {
    const req = { method: "PUT", url: "https://api.example.com/v1/items/7?x=1", headers: [["Authorization", "Bearer t"]] as [string, string][], body: "it's" };
    const raw = toRawRequest(req);
    expect(raw.split("\n").slice(0, 3)).toEqual(["PUT /v1/items/7?x=1 HTTP/1.1", "Host: api.example.com", "Authorization: Bearer t"]);
    const back = parseRawRequest(raw, targetOf(req.url));
    expect({ ...back, headers: back.headers.filter(([k]) => k !== "Host") }).toEqual(req);
    expect(toCurl(req, true)).toBe("curl -sS -i -k -X PUT -H 'Authorization: Bearer t' --data-raw 'it'\\''s' 'https://api.example.com/v1/items/7?x=1'");
    expect(toCurl({ method: "GET", url: "https://a.example.com/", headers: [], body: "" })).toBe("curl -sS -i 'https://a.example.com/'");
    expect(targetOf("not a url")).toBe("");
  });
});

describe("response comparison", () => {
  it("shows changed lines with context", () => {
    expect(diffLines("a\nb", "a\nb")).toEqual([{ kind: "skip", count: 2 }]);
    const before = ["{", '  "id": 7,', '  "role": "user",', '  "name": "a",', '  "plan": "free",', '  "x": 1,', "}"].join("\n");
    const after = before.replace('"role": "user"', '"role": "admin"');
    // a single unchanged line is shown, not replaced by a marker
    expect(diffLines(before, after, 1)).toEqual([
      { kind: "same", text: "{" },
      { kind: "same", text: '  "id": 7,' },
      { kind: "removed", text: '  "role": "user",' },
      { kind: "added", text: '  "role": "admin",' },
      { kind: "same", text: '  "name": "a",' },
      { kind: "skip", count: 3 },
    ]);
    expect(diffLines("a", "a\nb")).toEqual([{ kind: "same", text: "a" }, { kind: "added", text: "b" }]);
  });

  it("falls back to replacing very different large bodies", () => {
    const a = Array.from({ length: 50 }, (_, i) => `a${i}`).join("\n");
    const b = Array.from({ length: 50 }, (_, i) => `b${i}`).join("\n");
    const ops = diffLines(a, b, 2, 10);
    expect(ops.filter((o) => o.kind === "removed")).toHaveLength(50);
    expect(ops.filter((o) => o.kind === "added")).toHaveLength(50);
  });

  it("compares headers without regard to case", () => {
    expect(
      diffHeaders(
        [["Content-Type", "text/html"], ["Set-Cookie", "a=1"], ["X-Old", "1"]],
        [["content-type", "application/json"], ["Set-Cookie", "a=1"], ["Strict-Transport-Security", "max-age=1"]],
      ),
    ).toEqual([
      { name: "content-type", before: "text/html", after: "application/json" },
      { name: "Strict-Transport-Security", before: null, after: "max-age=1" },
      { name: "X-Old", before: "1", after: null },
    ]);
  });
});

describe("session history", () => {
  const res = (body: string): HttpResponseOut => ({ status: 200, reason: "OK", version: "HTTP/1.1", headers: [], body, bodyBytes: body.length, truncated: false, elapsedMs: 5, redirects: [], redirectStopped: null }) as unknown as HttpResponseOut;

  it("keeps the newest entries and cuts large bodies", () => {
    repeaterHistory.clear();
    for (let i = 0; i < HISTORY_LIMIT + 5; i++) {
      repeaterHistory.add({ projectId: 1, request: { method: "GET", url: `https://a.example.com/${i}`, headers: [], body: "" }, insecure: false, followRedirects: false, response: res("ok"), error: null });
    }
    const list = repeaterHistory.list();
    expect(list).toHaveLength(HISTORY_LIMIT);
    expect(list[0].request.url).toBe(`https://a.example.com/${HISTORY_LIMIT + 4}`);
    const big = repeaterHistory.add({ projectId: 1, request: { method: "GET", url: "https://a.example.com/big", headers: [], body: "" }, insecure: false, followRedirects: false, response: res("x".repeat(HISTORY_BODY_LIMIT + 10)), error: null });
    expect(big.response?.body.length).toBe(HISTORY_BODY_LIMIT);
    expect(big.response?.truncated).toBe(true);
    repeaterHistory.clear();
    expect(repeaterHistory.list()).toHaveLength(0);
  });
});
