// A local TAXII 2.1 server for the manual credential test (docs/release/TAXII_CREDENTIAL_TEST.md).
//
//   node scripts/qa/taxii-mock.mjs [--port 18556] [--log taxii-mock.log]
//
// Listens on 127.0.0.1 only. Debug builds of Cyber Hub accept plain HTTP to 127.0.0.1 for TAXII
// (release builds require HTTPS), so this is for a development build started with an isolated data
// folder. It accepts only the throwaway credentials below, never a real one:
//   HTTP Basic   user qa-analyst, password QA-only-not-a-real-secret-7f3a
//   API key      X-API-Key: QA-only-api-key-91c2
//   rotated      password QA-rotated-secret-55e1 (or key QA-rotated-key-08b4)
// Each request is logged with whether a credential arrived and which test value it matched; the
// value itself is never written. Two copies on two ports stand in for a server that moved.
import fs from "node:fs";
import http from "node:http";

const arg = (name, def) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : def;
};
const port = Number(arg("port", "18556"));
const logfile = arg("log", `taxii-mock-${port}.log`);
const PASSWORDS = { "QA-only-not-a-real-secret-7f3a": "password", "QA-rotated-secret-55e1": "rotated password" };
const KEYS = { "QA-only-api-key-91c2": "API key", "QA-rotated-key-08b4": "rotated API key" }; // gitleaks:allow (made-up test values)
const COLLECTION = "91a7b528-80eb-42ed-a74d-c6fbd5a26116";
const MEDIA = "application/taxii+json;version=2.1";

const indicator = (n, pattern) => ({
  type: "indicator",
  spec_version: "2.1",
  id: `indicator--00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
  created: "2026-11-01T00:00:00Z",
  modified: "2026-11-02T00:00:00Z",
  name: `QA indicator ${n}`,
  pattern,
  pattern_type: "stix",
  valid_from: "2026-11-01T00:00:00Z",
  confidence: 60,
});
// documentation values only (RFC 5737, RFC 2606): nothing real is imported
const OBJECTS = [indicator(1, "[ipv4-addr:value = '198.51.100.23']"), indicator(2, "[domain-name:value = 'c2.example.net']"), indicator(3, "[url:value = 'https://phish.example.org/login']")];

const send = (res, status, body, extra = {}) => {
  res.writeHead(status, { "Content-Type": MEDIA, ...extra });
  res.end(JSON.stringify(body));
};

http
  .createServer((req, res) => {
    const auth = req.headers.authorization ?? "";
    let who = "none";
    if (auth.startsWith("Basic ")) {
      const [user, ...rest] = Buffer.from(auth.slice(6), "base64").toString().split(":");
      who = `basic user=${user} ${PASSWORDS[rest.join(":")] ? `matches the test ${PASSWORDS[rest.join(":")]}` : "with an unknown password"}`;
    } else if (req.headers["x-api-key"]) {
      who = `x-api-key ${KEYS[req.headers["x-api-key"]] ? `matches the test ${KEYS[req.headers["x-api-key"]]}` : "with an unknown key"}`;
    } else if (auth) {
      who = "another Authorization scheme";
    }
    fs.appendFileSync(logfile, `${new Date().toISOString()} ${req.method} ${req.url} credential: ${who}\n`);
    const path = req.url.split("?")[0];
    if (path === "/taxii2/") return send(res, 200, { title: `QA feeds on port ${port}`, api_roots: ["/api1/"] });
    if (!/matches the test/.test(who)) return send(res, 401, { title: "Unauthorized", description: "Use the test credentials of scripts/qa/taxii-mock.mjs" });
    if (path === "/api1/collections/") return send(res, 200, { collections: [{ id: COLLECTION, title: "QA collection", can_read: true, can_write: false }] });
    if (path === `/api1/collections/${COLLECTION}/objects/`) {
      return send(res, 200, { more: false, objects: OBJECTS }, { "X-TAXII-Date-Added-First": "2026-11-01T00:00:00.000Z", "X-TAXII-Date-Added-Last": "2026-11-02T00:00:00.000Z" });
    }
    return send(res, 404, { title: "Not found" });
  })
  .listen(port, "127.0.0.1", () => console.log(`TAXII test server on http://127.0.0.1:${port}/taxii2/ (log: ${logfile})`));
