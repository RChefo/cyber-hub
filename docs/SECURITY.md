# Security model

Cyber Hub launches security software. Its security goals:

1. Nothing runs without an explicit human decision made outside the web page.
2. Tools that touch the network only reach targets inside an active project's authorized scope.
3. Data stays on the device; credentials are never persisted in clear text.
4. A compromised or buggy frontend cannot turn the app into a general-purpose command runner or file reader.

## Trust boundaries

```
web view (React)  ──IPC──▶  Rust commands  ──▶  process manager / file system / SQLite / OS keychain
   untrusted for            validate every                 native OS dialogs gate every
   consequential actions    input & path                   process start
```

The web view is treated as **untrusted for consequential actions**. Everything that starts a process, chooses a file path or writes outside the app's own database is decided in Rust and, where it starts a process, confirmed in a native OS dialog the page cannot script.

## Controls

| Area | Control |
|---|---|
| Process start | `exec_start` and `tool_install` show a **native OS confirmation dialog** (Win32 task dialog / AppKit / GTK, created by the Rust process) with the exact program, arguments (credentials redacted), project and authorized targets. Page script cannot see or click it. Cancelling returns a `cancelled` error and starts nothing. |
| No shell | Processes are spawned with argv through `tokio::process::Command`, never `sh -c` / `cmd /c`. stdin is closed. |
| Executables | Resolved by the backend from the catalog (or the allow-listed package managers `winget`, `brew`, `pipx`, `go`). Only **absolute PATH entries** are searched (relative entries such as `.` are ignored to prevent binary planting). On Windows only native `.exe`/`.com` files are executed with arguments — `.bat`/`.cmd` wrappers are refused because `cmd.exe` re-parses their arguments. Helper programs use fixed absolute paths (`/usr/bin/open`, `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`). |
| Arguments | ≤ 256 arguments, ≤ 4096 chars each, no NUL / CR / LF. Execution requests with unknown fields (e.g. a working directory) are rejected. |
| Scope | Scope-required tools need an **active** project with in-scope entries; every target named anywhere in the arguments — including inside target files — must be in scope (see below). |
| Process trees | Windows: each run is assigned to a Job Object with `KILL_ON_JOB_CLOSE`; cancel terminates the job; leftover descendants die when the run ends or Cyber Hub exits. Unix: each run gets its own process group; cancel sends SIGTERM then SIGKILL to the group; Cyber Hub kills all running groups on exit. |
| Output | Lines are read in bounded chunks (16 KB); stored output is capped at 2 MB per run. |
| Redaction | Before anything is persisted (run arguments, stored output, command history, activity details) credentials are redacted: options named like passwords/tokens/secrets/cookies/API keys, URL user-info, `Authorization`/`Cookie`/API-key headers, secret-named `key=value` pairs, `domain/user:password@host`, and JWTs. Redaction is lossy by design. |
| Temporary files | Validated target files are snapshotted into `<app data>/runtime/run-*`, read by the tool from there, and deleted when the run ends; the whole `runtime` directory is cleared at startup and exit. |
| File system | The web view never supplies file paths. Wordlist import, the extra wordlist folder and wordlist export use native dialogs opened by the backend. Preview reads only indexed files (≤ 64 MB). Deleting a wordlist file is limited to the managed folder (canonical-path check). |
| Tauri capabilities | The main window gets only: `opener:allow-open-url` restricted to `http(s)://*`; for the frameless window and its controls `core:window:allow-start-dragging`, `allow-minimize`, `allow-toggle-maximize`, `allow-internal-toggle-maximize`, `allow-is-maximized` and `allow-close`; and `core:event:allow-listen` / `allow-unlisten` so the maximize/restore button can follow resize events. No `core:default`, no shell, no fs, no dialog, no HTTP permissions. |
| `freezePrototype` | **Enabled.** `Object.prototype` is frozen in the web view. Chart dependencies that relied on the JavaScript "override mistake" are patched at install time (`scripts/patch-deps.mjs`, exact-statement rewrites to `Object.defineProperty`, verified by a self-test that loads them with a frozen prototype; the install fails if any patch no longer applies). |
| CSP | `default-src 'self'`; scripts from self only; no remote origins for connect/img/font; `frame-ancestors 'none'`; `form-action 'none'`. `style-src` allows inline styles (required by HeroUI / motion). |
| Secrets | The NVD key and the threat-intelligence keys (VirusTotal, AbuseIPDB, OTX, abuse.ch, Shodan) live in the OS credential store (Windows Credential Manager, macOS Keychain, Secret Service). The UI can set, delete and check them, never read them. Threat-intelligence keys have dedicated commands (`ti_key_set` / `ti_key_test` / `ti_key_delete`) and cannot be reached through the generic secret commands. |
| Network | No telemetry, no update pings. Requests happen only on explicit actions: live CVE search (services.nvd.nist.gov), threat-intelligence lookups and VirusTotal file uploads (see below), DNS lookup (system resolver), HTTP header fetch (the URL entered; redirects not followed; body not read), opening links. |
| Preferences | Settable keys are allow-listed and some are range-checked (the VirusTotal upload limit must be 1–650 MB); the wordlist folder can only be set through the native folder picker. |

## Threat-intelligence providers

Providers, endpoints and documented access conditions are listed in [PROVIDERS.md](PROVIDERS.md).

| Concern | Control |
|---|---|
| API keys | One OS-keychain entry per key (`virustotal_api_key`, `abuseipdb_api_key`, `otx_api_key`, `abusech_auth_key`, `shodan_api_key`). A key is read only inside the Rust function that sends the request and is sent only to that provider's fixed API base: in a header (`x-apikey`, `Key`, `X-OTX-API-KEY`, `Auth-Key`) or, for Shodan, in the `key` query parameter that its API requires. Keys never cross IPC after saving and are never written to SQLite, history, exports or logs. |
| Error messages | Transport errors are reported without their URL (`without_url`), and every provider message is scrubbed of the key before it reaches the UI. This covers Shodan's query-string key. `x-apikey` and API-key headers are also covered by the output redaction rules. |
| Key management | Settings → Threat intelligence providers: format check, then one read-only verification request with a fixed, public probe (VirusTotal and AbuseIPDB: `8.8.8.8`; OTX: subscribed pulses; abuse.ch: the EICAR test hash at MalwareBazaar; Shodan: `/api-info`). The key is stored only if the provider accepts it. Test connection re-checks the stored key and shows quota or plan information where the provider returns it. Remove deletes the keychain entry. |
| Fixed endpoints | Production API bases are constants (`ti::ProviderId::production_base`). Requests never follow redirects, and response bodies are read incrementally and capped at 8 MB (including chunked responses). A debug-only override (`CYBERHUB_MOCK_API_BASE`, parsed and accepted only as `http://127.0.0.1:<port>` or `http://localhost:<port>` with no credentials, path or query) routes every provider to a local mock for testing; it is compiled out of release builds (`cfg(debug_assertions)`). |
| No arbitrary requests | The web view sends only the indicator text and the provider IDs to use. The backend validates the indicator, builds every path and body itself and uses its own stored keys. No command accepts a key, URL or header for a lookup, and the web view has no HTTP permission. |
| Private data | Private, loopback, link-local, CGNAT, documentation and other reserved IP addresses are refused before any provider is contacted. IPv6 forms that embed an IPv4 address (mapped, IPv4-compatible, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) are judged by the embedded address, and `fec0::/10` and `192.0.0.0/24` are refused. URLs on such addresses, single-label names and internal suffixes (`.local`, `.internal`, `.corp`, `.lan`, `.home.arpa`, …) are refused too. Only http(s) URLs without embedded user names or passwords are accepted. |
| Isolation | Providers run concurrently and independently. A missing key, a disabled provider, a rate limit, an HTTP error or an unparsable response becomes a status on that provider's result and never fails the others. |
| Rate limits and cache | Each provider has its own client-side limit at or below its documented allowance (VirusTotal 4/min, Shodan 1/s, AbuseIPDB and OTX 30/min, abuse.ch 20/min). Provider quota errors are shown as such. Results are cached per provider (`vt_cache`, `ti_cache`; 6–24 h for records, 1 h for "no record"); errors are not cached. Refresh bypasses the cache explicitly. |
| Verdicts | Each provider's verdict is kept in its own wording, and scores are never combined. The colour buckets per provider are documented in [PROVIDERS.md](PROVIDERS.md). |
| No external actions | Nothing is reported, submitted, blocked or changed at a provider. Pivoting to a related indicator only starts another read-only lookup after the user selects it. |
| History and exports | Each multi-provider search is recorded in `ti_history` (indicator plus the list of providers per outcome) and in the activity log. Reports are exported from stored results only (no network) through a native save dialog. Provider-written text in Markdown exports is escaped, so it cannot form links, images, headings or HTML, and control and line-separator characters are removed. Links come only from Cyber Hub's own URL patterns or, for URLhaus, must point to `https://urlhaus.abuse.ch/`. |

## VirusTotal file analysis

| Concern | Control |
|---|---|
| File selection | `vt_file_pick` opens the native file picker in the backend. The web view receives an opaque random handle plus the file name, size and hashes, never a path. Handles expire after one hour (at most ten are kept). Only regular files are accepted (links are resolved first); files over 2 GB are not hashed. |
| Hash first | SHA-256, SHA-1 and MD5 are computed locally. "Look up hash" sends only the SHA-256 (a normal reputation lookup). A missing report never triggers an upload. |
| Explicit confirmation | Uploading requires (1) an in-page acknowledgement that the file is shared publicly and contains no sensitive data, reset after every attempt, and (2) a **native OS dialog** for that file, showing its name, size, SHA-256 and the public-sharing warning. Page script cannot see or click that dialog. Declining returns `cancelled`, and nothing is read for upload or sent. |
| Public, not private | The upload is a standard public submission and is labelled as such everywhere. Private scanning is not implemented (see PROVIDERS.md). |
| Original file untouched | The file is copied into a private snapshot under `<app data>/runtime` while being re-hashed. If its size or SHA-256 differs from what was shown at selection, nothing is uploaded. The upload streams from the snapshot, which is deleted when the operation ends (success, error or cancellation) and also at app start and exit. The original file is never written, moved or deleted. |
| Size limits | A user-configurable limit (default 32 MB, 1–650 MB) is checked before the confirmation. Files ≤ 32 MB use `POST /files`. Larger files use `GET /files/upload_url`, and the returned one-time URL must be an HTTPS `virustotal.com` host without credentials or a custom port (the documented `http://` form is upgraded to HTTPS). Otherwise the file is not sent. Uploads count against the local 4/minute limit (two requests for the upload-URL flow). Availability is checked before the confirmation without using quota, and the slots are taken only after approval. Only one upload per selected file can run at a time. |
| Cancellation | An upload in progress can be cancelled; the request is dropped and the snapshot deleted. VirusTotal may already have received part of the file. |
| Analysis | The analysis ID is validated (base64-style characters, ≤ 256) and percent-encoded into `GET /analyses/{id}`. The UI polls every 20 seconds for up to 30 minutes; each poll counts against the quota. When the analysis completes, the file report is fetched and shown. |
| Recording | Each upload is recorded in the activity log (file name, SHA-256, size). File contents are never stored. |

Tests:
* `src-tauri/src/vtfile.rs`: hash vectors; nothing is uploaded and no snapshot is created when the confirmation is declined; an approved upload sends exactly the file as multipart with the key only in the header, then deletes the snapshot; size limit enforced before asking; a file changed after selection is refused; cancellation after approval sends nothing; large files use the upload URL; a foreign upload URL is refused; upload-URL, analysis-ID and file-name sanitising.
* `src-tauri/src/ti/*.rs`: per-provider parsing fixtures and local mock HTTP servers. They check where each key is sent, error mapping, that errors never contain the key (including Shodan's query-string key), and that unsupported hash types make no request.

## Scope enforcement

Scope entries:

| Entry | Matches |
|---|---|
| `example.com` | exactly `example.com` |
| `*.example.com` | any sub-domain at any depth (not the apex) |
| `10.0.0.5` | that address (IPv4-mapped IPv6 such as `::ffff:10.0.0.5` is normalized and matches too) |
| `10.0.0.0/24` | addresses and sub-networks fully inside it |
| `https://app.example.com` | the URL's host |
| out-of-scope entry | always wins; a network or IPv4 range that **overlaps** an excluded host or network is rejected |

### Target resolution (tool-independent)

For a scope-required run every argument value (whole positional values and the part after `=` in `--opt=value`) is examined:

* **Existing files** are read and classified:
  * *raw HTTP request* (`METHOD target HTTP/x` first line): the `Host` header and an absolute request-line URL must be in scope; duplicate `Host` headers are rejected;
  * *target list* (any line names a network endpoint): **every** non-comment line must parse strictly (hosts, IPs, `[IPv6]:port`, CIDRs, IPv4 ranges, URLs) and every entry must be in scope — wildcards like `10.0.0.*`, single-word names (which may resolve through DNS search domains) and other unparseable lines reject the run;
  * *data* (wordlists, payloads, binaries): allowed.
  Target lists and requests are **snapshotted** and the argument rewritten to the snapshot; the snapshot is re-validated after copying, so a file swapped during validation is detected.
* **Other values** are scanned for URLs (any host, including single-label hosts and decimal IPs such as `http://2130706433/` which normalizes to 127.0.0.1), IPs, `[IPv6]`, CIDRs, IPv4 ranges, `host:port` (including single-label), `user@host` / `domain/user:pass@host`, `localhost`, and dotted host names. File-name heuristics only exclude extensions that are **not** top-level domains (`.zip`, `.py`, `.sh`, `.pl`, `.md` are real TLDs and are checked as hosts).
* Explicit targets from builders are parsed strictly.
* At least one target must be identified, otherwise the run is refused.

Fuzzing keywords in host names need no special handling: `https://FUZZ.example.com/` is a real host under `*.example.com` and passes only if that wildcard is in scope, while `https://exaFUZZ.com/`, `https://FUZZ/` or `https://10.0.0.FUZZ/` name other hosts and are rejected.

Tests: `src-tauri/src/scope.rs` and `src-tauri/src/targets.rs` (target files, exclusions, malformed lines, request files, `--opt=file` rewriting, smuggling through mixed arguments, TLD look-alikes, fuzz keywords, IPv6/mapped addresses, empty targets).

## Accepted risks and limitations

| Risk | Status / mitigation |
|---|---|
| **Single-word arguments** (`intranet`, `dir`, `smb`) cannot be told apart from sub-commands without per-tool knowledge, so they are not scope-checked when they appear as bare arguments. | The preview shows a warning listing them; target files reject them; URLs and `host:port` forms are checked. Use fully-qualified names or IPs. |
| **Indirect inputs not visible on the command line** — configuration files, resume/state files, environment variables, tool-internal crawling, recursion, redirects and template-defined hosts. | Files named in arguments are inspected (a config or resume file that names endpoints is treated as a target list and must be fully in scope). Crawl/recursion behavior is the tool's; keep depth and rate limits conservative. stdin is closed. |
| **Tool features that execute code** (custom scripts, plugins) are part of many security tools. | Every run requires the native OS confirmation showing the full command; there is no shell and no automatic execution. |
| **DNS-based scope**: names are checked, not the addresses they resolve to. | Prefer IPs/CIDRs for internal ranges; exclusions still apply by name. |
| **Windows process trees**: a descendant spawned in the instant before the child is assigned to its Job Object could escape. | Window is microseconds; verified by an automated test that a grandchild is killed. |
| **Very large target files** (> 256 MB) cannot be validated. | They are rejected, not skipped. |
| **Existing history** recorded before redaction was added is not rewritten. | Clear it in Settings → Local data if needed. |
| **Process output** is shown live without redaction (it is ephemeral); stored output is redacted. | — |
| **Live CVE searches** send the query text to NVD. | Labeled in the UI; a local-cache mode exists. |
| **Threat-intelligence lookups** send the indicator (IP, domain, URL or hash) to every selected provider. VirusTotal documents that queried indicators may be added to its dataset. Lookups are recorded in the local history. | Only on an explicit Look up or Refresh; providers can be turned off; private addresses and internal names are refused; the UI lists the providers that will receive the indicator. |
| **VirusTotal file uploads are public** and cannot be withdrawn by Cyber Hub. | Two explicit confirmations per file (in-page acknowledgement and a native dialog), a prominent warning, a hash lookup first, and a size limit. |
| **Shodan requires the key in the URL.** A proxy that logs full URLs would see it. | Only sent to `api.shodan.io` over HTTPS; never logged or shown by Cyber Hub. |
| **Provider rate limits are per process.** Client-side limits reset when the app restarts; daily quotas (e.g. AbuseIPDB's 1,000 checks/day) are enforced by the provider. | Quota errors are shown; remaining AbuseIPDB quota is displayed. |
| **Third-party advisories** (`cargo audit`): 0 vulnerabilities; 8 informational warnings (unmaintained D-Bus crates and an unsound `glib` iterator in Tauri's Linux GTK stack, transitive only). | Monitor upstream Tauri / keyring releases. |
| **Installers are unsigned** (when built). | Code signing is a release task. |
| **Payloads** are well-known, non-destructive detection probes for authorized testing; Cyber Hub never sends them anywhere. | — |
