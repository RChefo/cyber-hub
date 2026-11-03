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
| Tauri capabilities | The main window gets only: `opener:allow-open-url` restricted to `http(s)://*`, and `core:window:allow-start-dragging` / `allow-toggle-maximize` / `allow-internal-toggle-maximize` for the frameless window. No `core:default`, no shell, no fs, no dialog permissions. |
| `freezePrototype` | **Enabled.** `Object.prototype` is frozen in the web view. Chart dependencies that relied on the JavaScript "override mistake" are patched at install time (`scripts/patch-deps.mjs`, exact-statement rewrites to `Object.defineProperty`, verified by a self-test that loads them with a frozen prototype; the install fails if any patch no longer applies). |
| CSP | `default-src 'self'`; scripts from self only; no remote origins for connect/img/font; `frame-ancestors 'none'`; `form-action 'none'`. `style-src` allows inline styles (required by HeroUI / motion). |
| Secrets | The NVD API key lives in the OS credential store (Windows Credential Manager, macOS Keychain, Secret Service). The UI can set/delete/check it, never read it. |
| Network | No telemetry, no update pings. Requests happen only on explicit actions: live CVE search (services.nvd.nist.gov), DNS lookup (system resolver), HTTP header fetch (the URL entered; redirects not followed; body not read), opening links. |
| Preferences | Settable keys are allow-listed; the wordlist folder can only be set through the native folder picker. |

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
| **Third-party advisories** (`cargo audit`): 0 vulnerabilities; 8 informational warnings (unmaintained D-Bus crates and an unsound `glib` iterator in Tauri's Linux GTK stack, transitive only). | Monitor upstream Tauri / keyring releases. |
| **Installers are unsigned** (when built). | Code signing is a release task. |
| **Payloads** are well-known, non-destructive detection probes for authorized testing; Cyber Hub never sends them anywhere. | — |
