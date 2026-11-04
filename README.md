# Cyber Hub

A local-first, cross-platform cybersecurity workstation built with **Tauri 2 (Rust)** and **React 19 + TypeScript**. It brings a curated tools library with real installation detection, a scoped execution engine, command builders, Google Dorks Studio, payloads and wordlists, security utilities, a projects workspace with findings, and CVE intelligence together in one desktop app.

No account, no telemetry, no background network traffic. Everything is stored in a local SQLite database and the OS keychain.

## Quick start

Prerequisites: Node.js 20+ (tested on 22 and 24), Rust 1.80+ (tested on 1.94 and 1.99), and the [Tauri 2 system prerequisites](https://v2.tauri.app/start/prerequisites/) for your OS (WebView2 on Windows, Xcode CLT on macOS, WebKitGTK 4.1 + `libdbus-1-dev` on Linux).

```bash
npm ci                 # also runs scripts/patch-deps.mjs (freezePrototype compatibility, self-tested)
npm run tauri dev      # run the desktop app with hot reload
```

Installer packaging (`npm run tauri build`) is a release step, done once after sign-off. It first runs `scripts/build-sidecar.mjs`, which builds the MCP server `cyberhub-mcp` for the target platform and stages it as a Tauri sidecar, so the installers place it next to the app.

Other scripts:

| Command | What it does |
|---|---|
| `npm run typecheck` | TypeScript check of the frontend |
| `npm test` | Frontend unit tests (Vitest) |
| `cd src-tauri && cargo test` | Backend unit tests: scope engine, target resolution and target files, redaction, process-tree termination, migrations, catalog, NVD parsing, PATH lookup |
| `node scripts/gen-tools-catalog.mjs` | Regenerate `src-tauri/catalog/tools.json` from the catalog source |
| `node scripts/build-sidecar.mjs [--target <triple>] [--debug]` | Build and stage the `cyberhub-mcp` sidecar (also run automatically by `tauri build`) |

`npm run dev` alone starts a browser preview of the UI. It has no backend, so data-driven views show a "desktop runtime not available" state instead of fake data.

## Modules

| Module | Highlights |
|---|---|
| Dashboard | Workstation readiness (tool coverage by category), activity chart, key numbers, activity feed, tasks, favorite and recent tools, recent commands and projects, resource shortcuts, system info. Customizable (show/hide, reorder). |
| Tools Library | 70 tools in 14 categories with docs, platform support, dependencies, install steps per OS, common commands. Real detection (PATH plus known install paths), optional version probing, managed installs through winget, brew, pipx or go (exact command shown and confirmed first), GUI launch, scoped Run. |
| Command Center | Builders for Nmap, FFUF, Gobuster, Nuclei, SQLmap, Subfinder and HTTPX (structured argv, validation, run, copy, save), 49 OS-aware templates with explanations, saved commands with `{{placeholders}}`, and history. |
| Runs | Execution and installation history, live output, cancellation, stored output (up to 2 MB per run). |
| Payloads & Wordlists | 64 reference detection payloads plus your own, with encode-on-copy. A wordlist index that references files in place or copies them into a managed folder, with preview, search, export and favorites. |
| Dorks Studio | Visual operator builder, raw mode, live preview, 37 templates, saved queries, history, open in Google. |
| Cyber Resources | 46 curated sites, custom links, favorites, recently visited. |
| Threat Intel | One search across VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, MalwareBazaar, ThreatFox and Shodan (each optional; credentials are provisioned by the application owner). Per-provider verdicts in the provider's own terms, scores, malware families, categories, timestamps and source links. A side-by-side comparison, related indicators merged across providers with one-click pivots, saved indicators, search history, and Markdown/JSON reports. See [docs/PROVIDERS.md](docs/PROVIDERS.md). |
| VirusTotal | Reputation lookups with automatic type detection, and File analysis: pick a file, hash it locally, check the hash, and only if you choose, upload it publicly after a warning and a system confirmation. Supports ≤ 32 MB and larger files via a one-time upload URL, with progress, cancellation and analysis tracking. |
| Vulnerability Intel | NVD CVE API 2.0 search (live or local cache, clearly labeled), CVSS 4.0/3.x/2.0 with vector breakdown, CWE names, affected products, references, CISA KEV flag, add as finding. |
| Projects | Assessments with authorized scope (domains, wildcards, IPs, CIDRs, URLs, exclusions), findings with evidence references, notes, tool run history, Markdown report export. |
| Security Utilities | Transform workbench, Base64, URL, Hex, JWT inspector, hash identifier, hash calculator, regex tester, JSON/XML/HTML formatters, URL parser, IP/CIDR calculator, User-Agent parser, DNS lookup, HTTP header analyzer. |
| MCP integration | Claude Code, Claude Desktop and other MCP clients can use Cyber Hub's real functionality through `cyberhub-mcp`: 34 tools, 7 resources and 6 prompts. Sensitive operations (runs, uploads, exports, local writes and, by default, external lookups) wait for your approval inside Cyber Hub, and every call is recorded. The MCP page in the sidebar has the status, Approval Center, clients, tool catalog, permissions, audit log and client setup. See [docs/MCP.md](docs/MCP.md). |
| Global search | `Ctrl/⌘ + K` across tools, commands, resources, projects, dorks, payloads, wordlists, utilities and pages. |

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): layers, data model, execution engine, frontend structure, UI library usage
- [docs/SECURITY.md](docs/SECURITY.md): threat model, scope enforcement semantics, provider and upload safeguards, privileges, known limitations
- [docs/PROVIDERS.md](docs/PROVIDERS.md): threat-intelligence providers, their requirements and limits, and deferred candidates
- [docs/PROVISIONING.md](docs/PROVISIONING.md): how the application owner provisions and checks service credentials
- [docs/MCP.md](docs/MCP.md): MCP architecture, tools, resources, prompts, approvals, client setup and troubleshooting
- [docs/PLATFORMS.md](docs/PLATFORMS.md): per-OS dependencies, validation status, platform-specific behavior

## Security at a glance

* Every tool run and installation needs a **native OS confirmation** that page script cannot click.
* Scope-required tools run only inside an active project; every target on the command line **and inside target files** (e.g. `nmap -iL`) is validated, and target files are executed from validated snapshots.
* No shell, closed stdin, absolute executable paths, whole process trees cancelled, credentials redacted before storage.
* Minimal Tauri capabilities (no shell/fs/dialog/HTTP for the web view), strict CSP, `freezePrototype` on.
* MCP clients reach Cyber Hub only through an authenticated loopback bridge that is off by default. They use the same scope engine and native confirmations as the GUI and cannot approve their own sensitive requests.
* Service credentials are provisioned by the application owner with a developer-only tool ([docs/PROVISIONING.md](docs/PROVISIONING.md)), stored in the OS credential store and read only by the Rust backend. No UI or IPC command can read or change them, and none are shipped in binaries or installers.
* Files are uploaded to VirusTotal only after a public-sharing warning, an in-page acknowledgement and a native confirmation for that file. The original file is never modified.

Details and accepted risks: [docs/SECURITY.md](docs/SECURITY.md).

## Implementation status

| Platform | Status |
|---|---|
| Windows 11 | Verified in the running app (detection, scoped runs incl. target files, native confirmations, cancellation, frameless window and its controls, all threat-intelligence providers and VirusTotal file uploads against a local mock API, all pages with a frozen prototype) plus all automated tests. |
| Linux | Automated verification in a Debian 12 container: typecheck, 93 frontend tests, 119 backend tests, frontend and backend builds, and sidecar staging with executable permissions. The GUI has not been run on Linux. |
| macOS | Not built or tested (a cross-compilation check from Windows stops at C dependencies that need the Apple SDK). |

Installers have not been rebuilt since the hardening pass and the MCP sidecar packaging. See [docs/PLATFORMS.md](docs/PLATFORMS.md).
