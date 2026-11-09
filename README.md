# Cyber Hub

A local-first, cross-platform cybersecurity workstation built with **Tauri 2 (Rust)** and **React 19 + TypeScript**. It brings a curated tools library with real installation detection, a scoped execution engine, command builders, Google Dorks Studio, payloads and wordlists, security utilities, a projects workspace with findings, and CVE intelligence together in one desktop app.

No account and no telemetry. The only background request is the optional update check, which fetches the signed release manifest and never downloads or installs anything by itself. Everything is stored in a local SQLite database and the OS credential store.

**Status:** under active development for **Windows 10/11 x64** and **Linux x64**. Cyber Hub is not released: no installers, packages or downloads are published. macOS is not supported.

## Quick start

Prerequisites: Node.js 20.19+ or 22.12+ (required by Vite 8; tested on 22 and 24), Rust 1.90+ (tested on 1.90, 1.94 and 1.99), and the [Tauri 2 system prerequisites](https://v2.tauri.app/start/prerequisites/) for your OS (WebView2 on Windows, WebKitGTK 4.1 + `libdbus-1-dev` on Linux).

```bash
npm ci                 # also runs scripts/patch-deps.mjs (freezePrototype compatibility, self-tested)
npm run tauri dev      # run the desktop app with hot reload
```

Installers and packages (`npm run tauri build`) are deferred until development is complete; none are built or published. When that step comes, `tauri build` first runs `scripts/build-sidecar.mjs`, which builds the MCP server `cyberhub-mcp` for the target platform and stages it as a Tauri sidecar, so the installers place it next to the app.

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
| Threat Intel | One search across VirusTotal, AbuseIPDB, AlienVault OTX, URLhaus, MalwareBazaar, ThreatFox and Shodan (each optional; credentials are provisioned by the application owner). Per-provider verdicts in the provider's own terms, scores, malware families, categories, timestamps and source links. A side-by-side comparison, related indicators merged across providers with one-click pivots, saved indicators, search history, and Markdown/JSON reports, and STIX 2.1 export of saved indicators. See [docs/PROVIDERS.md](docs/PROVIDERS.md). |
| VirusTotal | Reputation lookups with automatic type detection, and File analysis: pick a file, hash it locally, check the hash, and only if you choose, upload it publicly after a warning and a system confirmation. Supports ≤ 32 MB and larger files via a one-time upload URL, with progress, cancellation and analysis tracking. |
| Vulnerability Intel | NVD CVE API 2.0 search (live or local cache, clearly labeled), CVSS 4.0/3.x/2.0 with vector breakdown, CWE names, affected products, references, CISA KEV flag, add as finding. |
| OSINT Workspace | Investigations with an interactive link-analysis graph (force, hierarchical, radial, circular and manual layouts, filters, groups, path finding, expansion, full screen), saved graphs with Save As, a Graph Manager and version history with compare and non-destructive restore. Collection from Cyber Hub data and public sources (DNS, Team Cymru ASN, RDAP, Certificate Transparency, GitHub, scoped web fingerprint, threat intelligence, NVD) with review before import. Evidence for every entity and relationship, qualitative confidence with reasons, review decisions, a timeline, deterministic suggestions, Markdown reports, and JSON/GraphML/CSV/PNG/SVG export with validated import. See [docs/OSINT.md](docs/OSINT.md). |
| Projects | Assessments with authorized scope (domains, wildcards, IPs, CIDRs, exclusions, and URL entries that authorize only their paths, never the host), findings with evidence references, notes, tool run history, Markdown report export. Findings export as CSV, JSON, SARIF 2.1.0 (for GitHub code scanning and vulnerability managers) or an ATT&CK Navigator layer of the techniques they name. Import of Nmap, Nuclei, Nessus, Greenbone/OpenVAS, Burp Suite, OWASP ZAP, SARIF and Prowler (OCSF) results, and of any CSV file with a column mapping, with a preview, scope checks, deduplication across imports and fix verification by rescan (for Prowler, from the checks that now pass) (see [docs/DATA_MODEL.md](docs/DATA_MODEL.md#scan-import-schema-13)). CVSS 4.0 and 3.1 vectors on findings with a calculator and scores computed as in FIRST's calculators. An OWASP WSTG testing checklist per project with coverage and findings linked to failed tests. An API inventory from OpenAPI, Swagger, Postman and HAR files with checks mapped to the OWASP API Security Top 10 (2023), a test plan, scope status per endpoint and a link to the request builder. SBOM and dependency lockfile analysis (CycloneDX, SPDX; npm, Yarn, pnpm, Cargo, Poetry, uv, Pipfile, requirements.txt, Composer, Bundler, go.mod, NuGet, Gradle) with license risks, completeness and supply-chain checks, and known vulnerabilities from the SBOM or OSV.dev; two versions can be compared for added, removed, upgraded and downgraded components, new vulnerabilities, packages from another source and changed package contents. An Investigation tab that correlates the modules' results into reviewed relationships (each with its reason, matched fields, origin and confidence; nothing is confirmed without you), a panel of everything related to a record, an investigation graph with paths and JSON/SVG/PNG export, an ATT&CK matrix that keeps techniques named by findings, your assessments and imported Navigator layers (such as detection coverage) apart, with gaps and layer export, a filtered and exportable timeline, and evidence provenance (see [docs/DATA_MODEL.md](docs/DATA_MODEL.md#investigation-layer-schema-22)). |
| Finding Library | Reusable finding write-ups: start a finding from a template, save a finding as one, 14 starter templates, JSON export and import, and import rules so scan imports use your text for matching scanner rules (see [docs/DATA_MODEL.md](docs/DATA_MODEL.md#finding-library-schema-14)). |
| Security Utilities | Transform workbench (with defang and refang), Base64, URL, Hex, JWT inspector, hash identifier, hash calculator, IOC extractor, regex tester, JSON/XML/HTML formatters, URL parser, IP/CIDR calculator, User-Agent parser, DNS lookup, HTTP header analyzer, Container & Kubernetes checks (Dockerfiles, Compose files and manifests against the Pod Security Standards and the CIS Docker Benchmark; RBAC roles and bindings for ways to more privileges), Cloud & IaC checks (Terraform, CloudFormation and AWS IAM policies, including account exports, for public resources, open security groups and privilege escalation), File triage of PE and ELF programs without running them (hashes and import hash, sections and entropy, hardening, ATT&CK-mapped capabilities from imports, strings and indicators), Linux persistence triage of an image or triage collection (cron, systemd, preloaded libraries, shell start-up files, SSH keys, accounts, sudo and PAM, with ATT&CK techniques), packet capture triage (pcap, pcapng) and log triage (web access and SSH logs, and Windows event logs with ATT&CK-mapped detections), and the scope-checked HTTP request builder (form or raw requests, session history, resend, response comparison, cURL), TLS analyzer and OAuth & OpenID Connect review (an authorization server's metadata, pasted or fetched within scope, checked against RFC 9700 and the OpenID Connect specifications). |
| MCP integration | Claude Code, Claude Desktop and other MCP clients can use Cyber Hub's real functionality through `cyberhub-mcp`: 49 tools, 7 resources and 6 prompts. Sensitive operations (runs, uploads, exports, local writes and, by default, external lookups) wait for your approval inside Cyber Hub, and every call is recorded. The MCP page in the sidebar has the status, Approval Center, clients, tool catalog, permissions, audit log and client setup. See [docs/MCP.md](docs/MCP.md). |
| Global search | `Ctrl/⌘ + K` across tools, commands, resources, projects, dorks, payloads, wordlists, utilities and pages. |

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): layers, data model, execution engine, frontend structure, UI library usage
- [docs/SECURITY.md](docs/SECURITY.md): threat model, scope enforcement semantics, provider and upload safeguards, privileges, known limitations
- [docs/OSINT.md](docs/OSINT.md): the OSINT workspace: concepts, collection sources, review, graphs, versions, import/export, reports, limits
- [docs/PROVIDERS.md](docs/PROVIDERS.md): threat-intelligence providers, their requirements and limits, and deferred candidates
- [docs/PROVISIONING.md](docs/PROVISIONING.md): how the application owner provisions and checks service credentials
- [docs/MCP.md](docs/MCP.md): MCP architecture, tools, resources, prompts, approvals, client setup and troubleshooting
- [docs/PLATFORMS.md](docs/PLATFORMS.md): per-OS dependencies, validation status, platform-specific behavior
- [docs/WEBSITE.md](docs/WEBSITE.md): the public website (landing and download pages): architecture, release-data integration, configuration, deployment
- [docs/UPDATER.md](docs/UPDATER.md): signed automatic updates: formats, signing keys and their protection, the release workflow, manifest, staging tests, recovery and key rotation
- [docs/UPGRADE.md](docs/UPGRADE.md): database upgrades (automatic backup, tested compatibility), manual backups, restoring a backup in the app, rollback and its limits
- [docs/SIGNING.md](docs/SIGNING.md): Windows Authenticode signing: certificate routes, configuration, secrets, verification, SmartScreen

## Security at a glance

* Every tool run and installation needs a **native OS confirmation** that page script cannot click.
* Scope-required tools run only inside an active project; every target on the command line **and inside target files** (e.g. `nmap -iL`) is validated, and target files are executed from validated snapshots.
* No shell, closed stdin, absolute executable paths, whole process trees cancelled, credentials redacted before storage.
* Minimal Tauri capabilities (no shell/fs/dialog/HTTP for the web view), strict CSP, `freezePrototype` on.
* MCP clients reach Cyber Hub only through an authenticated loopback bridge that is off by default. They use the same scope engine and native confirmations as the GUI and cannot approve their own sensitive requests.
* Service credentials are provisioned by the application owner with a developer-only tool ([docs/PROVISIONING.md](docs/PROVISIONING.md)), stored in the OS credential store and read only by the Rust backend. No UI or IPC command can read or change them, and none are shipped in binaries or installers.
* Files are uploaded to VirusTotal only after a public-sharing warning, an in-page acknowledgement and a native confirmation for that file. The original file is never modified.
* Updates come only from the official Tauri updater: each package must carry a signature from the Cyber Hub update key that names its version, feeds and downloads must use HTTPS, and nothing is installed without a native confirmation or while work is running ([docs/UPDATER.md](docs/UPDATER.md)).

Details and accepted risks: [docs/SECURITY.md](docs/SECURITY.md).

## Implementation status

Development is ongoing. Current verification (details in [docs/PLATFORMS.md](docs/PLATFORMS.md)):

| Platform | Status |
|---|---|
| Windows 10/11 x64 | Verified in the running app on Windows 11: every module, scoped runs incl. target files, native confirmations, cancellation, the frameless window and its controls, VirusTotal file uploads and all threat-intelligence providers against a local mock API, MCP with Claude Code and a scripted client, single-instance behaviour, persistence across restarts. OSINT Workspace: full reliability pass in the GUI (investigations, entities, live public sources, review and import, graph interactions, save and restore across restarts, Save As, Graph Manager, versions, save conflicts, every export and import format through the native dialogs, performance up to 2,000 entities, MCP tools through Claude Code). Durability: crashes during saves and collections, restoration after restart, save conflicts and live collection refresh verified (see docs/PLATFORMS.md). Automated tests: 224 frontend and release-script, 351 backend, 4 provisioning-tool (Windows and Linux each run one platform-only backend test, so both count 351). Final QA audit (November 2026): see docs/EXPANSION_PLAN.md, section 15. Development mission after it (scan import including CSV, finding library, rescan verification, CVSS checked against FIRST's calculators, IOC/STIX, WSTG checklist, exports, backup and restore, MCP tools for these, path-level scope, evidence verification, cross-module reference fixes): see docs/autonomous/ and docs/research/. Updates: an NSIS installation of a test build updated through a local staging feed with signature, downgrade, TLS, cancellation and data-preservation checks (Linux formats and MSI updates untested, see docs/UPDATER.md). |
| Linux x64 | The real app tested on a virtual X display (Xvfb + Openbox) in Debian 12 and Ubuntu 24.04 containers, driven through Tauri's WebDriver support: every module, window behaviour, native GTK dialogs and file choosers, Secret Service provisioning (Debian), Nmap runs and cancellation, VirusTotal and threat intelligence against mocks, findings and reports, MCP, restart persistence; plus builds and all automated tests. Not tested on a physical GNOME/KDE desktop or under Wayland. The features added after the final QA audit were checked in the Linux GUI on Ubuntu 24.04.5 and Debian 12 (offline containers, 62 checks each): path-level scope (the local target's log shows that refused URLs were never requested); CSV import and CVE tracking through the GTK dialogs; findings, vulnerabilities and evidence verification with checked exports; workflows, OSINT, MCP through the real sidecar, and the settings; backup and restore with the automatic restart; and recovery after SIGKILL. The automated suites passed too: type check, all frontend test files, 351 backend tests and clippy. |
| macOS | Not supported. |

No installers or packages exist for the current code.
