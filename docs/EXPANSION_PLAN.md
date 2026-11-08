# Platform expansion: architecture audit and plan (Phase 0)

Status: **Phases 0–8 complete.** Installers have not been built (final release step, not authorized). Phases 1–3 (shared data foundation, attack surface discovery, vulnerabilities and findings; schemas 9 and 10) are described in [DATA_MODEL.md](DATA_MODEL.md), phase 4 (workflow automation; schema 11) in [WORKFLOWS.md](WORKFLOWS.md), phase 5 (analysis and assistant) in [DATA_MODEL.md](DATA_MODEL.md#analysis) and [ASSISTANT.md](ASSISTANT.md), phase 6 (security utilities) in [UTILITIES.md](UTILITIES.md), phase 7 (engagement workspace; schema 12) in [DATA_MODEL.md](DATA_MODEL.md#engagement-workspace-schema-12). Phase 8 results and release readiness are in section 14.
Scope: the "Advanced Platform Expansion" request (attack surface management, vulnerability management, findings, workflow automation, assistant, attack paths, IOC correlation, scan comparison, utilities, engagement workspace, reporting). This document records what already exists, what each new capability reuses, the shared data contracts, migration risks, decisions that need the owner, and the phase plan. It is updated at the end of every phase.

## 1. What exists today

| Area | Implementation | Data |
|---|---|---|
| Projects and scope | `commands/projects.rs`, `scope.rs` (domains, wildcards, IPs, CIDRs, ranges, URLs, exclusions), `targets.rs` (argument and target-file resolution, snapshots) | `projects` (status planning/active/paused/completed/archived), `project_targets` (kind, in_scope, note) |
| Findings | `commands/projects.rs` (`finding_upsert`, list, delete), Markdown project report | `findings` (severity, status open/confirmed/reported/resolved/false_positive, description, affected_target, cve, evidence JSON of `{label, reference}`); extended in Phase 1 |
| Tool execution | `process.rs` (argv only, no shell, Job Objects / process groups, bounded output, cancel), native confirmation (`confirm.rs`), scope gate in `exec_start` | `executions` (tool, program, args redacted, project_id, status, exit code, output ≤ 2 MB, truncated) |
| OSINT | `osint/` (20 entity types incl. Service, Technology, Vulnerability, Certificate, Asn, FileHash; 38 relationship types; evidence with strength; confidence with reasons; verification states; providers: DNS, Team Cymru ASN, RDAP, crt.sh, GitHub, scoped web fingerprint, threat intel, NVD; review-before-import; graphs, versions, merges, timeline events, reports, JSON/GraphML/CSV/PNG/SVG I/O) | `osint_*` tables (investigations with optional `project_id`, entities, relationships, operations, evidence, entity/relationship evidence links, events, graphs, nodes, versions, merges, source cache) |
| Vulnerability intel | `commands/intel.rs` NVD CVE API 2.0 search with cache; CVSS 4.0/3.x/2.0 parsing, CWE, CPE products, CISA KEV flag (from NVD), "add as finding" | `cve_cache`, `cve_search_history` |
| Threat intel / VirusTotal | `ti/` (7 providers, indicator detection, refusal of private targets, per-provider rate limits, normalized verdicts), `vt.rs`/`vtfile.rs` | `ti_cache`, `ti_history`, `ti_saved`, `ti_provider_settings`, `vt_cache` |
| MCP | `mcp/` (stdio server, authenticated loopback bridge, 44 tools, policies, approval center, audit) | `mcp_audit`, preferences |
| Utilities | `src/modules/utilities` (encoders, JWT, hashes, regex, formatters, URL parser, IP/CIDR, UA parser), DNS lookup and HTTP header fetch (`intel.rs`, redirects not followed, body not read) | none |
| Wordlists / payloads | `commands/wordlists.rs` (index by reference or managed copy, preview, export) | `wordlists`, `payloads` |
| Activity, tasks, updates | `commands/activity.rs`, `updates.rs` | `activity_logs`, `tasks`, `user_preferences` |
| Database | rusqlite, WAL, foreign keys on, ordered migrations in `db.rs` (`PRAGMA user_version`, **schema 8**), history and cache trimming at startup | — |

Backend size: about 17,500 lines of Rust; 191 backend, 175 frontend, 4 provisioning-tool tests.

## 2. Overlaps: what is extended, not rebuilt

| Requested | Existing basis | Decision |
|---|---|---|
| Findings Manager | `findings` table and project findings UI | **Extend** `findings` (new lifecycle, category, confidence, reproduction, remediation, tags, due date, assignee label) with a status-history table; one Findings Manager view across projects. No second findings store. |
| Scope Manager | `project_targets`, `scope.rs`, `targets.rs` | **Extend**: explicit assets, scope history/audit table; every active path keeps calling the existing scope engine. |
| Evidence Vault | `osint_evidence` (+ link tables), findings `evidence` JSON, `executions` output | **Unify by reference**: one evidence registry that points at existing records (OSINT evidence, executions) and adds project evidence files (hash, size, path in app data). No copies of existing evidence. |
| ASM asset discovery | OSINT providers and entities (Domain, Ip, Netblock, Service, Technology, Certificate, Asn, Url) | **Reuse providers and normalization**; ASM keeps a project-level asset inventory whose records link to OSINT entities. No second discovery implementation. |
| Vulnerability Management | `cve_cache` (NVD, CVSS, KEV), "add as finding" | **Extend** with project vulnerability records (asset links, lifecycle, history, remediation) referencing `cve_cache`. |
| Attack Path Visualization | OSINT graph module (`src/modules/osint/graph`), relationships, evidence, confidence, verification | **Extend the OSINT graph** with project-level views and finding/vulnerability nodes; no new graph engine. |
| IOC Correlation | `ti/`, `vt`, `ti_history`/`ti_cache`, OSINT entities | **Correlation layer and UI** over existing providers and caches; no new providers. |
| Scan Comparison | `executions` (stored, redacted output) | **Parsers + comparison** over stored executions; originals are never modified. |
| DNS Intelligence | `dns_lookup`, OSINT DNS provider | **Extend** (more record types, history, save as assets). |
| HTTP Request Builder | `http_inspect` (GET, no redirects) | **Extend** with methods, headers, bodies, collections, project scope. |
| Wordlist Manager | `commands/wordlists.rs` | **Extend** (categories, tags, duplicates, integrity hashes, project links). |
| Reporting | project Markdown report, OSINT Markdown report | **Extend** to a template-based report builder (Markdown, HTML; PDF see decisions). |
| Project Timeline | `activity_logs`, `osint_events`, `executions`, finding timestamps | **Unified timeline query** across existing sources plus a small `timeline_events` table for new event types. |
| Cyber Assistant | none (MCP lets *external* AI clients use Cyber Hub) | **New**, behind a provider interface (see decisions). |
| Workflow Automation | execution engine, scope, native confirmation, MCP approval model | **New engine** that drives existing operations only; every step uses the existing safety gates. |
| SSL/TLS Analyzer, Secrets Scanner, Subdomain Monitor, Port/Service Intelligence | parts: OSINT crt.sh, web fingerprint; none for TLS or secrets | **New**, reusing the request clients, scope engine, redaction and evidence registry. |

## 3. Shared data contracts (Phase 1 target)

All new tables use integer primary keys, `project_id` foreign keys, `created_at`/`updated_at` RFC 3339 timestamps, a `source` (provenance) column, and indexes on `(project_id, …)`. Multi-record changes run in one transaction. History is append-only.

```
projects ─┬─ project_targets (scope; + scope_events audit)
          ├─ assets (type, value, normalized key, status, confidence, first/last observed,
          │          osint_entity_id?, source)  UNIQUE(project_id, type, normalized key)
          │     └─ asset_observations (snapshot_id, data, observed_at)   ← change detection
          ├─ discovery_snapshots (kind passive|active, started/finished, operation/execution refs)
          ├─ vulnerabilities (cve_id → cve_cache, asset_id?, status, priority + reasons JSON)
          │     └─ vulnerability_events (status history, notes, remediation, verification)
          ├─ findings (extended) ── finding_events (history) ── finding_links (asset, vulnerability,
          │                                                     osint entity, execution, evidence)
          ├─ evidence (registry: kind file|text|execution|osint_evidence, ref ids, sha256, size, path)
          ├─ workflows ── workflow_runs ── workflow_run_steps (state, inputs/outputs, logs)
          ├─ ioc_records (normalized indicator, last enrichment) ── links to ti_history / osint
          ├─ reports (template, generated file refs, inputs snapshot)
          └─ timeline_events (type, ref, at)  + union view over existing sources
```

Reusable backend interfaces to define in Phase 1:

* `ScopeGate::check(project, targets, mode: Passive|Active)`: a single entry point over `scope.rs`/`targets.rs`, used by tools, workflows, HTTP builder, TLS analyzer, monitors.
* `EvidenceStore::register(...)`: references existing records or stores a file once (content-addressed by SHA-256 inside the app data folder, path-traversal and symlink safe).
* `Timeline::record(project, event)`.
* `AssetStore::upsert_observation(...)`: normalization reuses `osint/normalize.rs`.

## 4. Migration risks

| Risk | Mitigation |
|---|---|
| Extending `findings.status` and `projects.status` `CHECK` constraints needs SQLite table rebuilds (create new table, copy, drop, rename) with foreign keys involved | One migration per rebuild inside the migration transaction; `PRAGMA foreign_key_check` after; tests that run every migration on a database populated at schema 8 and compare row counts and values. Existing status values map 1:1 (`open`→`new`… mapping documented and tested). |
| Large existing databases (OSINT evidence, executions up to 2 MB output) | New tables only reference; no data is copied out of existing tables. |
| Interrupted migration | Each migration runs in one transaction (existing `migrate()` behaviour); a crash leaves the previous version intact. Test with an injected failure. |
| Downgrade (older app on a newer database) | Not supported by any version today; document; the updater never offers downgrades. |
| Unique keys on assets colliding with existing OSINT duplicates | Assets link to entities by id; uniqueness only within the asset table. |

## 5. Decisions needed from the owner

1. **Assistant model provider and credentials.** Cyber Hub has no AI provider today, and its security model says no IPC command may set or read a credential (credentials are provisioned by the owner with `cyberhub-keys`). Options: (a) owner-provisioned key through `cyberhub-keys` (consistent with today); (b) a new user-entered key flow (changes the security model); (c) local models only (e.g. an OpenAI-compatible local endpoint). Recommendation: (a) plus optional (c).
2. **EPSS.** No EPSS source exists. FIRST's public EPSS API would be a new external provider (sends CVE ids). Recommendation: add it as an optional, clearly labelled provider; otherwise prioritization runs without EPSS and says so.
3. **PDF reports.** No PDF engine exists. Options: render HTML and use the system webview's print-to-PDF, or add a Rust PDF crate. Recommendation: HTML report plus print-to-PDF through a native save dialog.
4. **Scheduled workflows.** Background execution while the user is not looking is a change to "nothing runs automatically". Recommendation: scheduled triggers allowed only for passive steps; any active step still needs a native confirmation when the run starts.
5. **Scan parsing.** Reliable service comparison needs structured output (Nmap XML). Recommendation: builders add `-oX` to a run artifact in the private work folder, and parsers read that artifact; free-text output is compared as text only.

### Decided (2026-11-05)

| Decision | Choice |
|---|---|
| 1. Assistant provider | Owner-provisioned API key through `cyberhub-keys`; no in-app credential entry; the security model is unchanged. |
| 2. EPSS | Added as an optional, clearly labelled provider (FIRST EPSS API) that can be turned off; priorities state whether EPSS was available. |
| 3. PDF reports | HTML report saved as PDF through the system webview's print, via a native save dialog; no new dependency. |
| 4. Scheduled workflows | Scheduled runs may execute passive steps only; any step that contacts a target needs a native confirmation when the run starts. |
| 5. Scan parsing | Not asked; the recommendation stands (structured Nmap XML artifacts in the private work folder; free text compared as text only). |

## 6. Phase plan

Each phase: plan, implement, targeted tests, full regression (typecheck, frontend tests, `cargo test`, clippy `-D warnings`), security checks (cargo/npm audit, injection, traversal, SSRF and scope tests for the phase), documentation, one commit, clean tree. No installers are built until final release authorization.

| Phase | Content | Depends on decisions |
|---|---|---|
| 1. Shared data foundation **(done)** | migrations (schema 9+), `ScopeGate`, `EvidenceStore`, `Timeline`, `AssetStore`, extended findings model and history, scope audit; migration tests on populated databases | — |
| 2. Attack surface management **(done)** | asset inventory UI, passive discovery via OSINT providers, active discovery via scoped tools, snapshots, change classification (confirmed/observed/possible/incomplete), dashboard | 5 |
| 3. Vulnerabilities and findings **(done)** | vulnerability records, transparent priority model, lifecycle and history, remediation tracking, Findings Manager (search, filters, bulk status, tags, links) | 2 |
| 4. Workflow automation **(done)** | definitions, node schemas, validation, executor (ordering, timeouts, retries, cancellation, persistence), builder UI, history, templates | 4 |
| 5. Intelligence and analysis **(done)** | IOC correlation, attack-path views on the OSINT graph, scan comparison, assistant | 1, 5 |
| 6. Security utilities **(done)** | HTTP builder, DNS intelligence, TLS analyzer, port/service intelligence, subdomain monitor, secrets scanner, wordlist manager | — |
| 7. Engagement workspace **(done)** | engagement fields, scope manager UI, evidence vault, project timeline, report builder | 3 |
| 8. Integration and final QA **(done)** | cross-module tests, Windows and Linux (container) verification, performance, security review, release readiness | — |

Realistic size: each of phases 1–7 is several thousand lines with tests; the whole expansion is a multi-week effort, done and committed phase by phase.

## 7. Phase 1 result

* **Schema 9** (`db.rs` migration 9): findings rebuilt with the lifecycle statuses and new fields, plus `finding_events`, `finding_links`, `scope_events`, `discovery_snapshots`, `assets`, `asset_observations`, `evidence` and `timeline_events`. Existing data keeps its ids and values; `open` → `new`, `reported` → `confirmed` (recorded in the finding's history). Tests upgrade a populated schema-8 database, inject a failure (schema 8 stays intact, the retry succeeds) and check foreign keys and integrity.
* **Interfaces** (`src-tauri/src/workspace/`): `scope_gate::{decide, enforce}`, `EvidenceStore::{add_file, delete, sweep}` and `evidence::{add_text, link_execution, link_osint}`, `timeline::{record, project_timeline}`, `assets::upsert_observation` with snapshots, and `findings::{set_status, add_note, link, unlink, history}`. Commands are in `commands/workspace.rs`, typed IPC wrappers in `src/lib/ipc.ts`.
* **Existing features adjusted:** the finding editor shows category, confidence, reproduction, technical details and remediation, and keeps fields it does not show. Status changes go through the lifecycle command, and invalid ones (reopening an open finding) are disabled. Findings created from OSINT entities are linked to the entity. MCP accepts the new and the old status names. The report includes the new detail sections. Scope additions, changes and removals are audited.
* **Not in Phase 1:** user interfaces for assets, evidence, the timeline and scope history (phases 2 and 7); vulnerability links (phase 3). `enforce` and discovery snapshots have no caller until phase 2.

## 8. Phase 2 result

* **Attack surface tab** in each project:
  * asset inventory with filters (type, status, text), certainty, status, last seen, observation history, retire or delete, and manual entry;
  * discovery controls: passive discovery, web services check, service scan;
  * run list with status and summary, and a per-run change view (new, changed, missing, each with its certainty).
* **Backend:** `workspace/discovery.rs` and `commands/discovery.rs`, described in [DATA_MODEL.md](DATA_MODEL.md#attack-surface-discovery). `start_execution` accepts a finish hook that receives the run id. Interrupted runs are marked failed at startup.
* **Tests:** Nmap XML parsing (complete, truncated and invalid output), scan arguments accepted by the execution engine's scope resolution (and an out-of-scope target refused), DNS answer mapping and merging, passive roots from the scope, HTML titles, and the snapshot lifecycle (change classification, partial runs, not-observed marking limited to the source, manual assets untouched). Frontend helpers are tested too.
* **Not verified here:** live crt.sh, DNS, HTTP and Nmap runs against real targets; there is no authorized target in this environment. The UI is checked visually in phase 8.

## 9. Phase 3 result

* **Schema 10:** `vulnerabilities`, `vulnerability_events`, `epss_cache` (bounded to 20,000 rows like the other caches). The `epss.enabled` preference is allow-listed.
* **Vulnerabilities tab:**
  * open counts by priority and overdue;
  * search and filters;
  * tracking with asset, exposure, criticality and known exploitation;
  * per vulnerability: the priority explanation, context, status with reasons, remediation plan, verification, history, finding creation;
  * the EPSS switch and score updates.
* **Findings manager:** search, tag filter, tags, assignee and due date in the editor, a history and links view with notes, and bulk status changes.
* **Tests:**
  * the priority model (bands, missing data stated, KEV and analyst knowledge not counted twice), CVSS version choice, and EPSS response validation;
  * the vulnerability lifecycle: uniqueness per CVE and asset, exposure derived from a private service, reasons required, remediation date validation, verification cleared on reopen, project isolation;
  * bulk status (invalid steps skipped and reported, legacy names accepted);
  * frontend helpers.
* **Not verified here:** live NVD and EPSS requests; the UI is checked visually in phase 8.

## 10. Phase 4 result

* **Schema 11:** `workflows`, `workflow_runs` (with a copy of the definition run) and `workflow_run_steps` (state, attempts, summary, log). Interrupted runs are recovered at startup.
* **Automation tab:**
  * workflows from templates or empty;
  * an editor for steps (settings per type, time limit, retries, continue on error, reordering), schedule and enabled state;
  * run with confirmation, run history, and run details with step logs and cancellation.
* **Refactoring:** the discovery commands were split into prepare/begin/run functions shared by the manual actions and the workflow steps. A guard closes a discovery snapshot that is stopped before it finishes.
* **Safety:** no arbitrary code; active steps are confirmed natively and checked against the scope at run time; schedules are passive only (see [WORKFLOWS.md](WORKFLOWS.md)).
* **Not verified here:** live runs against real targets; the UI is checked visually in phase 8.

## 11. Phase 5 result

* **Analysis tab:**
  * exposure paths;
  * indicator correlation with cached threat-intelligence verdicts;
  * comparison of any two discovery runs of the same kind, and a line diff of two tool runs.

  It uses stored data only, with no new tables. The correlation is computed on demand instead of the `ioc_records` table sketched in section 3, so nothing is duplicated.
* **Assistant tab:**
  * Claude (`claude-opus-5-5`) through the Messages API with the owner-provisioned key (decision 1);
  * selectable project data with an exact preview, sent after a native confirmation;
  * no tools, the data wrapped as untrusted data, plain-text answers, in-memory conversations;
  * server-side refusal fallback (`fallbacks: "default"`) and prompt caching.

  `cyberhub-keys` has a new `anthropic` credential, whose test lists models.
* **Tests:** indicator normalization and correlation (sources, cached verdicts, flags, project isolation), exposure path order, the line diff, comparison of arbitrary runs, the assistant's context (selected sections only, credentials redacted), its request shape, and response and error handling (refusal, fallback, truncation, 401/429/400).
* **Not verified here:** live Anthropic requests; no key is provisioned in this environment. The UI is checked visually in phase 8.

## 12. Phase 6 result

* **New utilities** (Security Utilities, new *Assessment* group): HTTP request builder, TLS analyzer, DNS intelligence, port & service reference, subdomain monitor, secrets scanner. See [UTILITIES.md](UTILITIES.md). The wordlist manager already existed and covers that item.
* **Dependencies:** `x509-parser` 0.18 (rusticata; certificate parsing) is new. `rustls` 0.23, `tokio-rustls` 0.26 and `rustls-native-certs` 0.8 were already in the dependency tree and are now direct dependencies, using the `ring` provider.
* **Tests:**
  * TLS issue grading and parsing of the system's root certificates;
  * SPF and DMARC parsing and the mail-authentication assessment;
  * HTTP request validation: methods, schemes, header injection, reserved headers, header count, and an out-of-scope `Host` header refused by the gate;
  * TLS target parsing;
  * the secrets rules: detections, masking, placeholders, entropy, and folder scans skipping dependency folders and binaries. The fake tokens in the tests are split so that no complete token appears in the source;
  * the port reference.
* **Not verified here:** live TLS, DNS and HTTP requests against real targets. The UI is checked visually in phase 8.

## 13. Phase 7 result

* **Schema 12:** engagement details on projects.
* **Project workspace:**
  * the engagement fields in the form and the overview;
  * the scope tester and scope history;
  * the evidence vault (files, notes, tool runs, links to findings, export);
  * the Timeline tab;
  * the Report tab: HTML report builder with preview, print to PDF, HTML export and a copy kept in the evidence.

  The Markdown report includes the engagement details.
* **Tests:** report escaping (no markup from data) and the report CSP, section and severity options, closed findings, and engagement details in the Markdown report. The populated-database upgrade test now runs through schema 12.
* **Not verified here:** printing and the UI are checked visually in phase 8.

## 14. Phase 8: integration, QA and release readiness

### Integration and performance

* **Cross-module test** (`workspace/integration_tests.rs`). One project goes through every module:
  * scope changes, passive discovery and a parsed Nmap scan;
  * a vulnerability on the discovered service, a finding linked to it, and linked evidence;
  * exposure paths, indicator correlation, the timeline and the HTML report;
  * finally, deleting the project removes every dependent row.
* **Volume check** (ignored test, `cargo test --release -- --ignored volume`): 20,000 address assets, 2,000 services and vulnerabilities, and 5,000 findings with history and links. The timings measured:

  | Query | Time |
  |---|---|
  | Asset list (5,000 rows) | 19 ms |
  | Timeline (200 events) | 2 ms |
  | Indicator correlation | 69 ms |
  | Exposure paths | 35 ms |
  | Vulnerability list | 4 ms |
  | Report | 32 ms |

  No additional indexes were needed.

### Security review

An independent review of the phases 1–7 code found no critical or high issues. All reported issues were fixed and covered by tests:
* **Report markup.** A string-prefix shortcut could let report text through as markup. Cells are now typed, and the report CSP adds `form-action 'none'` and `base-uri 'none'`.
* **HTTP check targets.** A URL-form host could make the contacted host differ from the checked one. Entries are now normalized, so the host that is checked is the host that is contacted.
* **Scope history flooding.** Refused attempts are bounded (see SECURITY.md), and the HTTP builder's URL is limited to 8 KB.
* **Schedules.** Scheduled workflows no longer run for projects that are completed, paused or archived.
* **Assistant data wrapper.** The project data can no longer close its own `<project_data>` wrapper.
* **Evidence copies.** Temporary file names are now unique, so two concurrent copies cannot collide.
* **IPv6 `Host` headers** are parsed correctly.

Name-based scope for the active utilities stays an accepted risk (SECURITY.md).

### Visual QA (Windows, WebView2)

The debug build ran with an isolated data folder (`CYBERHUB_DATA_DIR`, honored by debug builds only, now also by the app itself and not just the MCP sidecar). It was seeded through the app's own IPC and driven through the DevTools protocol:
* every new project tab and the new utilities were checked;
* a live passive discovery of `example.com` ran (crt.sh and DNS);
* a live NVD lookup, the passive workflow run and DNS intelligence were checked;
* the print-to-PDF path was checked, and the system print dialog showed the report.

Fixed during QA:
* **Assistant tab crash.** `scrollIntoView` returns a Promise in current WebView2, and an effect returned it.
* **Future times** showed as "just now".
* **Discovery notes:** a null MX record (`0 .`) counted as an invalid asset, the names outside the scope were counted per occurrence instead of distinct, and singular/plural forms were wrong in counts.
* **Timeline label** for discovery runs.
* **Doubled word** in the default report title.
* **Duplicate target tester** on the Scope tab.
* **Stale evidence list** after workflow runs.

### Release readiness

Updated by the final QA audit (section 15).

| Item | State |
|---|---|
| Rust tests, clippy `-D warnings`, frontend typecheck and tests, bundle build | pass on Windows: 257 Rust tests (261 with the `provisioning` feature; the opt-in volume test also passes), 197 frontend tests, clippy clean with and without `provisioning` |
| Migrations 9–12 | upgrade from a real 0.1.0 (schema 8) database verified table by table, with an automatic pre-upgrade backup; interrupted upgrades roll back and complete on the next start; newer databases are refused. 0.1.0 itself misbehaves on an upgraded database: restoring the backup is the only way back ([UPGRADE.md](UPGRADE.md)) |
| `cargo audit` / `npm audit` | no vulnerabilities; 8 allowed warnings (unmaintained or unsound transitive crates in Tauri's Linux stack) |
| Secret scan | gitleaks: no leaks in the 26 commits of history or in the working tree |
| Installers (MSI, NSIS, AppImage, DEB, RPM) | **not built**: the final release step, after release authorization |
| Windows code signing (Authenticode) | **release blocker**: not set up. Procedure in [SIGNING.md](SIGNING.md) |
| Anthropic assistant | live API **not verified** (no key provisioned). Request and error handling verified against a local mock server |
| Version and changelog | unchanged (0.1.0); bump and release notes belong to the release step |

## 15. Final QA, stability and release-readiness audit (November 2026)

Local QA only, on disposable data. The real user database and installation were not touched, and no installer was built.

### Fixed

* **DNS rebinding and SSRF in active utilities.** The HTTP request builder, the TLS analyzer and web checks checked names against the scope but connected to whatever the name resolved to. They now resolve once, refuse non-public addresses that are not in scope (recorded in the scope history), and pin the connection to the vetted addresses. Service scans run the same check before starting (Nmap resolves again; documented). Regression tests: `scope_gate` unit and resolver tests. Verified live against local servers: a name resolving to loopback is refused unless loopback is in scope, and a 302 to the cloud-metadata address is not followed.
* **Pre-upgrade backup and newer-database refusal** (`db.rs`), with a test.
* **Assistant fallback setting.** The fallback can be turned off (on by default); the answer names the model that wrote it. Mock-server test covering success, fallback, 401, 429, 529, 400, a malformed body, a refusal, a timeout and an unreachable server.
* **Junk technologies from web checks.** `Date` and `Content-Type` values were recorded as technologies (`GMT`, `Thu`, `text/html`); only software headers count now. Test added.
* **Readable errors.** A non-HTTP response now says so instead of showing reqwest's text, and a database locked by another program says what to do. Tests added.
* **UI freezes with large data.** The Findings tab rendered every row: 20,000 findings froze the window for 44 s and search took 10 s. The Evidence tab with 10,000 records froze for 10 s. Both now render in steps of 200 with "Show more": 0.6 s and 73 ms for findings, 0.7 s for evidence. Test for the list helper.
* "1 steps" on workflow cards.

### Verified

* **Windows (live app, WebView2, disposable data).** Every module and project tab, the OSINT graph (render, drag, select), Settings switches, restart persistence and a hard kill. HTTP builder, TLS analyzer, web check and Nmap service scan were run against local authorized targets through the native confirmations (cancel and confirm), including scope refusals, a redirect, the 20 s timeout, a malformed response, self-signed certificates, cancellation and duplicate-run refusal. Workflow checks:
  * a failed step with a retry, with and without continue-on-error;
  * cancellation (settles in about 1 s);
  * duplicate-run and delete-while-running refusal;
  * scope refusal before start, and active steps refused in schedules;
  * an interrupted run marked failed after a hard kill;
  * a due schedule runs once on an active project and not on an archived one.
* **Concurrency.** 40 writes while another process held 2 s write locks: all saved. A 7 s lock gives a clear error after the 5 s busy timeout, writes nothing partial, and the next write succeeds. Integrity checks clean.
* **Performance** (optimized build; 30,000 assets, 20,000 findings, 10,000 evidence records, 5,000 runs, 3,000 workflow runs, a 2,000-entity and 4,000-link graph):
  * startup in 2.1 s;
  * findings list 0.33 s;
  * graph load 30 ms with no long tasks while it settles;
  * Attack surface (1,000-row page) 0.6 s;
  * other views under 0.2 s.
* **Linux, with real UI** (Ubuntu 24.04.5 and Debian 12 containers, Xvfb with Openbox, WebKitGTK through WebDriver and xdotool). Steps:
  * started from a copy of a 0.1.0 database: upgraded to schema 12 with a backup, data folder and `backups/` at mode 0700;
  * all 15 modules and the 13 tabs of the migrated project, with no runtime errors;
  * GTK save dialog wrote the report;
  * clipboard (X selection) and toasts;
  * OSINT graph canvas and zoom;
  * HTTP builder scope checks;
  * web check and Nmap scan through the GTK confirmations (confirm and cancel);
  * workflow cancel and duplicate refusal;
  * restart persistence, and recovery after SIGKILL.

  Limits of this environment: virtual display and window manager only (no GNOME or KDE session, no compositor or HiDPI); the clipboard is an X selection; desktop notifications are not used by the app (in-app toasts only); Wayland was not tested.

### Not verified or open

* Live Anthropic API (no key); Authenticode signing (not set up); installers (not built).
* The HTTP header analyzer in Security Utilities fetches any URL the user types, without a scope gate (pre-existing; not reachable by MCP or the assistant). Decision for the owner: keep, or gate it like the HTTP builder.
* Linux: the database file is created with the default umask (0644) inside the 0700 data folder; tightening it to 0600 is optional hardening.
* Version 0.1.0 has no newer-database check, so opening an upgraded database with it is unsafe (documented in UPGRADE.md).
