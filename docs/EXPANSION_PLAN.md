# Platform expansion: architecture audit and plan (Phase 0)

Status: **Phase 0 complete (audit and plan only; no code changed). Phases 1–8 not started.**
Scope: the "Advanced Platform Expansion" request (attack surface management, vulnerability management, findings, workflow automation, assistant, attack paths, IOC correlation, scan comparison, utilities, engagement workspace, reporting). This document records what already exists, what each new capability reuses, the shared data contracts, migration risks, decisions that need the owner, and the phase plan. It is updated at the end of every phase.

## 1. What exists today

| Area | Implementation | Data |
|---|---|---|
| Projects and scope | `commands/projects.rs`, `scope.rs` (domains, wildcards, IPs, CIDRs, ranges, URLs, exclusions), `targets.rs` (argument and target-file resolution, snapshots) | `projects` (status planning/active/paused/completed/archived), `project_targets` (kind, in_scope, note) |
| Findings | `commands/projects.rs` (`finding_upsert`, list, delete), Markdown project report | `findings` (severity, status open/confirmed/reported/resolved/false_positive, description, affected_target, cve, evidence JSON of `{label, reference}`) |
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

## 6. Phase plan

Each phase: plan, implement, targeted tests, full regression (typecheck, frontend tests, `cargo test`, clippy `-D warnings`), security checks (cargo/npm audit, injection, traversal, SSRF and scope tests for the phase), documentation, one commit, clean tree. No installers are built until final release authorization.

| Phase | Content | Depends on decisions |
|---|---|---|
| 1. Shared data foundation | migrations (schema 9+), `ScopeGate`, `EvidenceStore`, `Timeline`, `AssetStore`, extended findings model and history, scope audit; migration tests on populated databases | — |
| 2. Attack surface management | asset inventory UI, passive discovery via OSINT providers, active discovery via scoped tools, snapshots, change classification (confirmed/observed/possible/incomplete), dashboard | 5 |
| 3. Vulnerabilities and findings | vulnerability records, transparent priority model, lifecycle and history, remediation tracking, Findings Manager (search, filters, bulk status, tags, links) | 2 |
| 4. Workflow automation | definitions, node schemas, validation, executor (ordering, timeouts, retries, cancellation, persistence), builder UI, history, templates | 4 |
| 5. Intelligence and analysis | IOC correlation, attack-path views on the OSINT graph, scan comparison, assistant | 1, 5 |
| 6. Security utilities | HTTP builder, DNS intelligence, TLS analyzer, port/service intelligence, subdomain monitor, secrets scanner, wordlist manager | — |
| 7. Engagement workspace | engagement fields, scope manager UI, evidence vault, project timeline, report builder | 3 |
| 8. Integration and final QA | cross-module tests, Windows and Linux (container) verification, performance, security review, release readiness | — |

Realistic size: each of phases 1–7 is several thousand lines with tests; the whole expansion is a multi-week effort, done and committed phase by phase.
