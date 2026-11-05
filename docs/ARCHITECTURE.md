# Architecture

```
React UI (src/modules/*)
   │  typed calls only (src/lib/ipc.ts — the single place that calls `invoke`)
   ▼
Tauri commands (src-tauri/src/commands/*)      ← input validation, no raw SQL / shell / paths from the UI
   │
   ├── confirm.rs   native OS confirmation dialogs (gate every process start)
   ├── targets.rs   tool-independent target resolution: argument scan, target-file validation + snapshots
   ├── scope.rs     authorized-scope engine (domains, wildcards, IPs, CIDRs, ranges, URLs, exclusions)
   ├── process.rs   process manager: argv spawn (no shell), Job Object / process-group trees, bounded output, cancel, persist
   ├── redact.rs    credential redaction before anything is stored
   ├── detect.rs    tool adapter: absolute-PATH lookup + known locations, dependency check, version probe
   ├── catalog.rs   tool registry compiled from catalog/tools.json
   ├── osint/       OSINT workspace: entity model, ingest pipeline, providers, graphs, versions, analysis, import/export, reports
   ├── updates.rs   signed updates (tauri-plugin-updater): check/download/verify/install state machine, scheduler, install guards
   └── db.rs        SQLite (rusqlite, bundled) + ordered migrations
```

## Backend (Rust)

| Module | Responsibility |
|---|---|
| `commands/activity.rs` | activity log, daily aggregates, preferences (allow-listed keys), favorites, tasks |
| `commands/library.rs` | custom resources and visits, saved commands and history, saved dorks and history, custom payloads |
| `commands/projects.rs` | projects, scope targets (every change recorded in `scope_events`), scope checks, findings (lifecycle statuses, history events, legacy status names accepted), per-project run history, Markdown report |
| `workspace/analysis.rs` + `commands/analysis.rs` | analysis over stored data: indicator correlation (assets, scope, findings, linked OSINT, saved indicators, cached threat intelligence), exposure paths, discovery run comparison, line diff of tool run outputs |
| `commands/assistant.rs` | project assistant (see ASSISTANT.md): context builder with redaction and limits, Anthropic Messages API client (raw HTTPS, owner-provisioned key), in-memory conversations, native confirmation before data is sent |
| `workspace/workflows.rs` + `commands/workflows.rs` | workflow automation (see WORKFLOWS.md): predefined step types with setting schemas and strict validation, templates, persistence of runs and steps, an executor with ordering, time limits, retries, continue on error and cancellation, native confirmation for active steps, and a scheduler for passive workflows |
| `workspace/vulns.rs` + `commands/vulns.rs` | vulnerability management: transparent priority model (CVSS, KEV, optional EPSS, exposure, criticality), lifecycle with history, remediation and verification, EPSS client and cache, finding creation from vulnerabilities, bulk finding status |
| `workspace/discovery.rs` + `commands/discovery.rs` | attack-surface discovery: passive (crt.sh + DNS), web services check, Nmap service scans (XML from standard output through `start_execution` with a finish hook), snapshot comparison with certainty levels, not-observed marking for completed runs; `asm-changed` events |
| `workspace/` + `commands/workspace.rs` | shared project data (see DATA_MODEL.md): `scope_gate.rs` (one passive/active scope decision for new operations, blocked attempts audited), `assets.rs` (normalized asset inventory, observations, discovery snapshots), `findings.rs` (lifecycle rule, history, links to assets, runs, evidence and OSINT entities within the project), `evidence.rs` (evidence registry and content-addressed file store), `timeline.rs` (project timeline as one query over every source) |
| `commands/tools.rs` | catalog sync, detection scan, package-manager availability, managed install, GUI launch, `exec_validate` / `exec_start` / `exec_cancel`, run history |
| `commands/wordlists.rs` | native file/folder/save dialogs opened by the backend, index by reference or managed copy, folder scan, preview (64 MB read cap), export, safe delete (managed folder only) |
| `commands/intel.rs` | DNS lookup (hickory-resolver), HTTP header inspection (reqwest, no redirects, body never read), NVD CVE search and cache |
| `updates.rs` + `commands/updates.rs` | Update Center backend (see UPDATER.md): the official updater plugin driven only from Rust (the web view has no updater permission); stable-channel comparator (newer, no pre-releases, no downgrades), HTTPS-only clients, feed from the build configuration, in-memory download with progress events (`update-status`) and cancellation, signature and signed-version verification by the plugin, install guards (running tools, OSINT collections, MCP approvals, VirusTotal uploads, a running `cyberhub-mcp.exe` on Windows), native install confirmation, automatic checks with backoff and one `update-notice` per version; settings in `user_preferences` (`updates.*`). `lib.rs::shutdown` is the single exit path (normal exit, restart, Windows installer hand-over) |
| `scripts/updater-manifest.mjs` + `.github/workflows/release.yml` | release tooling: builds `latest.json` from the signed artifacts and verifies every entry (file present, HTTPS, minisign signature against the app's public key, signed version) before the release workflow uploads anything |
| `commands/system.rs` | system info (sysinfo), open terminal (no command passed), backend-only credential reads from the OS credential store (no credential IPC commands) |
| `mcp/` + `bin/cyberhub-mcp.rs` + `commands/mcp.rs` | MCP integration: stdio server on the official `rmcp` SDK (`server.rs`, `client.rs`), authenticated loopback bridge (`proto.rs`, `bridge.rs`), operations through the existing commands with policy, approvals and audit (`ops.rs`, `approvals.rs`), tool and resource catalogue (`catalog.rs`), prompts (`prompts.rs`), commands for the MCP page: status, catalog, clients, policy, approvals, filtered audit, client configs (`commands/mcp.rs`). See MCP.md |
| `scripts/build-sidecar.mjs` | packaging check for `cyberhub-mcp`: `tauri build` runs the script (beforeBuildCommand), which compiles the server for the target triple and checks it. The installers ship the crate's own `cyberhub-mcp` binary next to the app (the bundler includes every `[[bin]]` of the crate); it is deliberately not also declared as `bundle.externalBin`, which put it into the MSI twice |
| `provision.rs` + `bin/cyberhub-keys.rs` | developer-only credential provisioning and diagnostics CLI, compiled only with the `provisioning` Cargo feature (see PROVISIONING.md) |
| `commands/virustotal.rs` + `vt.rs` + `vtfile.rs` | VirusTotal API v3: cached reputation lookups (`vt_cache`), file analysis (backend file picker → opaque handle, local hashing, native confirmation, verified snapshot, streamed multipart upload with progress and cancellation, upload-URL flow for > 32 MB, analysis polling) |
| `commands/osint.rs` + `osint/` | OSINT workspace (see OSINT.md): `model.rs` (20 entity types, 38 relationship types, verification, confidence, evidence strength), `normalize.rs` (per-type normalization and match keys), `confidence.rs` (qualitative rules with stored reasons), `ingest.rs` (evidence dedup, exact-identity resolution, derived and observed relationships, bounded correlation, timeline events, follow-new graphs), `store.rs` (investigations, entities, merges, graphs with merge-on-save, versions with diff and non-destructive restore, timeline, comparison), `analysis.rs` (paths, components, degree, shared infrastructure), `providers/` (DNS, Team Cymru ASN, RDAP, crt.sh, GitHub, web fingerprint, threat intelligence, NVD, internal data), `discovery.rs` (background operations with review, cancellation, rate limits, SSRF and scope checks), `io.rs` (native JSON, GraphML, CSV; validated imports), `report.rs` (Markdown report, deterministic suggestions). Commands add transactions, native dialogs and the `osint-changed` event |
| `commands/threat_intel.rs` + `ti/` | Threat-intelligence providers: `ti/indicator.rs` (shared detection, refusal of private targets), `ti/http.rs` (client without redirects, size-capped bodies, key scrubbing, error model), `ti/limit.rs` (per-provider rate limiter), `ti/model.rs` (normalized result), adapters `abuseipdb.rs`, `otx.rs`, `abusech.rs` (URLhaus, MalwareBazaar, ThreatFox), `shodan.rs`, and `ti/mod.rs` (fixed bases, key groups, limits, cache lifetimes). Commands: read-only provider status (configured, enabled, availability observed from real lookups), enable/disable, concurrent multi-provider lookups, history, saved indicators, Markdown/JSON export |

Every command returns `Result<T, AppError>`. `AppError` serializes as `{ kind, message }` so the UI can render specific error states (`validation`, `scope`, `network`, `not_found`, …).

### Threat-intelligence lookups

1. The UI sends `ti_lookup { query, providers?, refresh }`. The backend detects and validates the indicator (`ti::indicator::detect`) and refuses private or internal values.
2. For every requested provider, concurrently (`tokio::join!`): not applicable to this type → `unsupported`; turned off → `disabled`; fresh cache entry → cached result; no key → `no_key`; local limit exhausted → `rate_limited`; otherwise one request to the fixed endpoint, parsed into `ti::model::Report` (verdict in the provider's wording, scores, categories, families, tags, first/last seen, facts, tables, related indicators, permalink).
3. Errors become per-provider statuses. Results with or without a record are cached; errors are not.
4. `summarize` lists which providers reported malicious, suspicious, benign, informational, no record, failed or skipped. It is a grouping, not a score.
5. The search is stored in `ti_history` and the activity log. Exports are rendered from stored results only.

### Shared execution path

`commands/tools.rs::start_execution` is the only way a tool run starts. The GUI command `exec_start` and the MCP operation `cyberhub_run_tool` both call it. The only difference for MCP is a line in the native confirmation naming the requesting client. Run previews (`preview_execution`) and the project report (`projects.rs::markdown_report`) are shared in the same way.

### Execution engine

1. The UI builds a structured `ExecRequest { toolId, args[], projectId, targets[], confirmed }` (unknown fields are rejected). Builders produce argv directly; the Run dialog splits an editable line into argv locally (quotes supported, no shell semantics).
2. `exec_validate` (preview, no side effects) and `exec_start` share `validate_exec`:
   - the tool must be a catalog `cli` tool; the executable is resolved by the detection adapter (never taken from the UI); on Windows it must be a native `.exe`/`.com`
   - argument limits: ≤ 256 args, ≤ 4096 chars each, no NUL / CR / LF
   - if the tool `requiresScope`: the project must exist, be `active` and have in-scope entries; `targets::resolve` examines every argument value and every target file (see `docs/SECURITY.md`) and at least one target must be found
3. `exec_start` builds a confirmation text (program, arguments exactly as they will run, project, authorized targets, and a note when the tool is not scope-checked) and awaits `confirm::native` — a **native OS dialog**. Only on approval does it re-validate with a per-run snapshot directory (`<app data>/runtime/run-*`), rewriting target-file arguments to validated snapshots, and refuse if the target set changed meanwhile.
4. Redacted command history is recorded; `process::start` spawns `tokio::process::Command` (piped output, stdin closed, `kill_on_drop`, no console window on Windows) in Cyber Hub's working directory, which is set at startup to the private `<app data>/work` folder, and attaches the process tree (Windows Job Object with `KILL_ON_JOB_CLOSE`, Unix process group).
5. Output is read in bounded chunks, streamed to a `tauri::ipc::Channel` and buffered (2 MB cap, redacted) into the `executions` row on exit. Cancellation terminates the whole tree; the snapshot directory is removed when the run ends. On app exit all running trees are killed and the runtime directory is cleared.
6. Managed installs reuse the engine with `kind = "install"` after their own native confirmation. Program = resolved package manager, args = exact catalog recipe. A finish hook re-detects the tool or marks it `installation_failed`.

### Data model (migrations 1–9)

`user_preferences`, `favorites`, `tool_categories`, `tools`, `tool_installations`, `resources` (custom), `resource_visits`, `projects`, `project_targets`, `findings`, `command_categories`, `commands`, `command_history`, `saved_dorks`, `dork_history`, `payloads` (custom), `wordlists`, `activity_logs`, `executions`, `cve_cache`, `cve_search_history`, `tasks`. Migration 2 adds `vt_cache` (VirusTotal reports keyed by type and indicator, with fetch time and a not-found flag). Migration 3 adds `ti_cache` (normalized results per provider and indicator), `ti_history` (searches with per-provider outcome lists), `ti_saved` (saved indicators with a note) and `ti_provider_settings` (enable/disable per provider). Migration 4 adds `mcp_audit` (one row per MCP tool call, with redacted arguments). Migration 5 adds the permission category that applied to each call. Migration 6 indexes runs by project. Migration 7 adds the OSINT workspace: `osint_investigations`, `osint_entities` (unique per investigation, type and match key), `osint_relationships` (unique per investigation, ends and type), `osint_evidence` (fingerprint unique per investigation) with the link tables `osint_entity_evidence` and `osint_relationship_evidence`, `osint_operations` (collection runs with their proposed results), `osint_events` (timeline), `osint_graphs`, `osint_graph_nodes` (per-graph membership, position, pin, hidden, group), `osint_graph_versions` (snapshots with content hash and change summary), `osint_entity_merges` and `osint_source_cache`, plus indexes for the common lookups. Investigations cascade to all their rows; a linked project is set to null when it is deleted. Migration 8 adds `osint_graphs.state_revision`, the optimistic-concurrency counter of a graph's saved state: saves and restores increase it, entities added automatically to a graph that follows new data do not. A save based on an older value fails with the `conflict` error kind unless forced. At startup the OSINT source cache is trimmed to 5,000 rows like the other caches. Migration 9 adds the shared project data: the findings table rebuilt with the lifecycle statuses and detail fields (`open` → `new`, `reported` → `confirmed`), `finding_events`, `finding_links`, `scope_events`, `discovery_snapshots`, `assets`, `asset_observations`, `evidence` and `timeline_events` ([DATA_MODEL.md](DATA_MODEL.md)).

History tables are bounded (`db::HISTORY_LIMITS`): the activity log keeps 5,000 rows, CVE search history 500, command history 2,000 and dork history 500. The MCP audit log keeps 1,000 ordinary rows and 5,000 rows tied to approvals or runs. At startup the lookup caches are trimmed (`vt_cache` 5,000, `ti_cache` 10,000, `cve_cache` 20,000 most recent) and runs still marked `running` (the app was killed) are marked as errors; only one instance runs at a time (single-instance plugin), so no run can still be live then.

Foreign keys are enforced (`PRAGMA foreign_keys = ON`). Deleting a project cascades to targets, findings and tasks, assets, evidence records and all project history, and nulls references in history. Evidence files no record refers to are removed at the next start. The database lives at `<app data dir>/cyberhub.db` (on Windows: `%APPDATA%\dev.cyberhub.workstation`).

Static catalogs (tools, resources, dork templates, payloads, command templates) ship with the app as versioned source files. Only user data is stored in SQLite. Catalog tool rows are synced into `tools` at startup so detection results have referential integrity.

## Frontend

```
src/
  app/            shell: store (route, catalog, detections, favorites, prefs), Sidebar, Topbar, CommandPalette, routes
  components/
    ui/           shared kit built on HeroUI (Panel, fields, dialogs, badges, feedback, code blocks)
    charts/       ActivityAreaChart (shadcn Charts + Recharts), SeverityBarChart (ECharts via EvilCharts core)
    vendor/       vendored third-party components (see below)
  data/           static catalogs
  lib/            ipc (typed API), query (tag-invalidated useQuery), actions (copy, open, notify), utils, types
  modules/        one folder per feature, lazy-loaded
  styles/         Tailwind v4 + HeroUI theme token overrides
```

State is deliberately small: a React context for app-wide state, and `useQuery` / `invalidate(tag)` for backend data. Each module is code-split with `React.lazy`.

`modules/osint/graph/` is the link-analysis engine of the OSINT workspace, written for this project without a graph library. It draws on a single canvas with batched passes and label culling, and does hit-testing, marquee selection, dragging, panning, zooming and keyboard navigation. It provides force-directed (Barnes–Hut), hierarchical, radial and circular layouts, run in a Web Worker above 200 nodes and honouring pinned nodes. It also has incremental placement of new nodes, group hulls, and PNG/SVG exporters that share the canvas styling. `GraphCanvas` is fully controlled: positions, viewport and selection live in `GraphWorkspace.tsx`, which persists them through the graph commands. The workspace listens to the backend's `osint-changed` event so background collections and MCP proposals appear without a reload. An event with `scope: "operations"` (a collection started) refreshes only the operations lists (`osint-ops` query tag); every other event refreshes the OSINT queries once (debounced), and the open graph merges the changes into its editor state instead of reloading it.

## UI libraries

| Library | How it is used |
|---|---|
| **HeroUI v3** (`@heroui/react`, `@heroui/styles`) | Primary design system: buttons, cards, inputs, selects, tabs, modals, alert dialogs, dropdowns, popovers, tooltips, switches, checkboxes, toasts, skeletons. The Cyber Hub palette is applied by overriding HeroUI's dark-theme CSS variables in `src/styles/index.css`. |
| **ReactBits** | `CountUp` (vendored unmodified) for dashboard figures. `BranchedMenu` (typed TSX port of the JavaScript + CSS variant) for the expanded sidebar (its groups are the branches; the collapsed sidebar keeps the icon rail): icons are passed as lucide components, so the `@hugeicons` packages are not installed; an optional controlled `value` keeps it in step with the route; focus rings stay visible. |
| **Lightswind** | `DotPattern` (vendored, made static) as subtle texture on the readiness card and empty states. The npm package was not installed because its peer dependencies (three, gsap, ai SDK) are unnecessary. |
| **Untitled UI React** | `FeaturedIcon` pattern adapted onto HeroUI tokens for icon tiles (activity feed, KPIs, empty states). |
| **shadcn Charts** | `chart.tsx` vendored unmodified (Recharts) for the dashboard activity area chart. |
| **EvilCharts** | Shared ECharts core (`echarts-chart.tsx`) vendored unmodified, with a compact severity bar chart built on it (findings and CVSS distributions). |

No other component libraries are used. Vendored files carry a source and attribution header.

### Dependency patch for `freezePrototype`

Tauri's `freezePrototype` is enabled. A few chart dependencies assign `constructor` / `toString` / `valueOf` onto objects that only inherit them from `Object.prototype`, which throws once it is frozen. `scripts/patch-deps.mjs` runs as `postinstall` and rewrites exactly those statements to `Object.defineProperty` (same resulting property):

| Package | Statement |
|---|---|
| `decimal.js-light` (Recharts) | `P.toString = P.valueOf = …`, `x.constructor = Decimal` |
| `d3-color` (+ `victory-vendor` copy) | `prototype.constructor = constructor` |
| `d3-format` (+ `victory-vendor` copy) | `FormatSpecifier.prototype.toString = function…` |
| `echarts` `lib/core/Scheduler.js` | `target[name] = noop` in `mockMethods` |

The script fails the install if an expected statement is missing (dependency changed) and ends with a self-test that loads every patched module with a frozen `Object.prototype`. Other `constructor`/`toString` assignments in the bundle were reviewed: they target functions or objects that already own the property, which is safe.

### Window

The window is frameless (`decorations: false`, `shadow: false`). The top bar and the sidebar header move the window and double-click toggles maximize (`lib/dragRegion.ts`: Tauri's `data-tauri-drag-region` on Windows; on Linux the move starts only after the pointer moves, because a window-manager move started on the first press swallowed the double-click); edges and corners resize natively. Minimize, maximize/restore and close buttons sit at the far right of the top bar (`src/app/WindowControls.tsx`). They use Tauri's window API (`minimize`, `toggleMaximize`, `close`), so the same code serves Windows, macOS and Linux. The maximize icon switches to restore by re-reading `isMaximized()` on every resize event, which keeps it correct when the window is maximized by double-click, snapping or keyboard shortcuts. The buttons are not drag regions, so pressing them never starts a window drag.

### Visual system

Dark, border-free layering: page `#0B0D10` → sidebar/insets `#101318` → cards `#15181F` → raised `#1B1F27`, with soft shadows. Container stroke tokens are transparent by design. Focus rings (`--focus`, cyber blue `#4C8DFF`) and invalid-field borders are kept for accessibility. Status colors: success `#3FB68B`, warning `#E0A43A`, danger `#E5484D`. The severity scale was checked with the dataviz palette validator and is always paired with text labels. Typography uses IBM Plex Sans, with JetBrains Mono (ligatures disabled) only for commands and data.
