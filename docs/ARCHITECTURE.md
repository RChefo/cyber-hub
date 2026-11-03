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
   └── db.rs        SQLite (rusqlite, bundled) + ordered migrations
```

## Backend (Rust)

| Module | Responsibility |
|---|---|
| `commands/activity.rs` | activity log, daily aggregates, preferences (allow-listed keys), favorites, tasks |
| `commands/library.rs` | custom resources and visits, saved commands and history, saved dorks and history, custom payloads |
| `commands/projects.rs` | projects, scope targets, scope checks, findings with evidence, per-project run history |
| `commands/tools.rs` | catalog sync, detection scan, package-manager availability, managed install, GUI launch, `exec_validate` / `exec_start` / `exec_cancel`, run history |
| `commands/wordlists.rs` | native file/folder/save dialogs opened by the backend, index by reference or managed copy, folder scan, preview (64 MB read cap), export, safe delete (managed folder only) |
| `commands/intel.rs` | DNS lookup (hickory-resolver), HTTP header inspection (reqwest, no redirects, body never read), NVD CVE search and cache |
| `commands/system.rs` | system info (sysinfo), open terminal (no command passed), OS-keychain secrets (write-only from the UI) |
| `commands/virustotal.rs` + `vt.rs` | VirusTotal API v3 reputation lookups: indicator detection and refusal of private targets, HTTP client (key only in the `x-apikey` header, no redirects, 20 s timeout), report parsing, local rate limiter, `vt_cache`, key management |

Every command returns `Result<T, AppError>`. `AppError` serializes as `{ kind, message }` so the UI can render specific error states (`validation`, `scope`, `network`, `not_found`, …).

### Execution engine

1. The UI builds a structured `ExecRequest { toolId, args[], projectId, targets[], confirmed }` (unknown fields are rejected). Builders produce argv directly; the Run dialog splits an editable line into argv locally (quotes supported, no shell semantics).
2. `exec_validate` (preview, no side effects) and `exec_start` share `validate_exec`:
   - the tool must be a catalog `cli` tool; the executable is resolved by the detection adapter (never taken from the UI); on Windows it must be a native `.exe`/`.com`
   - argument limits: ≤ 256 args, ≤ 4096 chars each, no NUL / CR / LF
   - if the tool `requiresScope`: the project must exist, be `active` and have in-scope entries; `targets::resolve` examines every argument value and every target file (see `docs/SECURITY.md`) and at least one target must be found
3. `exec_start` builds a confirmation text (program, redacted arguments, project, authorized targets) and awaits `confirm::native` — a **native OS dialog**. Only on approval does it re-validate with a per-run snapshot directory (`<app data>/runtime/run-*`), rewriting target-file arguments to validated snapshots, and refuse if the target set changed meanwhile.
4. Redacted command history is recorded; `process::start` spawns `tokio::process::Command` (piped output, stdin closed, `kill_on_drop`, no console window on Windows), attaches the process tree (Windows Job Object with `KILL_ON_JOB_CLOSE`, Unix process group).
5. Output is read in bounded chunks, streamed to a `tauri::ipc::Channel` and buffered (2 MB cap, redacted) into the `executions` row on exit. Cancellation terminates the whole tree; the snapshot directory is removed when the run ends. On app exit all running trees are killed and the runtime directory is cleared.
6. Managed installs reuse the engine with `kind = "install"` after their own native confirmation. Program = resolved package manager, args = exact catalog recipe. A finish hook re-detects the tool or marks it `installation_failed`.

### Data model (migrations 1–2)

`user_preferences`, `favorites`, `tool_categories`, `tools`, `tool_installations`, `resources` (custom), `resource_visits`, `projects`, `project_targets`, `findings`, `command_categories`, `commands`, `command_history`, `saved_dorks`, `dork_history`, `payloads` (custom), `wordlists`, `activity_logs`, `executions`, `cve_cache`, `cve_search_history`, `tasks`. Migration 2 adds `vt_cache` (VirusTotal reports keyed by type and indicator, with fetch time and a not-found flag).

Foreign keys are enforced (`PRAGMA foreign_keys = ON`). Deleting a project cascades to targets, findings and tasks, and nulls references in history. The database lives at `<app data dir>/cyberhub.db` (on Windows: `%APPDATA%\dev.cyberhub.workstation`).

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

## UI libraries

| Library | How it is used |
|---|---|
| **HeroUI v3** (`@heroui/react`, `@heroui/styles`) | Primary design system: buttons, cards, inputs, selects, tabs, modals, alert dialogs, dropdowns, popovers, tooltips, switches, checkboxes, toasts, skeletons. The Cyber Hub palette is applied by overriding HeroUI's dark-theme CSS variables in `src/styles/index.css`. |
| **ReactBits** | `CountUp` (vendored unmodified) for dashboard figures. |
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

The window is frameless (`decorations: false`, `shadow: false`). The top bar (`data-tauri-drag-region`) moves the window and double-click toggles maximize; edges and corners resize natively. Minimize, maximize/restore and close buttons sit at the far right of the top bar (`src/app/WindowControls.tsx`). They use Tauri's window API (`minimize`, `toggleMaximize`, `close`), so the same code serves Windows, macOS and Linux. The maximize icon switches to restore by re-reading `isMaximized()` on every resize event, which keeps it correct when the window is maximized by double-click, snapping or keyboard shortcuts. The buttons are not drag regions, so pressing them never starts a window drag.

### Visual system

Dark, border-free layering: page `#0B0D10` → sidebar/insets `#101318` → cards `#15181F` → raised `#1B1F27`, with soft shadows. Container stroke tokens are transparent by design. Focus rings (`--focus`, cyber blue `#4C8DFF`) and invalid-field borders are kept for accessibility. Status colors: success `#3FB68B`, warning `#E0A43A`, danger `#E5484D`. The severity scale was checked with the dataviz palette validator and is always paired with text labels. Typography uses IBM Plex Sans, with JetBrains Mono (ligatures disabled) only for commands and data.
