# Development guide

How ExploitX is built, tested and released, for contributors. It complements [CONTRIBUTING.md](../../CONTRIBUTING.md), which covers the workflow and rules. Deeper references: [ARCHITECTURE.md](../ARCHITECTURE.md), [SECURITY.md](../SECURITY.md), [DATA_MODEL.md](../DATA_MODEL.md), [MCP.md](../MCP.md), [UPGRADE.md](../UPGRADE.md), [UPDATER.md](../UPDATER.md).

## Repository layout

| Path | What it holds |
|---|---|
| `src/` | The React 19 + TypeScript frontend. `app/` is the shell (sidebar, routes, command palette, store); `modules/` has one folder per feature (projects, osint, threatintel, tools, …); `components/` holds shared UI and `components/vendor/` the copied third-party components; `lib/` has IPC wrappers, types and helpers |
| `src-tauri/src/` | The Rust backend: `commands/` (the IPC commands the frontend calls), `workspace/` (projects, findings, imports, assessments), `osint/`, `ti/` (threat intelligence), `sectools/` (offline analysers), `detection/` (Sigma, YARA), `mcp/` (the MCP server and bridge), and the core: `db.rs`, `scope.rs`, `targets.rs`, `confirm.rs`, `process.rs`, `redact.rs`, `tls_trust.rs`, `updates.rs` |
| `src-tauri/src/bin/` | `cyberhub-mcp` (the MCP server sidecar) and `cyberhub-keys` (the developer-only credential provisioning tool, built only with `--features provisioning`) |
| `src-tauri/catalog/` | Bundled data: the tools catalog, ATT&CK catalogs, ASVS |
| `src-tauri/capabilities/` | What the web view may call (Tauri capabilities): deliberately minimal |
| `src-tauri/windows/` | NSIS installer hooks |
| `scripts/` | Build and maintenance scripts (sidecar staging, catalogs, the update manifest, license and link checks) with their tests |
| `website/` | The separate marketing site (its own `package.json`); not part of the app, not deployed |
| `docs/` | Documentation. See [docs/README.md](../README.md) for which documents are for users, for contributors, and for internal release engineering |
| `.github/` | CI and release workflows, issue and pull request templates, Dependabot |

## Architecture

```
React web view ──IPC (tauri::command)──▶ Rust backend ──▶ SQLite · OS credential store · processes · network
  untrusted for consequential actions      validates every input; native OS dialogs gate every process start

MCP client ──stdio──▶ cyberhub-mcp ──loopback bridge (token, off by default)──▶ the running app (same checks and approvals)
```

* **Frontend.**
  * React 19, HeroUI 3 and React Aria, Tailwind CSS 4, built by Vite 8.
  * Every call to the backend goes through `src/lib/ipc.ts` (typed wrappers around `invoke`), with types in `src/lib/types.ts`.
  * The frontend has **no** direct access to the file system, the shell, dialogs or HTTP: the capabilities grant only window control and opening http(s) links.
* **Backend.**
  * Rust on Tauri 2. Commands live in `src-tauri/src/commands/` and are registered in `lib.rs`.
  * Errors are `AppError` (`error.rs`): typed kinds (validation, network, cancelled, …) with a user-facing message, shown by the frontend's error states.
  * Long work runs on Tokio; processes run through `process.rs` (Job Objects on Windows, process groups on Linux).
* **Data layer.**
  * One SQLite database (`rusqlite`, SQLite bundled) in the data folder: `%APPDATA%\dev.cyberhub.workstation` or `~/.local/share/dev.cyberhub.workstation`, or `CYBERHUB_DATA_DIR` in development builds.
  * Evidence files sit next to it.
  * Credentials are never in the database: they are in the OS credential store (Windows Credential Manager, the Secret Service on Linux).
* **Tauri integration.**
  * The window is frameless with custom controls.
  * Native confirmations (`confirm.rs`) are Windows task dialogs or GTK dialogs created by the Rust process, which the page cannot script.
  * File pickers are opened by the backend.
  * `tauri.conf.json` holds the strict CSP, `freezePrototype`, the updater's public key and the bundle settings.

## Security boundaries

The full model is in [SECURITY.md](../SECURITY.md). For development, keep these invariants:

1. **The web view is untrusted for consequential actions.** Anything that starts a process, picks a file, uploads data or writes outside the app's database is decided in Rust. Where a process starts, a native confirmation the page cannot click comes first (Cancel is the default; the approve button is disabled briefly).
2. **Scope.**
   * Tools that reach targets run only in an active project, against targets inside its authorized scope; this includes targets inside target files.
   * Passive lookups never send private or internal addresses to public services.
   * One gate decides this: `workspace/scope_gate.rs`.
3. **No shell.** Programs run with argument vectors, closed stdin and absolute executable paths. Arguments are validated and credentials redacted before storage.
4. **Credentials stay in the OS store** and are read only by the backend. No IPC command reveals them.
5. **MCP clients** go through the same checks and the in-app Approval Center, and cannot approve their own sensitive requests.
6. **Network clients verify TLS** through `tls_trust::build`. Without CA certificates no client is created and the feature says so; never disable verification.
7. **Updates** are accepted only with a valid signature from the release key that names the version.

## Network access

* ExploitX has no telemetry and no account.
* Network requests happen only when the user uses a network feature:
  * threat-intelligence and VirusTotal lookups;
  * NVD and OSV queries;
  * OSINT collection;
  * DNS and HTTP utilities;
  * TAXII feeds;
  * the assistant (if configured);
  * the update check.
* Every active feature respects the project scope; every passive one, the public-only rules.
* **In development and tests:**
  * Debug builds accept `CYBERHUB_MOCK_API_BASE=http://127.0.0.1:<port>`, which sends the threat-intelligence providers to a local mock (loopback only; ignored by release builds).
  * The automated tests use local servers on 127.0.0.1 and never call real services.
  * No test needs an API key.

## Environment variables

| Variable | Where | Effect |
|---|---|---|
| `CYBERHUB_DATA_DIR` | Debug builds only (app and MCP sidecar) | Use this folder instead of the real data folder. Use it so a development build never touches your own data |
| `CYBERHUB_MOCK_API_BASE` | Debug builds only | Loopback base URL for threat-intelligence mocks |
| `CYBERHUB_UPGRADE_FIXTURES` | A test helper | Writes the upgrade fixtures (a database for every schema) into an empty folder |
| `CYBERHUB_EVTX_DIR`, `CYBERHUB_EVTX_OUT`, `CYBERHUB_EVTX_SAMPLES`, `CYBERHUB_SIGMA_RULES`, `CYBERHUB_YARA_RULES`, `CYBERHUB_OCSF_DIR` | Optional, ignored tests | Run the parsers over your own sample folders (event logs, rules, Prowler outputs); the normal test run skips them |
| `TAURI_SIGNING_PRIVATE_KEY`, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | The release workflow only | The update-signing key. Contributors never need it |

`SSL_CERT_FILE` and `SSL_CERT_DIR`, when set, replace the system's CA certificates for ExploitX's TLS clients on Linux (the rule of `rustls-native-certs`).

## Database and migrations

* The schema version is `PRAGMA user_version`. Migrations are the append-only list `MIGRATIONS` in `src-tauri/src/db.rs`, applied at start-up, each in its own transaction with its version.
* Before upgrading, the app copies the database to `backups/cyberhub-schema<N>-<time>.db`. An older ExploitX refuses a newer database and explains how to recover.
* Backups made in the app can be restored in the app (`restore.rs`); the replaced database is kept.
* Tests:
  * `db_upgrade_tests.rs` upgrades every earlier schema, with a row in every table, through the real start-up path. It also covers a failure injected before a commit and a process killed mid-migration;
  * `restore_tests.rs` covers backup and restore.

  Rules for changes: CONTRIBUTING.md, "Database changes".

## Testing structure

| Suite | Where | Runs with |
|---|---|---|
| Rust unit and integration tests | Next to the code (`#[cfg(test)]`), plus `*_tests.rs` files (`db_upgrade_tests`, `hostile_tests` for the hostile-input sweep, `restore_tests`, `perf_tests`, `ci_tests` for the workflows' rules) | `cargo test --locked` in `src-tauri/` |
| Frontend tests | `src/**/*.test.ts` (logic: ranking, parsing, report building, …) | `npx vitest run` |
| Script tests | `scripts/*.test.mjs` (update manifest, license policy, link check) | `npx vitest run` |
| Fuzzing | `src-tauri/fuzz/` (cargo-fuzz targets; the entry points compile in CI) | `cargo +nightly fuzz` |
| Desktop and installer validation | Manual procedures in `docs/release/`, run by the maintainer in disposable VMs | Not required from contributors |

* Some tests are `#[ignore]`d by design: they need sample folders (the variables above), a child process, or long runs. Run them with `cargo test -- --ignored <name>` when you work in that area.
* The counts on 2026-11-13:
  * Windows: 648 Rust tests pass, 29 ignored;
  * Debian 12: 649 pass, 29 ignored (one more test runs on Linux only);
  * frontend and scripts: 319 tests in 58 files.

## Building

* **Development:** `npm run tauri dev`.
* **A local installer:** `npx tauri build --config '{"bundle":{"createUpdaterArtifacts":false}}'`. It needs no signing key. It is not Authenticode-signed and not update-signed: use it for testing only.
* **The MCP sidecar** is built and staged by `scripts/build-sidecar.mjs`, which `tauri build` runs; `node scripts/build-sidecar.mjs --debug` builds it for development.
* **Linux packages** need the Tauri prerequisites, plus `rpm`, `patchelf` and `file` for the rpm and AppImage formats (see the release workflow).

## Release workflow

Releases are maintainer-only. The details are in [UPDATER.md](../UPDATER.md) and [docs/release/](../release/).

* **CI** (`.github/workflows/ci.yml`) verifies every pull request, and every push to `main`, `release/**` and `v*` tags:
  * builds, tests and Clippy on Windows, Ubuntu 24.04 and Debian 12;
  * the minimum Rust version;
  * `cargo audit`, `npm audit`, gitleaks and actionlint;
  * the repository checks (licenses, links, pull request titles).

  It reads no secret, and its token is read-only.
* **Release** (`.github/workflows/release.yml`) runs only for a pushed version tag (which only validates) or by hand. Even then it builds only when the owner has set the `RELEASE_PUBLISHING` switch for that run, and the `release` environment needs the owner's approval.
  * Only that environment holds the update-signing key.
  * Every upload is a draft, and the build artifacts are deleted after the upload.
  * A release candidate (`vX.Y.Z-rc.N`) is never published by the workflow.
* **Authenticode signing of Windows binaries** is not set up yet ([SIGNING.md](../SIGNING.md)).

## Known limitations for contributors

* **macOS** is not supported, and the app does not build there without work.
* **Desktop behaviours** (native dialogs, file choosers, keyrings, HiDPI) are covered by manual validation in VMs, not by CI.
* **A development build shares the identifier of installed builds.** Use `CYBERHUB_DATA_DIR` so it never opens your real database.
* **Provider credentials have no in-app screen, by design** ([PROVISIONING.md](../PROVISIONING.md)). They live in the OS credential store under documented entry names. They are written with the developer-only `cyberhub-keys` tool, which the installers do not include; build it from source with `--features provisioning`. Users of an installed build therefore need that tool or their operating system's credential tools to add keys. A friendlier path for external users would be a product change, outside the open-source preparation.
* **The project has no license yet:** see the README.
