# Contributing to ExploitX

Thank you for your interest in ExploitX. This guide covers setting up a development environment, the checks a change must pass, and how changes are reviewed.

> **Licensing.** The repository is public but **no open-source license has been selected yet**. See the README, section "License". Until the owner selects one, the maintainer may hold pull requests that add substantial code. Issues, bug reports, reproductions, documentation fixes and small fixes are welcome now. The options under consideration are in [docs/governance/LICENSE_COMPARISON.md](docs/governance/LICENSE_COMPARISON.md).

Please also read the [Code of Conduct](CODE_OF_CONDUCT.md). **Never report a security vulnerability in a public issue or pull request:** follow [SECURITY.md](SECURITY.md).

## Contents

* [Prerequisites](#prerequisites)
* [Setup and running the app](#setup-and-running-the-app)
* [Checks](#checks)
* [Project standards](#project-standards)
* [Database changes](#database-changes)
* [Security-sensitive changes](#security-sensitive-changes)
* [Dependencies](#dependencies)
* [Branches, commits and pull requests](#branches-commits-and-pull-requests)
* [Code review](#code-review)
* [Releases](#releases)

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Rust | **1.90** or later (the minimum CI checks); CI builds with **1.99.1** | Install with [rustup](https://rustup.rs/). Clippy is part of the default profile |
| Node.js | **20.19+ or 22.12+** (required by Vite 8); CI uses **22.12.0** | |
| npm | the version that comes with Node | The project uses **npm** and `package-lock.json`. Please do not add a pnpm or Yarn lock file |
| Platform libraries | see [Tauri's prerequisites](https://v2.tauri.app/start/prerequisites/) | **Windows 10/11:** WebView2 (preinstalled on Windows 11) and the MSVC build tools. **Linux** (Debian/Ubuntu): `libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libdbus-1-dev pkg-config build-essential` |

macOS is not supported. More detail per platform: [docs/PLATFORMS.md](docs/PLATFORMS.md).

## Setup and running the app

```bash
git clone https://github.com/RChefo/cyber-hub.git
cd cyber-hub
npm ci                 # installs the frontend; also runs scripts/patch-deps.mjs (a self-tested compatibility patch)
npm run tauri dev      # the desktop app with hot reload
```

* **Your own data stays separate.** A development build keeps its data in the same folder as an installed ExploitX (`%APPDATA%\dev.cyberhub.workstation` on Windows, `~/.local/share/dev.cyberhub.workstation` on Linux). If you also use ExploitX for real work, give the development build a disposable folder: development builds honour `CYBERHUB_DATA_DIR`.

  ```bash
  CYBERHUB_DATA_DIR=/tmp/cyberhub-dev npm run tauri dev      # Linux
  $env:CYBERHUB_DATA_DIR = "$env:TEMP\cyberhub-dev"; npm run tauri dev   # Windows PowerShell
  ```

* `npm run dev` alone serves the UI in a browser without the Rust backend, so data views show a "desktop runtime not available" state. That is useful for layout work only.
* **No credentials are needed** to build, run or test. Without provider keys the app runs normally, and the features that need a key (threat-intelligence providers, VirusTotal, the assistant) say that none is configured. NVD lookups work without a key, at NVD's lower rate limit. The tests use local mock servers. Provider keys are optional and stay in your OS credential store ([docs/PROVISIONING.md](docs/PROVISIONING.md)).
* **A local installer build** needs no signing key if updater artifacts are turned off. The release configuration signs updates with a key only the release workflow has.

  ```bash
  npx tauri build --config '{"bundle":{"createUpdaterArtifacts":false}}'
  ```

  Such a build is for your own testing. It is not Authenticode-signed and not update-signed, and it must not be redistributed as ExploitX.

The architecture and the development workflow are described in [docs/governance/DEVELOPMENT_GUIDE.md](docs/governance/DEVELOPMENT_GUIDE.md).

## Checks

CI runs the following checks on Windows, Ubuntu 24.04 and Debian 12, and every one of them must pass. Run them locally before you open a pull request:

```bash
# frontend
npx tsc --noEmit -p tsconfig.json          # TypeScript (strict)
npx vitest run                             # frontend and release-script tests
npx vite build                             # production build of the UI

# backend (from src-tauri/)
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked                        # includes upgrades from every database schema and the hostile-input sweep

# repository checks (from the repository root)
node scripts/licenses.mjs check            # dependency licenses against scripts/license-policy.json
node scripts/check-links.mjs               # relative links in the Markdown files
npm audit --audit-level=high
```

CI also runs these, which need extra tools:

* `cargo audit` (cargo-audit 0.22.2);
* [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 over the whole history;
* [actionlint](https://github.com/rhysd/actionlint) 1.7.7 with shellcheck, on the workflows;
* the minimum Rust version.

**Formatting.**
* **Do not run `cargo fmt` on the project.** The Rust code uses its own style and has no rustfmt configuration, so `cargo fmt` would reformat hundreds of unrelated files. Follow the style of the code around your change.
* TypeScript has no formatter configured either: match the surrounding code (two-space indentation, double quotes).
* `tsc` and Clippy with `-D warnings` are the linters.

**Tests that need a network or a desktop.** The automated suites need neither: they use local servers on 127.0.0.1, temporary folders and in-memory databases. The project's manual desktop and installer validation ([docs/release/MANUAL_VALIDATION.md](docs/release/MANUAL_VALIDATION.md)) uses real desktops and disposable virtual machines. Contributors are not expected to run it.

## Project standards

Every change follows the five standards the project was built with:

1. **Feature isolation.** A feature lives in its own module (a frontend module under `src/modules/`, a backend module under `src-tauri/src/`). It does not reach into another feature's internals, and it can fail without taking other features down.
2. **Automated regression tests.**
   * A bug fix comes with a test that fails without it.
   * A feature comes with tests of its rules and edge cases: Rust unit tests next to the code, and Vitest for frontend logic in `*.test.ts`.
   * Hostile input belongs in the parser tests (`hostile_tests.rs` and the parser test files).
3. **Graceful failure.**
   * Errors reach the user as a clear message through the existing error paths (`AppError`, the UI's error states); nothing crashes or hangs.
   * A missing tool, credential, network or certificate is reported, not ignored.
   * Never weaken a check (TLS verification, scope, confirmations) to make something work.
4. **Safe database changes.** See [Database changes](#database-changes).
5. **Safe deployment and rollback.**
   * Changes must keep upgrades from earlier versions working, and keep the pre-upgrade backup restorable.
   * Nothing in a change may publish, sign or release anything; releases are maintainer actions ([Releases](#releases)).

## Database changes

ExploitX's SQLite schema is versioned with `PRAGMA user_version`. The migrations are the list `MIGRATIONS` in `src-tauri/src/db.rs`, applied in order, each in its own transaction together with its new version.

* **Append, never edit.** Add a new migration at the end of `MIGRATIONS`. Never change, reorder or remove a migration that is already on the default branch: existing databases have already run it.
* **Keep data.** A migration must keep every existing row that is still meaningful. If data must change shape, migrate it in SQL within the same migration.
* **Backups and rollback.** Before any migration, ExploitX copies the database to `backups/cyberhub-schema<N>-<time>.db`. An older version refuses a newer database and says how to recover ([docs/UPGRADE.md](docs/UPGRADE.md)). Do not break either path.
* **Tests.** `db_upgrade_tests.rs` builds every earlier version with a row in every table and upgrades it through the real start-up path, including failures injected before a commit and a process killed mid-migration.
  * Make sure your migration passes it.
  * Extend it when your migration transforms data.
  * Document the new schema in [docs/DATA_MODEL.md](docs/DATA_MODEL.md).
* **Use disposable data only** while developing; see `CYBERHUB_DATA_DIR` above.

## Security-sensitive changes

Some areas protect the user and their systems. Changes there get extra scrutiny, and their tests must include the abuse case, not only the normal one:

* the execution engine: native confirmations (`confirm.rs`), argument validation, process trees;
* scope enforcement (`scope.rs`, `targets.rs`, `workspace/scope_gate.rs`) and redirect checks;
* the Tauri capabilities and IPC commands (`src-tauri/capabilities/`, `commands/`): the web view is untrusted for consequential actions;
* credentials (the OS credential store, `cyberhub-keys`) and redaction (`redact.rs`);
* the MCP bridge and its approvals (`mcp/`);
* the updater and its signature checks (`updates.rs`, `scripts/updater-manifest.mjs`);
* network clients and TLS (`tls_trust.rs`). **Never** disable certificate verification or fall back to plain HTTP;
* parsers of untrusted files (scan imports, logs, pcap, EVTX, SBOMs, Sigma and YARA rules, backups).

Read [docs/SECURITY.md](docs/SECURITY.md) first. If your change could weaken a control, say so in the pull request. If you find a vulnerability while working, stop and report it privately ([SECURITY.md](SECURITY.md)).

## Dependencies

* Add a dependency only when it is clearly needed, and say why in the pull request. Prefer what the project already uses.
* Commit the lock file changes (`src-tauri/Cargo.lock`, `package-lock.json`). CI builds with `--locked` and `npm ci`.
* The dependency's license must be accepted by `scripts/license-policy.json`. The check fails otherwise. A license outside the policy needs a maintainer's review and a reasoned exception.
  * Regenerate the inventories with `node scripts/licenses.mjs report` when dependencies change.
  * Copying code from another project needs its license and a source note at the top of the file, and an entry in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
* `cargo audit` and `npm audit` must stay clean. Dependabot opens update pull requests weekly.
* GitHub Actions must be pinned to a full commit SHA (a test fails otherwise).

## Branches, commits and pull requests

* **Base branch:** the default branch, currently `release/v0.1.0`.
* **Branch names:** `<type>/<short-topic>`, for example `fix/osint-graph-positions` or `docs/contributing`.
* **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): short description` in English, in the imperative mood.
  * Types: `feat`, `fix`, `refactor`, `perf`, `test`, `docs`, `build`, `ci`, `chore`, `revert`.
  * The scope is the area, such as `osint`, `projects`, `mcp`, `release` or `installer`.
  * Keep one logical change per commit, and explain *why* in the body when it is not obvious.
  * Write the messages yourself, without generated footers.
* **Pull requests:**
  * a Conventional Commit title (CI checks it), filling in the template: what changed, why, how it was tested;
  * one topic per pull request;
  * tests and documentation updated with the code;
  * all checks green;
  * no unrelated reformatting.
* The default branch is protected: changes arrive through pull requests with passing checks, and history on it is never rewritten.

## Code review

* The maintainer reviews pull requests as their time allows; no review time is promised.
* Reviews look at correctness, tests, failure handling, security impact, data safety, and consistency with the existing code and documentation. They do not look at style preferences.
* Expect questions and change requests. Resolve each conversation before merging.
* Pull requests from forks need the maintainer's approval before their CI runs. That protects the project's CI resources; it says nothing about your change.

## Releases

Releases are made by the maintainer through the release workflow, in a protected environment that holds the update-signing key and needs the owner's approval for each run ([docs/release/](docs/release/)). Contributors never need signing keys, and pull requests cannot reach them: CI has no secrets, and its token is read-only.
