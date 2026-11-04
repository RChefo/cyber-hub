# Platform notes

## Validation status

| Platform | What was verified | What was NOT verified |
|---|---|---|
| **Windows 11 x64** (dev machine) | Dev build and the running app: real detection (Nmap 7.99 at its Program Files path, Ncat, OpenSSL from Git for Windows), version probing; end-to-end Nmap runs inside an authorized loopback scope, including `-iL` target files read from validated snapshots; native confirmation dialog (approve and cancel); cancelling a live run kills the process; process-tree kill of a grandchild (automated test); all pages render with `freezePrototype` enabled; frameless window: drag to move, double-click maximize/restore, all edges and corners resize, Win+↓ minimizes; window controls with real clicks: minimize, maximize/restore (icon follows double-click and OS restore), close, tooltips and hover states, pressing a control never moves the window; VirusTotal against a local mock API (no real quota used): key rejection and verified save, IP/domain/URL/hash lookups, not-found, quota and local rate-limit errors, cache hit and manual refresh, refusal of private/internal indicators without a request, key removal, and a scan of the database, app-data files and dev log that found no trace of the key; threat-intelligence providers against a local mock of all seven APIs. Credentials were provisioned with the developer-only `cyberhub-keys` tool: import from a git-ignored file, an unignored file refused, a wrong key rejected without replacing the stored one, `status` / `test` with quota, `remove all`. Settings showed read-only availability, including Not configured and availability observed from lookups. Also tested: concurrent IP/domain/URL/hash lookups, provider failure isolation, a disabled provider not being contacted, cache hits, compare and related-indicator views, saved indicators, Markdown export through the native save dialog, and a scan of the database, app-data files, export and dev log for every test key (none found); VirusTotal File analysis: native file picker (path never reaches the page), local hashes matching an independent computation, hash-only lookup, declining the native confirmation (no request, no snapshot), approved upload of 4 KB (`POST /files`) and 33 MB (upload-URL flow) files with analysis polling to the completed report, and snapshots removed afterwards; DNS lookup and live NVD search; typecheck, 90 frontend tests, 80 backend tests (plus 4 provisioning-tool tests), `npm audit`, `cargo audit`. Current counts after the MCP integration: 87 frontend tests, 111 backend tests plus 4 provisioning-tool tests. | Installer builds after this hardening pass (the earlier MSI/NSIS were built before it and are outdated). All providers against their real APIs (no real keys were used, to avoid spending quota and uploading data). Cancelling an upload mid-transfer in the GUI (loopback uploads finish too quickly; covered by an automated test). |
| **Linux** — Debian 12 (bookworm) container, Rust 1.99.1, Node 22 | `npm ci` (incl. the `freezePrototype` dependency patch and its self-test), typecheck, 87 frontend tests, Vite production build, `cargo test` — all 111 backend tests including the Unix process-group kill test and PATH resolution — and a warning-free `cargo build` of the Tauri backend against WebKitGTK 4.1. | The GUI was not launched (no display in the container); window behavior, native dialogs, Secret Service storage and real tool runs on Linux are untested. Kali WSL on this machine has no Rust/Node toolchain and no password-less sudo, so it could not be used. |
| **macOS** | Nothing — no macOS machine was available. | Everything. The code has macOS adapters (see below) and CI is prepared to build and test on `macos-latest`. |

`.github/workflows/ci.yml` runs typecheck, frontend tests, a frontend build and `cargo test` on Windows, macOS and Ubuntu (no installer packaging). It has not been run yet because the repository has not been pushed.

## Build and test instructions

### Common

```bash
npm ci                 # installs deps and runs scripts/patch-deps.mjs (+ self-test)
npx tsc --noEmit -p tsconfig.json
npx vitest run
cd src-tauri && cargo test
npm run tauri dev      # run the app
```

Installers (`npm run tauri build`) are a release step and are not part of development or CI.

### Windows

* Rust (MSVC toolchain), Visual Studio Build Tools with the C++ workload (SQLite is compiled from source), WebView2 runtime (preinstalled on Windows 10/11).
* Process trees use Job Objects (`windows-sys`); no extra setup.

### macOS

* Xcode Command Line Tools, Rust, Node 20+.
* Keychain holds the owner-provisioned service credentials (see PROVISIONING.md).
* Helper: `/usr/bin/open` (GUI tool launch, Terminal).

### Linux (Debian / Ubuntu)

```bash
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libdbus-1-dev pkg-config build-essential
```

* A running Secret Service (GNOME Keyring, KWallet) is needed for the owner-provisioned service credentials (see PROVISIONING.md).
* Process trees use process groups (`libc::killpg`).
* To reproduce the container verification: `docker run --rm -v "$PWD:/src:ro" rust:1-bookworm bash -c "<install deps above>; cp -r /src /work; cd /work && npm ci && npx vitest run && cd src-tauri && cargo test"`.

## Platform-specific behavior

| Concern | Windows | macOS | Linux |
|---|---|---|---|
| Executable lookup | absolute PATH entries only (PATHEXT applied); catalog candidate paths with `{ProgramFiles}`, `{ProgramFiles(x86)}`, `{LOCALAPPDATA}`, `{APPDATA}`, `{HOME}` | absolute PATH entries; `/Applications/*.app` bundles | absolute PATH entries |
| Executables run with arguments | native `.exe`/`.com` only (no `.bat`/`.cmd`) | any regular executable | any regular executable |
| Process tree / cancel | Job Object, `KILL_ON_JOB_CLOSE` | process group, SIGTERM → SIGKILL | process group, SIGTERM → SIGKILL |
| Console windows | suppressed (`CREATE_NO_WINDOW`) | n/a | n/a |
| GUI launch | the detected `.exe` | `/usr/bin/open -a <app>` | the detected binary |
| Open terminal | Windows Terminal (`wt -d`), fallback `%SystemRoot%\…\powershell.exe` | Terminal.app via `/usr/bin/open` | first available of x-terminal-emulator, gnome-terminal, konsole, xfce4-terminal, kitty, alacritty, xterm |
| Secrets | Credential Manager | Keychain | Secret Service (D-Bus) |
| App data | `%APPDATA%\dev.cyberhub.workstation` | `~/Library/Application Support/dev.cyberhub.workstation` | `~/.local/share/dev.cyberhub.workstation` |
| Managed installers | winget, pipx, go | brew/cask, pipx, go | pipx, go (apt/sudo shown as instructions only) |
| Frameless window | verified (move, maximize, resize, minimize) | untested (native traffic-light buttons are hidden when undecorated; the in-app controls replace them) | untested |
| Window controls (minimize, maximize/restore, close) | verified in the running app | untested (same Tauri API) | untested (same Tauri API) |
| MCP (`cyberhub-mcp`, loopback bridge, approvals) | verified end to end, including with Claude Code (Claude Desktop not installed, not tested) | not built or tested | builds and unit tests in a container; not run with a GUI |

### Unsupported or limited functionality

* Tools that need elevated privileges or capture drivers (SYN/UDP/OS scans, packet capture, wireless) fail with the tool's own error; Cyber Hub never elevates.
* `go install` puts binaries in `$GOPATH/bin` — add it to PATH and rescan.
* Linux `apt` installs requiring `sudo` are shown as instructions, not executed.
* Interactive tools (shells, REPLs) receive no stdin and are better run in a terminal.
