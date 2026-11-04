# Platform notes

Cyber Hub is under active development. It is not released or distributed, and no installers or packages are published.

## Supported platforms

| Platform | Status |
|---|---|
| **Windows 10/11 x64** | Supported. Developed and tested on Windows 11. |
| **Linux x64** | Supported. Tested on Debian 12 and Ubuntu 24.04 LTS (see below for what that covered). |
| macOS | **Not supported.** It is not built, tested, signed or packaged. A few macOS branches remain in shared code (terminal launch, `/Applications` detection) but are unmaintained. |

## Validation status

| Platform | What was verified | What was NOT verified |
|---|---|---|
| **Windows 11 x64** (dev machine) | **OSINT Workspace pass (dev build):** an investigation created and removed; a DNS collection from the real system resolver (no keyed providers were called) reviewed and imported in two parts; private-address, internal-name and unscoped web-fingerprint requests refused; the Main graph rendered with saved positions and pins, force layout, node selection opening the inspector, a verify decision, save, version history with compare and restore (later versions kept), Save As; Entities, Timeline, Data Sources and Reports tabs; no runtime errors. Automated after this pass: typecheck, 163 frontend tests, 167 backend tests, 4 provisioning-tool tests, clippy with warnings denied. Not exercised live: the native Save/Open dialogs for graph export, image export and import (covered by unit tests of the formats), RDAP, crt.sh, GitHub, ASN and web-fingerprint requests against real services, the OSINT MCP tools through a real client (covered by unit tests), Linux. **Previous pass** (dev build against local provider mocks): every module and tab with the sidebar expanded and collapsed, no runtime errors; tool detection (Nmap, Ncat, OpenSSL); a project with scope and an exclusion, target checks; an Nmap run through the native confirmation and its cancellation (process killed, run recorded as cancelled); VirusTotal lookups and refusal of a private indicator; native file picker, upload declined (Escape, no request) and approved in the native dialog, snapshot cleanup; threat-intelligence lookups across all mocked providers; a finding and the report preview; MCP enable/disable, discovery, a policy set to Block in the Permissions UI and enforced against a real client, an approval in the Approval Center, audit filters; developer provisioning into Credential Manager; frameless window: drag and double-click maximize/restore; a second launch exits and focuses the first window; close and restart with data persisting. **Earlier passes, code unchanged since:** `-iL` target files read from validated snapshots, MCP approval expiry and declines, Claude Code connecting through an installed-style sidecar path with spaces, shutdown during an active run, edge and corner resizing, the custom window controls. Automated: typecheck, 96 frontend tests, 122 backend tests plus 4 provisioning-tool tests. | Writing the report through the Windows **Save** dialog was not automated (the dialog opened and cancelling it was handled; the same Rust code wrote the file on Linux). Claude Desktop (not installed). All providers against their real APIs (no real keys were used). |
| **Linux — Debian 12** (Docker container, virtual X display: Xvfb + Openbox window manager + GNOME Keyring, app driven through Tauri's WebDriver support: `tauri-driver` + WebKitWebDriver, native dialogs through `xdotool`) | The real app on WebKitGTK 4.1 as an unprivileged user: every module and tab, expanded and collapsed sidebar, no runtime errors; frameless window under a real window manager: custom minimize (window hidden), maximize/restore (EWMH state), title-bar drag, edge and corner resize, the 1100×700 minimum, double-click maximize/restore; a second launch exits and leaves one window; developer provisioning into the Secret Service (GNOME Keyring) against the mock, read back by the app; tool detection (`/usr/bin/nmap`, OpenSSL); project with scope and exclusion, target checks; Nmap run through the native GTK confirmation and cancellation (process gone, run recorded as cancelled); VirusTotal lookups and refusal of private and internal indicators; file analysis through the GTK file chooser with a matching SHA-256, upload declined (no request, no temp copy) and approved (upload and analysis polling, temp copy removed); threat-intelligence lookups; finding and report saved through the GTK save dialog; MCP: enable from the page, bridge files 0600 in a 0700 folder, sidecar executable, discovery, approval through the native dialog, decline, turning MCP off with a request waiting; close and restart with data persisting. Also: typecheck, frontend tests, `cargo test`, a warning-free build and sidecar staging (mode `rwxr-xr-x`). | A physical Linux desktop (GNOME/KDE on Wayland or X11): the tests ran on a virtual display, so compositor, HiDPI scaling, Wayland behaviour and desktop portals are untested. Claude Code on Linux (not installed in the container; the scripted MCP client was used). KWallet. |
| **Linux — Ubuntu 24.04 LTS** (same container setup) | Build, app start, every module and tab with no runtime errors (expanded and collapsed sidebar), custom maximize/restore/minimize, drag, edge and corner resize, the minimum size, MCP enable and discovery through the sidecar. | Secret Service provisioning: in this container the GNOME Keyring 46 session did not provide a default collection, so provisioning failed with a clear "Secret Service: no result found" error. This is a test-environment limitation; on a desktop the login keyring provides it. Title-bar double-click (the scripted click hit the search box at that window width) and the remaining Debian flows were not repeated on Ubuntu. |

`.github/workflows/ci.yml` runs typecheck, frontend tests, a frontend build, `cargo test` and the sidecar staging on Windows and Ubuntu (no packaging). It has not run yet because the repository has not been pushed.

### Reproducing the Linux GUI tests

The Linux checks above were run in Docker with:

* a Debian 12 (`rust:1-bookworm`) or Ubuntu 24.04 image plus `libwebkit2gtk-4.1-dev`, `xvfb`, `openbox`, `xdotool`, `x11-utils`, `imagemagick`, `dbus-x11`, `gnome-keyring`, `libsecret-tools`, `webkit2gtk-driver`, `nmap` and `cargo install tauri-driver`;
* an unprivileged user running `Xvfb :99`, `openbox`, `dbus-launch` and `gnome-keyring-daemon --unlock --components=secrets`;
* a debug build with the frontend embedded (`cargo build --features tauri/custom-protocol`), started through `tauri-driver` (WebDriver on port 4444) with `CYBERHUB_MOCK_API_BASE` pointing at a local mock of the provider APIs.

WebKitWebDriver reports elements under the legacy key `element-6066-11e4-a52e-4f735466cecf`, and its element clear does not update React state (select the text and type instead).

## Build and test instructions

### Common

```bash
npm ci                 # installs deps and runs scripts/patch-deps.mjs (+ self-test)
npx tsc --noEmit -p tsconfig.json
npx vitest run
cd src-tauri && cargo test
npm run tauri dev      # run the app
```

Installers and packages (`npm run tauri build`) are deferred: Cyber Hub is still in development and nothing is packaged or distributed.

### Packaging and the MCP sidecar (prepared, not used yet)

`tauri build` runs `npm run build && node scripts/build-sidecar.mjs` before compiling the app. The script builds `cyberhub-mcp` for the target triple (`TAURI_ENV_TARGET_TRIPLE`; macOS targets are refused), without the `provisioning` feature, and stages it as `src-tauri/binaries/cyberhub-mcp-<triple>[.exe]` (git-ignored, mode 0755 on Unix, `--version` checked when it can run on the build machine). `bundle.externalBin` then installs it next to the app executable:

| Platform | Installed as |
|---|---|
| Windows (MSI / NSIS) | `<install folder>\cyberhub-mcp.exe` |
| Linux .deb / .rpm | `/usr/bin/cyberhub-mcp` |
| Linux AppImage | `usr/bin/cyberhub-mcp` inside the image; the mount path changes on every start, so MCP client configurations break after a restart (the MCP page warns) |

If the sidecar cannot be built for the target, the script exits with an error, so `tauri build` stops at its beforeBuildCommand instead of producing an installer without it (the failure exit was checked; a full `tauri build` was not run). Installers including the sidecar have not been built yet.

### Windows

* Rust (MSVC toolchain), Visual Studio Build Tools with the C++ workload (SQLite is compiled from source), WebView2 runtime (preinstalled on Windows 10/11).
* Process trees use Job Objects (`windows-sys`); no extra setup.

### Linux (Debian / Ubuntu)

```bash
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libdbus-1-dev pkg-config build-essential
```

* A running Secret Service (GNOME Keyring, KWallet) is needed for the owner-provisioned service credentials (see PROVISIONING.md).
* Process trees use process groups (`libc::killpg`).
* To reproduce the build and unit-test verification: `docker run --rm -v "$PWD:/src:ro" rust:1-bookworm bash -c "<install deps above>; cp -r /src /work; cd /work && npm ci && npx vitest run && cd src-tauri && cargo test"`. For the GUI tests see above.

## Platform-specific behavior

| Concern | Windows | Linux |
|---|---|---|
| Executable lookup | absolute PATH entries only (PATHEXT applied); catalog candidate paths with `{ProgramFiles}`, `{ProgramFiles(x86)}`, `{LOCALAPPDATA}`, `{APPDATA}`, `{HOME}` | absolute PATH entries |
| Executables run with arguments | native `.exe`/`.com` only (no `.bat`/`.cmd`) | any regular executable |
| Process tree / cancel | Job Object, `KILL_ON_JOB_CLOSE` | process group, SIGTERM → SIGKILL |
| Console windows | suppressed (`CREATE_NO_WINDOW`) | n/a |
| GUI launch | the detected `.exe` | the detected binary |
| Open terminal | Windows Terminal (`wt -d`), fallback `%SystemRoot%\…\powershell.exe` | first available of x-terminal-emulator, gnome-terminal, konsole, xfce4-terminal, kitty, alacritty, xterm |
| Secrets | Credential Manager (verified) | Secret Service over D-Bus (verified with GNOME Keyring on Debian; KWallet untested) |
| App data | `%APPDATA%\dev.cyberhub.workstation` | `~/.local/share/dev.cyberhub.workstation` |
| Managed installers | winget, pipx, go | pipx, go (apt/sudo shown as instructions only) |
| Frameless window | verified (move, double-click maximize/restore, resize, minimize) | verified on a virtual display under Openbox (move, double-click maximize/restore, edge and corner resize, minimum size); untested on GNOME/KDE and Wayland |
| Window controls (minimize, maximize/restore, close) | verified in the running app | verified (EWMH maximized/hidden states, close exits) |
| MCP (`cyberhub-mcp`, loopback bridge, approvals, MCP page) | verified end to end, including with Claude Code (Claude Desktop not installed, not tested); installed layout simulated with a release build in a folder with spaces | verified in the GUI tests with a scripted MCP client (Claude Code not tested on Linux) |
| Tool working directory | `%APPDATA%\dev.cyberhub.workstation\work` | `~/.local/share/dev.cyberhub.workstation/work` (mode 0700) |

### Unsupported or limited functionality

* Tools that need elevated privileges or capture drivers (SYN/UDP/OS scans, packet capture, wireless) fail with the tool's own error; Cyber Hub never elevates.
* `go install` puts binaries in `$GOPATH/bin` — add it to PATH and rescan.
* Linux `apt` installs requiring `sudo` are shown as instructions, not executed.
* Interactive tools (shells, REPLs) receive no stdin and are better run in a terminal.
