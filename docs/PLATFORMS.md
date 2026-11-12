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
| **Windows 11 x64** (dev machine) | **OSINT durability pass:** the app force-killed during continuous graph saves (database intact, the graph in its last committed state, positions, workspace and latest version from the same save) and during a running collection (marked *Interrupted* at the next start); all graphs of an investigation (Main, Save As copy, restored duplicate, a scratch graph) reopened right after the restart and while switching between them, each with its own saved layout, labels, hidden nodes and filters; the open graph during a live collection and import (refreshed only when the collection finished and when results were imported, no saves, no remount, selection, viewport, unsaved edits and node positions kept, no duplicates); save conflicts from a second editor with Cancel, *Save mine as a new graph* and *Overwrite* after an external restore; crt.sh live (60 certificates, cache, import, rate limit); loopback, metadata, IPv4-mapped and rebinding targets refused even inside a project scope. **OSINT reliability pass (dev build, real GUI driven through trusted input events):** investigations created through the form and the API, edited (name, tags, notes, authorization, linked project, target change), closed, archived, reactivated, compared and deleted through the native confirmation; entity identity and normalization (no merging of distinct values, possible duplicates listed), merge with alias and history, verify/dispute/reject; live public sources: DNS (forward, PTR, cache), Team Cymru ASN, RDAP (domain, IP, ASN), GitHub search, NVD (live and cache), the web fingerprint against the Nmap-authorized host `scanme.nmap.org` inside a project scope, plus refusals (private address, internal name, out of scope, archived investigation), cancellation, the per-source rate limit and the concurrency limit; review and partial import followed by importing the rest; the graph: drag, zoom, pan, rectangle selection, pin, hide, group, filters, labels, search, context menu, shortest path, layouts, inspector; save, restart of the application and full restoration of the workspace; Save As independence, Graph Manager (rename, duplicate, delete with native confirmation and its cancel, unsaved-changes guard with cancel and discard); versions (checkpoint, 60-version retention, compare, restore, edit after restore); conflicting saves (refusal, overwrite, discard and reload); JSON, GraphML, both CSVs, PNG, SVG and the Markdown report written through the native Save dialog and inspected; JSON and GraphML imports through the native Open dialog (round trip exact; malformed, DOCTYPE/XXE, entity bomb, duplicate IDs, oversized, too many entities, newer format and wrong type refused); performance with 100 to 2,000 entities (see OSINT.md); the OSINT MCP tools through Claude Code 2.1.318 with approvals in the app. **Earlier OSINT pass**: the first live DNS collection and graph checks. **Previous pass** (dev build against local provider mocks): every module and tab with the sidebar expanded and collapsed, no runtime errors; tool detection (Nmap, Ncat, OpenSSL); a project with scope and an exclusion, target checks; an Nmap run through the native confirmation and its cancellation (process killed, run recorded as cancelled); VirusTotal lookups and refusal of a private indicator; native file picker, upload declined (Escape, no request) and approved in the native dialog, snapshot cleanup; threat-intelligence lookups across all mocked providers; a finding and the report preview; MCP enable/disable, discovery, a policy set to Block in the Permissions UI and enforced against a real client, an approval in the Approval Center, audit filters; developer provisioning into Credential Manager; frameless window: drag and double-click maximize/restore; a second launch exits and focuses the first window; close and restart with data persisting. **Earlier passes, code unchanged since:** `-iL` target files read from validated snapshots, MCP approval expiry and declines, Claude Code connecting through an installed-style sidecar path with spaces, shutdown during an active run, edge and corner resizing, the custom window controls. Automated: typecheck, 96 frontend tests, 122 backend tests plus 4 provisioning-tool tests. | crt.sh: unavailable during the reliability pass; verified live in the durability pass while it alternated between answers and HTTP 502. Threat-intelligence providers were not called live (no real keys or quotas used; covered by mocks). The graph that once showed default workspace settings was explained in the durability pass: the QA script had opened a different investigation with the same name (an imported copy whose main graph had never been saved); imported investigations are now named "… (imported)". Claude Desktop (not installed). |
| **Linux — Debian 12** (Docker container, virtual X display: Xvfb + Openbox window manager + GNOME Keyring, app driven through Tauri's WebDriver support: `tauri-driver` + WebKitWebDriver, native dialogs through `xdotool`) | **OSINT durability pass (virtual display):** node drag and wheel zoom with real X pointer events, saved; the app killed with SIGKILL during continuous saves and restarted (integrity clean, consistent last committed state); the OSINT durability tests and the process-tree test (20 runs) natively. **OSINT pass (virtual display, not a physical desktop):** fresh database created at schema 8; investigation and entity creation; a live DNS collection (real resolver) reviewed and imported; private address refused; the graph rendered on WebKitGTK; a workspace change made in the UI and saved; a version checkpoint; graph JSON and the Markdown report written through the GTK save dialog and checked; the JSON imported through the GTK file chooser (preview and apply); the app restarted and the investigation, graph workspace, positions and versions restored; data folder `drwx------` (fixed in this pass, it was `755`); database integrity and foreign keys checked; no runtime errors. **Earlier pass:** the real app on WebKitGTK 4.1 as an unprivileged user: every module and tab, expanded and collapsed sidebar, no runtime errors; frameless window under a real window manager: custom minimize (window hidden), maximize/restore (EWMH state), title-bar drag, edge and corner resize, the 1100×700 minimum, double-click maximize/restore; a second launch exits and leaves one window; developer provisioning into the Secret Service (GNOME Keyring) against the mock, read back by the app; tool detection (`/usr/bin/nmap`, OpenSSL); project with scope and exclusion, target checks; Nmap run through the native GTK confirmation and cancellation (process gone, run recorded as cancelled); VirusTotal lookups and refusal of private and internal indicators; file analysis through the GTK file chooser with a matching SHA-256, upload declined (no request, no temp copy) and approved (upload and analysis polling, temp copy removed); threat-intelligence lookups; finding and report saved through the GTK save dialog; MCP: enable from the page, bridge files 0600 in a 0700 folder, sidecar executable, discovery, approval through the native dialog, decline, turning MCP off with a request waiting; close and restart with data persisting. Also: typecheck, frontend tests, `cargo test`, a warning-free build and sidecar staging (mode `rwxr-xr-x`). | A physical Linux desktop (GNOME/KDE on Wayland or X11): the tests ran on a virtual display, so compositor, HiDPI scaling, Wayland behaviour and desktop portals are untested. The OSINT performance measurements were done on Windows only; the OSINT MCP tools were not repeated on Linux. No physical Linux desktop was available for any OSINT pass: GNOME, Wayland, HiDPI scaling, desktop portals and a real login keyring remain unverified for the OSINT workspace. Claude Code on Linux (not installed in the container; the scripted MCP client was used). KWallet. |
| **Linux — Ubuntu 24.04 LTS** (same container setup) | **OSINT durability pass:** the same as on Debian 12, with the same results (virtual display). **OSINT pass:** the same OSINT flow as on Debian 12, with the same results (virtual display). **Earlier pass:** build, app start, every module and tab with no runtime errors (expanded and collapsed sidebar), custom maximize/restore/minimize, drag, edge and corner resize, the minimum size, MCP enable and discovery through the sidecar. | Secret Service provisioning: in this container the GNOME Keyring 46 session did not provide a default collection, so provisioning failed with a clear "Secret Service: no result found" error. This is a test-environment limitation; on a desktop the login keyring provides it. Title-bar double-click (the scripted click hit the search box at that window width) and the remaining Debian flows were not repeated on Ubuntu. |

**Mission 5 (2026-11-10), Linux at `91b064a`:**
* **Suites:** Ubuntu 24.04.5 and Debian 12 containers. On both, these pass:
  * tsc;
  * 50 frontend test files;
  * clippy with warnings as errors;
  * `cargo test`: 568 passed and 16 ignored, including the Unix-only symlink tests;
  * npm audit.

  The minimum Rust version also passed on Ubuntu: `cargo +1.90.0 check --locked --all-targets`.
* **GUI regression on a virtual display:** 71/71 on each distribution: scope, imports, findings, workflows, evidence, OSINT, MCP, settings, backup, a restore that restarts the app, and recovery after SIGKILL.
  * Debian reached 71/71 on a re-run. Its first run lost the WebDriver session when the app was started after SIGKILL.
  * That did not reproduce in the re-run, nor in 12 more cycles of SIGKILL and restart.
* **The Mission 5 features on a virtual display:** 18/18 on each distribution. This covers:
  * a Sigma correlation and a YARA rule over files added through the GTK file chooser;
  * risk acceptance through the status menu, its form and the Risks tab, with keyboard input and Escape;
  * TAXII through the GTK confirmation, both cancel and confirm;
  * the ASVS report through the GTK save dialog;
  * Ctrl+K search, the charts and the investigation graph;
  * a 50 MB log read off the UI thread (the slowest frame while reading was 27 ms on Ubuntu and 54 ms on Debian).
* **A real compositor:** WSLg 1.0.71 (Weston) on this Windows 11 machine, reached from both containers through its sockets mounted read-only.
  * **Native Wayland** (`GDK_BACKEND=wayland`): 4/4 on each distribution. This covers rendering, navigation, keyboard search, the charts and no runtime errors.
  * **X11 through XWayland:** 6/6 on each. This is the same, plus a GTK file chooser and a GTK confirmation.

  Native dialogs were not driven under native Wayland, because xdotool needs X11.
* **Mission 6, the compositors of GNOME and KDE** (Ubuntu 24.04 container with the distribution's packages, the app as a native Wayland client, software rendering): Mutter 46.2 in headless mode and KWin 5.27.11 with a virtual output, 5/5 each: rendering and navigation, Ctrl+K and Escape, the window's size, maximize and restore, the display scale, no runtime errors, and a clean quit. These are the compositors without GNOME Shell or Plasma. KWin's XWayland crashed in the container, so the app was not run through it there.
* **Mission 6, HiDPI** (`GDK_SCALE=2`, Xvfb and Openbox): 7/7. The web view renders at a device pixel ratio of 2; a GTK credential dialog stores into GNOME Keyring and a GTK file chooser opens a file. The window's minimum size then (1100 × 700 logical pixels) was larger than a 1920 × 1080 screen at 150 % or 200 % scaling; Mission 7 lowered it to 800 × 480 and sizes the window to the screen (see "Display scaling and window size").
* **Mission 6 features on a virtual display**, both distributions: TAXII credentials typed into the GTK dialog (store, connection test, rotation, cancel by Escape and by the window manager, forget, deletion when the server moves or is removed) 14/14; a WSTG exception and the question before a result ends it, process chains and logons from EVTX files chosen in the GTK file chooser, the ICS matrix and a layer saved through the GTK save dialog, and cloud resources from a Prowler file, 11/11.
* **Still untested:** full GNOME Shell and Plasma sessions, desktop portals (the app uses GTK's own dialogs), a GPU (every container rendered in software), a physical HiDPI screen, and a real login keyring.

**Updater (Windows 11, staging):** a disposable NSIS installation of a test build updated from 0.1.0 to 0.2.0 through a local feed, with signature, version-binding, downgrade, TLS, cancellation, install-guard and data-preservation checks (details and the untested parts in [UPDATER.md](UPDATER.md#testing)).

`.github/workflows/release.yml` builds, signs and publishes releases. Its first runs, in Mission 10, built the `v0.1.0` candidate as a private draft. Since Mission 6:
* it builds and uploads nothing unless the repository variable `RELEASE_PUBLISHING` is `enabled`;
* a tag push stops at a draft;
* its toolchains are pinned like `ci.yml`'s.

See [UPDATER.md](UPDATER.md#the-release-workflow).

`.github/workflows/ci.yml` (Mission 5) runs no packaging. It has not run yet because the repository has not been pushed. It has four jobs:
* **Windows (`windows-2022` image) and Ubuntu 24.04:** typecheck, frontend tests, the frontend build, clippy with warnings as errors, `cargo test --locked`, a check that the fuzz entry points compile, the sidecar staging and `npm audit`. The tests include database upgrades from every schema and the hostile-input sweep.
* **Debian 12:** a container job running the frontend checks and `cargo test --locked`.
* **Audit:** `cargo audit`, a gitleaks scan of the whole history, and actionlint (1.7.7, checksum-verified) over both workflows, including shellcheck on their scripts.
* **MSRV:** `cargo check --all-targets` with Rust 1.90.0.

It is deterministic:
* actions are pinned by commit and the Debian image by digest;
* Rust (1.99.1), Node (22.12.0), cargo-audit (0.22.2) and gitleaks (8.30.1, checksum-verified) are pinned by exact version;
* runner images are exact (no `*-latest`), and every job has a timeout;
* a test (`ci_tests.rs`) fails if a workflow stops parsing, an action loses its commit pin, a toolchain, runner or tool floats, a job loses its timeout, or one of these checks disappears.
  * For `release.yml`, it also fails if the top-level permissions grow, secrets appear outside the `release` environment, the release switch or the publish condition goes, or a second step can make a release public.

**First run of the workflows** (owner's steps; nothing has been pushed):
1. Create the GitHub repository, private until a release, and push `release/v0.1.0`. A push starts `ci.yml`: the jobs `verify` (Windows and Ubuntu), `debian`, `audit` and `msrv`.
2. Before that push, set these under Settings → Actions → General:
   * *Workflow permissions* to **Read repository contents** (both workflows ask for what they need per job);
   * optionally, *Allow select actions*, limited to `actions/checkout`, `actions/setup-node`, `actions/upload-artifact`, `actions/download-artifact`, `dtolnay/rust-toolchain` and `Swatinem/rust-cache`.
3. Expect the first run to download the toolchains and dependencies. Nothing in it needs a secret.
   * The `audit` job scans the whole history with gitleaks; known false positives are listed in `.gitleaksignore`.
   * If a job fails only on GitHub, compare its tool versions with the pins above before changing code.
4. Leave `RELEASE_PUBLISHING` unset until the `release` environment, its reviewers and its secrets exist ([UPDATER.md](UPDATER.md#owner-setup)). Until then a version tag only runs the release checks.

### Reproducing the Linux GUI tests

The Linux checks above were run in Docker with:

* a Debian 12 (`rust:1-bookworm`) or Ubuntu 24.04 image plus `libwebkit2gtk-4.1-dev`, `xvfb`, `openbox`, `xdotool`, `x11-utils`, `imagemagick`, `dbus-x11`, `gnome-keyring`, `libsecret-tools`, `webkit2gtk-driver`, `nmap` and `cargo install tauri-driver`;
* an unprivileged user running `Xvfb :99`, `openbox`, `dbus-launch` and `gnome-keyring-daemon --unlock --components=secrets`;
* a debug build with the frontend embedded (`cargo build --features tauri/custom-protocol`), started through `tauri-driver` (WebDriver on port 4444) with `CYBERHUB_MOCK_API_BASE` pointing at a local mock of the provider APIs.

WebKitWebDriver reports elements under the legacy key `element-6066-11e4-a52e-4f735466cecf`, and its element clear does not update React state (select the text and type instead).

## Build and test instructions

### Required environments

| Component | Version |
|---|---|
| Rust | **1.90.0 at least**: Cargo refuses 1.89 because of the locked Tauri 2 crates. CI and the Linux checks use 1.99.1; the Windows development machine uses 1.94.1. Clippy lints change between releases, so CI pins the version. Nightly Rust is needed only for the fuzz targets (`src-tauri/fuzz`). |
| Node.js | 22.12.0 in CI and on Linux; 24.19.0 on the Windows development machine. |
| Windows 10/11 x64 | Visual Studio Build Tools with the C++ workload (SQLite is compiled from source), and the WebView2 runtime. |
| Ubuntu 24.04 | `libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libdbus-1-dev pkg-config build-essential`. Tested with WebKitGTK 2.52.6 and GTK 3.24.41. |
| Debian 12 | The same, plus `libsoup-3.0-dev libjavascriptcoregtk-4.1-dev`. Tested with WebKitGTK 2.50.6 and GTK 3.24.38. |
| Linux GUI tests | `xvfb openbox xdotool x11-utils imagemagick dbus-x11 gnome-keyring libsecret-tools webkit2gtk-driver at-spi2-core`, and `cargo install tauri-driver` (see above). |

### Common

```bash
npm ci                 # installs deps and runs scripts/patch-deps.mjs (+ self-test)
npx tsc --noEmit -p tsconfig.json
npx vitest run
cd src-tauri && cargo test
npm run tauri dev      # run the app
```

Installers and packages (`npm run tauri build`) are deferred: Cyber Hub is still in development and nothing is packaged or distributed.

### The release build's Linux environment (Mission 8)

The release workflow builds the Linux packages on Ubuntu 22.04, which no CI job tests: its older system libraries give the packages wider compatibility. Mission 8 checked that the code compiles there, without building anything:

* `cargo check --locked --release --bins` passed in an `ubuntu:22.04` container (22.04.5);
* the release job's packages were installed: WebKitGTK 2.50.4, GTK 3.24.33, libsoup 3.0.7, glibc 2.35;
* Rust 1.99.1 and Node 22.12.0 were used, and the frontend was built first.

The packages themselves are first built by the release workflow (RELEASE_CANDIDATE_PROCEDURE.md).

### Packaging and the MCP server

`tauri build` runs `npm run build && node scripts/build-sidecar.mjs` before compiling the app. The script builds `cyberhub-mcp` for the target triple (`TAURI_ENV_TARGET_TRIPLE`; macOS targets are refused), without the `provisioning` feature, checks it (`--version` when it can run on the build machine) and stages a copy as `src-tauri/binaries/cyberhub-mcp-<triple>[.exe]` (git-ignored) for manual use. The installers ship the crate's own `cyberhub-mcp` binary: the bundler includes every `[[bin]]` of the app crate next to the app executable. It was previously also declared as `bundle.externalBin`; the first real MSI build (updater tests) failed because the MSI then contained the same file twice (WiX ICE30), so that entry was removed.

| Platform | Installed as |
|---|---|
| Windows (MSI / NSIS) | `<install folder>\cyberhub-mcp.exe` |
| Linux .deb / .rpm | `/usr/bin/cyberhub-mcp` |
| Linux AppImage | `usr/bin/cyberhub-mcp` inside the image; the mount path changes on every start, so MCP client configurations break after a restart (the MCP page warns) |

If the server cannot be built for the target, the script exits with an error, so `tauri build` stops at its beforeBuildCommand instead of producing an installer without it. Signed release installers are built only by the release workflow (see UPDATER.md); disposable test installers were built locally for the updater tests.

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
| Frameless window | verified (move, double-click maximize/restore, resize, minimize) | verified on a virtual display under Openbox (move, double-click maximize/restore, edge and corner resize, minimum size); maximize and restore also under Mutter and KWin (native Wayland, Mission 6) |
| Window controls (minimize, maximize/restore, close) | verified in the running app | verified (EWMH maximized/hidden states, close exits) |
| MCP (`cyberhub-mcp`, loopback bridge, approvals, MCP page) | verified end to end, including with Claude Code (Mission 6: Claude Code 2.1.319 for discovery, reads, errors, approvals, a cancelled call, a client killed while its request waited, and reconnection after MCP was turned off and on; Claude Desktop not installed, not tested); installed layout simulated with a release build in a folder with spaces | verified in the GUI tests with a scripted MCP client (Claude Code not tested on Linux) |
| Updates (Settings → Updates) | NSIS (per-user) and MSI packages update themselves. The NSIS path was tested end to end against a local staging feed; MSI updates were not (they need administrator approval). Unsigned builds were quarantined by Microsoft Defender after the update (ML false positive): Authenticode signing is required before distribution. See UPDATER.md | AppImage, deb and rpm are supported by the updater plugin (deb/rpm ask for an administrator password through `pkexec`, zenity/kdialog + sudo or terminal sudo; AppImage needs a writable folder). **No Linux format was tested** |
| Tool working directory | `%APPDATA%\dev.cyberhub.workstation\work` | `~/.local/share/dev.cyberhub.workstation/work` (mode 0700) |

### Display scaling and window size (Mission 7)

* The window is created hidden and sized for the work area of the monitor it opens on (`src-tauri/src/window_fit.rs`): the configured 1440 × 900 window when it fits, otherwise 94 % of the work area, maximized below 1024 × 640 logical pixels. The minimum is 800 × 480 logical pixels, which fits a 1920 × 1080 screen at 200 % under the Windows taskbar and the GNOME and KDE panels; a smaller screen lowers it to the screen.
* Below 1024 logical pixels the sidebar shows icons only, whatever the collapse preference (`src/lib/viewport.ts`).
* Checked with `scripts/qa/layout-probe.mjs` (DevTools device emulation in the Windows development build): every page, every project tab and the finding form at 1920 × 1040 (100 %), 1536 × 826 (125 %), 1280 × 688 (150 %), 960 × 516 and 960 × 496 (200 %) and 800 × 480, with no horizontal overflow and no unreachable content. This is emulated scaling; a physical HiDPI screen is on the release checklist (docs/release/).
* On Linux, in the real WebKitGTK app on Ubuntu 24.04 and Debian 12 (virtual X screens, not physical monitors):
  * with `GDK_SCALE=2` on a 1920 × 1080 screen, the page ran at device scale 2 (960 × 540 logical) and the window opened maximized. The minimum hint was 1600 × 960 device pixels, a dialog fitted, and text kept its 14 px;
  * at scale 1, the window manager (Openbox) refused sizes below 800 × 480. At 800 × 480, Dashboard, Projects, Threat Intel and Settings fitted, with the 60 px sidebar.
* Windows ignores the minimum when a program resizes the window itself (`MoveWindow`). Resizing with the mouse respects it; that was not exercised here.

### Linux desktops and compositors (Mission 7)

* **KWin with XWayland.** In the containers, KWin's virtual output has no GPU, and Xwayland's GPU path (glamor) crashed with a segmentation fault before any client connected, even a plain `xdpyinfo` (`kwin-xw-diag.sh`, Mission 7). This is the environment, not Cyber Hub. With `XWAYLAND_NO_GLAMOR=1` (software rendering), the X11 clients and Cyber Hub ran normally, and the desktop checks passed 7 of 7 through XWayland:
  * pages;
  * the command palette;
  * maximize and restore;
  * the GTK credential dialog storing into the Secret Service;
  * the GTK file chooser.

  Mutter and KWin as native Wayland compositors passed 5 of 5 each; native dialogs are not drivable there.
* **What was not tested:**
  * full GNOME Shell and Plasma sessions (panels, desktop portals, a keyring unlocked by the login);
  * a GPU;
  * a physical HiDPI screen.

  These are on the release checklist (`docs/release/RELEASE_READINESS.md`).

### Unsupported or limited functionality

* Tools that need elevated privileges or capture drivers (SYN/UDP/OS scans, packet capture, wireless) fail with the tool's own error; Cyber Hub never elevates.
* `go install` puts binaries in `$GOPATH/bin` — add it to PATH and rescan.
* Linux `apt` installs requiring `sudo` are shown as instructions, not executed.
* Interactive tools (shells, REPLs) receive no stdin and are better run in a terminal.
