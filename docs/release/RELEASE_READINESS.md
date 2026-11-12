# Release readiness: Cyber Hub 0.1.0 (after Mission 10)

This is the checklist for the first release. It separates what was verified from what still needs a person, hardware, a GitHub run or a signing key.

**Mission 10 (2026-11-11 and 12), what was done:**
* **M1 passes** in a disposable Windows 11 VM: all 17 steps, with every credential typed into Windows' own credential dialog.
* **M7 passes on Plasma**, both with KWallet as the Secret Service and with GNOME Keyring. Mission 9's Plasma failure was that VM session's state.
* **Virtual HiDPI** at 100, 125, 150 and 200 % passes on GNOME and on Windows, including the minimum window. No physical screen was used.
* **The update key is stored:** `TAURI_SIGNING_PRIVATE_KEY` is in the `release` environment.
* **The Authenticode choice** now covers SmartScreen, identity, renewal and cost (`SIGNING_SETUP.md`). Nothing was bought.

**What was not done:**
* **No release candidate.** Three things stop it, each the owner's:
  * the update key's password, `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`, is not stored: the session's permission classifier refused the command;
  * the release workflow builds only while `RELEASE_PUBLISHING` is `enabled`, and Mission 10 had no authorization to set it;
  * there is no Authenticode certificate.
* So there are no packages, no package tests, no tag and no draft release. Nothing was published.

**Cyber Hub is not release-ready.**
* The engineering checks pass, and CI is green on the final code.
* What remains needs the owner: the password secret, the decision to let the workflow build, the certificate, a physical HiDPI screen, and the candidate's packages (M4, M9, M10).

Status words:

* **PASS:** verified, with the evidence named.
* **PARTIAL:** verified only in part, or only in a substitute environment (emulated or virtual scaling, a container, a debug build, a stand-in for a person). What is missing is named.
* **NOT TESTED:** no evidence. Each one says why.
* **BLOCKED:** it needs something only the owner can provide: a signing key or certificate, an authorization, or an environment that was not available.

Evidence is a test name in the repository, a GitHub Actions run, a log or screenshot of the Mission 7–10 runs (MISSION_REPORT.md), or, for the manual items, the tester's own record below.

## Release requirements

| Requirement | Status | Evidence or reason |
|---|---|---|
| Rust and frontend tests, tsc, clippy on Windows, Ubuntu 24.04, Debian 12 | **PASS** | **On GitHub, green on `windows-2022`, `ubuntu-24.04` and Debian 12:** run 43105721393 (`d4372b5`, the final code): 641 passed, 28 ignored, on each, and 56 frontend test files; run 43107766877 (`c7052bd`) green as well. Earlier runs: 43084985623 (`a1edbaf`) and 43089305680 (`5ad2ad1`), 637 passed each.<br>**Locally (Mission 9):** Windows 641 passed; vitest 308 tests in 56 files. The code has not changed since (`63d2cd6`) |
| Minimum Rust version 1.90 | **PASS** | The `msrv` job of every green run, including the final code |
| Dependency audits | **PASS** for the app | cargo audit 0.22.2 on 2026-11-12, with that day's advisories: 0 vulnerabilities, 8 allowed warnings (unmaintained or unsound crates, among them the new RUSTSEC-2026-0372, `zvariant_derive` unmaintained). npm audit of the app: 0. Both also in every CI run.<br>**GitHub's Dependabot** has two medium alerts, open since 2026-11-11:<br>• `glib` below 0.20 (GHSA-wrw7-89jp-8q8g), the same unsound iterator as the allowed warning, pulled in by Tauri's GTK 3 stack;<br>• `minimatch` 10.2.6 (GHSA-g3hv-75wg-m249, a denial of service through glob patterns) in `website/`'s ESLint tools, development only and not in the app (FEATURE_BACKLOG.md, item 94) |
| Secret scan of the whole history (gitleaks 8.30.1) | **PASS** | The `audit` job of every green CI run, with a checked download. Mission 10's documents are scanned by the CI run of their commit |
| Workflow linting (actionlint 1.7.7 with shellcheck) | **PASS** | The `audit` job of every green CI run |
| GitHub Actions settings | **PASS** | Read back on 2026-11-12: selected actions only (six patterns), SHA pinning required, read-only `GITHUB_TOKEN`, no approving pull requests, fork pull requests get neither runs, write tokens nor secrets. The `release` environment: branches `main` and `release/*`, no administrator bypass. No repository secrets; no variables, so `RELEASE_PUBLISHING` is not set |
| Database upgrades from every schema, backup before migrating, interrupted and failed upgrades | **PASS** | The upgrade tests (MISSION_REPORT.md, "Mission 8"). `write_upgrade_fixtures` writes data folders at schemas 1, 8, 19, 26 and 31 for the installer upgrade test |
| An older version refuses a newer database and says how to recover | **PASS** | `startup_error.rs`; Mission 8 checks |
| Backup and restore keep IDs, relationships and evidence | **PASS** | `restore_tests.rs`. In a real GNOME session (Mission 9): the backup and the restore went through the native dialogs, and Cyber Hub restarted into the restored database. On Windows (Mission 10, M1 step 10): a backup through the native Save dialog |
| End-to-end flows in the real app | **PASS** on development builds | Windows (Missions 8 and 10), the Linux GUI phases (Mission 8), real GNOME and Plasma sessions (Missions 9 and 10). A release build is exercised only with the installers (M10) |
| MCP | **PASS** | The MCP tests in the suites; Missions 6–8 live checks; Mission 10 on Windows: three MCP calls without a credential value in their results (M1 step 10) |
| TAXII credential lifecycle | **PASS** on Windows, GNOME and Plasma | **Windows (Mission 10):** M1, 17/17, typed into Windows' credential dialog. **GNOME (Mission 9)** and **Plasma with KWallet or GNOME Keyring (Mission 10):** M7 steps 1–7 |
| Parser malformed input | **PASS** | `hostile_tests.rs` and the parser regressions, on GitHub |
| Security review | **PASS** for the code | Missions 7 and 8; Mission 9 fixed three defects found in real sessions. Mission 10 found no defect in Cyber Hub: its two step failures were harness errors (MISSION_REPORT.md, "Mission 10") |
| Native confirmations | **PASS** on Windows and on Linux | Mission 9 in real sessions. Mission 10 on Windows: an early click on Delete at 59 ms leaves the dialog open, Delete is enabled at 993 ms, and Cancel is the default at four scales |
| Release workflow | **PARTIAL** | Static review, guard tests and actionlint pass. `release.yml` has never built: it needs the password secret and `RELEASE_PUBLISHING` (M9, M10) |
| The release build's Linux environment (Ubuntu 22.04) | **PARTIAL** | Type-checked (Mission 8); nothing built |
| High-DPI and minimum window | **PARTIAL** | Virtual scaling at 100, 125, 150 and 200 % on GNOME Wayland and Windows 11 (Mission 10, 5/5 at each), the minimum included. No physical HiDPI screen (M4) |
| Linux desktops | **PARTIAL** | Real GNOME 46 and Plasma 5.27 sessions, development build (M2, M3, M6, M7). Packaging is open |
| Code signing | **BLOCKED** | No Authenticode certificate (M9). The update key is in the `release` environment; its password is not |
| Installers: install, upgrade, uninstall | **BLOCKED** | Not built (M10) |

## Manual release-candidate checklist

*Status* is what is known today. Fill in *Result* (pass or fail), *Evidence*, the tester and the date when you run an item. The procedures are in:
* `MANUAL_VALIDATION.md` (M1–M7);
* `GITHUB_FIRST_RUN.md` (M8);
* `SIGNING_SETUP.md` (M9);
* `RELEASE_CANDIDATE_PROCEDURE.md` (M10).

| # | Item | Status today | Environment | Procedure | Expected | Blocks |
|---|---|---|---|---|---|---|
| M1 | TAXII credentials in Windows' credential dialog | **PASS (VM).** Mission 10, run 3: all 17 steps in a disposable Windows 11 26H2 VM (build 26300.9457), development build, isolated data folder, the local test servers. Every credential was typed into Windows' credential dialog through the VM's keyboard; no `taxii_` entry was left. Runs 1 and 2 failed step 16 through harness errors, explained in MANUAL_VALIDATION.md, "Mission 10". A run on the installed candidate is still worth doing (M10) | Windows 11, development build | `TAXII_CREDENTIAL_TEST.md` | As listed there | No |
| M2 | Full GNOME Shell session (Wayland, Xorg, XWayland) | **PARTIAL.** Real GNOME 46 sessions on Ubuntu 24.04.5, development build (Mission 9). Wayland: all 12 steps pass. Xorg: steps 1–8, the backup of 9, 10 and 12. XWayland: steps 1–6, 10 and 12. Not yet: the rest of Xorg and XWayland, the installed deb and AppImage, the app-grid launcher | Ubuntu 24.04 desktop | `MANUAL_VALIDATION.md`, M2 | Every step in both sessions and under XWayland | **Yes**, for Linux, until the packages are checked |
| M3 | Full KDE Plasma session (Wayland, X11, XWayland) | **PARTIAL.** Real Plasma 5.27 sessions on Debian 12 (Mission 9): M2's steps 1–6, 10 and 12 pass in all three sessions, and in Wayland also 7, 8, the backup of 9, and 11. Credentials pass on Plasma X11 with KWallet and with GNOME Keyring (Mission 10, M7) | Debian 12 KDE or Kubuntu 24.04 | `MANUAL_VALIDATION.md`, M3 | As M2, plus a clear error without a usable Secret Service | **Yes**, for Linux, until the packages are checked |
| M4 | Physical HiDPI: 100, 125, 150, 200 % | **BLOCKED** on hardware. Virtual substitute passes (Mission 10): GNOME Wayland and Windows 11 at 2560 × 1600, 5/5 checks at each scale. On GNOME the page renders at scale 2 for 125 and 150 % (GTK 3) and is scaled down: sharpness needs a real screen | Windows 11, GNOME (also fractional), Plasma | `MANUAL_VALIDATION.md`, M4 | Sharp, nothing cut off, the minimum held, dialogs fit | **Yes** |
| M5 | The minimum window on a real screen | **PASS (virtual).** Windows: a mouse drag of the corner stops at 800 × 480 logical pixels at 100, 125, 150 and 200 % (Mission 10). GNOME: the same minimum at the four scales; every Mission 9 Linux session at 100 %. A resize sent by another program is not limited on Windows (FEATURE_BACKLOG.md, item 92) | Any M4 screen | `MANUAL_VALIDATION.md`, M5 | Everything reachable, no sideways scrolling | No |
| M6 | Desktop portals and the native file chooser | **PARTIAL** (development build). With `GTK_USE_PORTAL=1`, Open and Save reach the portal and show the desktop's own chooser: GNOME's in Wayland and Xorg, KDE's in Plasma Wayland. Without the variable, GTK's chooser and no portal call. The package format should not change this, since none is sandboxed | GNOME and Plasma sessions | `MANUAL_VALIDATION.md`, M6 | Portal calls with the variable, GTK's chooser without it | No, unless shipped sandboxed |
| M7 | A real login keyring (GNOME Keyring, KWallet) | **PASS.** GNOME (Mission 9): steps 1–7 with the login keyring unlocked by PAM, across restarts, a log-out and log-in, lock, unlock and a cancelled unlock. Plasma X11 (Mission 10): steps 1–7 with KWallet serving the Secret Service, including KWallet's own unlock prompt and a cancelled one, and again with GNOME Keyring | GNOME and Plasma sessions | `MANUAL_VALIDATION.md`, M7 | Kept across restarts and log-ins; no prompt loop; removed when forgotten | No |
| M8 | First GitHub Actions run | **PARTIAL.** CI is green on all five jobs, actionlint included, at `a1edbaf`, `5ad2ad1`, `d4372b5` (the final code) and `c7052bd`. Two runs of 2026-11-11 (20:22Z and 20:41Z) were queued by GitHub and never started; the later runs supersede them. The release workflow has not run | GitHub | `GITHUB_FIRST_RUN.md` | `ci.yml` green, actionlint included; the release runs only validate | **Yes** |
| M9 | Code signing (Authenticode; update signatures in CI) | **BLOCKED.** No code-signing certificate: `SIGNING_SETUP.md` recommends SSL.com IV with eSigner (about $309 a year) and explains SmartScreen, identity, renewal and cost. The update key is stored in the `release` environment (2026-11-11 22:13Z). **Its password is not:** the session's permission classifier refused the command, so it is the owner's step | The `release` environment; a certificate | `SIGNING_SETUP.md` | Valid, timestamped Authenticode on four Windows files; update signatures verify | **Yes** |
| M10 | Installers: build once, install, upgrade a copy, back up and restore, uninstall | **BLOCKED** on the password secret, on `RELEASE_PUBLISHING` (an owner's decision: the build job runs only while it is `enabled`, and a run still stops at a draft) and, for Windows, on Authenticode. Ready: the `release` environment, the upgrade fixtures, and the VMs: Ubuntu 24.04 GNOME, Debian 12 Plasma and **a clean Windows 11 VM** (`chqa-win11b`) | The release workflow; Windows 11, Ubuntu 24.04, Debian 12 | `RELEASE_CANDIDATE_PROCEDURE.md` | As listed there for every package | **Yes** |

## Accepted risks after Mission 10

* **Unchanged from Mission 8:**
  * the version probes of tool detection start without a dialog;
  * a page can move a project between planning, active and paused;
  * the PowerShell quoting case that remains;
  * the other rows of SECURITY.md, "Accepted risks and limitations".
* **Fixed in Mission 9, with tests:**
  * a locked keyring asked to be unlocked, and held the database, when a page only showed whether a credential was stored (`63d2cd6`);
  * an interrupted restore left a copy of the backup in the data folder (`ed99331`);
  * the command palette ranked pages above a project whose name starts with the query (`810e024`).
* **New in Mission 10, accepted as low:**
  * on Windows, another program can size the window below its minimum with `SetWindowPos`; users cannot (item 92);
  * on GNOME at 125 and 150 %, WebKitGTK renders at scale 2 and the compositor scales it down, which may soften text (item 91).
* **Release builds share the data folder of development builds**, because the identifier is `dev.cyberhub.workstation`. Install candidates only where no real data is: a VM, Windows Sandbox or another account.
* **Third-party GitHub Apps.** Eight apps installed on the owner's account with access to all repositories receive this repository's commits: Vercel, Render, Cursor, Netlify, Wasmer, Mintlify, Claude and Cloudflare.
  * Some hold permissions that reach the release path: administration (Vercel, Wasmer, Cloudflare), environments (Render), actions or workflows (Vercel, Render, Cursor, Wasmer, Claude).
  * None is needed by this repository. Limit them to the repositories that need them (`GITHUB_FIRST_RUN.md`, "Mission 10").
* **The release workflow, signing and the installers have never run.**
