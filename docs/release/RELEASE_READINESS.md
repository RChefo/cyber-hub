# Release readiness: Cyber Hub 0.1.0 (after Mission 9)

This is the checklist for the first release. It separates what was verified from what still needs a person, hardware, a GitHub run or a signing key.

**Mission 9 (2026-11-11), what was done:**
* The repository went to GitHub as a private repository, `RChefo/cyber-hub`, and CI ran there for the first time.
* Real GNOME and Plasma sessions were tested in disposable VMs.
* Three defects found in them were fixed.

**What was not done:**
* **No installer, package or release binary has been built.** The release workflow needs the update key in the `release` environment, and storing it there is the owner's step. Mission 9 was not permitted to write signing secrets.
* Nothing has been signed, tagged or published.

**Cyber Hub is not release-ready.**
* The engineering checks pass.
* Every M item except M8 is still open on something only the owner can provide: the update-signing secrets, an Authenticode certificate, a Windows machine for M1, a physical HiDPI screen, and the release-candidate build.
* M8 is open only because the release workflow has not run. CI is green on the final code (run 43105721393).

Status words:

* **PASS:** verified, with the evidence named.
* **PARTIAL:** verified only in part, or only in a substitute environment (emulated scaling, a container, a debug build, a stand-in for a person). What is missing is named.
* **NOT TESTED:** no evidence. Each one says why.
* **BLOCKED:** it needs something only the owner can provide: a signing key or certificate, an authorization, or an environment that was not available.

Evidence is a test name in the repository, a GitHub Actions run, a log or screenshot of the Mission 7–9 runs (MISSION_REPORT.md), or, for the manual items, the tester's own record below.

## Release requirements

| Requirement | Status | Evidence or reason |
|---|---|---|
| Rust and frontend tests, tsc, clippy on Windows, Ubuntu 24.04, Debian 12 | **PASS** | **On GitHub, green on `windows-2022`, `ubuntu-24.04` and Debian 12:**<br>• runs 43084985623 (`a1edbaf`) and 43089305680 (`5ad2ad1`): 637 passed, 28 ignored, on each;<br>• run 43105721393 (`d4372b5`, the final code): 641 passed, 28 ignored, on each, and 56 frontend test files.<br>**Locally:** Windows 641 passed; vitest 308 tests in 56 files.<br>Two runs queued at 20:22Z and 20:41Z were never started by GitHub; the final run supersedes them |
| Minimum Rust version 1.90 | **PASS** | The `msrv` job of every green run, including the final code (43105721393), where `dbus-secret-service` 4.1.0 is a direct dependency |
| Dependency audits | **PASS** | cargo audit 0.22.2: 0 vulnerabilities, 8 allowed warnings (on GitHub at `5ad2ad1`, locally at the final lock file, 652 crates). npm audit: 0 |
| Secret scan of the whole history (gitleaks 8.30.1) | **PASS** | Before the push and on GitHub (`audit` job): 191 commits without leaks. The final history is scanned again in MISSION_REPORT.md, "Mission 9" |
| Workflow linting (actionlint 1.7.7 with shellcheck) | **PASS** | First run on GitHub, `audit` job of both green CI runs, with checked downloads |
| Database upgrades from every schema, backup before migrating, interrupted and failed upgrades | **PASS** | The upgrade tests (MISSION_REPORT.md, "Mission 8"). Mission 9 added `write_upgrade_fixtures`, which writes data folders at schemas 1, 8, 19, 26 and 31 for the installer upgrade test |
| An older version refuses a newer database and says how to recover | **PASS** | `startup_error.rs`; Mission 8 checks |
| Backup and restore keep IDs, relationships and evidence | **PASS** | `restore_tests.rs`. In a real GNOME session (Mission 9): the backup and the restore went through the native dialogs, Cyber Hub restarted into the restored database and kept the previous one. Fixed in Mission 9: a restore interrupted while its copy was made left that copy in the data folder (`a_stage_ended_during_its_copy_leaves_no_copy_behind`) |
| End-to-end flows in the real app | **PASS** on development builds | Windows (Mission 8), the Linux GUI phases (Mission 8), and in Mission 9 the real GNOME and Plasma sessions (MANUAL_VALIDATION.md, "Mission 9"). A release build is exercised only with the installers (M10) |
| MCP | **PASS** | The MCP tests in the suites; Missions 6–8 live checks |
| TAXII credential lifecycle | **PASS** on GNOME with a real login keyring. **PARTIAL** on Windows and Plasma | **GNOME (Mission 9):** steps 1–7 of M7, including lock, unlock and a cancelled unlock. **Plasma:** the Secret Service of the test VM was not usable (M3, M7). **Windows:** all but typing into the dialog (M1) |
| Parser malformed input | **PASS** | `hostile_tests.rs` and the parser regressions, on GitHub |
| Security review | **PASS** for the code | Missions 7 and 8; Mission 9 found and fixed three defects in real desktop sessions (MISSION_REPORT.md, "Mission 9") |
| Native confirmations | **PASS** on Windows and on Linux | Mission 9 in real sessions (GNOME Wayland, Xorg and XWayland; Plasma Wayland, X11 and XWayland): a real Return at once cancels, an early click does nothing, approving after the delay works, and the terminal asks |
| Release workflow | **PARTIAL** | Static review, guard tests and actionlint pass. `release.yml` has not run: no tag was pushed, because the candidate cannot be built without the update secrets (M9, M10) |
| The release build's Linux environment (Ubuntu 22.04) | **PARTIAL** | Type-checked (Mission 8); nothing built |
| High-DPI and minimum window | **PARTIAL** | Emulated and virtual scaling only; no physical HiDPI screen (M4). The minimum window in a real window on Windows (M5) and in every Mission 9 Linux session (800 × 480) |
| Linux desktops | **PARTIAL** | Real GNOME 46 and Plasma 5.27 sessions, development build (M2, M3, M6, M7). Packaging is open |
| Code signing | **BLOCKED** | No Authenticode certificate exists (M9). The update key exists on the owner's machine; storing it in the `release` environment is the owner's step |
| Installers: install, upgrade, uninstall | **BLOCKED** | Not built (M10): the release workflow needs the update secrets |

## Manual release-candidate checklist

*Status* is what is known today. Fill in *Result* (pass or fail), *Evidence*, the tester and the date when you run an item. The procedures are in:
* `MANUAL_VALIDATION.md` (M1–M7);
* `GITHUB_FIRST_RUN.md` (M8);
* `SIGNING_SETUP.md` (M9);
* `RELEASE_CANDIDATE_PROCEDURE.md` (M10).

| # | Item | Status today | Environment | Procedure | Expected | Blocks |
|---|---|---|---|---|---|---|
| M1 | TAXII credentials in Windows' credential dialog | **PARTIAL.** Everything except typing into the dialog was automated (Mission 8, 16/16, real Credential Manager). Mission 9's Windows 11 VM hung during Windows Setup under VirtualBox with Hyper-V active, so the dialog was not reached. Steps 2, 3 and 9 need a person, or a Windows VM or Windows Sandbox where the dialog can be typed into | Windows 11, development build, isolated data folder, the local test servers | `TAXII_CREDENTIAL_TEST.md` | As listed there | **Yes** |
| M2 | Full GNOME Shell session (Wayland, Xorg, XWayland) | **PARTIAL.** Real GNOME 46 sessions on Ubuntu 24.04.5 (VM, password login through GDM), development build (Mission 9). Wayland: all 12 steps pass. Xorg: steps 1–8, the backup of 9, 10 and 12. XWayland: steps 1–6, 10 and 12. Not yet: the rest of Xorg and XWayland, the installed deb and AppImage, the app-grid launcher | Ubuntu 24.04 desktop | `MANUAL_VALIDATION.md`, M2 | Every step in both sessions and under XWayland | **Yes**, for Linux, until the packages are checked |
| M3 | Full KDE Plasma session (Wayland, X11, XWayland) | **PARTIAL.** Real Plasma 5.27 sessions on Debian 12: M2's steps 1–6, 10 and 12 pass in all three sessions, and in Wayland also 7, 8, the backup of 9, and 11. Under real KWin, XWayland did not crash. Storing a credential failed with a clear error, because the VM's GNOME Keyring did not serve its login collection (step 13's behaviour). KWallet as the Secret Service was not tried | Debian 12 KDE or Kubuntu 24.04 | `MANUAL_VALIDATION.md`, M3 | As M2, plus a clear error without a usable Secret Service | **Yes**, for Linux, until the packages and a working Plasma keyring are checked |
| M4 | Physical HiDPI: 100, 125, 150, 200 % | **BLOCKED.** No physical HiDPI screen. Substitute: emulated and virtual scaling | Windows 11, GNOME (also fractional), Plasma | `MANUAL_VALIDATION.md`, M4 | Sharp, nothing cut off, the minimum held, dialogs fit | **Yes** |
| M5 | The minimum window on a real screen | **PARTIAL.** Windows at 100 % (Mission 8, 37/37). In every Mission 9 Linux session the window stops at 800 × 480 and the page fits. Not tested: a HiDPI screen, resizing with the mouse | Any M4 screen | `MANUAL_VALIDATION.md`, M5 | Everything reachable, no sideways scrolling | No |
| M6 | Desktop portals and the native file chooser | **PARTIAL** (development build). With `GTK_USE_PORTAL=1`, Open and Save reach the portal and show the desktop's own chooser: GNOME's in Wayland and Xorg, KDE's in Plasma Wayland. Without the variable, GTK's chooser and no portal call. The package format should not change this, since none is sandboxed | GNOME and Plasma sessions | `MANUAL_VALIDATION.md`, M6 | Portal calls with the variable, GTK's chooser without it | No, unless shipped sandboxed |
| M7 | A real login keyring (GNOME Keyring, KWallet) | **PARTIAL.** GNOME: steps 1–7 pass with the login keyring unlocked by PAM at a GDM password login, across restarts, a log-out and log-in, lock, unlock and a cancelled unlock. Plasma: not usable in this VM's configuration (M3). Fixed in Mission 9: a locked keyring raised an unlock prompt and held the database while the TAXII list was shown | GNOME and Plasma sessions | `MANUAL_VALIDATION.md`, M7 | Kept across restarts and log-ins; no prompt loop; removed when forgotten | **Yes**, for Plasma |
| M8 | First GitHub Actions run | **PARTIAL.** The private repository is configured (`GITHUB_FIRST_RUN.md`, "Mission 9"). CI is green on all five jobs, actionlint included, at `a1edbaf`, `5ad2ad1` and `d4372b5` (the final code). Two runs, pushed at 20:22Z and 20:41Z, were queued by GitHub and never started: no job was created. The next push ran at once, so those two are superseded. The release workflow has not run | GitHub | `GITHUB_FIRST_RUN.md` | `ci.yml` green, actionlint included; the release runs only validate | **Yes** |
| M9 | Code signing (Authenticode; update signatures in CI) | **BLOCKED.** No code-signing certificate on this machine. A route is recommended in `SIGNING_SETUP.md`. The update key exists and matches the app's public key (ID `957F3F7D955C72FA`), but storing it as a GitHub secret was the owner's step: Mission 9's attempt was refused by the session's permission rules | The `release` environment; a certificate | `SIGNING_SETUP.md` | Valid, timestamped Authenticode on four Windows files; update signatures verify | **Yes** |
| M10 | Installers: build once, install, upgrade a copy, back up and restore, uninstall | **BLOCKED** on M9's update secrets. Ready: the private repository, the `release` environment, the upgrade fixtures, and the VMs: Ubuntu 24.04 GNOME and Debian 12 Plasma. A clean Windows machine is not | The release workflow; Windows 11, Ubuntu 24.04, Debian 12 | `RELEASE_CANDIDATE_PROCEDURE.md` | As listed there for every package | **Yes** |

## Accepted risks after Mission 9

* **Unchanged from Mission 8:**
  * the version probes of tool detection start without a dialog;
  * a page can move a project between planning, active and paused;
  * the PowerShell quoting case that remains;
  * the other rows of SECURITY.md, "Accepted risks and limitations".
* **Fixed in Mission 9, with tests:**
  * a locked keyring asked to be unlocked, and held the database, when a page only showed whether a credential was stored (`63d2cd6`);
  * an interrupted restore left a copy of the backup in the data folder (`ed99331`);
  * the command palette ranked pages above a project whose name starts with the query (`810e024`).
* **Release builds share the data folder of development builds**, because the identifier is `dev.cyberhub.workstation`. Install candidates only where no real data is: a VM, Windows Sandbox or another account.
* **Third-party GitHub Apps.** The private repository's commits receive check suites from eight third-party apps installed on the owner's account with access to all repositories: Vercel, Render, Cursor, Netlify, Wasmer, Mintlify, Claude and Cloudflare. Limit them to the repositories that need them (`GITHUB_FIRST_RUN.md`, "Mission 9").
* **The release workflow, signing and the installers have never run.**
