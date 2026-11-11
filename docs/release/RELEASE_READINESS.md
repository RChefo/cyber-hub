# Release readiness: Cyber Hub 0.1.0 (after Mission 8)

This is the checklist for the first release. It separates what was verified automatically from what still needs a person, hardware, a GitHub run or a signing key. **No installer, package or release binary has been built, nothing has been signed, and nothing has been pushed.** That happens once, at the final stage, with the owner's explicit authorization, so nothing here describes a built package.

**Cyber Hub is not release-ready.** The engineering checks pass; the release decision rests on M1–M10 below, and eight of them block it.

Status words:

* **PASS:** verified, with the evidence named.
* **PARTIAL:** verified only in part, or only in a substitute environment (emulated scaling, a container, a debug build, a stand-in for a person). What is missing is named.
* **NOT TESTED:** no evidence. Each one says why.
* **BLOCKED:** it needs something only the owner can provide: a push, a signing key, an authorization, or an environment that was not available (a real desktop session, a physical HiDPI screen).

Evidence is a test name in the repository, a log or screenshot from the Mission 7 or 8 runs (MISSION_REPORT.md), or, for the manual items, the tester's own record below.

## Release requirements

| Requirement | Status | Evidence or reason |
|---|---|---|
| Rust and frontend tests, tsc, clippy on Windows 11, Ubuntu 24.04, Debian 12 | PASS | Final regression of Mission 8, MISSION_REPORT.md "Mission 8" (counts, commands, environments) |
| Minimum Rust version 1.90 | PASS | `cargo +1.90.0 check --locked --all-targets` on Ubuntu and Debian |
| Dependency audits (cargo audit, npm audit) | PASS | 0 vulnerabilities; the allowed warnings are listed in the report |
| Secret scan of the whole history (gitleaks 8.30.1) | PASS | Every commit up to the last one of Mission 8, and the documentation, without leaks |
| Database upgrades from every schema, backup before migrating, interrupted and failed upgrades | PASS | `every_schema_version_upgrades_to_the_latest_with_all_its_rows_and_a_usable_backup`, `a_failed_upgrade_leaves_the_previous_database_untouched_and_can_be_retried`, `an_interrupted_rebuild_is_rolled_back_at_the_next_open`, `upgrade_child_process` |
| An older version refuses a newer database and says how to recover | PASS | `startup_error.rs`; the message box on Windows, the GTK dialog on Ubuntu and Debian; exit code 1, the file unchanged |
| Backup and restore keep IDs, relationships and evidence | PASS | `restore_tests.rs`; the Linux GUI restore cycle (segment 3) on both distributions; a backup made by the Mission 8 Windows TAXII run |
| End-to-end flows in the real app | PASS on debug builds | The Windows end-to-end script; the Linux GUI phases and segment 3 on both distributions. A release build is exercised only with the installers (M10) |
| MCP | PASS | The MCP tests in the suites; segment 3's MCP checks on Linux; three read tools through the real sidecar on Windows (Mission 8) |
| TAXII credential lifecycle | PASS on Linux (GTK dialog), PARTIAL on Windows | Linux: 16/16 on both distributions, and the removal race 0/17. Windows: everything except typing into the credential dialog, 16/16 with the real Credential Manager (M1) |
| Parser malformed input | PASS | `hostile_tests.rs` and the parser regressions in the suites; the amplification tests in the optimized build (Mission 7) |
| Security review (Mission 7: 25 distinct findings and 2 found live; Mission 8: the accepted risks) | PASS for the code | Every finding fixed with a regression test or recorded as an accepted risk. Mission 8 fixed two accepted risks and narrowed one (below) |
| Native confirmations: Cancel default, approval delayed, one at a time; also for the terminal, GUI tools and reopening an ended project | PASS on Windows and Linux | Windows: Win32 reads and presses. Linux: the GTK dialogs through xdotool, including the Mission 8 phase |
| Release workflow | PARTIAL | A static review, the guard tests and a local test of the tag check pass. It has never run on GitHub (M8) |
| The release build's Linux environment (Ubuntu 22.04) | PARTIAL | `cargo check --locked --release --bins` passed there with the release job's packages; nothing was built |
| High-DPI and minimum window | PARTIAL | HiDPI emulated (Windows) and virtual (Linux) only (M4). The minimum window was checked in a real window on a physical screen at 100 % (M5, partial) |
| Linux desktops | PARTIAL | Compositors in containers only (M2, M3, M6, M7) |
| Code signing | BLOCKED | The owner's certificate and keys (M9) |
| Installers: install, upgrade a copy of a real database, uninstall | BLOCKED | Built only at the final stage with authorization (M10) |

## Manual release-candidate checklist

*Status* is what is known today. Fill in *Result* (pass or fail), *Evidence*, the tester and the date when you run an item. The procedures are in `MANUAL_VALIDATION.md` (M1–M7), `GITHUB_FIRST_RUN.md` (M8), `SIGNING_SETUP.md` (M9) and `RELEASE_CANDIDATE_PROCEDURE.md` (M10).

| # | Item | Status today | Environment | Procedure | Expected | Blocks | Result | Evidence |
|---|---|---|---|---|---|---|---|---|
| M1 | TAXII credentials in Windows' credential dialog | **PARTIAL.** Everything but the dialog was automated: 16/16 on Windows 11 with the real Credential Manager. Steps 2, 3 and 9 need a person | Windows 11, development build, isolated data folder, the local test servers | `TAXII_CREDENTIAL_TEST.md` | As listed there; no test value outside Credential Manager | **Yes** | | |
| M2 | Full GNOME Shell session (Wayland, Xorg, XWayland) | **BLOCKED:** no GNOME session available. Substitute: Mutter in a container 5/5 | Ubuntu 24.04 desktop, hardware or VM | `MANUAL_VALIDATION.md`, M2 | Every step in both sessions and under XWayland | **Yes**, for Linux | | |
| M3 | Full KDE Plasma session (Wayland, X11, XWayland) | **BLOCKED:** no Plasma session available. Substitute: KWin 5/5, KWin with XWayland 7/7 in containers | Kubuntu 24.04 or Debian 12 KDE | `MANUAL_VALIDATION.md`, M3 | As M2, plus a clear error without a Secret Service | **Yes**, for Linux | | |
| M4 | Physical HiDPI: 100, 125, 150, 200 % | **BLOCKED:** this machine's screens are at 100 %, and changing your display scale is your decision. Substitute: emulated and virtual scaling | Windows 11, GNOME (also fractional), Plasma | `MANUAL_VALIDATION.md`, M4 | Sharp, nothing cut off, the minimum held, dialogs fit | **Yes** | | |
| M5 | The minimum window on a real screen | **PARTIAL.** Windows only: a real window resized to 800 × 480 on a physical 1920 × 1080 screen at 100 %, every page, project tab and the finding form, 37/37 (Mission 8). Not tested: a HiDPI screen, a Linux session, resizing with the mouse | Any M4 screen | `MANUAL_VALIDATION.md`, M5 | Everything reachable, no sideways scrolling | No | | |
| M6 | Desktop portals and the native file chooser | **BLOCKED:** needs the M2 and M3 sessions. Cyber Hub uses the portal only with `GTK_USE_PORTAL=1` or in a sandbox | GNOME and Plasma sessions | `MANUAL_VALIDATION.md`, M6 | Portal calls with the variable, GTK's chooser without it | No, unless shipped sandboxed | | |
| M7 | A real login keyring (GNOME Keyring, KWallet) | **BLOCKED:** needs a login session. Substitute: GNOME Keyring unlocked by a script in containers, 16/16 | GNOME and Plasma sessions | `MANUAL_VALIDATION.md`, M7 | Kept across restarts and log-ins; no prompt loop; removed when forgotten | **Yes**, for Linux | | |
| M8 | First GitHub Actions run | **BLOCKED:** needs your push. The static review and guards pass (`GITHUB_FIRST_RUN.md`, section 2) | GitHub | `GITHUB_FIRST_RUN.md` | `ci.yml` green, actionlint included; the release runs only validate | **Yes** | | |
| M9 | Code signing (Authenticode; update signatures in CI) | **BLOCKED:** your certificate and keys. The setup and verification are written; nothing was signed | GitHub `release` environment; a code-signing certificate | `SIGNING_SETUP.md` | Valid, timestamped Authenticode on four Windows files; update signatures verify | **Yes** | | |
| M10 | Installers: build once, install, upgrade a copy, back up and restore, uninstall | **BLOCKED:** your authorization. The procedure is written; nothing was built | The release workflow; Windows 11, Ubuntu 24.04, Debian 12 (Fedora optional) | `RELEASE_CANDIDATE_PROCEDURE.md` | As listed there for every package | **Yes** | | |

## Accepted risks after Mission 8

* **Fixed in Mission 8, with tests and live checks on Windows and Linux:**
  * a GUI tool or a terminal starting without a native dialog;
  * a compromised page reopening a completed or archived project.
* **Narrowed in Mission 8.** Copied command lines are exact in PowerShell too, except for a word that has a quote together with `$`, a backtick, `"`, `\` or `!`. Such a word still arrives split, and pasting never runs another command.
* **Still accepted** (SECURITY.md, "Accepted risks and limitations"):
  * tool detection's version probes start without a dialog (fixed flags, offline);
  * a page can still move a project between planning, active and paused;
  * the other rows of that table.
* **TAXII credentials stored by earlier development builds** (entry `taxii_<number>`) are no longer read; they have to be stored again.
* **Release builds share the data folder of development builds**, because the identifier is `dev.cyberhub.workstation`. Install candidates only where no real data is, or set it aside first (`RELEASE_CANDIDATE_PROCEDURE.md`, section 4).
* **The release workflow, signing and the installers have never run.** The first run will be the first test of the hosted runners.
