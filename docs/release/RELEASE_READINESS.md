# Release readiness: Cyber Hub 0.1.0 (after Mission 7)

This is the checklist for the first release. It separates what was verified automatically from what still needs a person, hardware, a GitHub run or a signing key. **No installer or release binary has been built** (that happens once, at the final stage, with the owner's authorization), so nothing here describes a built package.

Status words:

* **PASS:** verified, with the evidence named.
* **PARTIAL:** verified in a substitute environment (emulated scaling, containers, a debug build), or only part of it.
* **NOT TESTED:** not run in this mission. Each one says why.
* **BLOCKED:** it needs something only the owner can provide: a push, a signing key, an authorization.

Evidence means one of:

* a test name in the repository;
* a log or screenshot from the Mission 7 runs (MISSION_REPORT.md, "Mission 7");
* for the manual items, the tester's own record in the table below.

## Release requirements

| Requirement | Status | Evidence or reason |
|---|---|---|
| Rust and frontend tests, tsc, clippy on Windows 11, Ubuntu 24.04, Debian 12 | PASS | Final regression, MISSION_REPORT.md "Mission 7" (exact counts and commands) |
| Minimum Rust version 1.90 | PASS | `cargo +1.90.0 check --locked --all-targets` in the Linux container |
| Dependency audits (cargo audit, npm audit) | PASS | 0 vulnerabilities; see the report for advisory warnings |
| Secret scan of the whole history (gitleaks 8.30.1) | PASS | 183 commits at `d21c76e` and the documentation, no leaks after the two test fixtures were marked (`.gitleaksignore`) |
| Database upgrades from every schema, backup before migrating, interrupted and failed upgrades | PASS | `every_schema_version_upgrades_to_the_latest_with_all_its_rows_and_a_usable_backup`, `a_failed_upgrade_leaves_the_previous_database_untouched_and_can_be_retried`, `an_interrupted_rebuild_is_rolled_back_at_the_next_open`, `upgrade_child_process` |
| An older version refuses a newer database and says how to recover | PASS on Windows (live), PASS on Linux (live, container) | `startup_error.rs`; the message box was read through Win32 and the GTK dialog captured; the exit code is 1 and the file is unchanged |
| Backup and restore keep IDs, relationships and evidence | PASS | `restore_tests.rs`; the Linux GUI restore cycle (segment 3: restart, kept database, evidence) on both distributions |
| End-to-end flows in the real app | PASS on debug builds | Windows: the Mission 6 end-to-end script, 23/23, with native Open and Save dialogs. Linux: the Mission 7 and Mission 6 GUI phases and segment 3 on both distributions. A release build is exercised only with the installers (item M10) |
| MCP | PASS | The MCP tests in the suites on all three systems; segment 3's MCP checks in the real app on both distributions |
| Security review of Mission 7 (25 distinct findings: 3 High, 10 Medium, 12 Low), and 2 found in live testing | PASS for the code | Every finding is fixed with a regression test or recorded as an accepted risk in SECURITY.md (MISSION_REPORT.md lists each with severity and commit) |
| Native confirmations: Cancel default, approve delayed, one at a time | PASS on Windows and Linux | Windows: task dialog read and pressed through Win32, including an early synthetic click being ignored. Linux: GTK dialog through xdotool (Return cancels, early click ignored, late click approves) |
| High-DPI and minimum window | PARTIAL | Emulated on Windows (device emulation at 100–200 %), virtual X screens on Linux (`GDK_SCALE=2`, minimum enforced by the window manager). No physical HiDPI screen (item M4) |
| Linux desktops | PARTIAL | Compositors in containers: Mutter and KWin (Wayland), KWin with XWayland (software rendering). No full GNOME Shell or Plasma session, no portal, no login keyring (items M2, M3, M6, M7) |
| TAXII credentials in Windows' credential dialog | NOT TESTED | It cannot be scripted (UIPI). Linux GTK dialog: PASS, with a check that no copy reaches the disk. Procedure for Windows: `TAXII_CREDENTIAL_TEST.md` (item M1) |
| CI on GitHub | BLOCKED | Needs a push, which only the owner can authorize (item M8) |
| Release workflow | PARTIAL | Static checks and the guard test pass; never run on GitHub (item M8). It builds and signs only in a manual run with `RELEASE_PUBLISHING` enabled |
| Code signing (Authenticode, updater key in the `release` environment) | BLOCKED | Owner's keys and setup (`docs/SIGNING.md`, `docs/UPDATER.md`) (item M9) |
| Installers: install, upgrade a copy of a real database, uninstall, first start | BLOCKED | Installers are built only at the final stage with authorization (item M10) |

**Engineering readiness is not release readiness.** The automated checks pass, but items M1–M10 below decide the release, and several of them block it.

## Manual release-candidate checklist

Fill in *Result* (pass / fail) and *Evidence* when you run an item. *Blocks* says whether the release waits for it.

| # | Item | Environment | Steps | Expected | Evidence | Result | Blocks |
|---|---|---|---|---|---|---|---|
| M1 | TAXII credentials in Windows' credential dialog | Windows 11, development build with an isolated data folder, `scripts/qa/taxii-mock.mjs` | `docs/release/TAXII_CREDENTIAL_TEST.md`, steps 1–17 and the leak check | As listed there for each step; no test value outside Credential Manager | Screenshots, the test server's log lines, the leak-check output | | **Yes** |
| M2 | Full GNOME Shell session | Ubuntu 24.04 desktop (VM or hardware), Wayland session, then "GNOME on Xorg" | Start the release candidate; open every page; run a tool through the native confirmation (Return at once must cancel); store a TAXII credential (GTK dialog); open and save files (backup, report); maximize, restore, log out with the app open | Every page renders; dialogs belong to the window and work by keyboard; files open and save; the app ends cleanly at log-out | Screenshots, the activity log | | **Yes** for Linux |
| M3 | Full KDE Plasma session | Kubuntu 24.04 or Debian 12 KDE, Plasma on Wayland, then X11 | As M2 | As M2 | As M2 | | **Yes** for Linux |
| M4 | Physical HiDPI | Windows 11 on a 1920 × 1080 (or larger) screen at 150 % and 200 %; GNOME with 200 % and with fractional 125 % scaling | Start the app; check the first window size and position; resize to the minimum with the mouse; open the finding form, a project's tabs, the ATT&CK matrix and the OSINT graph; move the window between screens of different scales if available | Sharp text, nothing cut off, the minimum is held by the window manager, dialogs fit | Screenshots at each scale | | **Yes** |
| M5 | Minimum window usability | Same as M4 at the smallest size (800 × 480 logical) | Use the sidebar (icons only), Projects, a project's tabs, the record panel and a dialog with the keyboard and mouse | Everything reachable by scrolling, no horizontal page overflow | Screenshots | | No |
| M6 | Desktop portals | GNOME and KDE sessions; `GTK_USE_PORTAL=1` | Open and save files (import, backup, report, evidence) with the portal file chooser | The portal chooser opens; files are read and written | Screenshots | | No, unless the package is sandboxed (Flatpak or Snap) |
| M7 | A real keyring | GNOME (GNOME Keyring unlocked by the login), KDE (KWallet through the Secret Service) | Store, use and forget a TAXII credential; quit and start again | The credential survives a restart, is used, and is removed when forgotten; no unlock prompt loops | Screenshots, `secret-tool search` output | | **Yes** for Linux |
| M8 | First GitHub Actions run | GitHub, after the owner pushes a branch | Push a branch; check `ci.yml` on windows-2022, ubuntu-24.04, Debian 12 (container), audit (cargo audit, gitleaks, actionlint) and MSRV. Then push a test tag `v0.1.0-rc…` in a fork or start `release.yml` by hand with `RELEASE_PUBLISHING` unset | `ci.yml` green; the release run validates only and says nothing is built | The run links | | **Yes** |
| M9 | Code signing | Owner's Authenticode certificate; the updater key in the `release` environment with required reviewers | `docs/SIGNING.md` and `docs/UPDATER.md` (owner's checklist) | Signed installers; `latest.json` signatures verify against the key in `tauri.conf.json` | Signature check output | | **Yes** |
| M10 | Installers | Windows 11 (NSIS and MSI), Ubuntu 24.04 and Debian 12 (DEB, AppImage), Fedora or RHEL (RPM) if offered | Build once with authorization; install; upgrade a **copy** of a real database; start; uninstall | The upgrade keeps all data with a backup taken first; uninstall leaves the data folder | Notes and screenshots | | **Yes** |

## Known risks at this point

* The accepted risks in `docs/SECURITY.md` ("Accepted risks and limitations") apply, including the two recorded in Mission 7:
  * process starts without a native dialog (GUI tools, a terminal, version probes);
  * a project's status changed by a compromised page.
* Copied command lines are exact in POSIX shells. In PowerShell, a word that contains a quote character arrives split, and pasting never runs another command. Command history written before Mission 7 is not quoted.
* TAXII credentials stored by earlier development builds (entry `taxii_<number>`) are no longer read; they have to be stored again.
