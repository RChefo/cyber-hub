# Release readiness: Cyber Hub 0.1.0 (after the release candidate)

This is the checklist for the first release. It separates what was verified from what still needs a person, hardware, a GitHub run or a signing key.

**Mission 10, continued (2026-11-12): the release candidate exists.**
* **The owner's authorizations:** the session stored the update key's password, and the release workflow ran three draft runs with `RELEASE_PUBLISHING` set only during each.
* **The draft.** [Run 43242424304](https://github.com/RChefo/cyber-hub/actions/runs/43242424304) built and update-signed every package from tag `v0.1.0` (`add894e`; the application code of `63d2cd6`). They are a **private draft release**, and nothing was published.
* **Two pipeline defects found by the first runs were fixed:**
  * the password secret had been stored with a byte-order mark (`add894e`, the documented command);
  * update notes longer than the app shows stopped the upload (`598b1f9`).
* **Verified:**
  * checksums, and the update signatures, twice (the repository's validator and the reference minisign);
  * installation, first start, the app checks, backup and restore, upgrade and rollback, credentials, the MCP sidecar and uninstall, for NSIS and MSI on Windows 11, deb and AppImage on Ubuntu 24.04 GNOME and Debian 12 Plasma with KWallet, and the rpm in a clean Fedora 43 container.

**Cyber Hub is not release-ready, and the candidate is PARTIALLY VERIFIED:**
* the Windows installers are not Authenticode-signed: SmartScreen and UAC say "unknown publisher";
* an update can only be tested after publication;
* Cyber Hub does not start on a system without CA certificates (item 95);
* physical HiDPI is untested.

Status words:

* **PASS:** verified, with the evidence named.
* **PARTIAL:** verified only in part, or only in a substitute environment (emulated or virtual scaling, a container, a debug build, a stand-in for a person). What is missing is named.
* **NOT TESTED:** no evidence. Each one says why.
* **BLOCKED:** it needs something only the owner can provide: a signing key or certificate, an authorization, or an environment that was not available.

Evidence is a test name in the repository, a GitHub Actions run, a log or screenshot of the Mission 7–10 runs (MISSION_REPORT.md; `E:\CyberHubQA\evidence\M10\2026-11-12\` for the candidate), or, for the manual items, the tester's own record below.

## Release requirements

| Requirement | Status | Evidence or reason |
|---|---|---|
| Rust and frontend tests, tsc, clippy on Windows, Ubuntu 24.04, Debian 12 | **PASS** | The release run's validation of the tagged commit (run 43242424304): 641 passed, 0 failed, 28 ignored; 56 frontend test files; clippy, tsc, the production build. CI 43239973165 on `add894e` green on `windows-2022`, `ubuntu-24.04`, Debian 12 and MSRV |
| Minimum Rust version 1.90 | **PASS** | The `msrv` job of every green CI run, including `add894e` |
| Dependency audits | **PASS** for the app | cargo audit 0.22.2 in the release run on 2026-11-12: 0 vulnerabilities in 652 crates, 8 allowed warnings. npm audit of the app: 0. GitHub's Dependabot: the two medium alerts of Mission 10 (`glib` below 0.20; `minimatch` in `website/`'s lint tools, item 94) |
| Secret scan of the whole history (gitleaks 8.30.1) | **PASS** | The `audit` job of every green CI run |
| Workflow linting (actionlint 1.7.7 with shellcheck) | **PASS** | The `audit` job of every green CI run |
| GitHub Actions settings | **PASS** | Selected actions only, SHA pinning required, read-only `GITHUB_TOKEN`, fork pull requests without runs, write tokens or secrets. The `release` environment: branches `main` and `release/*`, no administrator bypass, both update secrets. `RELEASE_PUBLISHING` existed only during the three draft runs and is unset |
| The release workflow | **PASS** | Run 43242424304, green end to end: validation, both builds and their update signatures, `latest.json` generated and validated, the tag still naming the built commit, the upload to a draft, GitHub's digests equal to `SHA256SUMS.txt`. The tag push and a manual run without the variable only validated (runs 43219450467, 43222864191) |
| Update signatures | **PASS** | Every package's `.sig` verifies against the public key compiled into the app (key `957F3F7D955C72FA`), with the repository's validator and independently with the reference minisign 0.12; each names version 0.1.0 |
| Authenticode | **BLOCKED** | No certificate: the NSIS installer, the MSI and the installed programs are "NotSigned". SmartScreen blocks the downloads ("Unknown publisher") until *Run anyway*; the MSI's UAC prompt says "unknown publisher" (M9) |
| Database upgrades from every schema, backup before migrating, interrupted and failed upgrades | **PASS** | The upgrade tests (Mission 8). On the installed candidate: schema 31 on Windows, 19 on Ubuntu and 8 on Debian upgrade to 32 after a backup at the old schema. Every seeded row is kept, except the fixtures' made-up tool, which the start-up catalog sync removes by design |
| Rollback to the pre-upgrade backup | **PASS** | On the installed candidate (Windows, Ubuntu, Debian): the pre-upgrade backup is accepted for a restore, the replaced database is kept, and the next start upgrades the restored data again after another backup. A restore drops wordlists indexed by reference by design (Mission 7) |
| An older version refuses a newer database and says how to recover | **PASS** | `startup_error.rs`; Mission 8 checks |
| Backup and restore keep IDs, relationships and evidence | **PASS** | `restore_tests.rs`. On the installed candidate: backup and restore through Windows' file dialogs (NSIS and MSI) and GTK's (GNOME, Plasma), with a text file named `.db` refused |
| End-to-end flows in the installed release build | **PASS** | Windows NSIS and MSI: ten checks each (version and schema, data folder, update check, MCP sidecar, window, every page, native confirmation, backup and restore). Ubuntu and Debian deb: M2 9/9 and the same release checks; the AppImage: the release checks |
| MCP | **PASS** | The installed `cyberhub-mcp` serves 62 tools through the bridge on Windows (NSIS, MSI), Ubuntu and Debian (deb, AppImage). The bridge files are 0600 in a 0700 folder on Linux and are removed when MCP is off. The AppImage's MCP page warns that its path changes |
| TAXII credential lifecycle | **PASS** on Windows (development build), GNOME and Plasma (installed deb) | M1 17/17 (Mission 10, development build of the same code). M7 on the installed deb with GNOME Keyring and with KWallet |
| Parser malformed input | **PASS** | `hostile_tests.rs` and the parser regressions |
| Security review | **PASS** for the code | Missions 7 and 8; Mission 9 fixed three defects found in real sessions. The candidate's tests found no security defect |
| Native confirmations | **PASS** on Windows and on Linux | Installed candidate: Cancel is the default, and an early click does nothing (GNOME, Plasma); Windows' task dialog cancels |
| Start-up on a system without CA certificates | **Open** (item 95) | Bare Ubuntu 24.04 and Debian 12 containers: "Cyber Hub could not start: builder error". With `ca-certificates` it starts. Desktop systems have them |
| High-DPI and minimum window | **PARTIAL** | Virtual scaling at 100, 125, 150 and 200 % on GNOME Wayland and Windows 11 (Mission 10). The installed builds' first windows fit the work area. No physical HiDPI screen (M4) |
| Installers: install, upgrade, uninstall | **PASS** for NSIS, MSI, deb, AppImage; **PARTIAL** for rpm | Windows 11 26H2 VM, Ubuntu 24.04 and Debian 12 VMs. The rpm only in a clean Fedora 43 container (install, start, removal). The MSI after an NSIS install goes to the NSIS folder (item 96) |
| Updates end to end | **NOT TESTED** | Possible only after publication: the feed is `releases/latest`. Before it, every package reports that no update manifest is published, as expected (item 98) |

## Manual release-candidate checklist

*Status* is what is known today. Fill in *Result* (pass or fail), *Evidence*, the tester and the date when you run an item. The procedures are in:
* `MANUAL_VALIDATION.md` (M1–M7);
* `GITHUB_FIRST_RUN.md` (M8);
* `SIGNING_SETUP.md` (M9);
* `RELEASE_CANDIDATE_PROCEDURE.md` (M10).

| # | Item | Status today | Environment | Procedure | Expected | Blocks |
|---|---|---|---|---|---|---|
| M1 | TAXII credentials in Windows' credential dialog | **PASS (VM, development build).** Mission 10, run 3: all 17 steps in a disposable Windows 11 VM, every credential typed into Windows' credential dialog; no `taxii_` entry left. Not repeated on the installed candidate (same application code) | Windows 11 | `TAXII_CREDENTIAL_TEST.md` | As listed there | No |
| M2 | Full GNOME Shell session (Wayland, Xorg, XWayland) | **PASS on Wayland with the installed deb** (Mission 10, 9/9, plus files, restore and AppImage). Xorg and XWayland: Mission 9's partial results with a development build | Ubuntu 24.04 desktop | `MANUAL_VALIDATION.md`, M2 | Every step in both sessions and under XWayland | No |
| M3 | Full KDE Plasma session (Wayland, X11, XWayland) | **PASS on X11 with the installed deb** (Mission 10, M2's steps 9/9, files, restore, KWallet, AppImage). Wayland and XWayland: Mission 9's partial results | Debian 12 KDE | `MANUAL_VALIDATION.md`, M3 | As M2, plus a clear error without a usable Secret Service | No |
| M4 | Physical HiDPI: 100, 125, 150, 200 % | **BLOCKED** on hardware. The virtual substitute passes (Mission 10) | Windows 11, GNOME, Plasma | `MANUAL_VALIDATION.md`, M4 | Sharp, nothing cut off, the minimum held, dialogs fit | **Yes** |
| M5 | The minimum window on a real screen | **PASS (virtual)** (Mission 10). The installed builds' windows fit and stop at 800 × 480 on Linux | Any M4 screen | `MANUAL_VALIDATION.md`, M5 | Everything reachable, no sideways scrolling | No |
| M6 | Desktop portals and the native file chooser | **PARTIAL** (Mission 9, development build). The installed deb used GTK's chooser for import, reports, backup and restore | GNOME and Plasma sessions | `MANUAL_VALIDATION.md`, M6 | Portal calls with the variable, GTK's chooser without it | No |
| M7 | A real login keyring (GNOME Keyring, KWallet) | **PASS**, now on the installed deb too: steps 1–4, 6 and 7 with GNOME Keyring and with KWallet; step 5 (lock, cancelled unlock) in Missions 9 and 10 | GNOME and Plasma sessions | `MANUAL_VALIDATION.md`, M7 | Kept across restarts and log-ins; no prompt loop; removed when forgotten | No |
| M8 | First GitHub Actions run | **PASS.** CI green at `add894e`. The release workflow's validation-only runs behave as section 5 says, and run 43242424304 is green end to end | GitHub | `GITHUB_FIRST_RUN.md` | `ci.yml` green, actionlint included; the release runs only validate without the variable | No |
| M9 | Code signing (Authenticode; update signatures in CI) | **PARTIAL.** Update signatures: PASS (both secrets stored; every package signed and verified). Authenticode: **BLOCKED**, no certificate (SSL.com IV with eSigner recommended, about $309 a year) | The `release` environment; a certificate | `SIGNING_SETUP.md` | Valid, timestamped Authenticode on four Windows files; update signatures verify | **Yes** |
| M10 | Installers: build once, install, upgrade a copy, back up and restore, uninstall | **PARTIAL.** The candidate is a private draft. Every package passed in disposable VMs or a clean container (MISSION_REPORT.md, "Mission 10, continued"). Missing: Authenticode, updates end to end, the rpm in a desktop session | Windows 11, Ubuntu 24.04, Debian 12, Fedora 43 container | `RELEASE_CANDIDATE_PROCEDURE.md` | As listed there for every package | **Yes**, until Authenticode |

## Accepted risks and open decisions after the release candidate

* **Unchanged from Mission 8:** the version probes of tool detection start without a dialog; a page can move a project between planning, active and paused; the remaining PowerShell quoting case; SECURITY.md, "Accepted risks and limitations".
* **Accepted as low in Mission 10:** another program can size the Windows window below its minimum (item 92); at 125 and 150 % on GNOME the page is scaled down (item 91).
* **Open decisions before publishing:**
  * no start without CA certificates (item 95): fix or accept;
  * the MSI's folder after an NSIS install (item 96);
  * the publisher name "cyberhub" (item 97).
* **Release builds share the data folder of development builds,** because the identifier is `dev.cyberhub.workstation`. Install candidates only where no real data is: a VM, Windows Sandbox or another account.
* **Third-party GitHub Apps.** Eight apps installed on the owner's account can reach this repository, some with permissions on the release path (`GITHUB_FIRST_RUN.md`, "Mission 10"). Limit them to the repositories that need them.
