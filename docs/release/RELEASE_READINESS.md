# Release readiness: Cyber Hub 0.1.0 (after the second release candidate)

This is the checklist for the first release. It separates what was verified from what still needs a person, hardware, a GitHub run or a signing key.

**Mission 14 (2026-11-13): licensing remediation.** The drafts are unchanged. The next candidate, built from `840f6c9` or later, is the first to carry:
* **`THIRD_PARTY_LICENSES.txt` in every package** (NSIS, MSI, deb, rpm, AppImage; also `/usr/share/doc/cyber-hub/` and `/usr/share/licenses/cyber-hub/`), shown in Settings > About. The release checks every signed package for it before the upload (`scripts/check-package-notices.mjs`).
* **In the AppImage**, the copyright file of every bundled library and the license texts they refer to (`usr/share/doc/exploitx-appimage/`). The release fails if a bundled library has none.
* **A new release asset, `ExploitX-AppImage-library-sources_<version>.tar`** (about 410 MB): the Debian source packages of the AppImage's GPL and LGPL libraries. It is listed in `SHA256SUMS.txt` and not update-signed. The release's Linux job downloads it from the Ubuntu archive (its duration on GitHub's runner is not measured yet).

Check on the first such draft that the source archive is attached and that the AppImage contains `usr/share/doc/exploitx-appimage/` (`docs/governance/DISTRIBUTION_LICENSE_COMPLIANCE.md`, "Legal review and owner decisions").

Also from Mission 14:
* **Repository renamed.** The owner renamed the repository to **RChefo/ExploitX**. The release workflow takes the name from `$GITHUB_REPOSITORY`, so new builds name it in their update feed. The drafts' compiled feed (`RChefo/cyber-hub/releases/latest/download/latest.json`) keeps working through GitHub's redirect, as long as no new repository is named `cyber-hub`.
* **Licensing.** The React Bits components are replaced (no non-open third-party code remains), and the license decision is prepared but not applied.

**Mission 13 (2026-11-13): ExploitX.** The product is now called ExploitX (website exploitx.net, its code in RChefo/ExploitX-Web). For releases this means:
* the two drafts (`v0.1.0`, `v0.1.0-rc.2`) are **Cyber Hub builds** and stay as they are; an ExploitX release needs a new candidate built from `02a1285` or later, with updated notes (`docs/releases/0.1.0.md`) and the owner's authorization;
* the **package identity is unchanged** (productName "Cyber Hub", identifier, MSI upgrade code, package and binary names), so an ExploitX build upgrades existing installations in place; the Windows installer, Start menu and *Apps & features* still show "Cyber Hub" until the owner decides on an identity migration (docs/brand/NAME_MIGRATION.md);
* new drafts are titled "ExploitX X.Y.Z"; the update feed and signing key are unchanged.

**Mission 12 (2026-11-13): open-source readiness.** The candidates are unchanged. Cyber Hub stays public as an open-source project, the owner's decision.

What changed for releases:
* **Repository protections.** Secret scanning and push protection are on, rulesets protect the default branch and the `v*` tags, and the `release` environment needs the owner's approval for every deployment.
* **Release artifacts.** A release run's build artifacts no longer stay downloadable: one day at most, deleted after the draft upload.

What a public release now also needs (`docs/governance/THIRD_PARTY_LICENSE_AUDIT.md`):
* a **project license** selected by the owner (`docs/governance/LICENSE_COMPARISON.md`);
* the **React Bits** components replaced, or excluded from that license;
* **third-party license texts and NOTICE contents shipped with the installers**;
* for the **AppImage**, a source offer for its bundled LGPL libraries and its GPL-2.0-or-later `libjbig`, or that library removed.

The six artifacts of the first and second candidates' runs remain downloadable by signed-in GitHub users until 2026-11-19, unless the owner deletes them (FEATURE_BACKLOG.md, item 108).

**Mission 11 (2026-11-12): the second release candidate.**
* **The fixes it carries:**
  * Cyber Hub starts without CA certificates, and every network feature says what to install (`1c98af4`, item 95);
  * the MSI no longer installs into a removed NSIS copy's folder (`1aed064`, item 96);
  * the Projects page no longer scrolls sideways when a project has dates (`4d1a902`);
  * the ASVS section no longer fails on a history status it does not know (`7e62a10`);
  * the 0.1.0 notes state the signing, CA-certificate and scaling limits (`f049e08`).
* **The draft.** [Run 43288379505](https://github.com/RChefo/cyber-hub/actions/runs/43288379505) built and update-signed every package from tag `v0.1.0-rc.2` (`f049e08`, CI 43286877265 green). It is a private draft **pre-release**, "Cyber Hub 0.1.0, release candidate 2". `RELEASE_PUBLISHING` existed only from 19:15:58Z to 19:50:58Z. The first candidate's draft (`v0.1.0`, `add894e`) is unchanged.
* **Verified:** checksums and update signatures, twice (the repository's validator and the reference minisign); the tag and the run name `f049e08`; the draft carries the full notes. The deb on Ubuntu 24.04 GNOME (release checks, removal and reinstall) and on bare Ubuntu 24.04 and Debian 12 images **without CA certificates**; the rpm on Fedora 43, also with its certificates hidden; network features refusing with the message and recovering without a restart; virtual HiDPI at 100–200 % (175 % included) on Windows and GNOME, in the largest and the smallest window. The Windows install matrix: section "Windows installers" below.
* **Decided, not changed:** the publisher "cyberhub" (section "Publisher identity").
* **Found:** the GitHub repository is **public** (FEATURE_BACKLOG.md, item 99). Mission 11 did not change it.

**Cyber Hub is not release-ready, and the second candidate is PARTIALLY VERIFIED:**
* the Windows installers are not Authenticode-signed: SmartScreen and UAC say "unknown publisher";
* an update can only be tested after publication;
* physical HiDPI is untested;
* the owner decides the repository's visibility, the publisher name, and how `v0.1.0` gets the validated commit (item 101).

**Mission 10, continued (2026-11-12): the first release candidate exists.**
* **The owner's authorizations:** the session stored the update key's password, and the release workflow ran three draft runs with `RELEASE_PUBLISHING` set only during each.
* **The draft.** [Run 43242424304](https://github.com/RChefo/cyber-hub/actions/runs/43242424304) built and update-signed every package from tag `v0.1.0` (`add894e`; the application code of `63d2cd6`). They are a **private draft release**, and nothing was published.
* **Two pipeline defects found by the first runs were fixed:**
  * the password secret had been stored with a byte-order mark (`add894e`, the documented command);
  * update notes longer than the app shows stopped the upload (`598b1f9`).
* **Verified:**
  * checksums, and the update signatures, twice (the repository's validator and the reference minisign);
  * installation, first start, the app checks, backup and restore, upgrade and rollback, credentials, the MCP sidecar and uninstall, for NSIS and MSI on Windows 11, deb and AppImage on Ubuntu 24.04 GNOME and Debian 12 Plasma with KWallet, and the rpm in a clean Fedora 43 container.

At the time, the first candidate was PARTIALLY VERIFIED for the same reasons, plus the start-up without CA certificates (item 95), now fixed.

Status words:

* **PASS:** verified, with the evidence named.
* **PARTIAL:** verified only in part, or only in a substitute environment (emulated or virtual scaling, a container, a debug build, a stand-in for a person). What is missing is named.
* **NOT TESTED:** no evidence. Each one says why.
* **BLOCKED:** it needs something only the owner can provide: a signing key or certificate, an authorization, or an environment that was not available.

Evidence is a test name in the repository, a GitHub Actions run, a log or screenshot of the Mission 7–11 runs (MISSION_REPORT.md; `E:\CyberHubQA\evidence\M10\2026-11-12\` for the first candidate, `E:\CyberHubQA\evidence\M11\` for the second), or, for the manual items, the tester's own record below.

## Release requirements

| Requirement | Status | Evidence or reason |
|---|---|---|
| Rust and frontend tests, tsc, clippy on Windows, Ubuntu 24.04, Debian 12 | **PASS** | Second candidate: CI 43286877265 on `f049e08` green on `windows-2022`, `ubuntu-24.04`, Debian 12 and MSRV, and the release run's validation of the tag (43288379505). Locally: Windows 647 passed, 29 ignored; Debian 12 (Rust 1.99.1) 648 passed, 29 ignored; 56 frontend files, 310 tests; clippy `-D warnings` and tsc clean. The first candidate's run had 641 and 28: the new TLS and installer tests account for the difference. `cargo fmt` is not used by the project (no configuration, no CI step) |
| Minimum Rust version 1.90 | **PASS** | The `msrv` job of every green CI run, including `add894e` |
| Dependency audits | **PASS** for the app | cargo audit 0.22.2 (2026-11-12, again in Mission 11 and in the release run): 0 vulnerabilities in 652 crates, 8 allowed warnings. npm audit of the app: 0. GitHub's Dependabot: the same two medium alerts (`glib` below 0.20; `minimatch` in `website/`'s lint tools, item 94). Mission 11 added no dependency; `ring`, already in the tree through rustls, became a dev-dependency for a test certificate |
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
| Start-up on a system without CA certificates | **PASS** (Mission 11) | The second candidate's deb on bare `ubuntu:24.04` and `debian:12` images with no `ca-certificates` and no certificate file: it starts, shows its window, opens schema 32. Its rpm on Fedora 43 with the certificates hidden: the same. Its deb in GUI containers with the certificates hidden (Ubuntu 24.04, Debian 12): 5/5 each, the HTTP header analyzer and a live CVE search refuse with the message that says what to install, offline work goes on, and the next request after the certificates come back builds its client without a restart. Tests in `tls_trust.rs`, including an untrusted certificate still refused. The first candidate failed here with "builder error" |
| High-DPI and minimum window | **PARTIAL**: virtual PASS, physical NOT TESTED | Mission 11's layout audit (every page, every project section, three dialogs; sideways scrolling, clipped tables, unreachable controls, dialogs that do not fit) in the largest and the smallest window: Windows 11 at 100, 125, 150, 175 and 200 % 20/20 (QA debug build of the candidate's code); GNOME Wayland at Mutter's 1, 1.25, 1.502, 1.749 and 2 20/20 (Linux build of the same code), and the installed candidate deb at 1 and 1.749 8/8. It found and the candidate fixes two defects (`4d1a902`, `7e62a10`). No physical HiDPI screen (M4) |
| Installers: install, upgrade, uninstall | **PASS** for NSIS, MSI, deb, AppImage; **PARTIAL** for rpm | Second candidate: the Windows matrix above (8 scenarios, including upgrades over the first candidate); the deb in the Ubuntu 24.04 GNOME VM (release checks 5/5, removal with data kept, reinstall without a migration) and on bare Ubuntu 24.04 and Debian 12 images; the rpm in a clean Fedora 43 container (install, start, start with the certificates hidden, removal); the AppImage in a GUI container with the certificates hidden (it needs a desktop's libraries: on a bare image it stops at `libwayland-client`/`libEGL`). First candidate: Debian 12 Plasma and the AppImage in VMs (Mission 10). The rpm was not run in a desktop session |
| Updates end to end | **NOT TESTED** | Possible only after publication: the feed is `releases/latest`. Before it, every package reports that no update manifest is published, as expected (item 98); the second candidate's deb again on Ubuntu 24.04 |
| Release candidates | **PASS** (Mission 11) | `vX.Y.Z-rc.N` tags build like the release, as draft pre-releases the workflow never publishes (`00939e1`, tests in `ci_tests.rs`); run 43288379505 skipped *Publish the release* by design. CI's actionlint caught a shellcheck style rule in the first push (`44a0384`) |
| Publisher identity | **Decided, unchanged** (Mission 11) | "cyberhub" everywhere Windows shows it; see "Publisher identity" below. A test pins the install identity |
| Repository visibility | **Decided: public** (Mission 12) | The owner chose to keep the repository public as an open-source project. Drafts stay hidden from anonymous readers |
| Public repository protections | **PASS** (Mission 12) | `docs/governance/REPOSITORY_SECURITY.md`: history audit (no leak in 210 commits of 10 refs), secret scanning and push protection, Dependabot security updates, private vulnerability reporting, branch and tag rulesets, approval of outside contributors' runs, the owner as required reviewer of `release` |
| Project license | **NOT SELECTED** | Owner decision (`docs/governance/LICENSE_COMPARISON.md`; Apache-2.0 recommended). Until then the repository is public but not open-source licensed |
| Third-party licenses | **PARTIAL** | Every dependency's license passes the policy in CI. Open: React Bits (Commons Clause), the website's unlicensed Ink Orbit component, license texts and NOTICE contents not shipped with the installers, the AppImage's LGPL and GPL libraries (`THIRD_PARTY_LICENSE_AUDIT.md`) |

## Publisher identity (Mission 11)

No publisher identity is documented in the repository beyond Cargo.toml's `authors = ["Cyber Hub contributors"]`, and no legal name or company is invented here. `bundle.publisher` is unset, so Tauri derives "cyberhub" from the identifier `dev.cyberhub.workstation`.

| Where Windows shows it | Field | 0.1.0 | Comes from | Needs Authenticode |
|---|---|---|---|---|
| *Apps & features*, NSIS install | Publisher (uninstall entry) | cyberhub | `bundle.publisher` | No |
| *Apps & features*, MSI install | Publisher (Manufacturer) | cyberhub | `bundle.publisher` | No |
| `cyber-hub.exe`, `cyberhub-mcp.exe` → Properties → Details | Company; Product name; File description; Copyright | cyberhub; Cyber Hub; Cyber Hub; empty | `bundle.publisher`, `productName`, `bundle.copyright` (unset) | No |
| The NSIS installer's Properties | Product name, File description; no Company field (Tauri's template) | Cyber Hub | `productName` | No |
| SmartScreen "Windows protected your PC" | Publisher | **Unknown publisher** | the Authenticode certificate's subject | **Yes** |
| The MSI's UAC prompt | Verified publisher | **Unknown** | the certificate's subject | **Yes** |
| A file's *Digital Signatures* tab | Signer | (no tab) | the certificate | **Yes** |
| Linux: the deb | Maintainer | Cyber Hub contributors | Cargo.toml `authors` | n/a |

**Why it stays "cyberhub" for 0.1.0.** The publisher is part of the NSIS install identity:
* `HKCU\Software\<publisher>\Cyber Hub` holds the install folder;
* the next NSIS installer reads it to find the old copy and hands that folder to the old uninstaller;
* Tauri's MSI reads it for its folder and its shortcut flags.

With another publisher, a manual NSIS upgrade from a build with the old value would find no folder there. This follows from Tauri's template and was not tried. The MSI's upgrade code comes from the product name, `{35C1D9FD-CFC7-5020-B4AC-A031E55D0494}`, so MSI upgrades do not depend on the publisher, and neither does the NSIS uninstall entry, which is named after the product. A test (`ci_tests.rs`, `the_windows_install_identity_stays_the_same`) pins the product name, the identifier, the unset publisher, the absence of WiX overrides and the binary name.

**The owner's decision, before the first public release:** keep "cyberhub", or set `bundle.publisher` once, for example to the Authenticode certificate's subject so that *Apps & features* and SmartScreen agree. Until 0.1.0 is public the only installs with the old value are QA VMs. After that, a change needs a migration (an installer hook cannot run before Tauri's reinstall page).

## Windows installers (Mission 11)

The second candidate's NSIS installer (`8c7c136c…`) and MSI (`ded2c1be…`), and the first candidate's for the upgrades, in `chqa-win11b` (Windows 11 26H2), 2026-11-12T20:00–20:10Z. NSIS ran silently; the MSI ran with basic UI, Windows asked for administrator approval and the prompt was answered (7 prompts). The app checks are Mission 10's harness on the installed build.

| # | Scenario | Result |
|---|---|---|
| 1 | Fresh NSIS (no earlier data) | **PASS.** `%LOCALAPPDATA%\Cyber Hub`, a Start-menu entry and a desktop shortcut, an HKCU uninstall entry; RC-1–RC-9 10/10 and 1/1: version and schema, data folder, update check, the MCP sidecar's 62 tools, window, every page, native confirmation, backup and restore through Windows' dialogs |
| 6 | NSIS uninstall, data kept | **PASS.** The program and its entries went; the data and its marker file stayed; `HKCU\Software\cyberhub\Cyber Hub` lost its folder value and kept only `Installer Language` |
| 2 | The MSI after that uninstall | **PASS, fixed.** `C:\Program Files\Cyber Hub\` (the first candidate went to the removed NSIS copy's per-user folder) |
| 7 | That MSI on the same data | **PASS.** 0.1.0 and schema 32, the data and the marker there, no pre-upgrade backup: no migration |
| 4 | MSI uninstall, then NSIS | **PASS.** The MSI's values went; NSIS went back to `%LOCALAPPDATA%\Cyber Hub`, with its shortcuts; the app opened the same data |
| 8 | The second candidate's NSIS over the first's | **PASS.** The program was replaced in place (`cyber-hub.exe` `5af4e8ba…` → `46416537…`), one uninstall entry, shortcuts kept, data opened without a migration |
| 5 | The second candidate's MSI over the first's | **PASS.** A major upgrade: product code `{28A6D9EA…}` → `{BAD29292…}`, one entry, the program replaced (`62b5a52a…` → `7b530c14…`), data opened without a migration |
| 3 | Fresh MSI (no earlier data) | **PASS.** Program Files, all-users Start menu; RC-1–RC-9 10/10 and 1/1; then an upgrade from fixture schema 31 (backup at 31 first, all 87 seeded tables compared, only the designed catalog pruning), a rollback to that backup and the upgrade again (UP-1, UP-2, RB-1, RB-2) |

**Not repeated for the second candidate:** SmartScreen and the interactive wizards (Mission 10 recorded them on the first candidate; the files are unsigned in the same way, so the same "Unknown publisher" warnings apply), Defender's scan over time, and M1 on the installed build.

**Limits:** a machine where an older NSIS uninstaller already left the folder value keeps it until the next NSIS uninstall (only QA VMs: the first candidate). While an NSIS copy is installed, Tauri's MSI follows its folder: install one Windows package at a time.

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
| M4 | Physical HiDPI: 100, 125, 150, 200 % | **BLOCKED** on hardware: NOT TESTED on a physical screen. The virtual substitute passes, Mission 11 with 175 % and the largest and smallest window on Windows and GNOME | Windows 11, GNOME, Plasma | `MANUAL_VALIDATION.md`, M4 | Sharp, nothing cut off, the minimum held, dialogs fit | **Yes** |
| M5 | The minimum window on a real screen | **PASS (virtual)** (Missions 10 and 11). The installed builds' windows fit and stop at 800 × 480; Mission 11's audit found every page, project section and dialog usable at that size, at 100–200 % | Any M4 screen | `MANUAL_VALIDATION.md`, M5 | Everything reachable, no sideways scrolling | No |
| M6 | Desktop portals and the native file chooser | **PARTIAL** (Mission 9, development build). The installed deb used GTK's chooser for import, reports, backup and restore | GNOME and Plasma sessions | `MANUAL_VALIDATION.md`, M6 | Portal calls with the variable, GTK's chooser without it | No |
| M7 | A real login keyring (GNOME Keyring, KWallet) | **PASS**, now on the installed deb too: steps 1–4, 6 and 7 with GNOME Keyring and with KWallet; step 5 (lock, cancelled unlock) in Missions 9 and 10 | GNOME and Plasma sessions | `MANUAL_VALIDATION.md`, M7 | Kept across restarts and log-ins; no prompt loop; removed when forgotten | No |
| M8 | First GitHub Actions run | **PASS.** CI green at `add894e` and, for the second candidate, at `f049e08` (43286877265) and its tag (43288219836). The release workflow's validation-only runs behave as section 5 says, and run 43242424304 is green end to end | GitHub | `GITHUB_FIRST_RUN.md` | `ci.yml` green, actionlint included; the release runs only validate without the variable | No |
| M9 | Code signing (Authenticode; update signatures in CI) | **PARTIAL.** Update signatures: PASS (both secrets stored; every package signed and verified). Authenticode: **BLOCKED**, no certificate (SSL.com IV with eSigner recommended, about $309 a year) | The `release` environment; a certificate | `SIGNING_SETUP.md` | Valid, timestamped Authenticode on four Windows files; update signatures verify | **Yes** |
| M10 | Installers: build once, install, upgrade a copy, back up and restore, uninstall | **PARTIAL.** Two private drafts; the second candidate passed the Windows matrix ("Windows installers" above), the deb in the GNOME VM and on bare images, the rpm and the AppImage in containers (MISSION_REPORT.md, "Mission 11"). Missing: Authenticode, updates end to end, the rpm in a desktop session | Windows 11, Ubuntu 24.04, Debian 12, Fedora 43 container | `RELEASE_CANDIDATE_PROCEDURE.md` | As listed there for every package | **Yes**, until Authenticode |

## Accepted risks and open decisions after the second release candidate

* **Unchanged from Mission 8:** the version probes of tool detection start without a dialog; a page can move a project between planning, active and paused; the remaining PowerShell quoting case; SECURITY.md, "Accepted risks and limitations".
* **Accepted as low in Mission 10:** another program can size the Windows window below its minimum (item 92); at 125 and 150 % on GNOME the page is scaled down (item 91).
* **Resolved in Mission 11:** the start without CA certificates (item 95, fixed; `ca-certificates` deliberately not declared as a package dependency); the MSI's folder after an NSIS uninstall (item 96, fixed).
* **Open decisions before publishing:**
  * the repository's visibility: public since 2026-11-12, not changed by any session (item 99);
  * the publisher name, kept "cyberhub" for now (item 97, "Publisher identity" above);
  * how `v0.1.0` gets the validated commit: move the tag (a rewrite of a public tag) or release 0.1.1 (item 101);
  * deleting the first candidate's draft, which the stable build requires.
* **Release builds share the data folder of development builds,** because the identifier is `dev.cyberhub.workstation`. Install candidates only where no real data is: a VM, Windows Sandbox or another account.
* **Third-party GitHub Apps.** Eight apps installed on the owner's account can reach this repository, some with permissions on the release path (`GITHUB_FIRST_RUN.md`, "Mission 10"; re-checked in `docs/governance/REPOSITORY_SECURITY.md`, "Mission 14 review"). Limit them to the repositories that need them.
* **The AppImage's `libjbig` (GPL-2.0-or-later)** ships with its source since Mission 14; whether that settles it is a legal question (`docs/governance/DISTRIBUTION_LICENSE_COMPLIANCE.md`). Alternatives: drop GDK-Pixbuf's TIFF loader from the AppImage, or ship only deb and rpm for Linux.
