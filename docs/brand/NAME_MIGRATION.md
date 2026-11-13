# Name migration: Cyber Hub → ExploitX

The inventory of Mission 13 (2026-11-13). It lists what now says ExploitX, what keeps the old name on purpose and why, and what a later change of the package identity would involve. Search terms: "Cyber Hub", "CyberHub", "cyberhub", "cyber_hub", "cyber-hub", "THREATIQ", "ThreatIQ", "threatiq". **THREATIQ appears nowhere in the repository.**

## 1. User-facing branding: replaced

"Cyber Hub" became "ExploitX" (with "an ExploitX …" where an article precedes it):

| Area | Replaced | Notes |
|---|---|---|
| Desktop app interface (`src/`, `index.html`) | 98 occurrences in 47 files | Page text, dialogs, empty and error states, notifications, the update centre, MCP setup texts, the window's `<title>` |
| Backend messages, catalogs, scripts (`src-tauri/src`, `src-tauri/catalog`, capability description, `scripts/`) | 316 occurrences in 90 files | Native confirmations, errors, the start-up error title, MCP server title, instructions and prompts, report footers, export metadata (SARIF driver name, ATT&CK layer source, STIX descriptions), the user agent of the attack-surface check |
| Window title, package texts | `tauri.conf.json`, `Cargo.toml` | Title "ExploitX"; deb/rpm summary and description; Maintainer "ExploitX contributors" |
| Linux desktop entry | `src-tauri/linux/exploitx.desktop.hbs` | `Name=ExploitX` (the file name, Exec, Icon and StartupWMClass stay; see 5) |
| Logo, icons, colours, fonts | New identity | Sidebar logo, `public/logo.svg`, every icon in `src-tauri/icons/`, theme tokens |
| Website (then `website/`, now RChefo/ExploitX-Web) | 70 occurrences in 18 files, plus the logo, metadata and screenshots | Titles, descriptions, Open Graph, JSON-LD, canonical `https://exploitx.net`, favicons, footer |
| Public and contributor documentation | 215 occurrences in 29 files | README, CONTRIBUTING, SECURITY, SUPPORT, CODE_OF_CONDUCT, THIRD_PARTY_NOTICES, `docs/*.md`, `docs/governance/`, issue forms |
| Release workflow | Draft titles | New drafts are titled "ExploitX X.Y.Z"; **existing drafts are unchanged** |

Data written before the rename keeps its text. Examples: a finding's tool "Cyber Hub file triage", or "Interrupted: Cyber Hub was closed". Nothing matches on these strings: utility findings are matched by module and content hash. So old and new records live side by side.

## 2. Internal technical identifiers: kept

| Identifier | Where it counts | Why it stays |
|---|---|---|
| `dev.cyberhub.workstation` | Tauri identifier; the data folder (`%APPDATA%\dev.cyberhub.workstation`, `~/.local/share/dev.cyberhub.workstation`); the OS credential store service name; WebView data | Changing it would orphan every installation's database, backups, evidence and stored credentials |
| `cyberhub.db`, `backups/cyberhub-schema<N>-…db`, `cyberhub-backup-…` | Database and backup file names | Restore, backup rotation and upgrade code find files by these names |
| `CYBERHUB_DATA_DIR`, `CYBERHUB_*` test and sample variables | Environment variables | Documented for developers and MCP client setups; existing configurations would stop working |
| `cyberhub-mcp` | The MCP server binary (sidecar) | MCP clients (Claude Code, Claude Desktop) are configured with its path and name |
| `cyberhub` (MCP server name), `cyberhub_*` (62 tools), `cyberhub://…` (7 resources) | The MCP protocol surface | Clients store permissions and prompts by tool name (`mcp__cyberhub__…`); renaming would silently break them |
| `cyberhub-keys` | Developer credential provisioning tool | Documented command; scripts use it |
| `cyber-hub` (Cargo package), `cyber_hub_lib` | Rust crate and library names | The Linux binary `/usr/bin/cyber-hub`, the window class `cyber-hub`, the icon name, `src-tauri/target/…/cyber-hub.exe` |
| File-format identifiers: `cyberhub-osint-graph`, `cyberhub-findings`, `cyberhub-finding-templates`, `cyberhubFindingId/v1`, `cyberhub-no-share` | Export and import formats | Files exported by earlier versions must still import |
| `cyberhub.releases.v2` (website), `cyber-hub-website` (website package), `cyber-hub: override-mistake patch` (patch marker) | Internal keys | No user sees them; renaming has no benefit |

## 3. Repository references: renamed by the owner

* Mission 13 kept `github.com/RChefo/cyber-hub`, because the update feed URL is compiled into installed copies and a rename needed its own decision.
* **The owner has since renamed the repository to `RChefo/ExploitX`** (observed 2026-11-13, Mission 14). GitHub redirects the old name, for the web pages, Git, the API and release downloads, as long as no new repository takes the name `RChefo/cyber-hub`. That redirect keeps the update feed of the two release-candidate drafts working (`https://github.com/RChefo/cyber-hub/releases/latest/download/latest.json`); builds made from now on compile the new name (`$GITHUB_REPOSITORY`). **Never create a new repository named `cyber-hub` under RChefo.**
* Mission 14 moved the README, CONTRIBUTING, SECURITY, SUPPORT, the issue forms, the procedures and the app's links to the new name, and the website's `VITE_GITHUB_REPOSITORY` to `RChefo/ExploitX`. Its download page offers only assets whose URLs name the configured repository, and GitHub now returns `RChefo/ExploitX` URLs. The historical documents below keep the old name; their links redirect.

## 4. Historical documentation: kept

These describe what happened under the old name and stay as written:
* `docs/autonomous/` (mission state, log, reports, backlog);
* `docs/release/` (release readiness, procedures, Windows VM records);
* `docs/releases/0.1.0.md` (the notes of the two existing release candidates, whose packages say Cyber Hub);
* `docs/research/`;
* `docs/EXPANSION_PLAN.md`.

New entries in these files say ExploitX. Git history and tags are unchanged.

## 5. Compatibility-sensitive identifiers: kept, with what they show

Tauri derives the **package identity** from `productName` ("Cyber Hub") and the derived publisher ("cyberhub"). `ci_tests.rs` pins them (`the_windows_install_identity_stays_the_same`), and the brief does not allow changing them for branding.

| What | Value | What the user sees today |
|---|---|---|
| Windows install folders | `%LOCALAPPDATA%\Cyber Hub\` (NSIS), `C:\Program Files\Cyber Hub\` (MSI) | Folder names; MCP client configurations point into them |
| Windows registry | `HKCU\Software\cyberhub\Cyber Hub`, the uninstall key "Cyber Hub", the MSI upgrade code `{35C1D9FD-CFC7-5020-B4AC-A031E55D0494}` | The NSIS upgrade finds the old copy, and the MSI's major upgrade replaces it |
| Windows names derived from `productName` | The installer's title, the Start menu shortcut, *Apps & features*, the executable's file description and product name | **"Cyber Hub"**. These cannot be changed without changing the identity |
| Windows executable | `cyber-hub.exe` (Tauri's main binary name) | File name |
| Linux packages | deb and rpm package `cyber-hub`, desktop file `Cyber Hub.desktop`, binary `/usr/bin/cyber-hub`, icons `cyber-hub.png`, window class `cyber-hub` | The applications menu and the window show **ExploitX** (the desktop entry's `Name`), with the new icon |
| Package file names | `Cyber Hub_<v>_x64-setup.exe`, `…_x64_en-US.msi`, `Cyber Hub_<v>_amd64.deb/.AppImage`, `Cyber Hub-<v>-1.x86_64.rpm` (GitHub shows spaces as dots) | Download file names |
| Updater | Feed URL in the repository; minisign key `957F3F7D955C72FA`; temporary file names `Cyber Hub-<v>-updater-…` | Nothing; signatures and feed unchanged |
| NSIS hook | `src-tauri/windows/installer-hooks.nsh` deletes `HKCU\Software\cyberhub\Cyber Hub` after an uninstall | Unchanged |

**Verified (Mission 13).** The rebranded deb installed over the first release candidate's deb as the same package `cyber-hub` 0.1.0 (one entry). The applications menu entry became "ExploitX", the icon was replaced, the window is titled "ExploitX" with class `cyber-hub` (matching the entry), and a file in the data folder survived the upgrade and the removal. The rpm carries the same entry.

## 6. Third-party references

* No third-party name contained the old name.
* "Cyber Resources" (a module of the app) is a generic page name, not the brand, and stays.

## Changing the package identity later (the owner's decision)

If the owner wants Windows to show ExploitX in the Start menu, *Apps & features* and the installer as well, the identity itself must change **before the first public release**. Every published release makes the change more expensive.

| Change | What it involves |
|---|---|
| `productName: "ExploitX"` | New install folders and uninstall entries; new package names (`exploitx`) and file names |
| Keep MSI upgrades working | Set `bundle.windows.wix.upgradeCode` to `{35C1D9FD-CFC7-5020-B4AC-A031E55D0494}` explicitly (it is derived from the product name today) |
| Keep NSIS upgrades working | An `NSIS_HOOK_PREINSTALL` that finds the "Cyber Hub" uninstall entry and runs its uninstaller silently (data is kept), because the new installer would not see the old copy |
| Linux | `provides`, `conflicts` and `replaces` for `cyber-hub` (deb), and `obsoletes` (rpm), so the package manager replaces the old package |
| MCP clients | Their configured `cyberhub-mcp` path changes with the install folder: release notes must tell users to re-run the client setup (the MCP page shows the new command) |
| Keep | The identifier, the data folder, the database, the credentials, the MCP names, the updater key and feed. Data then survives the change |
| Test | Fresh install, upgrade from each candidate, update through the updater, uninstall, data kept: on Windows (NSIS and MSI) and Linux (deb, rpm, AppImage), in disposable VMs |

## The existing release candidates

* The drafts of `v0.1.0` (`add894e`) and `v0.1.0-rc.2` (`f049e08`) are unchanged. Their packages, icons and texts say **Cyber Hub**, and they stay valid as records of those builds.
* **A release under the ExploitX brand needs a new build** from a commit that includes this mission: icons, window title, interface texts, report and export metadata, and the desktop entry are compiled or bundled into the packages.
* The rebuild needs:
  * a new tag (`v0.1.0-rc.3` or a later version; the tag ruleset protects the existing ones);
  * updated release notes (`docs/releases/0.1.0.md` still says Cyber Hub);
  * the owner's authorization for the release run.
