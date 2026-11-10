# Updates

Cyber Hub updates itself with the official [Tauri updater plugin](https://v2.tauri.app/plugin/updater/) (`tauri-plugin-updater` 2.14). Every update is signed with the Cyber Hub update key and verified by the app before it can be installed. Updates are found automatically (optional) but are downloaded and installed only when you choose to.

> **Status:** the updater, the signing setup, the release workflow and the manifest tooling are implemented; the Windows NSIS update path was tested end to end against a local staging feed, Linux formats and MSI updates were not (see [Testing](#testing)). No release has been published, the release workflow has never run, and the production key has never signed a release. Until the owner completes [the setup](#owner-setup), installed copies have nothing to update from.

## How it works

```
GitHub release vX.Y.Z                         Cyber Hub (installed copy)
  ├─ latest.json  ◀────── HTTPS GET ─────────  update service (Rust, backend only)
  ├─ Cyber.Hub_X.Y.Z_x64-setup.exe (+ .sig)      │ 1. newer stable version for this OS + package type?
  ├─ Cyber.Hub_X.Y.Z_x64_en-US.msi (+ .sig)      │ 2. download into memory (progress, cancellable)
  ├─ Cyber.Hub_X.Y.Z_amd64.AppImage (+ .sig)     │ 3. verify the minisign signature with the public key
  ├─ Cyber.Hub_X.Y.Z_amd64.deb (+ .sig)          │    compiled into the app, bound to version X.Y.Z
  └─ Cyber.Hub-X.Y.Z-1.x86_64.rpm (+ .sig)       │ 4. native confirmation, no running work → install
```

* **Backend-driven.** `src-tauri/src/updates.rs` owns the whole flow (state machine, checks, download, install, scheduler). The web view calls seven commands (`update_status`, `update_check`, `update_download`, `update_cancel`, `update_install`, `update_restart`, `update_settings_set`) and receives `update-status` events with progress. The window's capability grants **no updater permission**: the plugin's own JavaScript API (`@tauri-apps/plugin-updater`) is deliberately not installed and its commands are refused for the page. A compromised page can at most ask the backend to check, download a signed update or open the native install confirmation.
* **Feed.** A static `latest.json` in the GitHub release, read from `https://github.com/<owner>/<repo>/releases/latest/download/latest.json`. The address is **not** in the committed `tauri.conf.json` (the repository has no remote yet, and no URL is guessed): the release workflow compiles the feed of the repository it runs in into release builds (`tauri build --config`). Development and local builds have no feed and say so in Settings → Updates.
* **Channel.** Stable only: a release is offered when it is strictly newer than the installed version (semantic-version precedence) and is not a pre-release. Downgrades and reinstalls of the same version are never offered (`allowDowngrades` stays off). The channel is a field of the status and of the comparator (`updates::offered`), so a beta channel can be added later without changing the flow.
* **Package type.** The bundler records how a copy was packaged (NSIS, MSI, AppImage, deb, rpm). The updater looks for `{os}-{arch}-{type}` in the manifest first (for example `linux-x86_64-deb`), then `{os}-{arch}`, so a deb installation is updated with the deb package, an MSI installation with the MSI.

### Supported installation formats

| Format | Updates itself | How the update is installed | Notes |
|---|---|---|---|
| Windows NSIS (`…_x64-setup.exe`, per-user) | yes | the installer runs in passive mode (progress bar, no questions) with `/UPDATE` and restarts Cyber Hub | the recommended Windows package |
| Windows MSI (`…_x64_en-US.msi`) | yes | `msiexec /i … /passive /promptrestart`; Windows asks for administrator approval | per-machine install |
| Linux AppImage | yes | the AppImage file is replaced in place; Cyber Hub then offers **Restart now** | the AppImage's folder must be writable by you (the plugin keeps a backup of the old file in a temporary folder on the same file system — the system temporary folder, the cache folder or the AppImage's own folder — and restores it if writing fails) |
| Linux .deb | yes | `dpkg -i` through `pkexec` (or a graphical/terminal `sudo` prompt); then **Restart now** | asks for an administrator password every time |
| Linux .rpm | yes | `rpm -U` through `pkexec` (or `sudo`); then **Restart now** | asks for an administrator password every time |
| Development build (`npm run tauri dev`), a copied executable, a portable copy | **no** | — | Settings → Updates explains that this copy cannot update itself |
| macOS | not supported | — | macOS is not a supported platform |

What was actually tested for each format is listed under [Testing](#testing); formats marked untested there must not be assumed to work.

## Security

| Property | How |
|---|---|
| Signatures are mandatory | The plugin verifies every download (minisign, Ed25519 over a BLAKE2b-512 hash) against `plugins.updater.pubkey` in `tauri.conf.json`, which is compiled into the app. There is no switch to skip it. An artifact that fails is discarded and never offered again without a new check. |
| Version binding | `requireSignedVersion: true`: the signature's trusted comment must name the version the feed announces (`tauri build` writes `version:X.Y.Z` into it). A tampered feed cannot pair a new version number with an older, validly signed build. |
| HTTPS only | Release builds reject non-HTTPS feeds (plugin) and the service also refuses a manifest whose download URL is not HTTPS, and builds every request client with `https_only` (redirects included). A build configured to accept invalid certificates or host names refuses to check at all. Only a test build that sets `dangerousInsecureTransportProtocol` accepts plain HTTP, and Settings → Updates then shows a "Test build" warning; the release workflow fails if any `dangerous*` option is set. |
| No silent install | Downloading needs a click; installing needs a click **and** a native OS confirmation created by the Rust process (the page cannot click it). Automatic checks only fetch `latest.json`. |
| No interrupted work | Installing (and restarting after a Linux install) is refused while tool runs, OSINT collections, MCP approvals or VirusTotal uploads are in progress, and on Windows while an MCP client is running `cyberhub-mcp.exe` (the installer could not replace it). The list is shown in Settings → Updates. |
| Clean shutdown | Before the Windows installer takes over, the normal exit path runs: tool process trees are killed, run snapshots removed, the MCP bridge closed, the database's write-ahead log checkpointed. |
| No partial files | The package is downloaded into memory (capped at 512 MB), verified there, and written to the system temporary folder only when installing. Cancelling, a failure, or quitting during a download leaves nothing behind. Nothing is written next to the application. |
| Plain-text notes | Release notes are shown as plain text (control characters removed, capped at 20,000 characters); no HTML or Markdown is rendered. |
| Private key | Never in the repository, the app, logs or the frontend; only in the owner's key file and the `release` environment's secrets. |

## Data during an update

The installers replace program files only. These are kept, because they live outside the installation folder:

| Data | Location |
|---|---|
| Database (projects, findings, OSINT investigations and graphs, history, settings, update settings) | Windows `%APPDATA%\dev.cyberhub.workstation\cyberhub.db`, Linux `~/.local/share/dev.cyberhub.workstation/cyberhub.db` |
| Provider credentials | Windows Credential Manager / Linux Secret Service (never touched by installers) |
| MCP client configuration | in each client's own configuration file; the server path stays the same for NSIS, MSI, deb and rpm (the AppImage path changes on every start anyway, see MCP.md) |

Database migrations run at the next start, as for any version change. There is **no automatic rollback**: if a new version misbehaves, install the previous release's installer by hand (NSIS and MSI allow installing an older version over a newer one; for deb use `sudo dpkg -i` with the older package, for rpm `sudo rpm -U --oldpackage`; for the AppImage keep the older file). A database that a newer version has migrated may not open in an older version; back up `cyberhub.db` (with Cyber Hub closed) before installing if you need to be able to go back. If the installer fails, the current version stays installed (NSIS/MSI roll back their own transaction; dpkg/rpm leave the old package when installation fails).

## Using it

**Settings → Updates** shows the installed version, platform and package type, channel, the last check and its result, the next automatic check, the available version with its date, size and release notes, and the state: *Not checked, Checking, Up to date, Update available, Downloading, Verifying, Ready to install, Installing, Restart required, Cancelled, Failed*.

* **Check for updates**: one request for `latest.json`. Checks never overlap; a second click while one runs gets the running check's result.
* **Download**: progress in bytes, **Cancel download**; then *Verifying the signature…* and *Ready to install*.
* **Install and restart…**: lists any work that must finish first; then a native dialog. Windows: Cyber Hub closes, the installer updates and restarts it. Linux: the package is installed (a password prompt for deb/rpm), then **Restart now**.
* **Check for updates automatically** (on by default) and **How often** (every 6 h, 12 h, daily — the default — or weekly). The first automatic check runs 90 s after startup, never on the startup path; a check is made only when one is due (the last check time is stored), so restarting the app does not cause extra checks. Failed automatic checks (offline, server errors) retry after 15 min, 30 min, 1 h … up to the normal interval, and are shown only in Settings → Updates, never as notifications.
* **Notifications**: when a check finds a new version, one dismissable toast (with *View*) and one entry in the activity list (bell menu) — once per version, also across restarts. No dialog is opened.

Errors name the cause: no connection or timeout, HTTP status, no release manifest, invalid manifest, no package for this platform/type, signature failure (with the plugin's reason), not HTTPS, disk/temporary-folder errors, a cancelled administrator prompt, package-manager failure.

## Signing keys

### Key generation and storage

The production key pair was generated on the owner's development machine with the official CLI (`tauri signer generate`), password-protected:

* private key: `%USERPROFILE%\.cyberhub\updater-signing\cyberhub-updater.key` (encrypted with the password; folder and file ACL restricted to the owner's account; outside the repository);
* password: Windows Credential Manager, generic credential `CyberHub.UpdaterSigning` / `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` (random, 256 bits; never printed);
* public key: `%USERPROFILE%\.cyberhub\updater-signing\cyberhub-updater.key.pub`, copied into `src-tauri/tauri.conf.json` → `plugins.updater.pubkey` (key ID `957F3F7D955C72FA`).

To generate a key pair yourself (for example on another machine or after a compromise):

```bash
npx tauri signer generate -w ~/.cyberhub/updater-signing/cyberhub-updater.key
# enter a strong password when asked; copy the content of the .pub file into plugins.updater.pubkey
```

**Back up the private key file and its password** (for example in a password manager, offline). **If the private key or its password is lost, installed copies can never receive another trusted update**: they only accept updates signed by the key compiled into them, so users would have to download and install a new version by hand.

### Release secrets

The release workflow reads two secrets, which should be stored in a GitHub **environment** named `release` (not as repository secrets), with required reviewers:

| Secret | Value |
|---|---|
| `TAURI_SIGNING_PRIVATE_KEY` | the content of `cyberhub-updater.key` |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | its password |

Set them from the owner's machine without displaying them (PowerShell, after `gh auth login` and creating the `release` environment):

```powershell
gh secret set TAURI_SIGNING_PRIVATE_KEY --env release --repo <owner>/<repo> < "$env:USERPROFILE\.cyberhub\updater-signing\cyberhub-updater.key"
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$c = (New-Object Windows.Security.Credentials.PasswordVault).Retrieve('CyberHub.UpdaterSigning','TAURI_SIGNING_PRIVATE_KEY_PASSWORD'); $c.RetrievePassword()
$c.Password | gh secret set TAURI_SIGNING_PRIVATE_KEY_PASSWORD --env release --repo <owner>/<repo>
```

Never paste the key or password into chats, issues, workflow files or logs.

### Key rotation

Installed copies trust only the public key they were built with, so rotation needs an overlap release:

1. Generate a new key pair (above).
2. Release version N with the **new public key** in `tauri.conf.json`, but signed with the **old private key** (old secrets). Copies on N−1 verify it with the old key they trust, and after installing it trust the new key.
3. Switch the `release` environment secrets to the new key; release N+1 and later are signed with the new key.
4. Copies older than N must update to N first (they reach it automatically, since N is signed with the key they trust).

If the old private key was **compromised**, do steps 1–3 immediately, and treat any release signed by the attacker as possible; there is no revocation in the updater, so publish a notice and consider shortening the overlap. If the old key was **lost**, step 2 is impossible: existing installations must reinstall manually.

## The release workflow

`.github/workflows/release.yml` (never run yet) — triggered by pushing a tag `vX.Y.Z` or by a manual run naming an existing tag. **Building, signing and uploading happen only in a manual run, and only while the repository variable `RELEASE_PUBLISHING` is `enabled`**; a tag push only runs *validate*, also while publishing is enabled (Mission 7: nothing is signed or uploaded unless someone starts the run by hand). A manual run stops at a **draft**; a release becomes public only by a manual run with *draft* unchecked and the tag typed again in *confirm*, or by publishing the reviewed draft by hand:

1. **validate** (no secrets): the tag is `vMAJOR.MINOR.PATCH`; `package.json`, `tauri.conf.json` and `Cargo.toml` carry that version; the commit is on `main` or a `release/*` branch; the updater configuration is intact (public key present, `requireSignedVersion` on, updater artifacts on, no `dangerous*` option); no private key file is committed; release notes exist (`docs/releases/X.Y.Z.md`, otherwise the annotated tag message); no release exists for the tag yet; typecheck, frontend and release-script tests, frontend build, `cargo test`, clippy with warnings denied, `npm audit`, `cargo audit`.
2. **build** (environment `release`, the only job with the signing secrets, read-only token): Windows (NSIS, MSI) and Linux on Ubuntu 22.04 (AppImage, deb, rpm), `tauri build` with the repository's feed compiled in; every package must have its `.sig`.
3. **publish** (environment `release`, `contents: write`): generates `latest.json` with `scripts/updater-manifest.mjs`, **validates it** (every entry points to a file that exists, HTTPS, the file name survives the upload, supported platform keys only, the signature verifies against the public key in `tauri.conf.json` and names the release's version, all five package types present), writes `SHA256SUMS.txt`, uploads everything to a **draft** release, checks every asset arrived and that GitHub's SHA-256 digest of every uploaded file equals `SHA256SUMS.txt` (the website shows those digests as the download checksums, see WEBSITE.md), and leaves it a draft. Only the manual run described above makes it public, after all of these checks.

Hardening: workflow-level `permissions: {}` with per-job grants; actions pinned to commit SHAs; Rust (1.99.1), Node (22.12.0) and cargo-audit (0.22.2) pinned by exact version, the same as `ci.yml`; a timeout on every job; `persist-credentials: false`; no caches; secrets only as step environment variables, only in jobs of the `release` environment; no `pull_request` trigger. `src-tauri/src/ci_tests.rs` fails if any of this, the release switch or the publish condition is removed.

Normal CI (`ci.yml`) never needs the signing key, never runs `tauri build` and never publishes.

### Manifest format

```json
{
  "version": "0.2.0",
  "notes": "Plain-text release notes",
  "pub_date": "2026-11-05T10:00:00Z",
  "platforms": {
    "windows-x86_64-nsis":   { "url": "https://github.com/<owner>/<repo>/releases/download/v0.2.0/Cyber.Hub_0.2.0_x64-setup.exe", "signature": "<content of the .sig file>" },
    "windows-x86_64-msi":    { "url": "…/Cyber.Hub_0.2.0_x64_en-US.msi", "signature": "…" },
    "windows-x86_64":        { "url": "…/Cyber.Hub_0.2.0_x64-setup.exe", "signature": "…" },
    "linux-x86_64-appimage": { "url": "…/Cyber.Hub_0.2.0_amd64.AppImage", "signature": "…" },
    "linux-x86_64-deb":      { "url": "…/Cyber.Hub_0.2.0_amd64.deb", "signature": "…" },
    "linux-x86_64-rpm":      { "url": "…/Cyber.Hub-0.2.0-1.x86_64.rpm", "signature": "…" },
    "linux-x86_64":          { "url": "…/Cyber.Hub_0.2.0_amd64.AppImage", "signature": "…" }
  }
}
```

```bash
node scripts/updater-manifest.mjs generate --normalize-names --version 0.2.0 --assets <folder> \
  --base-url https://github.com/<owner>/<repo>/releases/download/v0.2.0 --notes-file notes.md --out latest.json
node scripts/updater-manifest.mjs validate --manifest latest.json --assets <folder> [--require windows-x86_64-nsis,…]
```

`--normalize-names` replaces spaces in file names with dots, as GitHub would on upload, so the URLs in the manifest match the uploaded assets.

## Owner setup

1. Push the repository to GitHub (the workflow derives the feed address from the repository it runs in).
2. Create the environment **release** (Settings → Environments) with required reviewers, and restrict it to tags `v*`.
3. Add the two secrets to that environment (see [Release secrets](#release-secrets)).
4. Back up the private key file and its password offline.
5. Only when the environment, its reviewers and its secrets are in place, set the repository variable `RELEASE_PUBLISHING` to `enabled` (Settings → Secrets and variables → Actions → Variables). Remove it again to stop all building and publishing.
6. For each release: bump the version in `package.json`, `src-tauri/tauri.conf.json` and `src-tauri/Cargo.toml`; write `docs/releases/X.Y.Z.md`; merge to `main` or a `release/*` branch; push the tag `vX.Y.Z` (this validates only). Then start *Release* by hand (Actions → Release → Run workflow) with that tag: leave *draft* checked, review the draft the run leaves, and publish it by hand; or run it with *draft* unchecked and the tag typed again in *confirm*.
7. **Set up Windows Authenticode code signing** for the installers and executables before distributing anything (separate from update signing). Without it SmartScreen warns on download, and in the staging test Microsoft Defender quarantined an unsigned updated build as a machine-learning false positive. Not part of this setup.

## Testing

### Automated

* Backend (`cargo test`): version policy (newer only, no downgrade, no pre-release, build metadata ignored), install-format support, backoff and next-check computation, one notification per version, cleanup of only the updater's own temporary folders, plain-text notes and dates, error classification.
* Frontend (`npx vitest run`): Update Center actions per state (no install before verification, blocked installs, checking while a download is ready) and progress.
* Release script (`scripts/updater-manifest.test.mjs`, run by `npx vitest run`): minisign keys and signatures made with Node's Ed25519 in the format the Tauri CLI writes; a valid manifest passes; a modified artifact, a wrong key, an empty and a broken signature, an edited trusted comment, an unsigned build, a signature for another version, plain HTTP, a missing file, unknown platforms, a non-semver version, a pre-release and a bad date are all refused.
* The manifest tool was also run on real `tauri build` output: the NSIS and MSI packages and their signatures verified against the test key and were refused against the production key (key ID mismatch reported).

### Windows staging test (2026-11-05, Windows 11, local feed, disposable install)

Disposable builds with their own product name and identifier (`Cyber Hub Updater Test`, `dev.cyberhub.workstation.updatertest`), so the developer's data and any real installation stayed untouched; a separate **test** key pair (the production key never signed a test package); a local feed on `127.0.0.1` (HTTP, which only these test builds accept, plus HTTPS with a self-signed certificate for the TLS cases). The app was driven through its own IPC commands; the native confirmation was answered by clicking it. The test installation and its data were removed afterwards.

| Case | Result |
|---|---|
| Status of an NSIS-installed copy | package type `nsis`, supported, stable channel, *Test build* warning shown |
| Same version, older version (downgrade), pre-release `0.3.0-beta.1` | *Up to date* (not offered) |
| Feed returns 404; malformed JSON; no entry for this platform; entry without `signature` | *Failed* with a specific message for each |
| Valid 0.2.0 | *Update available* with version, date, notes and size (6.3 MB, from a HEAD request); download with byte progress; *Ready to install* after verification |
| Modified installer; signature from another key; empty signature; garbage signature | download *Failed* with a signature error; the update is withdrawn until the next check |
| Signature without a version; feed announcing 0.3.0 for the 0.2.0 package; feed announcing 0.2.0 for the genuine **0.1.0** package (downgrade through a tampered feed) | all refused as signature errors (`MissingSignedVersion`, `SignedVersionMismatch`) |
| Package URL that returns 404 | *Failed* with the HTTP status; the update stays offered for a retry |
| Download from an HTTPS server with an untrusted certificate | refused (the server logged the client's `unknown CA` alert; no fallback) |
| Throttled download, **Cancel download** after 3 s | *Cancelled* at 0.7 of 6.3 MB, connection closed by the client, nothing written to disk, update still offered |
| **Install** while the installation's `cyberhub-mcp.exe` was running | refused before any dialog; the blocker is listed in the status |
| **Install** → native dialog → **Cancel** | "Installation cancelled", nothing changed, still *Ready* |
| **Install** → native dialog → **Install update** | Cyber Hub exited, the NSIS installer ran in passive mode, replaced the program files and started the new version: version 0.2.0, with the project, the OSINT investigation, a changed preference and the update settings (12 h interval, last check) all present |
| Update settings across a restart | auto-check and interval kept |

Found and fixed during the test:

* The MSI could not be built at all: the MCP server was in it twice (see PLATFORMS.md).
* While a verified download waited in *Ready*, checking was refused, so a newer release could never replace it. Checking is now allowed in *Ready*, and the verified download is kept if the feed still announces it.
* A feed going 0.2.0 → 0.3.0 → 0.2.0 announced 0.2.0 twice. Now only versions newer than every one already announced are notified.
* The plugin leaves the installer in `%TEMP%\<product>-<version>-updater-*`. These folders are now removed at a later start.

These fixes are covered by unit tests; the last three were not repeated in a live update (see below).

Observed and **not** an updater defect:

* About 10 s after the updated test build started, Microsoft Defender quarantined its unsigned executable as `Trojan:Win32/Bearfoos.A!ml` and removed its shortcut and uninstall entry (see [Limitations](#limitations)).
* Every MSI build logs "Windows Installer installed the product" events in the Application log. That is WiX's ICE validation during the build, not an installation (no product was registered).

### Not tested

* **Linux: no format was tested** (AppImage, deb, rpm). The code paths are the plugin's; the Update Center reports them as supported, but that must not be read as verified.
* **MSI updates**: installing the MSI needs an administrator approval that could not be automated. The MSI package was built, signed and its signature verified.
* A second live update hop (0.2.0 → 0.3.0) and the live effect of the fixes above: the 0.3.0 package was built and staged, but the 0.2.0 executable had been quarantined by Defender.
* The automatic check firing on schedule in a live app: the computation is unit-tested, but in the live test every check was manual, so none was due.
* The release workflow (never run; no repository remote) and `actionlint` (pulling its container image was not permitted in this session).
* Live blockers other than the MCP server (tool runs, OSINT collections, MCP approvals, VirusTotal uploads): code review only.
* Restart after a Linux install (`Restart now`).

## Limitations

* No automatic rollback (see [Data during an update](#data-during-an-update)).
* No delta updates: every update downloads the full package (tens of MB).
* The feed is GitHub's `releases/latest`; a draft or pre-release is never served by it.
* Windows Authenticode signing of the installers is not set up; update signatures are independent of it.
* Linux deb/rpm updates need an administrator password each time; a headless session without `pkexec`, zenity/kdialog or a terminal cannot authenticate.
* An AppImage stored in a folder you cannot write to cannot replace itself (the error says so).
* **Unsigned Windows builds trigger Microsoft Defender.** In the staging test, Defender's machine-learning heuristic quarantined the freshly installed, unsigned test build (`Trojan:Win32/Bearfoos.A!ml`, a generic ML verdict) about 10 seconds after the installer restarted it. The update itself had completed. Release installers and executables must be Authenticode-signed (and, if needed, submitted to Microsoft as a false positive) before anything is distributed; see [Owner setup](#owner-setup).
