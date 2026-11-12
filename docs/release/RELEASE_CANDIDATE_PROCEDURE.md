# Release-candidate procedure (M10)

This is how the one release-candidate build is made and validated. Mission 8 prepared it.

**Status after Mission 11 (2026-11-12): carried out twice.**
* **The second candidate** is the private draft **pre-release** of `v0.1.0-rc.2` (tag on `f049e08`), built by [run 43288379505](https://github.com/RChefo/cyber-hub/actions/runs/43288379505). It contains Mission 11's fixes: start-up without CA certificates, the MSI folder after an NSIS uninstall, two front-end layout and rendering defects, and the corrected notes.
* **The first candidate** is unchanged: the draft of `v0.1.0` (tag on `add894e`). It was kept until the second was validated. Delete it before building the stable release (section 12).
* **Release-candidate tags** (Mission 11, `00939e1`): the workflow accepts `vMAJOR.MINOR.PATCH-rc.N` on the same version files, makes the draft a GitHub pre-release (never the "latest" release the update feed points to) and refuses to publish it. A candidate therefore never needs the stable tag moved.
* **Results:** MISSION_REPORT.md, "Mission 11".

**Status after Mission 10 (2026-11-12): carried out once.**
* **The candidate is a private draft release** of `v0.1.0` (tag on `add894e`), built by [run 43242424304](https://github.com/RChefo/cyber-hub/actions/runs/43242424304). Nothing was published.
* **Sections 3–9 were run** in disposable VMs and clean containers; the results are in MISSION_REPORT.md, "Mission 10, continued". `RELEASE_PUBLISHING` was set only during each draft run.
* **What it taught, for the next candidate:**
  * **Store the password without a byte-order mark** (`SIGNING_SETUP.md`, section 5, corrected). The first build failed with "Wrong password for that key".
  * **Release notes longer than 20,000 characters** are now shortened for `latest.json` (`598b1f9`). The second build failed there.
  * **A failed run uploads nothing.** Fix the cause, delete and re-create the tag if the fix is a commit, set the variable again and run again.
  * **Without Authenticode,** section 6's NSIS and MSI rows are not met: SmartScreen says "Unknown publisher" and blocks until *More info → Run anyway*, and the MSI's UAC prompt says "unknown publisher". Defender did not quarantine the unsigned installed program (11 minutes, then a restart).
  * **The MSI** installs into the NSIS folder (`%LOCALAPPDATA%\Cyber Hub`) when an NSIS install was there before (FEATURE_BACKLOG.md, item 96). Test it on a machine without that history.
  * **The deb declares** `libwebkit2gtk-4.1-0` and `libgtk-3-0`. It does not declare `ca-certificates`, without which Cyber Hub does not start (item 95).
  * **The AppImage ran on Ubuntu 24.04 with only FUSE 3 installed.**
  * **Verification (section 5)** also ran the reference `minisign` against the public key compiled into the app, independently of the repository's validator.

**Mission 9 status.** The owner authorized the candidate build, and the steps up to it are done:
* the private repository;
* green CI at `5ad2ad1`;
* the `release` environment;
* the upgrade fixtures;
* the Linux test VMs.

In Mission 9 the build itself was not done: storing the update key was refused by the session's permission rules. The owner authorized it in Mission 10.

**The build happens only after the owner has reviewed `RELEASE_READINESS.md` and explicitly authorized it.** A checklist in the repository is not that authorization.

## 0. The authorization boundary

Each of these is the owner's decision, made separately:

1. pushing the branch (M8, `GITHUB_FIRST_RUN.md`);
2. creating and pushing the tag `v0.1.0`;
3. adding the signing secrets and configuration (M9, `SIGNING_SETUP.md`);
4. setting the repository variable `RELEASE_PUBLISHING` to `enabled`;
5. starting the release run by hand and approving its two `release`-environment deployments, which builds, signs and uploads a **draft**;
6. publishing the draft.

## 1. What to build

* **Source.** The commit you tag `v0.1.0`: the head of `release/v0.1.0` after Mission 8 and after any fix that M1–M7 require. Mission 8's last code commit is named in MISSION_REPORT.md, "Mission 8"; the commits after it change documentation only.

  Before tagging:

  ```bash
  git status                         # clean
  git log --oneline -3               # the commit you reviewed
  git tag -a v0.1.0 -m "Cyber Hub 0.1.0" <commit>
  git rev-parse "v0.1.0^{commit}"    # must print that commit
  ```

* **Version.** 0.1.0 in `package.json`, `src-tauri/tauri.conf.json` and `src-tauri/Cargo.toml`. The release workflow refuses a tag that differs from them. The tag is either `vMAJOR.MINOR.PATCH`, the release itself, or **`vMAJOR.MINOR.PATCH-rc.N`** (N ≥ 1), a release candidate of that version (Mission 11). A candidate is built from the same version files, so its app says 0.1.0. Its draft is a GitHub pre-release titled "Cyber Hub 0.1.0, release candidate N", and the workflow never publishes it. Other pre-release tags are refused, because the update channel has none. If a candidate fails, nothing was published: delete its draft and its tag, fix, and tag the next number.

  ```bash
  git tag -a v0.1.0-rc.3 -m "Cyber Hub 0.1.0, release candidate 3" <commit>
  ```
* **Metadata.**
  * Product name *Cyber Hub*; identifier `dev.cyberhub.workstation`, shared with development builds (see section 4).
  * The update feed is compiled in by the workflow, `https://github.com/<owner>/<repo>/releases/latest/download/latest.json`.
  * The MSI's version is 0.1.0. MSI versions must be numeric, which 0.1.0 is.
* **Release notes.** `docs/releases/0.1.0.md` is published as written. Read it once more at the tagged commit; Mission 8 corrected its schema number.

## 2. Prerequisites

* M8: `ci.yml` is green on GitHub, and the validation-only release runs passed (`GITHUB_FIRST_RUN.md`, section 5).
* M9: both update secrets are in the `release` environment, and the Authenticode route is configured with its verification step (`SIGNING_SETUP.md`). **Do not distribute Windows installers without Authenticode.** In the 2026-11-05 staging test, Microsoft Defender quarantined an unsigned build.
* M1–M7 done or consciously deferred. Their order relative to the build is the owner's choice: M2–M7 test the installed candidate, so they follow it.

## 3. Build: the release workflow, once

1. Set `RELEASE_PUBLISHING` to `enabled` (*Settings → Secrets and variables → Actions → Variables*).
2. Choose *Actions → Release → Run workflow*:
   * *Use workflow from* `release/v0.1.0`;
   * *tag* `v0.1.0`, or the candidate's tag, for example `v0.1.0-rc.2`;
   * *draft* **checked**;
   * *confirm* empty.

   Pushing the tag starts a validation-only run first. It builds nothing; Missions 10 and 11 cancelled it so that the manual run did not wait behind it.
3. Approve the `release` deployment twice when asked: *Build and sign*, then *Publish*. **Without required reviewers there is no approval step.** A private repository on GitHub Free cannot have them (Mission 9). A public repository can: the repository was public on 2026-11-12, and adding the owner as a required reviewer is recommended (FEATURE_BACKLOG.md, item 99). Without them the run goes on by itself, so set `RELEASE_PUBLISHING` only just before this run.
4. When the run ends, **set `RELEASE_PUBLISHING` back** (delete it, or set it to anything but `enabled`), so no later run can build.

**What the workflow runs:**

* Validation: the tests, clippy and both audits again.
* Then, with the repository's feed compiled in:
  * on `windows-2022`: `npx tauri build --ci --bundles nsis,msi --config <feed>`;
  * on `ubuntu-22.04`: `npx tauri build --ci --bundles appimage,deb,rpm --config <feed>`. Mission 8 type-checked this environment's release profile, without building.
* Update signatures, then `latest.json` and `SHA256SUMS.txt`, checked.
* The two tag checks, then the upload to a draft release, and a check of its digests.

Never build a release locally. A local `tauri build` without the update key stops at the updater step by design; a local package is a test build that must never be distributed.

**Expected draft assets:**

| File | For | Signatures |
|---|---|---|
| `Cyber.Hub_0.1.0_x64-setup.exe` | Windows, NSIS | `.sig` (update); Authenticode |
| `Cyber.Hub_0.1.0_x64_en-US.msi` | Windows, MSI | `.sig`; Authenticode |
| `Cyber.Hub_0.1.0_amd64.AppImage` | Linux, any x86-64 distribution | `.sig` |
| `Cyber.Hub_0.1.0_amd64.deb` | Ubuntu 24.04, Debian 12 | `.sig` |
| `Cyber.Hub-0.1.0-1.x86_64.rpm` | Fedora, RHEL | `.sig` |
| `latest.json` | the updater | each entry's signature |
| `SHA256SUMS.txt` | all of the above | |

**Retain:** the run's URL, the draft's URL, and the logs of *Build and sign* and *Publish*.

## 4. Test machines, and your data

Release builds use the real data folder and ignore `CYBERHUB_DATA_DIR`:

* Windows: `%APPDATA%\dev.cyberhub.workstation`
* Linux: `~/.local/share/dev.cyberhub.workstation`

Development builds use the same folder unless told otherwise. **Install the candidate only on machines or OS accounts without your real Cyber Hub data**, or set your data folder aside first and put it back afterwards:

| Machine | For |
|---|---|
| A clean Windows 11 VM or spare computer | First install, MSI, uninstall, SmartScreen and Defender |
| A second Windows account or VM holding an earlier data folder (section 7) | The upgrade test |
| Ubuntu 24.04 and Debian 12 desktops (VM or hardware) | deb, AppImage; M2, M3, M6, M7 |
| Fedora or RHEL (optional) | rpm |

**What Mission 9 found about these machines on the owner's computer:**
* **Linux.** VirtualBox VMs of Ubuntu 24.04 with GNOME and Debian 12 with Plasma work, under Hyper-V too. Mission 9 kept the two it made, `chqa-noble` and `chqa-deb12` (MISSION_REPORT.md, "Mission 9").
* **Windows.** A Windows 11 VirtualBox VM did not finish Windows Setup while Hyper-V (WSL 2, Docker) was active.
* **Windows, after Mission 10.** A second VM, `chqa-win11b`, works under Hyper-V: Windows 11 26H2 with 2 vCPUs, no paravirtualization and an emulated TSC.
  * M1 and the virtual HiDPI tests ran in it (MANUAL_VALIDATION.md, "Mission 10"). They used a development build copied to a temporary folder, so Cyber Hub was never installed there and the VM is ready for the installers. Only VirtualBox's Guest Additions were installed.
  * Boot it cold, never from a saved state.
  * Start GUI tests from its desktop session (Win+R): VirtualBox's guest control starts processes outside that session.
* **Other ways to get a clean Windows:**
  * **Windows Sandbox:** *Turn Windows features on or off → Windows Sandbox*. It needs an administrator and a restart, and is the simplest isolation: a fresh Windows with its own `%APPDATA%`, discarded when closed;
  * a Hyper-V VM;
  * a spare computer.

## 5. Download and verify

```powershell
# Windows: every file against SHA256SUMS.txt
Get-Content SHA256SUMS.txt | ForEach-Object { $h, $n = $_ -split '\s+', 2; $n = $n.TrimStart('*'); if ((Get-FileHash $n -Algorithm SHA256).Hash -ne $h.ToUpper()) { "MISMATCH $n" } else { "ok $n" } }
signtool verify /pa /all /v .\Cyber.Hub_0.1.0_x64-setup.exe
signtool verify /pa /all /v .\Cyber.Hub_0.1.0_x64_en-US.msi
```

```bash
# Linux
sha256sum -c SHA256SUMS.txt
# with the repository at the tag: the update signatures against the compiled public key
node scripts/updater-manifest.mjs validate --manifest latest.json --assets . --require windows-x86_64-nsis,windows-x86_64-msi,linux-x86_64-appimage,linux-x86_64-deb,linux-x86_64-rpm
```

**Pass:** every hash matches; Authenticode `Valid` with the owner's certificate and an RFC 3161 timestamp; the manifest validates. `SIGNING_SETUP.md`, section 7, explains the output.

## 6. Installation

| Package | Do | Expected |
|---|---|---|
| NSIS | Run `Cyber.Hub_0.1.0_x64-setup.exe` on the clean machine | SmartScreen and the installer name the publisher. It installs per user without an administrator prompt, and a Start-menu entry appears. `Get-AuthenticodeSignature` on the installed `cyber-hub.exe` and `cyberhub-mcp.exe` is `Valid` |
| MSI | `msiexec /i Cyber.Hub_0.1.0_x64_en-US.msi` | The UAC prompt names the publisher; it installs; the same checks |
| deb | `sudo apt install ./Cyber.Hub_0.1.0_amd64.deb` | Dependencies resolve; `/usr/bin/cyber-hub`, `/usr/bin/cyberhub-mcp` and a desktop entry exist |
| AppImage | `chmod +x Cyber.Hub_0.1.0_amd64.AppImage && ./Cyber.Hub_0.1.0_amd64.AppImage` | It starts. The MCP page warns that the AppImage's path changes at every start |
| rpm (optional) | `sudo dnf install ./Cyber.Hub-0.1.0-1.x86_64.rpm` | As deb |

**At the first start of each:**

* the window fits the screen;
* *Settings → About* shows 0.1.0;
* the data folder is created (`0700` on Linux);
* there is no error;
* *Settings → Updates* checking for updates reports that no update manifest exists yet. That is expected while the release is a draft, because the feed is `releases/latest`.

**On Windows**, leave the application open for ten minutes and start it again after a reboot. Microsoft Defender must not quarantine it. In the 2026-11-05 staging test, an unsigned build was quarantined about 10 s after it started.

## 7. Upgrade from earlier builds

There is no earlier *release*. The earlier versions are the development builds of 0.1.0:

* the first build, commit `d1cf064`, at schema 8, which **does not** check for newer databases;
* later development builds at schemas 12–31.

The candidate upgrades their database to schema 32 at its first start, after writing a backup to `backups/`.

1. On the upgrade machine, with the old build closed, put an earlier data folder into the test account's data folder: `cyberhub.db` with its `-wal` and `-shm` files, and `evidence/`.
   * **Preferred: no real data.** Since Mission 9 the test suite writes data folders as earlier builds left them, at schemas 1, 8, 19, 26 and 31, each with a row in every table and a `seeded.tsv` listing them:

     ```bash
     CYBERHUB_UPGRADE_FIXTURES=/path/to/an/empty/folder cargo test write_upgrade_fixtures
     ```

     Copy one `schema<N>/cyberhub.db` into the test data folder, and compare its tables with `seeded.tsv` after the upgrade.
   * A copy of a real data folder is a stronger test. Use it only with the owner's agreement, and only on a disposable machine.
2. Before the upgrade, record what is there:

   ```bash
   sqlite3 cyberhub.db "PRAGMA user_version; SELECT COUNT(*) FROM projects; SELECT COUNT(*) FROM findings; SELECT COUNT(*) FROM evidence;"
   ```
3. Install the candidate and start it.

   **Expected:**
   * the upgrade completes without an error;
   * `backups/` holds a new backup, whose `PRAGMA user_version` is the old schema;
   * the new database is at version 32, with the same counts;
   * a project's scope history shows the schema-19 notes where URL exclusions existed;
   * *Verify* in the evidence register reports no problem.
4. **Do not open the upgraded database with the old build**: `d1cf064` would open it without a warning and misbehave (UPGRADE.md). To go back, restore the pre-upgrade backup (section 10).

## 8. Backup and restore in the installed build

1. *Settings → Local data → Back up*, then *Restore* from that file and restart.

   **Expected:** the restore notice appears, and the projects, findings, evidence and scope are as before.
2. Try to restore a text file renamed `.db`.

   **Expected:** it is refused with a reason, and the current database is untouched.
3. Restore the pre-upgrade backup from section 7.

   **Expected:** it is accepted; Cyber Hub upgrades it again at the next start.

## 9. Uninstall

| Package | Do | Expected |
|---|---|---|
| NSIS | *Settings → Apps → Cyber Hub → Uninstall*. If the uninstaller offers to delete the application data, leave that **unchecked** | The program, its Start-menu entry and its uninstall entry are gone. `%APPDATA%\dev.cyberhub.workstation` stays, and stored credentials stay in Credential Manager |
| NSIS, disposable VM only | Uninstall again after reinstalling, **checking** the option to delete the application data, if it is offered | The data folder is removed: only do this where no real data exists |
| MSI | *Settings → Apps*, or `msiexec /x Cyber.Hub_0.1.0_x64_en-US.msi` | As NSIS without the option; the data folder stays |
| deb, rpm | `dpkg -l \| grep -i cyber` gives the package name; `sudo apt remove <name>` or `sudo dnf remove <name>` | The binaries and the desktop entry are gone; `~/.local/share/dev.cyberhub.workstation` stays |
| AppImage | Delete the file | The data stays |

**Then reinstall.** The kept data opens at schema 32 without another upgrade.

## 10. Rollback

* **Before publishing** (the draft is the release candidate):
  1. delete the draft release;
  2. a candidate's tag (`v0.1.0-rc.N`) can stay, as a record; or delete the tag with `git push --delete origin <tag>` and `git tag -d <tag>`;
  3. turn `RELEASE_PUBLISHING` off;
  4. fix the problem on `release/v0.1.0`, then tag the next candidate and build again.

  Nothing reached users.
* **After publishing:**
  1. Set the release back to a draft (`gh release edit v0.1.0 --draft=true`). The feed then no longer offers it, but anyone who already downloaded it keeps that copy.
  2. Fix forward with 0.1.1, signed with the same update key. Never publish other binaries under a version that was already published.
* **A user's data after a bad upgrade:** Cyber Hub has no automatic rollback (SECURITY.md).
  1. Close it.
  2. Restore the pre-upgrade backup from `backups/` with the earlier build.

  Data created after the upgrade is not in that backup.
* **Signing keys:** if a key may have leaked, follow `SIGNING_SETUP.md`, section 8, before anything else.

## 11. Evidence to keep

Keep it in `evidence/M10/<date>/`, and record it in `RELEASE_READINESS.md`:

* the run and draft URLs, `SHA256SUMS.txt`, `latest.json`;
* the output of every verification command in section 5;
* for each package: screenshots of installation (SmartScreen, UAC, installer), the first start, the upgrade counts before and after, the backup file name, restore, uninstall and reinstall;
* Defender's history after ten minutes and after a reboot;
* the tester, the date, and each machine's operating-system build.

## 12. Publish (the owner's decision, after everything above passes)

**A release candidate is never published.** Its draft names `v0.1.0-rc.N` in its tag and in `latest.json`'s download addresses, and the workflow refuses it. To release the version the candidate validated (Mission 11):

1. Delete the first candidate's draft (the draft of `v0.1.0`). The workflow refuses a tag that already has a release, drafts included.
2. Point `v0.1.0` at the validated commit. That tag exists on `add894e` and the repository is public, so this is a rewrite of a public tag: do it knowingly, `git tag -f -a v0.1.0 -m "Cyber Hub 0.1.0" <commit>` then `git push --force origin v0.1.0`. Or release a later version (0.1.1) instead.
3. Run section 3 with the stable tag. The build is new, so its checksums differ from the candidate's: repeat section 5 and a short installation check of each package.
4. Then publish in one of the two ways below.

Publish in one of two ways:

* publish the reviewed draft in GitHub's interface;
* or run the workflow by hand again with *draft* **unchecked** and *confirm* `v0.1.0`. It checks the tag again before making the release public.

**Afterwards:**

1. Turn `RELEASE_PUBLISHING` off.
2. Check that `https://github.com/<owner>/<repo>/releases/latest/download/latest.json` returns the manifest.
3. Check that an installed 0.1.0 reports that it is up to date.
