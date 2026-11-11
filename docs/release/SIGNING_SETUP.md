# Signing setup (M9)

This is the owner's guide to the signing Cyber Hub needs before its first release. It is based on the review of the signing architecture in Mission 8. [SIGNING.md](../SIGNING.md) compares the Authenticode certificate routes, and [UPDATER.md](../UPDATER.md) covers the update key.

**Status:**

* Update signing is configured in the release workflow, and its key exists on the owner's computer.
* Authenticode signing is **not configured**, and no certificate exists.
* The workflow has never run.

In Mission 8:

* no certificate, key or signing secret was created, requested, read or copied;
* nothing was signed;
* the update key's file and its Credential Manager entry were not opened.

## 1. What is signed, and how

| What | Format | Tool and key | Where | State |
|---|---|---|---|---|
| Update packages: the NSIS and MSI installers, AppImage, deb and rpm | A minisign signature (Ed25519) in a `.sig` next to each package, whose trusted comment names the version | `tauri build` with `bundle.createUpdaterArtifacts`, reading `TAURI_SIGNING_PRIVATE_KEY` and `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`. The public key (key ID `957F3F7D955C72FA`) is compiled into the app from `plugins.updater.pubkey` | The release workflow's build job, in the protected `release` environment | Configured, never run |
| The update manifest `latest.json` | Lists each package's URL and signature | `scripts/updater-manifest.mjs`, which verifies every signature against the compiled public key and the version | The publish job | Configured, never run |
| Windows executables and installers: `cyber-hub.exe`, `cyberhub-mcp.exe`, `*-setup.exe`, `*.msi` | Authenticode, SHA-256, RFC 3161 timestamp | `signtool`, or Microsoft Artifact Signing, through Tauri's `bundle.windows.certificateThumbprint` or `bundle.windows.signCommand` | To be added to the build job | **Not configured. Release blocker.** |
| Linux packages: AppImage, deb, rpm | No package signature | Integrity comes from `SHA256SUMS.txt`, GitHub's per-asset digests (both checked by the publish job), and the update signatures | The publish job | By design for 0.1.0. Optionally, sign `SHA256SUMS.txt` with a GPG key (section 7) |

`cyberhub-mcp` is not a Tauri `externalBin`. It is a second binary of the app crate, which the bundler ships next to `cyber-hub` (`scripts/build-sidecar.mjs` explains why). Whether Tauri's Windows signing also signs that binary has not been verified, so the verification step below must check it explicitly.

## 2. Development builds and release builds

| | Development build | Release build |
|---|---|---|
| Made by | `npm run tauri dev`, `cargo build` | The release workflow, `tauri build` |
| Update endpoint | None (`plugins.updater.endpoints` is empty), so it never checks for updates | The repository's feed, compiled in by the workflow (`--config`) |
| `.sig` files | None | One per package |
| Authenticode | None: `Get-AuthenticodeSignature` says `NotSigned` (checked on the Mission 8 development build) | `Valid`, signed by the owner's certificate, with a timestamp |
| `CYBERHUB_DATA_DIR` | Honoured | Ignored: the real data folder is used |

A local `tauri build` stops when no update key is set, because `createUpdaterArtifacts` is on in `tauri.conf.json`. That is intended. To build packages, use the release workflow (`RELEASE_CANDIDATE_PROCEDURE.md`).

## 3. How failures stop a release

* The build job fails at once if either update secret is missing. It also fails if any package lacks its `.sig`. Nothing is uploaded.
* The publish job fails if any signature does not verify against the compiled public key, or does not name the version.
* The release stays a draft if an uploaded file's digest differs from `SHA256SUMS.txt`.
* It also stays a draft if the tag no longer names the commit that was built (Mission 8).
* For Authenticode, once configured, `tauri build` fails when the signing command fails. The verification step in section 6 must fail the job as well, so that a file that was signed but not timestamped, or not signed at all, never reaches the draft.

## 4. What to obtain

### Windows: a code-signing certificate

* **A publicly trusted code-signing certificate.** It must chain to a root in the Microsoft Trusted Root Program. OV is enough: EV no longer gives instant SmartScreen reputation.
* **Its key lives in certified hardware.** CA/Browser Forum rules have required this since June 2023: a cloud HSM, an HSM or a USB token. **New certificates are not issued as downloadable `.pfx` files.** The routes, in order of fit:
  1. Microsoft Artifact Signing, if the owner is eligible;
  2. an OV certificate with a cloud HSM, such as DigiCert KeyLocker, SSL.com eSigner, GlobalSign or Sectigo, or Azure Key Vault Premium with a CA that supports it;
  3. a USB token, which needs a self-hosted runner.

  See SIGNING.md, section 1.
* **Validity:** at most 460 days (ballot CSC-31, since March 2026). Plan a yearly renewal.
* **Timestamp authority:** your CA's RFC 3161 service, such as `http://timestamp.digicert.com` or `http://ts.ssl.com`. Artifact Signing uses `http://timestamp.acs.microsoft.com`.

### Updates

The existing minisign key pair. There is no CA, and trust is the public key in the app. **Do not generate a new key for the first release**: installed copies trust only `957F3F7D955C72FA`.

### Linux

Nothing is required. A GPG key is optional (section 7).

## 5. Secrets, names and storage

All signing material lives only in the `release` environment, never in repository-wide secrets. Set the environment up first (`GITHUB_FIRST_RUN.md`, section 3):

* required reviewers;
* deployment limited to the branches release runs start from: `main` and `release/*`. A manual run runs on the branch chosen under *Run workflow*, and only manual runs reach this environment;
* no administrator bypass.

| Name | Kind | Format | Needed for |
|---|---|---|---|
| `TAURI_SIGNING_PRIVATE_KEY` | Environment secret | The text content of `cyberhub-updater.key`, as `tauri signer generate` wrote it (password-encrypted) | Update signatures |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | Environment secret | The key's password | Update signatures |
| `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` | Environment variables (not secret) | GUIDs | Artifact Signing or Key Vault, through GitHub OIDC (`azure/login` with `id-token: write` on the build job only). Prefer this to a client secret |
| The vendor's API credentials, such as eSigner's `ES_USERNAME`, `ES_PASSWORD`, `ES_TOTP_SECRET`, `CREDENTIAL_ID` | Environment secrets | As the vendor documents | A cloud HSM other than Azure |

UPDATER.md ("Release secrets") gives the commands that copy the update key and its password into the environment without printing them.

**Storage:**

* Keep the update key file and its password apart.
* Keep both in a password manager, and also offline.
* Never put a key, a password or a `.pfx` in the repository, an issue, a log, an artifact or a cache. The release workflow already refuses caches and checks that no update key is committed.
* When a certificate route is chosen, extend that check to `*.pfx` and `*.p12` files.

## 6. CI configuration to add when the route is chosen

Nothing here has been added. Each piece needs a run on GitHub to test.

1. **A release-only signing configuration**, such as `src-tauri/tauri.release-signing.json`, passed to `tauri build` with a second `--config` in the build job's Windows leg only. Development builds then never try to sign. Choose one of:

   * Thumbprint route, with the certificate in the runner's store (cloud HSM clients install it so):

     ```json
     { "bundle": { "windows": { "certificateThumbprint": "<SHA-1 thumbprint>", "digestAlgorithm": "sha256", "timestampUrl": "<RFC 3161 URL>", "tsp": true } } }
     ```

     `tsp: true` makes Tauri use RFC 3161 (`/tr`) rather than the legacy timestamp protocol.
   * Command route (Artifact Signing or a vendor CLI), where `%1` is the file:

     ```json
     { "bundle": { "windows": { "signCommand": "<the vendor's signing command> %1" } } }
     ```

     The command must timestamp with RFC 3161 itself.
2. **A verification step after `tauri build`** on the Windows runner, failing the job unless each file is `Valid`, signed by the expected certificate and timestamped. The files are:
   * `src-tauri\target\release\cyber-hub.exe`;
   * `src-tauri\target\release\cyberhub-mcp.exe`;
   * the NSIS `*-setup.exe` and the `*.msi`.

   ```powershell
   foreach ($f in $files) {
     $s = Get-AuthenticodeSignature $f
     if ($s.Status -ne 'Valid' -or -not $s.TimeStamperCertificate -or $s.SignerCertificate.Thumbprint -ne $env:EXPECTED_THUMBPRINT) { throw "$f is not signed as expected: $($s.Status)" }
   }
   ```

   If `cyberhub-mcp.exe` is unsigned, sign it in a step before `tauri build`: the bundler copies the file as it is.
3. **For OIDC:** `permissions: id-token: write` on the build job only, and `azure/login` pinned by commit like every other action.
4. **A guard test** in `src-tauri/src/ci_tests.rs` that keeps the verification step and refuses signing outside the `release` environment. The existing guards already refuse secrets outside it.

Never sign in `ci.yml`, for a pull request, or with a cache in the job.

## 7. Verify a release independently

Anyone can check a downloaded release with these.

**Checksums** (Windows PowerShell, then Linux):

```powershell
Get-FileHash .\Cyber.Hub_0.1.0_x64-setup.exe -Algorithm SHA256   # compare with SHA256SUMS.txt
```

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing
```

**Authenticode** (Windows SDK's `signtool`, or PowerShell):

```powershell
signtool verify /pa /all /v .\Cyber.Hub_0.1.0_x64-setup.exe
Get-AuthenticodeSignature .\Cyber.Hub_0.1.0_x64-setup.exe | Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
```

What to expect:

* **Signed:** `Successfully verified` with `sha256` and `RFC3161`, and `Status: Valid` with the publisher and a timestamp certificate. The commands were checked in Mission 8 against a signed third-party binary.
* **Unsigned:** `No signature found` and `Status: NotSigned`. Mission 8's development build gave this.
* **Inside the installed application:** check `cyber-hub.exe` and `cyberhub-mcp.exe` the same way.

**Update signatures:** with the repository at the release's tag, run:

```bash
node scripts/updater-manifest.mjs validate --manifest latest.json --assets <folder with the downloaded files> --require windows-x86_64-nsis,windows-x86_64-msi,linux-x86_64-appimage,linux-x86_64-deb,linux-x86_64-rpm
```

It checks each signature against the public key in `tauri.conf.json` and the manifest's version, and never needs the private key.

**Optional GPG signature of the checksums**, if the owner adds one:

```bash
gpg --verify SHA256SUMS.txt.asc SHA256SUMS.txt
```

## 8. Rotation and expiry

* **Authenticode certificate.** Renew about a month before expiry, keeping the same publisher name so that SmartScreen reputation carries over. Timestamped signatures stay valid after the certificate expires.
  * If the key may be compromised, have the CA revoke the certificate, choose a revocation date before any doubtful signature, and sign the next release with the new certificate.
* **Update key.** It does not expire. Rotate it only through an overlap release (UPDATER.md, "Key rotation").
  * Installed copies older than that release must update through it.
  * If the key leaks, rotate at once and publish a notice: the updater has no revocation.
* **GitHub secrets.** Replace the update key password and any vendor credential at once if a log, an artifact or a person may have seen it. OIDC leaves no long-lived secret to rotate.

## 9. Owner checklist

1. Choose the certificate route and complete the identity validation (SIGNING.md).
2. Create the `release` environment with reviewers and the branch rule, and add the two update secrets (GITHUB_FIRST_RUN.md).
3. Add the release-only signing configuration and the verification step (section 6), then push and run the workflow by hand on the release-candidate tag. Leave *draft* checked.
4. Download the draft's files and verify them as in section 7, on a clean Windows machine too.
5. Record the evidence in RELEASE_READINESS.md (M9).
