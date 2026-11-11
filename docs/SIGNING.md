# Windows code signing (Authenticode)

Cyber Hub's Windows installers and executables are **not yet Authenticode-signed**. This is a release blocker: in the staging test Microsoft Defender quarantined an unsigned build (see [UPDATER.md](UPDATER.md)). Authenticode signing is separate from update signing. The update key (`TAURI_SIGNING_PRIVATE_KEY`) proves that an update comes from the Cyber Hub release pipeline. An Authenticode certificate proves the publisher to Windows, SmartScreen and Defender. Both are needed.

This document describes the procedure. Nothing here has been bought or configured. No certificate, key or secret exists in the repository, and none may be added to it.

Facts checked in November 2026. Recheck the certificate authority's and Microsoft's current terms before buying.

## 1. Choose a certificate route

Since June 2023, the CA/Browser Forum code-signing requirements oblige certificate authorities to generate and keep the private keys of publicly trusted code-signing certificates in certified hardware (FIPS 140-2 level 2 or Common Criteria EAL4+). That hardware is a USB token, an HSM or a cloud HSM. **A downloadable `.pfx` is no longer issued for new certificates**, so the PFX-in-a-secret pattern from older guides (including the PFX example in the Tauri documentation) does not apply to a new certificate.

Since March 1, 2026 (ballot CSC-31), a publicly trusted code-signing certificate is valid for at most **460 days** (OV and EV). Plan a yearly renewal. Timestamping (step 3) keeps already-signed files valid after the certificate expires.

| Route | Who can use it | Key storage | Fit for Cyber Hub |
|---|---|---|---|
| **Microsoft Artifact Signing** (formerly Azure Trusted Signing; generally available since January 2026) | Organizations in the USA, Canada, EU and UK. Microsoft documents individual developers as USA and Canada only, and reports from 2026 say individual onboarding was paused. Check before relying on it. | Microsoft-managed HSM; short-lived certificates renewed automatically | Recommended **if eligible**: no hardware to manage, works from GitHub-hosted runners, and Tauri supports it through `signCommand` |
| **OV certificate with a cloud HSM** (for example DigiCert KeyLocker, SSL.com eSigner, GlobalSign or Sectigo cloud signing, or Azure Key Vault Premium/Managed HSM with a CA that supports it) | Organizations, and individuals where the CA allows it | Cloud HSM; signing through the vendor's tool | Recommended otherwise. It works from CI. |
| OV or EV certificate on a USB token | Anyone the CA validates | Physical token | Needs a self-hosted Windows runner with the token attached. Avoid for CI. |

**EV certificates no longer give instant SmartScreen reputation.** Microsoft changed this in 2024 and its documentation now says so. EV still means stronger identity validation, which some enterprise buyers ask for, but it is not worth paying extra for to avoid SmartScreen warnings.

## 2. What must be signed

Every Windows binary that ships, before it is packed:

* `cyber-hub.exe` (the application)
* `cyberhub-mcp.exe`, the MCP sidecar. It is not a Tauri `externalBin`: it is a second binary of the app crate, which the bundler ships next to the application (`scripts/build-sidecar.mjs` explains why). This was corrected in Mission 8.
* the NSIS installer (`*-setup.exe`) and the MSI (`*.msi`)

Tauri's bundler runs the configured signing for the application and the installers. **Whether it also signs the crate's second binary has not been verified for this project**, and the Tauri documentation does not say. Check it with the verification commands below after the first signed build; `docs/release/SIGNING_SETUP.md` (section 6) gives a verification step for the workflow. If the sidecar is unsigned, sign it in a step before `tauri build` (the bundler copies the already-signed file).

Update packages are produced from these signed files, so the updater keeps working unchanged. The update signature covers the signed installer.

## 3. Configure Tauri

In `src-tauri/tauri.conf.json`, under `bundle.windows`, use **either** a certificate in the Windows certificate store:

```json
"certificateThumbprint": "<SHA-1 thumbprint of the code-signing certificate>",
"digestAlgorithm": "sha256",
"timestampUrl": "http://timestamp.digicert.com"
```

**or** a custom command (cloud signing), where `%1` is the file to sign:

```json
"signCommand": "artifact-signing-cli -e https://<region>.codesigning.azure.net -a <account> -c <certificate-profile> -d \"Cyber Hub\" %1"
```

The thumbprint is not a secret, but keep the configuration in a release-only override (`tauri build --config src-tauri/tauri.release-signing.json`) so development builds do not try to sign.

Always timestamp, with an RFC 3161 server from your certificate authority. A timestamped signature stays valid after the certificate expires. An untimestamped one stops validating on the certificate's expiry date. The equivalent `signtool` options are:

```powershell
signtool sign /fd SHA256 /tr <RFC 3161 timestamp URL> /td SHA256 /sha1 <thumbprint> /d "Cyber Hub" <file>
```

## 4. Secrets and CI

* Signing runs only in the existing protected `release` environment of `.github/workflows/release.yml`, in the build job. This is the job that already receives the update key, and only for version tags, never for pull requests.
* Store only what the chosen route needs. For Artifact Signing or Azure Key Vault, prefer **GitHub OIDC federated credentials** (`azure/login` with `id-token: write`) over a client secret. Otherwise store `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_CLIENT_SECRET` as environment secrets. For a vendor cloud HSM, store the vendor's API credentials. Scope the identity to signing only.
* Never write a key, password or token to the log, an artifact, the repository or a cache. The workflow already refuses caches in release jobs and checks that no private update key is committed. Extend that check to any `.pfx` or `.p12` file.
* Rotate a credential immediately if a log or artifact may have exposed it, and revoke the certificate through the certificate authority if its key may be compromised.
* Add the signing step to the workflow only after the route is chosen and the identity exists. Until then the workflow stays as it is, and **no installer should be distributed**.

## 5. Verify every signed file

After the build and before publishing, verify every file from section 2. Make this a failing step in the workflow:

```powershell
signtool verify /pa /v /tw <file>          # /pa: Authenticode policy; /tw: warn if not timestamped
Get-AuthenticodeSignature <file> | Format-List Status, StatusMessage, SignerCertificate, TimeStamperCertificate
```

`Status` must be `Valid`, `SignerCertificate` must be Cyber Hub's certificate, and `TimeStamperCertificate` must be present. Also install the signed NSIS build on a clean Windows machine and confirm that:

* the UAC prompt (MSI) and the file properties (Digital Signatures tab) name the publisher;
* Microsoft Defender does not quarantine the application after the first start or after an update. Repeat the update test from UPDATER.md with signed builds.

## 6. SmartScreen and Defender

* SmartScreen reputation is per file and publisher. **Each new build starts with little or no reputation**, so the first users of a new release may still see "Windows protected your PC" until enough people have downloaded it. A consistent signing identity carries reputation over to later releases faster.
* Do not change the signing identity between releases without need. With a new certificate, reputation may have to be built again.
* If Defender flags a signed build, submit the files as a false positive at the Microsoft Security Intelligence submission portal (<https://www.microsoft.com/wdsi/filesubmission>), as a software developer. Attach the signed installer.
* Distribution through the Microsoft Store avoids SmartScreen warnings entirely, but it is a separate packaging and review process (MSIX) that Cyber Hub does not use.

## 7. Release checklist (signing part)

1. Choose the route (section 1) and complete the certificate authority's or Microsoft's identity validation.
2. Create the signing identity and the protected-environment secrets or OIDC trust (section 4).
3. Add the release-only Tauri signing configuration (section 3), the sidecar check, and the verification step (section 5) to the workflow.
4. Do a signed dry run on a test tag in a private fork or with publishing disabled, then verify (section 5).
5. Only then build and publish a release. This needs the owner's explicit release authorization.
