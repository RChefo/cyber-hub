# Dependency license policy

**Since Mission 14 (2026-11-13).** This policy decides which third-party licenses ExploitX may depend on, and what happens when a new one appears. `node scripts/licenses.mjs check` enforces it in CI ("Repository checks"), on every pull request and push. **This is an engineering policy, not legal advice.** ExploitX's own license is **Apache-2.0** (Mission 15; [LICENSE_COMPARISON.md](LICENSE_COMPARISON.md)); everything allowed here is compatible with distributing ExploitX under it.

The policy itself is [`scripts/license-policy.json`](../../scripts/license-policy.json). Copied code and bundled data are listed in [`scripts/license-assets.json`](../../scripts/license-assets.json).

## What is checked

| What | Where the license comes from | Checked |
|---|---|---|
| Every Rust crate in `Cargo.lock`, for every platform: shipped, build-only and test-only | The crate's `license` field (SPDX expression), at the locked version | Each one |
| Every npm package in `package-lock.json`: runtime and development | The `license` field the lockfile records from the package's `package.json` | Each one |
| Copied code and bundled data: every tracked file under `src/components/vendor/` and `src-tauri/catalog/`, plus the other entries of `license-assets.json` | The entry's `license`, `source` and `copyright` | Each file needs an entry; each entry's path must exist |
| The notices bundled with the app, `src-tauri/resources/THIRD_PARTY_LICENSES.txt` | Generated from the packages' own license files | It must equal what `node scripts/licenses.mjs notices` would write now |
| The website (RChefo/ExploitX-Web) | Its own `scripts/license-policy.json`, same categories | In that repository's CI |

Build-only and test-only dependencies are checked too: they are part of the source a contributor installs. Only what ships (the crates compiled into the Windows or Linux binaries, the npm packages bundled into the interface) goes into the notices file.

## How a license is evaluated

The SPDX expression is parsed, not matched as text:
* `A OR B` is acceptable when either side is; `A AND B` only when both are;
* `A WITH exception` is acceptable when `A` is, or when the policy lists `A WITH exception` itself (an exception only adds permissions);
* the old Cargo form `MIT/Apache-2.0` means `MIT OR Apache-2.0`; a trailing `+` (`LGPL-2.1+`) is read as the license it extends;
* a missing, empty or unparsable expression is **unknown**.

## Categories

| Category | Licenses | Obligations | In CI |
|---|---|---|---|
| **Permissive** | 0BSD, Apache-2.0 (also WITH LLVM-exception), BSD-2-Clause, BSD-3-Clause, BSL-1.0, BlueOak-1.0.0, CC0-1.0, ISC, MIT, MIT-0, Unlicense, Zlib | Keep the copyright and license text with binary copies; Apache-2.0 also its NOTICE file. The notices file does this | Passes |
| **Attribution** | CC-BY-4.0, CDLA-Permissive-2.0, OFL-1.1, Unicode-3.0, Unicode-DFS-2016 | Credit the source and keep the license with the data or font (OFL: fonts are not sold on their own) | Passes |
| **Source obligations (file-level)** | MPL-2.0 | Recipients of binaries must be able to get the source of the MPL files; changes to those files stay MPL. ExploitX uses them unmodified from crates.io, where the source is published | Passes |
| **Data only** | CC-BY-SA-4.0, LicenseRef-MITRE-ATTACK-Terms | Only for data files listed in `license-assets.json` with `"kind": "data"`: attribution, and share-alike for changes to CC BY-SA data. Code under these licenses needs a review | Passes for data entries; otherwise review / unknown |
| **Review** | LGPL-2.1, LGPL-3.0 (only / or later), EPL-2.0, CDDL-1.0, CC-BY-SA-4.0 (outside data) | Weak copyleft or share-alike: acceptable in some forms of linking and distribution, not in others. Needs a decision before it is added | **Fails** unless a reviewed exception covers it |
| **Prohibited** | GPL-2.0 and GPL-3.0 (only / or later), AGPL-3.0, SSPL-1.0, BUSL-1.1, CC-BY-NC-4.0, CC-BY-NC-SA-4.0, LicenseRef-Commons-Clause, UNLICENSED | Strong copyleft over the whole program, source-available, non-commercial or proprietary terms: incompatible with keeping every candidate license open, or not open source at all | **Fails**. An exception needs the owner's written approval |
| **Unknown** | Anything else: missing metadata, `SEE LICENSE IN …`, licenses the policy does not list, deprecated identifiers such as `GPL-2.0` | Unknown obligations | **Fails** until the license is classified (added to a category in a reviewed pull request) or an exception covers the package |

The categories never overlap for code: nothing allowed is also in review or prohibited (tested in `scripts/licenses.test.mjs`).

## Exceptions

An exception lets one package with one exact license string pass. It lives in `scripts/license-policy.json` under `exceptions`:

```json
{
  "ecosystem": "npm",
  "name": "gsap",
  "license": "Standard 'no charge' license: https://gsap.com/standard-license.",
  "reason": "Why it is acceptable, where it is used, what would replace it (at least 40 characters)",
  "reviewed": "2026-11-13",
  "reviewBy": "2027-05-13"
}
```

* It matches the package's license **exactly**: if a new version changes its license, the exception no longer applies and CI fails again.
* `reviewed` and `reviewBy` are required dates; once `reviewBy` has passed, CI fails until someone reviews the exception again and moves the date.
* The app has **no exceptions** (Mission 14). The website has one: GSAP (`gsap`, `@gsap/react`), free but proprietary, reviewed 2026-11-13, due 2027-05-13.

## Adding a dependency

1. Check its license before adding it: `npm view <package> license`, or the crate's page on crates.io. Prefer a permissive one.
2. Run `node scripts/licenses.mjs check`. If it fails:
   * a license in **review** or **prohibited**: look for an alternative first; if there is none, open an issue explaining why the package is needed. The owner decides;
   * an **unknown** license: read the package's license file. If it is a standard license under another spelling, propose its SPDX identifier in the right category, in a pull request of its own.
3. Regenerate the notices when the shipped set changed: `node scripts/licenses.mjs notices`, and commit `src-tauri/resources/THIRD_PARTY_LICENSES.txt`.
4. Regenerate the inventories: `node scripts/licenses.mjs report` (`docs/governance/third-party/`).

Copying code or data into the repository: add an entry to `scripts/license-assets.json` with its source, license and copyright, and its notice to `THIRD_PARTY_NOTICES.md`. Code without a license, or with one outside the allowed categories, is not copied.

## Limits

* Licenses come from package metadata. A package whose metadata is wrong would pass; the audits in [THIRD_PARTY_LICENSE_AUDIT.md](THIRD_PARTY_LICENSE_AUDIT.md) check the important ones by hand.
* The license texts in the notices file are the files each package publishes. Nine packages publish none (alloc-stdlib, dlopen2, libappindicator-sys, pratt, selectors, webview2-com, webview2-com-sys, yaml-rust2 and the npm package client-only); for them the notices use the standard text of their declared license (SPDX license list 3.26.0, `scripts/license-texts/`), with the authors the package names, and say so.
* Native libraries are outside this check: the Windows and deb/rpm packages bundle none, and the AppImage's libraries are handled by `scripts/appimage-licenses.sh` ([DISTRIBUTION_LICENSE_COMPLIANCE.md](DISTRIBUTION_LICENSE_COMPLIANCE.md)).
* The project's own files are under **Apache-2.0** (Mission 15): `license-assets.json` marks the project's assets with it, and every project source file declares `SPDX-License-Identifier: Apache-2.0`. Copied code and data declare their own license, which `scripts/licenses.mjs check` compares with their entry. Apache-2.0 is never applied to third-party code or data.
