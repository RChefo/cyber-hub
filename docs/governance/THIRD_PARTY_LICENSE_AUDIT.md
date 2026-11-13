# Third-party license audit

**Audit date:** 2026-11-13 (Mission 12), on the default branch after commit `8e309ca`, ExploitX 0.1.0. **This is an engineering audit, not legal advice.** It records what each component declares and what was verified by hand, and it lists what remains open.

**ExploitX's own license:** none selected yet ([LICENSE_COMPARISON.md](LICENSE_COMPARISON.md)). Compatibility below is assessed against the candidates there; it is not final until the owner selects one.

> **Mission 13 (2026-11-13):** the website moved to its own repository, RChefo/ExploitX-Web, with its lockfile, GSAP, the React Bits `OrbitImages` files and the unlicensed Ink Orbit component. The findings about them below are a record of this audit; they now apply to that repository (its THIRD_PARTY_NOTICES.md), and this repository's license check covers the app only.

## Method

| Part | How it was checked |
|---|---|
| Rust crates | `cargo metadata --locked` for every platform, and per platform (`x86_64-pc-windows-msvc`, `x86_64-unknown-linux-gnu`) to tell what ships in the binaries from what only builds or tests them. The license is the crate's declared SPDX expression. Some crates were opened in the Cargo registry (AWS-LC's license file, NOTICE files) |
| npm packages | The lock files' `license` fields (from each package's `package.json`): `package-lock.json` for the app, `website/package-lock.json` for the website. Runtime and development packages are told apart by the lock file. Installed packages were scanned for NOTICE files |
| Copied code | Every file under `src/components/vendor/` and the website's `src/components/ui/`, against the upstream license files (GitHub, npm and unpkg, 2026-11-13) |
| Assets and data | Fonts, icons, app icons, screenshots and the data catalogs, against their packages and `THIRD_PARTY_NOTICES.md` |
| Native libraries | The Windows installers' WebView2 handling; the deb and rpm dependencies; the second release candidate's **AppImage**, unpacked, with its bundled libraries and their Debian copyright files |
| History | Only two files were ever deleted in the repository's history (`src/modules/settings/McpPanel.tsx`, `website/src/lib/useRelease.ts`), both the project's own; no copied code was removed |

**Automated from now on:**
* `node scripts/licenses.mjs check` runs in CI ("Repository checks"). It fails when a dependency's license is missing or outside `scripts/license-policy.json`, unless a reviewed exception covers it.
* `node scripts/licenses.mjs report` regenerates the full inventories:
  * [Rust crates](third-party/RUST_CRATES.md): 649 crates; 333 ship on Windows, 396 on Linux;
  * [npm packages of the app](third-party/NPM_PACKAGES.md): 229 packages, 106 runtime;
  * npm packages of the website: 228 packages, 7 runtime (inventory removed when the website moved).

  Each entry gives the version, license, source, whether it is direct or transitive, and where it is used.

"Ships" in the Rust inventory means compiled into the target's graph through normal dependencies. It is an upper bound: a few crates counted there end up as unused code.

## Summary

| Area | Result |
|---|---|
| Rust crates (649) | All permissive, MPL-2.0 (file-level copyleft), Unicode or CDLA data licenses. No GPL, AGPL, LGPL-only, source-available or unknown license. Two crates offer LGPL only as one alternative among MIT and Apache-2.0 (`r-efi`, UEFI code that the Windows and Linux builds do not use) |
| npm packages of the app (229) | Runtime: MIT, Apache-2.0, ISC, BSD, 0BSD, MPL-2.0 and OFL-1.1 (fonts). Development only: the same, plus CC-BY-4.0 (`caniuse-lite` data) and BlueOak-1.0.0 (`minimatch`) |
| npm packages of the website (228) | As the app, plus **GSAP's proprietary "no charge" license** (`gsap`, `@gsap/react`): website only, a reviewed exception |
| Copied UI components (10 files) | MIT (4 sources). **React Bits: MIT + Commons Clause, not open source** (5 files). **Ink Orbit: no license found** (1 website file) |
| Fonts and icons in the app | OFL-1.1 (IBM Plex Sans, JetBrains Mono), ISC (Lucide) |
| Data catalogs | CC BY-SA 4.0 (OWASP WSTG, ASVS), MITRE ATT&CK terms, BSD-2-Clause (FIRST CVSS calculator data): all with notices in `THIRD_PARTY_NOTICES.md` |
| Native libraries | Windows: none bundled. deb and rpm: none bundled (system packages). **AppImage: 171 bundled libraries, mostly LGPL, one GPL-2.0-or-later (`libjbig`)** |
| Binary notices | **Not shipped with the installers yet** |

## Direct dependencies

### Rust (`src-tauri/Cargo.toml`)

"Windows" and "Linux" give where the crate is used: *ships* (linked into the binaries), *build* (build scripts), *test*.

| Crate | Version | License | Kind | Windows | Linux |
|---|---|---|---|---|---|
| boreal | 1.4.0 | MIT OR Apache-2.0 | normal | ships | ships |
| chrono | 0.4.45 | MIT OR Apache-2.0 | normal | ships | ships |
| dbus-secret-service | 4.1.0 | MIT OR Apache-2.0 | normal | — | ships |
| dirs | 7.0.0 | MIT OR Apache-2.0 | normal | ships | ships |
| encoding_rs | 0.8.44 | (Apache-2.0 OR MIT) AND BSD-3-Clause | normal | ships | ships |
| futures-util | 0.3.34 | MIT OR Apache-2.0 | normal | ships | ships |
| getrandom | 0.3.4 | MIT OR Apache-2.0 | normal | ships | ships |
| goblin | 0.10.7 | MIT | normal | ships | ships |
| gtk | 0.18.2 | MIT | normal | — | ships |
| hcl-rs | 0.20.0 | MIT OR Apache-2.0 | normal | ships | ships |
| hickory-resolver | 0.26.3 | MIT OR Apache-2.0 | normal | ships | ships |
| hmac, md-5, sha1, sha2 | 0.12.1, 0.10.6, 0.10.7, 0.10.9 | MIT OR Apache-2.0 | normal | ships | ships |
| ipnet | 2.12.2 | MIT OR Apache-2.0 | normal | ships | ships |
| keyring | 3.6.3 | MIT OR Apache-2.0 | normal | ships | ships |
| libc | 0.2.191 | MIT OR Apache-2.0 | normal | ships | ships |
| once_cell | 1.21.4 | MIT OR Apache-2.0 | normal | ships | ships |
| pulldown-cmark | 0.13.6 | MIT | dev | test | test |
| quick-xml | 0.42.0 | MIT | normal | ships | ships |
| regex | 1.13.1 | MIT OR Apache-2.0 | normal | ships | ships |
| reqwest | 0.13.5 | MIT OR Apache-2.0 | normal | ships | ships |
| ring | 0.17.14 | Apache-2.0 AND ISC | dev (and through rustls) | ships | ships |
| rmcp | 3.9.0 | Apache-2.0 | normal | ships | ships |
| rusqlite (bundled SQLite: public domain) | 0.41.1 | MIT | normal | ships | ships |
| rustls, rustls-native-certs | 0.23.46, 0.8.5 | Apache-2.0 OR ISC OR MIT | normal | ships | ships |
| semver, serde, serde_json | 1.0.28, 1.0.229, 1.0.154 | MIT OR Apache-2.0 | normal | ships | ships |
| sysinfo | 0.36.1 | MIT | normal | ships | ships |
| tauri, tauri-plugin-dialog, -opener, -single-instance, -updater | 2.12.5, 2.8.4, 2.7.2, 2.5.5, 2.14.1 | Apache-2.0 OR MIT | normal | ships | ships |
| tauri-build | 2.7.4 | Apache-2.0 OR MIT | build | build | build |
| thiserror | 2.0.21 | MIT OR Apache-2.0 | normal | ships | ships |
| tokio, tokio-util | 1.54.1, 0.7.20 | MIT | normal | ships | ships |
| tokio-rustls | 0.26.6 | MIT OR Apache-2.0 | normal | ships | ships |
| toml | 1.1.8 | MIT OR Apache-2.0 | normal | ships | ships |
| url | 2.5.8 | MIT OR Apache-2.0 | normal | ships | ships |
| which | 8.0.6 | MIT | normal | ships | ships |
| windows-sys | 0.60.2 | MIT OR Apache-2.0 | normal | ships | — |
| x509-parser | 0.18.1 | MIT OR Apache-2.0 | normal | ships | ships |
| yaml-rust2 | 0.13.0 | MIT OR Apache-2.0 | normal | ships | ships |
| zeroize | 1.9.1 | Apache-2.0 OR MIT | normal | ships | ships |

### npm (`package.json`)

| Package | Version | License | Scope |
|---|---|---|---|
| @fontsource/ibm-plex-sans, @fontsource-variable/jetbrains-mono | 5.3.0 | OFL-1.1 | runtime (fonts in the interface) |
| @heroui/react, @heroui/styles | 3.2.7 | Apache-2.0 | runtime |
| react-aria, react-aria-components, @react-aria/ssr, @react-aria/utils, @internationalized/date | 3.53.1, 1.22.1, 3.10.1, 3.34.1, 3.12.4 | Apache-2.0 | runtime |
| @tauri-apps/api, @tauri-apps/plugin-opener | 2.12.4, 2.7.2 | Apache-2.0 OR MIT | runtime |
| react, react-dom | 19.3.1 | MIT | runtime |
| echarts | 6.1.0 | Apache-2.0 (with a NOTICE file) | runtime |
| recharts | 3.10.1 | MIT | runtime |
| motion | 14.9.0 | MIT | runtime |
| lucide-react | 1.67.0 | ISC | runtime |
| clsx, tailwind-merge | 2.1.1, 3.7.0 | MIT | runtime |
| @tauri-apps/cli | 2.12.4 | Apache-2.0 OR MIT | development (builds the installers) |
| vite, vitest, @vitejs/plugin-react, tailwindcss, @tailwindcss/vite | 8.3.5, 5.1.0, 6.2.1, 4.3.4, 4.3.4 | MIT | development |
| typescript | 7.0.2 | Apache-2.0 | development |
| @types/node, @types/react, @types/react-dom | 26.6.6, 19.3.0, 19.3.0 | MIT | development |

## Transitive dependencies that need attention

| Component | License | Where | Assessment |
|---|---|---|---|
| **aws-lc-rs / aws-lc-sys** 1.19.0 / 0.47.0 | ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND … MIT-0 | Ships (reqwest's rustls feature enables rustls' AWS-LC provider) | Permissive. AWS-LC is a fork of BoringSSL, itself a fork of OpenSSL. Its license file keeps each source's license: Apache-2.0, ISC, MIT, BSD-3-Clause and MIT-0. Binary redistribution needs those notices |
| **ring** 0.17.14 | Apache-2.0 AND ISC | Ships | Permissive; notices |
| **cssparser, cssparser-macros, selectors** (servo), **dtoa-short**, **option-ext** | MPL-2.0 | cssparser and selectors ship through `tauri-utils`; option-ext through `dirs` | File-level copyleft: unmodified files from crates.io. Compatible with all four candidate licenses (MPL-2.0 §3.3 for the GPL). Recipients of binaries must be told where to get these files' source |
| ICU4X crates (`icu_*`, `zerovec`, `yoke`, `litemap`, …) | Unicode-3.0 | Ships | Permissive; notice |
| **webpki-root-certs** 1.0.11 | CDLA-Permissive-2.0 | Ships | Mozilla's root certificates as data; permissive data license |
| **moka** 0.12.16, **tlsh2** 1.1.0 | (MIT OR Apache-2.0) AND Apache-2.0; Apache-2.0 OR BSD-3-Clause | Ship | Both carry **NOTICE files** (Apache-2.0 §4(d)): include them with binaries |
| **es-toolkit** 1.53.1 | MIT | Runtime npm | Its NOTICE carries Lodash's copyright and MIT notice |
| r-efi 5.3.0, 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | Other platforms only | MIT or Apache-2.0 can be chosen; not compiled for Windows or Linux |
| encoding_rs, brotli, alloc-*, subtle | including BSD-3-Clause | Ship | Permissive; notices |

## Copied UI components

| File(s) | Upstream | License, verified | Attribution | Redistribution | Issues |
|---|---|---|---|---|---|
| `src/components/vendor/shadcn/chart.tsx` | shadcn/ui | MIT, Copyright (c) 2023 shadcn (repository license) | Source note in the file; license text in `THIRD_PARTY_NOTICES.md` (Mission 12) | Permitted | None |
| `src/components/vendor/untitledui/FeaturedIcon.tsx` | Untitled UI React | MIT, Copyright (c) 2025 Untitled UI | As above | Permitted | None |
| `src/components/vendor/evilcharts/echarts-chart.tsx` | EvilCharts | MIT, Copyright (c) 2026 Gurbinder | As above | Permitted | None |
| `src/components/vendor/lightswind/DotPattern.tsx` | Lightswind (npm `lightswind` 3.2.5) | **MIT declared in the npm metadata only**: the package has no license file, no repository and no copyright line | As above | Permitted under the declared license | Low: ask the author for a license file, or replace the 30-line component |
| `src/components/vendor/reactbits/BranchedMenu.tsx`, `BranchedMenu.css`, `CountUp.tsx` (app); `website/src/components/ui/OrbitImages.jsx`, `OrbitImages.css` (website) | React Bits | **MIT + Commons Clause License Condition v1.0**, Copyright (c) 2026 David Haz, verified in the upstream repository | Source note and license in each file's header (Mission 12); license text in `THIRD_PARTY_NOTICES.md` | Only **as part of an application, website or product**; not alone; no selling or sublicensing | **High** for licensing: see below |
| `website/src/components/ui/ink-orbit-features.tsx` (website only) | Ink Orbit (Kedhareswer Naidu, 21st.dev), repository `Kedhareswer/21stdev-my-components` | **No license found**: GitHub reports none and there is no license file (checked 2026-11-13) | Source note (Mission 12) | **Not established** | **High** for the website: replace, or obtain the author's permission |

### React Bits and the Commons Clause

React Bits' license (retrieved 2026-11-13) grants rights to "use, copy, modify, merge, publish, and distribute the Software **as part of an application, website, or product**". Its Commons Clause restriction adds: "You may use this Software, including for any commercial purpose, so long as you do not sell, sublicense, or redistribute the components themselves - whether alone, in a bundle, or as a ported version."

What that means for ExploitX:
* **Today:** ExploitX uses and distributes the components as part of its application and website, which the license allows. The copyright and permission notice is now carried in each file and in `THIRD_PARTY_NOTICES.md`.
* **For any open-source license on the whole repository:** the Commons Clause makes these files **not open source**. The Open Source Definition does not allow restrictions on selling or field of use.
  * ExploitX cannot pass them on under MIT, Apache-2.0 or the GPL. A permissive license would grant the rights to sublicense and redistribute them alone, which React Bits forbids. The GPL forbids added restrictions.
  * A repository-wide license would therefore have to **exclude these files explicitly**, and ExploitX would then not be entirely open source.
* **Recommendation:** replace the three app files and the website's orbit component with original implementations before the license is applied. They are small:
  * `CountUp` is a number animation;
  * `BranchedMenu` is the sidebar's menu presentation;
  * `OrbitImages` is a website animation.

  The audit does not remove them on its own: replacing visible UI is a product decision.

## Assets and data

| Asset | License | Notes |
|---|---|---|
| IBM Plex Sans, JetBrains Mono (through `@fontsource`) | OFL-1.1 | Bundled into the interface. OFL allows bundling with software; the font license and copyright must accompany them (now in `THIRD_PARTY_NOTICES.md`). The fonts may not be sold by themselves |
| Lucide icons (`lucide-react`) | ISC | Bundled into the interface; notice in `THIRD_PARTY_NOTICES.md` |
| App icons (`src-tauri/icons/`, `public/logo.svg`) | Not recorded | Added in the project's first commit with no third-party source recorded. **The owner should confirm they are original work** |
| Screenshots (`design/brand/screens/`, also in the website repository) | The project's own | Real screenshots of ExploitX with demo data (docs/WEBSITE.md) |
| OWASP WSTG checklist (`src-tauri/src/methodology/wstg.json`), OWASP ASVS 5.0.0 (`src-tauri/catalog/asvs-5.0.0.json`) | CC BY-SA 4.0 | Attribution and share-alike apply to these data files; in-app attribution exists. They keep CC BY-SA under any ExploitX license |
| MITRE ATT&CK catalogs (`src-tauri/catalog/attack-*.json`) | MITRE ATT&CK terms of use | Reproduce MITRE's copyright and license; done in `THIRD_PARTY_NOTICES.md` and the app |
| FIRST CVSS v4.0 lookup data (`src-tauri/src/cvss/v4_lookup.rs`) | BSD-2-Clause (FIRST, Red Hat) | Notice in `THIRD_PARTY_NOTICES.md`; "CVSS is owned by FIRST and used by permission" |
| Tools catalog (`src-tauri/catalog/tools.json`), resources, payload examples | The project's own text | They describe and link third-party tools and sites; no third-party text was found copied |

## Native libraries

* **Windows (NSIS, MSI):**
  * no third-party native library is bundled. The installers download and run Microsoft's **WebView2** bootstrapper when WebView2 is missing (Tauri's default), so ExploitX does not redistribute WebView2;
  * the Rust crates above are linked statically into the binaries.
* **deb and rpm:** they depend on the system's `libwebkit2gtk-4.1-0` and `libgtk-3-0` and bundle no system library.
* **AppImage:** it bundles **171 shared libraries** from the build machine (Ubuntu 22.04) with **98 Debian copyright files**, so the license texts are present. Among them:
  * **LGPL-2.0/2.1/3.0-or-later:** WebKitGTK, JavaScriptCore, GTK 3, GLib, GStreamer, libsoup, GnuTLS, Nettle, Pango, cairo, libsecret, systemd's libraries, and others. Distributing them requires making their **source code** available (LGPL §6: the source with the binaries, or a written offer valid for three years), and allowing them to be replaced. Being separate shared libraries, they can be replaced.
  * **`libjbig.so.0`** (jbigkit, **GPL-2.0-or-later**), loaded through libtiff by GTK's TIFF image loader. Distributing it requires its source (GPL §3). Whether ExploitX, which reaches it only through that chain of plug-ins, forms a combined work with it is a legal question this audit does not answer.
  * The remaining libraries are permissive, as their copyright files list them: ICU, libxml2, libpng, libjpeg, libwebp, SQLite, HarfBuzz, libffi and others.

  **Before the AppImage is distributed publicly:** publish the corresponding source for the bundled LGPL and GPL libraries (or a written offer), or remove `libjbig` and the TIFF loader from the AppImage, or ship only the deb and rpm for Linux. **Owner decision.**

## Binary distribution: notices

The installers and packages do **not yet include third-party license texts**. MIT, BSD, ISC, Apache-2.0, OFL and the data licenses all require their notices to accompany binary copies, and Apache-2.0 requires NOTICE contents: ECharts, moka, tlsh2, and es-toolkit's Lodash notice. `THIRD_PARTY_NOTICES.md` covers the copied code, fonts, icons and data, but not every crate and npm package.

**Recommendation before a public release:**
* generate a complete notices file (every shipped crate's and runtime npm package's license text, plus the NOTICE files);
* install it with each package, for example through Tauri's `bundle.resources`;
* show it from the app's About section.

Generating it can extend `scripts/licenses.mjs`. **Not done in Mission 12:** it changes the installers' contents, which needs a new candidate build.

## Website

`website/` (not deployed, not part of the app):
* **GSAP** (`gsap` 3.15.1, `@gsap/react` 2.1.2) uses the GSAP Standard "no charge" license. It is free, commercial use included, but it is proprietary and has a field-of-use restriction on tools that compete with Webflow's visual animation builder. The website uses it to animate its own pages, which the license permits. GSAP is installed from npm and not redistributed in this repository. It is a reviewed exception in the license policy.
* If the repository adopted the GPL, the website would combine with a proprietary library. In that case, license the website separately or replace GSAP.
* The React Bits and Ink Orbit components above.

## Unresolved issues

| # | Issue | Severity | Owner of the decision |
|---|---|---|---|
| 1 | No project license is selected; the repository's code is not open-source licensed | High | Owner ([LICENSE_COMPARISON.md](LICENSE_COMPARISON.md)) |
| 2 | React Bits components (5 files) are under MIT + Commons Clause: not open source; they block a repository-wide OSI license unless replaced or excluded | High | Owner (replace recommended) |
| 3 | The website's Ink Orbit component has no license | High (website) | Owner: replace or obtain permission |
| 4 | The AppImage bundles LGPL libraries and GPL-2.0-or-later `libjbig` without a source offer | High before public AppImage distribution | Owner; possibly legal advice |
| 5 | Installers do not ship third-party license texts and NOTICE contents | Medium before a public release | Engineering, in the next candidate |
| 6 | Lightswind's MIT is declared only in npm metadata, without a license file or copyright line | Low | Engineering: ask the author, or replace |
| 7 | The app icons' authorship is not recorded | Low | Owner: confirm |
| 8 | The dependency licenses come from metadata; a crate whose metadata is wrong would not be caught | Low | Re-audit on major dependency changes |

**Compatibility conclusion.** Once issues 2 and 3 are resolved, the dependency set allows each of the four candidate licenses as ExploitX's own license. Issues 4 and 5 are distribution obligations that apply whatever license is chosen. No compatibility is claimed until the owner selects the license and these items are closed.
