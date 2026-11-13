# License comparison for ExploitX

**Status (Mission 15, 2026-11-13): decided and applied.** The owner approved the **Apache License 2.0** for both repositories (RChefo/ExploitX and RChefo/ExploitX-Web), with contributions under the Developer Certificate of Origin. Mission 15 applied it: `LICENSE` (the official text), `NOTICE`, the license fields of the manifests, an SPDX line in every source file, the README and CONTRIBUTING ("Applying the license", below). This document keeps the comparison and the reasons for the choice. **It is not legal advice.**

The Apache License covers ExploitX's own code, documentation and assets. Third-party code and data keep their own licenses, and the AppImage's system libraries keep theirs, with their obligations ([DISTRIBUTION_LICENSE_COMPLIANCE.md](DISTRIBUTION_LICENSE_COMPLIANCE.md)).

## What ExploitX is, for licensing purposes

* A **desktop application** for Windows and Linux (Tauri 2: Rust backend, React frontend), distributed as installers and packages. It is not a hosted network service.
* Its MCP server (`cyberhub-mcp`) is a local sidecar. It reaches the app through a loopback bridge on the same machine and serves no remote users.
* It **bundles third-party code**:
  * about 330–400 Rust crates linked into the binaries (Windows and Linux respectively);
  * npm packages bundled into the interface;
  * four small copied UI components, all MIT;
  * fonts;
  * data catalogs (OWASP WSTG and ASVS, MITRE ATT&CK, FIRST CVSS).
  * The Linux AppImage additionally carries system libraries such as WebKitGTK and GTK.

  The audit is in [THIRD_PARTY_LICENSE_AUDIT.md](THIRD_PARTY_LICENSE_AUDIT.md).
* It is maintained by one owner and is opening to **external contributions**.

## The candidates

| | MIT | Apache-2.0 | GPL-3.0 | AGPL-3.0 |
|---|---|---|---|---|
| Kind | Permissive | Permissive | Strong copyleft | Strong copyleft, plus network use |
| OSI-approved | Yes | Yes | Yes | Yes |
| Length and complexity | Very short | Long, precise | Long | Long |
| Others may use it commercially, in closed products | Yes | Yes | Yes, but a distributed product must be under the GPL with its source | As GPL-3.0, and also when offered over a network |
| Main obligation when redistributing | Keep the copyright and permission notice | Keep the license, notices and the NOTICE file; mark modified files | Provide the complete corresponding source under GPL-3.0; no added restrictions | As GPL-3.0, plus offer the source to users who interact with a modified version over a network (§13) |
| Derivative works | Any license | Any license (with the notices) | Must be GPL-3.0 (or compatible) when distributed | Must be AGPL-3.0 when distributed or offered over a network |
| Express patent license from contributors | No (at most implied) | **Yes** (§3), ended for anyone who sues over the work's patents | Yes (§11), with patent-retaliation and anti-discrimination terms | Yes, as GPL-3.0 |
| Terms for contributions | Not stated (GitHub's Terms: inbound = outbound) | **Stated** (§5: contributions are under the license unless said otherwise) | Not stated (GitHub's Terms: inbound = outbound) | As GPL-3.0 |
| Trademarks | Silent | Not granted (§6) | Not granted (§7 allows terms on trademarks) | As GPL-3.0 |
| Compatibility, as the outer license | Combines with almost anything | Combines with permissive and weak-copyleft code; Apache-2.0 code can go into GPL-3.0 projects, not GPL-2.0-only ones | Needs GPL-3.0-compatible inputs; incompatible with GPL-2.0-only code | As GPL-3.0; GPL-3.0 and AGPL-3.0 may be combined (§13 of both) |
| Typical effect on adoption | Highest | Very high; often preferred by companies for its patent terms | Lower in companies that ship closed products | Lowest: many companies do not allow AGPL code |

### MIT

* **Simplicity:** one paragraph of permission, one condition (keep the notice), one disclaimer. Easy for contributors and users to understand.
* **Commercial reuse:** unrestricted. Anyone, including competitors, may sell or close a derivative.
* **Attribution:** the copyright and permission notice must stay in copies and substantial portions.
* **Patents:** no express grant. A contributor holding a patent on their contribution gives no explicit license to it, and there is no termination clause against patent suits.

### Apache License 2.0

* **Permissive reuse:** as MIT, with more precise terms.
* **Explicit patent grant (§3):** each contributor licenses the patents their contribution necessarily infringes. **Patent termination:** a licensee who sues claiming the work infringes a patent loses that patent license. For a security tool used inside companies, this clarity is often a reason it is preferred.
* **NOTICE (§4(d)):** if the project has a NOTICE file, redistributions must carry its attribution notices. §4 also requires a copy of the license and marking modified files.
* **Contributions (§5):** submissions are under the license unless the contributor says otherwise. This gives the project clear inbound terms without a separate agreement.
* **Compatibility:**
  * Apache-2.0 code can be included in GPL-3.0 projects, though not in GPL-2.0-only ones.
  * As the outer license, it accepts the permissive and MPL-2.0 dependencies ExploitX has.

### GNU GPL v3

* **Copyleft:** anyone who distributes ExploitX or a derivative, as source or binaries, must license it under GPL-3.0 and provide the complete corresponding source, and may not add restrictions.
* **Distribution and source:** installers (NSIS, MSI, deb, rpm, AppImage) are distribution. Each release must come with the source or a written offer, which for a public GitHub repository is straightforward.
* **Derivative works:** modified versions that are distributed must stay GPL-3.0. This is the "protection against incompatible redistribution": no one can ship a closed fork.
* **Commercial distribution:** allowed, including selling, but always with the source. If the owner wants to sell a closed or differently licensed edition later, they need the rights to every contribution, through a contributor license agreement.
* **Compatibility:** Apache-2.0, MIT, BSD, ISC, Zlib and MPL-2.0 (through MPL §3.3) code can be included. GPL-2.0-only code cannot.
* **Installation information (§6)** applies to "User Products" (consumer devices). It does not restrict desktop installers.

### GNU AGPL v3

* **Network use (§13):** if a modified version is offered to users over a network, those users must be able to get its source.
* **Relevance to ExploitX: low.** ExploitX runs on the user's own computer, and its MCP server serves local clients over loopback. §13 would matter only if someone turned it into a hosted service. AGPL would protect against that case, at the cost of adoption: many organisations forbid AGPL software.

### Also worth knowing

* **MIT OR Apache-2.0** (dual licensing at the recipient's choice) is the Rust ecosystem's convention; most of ExploitX's crates use it. It combines MIT's compatibility (including with GPL-2.0) with Apache-2.0's patent grant for those who choose it.
* **MPL-2.0** (file-level copyleft) keeps changes to ExploitX's own files open while letting others combine the code with closed code. It is a middle path the brief did not ask about, listed for completeness.

## What the dependency audit means for the choice

The details are in [THIRD_PARTY_LICENSE_AUDIT.md](THIRD_PARTY_LICENSE_AUDIT.md).

* **Package dependencies:** every Rust crate and npm package of the app has a permissive license, MPL-2.0, a permissive data license or a font license (OFL-1.1). That is enforced in CI by `scripts/license-policy.json`. These are compatible with each of the four candidates as ExploitX's own license.
* **Data files** keep their own licenses whatever ExploitX chooses:
  * WSTG and ASVS are CC BY-SA 4.0, which can be combined one way into GPL-3.0 works and stays on the files under a permissive choice;
  * MITRE ATT&CK has its own terms;
  * FIRST's CVSS data is BSD-2-Clause.

  A NOTICE file or the README must say that these files are excluded from ExploitX's own license.
* **Former blockers, resolved in Mission 14:**
  * the **React Bits components** (three files in the app, two on the website; MIT + Commons Clause, which forbids redistributing the components alone and is therefore not open source) were replaced by original components (`NavTree`, `AnimatedNumber` in the app; `ScreenOrbit` on the website). Before that, no open-source license could have covered them: a permissive license would have granted rights React Bits withholds, and GPL-3.0 §10 forbids further restrictions;
  * the website's **Ink Orbit** section, from a repository without a license, was replaced by an original component (`EvidenceFlow`).
* **Remaining exception, website only:** the website depends on **GSAP** (free, proprietary "no charge" license), a reviewed exception in its license policy. It does not affect the app. For the website, it is compatible with a permissive license (GSAP stays under its own terms and is installed from npm, not copied); under the GPL the website's bundle would combine with a proprietary library, so the website would need a separate license or GSAP's replacement (CSS animations could do most of its work).
* **Independent of the choice:** distributing the **AppImage** means distributing its bundled LGPL libraries and one GPL-2.0-or-later library (`libjbig`), which carries source-availability obligations of its own. Since Mission 14 the release workflow ships their copyright files inside the AppImage and their source packages next to it ([DISTRIBUTION_LICENSE_COMPLIANCE.md](DISTRIBUTION_LICENSE_COMPLIANCE.md)). These obligations are the same under each candidate: the libraries stay under their own licenses, separate and replaceable.

## Contributions, ownership and commercial plans

* **Without an agreement,** each contributor keeps the copyright of their contribution and licenses it under the project license ("inbound = outbound"). Apache-2.0 states this in §5; GitHub's Terms of Service say the same for repositories with a license.
* **A Developer Certificate of Origin** (a `Signed-off-by:` line in each commit) adds a record that the contributor had the right to submit the code. It is lightweight, and needs no legal entity.
* **A Contributor License Agreement** (CLA) is needed only if the owner wants to **relicense later** or **sell a differently licensed edition**: for example a GPL community edition plus a commercial license. A CLA discourages some contributors and needs administration.
* **Future commercial offerings:**
  * Under a permissive license the owner can still sell signed builds, support, hosted services or add-ons, and so can anyone else.
  * Under the GPL, others can sell too, but only with the source.
  * Dual licensing works only with a CLA.
* **The name and logo** are not licensed by any of these licenses. Apache-2.0 says so explicitly. A short trademark note can say how forks may use the name.

## Recommendation

**Apache License 2.0** for ExploitX's own code, with a NOTICE file. Re-evaluated after Mission 14: the recommendation stands, and the replacements removed the only third-party reason that could have forced a different choice. Recommended together with:
* keeping the data files' licenses explicit (they are excluded from ExploitX's own license);
* a Developer Certificate of Origin for contributions ([CONTRIBUTOR_TERMS.md](CONTRIBUTOR_TERMS.md));
* a short trademark note;
* the same license for the website repository, with GSAP documented as a third-party exception.

**Why**, against the project's likely goals:

| Goal | MIT | Apache-2.0 | GPL-3.0 | AGPL-3.0 |
|---|---|---|---|---|
| Community adoption | ++ | ++ | + | − |
| External contributions with clear terms | + | ++ (§5) | + | + |
| Commercial reuse (by companies, and by the owner) | ++ | ++ | + (with source) | − |
| Protection against closed redistribution | − | − | ++ | ++ |
| Patent clarity | − | ++ | ++ | ++ |
| Long-term maintainability (compatibility with the dependency set) | ++ | ++ | + | + |

* Apache-2.0 serves adoption, contributions, commercial reuse and patent clarity best. Its explicit patent grant and contribution terms matter for a security tool that companies will evaluate.
* **The trade-off:** Apache-2.0 does not stop a company from shipping a closed fork. **If preventing closed derivatives matters more to the owner than adoption, choose GPL-3.0-or-later** instead; it is compatible with the current dependencies.
* **AGPL-3.0 is not recommended:** its network clause does not fit a desktop app, and it reduces adoption.
* **"MIT OR Apache-2.0"** is a reasonable alternative if compatibility with GPL-2.0 projects matters.

## Applying the license (done in Mission 15)

| Step | Done |
|---|---|
| `LICENSE` at the root: the official Apache License 2.0 text | Yes, SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`, as published at <https://www.apache.org/licenses/LICENSE-2.0.txt>. CI fails if it changes |
| `NOTICE`: the project's copyright line, what stays under other licenses, the name and logos | Yes |
| Metadata | Yes: `"license": "Apache-2.0"` in `package.json`; `license = "Apache-2.0"` in `src-tauri/Cargo.toml` and `src-tauri/fuzz/Cargo.toml`. Tauri takes the packages' license field (rpm `License:`) from Cargo.toml. `tauri.conf.json` has the copyright string, shown in the Windows file properties. No `licenseFile`: Apache-2.0 needs no acceptance, so the installers show no license page |
| SPDX lines | Yes, `SPDX-License-Identifier: Apache-2.0` in every project source file (475 files). Copied code keeps its own: MIT for `src/components/vendor/`, BSD-2-Clause for `src-tauri/src/cvss/v4_lookup.rs`. CI fails on a missing or wrong line (`scripts/licenses.mjs check`) |
| Data files | Unchanged: OWASP CC BY-SA 4.0, MITRE ATT&CK terms, FIRST BSD-2-Clause, listed in `scripts/license-assets.json` and NOTICE |
| The packages | `LICENSE` and `NOTICE` installed with every package, next to `THIRD_PARTY_LICENSES.txt` (also in `/usr/share/doc/cyber-hub/` and `/usr/share/licenses/cyber-hub/`); Settings > About names the license |
| README, CONTRIBUTING, DCO check | Yes ([CONTRIBUTOR_TERMS.md](CONTRIBUTOR_TERMS.md)) |
| The website repository | The same license, `LICENSE`, `NOTICE`, metadata and SPDX lines; GSAP stays a third-party exception under its own license |

The project's own assets (icons, the brand folder, the favicon) are under Apache-2.0 too (`scripts/license-assets.json`). The ExploitX name and logos are not licensed for other uses beyond what Apache-2.0 section 6 allows. Nothing here is a trademark registration or clearance.

## Decision

Approved by the owner for Mission 15 (2026-11-13): **Apache-2.0 for RChefo/ExploitX and RChefo/ExploitX-Web, contributions under the DCO.**
