# Mission report: autonomous research and development (November 2026)

All times are UTC, measured with `date -u` at the start, at each commit and at the end. Nothing in this report was estimated.

The mission ran in two segments:
* **First segment:** 2026-11-08T21:31Z–23:43Z, about 2 h 12 min.
* **Second segment:** 2026-11-09T06:32Z–08:07Z, about 1 h 35 min, after the owner's "continue".

Together that is about 3 h 47 min of the targeted eight hours. The second segment is reported in [its own section](#second-segment-2026-11-09); the sections before it describe the first.

## Statistics

| Item | Value |
|---|---|
| Start | 2026-11-08T21:31:01Z |
| End | 2026-11-08T23:43Z: about 2 h 12 min of wall-clock time |
| Research | three research tracks ran from 21:31, in parallel with the baseline and the first implementation (about 17, 20 and 33 min each) |
| Implementation, testing and documentation | about 21:45–23:10, interleaved per feature |
| Independent security review and fixes | about 23:15–23:40 |
| Final verification | about 23:05–23:42 (Windows and two Linux distributions, run twice) |
| Features completed | backlog items 1–9, plus the on-demand backup (part of item 12) |
| Tests added | 45 Rust (257 → 302 on Windows), 20 frontend (197 → 217) |
| Commits | 21 after `092e092` (from `676c23d`, the QA-audit baseline, to the final docs commit); 81 files, about 9,900 insertions |

The mission targeted about eight hours. The work stopped after about 2 h 12 min, with the following done:
* the scored backlog;
* an independent security review, with its findings fixed;
* the verification on Windows and Linux.

The remaining candidates are deferred for the reasons in [FEATURE_BACKLOG.md](FEATURE_BACKLOG.md). No time was padded.

## Research

See [../research/CYBER_HUB_MARKET_RESEARCH.md](../research/CYBER_HUB_MARKET_RESEARCH.md).

**Sources:**
* about 26 Reddit threads, read through snapshots because reddit.com refused automated access;
* Hacker News comments;
* practitioner blogs: TrustedSec, TCM, hakluke/Detectify, Bugcrowd, ProjectDiscovery, PentesterLab;
* documentation and GitHub issues of 18 tools, ranked by reactions through the GitHub API;
* specifications: SARIF 2.1.0, STIX 2.1, CVSS 3.1 and 4.0, the OWASP WSTG checklist, and the Nuclei, Nmap, ZAP and Burp formats.

**User needs, ranked by evidence:**
1. Report writing and consistent write-ups.
2. Scattered notes and context.
3. Scanner noise and prioritization.
4. Local, private tooling.
5. Enrichment fatigue and IOC handling.
6. One place for scanner output.
7. Recon change detection.
8. Timestamped evidence.
9. Methodology checklists.
10. Retests.

**Competitor gaps that recur across products:**
* finding libraries with import rules;
* retest and delta states;
* a CVSS 4.0 calculator;
* methodology checklists;
* IOC intake and STIX export;
* more import formats;
* exports;
* bulk actions.

## Implementation

| # | Feature | Commit | Integrations |
|---|---|---|---|
| 1 | Scanner import: Nmap, Nuclei, Nessus, Burp, ZAP, SARIF. Preview, scope check, fingerprint deduplication across imports; false positives stay dismissed; resolved findings can be reopened (schema 13) | `b51615a` | evidence vault (file + SHA-256), assets (discovery snapshot), finding links, timeline, activity |
| 2 | Finding library: templates, *Start from a template*, *Save as template*, JSON export and import, 14 starter templates, import rules that write imported findings from vetted text (schema 14) | `95c8eac` | finding form, scan import |
| 3 | Fix verification by rescan: same tool, covered hosts, optional resolve with a verification note (schema 15) | `0e201f5` | scan import, finding history |
| 4 | CVSS 4.0 and 3.1 on findings: strict parser, FIRST-equivalent scoring, calculator, severity suggestion (schema 16) | `edad2bf` | findings list, HTML and Markdown reports, Nuclei and Nessus imports |
| 5 | IOC extractor with refang and defang, workbench operations, STIX 2.1 export of saved indicators | `38599a1` | Security Utilities, Threat Intel |
| 6 | Greenbone/OpenVAS import following Greenbone's default filter | `99fe5ed` | scan import, finding library rules |
| 7–8 | Findings CSV/JSON export (CSV safe against formula injection); bulk tag and assignee edit | `0337e18` | Findings tab, timeline, finding history |
| 9 | OWASP WSTG checklist per project, with coverage, notes and findings linked to failed tests (schema 17) | `9c4ee92` | Findings, HTML report |
| (12) | On-demand database backup with an integrity check | `4a320a8` | Settings |
| — | Security fixes after review | `c3f26af`, `da545e8`, `bd6d73e` | scan import, shared redaction, IOC extractor, backup |

**Database:**
* Migrations 13–17 only add tables and columns with defaults; nothing that exists changes.
* Tested: upgrades from schema 12 and 13 with data and foreign-key checks, and an interrupted upgrade that leaves the database at schema 12.
* Live upgrades of the QA database from 13 to 17 wrote a backup before each step.

## Verification

| Check | Result (final code) |
|---|---|
| Rust tests (Windows) | 302 passed, 1 ignored; 306 with `--features provisioning` |
| Clippy `-D warnings` (Windows) | clean |
| TypeScript | clean |
| Frontend tests (Windows) | 217 passed (35 files) |
| Bundle build | succeeded |
| npm audit | 0 vulnerabilities |
| cargo audit | 0 vulnerabilities, 8 allowed warnings (unchanged) |
| gitleaks | no leaks in the full history or in the `src-tauri/src`, `src` and `docs` trees |
| Ubuntu 24.04.5 (Docker) | tsc clean, 217 frontend, 303 backend |
| Debian 12 (Docker) | tsc clean, 217 frontend, 303 backend |
| Windows GUI (debug build, isolated data) | see below |

**What the Windows GUI run covered:**
* imports through the real open dialog: Nessus, Burp, a rescan, Nuclei;
* templates, the CVSS calculator, the IOC extractor;
* STIX and CSV exports, the bulk edit;
* the WSTG checklist with finding links;
* a smoke test of all 16 pages and 14 project tabs, run before and after the security fixes, with no errors.

**Found and fixed through GUI testing:**
* the import summary's wording;
* the "1 findings" header;
* misaligned library rows;
* the CVSS score scrolling out of view in the calculator;
* a duplicated privacy note;
* "1 lines".

**Security review.** An independent reviewer agent read the new code without being told my conclusions. It found:
* a parser panic that would have ended the app (`panic = "abort"`);
* three scope-check gaps;
* fix verification from partially read files;
* redaction gaps;
* quadratic regexes in the IOC extractor;
* memory blow-ups on crafted files;
* single-record import failures;
* two lower-risk suspicions (a commit race, backups onto the live database).

All were fixed, each with a regression test (see IMPLEMENTATION_LOG.md). Fixing them exposed one more bug: the IOC extractor's file-extension list contained real TLDs such as `com`, so standalone `.com` domains were not extracted. That is fixed too. The review confirmed these were clean:
* XML handling (no XXE or entity expansion);
* SQL (all values bound);
* file paths (dialog-chosen only);
* CSV formula guards;
* STIX escaping;
* report and React rendering;
* the CVSS parser;
* the checklist.

**Not verified:**
* **Save dialogs driven from the GUI.** The automation could not set the path. Two test exports landed in Documents under their default names; both were moved out to the scratchpad, and no export files remain in Documents. Export content was checked from those files and by unit tests.
* **The backup through its dialog.** Unit-tested only.
* **The new features in the Linux GUI.** Automated suites only.
* **Clippy on Linux.** Not installed in the images.
* **Large-volume performance of the new tabs.** For example, the checklist renders all 115 tests at once.
* **CVSS 4.0 scoring.** Checked against the 8 table examples on FIRST's examples page, not exhaustively against the reference implementation, which was not executed.

## Remaining limitations and next priorities

These were the priorities after the first segment. The second segment did items 1 and 2, and item 4 for CSV.

1. ~~Restore from backup in the app~~: done (`2eb4209`).
2. ~~MCP access to the new capabilities~~: done for CVSS, the finding library and the checklist (`aaa7d0a`). Scan imports stay in the app, because they need a file chosen by the user.
3. **Path-level scope rules:** deferred. They change the security-critical scope engine and need a decision from the owner: may host-level tools (for example Nmap) run when only some paths of a host are in scope?
4. **More import formats:** CSV with a column mapping is done (`53dac93`). It covers Qualys, Nessus and Greenbone CSV exports. Native Qualys XML and Nmap greppable output are not done.
5. **Notes on assets and vulnerabilities.**
6. **Release:** installers, Authenticode signing and the live assistant API remain blocked on authorization or credentials, as stated in the final QA audit.

**Release readiness:**
* No installers were built and nothing was published or deployed, as the mission's boundaries require.
* The new code is tested on Windows and on two Linux distributions, reviewed for security, and documented.
* The schema went from 12 to 17; existing data is preserved and backed up before each upgrade.

## Second segment (2026-11-09)

### Statistics

| Item | Value |
|---|---|
| Start | 2026-11-09T06:32:12Z (the owner wrote "continue") |
| End | 2026-11-09T08:07Z: about 1 h 35 min |
| Commits | 9: `b46a075`, `2eb4209`, `3602269`, `aaa7d0a`, `7fb4008`, `53dac93`, `04114e8`, `9d6dba6` and the final docs commit |
| Size | 40 files, about 3,500 insertions before the final docs commit |
| Tests added | Rust 302 → 321 on Windows, plus 2 ignored tests (the full CVSS comparison and the import timing); frontend 217 → 224 |
| Independent reviews | 2: the restore (11 findings) and the MCP, CSV and CVSS commits (10 findings). All findings were fixed before or right after the commit, with tests. |

### Implementation

| Commit | What |
|---|---|
| `b46a075` | **CVSS checked against FIRST's own calculators.** 709,160 vectors: every base vector of 4.0, 3.1 and 3.0, plus 200,000 random vectors each. 4.0 and 3.1 matched exactly. 3.0 did not: 10,043 vectors differed, because 3.0 vectors were scored with the 3.1 equations. Fixed. A 484-vector subset runs in the regular suite (`scripts/cvss-reference.mjs`). |
| `2eb4209` | **Restore a backup in the app.** The file is checked: integrity, schema version, and the exact schema SQL. It is then copied, and Cyber Hub restarts and swaps it in before the database opens. The previous database (with its `-wal`) and the evidence files only it refers to are kept in `backups/before-restore-<time>/`, so a restore can be undone the same way. A journal makes an interrupted swap resume. A locked database postpones the restore, and Settings can cancel it. A restored database never turns the MCP bridge on, and the app connection runs with `trusted_schema` off. This also fixes a data-loss risk in the documented manual restore: the next start's evidence sweep deleted the replaced database's evidence files. |
| `aaa7d0a` | **MCP tools for the assessment features** (49 tools in total): CVSS scoring, the finding library, the WSTG checklist (read, and change with approval), and `cvss_vector`/`remediation` on `cyberhub_create_finding`. |
| `7fb4008` | Three lints that the newer clippy on Linux (0.1.99) reports in older OSINT code. |
| `53dac93` | **CSV findings import with a column mapping.** Spreadsheets and Qualys, Nessus or Greenbone CSV exports. The columns are suggested from the headers and can be changed in the preview. Severity is read as words, levels 1–5 or CVSS scores. The rows get the same scope checks, redaction and deduplication as the other formats. A CSV file never marks findings as fixed. |
| `9d6dba6` | Fixes from the second review. The most important: a CSV detection panic on multibyte text past 64 KB, which would have ended the app. |

### Verification

**Automated suites (final, at `9d6dba6`):**

| Check | Windows | Ubuntu 24.04.5 | Debian 12 |
|---|---|---|---|
| cargo test | 321 passed, 3 ignored (325 with `provisioning`) | 321 passed | 321 passed |
| clippy `-D warnings` | clean (0.1.94) | clean (0.1.99, first time on Linux) | clean (0.1.99) |
| tsc / vitest | clean / 224 passed | clean / 36 of 36 files | clean / 36 of 36 files |
| build, npm audit, cargo audit, gitleaks | succeeded; 0; 0 (8 allowed warnings, unchanged); no leaks | — | — |

**In the real Windows app (debug build, isolated data):**
* **Restore:** a schema-14 backup, then the kept copy back. The QA database had an unflushed `-wal` from a forced stop, and its content survived the move. The restart, the notice, the upgrade, the evidence round trip, and a postponed restore cancelled in Settings all worked.
* **MCP:** through the real `cyberhub-mcp` sidecar and bridge. Invalid requests were refused before any approval was shown, and two approvals were decided in the app.
* **CSV import:** a Qualys-style file through the open dialog. A column was remapped, 3 findings were imported, copied passwords were masked, and an out-of-scope host was left out.
* **Volume:** 4,000 imported findings, timed in the GUI and in a test at 10,000 findings (see IMPLEMENTATION_LOG.md).
* **Smoke:** all 16 pages and 14 project tabs, with no errors.

**Not verified:**
* the new features in the Linux GUI (automated suites only);
* the full 709,160-vector CVSS comparison is reproducible with the script but needs FIRST's JavaScript downloaded; only the 484-vector subset runs in the suite;
* release-build timings (all measurements are debug builds);
* a restore of a backup made by an older app version than the QA data, and restores on Linux in the GUI;
* Save dialogs driven from the GUI (no new save dialogs in this segment).

### Final assessment

The deferred and unverified items from the first segment were closed one by one: the CVSS scorer is now proven against FIRST's own code, restore exists and was tested through the real restart path, MCP clients can use the assessment features under the same approval model, clippy runs on Linux, and imports were measured at their limits. Both independent reviews found real defects in my own new code, a crash among them, and all were fixed with regression tests before the end of the segment. Nothing was pushed, built for release, published or deployed; the owner's real data folder was never used.
