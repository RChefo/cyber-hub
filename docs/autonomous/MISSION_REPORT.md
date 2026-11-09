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

## Third segment (2026-11-09)

### Statistics

| Item | Value |
|---|---|
| Start | 2026-11-09T08:51:44Z (the owner asked to continue with path-level scope, Linux GUI verification, reliability and integration audits) |
| End | 2026-11-09T11:05Z: about 2 h 15 min |
| Commits | 10 code commits (`80f34de` … `0641a0e`) and the final docs commit |
| Size | 52 files, +2,639 / −350 lines before the docs commit |
| Tests | Rust 321 → 351 (355 with `provisioning`), 3 ignored; frontend 224 (36 files, several extended) |
| Independent reviews | 2: the path-level scope (13 findings, all fixed in `8355745`) and a cross-module reference audit (13 items: 12 fixed or documented, 1 kept by decision) |
| Linux GUI | 4 full passes of the real WebKitGTK app per distribution, offline, final: 62 of 62 checks on Ubuntu 24.04.5 and Debian 12 |

### Implementation

| Commit | What |
|---|---|
| `80f34de` | **Path-level scope.** A URL entry authorizes only its paths (same scheme, host, port; segment boundaries) and never its host. Port scans, service scans, TLS analysis, the HTTP check and host names in tool arguments need a domain, wildcard, address or range entry, and the refusal says what is missing. Excluded URLs exclude their path on every scheme and port and keep host-level operations away from their host. The HTTP request builder follows redirects only when asked, checking every hop against the scope and DNS vetting first. Identical refusals within ten minutes are counted on one history entry (schema 18). |
| `e326ace` | Imported files saved as UTF-16 or Windows-1252 (Excel) are decoded correctly. |
| `8355745` | **Fixes from the independent review of the path-level scope** (see IMPLEMENTATION_LOG.md): URLs in tool arguments are read whole and as cut at separators, attached option values and scheme-less forms are checked, unreadable URLs refuse the run, backslashes and ambiguous paths are refused, paths are also compared as servers read them, raw requests need both schemes, refusals are recorded without credentials, the clients that contact targets ignore system proxies, and schema 19 keeps URL exclusions from before schema 18 excluding their host. |
| `96fe970` | **Cross-module references:** "Add tool run" to the evidence works; deleting an asset keeps its vulnerabilities for the project; clearing the run history keeps referenced runs; OSINT entity deletion and merges update finding links, asset origins and events; an investigation cannot be moved while its project refers to it; findings created from vulnerabilities or entities are saved with their links in one transaction. |
| `d26f799` | The timeline filters in SQL and pages with a cursor (nothing hidden or skipped); the Markdown report leaves out closed findings and the project's internal notes, as the HTML report does. |
| `aa4d17d` | **Evidence integrity:** *Verify* checks stored files and text against their SHA-256; exports hash the copy and refuse a mismatch; file placement and deletion run under the database lock. MCP approvals warn about a likely duplicate finding. |
| `ce76bfa` | MCP clients cannot change archived projects (checked before the approval and again when it runs); project status changes are recorded. |
| `7e74883` | HTTP requests and TLS analyses sent to targets, and asset status changes, appear on the project timeline. |
| `6860814` | **Imported CVEs as vulnerabilities (optional):** each CVE of a recorded finding is tracked for its asset and linked to the finding, without network access during the import. |
| `0641a0e` | **Two new advisories fixed:** RUSTSEC-2026-0459 (SQLite before 3.54.0 could expose uninitialized memory through a crafted `-wal`; restore opens user-chosen files) with `rusqlite` 0.41.1 and SQLite 3.54.1, guarded by a test; RUSTSEC-2026-0462 (`rmcp` HTTP client, not compiled in) with `rmcp` 3.9.0. The MSRV moves from 1.80 to 1.89. |

### Verification

**Automated suites at `0641a0e`:**

| Check | Windows 11 | Ubuntu 24.04.5 | Debian 12 |
|---|---|---|---|
| cargo test | 351 passed, 3 ignored (355 with `provisioning`) | 351 passed, 3 ignored | 351 passed, 3 ignored |
| clippy `-D warnings` | clean (0.1.94) | clean (0.1.99) | clean (0.1.99) |
| tsc / vitest | clean / 224 passed (36 files) | clean / 36 of 36 files | clean / 36 of 36 files |
| frontend build | succeeded | succeeded (embedded in the GUI build) | succeeded (embedded in the GUI build) |
| npm audit / cargo audit | 0 / 0 vulnerabilities (8 allowed warnings, unchanged) | — | — |
| gitleaks | no leaks in this segment's commits | — | — |

**Real Linux GUI (WebKitGTK under Xvfb, offline containers, GTK dialogs answered like a user):** 62 of 62 checks on both distributions at `0641a0e`. Among them:
* **Path scope:** requests inside the path pass; outside and excluded paths are refused; a redirect leaving the path is stopped. The local server's log proves that the refused URLs were never requested.
* **CSV import:** through the GTK open dialog, with CVE tracking switched on in the real dialog.
* **Evidence:**
  * a checked export through the GTK save dialog;
  * a stored file changed behind the app's back is reported, its export is refused, and no partial file is left.
* **Assets and vulnerabilities:** the asset and vulnerability rules, timeline paging, project status history.
* **MCP through the real sidecar:**
  * a duplicate-finding warning in the approval;
  * a refused write to an archived project.
* **Backup, restore and recovery:**
  * backup through the GTK save dialog;
  * restore through the GTK open dialog, with the automatic restart and the previous database kept;
  * recovery after SIGKILL during a workflow run.

**Real Windows app (debug build, isolated copy of earlier QA data):** the copy at schema 12 was upgraded to 19 at startup, with a pre-upgrade backup and integrity ok. All 16 pages and 14 project tabs rendered with no error boundary or console error, and *Verify* reported the stored evidence intact. The owner's real database was not opened (its modification time is unchanged since 2026-11-05).

### Not verified

* **Third-party tools:** external tools' own redirect handling. Cyber Hub warns when a URL is authorized only by path; it cannot see a tool's later requests (documented as an accepted risk).
* **Timings:** release-build timings; all measurements are debug builds.
* **macOS:** out of scope by instruction.
* **Live third-party services:** NVD, EPSS and crt.sh were not called during these passes (offline containers).
* **Release artifacts:** installers, signing and published artifacts, which are not authorized.

### Remaining release blockers and decisions for the owner

1. **Release steps** need the owner's authorization: installers, signing, notarization and publishing were not done.
2. **MSRV 1.89** (`0641a0e`) is needed for the SQLite fix. CI uses `stable` and is unaffected. Anyone building with an older toolchain must update.
3. **Release notes for the scope change** must explain path-level URL entries and the schema-19 step. That step can add host exclusions; UPGRADE.md describes it.
4. **Redirect flags of external tools:** decide whether a run authorized only by path should refuse such flags (today it warns).
5. **Open audit items** (documented, lower risk):
   * the HTML and Markdown reports still have different sections;
   * checklist links cannot be cleared through the API;
   * a migration that rebuilds a referenced table would need a foreign-key-off mode;
   * the activity entry of a run whose project was deleted meanwhile is lost;
   * importing another project's run into an OSINT investigation is kept by design (toggle and confirmation).

### Final assessment

The owner's request for a conservative path-level scope model is implemented and was attacked by an independent reviewer whose 13 findings were all fixed with regression tests. Every rule the owner listed holds in both the unit tests and the real Linux GUI, where the target server's own log shows that no refused URL was requested. The cross-module audit found real defects, among them a feature that always failed, a deletion that failed with a constraint error, and a history clear that destroyed other projects' references. They were fixed with tests and verified in the GUI. Two dependency advisories published since the last segment were fixed. Nothing was pushed, released or signed, and the owner's real data was never used.
