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

## Fourth segment: final pre-release hardening (2026-11-09)

### Statistics

| Item | Value |
|---|---|
| Start | 2026-11-09T11:28:28Z |
| End | 2026-11-09T12:20Z: about 50 min |
| Commits | 7: `e43f3cb`, `c4c80c8`, `a1e78ca`, `223491c`, `ca685c0`, `d6a192e` and the final docs commit |
| Tests | Rust 351 → 362 (366 with `provisioning`), 3 ignored; frontend 224 |

### Implementation

| Commit | What |
|---|---|
| `e43f3cb` | **Redirects of external tools need host-level authorization.** A run is refused when the tool would follow redirects and one of its URLs is authorized only by path, or lies on a host with an excluded path. Per-tool policies are taken from each tool's help text or source (checked in November 2026): ffuf, gobuster, feroxbuster (also bundled short options), httpx, dalfox and nikto follow when asked; nuclei, katana, sqlmap and whatweb follow unless told not to; wpscan and CeWL always follow. The refusal names the option and the way out, and the options are never changed. Explicitly authorized hosts keep the normal behaviour. Cyber Hub's own HTTP client still checks every redirect hop. |
| `c4c80c8` | **WSTG checklist links can be removed:** the Unlink button, `unlink` in the app's API, and `unlink_finding` through MCP. MCP keeps the approval and the archived-project refusal. Every checklist change is now on the project timeline, with who made it. |
| `a1e78ca` | **Project deletion during active work.** Deletion is refused while a tool run, workflow run or discovery is still running for the project (one transaction). The end of a run is recorded atomically, under the project it belongs to at that moment, so its activity entry can no longer be lost. Evidence files only the deleted project used are removed at once, unless a restore is being sorted. |
| `223491c` | **Migration rebuild mode.** No current migration needs foreign keys off: migration 9 rebuilt `findings` before any table referred to it. Rebuilds of referenced tables now have a guarded mode: foreign keys off only around their transaction, `foreign_key_check` before commit, enforcement always restored. A test fails if a migration drops a referenced table without it. |
| `ca685c0` | **One model for both reports.** HTML and Markdown have the same sections, order and terms. Only open findings are listed; closed and below-minimum findings are counted. Notes and contacts are never included. Markdown free text cannot become HTML in a viewer. |
| `d6a192e` | Release notes (`docs/releases/0.1.0.md`), release preparation, UPGRADE and SECURITY updates. |

### Verification at `d6a192e`

| Check | Windows 11 | Ubuntu 24.04.5 | Debian 12 |
|---|---|---|---|
| cargo test | 362 passed, 3 ignored (366 with `provisioning`) | 362 passed, 3 ignored | 362 passed, 3 ignored |
| clippy `-D warnings` | clean, with and without `provisioning` | clean | clean |
| tsc | clean | clean | clean |
| vitest | 224 passed (36 files) | 36 of 36 files | 36 of 36 files |
| npm audit | 0 vulnerabilities | 0 vulnerabilities | 0 vulnerabilities |
| cargo audit | 0 vulnerabilities, 8 allowed warnings | not installed in the image; the lockfile is the same | not installed in the image; the lockfile is the same |
| gitleaks | no leaks: this segment's commits, and the tracked `src-tauri/src`, `src`, `docs` and `scripts` at HEAD | — | — |
| database integrity | QA copy upgraded 12 → 19 with its backup; `integrity_check` ok, no foreign-key violations | ok after SIGKILL, no foreign-key violations | ok after SIGKILL, no foreign-key violations |
| real GUI | smoke over 16 pages and 14 project tabs, plus 7 feature checks | 69 of 69 checks | 69 of 69 checks |

**What the real app showed.** These come from the GUI passes, not only from backend tests:
* **Redirects:** an ffuf run with `-r` on a path-only URL is refused in the preview, with the option and the way out. The same run is allowed without `-r`, and allowed with `-r` when the host is authorized. A stand-in `ffuf` on the app's PATH only answers the detection; the preview never runs it.
* **Checklist:** the Unlink button removes a test's finding link, and the change appears on the timeline. Checked on Ubuntu, Debian and Windows.
* **Reports:** both formats have the same sections and findings, and neither contains contacts, notes or closed findings. Checked on all three platforms.
* **Deletion:** a project with a running workflow is not deleted; after the workflow is cancelled it is. Checked on all three platforms.
* **Earlier checks, rerun:** scope, CSV import with CVE tracking, evidence verification and checked export, MCP through the real sidecar, backup and restore with the automatic restart, and recovery after SIGKILL.

The local target server's log shows only in-scope requests.

### Security assessment

* **Scope.** Path-level authorization never implies host-level authorization. Host-level tools need explicit host or network entries. HTTP operations are checked on the exact URL, with ambiguous forms refused. Cyber Hub's own redirects are rechecked per hop. Redirects of external tools now need host-level authorization for the tools whose options are known.
* **Remaining exposure.** For tools without a policy, Cyber Hub cannot see redirects, crawling or settings inside a tool's own configuration file. These are documented as accepted risks.
* **Reports.** The HTML report is inert (escaped, CSP). Markdown cannot carry raw HTML outside code. Internal notes and contacts are never exported.
* **Data integrity.** Deletions, end-of-run records and migrations are transactional. Rebuilds of referenced tables have a guarded mode. Evidence is verifiable by SHA-256, and exports are checked.
* **Dependencies.** Audits are clean. The SQLite memory-exposure advisory that affects restore is fixed (3.54.1).
* **Testing.** No production system, real user database or third-party target was touched. All network tests used a local server in an offline container.

### Remaining limitations

* **Tool configuration files.** Cyber Hub reads redirect options on the command line, not settings inside a tool's own configuration file (for example ffuf `-config` or nuclei `-config`).
* **Tools without a policy** keep the warning instead of a refusal.
* **Linux desktops:** GNOME/KDE, Wayland and HiDPI were not tested; the Linux checks ran on a virtual display.
* **macOS** is not supported.
* **Linux images:** cargo-audit is not in them (the same lockfile is audited on Windows).
* **Release builds:** their timings and installers were not measured or built, which needs authorization.

### Release blockers

1. **Authorization:** the owner must approve building installers, signing, notarization and publishing. None was done.
2. **Version and notes:** confirm the version, then review `docs/releases/0.1.0.md`; it is published as written.
3. **Upgrade rehearsal:** upgrade a copy of a real database from the previous build, checking the schema-19 host exclusions and the restore path, as `docs/releases/README.md` describes.
4. **Build toolchains** must be at Rust 1.89 or later. (Corrected in RC0: the locked Tauri crates need **1.90**; see below.)

## Release candidate validation, RC0 (2026-11-09)

A validation pass before building a release candidate. No installer was built, nothing was signed or published, no signing key was generated or replaced, nothing was pushed, and the real user database was not opened (its modification time, 2026-11-05 17:58:24 local, is unchanged).

### Statistics

| Item | Value |
|---|---|
| Start | 2026-11-09T12:16Z, after `4361d36` |
| End | 2026-11-09T13:30Z |
| Commits | `2ad9a1c`, `ae673e5`, `f90ab22` and this report |
| Tests | Rust 362 → 365, 3 ignored; frontend 224 (36 files) |

### Baseline

Branch `release/v0.1.0`, HEAD `4361d36`, clean tree. Version 0.1.0 in `package.json`, `src-tauri/Cargo.toml` and `src-tauri/tauri.conf.json`; schema 19 (19 migrations). There is no `rust-toolchain.toml`: the minimum is `rust-version` in `Cargo.toml`.

### Changes

| Commit | What |
|---|---|
| `2ad9a1c` | **Rust 1.90, not 1.89.** The highest `rust-version` among the 627 locked registry packages is 1.90 (`tauri` 2.12.5, `tauri-build` 2.7.4, `muda` 0.20.0, `tauri-plugin-updater` 2.14.1 and other Tauri crates). `cargo +1.89.0 check --locked` refuses to build; `cargo +1.90.0 test --locked` with a fresh target folder passed (362 tests). No dependency changed. CI gets an `msrv` job on 1.90.0. |
| `ae673e5` | **Redirect rule: browser modes and files of options.** Found by reading each tool's source: the browser of nuclei `-headless` (`-dr` does not reach it), katana's headless engine (`-hl`) and httpx screenshots (`-ss`) follow redirects whatever the redirect options say. A file of options can turn redirects on (ffuf `-config`/`ffufrc`, goflags `config.yaml` for httpx, katana and nuclei, nuclei profiles, dalfox `config.toml`, nikto `nikto.conf` `CLIOPTS`, sqlmap `-c`, feroxbuster `--resume-from` and `ferox-config.toml`). On path-only and near-exclusion runs, options that load such a file are refused, and the files a tool reads on its own are named in a warning; their settings are not read. |
| `f90ab22` | **Release notes checked line by line against the code.** Added the modules the notes left out; fixed claims that were wrong (no separate range kind in the scope; refused tool runs are not in the scope history; data leaves the computer with online features; Windows 10 not tested; Node 20.19+/22.12+); listed the cargo audit warnings; replaced relative links that break where the notes are published; new known limitations. UPGRADE.md: a restore killed during its copy is dropped, not resumed. |

### Database upgrade rehearsal (Windows 11, the real app)

A copy of the schema-12 QA database was given records of every kind the old schema holds: URL exclusions and in-scope URL entries in three projects, findings linked to evidence, a tool run and an OSINT entity, vulnerabilities with events, timeline events, an investigation, workflows, MCP settings, and three evidence files (one shared by two projects). Every table and evidence hash was recorded, and the debug build upgraded it with `CYBERHUB_DATA_DIR` pointing at the copy.

* Schema 12 → 19; the pre-upgrade backup `cyberhub-schema12-<time>.db` is identical to the original, row by row.
* Apart from the tool catalog (refreshed at every start), every original row is unchanged in its original columns. The changes: `api.acme.example` (in scope, with an excluded path on it) became an exclusion; host exclusions were added for `portal.acme.example`, `198.51.100.7` and `intranet.globex.example`; four scope-history entries with source "upgrade". New tables are empty.
* 20 scope probes: no target the old rules refused is allowed, and none they allowed is refused.
* `integrity_check` ok, `foreign_key_check` empty; evidence files 3 → 3, unchanged, *Verify* finds no problem; finding links (evidence, run, OSINT entity) keep their labels; the investigation, workflows, vulnerabilities, the timeline and the MCP policy (MCP off) are intact.
* A second start: no migration, no second backup, no change.

### Backup and restore rehearsal (the real app on all three platforms)

| Case | Windows 11 | Ubuntu 24.04.5 | Debian 12 |
|---|---|---|---|
| not a database, damaged copy: refused, nothing staged | pass | pass | pass |
| restore with the automatic restart; previous database kept with the evidence only it uses | pass | pass | pass |
| undo by restoring the kept copy; evidence comes back | pass | pass | pass |
| missing and modified evidence reported; tampered file next to the backup not copied in | — | pass | pass |
| killed 0.3 s after the confirmation (copy made): applied whole at the next start | pass | pass | pass |
| killed during the copy (395 MB on Windows, 790 MB on Linux): not applied, database unchanged, journal dropped | pass | pass | pass |
| schema-12 backup restored by schema 19: upgraded after its own backup, evidence copied in and verified | — | pass | pass |
| total | 37 of 37 | 43 of 43 | 43 of 43 |

The Windows run drove the native Open dialog with Win32 messages, the Linux runs the GTK dialogs with `xdotool` in containers without network. The first Ubuntu run had 3 harness failures (an error toast taken for a confirmation, a `pkill -f` that matched its own shell); the app's behaviour in that log was correct, and the fixed script passed. A second Ubuntu run started in parallel with Debian failed at the first step because the window manager was not ready; run alone, it passed.

**Finding (not blocking):** a kill while SQLite writes the copy leaves the unfinished `.restore-<id>.partial` file (and its `-journal`) in the data folder. It is never used; only disk space is lost. Documented in UPGRADE.md and the release notes.

### Scope and redirects

* Unit tests cover path-only authorization, host-level tools, network and port checks, URL exclusions in the forms servers treat as the same path (case, percent-encoding, `;params`, `//`, a `.` suffix), refused backslashes and encoded slashes, the history limits, per-hop redirect checks and the credential headers dropped on another origin (`Authorization`, `Cookie`, `Proxy-Authorization`). Other headers, such as `X-Api-Key`, are kept, but only reach in-scope hops.
* In the real app on Ubuntu and Debian: ffuf with `-r` on a path-only URL is refused; without `-r` it is allowed and the warning names `ffufrc`; with `-config <file>` it is refused; with `-r` on an authorized host it is allowed. The local target saw only requests under the authorized `/api/` path.
* Redirect enforcement is not complete: tools without a policy keep a warning, and the settings in files of options are not read.

### Platform validation (source `ae673e5`; `f90ab22` changes documentation only)

| Check | Windows 11 | Ubuntu 24.04.5 | Debian 12 |
|---|---|---|---|
| cargo test | 365 passed, 3 ignored | 365 passed, 3 ignored | 365 passed, 3 ignored |
| clippy `-D warnings` | clean | clean | clean |
| tsc | clean | clean | clean |
| vitest | 224 passed (36 files) | 36 of 36 files | 36 of 36 files |
| npm audit | 0 vulnerabilities | 0 vulnerabilities | 0 vulnerabilities |
| cargo audit | 0 vulnerabilities, 8 warnings | not in the image (same lockfile) | not in the image (same lockfile) |
| gitleaks | all 77 commits: no leaks | — | — |
| database checks | `integrity_check` ok, no foreign-key violations after every GUI run | same | same |
| real GUI | 16 pages and 14 project tabs on the upgraded data; 7 feature checks; restore 37 of 37 | 71 of 71; restore 43 of 43 | 71 of 71; restore 43 of 43 |

* **Automated tests:** the rows above, on all three systems.
* **Real GUI:** Windows on this machine's physical desktop (WebView2, driven over CDP). Linux under a virtual display (Xvfb) with WebKitGTK, driven by WebDriver and `xdotool`.
* **Physical Linux desktop:** not tested (no GNOME/KDE session, no Wayland, no HiDPI).
* **Offline:** the Linux GUI runs had no network; the local target was a server in the container.
* **Live providers:** none. No API key was used; the project assistant was tested against a local stand-in only.

### Rust MSRV

1.90, proven both ways (1.89 refused by Cargo, 1.90.0 builds and passes the tests). `tauri-plugin-updater` 2.14.1 declares 1.90 itself, so the updater does not raise the minimum further. CI checks 1.90.0. Release builds use the latest stable toolchain (`release.yml`), which is not pinned.

### Updater integrity

* Minisign public key in `tauri.conf.json`; `requireSignedVersion`, so a signature must carry the version it was made for. Endpoints are empty in the repository and injected only by `release.yml` (`--config`); without them the app reports the updater as not configured.
* The app offers only newer stable versions (no downgrade, no pre-release), uses HTTPS only, refuses non-HTTPS download URLs, caps downloads at 512 MB and asks for a native confirmation before installing. The web view has no updater permission; it calls the backend's commands.
* Release notes from the manifest are not signed, so the Update Center shows them as plain text (control characters removed, length capped).
* `scripts/updater-manifest.mjs`: platform keys `windows-x86_64-{nsis,msi}` and `linux-x86_64-{appimage,deb,rpm}` with `{os}-{arch}` fallbacks; validation requires semver, no pre-release on stable, HTTPS, existing files named for the version, a minisign signature that verifies against the configured key with an intact trusted comment, and a signed version equal to the manifest's. Its 4 tests pass.
* `release.yml`: no permissions by default, actions pinned by SHA, the signing secrets only in the `build` job of the protected `release` environment, publishing only in the `publish` job.
* Not exercised: a real update with the production key and feed. That needs release artifacts, which were not authorized.

### Windows signing

`docs/SIGNING.md` covers the certificate routes and their 460-day validity, every file to sign (including the sidecar, whose signing by the bundler is unverified), the Tauri configuration, RFC 3161 timestamping, verification with `signtool` and `Get-AuthenticodeSignature`, SmartScreen and Defender, secrets and OIDC in CI, rotation and revocation, and a checklist. Nothing was bought, configured or signed. `release.yml` has no Authenticode step yet.

### Technical debt

| Item | Class |
|---|---|
| Windows installers and executables are not Authenticode-signed; Defender quarantined an unsigned staging build | **release blocker** (final release) |
| Release-candidate installers not built or tested: install, upgrade, uninstall, a release-profile first start, an update through a staging feed | **release blocker** (final release; needs authorization) |
| Owner review: version, release notes (published verbatim), the production updater key in the `release` environment, the feed URL | **release blocker** (final release) |
| Linux tested on a virtual display only; Windows 10 not tested | acceptable limitation (documented) |
| Settings in files of options are not read (explicit options refused where it matters, automatic files named) | acceptable limitation (documented) |
| Tools without a redirect policy keep a warning | acceptable limitation (documented) |
| Refused tool runs are not kept in the scope history | acceptable limitation (documented) |
| `.restore-<id>.partial` left after a kill during a restore's copy | acceptable limitation (documented) |
| Reading a WAL-mode backup can add `-shm`/`-wal` next to it (the file itself is unchanged) | acceptable limitation (documented) |
| Custom headers kept on cross-origin redirects of the HTTP request builder (each hop is scope-checked) | acceptable limitation |
| The project assistant was not tested against the live API | acceptable limitation (documented) |
| cargo audit: 7 unmaintained indirect crates and 1 unsound `glib` API, all from Tauri's Linux stack | acceptable limitation (documented) |
| Update notes shown as plain text, Markdown syntax visible | acceptable limitation |
| Remove partial copies at start; record refused tool runs; read known option-file formats; drop custom credential headers across origins; pin the release toolchain; pin `ci.yml` actions by SHA and add clippy there; cargo-audit in the Linux images; a physical Linux desktop pass | future improvements |

No confirmed release-blocking defect remains in the code: the redirect-rule gaps were fixed in `ae673e5`, and the MSRV in `2ad9a1c`.

### Decision

**READY FOR RELEASE CANDIDATE BUILD.** The upgrade keeps every record and refuses nothing more and allows nothing new; restores are whole or not applied on all three platforms; the scope and redirect rules hold in the real app; the automated suites pass on Windows 11, Ubuntu 24.04.5 and Debian 12.

**Not ready for final release authorization** until the three release blockers above are resolved: Authenticode signing (best set up before the release-candidate build, so the candidate exercises the final pipeline), validation of the candidate's installers and updater, and the owner's review.

## Feature expansion round (2026-11-09)

The owner reviewed RC0 and pointed out that the mission's aim was new capabilities; the RC0 segment had implemented none. This round adds seven, in the six areas the owner named, each tested and committed. It came after RC0, so the RC0 validation does not cover it.

### Statistics

| Item | Value |
|---|---|
| Time | 2026-11-09T13:31Z–16:30Z |
| Commits | 9: seven capabilities, the SARIF import fix and the Findings layout fix (plus this report) |
| Schema | 19 → 21 (`api_specs`, `sbom_docs`); the pre-upgrade backups were checked in the app |
| Tests | Rust 365 → 405 (3 ignored); frontend 224 → 243 (36 → 41 files) |
| New dependency | yaml-rust2 0.13, without default features |
| Real-app checks (Windows 11) | 125 of 125 |

### New capabilities

| Capability | Where | Commit | Verification |
|---|---|---|---|
| API security: an endpoint inventory from OpenAPI 3.x, Swagger 2.0, Postman and HAR; checks mapped to the OWASP API Security Top 10 (2023); a test plan; the scope status of each endpoint; the request builder prefilled from an endpoint | Projects → APIs | `e36a9a3` | 12 Rust and 3 frontend tests; app 20/20 |
| HTTP repeater: raw requests, resend, history, response comparison, cURL | Security Utilities → HTTP request builder | `3b9ad54` | 7 frontend tests; app 13/13 |
| SBOM analysis: CycloneDX and SPDX, license risk, NTIA minimum elements, VEX, OSV.dev lookups on request | Projects → Components | `9b32276` | 10 Rust and 4 frontend tests; app 18/18 with a live OSV.dev query |
| Container checks: Dockerfiles, Compose files, Kubernetes manifests (Pod Security Standards, CIS Docker Benchmark) | Security Utilities | `eff1b18` | 6 Rust and 3 frontend tests; app 16/16 |
| Packet capture and log triage | Security Utilities | `6074b5f` | 6 Rust and 2 frontend tests; app 19/19 |
| SARIF 2.1.0 export of findings, and an import that skips suppressed results | Projects → Findings | `8a8f588`, `d776c58` | 3 Rust tests; OASIS schema; app 14/14, round trip 12/12 |
| Kubernetes RBAC escalation paths, with bindings resolved across files | Security Utilities → Container checks | `914f50a` | 3 Rust tests; app 13/13 |

### How the needs were established

FEATURE_BACKLOG.md records the evidence: the OWASP API Security Top 10 and HAR exports from browsers and proxies; the repeater workflows of Burp Suite and ZAP; Executive Order 14028, the NTIA minimum elements, CycloneDX (ECMA-424), SPDX (ISO/IEC 5962) and OSV.dev; the Pod Security Standards, the CIS benchmarks and tools such as hadolint, kube-linter and Checkov; Wireshark and Zeek; SARIF 2.1.0 (OASIS) as ingested by GitHub code scanning. A third round looked for depth in the same areas: the Kubernetes "RBAC Good Practices" page and SARIF suppressions.

### Defects found while testing, all fixed

* Finding titles over 200 characters (absolute paths) stopped the recording of container issues (`eff1b18`).
* URL decoding in log triage could panic on multi-byte text (fixed before `6074b5f`).
* The SARIF import turned dismissed results into new findings (`d776c58`).
* The Findings panel title was squeezed to "Fin" when tags exist (`31615cc`).

### Test-harness incidents (no product impact)

* The container test scanned the Documents folder once, read-only, through the folder picker; the 4 test findings in the disposable database were deleted.
* The first SARIF export run saved its default file name in Documents; the file was moved out. The Windows dialogs are now driven by typing the path.
* The real database was never opened (modification time checked in every run).

### Limitations

* Packet capture triage reads each packet on its own: requests or TLS ClientHello messages split over several TCP segments, and IP fragments after the first, are not reassembled.
* The RBAC check does not expand aggregated ClusterRoles (`aggregationRule`); the built-in admin, edit and view roles are modeled by their documented risks; a folder scan keeps at most 20,000 RBAC objects.
* SARIF locations are derived from the finding's target text: URLs and file paths become physical locations, anything else a logical one, which code-scanning platforms may not display.
* OSV.dev lookups need the network and send package URLs (after a confirmation).

### Not verified

* Linux (Ubuntu, Debian): neither the test suites nor the GUI checks were run for this round.
* Installers, signing, updates: not built or run (not authorized).

### Assessment

The six named areas each have a working, tested capability in the app, and interoperability now goes both ways: findings leave Cyber Hub as SARIF and come back without duplicates or revived false positives. Before a release that includes this round, the RC0 checks need repeating for schema 21 and the new modules (MISSION_STATE.md, "Next action").

## Mission 2: research-driven expansion (2026-11-09)

The owner's brief asked for new capabilities chosen from research in seven tracks, implemented, tested and committed one by one, with no release work. Ten capabilities were added. They are listed below with where they live and how each was verified. FEATURE_BACKLOG.md ("Mission 2") holds the sources, the scoring model and the ranked candidates.

### Statistics

| Item | Value |
|---|---|
| Time | 2026-11-09T16:31:14Z–20:05Z (about 3 h 35 min) |
| Commits | 12: the research and ranking (`c3a79c1`), ten capabilities and a parser robustness test (`a7b0368`), plus this report |
| Schema | unchanged (21); no migration |
| Tests | Rust 405 → 459 (3 → 6 ignored); frontend 243 → 258 (41 → 45 files) |
| New dependencies | `toml` 1, `hcl-rs` 0.20 (with `kstring` pinned at 2.0.2 for Rust 1.90), `goblin` 0.10 (PE and ELF only) |
| Real-app checks (Windows 11) | 174 of 174 |

### New capabilities

| Capability | Where | Commit | Verification |
|---|---|---|---|
| Dependency lockfiles (13 formats) read as SBOMs, with supply-chain checks and the OSV.dev check | Projects → Components | `4835950` | 8 Rust tests; app 21/21 |
| Windows event log (EVTX) triage: own MS-EVEN6 reader, 35 ATT&CK-mapped detections | Security Utilities → Log triage | `4d78bfd` | 8 Rust tests; python-evtx comparison on 174 sample and 59,907 local events; app 14/14 |
| Cloud and IaC checks: Terraform, CloudFormation, AWS IAM policies and account exports, 28 privilege-escalation methods | Security Utilities → Cloud & IaC checks | `b35fafa` | 10 Rust tests; app 16/16 |
| PE and ELF triage without running the file: hashes, import hash, sections, hardening, capabilities with ATT&CK, strings | Security Utilities → File triage | `f9d7594` | 6 Rust tests; app 18/18 |
| API definition comparison: endpoint changes, lost authentication, new anonymous endpoints | Projects → APIs | `25bb7a2` | 4 Rust and 1 frontend test; app 14/14 |
| OAuth and OpenID Connect review of server metadata against RFC 9700, pasted or fetched within scope | Security Utilities → OAuth & OpenID Connect review | `b77ddd2` | 5 frontend tests; app 29/29 against a local provider |
| Prowler (OCSF) import, with passing checks resolving earlier findings | Projects → Findings → Import results | `afd290c` | 4 Rust tests; Prowler's 4 example outputs; app 15/15 |
| Linux persistence triage of an image or UAC collection, read-only and confined to it | Security Utilities → Linux persistence triage | `2116f34` | 6 Rust and 1 frontend test; app 21/21 |
| ATT&CK Navigator layer of the techniques findings name | Projects → Findings → Export | `cd8b0b7` | 2 Rust tests; app 9/9; loaded in ATT&CK Navigator 5.3.2 |
| SBOM and lockfile comparison between versions | Projects → Components → Compare versions | `54d6534` | 4 Rust and 1 frontend test; app 17/17 |

The capabilities feed each other: the EVTX, file, Linux and Prowler results carry ATT&CK technique IDs, which the Navigator layer collects; lockfiles reach the SBOM comparison and the OSV.dev check; Prowler and SARIF results join the same import, deduplication and rescan logic.

### How the needs were established

The sources are listed in FEATURE_BACKLOG.md with the numbers read on 2026-11-09. In short:
* Event logs: Chainsaw, Hayabusa and DeepBlueCLI.
* IaC: Checkov, tfsec and KICS.
* IAM: the Rhino Security Labs escalation catalog.
* Lockfiles: OSV-Scanner.
* Binary triage: Detect It Easy and capa.
* Standards: OWASP ASVS 5.0, RFC 9700, MITRE ATT&CK v20.1 and the Navigator layer format 4.5.
* Linux artifacts: UAC.
* Cloud audits: Prowler's documented OCSF output.

Each capability was checked against primary sources before it was built: the RFCs, ATT&CK technique pages, the Navigator specification, the Prowler source and examples, and PortSwigger's research on OAuth attack vectors. A Reddit search returned mostly vendor content and was not counted as evidence.

### Ranked candidates

* Done: 27–32 and 34–37.
* Done in part: 38 (layer export; no matrix inside Cyber Hub).
* Not started: 33, the OWASP ASVS 5.0 checklist (score 53). It needs the requirement catalog (CC BY-SA 4.0, like the bundled WSTG) and per-project storage, which means a schema migration. That was too risky to start at the end of the mission.
* Deferred with reasons: 39 (request collections in the repeater) and 40 (YARA, which needs a WebAssembly runtime or a C toolchain).

### Defects found while testing, all fixed before their commits

* **Lockfiles:** wording and singular forms; the VEX switch is hidden for lockfiles.
* **EVTX:** timestamp conversion; log clearing counted only from its provider; zero-padded access masks; WMI parents.
* **IaC:** unresolved references reported as weak settings.
* **Binary triage:** joined UTF-16 strings.
* **API comparison:** renamed path parameters counted as changes.
* **Linux triage:**
  * an absolute link inside an image could have led the scan into the analyst's own files;
  * a helper turned `-c` into `c`;
  * the PAM program was taken from the wrong argument.
* **SBOM comparison:**
  * packages that moved to a URL source were not matched;
  * "0 new, 0 gone" read as an all-clear without lookups.
* **Scan import:** a project without scope was warned about hosts even for files without network targets (SARIF code results, cloud audits).

### Test-harness incidents (no product impact)

* Two GUI expectations were wrong and were corrected without changing the product:
  * the out-of-scope refusal's wording (the provider received nothing);
  * the SBOM panel's vulnerability wording, which did change, see above.
* A shell heredoc mangled backslashes in two test scripts; those scripts were then edited directly.
* The real database was never opened (modification time checked in every run).

### Security review

* **Offline by default.** Everything new reads local data offline except the OAuth fetch. That fetch uses the scope-checked HTTP command: active scope gate, address pinning against DNS rebinding, redirects checked per hop. It never sends an authorization or token request.
* **Read-only file access.** Files and folders are chosen in native dialogs opened by the backend. Nothing is executed (PE/ELF, Linux artifacts). The Linux triage does not follow links and refuses paths whose canonical form leaves the chosen file system.
* **Evidence and redaction.**
  * Hashes are kept for evidence (file triage, Linux triage, imports).
  * Copied text goes through the existing redaction.
  * Shadow hashes are never shown.
  * Imports keep their limits.
  * Every parser added in this mission is fed damaged, cut or multibyte input in a test; the lockfile and IaC tests were added at the end (`a7b0368`) and passed without a change.
* **Accurate claims.**
  * Leads are labelled as leads: OAuth tests, capabilities, persistence patterns.
  * Detections name their sources.
  * ATT&CK IDs were checked on attack.mitre.org.
* **Scans.** gitleaks over the mission's commits found nothing. cargo audit found 0 vulnerabilities (640 crates, 8 allowed warnings in transitive Linux GTK crates). npm audit found 0.

### Performance

* EVTX: a 21 MB System log (37,542 events) in 4.7–4.8 s in the debug app; 59,907 events read and written as JSON in about 13 s in a release build.
* The other new parsers ran within the GUI waits on their test inputs. Each runs on a blocking thread, so the window stays responsive. Their limits:
  * lockfiles and imports: 50 MB;
  * binaries: 256 MB;
  * Linux files: 1 MB each, 5,000 per scan;
  * EVTX: chunk by chunk.

### Limitations

* **EVTX:** the detections are Cyber Hub's own rules, not Sigma.
* **IAM and IaC:**
  * IAM policies are judged one document at a time; effective permissions across policies, boundaries and SCPs are not computed.
  * IaC references and variables are not resolved.
* **File triage:** Authenticode signatures are reported as present or not, never verified.
* **OAuth:** the review sees only what the metadata advertises, not each client's configuration.
* **Prowler:** OCSF 1.0 files (Prowler 3) are refused with advice.
* **Linux triage:**
  * its patterns are leads;
  * vendor units are checked for patterns only;
  * the symbolic-link test runs on Unix only (Windows uses a junction test).
* **ATT&CK layer:** export only, with no matrix inside the app.
* **SBOM comparison:** vulnerabilities are compared only when both sides were checked on OSV.dev, or neither was.

### Not verified

* Linux (Ubuntu, Debian): neither the test suites nor the GUI checks were run for this mission.
* Installers, signing, updates: not built or run (not authorized).

### Assessment

Each capability works in the real app, is covered by tests, and was checked against its specification or a reference implementation where one exists: python-evtx, pefile's import hash, ssh-keygen, Prowler's examples and the ATT&CK Navigator. Before a release that includes Mission 2, the RC0 checks need repeating for the new code, in particular the Linux suites and GUI checks.
