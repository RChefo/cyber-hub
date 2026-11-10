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
| Time | 2026-11-09T16:31:14Z–19:55Z (about 3 h 24 min) |
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


## Mission 3: unified investigation layer (2026-11-09)

The owner's brief asked for the layer that connects the modules' results: one data model with provenance, a real correlation engine, an investigation workspace, explainable correlation with review, evidence provenance, a unified timeline, the graph, playbooks, ATT&CK, findings across modules, AI and MCP, and global search. No release work. Everything below is built on the existing records (the project is the investigation; findings, evidence, assets, the timeline, the OSINT graph engine and the workflow engine are reused, none duplicated).

### Statistics

| Item | Value |
|---|---|
| Time | 2026-11-09T20:10:11Z–22:35Z (about 2 h 25 min) |
| Commits | 10: eight capabilities, a concurrency test (`54576dd`) and this report (`2d23aba`) |
| Schema | 21 → 23 (migration 22: relations, decisions, evidence provenance; migration 23: ATT&CK assessments and layers); each upgrade keeps a backup first |
| Tests | Rust 459 → 482 (6 → 7 ignored); frontend 258 → 264 (45 → 47 files) |
| New dependencies | none; the ATT&CK Enterprise 20.1 catalog is bundled as data (MITRE's notice in THIRD_PARTY_NOTICES.md) |
| Real-app checks (Windows 11, disposable data) | 112 of 112 across 8 scripts |

### New capabilities

| Capability | Where | Commit | Verification |
|---|---|---|---|
| Relationships between records of every module, with origin, verification, review and every decision kept; 10 explainable correlation rules; review queue; record panel; manual links (ATT&CK IDs checked); investigation graph with neighbourhood, shortest path and JSON, SVG, PNG export; filtered and exportable timeline; evidence provenance and stored integrity results; record search | Projects → Investigation, Timeline, Evidence | `7b1a842` | 23 Rust tests (migration 21 → 22, rules, decisions, deletion, merges, archived projects, graph, search, provenance) and 3 frontend tests; app 22/22 and 7/7 |
| Triage results recorded with their evidence: the analysed file and the analysis as evidence with provenance, findings linked to the file, one transaction, a changed file refused; analysed files as project indicators; the text-evidence viewer fixed | Security Utilities → file, capture, log triage, OAuth review | `24258c2` | 4 Rust tests; app 16/16 |
| ATT&CK matrix per project: techniques named by findings (leads), analyst assessments (confirmed, hypothesis, ruled out) and imported Navigator layers (overlay, gaps), layer import (format 2.x–4.5, revoked IDs mapped, version differences reported) and export (format 4.5) | Projects → Investigation → ATT&CK | `e3eeeca` | 3 Rust and 3 frontend tests; app 17/17 |
| Global search: the command palette finds the records of open projects and opens them | `Ctrl+K` | `3c761db` | app 7/7 |
| MCP: record search, related records, relationships, the ATT&CK matrix; correlation and relationship proposals after approval, stored as suggestions; the assistant's relationships and ATT&CK section and AI-suggestion labels | MCP, Projects → Assistant | `f0ab1d5` | 3 Rust tests; the real `cyberhub-mcp` server 17/17 |
| Investigation playbooks (suspicious file, incident logs, vulnerable dependency, web application, cloud account) as workflow templates, with new local steps: correlate, verify evidence, wait for a recorded result | Projects → Automation | `6dc7f63` | 1 Rust test; app 14/14 |
| Evidence provenance in the reports' evidence register | Reports | `f08a6bb` | report tests extended |
| Remediation groups: findings that one fix addresses (same CVE, package, check on several targets, remediation), with open, resolved and rescan-verified counts | Projects → Findings | `ab4a9db` | 1 Rust test; app 12/12 |

### Correlation and confidence

* **Rules compare exact or normalized values, never similarity:** URLs, web origins, hosts and addresses, CVE IDs (with OSV aliases), package URLs, file hashes (SHA-256, SHA-1, MD5) and API paths. Each suggestion names its rule, a one-sentence reason, the fields and values that matched and how (exact, normalized, alias), and a confidence (high for exact matches, medium for host-level, version-different or multi-endpoint matches). See DATA_MODEL.md, "Correlation".
* **Suggestions stay suggestions.** Origin `derived`, verification `inferred`, review `pending`. Only the analyst's *Accept* makes a relationship `verified`; accepting a finding relationship creates the finding link that reports use, and rejecting or restoring removes exactly what accepting created. Rejected pairs are never suggested again. Nothing is merged: OSINT entity identities keep their own policy, and a merge only moves relationships.
* **Bounded.** 50 pairs per group of findings that share something, 5 assets per finding, 5,000 pending suggestions per project.
* **AI suggestions are labelled.** A relationship proposed through MCP is `suggested`, `inferred`, low confidence, with the client's name; the assistant is told to present conclusions as suggestions and every answer says so.

### Evidence and provenance

Evidence records keep the module and record they came from, the tool and its version, when the source collected them (apart from when Cyber Hub stored them), the record they were derived from, and the result of the last integrity check. Imports (scans, API definitions, SBOMs, ATT&CK layers) and recorded utility results fill them; provenance is never overwritten. A utility result keeps the original file and stores the analysis as a separate, derived record; the file must still have the SHA-256 that was analysed.

### Security review

* **Nothing new contacts a network.** Correlation, search, the graph, the matrix, layer import and playbooks read the database; the playbooks' only active step is the existing web check, which keeps its confirmation and scope check.
* **The web view never names a file.** Utility files are named by a random token; layers and exports use native dialogs; exported SVG is checked to contain drawing elements only (no scripts, event handlers, links or external references).
* **Archived projects are read-only** for correlation, decisions, assessments, layers and MCP writes, and are left out of search unless asked.
* **MCP clients only propose.** Reads are allowed; correlation and proposals need the user's approval and are re-checked when carried out; clients cannot accept, reject, link or assess.
* **Scans.** gitleaks over the mission's 9 commits found nothing; cargo audit 0 vulnerabilities (640 crates, the same 8 allowed warnings); npm audit 0.

### Performance

* Correlation of 10,000 findings and 20,000 assets: candidates in 158 ms, a full run with storage in 462 ms (release build; the pending cap of 5,000 applied).
* Correlation, the graph, paths, search and remediation groups run on blocking threads. The deletion triggers and the related-records query use indexes (checked with `EXPLAIN QUERY PLAN` in a test); the API endpoint rule indexes endpoints by server and first path segment.
* The graph is capped at 1,500 edges by default (5,000 at most) and says when it is cut; relationship lists are paged.

### Defects found while building, fixed before their commits

* Text evidence never opened in the viewer: the list never carried the content (since the evidence vault was built). Fixed with a separate read.
* Finding links and the relationships that created them were drawn twice in the graph and listed twice in the record panel.
* The deletion triggers and the foreign keys of `relation_events.relation_id` and `evidence.derived_from` would have scanned whole tables.
* The API endpoint rule compared every finding with every endpoint and missed paths with capital letters.
* Merging two related OSINT entities could leave a relationship from an entity to itself.
* The ATT&CK view dropped a just-imported layer from the overlay (a race with the reload).
* A failed provenance write after a committed scan import would have deleted the import's file.

### Limitations

* **Correlation** compares values; it does not find relationships that need interpretation (the same attacker behind two hosts, renamed packages, a URL behind a redirect).
* **The ATT&CK catalog** is Enterprise only (no Mobile or ICS); its version is updated by rerunning `scripts/attack-catalog.mjs` with a newer MITRE bundle.
* **Playbooks** wait for the analyst's own recording; they cannot run file-based tools themselves, by design.
* **The graph** shows one project; there is no cross-project graph.
* **Search** matches text; it does not rank by recency or severity.

### Not verified

* Linux (Ubuntu, Debian): neither the test suites nor the GUI checks were run for this mission.
* Installers, signing, updates: not built or run (not authorized).

### Assessment

The integration layer works end to end in the real app: a file analysed in the utilities lands in the project with its evidence and provenance, is linked to its findings, appears on the timeline, in the indicators, the investigation panel, the graph and the report; correlation connects it to assets, vulnerabilities, components and OSINT entities as reviewed suggestions; the ATT&CK matrix keeps leads, assessments and coverage apart; MCP clients and the assistant read the same data and can only suggest. Before a release that includes Mission 3, the RC0 checks need repeating for the new code, in particular the Linux suites and GUI checks.

## Mission 4: detection engineering, threat hunting and compliance (2026-11-09/10)

The owner's brief asked for detection engineering (Sigma, YARA), threat hunting, OWASP ASVS 5.0 assessments, ATT&CK, threat-intelligence and remediation improvements, cross-module workflows, and MCP and assistant extensions, without executing untrusted content or overstating confidence.

### Statistics

| Item | Value |
|---|---|
| Time | 2026-11-09T23:21:37Z–2026-11-10T01:56Z (about 2 h 35 min) |
| Commits | 8: six capabilities, a test fix (`2d26fa2`) and this report |
| Schema | 23 → 26 (24 detection library and hits, 25 ASVS assessments, 26 indicator lifecycle); each upgrade keeps a backup first |
| Tests | Rust 482 → 522 (7 → 10 ignored); frontend 264 → 276 (47 → 49 files) |
| New dependency | `boreal` 1.4.0, MIT or Apache-2.0, without default features. It adds `boreal-parser`, `nom` 8, `object` 0.40, `tlsh2`, `der`, `der_derive`, `const-oid`, `codespan-reporting`, `termcolor` and `unicode-width` |
| Bundled data | OWASP ASVS 5.0.0 JSON, unmodified, CC BY-SA 4.0 (THIRD_PARTY_NOTICES.md) |
| Real-app checks (Windows 11, disposable data) | 121 of 121 in the final run of each of 6 scripts |

### Fully implemented

| Capability | Commit | Verification |
|---|---|---|
| Sigma library: validation that names errors, unsupported features and warnings; versions with a line diff; collections; export; tests on EVTX, JSON and text samples with expectations and regression re-tests; explanations per field; project runs whose matches stay hits until promoted or marked false positives; ATT&CK coverage with gaps and layer export | `e4a3987` | Rust tests incl. SigmaHQ rules on EVTX-ATTACK-SAMPLES; app 19/19 |
| OWASP ASVS 5.0.0 assessments: levels 1–3, five statuses that only the analyst sets, notes, evidence and finding links in the project, the analyst's mappings, history, progress, finding recording, Markdown report with attribution | `8150748` | 3 Rust and 3 frontend tests; app 28/28 |
| YARA rule files on boreal: library entries per file, versions, collections, tests on file samples, project runs, File Triage scan and recording, hit promotion, coverage | `4fa4a1a` | 11 engine tests, library tests, 2 corpora; app 25/25 |
| Hunting leads in packet captures: regular schedules and DNS patterns, each with what else it can be | `ef862c3` | 5 Rust and 2 frontend tests; app 15/15 |
| Indicator lifecycle: source and reliability, confidence, validity, status, history; STIX lifecycle fields; standing in the Analysis tab | `d8c8cbb` | 4 Rust and 2 frontend tests; app 16/16 |
| MCP: six detection and compliance tools with approvals | `285e439` | 3 Rust tests; real server 18/18 |

### Partially implemented

* **Threat hunting on hosts.** The tools are Sigma rules on Windows and JSON logs, together with the existing EVTX, Linux persistence and SSH triage. There are no dedicated analytics for process chains or logon anomalies.
* **ATT&CK.** Done: rule coverage, gaps, hits per technique and the coverage layer export, next to Mission 3's assessments and layers. Not done: technique history, comparison of several layers, and confidence beyond the assessments.
* **Threat intelligence.** Done: the lifecycle, STIX and false-positive handling. Not done: TAXII, feeds and report import.
* **Assistant.** It reaches the new data through MCP. The in-app assistant's context was not extended.

### Deferred

* Risk acceptance records and exceptions for findings. Every path that sets a finding's status would need to require and show them.
* Sigma correlation rules and aggregations.
* Assessment comparison and remediation metrics.
* TAXII feeds.
* ATT&CK Mobile and ICS.

The reasons are in FEATURE_BACKLOG.md, "Mission 4".

### Sigma: support and limitations

* **Support:**
  * specification v2.1.0 with the full modifier appendix (including base64offset, windash, cidr, fieldref and numeric comparisons);
  * `1 of`, `all of`, `N of` and `them` conditions;
  * Windows services and categories mapped to channels and event IDs (process creation from Sysmon 1 and Security 4688);
  * EVTX, JSON, JSON Lines and text events.
* **Refused with the reason:** placeholders, time modifiers, aggregations, correlation rules, rule collections with actions, look-around and back-references.
* **Evaluation:** a rule runs on one event at a time. Other log sources run against every event, and the result says so.

### YARA: support and limitations

* **Support:** boreal 1.4 (YARA 4.5) with text, hex and regular-expression strings and their modifiers, private and global rules, and the modules time, math, string, hash, pe, elf, macho, dotnet and dex.
* **Refused or absent:**
  * `include`, refused twice over (boreal's setting and a refusing include callback);
  * external variables (LOKI's and THOR's `filename` and `filepath` would mislead path-based rules on copied files);
  * the console, magic and cuckoo modules;
  * Authenticode verification (left off to avoid `rsa` and its advisory).
* **Limits:**
  * rule files of 2 MB, 1,000 strings per rule, conditions 64 levels deep (Cyber Hub) and 40 (boreal);
  * scans of 256 MB, stopped after 30 s;
  * 1,000 matches counted per string and 10 kept.
* **Compatibility:** 97.7% of signature-base and 87.6% of Yara-Rules files compile one file at a time. Failures are external variables, other modules, index files of includes and empty files.

### Threat hunting

* **Packet captures:**
  * connections on a regular schedule, marked "regular" or "jittered", with services that keep schedules by design named;
  * many long or random-looking names under one domain;
  * very long labels and TXT, NULL or ANY volume;
  * NXDOMAIN bursts across many domains.
* **Logs:** Sigma rules on logs, and YARA rules on any evidence file.
* Leads are hypotheses. They say what else they can be, become findings under review only when recorded, and carry no ATT&CK tag.

### ASVS

* Complete for the brief's list:
  * catalogue and version;
  * chapters and levels;
  * per-project assessments with statuses, evidence, notes, findings and history;
  * progress and an exportable report.
* No requirement is ever marked compliant automatically or by a client. The 5.0.0 data has no mappings, so mappings are the analyst's and say so.
* Exception management and assessment comparison are not done.

### ATT&CK and threat intelligence

* **ATT&CK:** detection coverage (Sigma, and YARA files whose metadata names techniques) is an overlay, never an observation. Gaps are techniques named or assessed without a rule, and hits are counted per technique as leads.
* **Indicators:** they keep their source and collection time, and are not presented as current once expired, revoked or rejected. A false positive overrides a provider's flag.

### Cross-module workflows

* **Sigma:** import, validate, map techniques, test on samples, run on evidence, review hits, promote to a finding linked to the evidence, then coverage, timeline and report.
* **YARA:**
  1. import and validate;
  2. analyse a file in File Triage and scan it;
  3. record matches as findings with the file and the analysis as evidence (indicators, correlation, the graph and the timeline follow from Mission 3's layer);
  4. or run on project evidence as hits.
* **ASVS:** create, choose a level, review requirements, link evidence and findings, record findings for failed requirements, then report.
* **Hunting:** open a capture, review the leads, record hypotheses, then correlate and build the timeline.

### MCP and assistant

* Six tools. The reads are rules, one rule, hits with redacted values, and ASVS assessments. The writes, after approval, are a hit's review and an ASVS status other than compliant.
* Results say that coverage is not evidence and that a hit is a lead.
* Other projects and archived projects are refused before an approval.

### Security review

* **Nothing new contacts a network.** Rules and files are data, and nothing in a rule, sample or capture is executed. Files are chosen in native dialogs or named by tokens.
* **A denial-of-service in YARA parsing** was found and fixed before release (see Mission 4 in IMPLEMENTATION_LOG.md). boreal's `unsafe` code that the chosen features compile was read.
* **Archived projects** are refused for every new write.
* **Values from logs and files** are redacted before an MCP client receives them.
* **Scans:**
  * gitleaks over the 7 commits: clean;
  * cargo audit: 0 vulnerabilities (651 crates, the same 8 allowed warnings);
  * npm audit: 0.

### Performance (development build unless stated)

* **ASVS:** 345 requirement rows render in about 1.0 s; 70 by default.
* **YARA:** compiling signature-base one file at a time takes 101.5 s, slowest 884 ms. Yara-Rules takes 28.9 s.
* **Not measured:** release-build timing, and large captures with the hunting accumulators (bounded at 100,000 flows of 2,000 events and 50,000 domains).

### Database changes

* **24:** `detection_rules`, `detection_rule_versions`, `detection_collections`, `detection_collection_rules`, `detection_samples`, `detection_rule_samples`, `detection_tests`, `detection_feedback`, `detection_hits`.
* **25:** `asvs_assessments`, `asvs_results`, `asvs_links`, `asvs_mappings`, `asvs_history`, and two triggers.
* **26:** `ti_saved` gains source, reliability, confidence, status, valid_until and updated_at, and `ti_saved_events` is added.

All three only add data. Each was exercised by the real app on a copy, after the automatic backup.

### Commits

`e4a3987`, `2d26fa2`, `8150748`, `4fa4a1a`, `ef862c3`, `d8c8cbb`, `285e439`, and this report.

### Remaining technical debt

* Risk acceptance records; Sigma aggregations and correlation; TAXII.
* A shared stack guard: other parsers could be checked for unbounded recursion the way boreal's was.
* YARA performance on large rule sets in the release build.
* The ASVS list renders all rows at once (about 1 s for 345 in development); it could be virtualized.
* The MCP client used for checks keeps 1,500 characters of each result, so long results were checked by their visible text.
* Linux runs of the suites and GUI checks for Missions 2–4, and the release-candidate checks again before any release.

### Not verified

* Linux (Ubuntu, Debian): neither the suites nor the GUI checks.
* Installers, signing and updates: not built or run (not authorized).

## Mission 5: platform-wide hardening, Linux compatibility and feature completion (2026-11-10)

The owner's brief asked, in this order, for:
* Linux compatibility;
* the security of every parser of untrusted input;
* database migrations;
* Sigma correlation rules;
* risk acceptance;
* TAXII 2.1;
* compliance and ATT&CK work;
* performance in an optimized build;
* end-to-end workflows and CI.

It ruled out pushing, publishing, installers, signing, release builds and the real database.

### Statistics

| Item | Value |
|---|---|
| Time | 2026-11-10T10:14:43Z–2026-11-10T14:08Z (about 3 h 53 min) |
| Commits | 12: four capabilities (`0c8084f`, `e6869ed`, `3573c2f`, `24045f0`), four fixes (`4d9b12f`, `6acf43e`, `3336d6b`, `91b064a`), two test commits (`ff3e5f5`, `d23ddf3`), CI (`7206810`) and this report |
| Schema | 26 → 29 (27 risk acceptances, 28 TAXII, 29 ATT&CK coverage snapshots). Each upgrade keeps a backup first, and the tests upgrade every earlier version |
| Tests | Rust 522 → 568, and 10 → 16 ignored: the six new ignored tests are the timing tests. Frontend 276 → 281 (49 → 50 files) |
| New dependency | None in the application. The separate fuzz crate (`src-tauri/fuzz`, never part of an application build) uses `libfuzzer-sys` 0.4 |
| Real-app checks | Windows: 48/48 end-to-end and 10/10 screens. Linux: the Mission 5 features 18/18 per distribution, WSLg 10/10 per distribution, and the 71-check regression on both, Debian after a re-run (details below) |

### Fully implemented

| Capability | Commit | Verification |
|---|---|---|
| **Sigma correlation rules:** `event_count`, `value_count`, `temporal`, `temporal_ordered`, `value_sum` and `value_avg`, with group-by, aliases, `generate` and chains of up to five. Validation that gives the reason; tests on samples; project runs across several files; hits with their group, window, value and events; promotion to a finding under review linked to every file it combined | `0c8084f`, `91b064a` | 9 correlation tests built on the specification's examples, plus library and promotion tests; Windows end-to-end; Linux GUI on both distributions |
| **Risk acceptance:** justification, compensating controls, owner, approver, approval, expiry and review dates; it covers findings, vulnerabilities and ASVS exceptions; renewal, revocation and history. Expiry is flagged, never acted on. Every path that sets *accepted risk* requires a covering acceptance | `e6869ed` | 5 Rust tests over every status path, frontend tests; Windows end-to-end and screens; Linux GUI (status menu, form, Escape, Risks tab) |
| **ASVS compliance:** gaps by chapter with exceptions and the remediation state of linked findings, compliant requirements without evidence, comparison of two assessments, and gaps and exceptions in the report | `e6869ed` | Rust test; Windows end-to-end and screens; the Linux report saved through the GTK save dialog |
| **TAXII 2.1:** servers, discovery, collections, incremental synchronization with a cursor, history and health. Deduplication, the server's reliability, STIX confidence, validity and revocation. The analyst's records and false positives are kept | `3573c2f` | 6 tests against a local mock server; Windows end-to-end; Linux GUI through the GTK confirmation, both cancel and confirm |
| **ATT&CK:** a technique's history, comparison of observed techniques, hypotheses, coverage, coverage snapshots and imported layers, and coverage snapshots | `24045f0` | Rust test; Windows end-to-end and screens |
| **Parser hardening:** review of every parser of untrusted input, the hostile-input harness and sweep, and 13 fuzz targets | `6acf43e`, `3336d6b` | A regression test for every defect; about 25 parsers in the sweep, which runs in `cargo test` |
| **Upgrade validation from every schema version**, with injected failures and killed processes | `ff3e5f5` | 3 tests (and the seeder's own) |
| **CI:** pinned actions, toolchains and image; clippy, Debian 12, audits and secret scanning | `7206810` | `ci_tests.rs`; the same commands ran locally and in the containers. Not run on GitHub |

### Partially implemented

* **Sigma correlation:**
  * `value_percentile` is refused, because the specification does not define the percentile;
  * correlations run over chosen evidence and samples, not over live log streams.
* **TAXII:**
  * it reads only ("Add Objects" is not used);
  * credentials are stored only with the developer tool `cyberhub-keys`, not entered in the app;
  * only equality patterns on IP, domain, URL and hash observables become indicators, and other patterns are skipped with the reason;
  * there is no scheduled synchronization, by design: every connection is confirmed.
* **Compliance:** comparison, gaps and exceptions exist for ASVS only. The WSTG checklist has none of them.
* **ATT&CK:** Enterprise only.
* **Parsers:** smaller amplifications remain open (SECURITY.md, "Accepted risks and limitations").

### Deferred

* ATT&CK Mobile and ICS: no official data is bundled.
* A cloud-resource asset type: the cloud workflow used a domain asset.
* Entering TAXII credentials in the app.
* Host hunting analytics beyond rules.
* The smaller parser amplifications.

The reasons are in FEATURE_BACKLOG.md, "Mission 5".

### Linux compatibility

| Environment | Versions |
|---|---|
| Ubuntu 24.04.5 LTS (Docker container) | Rust 1.99.1, Node 22.12.0, WebKitGTK 2.52.6, GTK 3.24.41 |
| Debian 12 (Docker container) | Rust 1.99.1, Node 22.12.0, WebKitGTK 2.50.6, GTK 3.24.38 |
| WSLg 1.0.71, the Weston compositor of this Windows 11 machine, used from both containers | Native Wayland (`GDK_BACKEND=wayland`) and X11 through XWayland |

* **Baseline:** clippy failed on both distributions with three lints that clippy 1.99 adds. They were fixed in `4d9b12f`. Nothing else failed.
* **Suites at `91b064a`:** all clean on both distributions:
  * tsc;
  * 50 frontend test files;
  * clippy with warnings as errors;
  * `cargo test` (568 passed and 16 ignored on each);
  * npm audit.

  Linux runs two Unix-only symlink tests, and Windows two Windows-only tests instead.
* **MSRV:** `cargo +1.90.0 check --locked --all-targets` passed on Ubuntu.
* **GUI regression at `91b064a`** (scope, imports, findings, workflows, evidence, OSINT, MCP, settings, backup, a restore that restarts the app, recovery after SIGKILL): 71/71 on Ubuntu 24.04.
  * On Debian 12, the first run passed main (62/62) and after-restore (6/6), but the after-kill phase could not start: its WebDriver session was gone for 60 s after the app was started again.
  * It did not reproduce. The full re-run passed 71/71, and a direct start after the kill ran normally.
  * 12 consecutive cycles of SIGKILL during a workflow run, each followed by a start through WebDriver, all came back usable within 5 s, with the run marked interrupted.
  * The cause is not known: the first run's driver log was not kept.
* **The new features on a virtual display:** 18/18 on each distribution. Every GUI run is offline, in a fresh container, as an unprivileged user:
  * Ctrl+K search by keyboard, and the dashboard charts;
  * a correlation chain and a YARA rule over two files added through the GTK file chooser, giving one hit each, promoted;
  * risk acceptance through the status menu and its form (Escape closes it, nothing changes), and the Risks tab;
  * TAXII through the GTK confirmation, both cancel and confirm;
  * the ASVS report through the GTK save dialog;
  * the investigation graph;
  * a 50 MB, 500,000-line auth log through the GTK chooser, read in about 17 s in the debug build while the window kept drawing (slowest frame 27 ms on Ubuntu, 54 ms on Debian);
  * no runtime errors.
* **A real compositor (WSLg):**
  * native Wayland: 4/4 on each distribution (rendering, navigation, keyboard search, charts, no errors);
  * XWayland: 6/6 on each (the same, plus a GTK file chooser and a GTK confirmation).
* **Data folder:** `0700`, with `evidence` and `work` also `0700`.
* **Found on Linux:** only the clippy difference. No defect specific to Linux was found in the new code.
* **Not tested on Linux:**
  * GNOME or KDE sessions, HiDPI scaling, desktop portals, a real login keyring;
  * native dialogs under native Wayland: xdotool needs X11, so dialogs were checked under Xvfb and XWayland;
  * a GPU (rendering was software in every container);
  * installers (not built).

### Parser security

* **Method:**
  1. a read-only review of every parser of untrusted input;
  2. `hostile.rs`, a harness of truncations, seeded mutations, random bytes, hostile text, oversized lines and deep nesting, each case run on a 2 MiB thread under a time budget;
  3. coverage-guided fuzzing of 13 parsers (libFuzzer with AddressSanitizer, nightly Rust, offline Ubuntu container).
* **Defects fixed:** 17, each with a regression test (SECURITY.md, "Parser safety"). Before their fixes:
  * five could end the app: the MCP handshake (any local process, before authenticating), PCAP and PCAPNG bounds, Sigma condition recursion, YAML recursion, and a tool-argument slice;
  * one could freeze it: nested YAML keys, found by fuzzing;
  * the rest were amplifications of memory or time, an unbounded read of a FIFO, a sample path taken from a restored database, and remote images in Markdown reports.
* **Fuzzing:**
  * 13 targets × 150 s: 0.19M to 38M inputs per target;
  * one defect, in YAML;
  * EVTX, run again for 600 s from the test suite's generated EVTX file: 570,797 inputs, coverage from 7,584 to 8,510 points (54 without a seed), and no crash, timeout or out-of-memory error.
* **The guarantees and how they are checked:**
  * imported files and rules are never executed: rules are data, and samples are read by hash;
  * paths come only from native dialogs or tokens, and a sample's name is a validated SHA-256;
  * evidence is hashed on intake and checked again;
  * limits are named in errors;
  * heavy parsing runs on blocking threads (the Linux check above measured it).

### Sigma

Correlation rules follow specification v2.1.0:
* **Windows:** a window starts at each matching event; a match is a window whose measure satisfies the condition, and the next window starts after it.
* **Unusable events:** events without a usable time or group field take no part, and the result says how many.
* **Imports:** a correlation's referenced rules (inner correlations too, since `91b064a`) are imported disabled unless the correlation says `generate: true`.
* **Unsupported syntax** is refused with the reason, never accepted silently: `value_percentile`, cycles, chains deeper than five, unknown references and ambiguous names.
* **Hits** never confirm anything: promotion makes a finding under review.

### Risk acceptance

* **One check for every path.** The check sits in the three functions every status change goes through (`findings::set_status`, the editor's write, `vulns::set_status`). The editor, status menus, bulk changes (uncovered findings are skipped), imports and internal services all meet it.
* **MCP:** clients cannot create an accepted finding and have no tool to record, renew or revoke an acceptance. The register is readable, which makes 62 tools.
* **Acceptance is not remediation.** Reports, the findings table, ASVS and the overview show accepted risks apart from resolved and verified ones.
* **Lifecycle:**
  * expiry is computed when read and flagged until renewal or revocation;
  * revocation reopens findings, reopens vulnerabilities and removes exceptions;
  * an item that leaves (reopened, fixed, verified, requirement met, deleted) is released with the reason.
* **Legacy data:** findings accepted before schema 27 are listed as accepted without a record, so they can be documented.

### TAXII 2.1

* **Network access:**
  * off by default, and nothing runs in the background;
  * every discovery and synchronization is confirmed in a native dialog naming the server;
  * HTTPS only (loopback HTTP in debug builds, for tests);
  * no credentials in URLs, no redirects, and API roots on other hosts ignored.
* **Limits:** 30 s timeouts, 16 MB per response, 200 pages and 100,000 objects per synchronization.
* **Paging:** it follows `next`, or `added_after` from `X-TAXII-Date-Added-Last`. The cursor moves only past stored pages, so an interrupted or capped synchronization continues on the next one, and one interrupted by a shutdown is marked failed at the next start.
* **Credentials** (HTTP Basic or an API-key header) live in the OS credential store; errors are scrubbed of them.
* **What a feed may change:**
  * it saves indicators, never findings, and never confirms anything as malicious;
  * it updates only its own indicators, and only with newer versions;
  * the analyst's records and false positives are never changed, and the feed's view goes to their history.

### Compliance (ASVS)

* **Gaps** by chapter, with:
  * the exceptions;
  * the remediation state of linked findings;
  * compliant requirements without evidence.
* **Comparison** of two assessments: improved, regressed and unchanged.
* **The report** has gaps and exceptions.
* **No requirement is marked compliant** by any of it. Mappings stay the analyst's and attribution stays in the report.

### ATT&CK

* **A technique's history:**
  * the analyst's assessments with notes;
  * findings that name it, with their status;
  * rule matches per rule, with how many are still to review;
  * investigation links.
* **Comparison** of any two sets: observed, hypotheses, coverage now, a coverage snapshot or an imported layer. A sentence says what the comparison means, so coverage is never read as activity, nor a layer as observation.
* **Coverage snapshots** keep the enabled, runnable rules per technique with the ATT&CK version.
* **Navigator layers:** the import and export from Mission 3 are unchanged.
* **Enterprise only:** no Mobile or ICS data is bundled.

### Migrations, backup and restore

* **Tests** (`db_upgrade_tests.rs`), on databases built at each earlier version with one row in every table:
  * every earlier version upgrades to 29 through the real start-up path, with `integrity_check` ok, no broken foreign keys and every row kept;
  * the backup taken before the upgrade keeps the old version, and opening it (what a restore does) upgrades the same way;
  * a failure injected before each migration's commit keeps the last complete version, and the next start finishes;
  * a child process killed inside a migration leaves the previous version, and the next start finishes.
* **The real app:** the Linux GUI regression above restores a backup (the app restarts and applies it) and recovers after SIGKILL.
* **Migrations 27–29 only add tables and columns.** None is destructive.

### End-to-end workflows (Windows 11, real app, disposable data, native dialogs, local servers)

48/48 in the final run:
1. **Suspicious file:** evidence with its SHA-256, File Triage with the library's YARA rule, the triage recorded, a project run, a hit promoted to a finding under review, IOC correlation with a saved indicator, investigation and report.
2. **Detection engineering:** the specification's chained correlation imported (referenced rules disabled), validated, tested on a sample (one chain for admin, none for guest), run on a log, promoted, and seen in ATT&CK as both observed and covered. **This run found the defect fixed in `91b064a`.**
3. **API security:** definition import, endpoint inventory, a path outside scope refused, a test in scope, then remediation and verification against the fixed target.
4. **Cloud (IaC):** issues found, a finding linked to the analysis and an asset, then verification by rescanning the fixed file.
5. **Compliance:** risk acceptance of a finding and an ASVS exception, refusal without an acceptance, comparison, gaps, report and register.
6. **Network:** capture leads (beacon-like timing), IOC extraction, timeline and report.
7. **Supply chain:** two SBOM versions compared (the vulnerability fixed), then remediation and verification.

TAXII ran against a local server: confirmation, a synchronization of 2 added, 1 revoked and 1 skipped, provenance kept, and cancelling connected nothing.

### Performance (release profile, Ubuntu 24.04 container, AMD Ryzen 7 5700X, 16 threads)

Peak memory is the test process's peak resident size up to that step. The steps of one timing test share a process, so a later step's peak includes the earlier ones. The tests are: Sigma; correlation; YARA; capture and log; SBOM and lockfile; and the project from "a fresh database" onwards.

| Path | Time | Peak memory |
|---|---|---|
| 1,000 Sigma rules compiled | 549 ms | 60 MB |
| 50 Sigma rules × 100,000 events (14,444 matches) | 3,096 ms | 137 MB |
| `event_count` correlation over 500,000 events, 1,000 groups | 156 ms | 421 MB |
| 100 YARA rules compiled / a 64 MB scan | 5 ms / 33 ms | 10 / 74 MB |
| PCAP of 200,000 packets (19 MB) | 196 ms | 71 MB |
| Auth log of 1,000,000 lines (99 MB) | 2,697 ms | 292 MB |
| SBOM of 20,000 components and 20,000 vulnerabilities | 162 ms | 103 MB |
| `package-lock.json` of 20,000 packages | 36 ms | 105 MB |
| A fresh database to schema 29 | 27 ms | 10 MB |
| 50,000 findings inserted / listed | 1,222 ms / 212 ms | 22 / 70 MB |
| Global search over them | 41 ms | 70 MB |
| ATT&CK matrix / Markdown report (12 MB) | 246 ms / 406 ms | 125 / 187 MB |
| ASVS level 3 view with gaps | 4 ms | 187 MB |

* **Responsiveness:** reading a 50 MB log kept the Linux window drawing (above).
* **Not measured:** cancellation latency and on-disk growth. Nothing was optimized: no measured path needed it.

### CI

`ci.yml`:
* **Pinning:** actions are pinned by commit and the Debian image by digest. Rust 1.99.1, Node 22.12.0, cargo-audit 0.22.2 and gitleaks 8.30.1 (with checksum) are pinned by exact version, with `--locked` and `npm ci`.
* **Windows and Ubuntu 24.04:** typecheck, frontend tests, the frontend build, clippy with warnings as errors, `cargo test` (upgrades and the sweep included), the fuzz entry points, sidecar staging and npm audit.
* **Debian 12:** frontend checks and `cargo test`.
* **Audit:** cargo audit and gitleaks over the whole history.
* **MSRV:** 1.90.0.

`ci_tests.rs` fails if a workflow stops parsing, loses a pin or loses a check. Build environments are in PLATFORMS.md. The workflow has not run on GitHub, because the repository has not been pushed. `release.yml` was not changed and still uses the floating stable toolchain.

### Security review

* **Network:** nothing new contacts a network except TAXII, after its confirmation.
* **Untrusted content:** nothing in a rule, sample, feed or capture is executed. Files come from native dialogs or tokens.
* **Status changes:**
  * risk acceptances cannot be created by MCP clients or imports;
  * feeds cannot create findings;
  * no status is set automatically by compliance or coverage.
* **Scans at the end:**
  * gitleaks 8.30.1 over all 132 commits before this report and over the changed documents: no leaks;
  * cargo audit: 0 vulnerabilities in 651 crates, the same 8 allowed warnings;
  * npm audit: 0.

### Database changes

* **27:** `risk_acceptances`, `risk_acceptance_items` and `risk_acceptance_history`, plus triggers that drop the items of deleted records.
* **28:**
  * `taxii_servers` (no secret);
  * `taxii_collections`, with the cursor and health;
  * `taxii_syncs`;
  * feed provenance columns on `ti_saved`.
* **29:** `attack_coverage_snapshots`.

All three only add data.

### Commits

`4d9b12f`, `ff3e5f5`, `0c8084f`, `6acf43e`, `e6869ed`, `3336d6b`, `3573c2f`, `24045f0`, `d23ddf3`, `7206810`, `91b064a`, and this report.

### Remaining limitations

* **TAXII:** credentials only through `cyberhub-keys`; reading only; equality patterns only.
* **Sigma:** `value_percentile`.
* **Assets:** no cloud-resource asset type.
* **Parsers:** the smaller amplifications in SECURITY.md.
* **Reports:** the default report leaves closed findings out (by design). Verification reports include them.
* **MCP:** the read-only risk tool was tested by its Rust test, not through a real MCP client.
* **CI:** `release.yml` still floats; neither workflow has run on GitHub.

### Not verified

* GitHub Actions runs.
* GNOME or KDE desktops, HiDPI, desktop portals and a GPU on Linux.
* Installers, signing and updates: not built or run (not authorized). No release build of the app was made: the timings come from optimized `cargo test` builds.

## Mission 6: product completion and release readiness (2026-11-10)

The owner's brief asked for:
* the parser issues left open by Mission 5;
* exceptions for failed WSTG tests;
* TAXII credentials entered in the app;
* ATT&CK Mobile and ICS;
* host hunting analytics and a cloud-resource asset type;
* validation with a real MCP client;
* Linux desktops;
* a release workflow that cannot publish by accident;
* an integration review, full regression and the mission documents.

It ruled out installers, release packages, signing, publishing, pushing, deployments, the real database, production credentials and testing systems without authorization.

### Statistics

| Item | Value |
|---|---|
| Time | 2026-11-10T14:05Z–18:31Z (about 4 h 26 min) |
| Hashes | Start `f8c49ac`. Last code change `b002e0e`; this report is the commit after it |
| Commits | 17: five capabilities (`c270a1e`, `b5c845d`, `020ad01`, `d0e706e`, `2eb6185`), one performance fix (`1f64034`), the release workflow (`9d89831`), eight fixes (`ea60e88`, `57d3c48`, `c8b0bdc`, `05500c5`, `92100da`, `1a93038`, `bfa6107`, `2a60d9f`), a test marker (`b002e0e`) and this report |
| Schema | 29 → 32 (30 WSTG exceptions, 31 ATT&CK domains, 32 cloud resources). Each upgrade keeps a backup first, and the tests upgrade every earlier version |
| Tests | Rust 568 → 593, and 16 → 27 ignored (10 amplification timings and the EVTX-sample chain test). Frontend 281 → 291 (50 → 53 files) |
| Dependencies | No new crate in `Cargo.lock`. `gtk` 0.18 (Linux) and `zeroize` 1.9 were already in the tree and are now direct; `windows-sys` gained the credential-UI features |
| Real-app checks | Windows 23/23 end-to-end, plus the TAXII and MCP checks below. Ubuntu 24.04 and Debian 12: Mission 6 features 25/25 each and the 71-check regression on each. On Ubuntu 24.04: Mutter 5/5, KWin 5/5, HiDPI 7/7 |

### Classification

| Feature | Status | Commits | Evidence |
|---|---|---|---|
| Parser amplifications (§1) | **Complete and verified** | `1f64034` | Before and after timings in an optimized build; regression tests with a time budget; the hostile-input sweep |
| Exceptions for failed WSTG tests, in the register and reports (§2) | **Complete and verified** | `c270a1e`, `c8b0bdc`, `2a60d9f` | Rust tests over every path (checklist, MCP, expiry, revocation, report options); Windows end-to-end; Linux GUI on both distributions |
| TAXII credentials typed into a native dialog (§3) | **Implemented but partially verified** | `2eb6185`, `bfa6107` | Linux: the whole flow through the GTK dialog, 14/14 on each distribution. Windows: the dialog, connection test, deletion and the origin rule were checked, but typing into Windows' dialog could not be automated (below) |
| ATT&CK Mobile and ICS (§4) | **Complete and verified** | `020ad01`, `92100da` | Official 20.1 data; catalog, migration and comparison tests; the ICS layer exported through native save dialogs on Windows and Linux |
| Host hunting: process chains and logons per account, Windows event logs (§5) | **Complete and verified** | `b5c845d`, `05500c5` | Tests; 17 files of the public EVTX-ATTACK-SAMPLES (the PsExec service shell and the comsvcs dump started through WMI found, nothing in the others; run again at the end); Windows and Linux GUI |
| Host hunting on Linux telemetry (§5) | **Deferred** | — | auditd names a parent's process ID but not its program |
| Cloud-resource assets (§6) | **Complete and verified** | `d0e706e`, `1a93038` | Import, provider and rebuild tests; Windows and Linux GUI with a Prowler file |
| MCP with a real client (§7) | **Complete and verified on Windows**; Linux with a scripted client only | `ea60e88`, `57d3c48`, `b002e0e` | Claude Code 2.1.319 and a scripted edge-case suite (below) |
| Linux desktops (§8) | **Implemented but partially verified** | — | X11 fully; the compositors of GNOME and KDE and HiDPI in smoke runs; no full desktop sessions, portals, GPU or physical HiDPI screen |
| Release workflow (§9) | **Implemented but partially verified**; the GitHub run is **blocked** on the owner | `9d89831` | `ci_tests.rs` and actionlint locally. Never run on GitHub: nothing may be pushed |
| Integration review (§10) | **Complete and verified**, two small items deferred | `c8b0bdc`–`2a60d9f` | 13 of 15 findings and one nit fixed; Windows and Linux end-to-end afterwards |
| Regression (§11) | **Complete for the available platforms** | — | Below |

### Partially implemented and deferred

* **TAXII:** typing into Windows' credential dialog needs a person (manual check before release). macOS is not supported; the developer tool `cyberhub-keys taxii-set` still works everywhere.
* **ATT&CK:** the domain switch does not show how many techniques each matrix holds (FEATURE_BACKLOG.md, item 62).
* **Event log triage:** a log's detections and chains are recorded through two bars (item 63).
* **Linux process chains** (item 64).
* **Linux desktops:** GNOME Shell and Plasma sessions, portals, a GPU and a physical HiDPI screen (item 65).
* **HiDPI:** the minimum window size does not fit a 1920 × 1080 screen at 150 % or 200 % (item 67).

### Security findings and fixes

| Finding | Severity | Fix |
|---|---|---|
| **MCP:** a call the client cancelled (`notifications/cancelled`, sent by Claude Code when a tool times out) kept its approval waiting in the Approval Center, and approving it later still ran it. rmcp cancels the request's token, but the handler did not watch it | Medium | `ea60e88`: the sidecar sends the app a bridge `cancel`, answered ahead of the in-flight limit; the approval queue cancels only that request and remembers it, so a call cancelled before its approval existed is refused |
| **MCP:** tool results carried credential-like values verbatim (a finding's `Authorization: Bearer …`, `password=…`) to clients, which pass them to their model provider | Medium | `57d3c48`: every result and error message is masked with the run-output rules at the dispatcher; only the read-only indicator lookups return exact values (a test pins that list) |
| **TAXII:** a stored credential would have followed its server to another address or kind of authentication after an edit | Medium | `2eb6185`: the credential is deleted when the origin or the kind of authentication changes, or the server is removed, and the dialog stores nothing if the server changed while it was open. The edit form warns first |
| **Release workflow:** a floating toolchain, and a tag push could publish | Medium | `9d89831`: pinned versions; publishing needs the `RELEASE_PUBLISHING` variable, a manual dispatch, `draft: false` and the tag typed again |
| **Parsers:** crafted import files could make imports quadratic in time or memory | Low (files the analyst chooses) | `1f64034` |
| **Exceptions:** changing a failed test's result ended its exception without a word | Low | `c8b0bdc`, `2a60d9f` |
| **Secret scan:** gitleaks flagged a made-up AWS key ID in a redaction test | False positive | `b002e0e`: marked inline and in `.gitleaksignore` |

Observed and left as is: Windows' credential dialog runs in `CredentialUIBroker` at integrity level 0x200A, above the app and the test shell (0x2000). UI Automation and synthetic input from ordinary processes cannot reach it, which protects the typed value from other programs.

### Parser performance (optimized build, Ubuntu 24.04 container, AMD Ryzen 7 5700X)

"Before" ran on an export of `c270a1e` with the same fixtures.

| Case | Before | After |
|---|---|---|
| Normal Nessus file, 10,000 items, 1.6 MB | 113 ms, 37 MB | 130 ms, 37 MB |
| Nessus, a 100 KB host name × 2,000 items, 516 KB | 553 ms, 212 MB | 27 ms, 16 MB |
| Burp, 20 KB host names, 40 MB | 917 ms, 252 MB | 523 ms, 93 MB |
| Greenbone, 20 KB host names, 40 MB | 238 ms, 334 MB, 2,000 findings | 18 ms, 133 MB, 0 findings (no usable host) |
| SARIF, 256 KB rule texts × 2,000 results, 1.6 MB | 8,260 ms | 838 ms |
| OCSF, a long product name, 673 KB | 604 ms | 29 ms |
| OCSF, 30,000 ATT&CK entries | 1,309 ms | 163 ms |
| OSINT, 1,000 records with 3,000 unknown evidence IDs, 121 KB | 1,410 ms, 4,007 events | 117 ms, 1,008 events |
| SBOM with duplicate references, 5 MB | 673 ms, 60,000 links | 269 ms, 20,000 |
| Postman, 30,000 query names | 911 ms | 2 ms |
| OSINT indicators, 3.3 MB | 2,393 ms | 82 ms |
| Wide JSON events, 30 MB | 5,202 ms | 1,283 ms |
| CSP header check in the frontend (Node), 200 KB | 2,333 ms | 3.0 ms (6.5 ms at 400 KB) |

At the largest accepted files, after: Nessus 42 MB parsed in 493 ms (10,000 findings committed in 2,074 ms), SARIF 41 MB in 546 ms, OCSF 42 MB in 452 ms. The normal Nessus case is within noise. Costs that remain proportional to the input are listed in SECURITY.md.

### MCP with a real client

* **Client:** Claude Code 2.1.319 (Windows 11), with `--strict-mcp-config` and only the `cyberhub` server, started against the debug app with an isolated data folder and MCP on.
* **Run 1** (14 turns):
  * initialization and discovery: 62 tools and 6 resources;
  * reads of projects, findings, the risk register and the checklist;
  * `not_found` errors; an unknown tool refused by the client;
  * the risk register read-only, with no tool to approve or accept anything;
  * it reported the unmasked credentials, fixed in `57d3c48`.
* **Run 2:** the description came back as `Authorization: ••••••`. A finding request declined in the app returned "The user declined this request in Cyber Hub. (denied)"; an approved one created the finding.
* **Cancellation:** with an 8 s tool timeout the client gave up, sent `notifications/cancelled`, and the waiting approval left the app at that moment (audited `cancelled`, nothing created).
* **Disconnect:** a client process tree killed while its request waited: the approval was cancelled within 0.6 s, and no sidecar was left.
* **Reconnection:** one stream-json session over three turns. While MCP was off, the same sidecar process answered "Cyber Hub is not running or MCP is turned off… (unavailable)"; after MCP was turned on again it reconnected with the new session key.
* **Scripted client against the real `cyberhub-mcp`:** 18/18:
  * protocol versions 2025-06-18 and 2024-11-05 echoed, and 2099-01-01 answered with 2025-11-25;
  * a request before `initialize` refused (-32602);
  * malformed lines and a 17 MB line dropped without ending the session;
  * -32601 for an unknown method; unknown tools, wrong types and unknown arguments refused with the reason; arguments over 256 KiB refused;
  * 30 concurrent calls in 25 ms;
  * a raw `notifications/cancelled` removing the waiting approval;
  * a clean exit with nothing but JSON on stdout;
  * a forged bridge handshake answered `ok: false` and closed, with real clients unaffected.
* **Not tested:** Claude Code on Linux, Claude Desktop and other clients.

### Linux environments actually used

| Environment | What ran | Result |
|---|---|---|
| Ubuntu 24.04.5 container: Xvfb, Openbox, D-Bus, GNOME Keyring; WebKitGTK 2.52.6, GTK 3.24.41 | Suites; the Mission 6 features (TAXII 14, main 11); the earlier GUI regression (scope, imports, findings, workflows, evidence, OSINT, MCP, settings, backup, a restore that restarts the app, recovery after SIGKILL) | All passed: 25/25 and 71/71 |
| Debian 12 container, the same setup; WebKitGTK 2.50.6, GTK 3.24.38 | The same | All passed: 25/25 and 71/71 |
| GNOME's compositor: Mutter 46.2, headless, the app as a native Wayland client | Rendering, navigation, keyboard, window size, scale, errors, quit | 5/5 |
| KDE's compositor: KWin 5.27.11, virtual output, the app as a native Wayland client | The same | 5/5. KWin needed a copy of its binary without the file capability the container cannot grant, and its XWayland crashed in the container, so the app was not run through XWayland under KWin |
| HiDPI: `GDK_SCALE=2` on Xvfb and Openbox | The same, plus a GTK credential dialog into GNOME Keyring and a GTK file chooser | 7/7, and the minimum-size finding |

* **Applies to every Linux run:** each GUI run was offline, in a fresh container, as an unprivileged user. In the compositor and HiDPI runs the app started in about a second and left no process after quitting.
* **Not available or not used:** full GNOME Shell and Plasma sessions, desktop portals (the app uses GTK's own dialogs), a GPU, a physical HiDPI screen, a login keyring of a real session, WSLg (used in Mission 5, not repeated).

### Migration and restore

* **Schema 30:** `risk_acceptance_items` rebuilt with its rows (by rowid) to allow `wstg` items; triggers recreated.
* **Schema 31:** a `domain` column on assessments, layers and snapshots; existing rows are Enterprise.
* **Schema 32:** `assets` rebuilt for `cloud_resource` through `run_rebuild`: foreign keys off around the transaction, every row copied with its id, index and trigger recreated, committed only if `foreign_key_check` is clean.
* **Tests:** on Windows, Ubuntu and Debian, every earlier schema upgrades to 32 with all its rows and a usable backup. A failure injected at any migration, including the rebuild, keeps the last complete version, and a retry finishes. A process killed during a migration leaves the previous version. After the assets rebuild, ids, observations, vulnerability links and the relationship trigger still work.
* **Restore:** the GUI regression backs up, restores (the app restarts) and recovers after SIGKILL on both distributions: 6/6 and 3/3 each. Restore was not repeated on Windows in this mission.

### Test counts

| Platform | Rust (passed / ignored) | Frontend | Static checks |
|---|---|---|---|
| Windows 11 (Rust 1.94.1, Node 24.19.0), at `2a60d9f` (`b002e0e` changed only comments and `.gitleaksignore`) | 593 / 27 | 291 tests, 53 files | clippy `-D warnings` (also with `fuzzing`), tsc |
| Ubuntu 24.04.5 (Rust 1.99.1, Node 22.12.0), at `b002e0e` | 593 / 27 | 53 files | clippy, tsc; `cargo +1.90.0 check --all-targets` passes |
| Debian 12 (Rust 1.99.1, Node 22.12.0), at `b002e0e` | 593 / 27 | 53 files | clippy, tsc |

The 27 ignored tests need external data or long runs:
* 10 amplification timings (run in an optimized build in this mission) and 6 timing tests from Mission 5;
* five that need the EVTX sample corpus (Mission 6's chain test was run with it);
* the scan-import limits, correlation at scale, a volume test, the exhaustive CVSS comparison, a folder read and the YARA corpus.

### Audits and secret scan

* **cargo audit 0.22.2:** 0 vulnerabilities in 651 crates, and the same 8 allowed warnings as before. They are unmaintained or unsound crates in the Linux GTK and D-Bus stack that Tauri brings: `proc-macro-error`, `zbus_names`, `zvariant`, `zvariant_derive`, `glib`.
* **npm audit:** 0 on Windows, Ubuntu and Debian.
* **gitleaks 8.30.1** over the whole history (149 commits): the first run found 2 matches, the made-up key ID of the new redaction test; after `b002e0e`, no leaks.

### End-to-end results

* **Windows 11, debug app, isolated data folder, native dialogs: 23/23.**
  * a WSTG exception recorded in the checklist and listed as a WSTG test in the register and the report;
  * changing the result asks first, then ends the exception, with the history kept;
  * process chains and logons from public EVTX files chosen in the native Open dialog;
  * Enterprise, Mobile and ICS, with the full ICS matrix and an ICS layer saved through the Save dialog naming its matrix and version;
  * a Prowler file imported with four cloud resources (provider, account, region, exposure only from the failed public-access check) and three findings;
  * no runtime errors.
* **TAXII on Windows:** described under "Classification".
* **Linux:** described under "Linux environments actually used".

### Unexpected failures and their investigation

* **Windows' credential dialog ignored synthetic keys.** Integrity levels showed the broker above the test shell. This is a Windows protection, not a defect; the remaining steps were checked with a throwaway credential stored by the developer tool, and the Linux run covers typing.
* **First Windows end-to-end runs (10/18, then 13/15):**
  * the scripts assumed tactic headers in an empty matrix, and waited on a description that already named Prowler;
  * UI Automation shows the save dialog's title without the `&` of "ATT&CK" (the real caption has it);
  * a project created through IPC was clicked before the list refreshed.

  These were all script problems, fixed in the scripts.
* **A leftover approver from an earlier run** approved the first cancellation test's request. It was stopped, and the test was repeated with a watcher only.
* **"Nothing to click: Log triage":** the dev server had cached an empty module, because a patch script truncated the file at the moment Vite read it. Touching the file fixed it; the product was not involved.
* **My own defect in `c8b0bdc`:** the new confirmation's element was never rendered, so a status change waited forever. The Windows end-to-end run found it, and `2a60d9f` fixed it.
* **Linux "main" at 10/11 on both distributions:** WebKitGTK's `innerText` begins with whitespace, so the script's `startsWith` failed. With the check relaxed, it passed 11/11 on both.
* **KWin would not start, then crashed through XWayland.** The causes were a file capability, a missing `/tmp/.X11-unix` and an XWayland crash in the container. A diagnostic showed the app runs under KWin without XWayland.
* **A TAXII test** still expected the old error text: my search for it had been cut off by `head`.

### Schema and backup implications

Schema 32. Opening an existing database upgrades it through 30–32, and a backup is taken first. The assets rebuild copies every row and keeps ids; a failure leaves the previous version. An older build cannot open a schema-32 database, as with every earlier upgrade; restoring the backup taken before the upgrade is the way back. No migration deletes data.

### Release blockers

1. **Signing:** not set up, and the brief forbids it until the owner authorizes the release.
2. **Installers:** never built. The release candidate must be built and validated once, at the final stage, with the owner's authorization (install, upgrade from a copy of a real database, uninstall, updates).
3. **CI:** neither workflow has run on GitHub. A push needs the owner. `RELEASE_PUBLISHING` is unset by design.
4. **Manual checks:** typing into Windows' credential dialog; a GNOME and a Plasma session and a physical HiDPI screen; a review of the minimum window size on scaled screens.

### Engineering readiness assessment

* **What the evidence shows:** the brief's features are implemented, and every check run here passed:
  * Windows 11 and containers of Ubuntu 24.04 and Debian 12;
  * a real MCP client;
  * the compositors of GNOME and KDE.

  The two security gaps the real client exposed are fixed, as is the defect the end-to-end run found in a review fix.
* **What it does not show:**
  * installed builds, signing and updates;
  * a GitHub run;
  * full desktop sessions on real hardware;
  * the Windows credential dialog with a person typing.
* **Conclusion:** the code is ready for the owner to run CI on GitHub and to authorize a signed release-candidate build. **It is not release-ready** until that build passes the installer, upgrade and manual checks above.
