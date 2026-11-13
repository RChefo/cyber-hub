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

## Mission 7: final hardening and release preparation (2026-11-10/11)

**Started** at `09c43a0` (2026-11-10T18:40Z), schema 32, clean tree. **Ended** at the commit that adds this report, on top of `d21c76e`. 34 commits, all on `release/v0.1.0` and none pushed. No installer, package or release binary was built, and the real database was never opened.

**Verdict.** Engineering is in good shape:

* every automated check passes on Windows 11, Ubuntu 24.04 and Debian 12;
* every finding of a full security review is fixed with a test, or recorded as an accepted risk;
* the measured performance problem is fixed.

**The product is not release-ready.** Ten manual or owner items remain, and eight of them block the release, three of those only on Linux (section 13). The automated tests passing does not change that.

### 1. Starting and ending hashes

* Start: `09c43a0` (Mission 6's report).
* Last code commit: `d21c76e`. The report commit only adds documentation.

### 2. Fixes, with their commits

| Commit | Change |
|---|---|
| `e9b5da1` | Window sized to the monitor's work area; minimum 800 × 480 (was 1100 × 700); compact sidebar below 1024 px |
| `bac82fe` | Restore: only SQLite's own schema objects are exempt from the comparison (High) |
| `a1c4ba9` | Native confirmations: Cancel by default, approve disabled for 1 s, one at a time (High) |
| `ab337f9` | Internal addresses in a scope, and removed exclusions, confirmed natively; local-use NAT64 is internal (High) |
| `5185c4a` | TAXII credentials bound to origin, authentication and header; collections only on the server's origin |
| `5bc31b0` | Argument validation repeats no file content; network paths refused on Windows; terminal without a directory |
| `98b4fbc` | Project and evidence deletion, clearing the activity log, MCP audit log and run history: native confirmation |
| `d3e8391` | Arguments and dialog text cannot hide characters; MCP client names cleaned |
| `488b075` | Markdown reports escaped by CommonMark's rules, checked with a CommonMark parser |
| `4ccc8f6` | Copied commands quoted for POSIX shells and PowerShell |
| `68be193` | MCP redaction masks values whose names mark them as credentials |
| `bd84971` | Request builder: credential headers stay with their origin, routing headers checked; OSINT client without proxy; probe port |
| `304c00d` | OSINT SVG exports checked for active content |
| `96f28d7` | Only regular files are read; restored wordlist paths dropped |
| `f19f258` | MCP: web fingerprint needs approval; no client contacts; attached option files; cancellations per connection |
| `88cf533` | Two accepted risks recorded |
| `4ac9eba` | TAXII: one synchronization per collection, visible after leaving the page; truthful toasts |
| `47d7a95` | Toast tones follow outcomes; declined dialogs are information |
| `a18c157` | ATT&CK: per-matrix counts (#62), state words in cells |
| `b135d5b` | One record bar for a log's detections and chains (#63) |
| `b43d3ee` | Saved indicators: search, stepped list |
| `2b8ce1a` | Focus moves to the page on navigation; skip link; Retry on a failed page |
| `ab17d66` | Readable network errors; NVD cache fallback on every network error |
| `c090836` | Markdown export with the Report tab's options |
| `dd6ca10` | Finding links and history show errors; evidence hashes can be copied |
| `8ca17b9` | Synthetic approve clicks during the delay are refused (found in live testing) |
| `74127e1` | Release workflow builds and signs only in a manual run; no expressions in run scripts |
| `1e5d4dd` | Windows TAXII credential test procedure and its local test server |
| `12108f6` | A start that fails says why in a native message box |
| `67d14b4` | Two made-up fixture values marked for the secret scan |
| `6f190d1` | Saved indicators sent one page at a time (28.7 MB → 29 KB per refresh at 100,000) |
| `0dd3dc0` | Test-only pulldown-cmark 0.13.4 → 0.13.6 (two advisories) |
| `d21c76e` | TAXII credentials stored and deleted one change at a time: a removal right after the dialog's Store no longer leaves the credential behind (found while investigating a Debian test failure) |

### 3. Remaining security risks

* **Accepted risks** in SECURITY.md, including the two added now:
  * GUI tools, a terminal and version probes start without a native dialog, though nothing can be passed to them;
  * a compromised page can reactivate a completed project, whose scope was authorized when it was added.
* **Copied commands in PowerShell.** A word with a quote character arrives split, and Windows PowerShell 5.1 may split an argument that contains a double quote. Pasting never runs another command; this was checked with PowerShell's own parser.
* **The release workflow has never run on GitHub,** and signing is not set up.
* **Two features are not exercised in a real environment:** the Windows credential dialog (manual) and Linux desktop portals.

### 4. High-DPI results

| Check | Where | Result |
|---|---|---|
| Every page, every project tab and the finding form at 100/125/150/200 % and 800 × 480: no overflow, nothing unreachable | Windows, DevTools device emulation (`scripts/qa/layout-probe.mjs`) | PASS (emulated) |
| First window: 1354 × 900, centred in a 1440 × 2512 work area | Windows, real window | PASS |
| `GDK_SCALE=2`, 1920 × 1080 screen: device scale 2, 960 × 540 logical, maximized, minimum 1600 × 960 device pixels, dialog fits, text 14 px | Ubuntu 24.04, Debian 12 (Xvfb) | PASS (virtual) |
| Minimum 800 × 480 enforced; at 800 × 480 Dashboard, Projects, Threat Intel and Settings fit with the 60 px sidebar | Ubuntu, Debian (Openbox) | PASS (virtual) |
| A physical HiDPI screen | none | NOT TESTED (checklist M4) |

Only emulated and virtual scaling was tested. No physical high-DPI validation is claimed.

### 5. GNOME and KDE results

* **Compositors in containers:**
  * Mutter (GNOME) Wayland: 5/5.
  * KWin (KDE) Wayland: 5/5.
  * KWin with XWayland: 7/7, including the GTK credential dialog and file chooser.
* **The Mission 6 KWin XWayland crash** is Xwayland's glamor (GPU) path crashing on KWin's GPU-less virtual output: a segmentation fault before any client connected, even `xdpyinfo`. That is the environment, not Cyber Hub. With `XWAYLAND_NO_GLAMOR=1` everything works.
* **Not tested:** full GNOME Shell and Plasma sessions, desktop portals, a keyring unlocked by the login, a GPU (checklist M2, M3, M6, M7).

### 6. TAXII credential dialog

* **Linux, automated, on both distributions:**
  * the GTK dialog: store, rotate, cancel by Escape and by the window manager, forget, deletion on origin, authentication and header changes, an API key in its header;
  * the keyring entry `taxii_<n>_<fingerprint>`;
  * no copy of any test value in the data folder, logs, caches, reports, diagnostics or the page.
* **A race found and fixed:** removing a server right after the dialog's Store could leave the new credential in the Secret Service (section 8, `d21c76e`). After the fix, removals swept from 10 to 405 ms after Store left nothing behind: 0 of 17 on each distribution.
* **Windows:** typing into CredUI cannot be automated (UIPI). The procedure (`docs/release/TAXII_CREDENTIAL_TEST.md`) and its test server are ready; the test has not been performed (checklist M1, blocks).

### 7. Usability findings and fixes

The review reported 15 findings, and the two deferred items from Mission 6 were added to them.

* **Done:**
  * #62, #63;
  * saved indicators at scale;
  * toast tones;
  * focus on navigation and a skip link;
  * ATT&CK state words;
  * errors with Retry and the NVD cache;
  * Markdown export options.
* **Partly done:**
  * a finding's links and history show errors, and evidence hashes can be copied; opening linked records is deferred;
  * TAXII synchronization is guarded and visible after leaving the page; cancelling it is deferred.
* **Deferred with reasons** (FEATURE_BACKLOG.md, items 68–75):
  * back navigation;
  * links from sightings to their sources;
  * "Open" focusing the record;
  * runs linked to projects;
  * keyboard selection in the graph;
  * tab order;
  * global search for more records;
  * Arabic and right-to-left (not supported: no i18n).

### 8. Security review

Five read-only reviews reported 30 findings, **25 distinct** once overlaps are merged. Two more were found in live testing. Every High and Medium is fixed, every Low is fixed or accepted, and each fix has a regression test. "Old code" below means the new test was run against the previous code before the fix and failed there.

| Severity | Finding | Fix | Regression test (reproduction) |
|---|---|---|---|
| High | The native confirmation's default button was approve (keystrokes could approve) | `a1c4ba9` | Live: Cancel default and approve disabled at 5 ms on Windows; on Linux, Return cancels and an early click is ignored |
| High | A page could add internal addresses to a scope and read them through the request builder | `ab337f9` | `non_public_coverage_is_recognized`, guard `widening_the_scope_is_confirmed_outside_the_page`; live dialog on Windows and Linux |
| High | Restore ignored any object named `sqlite` plus one character (LIKE wildcard) | `bac82fe` | Refused cases in `restore_tests.rs` (failed on the old filter) |
| Medium | TAXII credential sent to an old or restored API root | `5185c4a` | `a_credential_only_goes_to_the_servers_own_origin` (old code sent it), `a_credential_is_bound_to_where_and_how_it_is_sent` |
| Medium | `exec_validate` repeated part of any file | `5bc31b0` | `target_file_errors_never_repeat_the_files_content` (old code failed) |
| Medium | UNC paths make Windows authenticate to a host | `5bc31b0` | `network_paths_in_arguments_are_refused_on_windows` (old code accepted), `network_and_device_paths_are_recognized` |
| Medium | Deletions and clearing logs had no native confirmation | `98b4fbc` | `destructive_commands_confirm_natively` (0 confirmations in the old bodies), `clearing_the_audit_log_keeps_approved_actions`; live on Windows and Linux |
| Medium | Arguments and dialog text could hide characters | `d3e8391` | `arguments_cannot_disguise_the_confirmation`, `dialog_text_shows_hidden_characters`, `client_names_are_shown_without_hidden_characters` |
| Medium | Project Markdown report let HTML and images through | `488b075` | `markdown_text_never_becomes_markup` with pulldown-cmark (the old code let the reviewer's payload through) |
| Medium | OSINT Markdown fields raw | `488b075` | `imported_fields_never_become_markup` (6 markup items on the old code, 0 now) |
| Medium | History lines unquoted (paste ran a second command) | `4ccc8f6` | `history_lines_paste_back_as_the_same_words` (old rendering: `;` outside quotes); PowerShell parser: old forms 3 statements, new 1 |
| Medium | POSIX-only quoting in PowerShell | `4ccc8f6` | `shellQuote.test.ts`, `repeater.test.ts` |
| Medium | Detection-hit fields bypassed MCP redaction | `68be193` | `values_named_like_credentials_are_masked` (old redactor left all values) |
| Low | FIFOs and devices hung or exhausted scans | `96f28d7` | `pipes_and_devices_are_refused_without_blocking` (Linux), `regular_files_are_read_within_their_bound` |
| Low | Restored wordlist paths trusted | `96f28d7` | `restored_wordlist_paths_are_not_trusted`, `network_paths_are_never_touched_on_windows` |
| Low | Process starts without confirmation | `5bc31b0` (terminal), `88cf533` (accepted) | `the_terminal_takes_no_directory_from_the_page` |
| Low | OSINT SVG export unchecked; references and escapes | `304c00d` | `graph_svg_exports_are_checked_for_active_content`, `only_drawings_are_saved_as_svg` |
| Low | Credential headers across origins | `bd84971` | `credential_headers_stay_with_their_origin` (old code sent X-Api-Key) |
| Low | Routing headers and comma Host | `bd84971` | `routing_headers_are_scope_checked` (old code accepted) |
| Low | OSINT client used a system proxy | `bd84971` | `the_public_source_client_uses_no_proxy` |
| Low | Local-use NAT64 judged public | `ab337f9` | `the_local_use_nat64_prefix_is_not_public` |
| Low | Web fingerprint allowed under "External lookups" | `f19f258` | catalog test (`RunTools` for a source that contacts the target) |
| Low | MCP `get_project` returned contacts | `f19f258` | `projects_reach_clients_without_their_contacts` |
| Low | Attached short-option file names | `f19f258` | `attached_short_option_files_are_refused` |
| Low | Cancellation memory global and permanent | `f19f258` | `cancellations_are_remembered_per_connection` |
| Found live | A click message to the task dialog approved during the delay | `8ca17b9` | `an_early_click_on_approve_keeps_the_dialog_open`; live: a click at 333 ms left the dialog open |
| Found live (Low) | Removing a TAXII server 150–200 ms after the credential dialog's Store left the new credential in the Secret Service: the removal found nothing to delete, then the write landed. Debian, 2 of 10 timed attempts. A person cannot do this through the UI; a compromised page can. The value never reaches the page and stays bound to its origin | `d21c76e` | `credential_changes_never_interleave` (fails without the fix: the removal does not wait); live, after the fix: 0 left behind in 17 removals from 10 to 405 ms after Store on each distribution, where 2 of 10 had been left before |

### 9. Release workflow validation

* **Static checks:**
  * every action is pinned by commit;
  * least privilege (`permissions: {}` at the top, `contents: read` except for publishing);
  * secrets only in the protected `release` environment;
  * no `pull_request` trigger;
  * no caches;
  * since `74127e1`, build and sign only in a manual run with `RELEASE_PUBLISHING` enabled (a tag push validates only);
  * no expression inside a run script.

  `ci_tests.rs` checks all of it (2 tests, pass).
* **Not run:**
  * actionlint locally: the container was not allowed in this session; CI runs it on every push;
  * zizmor: not installed;
  * the workflows on GitHub: no push, as the brief requires (checklist M8).

### 10. Regression

Windows commands:

```
npx tsc -b --noEmit · npx vitest run · cargo clippy --offline --all-targets -- -D warnings
cargo test --offline · cargo audit · npm audit
```

| Environment | Commit | tsc | vitest | clippy | cargo test | ignored | audits |
|---|---|---|---|---|---|---|---|
| Windows 11 Pro 10.0.26200, rustc 1.94.1, Node 24.19.0 | `d21c76e` | OK | 299 in 55 files | OK | 633 passed | 28 | cargo audit 0 (652 crates, 8 allowed warnings); npm audit 0 |
| Ubuntu 24.04.5, rustc 1.99.1, Node 22.12.0, WebKitGTK 2.52.6 (container) | `d21c76e` | OK | 55 files | OK | 632 passed | 28 | npm audit 0 |
| Debian 12, rustc 1.99.1, Node 22.12.0, WebKitGTK 2.50.6 (container) | `d21c76e` | OK | 55 files | OK | 632 passed | 28 | npm audit 0 |

* **The same regression ran at `0dd3dc0`, before the fix.** Everything passed on Windows (632 Rust tests) and Ubuntu (631). Debian passed everything except one TAXII check (explained below).
* **Linux commands** (`scratchpad/linuxgui/suites5.sh`, `msrv.sh`): `npx tsc -b --noEmit`, `npx vitest run`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked --no-fail-fast`, `npm audit`.
* **MSRV 1.90.0:** passed on Ubuntu and Debian at `d21c76e` (`cargo +1.90.0 check --locked --all-targets`).
* **The 28 ignored tests:**
  * 10 timing and volume tests (7 in `perf_tests.rs`, import limits, correlation at scale, volume);
  * 10 amplification tests;
  * 8 that need samples or reference data kept outside the repository: EVTX samples and folders (5), an OCSF folder, CVSS reference output, a YARA corpus.

  The 20 timing, volume and amplification tests were run in an optimized build on Windows: 20/20 pass (section 11).
* **The Windows-only and Unix-only tests** account for 633 against 632.
* **Malformed input** is part of the default suites above, which pass on all three systems:
  * `hostile_tests.rs`: import, detection, capture and log, infrastructure, and command-line and protocol parsers;
  * expansion bombs and deep nesting (`yaml.rs`), crafted PCAP frames, truncated XML, hostile API specifications.

  The 10 amplification tests run in the optimized build (section 11).
* **GUI, Linux, at `d21c76e`** (the real app; no network):

  | Phase | Ubuntu | Debian |
  |---|---|---|
  | Mission 7 dialogs | 7/7 | 7/7 |
  | Minimum window | 3/3 | 3/3 |
  | HiDPI | 5/5 | 5/5 |
  | Start with a newer database | PASS | PASS |
  | Mission 6 TAXII (with the leak check) | 16/16 | 16/16 |
  | Mission 6 main | 11/11 | 11/11 |
  | Segment 3 (scope, imports, findings, workflows, MCP, backup, restore and restart, SIGKILL recovery) | 63/63, 6/6, 3/3 | 63/63, 6/6, 3/3 |
  | Compositors (KWin with XWayland, Mutter, KWin) | 7/7, 5/5, 5/5 | (not run) |
  | A server removed 10–405 ms after the credential dialog's Store (17 times) | none left behind | none left behind |

* **Failures that came from the QA scripts, not the product.** They were investigated and fixed in the scripts, which live outside the repository:
  * the Mission 6 scripts clicked "Mobile" and "ICS" by their exact text, and #62 added counts to those labels. The scripts now accept a label that contains the word. Ubuntu's first Mission 7 run failed there; the Windows script was changed before its run;
  * the TAXII and desktop phases looked up the old keyring entry `taxii_<id>`. They now search by prefix, because `5185c4a` binds the entry name to the server;
  * Debian's final run at `0dd3dc0` failed one TAXII check, "server and credential gone": nothing was stored before the removal, and its confirmation did not mention a credential. Ubuntu passed the same check, and an instrumented rerun on Debian passed it too. The cause was measured, not guessed:
    * on Debian the keyring write ends 340–398 ms after Return and the page shows it 418–483 ms after;
    * the step looked at about 540 ms without waiting for either, and its wait matched "No credential stored yet" at once;
    * its button helper also ignored a missing button.

    The step now waits for the stored state, and a missing button is an error. The investigation also found a product race, fixed in `d21c76e` (section 8).

* **GUI, Windows** (isolated debug app):
  * every new native dialog through Win32 (Cancel, approve after the delay, an early click ignored);
  * the Scope tab's decline shown as information;
  * the Report tab's Markdown buttons;
  * the matrix counts;
  * focus on navigation;
  * the saved-indicator list at 100,000;
  * the newer-schema message box;
  * the Mission 6 end-to-end script on a new data folder, 23/23 at `0dd3dc0` and again at `d21c76e`: a WSTG exception, process chains and logons from EVTX files chosen in the native Open dialog, the ATT&CK Mobile and ICS matrices with a layer saved through the native Save dialog, a Prowler import, no page errors;
  * at `d21c76e`, the TAXII commands through IPC: a server created, moved to another origin and kind of authentication, then removed while another call listed the servers, with no stall (29 ms in all).
* **MCP:**
  * the MCP tests (55 in the `mcp` modules) are part of the suites above and pass on the three systems;
  * in the real app, segment 3's MCP checks pass on both distributions: tools listed, a CVSS score, path-level validation, refusals before approval, a duplicate-finding warning, an archived project refused, an approved write read back.

### 11. Performance and stability

These were measured, and code was changed only where a measurement showed a cost.

* **Optimized test build on Windows: 20/20 within budget.** Examples:
  * Sigma: 50 rules × 100,000 events in 5.2 s;
  * correlation: 500,000 events in 245 ms;
  * a 1,000,000-line auth log in 2.3 s;
  * PCAP: 200,000 packets in 210 ms;
  * SBOM: 20,000 components in 127 ms;
  * 50,000 findings: listed in 144 ms, Markdown report in 428 ms;
  * the largest scan files: 42 MB Nessus parsed in 557 ms and committed in 1.9 s;
  * YARA: 64 MB in 25 ms.
* **Saved indicators at 100,000:** 1.7 s and 28.7 MB of JSON per refresh, measured live. Fixed in `6f190d1`: 63 ms and 29 KB, and 152–241 ms for a search.
* **Repeated cancellation:**
  * 25 sequential start-and-cancel cycles of a workflow: all cancelled, 262–280 ms each;
  * 5 concurrent runs cancelled together: all cancelled;
  * afterwards the app answered in 3 ms; memory 52.3 → 52.8 MB.
* **Shutdown during work:**
  * a graceful close during a run: the process ended within 20 s with nothing left, and the run was marked failed (interrupted) at the next start;
  * SIGKILL during a run (Linux, segment 3): marked interrupted, database intact.
* No leaks, queues or freezes were observed in these runs.

### 12. Migration and restore

* **Every earlier schema** upgrades to 32 with all rows and a usable backup taken first: `every_schema_version_upgrades_to_the_latest_with_all_its_rows_and_a_usable_backup`.
* **Failed and interrupted upgrades:**
  * `a_failed_upgrade_leaves_the_previous_database_untouched_and_can_be_retried`;
  * `an_interrupted_rebuild_is_rolled_back_at_the_next_open`;
  * `upgrade_child_process` (a killed upgrade).
* **A newer database is refused** and left unchanged, and since `12108f6` a release build says so in a native message box with the data folder. Previously it closed silently. Live on Windows, and in the GTK build on Ubuntu and Debian.
* **Restore keeps IDs, relationships and evidence** (`restore_tests.rs`; the GUI cycle on both distributions). The schema check is now exact (`bac82fe`), and restored wordlist paths are dropped (`96f28d7`).
* No migration was added in this mission (schema 32).

### 13. Manual release checklist and exact blockers

See `docs/release/RELEASE_READINESS.md`. Its status column is empty because none of these items was performed.

| # | Item | Blocks |
|---|---|---|
| M1 | Windows TAXII credential dialog (procedure written) | **Yes** |
| M2 | Full GNOME Shell session | **Yes** for Linux |
| M3 | Full KDE Plasma session | **Yes** for Linux |
| M4 | Physical HiDPI on Windows and Linux | **Yes** |
| M5 | Minimum window on a real screen | No |
| M6 | Desktop portals | No, unless sandboxed packaging |
| M7 | A real login keyring (GNOME Keyring, KWallet) | **Yes** for Linux |
| M8 | First GitHub Actions run | **Yes** (needs the owner's push) |
| M9 | Code signing | **Yes** (owner's keys) |
| M10 | Installers: install, upgrade a copy of a real database, uninstall | **Yes** (final stage, with authorization) |

### 14. Dependency audit and secret scan

* **cargo audit 0.22.2** on 652 crates:
  * 0 vulnerabilities after updating the test-only pulldown-cmark (RUSTSEC-2026-0414, -0433; wiki-links, not enabled by the tests);
  * 8 allowed warnings: unmaintained `proc-macro-error`, `zbus_names`, `zvariant` and `zvariant_derive`, and the unsound `glib` 0.18.5, all transitive through Tauri, GTK or D-Bus.
* **npm audit:** 0 on Windows and Linux.
* **gitleaks 8.30.1:** two made-up fixture values were marked (`67d14b4`). After that, no leaks in the whole history: 180 commits at `67d14b4`, 182 at `0dd3dc0` and 183 at `d21c76e`. The documents this report commit adds were also scanned, with no leaks.

### 15. Engineering readiness assessment

| Requirement | Status |
|---|---|
| Automated tests, typecheck, lints on the three systems | PASS |
| MSRV 1.90 | PASS |
| Dependency audits and secret scan | PASS |
| Security review fixed and regression-tested | PASS (code); accepted risks recorded |
| Database upgrades, failures, newer databases, restore | PASS |
| Performance and stability | PASS (measured) |
| High-DPI and minimum window | PARTIAL (emulated and virtual only) |
| Linux desktops | PARTIAL (compositors; no full sessions, portals or login keyring) |
| TAXII dialog on Windows | NOT TESTED (needs a person) |
| Release workflow | PARTIAL (static); first run BLOCKED (push) |
| Code signing | BLOCKED (owner) |
| Installers | BLOCKED (final stage, authorization) |

The code is ready for a release-candidate build once the owner authorizes one. **The product is not ready for release:** M1–M4 and M7–M10 must pass first.

## Mission 8: release validation and final readiness (2026-11-11)

**Started** at `5810c2e` (2026-11-11T00:04Z), schema 32, clean tree, no remote, no tag. **Ended** at the commit that adds this report. Everything is on `release/v0.1.0`; nothing was pushed or tagged, and no remote was created.

**Not done in this mission, by the brief:**

* no installer, package or release binary was built;
* nothing was signed, uploaded or published;
* no signing key, certificate or secret was created, read or used;
* the real database was never opened. Its modification time is unchanged, 2026-11-05T15:58:24.8534883Z.

**Verdict.** The engineering checks pass on Windows 11, Ubuntu 24.04 and Debian 12. Mission 8 fixed two accepted risks, narrowed a third, and closed a release-workflow gap. **Cyber Hub is not release-ready:**

* M1 is partial (typing into Windows' credential dialog needs a person);
* M2–M4 and M6–M10 are blocked on the owner: a real desktop, a HiDPI screen, a push, signing keys, an authorization;
* M5 is partial (a real window on Windows at 100 % only).

### 1. Starting and ending commits

* Start: `5810c2e` (Mission 7's report).
* Last code commit: `af88c00`. The commits after it change documentation only.
* End: the commit that adds this report.

### 2. Commits

| Commit | Kind | Change |
|---|---|---|
| `fb1f323` | fix(security) | A terminal and a GUI tool from the catalog start only after a native dialog (accepted risk 1, fixed) |
| `d3c654f` | fix(security) | Reopening a completed or archived project asks natively; compare-and-set save (accepted risk 2, fixed) |
| `8fe5ab5` | fix(security) | A copied word with a quote and nothing else special is double-quoted, exact in PowerShell too (the PowerShell limitation, narrowed) |
| `af88c00` | ci(release) | The release names the commit it built (two tag checks); static validation of both workflows in `ci_tests.rs` |
| `0db2dc4` | docs(release) | The 0.1.0 release notes brought up to date: schema 32, the Mission 6 capabilities, the Mission 7 and 8 changes, the audit warnings, the Linux limitation |
| `cc3d3ca` | docs(release) | `MANUAL_VALIDATION.md`, `GITHUB_FIRST_RUN.md`, `SIGNING_SETUP.md`, `RELEASE_CANDIDATE_PROCEDURE.md`; the readiness checklist with a status for every M item; the TAXII procedure corrected; `SIGNING.md` and `PLATFORMS.md` |
| (this commit) | docs(mission) | This report and the tracking files |

### 3. M1–M10

| # | Item | Status | Evidence or reason |
|---|---|---|---|
| M1 | TAXII credentials in Windows' credential dialog | **PARTIAL** | Everything but the dialog, on Windows 11 with the real Credential Manager: 16/16. Steps 2, 3 and 9 need a person (`TAXII_CREDENTIAL_TEST.md`) |
| M2 | Full GNOME Shell session | **BLOCKED** | No GNOME session available. Mutter in a container passes 5/5 (Mission 6), which is a substitute, not this test |
| M3 | Full KDE Plasma session | **BLOCKED** | No Plasma session available. KWin 5/5 and KWin with XWayland 7/7 in containers |
| M4 | Physical HiDPI | **BLOCKED** | This machine's screens are at 100 %, and changing your display scale is your decision; emulated and virtual scaling pass |
| M5 | Minimum window on a real screen | **PARTIAL** | Windows: a real window at 800 × 480 on a physical 1920 × 1080 screen at 100 %, 37/37 (every page, project tab and the finding form). Not on HiDPI or Linux; does not block |
| M6 | Desktop portals | **BLOCKED** | Needs the M2 and M3 sessions. The file dialog is `GtkFileChooserNative`, which uses the portal only with `GTK_USE_PORTAL=1` or in a sandbox; does not block unsandboxed packages |
| M7 | A real login keyring | **BLOCKED** | Needs a login session. GNOME Keyring unlocked by a script passes 16/16 in containers |
| M8 | First GitHub Actions run | **BLOCKED** | Needs your push. The static review and guards pass (section 5) |
| M9 | Code signing | **BLOCKED** | Your certificate and keys. The setup is documented (section 6) |
| M10 | Installers | **BLOCKED** | Your authorization. The procedure is documented (`RELEASE_CANDIDATE_PROCEDURE.md`) |

The procedures are in `docs/release/`:

* `MANUAL_VALIDATION.md` (M1–M7): each item's environment, steps, expected results, evidence and pass criteria;
* `GITHUB_FIRST_RUN.md` (M8);
* `SIGNING_SETUP.md` (M9);
* `RELEASE_CANDIDATE_PROCEDURE.md` (M10).

### 4. Security findings and accepted risks

| Risk (SECURITY.md) | Verified | Reproduced | Impact, exploitability | Outcome |
|---|---|---|---|---|
| GUI tools and a terminal start without a native dialog | Yes: the inventory of every `Command::new` found only these, plus version probes | Guard test against the earlier code | A compromised page could start GUI tools (a proxy listener, a vendor's update or licence check) or open terminals, without passing them anything. Low | **Fixed** (`fb1f323`). Checked live on Windows: the terminal declined (no terminal opened); a stand-in GUI tool declined, then approved. On Linux, the GTK dialogs: 6/6 on Debian and 6/6 on Ubuntu |
| Version probes start without a dialog | Yes | n/a | They run detected catalog tools with fixed flags; a page can trigger them but not choose the program or the arguments. The ProjectDiscovery tools pass `-duc`, so nothing is contacted | **Still accepted**, with that rationale recorded and the flag kept by a test |
| A compromised page reopens an ended project | Yes | **Live on the earlier build:** archived → active through IPC in 2 ms, no dialog | Reopened, its scope is usable by the HTTP request builder and TLS analyzer without a dialog per request, and by MCP clients. Low to medium; needs a compromised page | **Fixed** (`d3c654f`): a native dialog naming the project and what becomes usable, and a compare-and-set save. Live: declined (stays archived) and approved. On Linux, the same GTK dialog checks |
| Copied commands in PowerShell | Yes | In real shells: Windows PowerShell 5.1 passing to a native program, and bash with history expansion | A word with a quote arrived split; pasting never ran another command. Low (correctness) | **Narrowed** (`8fe5ab5`). A word with a quote and none of `$`, a backtick, `"`, `\`, `!` is double-quoted and arrives whole in both shells. The rest is still accepted: exact copies for every word need the argument list stored (a schema change, deferred as backlog item 76) |

**The release workflow:** a tag moved during a run could put the release on another commit than its binaries. Severity Low: it needs write access to the repository and a mistimed or malicious move. **Fixed** in `af88c00`, with two tag checks, tested against a stubbed `gh`.

No new product vulnerability was found. The other accepted risks in SECURITY.md are unchanged.

### 5. The GitHub workflows

* **Pins.** Every action is pinned to the commit of the upstream tag its comment names (`git ls-remote`); `dtolnay/rust-toolchain` is the head of its `stable` branch.
* **Downloads.** The gitleaks and actionlint sums equal the published checksum files. The Debian image digest is an official Rust 1.99.1 bookworm image from 2026-10-28; its tag has been rebuilt since, which the pin deliberately ignores.
* **Toolchains.** Exact versions throughout. The runner images and the Ubuntu packages float, which hosted runners cannot avoid.
* **Permissions.** Read-only for CI; nothing at the top of the release workflow, and `contents: write` only for `publish`.
* **Pull requests.** No `pull_request_target`; CI reads no secret; the release has no pull-request trigger.
* **Publishing.** It needs a manual run, the `RELEASE_PUBLISHING` variable, the environment's reviewers, and for a public release *draft* unchecked with the tag typed again. A tag push validates only; pre-release tags are refused.
* **Separation.** The verification and release workflows are separate. CI never builds packages and never touches user data: tests use in-memory databases and temporary folders, and the only resolution of the real data folder needs a running app.
* **actionlint did not run.** It is not installed, and its container was not permitted in Mission 7. In its place: static guards in `ci_tests.rs` (5 tests, one of them Linux-only), all 43 scripts through `bash -n`, and a local test of the tag check. CI runs actionlint on the first push.
* **The release build's Linux image**, Ubuntu 22.04: `cargo check --locked --release --bins` passed. It was a type-check; nothing was built.
* **Corrections.** The checklist's advice to push an `-rc` tag was wrong, since the workflow refuses pre-release tags. `GITHUB_FIRST_RUN.md` gives the correct sequence.

### 6. Signing

* **Update signatures** (minisign, Ed25519, version-bound) are configured in the build job. The public key `957F3F7D955C72FA` is compiled in, and the private key exists on the owner's computer; it was not opened in this mission.
* **Authenticode is not configured:** `bundle.windows` is unset, and no certificate exists. It covers `cyber-hub.exe`, `cyberhub-mcp.exe`, the NSIS installer and the MSI.
* **SIGNING.md** wrongly called the sidecar an `externalBin`. Corrected: it is a second binary of the crate, and whether Tauri signs it must be verified on the first signed build.
* **Linux packages** carry no package signature; `SHA256SUMS.txt`, GitHub's digests and the update signatures cover them.
* **The verification commands** were checked here. On a signed third-party binary: `Valid`, with an RFC 3161 timestamp. On the development build: `NotSigned`.
* **`SIGNING_SETUP.md`** covers:
  * formats and tools, secret names and formats;
  * certificate routes (hardware-backed keys; at most 460 days);
  * how development and release builds differ, how failures stop a release;
  * the CI step to add, independent verification, rotation and expiry.

### 7. Cross-platform regression (at `af88c00`)

| Environment | tsc | Frontend tests | clippy | cargo test | ignored | MSRV 1.90 | npm audit |
|---|---|---|---|---|---|---|---|
| Windows 11 Pro 10.0.26200, rustc 1.94.1, Node 24.19.0 | OK | 303 in 55 files | OK | 637 passed | 28 | (Linux) | 0 |
| Ubuntu 24.04.5, rustc 1.99.1, Node 22.12.0, WebKitGTK 2.52.6 (container) | OK | 55 files | OK | 637 passed | 28 | OK | 0 |
| Debian 12, rustc 1.99.1, Node 22.12.0, WebKitGTK 2.50.6 (container) | OK | 55 files | OK | 637 passed | 28 | OK | 0 |

**GUI and end-to-end** (the real app, debug builds, disposable data, no network on Linux):

| Phase | Windows | Ubuntu | Debian |
|---|---|---|---|
| End-to-end script (WSTG exception, EVTX chains and logons through the native Open dialog, ATT&CK Mobile and ICS with a layer saved through the native Save dialog, a Prowler import) | 23/23 | | |
| Mission 8 dialogs (terminal, GUI tool, reopen) | live (section 4) | 6/6 | 6/6 |
| TAXII credential lifecycle | 16/16 (all but the dialog) | 16/16 | 16/16 |
| Mission 7 dialogs, minimum window, HiDPI | | 7/7, 3/3, 5/5 | 7/7, 3/3, 5/5 |
| Start with a newer database | | PASS | PASS |
| Mission 6 main | | 11/11 | 11/11 |
| Segment 3 (scope, imports, findings, workflows, MCP, backup, restore and restart, SIGKILL recovery) | | 63/63, 6/6, 3/3 | 63/63, 6/6, 3/3 |
| Compositors (KWin with XWayland, Mutter, KWin) | | 7/7, 5/5, 5/5 | |
| A server removed 10–405 ms after Store, 17 times | | none left behind | none left behind |

**Commands:**

* Windows: `npx tsc -b --noEmit`, `npx vitest run`, `cargo clippy --offline --all-targets -- -D warnings`, `cargo test --offline`, `cargo audit`, `npm audit`.
* Linux: the same with `--locked`, run from a copy of the tree in the containers, and `cargo +1.90.0 check --locked --all-targets`.

**The 28 ignored tests** are the same as in Mission 7: 10 timing and volume, 10 amplification, and 8 that need samples kept outside the repository.

**Other checks:**

* **Malformed input** is in the default suites (`hostile_tests.rs` and the parser regressions).
* **MCP:** the suites, segment 3 on Linux, and three read tools through the real sidecar on Windows.

**Unexpected failures, investigated:**

* The first M1 run on Windows passed 13 of 16.
  * Step 6 expected 3 saved indicators. The product saves only public ones and skipped the documentation address, so the procedure was wrong; it is corrected.
  * Step 17 depended on step 6.
  * Step 10's MCP criterion was the harness's own error.

  The rerun on a new data folder passed 16/16.
* Two harness errors were mine and were corrected before any conclusion:
  * the tag check's `gh` stub dispatched on the wrong argument;
  * a test compared JSON keys in written order, though serde sorts them.

### 8. Dependency audits and secret scan

* **cargo audit 0.22.2:** 0 vulnerabilities in 652 crates. 8 allowed warnings: 7 unmaintained (`proc-macro-error`, and two versions each of `zbus_names`, `zvariant`, `zvariant_derive`) and 1 unsound (`glib` 0.18.5), all transitive through Tauri's Linux stack. The release notes had called these "seven unmaintained crates"; corrected.
* **npm audit:** 0, on Windows and both distributions.
* **gitleaks 8.30.1:** no leaks in the whole history (190 commits, up to `cc3d3ca`), nor in the documents this report commit adds.

### 9. Migrations and recovery

* **Every earlier schema** upgrades to 32 with all rows and a backup first, failed and interrupted upgrades are rolled back, and a killed upgrade recovers. The tests in the suites pass on all three systems.
* **A database from a newer version** is refused with a native message, and the file is unchanged: Linux GTK on both distributions in this mission; Windows live in Mission 7, with no change to that code since.
* **Backup and restore with a restart:** segment 3 on both distributions. A backup was also made through the native dialog on Windows during M1.
* No migration was added (schema 32).
* **The upgrade from the earlier builds** (`d1cf064` at schema 8, and later development schemas) is part of M10, on a copy.

### 10. Manual tasks left for the owner

1. **M1:** steps 2, 3 and 9 of `docs/release/TAXII_CREDENTIAL_TEST.md` on Windows 11. The whole procedure takes about 45 minutes, in an account without your own TAXII credentials.
2. **M2, M3, M6, M7:** `docs/release/MANUAL_VALIDATION.md` on Ubuntu 24.04 GNOME and on Kubuntu 24.04 or Debian 12 KDE (hardware or VMs), with the release-candidate packages.
3. **M4, M5:** physical HiDPI at 100–200 % on Windows and Linux, and the minimum window.
4. **M8:** create the repository and its settings, push, and check CI (`GITHUB_FIRST_RUN.md`).
5. **M9:** choose the Authenticode route, obtain the certificate, set up the `release` environment and its secrets, and add the release-only signing configuration with its verification step (`SIGNING_SETUP.md`).
6. **M10:** authorize and start the one build, then test installation, upgrade on a copy, backup and restore, uninstall, Defender and SmartScreen; publish only after that (`RELEASE_CANDIDATE_PROCEDURE.md`).

### 11. Commands the owner will need

* **First push:**

  ```bash
  git remote add origin https://github.com/<owner>/<repo>.git
  git push -u origin release/v0.1.0
  ```
* **The tag, on the reviewed release-candidate commit:**

  ```bash
  git tag -a v0.1.0 -m "Cyber Hub 0.1.0" <commit>
  git rev-parse "v0.1.0^{commit}"
  git push origin v0.1.0
  ```
* **The update secrets**, without printing them: UPDATER.md, "Release secrets" (`gh secret set … --env release`).
* **Verification:**

  ```bash
  sha256sum -c SHA256SUMS.txt
  signtool verify /pa /all /v <file>
  Get-AuthenticodeSignature <file>
  node scripts/updater-manifest.mjs validate --manifest latest.json --assets <dir> --require windows-x86_64-nsis,windows-x86_64-msi,linux-x86_64-appimage,linux-x86_64-deb,linux-x86_64-rpm
  ```
* **Rollback before publishing:**

  ```bash
  git push --delete origin v0.1.0
  git tag -d v0.1.0
  ```

  Then delete the draft release.
* **After publishing, a bad release:** `gh release edit v0.1.0 --draft=true`, then fix forward with 0.1.1.

### 12. Actions that need your explicit authorization

1. Creating the GitHub repository, adding the remote, and pushing a branch.
2. Creating and pushing the tag `v0.1.0`.
3. Adding signing secrets and certificates, and the signing configuration.
4. Setting `RELEASE_PUBLISHING` to `enabled`.
5. Starting the release run and approving its deployments; this builds and signs the installers once.
6. Publishing the draft release.
7. Changing your display scaling, using your VMs or accounts for desktop tests, or installing the release candidate where your real data is.

### 13. Engineering readiness

| Requirement | Status |
|---|---|
| Automated tests, typecheck and lints on the three systems | PASS |
| MSRV 1.90 | PASS |
| Dependency audits and secret scan | PASS |
| Security: accepted risks reviewed, two fixed, one narrowed | PASS (code) |
| Release workflow: static review, tag integrity, guards | PASS (static); first run BLOCKED |
| The release build's Linux environment | PARTIAL (type-checked only) |
| Database upgrades, recovery, newer databases, backup and restore | PASS |
| TAXII on Windows | PARTIAL (dialog steps manual) |
| High-DPI, minimum window, Linux desktops, portals, keyring | PARTIAL (substitutes) / BLOCKED (real environments) |
| Code signing | BLOCKED |
| Installers | BLOCKED |

**The code is ready for the owner to push, set up signing and authorize one release-candidate build. Cyber Hub is not ready for release:** M1–M4 and M7–M10 must pass first, and the first GitHub run has not happened.

## Mission 9: autonomous end-to-end release execution (2026-11-11)

**Brief.** Take Cyber Hub from its current state to a validated, signed release candidate, using a broad authorization to:
* create and configure a private GitHub repository, push, and run and fix CI;
* provision disposable VMs and run the manual tests there;
* configure signing where valid credentials exist;
* build, install, upgrade and uninstall the candidate in isolation;
* prepare a draft release.

Never install the candidate where the owner's real database lives, never publish, never expose keys.

**Classification: BLOCKED.**
* **The release candidate was not built.** The release workflow needs the update-signing key in the `release` environment. Mission 9's attempt to store it was refused by the session's permission rules (secret-store writes); the brief says not to work around such a refusal.
* **There is no Authenticode certificate.** Buying one is the owner's decision; section 7 recommends a route.
* **The Windows 11 test VM hung in Windows Setup** under VirtualBox with Hyper-V active.

Everything that did not need those three was done:
* the repository and CI;
* the Linux desktop validation in real sessions, which found three defects, all fixed with tests;
* the documents.

**Times:** 2026-11-11T19:08Z (`date -u`) to the commit that adds this report.

### 1. Repository and privacy

* **Repository:** `https://github.com/RChefo/cyber-hub`, **private** (`isPrivate: true`, visibility `PRIVATE`), created by Mission 9 with `gh` as `RChefo`.
* **Before anything left the machine:** gitleaks 8.30.1 scanned the whole history at `a1edbaf`: 191 commits, no leaks.
* **Settings, the plan's limits and the third-party apps:** `docs/release/GITHUB_FIRST_RUN.md`, "Mission 9".
  * Actions are limited to the six pinned actions, SHA pinning is required, and tokens are read-only.
  * The `release` environment allows only `main` and `release/*`, with no administrator bypass.
  * Refused on GitHub Free: required reviewers, wait timers, rulesets, branch protection and secret scanning.
  * Eight third-party GitHub Apps installed with access to all repositories receive this repository's commits.

### 2. Branches and tags

* **Pushed:** `release/v0.1.0` only, which is the default branch.
* **Not pushed:** no tag, and no other branch. `main` does not exist on GitHub.

### 3. GitHub Actions

| Run | Commit | Result |
|---|---|---|
| [43084985623](https://github.com/RChefo/cyber-hub/actions/runs/43084985623) | `a1edbaf` | **Success**, 22 min. Every job green (below) |
| [43089305680](https://github.com/RChefo/cyber-hub/actions/runs/43089305680) | `5ad2ad1` | **Success**, 12 min, all five jobs |
| [43095621019](https://github.com/RChefo/cyber-hub/actions/runs/43095621019) | `ed99331` | **Queued, not started** (no job created, since 20:22Z) |
| [43097581846](https://github.com/RChefo/cyber-hub/actions/runs/43097581846) | `63d2cd6` | **Queued, not started** (since 20:41Z) |
| [43105721393](https://github.com/RChefo/cyber-hub/actions/runs/43105721393) | `d4372b5` | **Success**, 12 min, the final code: 641 passed, 28 ignored, on each platform; 56 frontend test files; MSRV 1.90; gitleaks 196 commits; cargo audit 0 (8 allowed warnings) |

Jobs of the first green run:
* `windows-2022`, `ubuntu-24.04`, Debian 12: 637 passed, 28 ignored, each;
* MSRV 1.90;
* dependency and secret scans: cargo audit 0 with 8 allowed warnings, gitleaks 191 commits, **actionlint 1.7.7 with shellcheck, first run, clean**, npm audit 0.

No job failed, so nothing needed fixing. Why two runs never started is unknown. The next push ran at once and verified the final code, so they are superseded. GitHub's status page showed no incident; the likeliest cause is the account's Actions minutes or billing for private repositories, which this token cannot read.

`release.yml` has not run: no tag was pushed, because the candidate could not be built.

### 4. Commits

| Commit | Change |
|---|---|
| `5ad2ad1` | test(db): write older-schema data folders for the installer upgrade test |
| `810e024` | fix(palette): order result groups by their best match |
| `ed99331` | fix(restore): remove an interrupted stage's copy at the next start |
| `63d2cd6` | fix(credentials): check for a stored credential without unlocking the keyring |
| (this commit) | docs: the Mission 9 results, readiness checklist, release documents and tracking files |

### 5. Windows and Linux desktop validation

**The VMs.**
* **Where:** disposable VirtualBox 7.2.6 VMs on E:, NAT only, VM disks in `E:\CyberHubQA\vms`.
* **Logins:** password logins at GDM and SDDM, typed on the VM's virtual keyboard.
* **Driving:** the app through WebDriver; native GTK dialogs through AT-SPI; real key presses and full-screen screenshots through VirtualBox.
* **Evidence:** screenshots in `E:\CyberHubQA\evidence\` (folders `M2-*`, `M3-*`, `M6-*`, `M7-*`); the harness in `E:\CyberHubQA\desk\`.
* **Build:** the development build of the fixed code.
* **Details:** `docs/release/MANUAL_VALIDATION.md`, "Mission 9".

| Environment | Result |
|---|---|
| Ubuntu 24.04.5, GNOME Shell 46.0: Wayland, Xorg, XWayland | **M2:** all 12 steps in Wayland; steps 1–8, the backup of 9, 10 and 12 in Xorg; steps 1–6, 10 and 12 under XWayland. **M6 passes** with and without the portal (GNOME's GTK 4 chooser through the portal). **M7 steps 1–7 pass** with the PAM-unlocked login keyring |
| Debian 12, KDE Plasma 5.27.5 and KWin 5.27.5: Wayland, X11, XWayland | **M2:** steps 1–6, 10 and 12 in all three; in Wayland also 7, 8, the backup of 9, and 11. KDE's "— Portal" dialog works through the portal. **No crash under XWayland.** Credential storage was not usable in this VM: GNOME Keyring lists a `login` collection it does not serve, and `secret-tool store` hangs. Cyber Hub fails at once with a clear error and nothing else breaks (M3 step 13). KWallet's Secret Service was not tried |
| Windows 11 Enterprise Evaluation 26H2, VirtualBox with Hyper-V active | **Not reached.** Windows Setup stopped writing to its disk at 20:23Z with a black screen. Powered off at 21:31Z. The ISO's SHA-256 is `BC3F2408…C10E38`; Microsoft publishes no hash for it |

**M7 steps in GNOME:**
* **Steps 1–3:** the GTK dialog asks, and stores one entry in the login keyring.
* **Step 4:** the credential is kept across a restart and across logging out and in, with no prompt.
* **Step 5:** with the keyring locked, *Replace* makes GNOME Shell ask "Authentication required" once, and stores after the password. Cancelling gives "unlock prompt was dismissed", stores nothing, and no prompt follows.
* **Steps 6 and 7:** Forget and Remove leave nothing.

**Not covered: the packages** (deb, AppImage, rpm, desktop entry). They come with the candidate.

### 6. TAXII credential tests

* **GNOME:** M7 steps 1–7 pass with a real login keyring (section 5).
* **Windows:** M1 stays PARTIAL. It is Mission 8's 16/16 automated run, without typing into the dialog, because the Windows VM did not finish installing.
* **Prepared for a Windows VM or Windows Sandbox:** an M1 run that types into Windows' credential dialog from the host keyboard (`E:\CyberHubQA\win-share\m1\m1-vm.mjs`). It was not run.

### 7. Signing certificate status

* **Authenticode: none.** The current-user and machine stores hold no certificate with the code-signing usage, there is no smart-card reader, and no signing client is installed.
* **Recommendation** (research of 2026-11-11, `docs/release/SIGNING_SETUP.md`):
  * **SSL.com IV with eSigner**, about $309 a year, open to individuals in most countries, works on GitHub-hosted runners with a TOTP secret.
  * **Fallback:** Sectigo as an individual with a Google Cloud KMS key.
  * **Not available here:** Microsoft Artifact Signing serves individuals only in the US and Canada.
* **Update signing.** The key pair exists. The public key next to it is the app's (`957F3F7D955C72FA`). The key file is one line with no newline. Neither value was read. Storing the two secrets in the `release` environment was refused by the permission rules, and that is the owner's step (`SIGNING_SETUP.md`, section 5, "Commands").
* **Corrected:** `UPDATER.md`'s snippet for storing them could not have worked, since PowerShell has no `<` and a pipe adds a newline to the password.

### 8. Security findings and fixes

Found in the real desktop sessions:

| # | Finding | Severity | Fix |
|---|---|---|---|
| 1 | With the keyring locked, any page showing whether a credential is stored read the credential's value, so the desktop asked to unlock it. The TAXII list did this inside the database lock: the whole app waited until the prompt was answered (projects took 4.2 s to list, reproduced live), and a dismissed prompt showed the stored credential as missing | Medium (availability; misleading state) | `63d2cd6`. On Linux, presence is now a Secret Service search that neither unlocks nor transfers a value, made after the database lock is released. Two guard tests. Live in GNOME: the list returns in 9 ms with the credential shown as stored, and nothing waits |
| 2 | A process stopped while a restore was being staged left a full copy of the chosen backup, `.restore-<id>.partial` and its `-journal`, hidden in the data folder for good. Documented before as a known limitation | Low (data hygiene) | `ed99331`. The next start removes it. A test fails on the earlier code |
| 3 | The command palette listed pages that merely contained the query before a project whose name starts with it: "RC" + Return opened Cyber Resources | Low (usability) | `810e024`. Groups are ordered by their best match. 5 unit tests; checked live in GNOME, Plasma and XWayland |

**Mission 8's accepted risks re-checked.**
* Unchanged: the version probes, planning/active/paused moves, and the PowerShell remainder.
* The native-confirmation boundaries were re-verified in real sessions: Return at once cancels, an early click does nothing, and the terminal asks.

**Documentation errors corrected:**
* MANUAL_VALIDATION's import sample lacked `<runstats>`, which makes the preview warn.
* MANUAL_VALIDATION expected the preview to list an address it never lists.
* UPDATER's PowerShell snippet.
* UPDATER's environment advice: tags instead of branches.
* SIGNING's Artifact Signing regions.

### 9. Regression

| Where | Commit | Result |
|---|---|---|
| GitHub: Windows Server 2022, Ubuntu 24.04, Debian 12 (Rust 1.99.1) | `a1edbaf`, `5ad2ad1` | 637 passed, 28 ignored, on each; frontend tests, tsc, clippy, MSRV 1.90 (`msrv` job) |
| GitHub, the same | `d4372b5` (the final code) | **641 passed, 28 ignored, on each**; 56 frontend test files; tsc; clippy; MSRV 1.90; gitleaks 196 commits; cargo audit 0 |
| Windows 11 (this machine) | the final code | `cargo test`: **641 passed, 28 ignored** (+4: the fixture writer, the restore test and the two credential guards); clippy with warnings denied; `tsc -b`; **vitest 308 tests in 56 files**. cargo audit 0.22.2: 0 vulnerabilities, 8 allowed warnings, 652 crates; npm audit 0 |
| Ubuntu 24.04 image (Rust 1.99.1) | the final code | `cargo test`: **641 passed, 28 ignored**, including the Linux-only credential check; the Linux build. Clippy is not installed in that image, and the CI clippy for these commits is queued |
| Real sessions | the final code | Section 5 |

* **Migrations, backups and recovery:** the upgrade tests ran in CI. `write_upgrade_fixtures` produced databases at schemas 1, 8, 19, 26 and 31. The restore cycle ran in a real GNOME session.
* **Parsers:** the fuzz entry points compile, and the hostile-input suites pass in CI.
* **MCP:** the suites pass in CI.
* **Workflows:** actionlint on GitHub, plus the static guards in every `cargo test`.
* **gitleaks 8.30.1:** 195 commits up to `63d2cd6`, and the documents of the report commit, without leaks (before committing them).

### 10–13. Release artifacts, checksums, signatures, installation

**None.** No package, installer or release binary was built, so there is nothing to checksum, verify, install, upgrade or uninstall, and no draft release.

The downloaded test images were checked against their published sums:
* the Ubuntu cloud image's SHA-256 matched Canonical's `SHA256SUMS`;
* the Debian image's SHA-512 matched Debian's `SHA512SUMS`;
* Node 22.23.5 for the Windows VM matched `SHASUMS256.txt`.

### 14. Database isolation

* **The owner's real database was never opened.** Its modification time is unchanged: `2026-11-05T15:58:24.8534883Z`, at the start and the end of Mission 9.
* **Where every app run happened:**
  * inside the disposable VMs, with their own users and data folders;
  * in containers;
  * as `cargo test` with temporary folders.
* No installer was run, and nothing was installed on this machine.

### 15. Draft release

None was created.

### 16. Remaining blockers

1. **Update-signing secrets:** the owner stores them (`SIGNING_SETUP.md`, section 5, "Commands"). That unblocks the candidate build.
2. **Authenticode:** buy and validate a certificate (SSL.com IV recommended), then add signing and its verification step.
3. **Two GitHub Actions runs never started**; the next push ran normally. If it happens again, check the account's Actions usage and billing.
4. **M1 typing into Windows' dialog:** enable Windows Sandbox or use a Windows VM without a shared hypervisor. A person can also do the three steps by hand.
5. **M4:** a physical HiDPI screen.
6. **Plasma's credential store:** test with KWallet serving the Secret Service, or with a working GNOME Keyring.
7. **M10:** the candidate's packages, installed on clean machines.
8. **Recommended:**
   * limit the eight third-party GitHub Apps to the repositories that need them;
   * consider GitHub Pro for tag rulesets and branch protection.

### 17. Readiness

**BLOCKED.**
* The code is in good shape:
  * the suites pass;
  * real GNOME and Plasma sessions behave as specified;
  * three defects found there were fixed with tests;
  * the repository, CI and the release environment are in place.
* No release candidate exists, so nothing about installing, upgrading, signing or Defender's reaction is proven.
* Cyber Hub must not be released before items 1–4 and 7 of section 16 are done.

**Mission 9's infrastructure:**
* **The repository:** stays, private.
* **The Linux VMs** `chqa-noble` and `chqa-deb12`: kept, powered down with their state saved, for the candidate's Linux tests.
* **The Windows VM** `chqa-win11`: powered off, kept, but not usable.
* **What to delete when done:** `E:\CyberHubQA` (images, VMs, harness, evidence) and the three VMs in VirtualBox. Nothing of Mission 9 is on C: except the scratchpad.

## Mission 10: release-candidate completion (2026-11-11 and 12)

**Brief.** Resolve the remaining blockers, then build and validate the first release candidate and prepare a private draft release, but only once the signing prerequisites are in place.
* Never publish, never make the repository public, never expose or print signing material.
* Buy nothing without authorization, and do not enable `RELEASE_PUBLISHING` without a separate authorization.
* Never touch the real database, and never install a candidate on the owner's Windows.

**Classification: BLOCKED.**
* **No release candidate was built.** The signing prerequisites are not in place:
  * the update key's password is not in the `release` environment, because the session's permission classifier refused the command;
  * the release workflow builds only while `RELEASE_PUBLISHING` is `enabled`, and no authorization to set it was given;
  * there is no Authenticode certificate, and buying one needs the owner.
* **Everything that did not need the candidate was done.** Windows M1 passes 17/17 with every credential typed into Windows' own dialog. M7 passes on Plasma with KWallet and with GNOME Keyring. Virtual HiDPI passes on GNOME and Windows at four scales. The signing decision is documented.
* **No defect was found in Cyber Hub, and no code changed.**

**Times:** 2026-11-11T22:11Z (`date -u`) to the commit that adds this report.

### 1. Starting and ending commits

* **Start:** `c7052bd` on `release/v0.1.0`, clean, the same as GitHub, no tag.
* **End:** the commit that adds this report. It changes documentation only. The code is unchanged since `63d2cd6`.

### 2. GitHub Actions runs

| Run | Commit | Result |
|---|---|---|
| [43105721393](https://github.com/RChefo/cyber-hub/actions/runs/43105721393) | `d4372b5` (the final code) | **Success:** 641 passed, 28 ignored, on each of `windows-2022`, `ubuntu-24.04` and Debian 12; MSRV; actionlint, gitleaks, cargo audit, npm audit |
| [43107766877](https://github.com/RChefo/cyber-hub/actions/runs/43107766877) | `c7052bd` | **Success,** 10 min |
| The run for this report's commit | this commit | Started by the push; its result is on the repository's Actions page (documentation only, so it re-tests unchanged code) |
| [43095621019](https://github.com/RChefo/cyber-hub/actions/runs/43095621019), [43097581846](https://github.com/RChefo/cyber-hub/actions/runs/43097581846) | `ed99331`, `63d2cd6` | **Still queued, never started** (since 2026-11-11 20:22Z and 20:41Z). Superseded; left alone |

`release.yml` has never run: no tag was pushed.

**GitHub settings, read back on 2026-11-12:**
* the repository is private;
* Actions are limited to six action patterns, with SHA pinning required, a read-only `GITHUB_TOKEN`, and no approving pull requests;
* fork pull requests get no runs, no write tokens and no secrets;
* the `release` environment allows branches `main` and `release/*`, with no administrator bypass;
* there are no repository secrets and no variables, so **`RELEASE_PUBLISHING` is not set**.

### 3. Update-signing secrets

* **`TAURI_SIGNING_PRIVATE_KEY`: stored** in the `release` environment from the key file through `gh`'s standard input. Its metadata says updated 2026-11-11 22:13:18Z. The value was never printed, put in an argument or written elsewhere.
* **`TAURI_SIGNING_PRIVATE_KEY_PASSWORD`: not stored.** The command that pipes it from Credential Manager into `gh secret set` was refused by the session's permission classifier. Per the brief, the refusal was not worked around.
  * **What it takes:** the owner runs `SIGNING_SETUP.md`, section 5, "Commands", or allows this PowerShell command in the session's permission rules.
* **The key pair matches the app.** `plugins.updater.pubkey` in `tauri.conf.json` is identical to `cyberhub-updater.key.pub` (key ID `957F3F7D955C72FA`).

### 4. Authenticode certificate status

* **None exists. Nothing was bought or ordered.**
* **Research added to `SIGNING_SETUP.md`:**
  * **SmartScreen,** from Microsoft's page dated 2026-05-04: OV and EV certificates both start with the "unrecognized app" warning until reputation builds. EV no longer bypasses it, and changing the certificate affects the publisher signal.
  * **Identity:** an individual certificate puts the owner's legal name on the binaries; an organization certificate needs a registered entity.
  * **Key storage:** a cloud key works with GitHub-hosted runners; a token needs a self-hosted runner.
  * **Timestamps and renewal:** RFC 3161 timestamps keep signatures valid after expiry. Certificates last at most 460 days, and a renewal should keep the same subject.
  * **First-year cost:** about $309 for the recommendation (SSL.com IV with eSigner), about $332 for the fallback (Sectigo with Cloud KMS), about $120 for Artifact Signing where eligible, $696–972 for DigiCert KeyLocker.
* **The MCP binary's signature.** By tauri-cli 2.12.4's source, the bundler signs `cyberhub-mcp.exe` with the other crate binaries whenever Windows signing is configured. The planned verification step still checks it.

### 5. Windows environment

* **`chqa-win11b`:** a new disposable VM.
  * Windows 11 Enterprise Evaluation 26H2, build 26300.9457, from the ISO checked in Mission 9.
  * VirtualBox 7.2.6 on Hyper-V, 2 vCPUs, no paravirtualization, an emulated TSC.
  * NAT only, Guest Additions 7.2.6, local user `tester`, WebView2 157.0.4341.46.
* **The owner's Windows was not changed.** Nothing was installed on it, and its Credential Manager was not touched.
* **The first Windows VM (`chqa-win11`)** stays unusable: it hung in setup in Mission 9.
* **Windows Sandbox was not needed.**

### 6. TAXII test results

* **Windows, M1: 17/17 in run 3** (2026-11-12T00:04–00:07Z), every credential typed into Windows' own credential dialog. Details: `docs/release/MANUAL_VALIDATION.md`, "Mission 10".
  * **How it was typed:** through the VM's virtual keyboard, because the dialog runs above the test's integrity level.
  * **What the local test servers saw:** the typed password, the rotated password and the API key.
  * **Cancel, Escape and close** stored nothing.
  * **Deletion:** moving the server, Forget and Remove all deleted the credential.
  * **No leaks:** no test value appeared in data, exports, the backup, diagnostics, activity or MCP results.
  * **At the end:** no `taxii_` entry was left.
* **Runs 1 and 2 had 16/17,** both on step 16 (an early click on Delete is ignored), both through harness errors:
  * run 1's click was seconds late, after Delete had been enabled, so approving was correct;
  * run 2 looked up a control ID that task-dialog buttons do not carry.
* **Run 3's timings:** Delete was disabled when the dialog appeared. A click at 59 ms left the dialog open, Delete was enabled at 993 ms, and a click at 1,105 ms deleted the credential.

### 7. GNOME, KDE and KWallet results

* **GNOME 46 (Mission 9):** M2, M6 and M7 steps 1–7, unchanged.
* **Plasma 5.27.5 X11 on Debian 12, with GNOME Keyring:** after a fresh boot, M7 steps 1–7 pass. Mission 9's failure was that session's state.
* **Plasma 5.27.5 X11, with KWallet as the Secret Service** (GNOME Keyring purged; `kwalletd5` from KDE Frameworks 5.103; `pam_kwallet5`):
  * M7 steps 1–7 pass;
  * step 5 with KWallet's own password prompt, after the wallet was closed;
  * a cancelled prompt gives a clear error and no loop.
* **VM environment issues, not Cyber Hub:**
  * Plasma's power management suspended the Debian guest after about 40 minutes, and its e1000 adapter hung on resume;
  * resuming a saved state crashed a VM process under Hyper-V.

### 8. HiDPI results (virtual only)

| Environment | 100 % | 125 % | 150 % | 200 % |
|---|---|---|---|---|
| GNOME 46 Wayland, 2560 × 1600 (Mutter `scale-monitor-framebuffer`) | 5/5 | 5/5 | 5/5 (1.5023) | 5/5 |
| Windows 11, 2560 × 1600 (per-monitor DPI, as Settings sets it) | 5/5 | 5/5 | 5/5 | 5/5 |

The checks at each scale:
* the page's scale and logical screen;
* the first window inside the work area (sized to it at 200 %);
* six pages without sideways scrolling;
* the native confirmation, with Cancel as the default;
* the 800 × 480 minimum: a window resize on GNOME, a mouse drag of the corner on Windows;
* no page error.

On Windows the run was repeated (pass 3, 20/20) with the launcher's console hidden, so the screenshots show the app and its dialogs.

**Observations:**
* **GNOME:** `devicePixelRatio` is 2 at 125 and 150 %. GTK 3 renders at the next whole scale, and the compositor scales the window down (FEATURE_BACKLOG.md, item 91).
* **Windows:** another program's `SetWindowPos` can size the window below the minimum. Windows limits only sizing by the user (item 92).

**No physical HiDPI screen was used.** M4 stays blocked on hardware.

**Harness corrections on the way (none in Cyber Hub):**
* the expected `devicePixelRatio` on GNOME;
* the confirmation's test ranges: two public ranges were added in the VM's test data and then removed;
* the Windows scale helper;
* the Windows minimum check;
* the console window that covered pass 2's screenshots.

### 9. Linux package installation results

**None.** No deb, AppImage or rpm exists without the candidate. The Ubuntu and Debian VMs are kept for these tests.

### 10. Full regression results

* **The code is unchanged since `63d2cd6`.** Its full regression is CI run 43105721393: 641 passed and 28 ignored on Windows, Ubuntu and Debian, 56 frontend test files, tsc, clippy, MSRV 1.90 and the scans. Run 43107766877 (`c7052bd`) is green too.
* **This commit's CI run** re-runs everything on the same code; its result is on the repository's Actions page.
* **Audits on 2026-11-12:**
  * cargo audit 0.22.2: 0 vulnerabilities, 8 allowed warnings, including the new RUSTSEC-2026-0372 (`zvariant_derive` unmaintained, a transitive dependency of the D-Bus crates);
  * npm audit of the app: 0.
* **GitHub's Dependabot alerts,** two medium, both open since 2026-11-11 and not mentioned in Mission 9's report:
  * `glib` below 0.20 (GHSA-wrw7-89jp-8q8g): the unsound iterator already allowed in cargo audit;
  * `minimatch` 10.2.6 in `website/`'s ESLint tools (GHSA-g3hv-75wg-m249): development only, not in the app; npm audit of `website/` counts it 10 times through the lint packages (FEATURE_BACKLOG.md, item 94).
* **gitleaks and actionlint** run in CI on every push.
* **Real sessions and VMs:** sections 6–8.

### 11–13. Release artifacts, SHA-256 checksums, signature verification

**None.** No package, installer or release binary was built, so there is nothing to checksum or verify. The VMs' development builds are test builds, not artifacts.

### 14. Database isolation evidence

* **The real database was never opened.** Its modification time is `2026-11-05T15:58:24.8534883Z` (2026-11-05 17:58:24.8534883 +02:00), the same at the start and the end.
* **Where every Cyber Hub run happened:**
  * inside the VMs, with their own users;
  * on Windows, data folders in the VM's temporary folder: `chqa-m1\data` for M1 and `chqa-hidpi\data` for HiDPI, both deleted and recreated per run;
  * on Linux, the VMs' QA data folders.
* **The Windows debug build** was compiled on the host and run only inside the VM.
* **No installer was run anywhere.**
* **The only QA data changed by mistake:** two public test ranges in the Ubuntu VM's QA project, removed again (section 8).

### 15. Private draft release

**None was created.**

### 16. Every remaining blocker

1. **The update key's password secret.** The owner runs `SIGNING_SETUP.md`, section 5, "Commands". Alternatively, a session may run it if the owner adds a permission rule for that PowerShell command.
2. **`RELEASE_PUBLISHING`.** The release workflow builds only while this repository variable is `enabled`. Setting it is the owner's authorization. A run still stops at a draft unless *draft* is unchecked and the tag is typed again. FEATURE_BACKLOG.md item 90 proposes a separate build switch.
3. **Authenticode.** The owner authorizes and buys a certificate (SSL.com IV with eSigner recommended, about $309 a year), completes the identity validation, and adds signing and its verification step (`SIGNING_SETUP.md`, section 6).
4. **The candidate itself.** Tag `v0.1.0`, build once, then test the installers and packages (M10):
   * on the clean Windows 11 VM `chqa-win11b`;
   * on the Ubuntu 24.04 and Debian 12 VMs;
   * including upgrade from the fixture data folders, backup and restore, uninstall, and M1 on the installed copy.
5. **M4 on a physical HiDPI screen.**
6. **Recommended:**
   * limit the eight third-party GitHub Apps to the repositories that need them. Five of them can administer environments, start workflows or change workflow files (`GITHUB_FIRST_RUN.md`, "Mission 10");
   * GitHub Pro for tag rulesets, branch protection and required reviewers.

**QA storage (report only, nothing deleted).** `E:\CyberHubQA` holds about 64 GB; E: has 244 GB free.

| What | Size | Advice |
|---|---|---|
| `vms\chqa-win11b` (the working Windows VM) | 21 GB | Keep for the candidate's Windows tests |
| `vms\chqa-win11` (hung in setup in Mission 9) | 16 GB | Unusable: delete in VirtualBox (*Remove* → *Delete all files*) when convenient |
| `vms\chqa-noble`, `vms\chqa-deb12` | 7.5 GB, 7.1 GB | Keep for the package tests |
| `iso\` (Windows ISO 7.7 GB, Debian image 3.0 GB, Ubuntu appliance 0.6 GB) | 12 GB | Already imported; keep the Windows ISO only if another Windows VM may be needed |
| `evidence\`, `win-share\`, `desk\`, `linux-debug\`, `win-debug\`, `fixtures\`, `keys\` | about 0.8 GB | Keep until the release decision. `keys\` holds the VMs' SSH key and password only |

When the release is done: delete the four VMs in VirtualBox, then `E:\CyberHubQA`.

### 17. Final classification

**BLOCKED.**
* No release candidate exists, so nothing about the packages, installation, upgrade, signing or SmartScreen's reaction is proven.
* Every check that did not need the candidate passed, and the tests found no defect in Cyber Hub: Windows credentials, Plasma credentials with KWallet, and virtual HiDPI on two platforms.
* **Cyber Hub must not be released before items 1–4 of section 16 are done.**

**Mission 10's infrastructure:**
* **The repository:** stays private.
* **The VMs** `chqa-win11b`, `chqa-noble` and `chqa-deb12`: shut down from inside, never saved, and kept for the candidate.
* **`chqa-win11`:** off and unusable.

## Mission 10, continued: the release candidate (2026-11-12)

**What changed.** When the owner asked the session to continue, two of section 16's blockers were theirs to lift, and they did:
* they authorized the session to store the update key's password itself;
* they allowed `RELEASE_PUBLISHING` for one draft run, then for two more, when the first two failed and were fixed.

The release candidate was then built, verified, installed and tested. It is a **private draft release**. Nothing was published.

**Classification: RELEASE CANDIDATE PARTIALLY VERIFIED.**
* Every package was built and update-signed by the release workflow. Every signature verifies, independently too, and every checksum matches.
* Every package installed, ran and passed the app checks in disposable VMs (Windows 11, Ubuntu 24.04 GNOME, Debian 12 Plasma) or clean containers (Fedora for the rpm). That includes upgrade, rollback and uninstall.
* **Not verified:**
  * Authenticode: there is no certificate, so the Windows installers are unsigned, and SmartScreen and UAC say "unknown publisher";
  * an update end to end, which needs a published release and a later one;
  * physical HiDPI;
  * the rpm in a desktop session.
* **Found by the candidate's tests and fixed:** two release-pipeline defects, the password secret's byte-order mark and the update notes' length.
* **Found and recorded:** a start-up dependency on CA certificates, the MSI's install folder after an NSIS install, and the publisher name.

**Times:** 2026-11-12T12:04Z to the commit that adds this section.

### 1. Starting and ending commits

* **Start:** `f01dbdf`, clean, the same as GitHub, no tag.
* **Commits:**
  * `598b1f9` fix(release): shorten update notes that are longer than the app shows;
  * `add894e` docs(release): store the update key's password without a byte-order mark;
  * this documentation commit.
* **The tag `v0.1.0`** names `add894ecaa0d9d03da8a0709715dfc966fcf93f8`, locally and on GitHub. It was first created on `f01dbdf`, then moved with the owner's approval after the second build exposed the notes defect; nothing had been released from it.
* **The application code** is unchanged since `63d2cd6`. `598b1f9` changes only the update-manifest script and its test.

### 2. GitHub Actions runs

| Run | What | Result |
|---|---|---|
| [43219450467](https://github.com/RChefo/cyber-hub/actions/runs/43219450467) | Release, the tag push (`f01dbdf`) | Success: *Validate* only, with the notice that `RELEASE_PUBLISHING` is not enabled; *Build* and *Publish* skipped |
| [43222864191](https://github.com/RChefo/cyber-hub/actions/runs/43222864191) | Release, a manual run without the variable | Success: the same; nothing built (GITHUB_FIRST_RUN.md, section 5) |
| [43225209120](https://github.com/RChefo/cyber-hub/actions/runs/43225209120) | Release, draft run 1 | **Failure:** Linux built and bundled, then "incorrect updater private key password" (the stored password began with a byte-order mark). Windows cancelled, *Publish* skipped, nothing uploaded |
| [43231095560](https://github.com/RChefo/cyber-hub/actions/runs/43231095560) | Release, draft run 2 | **Failure:** both builds and signatures passed; *Publish* refused `latest.json`'s notes (25,720 characters, limit 20,000). Nothing uploaded |
| [43239973165](https://github.com/RChefo/cyber-hub/actions/runs/43239973165) | CI on `add894e` | Success, all five jobs |
| [43242291328](https://github.com/RChefo/cyber-hub/actions/runs/43242291328) | Release, the second tag push | Cancelled. It only validates; the draft run validated the same commit |
| [43242424304](https://github.com/RChefo/cyber-hub/actions/runs/43242424304) | Release, draft run 3 | **Success:** validate (641 Rust tests passed, 28 ignored; 56 frontend test files; clippy; npm audit 0; cargo audit 0 vulnerabilities in 652 crates, 8 allowed warnings), both builds and signatures, and *Publish* (manifest, tag check, upload to a draft, digest check) |
| The run of this commit | CI | Started by the push |

**`RELEASE_PUBLISHING`** existed only during the three draft runs (13:13–13:44Z, 13:50–14:35Z and 14:56–15:35Z). Each time it was deleted when the run ended, the last time 23 seconds after. No variable exists now.

### 3. Update-signing secret configuration status

* **Both secrets are stored** in the `release` environment, and the builds prove them: the key decoded, and the password opened it.
  * `TAURI_SIGNING_PRIVATE_KEY`: since 2026-11-11 22:13:18Z.
  * `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`: since 2026-11-12 13:47:49Z.
* **Neither value was displayed,** put in an argument or written to a file.
* **The first copy of the password** (12:34:26Z, through the documented command) began with a UTF-8 byte-order mark.
  * In Windows PowerShell, a child's standard input gets one first when the console uses UTF-8. A test string arrived as `efbbbf616263`.
  * The corrected command sets a mark-free input encoding and refuses to write if a mark would still be sent. SIGNING_SETUP.md and UPDATER.md carry it.

### 4. Authenticode certificate status

* **None.** Nothing was bought.
* **The NSIS installer, the MSI and the installed programs are "NotSigned".** What a Windows 11 user sees:
  * SmartScreen blocks the downloaded installers ("Windows protected your PC", "Publisher: Unknown publisher") until *More info → Run anyway*;
  * the MSI's administrator prompt says "an unknown publisher".
* **Microsoft Defender did not quarantine the installed program,** 11 minutes after its first start nor after a restart. In 2026-11-05's staging test, a development build had been quarantined.
* **Before distribution:** the certificate (SSL.com IV with eSigner recommended, about $309 a year), then rebuild the Windows installers.

### 5. Windows environment status

* **`chqa-win11b`:** Windows 11 Enterprise Evaluation 26H2. Pending updates were installed by a restart before the tests: build 26300.9457 → 26300.9974.
  * WebView2 157.0.4341.46.
  * Windows Update paused for seven days, sleep off.
* **One hang.** The guest stopped responding once (15:53:55Z, VirtualBox's heartbeat log). It was powered off and cold-booted; the test resumed. Disk resets were logged under host load.
* **Never touched:** the owner's Windows. Nothing was installed or run on it; the installers were downloaded there only to be hashed and their signatures read.

### 6. TAXII test results

* **M1 on Windows:** 17/17 earlier in Mission 10, with a development build of the same application code. It was not repeated on the installed candidate.
* **M7 on the installed deb:**
  * **GNOME Keyring (Ubuntu) and KWallet (Debian):** a server without a credential; the native dialog storing the typed password; one entry named by the server; still stored after a restart without an unlock prompt; Forget after the delay leaving nothing; removing the server removing its entry.
  * The lock and cancelled-unlock step (5) was not repeated.

### 7. GNOME, KDE and KWallet results

* **Installed deb, M2 (start, every page and project tab, Ctrl+K, native confirmations, the terminal, the window controls), 9/9:**
  * Ubuntu 24.04.5 with GNOME 46 on Wayland;
  * Debian 12 with Plasma 5.27 on X11, KWallet as the Secret Service.
* **Credentials:** M7 in both, section 6.
* **The AppImage** runs in both.
* **Two VM environment problems, not Cyber Hub:**
  * Plasma's screen locked despite `Autolock=false`, until a ScreenSaver inhibit was held;
  * report and backup files left by Mission 9 triggered GTK's "replace it?" prompt.
  * The affected runs were repeated on the final packages.

### 8. HiDPI results

* **Unchanged from earlier in Mission 10:** virtual scaling passes at 100, 125, 150 and 200 % on GNOME and Windows.
* **The installed builds' first windows fit the work area** on Windows (2560 × 1600) and Linux (1280 × 800).
* No physical screen (M4).

### 9. Linux package installation results

| Where | Package | Result |
|---|---|---|
| Ubuntu 24.04.5 GNOME, VM | deb | Installs (`Depends: libwebkit2gtk-4.1-0, libgtk-3-0`): `/usr/bin/cyber-hub`, `/usr/bin/cyberhub-mcp`, a desktop entry; no data before the first start. M2 9/9; RC-1 to RC-4; reports, backup and restore; M7; Alt+F4. Upgrade from schema 19 (backup first), then rollback. Uninstall keeps the data; a reinstall opens it without another upgrade |
| The same VM | AppImage | RC-1 to RC-4, with the AppImage path warning on the MCP page. Ran with FUSE 3 only, without `libfuse2` |
| Debian 12 Plasma X11, KWallet, VM | deb | The same, with an upgrade from schema 8 |
| The same VM | AppImage | RC-1 to RC-4 |
| Clean Ubuntu 24.04 and Debian 12 containers | deb | Installs with every dependency (92 → 311 and 88 → 314 packages), no library missing, removal clean. **Does not start without CA certificates**: "builder error" (section 16) |
| Clean Fedora 43 container | rpm | Installs (`Requires` the GTK 3 and WebKitGTK 4.1 libraries), starts with its window, schema 32 and a 0700 data folder; removal clean |

In both VMs, the import preview matches MANUAL_VALIDATION: with the address in scope, the complete sample gives Nmap XML, 0 findings, 3 assets and no warning.

### 10. Full regression results

* **The release run's own validation of the tagged commit:** 641 passed, 0 failed, 28 ignored; 56 frontend test files; tsc, clippy, the production build; npm audit 0; cargo audit 0 vulnerabilities in 652 crates, 8 allowed warnings.
* **CI on `add894e`:** green on Windows, Ubuntu, Debian 12, MSRV and the scans (gitleaks, actionlint).
* **The manifest script's tests:** 5/5, including the new shortening test.

### 11. Release artifacts and verified paths

* **The draft's 12 assets,** downloaded to `E:\CyberHubQA\rc\draft-v0.1.0\` and verified there:

| File | Bytes |
|---|---|
| `Cyber.Hub_0.1.0_x64-setup.exe` (NSIS) | 8,650,490 |
| `Cyber.Hub_0.1.0_x64_en-US.msi` | 11,378,688 |
| `Cyber.Hub_0.1.0_amd64.AppImage` | 90,724,856 |
| `Cyber.Hub_0.1.0_amd64.deb` | 13,232,520 |
| `Cyber.Hub-0.1.0-1.x86_64.rpm` | 13,234,766 |
| the five `.sig` files | 432–440 each |
| `latest.json` | 24,118 |
| `SHA256SUMS.txt` | 1,050 |

* **Installed paths:**
  * NSIS: `%LOCALAPPDATA%\Cyber Hub\{cyber-hub.exe, cyberhub-mcp.exe, uninstall.exe}`;
  * deb: `/usr/bin/cyber-hub`, `/usr/bin/cyberhub-mcp`, `/usr/share/applications/Cyber Hub.desktop`;
  * the MSI: section 16.
* **Evidence:** `E:\CyberHubQA\evidence\M10\2026-11-12\` holds `verify.log`, `SHA256SUMS.txt`, `latest.json`, the runs' logs, the containers, and the VMs' logs and screenshots.

### 12. SHA-256 checksums

```
6b1a708607b6f41a88dac9f4eeb7c634d5051b23c67d1cfdd139ec8152c09cfa  Cyber.Hub_0.1.0_x64-setup.exe
5051213a74ff3d890855dc638ef688a88e126dcb660f323a91f7f266aa145ed0  Cyber.Hub_0.1.0_x64_en-US.msi
0d96580351e5ac22f4fc33984e3a7ded44c9e70aee6edbc16f2c01eb38af5c40  Cyber.Hub_0.1.0_amd64.AppImage
60603f7c040d5047583783b2878d0a4c5d10cbc388d3ffb9671fdf0e65a4743b  Cyber.Hub_0.1.0_amd64.deb
092768b645464650e414eb6c1d2c890e7fb8757b06a593a704072b12f10ce581  Cyber.Hub-0.1.0-1.x86_64.rpm
202bc0a6db44370e33c2b41b9910dba54fe461519b4fb50cf1766d7ec0f058be  latest.json
```

The `.sig` files' sums are in `SHA256SUMS.txt`. GitHub's own asset digests equal these: the publish job checks that, and the draft's listing shows them.

### 13. Signature verification results

* **`sha256sum -c SHA256SUMS.txt`:** all 11 files OK.
* **The repository's validator** at the tagged commit: `latest.json` valid, 7 platform entries, every signature verified against the public key compiled into the app.
* **The reference minisign 0.12,** independent of the repository's code, against key `957F3F7D955C72FA`: all five packages OK. Every trusted comment names `version:0.1.0`.
* **Authenticode:** "NotSigned" for both Windows installers and the installed programs.

### 14. Database isolation evidence

* **The real database was never opened.** Its modification time is `2026-11-05T15:58:24.8534883Z`, unchanged.
* **Nothing was installed on the owner's Windows:** neither `%LOCALAPPDATA%\Cyber Hub` nor `Program Files\Cyber Hub` exists there.
* **Every installation ran in a disposable VM or a container,** with that machine's own data folder.
  * Before the packages, the VMs' earlier QA data was moved aside, not deleted: `dev.cyberhub.workstation.dev-builds-m9-m10`, `~/rc-run1`, `~/m9-leftovers`.
  * A leftover QA keyring entry of Mission 9 was removed in the Ubuntu VM.
* **The upgrade tests used the synthetic fixtures,** not real data.

### 15. Private draft release URL

https://github.com/RChefo/cyber-hub/releases/tag/untagged-be186ef1d1191b08b196
* Tag `v0.1.0`, a draft: `isDraft: true`, never published.
* It is visible only to people with write access to this private repository. GitHub gives a draft a new `untagged-…` address when it is edited.
* Its body starts with the candidate section (signature status, checksums, installation, upgrade and rollback, validation, limitations). The full release notes follow.

### 16. Every remaining blocker

1. **Authenticode (blocks Windows distribution).** Buy and set up the certificate, add signing and its verification to the release workflow, delete this draft and the tag, then rebuild.
2. **Start-up without CA certificates** (FEATURE_BACKLOG.md item 95). On a system with no CA certificates, Cyber Hub refuses to start with "builder error", because two network clients are built in setup. Desktop systems have them.
   * Fix before publishing, or accept: build those clients when first used, name the cause in the message, and declare `ca-certificates` in the deb and rpm.
3. **The update path** can only be tested after publication. Then the owner checks:
   * that `releases/latest/download/latest.json` serves the manifest;
   * that 0.1.0 reports it is up to date;
   * later, a 0.1.1 update.
4. **The MSI after an NSIS install** (item 96). The NSIS uninstaller leaves `HKCU\Software\cyberhub\Cyber Hub`, and the MSI then installs into that per-user folder. A clean-machine MSI install, and the publisher name "cyberhub" (item 97), remain to decide.
5. **Physical HiDPI (M4)**, the rpm in a desktop, M1 on the installed build.
6. **The owner's publication decision.** The draft stays a draft. Publishing needs a separate authorization and `RELEASE_PUBLISHING` for that run.
7. **Recommended, as before:** limit the eight third-party GitHub Apps; GitHub Pro for required reviewers and rulesets.

**QA storage** (`E:\CyberHubQA`, about 65 GB plus 0.4 GB of new evidence): the cleanup report above still applies. Nothing was deleted, and all three working VMs are off.

### 17. Final classification

**RELEASE CANDIDATE PARTIALLY VERIFIED.**
* The candidate exists as a private draft. Its packages are built and update-signed by the workflow, and verified twice, once independently.
* Every package was installed and exercised on the platform it targets: upgrade, rollback, backup and restore, credentials, the MCP sidecar, uninstall.
* It is **not** a release:
  * the Windows installers are unsigned;
  * the update path cannot be checked before publication;
  * physical HiDPI is untested;
  * the CA-certificate start-up issue is open.
* **Nothing was published,** the repository stays private, and `RELEASE_PUBLISHING` is unset.

## Mission 11: final release hardening and the second release candidate (2026-11-12)

**The authorization.** The owner authorized autonomous engineering, regression testing, private repository operations and an isolated release candidate. A public release and any purchase were not authorized. Neither happened.

**Classification: RELEASE CANDIDATE PARTIALLY VERIFIED.**

**Times:** 2026-11-12T17:35Z to the commit that adds this section.

### A. Executive summary

* **Fixed, with regression tests:**
  * **Start-up without CA certificates.** Cyber Hub now starts and works offline on a system without CA certificates, and every network feature says what to install. Verification is not weakened, and nothing is sent without it.
  * **The MSI's install folder.** An MSI installed after an NSIS uninstall now goes to Program Files instead of the removed per-user folder.
  * **Two front-end defects** found by a new HiDPI layout audit: the Projects page scrolled sideways, and the ASVS section failed on a history status it did not know.
* **Decided:** the publisher stays "cyberhub" for 0.1.0, because it is part of the NSIS install identity. What Windows shows, and what needs Authenticode, is documented. A test pins the install identity.
* **The release workflow** builds `vX.Y.Z-rc.N` tags as draft pre-releases and never publishes them. So the second candidate did not need the `v0.1.0` tag moved.
* **The second candidate** is the private draft pre-release of `v0.1.0-rc.2` (`f049e08`), built by run 43288379505.
  * Checksums and signatures were verified twice.
  * It passed on Windows 11 (an 8-scenario install matrix), on Ubuntu 24.04 GNOME, on bare Ubuntu and Debian images without CA certificates, on Fedora, and in GUI containers.
  * Virtual HiDPI at 100–200 % (175 % included) passed on Windows and GNOME, in the largest and the smallest window.
* **Found, not changed:** the GitHub repository is **public**. It was private at 00:06Z the same day, and no session changed it. Mission 10's closing line ("the repository stays private") was not re-checked when it was written. The owner was notified (item 99).
* **Not verified:**
  * Authenticode: there is no certificate, so the installers are unsigned;
  * an update end to end, which is possible only after publication;
  * physical HiDPI, for lack of hardware.

### B. Changes

| Commit | What |
|---|---|
| `1c98af4` | fix(network): start without CA certificates and say why requests fail. New `src-tauri/src/tls_trust.rs`: `LazyClient` (the VirusTotal and threat-intelligence clients are built on first use, a failure is not cached), `build()` (every client; a failure caused by missing CA certificates becomes one actionable message), `describe_build_error()` (also for the updater's `classify` and `describe_reqwest`). Every `reqwest::ClientBuilder::build()` call site moved to it (14 files). `ring`, already in the tree through rustls, became a dev-dependency for a run-time test certificate |
| `1aed064` | fix(installer): forget the NSIS install folder after an uninstall. `src-tauri/windows/installer-hooks.nsh` (`NSIS_HOOK_POSTUNINSTALL`) and `bundle.windows.nsis.installerHooks`; tests pin the hook's commands and the Windows install identity |
| `00939e1` | feat(release): build release candidates under `vX.Y.Z-rc.N` tags (draft pre-releases the workflow never publishes); tests for the tag pattern, the pre-release draft and the refusal to publish |
| `4d1a902` | fix(projects): a project row's details give way to the name (at least 10rem), long values end with an ellipsis, the dates keep a tooltip |
| `7e62a10` | fix(asvs): `statusLabel()` shows an unknown history status as stored; unit test |
| `44a0384` | fix(release): one redirect for the three outputs (shellcheck SC2129, found by CI's actionlint) |
| `f049e08` | docs(release): the 0.1.0 notes state the signing, CA-certificate and scaling limits (the old text read as if the release were signed) |
| this commit | docs: mission state, log, report, backlog, readiness, procedures, platforms, updater, signing |

The application's architecture, visual identity, updater key and signing architecture are unchanged. No runtime dependency was added.

### C. CA certificates (Priority A)

* **The exact path.**
  * reqwest 0.13.5 builds each client's verifier with rustls-platform-verifier 0.7.1.
  * On **Linux** (and other Unix systems except Android and Apple), `Verifier::new` loads the system's CA certificates through rustls-native-certs 0.8.5 while the client is **built**. Without any certificate it returns an error, which reqwest reports as "builder error".
  * On **Windows** the verifier asks Windows' certificate store during each connection, so building never fails there. (macOS is not supported.)
  * `setup_app` built two clients (`VtState::new()`, `TiState::new()`). A Linux system without `ca-certificates`, such as a bare container or a minimal install, therefore could not start Cyber Hub at all.
* **The fix.**
  * The two start-up clients are built when a request first needs them.
  * Every client is built through `tls_trust::build`. Missing CA certificates become one message: "Secure connections are not available: no trusted CA certificates were found on this computer, so Cyber Hub cannot verify any server's certificate and sends no request. Install the system's CA certificates (the ca-certificates package on Debian, Ubuntu and Fedora), then try again. Offline features keep working."
  * The message reaches the user through the existing error paths:
    * `AppError::Network` toasts and inline errors;
    * the threat-intelligence results' per-provider status;
    * OSINT's provider errors;
    * the HTTP tools' errors;
    * the Update Center's failure kind `tls`.
  * No request is attempted, and nothing retries at start-up. Nothing disables verification or falls back to HTTP: without CA certificates no client exists. A failure is not cached, so installing the certificates is enough, without a restart.
  * The TLS analyzer still analyzes a server and reports "No trusted root certificates are available on this system" as its trust result (unchanged).
  * Not done, on purpose: declaring `ca-certificates` as a package dependency. It would make an offline install fail on a minimal system, and Cyber Hub is local-first.
* **Regression tests,** with the six cases of the brief:
  1. **A normal system:** `a_client_builds_with_the_systems_ca_certificates` (Windows and Debian), and every other network test.
  2. **No CA certificates:** `without_ca_certificates_cyber_hub_starts_and_says_why_requests_cannot_be_made`, a Linux child process with `SSL_CERT_FILE` and `SSL_CERT_DIR` pointing at empty places. The start-up states are created, and every path gives the message: `build`, the threat-intelligence client, both lazy clients, and the updater's `classify`.
  3. **A request without roots:** the same test, plus `the_start_up_states_build_no_client`.
  4. **Recovery:** the child test points the variable at the system bundle, and the next `get()` builds the client. `a_lazy_client_is_built_on_first_use_tried_again_after_a_failure_and_then_kept` covers the same on every platform.
  5. **Invalid certificates still refused:** `an_untrusted_certificate_is_still_refused`. A self-signed ECDSA certificate is made at run time and served over TLS on 127.0.0.1. Cyber Hub's client refuses it for its certificate, and a client that trusts that certificate explicitly reaches the same server (the control).
  6. **Offline work:** the child test writes and reads the database.
* **On real packages** (the second candidate):
  * **Bare `ubuntu:24.04` and `debian:12`, no `ca-certificates`:** the deb installs without pulling them in. Cyber Hub starts, shows its window and opens schema 32. The first candidate printed "Cyber Hub could not start: builder error" here.
  * **Fedora 43:** the rpm starts with its certificates and with them hidden from the app.
  * **GUI containers, Ubuntu 24.04 and Debian 12, certificates hidden:** 5/5 each. The HTTP header analyzer and a live CVE search refuse with the message, a project is created offline, and after the bundle is written into the same file, the next request builds its client without a restart.
  * **The AppImage** starts with the certificates hidden.
  * **Windows** is not affected by this failure; its certificate store is always there.
* **Limitations.** On Linux, `SSL_CERT_FILE` / `SSL_CERT_DIR`, when set, replace the system's certificates for Cyber Hub (rustls-native-certs' rule). The message is shown on each network attempt; there is no banner at start-up. The user cannot tell that the certificates are missing until a network feature is used.

### D. Windows installers (Priority B)

* **The cause.** Tauri's NSIS installer saves its folder as the default value of `HKCU\Software\cyberhub\Cyber Hub`, and its uninstaller deletes that key only when *Delete the application data* is ticked. Tauri's MSI template searches that value for its `INSTALLDIR` (then its own `InstallDir` value). Both templates were read from the Tauri CLI 2.12.4 that builds the release.
* **The fix.** A supported Tauri hook, not a template fork. After a real uninstall the hook deletes only that value, then the two keys if they are empty. NSIS 3.13's `/ifempty` was checked in its help: no values and no subkeys. An update (`/UPDATE`) keeps the value.
  * It touches nothing else: no files, no data, no other value. `Installer Language` and the MSI's values stay.
  * A newer installer that removes the old copy first has already read the folder, and writes it again.
* **The matrix** with the second candidate's NSIS and MSI and the first candidate's for upgrades. Details: RELEASE_READINESS.md, "Windows installers".
  * Fresh NSIS: 10/10 + 1/1.
  * NSIS uninstall: the data is kept and the folder forgotten.
  * The MSI after it: Program Files.
  * The MSI on the same data: no migration.
  * MSI uninstall, then NSIS: the per-user folder.
  * NSIS over the first candidate's NSIS, in place.
  * MSI over the first candidate's MSI: a major upgrade with one entry.
  * Fresh MSI: 10/10 + 1/1, then an upgrade from schema 31 and a rollback, 4/4.
  * Shortcuts and uninstall entries were checked after every step. The data stayed throughout.
* **Limitations.**
  * A machine whose earlier NSIS copy was removed by an older uninstaller keeps the stale value until the next NSIS uninstall. Only the QA VMs had the first candidate.
  * While an NSIS copy is installed, Tauri's MSI follows its folder: install one Windows package at a time (PLATFORMS.md).
  * SmartScreen and the interactive wizards were not repeated; the files are unsigned exactly as before.

### E. Publisher identity (Priority C)

* **What exists.**
  * No publisher identity is documented beyond Cargo.toml's `authors = ["Cyber Hub contributors"]`, which is the deb's Maintainer.
  * `bundle.publisher` is unset, so Tauri derives "cyberhub" from `dev.cyberhub.workstation`.
  * "cyberhub" is consistent across the exe's CompanyName (the app and the MCP sidecar), the NSIS Publisher and the MSI Manufacturer.
  * Product name and file description are "Cyber Hub"; the copyright is empty. The NSIS installer's own version info has no Company field (Tauri's template).
* **What needs Authenticode.** Only the signer that SmartScreen ("Unknown publisher"), the UAC prompt ("Unknown") and the *Digital Signatures* tab show. *Apps & features* and file details show `bundle.publisher` whether or not the file is signed.
* **Decision: unchanged for 0.1.0, and pinned by a test.** The publisher names the NSIS key that holds the install folder. The next NSIS installer reads it to find and remove the old copy, and the MSI reads it for its folder. With another value, a manual NSIS upgrade from a build with the old value would find no folder there. This follows from the template's code and was not tried.
  * The MSI's upgrade code (`{35C1D9FD-CFC7-5020-B4AC-A031E55D0494}`, from the product name) and the NSIS uninstall entry (named after the product) do not depend on the publisher.
  * No legal name was invented, and nothing implies a signature.
* **The owner's decision, before the first public release:** keep "cyberhub", or set the final value once, for example the certificate's subject. Afterwards a change needs a migration.

### F. HiDPI (Priority D)

* **The audit** (`audit.js`, the same code in WebView2 and WebKitGTK) visits:
  * every sidebar page (17);
  * every section of a project (19);
  * the command palette, the new-project form and the scan import.

  It reports sideways scrolling of the page or of `<main>`, tables cut off by a container, controls no scrolling can reach, and dialogs that do not fit or whose controls stick out. Its data is a copy of the schema-31 upgrade fixture, so every table has a row.
* **Results, virtual displays at 2560 × 1600:**
  * **Windows 11** (QA debug build of the candidate's code), 100, 125, 150, 175 and 200 %: **20/20**. Each scale covers the page scale, a maximized window, the smallest window a user can drag to (800 × 480 logical) and the native confirmation.
  * **GNOME 46 on Wayland** (a Linux build of the same code), Mutter's 1, 1.25, 1.502, 1.749 and 2: **20/20**.
  * **The installed candidate deb** at 1 and 1.749: **8/8**.
  * Every window size: 17 pages, 19 project sections, 3 dialogs, no problem.
* **Fixed** after the audit's first run on the host:
  * the Projects page scrolled sideways by 230 px at 1354 px, because a project row's details could not shrink; with dates it happens just above the `lg` breakpoint;
  * the ASVS section failed to render on a history status it did not know.
* **Physical HiDPI: NOT TESTED.** No physical high-DPI display was available. At fractional scales GNOME draws the window at 2× and scales it down, as before.

### G. Security and regression (Priorities E and F)

* **Tests,** compared with Mission 10 (641 passed, 28 ignored, 56 frontend files):
  * Windows: 647 passed, 29 ignored; clippy `-D warnings` clean.
  * Debian 12 (Rust 1.99.1): 648 passed, 29 ignored.
  * Frontend: 56 files and 310 tests; tsc clean.
  * CI 43286877265 on `f049e08` green on `windows-2022`, `ubuntu-24.04`, Debian 12 and MSRV 1.90, with gitleaks and actionlint; CI on the tag green too.
  * The difference is the new tests: 4 TLS tests on every platform plus the Linux-only parent, 2 installer-identity tests, and the ignored child. No test was weakened. The release-workflow test changed with the policy: pre-release tags other than `-rc.N` are still refused.
* **Audits:** npm 0 vulnerabilities; cargo audit 0 vulnerabilities in 652 crates, the same 8 allowed warnings; Dependabot, the same two medium alerts (item 94).
* **Formatting:** `cargo fmt` is not used by the project (no configuration, no CI step). A run in this mission reformatted 184 files and was undone before any commit.
* **Database:** upgrades from every schema (`db_upgrade_tests.rs`); on the installed MSI, schema 31 to 32 with its backup and a rollback.
* **Backup and restore:** RC-8/RC-9 on both Windows packages. **MCP:** its security tests, and the installed sidecar's 62 tools on Windows (NSIS, MSI) and Ubuntu (deb). **End to end:** the installed-build checks, the audits and the no-CA GUI test above.
* **The release pipeline,** reviewed:
  * **Secrets.** Both update secrets are only in the `release` environment and only in the build step, never echoed. The password has no BOM: the build signed. `RELEASE_PUBLISHING` existed from 19:15:58Z to 19:50:58Z only.
  * **Notes.** The manifest's notes are 19,736 characters (limit 20,000), and the draft carries the full notes.
  * **Checksums and signatures.** `SHA256SUMS.txt` is checked against GitHub's digests in the run and again locally. The signatures were checked against the compiled key by the repository's validator and by the reference minisign.
  * **The commit.** The artifacts come from the validated commit: the tag check in the run says `v0.1.0-rc.2 names f049e08…`, and the run's head is `f049e08`.
  * **Actions and permissions.** Every action is pinned by SHA (a test, and the repository's SHA-pinning setting). Permissions are minimal: none at the top; `contents: read` for validation and build, `write` only for publish; read-only CI.
  * **No accidental publishing.** A stable tag publishes only with *draft* unchecked and the tag typed again; a candidate never.
  * **Defects found:** SC2129, fixed before the build. The update key and the signing architecture are unchanged.
* **Repository settings, now that it is public (item 99):** secret scanning and push protection are off (free for public repositories); the `release` environment has no required reviewers (now available); outside contributors' first workflow runs need approval.
* **The owner's database** (`%APPDATA%\dev.cyberhub.workstation\cyberhub.db`) kept its modification time `2026-11-05T15:58:24.8534883Z`. All QA used VMs, containers and disposable data folders.

### H. The second candidate's artifacts

* **Tag** `v0.1.0-rc.2` (annotated, object `d0d85cf8…`) names `f049e08c6ac9e81e03eec81b8bab1946154dca9a`. Run [43288379505](https://github.com/RChefo/cyber-hub/actions/runs/43288379505), 19:16–19:50Z, green; *Publish the release* was skipped.
* **Draft pre-release** "Cyber Hub 0.1.0, release candidate 2": https://github.com/RChefo/cyber-hub/releases/tag/untagged-232774a6d0480a7f3d47. The address changes when the draft is edited. Anonymous readers see no release.
* **SHA-256:**

  ```
  5b0c80925312b6f494e770dae221f350d9b47c43003030db4dc5212dbbf19deb  Cyber.Hub-0.1.0-1.x86_64.rpm
  af39bbc4611f91bb5f9a9dcf7df5c770d224db1f506006fd92171dba98849e22  Cyber.Hub_0.1.0_amd64.AppImage
  cfea5b3511a56416cc4113b4e153fab9a4b9b6cd9e574d3d3cb572661d8fca81  Cyber.Hub_0.1.0_amd64.deb
  8c7c136ca27a36ec38e027c59ca2744cb12c7f6d39dc635140de21c1b1c8b4fb  Cyber.Hub_0.1.0_x64-setup.exe
  ded2c1be72dd298bfd9d77adbbc8c0c4742f5249af2b60c85ad43b93a4c91b74  Cyber.Hub_0.1.0_x64_en-US.msi
  7a83e7a68977deaa51a8599d8fec134f0aa6216995e7edb9f8c539cca5d85849  latest.json
  ```

  The `.sig` files are listed in the draft's `SHA256SUMS.txt`.
* **Verification** (`E:\CyberHubQA\evidence\M11\rc2\verify.log`):
  * every file matches `SHA256SUMS.txt`;
  * the repository's validator passes;
  * the reference minisign verifies all five packages against key `957F3F7D955C72FA`, each trusted comment naming version 0.1.0;
  * Authenticode says `NotSigned`.
* **The two candidates.**
  * The first is the draft of `v0.1.0`, tag on `add894e`, run 43242424304. It was **kept** and still has its old defects (no start without CA certificates; the MSI's folder).
  * The second is the draft pre-release of `v0.1.0-rc.2`. Both report version 0.1.0.
  * The stable `v0.1.0` must name the validated commit before a final build (item 101).
* **Evidence:** `E:\CyberHubQA\evidence\M11\`: `win`, `win-hidpi`, `noble-hidpi-build`, `noble-rc2`, `linux`, `rc2`, and `E:\CyberHubQA\win-share\m11\out` for the matrix logs.

### I. Remaining blockers

* **Mandatory before a public release:**
  1. **Authenticode** for the Windows installers and programs. This is a purchase: not authorized and not made (`SIGNING_SETUP.md`). Signing changes the binaries, so a new candidate follows.
  2. **The owner's publication decision.** The stable build needs the first draft deleted and `v0.1.0` pointed at the validated commit (a rewrite of a public tag), or a later version (item 101).
* **Owner decisions:**
  1. **The repository's visibility.** It is public; confirm or change it. If public: secret scanning, push protection, and a required reviewer on `release`.
  2. **The publisher name,** before the first public release.
  3. Whether to delete the first candidate's draft now; it was kept per the brief.
* **External hardware or certificates:**
  1. a physical HiDPI screen (M4);
  2. the Authenticode certificate;
  3. after publication, the update path end to end (item 98).
* **Optional:**
  1. the rpm in a desktop session;
  2. the AppImage and M7 on Plasma again with this candidate;
  3. M1 on an installed build;
  4. limiting the third-party GitHub Apps;
  5. running actionlint locally before every workflow push (item 100).

### J. Final classification

**RELEASE CANDIDATE PARTIALLY VERIFIED.**
* The second candidate fixes Mission 10's start-up and installer findings. It passed every automated and installed-build check that this environment allows on Windows 11, Ubuntu 24.04, Debian 12 and Fedora 43, and its artifacts verify.
* It is not ready for a final owner review as a release:
  * the Windows files are unsigned, and signing will rebuild them;
  * an update cannot be checked before publication;
  * physical HiDPI is untested.
* Passing tests do not make it production-ready.
* **Nothing was published.** No visibility was changed, nothing was bought, and `RELEASE_PUBLISHING` is unset.

## Mission 12: open-source readiness and community foundation (2026-11-13)

**The decision and the authorization.** The owner decided that Cyber Hub stays public and becomes an open-source project. Authorized: securing the public repository, contributor documentation and governance, automated checks, a dependency and license review, commits and pushes. Not authorized, and not done:
* selecting or applying a license;
* a release, new binaries, purchases;
* deleting repository content;
* rewriting history or tags;
* product features or architecture changes.

**Classification: OPEN SOURCE PARTIALLY READY.**

**Times:** 2026-11-13T10:14Z to the commit that adds this section.

### A. Executive summary

* **The public repository is secured with GitHub's free features.**
  * Its whole history was audited: no leak in 210 commits of 10 refs.
  * Turned on: secret scanning, push protection, Dependabot security updates, private vulnerability reporting.
  * Two rulesets protect the default branch and the `v*` tags.
  * Every outside contributor's workflow run needs approval, and each `release` deployment needs the owner's approval.
  * Release build artifacts are no longer left downloadable.
* **Licenses.** MIT, Apache-2.0, GPL-3.0 and AGPL-3.0 are compared, with a recommendation (Apache-2.0). **No license was applied:** the owner selects it.
* **Third-party licenses.** Every one of 649 crates and 457 npm packages passes a written policy, now enforced in CI. The audit found four problems the owner must resolve:
  * the React Bits components (MIT + Commons Clause, not open source);
  * the website's Ink Orbit component (no license);
  * the AppImage's LGPL and GPL-2.0-or-later libraries without a source offer;
  * installers that do not ship third-party license texts.
* **Contributors** now have:
  * a README for the public;
  * CONTRIBUTING, CODE_OF_CONDUCT (Contributor Covenant 2.1), SECURITY and SUPPORT;
  * a development guide and a documentation index;
  * issue forms and a pull request template;
  * CODEOWNERS, Dependabot version updates and labels.
* **CI** gained a required "Repository checks" job: license policy, link check, pull request titles. It now runs once per pull request. CI run 43415411675 on `25c7401` is green on all six jobs.
* **The product is unchanged.** The only Rust change is in `ci_tests.rs`. Windows 648 passed, Ubuntu 24.04 and Debian 12 649 passed, 319 frontend and script tests.
* **Why not "license selection pending":** besides the license, two high-severity third-party issues sit in the source tree itself (React Bits, Ink Orbit). Selecting a license would not close them.

### B. Repository security

* **History** (gitleaks 8.30.1, pinned and hash-checked, over a mirror clone of every ref):
  * **no leak;**
  * nine suppressed findings, each confirmed as a test fixture;
  * never committed: the update-signing key, `.env`, `.pem`, `.key`, `.p12` or `.pfx` files.
  * Commit metadata carries the owner's personal e-mail. It is already public and was not rewritten; the recommendation is GitHub's e-mail privacy for future commits.
  * CI's gitleaks scanned 214 commits on `25c7401`: no leak.
* **Settings now** (details: `docs/governance/REPOSITORY_SECURITY.md`):
  * secret scanning, push protection, Dependabot alerts and security updates, private vulnerability reporting: on;
  * non-provider patterns and validity checks: not available to this account (paid);
  * ruleset 27194018 "Default branch protection":
    * no deletion or force push;
    * pull requests with resolved conversations;
    * six required checks: the five CI jobs and "Repository checks", added after the job passed on the default branch;
    * administrator bypass;
  * ruleset 27194022 "Release tag protection": `v*` tags cannot be deleted, moved or updated (administrator bypass);
  * Actions: selected actions pinned by SHA, read-only default token, approval for every outside contributor's run;
  * `release` environment: the owner as required reviewer (added in this mission), no administrator bypass, `main` and `release/*` only;
  * `RELEASE_PUBLISHING` unset; Discussions and wiki off.
* **Alerts:** 0 open secret-scanning alerts. Dependabot: the same two medium alerts (glib in `Cargo.lock`, minimatch in the website's lockfile; item 94). Their automatic security updates ended in `security_update_not_possible`, and GitHub shows those runs as failed:
  * glib's fix is 0.20, but GTK 0.18 under Tauri allows 0.18.5 at most;
  * minimatch's fix would downgrade other dependencies.
* **Artifacts:** six build artifacts of the release runs 43231095560, 43242424304 and 43288379505 hold the candidates' unsigned binaries. Any signed-in GitHub user can download them until 2026-11-19. They were not deleted: deleting repository content was not authorized (item 108). The release workflow now keeps build artifacts for one day and deletes them after the draft upload.
* **GitHub Apps:** the same eight third-party apps attach queued check suites to every commit. Their permissions are in GITHUB_FIRST_RUN.md (Mission 10's table); Vercel, Wasmer and Cloudflare Workers and Pages hold administration write. This is the owner's account setting (item 109).
* **Not inspected:** webhooks; the CLI token lacks `admin:repo_hook`.
* **Unresolved critical security issues: none.**

### C. License research

`docs/governance/LICENSE_COMPARISON.md` compares MIT, Apache-2.0, GPL-3.0 and AGPL-3.0 on:
* permissions and conditions;
* the patent grant;
* copyleft scope;
* compatibility with the dependency set;
* commercial forks;
* contributions (DCO or CLA).

* **Recommended:** Apache-2.0, with a NOTICE file, a Developer Certificate of Origin and the React Bits and Ink Orbit components replaced. It serves adoption, contributions with clear terms (§5), commercial reuse and patent clarity best. Its explicit patent grant matters for a security tool that companies will evaluate.
* **Alternative:** GPL-3.0-or-later, if preventing closed derivatives matters more to the owner than adoption. It is compatible with the current dependencies.
* **Not recommended:** AGPL-3.0. Its network clause does not fit a desktop app, and it reduces adoption. "MIT OR Apache-2.0" is noted as a reasonable variant.
* The official Apache-2.0 text (SHA-256 `cfc7749b…3d30`) is staged outside the repository. The steps to apply a license, once selected, are in the document.
* **No LICENSE file, no `license` field, no SPDX header was added.** The README states that no license is selected and what that means.

### D. Third-party license audit

`docs/governance/THIRD_PARTY_LICENSE_AUDIT.md`, with generated inventories in `docs/governance/third-party/`.

* **Rust:** 649 crates for Windows and Linux, classified by the resolve graph as shipped, build-only or test-only. All are under permissive licenses, MPL-2.0 (file-level copyleft), or Unicode and CDLA data licenses. There is no GPL, AGPL, source-available or unknown license; `r-efi` offers LGPL only as one alternative and is not used by these builds.
* **npm:** 457 packages for the app and the website. Two reviewed exceptions: the website's `gsap` and `@gsap/react` (GSAP's own no-charge license; website only).
* **Copied code:** 10 files.
  * Comments and THIRD_PARTY_NOTICES.md now name each file's license.
  * **React Bits** (`CountUp`, `BranchedMenu` in the app, `OrbitImages` on the website) is MIT + Commons Clause. It may be distributed as part of an application, but the components may not be sold or redistributed on their own. This is **not an open-source license**, and it blocks a repository-wide OSI license unless the files are replaced or excluded.
  * **Ink Orbit** (website) comes from a repository without a license.
* **Assets and data:**
  * fonts (OFL-1.1) and icons (Lucide, ISC) have their full texts in THIRD_PARTY_NOTICES.md;
  * the bundled data keeps its own licenses under any Cyber Hub license: OWASP WSTG and ASVS (CC BY-SA 4.0), MITRE ATT&CK (MITRE's terms), FIRST's CVSS v4.0 data (BSD-2-Clause);
  * the app icons' authorship is not recorded.
* **Native libraries:** the AppImage bundles LGPL libraries and GPL-2.0-or-later `libjbig`, read from the second candidate's AppImage. This needs a source offer before public AppImage distribution.
* **Binaries:** the installers do not ship the third-party license texts and NOTICE contents.
* **Enforced:** `scripts/licenses.mjs check` evaluates SPDX expressions against `scripts/license-policy.json` in CI. A new dependency under an unlisted license fails the build.
* No compatibility or compliance is claimed until the owner selects the license and closes the audit's issues 2–5.

### E. Contributor infrastructure

| Added | Content |
|---|---|
| `README.md` (rewritten) | What Cyber Hub is and for whom, screenshots, status (pre-release, no public downloads, unsigned, no license), capabilities, building from source, testing, modules, security, documentation, reporting, contributing, license |
| `CONTRIBUTING.md` | Prerequisites, setup with a disposable `CYBERHUB_DATA_DIR`, an unsigned local build, the checks (no `cargo fmt`), standards, database and security-sensitive areas, dependencies, commits and pull requests, review, releases |
| `CODE_OF_CONDUCT.md` | Contributor Covenant 2.1, official text; reports go to the maintainer through GitHub until a private address is published (item 111) |
| `SECURITY.md` | Supported versions (the default branch; no stable release), private vulnerability reporting, what to include, no guaranteed response time, scope |
| `SUPPORT.md` | Where to ask what; Discussions are off |
| `docs/README.md` | Every document, grouped for users, contributors and internal release engineering; the mission reports are kept and marked as internal records |
| `docs/governance/DEVELOPMENT_GUIDE.md` | Layout, architecture, security boundaries, network access, environment variables, database, tests, building, the release workflow, known limitations |
| `.github/ISSUE_TEMPLATE/` | Bug, feature and question forms; blank issues off; vulnerabilities routed to private reporting; reporters asked to remove credentials and target data |
| `.github/pull_request_template.md`, `CODEOWNERS`, `dependabot.yml` | The checks to run; the maintainer as owner of everything, with CI, release and security configuration listed; grouped weekly updates (website monthly) |
| Labels | security, needs triage, needs reproduction, platform: windows, platform: linux, database, performance, dependencies |

**Presentation:**
* The description is set, with 14 topics, and merged branches are deleted.
* Not changed: visibility, name, homepage (no deployed website).
* A social preview needs the web interface (item 112).

**Dependabot's first version updates** opened pull requests #1–#8 at about 11:15Z:
* the grouped minor and patch updates;
* majors for `getrandom`, `hmac`, `sha1`, `sha2` and the website's TypeScript 7.

None was merged; they wait for review like any contribution. Before the trigger change, each ran CI twice. The duplicate push runs were left to finish (cancelling them was not permitted in this session).

### F. CI/CD

| Commit | Change |
|---|---|
| `8df7f78` | New job "Repository checks": `node scripts/licenses.mjs check`, `node scripts/check-links.mjs` (209 relative links in 45 files), and on pull requests a Conventional Commits title check whose title reaches the script only through `env`. In the release workflow, build artifacts are kept for one day and deleted by the publish job after the draft and its digests are checked (`actions: write` for that job only). `ci_tests.rs` pins all of it |
| `07b5912` | CI runs for every pull request and for pushes to `main`, `release/**` and `v*` tags only, so a same-repository or Dependabot branch is checked once; pinned by `ci_tests.rs` |

* **Unchanged:**
  * CI reads no secret and has `contents: read`;
  * no `pull_request_target`, `workflow_run` or comment triggers;
  * checkouts keep no credentials;
  * every action and tool is pinned by SHA or hash.
* **Verified:**
  * actionlint 1.7.7 with shellcheck 0.9.0, run locally in a container: no issue;
  * CI run 43415411675 on `25c7401`, green: Windows 648 passed, Ubuntu 24.04 649, Debian 12 649 (29 ignored each), 319 frontend tests, MSRV 1.90, cargo audit over 652 crates, npm audit 0, gitleaks 214 commits, Repository checks.

### G. Product readiness

* **Unchanged by this mission:**
  * the application's code, schema 32, the update key and the signing architecture;
  * the two private draft candidates (`v0.1.0` on `add894e`, `v0.1.0-rc.2` on `f049e08`).
* **Regression, compared with Mission 11:**

  | Check | Mission 11 | Mission 12 |
  |---|---|---|
  | Windows Rust tests | 647 passed, 29 ignored | 648 passed, 29 ignored |
  | Debian 12 Rust tests | 648 passed, 29 ignored | 649 passed, 29 ignored |
  | Frontend and script tests | 56 files, 310 tests | 58 files, 319 tests |
  | Audits | npm 0; cargo 0 (8 allowed warnings) | npm 0; cargo 0 (8 allowed warnings) |

  * The Rust difference is the new `ci_tests` test. Debian runs one more test than Windows (`run_scripts_are_valid_bash`, Unix only).
  * The 9 new frontend and script tests belong to the license and link checks.
  * Clippy `-D warnings` and tsc are clean, and the vite build passes.
  * The website's npm audit shows 10 moderate findings, all minimatch (dev-only, item 94).
* The owner's database kept its modification time. All tests used disposable data.
* **Still open for a public release** (Mission 11, section I):
  * Authenticode;
  * the publisher name;
  * the stable tag;
  * an update end to end;
  * physical HiDPI.
* **New, for any public binary:** the third-party notices in the installers, and the AppImage's LGPL and GPL obligations.

### H. Remaining owner decisions

| # | Decision | Item |
|---|---|---|
| 1 | **Select the project license** (Apache-2.0 recommended; GPL-3.0-or-later the alternative) and DCO or CLA | 103 |
| 2 | **React Bits:** replace `CountUp`, `BranchedMenu` and `OrbitImages` (recommended), or exclude them from the license | 104 |
| 3 | **Ink Orbit** (website): replace, or obtain the author's permission | 105 |
| 4 | **The AppImage:** a source offer for its LGPL libraries and `libjbig`, removing `libjbig` and the TIFF loader, or no AppImage; possibly legal advice | 106 |
| 5 | **Ship third-party notices with the installers** (engineering, in the next candidate) | 107 |
| 6 | **Delete the six release-run artifacts** before they expire on 2026-11-19 | 108 |
| 7 | **Limit the eight third-party GitHub Apps** to the repositories they serve | 109 |
| 8 | **E-mail privacy** for future commits | 110 |
| 9 | A private contact for Code of Conduct reports | 111 |
| 10 | Discussions, a social preview image, a website URL | 112 |
| 11 | A user-facing way to enter provider credentials (a product change) | 113 |
| 12 | Lightswind's license file; the app icons' authorship | 114 |
| 13 | Review the eight Dependabot pull requests (the majors may need code changes) | 115 |
| 14 | Release path, unchanged: Authenticode, the publisher name, the stable `v0.1.0`, a public release, physical HiDPI | 97, 98, 101 |

### I. Final classification

**OPEN SOURCE PARTIALLY READY.**
* **Ready:**
  * the repository's security (no unresolved critical issue, every free protection on);
  * contributor documentation and governance;
  * issue and pull request templates;
  * CI with license, link and title checks;
  * a green regression.
* **Not ready:**
  * no owner-approved license;
  * two high-severity third-party license issues in the source tree (React Bits' Commons Clause, the unlicensed Ink Orbit component) that a license selection alone does not resolve.
* Cyber Hub is therefore **publicly visible but not open-source licensed**, and nothing in the repository claims otherwise.
* **Nothing was published or deleted.** No visibility, name or history changed, nothing was bought, and `RELEASE_PUBLISHING` is unset.
