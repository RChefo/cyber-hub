# Implementation log

Entries are newest last. Times are UTC, measured with `date -u`.

## 2026-11-08T21:31Z: baseline

* **Re-verified the QA-audit work** carried over from the previous session:
  * cargo test: 257 passed, 1 ignored;
  * clippy `-D warnings`: clean;
  * tsc: clean;
  * vitest: 197 passed.
* Committed it as `676c23d`.
* Started three research tracks: community demand, competitor features and format specifications.

## 2026-11-08T21:58Z: feature 1, scanner-output import (`b51615a`)

**What:**
* Import of six formats into a project:
  * Nmap XML;
  * Nuclei JSONL or JSON list;
  * Nessus v2;
  * Burp issue XML;
  * ZAP JSON;
  * SARIF 2.1.0.
* A preview before anything is written. Scope check of every network target.
* Fingerprint deduplication across imports (schema 13: `scan_imports`, `finding_fingerprints`):
  * resolved findings are reopened when they are reported again;
  * findings dismissed as false positive or accepted risk stay dismissed.
* The file is stored as evidence, and each finding links to it and to its asset. Assets are recorded as a discovery snapshot.

**Files:**
* `src-tauri/src/workspace/scan_import.rs`, `scan_import_tests.rs`;
* `commands/workspace.rs` (5 commands);
* `commands/projects.rs` (`finding_write`, without its own transaction);
* `workspace/evidence.rs` (`add_bytes`, shared `register`);
* `db.rs` (migration 13 and its tests);
* `src/modules/projects/ScanImportModal.tsx`, `scanImport.ts`, `scanImport.test.ts`, `FindingsTab.tsx`;
* docs: DATA_MODEL, SECURITY, UPGRADE and README.

**Security review:**
* XML is read by a streaming parser that does not expand entities (XXE test with `<!ENTITY xxe SYSTEM "file:///etc/passwd">`).
* Limits: 50 MB per file, 10,000 findings, 20,000 asset values, 256 KB of text per element, nesting depth 64.
* Copied text is redacted (tests cover `api_key=`, `password=` and curl commands with bearer tokens). Request and response bodies are not copied.
* The scope engine decides for every network target. A project without scope records no network results.
* Archived projects are refused.
* Paths only come from native dialogs.
* A preview token can be used once.

**Tests:**
* 11 Rust tests:
  * format detection;
  * each parser;
  * helpers;
  * truncated XML;
  * import, re-import, reopen and dismissed findings;
  * a project without scope;
  * Nmap assets.
* 2 migration tests: schema 12 to 13 with data and foreign-key checks, and an interrupted upgrade.
* 3 frontend tests.
* Full results:
  * cargo test: 270 passed;
  * clippy: clean after fixing the MSRV use of `is_none_or` and the type complexity;
  * tsc: clean;
  * vitest: 200 passed.

**GUI verification** (2026-11-08T22:10Z, debug build, isolated data folder):
* A Nessus file was chosen through the real Windows open dialog (UIA/Win32 helper `scratchpad/filedlg.ps1`).
* The preview showed new, out-of-scope and informational items.
* The import created the finding, its evidence and asset links, and the evidence vault entry with SHA-256.
* The GUI run found a summary wording problem (findings and assets were mixed in the count) and the existing "1 findings" header text; both are fixed in `95c8eac`.

## 2026-11-08T22:18Z: feature 2, finding library (`95c8eac`)

**What:**
* A workstation-wide template library (schema 14, `finding_templates`):
  * unique titles regardless of case;
  * references, tags, and import rules of the form `format:rule`, each rule owned by one template;
  * use counts.
* Commands: list, save, delete, use, starters, export and import through native dialogs.
* Finding Library page in the Workspace group.
* In the finding form: *Start from a template* (new findings) and *Save as template*.
* Scan import: new findings whose rule matches are written from the template. The target, CVEs and scanner evidence are kept. History notes record the template and rule. The preview counts and labels these findings, and a switch turns the template step off for one import.
* 14 original starter templates. The ZAP, Burp and Nessus rule IDs are ones known with confidence (40018, 40012, 10038, 10020, 10035, 10021, 0; 1049088, 2097920; 57582, 51192, 104743, 70658, 57608).
* Spec follow-ups from the format research:
  * Nuclei `matcher-status:false` lines are skipped;
  * SARIF `kind` pass and notApplicable are skipped, and other non-fail kinds become info.

**Tests:**
* 3 Rust template tests (validation and uniqueness, library-file round trip without overwriting, bad files).
* 1 template-import test and 1 spec-skip test.
* A schema-14 migration test.
* 4 frontend helper tests.
* Full run: cargo test 276 passed, clippy clean, tsc clean, vitest 204 passed.

**GUI verification:**
* 14 starter templates were added.
* A finding recorded from the "Insecure direct object reference" template has the template's severity, title and references, and the use count went 0 → 1.
* A Burp XML import matched `burp:1049088` and was written from the "SQL injection" template, keeping the location and the request line without cookies.

## 2026-11-08T22:25Z: feature 3, fix verification by rescan (`0e201f5`)

**What:**
* Schema 15 adds `finding_fingerprints.host`.
* A later file of the same tool that covers a host but no longer reports an open finding lists it in the preview and adds a history note.
* The *Resolve … this rescan no longer reports* switch (off by default) resolves those findings with a "Verified by rescan" note.
* Never applied to:
  * uncovered hosts;
  * other tools;
  * SARIF;
  * closed findings;
  * fingerprints from before schema 15 that have no host.

**Tests:** a Rust rescan test (covered and uncovered hosts, note only, resolve, no relisting, other tools) and a schema-15 column check. Full run: cargo test 277 passed, clippy clean, vitest 204 passed.

**GUI verification:**
* Restarting the debug build upgraded the QA database from 14 to 15, writing `backups/cyberhub-schema14-…db` first.
* Re-importing week 1 recorded the host.
* The week-2 file covering 93.184.215.7 without the Apache plugin listed that finding. With the switch on, it was resolved with the verification note.

## 2026-11-08T22:37Z: feature 4, CVSS on findings (`edad2bf`)

**What:**
* `src-tauri/src/cvss/`: strict parsing of v4.0, v3.1 and v3.0 vectors, canonical order, scores.
  * **v4.0** follows FIRST's `cvss_score.js` in the same arithmetic order.
  * The 270-entry macrovector table was generated from FIRST's `cvss_lookup.js` and checked identical to Red Hat's `cvss40.js` (BSD-2-Clause; notice in `THIRD_PARTY_NOTICES.md`).
  * **v3.1** follows the specification, including Appendix A Roundup.
* Schema 16 adds `findings.cvss_vector` and `cvss_score`; the score is computed by the backend on save.
* `cvss_score` command; a calculator in the finding form with a live score and a severity suggestion.
* Imports take vectors from Nuclei and Nessus. The list shows the score; reports print the score with its vector.

**Tests:**
* 6 CVSS unit tests: all 8 table examples from FIRST's v4.0 examples page, v3.1 specification vectors, temporal and environmental scores, Roundup, invalid vectors.
* A finding-storage test (canonical form, refusal, clearing, history, report line).
* Import tests for Nuclei and Nessus vectors; 3 frontend helper tests.
* Full run: cargo test 284 passed, clippy clean (one unused function removed), vitest 207 passed.

**GUI verification:**
* The calculator built `CVSS:4.0/…/VC:H/VI:H/VA:H/…` and showed 9.3 Critical (CVSS-B).
* *Set severity to critical* worked and the finding saved with its score.
* GUI testing showed the live score scrolled out of view while metrics were chosen. It now also shows in the calculator header.

## 2026-11-08T22:46Z: feature 5, IOC extractor, defang/refang, STIX 2.1 export (`38599a1`)

**What:**
* `src/modules/utilities/lib/ioc.ts`: refang conventions; extraction of 10 kinds with guards against file names, versions, times and MACs; per-kind defang; whole-text defang.
* IOC extractor tool (defanged or plain output, copy, Threat Intel lookup).
* Workbench Defang and Refang operations.
* `src-tauri/src/ti/stix.rs`: patterns with escaping, UUIDv5 indicator IDs and a UUIDv4 bundle ID, millisecond timestamps, no claimed verdicts.
* *STIX 2.1* button on Saved indicators.

**Tests:**
* 5 frontend IOC tests, including the defang/refang round trip.
* 3 Rust STIX tests: a UUIDv5 known-answer vector for the STIX SCO namespace, patterns and escaping, required properties and stable IDs.
* Full run: cargo test 287 passed, clippy clean, tsc clean, vitest 212 passed.

**GUI verification:**
* The extractor found 7 indicators in defanged text and did not take `report.pdf` for a domain.
* The STIX export went through the real save dialog, giving a bundle with 2 indicators and correct patterns.
* My dialog helper failed to type the path, so the dialog saved under its default name into `Documents`. That test file was moved out of Documents to the scratchpad; no user file was touched.

## 2026-11-08T22:50Z: feature 6, Greenbone/OpenVAS import (`99fe5ed`)

**What:**
* GMP XML reports become findings: one per NVT, host and port.
* Greenbone's default filter is applied: QoD below 70 % is left out, False Positive and Debug are skipped, Log is info.
* Text comes from the NVT tags (summary, insight, impact); remediation from the solution; also CVEs, URL references and the CVSS vector from `severities`.
* Assets: addresses, names and services. `openvas:<OID>` import rules are accepted.

**Tests:** 1 Rust parser test (16 scan-import tests in total).

**GUI:** not separately verified; it shares the import dialog verified for features 1–3.

## 2026-11-08T22:55Z: features 7 and 8, findings export and bulk edit (`0337e18`)

**What:**
* Export of the listed findings in the order shown, as RFC 4180 CSV (BOM, 21 columns, cells guarded against formula injection) or JSON.
* Bulk add or remove of tags (case-insensitive) and setting or clearing the assignee, with a per-finding history entry.

**Tests:**
* 2 export tests (quoting and the formula guard; CSV and JSON content) and 1 bulk-edit test.
* Full run: cargo test 291 passed, clippy clean, vitest 212 passed.

**GUI:**
* The bulk edit added a tag through the dialog.
* The CSV export was produced through the native save dialog and has the expected header and rows. The dialog ignored the path set by the helper (`WM_SETTEXT`) and saved to `Documents` under the default name. That test file was moved to the scratchpad, and Documents holds no export files from this session.
* Save-dialog GUI tests are not repeated in this session; see the memory note.

## 2026-11-08T23:02Z: feature 9, OWASP WSTG checklist (`9c4ee92`)

**What:**
* `src-tauri/src/methodology/` bundles the WSTG checklist: OWASP/wstg `checklists/checklist.json` at commit `8f7da50ddfda9bc6929ca312eff9c9cb9a68ccc7`, 115 tests in 13 categories, CC BY-SA 4.0. It was validated at generation: ID format, unique IDs, references only on `wstg.owasp.org`.
* Schema 17 adds `checklist_items`: status, note, and a linked finding (same project only; SET NULL on delete).
* Checklist tab with coverage, filters and search, and *Record finding* from a failed test, which links the finding. The HTML report states the coverage. The attribution is in the tab and in THIRD_PARTY_NOTICES.md.

**Tests:** 2 Rust tests (catalog integrity; progress, links and coverage), 1 report test, 3 frontend helper tests.

**GUI:** a status change persisted and coverage showed 1/115. A failed test → *Record finding* gave a prefilled finding (#5) linked to the test.

**Mistake caught:** I first wrote an invented full commit hash into THIRD_PARTY_NOTICES.md (only the first 12 characters were real). It was corrected to the real hash from the data file before the commit.

## 2026-11-08T23:05Z: secret-scan fix (`e4985ba`)

gitleaks flagged the made-up `sk_live_…` value in the scan-import fixture (stripe-access-token rule).
* The fixture now uses an obviously fake value; the redaction test still keys on `api_key=`.
* The two fingerprints in commit `b51615a` are recorded in `.gitleaksignore`, following the repository's existing convention.
* Rescan: full history and the source trees report no leaks.

## 2026-11-08T23:09Z: on-demand database backup (`4a320a8`)

**What:** *Settings* → *Local data* → *Back up the database*.
1. `VACUUM INTO <name>.partial`.
2. A read-only `PRAGMA integrity_check` on the copy.
3. A rename into place.
Documented in UPGRADE.md, together with how to restore manually.

**Tests:** 1 Rust test (a complete copy with the current schema and data, an existing file replaced, no temporary file left, a bad path refused).

**GUI:** not driven, because of the save-dialog limitation.

## 2026-11-08T23:10–23:20Z: final verification

**Windows:**
* cargo test: 295 passed, 1 ignored; with `--features provisioning`, 299.
* clippy `-D warnings`: clean.
* tsc: clean.
* vitest: 215 passed (35 files).
* `npm run build`: succeeded, with the existing INEFFECTIVE_DYNAMIC_IMPORT notice.

**Audits:**
* npm audit: 0 vulnerabilities.
* cargo audit: 0 vulnerabilities, 8 allowed warnings (unchanged).
* gitleaks: no leaks in the full history or the source trees, after `e4985ba`.

**Linux (Docker, automated suites only):**
* Ubuntu 24.04.5: tsc clean, vitest 215, cargo test 295 (one commit before the backup test).
* Debian 12: tsc clean, vitest 215, cargo test 296.
* The images have no clippy, so clippy was verified on Windows only. The Debian login shell resets PATH; use `bash -c`.

**GUI smoke (Windows, debug build, isolated data):** all 16 sidebar pages and all 14 project tabs render, with no error boundary and no console errors.
