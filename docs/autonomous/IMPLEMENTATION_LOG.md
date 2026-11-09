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

## 2026-11-08T23:15–23:40Z: independent security review and fixes (`c3f26af`, `da545e8`, `bd6d73e`)

A separate reviewer agent (read-only, unanchored on my reasoning) reviewed `092e092..HEAD`. Its findings, and what was done about each:

| Finding | Severity | Fix | Test |
|---|---|---|---|
| `decode_entities` sliced at byte 12. Multibyte text after `&` panicked, and with `panic = "abort"` the app ended | medium | byte-wise search for `;` | `parsers_never_panic_on_cut_or_multibyte_input` (every parser fed truncated and multibyte input; the 日 case would have panicked) |
| Scope skipped when the host was None: SARIF URL locations, unparseable Nuclei/ZAP targets | medium | network findings without a host are out of scope; SARIF URL locations are scope-checked | `network_findings_without_a_usable_or_in_scope_host_are_left_out` |
| Scope checked on a different value than the one stored: Nuclei `host` vs `matched-at`; Burp IP checked by hostname; `[v6]junk` | low/medium | each stored value is checked on its own host; bracket form requires a port or nothing | same test, plus `burp_address_assets_are_checked_as_addresses` |
| Fix verification from partially read files (limits, broken XML, skipped lines) | medium | `Parsed.incomplete` turns *not reported* off, with a preview notice | `an_incomplete_file_never_verifies_fixes` |
| Redaction gaps: Burp issue detail, SARIF message, targets; narrow patterns | medium | every copied field is redacted; PEM keys (also truncated), AWS key IDs, GitHub and Slack tokens and `key: value` added to the shared `redact_text` | `copied_text_is_redacted_in_every_field`, `credential_shapes_and_colon_forms_are_redacted` |
| Quadratic regexes in `ioc.ts` (seconds per 40k chars, hours at 2M) | low | bounded quantifiers and look-behinds, linear URL trimming, one-pass `defangText` | `stays fast on long runs…` (6 hostile inputs, each < 500 ms) |
| Memory and O(n²) on crafted files (Nmap names, SARIF rule text, URL dedupe, library dedupe) | low | caps: 50 names per host, 2,000 characters of rule text, 20 URLs, length checks before dedupe | covered by the parser sweep and the template tests |
| One odd record aborted the whole import (NUL, long tool tag, empty title) | low | control characters stripped, fields cut to limits, fallback title | `one_odd_record_does_not_abort_an_import` |
| Commit race and zero token on RNG failure (suspicion) | low | one commit at a time (mutex); RNG failure is an error | — |
| Backup onto the live DB; `.partial` leftovers (suspicion) | low | live DB and its `-wal`/`-shm`/`-journal` refused; random temp name, removed on failure | backup test extended |

**Also found during the fix:** the IOC extractor's file-extension list contained real TLDs (`com`, `zip`, `mov`, `pl`, `sh`, `md`, `rs`, `py`), so a standalone `evil.com` was not extracted. Fixed, with a regression test.

**Secret scan:** the new credential-shaped fixtures, and my own `.gitleaksignore` comment that quoted the fake Stripe value, were flagged. The PEM fixture line now has an inline `gitleaks:allow`; the comment was reworded; both historical fingerprints are recorded. gitleaks reports no leaks in the full history or in the `src-tauri/src`, `src` and `docs` trees.

**After the fixes (Windows):**
* cargo test: 302 passed, 1 ignored;
* clippy: clean;
* tsc: clean;
* vitest: 217 passed.

**GUI after the fixes:**
* All 30 page and tab smoke checks pass.
* A Nuclei preview showed the scope filtering, the merge, the skipped-line notice and the new incomplete-file notice. It was cancelled, so the QA data is unchanged.
* The visible "1 lines" text was fixed (`bd6d73e`).

## 2026-11-09T06:32Z: second segment starts

The owner said "continue". The mission resumed with the verification gaps and deferred items from MISSION_REPORT.md.

## 2026-11-09T06:35–06:48Z: CVSS scoring checked against FIRST's calculators (`b46a075`)

**What:** [`scripts/cvss-reference.mjs`](../../scripts/cvss-reference.mjs) scores vectors with FIRST's own code:
* the v4.0 reference calculator (`FIRSTdotorg/cvss-v4-calculator`, commit `c5b0d40`);
* the 3.1 and 3.0 calculator scripts served by first.org.

The scripts were downloaded into the scratchpad and reviewed first: plain arithmetic, no I/O. They then ran in a Docker container without network.

**Vectors:**
* every base vector of each version: 104,976 for 4.0, and 2,592 each for 3.1 and 3.0;
* 200,000 seeded random vectors per version, with threat or temporal, environmental and supplemental metrics.

**Result before the fix:**
* v4.0: 304,976 vectors, 0 differences;
* v3.1: 202,592 vectors, 0 differences;
* v3.0: 10,043 of 202,592 differed. 3.0 vectors were scored with the 3.1 equations, but 3.0 has its own `Roundup` (`ceil(x × 10) / 10`) and its own modified impact for a changed scope.

**Fix:** 3.0 vectors use the 3.0 equations, and both 3.x versions multiply in the calculators' order. Afterwards all 709,160 vectors match in both the base score and the score.

**Tests:**
* `matches_firsts_reference_calculators`: a 484-vector subset with FIRST's scores, in the regular suite;
* `matches_firsts_reference_calculators_exhaustively`: the full comparison, an ignored test that needs the script's output.

The CVSS feature is unreleased, so no stored scores needed recomputing.

## 2026-11-09T06:50–07:25Z: restore a backup in the app (`2eb4209`)

**What:** *Settings → Local data → Restore…* (backlog item 12, completing the backup work of `4a320a8`).
* **Check:** the file comes from a backend open dialog. It must pass an integrity check, have a known schema version, and have exactly the schema SQL the migrations create for that version.
* **Confirm:** the dialog shows the size, date, projects, findings, upgrade and evidence availability.
* **Stage:** SQLite copies the file into the data folder. A file that changed after the confirmation is refused.
* **Restart and swap:** before the database opens, the current database and its `-wal`/`-shm` files move to `backups/before-restore-<time>/`. Evidence files that only it refers to move too, because the start-up sweep would otherwise delete them. Missing evidence files are copied back from an `evidence/` folder next to the backup when their content matches their SHA-256 name.
* **Safety:**
  * A journal makes an interrupted swap resume.
  * A database still in use postpones the restore, which Settings can cancel.
  * A restored database that does not open goes aside, and the previous one returns with its evidence.
  * A restored database never turns the MCP bridge on.
  * The app connection runs with `trusted_schema` off.

**Found on the way:** the documented manual restore (replace `cyberhub.db` by hand) lets the next start's evidence sweep delete evidence files that the replaced database still referred to. UPGRADE.md now says how to keep them, and the in-app restore avoids it.

**Independent review:** a reviewer agent read the uncommitted code without my conclusions and found 11 issues. All were fixed before the commit:

| Finding | Fix |
|---|---|
| A crash between the final rename and the journal update made the next start skip the evidence step, so the sweep deleted the previous database's evidence | the state is inferred from the files: a journal with a folder but no staged copy means "swapped", so evidence sorting resumes |
| `undo` after evidence was sorted left those files in the kept folder | `undo` moves them back; no sweep at a start that restored |
| `undo` ignored rename failures | patient renames; a failure stops start-up with a message that names the kept folder |
| any swap failure discarded the staged copy | a database still in use keeps it for the next start (cancel in Settings) |
| the schema check compared only names and columns | the SQL of every table, index, trigger and view is compared; `trusted_schema` off on the app connection |
| restored preferences could turn the MCP bridge on | turned off after a restore, and the notice says so |
| the file could change between the confirmation and the copy | size, date and counts are compared |
| `.partial` copies left after a crash; unbounded sibling copies; symlinks | leftovers removed; files above the evidence limit and links skipped |
| a stage could interleave with an unfinished restore | refused while a journal exists; the journal is written before the copy |
| journal durability | the folder is synced on Unix |
| doc claims ("nothing is deleted", "exactly the schema") | now true; reading a WAL-mode backup may add SQLite's `-shm` file next to it, which is documented |

**Tests:** 7 Rust tests on disposable folders:
* refusals: not SQLite, no version, foreign tables, an added trigger, a changed index, an added column, a newer schema, damaged pages, the live database;
* a full restore with a dirty `-wal` and the round trip back;
* interrupted swaps;
* a failed restore and `undo` with evidence;
* a file changed after the confirmation, and cancel;
* `.partial` cleanup;
* a database held open by another handle (Windows: the restore is postponed and then applied).

There are 5 frontend tests for the summary and notice texts.

**GUI (Windows, debug build, isolated QA data that had an unflushed `-wal` from a forced stop):**
1. A marker project was added, then the schema-14 pre-upgrade backup was restored with *Restore and restart*. The app restarted by itself, upgraded the copy to 17, and showed the restored data. The kept folder holds the previous database with its `-wal`, including the marker project, and the one evidence file only that database referred to.
2. That kept copy was restored again. The marker project came back, the evidence file was copied back from the kept folder, and the notice said so (seen 1.3 s after the restart).
3. A postponed restore was simulated and cancelled in Settings.

The first run's screenshot showed no notice; the outcome had been taken. The second run polled for the notice and found it 1.3 s after the restart.

## 2026-11-09T07:26–07:36Z: MCP tools for the assessment features (`aaa7d0a`)

**What:** five MCP tools and two new `cyberhub_create_finding` arguments:
* `cyberhub_score_cvss` (read): validates and scores a CVSS 4.0, 3.1 or 3.0 vector; stores and sends nothing.
* `cyberhub_list_finding_templates` and `cyberhub_get_finding_template` (read): the user's finding library, so an assistant reuses vetted write-ups.
* `cyberhub_get_checklist` (read): a project's WSTG coverage and the status of every test.
* `cyberhub_set_checklist_item` (local write, asks for approval).
* `cvss_vector` and `remediation` on `cyberhub_create_finding`.

**Before the approval:** an invalid vector, an unknown test or a finding of another project is refused before any approval reaches the user. The approval shows the canonical vector with its score, or the test name. A note that is not given keeps the existing note. The catalog now has 49 tools. The web-assessment and report prompts mention the new tools.

**Tests:**
* 3 unit tests in `mcp/assessment.rs` (functions over the database);
* the catalog tests (count, sensitive-tool categories, groups) were updated.

**Live (Windows, QA data, the real `cyberhub-mcp` sidecar and bridge):**
* The sidecar listed 49 tools.
* The reads returned the expected data.
* The invalid vector and the unknown test were refused with no approval shown.
* Two approvals were decided in the app: the checklist change, and a finding with a CVSS 4.0 vector (shown as 9.3 critical). The finding was stored with its vector, score and remediation.
* The MCP page lists the new tools under their groups with the right badges.
* MCP was turned off again afterwards.

## 2026-11-09T07:38–07:45Z: Linux verification, now with clippy (`7fb4008`)

The Linux images now install clippy (`rustup component add clippy`). Results at `aaa7d0a`:
* Ubuntu 24.04.5 and Debian 12: tsc clean, vitest 36 files passed, cargo test 313 passed.
* Clippy 0.1.99 (Rust 1.99.1 in the images; Windows has 1.94.1) reported three lints in older OSINT code: a sort that can use `sort_by_key`, and two redundant references in `format!` arguments. They were fixed in `7fb4008`; clippy is clean on both versions, and the OSINT tests pass.

## 2026-11-09T07:45–07:52Z: CSV findings import with a column mapping (`53dac93`)

**What:**
* Any CSV file with a header row (a spreadsheet, or a Nessus, Qualys or Greenbone CSV export) imports through the same preview, scope checks, redaction and deduplication as the other formats.
* The parser follows RFC 4180: quoted delimiters, `""` escapes, line breaks and BOM. It is bounded at 200 columns and 50,000 characters per cell. A file that ends inside quotes is marked incomplete.
* The delimiter is detected from the first line.
* Eleven fields are suggested from the header names. The preview shows each column with its first value and reads the file again when one is changed (`scan_import_remap`).
* Severity is read per column: as words, as levels 1 to 5 (Qualys), or as CVSS scores, and the preview says which. Without a severity column, the CVSS value decides; otherwise the finding is informational, with a warning.
* A CSV file never verifies fixes, because exports are often filtered. Templates do not apply.

**Tests:**
* 3 parser unit tests: quoting, delimiters, limits, suggestions for Nessus and Qualys headers, severity scales;
* 3 integration tests: scope, merge, redaction (including the preview sample), formula text kept as text, a re-import seen again, a filtered later export never listed as fixed, remapping, levels, a missing title column, invalid mappings, cut and multibyte input;
* 2 frontend tests for the column options.

**GUI (Windows, QA data):**
* A Qualys-style CSV was chosen through the real open dialog.
* All columns were suggested correctly, and severity was read as levels.
* The private host was listed as outside the scope.
* Changing *Target* from IP to DNS refreshed the preview; the out-of-scope host became `intranet.local`.
* Importing created 3 findings with `host:port` targets and CVEs. A password in two copied columns was masked.

## 2026-11-09T07:53–08:00Z: performance at the limits, second independent review (`9d6dba6`)

**Performance at the import limits.** `import_at_the_limits`, an ignored test, measures 10,000 findings on 500 hosts (half outside the scope) in a debug build:

| Format | Parse | Preview | Import | Import again |
|---|---|---|---|---|
| Nessus XML (1.5 MB) | 0.92 s | 0.29 s | 2.4 s | 2.0 s |
| CSV (0.7 MB) | 0.88 s | 0.15 s | 1.3 s | 0.6 s |

The same check in the GUI, with a separate data folder and an 11 MB CSV of 10,000 rows with realistic descriptions:
* the preview appeared 5.6 s after the dialog opened, including the dialog automation;
* the import of 4,000 findings took 3.1 s;
* `findings_list` returned 4,000 findings (5.9 MB) in 292 ms;
* the Findings tab showed its first 200 rows 1.3 s after opening, with the rest available through *Show more*;
* a search narrowed the 4,000 findings to 250 in 726 ms.

All of these are debug builds with the Vite dev server.

**Second independent review** of `53dac93`, `aaa7d0a` and `b46a075`, by a reviewer agent without my conclusions. Fixed in `9d6dba6`, with tests:

| Finding | Severity | Fix |
|---|---|---|
| CSV detection sliced the text at byte 65,536: a CSV over 64 KB with a multibyte character there panicked, ending the app (`panic = "abort"`) | high | the start of a text is cut on a character boundary; tests with 2-byte and CJK text above 64 KB |
| Rule IDs (a user-chosen CSV column) and references were stored without redaction | medium | redacted and cleaned in `push_finding` for every format |
| CSV header names and the out-of-scope hosts in the preview were shown raw | low/medium | redacted and cleaned |
| A column number could overflow the error message | low | `saturating_add` |
| CSV rows without a target skipped the scope check | low (intent) | with a target column, an empty target counts as outside the scope; without one, the preview warns |
| Delimiter detection and the row splitter used different quoting rules; leading blank lines failed | low | one rule: the delimiter that splits the header and the next rows into the same number of columns |
| `cyberhub_create_finding` showed approvals for findings the save would refuse (title 201–300 characters, bad status, control characters) | low | the save's own checks run before the approval; schema title limit 200 |
| The checklist approval cut the note without its length, did not say it replaced a note, and did not check it like the write | low | the note is checked as on write, and the approval shows its length and "replaces the existing note" |
| Template search text unbounded | low | capped at 200 characters |

The reviewer confirmed the CVSS 3.0 change and the wiring of the reference tests, and found the MCP checklist and template tools, the CSV parser's bounds, scope handling and formula-safe exports sound.

## 2026-11-09T08:00–08:06Z: final verification of the second segment

At `9d6dba6`:

| Check | Windows | Ubuntu 24.04.5 | Debian 12 |
|---|---|---|---|
| cargo test | 321 passed, 3 ignored (325 with `provisioning`) | 321 passed, 3 ignored | 321 passed, 3 ignored |
| clippy `-D warnings` | clean (0.1.94) | clean (0.1.99) | clean (0.1.99) |
| tsc | clean | clean | clean |
| vitest | 224 passed (36 files) | 36 of 36 files passed | 36 of 36 files passed |
| bundle build | succeeded | — | — |
| npm audit | 0 vulnerabilities | — | — |
| cargo audit | 0 vulnerabilities, 8 allowed warnings (unchanged) | — | — |
| gitleaks | no leaks (full history; `src-tauri/src`, `src`, `docs`, `scripts`) | — | — |

**GUI smoke (Windows, QA data):** all 16 pages and 14 project tabs render with no error boundary and no console errors.

**Housekeeping:**
* The QA app and the Vite server I started were stopped; port 1420 is free.
* MCP was turned off again in the QA data.
* No file was written to Documents.
* QA and performance data stay in the scratchpad.

## 2026-11-09T08:51Z: third segment starts

The owner asked to:
* resolve path-level scope rules conservatively;
* continue the Linux GUI verification;
* audit reliability and cross-module references, and fix what is high-value;
* keep researching.

Not authorized: installers, signing, releases, production changes, or the real user database.

## 2026-11-09T08:52–09:15Z: path-level scope (`80f34de`) and import encodings (`e326ace`)

* **URL entries authorize paths.** A URL scope entry authorizes only URLs with the same scheme, host and effective port, inside its path: `/api` covers `/api` and `/api/…`, never `/apix`.
* **They never authorize the host.** Host-level operations need a domain, wildcard, address or range entry:
  * Nmap and other port scans;
  * service scans, TLS analysis and the HTTP check;
  * host names in tool arguments and target lists;
  * host-level import results.

  Refusals name the authorized URLs and say what is missing.
* **Excluded URLs.** An excluded URL excludes its path on every scheme and port. It also refuses host-level operations on its host. Passive lookups of the host are not affected.
* **Redirects.** The HTTP request builder can follow redirects, at most five:
  * every hop is checked against the scope and DNS vetting before it is sent;
  * credentials are dropped when the origin changes;
  * a refused hop stops the chain and is recorded.
* **Scope history (schema 18).** Identical refusals within ten minutes are counted on one entry ("N attempts"). At most 50 per attempt and 2,000 per project are kept.
* **Encodings.** Imported files saved by Excel as UTF-16 or Windows-1252 are decoded instead of becoming replacement characters.
* **Tests.** 331 → 332 Rust tests. A local redirect server proves that the URL outside the path is never requested.

## 2026-11-09T09:15–09:50Z: independent review of the path-level scope (`8355745`)

A reviewer agent got the code but not my conclusions. It found ways to reach paths outside an authorized URL. All were fixed, with regression tests:

| Finding | Fix |
|---|---|
| URLs in tool arguments were split at `;` `,` `=` `(` `'` `\|` `<`. So `https://app/api/;/../../admin` was checked as `https://app/api/`. | A URL runs from its scheme to the next whitespace or the next URL. It is also read as cut at quotes, brackets and separators, and every reading must be in scope. |
| `-uhttps://evil/` (an attached option value) and `-uhttps://x/?a=b` were not checked. | Options are scanned whole. An attached value is read from its web scheme. |
| Scheme-less `host/path` values were not treated as URLs. | They are checked under both HTTP and HTTPS. |
| URLs that could not be parsed were skipped. | They are refused ("cannot be read"). |
| Some clients read `\` as `/`, others as part of the user info. | A backslash is refused in every URL. |
| Servers resolve dot segments, `//` and `%2f`/`%5c` differently. | These forms are refused where a URL entry decides for the host. |
| Exclusions matched byte for byte only, so `/Admin`, `/%61dmin`, `/admin;x=1`, `/admin.json` and fullwidth letters escaped them. | Paths are also compared the way servers commonly read them. Authorization needs both readings to match; an exclusion needs either. |
| Raw request files were accepted when one scheme was authorized. | Both schemes must be authorized. |
| Refused URLs were recorded with credentials and queries. | URLs are recorded as scheme, host, port and path. Other values are redacted. |
| A system proxy would resolve names after DNS vetting. | The three clients that contact targets ignore system proxies. |
| Passive discovery dropped names whose host had an excluded path. | They are recorded, since recording contacts nothing. |
| OSINT values with quotes or spaces were checked after trimming but requested as stored. | They are refused. |
| URL exclusions recorded before schema 18 excluded the whole host. | Schema 19 excludes their host: an in-scope entry with the same value becomes an exclusion, or a new exclusion is added. Each change gets a note and a scope-history entry. |

Tool runs authorized only by URL entries now warn that the tool decides which further paths it requests and which redirects it follows. Redirect revalidation applies to Cyber Hub's own HTTP client. For external tools, the warning is the safeguard, and SECURITY.md documents this as an accepted risk.

## 2026-11-09T09:50–10:05Z: Linux GUI pass on Ubuntu 24.04 at `8355745`

**Setup.** An offline container (`--network none`) ran the real WebKitGTK app under Xvfb. It was driven through WebDriver and xdotool, and GTK dialogs were answered as a user would.

**Result: 43 checks passed, 0 failed.**
* **Path scope:**
  * a request inside the path succeeded;
  * requests outside the path and in the excluded path were refused;
  * a redirect inside the path was followed, and a redirect leaving it was stopped;
  * a host scan and a URL service scan were refused;
  * four refusals were counted on one entry and shown on the timeline;
  * the local server's log shows that `/admin` and `/api/private` were never requested.
* **Findings and vulnerabilities:**
  * CSV import through the GTK open dialog, with the copied secret masked;
  * the findings table and bulk edit;
  * a vulnerability added offline, with its warnings.
* **Evidence and attack surface:**
  * evidence added through the GTK open dialog, with its SHA-256 checked on disk;
  * the attack-surface web check through the GTK confirmation.
* **Workflows and OSINT:** a cancelled run, a report run that succeeded, and an OSINT investigation.
* **MCP through the real sidecar:**
  * 49 tools and a CVSS score;
  * path-level validation;
  * a refusal before approval;
  * an approved checklist write, read back.
* **Backup, restore and SIGKILL:**
  * backup through the GTK save dialog;
  * restore through the GTK open dialog. The app restarted itself, applied the restore, and kept the previous database with its marker project.
  * SIGKILL during a workflow run: the run was marked interrupted at the next start, the integrity check was ok, and there were no foreign-key violations.

## 2026-11-09T10:05–10:20Z: cross-module reference audit and fixes (`96fe970`, `d26f799`, `aa4d17d`, `ce76bfa`)

A second agent audited every writer and deleter of project data for references between projects, assets, findings, evidence, runs, vulnerabilities and OSINT. Fixed:

| Finding | Fix | Commit |
|---|---|---|
| Evidence → "Add tool run" always failed: no title was sent, and a title was required. | Untitled runs are named after the tool and the run number. | `96fe970` |
| Deleting an asset failed with a UNIQUE error when one of its CVEs was also tracked project-wide, or silently dropped the asset. | Its vulnerabilities stay with the project, each with a history entry. A conflicting case is refused with the reason. | `96fe970` |
| "Clear run history" removed every finished run of every project, leaving evidence and links pointing at nothing. | Runs referenced by evidence, finding links, OSINT evidence or discovery snapshots are kept. The result says how many. | `96fe970` |
| Deleting or merging OSINT entities left dangling finding links. Merges also dropped asset origins and events. | Links are removed with the entity. On a merge they move to the kept entity, with the asset origin and events. | `96fe970` |
| Re-linking an investigation to another project carried the old project's references along. | Refused while the current project refers to it. Both sides record the change. | `96fe970` |
| Deleting an investigation left links behind and no trace in the project. | Links are removed. The deletion appears on the project timeline and in the activity log under the project. | `96fe970` |
| Findings created from a vulnerability or an OSINT entity were saved before their links, so a failed link left a finding behind. | Both are written in one transaction. | `96fe970` |
| The timeline type filter ran after a fixed window, so a filter could show nothing. Paging by second skipped events. | The filter runs in SQL, and paging uses a keyset cursor (time, source, row). | `d26f799` |
| The Markdown report (export, MCP, workflows) included closed findings and the project's internal notes. | It lists open findings only and counts the closed ones. Notes are left out. Exports are recorded on the timeline. | `d26f799` |
| Evidence exports were not checked against the stored hash. A deletion could race a new record of the same content. | The export hashes the copy and refuses a mismatch. *Verify* checks a project's files and text. Placement and deletion run under the database lock. Deletions appear on the timeline. | `aa4d17d` |
| MCP approvals of a new finding did not mention an existing identical one. | The approval warns, with the numbers and statuses of the matches. | `aa4d17d` |
| MCP clients could write into archived projects, and status changes left no trace. | Refused both before the approval and when it is carried out. Status changes appear on the timeline and in the activity log. | `ce76bfa` |

Not changed, by decision: importing another project's run into an OSINT investigation is still possible behind the existing toggle and confirmation. It is a deliberate, GUI-only feature.

Documented for later:
* the Markdown and HTML reports still have different sections;
* scan imports do not create vulnerability records;
* checklist links cannot be cleared through the API;
* rebuilding a referenced table in a migration would need a foreign-key-off mode (no such migration exists).

Tests after these commits: 348 Rust tests passed (3 ignored); clippy and tsc clean; 224 frontend tests passed.

## 2026-11-09T10:20–10:45Z: timeline, imported CVEs, dependency advisories (`7e74883`, `6860814`, `0641a0e`)

* **Timeline (`7e74883`).** A new `utility` type records:
  * HTTP requests sent from the request builder: method, URL without its query, status, redirects, and why a redirect was stopped;
  * TLS analyses.

  Asset status changes are recorded too. Tests: the local redirect server test now also checks the timeline entry; asset status changes are covered by a unit test.
* **Imported CVEs (`6860814`).** The import preview offers *Track N CVEs as vulnerabilities* (off by default):
  * each CVE of a recorded finding is tracked for the finding's asset, or for the project, and linked to the finding;
  * an existing record is linked, not duplicated, and dismissed findings are skipped;
  * limits: 20 CVEs per finding, 500 per import;
  * priorities use only cached NVD and EPSS data, so the import stays offline;
  * vulnerability creation can run inside the import's savepoint, so the import stays all or nothing.
* **Advisories (`0641a0e`).** `cargo audit` reported two advisories published in November 2026:
  * **RUSTSEC-2026-0459** (CVE-2026-119375): before 3.54.0, the bundled SQLite can return uninitialized memory for a database opened with a crafted `-wal` file of another page size. Restore opens a user-chosen file together with its `-wal`. Fixed with `rusqlite` 0.41.1 (SQLite 3.54.1). A test fails if the bundled SQLite is older than 3.54.
  * **RUSTSEC-2026-0462**: `rmcp`'s Streamable HTTP client, which is not compiled into Cyber Hub. Upgraded to 3.9.0 anyway.
  * **MSRV.** `rusqlite` 0.41 needs Rust 1.89, so `rust-version` went from 1.80 to 1.89. The 18 lints that clippy enables for that version were fixed mechanically (`is_none_or`, `is_some_and`, `is_multiple_of`). The lockfile is now format 4.

## 2026-11-09T10:45–11:02Z: final verification of the third segment

At `0641a0e`:

| Check | Windows 11 | Ubuntu 24.04.5 | Debian 12 |
|---|---|---|---|
| cargo test | 351 passed, 3 ignored (355 with `provisioning`) | 351 passed, 3 ignored | 351 passed, 3 ignored |
| clippy `-D warnings` | clean (0.1.94) | clean (0.1.99) | clean (0.1.99) |
| tsc | clean | clean | clean |
| vitest | 224 passed (36 files) | 36 of 36 files | 36 of 36 files |
| frontend build | succeeded | succeeded (GUI build) | succeeded (GUI build) |
| npm audit | 0 vulnerabilities | — | — |
| cargo audit | 0 vulnerabilities, 8 allowed warnings | — | — |
| gitleaks | no leaks (this segment's commits; tracked `src-tauri/src`, `src`, `docs`, `scripts` at HEAD) | — | — |
| real GUI pass | smoke: 16 pages and 14 project tabs, no errors | 62 of 62 checks | 62 of 62 checks |

**Linux GUI passes.** Each ran in an offline container: the real WebKitGTK app under Xvfb, driven through WebDriver and xdotool, with GTK dialogs answered like a user. The 62 checks added these to the earlier 43:
* **Evidence:**
  * *Verify* on clean data, then after the stored file was changed on disk;
  * a checked export through the GTK save dialog;
  * a refused export that left no partial file;
  * the *Verify* button and its notice.
* **Run history:** clearing it reports what it removed and what it kept.
* **Assets and vulnerabilities:** an asset deletion that keeps its vulnerability, and a conflicting deletion that is refused.
* **Timeline:**
  * pages without overlap, and the type filter;
  * requests sent from the utilities;
  * asset and project status history.
* **Report:** it leaves out internal notes.
* **CSV import:** CVE tracking switched on in the real import dialog.
* **MCP:**
  * a duplicate-finding warning in the approval;
  * an archived project refused through the real sidecar.

The local target server's log, read at the end of every pass, shows only in-scope requests.

**Windows app.** A debug build ran against an isolated copy of earlier QA data:
* the copy was upgraded from schema 12 to 19 at startup, with a pre-upgrade backup and integrity ok;
* the smoke script visited every page and project tab;
* *Verify* reported the evidence intact.

The owner's real database was not opened; its modification time is still 2026-11-05.

**Housekeeping:**
* The QA app, the Vite server and every container I started were stopped. Ports 1420 and 9223 are free.
* Docker Desktop is still running. The `probot-mysql` container is not mine and was left alone.
* QA data, logs and screenshots stay in the scratchpad (`linuxgui/`, `qa-seg3/`).

## 2026-11-09T11:28Z: fourth segment starts (final pre-release hardening)

The owner decided that external tools must not follow redirects when a target is authorized only by path. The owner also asked for:
* report consistency;
* clearing checklist links through the API;
* a decision on the foreign-key-off migration mode;
* a fix for project deletion during active runs;
* a final regression on all three platforms;
* release documentation.

Not authorized: installers, signing, publishing, production changes, and the real database.

## 11:30–11:45Z: redirects of external tools (`e43f3cb`)

**Sources.** Each tool's redirect options and default were checked in its official help text or source:
* **ffuf:** `-r`, "Follow redirects (default: false)".
* **gobuster:** `follow-redirect`, alias `r`, default false (`cli/options.go`).
* **feroxbuster:** `-r, --redirects` (clap, so short options can be bundled).
* **httpx:** `-fr`, `-fhr`.
* **nuclei:** `-fr`, `-fhr`; `-dr, -disable-redirects`. Templates may follow redirects themselves.
* **katana:** `-dr, -disable-redirects  disable following redirects (default false)`, so it follows by default.
* **sqlmap:** asks "Do you want to follow? [Y/n]" with `default='Y'`, and runs have no input, so it follows; `--ignore-redirects` stops it.
* **whatweb:** `--follow-redirect=WHEN`, "Default: always".
* **dalfox:** `-F, --follow-redirects`.
* **nikto:** `-followredirects`; Getopt accepts prefixes such as `-f`.
* **wpscan:** the main redirect is always requested; `--ignore-main-redirect` only changes what is scanned.
* **CeWL:** the spider queues every redirect location.

**Rule.** A run is refused when the tool would follow redirects and a URL is authorized only by path, or lies on a host with an excluded path. The options are never changed. The refusal names the option and says how to run the tool without redirects, or to authorize the host.

**Tests:**
* the per-tool option parser (attached values, `=false`, bundles, prefixes, values);
* end to end through scope resolution: path-only, host-level, excluded paths, attached URLs, and exclusions and path checks still applying first.

Cyber Hub's own HTTP client keeps its per-hop checks (existing local-server test).

## 11:45–11:52Z: checklist links (`c4c80c8`)

* **API.** `Link::{Keep, To, Clear}` replaces "finding or nothing":
  * the GUI command takes `unlink`;
  * MCP takes `unlink_finding`, and its approval names the finding whose link goes;
  * a finding and an unlink together are refused, and finding ids must be positive.
* **History.** Every change (status, note, link, unlink) is recorded on the project timeline (type `checklist`), with whether the analyst or an MCP client made it.
* **Tests:** clearing; invalid test, project and finding ids; contradictions; archived projects through MCP (before the approval and when it is carried out); the history.

## 11:52–12:00Z: project deletion during runs (`a1e78ca`)

* **Cause.** The end of a run was two autocommitted statements. With the project deleted meanwhile, the activity insert failed its foreign key, and the log line wrongly said the run stayed "running".
* **Fix.**
  * Deletion is refused while a tool run, workflow run or discovery is still running; the check and the deletion are one transaction.
  * The end of a run is one transaction, under the run's current project. A deleted project is noted in the entry.
  * Evidence files that only the deleted project used are removed under the database lock, unless a restore is being sorted.
* **Tests:**
  * refusal, then deletion;
  * the end of a run after the project was removed;
  * an interrupted end-of-run write (a trigger that fails the insert, then nothing is half-written);
  * a deletion racing the end of a run on two threads (foreign keys and integrity checked).

## 12:00–12:05Z: migration rebuild mode (`223491c`)

* **Analysis.** Only migration 9 rebuilds a table (`findings`), and at schema 8 nothing referred to it. No current migration needs foreign keys off.
* **Why a helper anyway.** Today `findings` is referred to with `ON DELETE CASCADE`, so a rebuild written like migration 9 would delete finding history, links and fingerprints. A test demonstrates this.
* **Helper.** `REBUILD_MIGRATIONS` plus `run_rebuild`:
  * foreign keys are turned off only around the migration's transaction;
  * `foreign_key_check` must find nothing before commit;
  * enforcement is always restored.
* **Tests:**
  * the guard test (no migration drops a referenced table outside the mode);
  * a rebuild keeps child rows;
  * a failing and a lossy rebuild change nothing;
  * an interrupted rebuild is rolled back at the next open.

## 12:05–12:15Z: one report model (`ca685c0`)

* **Shared model.** `collect()` feeds `render()` (HTML) and `markdown()`. The sections, order, terms, counts of closed and below-minimum findings, linked evidence with SHA-256, vulnerabilities, assets, the evidence register and the checklist line are all shared.
* **Markdown escaping.** In free text, a `<` that could open HTML outside code is escaped. The CommonMark rules for code spans, backslash escapes and unpaired backticks are respected.
* **Tests:**
  * section and finding order equal in both formats, under several option sets;
  * facts both state, and secrets neither states;
  * inert Markdown that keeps code blocks;
  * empty projects.
* **Old builder.** The Markdown builder in `commands/projects.rs` is gone; `project_report` (export, MCP, workflows) uses the shared model.

## 12:05–12:20Z: final regression at `d6a192e`

* **Windows.** The checks are in the table below.
  * **GUI:** a fresh copy of the QA data, upgraded 12 → 19 with its backup.
    * the smoke covered 16 pages and 14 project tabs (the Vulnerabilities tab, which the smoke caught mid-switch, was rechecked directly: no error);
    * `seg4-win.mjs` passed 7 of 7: report parity, no contacts or closed findings, the Unlink button and its history, deletion refused and then allowed, evidence verification.
  * **Database:** integrity ok, no foreign-key violations.
* **Ubuntu 24.04.5.** Build, then the GUI pass, then the suites.
  * **GUI:** 69 of 69, including the new real-app checks:
    * the ffuf preview with `-r` on a path-only URL is refused; without `-r` it is allowed, and on a host-level scope with `-r` too (a stand-in `ffuf` on the app's PATH only answers the detection);
    * the Unlink button removes the link;
    * the report formats match;
    * deletion is refused while a workflow runs.
  * **Suites:** 362 Rust tests, 36 of 36 frontend files, clippy and tsc clean, npm audit 0.
* **Debian 12.** Build, then the suites (the same results), then the GUI pass: 69 of 69. Its screenshot after Unlink shows the refreshed row ("Failed", "Record finding"). The Ubuntu screenshot had been captured before the re-render; the Ubuntu data check had already passed.
* **gitleaks:** this segment's commits and the tracked tree at HEAD; no leaks.
