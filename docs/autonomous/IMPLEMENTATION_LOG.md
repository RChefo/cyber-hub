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

## 2026-11-09T12:16Z: RC0 release candidate validation starts

Validation only: no installers, no signing, no publishing, no push, never the real user database. Baseline: `release/v0.1.0` at `4361d36`, clean tree, version 0.1.0 everywhere, schema 19.

## 12:16–12:30Z: MSRV (`2ad9a1c`)

* The highest `rust-version` among the 627 locked registry packages is 1.90 (the Tauri crates, including `tauri-plugin-updater` 2.14.1).
* `cargo +1.89.0 check --locked` refuses them; `cargo +1.90.0 test --locked` with a fresh target folder passed 362 tests.
* `rust-version` 1.90, the docs, and a CI job on 1.90.0. No dependency changed. The 1.89.0 and 1.90.0 toolchains were added with rustup next to stable, which stays the default.

## 12:25–12:45Z: upgrade rehearsal (Windows, real app)

* A schema-12 copy with records of every kind, plus URL exclusions; every table and evidence hash snapshotted before and after.
* The app upgraded it to 19 with an identical pre-upgrade backup. The only data changes are the schema-19 scope entries and their four history entries; 20 scope probes show nothing newly allowed or refused.
* Integrity and foreign keys clean, evidence unchanged and verified, relationships intact; a second start changed nothing.

## 12:30–13:00Z: restore rehearsal on Linux (Ubuntu 24.04.5, Debian 12)

* The real app in containers without network, GTK dialogs driven with `xdotool`: invalid and damaged files, restore, undo, missing and modified evidence, a tampered file next to the backup, a kill after the confirmation, a kill during the copy of a 790 MB backup, and a schema-12 backup restored and upgraded.
* 43 of 43 on both. Harness fixes on the way: an error toast is not a confirmation, and `pkill -f` matched its own shell.
* Finding: a kill during the copy leaves `.restore-<id>.partial` in the data folder (never used). Documented, not blocking.

## 12:40–12:58Z: redirect rule (`ae673e5`)

* Each tool's source was read for options and files that turn redirects on: goflags (httpx, katana, nuclei) merges `config.yaml` from the user's configuration folder; nuclei also reads `/etc/nuclei` and template profiles; ffuf reads `ffufrc`; feroxbuster reads `ferox-config.toml` from four places and `--resume-from` restores a whole saved configuration; dalfox reads `config.toml`; nikto's `nikto.conf` can add options (`CLIOPTS`).
* Browser modes ignore the redirect options: nuclei's headless engine leaves redirects to Chromium, katana's `-hl` engine has no redirect check, httpx `-ss` only applies a network policy.
* Fix: browser modes count as following redirects; options that load a file of options are refused on path-only and near-exclusion runs; the files a tool reads on its own are named in a warning. Three new tests; the docs say what is not checked.

## 13:00–13:12Z: release notes (`f90ab22`)

Every claim was checked against the code. The fixes, missing modules and new limitations are listed in the commit; the notes no longer link to repository files, because they are published verbatim.

## 13:05–13:10Z: restore rehearsal on Windows

The real app with an isolated data folder, the native Open dialog driven with Win32 messages: the same cases as on Linux except the tampered-evidence and schema-12 ones, with a 395 MB backup for the kill during the copy. 37 of 37; the real database's modification time did not change.

## 13:10–13:30Z: final validation

* Windows: 365 Rust tests (3 ignored), clippy and tsc clean, 224 frontend tests, npm audit 0, cargo audit 0 vulnerabilities and 8 warnings, gitleaks over all 77 commits clean; GUI smoke over 16 pages and 14 project tabs on the upgraded data, and 7 of 7 feature checks.
* Ubuntu 24.04.5 and Debian 12: the same suites (365 Rust tests, 36 frontend files, clippy, tsc, npm audit 0), and the GUI regression with two new option-file checks: 71 of 71 on both.
* Decision: ready for a release-candidate build; final release authorization waits for Authenticode signing, the candidate's installer and updater validation, and the owner's review.

## 2026-11-09T13:31Z: feature expansion round starts

The owner pointed out that the RC0 segment had implemented no new features and asked for new capabilities in six areas: API security, an HTTP repeater, SBOM analysis, container security, packet capture and log analysis, and interoperability. A code search found none of them (FEATURE_BACKLOG.md, second research round, items 18–24).

## 14:27Z: API inventory (`e36a9a3`)

* OpenAPI 3.0/3.1 and Swagger 2.0 (JSON or YAML), Postman collections and HAR captures become a per-project endpoint inventory (schema 20, `api_specs`). YAML is read with yaml-rust2 0.13 through its event parser, with a node budget and a depth limit.
* Checks mapped to the OWASP API Security Top 10 (2023), a test plan for what a definition cannot show, the scope status of each endpoint, and the request builder prefilled from an endpoint.
* 12 Rust and 3 frontend tests; the real app on Windows 20/20, including migration 20 with its backup.

## 14:33Z: repeater (`3b9ad54`)

* Raw requests from a proxy, resend, an in-memory history (50 entries, 256 KB per body), response comparison and cURL export in the HTTP request builder. Raw requests and resends pass the scope gate.
* 7 frontend tests; the real app against a local server 13/13, including a refused out-of-scope raw request that never reached the server.

## 14:51Z: SBOM analysis (`9b32276`)

* CycloneDX 1.2–1.6 (JSON; XML without DTDs) and SPDX 2.2/2.3 (JSON, tag-value): license risk, the NTIA minimum elements, the SBOM's own vulnerabilities with VEX states (schema 21, `sbom_docs`).
* OSV.dev lookups by package URL, only after a confirmation.
* 10 Rust tests (one an XXE attempt, one the real HTTP client against a local OSV stand-in) and 4 frontend tests. The real app 18/18 with a live OSV.dev query for public test packages: lodash, minimist and Log4Shell found, 13 findings recorded.

## 15:15Z: container and Kubernetes checks (`eff1b18`)

* Dockerfiles (multi-stage aware), Compose files and Kubernetes manifests, against the Pod Security Standards and the CIS Docker Benchmark; pasted, a file or a folder.
* The real-app check found that recording stopped at the first finding title over 200 characters (an absolute path). Titles are now shortened and capped, a single file is shown by its name, recording goes on after an error, and API and SBOM titles are capped as well.
* While driving the Windows folder picker, the test scanned the Documents folder once (read-only). The 4 test findings this put in the disposable database were deleted.
* 6 Rust and 3 frontend tests; the real app 16/16.

## 15:30Z: packet capture and log triage (`6074b5f`)

* pcap and pcapng read as a stream (2 GB, five million packets): hosts, conversations, DNS, HTTP, TLS server names, and cleartext logins with the user name and the length of the secret only.
* Apache/Nginx access logs and OpenSSH logs: injection and traversal payloads, Log4Shell, Shellshock, scanners, sensitive files, password guessing; example lines are redacted.
* URL decoding sliced text by byte index, which could panic on multi-byte input; rewritten byte-wise before the commit.
* 6 Rust and 2 frontend tests; the real app 19/19, with no password in the view or in the findings.

## 16:00Z: SARIF export (`8a8f588`), suppressed results (`d776c58`), findings filters (`31615cc`)

* SARIF 2.1.0 in the Findings export menu: one rule per finding with `security-severity` and `security` tags, `level`, physical or logical locations, `partialFingerprints`, and suppressions for false positives and accepted risks.
* Both exported files pass the OASIS SARIF 2.1.0 JSON schema (jsonschema 4.23, URI and date-time formats checked) and the extra upload rules GitHub documents; the real app 14/14.
* Reading an export back showed that the SARIF import ignored `suppressions`: dismissed results came back as new findings. They are now skipped (an accepted suppression, or one without a status, as ESLint's SARIF formatter writes them). Round trip in the real app 12/12.
* The real-app check showed the Findings panel title squeezed to "Fin" when tags exist; the filters moved to the panel's toolbar row.
* The first export run wrote `Repeater_QA-findings.sarif` to Documents: the Windows save dialog ignores a name set with WM_SETTEXT and saved its default name. The file (test data from the disposable database) was moved out of Documents into the session's scratch folder; the test harness now types the name.

## 16:19Z: Kubernetes RBAC (`914f50a`)

* The escalation paths of the Kubernetes RBAC good practices, matched as the API server does. Bindings are resolved across files, with the built-in roles, and reported when they reach anonymous users, all users, all service accounts or a default service account.
* 3 Rust tests; the real app 13/13 through the folder picker (typing the path works there too). One run failed before its checks, because a button was looked for before the tool had rendered; the unchanged script then passed.

## 16:20–16:30Z: final checks

* Windows: 405 Rust tests (3 ignored), clippy and tsc clean, 243 frontend tests in 41 files, cargo audit 0 vulnerabilities (8 allowed warnings), npm audit 0, gitleaks over the round's 9 commits clean; `cargo +1.90.0 check --locked --all-targets` passes with the declared minimum Rust version.
* The real database was never opened: every real-app run checked its modification time (2026-11-05T15:58:24.853Z, unchanged).
* Not run: the Linux suites and GUI checks. No installers were built and nothing was pushed or published.

## 2026-11-09T16:31Z: Mission 2 starts

The owner's brief asked for research-driven new capabilities in seven tracks (web and API, cloud, DFIR, malware and threat intelligence, supply chain, pentest productivity, standards) and ruled out release work. The code was searched first: 26 Security Utilities and 16 project tabs, none of the candidates present. Sources, findings and the ranking of candidates 27–40 are in FEATURE_BACKLOG.md, "Mission 2" (`c3a79c1`).

## 16:55Z: dependency lockfiles (`4835950`)

* 13 lockfile formats (npm, Yarn classic and Berry, pnpm, Cargo, Poetry, uv, Pipfile, pinned requirements.txt, Composer, Bundler, go.mod, NuGet, Gradle) read into the SBOM model, so the OSV.dev check, licenses and findings work on them. New dependency: `toml` 1.
* Supply-chain checks: plain-HTTP downloads, missing integrity hashes, Git and URL dependencies, pip's `--extra-index-url`, several registries. The NTIA completeness checks are not applied to lockfiles.
* 8 Rust tests (the repository's own `Cargo.lock` and `package-lock.json` among them) and frontend tests; the real app 21/21.

## 17:46Z: Windows event logs (`4d78bfd`)

* The `evtx` crate needs serde_json's `preserve_order` in every version, which would change JSON key order in the whole app, so the EVTX binary XML format (MS-EVEN6) is read by an own parser. It matches python-evtx on all 174 events of the EVTX-ATTACK-SAMPLES files used and, on 59,907 events of this machine's logs, differs only in presentation.
* 35 detections with MITRE ATT&CK techniques. Testing on the machine's own logs found a driver service installed from a Temp folder (HWiNFO); it became the medium rule EVT-SERVICE-WRITABLE-FOLDER.
* Expectations corrected while testing: FILETIME conversion, log clearing counted only from the Eventlog provider, zero-padded LSASS access masks compared as numbers, WMI parents resolved through the creator process ID.
* 8 Rust tests (2 more read local folders on request); the real app 14/14.

## 18:08Z: cloud and IaC checks (`b35fafa`)

* Terraform (HCL through hcl-rs 0.20, JSON, `terraform show -json` plans), CloudFormation, single IAM policies and `get-account-authorization-details`; the 28 privilege-escalation methods catalogued by Rhino Security Labs. `kstring` is pinned at 2.0.2 because 2.0.3 needs Rust 1.96, above the declared minimum.
* Values written as references or variables are not resolved; a first version reported them as weak settings, which a four-state setting model replaced.
* 10 Rust tests and frontend tests; the real app 16/16.

## 18:23Z: PE and ELF file triage (`f9d7594`)

* goblin 0.10 with PE and ELF only; hashes, the import hash as pefile computes it, sections and entropy, hardening flags, capabilities from imports with ATT&CK techniques, strings and indicators. The file is never run.
* A UTF-16 string ran into the next one; the test data showed it and the reader was fixed.
* 6 Rust tests; the real app 18/18 (an inert test program and notepad.exe).

## 18:33Z: API definition comparison (`25bb7a2`)

* Endpoints added, removed and changed between two imports; lost authentication, new anonymous endpoints, new plain-HTTP servers and removed endpoints become recordable issues. Renamed path parameters showed as changes in the first version; path parameters are now ignored.
* 4 Rust tests and 1 frontend test; the real app 14/14.

## 18:51Z: OAuth and OpenID Connect review (`b77ddd2`)

* A Security Utility reviews authorization-server metadata, pasted, opened or fetched through the scope-checked HTTP command (the OpenID Connect address, then RFC 8414's). The RFC 9700, RFC 8725, RFC 8628 and OpenID Connect Discovery sections were read before they were cited; one reference was corrected (RFC 8725 treats `none` in section 3.2).
* 5 frontend tests; the real app 29/29 against a local provider in scope. The out-of-scope check first failed on its expected wording: the refusal came from the address check ("was not sent") instead of the scope check, and the provider received nothing either way.

## 19:08Z: Prowler import (`afd290c`)

* OCSF detection findings (Prowler's JSON) in the scan import: one finding per failed check and resource; passing checks resolve the findings of an earlier import on request; MANUAL and muted results skipped; an interrupted file read as far as it goes.
* Prowler's four published example outputs (AWS, Azure, Google Cloud, Kubernetes) parse; they showed that ATT&CK techniques sit in the `MITRE-ATTACK` compliance entries, which are now read too. The no-scope warning now appears only for files with network targets.
* 4 Rust tests (one more reads a folder on request); the real app 15/15.

## 19:26Z: Linux persistence triage (`2116f34`)

* Cron, systemd, rc and MOTD scripts, ld.so.preload, shell start-up files, authorized_keys, passwd and shadow, sudoers, PAM, autostart and udev, each with its ATT&CK technique (IDs checked on attack.mitre.org, ATT&CK v20.1).
* Review before the commit found that an absolute link in an image could make the scan read the analyst's own files; reads are now confined to the chosen file system by their canonical path. It also fixed a helper that turned `-c` into `c` and took the PAM program from the wrong argument.
* 6 Rust tests (a junction test on Windows; the symbolic-link variant runs on Unix only) and 1 frontend test; SSH fingerprints checked against `ssh-keygen -l`; the real app 21/21 with the collection unchanged afterwards.

## 19:34Z: ATT&CK Navigator layer (`cd8b0b7`)

* The Findings export menu writes a layer (format 4.5) of the techniques the findings name, colored by the highest severity; false positives are left out.
* 2 Rust tests; the real app 9/9. The exported file loaded in the ATT&CK Navigator 5.3.2 (the hosted page reads uploaded layers in the browser; the file held test data only), with the expected colors and without the false positive's technique.

## 19:46Z: SBOM comparison (`54d6534`)

* Components added, removed, upgraded and downgraded between two SBOMs or lockfiles; vulnerabilities compared only when both sides have the same kind of data; supply-chain issues for a new package source, the same version with other hashes, downgrades and stricter licenses.
* The tests found that packages moved to a URL source lost their ecosystem and could not be matched; they now match by name. The real-app check showed that "0 new, 0 gone" read as an all-clear when nothing was looked up; the panel now names the data it compared.
* 4 Rust tests and 1 frontend test; the real app 17/17.

## 19:46–19:55Z: final checks

* Several lockfile formats are read line by line by Cyber Hub's own code, and the lockfile and IaC readers had no test with cut input, as every other parser has; one was added for each (`a7b0368`). Both passed without a change.
* Windows: 459 Rust tests (6 ignored), `cargo clippy --all-targets -- -D warnings` and tsc clean, 258 frontend tests in 45 files, cargo audit 0 vulnerabilities in 640 crates (8 allowed warnings), npm audit 0, gitleaks over the mission's commits clean; `cargo +1.90.0 check --locked --all-targets` passes.
* The real database was never opened: every real-app run checked its modification time (2026-11-05T15:58:24.853Z, unchanged).
* Not run: the Linux suites and GUI checks. No installers were built and nothing was pushed or published.


## Mission 3 (2026-11-09T20:10Z): unified investigation layer

## 20:10–21:10Z: architecture, data model, correlation, review, graph, timeline, provenance (`7b1a842`)

* Recovered the architecture first: findings, finding links, evidence, assets, vulnerabilities, OSINT investigations and their graph engine, the timeline query, scan imports, the workflow engine, MCP and the assistant. The project stays the investigation; nothing was duplicated.
* Migration 22: `relations` (two `(kind, id, sub)` references, type, origin, verification, review, confidence, rules, reason, matched values), `relation_events`, deletion triggers, evidence provenance columns. Tested from a populated schema-21 database (data, defaults, triggers, foreign keys, integrity, query plans).
* Correlation: 10 rules; suggestions merged per pair; decided pairs untouched; caps. The ATT&CK Enterprise 20.1 catalog was built from MITRE's STIX bundle (SHA-256 recorded) for technique validation and search.
* The real-app check found finding links drawn twice next to the relationships that made them; verified relationships now stand for their links. A review before the commit found the deletion triggers would scan whole tables (indexes reordered, two foreign-key columns indexed), the endpoint rule's quadratic matching and case sensitivity, and self-relationships after an OSINT merge; all fixed with tests.
* Real app: 22/22 (upgrade 21 → 22 with backup, correlation, accept and reject, record panel, record timeline, search, manual technique link, graph and its JSON, SVG and PNG export) and 7/7 (provenance and integrity in the vault).

## 21:10–21:43Z: utility results with their evidence (`24258c2`)

* `utility_record`: file, packet capture, log and event log triage and the OAuth review record findings with the analysed file and the analysis as evidence, in one transaction; files named by tokens and re-hashed; the same analysis kept once.
* The real-app check found that text evidence never opened in the viewer (the list never carried the content); fixed with `evidence_text`.
* Real app 16/16 (including a file changed after its analysis, refused; a pasted log linked to its analysis).

## 21:43–21:59Z: ATT&CK matrix (`e3eeeca`)

* Migration 23: assessments and layers. Matrix in the Investigation tab, assessment dialog, layer import and export.
* The real-app check found the overlay dropping a just-imported layer (a reload race); fixed.
* 3 Rust and 3 frontend tests; real app 17/17 (a layer made for ATT&CK v14 with a revoked and an unknown ID).

## 21:59–22:02Z: global search (`3c761db`)

* The palette searches records of open projects; deep links apply on the same project page. Real app 7/7.

## 22:02–22:15Z: MCP and assistant (`f0ab1d5`)

* Six MCP tools; proposals stored as low-confidence suggestions with the client's name; the assistant's optional relationships and ATT&CK section; answers labelled as AI suggestions.
* The real `cyberhub-mcp` server against the debug app: 17/17, approvals given in the app, archived and cross-project requests refused before an approval.

## 22:15–22:21Z: playbooks (`6dc7f63`)

* Workflow steps `correlate`, `verify_evidence`, `await_result`; five playbook templates. Real app 14/14 (a run waits for a file triage done through the native dialog, then finishes; a second run is cancelled while waiting).

## 22:21–22:31Z: reports and remediation groups (`f08a6bb`, `ab4a9db`)

* The reports' evidence register shows each record's source.
* Remediation groups by CVE, package, check and remediation, with rescan-verified counts. Real app 12/12.

## 22:31–22:35Z: concurrency test and final checks (`54576dd`)

* Four threads correlate while a fifth accepts suggestions: no duplicate rows, decisions kept, one finding link per acceptance.
* Correlation at scale (release build): 10,000 findings and 20,000 assets in 158 ms (candidates), 462 ms with storage.
* Windows: 482 Rust tests (7 ignored), `cargo clippy --all-targets -- -D warnings` and tsc clean, 264 frontend tests in 47 files, cargo audit 0 vulnerabilities in 640 crates (8 allowed warnings), npm audit 0, gitleaks over the mission's 9 commits clean; `cargo +1.90.0 check --locked --all-targets` passes.
* The real database was never opened: every real-app run checked its modification time (2026-11-05T15:58:24.853Z, unchanged). Each check ran on a fresh copy of the disposable data folder.
* Not run: the Linux suites and GUI checks. No installers were built and nothing was pushed or published.

## Mission 4 (2026-11-09T23:21Z): detection engineering, threat hunting and compliance

## 23:21–23:23Z: research

* Read SigmaHQ's specification v2.1.0 and its modifier appendix and the YARA language documentation. Found OWASP ASVS 5.0.0's release assets through the GitHub API. Read 13 repositories' adoption signals. Sources and numbers are in FEATURE_BACKLOG.md, "Mission 4".

## 23:23–23:59Z: Sigma detection engineering (`e4a3987`)

* The engine (`detection/sigma.rs`): specification v2.1.0 with errors, unsupported features and warnings reported, the modifier appendix, conditions, Windows log sources, and explanations per field.
* Events (`detection/events.rs`): EVTX, JSON, JSON Lines and text logs, bounded.
* Migration 24: the rule library with versions, collections, samples kept by content hash, tests with expectations, feedback, and project hits.
* ATT&CK coverage overlay with gaps and a Navigator layer export.
* Tests include environment-driven runs of SigmaHQ rules on EVTX-ATTACK-SAMPLES files (8 cases pass).
* Real app: 19/19.

## 23:59–00:25Z: OWASP ASVS 5.0.0 (`8150748`) and a flaky test (`2d26fa2`)

* Migration 25:
  * assessments at a level;
  * statuses only the analyst sets;
  * links to findings and evidence of the same project, removed by triggers when those are deleted;
  * the analyst's mappings and a history of status changes.
* The project tab and a Markdown report with the CC BY-SA attribution.
* Real app 28/28. The script's own mistakes were fixed: the confirmation is an alert dialog, and HeroUI's Switch ignores a synthetic click. Listing all 345 requirements renders in about 1.0 s in the development build (measured in the page).
* Mission 3's concurrency test failed once under full-suite load: the reviewing thread could finish before correlation had suggested anything. It now reviews until it accepts something, within 30 s; four repeated full runs passed.

## 00:25–01:13Z: YARA rules (`4fa4a1a`)

* boreal 1.4 was vetted on crates.io, in its documentation and in its code, with default features off (no process scanning, memory maps or signature verification).
* **A crafted rule crashed the process** (`STATUS_STACK_OVERFLOW`). Probing each shape in a separate process found boreal's parser recursing without a limit on:
  * nested calls and indexes, fatal at 300 levels;
  * chains of `not`, `defined`, `~` and `-`, and arithmetic, bitwise and comparison chains, fatal at 5,000.

  Fixed with a lexical nesting estimate that refuses conditions deeper than 64 before boreal reads them, and compilation on a 16 MB stack. A regression test covers every shape.
* Compatibility, one file at a time:
  * signature-base: 736 of 753 files (5,257 rules);
  * Yara-Rules: 496 of 566 (5,182 rules);
  * no real rule was refused for nesting.
* Two defects in the earlier Sigma work, fixed:
  * a hit was looked up through the first page of 500, so later hits could not be reviewed;
  * binary files were read as text logs.
* Library, tests on file samples, project runs (all YARA files in one pass), File Triage scan with the SHA-256 checked again, and promotion. Real app 25/25.

## 01:13–01:26Z: hunting leads in captures (`ef862c3`)

* Beacon-like schedules (TCP by SYN, UDP by exchange) and DNS patterns (tunneling, long labels, TXT volume, NXDOMAIN bursts), each with its benign explanations. They are kept apart from the issues and recorded only as findings under review, without ATT&CK tags.
* The real-app run found a 60-second beacon reported as 63 s with 0% jitter: alternating gaps (57 s, 63 s) put the median on one mode and the median deviation at zero. The interval is now the mean of the gaps near the median, and the jitter their mean deviation (60 s, 5%). Real app 15/15.

## 01:26–01:40Z: indicator lifecycle (`d8c8cbb`)

* Migration 26 adds to saved indicators:
  * source and reliability (A–F);
  * confidence (0–100);
  * validity, with expiry computed when read;
  * status (active, revoked, false positive);
  * history.
* STIX gets `confidence`, `valid_until`, `revoked` and an external reference for the source. An indicator whose validity ended before it was saved is left out with the reason.
* The real-app run showed a provider's cached verdict still flagging an indicator the analyst had marked a false positive; the analyst's decision now outweighs it, and the verdict stays visible. Real app 16/16, including the migration of an indicator saved before it.

## 01:40–01:50Z: MCP tools (`285e439`)

* Six tools: rules, one rule, hits (redacted), ASVS assessments, a hit's review and an ASVS status. Writes wait for approval, and a client can never set *compliant*.
* The real `cyberhub-mcp` server against the debug app: 18/18. The script reads truncated results by their visible text, since the client keeps 1,500 characters.

## 01:50–01:56Z: final checks

* Windows:
  * 522 Rust tests (10 ignored); `cargo clippy --all-targets -- -D warnings` and tsc clean;
  * 276 frontend tests in 49 files;
  * `cargo +1.90.0 check --all-targets` passed;
  * cargo audit: 0 vulnerabilities in 651 crates (the same 8 allowed warnings); npm audit 0;
  * gitleaks over the mission's 7 commits clean.
* The real database was never opened: every real-app run checked its modification time (2026-11-05T15:58:24.853Z, unchanged), and each ran on a fresh copy of a disposable data folder.
* Not run: the Linux suites and GUI checks, and release-build performance. No installers were built, and nothing was pushed or published.

## Mission 5 (2026-11-10T10:14Z): hardening, Linux compatibility and feature completion

## 10:14–10:56Z: baseline, Linux, migrations and Sigma correlation (`4d9b12f`, `ff3e5f5`, `0c8084f`)

* Baseline:
  * `release/v0.1.0` at `0f51cd2`, clean tree, schema 26, MSRV 1.90;
  * Windows: 522 Rust tests (10 ignored), 276 frontend tests in 49 files.
* Ubuntu 24.04.5 and Debian 12 containers (Rust 1.99.1, Node 22.12.0, WebKitGTK 2.52.6 and 2.50.6):
  * tsc, 49 frontend test files and 522 Rust tests passed on both;
  * **clippy failed on both**: clippy 1.99 rejects three patterns that 1.94 on Windows accepts. Fixed in `4d9b12f` without a behaviour change.
* The earlier Linux GUI regression (scope, imports, findings, workflows, evidence, OSINT, MCP, settings, backup, a restore that restarts the app, recovery after SIGKILL) on a virtual display:
  * 71/71 on Debian 12;
  * 70/71 on Ubuntu 24.04, where the one failure was the script's outdated expected count of MCP tools; the app listed the right number.
* Upgrade validation (`ff3e5f5`):
  * `migrate()` became `migrate_to(target)`, so a test can build a database at any earlier version;
  * one row is seeded in every table from the schema itself;
  * every earlier version is upgraded to the latest, and so is its backup (1 to 25 then; the test follows the latest schema, so 1 to 28 at the end of the mission);
  * a failure injected before each migration's commit, and a real kill of a child process inside a migration, each leave the last complete version, and the next start finishes.
* Sigma correlation rules (`0c8084f`), from the correlation specification v2.1.0:
  * every type except `value_percentile`, with group-by, aliases, `generate` and chains of up to five;
  * windows anchored at each event;
  * bounded at 31-day windows, 1M matching events and 100k groups.

## 10:56–11:21Z: parser security (`6acf43e`)

* A read-only review of every parser of untrusted input, and `hostile.rs`, a reusable harness: truncations, seeded mutations, random bytes, hostile text, oversized lines and deep nesting, each case on a 2 MiB thread under a time budget.
* `hostile_tests.rs` sends about 200 cases through each of about 25 parsers.
* Found and fixed (SECURITY.md, "Parser safety"):
  * an MCP handshake panic that any local process could trigger before authenticating;
  * PCAP and PCAPNG out-of-bounds reads;
  * unbounded recursion in Sigma conditions and in the YAML loader;
  * YAML alias expansion bounded in values but not in bytes;
  * a byte-slicing panic in tool-run checks;
  * amplifications: self-referencing Postman variables, OpenAPI `allOf` cycles, hosts, remotes and keys copied into every item, unbounded SBOM vulnerabilities merged quadratically, EVTX text nodes, PE section counts, and quadratic duplicate checks;
  * an unbounded read in OSINT imports;
  * a detection sample path taken from the database;
  * Markdown reports that could load remote images.

  Each crash was reproduced before its fix and has a regression test.

## 11:21–11:51Z: risk acceptance and compliance gaps (`e6869ed`)

* Migration 27: acceptances, the items they cover, and history.
* The rule sits in the three functions every status change goes through, so the editor, status menus, bulk changes, imports and internal services all require a covering acceptance. MCP clients cannot create one.
* Expiry is computed when read and flagged, never acted on.
* ASVS: exceptions, gaps by chapter, compliant requirements without evidence, comparison of two assessments, and gaps in the report.

## 11:37–12:33Z: fuzzing (`3336d6b`) and TAXII 2.1 (`3573c2f`)

* cargo-fuzz targets for 13 parsers, behind a `fuzzing` feature that application builds never enable. Each ran for 150 s in an offline Ubuntu container: 0.19M to 38M inputs per target.
* **The YAML target found a 434-byte input that ran for more than ten minutes.** Cyber Hub's builder re-escaped nested complex keys at every level. Keys are now bounded at 1,024 characters, and the input is a regression test.
* The EVTX target started without a seed (54 coverage points), so it says little; see 13:28Z below.
* TAXII 2.1 client, from the OASIS standard:
  * discovery, collections, and incremental synchronization of STIX indicators into saved indicators with feed provenance;
  * a native confirmation for every connection, HTTPS only, no redirects;
  * limits on size, pages and objects;
  * credentials only in the OS store, through `cyberhub-keys taxii-set`;
  * migration 28.

  Tests use a local mock server.

## 12:33–12:51Z: ATT&CK, timing tests and CI (`24045f0`, `d23ddf3`, `7206810`)

* A technique's history, comparison of any two technique sets (observed, hypotheses, coverage now, a coverage snapshot, an imported layer), and coverage snapshots (migration 29).
* Six ignored timing tests for an optimized build, run one per process so that each peak memory is its own.
* `ci.yml`:
  * actions pinned by commit and the Debian image by digest;
  * exact tool versions;
  * clippy with warnings as errors, and the fuzz entry points compiled;
  * a Debian 12 job, cargo audit and gitleaks.

  `ci_tests.rs` guards it.
* Linux at `7206810`'s code, on both distributions: tsc, 50 frontend test files, clippy and 567 Rust tests (16 ignored), npm audit. Ubuntu also passed `cargo +1.90.0 check --all-targets` and the release timings (MISSION_REPORT.md, "Mission 5").

## 12:51–13:11Z: end-to-end workflows on Windows (`91b064a`)

* Seven workflows on disposable data in the real Windows app, with native dialogs and local servers: suspicious file, detection engineering, API security, cloud (IaC), compliance, network, supply chain, and TAXII.
* **The detection workflow found a defect:** with the specification's chained example, a project run reported two hits for one chain, because the inner correlation also ran on its own. `disable_correlated` now disables every referenced document of the imported file, inner correlations included (`91b064a`).
* Final run: 48/48. Screen checks of the new views: 10/10.

## 13:11Z–: Linux GUI for the new features, seeded EVTX fuzzing, final checks

* `build.sh` at `91b064a` on both distributions (debug build, frontend embedded).
* **Virtual display (Xvfb with Openbox, offline):** 18/18 on Ubuntu 24.04.5 and on Debian 12:
  * Ctrl+K search by keyboard, and the dashboard charts;
  * a correlation chain and a YARA rule run over two files added through the GTK file chooser, giving one hit each, promoted;
  * risk acceptance through the status menu, the form (Escape closes it unchanged) and the Risks tab;
  * TAXII through the GTK confirmation, both cancel and confirm;
  * the ASVS report through the GTK save dialog;
  * the investigation graph;
  * a 50 MB, 500,000-line auth log through the GTK chooser, read off the UI thread (slowest frame 27 ms on Ubuntu, 54 ms on Debian, while it was read);
  * no runtime errors.
* **WSLg, the real Weston compositor of this Windows machine (1.0.71), from both distributions:**
  * native Wayland (`GDK_BACKEND=wayland`): 4/4 (rendering, navigation, keyboard search, charts, no errors);
  * X11 through XWayland: 6/6 (the same, plus a GTK file chooser and a GTK confirmation).

  The containers mounted the WSLg sockets read-only and wrote nothing to the host's runtime directory.
* **The EVTX fuzz target, seeded:**
  * The seed is the test suite's generated EVTX file. A throwaway copy of the sources wrote it out; the repository was mounted read-only.
  * The target was rebuilt at `91b064a`, then ran for 600 s offline: 570,797 inputs, coverage 7,584 → 8,510 points, nothing found.
* **Final suites at `91b064a`:**
  * Windows: 568 Rust tests (16 ignored); clippy, also with `fuzzing`, and tsc clean; 281 frontend tests in 50 files; cargo audit 0 (651 crates, 8 allowed warnings); npm audit 0.
  * Ubuntu and Debian: tsc, 50 frontend test files, clippy, 568 Rust tests (16 ignored), npm audit.
  * Ubuntu first reported 569. The test binary from the seed run had been reused, because rsync restores older modification times, so cargo saw nothing to rebuild. With the sources touched, it was rebuilt and passed 568, with no seed test in it.
* **GUI regression at `91b064a`:**
  * Ubuntu: 71/71.
  * Debian's first run lost the WebDriver session when the app was started after SIGKILL, so the after-kill phase did not run.
  * The re-run with diagnostics passed 71/71, and a direct start after the kill ran normally.
  * A loop of 12 cycles (SIGKILL during a run, then a restart) came back usable every time, with the run marked interrupted.
  * The cause was not determined.
* `cargo +1.90.0 check --all-targets` at `91b064a`: passed.
* gitleaks over 132 commits and the changed documents: no leaks.
