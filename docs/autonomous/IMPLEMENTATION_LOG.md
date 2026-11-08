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
