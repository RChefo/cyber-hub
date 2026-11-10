# Upgrading the database

Cyber Hub keeps everything in one SQLite database, `cyberhub.db`, in the data folder:

* Windows: `%APPDATA%\dev.cyberhub.workstation`
* Linux: `~/.local/share/dev.cyberhub.workstation`

This document states exactly what an upgrade does, what was tested, and how far rollback goes.

## Versions

| Application | Database schema |
|---|---|
| 0.1.0 (first build, commit `d1cf064` and earlier) | 8 |
| 0.1.0 with the platform expansion (phases 1–8) | 12 |
| development after the final QA audit (scan import) | 13 |
| development: finding library | 14 |
| development: fix verification by rescan | 15 |
| development: CVSS on findings | 16 |
| development: methodology checklist | 17 |
| development: repeated scope refusals counted | 18 |
| development: URL exclusions keep excluding their host | 19 |
| development: API security inventory | 20 |
| development: SBOM analysis | 21 |
| development: investigation layer | 22 |
| development: ATT&CK matrix | 23 |
| development: detection engineering | 24 |
| development: OWASP ASVS assessments | 25 |
| development: saved indicator lifecycle | 26 |
| development: risk acceptance | 27 |
| development: TAXII 2.1 feeds | 28 |
| development: ATT&CK coverage snapshots | 29 |
| development: WSTG exceptions | 30 |

The schema version is SQLite's `user_version`. Migrations 9–25 are listed in [DATA_MODEL.md](DATA_MODEL.md); migration 26 in [PROVIDERS.md](PROVIDERS.md#saved-indicators).
* Migrations 9–12 add tables and columns, rebuild `findings` once to give it the new lifecycle, and map the old finding statuses: `open` becomes `new`, `reported` becomes `confirmed`, and every finding that was `reported` gets a history entry recording the mapping. Ids and all other columns are kept.
* Migrations 13–18 only add tables (`scan_imports`, `finding_fingerprints`; `finding_templates`; `checklist_items`) and columns with defaults (`finding_fingerprints.host`; `findings.cvss_vector`, `findings.cvss_score`; `scope_events.repeats`), and change nothing that exists.
* Migration 19 changes scope entries only, as described below.
* Migrations 20 and 21 only add tables (`api_specs`, the API inventory; `sbom_docs`, imported SBOMs) and change nothing that exists.
* Migration 22 adds the investigation layer's tables (`relations`, `relation_events`), triggers that remove a deleted record's relationships, and provenance columns with defaults to `evidence` (`source_module`, `source_ref`, `tool`, `tool_version`, `collected_at`, `derived_from`, `verification`, `verified_at`). Existing evidence keeps its data and starts as `unverified` with no provenance. A test upgrades a populated schema-21 database and checks the data, the defaults, the triggers, `foreign_key_check` and `integrity_check`.
* Migration 23 only adds tables (`attack_assessments`, the analyst's assessments of ATT&CK techniques; `attack_layers`, imported Navigator layers) and changes nothing that exists.
* Migration 24 only adds tables (the detection library: rules, versions, collections, samples, expectations, tests, feedback, and per project the detection hits) and changes nothing that exists.
* Migration 25 only adds tables (ASVS assessments with their statuses, links, mappings and history) and two triggers that remove a deleted finding's or evidence record's links, and changes nothing that exists.
* Migration 26 adds columns with defaults to `ti_saved` (source, reliability, confidence, status `active`, validity, and `updated_at`, set to the time each indicator was saved) and a table for their history. Saved indicators are kept as they were.
* Migration 27 only adds tables (risk acceptances, what they cover and their history) and triggers that remove a deleted finding's, vulnerability's or ASVS assessment's items, and changes nothing that exists. Findings already marked as accepted risks keep their status; the risk register lists them as accepted without a record.
* Migration 28 only adds tables (`taxii_servers`, `taxii_collections`, `taxii_syncs`) and three columns with empty defaults to `ti_saved` (the feed, the STIX object and its version), and changes nothing that exists. A synchronization interrupted by closing the app is marked failed at the next start; its cursor never moved past a page that was not stored.
* Migration 29 only adds a table (`attack_coverage_snapshots`) and changes nothing that exists.
* Migration 30 rebuilds `risk_acceptance_items` so that its `kind` can also be `wstg` (an exception for a failed WSTG test). It copies every row with its rowid into the new table, drops the old one, and recreates its index and the three triggers that name it; no table refers to it. Nothing else changes. The upgrade tests run it on databases from every earlier schema with a row in every table.
* Every migration is tested from every earlier schema (`db_upgrade_tests.rs`, Mission 5):
  * a row is seeded in every table of each schema from 1 to the latest − 1, and after the upgrade every one of them must still exist, with `integrity_check` and `foreign_key_check` clean;
  * the backup taken before the upgrade must keep the old version and the same rows, and must upgrade the same way when restored;
  * a failure injected before any migration's commit leaves the last complete version and its rows, and the next start finishes;
  * a process killed with SIGKILL or TerminateProcess inside a migration leaves the previous version, and the next start finishes.

**Scope semantics from schema 18.** URL scope entries authorize only their paths, not their host (see [SECURITY.md](SECURITY.md#path-level-scope)). A project that relied on a URL entry for host-level operations, such as an Nmap scan of the URL's host, now needs the host, its domain or its address range added to the scope. The refusal says so.

**Schema 19: old URL exclusions keep excluding their host.** Before schema 18, an out-of-scope URL entry excluded its whole host. So that the new semantics never allow something that was excluded, the upgrade to schema 19 excludes the host of every out-of-scope URL entry:
* an in-scope entry with exactly that host becomes an exclusion;
* otherwise a host exclusion is added;
* each change gets a note and a scope history entry (source "upgrade");
* the URL entries themselves are kept.

Development databases already at schema 18 are treated the same way, because the step cannot tell when an exclusion was added. To exclude only the path, remove the host exclusion afterwards.

**Behaviour changes that come with this version.** They need no migration, but users will notice them. See [SECURITY.md](SECURITY.md#path-level-scope) and [releases/0.1.0.md](releases/0.1.0.md).
* **Redirects of external tools.** A tool run is refused when the tool would follow HTTP redirects and one of its URLs is authorized only by path, or lies on a host with an excluded path. Browser modes count as following redirects (nuclei `-headless`, katana `-hl`, httpx `-ss`), and so does an option that loads a file of options (such as `-config`), because Cyber Hub does not read that file. The refusal names the option and says how to run the tool without redirects; the options are never changed. Authorize the host explicitly to allow redirects. The files of options a tool reads on its own are named in a warning; their settings are not checked. Cyber Hub's own HTTP request builder keeps checking every redirect hop itself.
* **Report confidentiality.** The HTML and Markdown reports have the same sections. Both list open findings only and count the closed ones, and neither includes the project's internal notes or contacts. The Markdown report used to export the notes.
* **Project deletion.** A project cannot be deleted while one of its tool runs, workflow runs or discovery operations is still running. Runs and activity entries are kept, unlinked.
* **Checklist.** Finding links can be removed, and every checklist change is recorded on the project timeline.
* **Building from source** needs Rust 1.90 or later. The Tauri 2 crates in `Cargo.lock` require it (Cargo refuses 1.89), and the bundled SQLite 3.54.1 needs at least 1.89. Checked by building and testing with Rust 1.90.0.

## What happens at startup

1. Cyber Hub reads the schema version.
2. **A database written by a newer version is refused.** Cyber Hub stops with a message instead of opening it. It does not change the file and does not try to downgrade it.
3. **Before any upgrade, Cyber Hub makes a complete copy of the database** with SQLite's `VACUUM INTO`. The copy goes to `backups/cyberhub-schema<old version>-<UTC time>.db` in the data folder (mode 0700 on Linux). It is written as `….db.partial` and renamed only when complete, so a half-written copy is never mistaken for a backup. Leftover `.partial` files are removed at the next start. The three newest backups are kept. If the copy cannot be made (for example the disk is full), **Cyber Hub stops and changes nothing**.
4. Each migration runs in its own transaction, together with the version bump. A crash, power loss or forced exit during a migration rolls that migration back completely. The database stays at the last completed version, and the next start continues from there.

   **Rebuilds of referenced tables.** SQLite cannot change a column's constraints in place, so such a change copies the table, drops the old one and renames the copy. With foreign keys on, dropping a table that other tables refer to would first delete the referring rows, for example finding history, links and fingerprints through `ON DELETE CASCADE`. A migration that does this must therefore be listed in `REBUILD_MIGRATIONS` (`src-tauri/src/db.rs`), and it then runs in a rebuild mode:
   * foreign-key enforcement is turned off only around that migration's transaction (inside a transaction SQLite ignores the setting), and turned back on afterwards whatever happens;
   * the migration commits only if `PRAGMA foreign_key_check` finds no broken reference; otherwise it is rolled back and the database stays as it was;
   * an interruption leaves the transaction uncommitted, so SQLite rolls it back at the next open, where enforcement is on again.

   No migration needs this so far. Migration 9 rebuilt `findings` at a time when no table referred to it. A test fails if a future migration drops a referenced table without the rebuild mode. Ordinary operation never runs with foreign keys off.
5. A database that is already current is opened as is. No backup is made and nothing is rewritten.

Credentials (API keys) are not in the database. They stay in the operating system's credential store and are not affected by upgrades or by restoring a backup. Evidence files in `evidence/` are not part of the database backup.

## Manual backups

*Settings* → *Local data* → *Back up the database* saves a copy whenever you want, through a native save dialog. It is the same kind of copy as the upgrade backup:
1. `VACUUM INTO` writes a consistent snapshot to `<chosen name>.partial`.
2. The copy is opened read-only and must pass `PRAGMA integrity_check`. Otherwise it is deleted and nothing is written.
3. It is renamed to the chosen name.

The live database file and its `-wal`, `-shm` and `-journal` files are refused as targets. The temporary file has a random name and is removed if anything fails. The copy contains the database only. Evidence files (`evidence/`) and credentials (the system credential store) are not included. Restore it as described below. A copy made by a newer version is refused by an older one.

## Restoring a backup

*Settings* → *Local data* → *Restore…* restores a manual backup, an automatic pre-upgrade backup (`backups/cyberhub-schema<N>-<time>.db`), or the copy that an earlier restore kept. The code is in `src-tauri/src/restore.rs`.

**Checking the file.** Nothing changes before you confirm. The file is chosen in a native dialog opened by the backend, and is refused unless:
* it is an SQLite database that passes `PRAGMA integrity_check`;
* its schema version is one this version knows (a backup from a newer version is refused);
* its schema is exactly what Cyber Hub's migrations create for that version. The SQL of every table, index, trigger and view is compared, so a foreign database, an added trigger or view, or a changed constraint is refused.

The confirmation shows the file's size and date, its projects and findings, whether it will be upgraded, and how many of the evidence files it refers to are available.

**Restoring.** On confirmation, SQLite copies the file into the data folder as `restore-pending.db`, the copy is checked again, and Cyber Hub restarts. A file that changed after the confirmation is refused. At the start, before the database opens:
1. The current database and its `-wal`/`-shm` files move to `backups/before-restore-<time>/`. Nothing is copied or rewritten, so changes that were still in the `-wal` file are kept.
2. The copy becomes `cyberhub.db`. An older schema is then upgraded as usual, with a pre-upgrade backup first.
3. Evidence files are sorted:
   * Files that only the previous database refers to move to `backups/before-restore-<time>/evidence/`, because the start-up sweep deletes evidence files that no record refers to.
   * Missing files that the restored database refers to are copied from an `evidence/` folder next to the chosen file, but only when their content matches their SHA-256 name and they are within the evidence size limit.
   * Evidence files deleted after the backup was made stay missing.

A notice and the activity log report the result.

**Undoing a restore.** Restore `backups/before-restore-<time>/cyberhub.db`. Its evidence files come back from the folder next to it.

**Safety:**
* Nothing is deleted.
* A journal (`restore-pending.json`) exists until the evidence files are sorted. While it exists, the evidence sweep does not run, and an interrupted restore resumes at the next start once its copy exists. The sweep is also skipped at the start that applies a restore.
* A restore interrupted while SQLite is still making the copy is not resumed: the next start drops it, and the current database stays in use unchanged. The unfinished copy, a hidden `.restore-<id>.partial` file (with a `-journal` file next to it), stays in the data folder; it is never used and can be deleted.
* If the database is still in use when Cyber Hub starts again (another process holds it), the copy waits for the next start. *Settings* shows it and can cancel it.
* If the restored database does not open, it is set aside as `restored-cyberhub.db` in the same folder, and the previous database and its evidence files go back.
* A restored database never turns the MCP bridge on by itself. If it was on in the backup, it is turned off and the notice says so.
* Restoring one of the automatic pre-upgrade backups writes a new pre-upgrade copy of it before its upgrade. As always, only the three newest automatic copies are kept, so the oldest one, possibly the file you chose, is replaced by an identical newer copy.

Restore backups you trust. A backup is a complete Cyber Hub database, and its contents (for example wordlist entries or preferences) are used like your own.

## What was tested (November 2026)

Tested on disposable copies, never on a real user database:

* **Realistic upgrade, schema 8 to 12.** The data was created by the 0.1.0 build itself (commit `d1cf064`): projects with scope and findings in every status, tool runs, OSINT investigations with graphs, versions and evidence, MCP settings and audit, saved commands, favorites, preferences, threat-intelligence and VirusTotal caches. After the upgrade:
  * all 41 pre-existing tables are byte-identical row by row;
  * findings are identical apart from the mapped status, with history entries for formerly `reported` findings;
  * `integrity_check` and `foreign_key_check` are clean;
  * the automatic backup is identical to the pre-upgrade database;
  * reopening keeps everything and makes no second backup.
* **Interrupted upgrade.** A schema-8 database with 400,015 findings was upgraded, and the application was killed after 1.5 s, 4 s and 8 s. Every time:
  * the database was still schema 8, intact and unchanged, with a complete backup;
  * a normal restart completed the upgrade, and all 400,015 findings were verified.

  At that size the first start takes about 9 seconds and shows no progress indicator.
* **Release candidate upgrade, schema 12 to 19** (Windows 11). A schema-12 copy held records of every kind: projects whose scope had excluded and in-scope URL entries, findings linked to evidence, a tool run and an OSINT entity, vulnerabilities with their history, timeline events, an investigation, workflows, MCP settings, and three evidence files, one of them shared by two projects. After the application upgraded it:
  * the automatic backup is identical to the original, row by row;
  * apart from the tool catalog, which is refreshed at every start, every original row is unchanged in its original columns. The only changes are the schema-19 scope entries: one in-scope entry became an exclusion, three host exclusions were added, and four scope history entries record them (source "upgrade");
  * of 20 scope checks, none that the old rules refused is allowed after the upgrade, and none that they allowed is refused;
  * `integrity_check` and `foreign_key_check` are clean, the evidence files are unchanged and pass *Verify*, and finding links, runs, the investigation, workflows, vulnerabilities, the timeline and the MCP settings are intact;
  * a second start changes nothing and makes no second backup.
* **Release candidate restore** (the real app on Windows 11, and on Ubuntu 24.04 and Debian 12 with a virtual display and no network):
  * a file that is not a database and a damaged copy are refused, and nothing is staged;
  * a restore keeps the previous database in `backups/before-restore-<time>/` with the evidence files only it refers to, and restoring that copy brings both back;
  * on Linux, *Verify* reported a missing and a modified evidence file, and a file next to the backup whose content did not match its SHA-256 was not copied in;
  * killed 0.3 s after the confirmation, when the copy was made, the restore was applied whole at the next start;
  * killed while SQLite copied a large backup (395 MB on Windows, 790 MB on Linux), the restore was not applied: the database was unchanged, and only the unfinished copy stayed in the data folder;
  * on Linux, a schema-12 backup restored by schema 19 was upgraded after its own pre-upgrade backup, with its evidence copied from the folder next to it and verified.
* **Newer database.** The current build refuses a database whose `user_version` is higher than it supports and leaves the file unchanged. There is an automated test.
* **Old build on an upgraded database** (0.1.0 opening schema 12). This is **not supported and not safe**. The old build does not check the version: it opens the file without a warning and then shows wrong counts of open findings, fails to create findings, rejects editing findings in the new statuses, and the Findings tab crashes. Only the current build has the newer-database check. It protects against downgrades from later versions, not against 0.1.0.

## Rollback

There is **no automatic downgrade**. Going back to an older version means restoring the backup made before the upgrade. A newer version can restore it in the app, but an older version cannot open a database with a newer schema, so do it by hand:

1. Close Cyber Hub.
2. In the data folder, move `cyberhub.db` together with `cyberhub.db-wal` and `cyberhub.db-shm` (if they exist) into a new folder. Keep all three together: the `-wal` file can hold the most recent changes, and it holds everything since the upgrade.
3. Copy `backups/cyberhub-schema8-<time>.db` to `cyberhub.db`.
4. Install and start the older version.

The older version's evidence sweep deletes evidence files that its database does not refer to. Copy `evidence/` elsewhere first if you need the files that were added after the upgrade.

Restoring a backup was tested: version 0.1.0 runs normally on its restored schema-8 backup. **Everything created or changed after the upgrade is not in the backup** and is lost to the older version. Only the three newest backups are kept, so copy the pre-upgrade backup elsewhere if it matters. Data cannot be merged back automatically.

## Limits

* Downgrade with data created after the upgrade: not possible.
* Running two versions on the same data folder: not supported.
* A very large database upgrades without a progress indicator; the window appears when the upgrade has finished.
* The backup needs free disk space about the size of the database.
