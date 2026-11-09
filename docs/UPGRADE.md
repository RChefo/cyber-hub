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

The schema version is SQLite's `user_version`. Migrations 9–18 are listed in [DATA_MODEL.md](DATA_MODEL.md). Migrations 13–18 only add tables (`scan_imports`, `finding_fingerprints`; `finding_templates`; `checklist_items`) and columns with defaults (`finding_fingerprints.host`; `findings.cvss_vector`, `findings.cvss_score`; `scope_events.repeats`), and change nothing that exists.

**Scope semantics after this version.** URL scope entries now authorize only their paths, not their host (see [SECURITY.md](SECURITY.md#path-level-scope)). The stored entries are unchanged. A project that relied on a URL entry for host-level operations, such as an Nmap scan of the URL's host, now needs the host, its domain or its address range added to the scope. The refusal says so. They add tables and columns, rebuild `findings` once to give it the new lifecycle, and map the old finding statuses: `open` becomes `new`, `reported` becomes `confirmed`, and every finding that was `reported` gets a history entry recording the mapping. Ids and all other columns are kept.

## What happens at startup

1. Cyber Hub reads the schema version.
2. **A database written by a newer version is refused.** Cyber Hub stops with a message instead of opening it. It does not change the file and does not try to downgrade it.
3. **Before any upgrade, Cyber Hub makes a complete copy of the database** with SQLite's `VACUUM INTO`. The copy goes to `backups/cyberhub-schema<old version>-<UTC time>.db` in the data folder (mode 0700 on Linux). It is written as `….db.partial` and renamed only when complete, so a half-written copy is never mistaken for a backup. Leftover `.partial` files are removed at the next start. The three newest backups are kept. If the copy cannot be made (for example the disk is full), **Cyber Hub stops and changes nothing**.
4. Each migration runs in its own transaction, together with the version bump. A crash, power loss or forced exit during a migration rolls that migration back completely. The database stays at the last completed version, and the next start continues from there.
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
* A journal (`restore-pending.json`) exists until the evidence files are sorted. While it exists, the evidence sweep does not run, and an interrupted restore resumes at the next start. The sweep is also skipped at the start that applies a restore.
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
