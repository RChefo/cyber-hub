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

The schema version is SQLite's `user_version`. Migrations 9–13 are listed in [DATA_MODEL.md](DATA_MODEL.md). Migration 13 only adds two tables (`scan_imports`, `finding_fingerprints`) and changes nothing that exists. They add tables and columns, rebuild `findings` once to give it the new lifecycle, and map the old finding statuses: `open` becomes `new`, `reported` becomes `confirmed`, and every finding that was `reported` gets a history entry recording the mapping. Ids and all other columns are kept.

## What happens at startup

1. Cyber Hub reads the schema version.
2. **A database written by a newer version is refused.** Cyber Hub stops with a message instead of opening it. It does not change the file and does not try to downgrade it.
3. **Before any upgrade, Cyber Hub makes a complete copy of the database** with SQLite's `VACUUM INTO`. The copy goes to `backups/cyberhub-schema<old version>-<UTC time>.db` in the data folder (mode 0700 on Linux). It is written as `….db.partial` and renamed only when complete, so a half-written copy is never mistaken for a backup. Leftover `.partial` files are removed at the next start. The three newest backups are kept. If the copy cannot be made (for example the disk is full), **Cyber Hub stops and changes nothing**.
4. Each migration runs in its own transaction, together with the version bump. A crash, power loss or forced exit during a migration rolls that migration back completely. The database stays at the last completed version, and the next start continues from there.
5. A database that is already current is opened as is. No backup is made and nothing is rewritten.

Credentials (API keys) are not in the database. They stay in the operating system's credential store and are not affected by upgrades or by restoring a backup. Evidence files in `evidence/` are not part of the database backup.

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

There is **no automatic downgrade**. Going back to an older version means restoring the backup made before the upgrade:

1. Close Cyber Hub.
2. In the data folder, rename `cyberhub.db` (keep it, it holds everything since the upgrade). Also remove `cyberhub.db-wal` and `cyberhub.db-shm` if they exist.
3. Copy `backups/cyberhub-schema8-<time>.db` to `cyberhub.db`.
4. Install and start the older version.

Restoring a backup was tested: version 0.1.0 runs normally on its restored schema-8 backup. **Everything created or changed after the upgrade is not in the backup** and is lost to the older version. Only the three newest backups are kept, so copy the pre-upgrade backup elsewhere if it matters. Data cannot be merged back automatically.

## Limits

* Downgrade with data created after the upgrade: not possible.
* Running two versions on the same data folder: not supported.
* A very large database upgrades without a progress indicator; the window appears when the upgrade has finished.
* The backup needs free disk space about the size of the database.
