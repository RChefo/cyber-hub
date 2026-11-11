//! Upgrades from every earlier schema version, with a row in every table.
//!
//! * Every version from 1 to the latest − 1 is built as a file, the way Cyber Hub's own
//!   migrations left it, and every table gets a row. The values come from the schema itself:
//!   foreign keys point at the parent's row, enumerated CHECKs take their first value, ranges
//!   their lower bound, and columns with a default keep it.
//! * The real start-up path (`Db::open`) then upgrades the file. Checked afterwards: the version,
//!   `integrity_check`, `foreign_key_check`, every seeded row of every table that still exists,
//!   and the backup taken before the upgrade (still at the old version, with the same rows). The
//!   backup is then opened the same way, which is what restoring it does.
//! * A failure injected just before any migration's commit leaves the last complete version with
//!   all its rows, and the next start finishes the upgrade.
//! * A process killed in the middle of a migration (a real kill, not a simulated error) leaves
//!   the previous version, and the next start finishes the upgrade.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rusqlite::types::Value as Sql;
use rusqlite::Connection;

use super::{migrate_to, Db, MIGRATIONS};
use crate::error::{AppError, AppResult};

thread_local! {
    /// a migration that fails just before its commit (0: none)
    static FAIL_AT: Cell<i64> = const { Cell::new(0) };
    /// a migration that stops just before its commit, for the kill test (0: none)
    static PAUSE_AT: Cell<i64> = const { Cell::new(0) };
}

const CHILD_ENV: &str = "CYBERHUB_TEST_UPGRADE_CHILD";
const MARKER_ENV: &str = "CYBERHUB_TEST_UPGRADE_MARKER";

/// Called by `migrate_to` inside each migration's transaction, just before the commit.
pub(super) fn before_commit(version: i64) -> AppResult<()> {
    if FAIL_AT.with(Cell::get) == version {
        return Err(AppError::Internal(format!("injected failure in migration {version}")));
    }
    if PAUSE_AT.with(Cell::get) == version {
        if let Ok(marker) = std::env::var(MARKER_ENV) {
            let _ = std::fs::write(marker, version.to_string());
        }
        std::thread::sleep(Duration::from_secs(120));
    }
    Ok(())
}

fn latest() -> i64 {
    MIGRATIONS.len() as i64
}

fn tmpdir(tag: &str) -> PathBuf {
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let d = std::env::temp_dir().join(format!("cyberhub-upgrade-{tag}-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/* ───────────── seeding a row in every table, from the schema ───────────── */

struct Col {
    name: String,
    ty: String,
    notnull: bool,
    has_default: bool,
    pk: bool,
}

fn tables(c: &Connection) -> Vec<String> {
    let mut st = c.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap();
    st.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
}

fn columns(c: &Connection, t: &str) -> Vec<Col> {
    let mut st = c.prepare("SELECT name, type, \"notnull\", dflt_value IS NOT NULL, pk FROM pragma_table_info(?1)").unwrap();
    st.query_map([t], |r| Ok(Col { name: r.get(0)?, ty: r.get(1)?, notnull: r.get(2)?, has_default: r.get(3)?, pk: r.get::<_, i64>(4)? > 0 }))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// (column, parent table, parent column or None for the parent's primary key)
fn parents(c: &Connection, t: &str) -> Vec<(String, String, Option<String>)> {
    let mut st = c.prepare("SELECT \"from\", \"table\", \"to\" FROM pragma_foreign_key_list(?1)").unwrap();
    st.query_map([t], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).unwrap().map(Result::unwrap).collect()
}

fn table_sql(c: &Connection, t: &str) -> String {
    c.query_row("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1", [t], |r| r.get(0)).unwrap()
}

/// The first value a CHECK allows for `col`: `col IN ('a', …)` gives 'a', `col BETWEEN 1 AND 3`
/// gives 1. Positions are found on the lowercase text and read from the original (same offsets).
fn check_value(sql: &str, col: &str) -> Option<Sql> {
    let lower = sql.to_ascii_lowercase();
    let name = col.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut from = 0;
    while let Some(i) = lower[from..].find(&name) {
        let at = from + i;
        from = at + name.len();
        if at > 0 && (bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_' || bytes[at - 1] == b'"') {
            continue;
        }
        let rest_at = from + (lower[from..].len() - lower[from..].trim_start().len());
        let rest = &lower[rest_at..];
        if let Some(r) = rest.strip_prefix("in").filter(|r| r.trim_start().starts_with('(')) {
            let open = rest_at + 2 + (r.len() - r.trim_start().len()) + 1;
            let item = sql[open..].trim_start();
            if let Some(q) = item.strip_prefix('\'') {
                let mut out = String::new();
                let mut chars = q.chars().peekable();
                while let Some(ch) = chars.next() {
                    if ch == '\'' {
                        if chars.peek() == Some(&'\'') {
                            chars.next();
                            out.push('\'');
                            continue;
                        }
                        break;
                    }
                    out.push(ch);
                }
                return Some(Sql::Text(out));
            }
            let num: String = item.chars().take_while(|c| c.is_ascii_digit() || *c == '-').collect();
            return num.parse().ok().map(Sql::Integer);
        }
        if let Some(r) = rest.strip_prefix("between") {
            let num: String = r.trim_start().chars().take_while(|c| c.is_ascii_digit() || *c == '-').collect();
            return num.parse().ok().map(Sql::Integer);
        }
    }
    None
}

fn text_for(table: &str, col: &str) -> String {
    let c = col.to_ascii_lowercase();
    if c == "at" || c.ends_with("_at") || c.contains("date") || c.ends_with("time") || c == "day" {
        return "2026-01-02T03:04:05Z".into();
    }
    format!("seed {table}.{col}")
}

/// Inserts one row in every table, parents first. Returns (table, rowid) of every seeded row,
/// or the tables that could not be seeded with the database's error.
fn seed(c: &Connection) -> Result<BTreeMap<String, i64>, Vec<String>> {
    let all = tables(c);
    let mut seeded: BTreeMap<String, i64> = BTreeMap::new();
    let mut errors = Vec::new();
    let mut pending: Vec<String> = all.clone();
    // parents first; a table whose parents cannot be seeded is reported, not looped on
    for _round in 0..all.len() + 1 {
        if pending.is_empty() {
            break;
        }
        let mut next = Vec::new();
        for t in pending {
            let fks = parents(c, &t);
            if fks.iter().any(|(_, p, _)| *p != t && all.contains(p) && !seeded.contains_key(p) && !errors.iter().any(|e: &String| e.starts_with(&format!("{p}:")))) {
                next.push(t);
                continue;
            }
            let sql = table_sql(c, &t);
            let mut names = Vec::new();
            let mut values: Vec<Sql> = Vec::new();
            let cols = columns(c, &t);
            // an INTEGER primary key is the rowid only when it is the whole key
            let rowid_alias = cols.iter().filter(|c| c.pk).count() == 1;
            for col in cols {
                if let Some((_, parent, to)) = fks.iter().find(|(from, _, _)| *from == col.name) {
                    let Some(rowid) = seeded.get(parent) else {
                        continue; // self-reference or unseeded parent: left NULL or default
                    };
                    let v: Sql = match to {
                        Some(to) => c.query_row(&format!("SELECT \"{to}\" FROM \"{parent}\" WHERE rowid = ?1"), [rowid], |r| r.get(0)).unwrap(),
                        None => Sql::Integer(*rowid),
                    };
                    names.push(col.name.clone());
                    values.push(v);
                    continue;
                }
                if col.pk && rowid_alias && col.ty.eq_ignore_ascii_case("INTEGER") {
                    continue; // the rowid
                }
                if col.has_default && check_value(&sql, &col.name).is_none() {
                    continue;
                }
                let v = if let Some(v) = check_value(&sql, &col.name) {
                    v
                } else {
                    let ty = col.ty.to_ascii_uppercase();
                    if ty.contains("INT") {
                        Sql::Integer(1)
                    } else if ty.contains("REAL") || ty.contains("FLOA") || ty.contains("DOUB") {
                        Sql::Real(1.5)
                    } else if ty.contains("BLOB") {
                        Sql::Blob(vec![1, 2, 3])
                    } else if !col.notnull && col.name.ends_with("_json") {
                        Sql::Null
                    } else {
                        Sql::Text(text_for(&t, &col.name))
                    }
                };
                names.push(col.name.clone());
                values.push(v);
            }
            let insert = if names.is_empty() {
                format!("INSERT INTO \"{t}\" DEFAULT VALUES")
            } else {
                let cols: Vec<String> = names.iter().map(|n| format!("\"{n}\"")).collect();
                let marks: Vec<String> = (1..=names.len()).map(|i| format!("?{i}")).collect();
                format!("INSERT INTO \"{t}\" ({}) VALUES ({})", cols.join(", "), marks.join(", "))
            };
            match c.execute(&insert, rusqlite::params_from_iter(values.iter())) {
                Ok(_) => {
                    seeded.insert(t.clone(), c.last_insert_rowid());
                }
                Err(e) => errors.push(format!("{t}: {e}")),
            }
        }
        pending = next;
    }
    for t in pending {
        errors.push(format!("{t}: its parents could not be seeded"));
    }
    if errors.is_empty() {
        Ok(seeded)
    } else {
        Err(errors)
    }
}

/// A database file at `version`, built with Cyber Hub's own migrations (as the app left it: WAL,
/// foreign keys on), with a row in every table.
fn file_at(dir: &Path, version: i64) -> (PathBuf, BTreeMap<String, i64>) {
    let path = dir.join("cyberhub.db");
    let c = Connection::open(&path).unwrap();
    c.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;").unwrap();
    migrate_to(&c, version).unwrap();
    assert_eq!(c.query_row::<i64, _, _>("PRAGMA user_version", [], |r| r.get(0)).unwrap(), version);
    let seeded = seed(&c).unwrap_or_else(|e| panic!("schema {version}: tables that could not be seeded:\n{}", e.join("\n")));
    drop(c);
    (path, seeded)
}

fn version_of(c: &Connection) -> i64 {
    c.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap()
}

/// integrity, foreign keys, and every seeded row of every table that still exists.
fn assert_intact(c: &Connection, seeded: &BTreeMap<String, i64>, what: &str) {
    let ok: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
    assert_eq!(ok, "ok", "{what}: integrity");
    let broken: i64 = c.query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |r| r.get(0)).unwrap();
    assert_eq!(broken, 0, "{what}: broken references");
    let now = tables(c);
    for (t, rowid) in seeded {
        assert!(now.contains(t), "{what}: table {t} disappeared");
        let n: i64 = c.query_row(&format!("SELECT COUNT(*) FROM \"{t}\" WHERE rowid = ?1"), [rowid], |r| r.get(0)).unwrap();
        assert_eq!(n, 1, "{what}: the row seeded in {t} is gone");
    }
}

fn backups(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir.join("backups")).map(|r| r.flatten().map(|e| e.path()).collect()).unwrap_or_default();
    v.sort();
    v
}

/// Mission 6: migration 32 rebuilds `assets`, which other tables refer to. Run with foreign keys
/// off, it keeps every id, and afterwards the references behave as before: deleting an asset
/// still removes its observations, clears vulnerabilities' link to it and drops its relationships.
#[test]
fn the_assets_rebuild_keeps_ids_and_every_reference_working() {
    let dir = tmpdir("assets32");
    let path = dir.join("cyberhub.db");
    let c = Connection::open(&path).unwrap();
    c.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;").unwrap();
    migrate_to(&c, 31).unwrap();
    c.execute_batch(
        "INSERT INTO projects (id, name, status, created_at, updated_at) VALUES (1, 'P', 'active', 't', 't');
         INSERT INTO assets (id, project_id, type, value, key, source, first_seen, last_seen, created_at, updated_at) VALUES (7, 1, 'ip', '10.0.0.7', '10.0.0.7', 'nmap', 't', 't', 't', 't'), (9, 1, 'domain', 'acme.test', 'acme.test', 'dns', 't', 't', 't', 't');
         INSERT INTO asset_observations (asset_id, observed_at, source, fingerprint) VALUES (7, 't', 'nmap', 'f1'), (9, 't', 'dns', 'f2');
         INSERT INTO vulnerabilities (id, project_id, cve_id, asset_id, status, priority, priority_score, created_at, updated_at) VALUES (3, 1, 'CVE-2024-3094', 7, 'open', 'p1', 9.0, 't', 't');
         INSERT INTO relations (project_id, a_kind, a_id, b_kind, b_id, type, origin, verification, created_by, created_at, updated_at) VALUES (1, 'asset', 7, 'vulnerability', 3, 'affects', 'manual', 'verified', 'user', 't', 't');",
    )
    .unwrap();
    migrate_to(&c, 32).unwrap();
    let n = |sql: &str| c.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap();
    assert_eq!(n("PRAGMA user_version"), 32);
    assert_eq!(n("SELECT COUNT(*) FROM assets WHERE id IN (7, 9)"), 2, "ids kept");
    assert_eq!(n("SELECT COUNT(*) FROM pragma_foreign_key_check"), 0);
    assert_eq!(n("PRAGMA foreign_keys"), 1, "enforcement is back on after the rebuild");
    c.execute("INSERT INTO assets (project_id, type, value, key, source, first_seen, last_seen, created_at, updated_at) VALUES (1, 'cloud_resource', 'arn:aws:s3:::b', 'arn:aws:s3:::b', 'import', 't', 't', 't', 't')", []).unwrap();
    assert!(n("SELECT MAX(id) FROM assets") > 9, "new ids continue after the copied ones");
    c.execute("DELETE FROM assets WHERE id = 7", []).unwrap();
    assert_eq!(n("SELECT COUNT(*) FROM asset_observations WHERE asset_id = 7"), 0, "observations cascade");
    assert_eq!(n("SELECT COUNT(*) FROM vulnerabilities WHERE id = 3 AND asset_id IS NULL"), 1, "the vulnerability's link is cleared");
    assert_eq!(n("SELECT COUNT(*) FROM relations"), 0, "the trigger drops the relationship");
    assert_eq!(n("SELECT COUNT(*) FROM asset_observations WHERE asset_id = 9"), 1);
    drop(c);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_seeder_reads_checks_from_the_schema() {
    let sql = "CREATE TABLE t (status TEXT NOT NULL CHECK (status IN ('new','done')), reliability TEXT NOT NULL DEFAULT '' CHECK (reliability IN ('','A','B')), level INTEGER CHECK (level BETWEEN 1 AND 3), confidence INTEGER CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 100), sub_status TEXT, quote TEXT CHECK (quote IN ('it''s')))";
    assert_eq!(check_value(sql, "status"), Some(Sql::Text("new".into())));
    assert_eq!(check_value(sql, "reliability"), Some(Sql::Text(String::new())));
    assert_eq!(check_value(sql, "level"), Some(Sql::Integer(1)));
    assert_eq!(check_value(sql, "confidence"), Some(Sql::Integer(0)));
    assert_eq!(check_value(sql, "sub_status"), None);
    assert_eq!(check_value(sql, "quote"), Some(Sql::Text("it's".into())));
}

#[test]
fn every_schema_version_upgrades_to_the_latest_with_all_its_rows_and_a_usable_backup() {
    for version in 1..latest() {
        let dir = tmpdir(&format!("v{version}"));
        let (path, seeded) = file_at(&dir, version);
        assert!(seeded.len() >= 3, "schema {version}: only {} tables seeded", seeded.len());

        let db = Db::open(&path).unwrap_or_else(|e| panic!("schema {version} did not upgrade: {e}"));
        assert_eq!(db.schema_version().unwrap(), latest());
        drop(db);
        let c = Connection::open(&path).unwrap();
        assert_eq!(version_of(&c), latest());
        assert_intact(&c, &seeded, &format!("schema {version} after the upgrade"));
        drop(c);

        // the copy taken before the upgrade: still at the old version, with the same rows
        let copies = backups(&dir);
        assert_eq!(copies.len(), 1, "schema {version}: one backup before the upgrade, no partial file: {copies:?}");
        assert!(copies[0].file_name().unwrap().to_string_lossy().starts_with(&format!("cyberhub-schema{version}-")));
        let b = Connection::open_with_flags(&copies[0], rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
        assert_eq!(version_of(&b), version, "the backup keeps the old version");
        assert_intact(&b, &seeded, &format!("schema {version} backup"));
        drop(b);

        // restoring that backup means starting from it: it upgrades the same way
        let restored_dir = dir.join("restored");
        std::fs::create_dir_all(&restored_dir).unwrap();
        let restored = restored_dir.join("cyberhub.db");
        std::fs::copy(&copies[0], &restored).unwrap();
        drop(Db::open(&restored).unwrap_or_else(|e| panic!("the schema {version} backup did not upgrade: {e}")));
        let r = Connection::open(&restored).unwrap();
        assert_eq!(version_of(&r), latest());
        assert_intact(&r, &seeded, &format!("schema {version} backup, restored"));
        drop(r);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn a_failure_at_any_migration_keeps_the_last_complete_version_and_a_retry_finishes() {
    let last = latest();
    let mut cases = Vec::new();
    for start in [1, 8, 13, 19, 24, last - 1] {
        for fail in [start + 1, (start + 1 + last) / 2, last] {
            if fail > start && fail <= last && !cases.contains(&(start, fail)) {
                cases.push((start, fail));
            }
        }
    }
    for (start, fail) in cases {
        let dir = tmpdir(&format!("fail-{start}-{fail}"));
        let (path, seeded) = file_at(&dir, start);
        FAIL_AT.with(|f| f.set(fail));
        let err = Db::open(&path).err().map(|e| e.to_string()).unwrap_or_default();
        FAIL_AT.with(|f| f.set(0));
        assert!(err.contains(&format!("injected failure in migration {fail}")), "schema {start}, failing {fail}: {err}");

        let c = Connection::open(&path).unwrap();
        assert_eq!(version_of(&c), fail - 1, "schema {start}: the migrations before {fail} are kept, {fail} is not");
        assert_intact(&c, &seeded, &format!("schema {start}, failed at {fail}"));
        drop(c);
        assert!(backups(&dir).iter().any(|b| b.file_name().unwrap().to_string_lossy().starts_with(&format!("cyberhub-schema{start}-"))), "a backup of schema {start} exists");

        // the next start continues from there
        drop(Db::open(&path).unwrap_or_else(|e| panic!("retry after a failure at {fail}: {e}")));
        let c = Connection::open(&path).unwrap();
        assert_eq!(version_of(&c), last);
        assert_intact(&c, &seeded, &format!("schema {start}, retried after {fail}"));
        drop(c);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Mission 9: data folders as earlier development builds left them, for the installer upgrade
/// test (RELEASE_CANDIDATE_PROCEDURE.md, section 7), instead of copies of anyone's real data.
/// Each is built by the real migrations with a row in every table, and lists the seeded rows in
/// `seeded.tsv`. It writes only into the empty folder named by CYBERHUB_UPGRADE_FIXTURES and does
/// nothing in a normal test run.
#[test]
fn write_upgrade_fixtures() {
    let Ok(out) = std::env::var("CYBERHUB_UPGRADE_FIXTURES") else { return };
    let out = PathBuf::from(out);
    std::fs::create_dir_all(&out).unwrap();
    assert!(std::fs::read_dir(&out).unwrap().next().is_none(), "{} must be an empty folder", out.display());
    // a spread of earlier schemas: 8 is the first build's (d1cf064, which has no check for newer
    // databases), and the one before the latest runs the last migration alone
    for version in [1, 8, 19, 26, latest() - 1] {
        let dir = out.join(format!("schema{version}"));
        std::fs::create_dir_all(&dir).unwrap();
        let (path, seeded) = file_at(&dir, version);
        let c = Connection::open(&path).unwrap();
        // one file to copy: no -wal or -shm beside it
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode = DELETE;").unwrap();
        assert_eq!(version_of(&c), version);
        drop(c);
        let rows: Vec<String> = seeded.iter().map(|(t, id)| format!("{t}\t{id}")).collect();
        std::fs::write(dir.join("seeded.tsv"), rows.join("\n") + "\n").unwrap();
    }
}

/// Runs only when started by `a_process_killed_during_a_migration_…` (the environment variable
/// names the database and the migration to stop in); otherwise it does nothing.
#[test]
fn upgrade_child_process() {
    let Ok(spec) = std::env::var(CHILD_ENV) else { return };
    let (path, pause) = spec.split_once('|').expect("path|version");
    PAUSE_AT.with(|p| p.set(pause.parse().unwrap()));
    let _ = Db::open(Path::new(path));
    panic!("the upgrade was expected to stop in migration {pause}");
}

#[test]
fn a_process_killed_during_a_migration_leaves_the_previous_version_and_the_next_start_finishes() {
    let last = latest();
    for (start, pause) in [(8, 9), (13, (13 + last) / 2), (last - 1, last)] {
        let dir = tmpdir(&format!("kill-{start}-{pause}"));
        let (path, seeded) = file_at(&dir, start);
        let marker = dir.join("paused");
        let name = format!("{}::upgrade_child_process", module_path!().split_once("::").map(|(_, m)| m).unwrap());
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env(CHILD_ENV, format!("{}|{pause}", path.display()))
            .env(MARKER_ENV, &marker)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(60);
        while !marker.exists() {
            assert!(Instant::now() < deadline, "the child never reached migration {pause}");
            if let Ok(Some(status)) = child.try_wait() {
                panic!("the child ended ({status}) before reaching migration {pause}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        child.kill().unwrap();
        let _ = child.wait();

        let c = Connection::open(&path).unwrap();
        assert_eq!(version_of(&c), pause - 1, "schema {start}, killed in {pause}: the unfinished migration is rolled back");
        assert_intact(&c, &seeded, &format!("schema {start}, killed in {pause}"));
        drop(c);
        drop(Db::open(&path).unwrap_or_else(|e| panic!("restart after the kill in {pause}: {e}")));
        let c = Connection::open(&path).unwrap();
        assert_eq!(version_of(&c), last);
        assert_intact(&c, &seeded, &format!("schema {start}, restarted after the kill in {pause}"));
        drop(c);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
