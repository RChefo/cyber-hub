use super::*;
use crate::db::Db;
use crate::workspace::evidence::EvidenceStore;

fn tmp(tag: &str) -> PathBuf {
    let mut nonce = [0u8; 4];
    getrandom::fill(&mut nonce).unwrap();
    let d = std::env::temp_dir().join(format!("cyberhub-restore-{tag}-{}-{}", std::process::id(), nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()));
    fs::create_dir_all(&d).unwrap();
    d
}

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// A data folder whose database has one project called `name` and the evidence files `files`.
fn data_dir(tag: &str, name: &str, files: &[&[u8]]) -> PathBuf {
    let dir = tmp(tag);
    let db = Db::open(&dir.join(DB_NAME)).unwrap();
    let pid = db
        .with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES (?1, 'active', 't', 't')", [name])?;
            Ok(c.last_insert_rowid())
        })
        .unwrap();
    let store = EvidenceStore::new(dir.join("evidence"));
    for (i, content) in files.iter().enumerate() {
        store.add_bytes(&db, pid, &format!("f{i}.txt"), content, ("Evidence", ""), "user").unwrap();
    }
    dir
}

fn project_names(path: &Path) -> Vec<String> {
    let c = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut st = c.prepare("SELECT name FROM projects ORDER BY id").unwrap();
    st.query_map([], |r| r.get(0)).unwrap().collect::<Result<_, _>>().unwrap()
}

fn backup_of(dir: &Path, dest: &Path) {
    let db = Db::open(&dir.join(DB_NAME)).unwrap();
    db.with(|c| crate::db::backup_to(c, dest)).unwrap();
}

/// A data folder "Current" and a backup "Old" made in another data folder.
fn current_and_backup(tag: &str) -> (PathBuf, PathBuf) {
    let old = data_dir(&format!("{tag}-old"), "Old", &[]);
    let backup = old.join("backup.db");
    backup_of(&old, &backup);
    (data_dir(tag, "Current", &[b"current only"]), backup)
}

/// Swaps, opens and finishes, as the start-up does.
fn restart(dir: &Path) -> Outcome {
    let mut swap = swap_pending(dir).expect("a restore was staged");
    assert!(!swap.done(), "{:?}", swap.outcome());
    let db = Db::open(&dir.join(DB_NAME)).unwrap();
    drop(db);
    finish(dir, &mut swap)
}

#[test]
fn only_checked_cyber_hub_databases_are_accepted() {
    let dir = data_dir("inspect", "Acme", &[b"proof"]);
    let backup = dir.join("copy.db");
    backup_of(&dir, &backup);
    let info = inspect(&backup, &dir).unwrap();
    assert_eq!((info.schema, info.latest, info.projects, info.findings), (crate::db::MIGRATIONS.len() as i64, crate::db::MIGRATIONS.len() as i64, 1, 0));
    assert_eq!((info.evidence_referenced, info.evidence_available), (1, 1));

    let refused = |path: &Path, why: &str| {
        let e = inspect(path, &dir).unwrap_err().to_string();
        assert!(e.contains(why), "{}: {e}", path.display());
    };
    let changed = |name: &str, sql: &str| {
        let path = dir.join(name);
        fs::copy(&backup, &path).unwrap();
        Connection::open(&path).unwrap().execute_batch(sql).unwrap();
        path
    };
    let text = dir.join("notes.db");
    fs::write(&text, "not a database").unwrap();
    refused(&text, "not an SQLite database");

    let plain = dir.join("plain.db");
    Connection::open(&plain).unwrap().execute_batch("CREATE TABLE t (x);").unwrap();
    refused(&plain, "no schema version");

    let foreign = dir.join("foreign.db");
    Connection::open(&foreign).unwrap().execute_batch("CREATE TABLE projects (id INTEGER); PRAGMA user_version = 5;").unwrap();
    refused(&foreign, "not a Cyber Hub database");

    // schema-embedded SQL from a file is never accepted: an added trigger, a changed index or an
    // added column is refused
    refused(&changed("trigger.db", "CREATE TRIGGER wipe AFTER INSERT ON projects BEGIN DELETE FROM findings; END;"), "unexpected: trigger wipe");
    refused(&changed("index.db", "DROP INDEX idx_activity_time; CREATE INDEX idx_activity_time ON activity_logs(kind);"), "index idx_activity_time");
    refused(&changed("column.db", "ALTER TABLE projects ADD COLUMN extra TEXT;"), "table projects");

    refused(&changed("newer.db", &format!("PRAGMA user_version = {};", crate::db::MIGRATIONS.len() + 1)), "newer version");

    // damaged pages: refused, whatever SQLite reports first
    let damaged = dir.join("damaged.db");
    let mut bytes = fs::read(&backup).unwrap();
    for b in bytes.iter_mut().skip(4096).take(8192) {
        *b = 0x5a;
    }
    fs::write(&damaged, bytes).unwrap();
    assert!(inspect(&damaged, &dir).is_err());

    // the live database is not a backup
    let e = stage(&dir, &dir.join(DB_NAME), None).unwrap_err().to_string();
    assert!(e.contains("own database"), "{e}");
    assert!(!pending(&dir) && !sorting_evidence(&dir));
}

#[test]
fn a_restore_keeps_the_previous_database_and_its_evidence() {
    // the backup comes from another data folder, with an evidence folder next to it
    let old = data_dir("old", "Old", &[b"shared", b"old only"]);
    let backup = old.join("backup.db");
    backup_of(&old, &backup);

    let dir = data_dir("live", "Current", &[b"shared", b"current only"]);
    // an unclean exit: committed changes still in the -wal file
    {
        let c = Connection::open(dir.join(DB_NAME)).unwrap();
        c.execute_batch("PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0;").unwrap();
        c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Only in WAL', 'active', 't', 't')", []).unwrap();
        let (db, wal) = (fs::read(dir.join(DB_NAME)).unwrap(), fs::read(dir.join("cyberhub.db-wal")).unwrap());
        drop(c);
        fs::write(dir.join(DB_NAME), db).unwrap();
        fs::write(dir.join("cyberhub.db-wal"), wal).unwrap();
    }

    let info = stage(&dir, &backup, None).unwrap();
    assert_eq!((info.projects, info.evidence_referenced, info.evidence_available), (1, 2, 2), "{info:?}");
    assert!(pending(&dir) && sorting_evidence(&dir), "staged, and the sweep waits");
    assert!(project_names(&dir.join(DB_NAME)).contains(&"Current".to_string()), "nothing changes before the restart");
    let e = stage(&dir, &backup, None).unwrap_err().to_string();
    assert!(e.contains("already waits"), "one restore at a time: {e}");

    let outcome = restart(&dir);
    assert!(outcome.ok && outcome.error.is_none(), "{outcome:?}");
    assert_eq!((outcome.source.as_str(), outcome.evidence_kept, outcome.evidence_restored), ("backup.db", 1, 1));
    assert_eq!(project_names(&dir.join(DB_NAME)), ["Old"]);
    assert!(!pending(&dir) && !sorting_evidence(&dir), "the restore is complete");

    // the previous database is kept whole, including what was only in its -wal file
    let kept = dir.join(outcome.kept_in.as_deref().unwrap());
    assert!(outcome.kept_in.as_deref().unwrap().starts_with("backups/before-restore-"));
    assert_eq!(project_names(&kept.join(DB_NAME)), ["Current", "Only in WAL"]);
    // its own evidence file moved with it; the restored database's files are all in place
    assert!(blob(&kept.join("evidence"), &sha(b"current only")).is_file());
    for f in [&b"shared"[..], b"old only"] {
        assert!(blob(&dir.join("evidence"), &sha(f)).is_file());
    }
    let db = Db::open(&dir.join(DB_NAME)).unwrap();
    assert_eq!(EvidenceStore::new(dir.join("evidence")).sweep(&db).unwrap(), 0, "the sweep finds nothing to delete");
    drop(db);

    // restoring the kept copy brings the previous database and its evidence back
    stage(&dir, &kept.join(DB_NAME), None).unwrap();
    let back = restart(&dir);
    assert!(back.ok && back.error.is_none(), "{back:?}");
    assert_eq!(project_names(&dir.join(DB_NAME)), ["Current", "Only in WAL"]);
    assert_eq!((back.evidence_kept, back.evidence_restored), (1, 1));
    assert!(blob(&dir.join("evidence"), &sha(b"current only")).is_file());
    assert!(blob(&dir.join(back.kept_in.unwrap()).join("evidence"), &sha(b"old only")).is_file());
}

#[test]
fn an_interrupted_swap_resumes_at_the_next_start() {
    let (dir, backup) = current_and_backup("resume");
    stage(&dir, &backup, None).unwrap();

    // interrupted after the current database moved, before the copy took its place
    let mut j = read_journal(&dir.join(JOURNAL));
    j.kept_in = Some("backups/before-restore-test".into());
    write_journal(&dir.join(JOURNAL), &j).unwrap();
    let kept = dir.join("backups/before-restore-test");
    fs::create_dir_all(&kept).unwrap();
    fs::rename(dir.join(DB_NAME), kept.join(DB_NAME)).unwrap();

    let swap = swap_pending(&dir).unwrap();
    assert!(!swap.done(), "{:?}", swap.outcome());
    assert_eq!(project_names(&dir.join(DB_NAME)), ["Old"]);
    assert_eq!(project_names(&kept.join(DB_NAME)), ["Current"]);

    // interrupted again, right after the copy replaced the database: the journal names the
    // folder and no staged copy is left. The sweep still waits, and the next start sorts the
    // evidence files.
    drop(swap);
    assert!(sorting_evidence(&dir) && !pending(&dir));
    let mut swap = swap_pending(&dir).expect("a replaced database is finished at the next start");
    let outcome = finish(&dir, &mut swap);
    assert!(outcome.ok && outcome.error.is_none(), "{outcome:?}");
    assert_eq!(outcome.evidence_kept, 1);
    assert!(blob(&kept.join("evidence"), &sha(b"current only")).is_file());
    assert!(swap_pending(&dir).is_none() && !sorting_evidence(&dir));

    // a stage interrupted before its copy existed leaves only a journal, which is dropped
    write_journal(&dir.join(JOURNAL), &Journal { source: "x.db".into(), ..Default::default() }).unwrap();
    assert!(swap_pending(&dir).is_none() && !sorting_evidence(&dir));
}

#[test]
fn a_failed_restore_keeps_the_current_database_and_its_evidence() {
    let dir = data_dir("bad", "Current", &[b"current only"]);
    // a staged copy that went bad before the restart
    fs::write(dir.join(PENDING), "garbage").unwrap();
    write_journal(&dir.join(JOURNAL), &Journal { source: "backup.db".into(), ..Default::default() }).unwrap();
    let swap = swap_pending(&dir).unwrap();
    assert!(swap.done() && !swap.outcome().retry);
    assert!(swap.outcome().error.as_deref().unwrap().contains("could not be used"), "{:?}", swap.outcome());
    assert_eq!(project_names(&dir.join(DB_NAME)), ["Current"]);
    assert!(!pending(&dir) && !sorting_evidence(&dir) && swap_pending(&dir).is_none());

    // a restored database that does not open goes aside; the previous one and its evidence go back
    let old = data_dir("bad-old", "Old", &[]);
    let backup = old.join("backup.db");
    backup_of(&old, &backup);
    stage(&dir, &backup, None).unwrap();
    let mut swap = swap_pending(&dir).unwrap();
    assert_eq!(project_names(&dir.join(DB_NAME)), ["Old"]);
    let kept = dir.join(swap.outcome().kept_in.as_deref().unwrap());
    // as if an earlier start had sorted the evidence before the database failed to open
    let moved = blob(&kept.join("evidence"), &sha(b"current only"));
    fs::create_dir_all(moved.parent().unwrap()).unwrap();
    fs::rename(blob(&dir.join("evidence"), &sha(b"current only")), &moved).unwrap();
    undo(&dir, &mut swap, &AppError::Internal("test".into())).unwrap();
    assert_eq!(project_names(&dir.join(DB_NAME)), ["Current"]);
    assert_eq!(project_names(&kept.join("restored-cyberhub.db")), ["Old"]);
    assert!(blob(&dir.join("evidence"), &sha(b"current only")).is_file(), "its evidence file came back");
    assert!(swap.outcome().error.as_deref().unwrap().contains("put back"));
    assert!(!sorting_evidence(&dir) && swap_pending(&dir).is_none());
}

#[test]
fn a_backup_that_changed_after_the_confirmation_is_refused() {
    let (dir, backup) = current_and_backup("changed");
    let seen = inspect(&backup, &dir).unwrap();
    let c = Connection::open(&backup).unwrap();
    c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('Added later', 'active', 't', 't')", []).unwrap();
    drop(c);
    let e = stage(&dir, &backup, Some(&seen)).unwrap_err().to_string();
    assert!(e.contains("changed after it was checked"), "{e}");
    assert!(!pending(&dir) && !sorting_evidence(&dir));
    let now = inspect(&backup, &dir).unwrap();
    stage(&dir, &backup, Some(&now)).unwrap();
    assert!(cancel(&dir).unwrap(), "a staged restore can be cancelled");
    assert!(!pending(&dir) && !sorting_evidence(&dir) && !cancel(&dir).unwrap());
}

#[test]
fn leftover_partial_copies_are_removed_when_evidence_is_sorted() {
    let (dir, backup) = current_and_backup("partial");
    let leftover = dir.join("evidence").join(&sha(b"x")[..2]).join(format!(".{}.partial", sha(b"x")));
    fs::create_dir_all(leftover.parent().unwrap()).unwrap();
    fs::write(&leftover, b"half").unwrap();
    stage(&dir, &backup, None).unwrap();
    let outcome = restart(&dir);
    assert!(outcome.ok && outcome.error.is_none(), "{outcome:?}");
    assert!(!leftover.exists());
}

/// The previous process still has the database open: the restore waits for the next start.
#[cfg(windows)]
#[test]
fn a_database_still_in_use_postpones_the_restore() {
    use std::os::windows::fs::OpenOptionsExt;
    let (dir, backup) = current_and_backup("in-use");
    stage(&dir, &backup, None).unwrap();
    // read and write sharing, but no delete sharing: renaming the file fails as while it is open
    let held = fs::OpenOptions::new().read(true).share_mode(0x1 | 0x2).open(dir.join(DB_NAME)).unwrap();
    let swap = swap_pending(&dir).unwrap();
    assert!(swap.done() && swap.outcome().retry, "{:?}", swap.outcome());
    assert!(swap.outcome().error.as_deref().unwrap().contains("still in use"));
    drop(held);
    assert!(pending(&dir) && sorting_evidence(&dir), "the staged copy waits");
    assert_eq!(project_names(&dir.join(DB_NAME)), ["Current"]);
    let outcome = restart(&dir);
    assert!(outcome.ok && outcome.error.is_none(), "{outcome:?}");
    assert_eq!(project_names(&dir.join(DB_NAME)), ["Old"]);
}
