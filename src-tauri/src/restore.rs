//! Restoring the database from a backup (docs/UPGRADE.md#restoring-a-backup).
//!
//! The open database cannot be replaced while Cyber Hub runs, so a restore has two steps:
//!
//! 1. **Stage**, while Cyber Hub runs ([`stage`]). The chosen file is checked ([`inspect`]: SQLite
//!    integrity, a schema version this version knows, and exactly the schema Cyber Hub's migrations
//!    create for that version, compared as SQL). SQLite then copies it into the data folder as
//!    `restore-pending.db`, and the copy is checked again. The chosen file is not changed.
//! 2. **Swap**, at the next start, before the database is opened ([`swap_pending`]). The current
//!    database and its `-wal`/`-shm` files move into `backups/before-restore-<time>/`, and the
//!    staged copy becomes `cyberhub.db`. When the restored database has opened, [`finish`] sorts the
//!    evidence files:
//!    * files only the previous database refers to move into that folder's `evidence/`, because
//!      the start-up sweep deletes files no record refers to;
//!    * missing files the restored database refers to are copied from an `evidence/` folder next to
//!      the chosen file, when their content matches their SHA-256 name.
//!
//! Nothing is deleted. Restoring `backups/before-restore-<time>/cyberhub.db` brings the previous
//! database and its evidence back. A journal (`restore-pending.json`) exists from staging until
//! the evidence files are sorted. While it exists the evidence sweep does not run, and an
//! interrupted swap resumes at the next start: a staged copy that is still there has not replaced
//! the database yet, and a journal with a folder but no staged copy has. If the database is still in
//! use, the staged copy waits for the next start. A restored database that does not open goes
//! aside, and the previous database and its evidence files go back.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{validation, AppError, AppResult};

pub const DB_NAME: &str = "cyberhub.db";
const PENDING: &str = "restore-pending.db";
const JOURNAL: &str = "restore-pending.json";
/// The database and the files SQLite keeps next to it
const DB_FILES: [&str; 4] = ["cyberhub.db", "cyberhub.db-wal", "cyberhub.db-shm", "cyberhub.db-journal"];

/// What a backup contains, shown before it is restored.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInfo {
    pub file_name: String,
    pub size: u64,
    /// last modified (RFC 3339), when the file system reports it
    pub modified: Option<String>,
    pub schema: i64,
    /// this version's schema; an older backup is upgraded when it is opened
    pub latest: i64,
    pub projects: i64,
    pub findings: i64,
    /// evidence files the backup refers to
    pub evidence_referenced: usize,
    /// of those, files in the data folder or in an `evidence/` folder next to the backup
    pub evidence_available: usize,
}

impl BackupInfo {
    /// The same file as when it was checked (for the confirmation the user saw)
    fn same_file(&self, other: &BackupInfo) -> bool {
        (self.size, &self.modified, self.schema, self.projects, self.findings) == (other.size, &other.modified, other.schema, other.projects, other.findings)
    }
}

/// The result of a restore, reported once after the restart.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    /// the restored database is in use (an error may still be a warning)
    pub ok: bool,
    /// file name of the restored backup
    pub source: String,
    /// where the previous database is kept, relative to the data folder
    pub kept_in: Option<String>,
    /// evidence files moved next to the previous database
    pub evidence_kept: usize,
    /// evidence files copied back from the backup's folder
    pub evidence_restored: usize,
    /// the MCP bridge was on in the restored database and was turned off
    pub mcp_turned_off: bool,
    /// the staged copy waits for the next start
    pub retry: bool,
    pub error: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Journal {
    source: String,
    /// `evidence/` folder next to the chosen file
    evidence_from: Option<String>,
    /// set before the first file moves
    kept_in: Option<String>,
}

fn read_journal(path: &Path) -> Journal {
    fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn write_journal(path: &Path, j: &Journal) -> AppResult<()> {
    let tmp = path.with_extension("json.partial");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(&serde_json::to_vec(j).map_err(|e| AppError::Internal(e.to_string()))?)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)?;
    // the rename itself is durable once the folder is synced (not possible on Windows, where NTFS
    // journals the rename)
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

fn is_sha(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `<root>/<first two characters>/<sha256>`, the evidence store's layout
fn blob(root: &Path, sha: &str) -> PathBuf {
    root.join(&sha[..2]).join(sha)
}

/// Canonical, lower-cased path for comparisons (file names compare without regard to case, as on
/// Windows). None when the parent folder does not exist.
fn norm(p: &Path) -> Option<String> {
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new("."));
    Some(dir.canonicalize().ok()?.join(p.file_name()?).to_string_lossy().to_lowercase())
}

/* ───────────────────────── checking a backup ───────────────────────── */

/// Every table, index, trigger and view with its SQL (whitespace collapsed), without SQLite's own
/// objects.
fn schema_of(c: &Connection) -> AppResult<BTreeSet<String>> {
    let mut st = c.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")?;
    let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, Option<String>>(3)?)))?;
    let mut out = BTreeSet::new();
    for row in rows {
        let (kind, name, table, sql) = row?;
        let sql = sql.unwrap_or_default().split_whitespace().collect::<Vec<_>>().join(" ");
        out.insert(format!("{kind} {name} on {table}: {sql}"));
    }
    Ok(out)
}

/// The database must have exactly the schema Cyber Hub's migrations create up to `version`: the
/// SQL of every table, index, trigger and view is compared, so a foreign database, an added
/// trigger or view, or a changed constraint, default or foreign-key action is refused.
fn check_schema(c: &Connection, version: i64) -> AppResult<()> {
    let reference = Connection::open_in_memory()?;
    reference.execute_batch("PRAGMA foreign_keys = ON;")?;
    for sql in &crate::db::MIGRATIONS[..version as usize] {
        reference.execute_batch(sql)?;
    }
    let (expected, found) = (schema_of(&reference)?, schema_of(c)?);
    let short = |s: &String| s.chars().take(120).collect::<String>();
    if let Some(extra) = found.difference(&expected).next() {
        return Err(validation(format!("This file is not a Cyber Hub database, or its schema was changed (unexpected: {}).", short(extra))));
    }
    if let Some(missing) = expected.difference(&found).next() {
        return Err(validation(format!("This file is not a Cyber Hub database, or its schema was changed (missing: {}).", short(missing))));
    }
    Ok(())
}

/// Opens a database file read-only and checks it. Returns the connection and its schema version.
fn open_checked(path: &Path) -> AppResult<(Connection, i64)> {
    let meta = fs::metadata(path).map_err(|e| validation(format!("The file cannot be read ({e})")))?;
    if !meta.is_file() {
        return Err(validation("Choose a database file"));
    }
    let mut magic = [0u8; 16];
    if fs::File::open(path)?.read_exact(&mut magic).is_err() || &magic != b"SQLite format 3\0" {
        return Err(validation("This file is not a Cyber Hub database (it is not an SQLite database)"));
    }
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
    // the schema of a file from elsewhere is not trusted
    conn.execute_batch("PRAGMA trusted_schema = OFF;")?;
    let result: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if result != "ok" {
        return Err(validation(format!("This copy is damaged and cannot be restored (integrity check: {})", result.chars().take(200).collect::<String>())));
    }
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let latest = crate::db::MIGRATIONS.len() as i64;
    if version < 1 {
        return Err(validation("This file is not a Cyber Hub database (it has no schema version)"));
    }
    if version > latest {
        return Err(validation(format!(
            "This backup was made by a newer version of Cyber Hub (schema {version}; this version supports up to {latest}). Restore it with that version."
        )));
    }
    check_schema(&conn, version)?;
    Ok((conn, version))
}

/// SHA-256 names of the evidence files a database refers to (none before the evidence table).
fn evidence_refs(c: &Connection) -> AppResult<HashSet<String>> {
    let has_table: i64 = c.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'evidence'", [], |r| r.get(0))?;
    if has_table == 0 {
        return Ok(HashSet::new());
    }
    let mut st = c.prepare("SELECT DISTINCT sha256 FROM evidence WHERE kind = 'file' AND sha256 IS NOT NULL")?;
    let refs = st.query_map([], |r| r.get::<_, String>(0))?.filter_map(Result::ok).filter(|s| is_sha(s)).collect();
    Ok(refs)
}

/// The `evidence/` folder next to a chosen file, if there is one
fn sibling_evidence(source: &Path) -> Option<PathBuf> {
    let dir = source.parent().filter(|d| !d.as_os_str().is_empty()).unwrap_or(Path::new(".")).join("evidence");
    dir.is_dir().then_some(dir)
}

/// A regular file (not a link) of at most the evidence size limit
fn usable_evidence(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.is_file() && m.len() <= crate::workspace::evidence::MAX_FILE)
}

/// Checks a backup without changing it and describes what it contains. (SQLite may create its
/// usual `-shm` file next to a WAL-mode database while reading it.)
pub fn inspect(source: &Path, data_dir: &Path) -> AppResult<BackupInfo> {
    let (conn, schema) = open_checked(source)?;
    let count = |table: &str| -> AppResult<i64> { Ok(conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))?) };
    let refs = evidence_refs(&conn)?;
    let live = data_dir.join("evidence");
    let beside = sibling_evidence(source);
    let available = refs.iter().filter(|sha| blob(&live, sha).is_file() || beside.as_ref().is_some_and(|b| usable_evidence(&blob(b, sha)))).count();
    let meta = fs::metadata(source)?;
    Ok(BackupInfo {
        file_name: source.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(),
        size: meta.len(),
        modified: meta.modified().ok().map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
        schema,
        latest: crate::db::MIGRATIONS.len() as i64,
        projects: count("projects")?,
        findings: count("findings")?,
        evidence_referenced: refs.len(),
        evidence_available: available,
    })
}

/// Refuses Cyber Hub's own database files (and a staged copy) as the file to restore.
fn refuse_own_files(data_dir: &Path, source: &Path) -> AppResult<()> {
    let chosen = norm(source);
    for name in DB_FILES.iter().chain([PENDING].iter()) {
        if chosen.is_some() && chosen == norm(&data_dir.join(name)) {
            return Err(validation("Choose a backup: this is Cyber Hub's own database"));
        }
    }
    Ok(())
}

/// Checks `source` and copies it into the data folder for the swap at the next start. `confirmed`
/// is what the user saw: a file that changed since is refused. The chosen file is not changed.
pub fn stage(data_dir: &Path, source: &Path, confirmed: Option<&BackupInfo>) -> AppResult<BackupInfo> {
    if data_dir.join(JOURNAL).exists() {
        return Err(validation(if pending(data_dir) {
            "A restore already waits for the next start of Cyber Hub. Restart Cyber Hub, or cancel that restore first."
        } else {
            "The previous restore is not complete yet. Restart Cyber Hub to complete it, then restore again."
        }));
    }
    refuse_own_files(data_dir, source)?;
    let info = inspect(source, data_dir)?;
    if confirmed.is_some_and(|c| !c.same_file(&info)) {
        return Err(validation("The backup changed after it was checked. Choose it again."));
    }
    // the journal first: a staged copy never exists without it
    let journal = Journal { source: info.file_name.clone(), evidence_from: sibling_evidence(source).map(|p| p.to_string_lossy().to_string()), kept_in: None };
    write_journal(&data_dir.join(JOURNAL), &journal)?;
    let staged = (|| -> AppResult<()> {
        let (conn, _) = open_checked(source)?;
        let mut nonce = [0u8; 6];
        getrandom::fill(&mut nonce).map_err(|e| AppError::Internal(format!("no random source: {e}")))?;
        let nonce: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let partial = data_dir.join(format!(".restore-{nonce}.partial"));
        // a consistent copy made by SQLite (includes a `-wal` next to the chosen file)
        let copied = conn.execute("VACUUM INTO ?1", [partial.to_string_lossy().to_string()]).map_err(AppError::from).and_then(|_| {
            drop(conn);
            open_checked(&partial).map(|_| ())
        });
        let result = copied.and_then(|_| fs::rename(&partial, data_dir.join(PENDING)).map_err(AppError::from));
        if result.is_err() {
            let _ = fs::remove_file(&partial);
        }
        result
    })();
    if let Err(e) = staged {
        let _ = fs::remove_file(data_dir.join(JOURNAL));
        return Err(e);
    }
    Ok(info)
}

/// Whether a staged restore waits for the next start.
pub fn pending(data_dir: &Path) -> bool {
    data_dir.join(PENDING).is_file()
}

/// Cancels a staged restore that has not replaced the database yet.
pub fn cancel(data_dir: &Path) -> AppResult<bool> {
    if !pending(data_dir) {
        return Ok(false);
    }
    fs::remove_file(data_dir.join(PENDING))?;
    let _ = fs::remove_file(data_dir.join(JOURNAL));
    Ok(true)
}

/// Whether a restore is in progress (staged, or swapped with its evidence files not sorted yet):
/// the start-up sweep must not delete evidence files then, because some belong to the previous
/// database.
pub fn sorting_evidence(data_dir: &Path) -> bool {
    data_dir.join(JOURNAL).exists()
}

/* ───────────────────────── the swap at start-up ───────────────────────── */

/// A restore at start-up, between [`swap_pending`] and [`finish`] or [`undo`].
#[derive(Debug)]
pub struct Swap {
    outcome: Outcome,
    /// absolute folder of the previous database
    kept: PathBuf,
    evidence_from: Option<PathBuf>,
}

impl Swap {
    /// The restore ended before the database opened (nothing to finish or undo).
    pub fn done(&self) -> bool {
        self.outcome.error.is_some()
    }
    pub fn outcome(&self) -> &Outcome {
        &self.outcome
    }
    pub fn outcome_mut(&mut self) -> &mut Outcome {
        &mut self.outcome
    }
}

/// A rename that waits for a file still held open: after a restart, the previous process may not
/// have released the database yet (Windows refuses to rename open files).
fn rename_patiently(from: &Path, to: &Path) -> std::io::Result<()> {
    // about ten seconds (half a second in tests)
    const PATIENCE: u32 = if cfg!(test) { 5 } else { 100 };
    let mut tries = 0;
    loop {
        match fs::rename(from, to) {
            Err(e) if tries < PATIENCE && in_use(&e) => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            other => return other,
        }
    }
}

/// Access denied, or a sharing or lock violation: another process has the file open.
fn in_use(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::PermissionDenied || matches!(e.raw_os_error(), Some(32 | 33))
}

/// Moves the database files that are still in `data_dir` into `kept`, then the staged copy into
/// place. On failure, the database files go back.
fn move_into_place(data_dir: &Path, pending: &Path, kept: &Path) -> std::io::Result<()> {
    fs::create_dir_all(kept)?;
    let result = (|| -> std::io::Result<()> {
        for name in DB_FILES {
            let (from, to) = (data_dir.join(name), kept.join(name));
            if !from.exists() {
                continue; // absent, or moved before an interruption
            }
            if to.exists() {
                return Err(std::io::Error::other(format!("{name} exists in both folders")));
            }
            rename_patiently(&from, &to)?;
        }
        rename_patiently(pending, &data_dir.join(DB_NAME))
    })();
    if result.is_err() {
        put_back(data_dir, kept);
    }
    result
}

/// Moves the previous database files from `kept` back into `data_dir`, without overwriting.
fn put_back(data_dir: &Path, kept: &Path) -> bool {
    let mut ok = true;
    for name in DB_FILES {
        let (from, to) = (kept.join(name), data_dir.join(name));
        if from.exists() && !to.exists() && rename_patiently(&from, &to).is_err() {
            ok = false;
        }
    }
    ok
}

/// Swaps in a staged restore before the database is opened. None when nothing is staged.
pub fn swap_pending(data_dir: &Path) -> Option<Swap> {
    let pending_path = data_dir.join(PENDING);
    let journal_path = data_dir.join(JOURNAL);
    if !journal_path.exists() && !pending_path.exists() {
        return None;
    }
    let mut j = read_journal(&journal_path);
    let staged = pending_path.is_file();
    let outcome = Outcome { source: if j.source.is_empty() { PENDING.into() } else { j.source.clone() }, ..Default::default() };
    let ended = |mut outcome: Outcome, retry: bool, msg: String| {
        outcome.retry = retry;
        outcome.error = Some(msg);
        Some(Swap { outcome, kept: PathBuf::new(), evidence_from: None })
    };

    if staged {
        if let Err(e) = open_checked(&pending_path) {
            let _ = fs::remove_file(&pending_path);
            let _ = fs::remove_file(&journal_path);
            return ended(outcome, false, format!("The copy waiting to be restored could not be used ({e}). It was removed, and the current database was kept."));
        }
        let kept_in = j.kept_in.clone().unwrap_or_else(|| {
            let stamp = format!("backups/before-restore-{}", chrono::Utc::now().format("%Y%m%dT%H%M%SZ"));
            (1..).map(|n| if n == 1 { stamp.clone() } else { format!("{stamp}-{n}") }).find(|name| !data_dir.join(name).exists()).unwrap_or(stamp)
        });
        j.kept_in = Some(kept_in.clone());
        if let Err(e) = write_journal(&journal_path, &j) {
            return ended(outcome, true, format!("The backup could not be restored yet ({e}). The current database was kept, and the restore is tried again at the next start."));
        }
        if let Err(e) = move_into_place(data_dir, &pending_path, &data_dir.join(&kept_in)) {
            if in_use(&e) {
                // most likely the previous process still had the database open: the staged copy
                // waits for the next start
                return ended(outcome, true, format!("The database was still in use ({e}), so the backup was not restored yet. Cyber Hub restores it at the next start; you can cancel that in Settings → Local data."));
            }
            let _ = fs::remove_file(&pending_path);
            let _ = fs::remove_file(&journal_path);
            return ended(outcome, false, format!("The backup could not be restored ({e}). The current database was kept."));
        }
    } else {
        // no staged copy: either it already replaced the database (a folder is in the journal) or
        // nothing was staged (an interrupted stage)
        let Some(kept_in) = j.kept_in.clone() else {
            let _ = fs::remove_file(&journal_path);
            return None;
        };
        let kept = data_dir.join(&kept_in);
        if !data_dir.join(DB_NAME).exists() {
            // the staged copy disappeared before it took the database's place
            put_back(data_dir, &kept);
            let _ = fs::remove_file(&journal_path);
            return ended(outcome, false, format!("The copy waiting to be restored is missing. The current database was put back from {kept_in}."));
        }
    }
    let kept_in = j.kept_in.clone().unwrap_or_default();
    let mut outcome = outcome;
    outcome.kept_in = Some(kept_in.clone());
    Some(Swap { outcome, kept: data_dir.join(kept_in), evidence_from: j.evidence_from.map(PathBuf::from) })
}

/// Moves every file under `kept/evidence` back into the evidence folder (without overwriting).
fn evidence_back(data_dir: &Path, kept: &Path) -> std::io::Result<()> {
    let live = data_dir.join("evidence");
    let Ok(dirs) = fs::read_dir(kept.join("evidence")) else { return Ok(()) };
    for d in dirs.flatten() {
        if !d.file_type().is_ok_and(|t| t.is_dir()) {
            continue;
        }
        for f in fs::read_dir(d.path())?.flatten() {
            let name = f.file_name().to_string_lossy().to_string();
            if !is_sha(&name) || !f.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            let to = blob(&live, &name);
            if !to.exists() {
                fs::create_dir_all(to.parent().unwrap_or(&live))?;
                rename_patiently(&f.path(), &to)?;
            }
        }
    }
    Ok(())
}

/// The restored database did not open: it goes aside next to the previous one, which goes back
/// with its evidence files. Err when the files could not be moved (the error names the folder).
pub fn undo(data_dir: &Path, swap: &mut Swap, error: &AppError) -> AppResult<()> {
    let kept_in = swap.outcome.kept_in.clone().unwrap_or_default();
    let mut problems = Vec::new();
    for name in DB_FILES {
        let from = data_dir.join(name);
        if from.exists() {
            if let Err(e) = rename_patiently(&from, &swap.kept.join(format!("restored-{name}"))) {
                problems.push(format!("{name}: {e}"));
            }
        }
    }
    if problems.is_empty() && !put_back(data_dir, &swap.kept) {
        problems.push("the previous database could not be moved back".into());
    }
    if let Err(e) = evidence_back(data_dir, &swap.kept) {
        problems.push(format!("evidence files: {e}"));
    }
    swap.outcome.ok = false;
    if !problems.is_empty() {
        return Err(AppError::Internal(format!(
            "The restored database could not be opened ({error}), and Cyber Hub could not put the previous database back ({}). The previous database is in {kept_in} in the data folder.",
            problems.join("; ")
        )));
    }
    let _ = fs::remove_file(data_dir.join(JOURNAL));
    swap.outcome.error = Some(format!(
        "The restored database could not be opened ({error}). The previous database and its evidence files were put back; the restored copy is in {kept_in} as restored-{DB_NAME}."
    ));
    Ok(())
}

/// Copies `from` to `to` when its content has the SHA-256 `sha`, through a temporary file.
fn copy_verified(from: &Path, to: &Path, sha: &str) -> AppResult<bool> {
    let parent = to.parent().ok_or_else(|| AppError::Internal("no folder".into()))?;
    fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".{sha}.partial"));
    let ok = (|| -> AppResult<bool> {
        let mut input = fs::File::open(from)?;
        let mut out = fs::File::create(&tmp)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 256 * 1024];
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n])?;
        }
        out.sync_all()?;
        let digest: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        Ok(digest == sha)
    })();
    match ok {
        Ok(true) => {
            fs::rename(&tmp, to)?;
            Ok(true)
        }
        other => {
            let _ = fs::remove_file(&tmp);
            other.map(|_| false)
        }
    }
}

/// Moves a file, copying it when a rename is not possible (another drive).
fn move_file(from: &Path, to: &Path, sha: &str) -> AppResult<()> {
    if let Some(parent) = to.parent() {
        fs::create_dir_all(parent)?;
    }
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    if copy_verified(from, to, sha)? {
        fs::remove_file(from)?;
        Ok(())
    } else {
        Err(AppError::Internal(format!("evidence file {sha} does not match its name")))
    }
}

/// Sorts the evidence files once the restored database has opened, then ends the restore.
pub fn finish(data_dir: &Path, swap: &mut Swap) -> Outcome {
    let result = (|| -> AppResult<(usize, usize)> {
        let refs = {
            let c = Connection::open_with_flags(data_dir.join(DB_NAME), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            evidence_refs(&c)?
        };
        let live = data_dir.join("evidence");
        let mut kept = 0;
        if let Ok(dirs) = fs::read_dir(&live) {
            for d in dirs.flatten() {
                if !d.file_type().is_ok_and(|t| t.is_dir()) || d.file_name() == "incoming" {
                    continue;
                }
                for f in fs::read_dir(d.path())?.flatten() {
                    let name = f.file_name().to_string_lossy().to_string();
                    if !f.file_type().is_ok_and(|t| t.is_file()) {
                        continue;
                    }
                    // a copy interrupted earlier
                    if name.len() == 73 && name.starts_with('.') && name.ends_with(".partial") && is_sha(&name[1..65]) {
                        let _ = fs::remove_file(f.path());
                        continue;
                    }
                    if !is_sha(&name) || refs.contains(&name) {
                        continue;
                    }
                    let to = blob(&swap.kept.join("evidence"), &name);
                    if !to.exists() {
                        move_file(&f.path(), &to, &name)?;
                    }
                    kept += 1;
                }
            }
        }
        let mut restored = 0;
        let same_as_live = |p: &Path| p.canonicalize().ok().map(|p| p.to_string_lossy().to_lowercase()) == live.canonicalize().ok().map(|p| p.to_string_lossy().to_lowercase());
        if let Some(src) = swap.evidence_from.as_deref().filter(|s| s.is_dir() && !same_as_live(s)) {
            for sha in &refs {
                let (from, to) = (blob(src, sha), blob(&live, sha));
                if !to.exists() && usable_evidence(&from) && copy_verified(&from, &to, sha)? {
                    restored += 1;
                }
            }
        }
        Ok((kept, restored))
    })();
    swap.outcome.ok = true;
    match result {
        Ok((kept, restored)) => {
            let _ = fs::remove_file(data_dir.join(JOURNAL));
            swap.outcome.evidence_kept = kept;
            swap.outcome.evidence_restored = restored;
        }
        // the journal stays: the sweep waits, and the next start sorts the rest
        Err(e) => {
            swap.outcome.error = Some(format!("The database was restored, but not every evidence file was sorted yet ({e}). Cyber Hub tries again at the next start and deletes no evidence files until then."));
        }
    }
    swap.outcome.clone()
}

#[cfg(test)]
#[path = "restore_tests.rs"]
mod tests;
