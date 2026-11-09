//! Evidence registry: one list of a project's evidence that *references* what already exists
//! (tool runs, OSINT evidence) and stores new files exactly once.
//!
//! Files live in `<app data>/evidence/<first two hex digits>/<sha256>`, named only by their hash:
//! the original name is kept for display and never used as a path, so a malicious file name cannot
//! escape the folder. The same file added twice (to the same or another project) is stored once.
//! Directories are created by Cyber Hub and refused if they are symbolic links.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::util::{clean, now};

/// Largest file accepted as evidence.
pub const MAX_FILE: u64 = 256 * 1024 * 1024;
/// Largest text evidence.
pub const MAX_TEXT: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceRecord {
    pub id: i64,
    pub project_id: i64,
    pub kind: String,
    pub title: String,
    pub description: String,
    pub source: String,
    pub sha256: Option<String>,
    pub size: Option<i64>,
    pub file_name: Option<String>,
    pub execution_id: Option<i64>,
    pub osint_evidence_id: Option<i64>,
    pub created_at: String,
    /// provenance (schema 22): the module that produced it ("scan_import", "file_triage"…), the
    /// record it came from ("scan_import:7"), the tool and its version, and when the source
    /// collected it (empty or None when not known)
    pub source_module: String,
    pub source_ref: String,
    pub tool: String,
    pub tool_version: String,
    pub collected_at: Option<String>,
    /// the evidence this record was derived from (an analysis of another file)
    pub derived_from: Option<i64>,
    /// unverified, intact, damaged or missing: the last integrity check, and when it ran
    pub verification: String,
    pub verified_at: Option<String>,
}

const COLS: &str = "id, project_id, kind, title, description, source, sha256, size, file_name, execution_id, osint_evidence_id, created_at, source_module, source_ref, tool, tool_version, collected_at, derived_from, verification, verified_at";

/// Where an evidence record came from. Fields left empty are not changed.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Provenance {
    pub source_module: String,
    pub source_ref: String,
    pub tool: String,
    pub tool_version: String,
    pub collected_at: Option<String>,
    pub derived_from: Option<i64>,
}

/// Records the provenance of an evidence record. A record that already has provenance keeps it:
/// the same file added again later does not rewrite where it first came from.
pub fn set_provenance(c: &Connection, id: i64, p: &Provenance) -> AppResult<()> {
    let cut = |s: &str, n: usize| s.chars().take(n).collect::<String>();
    c.execute(
        "UPDATE evidence SET source_module = CASE WHEN source_module = '' THEN ?2 ELSE source_module END,
                             source_ref = CASE WHEN source_ref = '' THEN ?3 ELSE source_ref END,
                             tool = CASE WHEN tool = '' THEN ?4 ELSE tool END,
                             tool_version = CASE WHEN tool_version = '' THEN ?5 ELSE tool_version END,
                             collected_at = COALESCE(collected_at, ?6),
                             derived_from = COALESCE(derived_from, ?7)
         WHERE id = ?1",
        params![id, cut(&p.source_module, 60), cut(&p.source_ref, 120), cut(&p.tool, 120), cut(&p.tool_version, 60), p.collected_at, p.derived_from.filter(|d| *d != id)],
    )?;
    Ok(())
}

fn row(r: &rusqlite::Row) -> rusqlite::Result<EvidenceRecord> {
    Ok(EvidenceRecord {
        id: r.get(0)?,
        project_id: r.get(1)?,
        kind: r.get(2)?,
        title: r.get(3)?,
        description: r.get(4)?,
        source: r.get(5)?,
        sha256: r.get(6)?,
        size: r.get(7)?,
        file_name: r.get(8)?,
        execution_id: r.get(9)?,
        osint_evidence_id: r.get(10)?,
        created_at: r.get(11)?,
        source_module: r.get(12)?,
        source_ref: r.get(13)?,
        tool: r.get(14)?,
        tool_version: r.get(15)?,
        collected_at: r.get(16)?,
        derived_from: r.get(17)?,
        verification: r.get(18)?,
        verified_at: r.get(19)?,
    })
}

pub fn get(c: &Connection, id: i64) -> AppResult<EvidenceRecord> {
    c.query_row(&format!("SELECT {COLS} FROM evidence WHERE id = ?1"), params![id], row)
        .optional()?
        .ok_or_else(|| AppError::NotFound(format!("evidence {id}")))
}

pub fn list(c: &Connection, project_id: i64) -> AppResult<Vec<EvidenceRecord>> {
    let mut st = c.prepare(&format!("SELECT {COLS} FROM evidence WHERE project_id = ?1 ORDER BY id DESC"))?;
    let rows = st.query_map(params![project_id], row)?.collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Display name of a file: no directories, no control characters, at most 255 characters.
pub fn display_name(path_or_name: &str) -> String {
    let base = path_or_name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base.chars().filter(|c| !c.is_control()).take(255).collect();
    let cleaned = cleaned.trim().trim_matches('.').to_string();
    if cleaned.is_empty() {
        "file".into()
    } else {
        cleaned
    }
}

fn require_project(c: &Connection, project_id: i64) -> AppResult<()> {
    let ok: Option<i64> = c.query_row("SELECT id FROM projects WHERE id = ?1", params![project_id], |r| r.get(0)).optional()?;
    ok.map(|_| ()).ok_or_else(|| AppError::NotFound(format!("project {project_id}")))
}

/// The content of a text record (lists leave it out: a record can hold 1 MB).
pub fn text_content(c: &Connection, id: i64) -> AppResult<String> {
    let content: Option<Option<String>> = c.query_row("SELECT content FROM evidence WHERE id = ?1 AND kind = 'text'", params![id], |r| r.get(0)).optional()?;
    content.map(Option::unwrap_or_default).ok_or_else(|| AppError::NotFound(format!("text evidence {id}")))
}

pub fn add_text(c: &Connection, project_id: i64, title: &str, content: &str, description: &str, source: &str) -> AppResult<EvidenceRecord> {
    require_project(c, project_id)?;
    let title = clean("Title", title, 200, true)?;
    let description = clean("Description", description, 5000, false)?;
    if content.len() > MAX_TEXT {
        return Err(validation("Text evidence is limited to 1 MB"));
    }
    if content.trim().is_empty() {
        return Err(validation("Text evidence is empty"));
    }
    let sha = hex(&Sha256::digest(content.as_bytes()));
    c.execute(
        "INSERT INTO evidence (project_id, kind, title, description, source, sha256, size, content, created_at) VALUES (?1, 'text', ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![project_id, title, description, source, sha, content.len() as i64, content, now()],
    )?;
    get(c, c.last_insert_rowid())
}

/// References a tool run of the same project (no copy of its output). Without a title, the run's
/// tool and number are the title.
pub fn link_execution(c: &Connection, project_id: i64, execution_id: i64, title: &str) -> AppResult<EvidenceRecord> {
    let owner: Option<(Option<i64>, String)> = c.query_row("SELECT project_id, tool_id FROM executions WHERE id = ?1", params![execution_id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    let tool = match owner {
        None => return Err(AppError::NotFound(format!("run {execution_id}"))),
        Some((p, _)) if p != Some(project_id) => return Err(validation("That run does not belong to this project")),
        Some((_, tool)) => tool,
    };
    if let Some(id) = c.query_row("SELECT id FROM evidence WHERE project_id = ?1 AND kind = 'execution' AND execution_id = ?2", params![project_id, execution_id], |r| r.get(0)).optional()? {
        return get(c, id);
    }
    let title = if title.trim().is_empty() {
        let name = crate::catalog::tool(&tool).map_or(tool.as_str(), |t| t.name.as_str());
        format!("{name} run #{execution_id}")
    } else {
        title.to_string()
    };
    let title = clean("Title", &title, 200, true)?;
    c.execute(
        "INSERT INTO evidence (project_id, kind, title, source, execution_id, created_at) VALUES (?1, 'execution', ?2, 'tool run', ?3, ?4)",
        params![project_id, title, execution_id, now()],
    )?;
    get(c, c.last_insert_rowid())
}

/// References OSINT evidence of an investigation linked to the same project (no copy).
pub fn link_osint(c: &Connection, project_id: i64, osint_evidence_id: i64) -> AppResult<EvidenceRecord> {
    let found: Option<(Option<i64>, String)> = c
        .query_row(
            "SELECT i.project_id, e.summary FROM osint_evidence e JOIN osint_investigations i ON i.id = e.investigation_id WHERE e.id = ?1",
            params![osint_evidence_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((owner, summary)) = found else { return Err(AppError::NotFound(format!("OSINT evidence {osint_evidence_id}"))) };
    if owner != Some(project_id) {
        return Err(validation("That OSINT evidence belongs to an investigation of another project (or of none)"));
    }
    if let Some(id) = c.query_row("SELECT id FROM evidence WHERE project_id = ?1 AND kind = 'osint_evidence' AND osint_evidence_id = ?2", params![project_id, osint_evidence_id], |r| r.get(0)).optional()? {
        return get(c, id);
    }
    let title: String = summary.chars().take(200).collect();
    c.execute(
        "INSERT INTO evidence (project_id, kind, title, source, osint_evidence_id, created_at) VALUES (?1, 'osint_evidence', ?2, 'OSINT', ?3, ?4)",
        params![project_id, if title.trim().is_empty() { "OSINT evidence".to_string() } else { title }, osint_evidence_id, now()],
    )?;
    get(c, c.last_insert_rowid())
}

/* ───────────────────────── file storage ───────────────────────── */

pub struct EvidenceStore {
    root: PathBuf,
}

/// An evidence record whose stored copy does not match what was recorded.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IntegrityProblem {
    pub id: i64,
    pub title: String,
    pub problem: String,
}

/// The result of checking a project's evidence.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrityReport {
    /// stored files and text records checked
    pub checked: usize,
    /// references (tool runs, OSINT evidence), which hold no copy to check
    pub references: usize,
    pub problems: Vec<IntegrityProblem>,
}

/// SHA-256 and size of a file, read in pieces.
fn hash_file(path: &Path) -> std::io::Result<(String, u64)> {
    let mut input = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut size: u64 = 0;
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hasher.update(&buf[..n]);
    }
    Ok((hex(&hasher.finalize()), size))
}

/// Why a stored text no longer matches its record, if it does not.
fn text_problem(content: Option<&str>, sha: Option<&str>, size: Option<i64>) -> Option<String> {
    let content = content.unwrap_or("");
    let actual = hex(&Sha256::digest(content.as_bytes()));
    match sha {
        None => Some("no SHA-256 was recorded".into()),
        Some(s) if s != actual => Some(format!("the text's SHA-256 is now {actual}, not the recorded {s}")),
        _ if size.is_some_and(|n| n != content.len() as i64) => Some(format!("the text is now {} bytes, not the recorded {}", content.len(), size.unwrap_or(0))),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Creates `dir` (and parents) and refuses it if any created component is a symbolic link.
fn safe_dir(dir: &Path) -> AppResult<()> {
    fs::create_dir_all(dir)?;
    let meta = fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(AppError::Internal(format!("{} is not a plain folder", dir.display())));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

impl EvidenceStore {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn blob(&self, sha: &str) -> PathBuf {
        self.root.join(&sha[..2]).join(sha)
    }

    /// Path of a stored file, for reading it back (export, report attachments).
    pub fn file_path(&self, record: &EvidenceRecord) -> Option<PathBuf> {
        let sha = record.sha256.as_deref()?;
        (record.kind == "file" && sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit())).then(|| self.blob(sha))
    }

    /// Why a file record's stored copy does not match it (missing, unreadable, other SHA-256 or
    /// size), if it does not.
    pub fn file_problem(&self, record: &EvidenceRecord) -> Option<String> {
        let Some(path) = self.file_path(record) else { return Some("the record has no valid SHA-256".into()) };
        match hash_file(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some("the stored file is missing from the evidence folder".into()),
            Err(e) => Some(format!("the stored file cannot be read: {e}")),
            Ok((sha, _)) if Some(sha.as_str()) != record.sha256.as_deref() => Some(format!("the stored file's SHA-256 is now {sha}, not the recorded {}", record.sha256.as_deref().unwrap_or(""))),
            Ok((_, size)) if record.size.is_some_and(|n| n != size as i64) => Some(format!("the stored file is now {size} bytes, not the recorded {}", record.size.unwrap_or(0))),
            Ok(_) => None,
        }
    }

    /// Checks every evidence record of a project: stored files against their SHA-256 and size, text
    /// against the SHA-256 recorded when it was added. The result is recorded on the timeline.
    pub fn verify_project(&self, db: &Db, project_id: i64) -> AppResult<IntegrityReport> {
        let (records, texts) = db.with(|c| {
            require_project(c, project_id)?;
            let mut st = c.prepare("SELECT id, content, sha256, size FROM evidence WHERE project_id = ?1 AND kind = 'text'")?;
            let texts = st.query_map(params![project_id], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, Option<String>>(2)?, r.get::<_, Option<i64>>(3)?)))?.collect::<Result<Vec<_>, _>>()?;
            Ok((list(c, project_id)?, texts))
        })?;
        let mut report = IntegrityReport { checked: 0, references: 0, problems: Vec::new() };
        let title = |id: i64| records.iter().find(|r| r.id == id).map(|r| r.title.clone()).unwrap_or_default();
        for r in &records {
            match r.kind.as_str() {
                "file" => {
                    report.checked += 1;
                    if let Some(problem) = self.file_problem(r) {
                        report.problems.push(IntegrityProblem { id: r.id, title: r.title.clone(), problem });
                    }
                }
                "text" => {}
                _ => report.references += 1,
            }
        }
        for (id, content, sha, size) in texts {
            report.checked += 1;
            if let Some(problem) = text_problem(content.as_deref(), sha.as_deref(), size) {
                report.problems.push(IntegrityProblem { id, title: title(id), problem });
            }
        }
        report.problems.sort_by_key(|p| p.id);
        // each stored record keeps the result of its last check
        db.with(|c| {
            let ts = now();
            let tx = c.unchecked_transaction()?;
            for r in records.iter().filter(|r| r.kind == "file" || r.kind == "text") {
                let state = match report.problems.iter().find(|p| p.id == r.id) {
                    None => "intact",
                    Some(p) if p.problem.contains("missing") => "missing",
                    Some(_) => "damaged",
                };
                tx.execute("UPDATE evidence SET verification = ?2, verified_at = ?3 WHERE id = ?1", params![r.id, state, ts])?;
            }
            tx.commit()?;
            Ok(())
        })?;
        let summary = if report.problems.is_empty() {
            format!("{} stored records match their SHA-256", report.checked)
        } else {
            format!("{} of {} stored records do not match: {}", report.problems.len(), report.checked, report.problems.iter().take(10).map(|p| format!("#{} {}", p.id, p.problem)).collect::<Vec<_>>().join("; "))
        };
        db.with(|c| crate::workspace::timeline::record(c, project_id, "evidence", "Evidence verified", &summary, None, None))?;
        Ok(report)
    }

    /// Copies a stored file to `dest`, checking its SHA-256 on the way: a copy that does not match
    /// the record is removed and refused.
    pub fn export_file(&self, record: &EvidenceRecord, dest: &Path) -> AppResult<()> {
        let src = self.file_path(record).ok_or_else(|| validation("Only file evidence can be saved as a file"))?;
        let mut input = File::open(&src).map_err(|e| if e.kind() == std::io::ErrorKind::NotFound { AppError::NotFound("The stored file is missing from the evidence folder".into()) } else { e.into() })?;
        let partial = dest.with_file_name(format!("{}.partial", dest.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "evidence".into())));
        let copied = (|| -> AppResult<String> {
            let mut out = File::create(&partial)?;
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
            Ok(hex(&hasher.finalize()))
        })();
        match copied {
            Ok(sha) if Some(sha.as_str()) == record.sha256.as_deref() => {
                fs::rename(&partial, dest)?;
                Ok(())
            }
            Ok(sha) => {
                let _ = fs::remove_file(&partial);
                Err(AppError::Validation(format!(
                    "The stored file no longer matches its record (SHA-256 {sha}, recorded {}), so it was not saved. Check the evidence folder and the project's evidence (Verify).",
                    record.sha256.as_deref().unwrap_or("")
                )))
            }
            Err(e) => {
                let _ = fs::remove_file(&partial);
                Err(e)
            }
        }
    }

    /// Copies a user-chosen file into the store (hashing while copying) and registers it.
    /// The same file added again to the same project returns the existing record.
    pub fn add_file(&self, db: &Db, project_id: i64, src: &Path, title: &str, description: &str, source: &str) -> AppResult<EvidenceRecord> {
        db.with(|c| require_project(c, project_id))?;
        let meta = fs::metadata(src)?;
        if !meta.is_file() {
            return Err(validation("Only regular files can be added as evidence"));
        }
        if meta.len() > MAX_FILE {
            return Err(validation("Evidence files are limited to 256 MB"));
        }
        let title = clean("Title", title, 200, true)?;
        let description = clean("Description", description, 5000, false)?;
        let name = display_name(&src.to_string_lossy());

        safe_dir(&self.root)?;
        let tmp_dir = self.root.join("incoming");
        safe_dir(&tmp_dir)?;
        let mut nonce = [0u8; 8];
        let _ = getrandom::fill(&mut nonce);
        let tmp = tmp_dir.join(format!("{}-{}", std::process::id(), hex(&nonce)));
        let (sha, size) = {
            let mut input = File::open(src)?;
            let mut out = File::create(&tmp)?;
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; 256 * 1024];
            let mut size: u64 = 0;
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                size += n as u64;
                if size > MAX_FILE {
                    drop(out);
                    let _ = fs::remove_file(&tmp);
                    return Err(validation("Evidence files are limited to 256 MB (the file grew while it was read)"));
                }
                hasher.update(&buf[..n]);
                out.write_all(&buf[..n])?;
            }
            out.sync_all()?;
            (hex(&hasher.finalize()), size)
        };
        self.register(db, project_id, &tmp, (&sha, size), (&name, &title, &description), source)
    }

    /// Stores bytes held in memory (an imported scan file) as file evidence, like [`Self::add_file`].
    pub fn add_bytes(&self, db: &Db, project_id: i64, file_name: &str, bytes: &[u8], (title, description): (&str, &str), source: &str) -> AppResult<EvidenceRecord> {
        db.with(|c| require_project(c, project_id))?;
        if bytes.len() as u64 > MAX_FILE {
            return Err(validation("Evidence files are limited to 256 MB"));
        }
        let title = clean("Title", title, 200, true)?;
        let description = clean("Description", description, 5000, false)?;
        let name = display_name(file_name);
        safe_dir(&self.root)?;
        let tmp_dir = self.root.join("incoming");
        safe_dir(&tmp_dir)?;
        let mut nonce = [0u8; 8];
        let _ = getrandom::fill(&mut nonce);
        let tmp = tmp_dir.join(format!("{}-{}", std::process::id(), hex(&nonce)));
        let sha = hex(&Sha256::digest(bytes));
        let written = (|| -> AppResult<()> {
            let mut out = File::create(&tmp)?;
            out.write_all(bytes)?;
            out.sync_all()?;
            Ok(())
        })();
        if let Err(e) = written {
            let _ = fs::remove_file(&tmp);
            return Err(e);
        }
        self.register(db, project_id, &tmp, (&sha, bytes.len() as u64), (&name, &title, &description), source)
    }

    /// Moves a hashed temporary file to its place in the store and registers it (the same content
    /// in the same project returns the existing record).
    fn register(&self, db: &Db, project_id: i64, tmp: &Path, (sha, size): (&str, u64), (name, title, description): (&str, &str, &str), source: &str) -> AppResult<EvidenceRecord> {
        let sha = sha.to_string();
        let dest = self.blob(&sha);
        // the file is placed and registered under the database lock, so a deletion of the same
        // content cannot remove it in between
        db.with(|c| {
            let placed = (|| -> AppResult<()> {
                safe_dir(dest.parent().expect("blob has a parent"))?;
                if dest.exists() {
                    fs::remove_file(tmp)?;
                } else {
                    fs::rename(tmp, &dest)?;
                }
                Ok(())
            })();
            if let Err(e) = placed {
                let _ = fs::remove_file(tmp);
                return Err(e);
            }
            if let Some(id) = c.query_row("SELECT id FROM evidence WHERE project_id = ?1 AND kind = 'file' AND sha256 = ?2", params![project_id, sha], |r| r.get(0)).optional()? {
                return get(c, id);
            }
            c.execute(
                "INSERT INTO evidence (project_id, kind, title, description, source, sha256, size, file_name, created_at) VALUES (?1, 'file', ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![project_id, title, description, source, sha, size as i64, name, now()],
            )?;
            get(c, c.last_insert_rowid())
        })
    }

    /// Deletes an evidence record; a stored file is removed once no record refers to it.
    /// Referenced runs and OSINT evidence are never touched.
    pub fn delete(&self, db: &Db, id: i64) -> AppResult<()> {
        db.with(|c| {
            let rec = get(c, id)?;
            let tx = c.unchecked_transaction()?;
            tx.execute("DELETE FROM finding_links WHERE kind = 'evidence' AND ref_id = ?1", params![id])?;
            tx.execute("DELETE FROM evidence WHERE id = ?1", params![id])?;
            let still_used: i64 = match rec.sha256.as_deref() {
                Some(sha) if rec.kind == "file" => tx.query_row("SELECT COUNT(*) FROM evidence WHERE kind = 'file' AND sha256 = ?1", params![sha], |r| r.get(0))?,
                _ => 1,
            };
            crate::workspace::timeline::record(&tx, rec.project_id, "evidence", &format!("Evidence removed: {}", rec.title), &rec.kind, None, None)?;
            tx.commit()?;
            // still under the database lock: a new record of the same content cannot be placed in
            // between and lose its file
            if let (0, Some(p)) = (still_used, self.file_path(&rec)) {
                let _ = fs::remove_file(p);
            }
            Ok(())
        })
    }

    /// Removes a stored file when no evidence record refers to it (after its project was deleted).
    /// Called with the database lock held, like [`Self::delete`].
    pub fn remove_unreferenced(&self, c: &Connection, sha: &str) {
        if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
            return;
        }
        let used: i64 = c.query_row("SELECT COUNT(*) FROM evidence WHERE kind = 'file' AND sha256 = ?1", params![sha], |r| r.get(0)).unwrap_or(1);
        if used == 0 {
            let _ = fs::remove_file(self.blob(sha));
        }
    }

    /// Removes files in the store that no record refers to (after a crash between copy and insert).
    pub fn sweep(&self, db: &Db) -> AppResult<usize> {
        let _ = fs::remove_dir_all(self.root.join("incoming"));
        let known: std::collections::HashSet<String> = db.with(|c| {
            let mut st = c.prepare("SELECT DISTINCT sha256 FROM evidence WHERE kind = 'file' AND sha256 IS NOT NULL")?;
            let v = st.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<_, _>>()?;
            Ok(v)
        })?;
        let mut removed = 0;
        let Ok(dirs) = fs::read_dir(&self.root) else { return Ok(0) };
        for d in dirs.flatten() {
            if !d.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            for f in fs::read_dir(d.path())?.flatten() {
                let name = f.file_name().to_string_lossy().to_string();
                if f.file_type().is_ok_and(|t| t.is_file()) && name.len() == 64 && !known.contains(&name) && fs::remove_file(f.path()).is_ok() {
                    removed += 1;
                }
            }
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cyberhub-evidence-{tag}-{}-{}", std::process::id(), now().replace(':', "")));
        fs::create_dir_all(&d).unwrap();
        d
    }
    fn project(db: &Db) -> i64 {
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('P', 'active', 't', 't')", [])?;
            Ok(c.last_insert_rowid())
        })
        .unwrap()
    }

    #[test]
    fn files_are_stored_once_by_hash_and_names_never_become_paths() {
        let dir = tmpdir("store");
        let store = EvidenceStore::new(dir.join("evidence"));
        let db = Db::open_in_memory().unwrap();
        let (p1, p2) = (project(&db), project(&db));
        let src = dir.join("..\\..\\evil name.txt".replace('\\', "_"));
        fs::write(&src, b"proof").unwrap();
        let a = store.add_file(&db, p1, &src, "Screenshot", "", "user").unwrap();
        assert_eq!(a.sha256.as_deref(), Some(hex(&Sha256::digest(b"proof")).as_str()));
        assert_eq!((a.size, a.file_name.as_deref()), (Some(5), Some(".._.._evil name.txt".trim_matches('.'))));
        let blob = store.file_path(&a).unwrap();
        assert!(blob.starts_with(dir.join("evidence")));
        assert_eq!(fs::read(&blob).unwrap(), b"proof");
        // same project, same content: same record; another project: new record, same file
        assert_eq!(store.add_file(&db, p1, &src, "Again", "", "user").unwrap().id, a.id);
        let b = store.add_file(&db, p2, &src, "Shared", "", "user").unwrap();
        assert_ne!(b.id, a.id);
        assert_eq!(store.file_path(&b), store.file_path(&a));
        // deleting one reference keeps the file, deleting the last removes it
        store.delete(&db, a.id).unwrap();
        assert!(blob.exists());
        store.delete(&db, b.id).unwrap();
        assert!(!blob.exists());
        assert_eq!(display_name("C:\\Users\\x\\..\\a\u{0}b.png"), "ab.png");
        assert_eq!(display_name("/etc/../.."), "file");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_evidence_is_refused() {
        let dir = tmpdir("invalid");
        let store = EvidenceStore::new(dir.join("evidence"));
        let db = Db::open_in_memory().unwrap();
        let p = project(&db);
        assert!(store.add_file(&db, p, &dir, "A folder", "", "user").is_err(), "folders are not files");
        assert!(store.add_file(&db, 999, &dir.join("x"), "No project", "", "user").is_err());
        db.with(|c| {
            assert!(add_text(c, p, "Empty", "  ", "", "user").is_err());
            assert!(add_text(c, p, "Huge", &"x".repeat(MAX_TEXT + 1), "", "user").is_err());
            assert!(add_text(c, p, "", "content", "", "user").is_err());
            let t = add_text(c, p, "Banner", "Server: nginx", "", "user")?;
            assert_eq!(t.kind, "text");
            Ok(())
        })
        .unwrap();
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn references_stay_within_their_project_and_are_not_duplicated() {
        let db = Db::open_in_memory().unwrap();
        let (p1, p2) = (project(&db), project(&db));
        db.with(|c| {
            c.execute("INSERT INTO executions (tool_id, kind, program, args, project_id, status, started_at) VALUES ('nmap','run','nmap','[]',?1,'succeeded','t')", params![p1])?;
            let run = c.last_insert_rowid();
            let e = link_execution(c, p1, run, "Nmap run")?;
            assert_eq!(link_execution(c, p1, run, "Nmap run again")?.id, e.id, "the same run is referenced once");
            assert!(link_execution(c, p2, run, "Other project").is_err());
            assert!(link_execution(c, p1, 4242, "Missing").is_err());
            // without a title (as the Evidence tab adds a run), the tool and run number name it
            c.execute("INSERT INTO executions (tool_id, kind, program, args, project_id, status, started_at) VALUES ('nmap','run','nmap','[]',?1,'succeeded','t')", params![p1])?;
            let untitled = c.last_insert_rowid();
            assert_eq!(link_execution(c, p1, untitled, "  ")?.title, format!("Nmap run #{untitled}"));
            c.execute("INSERT INTO osint_investigations (name, target_type, target_value, project_id, created_at, updated_at) VALUES ('I','domain','example.com',?1,'t','t')", params![p1])?;
            let inv = c.last_insert_rowid();
            c.execute("INSERT INTO osint_evidence (investigation_id, kind, source, observed_at, collected_at, summary, strength, fingerprint) VALUES (?1,'dns','DNS','t','t','A record','direct','fp')", params![inv])?;
            let ev = c.last_insert_rowid();
            assert_eq!(link_osint(c, p1, ev)?.title, "A record");
            assert!(link_osint(c, p2, ev).is_err());
            Ok(())
        })
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_store_folder_is_refused() {
        let dir = tmpdir("symlink");
        let elsewhere = dir.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.join("evidence")).unwrap();
        let store = EvidenceStore::new(dir.join("evidence"));
        let db = Db::open_in_memory().unwrap();
        let p = project(&db);
        let src = dir.join("f.txt");
        fs::write(&src, b"x").unwrap();
        assert!(store.add_file(&db, p, &src, "F", "", "user").is_err());
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 0, "nothing was written through the link");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn orphaned_files_are_swept() {
        let dir = tmpdir("sweep");
        let store = EvidenceStore::new(dir.join("evidence"));
        let db = Db::open_in_memory().unwrap();
        let p = project(&db);
        let src = dir.join("f.txt");
        fs::write(&src, b"kept").unwrap();
        store.add_file(&db, p, &src, "F", "", "user").unwrap();
        let orphan = dir.join("evidence").join("ab").join("ab".repeat(32));
        fs::create_dir_all(orphan.parent().unwrap()).unwrap();
        fs::write(&orphan, b"orphan").unwrap();
        assert_eq!(store.sweep(&db).unwrap(), 1);
        assert!(!orphan.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn stored_evidence_is_verified_against_its_sha256() {
        let dir = tmpdir("verify");
        let store = EvidenceStore::new(dir.join("evidence"));
        let db = Db::open_in_memory().unwrap();
        let p = project(&db);
        let (a_src, b_src) = (dir.join("a.txt"), dir.join("b.txt"));
        fs::write(&a_src, b"request and response").unwrap();
        fs::write(&b_src, b"screenshot bytes").unwrap();
        let a = store.add_file(&db, p, &a_src, "Request", "", "user").unwrap();
        let b = store.add_file(&db, p, &b_src, "Screenshot", "", "user").unwrap();
        let note = db.with(|c| add_text(c, p, "Banner", "Server: nginx", "", "user")).unwrap();
        db.with(|c| {
            c.execute("INSERT INTO executions (tool_id, kind, program, args, project_id, status, started_at) VALUES ('nmap','run','nmap','[]',?1,'succeeded','t')", params![p])?;
            link_execution(c, p, c.last_insert_rowid(), "")
        })
        .unwrap();
        let ok = store.verify_project(&db, p).unwrap();
        assert_eq!((ok.checked, ok.references, ok.problems.len()), (3, 1, 0));
        // an exported copy is the stored file, checked on the way
        let out = dir.join("out").join("request.txt");
        fs::create_dir_all(out.parent().unwrap()).unwrap();
        store.export_file(&a, &out).unwrap();
        assert_eq!(fs::read(&out).unwrap(), b"request and response");
        // a changed file, a missing file and changed text are each reported
        fs::write(store.file_path(&a).unwrap(), b"request and responsE").unwrap();
        fs::remove_file(store.file_path(&b).unwrap()).unwrap();
        db.with(|c| Ok(c.execute("UPDATE evidence SET content = 'Server: apache' WHERE id = ?1", params![note.id])?)).unwrap();
        let bad = store.verify_project(&db, p).unwrap();
        let problems: Vec<(i64, bool)> = bad.problems.iter().map(|x| (x.id, x.problem.contains("SHA-256") || x.problem.contains("missing"))).collect();
        assert_eq!(problems, vec![(a.id, true), (b.id, true), (note.id, true)], "{:?}", bad.problems);
        assert!(bad.problems[1].problem.contains("missing"));
        // a changed file is not exported, and no partial copy is left
        let refused = dir.join("out").join("changed.txt");
        let err = store.export_file(&a, &refused).unwrap_err().to_string();
        assert!(err.contains("no longer matches"), "{err}");
        assert!(!refused.exists() && fs::read_dir(dir.join("out")).unwrap().count() == 1);
        let noted: i64 = db.with(|c| Ok(c.query_row("SELECT COUNT(*) FROM timeline_events WHERE project_id = ?1 AND title = 'Evidence verified'", params![p], |r| r.get(0))?)).unwrap();
        assert_eq!(noted, 2, "each check is on the timeline");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn provenance_is_kept_and_each_check_is_recorded() {
        let dir = tmpdir("provenance");
        let store = EvidenceStore::new(dir.join("evidence"));
        let db = Db::open_in_memory().unwrap();
        let p = project(&db);
        let src = dir.join("scan.nessus");
        fs::write(&src, b"<NessusClientData_v2/>").unwrap();
        let rec = store.add_file(&db, p, &src, "Scan", "", "import").unwrap();
        assert_eq!((rec.source_module.as_str(), rec.verification.as_str(), rec.collected_at.as_deref()), ("", "unverified", None));
        db.with(|c| {
            // the text of a text record is read on its own; a file record has none
            let note = add_text(c, p, "Request", "GET / HTTP/1.1", "", "user")?;
            assert_eq!(text_content(c, note.id)?, "GET / HTTP/1.1");
            assert!(matches!(text_content(c, rec.id), Err(AppError::NotFound(_))));
            Ok(())
        })
        .unwrap();
        db.with(|c| {
            let first = Provenance { source_module: "scan_import".into(), source_ref: "scan_import:1".into(), tool: "Nessus".into(), collected_at: Some("2026-11-01T08:00:00Z".into()), derived_from: Some(rec.id), ..Default::default() };
            set_provenance(c, rec.id, &first)?;
            // the same file imported again later keeps where it first came from
            set_provenance(c, rec.id, &Provenance { source_module: "scan_import".into(), source_ref: "scan_import:2".into(), tool: "Other".into(), ..Default::default() })?;
            let r = get(c, rec.id)?;
            assert_eq!((r.source_ref.as_str(), r.tool.as_str(), r.collected_at.as_deref()), ("scan_import:1", "Nessus", Some("2026-11-01T08:00:00Z")));
            assert_eq!(r.derived_from, None, "a record is never derived from itself");
            Ok(())
        })
        .unwrap();
        store.verify_project(&db, p).unwrap();
        let r = db.with(|c| get(c, rec.id)).unwrap();
        assert_eq!(r.verification, "intact");
        assert!(r.verified_at.is_some());
        fs::remove_file(store.file_path(&r).unwrap()).unwrap();
        store.verify_project(&db, p).unwrap();
        assert_eq!(db.with(|c| get(c, rec.id)).unwrap().verification, "missing");
        let _ = fs::remove_dir_all(&dir);
    }
}
