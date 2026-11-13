//! Results of the assessment utilities recorded in a project with their evidence
//! (docs/DATA_MODEL.md#utility-results): the analysed file goes into the evidence vault, the
//! analysis is kept as text evidence derived from it, the findings are linked to the file, and the
//! timeline records what was done. All of it in one transaction, so a half-recorded result never
//! stays behind.
//!
//! The web view never names a file: a utility that analysed a file chosen in a native dialog gets
//! a random token for it, and recording names the token. The file is read again when it is stored
//! and must still have the SHA-256 that was analysed.

use std::collections::{HashMap, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager};

use crate::commands::activity::log;
use crate::commands::projects::{finding_write, FindingInput};
use crate::db::Db;
use crate::error::{validation, AppError, AppResult};
use crate::workspace::evidence::{self, EvidenceStore, Provenance};
use crate::workspace::{relations, timeline};

/// The utilities whose results can be recorded: (module, what it is called, the tool).
pub const MODULES: &[(&str, &str, &str)] = &[
    ("file_triage", "File triage", "ExploitX file triage"),
    ("pcap_triage", "Packet capture triage", "ExploitX packet capture triage"),
    ("log_triage", "Log triage", "ExploitX log triage"),
    ("evtx_triage", "Windows event log triage", "ExploitX Windows event log triage"),
    ("linux_persistence", "Linux persistence triage", "ExploitX Linux persistence triage"),
    ("oauth_review", "OAuth and OpenID Connect review", "ExploitX OAuth and OpenID Connect review"),
];
/// Files remembered for recording (the oldest is forgotten first).
const MAX_PICKED: usize = 32;
const MAX_FINDINGS: usize = 500;

/// A file chosen in a native dialog and analysed.
#[derive(Debug, Clone)]
pub struct PickedFile {
    path: PathBuf,
    file_name: String,
    /// the SHA-256 of the content analysed; None for a file too large for the evidence vault
    sha256: Option<String>,
}

#[derive(Default)]
pub struct PickedFiles(Mutex<VecDeque<(String, PickedFile)>>);

/// Remembers an analysed file so its results can be recorded with it; returns the token the web
/// view gets in place of the path.
pub fn remember(app: &AppHandle, path: &Path, sha256: Option<String>) -> Option<String> {
    let state = app.try_state::<PickedFiles>()?;
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).ok()?;
    let token: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let file_name = evidence::display_name(&path.to_string_lossy());
    let mut q = state.0.lock().ok()?;
    if q.len() >= MAX_PICKED {
        q.pop_front();
    }
    q.push_back((token.clone(), PickedFile { path: path.to_path_buf(), file_name, sha256 }));
    Some(token)
}

fn lookup(app: &AppHandle, token: &str) -> AppResult<PickedFile> {
    let state = app.try_state::<PickedFiles>().ok_or_else(|| AppError::Internal("no picked files".into()))?;
    let q = state.0.lock().map_err(|_| AppError::Internal("picked files poisoned".into()))?;
    q.iter().find(|(t, _)| t == token).map(|(_, p)| p.clone()).ok_or_else(|| validation("The analysed file is no longer known; analyse it again"))
}

/// The file behind a token: its path, the name it is shown by, and the SHA-256 that was analysed.
pub fn picked(app: &AppHandle, token: &str) -> AppResult<(PathBuf, String, Option<String>)> {
    let p = lookup(app, token)?;
    Ok((p.path, p.file_name, p.sha256))
}

/// The SHA-256 of a file that fits the evidence vault, None when it is larger.
pub fn file_sha256(path: &Path) -> AppResult<Option<String>> {
    if std::fs::metadata(path)?.len() > evidence::MAX_FILE {
        return Ok(None);
    }
    let mut f = crate::util::open_regular(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        size += n as u64;
        if size > evidence::MAX_FILE {
            return Ok(None);
        }
        hasher.update(&buf[..n]);
    }
    Ok(Some(hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordInput {
    pub project_id: i64,
    pub module: String,
    /// the analysed file, from the utility's file dialog; none for pasted text or fetched metadata
    #[serde(default)]
    pub token: Option<String>,
    /// what was analysed when there is no file (`pasted log`, an issuer)
    #[serde(default)]
    pub subject: String,
    /// the analysis as JSON, kept as text evidence (derived from the file when there is one)
    #[serde(default)]
    pub report: Option<String>,
    #[serde(default)]
    pub findings: Vec<FindingInput>,
}

#[derive(Debug, Serialize, Default, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Recorded {
    pub created: usize,
    /// findings with the same title recorded before; they are linked to the evidence too
    pub existing: usize,
    pub evidence_id: Option<i64>,
    pub report_id: Option<i64>,
    /// the report was larger than text evidence takes (1 MB) and was not kept
    pub report_too_large: bool,
}

/// Records a utility's result in a project: the analysed file and the analysis as evidence with
/// their provenance, the selected findings linked to it, and a timeline event.
#[tauri::command]
pub async fn utility_record(app: AppHandle, input: RecordInput) -> AppResult<Recorded> {
    let (label, tool) = MODULES.iter().find(|(m, _, _)| *m == input.module).map(|(_, l, t)| (*l, *t)).ok_or_else(|| validation("Unknown utility"))?;
    if input.findings.len() > MAX_FINDINGS {
        return Err(validation(format!("Record at most {MAX_FINDINGS} findings at a time")));
    }
    if input.findings.iter().any(|f| f.project_id != input.project_id || f.id.is_some()) {
        return Err(validation("Only new findings of the chosen project can be recorded"));
    }
    app.state::<Db>().with(|c| relations::require_open(c, input.project_id))?;
    let picked = input.token.as_deref().map(|t| lookup(&app, t)).transpose()?;
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || -> AppResult<Recorded> {
        let db = handle.state::<Db>();
        let store = handle.state::<Arc<EvidenceStore>>();
        let file = match &picked {
            Some(p) => Some((store_file(&db, &store, input.project_id, p, label, tool)?, p.file_name.as_str())),
            None => None,
        };
        let result = db.with(|c| write(c, &input, (label, tool), file));
        if let (Err(_), Some((created, _))) = (&result, file) {
            // nothing was recorded: a file this call added does not stay behind
            if created.1 {
                let _ = store.delete(&db, created.0);
            }
        }
        result
    })
    .await
    .map_err(|e| AppError::Internal(format!("recording failed: {e}")))?
}

/// Copies the analysed file into the evidence vault; (record, whether this call created it).
fn store_file(db: &Db, store: &EvidenceStore, project_id: i64, p: &PickedFile, label: &str, tool: &str) -> AppResult<(i64, bool)> {
    let Some(expected) = &p.sha256 else {
        return Err(validation(format!("{} is larger than the evidence vault takes (256 MB); record the findings without the file", p.file_name)));
    };
    let before: i64 = db.with(|c| Ok(c.query_row("SELECT COALESCE(MAX(id), 0) FROM evidence", [], |r| r.get(0))?))?;
    let rec = store.add_file(db, project_id, &p.path, &format!("{label}: {}", p.file_name), &format!("The file {tool} analysed. SHA-256 {expected}"), "utility")?;
    let created = rec.id > before;
    if rec.sha256.as_deref() != Some(expected.as_str()) {
        if created {
            let _ = store.delete(db, rec.id);
        }
        return Err(validation(format!("{} changed after it was analysed; analyse it again", p.file_name)));
    }
    Ok((rec.id, created))
}

/// The database part of a recording, in one transaction.
fn write(c: &Connection, input: &RecordInput, (label, tool): (&str, &str), file: Option<((i64, bool), &str)>) -> AppResult<Recorded> {
    relations::require_open(c, input.project_id)?;
    let tx = c.unchecked_transaction()?;
    let version = env!("CARGO_PKG_VERSION");
    let file_id = file.map(|((id, _), _)| id);
    let mut out = Recorded { evidence_id: file_id, ..Default::default() };
    let prov = |derived_from: Option<i64>| Provenance { source_module: input.module.clone(), tool: tool.into(), tool_version: version.into(), derived_from, ..Default::default() };
    if let Some(id) = file_id {
        evidence::set_provenance(&tx, id, &prov(None))?;
    }
    let subject: String = match file {
        Some((_, name)) => name.to_string(),
        None => input.subject.trim().chars().take(200).collect(),
    };
    let subject = if subject.is_empty() { label.to_string() } else { subject };
    if let Some(report) = input.report.as_deref().filter(|r| !r.trim().is_empty()) {
        if report.len() > evidence::MAX_TEXT {
            out.report_too_large = true;
        } else {
            // the same analysis recorded again is the record kept the first time
            let sha: String = Sha256::digest(report.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
            let same: Option<i64> = tx
                .query_row("SELECT id FROM evidence WHERE project_id = ?1 AND kind = 'text' AND sha256 = ?2 AND source_module = ?3 ORDER BY id LIMIT 1", params![input.project_id, sha, input.module], |r| r.get(0))
                .optional()?;
            let id = match same {
                Some(id) => id,
                None => {
                    let rec = evidence::add_text(&tx, input.project_id, &format!("{label} report: {subject}"), report, &format!("The analysis by {tool} {version}"), "utility")?;
                    evidence::set_provenance(&tx, rec.id, &prov(file_id))?;
                    rec.id
                }
            };
            out.report_id = Some(id);
        }
    }
    // each title once per project; findings recorded before are linked to the evidence as well
    let mut titles: HashMap<String, i64> = HashMap::new();
    {
        let mut st = tx.prepare("SELECT title, MIN(id) FROM findings WHERE project_id = ?1 GROUP BY title")?;
        for row in st.query_map(params![input.project_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))? {
            let (t, id) = row?;
            titles.insert(t, id);
        }
    }
    let link_to = file_id.or(out.report_id);
    for f in &input.findings {
        let title = f.title.trim().to_string();
        let id = match titles.get(&title) {
            Some(id) => {
                out.existing += 1;
                *id
            }
            None => {
                let id = finding_write(&tx, f, "utility", false)?;
                titles.insert(title, id);
                out.created += 1;
                id
            }
        };
        if let Some(eid) = link_to {
            crate::workspace::findings::link(&tx, id, "evidence", eid, "utility")?;
        }
    }
    let mut what = vec![format!("{} new finding{}", out.created, if out.created == 1 { "" } else { "s" })];
    if out.existing > 0 {
        what.push(format!("{} recorded before", out.existing));
    }
    if let Some(id) = file_id {
        what.push(format!("file kept as evidence #{id}"));
    }
    if let Some(id) = out.report_id {
        what.push(format!("report as evidence #{id}"));
    }
    let what = what.join(", ");
    timeline::record(&tx, input.project_id, "utility", &format!("{label} recorded: {subject}"), &what, link_to.map(|_| "evidence"), link_to)?;
    log(&tx, "finding", &format!("{label} recorded: {subject}"), &what, Some("project"), Some(&input.project_id.to_string()), Some(input.project_id))?;
    tx.commit()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(p: i64, title: &str) -> FindingInput {
        FindingInput { project_id: p, title: title.into(), severity: "high".into(), status: "new".into(), description: "SHA-256 in the file".into(), tags: vec!["file".into(), "T1055".into()], ..Default::default() }
    }

    fn input(p: i64, findings: Vec<FindingInput>, report: Option<&str>) -> RecordInput {
        RecordInput { project_id: p, module: "file_triage".into(), token: None, subject: String::new(), report: report.map(str::to_string), findings }
    }

    #[test]
    fn results_are_recorded_once_with_their_evidence_and_provenance() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('IR', 'active', 't', 't')", [])?;
            let p = c.last_insert_rowid();
            c.execute("INSERT INTO evidence (project_id, kind, title, source, sha256, size, file_name, created_at) VALUES (?1, 'file', 'File triage: drop.exe', 'utility', ?2, 10, 'drop.exe', 't')", params![p, "a".repeat(64)])?;
            let file = c.last_insert_rowid();
            let r = write(c, &input(p, vec![finding(p, "Injects code (drop.exe)"), finding(p, "Injects code (drop.exe)")], Some(r#"{"sha256":"aa"}"#)), ("File triage", "ExploitX file triage"), Some(((file, true), "drop.exe")))?;
            assert_eq!((r.created, r.existing, r.evidence_id), (1, 1, Some(file)), "the same title twice is one finding");
            let report = evidence::get(c, r.report_id.unwrap())?;
            assert_eq!((report.kind.as_str(), report.derived_from, report.source_module.as_str()), ("text", Some(file), "file_triage"));
            let f = evidence::get(c, file)?;
            assert_eq!((f.source_module.as_str(), f.tool.as_str(), f.tool_version.as_str()), ("file_triage", "ExploitX file triage", env!("CARGO_PKG_VERSION")));
            let fid: i64 = c.query_row("SELECT id FROM findings WHERE project_id = ?1", params![p], |r| r.get(0))?;
            assert_eq!(crate::workspace::findings::links(c, fid)?.iter().map(|l| (l.kind.as_str(), l.ref_id)).collect::<Vec<_>>(), vec![("evidence", file)]);
            let source: String = c.query_row("SELECT source FROM findings WHERE id = ?1", params![fid], |r| r.get(0))?;
            assert_eq!(source, "utility");
            let events = timeline::query(c, p, &timeline::Query { types: vec!["utility".into()], ..Default::default() })?;
            assert!(events.iter().any(|e| e.title == "File triage recorded: drop.exe" && e.detail.contains("1 new finding")), "{events:?}");

            // recording again adds nothing new, and a pasted result without a file is linked to its report
            let again = write(c, &input(p, vec![finding(p, "Injects code (drop.exe)")], Some(r#"{"sha256":"aa"}"#)), ("File triage", "ExploitX file triage"), Some(((file, false), "drop.exe")))?;
            assert_eq!((again.created, again.existing, again.report_id), (0, 1, r.report_id), "the same analysis is kept once");
            let mut pasted = input(p, vec![finding(p, "Password spraying")], Some("{}"));
            pasted.module = "log_triage".into();
            pasted.subject = "pasted log".into();
            let r = write(c, &pasted, ("Log triage", "ExploitX log triage"), None)?;
            let fid: i64 = c.query_row("SELECT id FROM findings WHERE title = 'Password spraying'", [], |r| r.get(0))?;
            assert_eq!(crate::workspace::findings::links(c, fid)?.iter().map(|l| l.ref_id).collect::<Vec<_>>(), vec![r.report_id.unwrap()]);
            assert_eq!(evidence::get(c, r.report_id.unwrap())?.derived_from, None);

            // a report too large for text evidence is left out and said so
            let big = "x".repeat(evidence::MAX_TEXT + 1);
            let r = write(c, &input(p, vec![], Some(&big)), ("File triage", "ExploitX file triage"), None)?;
            assert!(r.report_too_large && r.report_id.is_none());

            // archived projects take nothing, and nothing is half-written
            c.execute("UPDATE projects SET status = 'archived' WHERE id = ?1", params![p])?;
            let n: i64 = c.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))?;
            assert!(write(c, &input(p, vec![finding(p, "New one")], None), ("File triage", "ExploitX file triage"), None).is_err());
            assert_eq!(c.query_row("SELECT COUNT(*) FROM findings", [], |r| r.get::<_, i64>(0))?, n);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn a_failing_finding_leaves_nothing_behind() {
        let db = Db::open_in_memory().unwrap();
        db.with(|c| {
            c.execute("INSERT INTO projects (name, status, created_at, updated_at) VALUES ('IR', 'active', 't', 't')", [])?;
            let p = c.last_insert_rowid();
            let mut bad = finding(p, "Bad severity");
            bad.severity = "apocalyptic".into();
            assert!(write(c, &input(p, vec![finding(p, "Fine"), bad], Some("{}")), ("File triage", "ExploitX file triage"), None).is_err());
            for table in ["findings", "evidence", "timeline_events"] {
                assert_eq!(c.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get::<_, i64>(0))?, 0, "{table}");
            }
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn files_are_hashed_only_when_they_fit_the_vault() {
        let dir = std::env::temp_dir().join(format!("cyberhub-utility-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("sample.bin");
        std::fs::write(&f, b"MZ sample").unwrap();
        let expected: String = Sha256::digest(b"MZ sample").iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(file_sha256(&f).unwrap(), Some(expected));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
