//! Detection engineering commands (`workspace/detections.rs`, `detection/`): the rule library,
//! import and export through native dialogs, test samples kept by content hash in the app's data
//! folder, tests and regression re-tests, and runs over a project's evidence. Nothing here
//! contacts a network or executes rule or sample content.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::params;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};

use crate::commands::workspace::main_window_dialog;
use crate::db::Db;
use crate::detection::events::{self, Sample};
use crate::detection::sigma;
use crate::error::{validation, AppError, AppResult};
use crate::workspace::detections::{self as lib, Imported, RunResult, SampleRow, TestRow};
use crate::workspace::evidence::EvidenceStore;
use crate::workspace::{relations, timeline};

const MAX_IMPORT_FILES: usize = 500;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> AppResult<T> + Send + 'static) -> AppResult<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| AppError::Internal(format!("the task failed: {e}")))?
}

/// The Sigma engine: specification version, supported modifiers, mapped log sources.
#[tauri::command]
pub async fn detection_engine() -> AppResult<serde_json::Value> {
    Ok(sigma::capabilities())
}

/// Saves the detection library's ATT&CK coverage as a Navigator layer through a native dialog.
#[tauri::command]
pub async fn attack_coverage_export(app: AppHandle, project_id: i64) -> AppResult<Option<String>> {
    let content = app.state::<Db>().with(|c| {
        let m = crate::workspace::attack_matrix::matrix(c, project_id)?;
        crate::workspace::attack_matrix::export_coverage_layer(&crate::util::now(), &m).map_err(validation)
    })?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Export detection coverage").set_file_name("cyberhub-detection-coverage.json").add_filter("ATT&CK Navigator layer", &["json"]).save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, content).map_err(|e| AppError::Internal(format!("Could not write the layer: {e}")))?;
    Ok(path.file_name().map(|n| n.to_string_lossy().to_string()))
}

#[tauri::command]
pub async fn detection_rules_list(db: State<'_, Db>, filter: Option<lib::ListFilter>) -> AppResult<lib::Page> {
    db.with(|c| lib::list(c, &filter.unwrap_or_default()))
}

#[tauri::command]
pub async fn detection_rule_get(db: State<'_, Db>, id: i64) -> AppResult<lib::RuleDetail> {
    db.with(|c| lib::get(c, id))
}

#[tauri::command]
pub async fn detection_rule_version(db: State<'_, Db>, id: i64, version: i64) -> AppResult<String> {
    db.with(|c| lib::version_content(c, id, version))
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub imported: Vec<Imported>,
    /// files or documents that could not be read: (name, why)
    pub failed: Vec<(String, String)>,
}

/// Stores every rule of a Sigma file (one per YAML document).
fn import_sigma(c: &rusqlite::Connection, name: &str, text: &str, note: &str, report: &mut ImportReport) {
    let docs = lib::documents(text);
    if docs.is_empty() {
        report.failed.push((name.into(), "The file holds no rule".into()));
    }
    for (i, doc) in docs.iter().enumerate() {
        let label = if docs.len() > 1 { format!("{name} (document {})", i + 1) } else { name.to_string() };
        match sigma::read(doc) {
            Ok(mut v) if v.len() == 1 => {
                let checked = v.remove(0);
                match lib::upsert_sigma(c, doc, &checked, name, note) {
                    Ok(r) => report.imported.push(r),
                    Err(e) => report.failed.push((label, e.to_string())),
                }
            }
            Ok(_) => report.failed.push((label, "A document holds one rule".into())),
            Err(e) => report.failed.push((label, e)),
        }
    }
}

/// Imports Sigma rule files chosen in a native dialog; a rule already in the library (same id)
/// gets a new version when its content changed.
#[tauri::command]
pub async fn detection_rules_import(app: AppHandle) -> AppResult<Option<ImportReport>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Import detection rules").add_filter("Sigma rules", &["yml", "yaml"]).add_filter("All files", &["*"]).pick_files(move |f| {
        let _ = tx.send(f.map(|v| v.into_iter().filter_map(|p| p.into_path().ok()).collect::<Vec<PathBuf>>()));
    });
    let Some(paths) = rx.await.ok().flatten() else { return Ok(None) };
    if paths.len() > MAX_IMPORT_FILES {
        return Err(validation(format!("Import at most {MAX_IMPORT_FILES} files at a time")));
    }
    let handle = app.clone();
    blocking(move || {
        let db = handle.state::<Db>();
        let mut report = ImportReport::default();
        for p in paths {
            let name = crate::workspace::evidence::display_name(&p.to_string_lossy());
            let text = match read_limited(&p, sigma::MAX_RULE_BYTES as u64) {
                Ok(t) => t,
                Err(e) => {
                    report.failed.push((name, e.to_string()));
                    continue;
                }
            };
            db.with(|c| {
                import_sigma(c, &name, &text, "", &mut report);
                Ok(())
            })?;
        }
        let added = report.imported.iter().filter(|r| r.outcome == "added").count();
        let updated = report.imported.iter().filter(|r| r.outcome == "updated").count();
        let _ = db.with(|c| crate::commands::activity::log(c, "import", "Detection rules imported", &format!("{added} added, {updated} new versions, {} not read", report.failed.len()), None, None, None));
        Ok(Some(report))
    })
    .await
}

fn read_limited(p: &Path, max: u64) -> AppResult<String> {
    let meta = std::fs::metadata(p)?;
    if !meta.is_file() {
        return Err(validation("Choose a file"));
    }
    if meta.len() > max {
        return Err(validation(format!("The file is larger than {} KB", max / 1024)));
    }
    let mut s = String::new();
    std::fs::File::open(p)?.take(max).read_to_string(&mut s).map_err(|_| validation("The file is not UTF-8 text"))?;
    Ok(s)
}

/// Adds rules written or edited in the app (a rule with an existing id becomes its new version).
#[tauri::command]
pub async fn detection_rule_save(db: State<'_, Db>, content: String, note: Option<String>) -> AppResult<ImportReport> {
    if content.len() > sigma::MAX_RULE_BYTES {
        return Err(validation("The rule is too large"));
    }
    db.with(|c| {
        let mut report = ImportReport::default();
        import_sigma(c, "written in Cyber Hub", &content, note.as_deref().unwrap_or("Edited in Cyber Hub"), &mut report);
        Ok(report)
    })
}

#[tauri::command]
pub async fn detection_rule_set_enabled(db: State<'_, Db>, id: i64, enabled: bool) -> AppResult<()> {
    db.with(|c| lib::set_enabled(c, id, enabled))
}

#[tauri::command]
pub async fn detection_rule_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| lib::delete(c, id))
}

#[tauri::command]
pub async fn detection_collections(db: State<'_, Db>) -> AppResult<Vec<lib::Collection>> {
    db.with(lib::collections)
}

#[tauri::command]
pub async fn detection_collection_create(db: State<'_, Db>, name: String, description: Option<String>) -> AppResult<i64> {
    db.with(|c| lib::collection_create(c, &name, description.as_deref().unwrap_or("")))
}

#[tauri::command]
pub async fn detection_collection_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| lib::collection_delete(c, id))
}

#[tauri::command]
pub async fn detection_collection_member(db: State<'_, Db>, collection_id: i64, rule_id: i64, member: bool) -> AppResult<()> {
    db.with(|c| lib::collection_member(c, collection_id, rule_id, member))
}

/* ───────────────────────── samples and tests ───────────────────────── */

fn samples_dir(app: &AppHandle) -> AppResult<PathBuf> {
    let dir = crate::util::data_dir(app).map_err(|e| AppError::Internal(e.to_string()))?.join("detection-samples");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Copies a file into the sample store under its SHA-256 (hashed while copying, size-limited).
fn store_sample(dir: &Path, src: &Path) -> AppResult<(String, u64)> {
    let meta = std::fs::metadata(src)?;
    if !meta.is_file() || meta.len() > events::MAX_BYTES {
        return Err(validation(format!("Choose a file of at most {} MB", events::MAX_BYTES / 1024 / 1024)));
    }
    let mut nonce = [0u8; 8];
    let _ = getrandom::fill(&mut nonce);
    let tmp = dir.join(format!("incoming-{}", nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()));
    let copied = (|| -> AppResult<(String, u64)> {
        let mut input = std::fs::File::open(src)?;
        let mut out = std::fs::File::create(&tmp)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 256 * 1024];
        let mut size = 0u64;
        loop {
            let n = input.read(&mut buf)?;
            if n == 0 {
                break;
            }
            size += n as u64;
            if size > events::MAX_BYTES {
                return Err(validation("The file grew past the size limit while it was read"));
            }
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n])?;
        }
        out.sync_all()?;
        Ok((hasher.finalize().iter().map(|b| format!("{b:02x}")).collect(), size))
    })();
    let (sha, size) = match copied {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
    };
    let dest = dir.join(&sha);
    if dest.exists() {
        std::fs::remove_file(&tmp)?;
    } else {
        std::fs::rename(&tmp, &dest)?;
    }
    Ok((sha, size))
}

fn read_sample(path: &Path) -> AppResult<Sample> {
    events::read(std::io::BufReader::with_capacity(1 << 20, std::fs::File::open(path)?)).map_err(validation)
}

fn kind_name(k: events::Kind) -> &'static str {
    match k {
        events::Kind::Evtx => "evtx",
        events::Kind::Json => "json",
        events::Kind::Text => "text",
    }
}

#[tauri::command]
pub async fn detection_samples(db: State<'_, Db>) -> AppResult<Vec<SampleRow>> {
    db.with(lib::samples)
}

/// Adds a log sample (EVTX, JSON or JSON Lines, or a text log) chosen in a native dialog.
#[tauri::command]
pub async fn detection_sample_add(app: AppHandle) -> AppResult<Option<SampleRow>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Add a log sample").add_filter("Logs", &["evtx", "json", "jsonl", "ndjson", "log", "txt"]).add_filter("All files", &["*"]).pick_file(move |f| {
        let _ = tx.send(f.and_then(|p| p.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    let dir = samples_dir(&app)?;
    let handle = app.clone();
    blocking(move || {
        let name = crate::workspace::evidence::display_name(&path.to_string_lossy());
        let (sha, size) = store_sample(&dir, &path)?;
        let sample = read_sample(&dir.join(&sha))?;
        let db = handle.state::<Db>();
        let id = db.with(|c| lib::sample_add(c, &sha, &name, kind_name(sample.kind), size as i64, sample.events.len() as i64))?;
        db.with(|c| lib::sample(c, id)).map(Some)
    })
    .await
}

#[tauri::command]
pub async fn detection_rule_expect(db: State<'_, Db>, rule_id: i64, sample_id: i64, expect: String) -> AppResult<()> {
    db.with(|c| lib::set_expect(c, rule_id, sample_id, &expect))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestOutcome {
    pub sample: SampleRow,
    pub previous: Option<TestRow>,
    pub test: TestRow,
    pub result: RunResult,
}

fn test_one(app: &AppHandle, rule_id: i64, sample_id: i64) -> AppResult<TestOutcome> {
    let db = app.state::<Db>();
    let (stored, sample_row, previous) = db.with(|c| {
        let previous = c
            .query_row("SELECT id, version, sample_id, expect, events, matched, passed, ran_at FROM detection_tests WHERE rule_id = ?1 AND sample_id = ?2 ORDER BY id DESC LIMIT 1", params![rule_id, sample_id], |r| {
                Ok(TestRow { id: r.get(0)?, version: r.get(1)?, sample_id: r.get(2)?, expect: r.get(3)?, events: r.get(4)?, matched: r.get(5)?, passed: r.get(6)?, ran_at: r.get(7)? })
            })
            .ok();
        Ok((lib::stored(c, rule_id)?, lib::sample(c, sample_id)?, previous))
    })?;
    let rule = lib::compile(&stored)?;
    let path = samples_dir(app)?.join(&sample_row.sha256);
    if !path.exists() {
        return Err(validation(format!("The sample {} is missing from the sample store", sample_row.file_name)));
    }
    let sample = read_sample(&path)?;
    let result = lib::run(&rule, &sample);
    let test = db.with(|c| lib::record_test(c, rule_id, stored.version, sample_id, &result))?;
    Ok(TestOutcome { sample: sample_row, previous, test, result })
}

/// Tests the rule's current version on a sample and records the result.
#[tauri::command]
pub async fn detection_rule_test(app: AppHandle, rule_id: i64, sample_id: i64) -> AppResult<TestOutcome> {
    let handle = app.clone();
    blocking(move || test_one(&handle, rule_id, sample_id)).await
}

/// Tests the rule's current version again on every sample it was tested on, with the previous
/// result next to each (regression testing of a changed rule).
#[tauri::command]
pub async fn detection_rule_retest(app: AppHandle, rule_id: i64) -> AppResult<Vec<TestOutcome>> {
    let handle = app.clone();
    blocking(move || {
        let ids: Vec<i64> = handle.state::<Db>().with(|c| Ok(c.prepare("SELECT sample_id FROM detection_rule_samples WHERE rule_id = ?1 ORDER BY sample_id")?.query_map(params![rule_id], |r| r.get(0))?.collect::<Result<_, _>>()?))?;
        ids.into_iter().map(|s| test_one(&handle, rule_id, s)).collect()
    })
    .await
}

#[tauri::command]
pub async fn detection_feedback_add(db: State<'_, Db>, rule_id: i64, project_id: Option<i64>, verdict: String, note: Option<String>) -> AppResult<i64> {
    db.with(|c| lib::feedback_add(c, rule_id, project_id, &verdict, note.as_deref().unwrap_or(""), ""))
}

/* ───────────────────────── projects ───────────────────────── */

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileRun {
    pub evidence_id: i64,
    pub title: String,
    pub kind: String,
    pub events: usize,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleRun {
    pub rule_id: i64,
    pub title: String,
    pub matched: usize,
    pub new: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectRun {
    pub files: Vec<FileRun>,
    pub rules: usize,
    pub results: Vec<RuleRun>,
    pub new_hits: usize,
}

/// Runs the enabled rules (of a collection when given) over log files in the project's evidence
/// vault. Matches are stored as detection hits for review, never as findings.
#[tauri::command]
pub async fn detection_project_run(app: AppHandle, project_id: i64, evidence_ids: Vec<i64>, collection_id: Option<i64>) -> AppResult<ProjectRun> {
    if evidence_ids.is_empty() || evidence_ids.len() > 50 {
        return Err(validation("Choose 1 to 50 evidence files"));
    }
    let handle = app.clone();
    blocking(move || {
        let db = handle.state::<Db>();
        let store = handle.state::<Arc<EvidenceStore>>();
        let (records, rules) = db.with(|c| {
            relations::require_open(c, project_id)?;
            let mut records = Vec::new();
            for id in &evidence_ids {
                let r = crate::workspace::evidence::get(c, *id)?;
                if r.project_id != project_id || r.kind != "file" {
                    return Err(validation(format!("Evidence #{id} is not a file of this project")));
                }
                records.push(r);
            }
            Ok((records, lib::runnable(c, collection_id)?))
        })?;
        if rules.is_empty() {
            return Err(validation("No enabled rule can run: import Sigma rules or enable them first"));
        }
        let compiled: Vec<(lib::Stored, sigma::Rule)> = rules.into_iter().filter_map(|s| lib::compile(&s).ok().map(|r| (s, r))).collect();
        let mut files = Vec::new();
        let mut totals: Vec<RuleRun> = compiled.iter().map(|(s, _)| RuleRun { rule_id: s.id, title: s.title.clone(), matched: 0, new: 0, notes: vec![] }).collect();
        for rec in &records {
            let Some(path) = store.file_path(rec) else {
                files.push(FileRun { evidence_id: rec.id, title: rec.title.clone(), kind: String::new(), events: 0, error: Some("the stored file is missing".into()) });
                continue;
            };
            let sample = match read_sample(&path) {
                Ok(s) => s,
                Err(e) => {
                    files.push(FileRun { evidence_id: rec.id, title: rec.title.clone(), kind: String::new(), events: 0, error: Some(e.to_string()) });
                    continue;
                }
            };
            files.push(FileRun { evidence_id: rec.id, title: rec.title.clone(), kind: kind_name(sample.kind).into(), events: sample.events.len(), error: None });
            for (i, (s, rule)) in compiled.iter().enumerate() {
                let r = lib::run(rule, &sample);
                if r.matched == 0 {
                    continue;
                }
                let (new, _) = db.with(|c| lib::hits_store(c, project_id, s, rec.id, &r.matches))?;
                totals[i].matched += r.matched;
                totals[i].new += new;
                for n in r.notes {
                    if !totals[i].notes.contains(&n) {
                        totals[i].notes.push(n);
                    }
                }
            }
        }
        let results: Vec<RuleRun> = totals.into_iter().filter(|r| r.matched > 0).collect();
        let new_hits = results.iter().map(|r| r.new).sum();
        let read_files = files.iter().filter(|f| f.error.is_none()).count();
        let _ = db.with(|c| {
            timeline::record(
                c,
                project_id,
                "detection",
                &format!("Detection run: {} rules on {} file{}", compiled.len(), read_files, if read_files == 1 { "" } else { "s" }),
                &format!("{} rules matched, {} new hits", results.len(), new_hits),
                None,
                None,
            )
        });
        Ok(ProjectRun { files, rules: compiled.len(), results, new_hits })
    })
    .await
}

#[tauri::command]
pub async fn detection_hits(db: State<'_, Db>, project_id: i64, filter: Option<lib::HitFilter>) -> AppResult<lib::HitPage> {
    db.with(|c| lib::hits_list(c, project_id, &filter.unwrap_or_default()))
}

#[tauri::command]
pub async fn detection_hit_set(db: State<'_, Db>, id: i64, status: String, note: Option<String>) -> AppResult<()> {
    db.with(|c| lib::hit_set(c, id, &status, note.as_deref().unwrap_or("")))
}

#[tauri::command]
pub async fn detection_hit_promote(db: State<'_, Db>, id: i64) -> AppResult<i64> {
    db.with(|c| lib::hit_promote(c, id))
}

/* ───────────────────────── export ───────────────────────── */

fn file_name_for(title: &str) -> String {
    let s: String = title.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c.to_ascii_lowercase() } else { '_' }).take(80).collect();
    let s = s.trim_matches('_').to_string();
    if s.is_empty() {
        "rule".into()
    } else {
        s
    }
}

/// Saves a rule's current version as a .yml file through a native dialog.
#[tauri::command]
pub async fn detection_rule_export(app: AppHandle, id: i64) -> AppResult<Option<String>> {
    let s = app.state::<Db>().with(|c| lib::stored(c, id))?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Export a detection rule").set_file_name(format!("{}.yml", file_name_for(&s.title))).add_filter("Sigma rule", &["yml", "yaml"]).save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, s.content).map_err(|e| AppError::Internal(format!("Could not write the rule: {e}")))?;
    Ok(path.file_name().map(|n| n.to_string_lossy().to_string()))
}

/// Writes every Sigma rule of a collection as its own .yml file into a folder chosen in a native
/// dialog; existing files are never overwritten.
#[tauri::command]
pub async fn detection_collection_export(app: AppHandle, id: i64) -> AppResult<Option<usize>> {
    let rules = app.state::<Db>().with(|c| {
        let ids: Vec<i64> = c.prepare("SELECT r.id FROM detection_collection_rules cr JOIN detection_rules r ON r.id = cr.rule_id WHERE cr.collection_id = ?1 AND r.kind = 'sigma' ORDER BY r.title")?.query_map(params![id], |r| r.get(0))?.collect::<Result<_, _>>()?;
        ids.into_iter().map(|i| lib::stored(c, i)).collect::<AppResult<Vec<_>>>()
    })?;
    if rules.is_empty() {
        return Err(validation("The collection has no Sigma rule"));
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Export the collection into a folder").pick_folder(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(dir) = rx.await.ok().flatten() else { return Ok(None) };
    blocking(move || {
        let mut written = 0;
        for s in rules {
            let base = file_name_for(&s.title);
            let mut path = dir.join(format!("{base}.yml"));
            let mut n = 2;
            while path.exists() {
                path = dir.join(format!("{base}-{n}.yml"));
                n += 1;
            }
            std::fs::OpenOptions::new().write(true).create_new(true).open(&path)?.write_all(s.content.as_bytes())?;
            written += 1;
        }
        Ok(Some(written))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samples_are_stored_by_content_and_names_are_safe() {
        let dir = std::env::temp_dir().join(format!("cyberhub-samples-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("in.log");
        std::fs::write(&src, b"line one\nline two\n").unwrap();
        let (sha, size) = store_sample(&dir, &src).unwrap();
        assert_eq!(size, 18);
        assert!(dir.join(&sha).exists());
        assert_eq!(store_sample(&dir, &src).unwrap().0, sha, "the same content once");
        assert_eq!(read_sample(&dir.join(&sha)).unwrap().events.len(), 2);
        assert!(std::fs::read_dir(&dir).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().starts_with("incoming-")), "no temporary file stays");
        assert_eq!(file_name_for("Encoded PowerShell / -enc"), "encoded_powershell___-enc");
        assert_eq!(file_name_for("../../etc/passwd"), "etc_passwd");
        assert_eq!(file_name_for("✓✓"), "rule");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
