//! Detection engineering commands (`workspace/detections.rs`, `detection/`): the rule library,
//! import and export through native dialogs, test samples kept by content hash in the app's data
//! folder, tests and regression re-tests, and runs over a project's evidence. Nothing here
//! contacts a network or executes rule or sample content.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rusqlite::{params, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Manager, State};

use crate::commands::workspace::main_window_dialog;
use crate::db::Db;
use crate::detection::events::{self, Sample};
use crate::detection::{sigma, yara};
use crate::error::{validation, AppError, AppResult};
use crate::workspace::detections::{self as lib, Imported, RunResult, SampleRow, TestRow};
use crate::workspace::evidence::EvidenceStore;
use crate::workspace::{relations, timeline};

const MAX_IMPORT_FILES: usize = 500;

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> AppResult<T> + Send + 'static) -> AppResult<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| AppError::Internal(format!("the task failed: {e}")))?
}

/// The rule engines: Sigma (specification version, modifiers, mapped log sources) and, under
/// `yara`, YARA (modules, what is refused, limits).
#[tauri::command]
pub async fn detection_engine() -> AppResult<serde_json::Value> {
    let mut v = sigma::capabilities();
    v["yara"] = yara::capabilities();
    Ok(v)
}

/// Saves the detection library's ATT&CK coverage as a Navigator layer through a native dialog.
#[tauri::command]
pub async fn attack_coverage_export(app: AppHandle, project_id: i64, domain: Option<String>) -> AppResult<Option<String>> {
    let domain = match domain.as_deref().map(str::trim).filter(|d| !d.is_empty()) {
        None => crate::workspace::attack::ENTERPRISE,
        Some(d) => crate::workspace::attack::parse_domain(d).ok_or_else(|| validation("The ATT&CK domain is enterprise-attack, mobile-attack or ics-attack"))?,
    };
    let content = app.state::<Db>().with(|c| {
        let m = crate::workspace::attack_matrix::matrix_for(c, project_id, domain)?;
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
    /// what the import did beyond adding rules (rules disabled because a correlation uses them)
    pub notes: Vec<String>,
}

/// Stores every rule of a Sigma file (one per YAML document).
fn import_sigma(c: &rusqlite::Connection, name: &str, text: &str, note: &str, report: &mut ImportReport) {
    let docs = lib::documents(text);
    if docs.is_empty() {
        report.failed.push((name.into(), "The file holds no rule".into()));
    }
    let mut stored = Vec::new();
    for (i, doc) in docs.iter().enumerate() {
        let label = if docs.len() > 1 { format!("{name} (document {})", i + 1) } else { name.to_string() };
        match sigma::read(doc) {
            Ok(mut v) if v.len() == 1 => {
                let checked = v.remove(0);
                match lib::upsert_sigma(c, doc, &checked, name, note) {
                    Ok(r) => {
                        report.imported.push(r.clone());
                        stored.push((checked, r));
                    }
                    Err(e) => report.failed.push((label, e.to_string())),
                }
            }
            Ok(_) => report.failed.push((label, "A document holds one rule".into())),
            Err(e) => report.failed.push((label, e)),
        }
    }
    match lib::disable_correlated(c, &stored) {
        Ok(titles) if !titles.is_empty() => report.notes.push(format!(
            "Used only by a correlation of the same file (it does not say generate: true), so imported disabled: {}. They still run as part of the correlation.",
            titles.join(", ")
        )),
        Ok(_) => {}
        Err(e) => report.failed.push((name.into(), e.to_string())),
    }
}

/// Stores a YARA rule file (all its rules together, so private and global rules keep working).
fn import_yara(c: &rusqlite::Connection, name: &str, text: &str, note: &str, report: &mut ImportReport) {
    let checked = yara::check(text);
    match lib::upsert_yara(c, &lib::yara_key(name), name, text, &checked, name, note) {
        Ok(r) => report.imported.push(r),
        Err(e) => report.failed.push((name.into(), e.to_string())),
    }
}

/// Whether a rule file is YARA or Sigma: by its extension, otherwise by its content.
fn rule_kind(name: &str, text: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".yar") || lower.ends_with(".yara") {
        return "yara";
    }
    if lower.ends_with(".yml") || lower.ends_with(".yaml") {
        return "sigma";
    }
    if !yara::declared(text).is_empty() || text.lines().any(|l| l.trim_start().starts_with("import \"")) {
        "yara"
    } else {
        "sigma"
    }
}

/// Imports Sigma and YARA rule files chosen in a native dialog. A Sigma rule already in the
/// library (same id), or a YARA file of the same name, gets a new version when its content
/// changed.
#[tauri::command]
pub async fn detection_rules_import(app: AppHandle) -> AppResult<Option<ImportReport>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Import detection rules")
        .add_filter("Detection rules", &["yml", "yaml", "yar", "yara"])
        .add_filter("Sigma rules", &["yml", "yaml"])
        .add_filter("YARA rules", &["yar", "yara"])
        .add_filter("All files", &["*"])
        .pick_files(move |f| {
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
            let text = match read_limited(&p, yara::MAX_RULE_BYTES as u64) {
                Ok(t) => t,
                Err(e) => {
                    report.failed.push((name, e.to_string()));
                    continue;
                }
            };
            let kind = rule_kind(&name, &text);
            if kind == "sigma" && text.len() > sigma::MAX_RULE_BYTES {
                report.failed.push((name, format!("A Sigma rule file is at most {} KB", sigma::MAX_RULE_BYTES / 1024)));
                continue;
            }
            db.with(|c| {
                if kind == "yara" {
                    import_yara(c, &name, &text, "", &mut report);
                } else {
                    import_sigma(c, &name, &text, "", &mut report);
                }
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
    Ok(match s.strip_prefix('\u{feff}') {
        Some(rest) => rest.to_string(),
        None => s,
    })
}

/// Reads a whole file of at most `max` bytes (a YARA scan needs the bytes in memory).
fn read_bytes(p: &Path, max: u64) -> AppResult<Vec<u8>> {
    let meta = std::fs::metadata(p)?;
    if !meta.is_file() || meta.len() > max {
        return Err(validation(format!("YARA rules scan files of at most {} MB", max / 1024 / 1024)));
    }
    let mut data = Vec::with_capacity(meta.len() as usize);
    std::fs::File::open(p)?.take(max + 1).read_to_end(&mut data)?;
    if data.len() as u64 > max {
        return Err(validation("The file grew past the size limit while it was read"));
    }
    Ok(data)
}

/// Adds rules written or edited in the app. A Sigma rule with an existing id becomes its new
/// version; a YARA file edited from the library (`id`) becomes that file's new version, and a new
/// YARA file is named after its first rule.
#[tauri::command]
pub async fn detection_rule_save(db: State<'_, Db>, content: String, note: Option<String>, kind: Option<String>, id: Option<i64>) -> AppResult<ImportReport> {
    if kind.as_deref() == Some("yara") {
        if content.len() > yara::MAX_RULE_BYTES {
            return Err(validation("The rule file is too large"));
        }
        let note = note.unwrap_or_else(|| "Edited in Cyber Hub".into());
        return db.with(|c| {
            let (key, name) = match id {
                Some(id) => {
                    let (k, key): (String, String) = c.query_row("SELECT kind, rule_key FROM detection_rules WHERE id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?))).optional()?.ok_or_else(|| AppError::NotFound(format!("detection rule {id}")))?;
                    if k != "yara" {
                        return Err(validation("The rule being edited is not a YARA file"));
                    }
                    let name = key.strip_prefix("file:").unwrap_or(&key).to_string();
                    (key, name)
                }
                None => {
                    let first = yara::declared(&content).into_iter().next().ok_or_else(|| validation("Write at least one rule: rule Name { condition: … }"))?;
                    let name = format!("{first}.yar");
                    let key = lib::yara_key(&name);
                    if c.query_row("SELECT 1 FROM detection_rules WHERE kind = 'yara' AND rule_key = ?1", params![key], |_| Ok(())).optional()?.is_some() {
                        return Err(validation(format!("The library has a YARA file named {name}: edit it, or name the first rule differently")));
                    }
                    (key, name)
                }
            };
            let checked = yara::check(&content);
            let mut report = ImportReport::default();
            match lib::upsert_yara(c, &key, &name, &content, &checked, "written in Cyber Hub", &note) {
                Ok(r) => report.imported.push(r),
                Err(e) => report.failed.push((name, e.to_string())),
            }
            Ok(report)
        });
    }
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

/// Adds a sample chosen in a native dialog: a log (EVTX, JSON or JSON Lines, or a text log) for
/// Sigma rules, or with `kind` "file" any file for YARA rules. A file sample is only read, never
/// opened by another program.
#[tauri::command]
pub async fn detection_sample_add(app: AppHandle, kind: Option<String>) -> AppResult<Option<SampleRow>> {
    let file = kind.as_deref() == Some("file");
    let (tx, rx) = tokio::sync::oneshot::channel();
    let dialog = main_window_dialog(&app, if file { "Add a file sample" } else { "Add a log sample" });
    let dialog = if file { dialog.add_filter("All files", &["*"]) } else { dialog.add_filter("Logs", &["evtx", "json", "jsonl", "ndjson", "log", "txt"]).add_filter("All files", &["*"]) };
    dialog.pick_file(move |f| {
        let _ = tx.send(f.and_then(|p| p.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    let dir = samples_dir(&app)?;
    let handle = app.clone();
    blocking(move || {
        let name = crate::workspace::evidence::display_name(&path.to_string_lossy());
        let (sha, size) = store_sample(&dir, &path)?;
        let db = handle.state::<Db>();
        let id = if file {
            db.with(|c| lib::sample_add(c, &sha, &name, "file", size as i64, 0))?
        } else {
            let sample = read_sample(&dir.join(&sha))?;
            db.with(|c| lib::sample_add(c, &sha, &name, kind_name(sample.kind), size as i64, sample.events.len() as i64))?
        };
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
    // the hash comes from the database, which a restored file may have supplied: only a SHA-256
    // (64 hexadecimal characters) names a file of the sample store
    if sample_row.sha256.len() != 64 || !sample_row.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(validation(format!("The sample record of {} is damaged (its hash is not a SHA-256)", sample_row.file_name)));
    }
    let path = samples_dir(app)?.join(&sample_row.sha256);
    if !path.exists() {
        return Err(validation(format!("The sample {} is missing from the sample store", sample_row.file_name)));
    }
    let result = if stored.kind == "yara" {
        let scanner = lib::compile_yara(&stored)?;
        let data = read_bytes(&path, yara::MAX_SCAN_BYTES)?;
        lib::yara_result(&yara::scan(&scanner, &data), &sample_row.file_name)
    } else {
        if sample_row.kind == "file" {
            return Err(validation(format!("{} is a file sample for YARA rules; a Sigma rule runs on log samples (EVTX, JSON, text)", sample_row.file_name)));
        }
        match db.with(|c| lib::correlation_tree(c, &stored))? {
            Some(tree) => lib::correlation_result(tree, &read_sample(&path)?, sample_id, &sample_row.file_name),
            None => {
                let rule = lib::compile(&stored)?;
                lib::run(&rule, &read_sample(&path)?)
            }
        }
    };
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
    /// the log kind when Sigma rules read it, otherwise "file"
    pub kind: String,
    pub events: usize,
    /// YARA rules scanned the file
    pub scanned: bool,
    /// why nothing ran on the file
    pub error: Option<String>,
    /// what did not run on it, and why
    pub notes: Vec<String>,
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

/// Runs the enabled rules (of a collection when given) over files in the project's evidence vault:
/// Sigma rules over the logs, YARA rules over every file. Matches are stored as detection hits for
/// review, never as findings.
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
            return Err(validation("No enabled rule can run: import Sigma or YARA rules, or enable them first"));
        }
        let (sigma_rules, yara_rules): (Vec<lib::Stored>, Vec<lib::Stored>) = rules.into_iter().partition(|s| s.kind == "sigma");
        // correlation rules run over the matches of the rules they refer to, across every file
        let mut trees: Vec<(lib::Stored, crate::detection::correlation::Tree)> = Vec::new();
        let mut detections = Vec::new();
        let mut unresolved: Vec<(lib::Stored, String)> = Vec::new();
        db.with(|c| {
            for s in sigma_rules {
                match lib::correlation_tree(c, &s) {
                    Ok(Some(t)) => trees.push((s, t)),
                    Ok(None) => detections.push(s),
                    Err(e) => unresolved.push((s, e.to_string())),
                }
            }
            Ok(())
        })?;
        let compiled: Vec<(lib::Stored, sigma::Rule)> = detections.into_iter().filter_map(|s| lib::compile(&s).ok().map(|r| (s, r))).collect();
        let ylib = (!yara_rules.is_empty()).then(|| yara::library(&yara_rules.iter().map(|s| (s.id, s.content.as_str())).collect::<Vec<_>>()));
        let mut files = Vec::new();
        let mut totals: Vec<RuleRun> = compiled
            .iter()
            .map(|(s, _)| s)
            .chain(yara_rules.iter())
            .chain(trees.iter().map(|(s, _)| s))
            .chain(unresolved.iter().map(|(s, _)| s))
            .map(|s| RuleRun { rule_id: s.id, title: s.title.clone(), matched: 0, new: 0, notes: vec![] })
            .collect();
        let note = |t: &mut RuleRun, n: String| {
            if !t.notes.contains(&n) {
                t.notes.push(n);
            }
        };
        for (s, why) in &unresolved {
            if let Some(t) = totals.iter_mut().find(|t| t.rule_id == s.id) {
                note(t, format!("Not run: {why}"));
            }
        }
        if let Some(l) = &ylib {
            for (id, why) in &l.failed {
                if let Some(t) = totals.iter_mut().find(|t| t.rule_id == *id) {
                    note(t, format!("Not run: {why}"));
                }
            }
        }
        for rec in &records {
            let Some(path) = store.file_path(rec) else {
                files.push(FileRun { evidence_id: rec.id, title: rec.title.clone(), kind: String::new(), events: 0, scanned: false, error: Some("the stored file is missing".into()), notes: vec![] });
                continue;
            };
            let mut file = FileRun { evidence_id: rec.id, title: rec.title.clone(), kind: String::new(), events: 0, scanned: false, error: None, notes: vec![] };
            let mut problems = Vec::new();
            if !compiled.is_empty() || !trees.is_empty() {
                match read_sample(&path) {
                    Ok(sample) => {
                        file.kind = kind_name(sample.kind).into();
                        file.events = sample.events.len();
                        for (_, tree) in trees.iter_mut() {
                            tree.feed(&sample, rec.id, &rec.title);
                        }
                        for (i, (s, rule)) in compiled.iter().enumerate() {
                            let r = lib::run(rule, &sample);
                            if r.matched == 0 {
                                continue;
                            }
                            let (new, _) = db.with(|c| lib::hits_store(c, project_id, s, rec.id, &r.matches))?;
                            totals[i].matched += r.matched;
                            totals[i].new += new;
                            for n in r.notes {
                                note(&mut totals[i], n);
                            }
                        }
                    }
                    Err(e) => problems.push(format!("Sigma rules did not run: {e}")),
                }
            }
            if let Some(l) = &ylib {
                match read_bytes(&path, yara::MAX_SCAN_BYTES) {
                    Ok(data) => {
                        file.scanned = true;
                        if file.kind.is_empty() {
                            file.kind = "file".into();
                        }
                        let scan = yara::scan(&l.scanner, &data);
                        if scan.timed_out {
                            file.notes.push(format!("The YARA scan stopped after {} s: rules that would have matched later are missing", yara::SCAN_TIMEOUT.as_secs()));
                        }
                        let mut by_rule: std::collections::BTreeMap<i64, Vec<yara::RuleMatch>> = Default::default();
                        for m in scan.matches {
                            if let Some(id) = yara::namespace_id(&m.namespace).filter(|id| !l.failed.iter().any(|f| f.0 == *id)) {
                                by_rule.entry(id).or_default().push(m);
                            }
                        }
                        for (id, matches) in by_rule {
                            let Some(s) = yara_rules.iter().find(|s| s.id == id) else { continue };
                            let r = lib::yara_result(&yara::Scan { matches, timed_out: scan.timed_out, more: 0 }, &rec.title);
                            let (new, _) = db.with(|c| lib::hits_store(c, project_id, s, rec.id, &r.matches))?;
                            if let Some(t) = totals.iter_mut().find(|t| t.rule_id == id) {
                                t.matched += r.matched;
                                t.new += new;
                            }
                        }
                    }
                    Err(e) => problems.push(format!("YARA rules did not run: {e}")),
                }
            }
            if file.kind.is_empty() {
                file.error = Some(problems.join("; "));
            } else {
                file.notes.extend(problems);
            }
            files.push(file);
        }
        let correlation_count = trees.len();
        for (s, tree) in trees {
            let run = lib::finish_correlation(tree);
            let mut new = 0;
            for (evidence_id, m) in run.matches.iter().take(lib::MAX_MATCHES) {
                new += db.with(|c| lib::hits_store(c, project_id, &s, *evidence_id, std::slice::from_ref(m)))?.0;
            }
            if let Some(t) = totals.iter_mut().find(|t| t.rule_id == s.id) {
                t.matched += run.matched;
                t.new += new;
                for n in run.notes {
                    note(t, n);
                }
                if run.matched > lib::MAX_MATCHES {
                    note(t, format!("{} matches; the first {} were stored", run.matched, lib::MAX_MATCHES));
                }
            }
        }
        // rules that matched, and rules that could not run (with the reason)
        let results: Vec<RuleRun> = totals.into_iter().filter(|r| r.matched > 0 || r.notes.iter().any(|n| n.starts_with("Not run"))).collect();
        let new_hits = results.iter().map(|r| r.new).sum();
        let read_files = files.iter().filter(|f| f.error.is_none()).count();
        let rule_count = compiled.len() + yara_rules.len() + correlation_count;
        let _ = db.with(|c| {
            timeline::record(
                c,
                project_id,
                "detection",
                &format!("Detection run: {} rules on {} file{}", rule_count, read_files, if read_files == 1 { "" } else { "s" }),
                &format!("{} rule{} matched, {} new hit{}", results.len(), if results.len() == 1 { "" } else { "s" }, new_hits, if new_hits == 1 { "" } else { "s" }),
                None,
                None,
            )
        });
        Ok(ProjectRun { files, rules: rule_count, results, new_hits })
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

/* ───────────────────────── File Triage ───────────────────────── */

/// A YARA rule that matched the triaged file, with the library file it comes from.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageMatch {
    pub rule_id: i64,
    pub title: String,
    pub version: i64,
    pub level: String,
    pub techniques: Vec<String>,
    pub rule: String,
    pub tags: Vec<String>,
    pub metas: Vec<(String, String)>,
    pub strings: Vec<yara::StringHit>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageScan {
    /// rule files run
    pub files: usize,
    pub matches: Vec<TriageMatch>,
    /// rule files that did not compile: (title, why)
    pub failed: Vec<(String, String)>,
    pub notes: Vec<String>,
}

/// Scans the file File Triage analysed (named by its token) with the library's enabled YARA rules,
/// of a collection when given. The file must still have the SHA-256 that was analysed. Nothing is
/// recorded: a match becomes a finding only when the analyst records it.
#[tauri::command]
pub async fn yara_scan_file(app: AppHandle, token: String, collection_id: Option<i64>) -> AppResult<TriageScan> {
    let (path, name, sha) = crate::commands::utility_record::picked(&app, &token)?;
    let handle = app.clone();
    blocking(move || {
        let db = handle.state::<Db>();
        let rules: Vec<lib::Stored> = db.with(|c| lib::runnable(c, collection_id))?.into_iter().filter(|s| s.kind == "yara").collect();
        if rules.is_empty() {
            return Err(validation(if collection_id.is_some() { "The collection has no enabled YARA rule that can run" } else { "No enabled YARA rule: import YARA rules in Detections first" }));
        }
        let data = read_bytes(&path, yara::MAX_SCAN_BYTES)?;
        if let Some(expected) = &sha {
            let actual: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
            if &actual != expected {
                return Err(validation("The file changed since it was analysed: analyse it again"));
            }
        }
        let l = yara::library(&rules.iter().map(|s| (s.id, s.content.as_str())).collect::<Vec<_>>());
        let scan = yara::scan(&l.scanner, &data);
        let mut notes = Vec::new();
        if scan.timed_out {
            notes.push(format!("The scan stopped after {} s: rules that would have matched later are missing", yara::SCAN_TIMEOUT.as_secs()));
        }
        if scan.more > 0 {
            notes.push(format!("{} more rules matched; the first {} are listed", scan.more, scan.matches.len()));
        }
        let matches: Vec<TriageMatch> = scan
            .matches
            .into_iter()
            .filter_map(|m| {
                let id = yara::namespace_id(&m.namespace)?;
                if l.failed.iter().any(|f| f.0 == id) {
                    return None;
                }
                let s = rules.iter().find(|s| s.id == id)?;
                Some(TriageMatch { rule_id: id, title: s.title.clone(), version: s.version, level: s.level.clone(), techniques: s.techniques.clone(), rule: m.rule, tags: m.tags, metas: m.metas, strings: m.strings })
            })
            .collect();
        let failed = l.failed.iter().map(|(id, why)| (rules.iter().find(|s| s.id == *id).map(|s| s.title.clone()).unwrap_or_default(), why.clone())).collect();
        let _ = db.with(|c| crate::commands::activity::log(c, "scan", "YARA scan in File Triage", &format!("{name}: {} rule files, {} rules matched", rules.len(), matches.len()), None, None, None));
        Ok(TriageScan { files: rules.len(), matches, failed, notes })
    })
    .await
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

/// The file extension and dialog filter of a rule kind.
fn export_format(kind: &str) -> (&'static str, &'static str) {
    if kind == "yara" {
        ("yar", "YARA rules")
    } else {
        ("yml", "Sigma rule")
    }
}

/// Saves a rule's current version as a .yml (Sigma) or .yar (YARA) file through a native dialog.
#[tauri::command]
pub async fn detection_rule_export(app: AppHandle, id: i64) -> AppResult<Option<String>> {
    let s = app.state::<Db>().with(|c| lib::stored(c, id))?;
    let (ext, label) = export_format(&s.kind);
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Export a detection rule").set_file_name(format!("{}.{ext}", file_name_for(&s.title))).add_filter(label, &[ext]).save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, s.content).map_err(|e| AppError::Internal(format!("Could not write the rule: {e}")))?;
    Ok(path.file_name().map(|n| n.to_string_lossy().to_string()))
}

/// Writes every rule of a collection as its own file (.yml for Sigma, .yar for YARA) into a
/// folder chosen in a native dialog; existing files are never overwritten.
#[tauri::command]
pub async fn detection_collection_export(app: AppHandle, id: i64) -> AppResult<Option<usize>> {
    let rules = app.state::<Db>().with(|c| {
        let ids: Vec<i64> = c.prepare("SELECT r.id FROM detection_collection_rules cr JOIN detection_rules r ON r.id = cr.rule_id WHERE cr.collection_id = ?1 ORDER BY r.title")?.query_map(params![id], |r| r.get(0))?.collect::<Result<_, _>>()?;
        ids.into_iter().map(|i| lib::stored(c, i)).collect::<AppResult<Vec<_>>>()
    })?;
    if rules.is_empty() {
        return Err(validation("The collection has no rule"));
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
            let (ext, _) = export_format(&s.kind);
            let mut path = dir.join(format!("{base}.{ext}"));
            let mut n = 2;
            while path.exists() {
                path = dir.join(format!("{base}-{n}.{ext}"));
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
        assert_eq!(rule_kind("rules.YAR", ""), "yara");
        assert_eq!(rule_kind("rules.yml", "rule X { condition: true }"), "sigma", "the extension decides");
        assert_eq!(rule_kind("rules.txt", "private rule X { condition: true }"), "yara");
        assert_eq!(rule_kind("rules.txt", "title: x\nlogsource: {}\n"), "sigma");
        let bom = dir.join("bom.yar");
        std::fs::write(&bom, b"\xEF\xBB\xBFrule X { condition: true }").unwrap();
        assert!(read_limited(&bom, 1000).unwrap().starts_with("rule X"), "a byte-order mark is dropped");
        assert!(read_bytes(&bom, 10).is_err(), "larger than the limit");
        assert_eq!(read_bytes(&bom, 1000).unwrap().len(), 29, "the bytes as they are, mark included");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
