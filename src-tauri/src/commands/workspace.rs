//! Commands for the shared project data (docs/DATA_MODEL.md): assets, finding lifecycle and
//! links, evidence, scope history, scope decisions and the project timeline.

use std::sync::Arc;

use rusqlite::params;
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::workspace::evidence::{self, EvidenceRecord, EvidenceStore};
use crate::workspace::{assets, findings, scope_gate, timeline};

/* ───────────────────────── assets ───────────────────────── */

#[tauri::command]
pub async fn assets_list(db: State<'_, Db>, project_id: i64, kind: Option<String>, status: Option<String>, limit: Option<i64>, offset: Option<i64>) -> AppResult<Vec<assets::Asset>> {
    db.with(|c| assets::list(c, project_id, kind.as_deref(), status.as_deref(), limit.unwrap_or(1000), offset.unwrap_or(0)))
}

/// Records an asset by hand (nothing is contacted, so no scope decision is needed).
#[tauri::command]
pub async fn asset_add(db: State<'_, Db>, mut input: assets::AssetInput) -> AppResult<assets::Asset> {
    input.source = "manual".into();
    db.with(|c| {
        assets::with_savepoint(c, || {
            let (asset, created) = assets::upsert_observation(c, &input, None)?;
            if created {
                timeline::record(c, asset.project_id, "asset", &format!("Asset added: {}", asset.value), &asset.kind, Some("asset"), Some(asset.id))?;
            }
            Ok(asset)
        })
    })
}

#[tauri::command]
pub async fn asset_set_status(db: State<'_, Db>, id: i64, status: String) -> AppResult<assets::Asset> {
    db.with(|c| assets::set_status(c, id, &status))
}

#[tauri::command]
pub async fn asset_observations(db: State<'_, Db>, id: i64) -> AppResult<Vec<assets::Observation>> {
    db.with(|c| assets::observations(c, id, 200))
}

/// Removes an asset recorded by mistake, with its observations and finding links. Assets that are
/// simply no longer seen should be retired instead, which keeps their history.
#[tauri::command]
pub async fn asset_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| {
        assets::with_savepoint(c, || {
            let a = assets::get(c, id)?;
            findings::forget_ref(c, "asset", id)?;
            c.execute("DELETE FROM assets WHERE id = ?1", params![id])?;
            timeline::record(c, a.project_id, "asset", &format!("Asset removed: {}", a.value), &a.kind, None, None)
        })
    })
}

/* ───────────────────────── findings lifecycle ───────────────────────── */

#[tauri::command]
pub async fn finding_set_status(db: State<'_, Db>, id: i64, status: String, note: Option<String>) -> AppResult<String> {
    db.with(|c| assets::with_savepoint(c, || findings::set_status(c, id, &status, note.as_deref().unwrap_or(""), "user").map(str::to_string)))
}

#[tauri::command]
pub async fn finding_add_note(db: State<'_, Db>, id: i64, note: String) -> AppResult<()> {
    db.with(|c| findings::add_note(c, id, &note, "user"))
}

#[tauri::command]
pub async fn finding_history(db: State<'_, Db>, id: i64) -> AppResult<Vec<findings::FindingEvent>> {
    db.with(|c| findings::history(c, id))
}

#[tauri::command]
pub async fn finding_links(db: State<'_, Db>, id: i64) -> AppResult<Vec<findings::FindingLink>> {
    db.with(|c| findings::links(c, id))
}

#[tauri::command]
pub async fn finding_link(db: State<'_, Db>, id: i64, kind: String, ref_id: i64) -> AppResult<bool> {
    db.with(|c| assets::with_savepoint(c, || findings::link(c, id, &kind, ref_id, "user")))
}

#[tauri::command]
pub async fn finding_unlink(db: State<'_, Db>, id: i64, kind: String, ref_id: i64) -> AppResult<bool> {
    db.with(|c| assets::with_savepoint(c, || findings::unlink(c, id, &kind, ref_id, "user")))
}

/* ───────────────────────── scope ───────────────────────── */

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopeEvent {
    pub id: i64,
    pub action: String,
    pub value: String,
    pub kind: String,
    pub in_scope: Option<bool>,
    pub note: String,
    pub source: String,
    pub at: String,
    /// further identical refusals counted on this entry
    pub repeats: i64,
}

#[tauri::command]
pub async fn scope_history(db: State<'_, Db>, project_id: i64, limit: Option<i64>) -> AppResult<Vec<ScopeEvent>> {
    db.with(|c| {
        let mut st = c.prepare("SELECT id, action, value, kind, in_scope, note, source, at, repeats FROM scope_events WHERE project_id = ?1 ORDER BY id DESC LIMIT ?2")?;
        let rows = st
            .query_map(params![project_id, limit.unwrap_or(500).clamp(1, 5000)], |r| {
                Ok(ScopeEvent {
                    id: r.get(0)?,
                    action: r.get(1)?,
                    value: r.get(2)?,
                    kind: r.get(3)?,
                    in_scope: r.get::<_, Option<i64>>(4)?.map(|v| v != 0),
                    note: r.get(5)?,
                    source: r.get(6)?,
                    at: r.get(7)?,
                    repeats: r.get(8)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    })
}

/// Explains, without starting anything, whether targets may be used for a passive lookup or an
/// active operation in a project.
#[tauri::command]
pub async fn scope_decide(db: State<'_, Db>, project_id: Option<i64>, targets: Vec<String>, mode: String) -> AppResult<scope_gate::Decision> {
    let mode = match mode.as_str() {
        "active" => scope_gate::Mode::Active,
        "passive" => scope_gate::Mode::Passive,
        _ => return Err(crate::error::validation("Mode must be passive or active")),
    };
    db.with(|c| scope_gate::decide(c, project_id, &targets, mode))
}

/* ───────────────────────── timeline ───────────────────────── */

#[tauri::command]
pub async fn project_timeline(db: State<'_, Db>, project_id: i64, types: Option<Vec<String>>, before: Option<String>, limit: Option<i64>) -> AppResult<Vec<timeline::TimelineEvent>> {
    db.with(|c| timeline::project_timeline(c, project_id, &types.unwrap_or_default(), before.as_deref(), limit.unwrap_or(200)))
}

/* ───────────────────────── evidence ───────────────────────── */

#[tauri::command]
pub async fn evidence_list(db: State<'_, Db>, project_id: i64) -> AppResult<Vec<EvidenceRecord>> {
    db.with(|c| evidence::list(c, project_id))
}

#[tauri::command]
pub async fn evidence_add_text(db: State<'_, Db>, project_id: i64, title: String, content: String, description: Option<String>) -> AppResult<EvidenceRecord> {
    db.with(|c| evidence::add_text(c, project_id, &title, &content, description.as_deref().unwrap_or(""), "user"))
}

#[tauri::command]
pub async fn evidence_link_execution(db: State<'_, Db>, project_id: i64, execution_id: i64, title: Option<String>) -> AppResult<EvidenceRecord> {
    db.with(|c| evidence::link_execution(c, project_id, execution_id, title.as_deref().unwrap_or("")))
}

#[tauri::command]
pub async fn evidence_link_osint(db: State<'_, Db>, project_id: i64, osint_evidence_id: i64) -> AppResult<EvidenceRecord> {
    db.with(|c| evidence::link_osint(c, project_id, osint_evidence_id))
}

fn main_window_dialog(app: &AppHandle, title: &str) -> tauri_plugin_dialog::FileDialogBuilder<tauri::Wry> {
    let mut d = app.dialog().file().set_title(title);
    if let Some(w) = app.get_webview_window("main") {
        d = d.set_parent(&w);
    }
    d
}

/// Choose a file (native dialog) and copy it into the evidence store. None when cancelled.
#[tauri::command]
pub async fn evidence_add_file(app: AppHandle, project_id: i64, title: Option<String>, description: Option<String>) -> AppResult<Option<EvidenceRecord>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Add evidence file").pick_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    let title = title.filter(|t| !t.trim().is_empty()).unwrap_or_else(|| evidence::display_name(&path.to_string_lossy()).chars().take(200).collect());
    let handle = app.clone();
    // hashing and copying up to 256 MB must not hold up the async runtime
    let rec = tauri::async_runtime::spawn_blocking(move || {
        let store = handle.state::<Arc<EvidenceStore>>();
        let db = handle.state::<Db>();
        store.add_file(&db, project_id, &path, &title, description.as_deref().unwrap_or(""), "user")
    })
    .await
    .map_err(|e| AppError::Internal(format!("evidence copy failed: {e}")))??;
    Ok(Some(rec))
}

/// Save a copy of a stored evidence file (native dialog). Returns the file name, or None if cancelled.
#[tauri::command]
pub async fn evidence_export(app: AppHandle, id: i64) -> AppResult<Option<String>> {
    let (rec, src) = {
        let db = app.state::<Db>();
        let store = app.state::<Arc<EvidenceStore>>();
        let rec = db.with(|c| evidence::get(c, id))?;
        let src = store.file_path(&rec).ok_or_else(|| crate::error::validation("Only file evidence can be saved as a file"))?;
        (rec, src)
    };
    if !src.is_file() {
        return Err(AppError::NotFound("The stored file is missing from the evidence folder".into()));
    }
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Save evidence file").set_file_name(rec.file_name.clone().unwrap_or_else(|| "evidence".into())).save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(dest) = rx.await.ok().flatten() else { return Ok(None) };
    tauri::async_runtime::spawn_blocking(move || std::fs::copy(&src, &dest).map(|_| dest))
        .await
        .map_err(|e| AppError::Internal(format!("evidence export failed: {e}")))?
        .map(|dest| Some(dest.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()))
        .map_err(|e| AppError::Internal(format!("Could not save the file: {e}")))
}

#[tauri::command]
pub async fn evidence_delete(app: AppHandle, id: i64) -> AppResult<()> {
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || handle.state::<Arc<EvidenceStore>>().delete(&handle.state::<Db>(), id))
        .await
        .map_err(|e| AppError::Internal(format!("evidence delete failed: {e}")))?
}

/* ───────────────────────── reports ───────────────────────── */

fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

/// The HTML report for preview and printing (the web view prints it to PDF).
#[tauri::command]
pub async fn report_html(db: State<'_, Db>, project_id: i64, options: crate::workspace::report::ReportOptions) -> AppResult<String> {
    db.with(|c| crate::workspace::report::render(c, project_id, &options, &today()))
}

/// Saves the HTML report through a native save dialog. Returns the file name, or None if cancelled.
#[tauri::command]
pub async fn report_export_html(app: AppHandle, project_id: i64, options: crate::workspace::report::ReportOptions) -> AppResult<Option<String>> {
    let (html, name) = {
        let db = app.state::<Db>();
        let html = db.with(|c| crate::workspace::report::render(c, project_id, &options, &today()))?;
        let name: String = db.with(|c| Ok(c.query_row("SELECT name FROM projects WHERE id = ?1", params![project_id], |r| r.get(0))?))?;
        (html, name)
    };
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).take(60).collect();
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Save assessment report").set_file_name(format!("{safe}-report.html")).add_filter("HTML", &["html"]).save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, html).map_err(|e| AppError::Internal(format!("Could not write the report: {e}")))?;
    let file = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let _ = app.state::<Db>().with(|c| timeline::record(c, project_id, "report", "Report exported (HTML)", &file, None, None));
    Ok(Some(file))
}

/// Keeps a copy of the report in the project's evidence (text, at most 1 MB).
#[tauri::command]
pub async fn report_save_evidence(db: State<'_, Db>, project_id: i64, options: crate::workspace::report::ReportOptions) -> AppResult<EvidenceRecord> {
    db.with(|c| {
        let html = crate::workspace::report::render(c, project_id, &options, &today())?;
        let rec = evidence::add_text(c, project_id, &format!("Assessment report {}", today()), &html, "HTML report generated by Cyber Hub", "report")?;
        timeline::record(c, project_id, "report", "Report saved to evidence", &rec.title, Some("evidence"), Some(rec.id))?;
        Ok(rec)
    })
}

/// Records that a report was printed (the print itself happens in the web view).
#[tauri::command]
pub async fn report_printed(db: State<'_, Db>, project_id: i64) -> AppResult<()> {
    db.with(|c| timeline::record(c, project_id, "report", "Report printed", "", None, None))
}

/* ───────────────────────── scan import ───────────────────────── */

use crate::workspace::scan_import::{self, ImportRecord, ImportResult, Options as ImportOptions, Parsed, Preview};

/// A file that was read and previewed but not imported yet.
pub struct PendingScan {
    project_id: i64,
    file_name: String,
    sha256: String,
    bytes: Vec<u8>,
    parsed: Parsed,
}

/// Pending scan imports by token. At most two are held (each up to 50 MB).
#[derive(Default)]
pub struct ScanImports(std::sync::Mutex<std::collections::HashMap<String, PendingScan>>);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanImportPreview {
    token: String,
    file_name: String,
    sha256: String,
    size: usize,
    #[serde(flatten)]
    preview: Preview,
}

fn import_token() -> AppResult<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| AppError::Internal(format!("no random source for the import token: {e}")))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// One scan import is committed at a time: the evidence check, the evidence record and the import
/// must not interleave with another commit of the same file.
static COMMIT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Choose a scan result file (native dialog), read and preview it. Nothing is imported.
#[tauri::command]
pub async fn scan_import_pick(app: AppHandle, project_id: i64, options: Option<ImportOptions>) -> AppResult<Option<ScanImportPreview>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Import scan results")
        .add_filter("Scan results", &["xml", "nessus", "json", "jsonl", "sarif", "csv", "tsv", "txt"])
        .add_filter("All files", &["*"])
        .pick_file(move |f| {
            let _ = tx.send(f.and_then(|f| f.into_path().ok()));
        });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    let handle = app.clone();
    let opts = options.unwrap_or_default();
    // reading and parsing up to 50 MB must not hold up the async runtime
    let (pending, preview) = tauri::async_runtime::spawn_blocking(move || -> AppResult<(PendingScan, Preview)> {
        let meta = std::fs::metadata(&path)?;
        if !meta.is_file() {
            return Err(crate::error::validation("Choose a file"));
        }
        if meta.len() as usize > scan_import::MAX_FILE_BYTES {
            return Err(crate::error::validation(format!("The file is larger than {} MB", scan_import::MAX_FILE_BYTES / 1024 / 1024)));
        }
        let bytes = std::fs::read(&path)?;
        if bytes.len() > scan_import::MAX_FILE_BYTES {
            return Err(crate::error::validation("The file grew while it was read"));
        }
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let parsed = scan_import::parse(&text).map_err(AppError::Validation)?;
        let preview = handle.state::<Db>().with(|c| scan_import::preview(c, project_id, &parsed, opts))?;
        let sha256 = {
            use sha2::Digest;
            sha2::Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect()
        };
        let file_name = evidence::display_name(&path.to_string_lossy()).chars().take(200).collect();
        Ok((PendingScan { project_id, file_name, sha256, bytes, parsed }, preview))
    })
    .await
    .map_err(|e| AppError::Internal(format!("reading the scan file failed: {e}")))??;
    let out = ScanImportPreview { token: import_token()?, file_name: pending.file_name.clone(), sha256: pending.sha256.clone(), size: pending.bytes.len(), preview };
    let state = app.state::<ScanImports>();
    let mut m = state.0.lock().map_err(|_| AppError::Internal("scan import state poisoned".into()))?;
    if m.len() >= 2 {
        m.clear();
    }
    m.insert(out.token.clone(), pending);
    Ok(Some(out))
}

/// The preview again with other options (informational findings included or not).
#[tauri::command]
pub async fn scan_import_preview(db: State<'_, Db>, imports: State<'_, ScanImports>, token: String, options: ImportOptions) -> AppResult<Preview> {
    let m = imports.0.lock().map_err(|_| AppError::Internal("scan import state poisoned".into()))?;
    let p = m.get(&token).ok_or_else(|| crate::error::validation("This preview has expired; choose the file again"))?;
    db.with(|c| scan_import::preview(c, p.project_id, &p.parsed, options))
}

/// Reads a previewed CSV file again with the columns the user chose, and previews it.
#[tauri::command]
pub async fn scan_import_remap(db: State<'_, Db>, imports: State<'_, ScanImports>, token: String, mapping: scan_import::csv::CsvMapping, options: ImportOptions) -> AppResult<Preview> {
    let mut m = imports.0.lock().map_err(|_| AppError::Internal("scan import state poisoned".into()))?;
    let p = m.get_mut(&token).ok_or_else(|| crate::error::validation("This preview has expired; choose the file again"))?;
    let text = String::from_utf8_lossy(&p.bytes).into_owned();
    p.parsed = scan_import::parse_csv_with(&text, &mapping).map_err(AppError::Validation)?;
    db.with(|c| scan_import::preview(c, p.project_id, &p.parsed, options))
}

/// Imports a previewed file: stores it as evidence, then records findings and assets.
#[tauri::command]
pub async fn scan_import_commit(app: AppHandle, token: String, options: ImportOptions) -> AppResult<ImportResult> {
    // taken out first, so a second click cannot import the same file twice
    let pending = {
        let state = app.state::<ScanImports>();
        let mut m = state.0.lock().map_err(|_| AppError::Internal("scan import state poisoned".into()))?;
        m.remove(&token).ok_or_else(|| crate::error::validation("This preview has expired; choose the file again"))?
    };
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || -> AppResult<ImportResult> {
        let _one_at_a_time = COMMIT_LOCK.lock().map_err(|_| AppError::Internal("scan import lock poisoned".into()))?;
        let db = handle.state::<Db>();
        let store = handle.state::<Arc<EvidenceStore>>();
        let existed: Option<i64> = db.with(|c| {
            use rusqlite::OptionalExtension;
            Ok(c.query_row("SELECT id FROM evidence WHERE project_id = ?1 AND kind = 'file' AND sha256 = ?2", params![pending.project_id, pending.sha256], |r| r.get(0)).optional()?)
        })?;
        let tool = pending.parsed.tool.clone();
        let rec = store.add_bytes(&db, pending.project_id, &pending.file_name, &pending.bytes, (&format!("{tool} results: {}", pending.file_name), &format!("Imported scan results ({tool}). SHA-256 {}", pending.sha256)), "import")?;
        let info = scan_import::FileInfo { file_name: &pending.file_name, sha256: &pending.sha256, evidence_id: Some(rec.id) };
        let result = db.with(|c| scan_import::import(c, pending.project_id, &pending.parsed, options, &info));
        if result.is_err() && existed.is_none() {
            // the import was not recorded: do not leave its file behind
            let _ = store.delete(&db, rec.id);
        }
        result
    })
    .await
    .map_err(|e| AppError::Internal(format!("the import failed: {e}")))?
}

/// Forgets a previewed file without importing it.
#[tauri::command]
pub async fn scan_import_discard(imports: State<'_, ScanImports>, token: String) -> AppResult<()> {
    if let Ok(mut m) = imports.0.lock() {
        m.remove(&token);
    }
    Ok(())
}

/// Imports recorded for a project, newest first.
#[tauri::command]
pub async fn scan_imports_list(db: State<'_, Db>, project_id: i64) -> AppResult<Vec<ImportRecord>> {
    db.with(|c| scan_import::history(c, project_id))
}

/* ───────────────────────── finding library ───────────────────────── */

use crate::workspace::templates::{self, FindingTemplate, LibraryImport, TemplateInput};

#[tauri::command]
pub async fn finding_templates_list(db: State<'_, Db>) -> AppResult<Vec<FindingTemplate>> {
    db.with(templates::list)
}

#[tauri::command]
pub async fn finding_template_save(db: State<'_, Db>, input: TemplateInput) -> AppResult<FindingTemplate> {
    db.with(|c| {
        let id = templates::save(c, &input)?;
        templates::get(c, id)
    })
}

#[tauri::command]
pub async fn finding_template_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| templates::delete(c, id))
}

/// Counts a use of a template (a finding was recorded from it).
#[tauri::command]
pub async fn finding_template_used(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| templates::mark_used(c, id))
}

/// Adds the starter templates that are not in the library yet; returns how many were added.
#[tauri::command]
pub async fn finding_templates_add_starters(db: State<'_, Db>) -> AppResult<usize> {
    db.with(templates::add_starters)
}

/// Saves the library as a JSON file (native dialog). Returns the file name, or None if cancelled.
#[tauri::command]
pub async fn finding_templates_export(app: AppHandle) -> AppResult<Option<String>> {
    let json = app.state::<Db>().with(templates::export_json)?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Export finding library").set_file_name("cyberhub-finding-library.json").add_filter("JSON", &["json"]).save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, json).map_err(|e| AppError::Internal(format!("Could not write the library file: {e}")))?;
    Ok(Some(path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default()))
}

/// Adds the templates of a library file (native dialog). Existing titles are never overwritten.
#[tauri::command]
pub async fn finding_templates_import(app: AppHandle) -> AppResult<Option<LibraryImport>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Import finding library").add_filter("JSON", &["json"]).pick_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    let meta = std::fs::metadata(&path)?;
    if meta.len() as usize > templates::MAX_LIBRARY_FILE {
        return Err(crate::error::validation("The library file is larger than 5 MB"));
    }
    let text = std::fs::read_to_string(&path).map_err(|_| crate::error::validation("The file is not UTF-8 text"))?;
    Ok(Some(app.state::<Db>().with(|c| templates::import_json(c, &text))?))
}

/* ───────────────────────── CVSS ───────────────────────── */

/// Validates and scores a CVSS v3.1 or v4.0 vector (the finding form's calculator).
#[tauri::command]
pub async fn cvss_score(vector: String) -> AppResult<crate::cvss::Cvss> {
    crate::cvss::parse(&vector).map_err(AppError::Validation)
}

/* ───────────────────────── findings export ───────────────────────── */

/// Saves the chosen findings of a project as CSV or JSON through a native save dialog, in the
/// order given. Returns the file name, or None if cancelled.
#[tauri::command]
pub async fn findings_export(app: AppHandle, project_id: i64, ids: Vec<i64>, format: String) -> AppResult<Option<String>> {
    if ids.is_empty() || ids.len() > 50_000 {
        return Err(crate::error::validation("Choose 1 to 50,000 findings to export"));
    }
    let (content, name, ext) = {
        let db = app.state::<Db>();
        let (name, all) = db.with(|c| {
            let name: String = c.query_row("SELECT name FROM projects WHERE id = ?1", params![project_id], |r| r.get(0))?;
            Ok((name, crate::commands::projects::findings_of(c, project_id)?))
        })?;
        let mut by_id: std::collections::HashMap<i64, crate::commands::projects::Finding> = all.into_iter().map(|f| (f.id, f)).collect();
        let chosen: Vec<_> = ids.iter().filter_map(|id| by_id.remove(id)).collect();
        if chosen.is_empty() {
            return Err(crate::error::validation("None of these findings belong to the project"));
        }
        match format.as_str() {
            "csv" => (crate::workspace::findings_export::csv(&chosen), name, "csv"),
            "json" => (crate::workspace::findings_export::json(&name, &crate::util::now(), &chosen)?, name, "json"),
            _ => return Err(crate::error::validation("Export as csv or json")),
        }
    };
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).take(60).collect();
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Export findings").set_file_name(format!("{safe}-findings.{ext}")).add_filter(ext.to_uppercase(), &[ext]).save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, content).map_err(|e| AppError::Internal(format!("Could not write the export: {e}")))?;
    let file = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let _ = app.state::<Db>().with(|c| timeline::record(c, project_id, "report", &format!("Findings exported ({})", ext.to_uppercase()), &file, None, None));
    Ok(Some(file))
}

/* ───────────────────────── methodology checklist ───────────────────────── */

/// The bundled OWASP WSTG test catalog.
#[tauri::command]
pub async fn wstg_catalog() -> AppResult<crate::methodology::Catalog> {
    Ok(crate::methodology::catalog().clone())
}

#[tauri::command]
pub async fn checklist_items(db: State<'_, Db>, project_id: i64) -> AppResult<Vec<crate::methodology::ItemState>> {
    db.with(|c| crate::methodology::items(c, project_id))
}

#[tauri::command]
pub async fn checklist_set(db: State<'_, Db>, project_id: i64, test_id: String, status: String, note: Option<String>, finding_id: Option<i64>) -> AppResult<crate::methodology::ItemState> {
    db.with(|c| crate::methodology::set(c, project_id, &test_id, &status, note.as_deref().unwrap_or(""), finding_id))
}

/* ───────────────────────── database backup ───────────────────────── */

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupResult {
    file_name: String,
    size: u64,
}

/// Saves a consistent, integrity-checked copy of the database through a native save dialog.
/// Evidence files and credentials are not part of it. None when cancelled.
#[tauri::command]
pub async fn database_backup(app: AppHandle) -> AppResult<Option<BackupResult>> {
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Back up the database").set_file_name(format!("cyberhub-backup-{stamp}.db")).add_filter("SQLite database", &["db"]).save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    let handle = app.clone();
    // copying a large database must not hold up the async runtime
    let (file_name, size) = tauri::async_runtime::spawn_blocking(move || -> AppResult<(String, u64)> {
        let size = handle.state::<Db>().with(|c| crate::db::backup_to(c, &path))?;
        let file_name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let _ = handle.state::<Db>().with(|c| crate::commands::activity::log(c, "backup", "Database backed up", &file_name, None, None, None));
        Ok((file_name, size))
    })
    .await
    .map_err(|e| AppError::Internal(format!("the backup failed: {e}")))??;
    Ok(Some(BackupResult { file_name, size }))
}

/* ───────────────────────── database restore ───────────────────────── */

/// The backup chosen for a restore (until it is confirmed), and the result of a restore applied
/// at this start (reported once).
pub struct RestoreState {
    chosen: std::sync::Mutex<Option<(String, std::path::PathBuf, crate::restore::BackupInfo)>>,
    outcome: std::sync::Mutex<Option<crate::restore::Outcome>>,
}

impl RestoreState {
    pub fn new(outcome: Option<crate::restore::Outcome>) -> Self {
        Self { chosen: std::sync::Mutex::new(None), outcome: std::sync::Mutex::new(outcome) }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RestoreChoice {
    token: String,
    info: crate::restore::BackupInfo,
}

/// Choose a backup (native dialog) and check it. Nothing changes until it is confirmed with
/// `database_restore_apply`. None when cancelled.
#[tauri::command]
pub async fn database_restore_inspect(app: AppHandle, state: State<'_, RestoreState>) -> AppResult<Option<RestoreChoice>> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Restore a backup").add_filter("SQLite database", &["db"]).pick_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    let dir = crate::util::data_dir(&app)?;
    let chosen = path.clone();
    let info = tauri::async_runtime::spawn_blocking(move || crate::restore::inspect(&chosen, &dir))
        .await
        .map_err(|e| AppError::Internal(format!("the backup could not be checked: {e}")))??;
    let token = import_token()?;
    *state.chosen.lock().map_err(|_| AppError::Internal("restore state poisoned".into()))? = Some((token.clone(), path, info.clone()));
    Ok(Some(RestoreChoice { token, info }))
}

/// Copies the confirmed backup into the data folder and restarts Cyber Hub, which swaps it in
/// before it opens the database (`restore.rs`). The current database is kept in
/// `backups/before-restore-<time>/`.
#[tauri::command]
pub async fn database_restore_apply(app: AppHandle, state: State<'_, RestoreState>, token: String) -> AppResult<crate::restore::BackupInfo> {
    let (path, confirmed) = {
        let mut chosen = state.chosen.lock().map_err(|_| AppError::Internal("restore state poisoned".into()))?;
        match chosen.take() {
            Some((t, p, info)) if t == token => (p, info),
            other => {
                *chosen = other;
                return Err(AppError::Validation("Choose the backup again".into()));
            }
        }
    };
    let dir = crate::util::data_dir(&app)?;
    // the file must still be the one the user confirmed
    let info = tauri::async_runtime::spawn_blocking(move || crate::restore::stage(&dir, &path, Some(&confirmed)))
        .await
        .map_err(|e| AppError::Internal(format!("the backup could not be prepared: {e}")))??;
    let db = app.state::<Db>();
    // recorded in the current database, which is kept with this entry
    let _ = db.with(|c| crate::commands::activity::log(c, "restore", "Database restore prepared", &info.file_name, None, None, None));
    // the WAL is written back so the kept database is one file
    let _ = db.with(|c| Ok(c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?));
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        // the reply reaches the window first
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;
        handle.restart();
    });
    Ok(info)
}

/// The result of a restore applied when Cyber Hub started, once.
#[tauri::command]
pub fn database_restore_outcome(state: State<'_, RestoreState>) -> AppResult<Option<crate::restore::Outcome>> {
    Ok(state.outcome.lock().map_err(|_| AppError::Internal("restore state poisoned".into()))?.take())
}

/// Whether a restore waits for the next start (it could not replace the database yet).
#[tauri::command]
pub fn database_restore_pending(app: AppHandle) -> AppResult<bool> {
    Ok(crate::restore::pending(&crate::util::data_dir(&app)?))
}

/// Cancels a restore that waits for the next start. False when there was none.
#[tauri::command]
pub fn database_restore_cancel(app: AppHandle) -> AppResult<bool> {
    let cancelled = crate::restore::cancel(&crate::util::data_dir(&app)?)?;
    if cancelled {
        let _ = app.state::<Db>().with(|c| crate::commands::activity::log(c, "restore", "Database restore cancelled", "", None, None, None));
    }
    Ok(cancelled)
}
