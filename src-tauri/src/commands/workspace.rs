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
}

#[tauri::command]
pub async fn scope_history(db: State<'_, Db>, project_id: i64, limit: Option<i64>) -> AppResult<Vec<ScopeEvent>> {
    db.with(|c| {
        let mut st = c.prepare("SELECT id, action, value, kind, in_scope, note, source, at FROM scope_events WHERE project_id = ?1 ORDER BY id DESC LIMIT ?2")?;
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
