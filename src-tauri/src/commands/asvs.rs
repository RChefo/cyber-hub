//! OWASP ASVS assessment commands (`workspace/asvs.rs`). Nothing here contacts a network.

use rusqlite::params;
use tauri::{AppHandle, Manager, State};

use crate::commands::workspace::main_window_dialog;
use crate::db::Db;
use crate::error::{AppError, AppResult};
use crate::workspace::asvs;

#[tauri::command]
pub async fn asvs_catalog() -> AppResult<&'static asvs::Catalog> {
    Ok(asvs::catalog())
}

#[tauri::command]
pub async fn asvs_assessments(db: State<'_, Db>, project_id: i64) -> AppResult<Vec<asvs::Summary>> {
    db.with(|c| asvs::list(c, project_id))
}

#[tauri::command]
pub async fn asvs_assessment_create(db: State<'_, Db>, project_id: i64, name: String, level: u8, scope: Option<String>) -> AppResult<i64> {
    db.with(|c| asvs::create(c, project_id, &name, level, scope.as_deref().unwrap_or("")))
}

#[tauri::command]
pub async fn asvs_assessment_get(db: State<'_, Db>, id: i64) -> AppResult<asvs::View> {
    db.with(|c| asvs::get(c, id))
}

#[tauri::command]
pub async fn asvs_assessment_update(db: State<'_, Db>, id: i64, name: Option<String>, level: Option<u8>, scope: Option<String>) -> AppResult<()> {
    db.with(|c| asvs::update(c, id, name.as_deref(), level, scope.as_deref()))
}

#[tauri::command]
pub async fn asvs_assessment_delete(db: State<'_, Db>, id: i64) -> AppResult<()> {
    db.with(|c| asvs::delete(c, id))
}

#[tauri::command]
pub async fn asvs_set_status(db: State<'_, Db>, id: i64, requirement: String, status: String, note: Option<String>) -> AppResult<()> {
    db.with(|c| asvs::set_status(c, id, &requirement, &status, note.as_deref(), "user"))
}

#[tauri::command]
pub async fn asvs_link(db: State<'_, Db>, id: i64, requirement: String, kind: String, ref_id: i64, linked: bool) -> AppResult<()> {
    db.with(|c| asvs::link(c, id, &requirement, &kind, ref_id, linked))
}

#[tauri::command]
pub async fn asvs_mapping_add(db: State<'_, Db>, id: i64, requirement: String, framework: String, reference: String, note: Option<String>) -> AppResult<i64> {
    db.with(|c| asvs::mapping_add(c, id, &requirement, &framework, &reference, note.as_deref().unwrap_or("")))
}

#[tauri::command]
pub async fn asvs_mapping_delete(db: State<'_, Db>, mapping_id: i64) -> AppResult<()> {
    db.with(|c| asvs::mapping_delete(c, mapping_id))
}

#[tauri::command]
pub async fn asvs_record_finding(db: State<'_, Db>, id: i64, requirement: String, severity: String) -> AppResult<i64> {
    db.with(|c| asvs::record_finding(c, id, &requirement, &severity))
}

/// Saves the assessment as a Markdown report through a native dialog; recorded on the timeline.
#[tauri::command]
pub async fn asvs_report_export(app: AppHandle, id: i64) -> AppResult<Option<String>> {
    let (project_id, name, content) = app.state::<Db>().with(|c| {
        let (project_id, project, name): (i64, String, String) = c.query_row("SELECT a.project_id, p.name, a.name FROM asvs_assessments a JOIN projects p ON p.id = a.project_id WHERE a.id = ?1", params![id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        let md = asvs::report_markdown(c, id, &project, &chrono::Utc::now().format("%Y-%m-%d").to_string())?;
        Ok((project_id, name, md))
    })?;
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c } else { '_' }).take(60).collect();
    let (tx, rx) = tokio::sync::oneshot::channel();
    main_window_dialog(&app, "Export the ASVS assessment").set_file_name(format!("{safe}-asvs-{}.md", asvs::catalog().version)).add_filter("Markdown", &["md"]).save_file(move |f| {
        let _ = tx.send(f.and_then(|f| f.into_path().ok()));
    });
    let Some(path) = rx.await.ok().flatten() else { return Ok(None) };
    std::fs::write(&path, content).map_err(|e| AppError::Internal(format!("Could not write the report: {e}")))?;
    let file = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
    let _ = app.state::<Db>().with(|c| crate::workspace::timeline::record(c, project_id, "report", &format!("ASVS assessment exported: {name}"), &file, None, None));
    Ok(Some(file))
}
